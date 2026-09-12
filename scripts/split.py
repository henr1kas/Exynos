#!/usr/bin/env python3

import shutil
import importlib
import ctypes
import argparse
import os
import struct
import hashlib
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    Prehashed,
)
from cryptography.hazmat.primitives import hashes

from sbl1 import SBL1RSA, SBL1ECDSA

def print_struct(obj):
    for field_name, field_type in obj._fields_:
        value = getattr(obj, field_name)

        if isinstance(value, bytes):
            # char arrays
            try:
                print(f"{field_name:20}: {value.rstrip(b'\\x00').decode(errors='replace')}")
            except Exception:
                print(f"{field_name:20}: {value.hex()}")

        elif isinstance(value, ctypes.Array):
            # byte arrays
            print(f"{field_name:20}: {bytes(value).hex()}")

        else:
            print(f"{field_name:20}: {value}")

def load_sbl1_footer(data):
    sbl1_size = 512 * int.from_bytes(data[:4], byteorder="little", signed=False)
    footer = SBL1ECDSA(sbl1_size).from_buffer_copy(data[:sbl1_size])
    if footer.codesigner_version not in (4, 5):
        return SBL1RSA(sbl1_size).from_buffer_copy(data[:sbl1_size])
    return footer

def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def get_target_boundary(data):
    if len(data) >= 0x40:
        footer = data[-0x40:]
        if footer[:4] == b"AVBf":
            return struct.unpack_from(">Q", footer, 12)[0]
    return len(data)

def is_good_sig_ecdsa(data, public_key, clear_digest):
    target_size = len(data)
    r = int.from_bytes(data[target_size - 0x200 : target_size - 0x200 + 68], "big")
    s = int.from_bytes(data[target_size - 0x200 + 68 : target_size - 0x200 + 136], "big")

    hasher = hashlib.sha512()

    if clear_digest:
        hasher.update(data[:4])
        hasher.update(b"\x00\x00\x00\x00")
        hasher.update(data[8 : target_size - 0x200])
    else:
        hasher.update(data[: target_size - 0x200])

    digest = hasher.digest()

    try:
        public_key.verify(
            encode_dss_signature(r, s),
            digest,
            ec.ECDSA(Prehashed(hashes.SHA512()))
        )
        return True
    except InvalidSignature:
        return False

def is_good_sig_rsa(data, public_key, clear_digest):
    signature = bytes(data[-0x100:])[::-1]
    signed_data = data[:-0x100]

    hasher = hashlib.sha256()
    if clear_digest:
        hasher.update(signed_data[:4])
        hasher.update(b"\x00\x00\x00\x00")
        hasher.update(signed_data[8:])
    else:
        hasher.update(signed_data)
    digest = hasher.digest()

    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            Prehashed(hashes.SHA256()),
        )
    except InvalidSignature:
        return False
    return True

def is_good_sig(data, public_key, is_v5, clear_digest):
    if is_v5:
        return is_good_sig_ecdsa(data, public_key, clear_digest)
    return is_good_sig_rsa(data, public_key, clear_digest)

def find_st2(mv, offset_sig_meme, sig_meme_bytes, is_v5):
    if is_v5:
        pattern = (
            re.escape(sig_meme_bytes)
            + b'([\x00\x01])\x00\x00\x00'
            + b'(.{4})'
            + b'\x00' * 0x14
        )
    else:
        pattern = re.escape(sig_meme_bytes) + b'(.{4})'
    search_window = mv[:offset_sig_meme]
    results = []
    for match in re.finditer(pattern, search_window):
        if is_v5 and match.group(2) == b'\x00\x00\x00\x00':
            continue
        offset = match.start()
        variant = 0 if not is_v5 or match.group(1) == b'\x00' else 1
        results.append([offset, variant])
    return results

def load_public_key_p348(pubkey_blob):
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(pubkey_blob[:68], "big"),
        int.from_bytes(pubkey_blob[68:136], "big"),
        ec.SECP384R1()
    ).public_key()

def load_public_key_rsa(pubkey_blob):
    modulus = int.from_bytes(pubkey_blob[4:260], "little")
    exponent = int.from_bytes(pubkey_blob[264:268], "little")
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()

def load_public_key(pubkey_blob, is_v5):
    if is_v5:
        return load_public_key_p348(pubkey_blob)
    return load_public_key_rsa(pubkey_blob)

def get_output_name(index, is_pad=False, custom_names=()):
    if index < len(custom_names):
        return custom_names[index]
    return f"{index}_pad.bin" if is_pad else f"{index}.bin"

def get_toc_start_hints(data):
    if len(data) < 0x20 or bytes(data[:4]) != b"TOC\x00":
        return {}
    toc_size = u32(data, 0x14)
    if toc_size < 0x20 or toc_size > min(len(data), 0x100000) or toc_size % 0x20:
        return {}

    hints = {}
    for entry_off in range(0, toc_size, 0x20):
        entry = data[entry_off:entry_off + 0x20]
        name = bytes(entry[:12]).split(b"\x00", 1)[0]
        if not name:
            continue
        start = u32(data, entry_off + 0x0C)
        size = u32(data, entry_off + 0x14)
        end = start + size
        if size == 0 or end > len(data):
            continue
        if name != b"TOC":
            hints.setdefault(end, []).append(start)
    return hints

def find_blocks_by_sigs(data, sigs, pub_keys, is_v5, step_size, start_hints=None):
    if is_v5:
        sig_size = 0x210
    else:
        sig_size = 0x110

    if start_hints is None:
        start_hints = {}

    last_end = 0
    blocks = []
    failed = []
    for offset, var in sigs:
        end = offset + sig_size
        target_key = pub_keys[var]
        verified_start = None
        digest_cleared = False

        for hinted_start in start_hints.get(end, ()):
            if hinted_start < last_end or hinted_start > offset:
                continue
            data_slice = data[hinted_start:end]
            if is_good_sig(data_slice, target_key, is_v5, False):
                verified_start = hinted_start
                break
            if is_good_sig(data_slice, target_key, is_v5, True):
                verified_start = hinted_start
                digest_cleared = True
                break

        if verified_start is None:
            c = offset & ~(step_size - 1)
            while c >= last_end:
                data_slice = data[c:end]
                if is_good_sig(data_slice, target_key, is_v5, False):
                    verified_start = c
                    break
                if is_good_sig(data_slice, target_key, is_v5, True):
                    verified_start = c
                    digest_cleared = True
                    break
                c -= step_size
        if verified_start is None:
            failed.append((offset, var))
            continue
        if verified_start > last_end:
            blocks.append((last_end, verified_start, True, False, None))
        blocks.append((verified_start, end, False, digest_cleared, var))
        last_end = end
    if last_end < len(data):
        blocks.append((last_end, len(data), True, False, None))

    return blocks, failed

def split_file_by_sigs(
    output_dir,
    data,
    sigs,
    pub_keys,
    is_v5,
    step_size,
    custom_names=(),
    start_hints=None,
):
    blocks, failed = find_blocks_by_sigs(
        data, sigs, pub_keys, is_v5, step_size, start_hints
    )
    expected_count = len(custom_names)
    if failed and expected_count and len(blocks) < expected_count and step_size > 0x8:
        fine_blocks, fine_failed = find_blocks_by_sigs(
            data, sigs, pub_keys, is_v5, 0x8, start_hints
        )
        if abs(len(fine_blocks) - expected_count) < abs(len(blocks) - expected_count):
            blocks = fine_blocks
            failed = fine_failed

    os.makedirs(output_dir, exist_ok=True)
    for file_idx, (start, end, is_pad, digest_cleared, var) in enumerate(blocks):
        path = os.path.join(
            output_dir,
            get_output_name(file_idx, is_pad, custom_names),
        )
        with open(path, "wb") as f:
            f.write(data[start:end])
        if not is_pad:
            print(f"was cleared {digest_cleared}, index: {var}")
        print(f"{path}: {hex(end - start)} bytes")

    if expected_count and len(blocks) != expected_count:
        print(
            f"{output_dir}: expected {expected_count} parts, "
            f"but found {len(blocks)}"
        )
        sig_size = 0x210 if is_v5 else 0x110
        for offset, _ in failed:
            print(f"{output_dir}: failed to find start for {offset + sig_size}")

def looks_like_pss(signature, modulus, exponent):
    value = int.from_bytes(signature, "little")
    if value >= modulus:
        return False
    encoded = pow(value, exponent, modulus).to_bytes(0x100, "big")
    if encoded[-1] != 0xBC:
        return False
    masked_db = encoded[:223]
    h_value = encoded[223:255]
    unused_bits = 0x100 * 8 - (modulus.bit_length() - 1)
    if unused_bits and masked_db[0] >> (8 - unused_bits):
        return False
    mask = bytearray()
    for counter in range((len(masked_db) + 31) // 32):
        mask.extend(hashlib.sha256(h_value + counter.to_bytes(4, "big")).digest())
    db = bytearray(a ^ b for a, b in zip(masked_db, mask))
    if unused_bits:
        db[0] &= 0xFF >> unused_bits
    delimiter = len(db) - 32 - 1
    return not any(db[:delimiter]) and db[delimiter] == 1

def filter_v4_pss_candidates(data, sigs, public_key):
    numbers = public_key.public_numbers()
    valid = []
    for footer_offset, key_type in sigs:
        signature_offset = footer_offset + 0x10
        signature = bytes(data[
            signature_offset:signature_offset + 0x100
        ])
        if looks_like_pss(signature, numbers.n, numbers.e):
            valid.append((footer_offset, key_type))
    return valid

def split_file_wrapper(data, sboot_split_names, output_dir, footer):
    if footer.codesigner_version == 5:
        pub_keys = [load_public_key(footer.st2_key_tee, footer.codesigner_version == 5), load_public_key(footer.st2_key_ree, footer.codesigner_version == 5)]
    else:
        pub_keys = [load_public_key(footer.st2_publickey, footer.codesigner_version == 5), None]
    sboot = memoryview(data)

    size_no_avb = get_target_boundary(sboot)
    if footer.codesigner_version == 5:
        offset_sig_meme = size_no_avb - 0x210
        sig_meme = sboot[offset_sig_meme : offset_sig_meme + 8].tobytes()
    else:
        offset_sig_meme = size_no_avb - 0x110
        sig_meme = sboot[offset_sig_meme : offset_sig_meme + 12].tobytes()
    
    sigs = find_st2(sboot, offset_sig_meme, sig_meme, footer.codesigner_version == 5)
    if footer.codesigner_version == 4:
        sigs = filter_v4_pss_candidates(sboot, sigs, pub_keys[0])

    start_hints = get_toc_start_hints(sboot) if footer.codesigner_version == 4 else None

    split_file_by_sigs(
        output_dir,
        sboot,
        sigs,
        pub_keys,
        footer.codesigner_version == 5,
        0x1000,
        sboot_split_names,
        start_hints,
    )

def process_image(img, indir, outdir, footer):
    img_path = os.path.join(indir, img.name)
    if not getattr(img, "split", None):
        shutil.copy(img_path, os.path.join(outdir, img.name))
        return

    with open(img_path, "rb") as fp:
        data = fp.read()

    out_dir = os.path.join(outdir, os.path.splitext(img.name)[0])
    os.makedirs(out_dir, exist_ok=True)
    split_file_wrapper(data, [i.name for i in img.split], out_dir, footer)

    for child in img.split:
        if getattr(child, "split", None):
            process_image(child, out_dir, out_dir, footer)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Samsung Exynos bootloader splitter")
    parser.add_argument("soc", help="soc name")
    parser.add_argument("indir", help="Directory containing required images")
    parser.add_argument("outdir", help="Directory to copy files into and write split output")
    args = parser.parse_args()

    soc_module = importlib.import_module(args.soc)
    soc = soc_module.soc_data()

    indir = args.indir
    outdir = args.outdir

    os.makedirs(outdir, exist_ok=True)

    sboot_path = os.path.join(indir, "sboot.bin")
    fld_path = os.path.join(indir, "fld.bin")

    with open(sboot_path, "rb") as f:
        sboot = f.read()

    if os.path.exists(fld_path):
        with open(fld_path, "rb") as f:
            fld = f.read()
        footer = load_sbl1_footer(fld)
    else:
        footer = load_sbl1_footer(sboot)

    for value in vars(soc).values():
        if not isinstance(value, tuple):
            continue
        for img in value:
            process_image(img, indir, outdir, footer)
