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

#TODO: use frmo sbl1.py
class SBL1V5Footer(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        # BL1 info
        ("soc_info",           ctypes.c_uint8 * 8),
        # CodeSigner V5
        ("codesigner_version", ctypes.c_uint32),
        ("ap_info",            ctypes.c_char * 4),
        ("time",               ctypes.c_uint64),
        ("rb_count",           ctypes.c_uint32),
        ("signing_type",       ctypes.c_uint32),
        ("description",        ctypes.c_char * 36),
        ("key_index",          ctypes.c_uint32),
        ("debug_certificate",  ctypes.c_uint8 * 0x1C),
        ("st2_key_tee",        ctypes.c_uint8 * 524),
        ("st2_key_ree",        ctypes.c_uint8 * 524),
        ("func_ptr",           ctypes.c_uint8 * 128),
        ("major_id",           ctypes.c_uint16),
        ("minor_id",           ctypes.c_uint16),
        ("reserved",           ctypes.c_uint8 * 0x8),
        ("st1_publickey",      ctypes.c_uint8 * 524),
        ("hmac",               ctypes.c_uint8 * 0x20),
        ("signature_size",     ctypes.c_uint32),
        ("signature",          ctypes.c_uint8 * 136),
        ("padding",            ctypes.c_uint8 * 376)
    ]

class SBL1V4Footer(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        # BL1 info
        ("soc_info",           ctypes.c_uint8 * 8),
        # CodeSigner V4
        ("codesigner_version", ctypes.c_uint32),
        ("ap_info",            ctypes.c_char * 4),
        ("time",               ctypes.c_uint64),
        ("rb_count",           ctypes.c_uint32),
        ("signing_type",       ctypes.c_uint32),
        ("debug_certificate",  ctypes.c_uint8 * 0x1C),
        ("key_index",          ctypes.c_uint32),
        ("st2_publickey",      ctypes.c_uint8 * 0x10C),
        ("func_ptr",           ctypes.c_uint8 * 0x80),
        ("major_id",           ctypes.c_uint16),
        ("minor_id",           ctypes.c_uint16),
        ("reserved",           ctypes.c_uint8 * 0x8),
        ("st1_publickey",      ctypes.c_uint8 * 0x10C),
        ("hmac",               ctypes.c_uint8 * 0x20),
        ("signature_size",     ctypes.c_uint32),
        ("signature",          ctypes.c_uint8 * 0x100),
    ]

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
    footer = SBL1V5Footer.from_buffer_copy(data[sbl1_size - ctypes.sizeof(SBL1V5Footer):sbl1_size])
    if footer.codesigner_version not in (4, 5):
        return SBL1V4Footer.from_buffer_copy(data[sbl1_size - ctypes.sizeof(SBL1V4Footer):sbl1_size])
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
    signed_data = bytearray(data[:-0x100])
    if clear_digest:
        signed_data[4:8] = bytes(4)
    try:
        public_key.verify(
            signature,
            signed_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
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
        pattern = re.escape(sig_meme_bytes)
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

def find_blocks_by_sigs(data, sigs, pub_keys, is_v5, step_size):
    if is_v5:
        sig_size = 0x210
    else:
        sig_size = 0x110

    last_end = 0
    blocks = []
    failed = []
    for offset, var in sigs:
        end = offset + sig_size
        target_key = pub_keys[var]
        verified_start = None
        digest_cleared = False
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
):
    blocks, failed = find_blocks_by_sigs(
        data, sigs, pub_keys, is_v5, step_size
    )

    expected_count = len(custom_names)
    if failed and expected_count and len(blocks) < expected_count and step_size > 0x8:
        fine_blocks, fine_failed = find_blocks_by_sigs(
            data, sigs, pub_keys, is_v5, 0x8
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

# todo: i dont remember if works v4
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
        sig_meme = sboot[offset_sig_meme : offset_sig_meme + 16].tobytes()
    
    sigs = find_st2(sboot, offset_sig_meme, sig_meme, footer.codesigner_version == 5)
    split_file_by_sigs(
        output_dir,
        sboot,
        sigs,
        pub_keys,
        footer.codesigner_version == 5,
        0x1000,
        sboot_split_names,
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
