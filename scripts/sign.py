#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import mmap
import os
import struct
import time
import ctypes

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from SignerInfo import SignerInfo
from sbl1 import SBL1RSA, SBL1ECDSA
from st2 import ST2RSA, ST2ECDSA

def get_target_boundary(data):
    if len(data) >= 0x40:
        footer = data[-0x40:]
        if footer[:4] == b"AVBf":
            return struct.unpack_from(">Q", footer, 12)[0]
    return len(data)

RSA_MOD_SIZE = 0x100
RSA_EXP_SIZE = 0x4
SPARSE_MAGIC = 0xED26FF3A
EROFS_MAGIC = 0xE0F5E1E2

def load_private_key(path):
    with open(path, "rb") as f:
        pem = f.read()
    key = serialization.load_pem_private_key(pem, password=None)
    return key

def pubkey_blob(pub, sign_type):
    n = pub.public_numbers()
    if sign_type == 0:
        return struct.pack(
            f"<I{RSA_MOD_SIZE}sI{RSA_EXP_SIZE}s",
            RSA_MOD_SIZE, n.n.to_bytes(RSA_MOD_SIZE, "little"),
            RSA_EXP_SIZE, n.e.to_bytes(RSA_EXP_SIZE, "little"),
        )
    return b"\x00" * 20 + n.x.to_bytes(48, byteorder="big") + b"\x00" * 20 + n.y.to_bytes(48, byteorder="big") + (b"\x00" * 388)

def sign_pss(key, data):
    return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0x20), hashes.SHA256())[::-1]

def generate_padded_signature(r, s):
    r_bytes = r.to_bytes(48, byteorder="big")
    s_bytes = s.to_bytes(48, byteorder="big")
    r_padded = b"\x00" * 20 + r_bytes
    s_padded = b"\x00" * 20 + s_bytes
    return r_padded + s_padded

def sign_ecdsa_p384(key, data):
    signature = key.sign(data, ec.ECDSA(utils.Prehashed(hashes.SHA512())))
    r, s = decode_dss_signature(signature)
    return generate_padded_signature(r, s)

def header_digest(data, sign_type):
    if sign_type == 0:
        return hashlib.sha256(data[0x10:]).digest()[:4]
    return hashlib.sha512(data[0x10:]).digest()[:4]

def sign_st1(data, sign_type, st1_privatekey, st2_privatekeys, hmac_key, rb_count):
    if sign_type == 0:
        sbl1 = SBL1RSA(len(data)).from_buffer(data)
    else:
        sbl1 = SBL1ECDSA(len(data)).from_buffer(data)
 
    st1_publickey = pubkey_blob(st1_privatekey.public_key(), sign_type)
    sbl1.checksum = 0
    sbl1.time = int(time.time())
    if rb_count is not None:
        sbl1.rb_count = rb_count
    if sign_type == 0:
        sbl1.st2_publickey[:] = pubkey_blob(st2_privatekeys[0].public_key(), sign_type)
    else:
        sbl1.st2_key_tee[:] = pubkey_blob(st2_privatekeys[0].public_key(), sign_type)
        sbl1.st2_key_ree[:] = pubkey_blob(st2_privatekeys[1].public_key(), sign_type)
    sbl1.st1_publickey[:] = st1_publickey
    if sign_type == 0:
        sbl1.hmac[:] = hmac.digest(hmac_key, st1_publickey, hashlib.sha256)
        sbl1.signature[:] = sign_pss(st1_privatekey, memoryview(data)[:SBL1RSA(len(data)).st1_publickey.offset])
    else:
        sbl1.hmac[:] = hmac.digest(hmac_key, st1_publickey[:136], hashlib.sha512)[:32]
        sbl1.signature[:] = sign_ecdsa_p384(st1_privatekey, hashlib.sha512(memoryview(data)[:SBL1ECDSA(len(data)).signature.offset]).digest())
    sbl1.checksum = int.from_bytes(header_digest(data, sign_type), "little")
    return data

def sign_st2(data, sign_type, st2_privatekey, rb_count, key_type, key_index, update_header, has_signer, signerinfo_values, append_st2):
    footer_type = ST2RSA if sign_type == 0 else ST2ECDSA
    footer_size = ctypes.sizeof(footer_type)
    signerinfo_size = ctypes.sizeof(SignerInfo)
    is_sparse = data[:4] == struct.pack("<I", SPARSE_MAGIC)
    is_erofs = data[0x400:0x404] == struct.pack("<I", EROFS_MAGIC)
    legacy_sparse_rsa = is_sparse and sign_type == 0 and data[0x320:0x328] == b"SSANDOID"

    if is_erofs:
        signerinfo_offset = 0x300
    elif is_sparse:
        footer_offset = 0x220 if legacy_sparse_rsa else 0x28
        signerinfo_offset = 0x430 if legacy_sparse_rsa else 0x328
    else:
        footer_offset = get_target_boundary(data)
        if update_header:
            data[4:8] = bytes(4)
        if append_st2:
            data[footer_offset:footer_offset] = bytes(footer_size + (signerinfo_size if has_signer else 0))
            if has_signer:
                signerinfo_offset = footer_offset
                footer_offset += signerinfo_size
        else:
            footer_offset -= footer_size
            signerinfo_offset = footer_offset - signerinfo_size

    if has_signer:
        for field, _ in SignerInfo._fields_:
            value = (signerinfo_values[field] or "").encode("ascii")
            member = getattr(SignerInfo, field)
            start = signerinfo_offset + member.offset
            data[start:start + member.size] = value.ljust(member.size, b"\x00")

    if is_erofs:
        return data

    sparse_rsa = is_sparse and sign_type == 0
    if not sparse_rsa:
        footer = footer_type.from_buffer(data, footer_offset)
        if rb_count is not None:
            footer.rb_count = rb_count
        footer.sign_type = sign_type
        footer.key_type = key_type
        if key_index is not None:
            footer.key_index = key_index
        if sign_type != 0:
            footer.padding[:] = bytes(len(footer.padding))

    if is_sparse:
        payload = memoryview(data)[signerinfo_offset:]
        payload_digest = hashlib.sha1(payload).digest() if legacy_sparse_rsa else hashlib.sha256(payload).digest() if sign_type == 0 else hashlib.sha512(payload).digest()
        payload.release()
        signed_data = payload_digest if sign_type == 0 else hashlib.sha512(payload_digest + data[footer_offset:footer_offset + 0x10]).digest()
    else:
        signed_view = memoryview(data)[:footer_offset + 0x10]
        signed_data = signed_view if sign_type == 0 else hashlib.sha512(signed_view).digest()

    signature = sign_pss(st2_privatekey, signed_data) if sign_type == 0 else sign_ecdsa_p384(st2_privatekey, signed_data)
    if not is_sparse:
        signed_view.release()

    if sparse_rsa:
        data[footer_offset:footer_offset + 0x100] = signature
        if legacy_sparse_rsa:
            data[0x328:0x428] = signature
    else:
        footer.signature[:] = signature
    if update_header and not is_sparse:
        data[4:8] = header_digest(data, sign_type)
    return data

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Exynos CodeSigner")
    ap.add_argument("input_file", help="Path to the image to sign")
    ap.add_argument("keys_dir",  help="Directory containing the signing keys (hmac.bin, st1.pem, st2.pem)")
    ap.add_argument("stage", choices=["st1", "st2"], help="Signing stage")
    ap.add_argument("--update-header", action="store_true", help="Image requires updated header checksum (ST2 only)")
    ap.add_argument("--rb-count", type=int, default=None, help="Override rb_count of image")
    ap.add_argument("--signing-type", type=int, choices=[0, 4], default=4, help="Type of signature to use")
    ap.add_argument("--st2-key-type", type=int, choices=[0, 1], default=0, help="V5 only. 0 = tee, 1 = ree")
    ap.add_argument("--st2-key-index", type=lambda value: int(value, 16), default=None, help="Override ST2 key index (hex)")
    ap.add_argument("--append_st2", action="store_true", help="Append a new ST2 footer instead of resigning one")
    ap.add_argument("--has_signer", action="store_true", help="Ensure a 0x100-byte SignerInfo exists before ST2")
    for field, _ in SignerInfo._fields_:
        ap.add_argument(f"--{field}", help=f"Set {field} (empty clears it)")
    args = ap.parse_args()

    signerinfo_values = {field: getattr(args, field) for field, _ in SignerInfo._fields_}

    key_dir = os.path.join(args.keys_dir, str(args.signing_type))
    st2_privatekeys = []
    st1_privatekey = load_private_key(os.path.join(key_dir, "st1.pem"))
    if args.signing_type == 0:
        st2_privatekeys.append(load_private_key(os.path.join(key_dir, "st2.pem")))
    else:
        st2_privatekeys.append(load_private_key(os.path.join(key_dir, "st2t.pem")))
        st2_privatekeys.append(load_private_key(os.path.join(key_dir, "st2r.pem")))
    with open(os.path.join(args.keys_dir, "hmac.bin"), "rb") as f:
        hmac_key = f.read()

    with open(args.input_file, "rb") as f:
        image_header = f.read(0x404)
        use_mmap = image_header[:4] == struct.pack("<I", SPARSE_MAGIC) or image_header[0x400:0x404] == struct.pack("<I", EROFS_MAGIC)
        if not use_mmap:
            size = os.fstat(f.fileno()).st_size
            data = bytearray(size)
            f.seek(0)
            f.readinto(data)

    if use_mmap:
        image = open(args.input_file, "r+b")
        data = mmap.mmap(image.fileno(), 0)

    try:
        if args.stage == "st1":
            sign_st1(data, args.signing_type, st1_privatekey, st2_privatekeys, hmac_key, args.rb_count)
        else:
            sign_st2(data, args.signing_type, st2_privatekeys[args.st2_key_type], args.rb_count, args.st2_key_type, args.st2_key_index, args.update_header, args.has_signer, signerinfo_values, args.append_st2)

        if use_mmap:
            data.flush()
        else:
            with open(args.input_file, "wb") as f:
                f.write(data)
    finally:
        if use_mmap:
            data.close()
            image.close()
