#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import os
import struct
import time
import ctypes
import json
import subprocess

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from sbl1 import SBL1RSA, SBL1ECDSA, load_sbl1_json_into_struct
from st2 import ST2RSA, ST2ECDSA

def get_target_boundary(data):
    if len(data) >= 0x40:
        footer = data[-0x40:]
        if footer[:4] == b"AVBf":
            return struct.unpack_from(">Q", footer, 12)[0]
    return len(data)

RSA_MOD_SIZE = 0x100
RSA_EXP_SIZE = 0x4

def load_private_key(path, sign_type):
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

def sign_st1(data, sign_type, st1_privatekey, st2_privatekeys, hmac_key, rb_count, json_path):
    if sign_type == 0:
        sbl1 = SBL1RSA(len(data)).from_buffer(data)
    else:
        sbl1 = SBL1ECDSA(len(data)).from_buffer(data)
    if json_path is not None:
        with open(json_path) as f:
            j = json.load(f)
        load_sbl1_json_into_struct(sbl1, j)
 
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

def sign_st2(data, sign_type, st2_privatekey, rb_count, update_header, has_avb):
    size_no_avb = len(data)
    if has_avb:
        size_no_avb = get_target_boundary(data)
    if update_header:
        data[4:8] = bytes(4)
    if sign_type == 0:
        footer = ST2RSA.from_buffer(memoryview(data)[size_no_avb - ctypes.sizeof(ST2RSA):size_no_avb])
    else:
        footer = ST2ECDSA.from_buffer(memoryview(data)[size_no_avb - ctypes.sizeof(ST2ECDSA):size_no_avb])
    if rb_count is not None:
        footer.rb_count = rb_count
    if sign_type == 0:
        footer.signature[:] = sign_pss(st2_privatekey, memoryview(data)[:size_no_avb - 0x100])
    else:
        footer.signature[:] = sign_ecdsa_p384(st2_privatekey, hashlib.sha512(memoryview(data)[:size_no_avb - 0x200]).digest())
    if update_header:
        data[4:8] = header_digest(data, sign_type)
    return data

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Exynos CodeSigner")
    ap.add_argument("input_file", help="Path to the image to sign")
    ap.add_argument("keys_dir",  help="Directory containing the signing keys (hmac.bin, st1.pem, st2.pem)")
    ap.add_argument("stage", choices=["st1", "st2"], help="Signing stage")
    ap.add_argument("--sbl1-json", help="sbl1.json file containing BL1 signature information (ST1 only)")
    ap.add_argument("--update-header", action="store_true", help="Image requires updated header checksum (ST2 only)")
    ap.add_argument("--rb-count", type=int, default=None, help="Override rb_count of image")
    ap.add_argument("--signing-type", type=int, default=4, help="Type of signature to use")
    ap.add_argument("--st2-key-type", type=int, default=0, help="V5 only. 0 = tee, 1 = ree")
    ap.add_argument("--avb-partition-name", type=str, default="", help="AVB partition name, skip if not given")
    ap.add_argument("--avb-partition-size", type=int, default=0, help="AVB partition padding size")
    args = ap.parse_args()

    has_avb = args.avb_partition_name != ""

    key_dir = os.path.join(args.keys_dir, str(args.signing_type))
    st2_privatekeys = []
    st1_privatekey = load_private_key(os.path.join(key_dir, "st1.pem"), args.signing_type)
    if args.signing_type == 0:
        st2_privatekeys.append(load_private_key(os.path.join(key_dir, "st2.pem"), args.signing_type))
    else:
        st2_privatekeys.append(load_private_key(os.path.join(key_dir, "st2t.pem"), args.signing_type))
        st2_privatekeys.append(load_private_key(os.path.join(key_dir, "st2r.pem"), args.signing_type))
    with open(os.path.join(args.keys_dir, "hmac.bin"), "rb") as f:
        hmac_key = f.read()

    with open(args.input_file, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        data = bytearray(size)
        f.readinto(data)

    name = os.path.basename(args.input_file)
    if args.stage == "st1":
        signed = sign_st1(data, args.signing_type, st1_privatekey, st2_privatekeys, hmac_key, args.rb_count, args.sbl1_json)
    else:
        signed = sign_st2(data, args.signing_type, st2_privatekeys[args.st2_key_type], args.rb_count, args.update_header, has_avb)
    with open(args.input_file, "wb") as f:
        f.write(signed)

    if has_avb:
        subprocess.run([
            "python", "scripts/avbtool.py", "add_hash_footer",
            "--image", args.input_file,
            "--partition_name", args.avb_partition_name,
            "--partition_size", str(args.avb_partition_size),
            "--key", os.path.join(args.keys_dir, "avb.pem"),
            "--algorithm", "SHA256_RSA4096",
            "--salt", "0000000000000000000000000000000000000000000000000000000000000000",
        ], check=True)
