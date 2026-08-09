#!/usr/bin/env python3

import sys
import hashlib
import os
from struct import unpack
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes, serialization
import mmap

SIGNER_VER_03 = bytes.fromhex("53 69 67 6E 65 72 56 65 72 30 33")
def is_ecdsa_signer(data):
    marker = bytes(data[0x328:0x328 + len(SIGNER_VER_03)])
    return marker in SIGNER_VER_03

def download_final_digest(data, header):
    payload_digest = hashlib.sha256(bytes(data[0x328:])).digest()
    return payload_digest, hashlib.sha512(payload_digest + header).digest()

def generate_padded_signature(r, s):
    r_padded = b"\x00" * 20 + r.to_bytes(48, byteorder="big")
    s_padded = b"\x00" * 20 + s.to_bytes(48, byteorder="big")
    return r_padded + s_padded

def sign_digest(priv_key, digest):
    signature = priv_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA512())))
    r, s = decode_dss_signature(signature)
    return generate_padded_signature(r, s)

def sign(msg, priv_key):
    return priv_key.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )

def has_no_signer(data):
    return data != bytes.fromhex("53 69 67 6E 65 72 56 65 72 30")

def get_signer_info_if_missing():
    print("currently no signerver info, will take from sboot.bin")
    if not os.path.exists("sboot.bin"):
        print("place your device's sboot.bin in current dir and re-run script")
        return
    # sign type v5 todo
    with open("sboot.bin", "rb") as f:
        offset = -(0x210)
        f.seek(offset, os.SEEK_END)
        signer_info = bytearray(f.read(0x210))
    return signer_info

# for bootimg
def get_number_of_pages(size, page_size):
    return (size + page_size - 1) // page_size

def compute_min_size(data):
    (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr,
    second_size, second_addr, tags_addr, page_size,
    dtb_size) = unpack('9I', data[8:44])
    num_header_pages = 1
    num_kernel_pages = get_number_of_pages(kernel_size, page_size)
    num_ramdisk_pages = get_number_of_pages(ramdisk_size, page_size)
    num_second_pages = get_number_of_pages(second_size, page_size)
    num_dtb_pages = get_number_of_pages(dtb_size, page_size)
    return (num_header_pages + num_kernel_pages + num_ramdisk_pages + num_second_pages + num_dtb_pages)*page_size

def main():
    if len(sys.argv) not in (3, 4):
        print(f"Usage: {sys.argv[0]} <file> <private_key.pem> [signer.bin]")
        sys.exit(1)

    filename = sys.argv[1]
    keyfile = sys.argv[2]
    if not os.path.exists(filename):
        print("file not found!")
        return
    if not os.path.exists(keyfile):
        print("key not found!")
        return
    if len(sys.argv) == 4:
        if not os.path.exists(sys.argv[3]):
            print("signer file found!")
            return
        with open(sys.argv[3], "rb") as f:
            signer = bytearray(os.fstat(f.fileno()).st_size)
            f.readinto(signer)
    with open(keyfile, "rb") as f:
        priv_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    file_handle = open(filename, "r+b")
    data = mmap.mmap(file_handle.fileno(), 0)

    is_sparse = data[:4] == b'\x3a\xff\x26\xed'
    is_bootimg = data[:8] == b'ANDROID!'
    did_expand = False
    signer_info_added = False
    needs_reverse = True

    if is_sparse:
        print("sparse detected!")
        if has_no_signer(data[0x328:0x332]) or len(sys.argv) == 4:
            if len(sys.argv) == 4:
                signer_info_if_null = signer
            else:
                signer_info_if_null = get_signer_info_if_missing()
            signer_info_if_null[0x9C:0x9C+0x10] = filename.encode().ljust(0x10, b"\x00")
            signer_info_added = True
            data[0x328:0x428] = signer_info_if_null[:0x100]

        if is_ecdsa_signer(data):
            print("ECDSA detected!")

            h = hashlib.sha512()
            h.update(data[0x328:])
            payload_digest = h.digest()

            h = hashlib.sha512()
            h.update(payload_digest)
            h.update(data[0x28:0x38])
            digest = h.digest()

            sig = sign_digest(priv_key, digest)
            needs_reverse = False
        else:
            h = hashlib.sha256()
            h.update(data[0x328:])
            msg = h.digest()
            sig = sign(msg, priv_key)
    else:
        no_signer = has_no_signer(data[-0x210:-0x206])
        if no_signer or len(sys.argv) == 4:
            if len(sys.argv) == 4:
                signer_info_if_null = signer
            else:
                signer_info_if_null = get_signer_info_if_missing()
            signer_info_if_null[0x9C:0x9C+0x10] = filename.encode().ljust(0x10, b"\x00")
            did_expand = True
            if is_bootimg:
                print("bootimg detected!")
                sz = compute_min_size(data)
                data = data[:sz]
                seandroidenforce = bytes.fromhex("53 45 41 4E 44 52 4F 49 44 45 4E 46 4F 52 43 45")
                data += seandroidenforce
            if no_signer or is_bootimg:
                data += bytes(0x210)
            data[-0x210:-0x100] = signer_info_if_null
        msg = bytes(data[:-0x100])
        sig = sign(msg, priv_key)
        if did_expand:
            data[-0x100:] = sig[::-1]
    if not did_expand:
        if is_sparse:
            if signer_info_added:
                data[0x328:0x428] = signer_info_if_null[:0x100]

            if needs_reverse:
                data[0x28:0x28 + len(sig)] = sig[::-1]
            else:
                data[0x38:0x38 + len(sig)] = sig
        else:
            offset = data.size() - 0x100
            data[offset:offset + len(sig)] = sig[::-1] if needs_reverse else sig
    else:
        with open(filename, "wb") as f:
            f.write(data)

    data.flush()
    data.close()
    file_handle.close()

if __name__ == "__main__":
    main()
