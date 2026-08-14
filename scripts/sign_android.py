#!/usr/bin/env python3

import sys
import os
from struct import unpack
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import mmap

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
    print("currently no SignerInfo, will take from sboot.bin")
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
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <boot.img> <private_key.pem>")
        sys.exit(1)

    filename = sys.argv[1]
    keyfile = sys.argv[2]
    if not os.path.exists(filename):
        print("file not found!")
        return
    if not os.path.exists(keyfile):
        print("key not found!")
        return
    with open(keyfile, "rb") as f:
        priv_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    file_handle = open(filename, "r+b")
    mapped_data = mmap.mmap(file_handle.fileno(), 0)
    if mapped_data[:4] == b'\x3a\xff\x26\xed':
        print("sparse images are handled by sign.py")
        mapped_data.close()
        file_handle.close()
        return

    data = mapped_data
    is_bootimg = mapped_data[:8] == b'ANDROID!'
    did_expand = False

    no_signer = has_no_signer(data[-0x210:-0x206])
    if no_signer:
        signer_info_if_null = get_signer_info_if_missing()
        if signer_info_if_null is None:
            mapped_data.close()
            file_handle.close()
            return
        signer_info_if_null[0x9C:0x9C+0x10] = os.path.basename(filename).encode()[:0x10].ljust(0x10, b"\x00")
        did_expand = True
        if is_bootimg:
            print("bootimg detected!")
            sz = compute_min_size(data)
            data = bytearray(data[:sz])
            seandroidenforce = bytes.fromhex("53 45 41 4E 44 52 4F 49 44 45 4E 46 4F 52 43 45")
            data += seandroidenforce
        else:
            data = bytearray(data)
        data += bytes(0x210)
        data[-0x210:-0x100] = signer_info_if_null

    msg = bytes(data[:-0x100])
    sig = sign(msg, priv_key)
    if did_expand:
        data[-0x100:] = sig[::-1]

    if not did_expand:
        offset = data.size() - 0x100
        data[offset:offset + len(sig)] = sig[::-1]
        mapped_data.flush()
    else:
        with open(filename, "wb") as f:
            f.write(data)

    mapped_data.close()
    file_handle.close()

if __name__ == "__main__":
    main()
