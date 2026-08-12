#!/usr/bin/env python3

import re
import sys
import struct
import os

def write_u32(data, offset, value):
    struct.pack_into("<I", data, offset, value)

def write_words(data, offset, words):
    for i, word in enumerate(words):
        write_u32(data, offset + i * 4, word)

def jump_to_func_from(from_addr, to_addr):
    return 0x94000000 | (((to_addr - from_addr) >> 2) & 0x03FFFFFF)

def resolve_bl(data, pc_address):
    if pc_address is None:
        return None
    instr = struct.unpack_from("<I", data, pc_address)[0]
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc_address + imm26 * 4

def find_pattern(data, pattern_str, offset = 0):
    regex_bytes = b""
    for token in pattern_str.split():
        if token == "?":
            regex_bytes += b"."
        else:
            regex_bytes += re.escape(bytes.fromhex(token))
    match = re.compile(regex_bytes, re.DOTALL).search(data)
    if match:
        return match.start() + offset
    return None

def patch_prevent_warranty_fuse(data): # BYH2 S721B
    ret0 = [
        0xD2800000,
        0xD65F03C0,
    ]
    # seccmd_fwb has inlined warranty reaon setter, no point patching tho.
    write_words(data, 0x904D8, ret0) # set_warranty_void_bit_reason
    write_words(data, 0x932F4, ret0) # set_warrant_bit

def patch_check_signature(data): # BYH2 S721B
    ret0 = [
        0xD2800000,
        0xD65F03C0,
    ]
    write_words(data, 0x95A94, ret0)

if __name__ == "__main__":
    #load
    sboot_dir = sys.argv[1]
    bootloader_dir = os.path.join(sboot_dir, "bootload")
    output_bootload = os.path.join(sboot_dir, "bootload.bin")

    files = [
        "bootload_part1.bin",
        "spkg1.bin",
        "pad.bin",
        "spkg2.bin",
        "bootload_part2.bin",
    ]

    data = bytearray()
    sizes = []

    for filename in files:
        path = os.path.join(bootloader_dir, filename)
        with open(path, "rb") as f:
            piece = bytearray(f.read())
        data.extend(piece)
        sizes.append(len(piece))

    #patches
    patch_prevent_warranty_fuse(data)
    patch_check_signature(data)

    #write
    offset = 0
    for filename, size in zip(files, sizes):
        path = os.path.join(bootloader_dir, filename)
        chunk = data[offset:offset + size]
        with open(path, "wb") as f:
            f.write(chunk)
        offset += size
    with open(output_bootload, "wb") as f:
        f.write(data)
