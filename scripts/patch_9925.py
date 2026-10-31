#!/usr/bin/env python3

import re
import sys
import struct
import os
import keystorage

RETURN_ZERO = bytes.fromhex("00 00 80 D2 C0 03 5F D6")

def write_u32(data, offset, value):
    struct.pack_into("<I", data, offset, value)

def word(data, offset):
    return int.from_bytes(data[offset : offset + 4], "little")

def signed(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign

def adrp_add(data, offset):
    adrp = word(data, offset)
    if adrp & 0x9F000000 != 0x90000000:
        return None

    imm = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7FFFF) << 2)
    page = (offset & ~0xFFF) + (signed(imm, 21) << 12)
    for distance in range(4, 17, 4):
        add = word(data, offset + distance)
        if add & 0xFF000000 == 0x91000000 and (add >> 5) & 31 == adrp & 31:
            return page + (((add >> 10) & 0xFFF) << (12 if add & 0x400000 else 0))
    return None

def find_xref(data, string):
    string_offset = data.find(string)
    if string_offset < 0:
        raise ValueError(f"string not found: {string!r}")
    if data.find(string, string_offset + 1) >= 0:
        raise ValueError(f"expected one copy of {string!r}")

    refs = [
        offset
        for offset in range(0, string_offset & ~3, 4)
        if adrp_add(data, offset) == string_offset
    ]
    if len(refs) != 1:
        raise ValueError(f"expected one xref to {string!r}, found {len(refs)}")
    return refs[0]

# offsets S908B GZH3

def patch_cm_otp_write_otp_tune(data):
    cm_otp_write_otp_tune = (
        find_xref(data, b"[OTP] OTP_TUNE program start\n\0") - 0x10
    )
    print(f"cm_otp_write_otp_tune: +{hex(cm_otp_write_otp_tune)}")
    data[cm_otp_write_otp_tune : cm_otp_write_otp_tune + 8] = RETURN_ZERO

def patch_get_fmm_data(data):
    get_fmm_data = find_xref(data, b"[FMM] Set RPMB Default info to 512\n\0") - 0x2c
    print(f"get_fmm_data: +{hex(get_fmm_data)}")
    data[get_fmm_data : get_fmm_data + 8] = RETURN_ZERO

def patch_set_warranty_void_bit_reason(data):
    set_warranty_void_bit_reason = (
        find_xref(data, b"CURRENT BINARY: Samsung Official\n\0") - 0x264
    )
    print(f"set_warranty_void_bit_reason: +{hex(set_warranty_void_bit_reason)}")
    data[set_warranty_void_bit_reason : set_warranty_void_bit_reason + 8] = RETURN_ZERO

def patch_set_warrant_bit(data):
    set_warrant_bit = find_xref(data, b"[EFUSE] Set warranty bit(0x%llx)\n\0") - 0x58
    print(f"set_warrant_bit: +{hex(set_warrant_bit)}")
    data[set_warrant_bit : set_warrant_bit + 8] = RETURN_ZERO

def patch_read_dmc_rpmb(data):
    read_dmc_rpmb = find_xref(data, b"%s : all zero\n\0") - 0xB4
    print(f"read_dmc_rpmb: +{hex(read_dmc_rpmb)}")
    data[read_dmc_rpmb : read_dmc_rpmb + 8] = RETURN_ZERO

def patch_keystorage_avb_keys(data, key):
    for slot, meta in enumerate(data.header.key_meta[:data.header.key_count]):
        if meta.sign_type == 0xff:
            data.set_pubkey(slot, key)

if __name__ == "__main__":
    keys_dir = sys.argv[1]
    output_dir = sys.argv[2]

    sboot_dir = os.path.join(output_dir, "sboot")
    bootloader_dir = os.path.join(sboot_dir, "bootload")
    output_bootload = os.path.join(sboot_dir, "bootload.bin")
    output_keystorage = os.path.join(os.path.join(output_dir, "keystorage"), "keystorage.bin")
    with open(output_bootload, "rb") as f:
        data = bytearray(f.read())

    patch_cm_otp_write_otp_tune(data)
    patch_get_fmm_data(data)
    patch_set_warranty_void_bit_reason(data)
    patch_set_warrant_bit(data)
    patch_read_dmc_rpmb(data)

    with open(output_bootload, "wb") as f:
        f.write(data)

    with open(os.path.join(keys_dir, "avb.pubkey"), "rb") as f:
        avb_pubkey = f.read()
    image = keystorage.load(output_keystorage)
    patch_keystorage_avb_keys(image, avb_pubkey)
    image.save(output_keystorage)
