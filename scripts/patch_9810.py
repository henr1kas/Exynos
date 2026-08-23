#!/usr/bin/env python3

import struct
import sys

RETURN_ZERO = bytes.fromhex("00 00 80 D2 C0 03 5F D6")
RETURN_ONE = bytes.fromhex("20 00 80 D2 C0 03 5F D6")

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

def write_words(data, offset, words):
    for i, word_value in enumerate(words):
        write_u32(data, offset + i * 4, word_value)

def jump_to_func_from(from_addr, to_addr):
    return 0x94000000 | (((to_addr - from_addr) >> 2) & 0x03FFFFFF)

def patch_check_signature(data):
    check_signature = find_xref(data, b"There is no signature\n\0") - 0x104
    print(f"check_signature: {check_signature:#x}")
    data[check_signature : check_signature + len(RETURN_ZERO)] = RETURN_ZERO

def patch_initialize_efuse_data(data): # these patches should be moved to el3_mon?
    etc_market = find_xref(data, b"nantirbk0 mismatch!(%d vs %d), updating...\n\0") - 0xB0
    commercial_bit = find_xref(data, b"commercial_bit mismatch!(%d vs %d), updating...\n\0") - 0x6C
    print(f"etc_market: {etc_market:#x}")
    print(f"commercial_bit: {commercial_bit:#x}")
    write_u32(data, etc_market, 0x52800000)          # etc_market 0
    write_u32(data, etc_market + 16, 0x52800020)     # etc_development 1
    write_u32(data, commercial_bit, 0x52800000)      # commercial_bit 0
    write_u32(data, commercial_bit + 16, 0x52800020) # test_bit 1
    write_u32(data, commercial_bit + 32, 0x52800000) # warranty_bit 0

def patch_set_warranty_void_bit_reason(data): # TODO: may not be needed if DEV DEVICE?
    set_warranty_void_bit_reason = find_xref(data, b"%s : no reason\n\0") + 0x18
    print(f"set_warranty_void_bit_reason: {set_warranty_void_bit_reason:#x}")
    data[set_warranty_void_bit_reason : set_warranty_void_bit_reason + len(RETURN_ZERO)] = RETURN_ZERO

def patch_set_warranty_bit(data): # TODO: may not be needed if DEV DEVICE?
    set_warranty_bit = find_xref(data, b"[EFUSE] Set warranty bit(%d)\n\0") - 0x58
    print(f"set_warranty_bit: {set_warranty_bit:#x}")
    data[set_warranty_bit : set_warranty_bit + len(RETURN_ZERO)] = RETURN_ZERO

def patch_read_rmm_rpmb(data): # n10l does not have this i think? TODO
    read_rmm_rpmb = find_xref(data, b"[RMM] read_data fail...\n\0") - 0x50
    print(f"read_rmm_rpmb: {read_rmm_rpmb:#x}")
    data[read_rmm_rpmb : read_rmm_rpmb + len(RETURN_ZERO)] = RETURN_ZERO

def patch_read_kg_rpmb(data):
    read_kg_rpmb = find_xref(data, b"[KG] read_data fail...\n\0") - 0x78
    print(f"read_kg_rpmb: {read_kg_rpmb:#x}")
    data[read_kg_rpmb : read_kg_rpmb + len(RETURN_ZERO)] = RETURN_ZERO

def patch_have_this_mode(data):
    have_this_mode = find_xref(data, b"ENG MODE : ENG ALLOWED(%s)\n\0") - 0x58
    print(f"have_this_mode: {have_this_mode:#x}")
    data[have_this_mode : have_this_mode + len(RETURN_ONE)] = RETURN_ONE

def get_efuse_data():
    import hmac
    from sign import load_private_key, pubkey_blob
    with open("keys/hmac.bin", "rb") as f:
        hmac_key = f.read()
    if len(hmac_key) != 32:
        raise ValueError("hmac.bin should be 32 bytes")
    key = load_private_key("keys/0/st1.pem")
    public_blob = pubkey_blob(key.public_key(), 0)
    return bytes(a ^ b for a, b in zip(hmac.digest(hmac_key, public_blob, "sha256"), hmac_key))

def patch_fuse_boot_key(data):
    check_signature = find_xref(data, b"There is no signature\n\0") - 0x104
    cm_otp_write_rom_sec_boot_key = find_xref(data, b"[OTP] ROM_SECURE_BOOT_KEY program start\n\0") - 0x58
    cm_otp_write_use_rom_sec_boot_key = find_xref(data, b"[OTP] USE_ROM_SEC_BOOT_KEY program start\n\0") - 0x4

    print("cm_otp_write_rom_sec_boot_key: " f"{cm_otp_write_rom_sec_boot_key:#x}")
    print("cm_otp_write_use_rom_sec_boot_key: " f"{cm_otp_write_use_rom_sec_boot_key:#x}")
    print("WARNING: patching for burning BOOT_KEY!")

    payload = [
        0xA9BF7BFD,
        0x100000E0,
        0x52800401,
        jump_to_func_from(check_signature + 12, cm_otp_write_rom_sec_boot_key),
        jump_to_func_from(check_signature + 16, cm_otp_write_use_rom_sec_boot_key),
        0xD2800000,
        0xA8C17BFD,
        0xD65F03C0,
    ]
    payload.extend(struct.unpack("<8I", get_efuse_data()))
    write_words(data, check_signature, payload)

should_fuse_key = False # Burns BOOT_KEY once after UFS boot into ODIN MODE.

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())

    patch_check_signature(data)
    patch_initialize_efuse_data(data)
    patch_set_warranty_void_bit_reason(data)
    patch_set_warranty_bit(data)
    patch_read_rmm_rpmb(data)
    patch_read_kg_rpmb(data)
    patch_have_this_mode(data)

    if should_fuse_key:
        patch_fuse_boot_key(data)

    with open(sys.argv[1], "wb") as f:
        f.write(data)
