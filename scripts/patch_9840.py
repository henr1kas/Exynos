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

def patch_check_signature(data): # required because PIT will not load on USB boot with custom st2 key
    check_signature = find_xref(data, b"%s: There is no signature\n\0") - 0xDC
    print(f"check_signature: {check_signature:#x}")
    data[check_signature : check_signature + len(RETURN_ZERO)] = RETURN_ZERO

def patch_prevent_warranty_fuse(data):
    set_warranty_void_bit_reason = find_xref(data, b"%s : invalid value\n\0") + 0x24
    set_warrant_bit = find_xref(data, b"[EFUSE] Set warranty bit(0x%llx)\n\0") - 0x4C
    print(f"set_warranty_void_bit_reason: {set_warranty_void_bit_reason:#x}")
    print(f"set_warrant_bit: {set_warrant_bit:#x}")
    data[set_warranty_void_bit_reason : set_warranty_void_bit_reason + len(RETURN_ZERO)] = RETURN_ZERO
    data[set_warrant_bit : set_warrant_bit + len(RETURN_ZERO)] = RETURN_ZERO

def get_efuse_data():
    import hmac
    from sign import load_private_key, pubkey_blob
    with open("keys/hmac.bin", "rb") as f:
        hmac_key = f.read()
    if len(hmac_key) != 32:
        raise ValueError("hmac.bin should be 32 bytes")
    key = load_private_key("keys/4/st1.pem")
    public_blob = pubkey_blob(key.public_key(), 4)
    return bytes(a ^ b for a, b in zip(hmac.digest(hmac_key, public_blob[:136], "sha512")[:32], hmac_key))

def patch_sbl_check_upload(data):
    sbl_check_upload = find_xref(data, b"sbl_check_upload\0") - 0x24
    print(f"sbl_check_upload: {sbl_check_upload:#x}")
    data[sbl_check_upload : sbl_check_upload + len(RETURN_ONE)] = RETURN_ONE

def patch_fuse_boot_key(data):
    check_signature = find_xref(data, b"%s: There is no signature\n\0") - 0xDC

    rom_key_start_xref = find_xref(data, b"[OTP] ROM_SECURE_BOOT_KEY program start\n\0")
    cm_otp_write_rom_sec_boot_key = rom_key_start_xref - 0x58
    rom_key_selector = rom_key_start_xref + 0x88

    use_key_start_xref = find_xref(data, b"[OTP] USE_ROM_SEC_BOOT_KEY program start\n\0")
    cm_otp_write_use_rom_sec_boot_key = use_key_start_xref - 0x4
    use_key_selector = use_key_start_xref + 0x18

    print(f"check_signature: {check_signature:#x}")
    print(f"cm_otp_write_rom_sec_boot_key: {cm_otp_write_rom_sec_boot_key:#x}")
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

    write_u32(data, rom_key_selector, 0xD28002C1) # write key2
    write_u32(data, use_key_selector, 0xD28002E1) # write use key2

    payload.extend(struct.unpack("<8I", get_efuse_data()))
    write_words(data, check_signature, payload)

should_fuse_key = False # Burns BOOT_KEY once after UFS boot into ODIN MODE.

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())

    patch_check_signature(data)
    patch_prevent_warranty_fuse(data)
    if should_fuse_key:
        patch_fuse_boot_key(data)
    #patch_sbl_check_upload(data)

    with open(sys.argv[1], "wb") as f:
        f.write(data)
