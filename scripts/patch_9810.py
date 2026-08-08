#!/usr/bin/env python3

import re
import sys
import struct

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

def patch_secure_check(data, check_signature):
    ret0 = [
        0xD2800000,
        0xD65F03C0,
    ]
    write_words(data, check_signature, ret0)

def patch_efuse_init(data, etc_market, commercial_bit):
    write_u32(data, etc_market, 0x52800000)          # etc_market 0
    write_u32(data, etc_market + 16, 0x52800020)     # etc_development 1
    write_u32(data, commercial_bit, 0x52800000)      # commercial_bit 0
    write_u32(data, commercial_bit + 16, 0x52800020) # test_bit 1
    write_u32(data, commercial_bit + 32, 0x52800000) # warranty_bit 0

def patch_rmm(data, rmm_check):
    ret0 = [
        0xD2800000,
        0xD65F03C0,
    ]
    write_words(data, rmm_check, ret0)

def patch_kg(data, kg_check):
    ret0 = [
        0xD2800000,
        0xD65F03C0,
    ]
    write_words(data, kg_check, ret0)

def patch_engmode(data, have_this_mode):
    ret1 = [
        0xD2800020,
        0xD65F03C0,
    ]
    write_words(data, have_this_mode, ret1)

def get_efuse_data():
    import hmac
    from sign import load_private_key, pubkey_blob

    with open("keys/hmac.bin", "rb") as f:
        hmac_key = f.read()
    if len(hmac_key) != 32:
        raise ValueError("hmac.bin should be 32 bytes")
    key = load_private_key("keys/st1.pem")
    public_blob = pubkey_blob(key.public_key())
    return bytes(a ^ b for a, b in zip(hmac.digest(hmac_key, public_blob, "sha256"), hmac_key))

def patch_fuse_boot_key(data, kg_check, cm_otp_write_rom_sec_boot_key, cm_otp_write_use_rom_sec_boot_key):
    payload = [
        0xA9BF7BFD,
        0x100000E0,
        0x52800401,
        jump_to_func_from(kg_check + 12, cm_otp_write_rom_sec_boot_key),
        jump_to_func_from(kg_check + 16, cm_otp_write_use_rom_sec_boot_key),
        0xD2800000,
        0xA8C17BFD,
        0xD65F03C0,
    ]
    payload.extend(struct.unpack("<8I", get_efuse_data()))
    write_words(data, kg_check, payload)

should_fuse_key = False # if True will burn BOOT_KEY once you UFS boot to ODIN MODE

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())

    # TODO: investigate %s: usable! (%d:0x%x), warranty reason : (0x%04x) and (SYSTEM STATUS)
    # not have_this_mode, idk what this is but on old BL of combination S9
    #have_this_mode = resolve_bl(data, find_pattern(data, "? ? ? 94 ? ? ? 71 ? ? ? 54 ? ? ? 39"))
    have_this_mode = resolve_bl(data, find_pattern(data, "? ? ? 94 ? ? ? 35 ? ? ? B9 ? ? ? F0"))
    rmm_check = resolve_bl(data, find_pattern(data, "? ? ? 94 ? ? ? 37 ? ? ? 52 ? ? ? 94 ? ? ? 34"))    
    kg_check = resolve_bl(data, find_pattern(data, "94 ? 40 F9 E0 03 14 AA", -12))
    check_signature = resolve_bl(data, find_pattern(data, "11 ? ? ? 97 ? ? F8 37", 1))
    cm_otp_write_rom_sec_boot_key = find_pattern(data, "80 02 82 D2 21 00 80 D2 00 40 B8 F2 E2 03 13 AA", -344)
    cm_otp_write_use_rom_sec_boot_key = find_pattern(data, "80 02 82 D2 41 00 80 D2 00 40 B8 F2 02 00 80 D2", -28)
    etc_market = find_pattern(data, "E0 00 80 52 ? ? ? ? ? ? ? ? 20 43 00 B9", 4)
    commercial_bit = find_pattern(data, "20 00 80 52 ? ? ? ? ? ? ? ? 20 07 00 B9", 8)

    if check_signature is None:
        print("WARNING: check_signature function not found!")
    else:
        print(f"check_signature: {hex(check_signature)}")
        patch_secure_check(data, check_signature)

    if etc_market is None or commercial_bit is None:
        if etc_market is None:
            print("WARNING: etc_market offset not found!")
        if commercial_bit is None:
            print("WARNING: commercial_bit offset not found!")
    else:
        print(f"etc_market: {hex(etc_market)}")
        print(f"commercial_bit: {hex(commercial_bit)}")
        patch_efuse_init(data, etc_market, commercial_bit)

    if rmm_check is None:
        print("WARNING: rmm_check function not found! (can ignore if N10lite)")
    else:
        print(f"rmm_check: {hex(rmm_check)}")
        patch_rmm(data, rmm_check)

    if kg_check is None:
        print("WARNING: kg_check function not found!")
    else:
        print(f"kg_check: {hex(kg_check)}")
        patch_kg(data, kg_check)

    if have_this_mode is None:
        print("WARNING: have_this_mode function not found!")
    else:
        print(f"have_this_mode: {hex(have_this_mode)}")
        patch_engmode(data, have_this_mode)

    if should_fuse_key:
        if cm_otp_write_rom_sec_boot_key is not None and cm_otp_write_use_rom_sec_boot_key is not None and kg_check is not None:
            print(f"cm_otp_write_rom_sec_boot_key: {hex(cm_otp_write_rom_sec_boot_key)}")
            print(f"cm_otp_write_use_rom_sec_boot_key: {hex(cm_otp_write_use_rom_sec_boot_key)}")
            print("WARNING: patching for burning BOOT_KEY!")
            patch_fuse_boot_key(data, kg_check, cm_otp_write_rom_sec_boot_key, cm_otp_write_use_rom_sec_boot_key)
        else:
            if cm_otp_write_rom_sec_boot_key is None:
                print("WARNING: cm_otp_write_rom_sec_boot_key function not found!")
            if cm_otp_write_use_rom_sec_boot_key is None:
                print("WARNING: cm_otp_write_use_rom_sec_boot_key function not found!")

    with open(sys.argv[1], "wb") as f:
        f.write(data)
