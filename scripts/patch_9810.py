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

def is_bl(data, offset):
    return word(data, offset) & 0xFC000000 == 0x94000000

def resolve_bl(data, offset):
    if not is_bl(data, offset):
        raise ValueError(f"expected BL at {offset:#x}")
    return offset + signed(word(data, offset) & 0x03FFFFFF, 26) * 4

def called_targets(data):
    return {
        resolve_bl(data, offset)
        for offset in range(0, len(data) - 3, 4)
        if is_bl(data, offset)
    }

def unique_offset(offsets, description):
    if len(offsets) != 1:
        raise ValueError(f"expected one {description}, found {len(offsets)}")
    return offsets[0]

def is_prologue(data, offset):
    instruction = word(data, offset) & 0xFFC003FF
    return instruction in (0xA98003FD, 0xD10003FF)

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
    nantirbk_xref = find_xref(data, b"nantirbk0 mismatch!(%d vs %d), updating...\n\0")
    etc_market = unique_offset([
        offset + 4
        for offset in range(max(0, nantirbk_xref - 0x200), nantirbk_xref - 28, 4)
        if word(data, offset) == 0x528000E0  # MOV W0, #7
        and is_bl(data, offset + 4)
        and word(data, offset + 12) == 0xB9004320  # STR W0, [X25,#0x40]
        and word(data, offset + 16) == 0x52800100  # MOV W0, #8
        and is_bl(data, offset + 20)
        and word(data, offset + 28) == 0xB9004740  # STR W0, [X26,#0x44]
    ], "etc_market call near nantirbk0")
    commercial_bit = find_xref(data, b"commercial_bit mismatch!(%d vs %d), updating...\n\0") - 0x6C
    if not all(is_bl(data, commercial_bit + distance) for distance in (0, 16, 32)):
        raise ValueError("commercial/test/warranty efuse calls do not match")
    if [word(data, commercial_bit + distance) for distance in (4, 24, 36)] != [
        0xB9000720, 0xB9000B40, 0xB9000F20
    ]:
        raise ValueError("commercial/test/warranty efuse stores do not match")
    print(f"etc_market: {etc_market:#x}")
    print(f"commercial_bit: {commercial_bit:#x}")
    write_u32(data, etc_market, 0x52800000)          # etc_market 0
    write_u32(data, etc_market + 16, 0x52800020)     # etc_development 1
    write_u32(data, commercial_bit, 0x52800000)      # commercial_bit 0
    write_u32(data, commercial_bit + 16, 0x52800020) # test_bit 1
    write_u32(data, commercial_bit + 32, 0x52800000) # warranty_bit 0

def patch_set_warranty_void_bit_reason(data): # TODO: may not be needed if DEV DEVICE?
    reason_xref = find_xref(data, b"%s : no reason\n\0")
    set_warranty_void_bit_reason = unique_offset([
        target
        for target in called_targets(data)
        if reason_xref < target < reason_xref + 0x80
        and (word(data, target) == 0x529FFFE1 or is_prologue(data, target))
        and any(word(data, target + distance) == 0x529FFFE1 for distance in range(0, 16, 4))
        and any(word(data, target + distance) == 0x6B01001F for distance in range(4, 24, 4))
    ], "set_warranty_void_bit_reason after its diagnostic")
    print(f"set_warranty_void_bit_reason: {set_warranty_void_bit_reason:#x}")
    data[set_warranty_void_bit_reason : set_warranty_void_bit_reason + len(RETURN_ZERO)] = RETURN_ZERO

def patch_set_warranty_bit(data): # TODO: may not be needed if DEV DEVICE?
    set_warranty_bit = find_xref(data, b"[EFUSE] Set warranty bit(%d)\n\0") - 0x58
    print(f"set_warranty_bit: {set_warranty_bit:#x}")
    data[set_warranty_bit : set_warranty_bit + len(RETURN_ZERO)] = RETURN_ZERO

def patch_read_rmm_rpmb(data):
    read_rmm_rpmb = find_xref(data, b"[RMM] read_data fail...\n\0") - 0x50
    print(f"read_rmm_rpmb: {read_rmm_rpmb:#x}")
    data[read_rmm_rpmb : read_rmm_rpmb + len(RETURN_ZERO)] = RETURN_ZERO

def patch_read_kg_rpmb(data):
    kg_xref = find_xref(data, b"[KG] read_data fail...\n\0")
    read_kg_rpmb = max(
        (target for target in called_targets(data)
         if kg_xref - 0x100 <= target < kg_xref and is_prologue(data, target)),
        default=None,
    )
    if read_kg_rpmb is None:
        raise ValueError("read_kg_rpmb entry not found near its diagnostic")
    print(f"read_kg_rpmb: {read_kg_rpmb:#x}")
    data[read_kg_rpmb : read_kg_rpmb + len(RETURN_ZERO)] = RETURN_ZERO

def patch_have_this_mode(data):
    mode_xref = find_xref(data, b"ENG MODE : ENG ALLOWED(%s)\n\0")
    have_this_mode = unique_offset([
        target
        for offset in range(mode_xref - 0x50, mode_xref - 4, 4)
        if is_bl(data, offset)
        and word(data, offset + 4) & 0xFF00001F == 0x34000000  # CBZ W0
        for target in [resolve_bl(data, offset)]
        if [word(data, target + distance) for distance in (12, 16, 20)] == [
            0x6A01001F, 0x1A9F07E0, 0xD65F03C0  # TST, CSET, RET
        ]
    ], "have_this_mode call before ENG MODE diagnostic")
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
    if b"SM-N770" in data:
        print("N770 image: skipping RMM patch")
    else:
        patch_read_rmm_rpmb(data)
    patch_read_kg_rpmb(data)
    patch_have_this_mode(data)

    if should_fuse_key:
        patch_fuse_boot_key(data)

    with open(sys.argv[1], "wb") as f:
        f.write(data)
