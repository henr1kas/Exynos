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

def patch_fuse_boot_key(data): # currently hardcoded for G935FXXU8EZCD
    some_fuse_thing = 0x15D9C
    smc_call = 0x21A4
    print("WARNING: patching for burning BOOT_KEY!")

    payload = [
        0xA9BE5BF5,  # stp x21, x22, [sp, #-0x20]!
        0xF9000BFE,  # str x30, [sp, #0x10]
        0x10000235,  # adr x21, 8F015DE8
        0x52800216,  # mov w22, #0x10
        0x180001C0,  # ldr w0, smc_id
        0x28C10EA1,  # ldp w1, w3, [x21], #8
        0x2A1603E2,  # mov w2, w22
        jump_to_func_from(some_fuse_thing + 0x1C, smc_call),
        0x110006D6,  # add w22, w22, #1
        0x3617FF76,  # tbz w22, #2, loop
        0x18000100,  # ldr w0, smc_id
        0xAA1F03E1,  # mov x1, xzr
        0x52800022,  # mov w2, #1
        0xAA1F03E3,  # mov x3, xzr
        jump_to_func_from(some_fuse_thing + 0x38, smc_call),
        0xF9400BFE,  # ldr x30, [sp, #0x10]
        0xA8C25BF5,  # ldp x21, x22, [sp], #0x20
        0xD65F03C0,  # ret
        0xC2001014,  # smc_id literal
    ]
    payload.extend(struct.unpack("<8I", get_efuse_data()))
    write_words(data, some_fuse_thing, payload)
    write_u32(data, 0x116DC, 0x940011B0) # SECURE DOWNLOAD print string now goes to 0x15D9C

should_fuse_key = True # Burns BOOT_KEY once after UFS boot into ODIN MODE.

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())

    if should_fuse_key:
        patch_fuse_boot_key(data)

    with open(sys.argv[1], "wb") as f:
        f.write(data)
