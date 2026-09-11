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

def patch_fuse_boot_key(data):
    odin_useless_func = find_xref(data, b"ODIN MODE\0") - 0x5C
    print("WARNING: patching for burning BOOT_KEY!")

    payload = [
        0xA9BF57F4,  # stp x20, x21, [sp, #-0x10]!
        0x10000255,  # adr x21, key (PC + 0x48)
        0x52800214,  # mov w20, #0x10
        0x180001E0,  # loop: ldr w0, smc_id
        0x28C10EA1,  # ldp w1, w3, [x21], #8
        0x2A1403E2,  # mov w2, w20
        0xD5033F9F,  # dsb sy
        0xD4000003,  # smc #0
        0x11000694,  # add w20, w20, #1
        0x3617FF54,  # tbz w20, #2, loop
        0x18000100,  # ldr w0, smc_id
        0xAA1F03E1,  # mov x1, xzr
        0x52800022,  # mov w2, #1
        0xAA1F03E3,  # mov x3, xzr
        0xD5033F9F,  # dsb sy
        0xD4000003,  # smc #0
        0xA8C157F4,  # ldp x20, x21, [sp], #0x10
        0xD65F03C0,  # ret
        0xC2001014,  # smc_id literal
    ]
    payload.extend(struct.unpack("<8I", get_efuse_data()))
    write_words(data, odin_useless_func, payload)

should_fuse_key = True # Burns BOOT_KEY once after UFS boot into ODIN MODE.

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())

    if should_fuse_key:
        patch_fuse_boot_key(data)

    with open(sys.argv[1], "wb") as f:
        f.write(data)
