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

def get_efuse_data():
    import hmac
    from sign import load_private_key, pubkey_blob

    with open("keys/hmac.bin", "rb") as f:
        hmac_key = f.read()
    if len(hmac_key) != 32:
        raise ValueError("hmac.bin should be 32 bytes")
    key = load_private_key("keys/4/st1.pem", 4)
    public_blob = pubkey_blob(key.public_key(), 4)
    return bytes(a ^ b for a, b in zip(hmac.digest(hmac_key, public_blob[:136], "sha512")[:32], hmac_key))

def patch_fuse_boot_key(data):
    check_signature = 0x91D14 # use this as dummy func
    payload = [
        0xA9BF7BFD,
        0x100000E0,
        0x52800401,
        jump_to_func_from(check_signature + 12, 0x23DB0),
        jump_to_func_from(check_signature + 16, 0x24200),
        0xD2800000,
        0xA8C17BFD,
        0xD65F03C0,
    ]
    
    write_u32(data, 0x23EF4, 0x528002C1) # write key2
    write_u32(data, 0x24228, 0x528002E1) # write use key2
    
    payload.extend(struct.unpack("<8I", get_efuse_data()))
    write_words(data, check_signature, payload)
    payload_bytes = struct.pack("<{}I".format(len(payload)), *payload)
    print(payload_bytes)

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())

    patch_fuse_boot_key(data)

    with open(sys.argv[1], "wb") as f:
        f.write(data)
