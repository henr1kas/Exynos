#!/usr/bin/env python3

import ctypes
from datetime import datetime, timezone

def SBL1RSA(image_size):
    class _SBL1RSA(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [
            # Header
            ("num_of_sector",      ctypes.c_uint32),
            ("checksum",           ctypes.c_uint32),
            ("en_addr",            ctypes.c_uint32),
            ("en_size",            ctypes.c_uint32),
            # BL1
            ("image",              ctypes.c_uint8 * (image_size - 1048)),
            # BL1 info
            ("soc_info",           ctypes.c_uint8 * 8),
            # CodeSigner V4
            ("codesigner_version", ctypes.c_uint32),
            ("ap_info",            ctypes.c_char * 4),
            ("time",               ctypes.c_uint64),
            ("rb_count",           ctypes.c_uint32),
            ("signing_type",       ctypes.c_uint32),
            ("debug_certificate",  ctypes.c_uint8 * 0x1C),
            ("key_index",          ctypes.c_uint32),
            ("st2_publickey",      ctypes.c_uint8 * 0x10C),
            ("func_ptr",           ctypes.c_uint8 * 0x80),
            ("major_id",           ctypes.c_uint16),
            ("minor_id",           ctypes.c_uint16),
            ("reserved",           ctypes.c_uint8 * 0x8),
            ("st1_publickey",      ctypes.c_uint8 * 0x10C),
            ("hmac",               ctypes.c_uint8 * 0x20),
            ("signature_size",     ctypes.c_uint32),
            ("signature",          ctypes.c_uint8 * 0x100),
        ]
    return _SBL1RSA

def SBL1ECDSA(image_size):
    class _SBL1ECDSA(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [
            # Header
            ("num_of_sector",      ctypes.c_uint32),
            ("checksum",           ctypes.c_uint32),
            ("en_addr",            ctypes.c_uint32),
            ("en_size",            ctypes.c_uint32),
            # BL1
            ("image",              ctypes.c_uint8 * (image_size - 2376)),
            # BL1 info
            ("soc_info",           ctypes.c_uint8 * 8),
            # CodeSigner V5
            ("codesigner_version", ctypes.c_uint32),
            ("ap_info",            ctypes.c_char * 4),
            ("time",               ctypes.c_uint64),
            ("rb_count",           ctypes.c_uint32),
            ("signing_type",       ctypes.c_uint32),
            ("description",        ctypes.c_char * 36),
            ("key_index",          ctypes.c_uint32),
            ("debug_certificate",  ctypes.c_uint8 * 0x1C),
            ("st2_key_tee",        ctypes.c_uint8 * 524),
            ("st2_key_ree",        ctypes.c_uint8 * 524),
            ("func_ptr",           ctypes.c_uint8 * 128),
            ("major_id",           ctypes.c_uint16),
            ("minor_id",           ctypes.c_uint16),
            ("reserved",           ctypes.c_uint8 * 0x8),
            ("st1_publickey",      ctypes.c_uint8 * 524),
            ("hmac",               ctypes.c_uint8 * 0x20),
            ("signature_size",     ctypes.c_uint32),
            ("signature",          ctypes.c_uint8 * 136),
            ("padding",            ctypes.c_uint8 * 376),
        ]
    return _SBL1ECDSA

def load_sbl1_json_into_struct(sbl1, j):
    if all(k in j for k in ("evt", "soc", "timestamp")):
        if "." in j["evt"]:
            major, minor = j["evt"].split(".")
            evt_hex = f"{int(major):02x}{int(minor):02x}"
        else:
            evt_hex = f"{int(j["evt"]):x}"
        sbl1.soc_info[:] = int(f"{j["soc"]:04d}{evt_hex}", 16).to_bytes(4, byteorder="little") + int(datetime.fromtimestamp(j["timestamp"], tz=timezone.utc).strftime("%y%m%d%H"), 16).to_bytes(4, "little")

    for name, ctype in sbl1._fields_:
        if name in ("image", "soc_info") or name not in j:
            continue
        val = j[name]
        if name == "ap_info":
            sbl1.ap_info = val.encode()
            continue
        cur = getattr(sbl1, name)
        if isinstance(cur, ctypes.Array):
            cur[:] = bytes.fromhex(val)
        else:
            setattr(sbl1, name, val)

def sbl1_to_dict(s):
    out = {}
    for name, ctype in s._fields_:
        if name == "image":
            continue
        val = getattr(s, name)
        if name == "soc_info":
            v = int.from_bytes(bytes(val[0:4]), "little")
            t = int.from_bytes(bytes(val[4:8]), "little")
            hex_str = f"{v:x}"
            evt_str = hex_str[4:]
            if len(evt_str) == 4:
                evt_str = f"{int(evt_str[:2], 16)}.{int(evt_str[2:], 16)}"
            out["evt"] = evt_str
            out["soc"] = int(hex_str[:4])
            h = f"{t:08x}"
            dt = datetime(year=2000 + int(h[0:2]), month=int(h[2:4]), day=int(h[4:6]), hour=int(h[6:8]), tzinfo=timezone.utc)
            out["timestamp"] = int(dt.timestamp())
        elif isinstance(val, ctypes.Array):
            out[name] = bytes(val).hex()
        elif isinstance(val, bytes):
            out[name] = val.decode() if name == "ap_info" else val.hex()
        else:
            out[name] = val
    return out
