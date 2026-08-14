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
