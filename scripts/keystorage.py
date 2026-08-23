#!/usr/bin/env python3

import binascii
import struct
from dataclasses import dataclass, field
from pathlib import Path

KEYSTORAGE_MAGIC = 0x49534C53
MAX_PUBKEY_LEN = 1056
MAX_WHITE_LIST_TARGET_NUM = 12
SB_KST_V30_MAX_KEY_NAME_LEN = 8
SB_KST_V40_MAX_KEY_NAME_LEN = 16

@dataclass
class st_testkey_whitelist:
    target_name: str
    reserved1: int = 0
    reserved2: int = 0

@dataclass
class st_key_meta:
    key_name: str
    key_index: int
    sign_type: int

@dataclass
class st_pubkey:
    pubkey: bytearray

@dataclass
class st_header:
    magic: int
    version: int
    header_len: int
    key_count: int
    date: int
    user: str
    body_len: int
    whitelist_target_num: int = 0
    reserved1: int = 0
    reserved2: int = 0
    reserved3: int = 0
    testkey_whitelist: list = field(default_factory=list)
    key_meta: list = field(default_factory=list)

def _cstr(value):
    return value.split(b"\0", 1)[0].decode("ascii", "replace")

def _fixed(value, size, old=b""):
    if len(old) == size and _cstr(old) == value:
        return bytes(old)
    value = value.encode("ascii")
    if len(value) > size:
        raise ValueError("string is too long")
    return value.ljust(size, b"\0")

def _crc_len(pubkey, key_index):
    for size in range(1, len(pubkey) + 1):
        if binascii.crc32(pubkey[:size]) & 0xFFFFFFFF == key_index:
            return size

def _layout(version):
    return (2592, 24) if version >= 0x50 else (MAX_PUBKEY_LEN, MAX_WHITE_LIST_TARGET_NUM)

class keystorage:
    def __init__(self, header, pubkey, data, crc_len):
        self.header, self.pubkey = header, pubkey
        self._data, self.crc_len = data, crc_len
        self.pubkey_len, self.whitelist_len = _layout(header.version)

    @classmethod
    def load(cls, filename):
        data = bytearray(Path(filename).read_bytes())
        if len(data) < 48:
            raise ValueError("truncated keystorage")
        magic, version, header_len, key_count, date, user, body_len, value, r1, r2 = struct.unpack_from(
            "<IIIIQ8sIIII", data)
        if magic != KEYSTORAGE_MAGIC or version not in (0x20, 0x30, 0x40, 0x50):
            raise ValueError("invalid keystorage")

        MAX_PUBKEY_LEN, MAX_WHITE_LIST_TARGET_NUM = _layout(version)
        offset, testkey_whitelist = 48, []
        if version >= 0x30:
            whitelist_target_num, reserved1, reserved2, reserved3 = value, r1, r2, 0
            if whitelist_target_num > MAX_WHITE_LIST_TARGET_NUM:
                raise ValueError("invalid whitelist_target_num")
            for slot in range(MAX_WHITE_LIST_TARGET_NUM):
                name, a, b = struct.unpack_from("<8sII", data, offset + slot * 16)
                testkey_whitelist.append(st_testkey_whitelist(_cstr(name), a, b))
            offset += MAX_WHITE_LIST_TARGET_NUM * 16
        else:
            whitelist_target_num, reserved1, reserved2, reserved3 = 0, value, r1, r2

        MAX_KEY_NAME_LEN = SB_KST_V40_MAX_KEY_NAME_LEN if version >= 0x40 else SB_KST_V30_MAX_KEY_NAME_LEN
        KEY_META_LEN = MAX_KEY_NAME_LEN + 8
        if header_len < offset or (header_len - offset) % KEY_META_LEN:
            raise ValueError("invalid header_len")
        MAX_KEY_COUNT = (header_len - offset) // KEY_META_LEN
        if (key_count > MAX_KEY_COUNT or body_len != key_count * MAX_PUBKEY_LEN or
                len(data) < header_len + MAX_KEY_COUNT * MAX_PUBKEY_LEN):
            raise ValueError("invalid key_count/body_len")

        key_meta, pubkey, crc_len = [], [], []
        for key_slot in range(MAX_KEY_COUNT):
            name, index, sign_type = struct.unpack_from("<%dsII" % MAX_KEY_NAME_LEN, data,
                                                        offset + key_slot * KEY_META_LEN)
            key_meta.append(st_key_meta(_cstr(name), index, sign_type))
            start = header_len + key_slot * MAX_PUBKEY_LEN
            pubkey.append(st_pubkey(bytearray(data[start:start + MAX_PUBKEY_LEN])))
            crc_len.append(_crc_len(pubkey[-1].pubkey, index) if key_slot < key_count else None)
        header = st_header(magic, version, header_len, key_count, date, _cstr(user), body_len,
                           whitelist_target_num, reserved1, reserved2, reserved3,
                           testkey_whitelist, key_meta)
        return cls(header, pubkey, data, crc_len)

    def update_crc(self, key_slot, size=None):
        size = size or self.crc_len[key_slot]
        if not size or not 0 < size <= self.pubkey_len:
            raise ValueError("CRC input length is required")
        self.header.key_meta[key_slot].key_index = binascii.crc32(self.pubkey[key_slot].pubkey[:size]) & 0xFFFFFFFF
        self.crc_len[key_slot] = size

    def set_pubkey(self, key_slot, value, crc_len=None):
        value = bytes(value)
        if len(value) > self.pubkey_len:
            raise ValueError("public key is too large")
        self.pubkey[key_slot].pubkey = bytearray(value.ljust(self.pubkey_len, b"\0"))
        self.update_crc(key_slot, crc_len or len(value))

    def save(self, filename):
        h, data = self.header, bytearray(self._data)
        MAX_PUBKEY_LEN, MAX_WHITE_LIST_TARGET_NUM = _layout(h.version)
        if (MAX_PUBKEY_LEN, MAX_WHITE_LIST_TARGET_NUM) != (self.pubkey_len, self.whitelist_len):
            raise ValueError("version/layout cannot be changed")
        if not 0 <= h.key_count <= len(h.key_meta):
            raise ValueError("invalid key_count")
        h.body_len = h.key_count * MAX_PUBKEY_LEN
        MAX_KEY_NAME_LEN = SB_KST_V40_MAX_KEY_NAME_LEN if h.version >= 0x40 else SB_KST_V30_MAX_KEY_NAME_LEN
        offset = 48
        if h.version >= 0x30:
            if len(h.testkey_whitelist) != MAX_WHITE_LIST_TARGET_NUM:
                raise ValueError("invalid testkey_whitelist")
            h.whitelist_target_num = sum(x.target_name not in ("", "null") for x in h.testkey_whitelist)
            value, r1, r2 = h.whitelist_target_num, h.reserved1, h.reserved2
        else:
            value, r1, r2 = h.reserved1, h.reserved2, h.reserved3
        struct.pack_into("<IIIIQ8sIIII", data, 0, h.magic, h.version, h.header_len, h.key_count,
                         h.date, _fixed(h.user, 8, data[24:32]), h.body_len, value, r1, r2)
        if h.version >= 0x30:
            for slot, entry in enumerate(h.testkey_whitelist):
                start = offset + slot * 16
                struct.pack_into("<8sII", data, start, _fixed(entry.target_name, 8, data[start:start + 8]),
                                 entry.reserved1, entry.reserved2)
            offset += MAX_WHITE_LIST_TARGET_NUM * 16
        if len(h.key_meta) != len(self.pubkey) or h.header_len != offset + len(h.key_meta) * (MAX_KEY_NAME_LEN + 8):
            raise ValueError("invalid key_meta/pubkey layout")
        for slot, entry in enumerate(h.key_meta):
            meta = offset + slot * (MAX_KEY_NAME_LEN + 8)
            struct.pack_into("<%dsII" % MAX_KEY_NAME_LEN, data, meta,
                             _fixed(entry.key_name, MAX_KEY_NAME_LEN, data[meta:meta + MAX_KEY_NAME_LEN]),
                             entry.key_index, entry.sign_type)
            start = h.header_len + slot * MAX_PUBKEY_LEN
            value = bytes(self.pubkey[slot].pubkey)
            if len(value) > MAX_PUBKEY_LEN:
                raise ValueError("public key is too large")
            self.pubkey[slot].pubkey = bytearray(value.ljust(MAX_PUBKEY_LEN, b"\0"))
            data[start:start + MAX_PUBKEY_LEN] = self.pubkey[slot].pubkey
        Path(filename).write_bytes(data)
        self._data = data

def load(filename):
    return keystorage.load(filename)
