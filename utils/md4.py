#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
utils/md4.py — Pure-Python MD4 (RFC 1320), used as an NTLM fallback.

WHY THIS EXISTS: NTLM = MD4(password.encode("utf-16-le")). The original
code called hashlib.new("md4", ...) directly. That works on systems where
OpenSSL still exposes MD4 in an enabled provider — but on OpenSSL 3.x
(the default on Ubuntu 22.04+, Debian 12+, and recent Kali releases),
MD4 was moved into the "legacy" provider, which is disabled unless the
system OpenSSL config explicitly loads it. On those systems,
hashlib.new("md4", ...) raises:

    ValueError: unsupported hash type md4

...which means every NTLM crack/generate/identify call silently breaks.
ntlm_hash() below tries the fast C implementation first and transparently
falls back to this pure-Python one when it's unavailable, so NTLM support
keeps working everywhere without adding a third-party dependency.

The implementation is verified against all seven official RFC 1320 test
vectors in tests/test_md4.py.
"""
import hashlib
import struct


def _lrot(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(data: bytes) -> bytes:
    """Return the raw 16-byte MD4 digest of `data` (RFC 1320)."""
    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def F(x, y, z): return (x & y) | (~x & z & 0xFFFFFFFF)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", bytes(msg[off:off + 64])))
        A, B, C, D = a, b, c, d

        for i, s in zip(range(16), [3, 7, 11, 19] * 4):
            t = (A + F(B, C, D) + X[i]) & 0xFFFFFFFF
            A, D, C, B = D, C, B, _lrot(t, s)

        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for k, s in zip(order2, [3, 5, 9, 13] * 4):
            t = (A + G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF
            A, D, C, B = D, C, B, _lrot(t, s)

        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for k, s in zip(order3, [3, 9, 11, 15] * 4):
            t = (A + H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF
            A, D, C, B = D, C, B, _lrot(t, s)

        a = (a + A) & 0xFFFFFFFF
        b = (b + B) & 0xFFFFFFFF
        c = (c + C) & 0xFFFFFFFF
        d = (d + D) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def ntlm_hash(plaintext: str) -> str:
    """NT hash (NTLM) of a password: MD4 of its UTF-16LE encoding.

    Tries the system hashlib first (fast, C-implemented) and transparently
    falls back to the pure-Python implementation above if the system
    OpenSSL doesn't expose MD4.
    """
    data = plaintext.encode("utf-16-le")
    try:
        return hashlib.new("md4", data).hexdigest()
    except (ValueError, TypeError):
        return md4(data).hex()
