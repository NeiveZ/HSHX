"""Tests for utils/md4.py against the official RFC 1320 test suite.

These are the same seven vectors published in RFC 1320, Appendix A.5.
If this file ever fails, the pure-Python MD4 fallback (and therefore
every NTLM hash/crack/identify result) cannot be trusted.
"""
import pytest

from utils.md4 import md4, ntlm_hash

RFC1320_VECTORS = [
    (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
    (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    (b"message digest", "d9130a8164549fe818874806e1c7014b"),
    (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "043f8582f241db351ce627e153e7f0e4"),
    (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
     "e33b4ddc9c38f2199c3e7b164fcc0536"),
]


@pytest.mark.parametrize("data,expected_hex", RFC1320_VECTORS)
def test_md4_matches_rfc1320_test_suite(data, expected_hex):
    assert md4(data).hex() == expected_hex


def test_ntlm_hash_of_empty_password_is_the_well_known_value():
    # This exact value is the famous "blank password" NT hash that shows
    # up constantly in real dumps (and in HSHX's own README example).
    assert ntlm_hash("") == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_ntlm_hash_uses_utf16_le_encoding():
    import hashlib
    expected = hashlib.new("md4" if "md4" in hashlib.algorithms_available else "md5",
                            "test".encode("utf-16-le"))
    # We can't always rely on the system having md4, so just check our
    # own implementation is internally consistent with utf-16-le input.
    assert ntlm_hash("test") == md4("test".encode("utf-16-le")).hex()


def test_ntlm_hash_is_deterministic():
    assert ntlm_hash("Sup3rSecret!") == ntlm_hash("Sup3rSecret!")


def test_different_passwords_give_different_hashes():
    assert ntlm_hash("password1") != ntlm_hash("password2")
