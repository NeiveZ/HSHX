"""Tests for modules/generator.py — every digest is cross-checked against
Python's own hashlib/hmac to make sure HSHX's output matches the standard."""
import hashlib
import hmac as hmac_lib

from modules.generator import HashGenerator
from utils.md4 import ntlm_hash


def _generate(text: str, h_type: str, key: str = "", rounds: int = 12):
    m = HashGenerator()
    m.set_option("TEXT", text)
    m.set_option("TYPE", h_type)
    if key:
        m.set_option("KEY", key)
    m.set_option("ROUNDS", str(rounds))
    results = m.run()
    return results[0]["hash"] if results else None


def test_md5_matches_hashlib():
    assert _generate("password123", "md5") == hashlib.md5(b"password123").hexdigest()


def test_sha256_matches_hashlib():
    assert _generate("password123", "sha256") == hashlib.sha256(b"password123").hexdigest()


def test_sha512_matches_hashlib():
    assert _generate("password123", "sha512") == hashlib.sha512(b"password123").hexdigest()


def test_sha3_256_matches_hashlib():
    assert _generate("password123", "sha3_256") == hashlib.sha3_256(b"password123").hexdigest()


def test_ntlm_matches_md4_fallback():
    assert _generate("password123", "ntlm") == ntlm_hash("password123")


def test_hmac_sha256_matches_hmac_lib():
    expected = hmac_lib.new(b"secret_key", b"api_payload", hashlib.sha256).hexdigest()
    assert _generate("api_payload", "hmac-sha256", key="secret_key") == expected


def test_hmac_without_key_returns_no_result(capsys):
    m = HashGenerator()
    m.set_option("TEXT", "api_payload")
    m.set_option("TYPE", "hmac-sha256")
    assert m.run() == []


def test_type_all_generates_every_supported_type():
    m = HashGenerator()
    m.set_option("TEXT", "password123")
    m.set_option("TYPE", "all")
    results = m.run()
    returned_types = {r["type"] for r in results}
    # hmac-sha256 needs a KEY and bcrypt needs the optional package, so
    # both legitimately produce nothing here — every other type must.
    expected_minimum = set(HashGenerator.SUPPORTED) - {"hmac-sha256", "bcrypt"}
    assert expected_minimum.issubset(returned_types)
