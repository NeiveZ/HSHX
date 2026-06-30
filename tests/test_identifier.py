"""Tests for modules/identifier.py."""
import hashlib

from modules.identifier import HashIdentifier


def _identify_types(h: str) -> list:
    m = HashIdentifier()
    matches = m._identify(h, verbose=False)
    return [name for name, _notes in matches]


def test_md5_of_known_string_is_identified():
    h = hashlib.md5(b"password").hexdigest()
    assert "MD5" in _identify_types(h)


def test_sha1_of_known_string_is_identified():
    h = hashlib.sha1(b"password").hexdigest()
    assert "SHA-1" in _identify_types(h)


def test_sha256_of_known_string_is_identified():
    h = hashlib.sha256(b"password").hexdigest()
    assert "SHA-256" in _identify_types(h)


def test_sha512_of_known_string_is_identified():
    h = hashlib.sha512(b"password").hexdigest()
    assert "SHA-512" in _identify_types(h)


def test_bcrypt_format_is_identified():
    # Well-formed bcrypt hash shape ($2b$ + cost + 53-char salt+hash), no
    # need for the bcrypt package itself just to check pattern matching.
    fake_bcrypt = "$2b$12$" + "A" * 53
    assert "bcrypt" in _identify_types(fake_bcrypt)


def test_wordpress_phpass_format_is_identified():
    fake_wp = "$P$" + "B" * 31
    assert "WordPress" in _identify_types(fake_wp)


def test_unrecognized_string_returns_no_matches():
    m = HashIdentifier()
    matches = m._identify("not-a-hash-at-all!!", verbose=False)
    assert matches == []


def test_run_without_hash_or_file_returns_empty_list(capsys):
    m = HashIdentifier()
    assert m.run() == []


def test_run_with_hash_option_returns_one_result():
    m = HashIdentifier()
    m.set_option("HASH", hashlib.md5(b"password").hexdigest())
    results = m.run()
    assert len(results) == 1
    assert "MD5" in results[0]["types"]
