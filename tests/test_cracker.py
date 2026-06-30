"""Tests for modules/cracker.py — wordlist mode against known plaintexts."""
import hashlib

from modules.cracker import HashCracker, DEFAULT_WORDLIST, _compute
from utils.md4 import ntlm_hash


def test_cracks_md5_of_word_from_default_wordlist():
    plaintext = "password"
    assert plaintext in DEFAULT_WORDLIST
    target = hashlib.md5(plaintext.encode()).hexdigest()

    m = HashCracker()
    m.set_option("HASH", target)
    m.set_option("ALGO", "md5")
    results = m.run()

    assert len(results) == 1
    assert results[0]["plaintext"] == plaintext


def test_cracks_sha256_of_word_from_default_wordlist():
    plaintext = "admin"
    target = hashlib.sha256(plaintext.encode()).hexdigest()

    m = HashCracker()
    m.set_option("HASH", target)
    m.set_option("ALGO", "sha256")
    results = m.run()

    assert len(results) == 1
    assert results[0]["plaintext"] == plaintext


def test_cracks_ntlm_hash_using_md4_fallback():
    plaintext = "admin"
    target = ntlm_hash(plaintext)

    m = HashCracker()
    m.set_option("HASH", target)
    m.set_option("ALGO", "ntlm")
    results = m.run()

    assert len(results) == 1
    assert results[0]["plaintext"] == plaintext


def test_hash_not_in_wordlist_returns_no_result():
    target = hashlib.md5(b"this-is-not-in-the-default-wordlist-xyz").hexdigest()

    m = HashCracker()
    m.set_option("HASH", target)
    m.set_option("ALGO", "md5")
    assert m.run() == []


def test_unsupported_algorithm_returns_no_result(capsys):
    m = HashCracker()
    m.set_option("HASH", "deadbeef")
    m.set_option("ALGO", "made_up_algo")
    assert m.run() == []


def test_mutation_rules_crack_a_simple_variant():
    # "password" with the "1" suffix mutation rule applied
    target = hashlib.md5(b"password1").hexdigest()

    m = HashCracker()
    m.set_option("HASH", target)
    m.set_option("ALGO", "md5")
    m.set_option("RULES", "true")
    results = m.run()

    assert len(results) == 1
    assert results[0]["plaintext"] == "password1"


def test_compute_helper_matches_hashlib_directly():
    assert _compute("sha1", "hello") == hashlib.sha1(b"hello").hexdigest()
