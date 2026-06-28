#!/usr/bin/env python3
# modules/cracker.py — Hash cracker (wordlist + brute force) for HSHX

import hashlib
import itertools
import string
import concurrent.futures
import time
import os
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section

DEFAULT_WORDLIST = [
    "password", "123456", "admin", "root", "toor", "pass", "1234",
    "qwerty", "letmein", "welcome", "monkey", "dragon", "master",
    "123456789", "password1", "superman", "batman", "iloveyou",
    "sunshine", "princess", "football", "shadow", "michael",
    "abc123", "login", "passw0rd", "test", "guest", "user",
]

SUPPORTED = {
    "md5":     (hashlib.md5,    32),
    "sha1":    (hashlib.sha1,   40),
    "sha256":  (hashlib.sha256, 64),
    "sha512":  (hashlib.sha512, 128),
    "sha224":  (hashlib.sha224, 56),
    "sha384":  (hashlib.sha384, 96),
    "ntlm":    (None,           32),  # special handler
}


def _ntlm_hash(plaintext: str) -> str:
    import hashlib
    return hashlib.new("md4", plaintext.encode("utf-16-le")).hexdigest()


def _compute(algo: str, plaintext: str) -> str:
    if algo == "ntlm":
        return _ntlm_hash(plaintext)
    fn, _ = SUPPORTED[algo]
    return fn(plaintext.encode("utf-8", errors="replace")).hexdigest()


class HashCracker(BaseModule):

    NAME        = "hash/crack"
    DESCRIPTION = "Crack hashes via wordlist or brute force — MD5, SHA-1, SHA-256, SHA-512, NTLM"
    REFERENCES  = [
        "https://hashcat.net/wiki/",
        "https://crackstation.net/",
    ]

    def _define_options(self):
        self._add_option("HASH",      "",          True,  "Hash to crack")
        self._add_option("ALGO",      "md5",       True,  "Algorithm: md5 | sha1 | sha256 | sha512 | sha224 | sha384 | ntlm")
        self._add_option("MODE",      "wordlist",  False, "Mode: wordlist | brute")
        self._add_option("WORDLIST",  "",          False, "Path to wordlist (default: built-in)")
        self._add_option("CHARSET",   "lower",     False, "Brute charset: lower | upper | digits | all | custom")
        self._add_option("CUSTOM",    "",          False, "Custom charset string (charset=custom)")
        self._add_option("MIN_LEN",   "1",         False, "Min password length (brute mode)")
        self._add_option("MAX_LEN",   "6",         False, "Max password length (brute mode)")
        self._add_option("THREADS",   "4",         False, "Parallel threads (wordlist mode)")
        self._add_option("RULES",     "false",     False, "Apply basic mutation rules (true/false)")

    def run(self) -> list:
        if not self._validate():
            return []

        target  = self.get_option("HASH").strip().lower()
        algo    = self.get_option("ALGO").lower()
        mode    = self.get_option("MODE").lower()
        threads = int(self.get_option("THREADS") or 4)

        if algo not in SUPPORTED:
            print_status(f"Unsupported algorithm: {algo}. Use: {', '.join(SUPPORTED)}", "error")
            return []

        # Validate hash length
        expected_len = SUPPORTED[algo][1]
        if len(target) != expected_len and not target.startswith("*"):
            print_status(f"Hash length {len(target)} doesn't match {algo} (expected {expected_len})", "warn")

        print_section(f"Hash Cracker — {algo.upper()}")
        print_status(f"Hash    : {Colors.WHITE}{target}{Colors.RESET}", "info")
        print_status(f"Algo    : {Colors.CYAN}{algo.upper()}{Colors.RESET}", "info")
        print_status(f"Mode    : {Colors.WHITE}{mode}{Colors.RESET}", "info")
        print()

        start = time.time()
        result = None

        if mode == "wordlist":
            result = self._wordlist_attack(target, algo, threads)
        elif mode == "brute":
            result = self._brute_attack(target, algo)
        else:
            print_status(f"Unknown mode: {mode}. Use wordlist or brute.", "error")
            return []

        elapsed = time.time() - start

        if result:
            print(f"\n  {Colors.BOLD}{Colors.GREEN}[CRACKED]{Colors.RESET} "
                  f"{Colors.WHITE}{target}{Colors.RESET} "
                  f"{Colors.DARK_GRAY}=>{Colors.RESET} "
                  f"{Colors.RED}{Colors.BOLD}{result}{Colors.RESET}")
            print(f"  {Colors.DARK_GRAY}Time: {elapsed:.2f}s{Colors.RESET}\n")
            return [{"hash": target, "algo": algo, "plaintext": result, "time": f"{elapsed:.2f}s"}]
        else:
            print_status(f"Hash not cracked after {elapsed:.2f}s.", "warn")
            return []

    # ── Wordlist attack ───────────────────────────────────────────

    def _wordlist_attack(self, target: str, algo: str, threads: int) -> str | None:
        words    = self._load_wordlist()
        rules    = self.get_option("RULES").lower() == "true"
        total    = len(words)
        count    = 0
        found    = [None]

        if rules:
            expanded = []
            for w in words:
                expanded.append(w)
                expanded.append(w.capitalize())
                expanded.append(w.upper())
                expanded.append(w + "1")
                expanded.append(w + "123")
                expanded.append(w + "!")
                expanded.append(w + "@")
                expanded.append("1" + w)
            words = expanded
            total = len(words)

        print_status(f"Wordlist: {Colors.WHITE}{total}{Colors.RESET} words | threads: {threads}", "run")

        lock = __import__("threading").Lock()

        def try_word(word):
            if found[0]:
                return None
            word = word.strip()
            if not word:
                return None
            try:
                h = _compute(algo, word)
                with lock:
                    nonlocal count
                    count += 1
                    if count % 500 == 0:
                        print(f"  {Colors.DARK_GRAY}[{count}/{total}] testing...{Colors.RESET}",
                              end="\r")
                if h == target:
                    found[0] = word
                    return word
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(try_word, w): w for w in words}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    ex.shutdown(wait=False, cancel_futures=True)
                    break

        print(" " * 60, end="\r")
        return found[0]

    # ── Brute force attack ────────────────────────────────────────

    def _brute_attack(self, target: str, algo: str) -> str | None:
        charset_name = self.get_option("CHARSET").lower()
        custom       = self.get_option("CUSTOM") or ""
        min_len      = int(self.get_option("MIN_LEN") or 1)
        max_len      = int(self.get_option("MAX_LEN") or 6)

        charsets = {
            "lower":  string.ascii_lowercase,
            "upper":  string.ascii_uppercase,
            "digits": string.digits,
            "alpha":  string.ascii_letters,
            "alnum":  string.ascii_letters + string.digits,
            "all":    string.printable.strip(),
            "custom": custom,
        }
        charset = charsets.get(charset_name, string.ascii_lowercase)
        if not charset:
            print_status("Custom charset is empty. Set CUSTOM option.", "error")
            return None

        total_est = sum(len(charset) ** l for l in range(min_len, max_len + 1))
        print_status(f"Charset : {Colors.WHITE}{charset_name}{Colors.RESET} ({len(charset)} chars)", "run")
        print_status(f"Length  : {Colors.WHITE}{min_len}-{max_len}{Colors.RESET}", "run")
        print_status(f"Estimated combinations: {Colors.WHITE}{total_est:,}{Colors.RESET}", "run")
        print()

        count = 0
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                candidate = "".join(combo)
                count    += 1
                if count % 10000 == 0:
                    print(f"  {Colors.DARK_GRAY}[{count:,}] trying: {candidate}{Colors.RESET}", end="\r")
                try:
                    if _compute(algo, candidate) == target:
                        print(" " * 60, end="\r")
                        return candidate
                except Exception:
                    pass

        print(" " * 60, end="\r")
        return None

    # ── Helpers ───────────────────────────────────────────────────

    def _load_wordlist(self) -> list:
        path = self.get_option("WORDLIST")
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    return [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except Exception as e:
                print_status(f"Cannot read wordlist: {e} — using built-in", "warn")
        return DEFAULT_WORDLIST
