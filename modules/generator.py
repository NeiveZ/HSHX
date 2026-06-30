#!/usr/bin/env python3
# modules/generator.py — Hash generator for HSHX

import hashlib
import hmac
import os
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section
from utils.md4 import ntlm_hash


class HashGenerator(BaseModule):

    NAME        = "hash/generate"
    DESCRIPTION = "Generate hashes from plaintext — MD5, SHA family, NTLM, HMAC, bcrypt"
    REFERENCES  = [
        "https://docs.python.org/3/library/hashlib.html",
    ]

    SUPPORTED = [
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3_256", "sha3_512", "ntlm", "bcrypt", "hmac-sha256",
    ]

    def _define_options(self):
        self._add_option("TEXT",   "",     True,  "Plaintext to hash")
        self._add_option("TYPE",   "all",  False, "Hash type: all | md5 | sha256 | ntlm | bcrypt | hmac-sha256")
        self._add_option("KEY",    "",     False, "HMAC key (hmac-sha256 only)")
        self._add_option("ROUNDS", "12",   False, "bcrypt rounds (bcrypt only, default: 12)")

    def run(self) -> list:
        if not self._validate():
            return []

        text    = self.get_option("TEXT")
        h_type  = self.get_option("TYPE").lower()
        key     = self.get_option("KEY") or ""
        rounds  = int(self.get_option("ROUNDS") or 12)

        print_section(f"Hash Generator — '{text}'")

        results = []
        types   = self.SUPPORTED if h_type == "all" else [h_type]

        for t in types:
            digest = self._generate(text, t, key, rounds)
            if digest:
                print(f"  {Colors.DARK_GRAY}{t:<15}{Colors.RESET}: {Colors.WHITE}{digest}{Colors.RESET}")
                results.append({"type": t, "plaintext": text, "hash": digest})

        print()
        print_status(f"Generated {Colors.WHITE}{len(results)}{Colors.RESET} hash(es).", "ok")
        return results

    def _generate(self, text: str, h_type: str, key: str, rounds: int) -> str | None:
        try:
            if h_type == "md5":
                return hashlib.md5(text.encode()).hexdigest()
            elif h_type == "sha1":
                return hashlib.sha1(text.encode()).hexdigest()
            elif h_type == "sha224":
                return hashlib.sha224(text.encode()).hexdigest()
            elif h_type == "sha256":
                return hashlib.sha256(text.encode()).hexdigest()
            elif h_type == "sha384":
                return hashlib.sha384(text.encode()).hexdigest()
            elif h_type == "sha512":
                return hashlib.sha512(text.encode()).hexdigest()
            elif h_type == "sha3_256":
                return hashlib.sha3_256(text.encode()).hexdigest()
            elif h_type == "sha3_512":
                return hashlib.sha3_512(text.encode()).hexdigest()
            elif h_type == "ntlm":
                return ntlm_hash(text)
            elif h_type == "bcrypt":
                try:
                    import bcrypt as _bcrypt
                    salt   = _bcrypt.gensalt(rounds=rounds)
                    return _bcrypt.hashpw(text.encode(), salt).decode()
                except ImportError:
                    print_status("bcrypt requires: pip install bcrypt", "warn")
                    return None
            elif h_type == "hmac-sha256":
                if not key:
                    print_status("Set KEY option for HMAC generation.", "warn")
                    return None
                return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()
        except Exception as e:
            print_status(f"Error generating {h_type}: {e}", "error")
        return None
