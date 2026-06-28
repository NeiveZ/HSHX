#!/usr/bin/env python3
# modules/identifier.py — Hash type identifier for HSHX

import re
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section

HASH_PATTERNS = [
    ("MD5",              r"^[a-f0-9]{32}$",                                   ""),
    ("MD5 (Unix)",       r"^\$1\$.{1,8}\$.{22}$",                             "Linux shadow"),
    ("MD4",              r"^[a-f0-9]{32}$",                                   "Same len as MD5"),
    ("SHA-1",            r"^[a-f0-9]{40}$",                                   ""),
    ("SHA-224",          r"^[a-f0-9]{56}$",                                   ""),
    ("SHA-256",          r"^[a-f0-9]{64}$",                                   ""),
    ("SHA-384",          r"^[a-f0-9]{96}$",                                   ""),
    ("SHA-512",          r"^[a-f0-9]{128}$",                                  ""),
    ("bcrypt",           r"^\$2[ayb]\$.{56}$",                                "Blowfish"),
    ("SHA-256 (Unix)",   r"^\$5\$.{1,16}\$.{43}$",                            "Linux shadow"),
    ("SHA-512 (Unix)",   r"^\$6\$.{1,16}\$.{86}$",                            "Linux shadow"),
    ("NTLM",             r"^[a-f0-9]{32}$",                                   "Windows SAM"),
    ("NTLMv1",           r"^[a-f0-9]{48}$",                                   "Net-NTLMv1"),
    ("NTLMv2",           r"^[a-f0-9]{32}:.+$",                                "Net-NTLMv2"),
    ("LM",               r"^[a-f0-9]{32}$",                                   "Windows LAN Manager"),
    ("MySQL 3.x",        r"^[a-f0-9]{16}$",                                   "OLD_PASSWORD()"),
    ("MySQL 4.1+",       r"^\*[a-f0-9]{40}$",                                 "SHA1(SHA1(pass))"),
    ("PostgreSQL MD5",   r"^md5[a-f0-9]{32}$",                                ""),
    ("Django PBKDF2",    r"^pbkdf2_sha256\$\d+\$.+\$.+$",                     ""),
    ("WordPress",        r"^\$P\$.{31}$",                                     "phpass"),
    ("Joomla",           r"^[a-f0-9]{32}:[a-z0-9]{32}$",                     "MD5+salt"),
    ("Drupal 7",         r"^\$S\$.{52}$",                                     "SHA-512+salt"),
    ("WPA PMKID",        r"^[a-f0-9]{32}\*[a-f0-9]+\*[a-f0-9]+\*[a-f0-9]+$","WiFi"),
    ("Cisco Type 5",     r"^\$1\$[a-z0-9./]{0,8}\$[a-z0-9./]{22}$",          "MD5 based"),
    ("Cisco Type 8",     r"^\$8\$.{14}\$.{43}$",                              "PBKDF2-SHA256"),
    ("Argon2i",          r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$.+$",  "Modern KDF"),
    ("Argon2id",         r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$.+$", "Modern KDF"),
    ("scrypt",           r"^\$scrypt\$N=\d+,r=\d+,p=\d+\$.+\$.+$",           "Memory-hard"),
    ("CRC32",            r"^[a-f0-9]{8}$",                                    "Checksum"),
    ("RIPEMD-160",       r"^[a-f0-9]{40}$",                                   ""),
    ("Whirlpool",        r"^[a-f0-9]{128}$",                                  ""),
    ("BLAKE2b-512",      r"^[a-f0-9]{128}$",                                  ""),
]

LENGTH_MAP = {
    8:   ["CRC32"],
    16:  ["MySQL 3.x"],
    32:  ["MD5", "NTLM", "LM", "MD4"],
    40:  ["SHA-1", "RIPEMD-160"],
    48:  ["NTLMv1"],
    56:  ["SHA-224"],
    64:  ["SHA-256"],
    96:  ["SHA-384"],
    128: ["SHA-512", "Whirlpool", "BLAKE2b-512"],
}


class HashIdentifier(BaseModule):

    NAME        = "hash/identify"
    DESCRIPTION = "Identify hash type — supports 30+ formats (MD5, SHA, bcrypt, NTLM, MySQL...)"
    REFERENCES  = ["https://hashcat.net/wiki/doku.php?id=example_hashes"]

    def _define_options(self):
        self._add_option("HASH",    "",      False, "Single hash string to identify")
        self._add_option("FILE",    "",      False, "File with one hash per line")
        self._add_option("VERBOSE", "false", False, "Show all possible types (true/false)")

    def run(self) -> list:
        hashes  = self._collect()
        verbose = self.get_option("VERBOSE").lower() == "true"

        if not hashes:
            print_status("No hash provided. Set HASH or FILE.", "error")
            return []

        print_section(f"Hash Identifier — {len(hashes)} hash(es)")
        results = []

        for h in hashes:
            h = h.strip()
            if not h or h.startswith("#"):
                continue
            matches = self._identify(h, verbose)
            self._print(h, matches)
            results.append({"hash": h, "types": [m[0] for m in matches], "length": len(h)})

        print_status(f"Identified {Colors.WHITE}{len(results)}{Colors.RESET} hash(es).", "ok")
        return results

    def _identify(self, h: str, verbose: bool) -> list:
        matches = []
        seen    = set()
        for name, pattern, notes in HASH_PATTERNS:
            try:
                if re.match(pattern, h.lower(), re.IGNORECASE) and name not in seen:
                    matches.append((name, notes))
                    seen.add(name)
            except re.error:
                pass

        if not verbose and matches:
            likely   = LENGTH_MAP.get(len(h), [])
            filtered = [(n, nt) for n, nt in matches if n in likely]
            return filtered if filtered else matches

        return matches

    def _print(self, h: str, matches: list):
        trunc = h[:45] + "..." if len(h) > 45 else h
        print(f"  {Colors.DARK_GRAY}Hash  :{Colors.RESET} {Colors.WHITE}{trunc}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Length:{Colors.RESET} {len(h)}")
        if not matches:
            print(f"  {Colors.DARK_GRAY}Type  :{Colors.RESET} {Colors.RED}Unknown{Colors.RESET}\n")
            return
        for i, (name, notes) in enumerate(matches):
            label = "Type  :" if i == 0 else "       "
            note  = f"  {Colors.DARK_GRAY}({notes}){Colors.RESET}" if notes else ""
            print(f"  {Colors.DARK_GRAY}{label}{Colors.RESET} {Colors.GREEN}{name}{Colors.RESET}{note}")
        print()

    def _collect(self) -> list:
        out   = []
        single = self.get_option("HASH")
        fpath  = self.get_option("FILE")
        if single:
            out.append(single)
        if fpath:
            try:
                with open(fpath) as f:
                    out.extend(f.readlines())
            except Exception as e:
                print_status(f"Cannot read file: {e}", "error")
        return out
