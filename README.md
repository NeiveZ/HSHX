# HSHX

> Hash Cracker & Identifier — identify, crack, and generate hashes with a Metasploit-style interactive shell.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-557C94?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

HSHX covers the complete hash workflow in a pentest engagement — identify what type of hash you're dealing with, crack it against a wordlist, or generate hashes from plaintext for testing. Integrates directly with loot collected by PWNX/hashdump.

---

## Modules

| Module | Description |
|---|---|
| `hash/identify` | Identify hash type — 30+ algorithms including MD5, SHA family, NTLM, bcrypt, Django, WordPress, Cisco, Kerberos |
| `hash/crack` | Wordlist-based cracking — MD5, SHA-1/256/512, NTLM, bcrypt with optional mutation rules |
| `hash/generate` | Generate hashes from plaintext — all major types including HMAC-SHA256 and bcrypt |

---

## Features

- **30+ hash signatures** — pattern + length matching for accurate identification
- **Mutation rules** — expands wordlist with common variations (uppercase, l33t, append numbers/symbols)
- **Multi-hash files** — crack or identify an entire file of hashes in one run
- **Parallel cracking** — configurable thread pool for faster wordlist attacks
- **HMAC support** — generate and identify HMAC-SHA256 with custom keys
- **Session persistence** — cracked hashes accumulate across modules
- **Report export** — TXT, JSON, HTML

---

## Requirements

```bash
# Optional (for bcrypt cracking/generation)
pip install bcrypt --break-system-packages
```

No other external dependencies.

---

## Installation

```bash
git clone https://github.com/NeiveZ/HSHX.git
cd HSHX
chmod +x hshx.sh
./hshx.sh
```

---

## Usage

```
hshx > use hash/identify
hshx > use hash/crack
hshx > use hash/generate
```

### Core commands

```
use <module>            Load a module
set <OPTION> <value>    Set option
run                     Execute module
show modules            List modules
show results            Cracked hashes
report [txt|json|html]  Export report
```

---

## Examples

**Identify a hash:**
```
hshx > use hash/identify
hshx (hash/identify) > set HASH 5f4dcc3b5aa765d61d8327deb882cf99
hshx (hash/identify) > run
# → MD5  hashcat:0  john:md5
```

**Identify from file:**
```
hshx (hash/identify) > set FILE /path/to/hashes.txt
hshx (hash/identify) > run
```

**Crack with built-in wordlist:**
```
hshx > use hash/crack
hshx (hash/crack) > set HASH 5f4dcc3b5aa765d61d8327deb882cf99
hshx (hash/crack) > set TYPE md5
hshx (hash/crack) > run
# → [CRACKED] password
```

**Crack with rockyou + mutation rules:**
```
hshx (hash/crack) > set WORDLIST /usr/share/wordlists/rockyou.txt
hshx (hash/crack) > set RULES true
hshx (hash/crack) > run
```

**Crack NTLM hash (from PWNX hashdump):**
```
hshx (hash/crack) > set HASH 31d6cfe0d16ae931b73c59d7e0c089c0
hshx (hash/crack) > set TYPE ntlm
hshx (hash/crack) > run
```

**Crack entire file:**
```
hshx (hash/crack) > set FILE /loot/hashes.txt
hshx (hash/crack) > set TYPE sha256
hshx (hash/crack) > set WORDLIST /usr/share/wordlists/rockyou.txt
hshx (hash/crack) > run
```

**Generate all hash types for a password:**
```
hshx > use hash/generate
hshx (hash/generate) > set TEXT password123
hshx (hash/generate) > set TYPE all
hshx (hash/generate) > run
```

**Generate HMAC-SHA256:**
```
hshx (hash/generate) > set TEXT api_payload
hshx (hash/generate) > set TYPE hmac-sha256
hshx (hash/generate) > set KEY secret_key
hshx (hash/generate) > run
```

---

## Supported Hash Types

| Hash | Hashcat Mode | John Format |
|---|---|---|
| MD5 | 0 | md5 |
| SHA-1 | 100 | raw-sha1 |
| SHA-256 | 1400 | raw-sha256 |
| SHA-512 | 1700 | raw-sha512 |
| NTLM | 1000 | nt |
| bcrypt | 3200 | bcrypt |
| MD5(Unix) `$1$` | 500 | md5crypt |
| SHA-512(Unix) `$6$` | 1800 | sha512crypt |
| WordPress `$P$` | 400 | phpass |
| Drupal 7 `$S$` | 7900 | drupal7 |
| Django PBKDF2 | 10000 | — |
| MySQL 5.x `*` | 300 | mysql-sha1 |
| Kerberos 5 TGS | 13100 | krb5tgs |
| NTLMv2 | 5600 | netntlmv2 |

---

## Integration with PWNX

```bash
# 1. Collect hashes with PWNX
./pwnx.sh → use post/hashdump → run
# → saves to loot/hashes_*.json

# 2. Extract and crack with HSHX
./hshx.sh → use hash/identify → set FILE loot/hashes.txt → run
./hshx.sh → use hash/crack    → set FILE loot/hashes.txt → run
```

---

## Repository Structure

```
HSHX/
├── hshx.py               # Interactive shell
├── hshx.sh               # Launcher
├── modules/
│   ├── identifier.py     # Hash type identification
│   ├── cracker.py        # Wordlist-based cracking
│   ├── generator.py      # Hash generation
│   └── report_gen.py     # Report generator
├── utils/
│   ├── colors.py
│   └── session.py
└── wordlists/            # Drop custom wordlists here
```

---

## Legal

For use only on systems you own or have explicit written authorization to test.
