#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HSHX - Hash Cracker & Identifier
Author: NeiveZ | github.com/NeiveZ/HSHX
For authorized security testing only.
"""
from core.base_shell import PentestShell, main_entrypoint
from utils.colors import Colors
from modules.identifier import HashIdentifier
from modules.cracker import HashCracker
from modules.generator import HashGenerator
from modules.report_gen import ReportGenerator


class HSHXShell(PentestShell):
    TOOL_NAME = "hshx"
    TAGLINE = "Hash Cracker & Identifier"
    VERSION = "1.0.0"
    RESULT_LABEL = "Cracked"
    DEFAULT_REPORT_FORMAT = "txt"
    REPORT_GENERATOR = ReportGenerator
    MODULES = {
        "hash/identify": HashIdentifier,
        "hash/crack": HashCracker,
        "hash/generate": HashGenerator,
    }

    def _print_result_item(self, item):
        if not isinstance(item, dict):
            return
        h = item.get("hash", item.get("type", ""))
        pt = item.get("plaintext", "")
        t = item.get("type", "")
        if pt:
            print(f"   {Colors.GREEN}[CRACKED]{Colors.RESET} "
                  f"{Colors.DARK_GRAY}{h[:40]}{Colors.RESET} → "
                  f"{Colors.BOLD}{Colors.WHITE}{pt}{Colors.RESET} "
                  f"{Colors.DARK_GRAY}({t}){Colors.RESET}")
        else:
            print(f"   {Colors.DARK_GRAY}{h[:60]}{Colors.RESET} — {t}")


if __name__ == "__main__":
    main_entrypoint(HSHXShell)
