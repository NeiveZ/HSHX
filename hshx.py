#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HSHX - Hash Cracker & Identifier
Author: NeiveZ | github.com/NeiveZ/HSHX
For authorized security testing only.
"""

import cmd
import sys
import os
import json
import shutil
from datetime import datetime

from utils.colors import Colors, print_status
from utils.session import Session

from modules.identifier import HashIdentifier
from modules.cracker    import HashCracker
from modules.generator  import HashGenerator
from modules.report_gen import ReportGenerator


class HSHXShell(cmd.Cmd):

    intro  = ""
    prompt = f"{Colors.BOLD}{Colors.RED}hshx{Colors.RESET} {Colors.WHITE}>{Colors.RESET} "

    def __init__(self):
        super().__init__()
        self.session = Session()
        self.modules = {
            "hash/identify":  HashIdentifier,
            "hash/crack":     HashCracker,
            "hash/generate":  HashGenerator,
        }
        self.active_module      = None
        self.active_module_name = None
        self._show_header()

    def _show_header(self):
        stats = self.session.get_stats()
        print(f"\n  {Colors.BOLD}{Colors.RED}HSHX{Colors.RESET}  "
              f"{Colors.DARK_GRAY}Hash Cracker & Identifier{Colors.RESET}  "
              f"{Colors.WHITE}v1.0.0{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Author: NeiveZ  |  For authorized testing only{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Scans: {Colors.WHITE}{stats['scans']}"
              f"  {Colors.DARK_GRAY}Cracked: {Colors.WHITE}{stats['cracks']}"
              f"  {Colors.DARK_GRAY}Reports: {Colors.WHITE}{stats['reports']}{Colors.RESET}")
        print(f"\n  {Colors.DARK_GRAY}Type {Colors.CYAN}help{Colors.DARK_GRAY} to list commands.{Colors.RESET}\n")

    def _update_prompt(self):
        if self.active_module_name:
            self.prompt = (
                f"{Colors.BOLD}{Colors.RED}hshx{Colors.RESET}"
                f"{Colors.DARK_GRAY}({Colors.RESET}"
                f"{Colors.YELLOW}{self.active_module_name}{Colors.RESET}"
                f"{Colors.DARK_GRAY}){Colors.RESET} "
                f"{Colors.WHITE}>{Colors.RESET} "
            )
        else:
            self.prompt = f"{Colors.BOLD}{Colors.RED}hshx{Colors.RESET} {Colors.WHITE}>{Colors.RESET} "

    def default(self, line):
        print_status(f"Unknown command: '{line}'. Type 'help'.", "error")

    def emptyline(self):
        pass

    def do_use(self, module_name):
        """Load a module.\n  Usage: use <module>"""
        module_name = module_name.strip()
        if not module_name:
            print_status("Usage: use <module_name>", "warn")
            return
        if module_name not in self.modules:
            print_status(f"Module '{module_name}' not found. Run 'show modules'.", "error")
            return
        self.active_module_name = module_name
        self.active_module = self.modules[module_name]()
        self._update_prompt()
        print_status(f"Module loaded: {Colors.YELLOW}{module_name}{Colors.RESET}", "ok")
        print()
        self.active_module.show_info()

    def do_set(self, args):
        """Set a module option.\n  Usage: set <OPTION> <value>"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            print_status("Usage: set <OPTION> <value>", "warn")
            return
        opt, val = parts[0].upper(), parts[1]
        if self.active_module.set_option(opt, val):
            print_status(f"{Colors.CYAN}{opt}{Colors.RESET} => {Colors.WHITE}{val}{Colors.RESET}", "ok")
        else:
            print_status(f"Unknown option: {opt}.", "error")

    def do_run(self, _):
        """Execute the loaded module.\n  Usage: run"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        print()
        try:
            results = self.active_module.run()
            if results:
                self.session.add_cracks(self.active_module_name, results)
                self._auto_save(results)
        except KeyboardInterrupt:
            print()
            print_status("Interrupted.", "warn")
        except Exception as e:
            print_status(f"Module error: {e}", "error")

    def do_options(self, _):
        """Show module options.\n  Usage: options"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        self.active_module.show_options()

    def do_info(self, _):
        """Show module info.\n  Usage: info"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        self.active_module.show_info()

    def do_back(self, _):
        """Unload current module.\n  Usage: back"""
        if self.active_module:
            print_status(f"Unloaded: {self.active_module_name}", "info")
            self.active_module      = None
            self.active_module_name = None
            self._update_prompt()
        else:
            print_status("No module loaded.", "warn")

    def do_show(self, args):
        """Show modules, results, or session.\n  Usage: show modules | results | session"""
        arg = args.strip().lower()
        if arg == "modules":
            self._show_modules()
        elif arg in ("results", "cracks"):
            self._show_results()
        elif arg in ("session",):
            self._show_session()
        else:
            print_status("Usage: show [modules|results|session]", "warn")

    def _show_modules(self):
        col_w = shutil.get_terminal_size((80, 20)).columns
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Available Modules{Colors.RESET}\n")
        print(f"  {'─' * (col_w - 4)}")
        print(f"{Colors.DARK_GRAY}  {'Name':<20} Description{Colors.RESET}")
        print(f"  {'─' * (col_w - 4)}")
        info = {
            "hash/identify":  "Identify hash type — supports 30+ algorithms",
            "hash/crack":     "Wordlist cracker — MD5, SHA-1/256/512, NTLM, bcrypt",
            "hash/generate":  "Generate hashes from plaintext — all major types + HMAC",
        }
        for name, desc in info.items():
            print(f"  {Colors.CYAN}{name:<20}{Colors.RESET}{Colors.WHITE}{desc}{Colors.RESET}")
        print(f"  {'─' * (col_w - 4)}\n")

    def _show_results(self):
        all_cracks = self.session.get_all_cracks()
        if not all_cracks:
            print_status("No results yet. Run a module first.", "warn")
            return
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Results{Colors.RESET}\n")
        for module, items in all_cracks.items():
            print(f"  {Colors.YELLOW}[{module}]{Colors.RESET}")
            for item in (items if isinstance(items, list) else [items]):
                if isinstance(item, dict):
                    h  = item.get("hash", item.get("type", ""))
                    pt = item.get("plaintext", "")
                    t  = item.get("type", "")
                    if pt:
                        print(f"    {Colors.GREEN}[CRACKED]{Colors.RESET} "
                              f"{Colors.DARK_GRAY}{h[:40]}{Colors.RESET} → "
                              f"{Colors.BOLD}{Colors.WHITE}{pt}{Colors.RESET} "
                              f"{Colors.DARK_GRAY}({t}){Colors.RESET}")
                    else:
                        print(f"    {Colors.DARK_GRAY}{h[:60]}{Colors.RESET} — {t}")
            print()

    def _show_session(self):
        stats = self.session.get_stats()
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Session{Colors.RESET}\n")
        print(f"  {Colors.DARK_GRAY}Session ID{Colors.RESET}: {Colors.CYAN}{stats['id']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Started   {Colors.RESET}: {stats['started']}")
        print(f"  {Colors.DARK_GRAY}Scans     {Colors.RESET}: {Colors.WHITE}{stats['scans']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Cracked   {Colors.RESET}: {Colors.WHITE}{stats['cracks']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Reports   {Colors.RESET}: {Colors.WHITE}{stats['reports']}{Colors.RESET}\n")

    def do_report(self, args):
        """Generate report.\n  Usage: report [json|txt|html] [filename]"""
        parts = args.strip().split()
        fmt   = parts[0].lower() if parts else "txt"
        fname = parts[1] if len(parts) > 1 else None
        cracks = self.session.get_all_cracks()
        if not cracks:
            print_status("No results to report.", "warn")
            return
        gen  = ReportGenerator(cracks, self.session.get_stats())
        path = gen.generate(fmt=fmt, filename=fname)
        if path:
            self.session.increment_reports()
            print_status(f"Report saved: {Colors.CYAN}{path}{Colors.RESET}", "ok")

    def _auto_save(self, results):
        os.makedirs("reports", exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"reports/auto_{self.active_module_name.replace('/', '_')}_{ts}.json"
        try:
            with open(path, "w") as f:
                json.dump({"module": self.active_module_name, "timestamp": ts, "results": results},
                          f, indent=2, default=str)
        except Exception:
            pass

    def do_clear(self, _):
        """Clear screen."""
        os.system("clear")
        self._show_header()

    def do_exit(self, _):
        """Exit HSHX."""
        print(f"\n  {Colors.DARK_GRAY}Goodbye. Stay ethical.{Colors.RESET}\n")
        return True

    def do_quit(self, _):
        return self.do_exit(_)

    def do_help(self, arg):
        if arg:
            super().do_help(arg)
            return
        print(f"""
  {Colors.BOLD}{Colors.WHITE}Core Commands{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}use <module>{Colors.RESET}            Load a module
  {Colors.CYAN}set <OPTION> <value>{Colors.RESET}    Set option
  {Colors.CYAN}run{Colors.RESET}                     Execute module
  {Colors.CYAN}options{Colors.RESET}                 Show options
  {Colors.CYAN}info{Colors.RESET}                    Module info
  {Colors.CYAN}back{Colors.RESET}                    Unload module

  {Colors.BOLD}{Colors.WHITE}Show{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}show modules{Colors.RESET}            List modules
  {Colors.CYAN}show results{Colors.RESET}            Cracked hashes
  {Colors.CYAN}show session{Colors.RESET}            Session info

  {Colors.BOLD}{Colors.WHITE}Output{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}report [json|txt|html]{Colors.RESET}  Generate report

  {Colors.BOLD}{Colors.WHITE}Utility{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}clear{Colors.RESET}                   Clear screen
  {Colors.CYAN}exit{Colors.RESET}                    Exit HSHX
""")


def main():
    try:
        shell = HSHXShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.DARK_GRAY}Interrupted. Goodbye.{Colors.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
