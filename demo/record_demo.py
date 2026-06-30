#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
demo/record_demo.py — Drives a real HSHX session for an asciinema recording.

This doesn't fake the output: it actually launches hshx.py in a pty via
pexpect and types real commands into it with human-ish delays, so what
gets recorded is the genuine tool running, not a mockup.

Usage:
    pip install asciinema pexpect --break-system-packages
    cd HSHX/
    asciinema rec demo/hshx_demo.cast --command "python3 demo/record_demo.py" --overwrite

Then either:
  - upload:   asciinema upload demo/hshx_demo.cast
              (gives you an asciinema.org URL + embeddable <script> snippet
              for the README — this plays as an interactive terminal, which
              is generally a stronger portfolio signal than a static GIF
              and is what tools like httpie/bat/exa use in their READMEs)
  - or convert to GIF locally:
              cargo install --locked agg     # or download a prebuilt binary
              agg demo/hshx_demo.cast demo/hshx_demo.gif
"""
import sys
import time

import pexpect

PROMPT = r"hshx[^>]*> "

STEPS = [
    ("use hash/identify", 1.0),
    ("set HASH 5f4dcc3b5aa765d61d8327deb882cf99", 1.2),
    ("run", 1.6),
    ("back", 0.8),
    ("use hash/crack", 1.0),
    ("set HASH 5f4dcc3b5aa765d61d8327deb882cf99", 1.0),
    ("set ALGO md5", 1.0),
    ("run", 2.2),
    ("show results", 1.2),
    ("report html", 1.0),
    ("exit", 0.6),
]


def main():
    child = pexpect.spawn("python3 hshx.py", dimensions=(30, 100), encoding="utf-8", timeout=15)
    child.logfile_read = sys.stdout  # mirror the child's output live
    time.sleep(1.0)

    for command, pause in STEPS:
        time.sleep(0.3)
        child.sendline(command)
        time.sleep(pause)

    child.close(force=True)


if __name__ == "__main__":
    main()
