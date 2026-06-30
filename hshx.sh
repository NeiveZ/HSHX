#!/usr/bin/env bash
# hshx.sh — launcher for HSHX (Hash Cracker & Identifier)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "[-] $PYTHON_BIN not found. Install Python 3.10+ and try again." >&2
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION##*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo "[!] Detected Python $PY_VERSION — HSHX targets 3.10+. Continuing anyway." >&2
fi

if ! "$PYTHON_BIN" -c "import bcrypt" >/dev/null 2>&1; then
    echo "[!] bcrypt not installed — bcrypt hash/crack/generate will be unavailable." >&2
    echo "    Install with: pip install -r requirements-optional.txt --break-system-packages" >&2
fi

exec "$PYTHON_BIN" hshx.py "$@"
