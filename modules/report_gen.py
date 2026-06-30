#!/usr/bin/env python3
# modules/report_gen.py — Report generator for HSHX

import os
import json
from datetime import datetime
from utils.colors import print_status


class ReportGenerator:

    def __init__(self, cracks: dict, stats: dict):
        self.cracks   = cracks
        self.stats    = stats
        self.ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.ts_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.all      = [i for v in cracks.values() for i in (v if isinstance(v, list) else [v])]
        os.makedirs("reports", exist_ok=True)

    def generate(self, fmt: str = "txt", filename: str = None) -> str | None:
        fmt = fmt.lower()
        if fmt not in ("txt", "json", "html"):
            print_status(f"Unknown format '{fmt}'.", "error")
            return None
        fname = filename or f"hshx_report_{self.ts}.{fmt}"
        if not fname.endswith(f".{fmt}"):
            fname += f".{fmt}"
        path  = os.path.join("reports", fname)
        content = {"txt": self._txt, "json": self._json, "html": self._html}[fmt]()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def _txt(self):
        lines = ["=" * 60, "  HSHX — HASH CRACKING REPORT", "=" * 60,
                 f"  Generated : {self.ts_human}",
                 f"  Session   : {self.stats['id']}",
                 f"  Cracked   : {len(self.all)}", "=" * 60, ""]
        for module, items in self.cracks.items():
            lines += [f"[{module}]", "-" * 40]
            for item in (items if isinstance(items, list) else [items]):
                if isinstance(item, dict):
                    for k, v in item.items():
                        lines.append(f"  {k}: {v}")
                    lines.append("")
        return "\n".join(lines)

    def _json(self):
        return json.dumps({
            "meta":    {"tool": "HSHX v1.0", "generated": self.ts_human, "session": self.stats},
            "summary": {"total": len(self.all)},
            "results": self.cracks,
        }, indent=2, default=str)

    def _html(self):
        rows = ""
        for item in self.all:
            if not isinstance(item, dict):
                continue
            h  = item.get("hash", "")
            pt = item.get("plaintext", "")
            t  = item.get("type", "")
            color = "#3fb950" if pt else "#6e7681"
            rows += f"""<tr>
                <td class="mono">{h[:60]}{'...' if len(h) > 60 else ''}</td>
                <td style="color:var(--dim)">{t}</td>
                <td style="color:{color};font-weight:bold;font-family:monospace">{pt or '—'}</td>
            </tr>"""

        return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>HSHX Report</title>
<style>
:root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--red:#f85149;--green:#3fb950;--text:#c9d1d9;--dim:#6e7681;--blue:#79c0ff}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif;padding:2rem}}
h1{{color:var(--red);font-size:1.5rem;font-family:monospace;letter-spacing:2px;margin-bottom:.5rem}}
.meta{{color:var(--dim);font-size:.85rem;margin-bottom:2rem}}
.meta span{{color:var(--blue)}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{background:#1c2128;color:var(--dim);padding:.6rem .8rem;text-align:left;border-bottom:1px solid var(--border)}}
td{{padding:.6rem .8rem;border-bottom:1px solid var(--border);word-break:break-all}}
.mono{{font-family:monospace;font-size:.75rem;color:var(--blue)}}
footer{{color:var(--dim);font-size:.75rem;margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);text-align:center}}
</style></head><body>
<h1>HSHX — HASH CRACKING REPORT</h1>
<p class="meta">Generated: <span>{self.ts_human}</span> | Session: <span>{self.stats['id']}</span> | Cracked: <span>{len(self.all)}</span></p>
<table><thead><tr><th>Hash</th><th>Type</th><th>Plaintext</th></tr></thead>
<tbody>{rows or '<tr><td colspan="3" style="text-align:center;color:var(--dim)">No results</td></tr>'}</tbody></table>
<footer>HSHX v1.0 — For authorized security testing only | NeiveZ</footer>
</body></html>"""
