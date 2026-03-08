"""
subliminal/modules/report.py — Export results in TXT, JSON, CSV, and HTML
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import List

from subliminal.modules.probe import ProbeResult


def save_txt(results: List[ProbeResult], path: str | Path) -> None:
    Path(path).write_text("\n".join(r.url for r in results) + "\n")


def save_json(results: List[ProbeResult], path: str | Path) -> None:
    data = [
        {
            "url": r.url,
            "host": r.host,
            "status": r.status,
            "title": r.title,
            "tls": r.tls,
            "content_length": r.content_length,
            "redirect_url": r.redirect_url,
        }
        for r in results
    ]
    Path(path).write_text(json.dumps(data, indent=2))


def save_csv(results: List[ProbeResult], path: str | Path) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["url", "host", "status", "title", "tls", "content_length", "redirect_url"]
        )
        writer.writeheader()
        for r in results:
            writer.writerow(
                {
                    "url": r.url,
                    "host": r.host,
                    "status": r.status,
                    "title": r.title or "",
                    "tls": r.tls,
                    "content_length": r.content_length or 0,
                    "redirect_url": r.redirect_url or "",
                }
            )


def save_html(results: List[ProbeResult], domain: str, path: str | Path) -> None:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    tls_count = sum(1 for r in results if r.tls)
    rows = "\n".join(
        f"""
        <tr>
          <td><a href="{r.url}" target="_blank">{r.url}</a></td>
          <td class="status s{r.status // 100}xx">{r.status}</td>
          <td>{"🔒" if r.tls else "🔓"}</td>
          <td>{r.title or "—"}</td>
          <td>{r.content_length or "—"}</td>
        </tr>"""
        for r in results
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SUBLIMINAL Report — {domain}</title>
  <style>
    :root {{
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950;
      --yellow: #d29922; --red: #f85149;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', monospace, monospace; padding: 2rem; }}
    h1 {{ color: var(--accent); font-size: 1.4rem; margin-bottom: .25rem; }}
    .meta {{ color: #8b949e; font-size: .8rem; margin-bottom: 2rem; }}
    .stats {{ display: flex; gap: 1.5rem; margin-bottom: 2rem; }}
    .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: .75rem 1.25rem; }}
    .stat-n {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
    .stat-l {{ font-size: .75rem; color: #8b949e; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .82rem; }}
    th {{ background: var(--surface); border-bottom: 2px solid var(--border); padding: .5rem .75rem; text-align: left; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; }}
    td {{ padding: .45rem .75rem; border-bottom: 1px solid var(--border); }}
    tr:hover td {{ background: var(--surface); }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .s2xx {{ color: var(--green); }}
    .s3xx {{ color: var(--yellow); }}
    .s4xx, .s5xx {{ color: var(--red); }}
  </style>
</head>
<body>
  <h1>▶ SUBLIMINAL — {domain}</h1>
  <p class="meta">Generated {now}</p>
  <div class="stats">
    <div class="stat"><div class="stat-n">{len(results)}</div><div class="stat-l">Alive Hosts</div></div>
    <div class="stat"><div class="stat-n">{tls_count}</div><div class="stat-l">HTTPS</div></div>
    <div class="stat"><div class="stat-n">{len(results) - tls_count}</div><div class="stat-l">HTTP Only</div></div>
  </div>
  <table>
    <thead><tr><th>URL</th><th>Status</th><th>TLS</th><th>Title</th><th>Content-Length</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
    Path(path).write_text(html)
