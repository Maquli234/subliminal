<div align="center">

```
███████╗██╗   ██╗██████╗ ██╗     ██╗███╗   ███╗██╗███╗   ██╗ █████╗ ██╗
██╔════╝██║   ██║██╔══██╗██║     ██║████╗ ████║██║████╗  ██║██╔══██╗██║
███████╗██║   ██║██████╔╝██║     ██║██╔████╔██║██║██╔██╗ ██║███████║██║
╚════██║██║   ██║██╔══██╗██║     ██║██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║
███████║╚██████╔╝██████╔╝███████╗██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
```

**passive · precise · silent subdomain reconnaissance**

[![CI](https://github.com/Maquli/subliminal/actions/workflows/ci.yml/badge.svg)](https://github.com/Maquli/subliminal/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-orange)](https://docs.astral.sh/ruff)

</div>

---

## Overview

**SUBLIMINAL** is a fast, extensible subdomain enumeration tool built for bug-bounty hunters, penetration testers, and red-teamers. It aggregates passive certificate-transparency and DNS data from multiple public APIs, optionally enriches results with active TLS-SAN extraction and DNS brute-force, then probes every candidate for HTTP liveness — all from a clean CLI or a native GUI.

### Why SUBLIMINAL?

| Feature | SUBLIMINAL | Basic tools |
|---|---|---|
| Multi-source passive collection | ✅ 6 sources | ❌ 1–2 sources |
| Active TLS-SAN enrichment | ✅ | ❌ |
| DNS brute-force (built-in wordlist) | ✅ | varies |
| Async HTTP probing | ✅ 150+ concurrent | ❌ serial |
| Scan profiles (quick / deep / stealth) | ✅ | ❌ |
| YAML/JSON config files | ✅ | ❌ |
| HTML / JSON / CSV / TXT export | ✅ 4 formats | ❌ |
| Native Tkinter GUI | ✅ | ❌ |
| Docker support | ✅ | varies |

---

## Installation

### From PyPI (recommended)

```bash
pip install subliminal-recon
```

### From source

```bash
git clone https://github.com/Maquli/subliminal.git
cd subliminal
pip install -e .
```

### With YAML config support

```bash
pip install "subliminal-recon[yaml]"
```

### Docker

```bash
# Build
docker build -t subliminal .

# Run
docker run --rm subliminal -d example.com --profile deep
```

---

## Quick Start

```bash
# Passive-only, print to stdout
subliminal -d example.com

# Deep scan with TLS-SAN enrichment, HTML report
subliminal -d example.com --active --html report.html

# Stealth mode — minimal API footprint
subliminal -d example.com --profile stealth

# Brute-force with custom wordlist, CSV output
subliminal -d example.com --bruteforce -w /path/to/wordlist.txt --csv results.csv

# Quick audit, only show HTTP 200s and 301s
subliminal -d example.com --profile quick --status 200 301

# Launch the GUI
subliminal --gui
```

---

## CLI Reference

```
usage: subliminal [-h] [-d DOMAIN] [-w WORDLIST] [-p PROFILE] [-c FILE]
                  [--sources SRC [SRC ...]] [--active] [--bruteforce] [--no-probe]
                  [-t TIMEOUT] [-n CONCURRENCY] [--status CODE [CODE ...]]
                  [-o FILE] [--json FILE] [--csv FILE] [--html FILE]
                  [-v] [--gui] [--version]
```

### Scan Profiles

| Profile | Concurrency | Sources | Active | Use case |
|---------|-------------|---------|--------|----------|
| `quick` | 80 | crtsh, hackertarget | ❌ | Fast initial recon |
| `deep` | 200 | All 6 sources | ✅ | Thorough enumeration |
| `stealth` | 20 | crtsh, certspotter | ❌ | Low-noise audits |

### Output Formats

| Flag | Format | Description |
|------|--------|-------------|
| `-o FILE` | Plain text | One URL per line |
| `--json FILE` | JSON array | Full result objects with status, title, TLS flag |
| `--csv FILE` | CSV | Spreadsheet-friendly |
| `--html FILE` | HTML report | Styled, self-contained report with stats |

---

## Config Files

Copy `subliminal/data/config.example.yaml` and customise:

```yaml
# ~/.subliminal.yaml
domain: ""
sources: [crtsh, certspotter, hackertarget]
active: true
concurrency: 200
timeout: 5
output_html: reports/latest.html
```

Load with:

```bash
subliminal -d example.com -c ~/.subliminal.yaml
```

Environment variable overrides are also supported:

```bash
export SUBLIMINAL_CONCURRENCY=50
export SUBLIMINAL_TIMEOUT=8
```

---

## GUI

Launch the graphical interface:

```bash
subliminal --gui
```

The GUI mirrors full CLI functionality with:
- Domain input and profile picker
- Concurrency slider
- Toggle switches for active / brute-force / probing modes
- Live results table (URL · status · TLS · page title)
- In-app log pane
- One-click export to TXT, JSON, or HTML

> Tkinter ships with CPython — no extra dependencies required.

---

## Project Structure

```
subliminal/
├── subliminal/
│   ├── cli/
│   │   └── main.py          # Argparse CLI + banner
│   ├── gui/
│   │   └── app.py           # Tkinter GUI
│   ├── modules/
│   │   ├── passive.py       # 6 passive discovery sources
│   │   ├── active.py        # TLS-SAN enrichment + DNS brute-force
│   │   ├── probe.py         # Async HTTP probing
│   │   └── report.py        # TXT / JSON / CSV / HTML export
│   ├── utils/
│   │   ├── config.py        # SubliminalConfig dataclass + profiles
│   │   └── logger.py        # Coloured structured logging
│   ├── data/
│   │   ├── wordlist.txt     # Built-in DNS brute-force wordlist
│   │   └── config.example.yaml
│   ├── tests/
│   │   └── test_core.py
│   └── engine.py            # Scan pipeline orchestrator
├── .github/workflows/ci.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

---

## Library / API Usage

SUBLIMINAL can be imported as a Python library:

```python
import asyncio
from subliminal.engine import run_scan
from subliminal.utils.config import SubliminalConfig

cfg = SubliminalConfig.from_profile("deep", domain="example.com")
cfg.output_html = "report.html"

results = asyncio.run(run_scan(cfg))

for r in results:
    print(f"{r.url}  [{r.status}]  {r.title or ''}")
```

---

## Passive Sources

| Source | Method |
|--------|--------|
| [crt.sh](https://crt.sh) | Certificate Transparency log search |
| [CertSpotter](https://sslmate.com/certspotter) | CT log issuances API |
| [BufferOver](https://dns.bufferover.run) | DNS dataset query |
| [ThreatCrowd](https://threatcrowd.org) | Threat intelligence |
| [HackerTarget](https://hackertarget.com) | Host search API |
| [AlienVault OTX](https://otx.alienvault.com) | Passive DNS |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest -v
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/new-source`)
3. Write tests for new functionality
4. Open a pull request against `main`

Please follow [PEP 8](https://pep8.org/) / [ruff](https://docs.astral.sh/ruff/) style and add docstrings to public functions.

---

## Legal Disclaimer

> SUBLIMINAL is intended for **authorised security testing and educational purposes only**.
> Only scan domains and systems you own or have explicit written permission to test.
> Unauthorised scanning may violate the Computer Fraud and Abuse Act (CFAA), GDPR, and other laws.
> The authors accept no liability for misuse.

---

## License

[MIT](LICENSE) © Maquli
