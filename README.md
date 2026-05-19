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

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-orange)](https://docs.astral.sh/ruff)
[![Stars](https://img.shields.io/github/stars/Maquli/subliminal?style=flat&color=yellow)](https://github.com/Maquli/subliminal/stargazers)
[![Issues](https://img.shields.io/github/issues/Maquli/subliminal?color=red)](https://github.com/Maquli/subliminal/issues)

</div>

---

## Overview

**SUBLIMINAL** is a fast, extensible passive subdomain enumeration framework built for bug-bounty hunters, penetration testers, and red-teamers. It aggregates certificate-transparency and DNS intelligence from multiple public sources, enriches results with active TLS-SAN extraction and DNS brute-force, then probes every candidate for HTTP liveness — all from a clean CLI or native GUI.

Designed to be quiet by default and powerful when needed.

```
[ Domain ] ──► [ Passive Sources x6 ] ──► [ TLS Enrichment ] ──► [ DNS Brute-force ] ──► [ HTTP Probe ] ──► [ Report ]
```

---

## Why SUBLIMINAL?

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
| Library/API usage | ✅ | ❌ |
| Docker support | ✅ | varies |

---

## Installation

### From PyPI (recommended)

```bash
pip install subliminal-recon
```

### From Source

```bash
git clone https://github.com/Maquli/subliminal.git
cd subliminal
pip install -e .
```

### With YAML Config Support

```bash
pip install "subliminal-recon[yaml]"
```

### With All Optional Dependencies

```bash
pip install "subliminal-recon[all]"
```

### Docker

```bash
# Build
docker build -t subliminal .

# Run
docker run --rm subliminal -d example.com --profile deep

# Run with output volume
docker run --rm -v $(pwd)/reports:/reports subliminal -d example.com --html /reports/out.html
```

---

## Quick Start

```bash
# Passive-only discovery, print to stdout
subliminal -d example.com

# Deep scan with TLS-SAN enrichment and HTML report
subliminal -d example.com --active --html report.html

# Stealth mode — minimal API footprint, low noise
subliminal -d example.com --profile stealth

# Brute-force with custom wordlist and CSV output
subliminal -d example.com --bruteforce -w /path/to/wordlist.txt --csv results.csv

# Quick audit — show only HTTP 200s and 301s
subliminal -d example.com --profile quick --status 200 301

# Full pipeline: passive + active + brute-force + report
subliminal -d example.com --profile deep --active --bruteforce --html report.html --json results.json

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

### Options

| Flag | Description | Default |
|---|---|---|
| `-d DOMAIN` | Target domain to enumerate | required |
| `-w WORDLIST` | Custom wordlist for brute-force | built-in |
| `-p PROFILE` | Scan profile: `quick`, `deep`, `stealth` | `quick` |
| `-c FILE` | Load config from YAML file | none |
| `--sources` | Specify passive sources to use | all |
| `--active` | Enable TLS-SAN enrichment | off |
| `--bruteforce` | Enable DNS brute-force | off |
| `--no-probe` | Skip HTTP liveness probing | off |
| `-t TIMEOUT` | HTTP probe timeout (seconds) | 5 |
| `-n CONCURRENCY` | Max concurrent probe connections | 150 |
| `--status` | Filter results by HTTP status codes | all |
| `-o FILE` | Output to plain text file | stdout |
| `--json FILE` | Output to JSON file | none |
| `--csv FILE` | Output to CSV file | none |
| `--html FILE` | Output to HTML report | none |
| `-v` | Verbose logging | off |
| `--gui` | Launch the native GUI | off |

### Scan Profiles

| Profile | Concurrency | Sources | Active TLS | Use Case |
|---------|-------------|---------|------------|----------|
| `quick` | 80 | crtsh, hackertarget | ❌ | Fast initial recon |
| `deep` | 200 | All 6 sources | ✅ | Thorough enumeration |
| `stealth` | 20 | crtsh, certspotter | ❌ | Low-noise authorized audits |

---

## Output Formats

| Flag | Format | Description |
|------|--------|-------------|
| `-o FILE` | Plain text | One URL per line — pipe-friendly |
| `--json FILE` | JSON array | Full result objects with status, title, TLS flag, timestamp |
| `--csv FILE` | CSV | Spreadsheet-friendly, importable into reporting tools |
| `--html FILE` | HTML report | Styled, self-contained report with stats and filtering |

### Example JSON Output Structure

```json
[
  {
    "url": "api.example.com",
    "status": 200,
    "title": "API Gateway",
    "tls": true,
    "source": "crtsh",
    "timestamp": "2026-03-15T14:30:21Z"
  }
]
```

---

## Passive Sources

SUBLIMINAL aggregates data from six independent passive sources and deduplicates results automatically.

| Source | Method | Rate Limited |
|--------|--------|--------------|
| [crt.sh](https://crt.sh) | Certificate Transparency log search | No |
| [CertSpotter](https://sslmate.com/certspotter) | CT log issuances API | No |
| [BufferOver](https://dns.bufferover.run) | DNS dataset query | No |
| [ThreatCrowd](https://threatcrowd.org) | Threat intelligence passive DNS | No |
| [HackerTarget](https://hackertarget.com) | Host search API | Free tier |
| [AlienVault OTX](https://otx.alienvault.com) | Passive DNS repository | API key optional |

> API keys for rate-limited sources can be set in `~/.subliminal.yaml` or as environment variables.

---

## Active Enrichment

When `--active` is enabled, SUBLIMINAL goes beyond passive discovery:

**TLS-SAN Extraction** — Connects to each discovered host and extracts Subject Alternative Names from the TLS certificate. These often reveal additional subdomains not present in any passive source.

**DNS Brute-force** — Resolves a wordlist of common subdomain prefixes against the target domain. Uses the built-in wordlist by default, or a custom wordlist with `-w`. Fully async — resolves thousands of candidates per second.

**HTTP Liveness Probing** — Probes every candidate (passive + active) for HTTP/HTTPS responses. Records status code, page title, redirect chain, and TLS status. Up to 200 concurrent connections in `deep` profile.

---

## Config Files

Copy `subliminal/data/config.example.yaml` and customise:

```yaml
# ~/.subliminal.yaml

domain: ""
profile: deep
sources:
  - crtsh
  - certspotter
  - hackertarget
  - alienvault

active: true
bruteforce: false
concurrency: 200
timeout: 5

# Output
output_txt: results/latest.txt
output_html: reports/latest.html
output_json: results/latest.json

# Optional API keys
api_keys:
  alienvault: ""
  hackertarget: ""
```

Load with:

```bash
subliminal -d example.com -c ~/.subliminal.yaml
```

Environment variable overrides:

```bash
export SUBLIMINAL_CONCURRENCY=50
export SUBLIMINAL_TIMEOUT=8
export SUBLIMINAL_ALIENVAULT_KEY=your_key_here
```

---

## GUI

Launch the full graphical interface:

```bash
subliminal --gui
```

Features:
- Domain input and scan profile picker
- Concurrency slider and timeout control
- Toggle switches for active enrichment, brute-force, and HTTP probing
- Live results table — URL · Status · TLS · Page Title
- Real-time in-app log pane
- One-click export to TXT, JSON, CSV, or HTML
- Scan history and session management

> Tkinter ships with CPython — no extra install required.

---

## Library / API Usage

SUBLIMINAL can be imported directly as a Python library for integration into your own tooling or pipelines:

```python
import asyncio
from subliminal.engine import run_scan
from subliminal.utils.config import SubliminalConfig

# Load a profile and customise
cfg = SubliminalConfig.from_profile("deep", domain="example.com")
cfg.active = True
cfg.bruteforce = True
cfg.output_html = "report.html"

# Run the full pipeline
results = asyncio.run(run_scan(cfg))

# Process results
for r in results:
    print(f"[{r.status}] {r.url}  TLS={r.tls}  '{r.title or ''}'")

# Filter to live hosts only
live = [r for r in results if r.status and r.status < 400]
print(f"\n{len(live)} live hosts discovered")
```

---

## Project Structure

```
subliminal/
├── subliminal/
│   ├── cli/
│   │   └── main.py              # Argparse CLI and banner
│   ├── gui/
│   │   └── app.py               # Native Tkinter GUI
│   ├── modules/
│   │   ├── passive.py           # 6 passive discovery sources
│   │   ├── active.py            # TLS-SAN enrichment + DNS brute-force
│   │   ├── probe.py             # Async HTTP liveness probing
│   │   └── report.py           # TXT / JSON / CSV / HTML export
│   ├── utils/
│   │   ├── config.py            # SubliminalConfig dataclass + profiles
│   │   └── logger.py            # Coloured structured logging
│   ├── data/
│   │   ├── wordlist.txt         # Built-in DNS brute-force wordlist (~10k entries)
│   │   └── config.example.yaml # Example configuration template
│   ├── tests/
│   │   ├── test_passive.py
│   │   ├── test_active.py
│   │   ├── test_probe.py
│   │   └── test_core.py
│   └── engine.py                # Scan pipeline orchestrator
├── .github/
│   └── workflows/
│       └── ci.yml               # CI pipeline (lint, test, build)
├── Dockerfile
├── pyproject.toml
└── README.md
```

---

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run full test suite
pytest -v

# Run with coverage report
pytest --cov=subliminal --cov-report=html

# Run linting
ruff check subliminal/
ruff format subliminal/ --check
```

---

## Roadmap

**v1.1**
- Permutation engine — generate subdomain candidates via common mutation patterns (dev-, api-, staging-, etc.)
- Wayback Machine integration — extract historical subdomains from web archive
- DNS record enrichment — A, AAAA, MX, TXT, CNAME records per discovered host

**v1.2**
- Slack / webhook notifications on scan completion
- Scheduled recurring scans with delta reporting (new / removed subdomains)
- Screenshot capture for live HTTP hosts via headless browser

**Future**
- SENTINEL AI integration — feed discovered subdomains directly into full recon pipeline
- Cloud-friendly distributed mode — split large domain sets across multiple workers
- Plugin API — community-developed passive sources and enrichment modules

---

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/new-source`)
3. Write tests for any new functionality
4. Ensure linting passes (`ruff check .`)
5. Open a pull request against `main` with a clear description

Please follow [PEP 8](https://pep8.org/) style, use [ruff](https://docs.astral.sh/ruff/) for formatting, and add docstrings to all public functions and classes.

---

## Legal Disclaimer

> ⚠️ **Authorized Use Only**

SUBLIMINAL is intended exclusively for:

- **Authorized penetration testing** — Use only on domains and systems you own or have explicit written permission to test
- **Bug bounty programs** — Within the defined scope of the program rules
- **Security research** — In controlled lab environments or responsible disclosure contexts
- **Educational purposes** — Learning reconnaissance techniques in isolated, legal environments

Unauthorized use of SUBLIMINAL against systems you do not own or have explicit permission to test may violate the Computer Fraud and Abuse Act (CFAA), GDPR, and applicable local laws. The authors accept no liability for misuse. Users are solely responsible for ensuring compliance with all applicable laws.

**If you are unsure whether your use is authorized, it is not.**

---

## License

[MIT](LICENSE) © 2026 Maquli

---

<div align="center">

Built for the security community. Use responsibly.

*If SUBLIMINAL helped your recon — leave a ⭐ on [GitHub](https://github.com/Maquli/subliminal)*

</div>
