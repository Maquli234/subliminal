"""
subliminal/utils/config.py — Configuration management (YAML/JSON/env)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ─── Scan Profiles ────────────────────────────────────────────────────────────

PROFILES = {
    "quick": {
        "concurrency": 80,
        "timeout": 3,
        "sources": ["crtsh", "hackertarget"],
        "active": False,
        "screenshot": False,
        "description": "Fast passive-only sweep — results in seconds.",
    },
    "deep": {
        "concurrency": 200,
        "timeout": 5,
        "sources": ["crtsh", "certspotter", "bufferover", "threatcrowd", "hackertarget"],
        "active": True,
        "screenshot": False,
        "description": "Full passive + TLS-SAN active enrichment.",
    },
    "stealth": {
        "concurrency": 20,
        "timeout": 8,
        "sources": ["crtsh", "certspotter"],
        "active": False,
        "screenshot": False,
        "description": "Low-noise, slow scan — minimal API footprint.",
    },
}


# ─── Config Dataclass ─────────────────────────────────────────────────────────

@dataclass
class SubliminalConfig:
    # Target
    domain: str = ""
    wordlist: Optional[str] = None

    # Discovery
    sources: List[str] = field(default_factory=lambda: list(PROFILES["deep"]["sources"]))
    active: bool = False
    bruteforce: bool = False
    bruteforce_depth: int = 1

    # HTTP Probing
    probe: bool = True
    concurrency: int = 150
    timeout: int = 3
    follow_redirects: bool = True
    status_filter: List[int] = field(default_factory=list)  # empty = all

    # Output
    output_txt: Optional[str] = None
    output_json: Optional[str] = None
    output_csv: Optional[str] = None
    output_html: Optional[str] = None
    verbose: bool = False

    # Modules
    screenshot: bool = False
    nuclei: bool = False

    # Misc
    rate_limit: int = 0      # req/s per API source; 0 = unlimited
    user_agent: str = "SUBLIMINAL/2.0"
    profile: str = "deep"

    # ── Loaders ──────────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str | Path) -> "SubliminalConfig":
        path = Path(path)
        raw = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            if not HAS_YAML:
                raise ImportError("PyYAML is required to load YAML configs: pip install pyyaml")
            data = yaml.safe_load(raw)
        elif path.suffix == ".json":
            data = json.loads(raw)
        else:
            raise ValueError(f"Unsupported config format: {path.suffix}")
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})

    @classmethod
    def from_profile(cls, profile: str, domain: str = "") -> "SubliminalConfig":
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile '{profile}'. Choose from: {list(PROFILES)}")
        p = PROFILES[profile]
        return cls(
            domain=domain,
            profile=profile,
            concurrency=p["concurrency"],
            timeout=p["timeout"],
            sources=p["sources"],
            active=p["active"],
            screenshot=p["screenshot"],
        )

    def apply_profile(self, profile: str) -> None:
        if profile not in PROFILES:
            return
        p = PROFILES[profile]
        self.profile = profile
        self.concurrency = p["concurrency"]
        self.timeout = p["timeout"]
        self.sources = p["sources"]
        self.active = p["active"]

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        data = self.to_dict()
        if path.suffix in (".yaml", ".yml"):
            if not HAS_YAML:
                raise ImportError("PyYAML required: pip install pyyaml")
            path.write_text(yaml.dump(data, default_flow_style=False))
        else:
            path.write_text(json.dumps(data, indent=2))

    # ── Env overrides ─────────────────────────────────────────────────────────

    def apply_env(self) -> None:
        """Apply environment variable overrides (SUBLIMINAL_*)."""
        if v := os.getenv("SUBLIMINAL_CONCURRENCY"):
            self.concurrency = int(v)
        if v := os.getenv("SUBLIMINAL_TIMEOUT"):
            self.timeout = int(v)
        if v := os.getenv("SUBLIMINAL_USER_AGENT"):
            self.user_agent = v
