"""
subliminal/modules/passive.py — Passive subdomain discovery sources
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable, Dict, Set

import httpx

logger = logging.getLogger("subliminal")


# ─── Individual Source Fetchers ───────────────────────────────────────────────

async def fetch_crtsh(client: httpx.AsyncClient, domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        for entry in json.loads(r.text):
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower()
                if name and "*" not in name:
                    out.add(name)
    except Exception as exc:
        logger.debug(f"crt.sh error: {exc}")
    return out


async def fetch_certspotter(client: httpx.AsyncClient, domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = await client.get(
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names"
        )
        for entry in r.json():
            for name in entry.get("dns_names", []):
                name = name.strip().lower()
                if name and "*" not in name:
                    out.add(name)
    except Exception as exc:
        logger.debug(f"certspotter error: {exc}")
    return out


async def fetch_bufferover(client: httpx.AsyncClient, domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = await client.get(f"https://dns.bufferover.run/dns?q=.{domain}")
        data = r.json()
        for rec in data.get("FDNS_A", []) + data.get("RDNS", []):
            try:
                out.add(rec.split(",")[1].strip().lower())
            except Exception:
                continue
    except Exception as exc:
        logger.debug(f"bufferover error: {exc}")
    return out


async def fetch_threatcrowd(client: httpx.AsyncClient, domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = await client.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        )
        for s in r.json().get("subdomains", []):
            if s:
                out.add(s.strip().lower())
    except Exception as exc:
        logger.debug(f"threatcrowd error: {exc}")
    return out


async def fetch_hackertarget(client: httpx.AsyncClient, domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if "error" not in r.text.lower():
            for line in r.text.splitlines():
                try:
                    out.add(line.split(",")[0].strip().lower())
                except Exception:
                    continue
    except Exception as exc:
        logger.debug(f"hackertarget error: {exc}")
    return out


async def fetch_alienvault(client: httpx.AsyncClient, domain: str) -> Set[str]:
    out: Set[str] = set()
    try:
        page = 1
        while True:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"
                f"/passive_dns?limit=500&page={page}"
            )
            data = r.json()
            entries = data.get("passive_dns", [])
            if not entries:
                break
            for e in entries:
                hostname = e.get("hostname", "").strip().lower()
                if hostname and hostname.endswith(domain):
                    out.add(hostname)
            if not data.get("has_next"):
                break
            page += 1
    except Exception as exc:
        logger.debug(f"alienvault error: {exc}")
    return out


# ─── Registry ─────────────────────────────────────────────────────────────────

SOURCES: Dict[str, Callable] = {
    "crtsh":       fetch_crtsh,
    "certspotter": fetch_certspotter,
    "bufferover":  fetch_bufferover,
    "threatcrowd": fetch_threatcrowd,
    "hackertarget":fetch_hackertarget,
    "alienvault":  fetch_alienvault,
}


# ─── Runner ───────────────────────────────────────────────────────────────────

async def collect_passive(
    client: httpx.AsyncClient,
    domain: str,
    enabled_sources: list[str] | None = None,
) -> Set[str]:
    """
    Run all (or selected) passive sources concurrently and return the
    de-duplicated union of discovered subdomains.
    """
    fns = {k: v for k, v in SOURCES.items() if enabled_sources is None or k in enabled_sources}
    logger.info(f"Running {len(fns)} passive source(s): {', '.join(fns)}")

    results = await asyncio.gather(*[fn(client, domain) for fn in fns.values()])
    subs = set().union(*results)

    # Seed common prefixes
    for prefix in ("www", "api", "mail", "dev", "test", "beta", "cdn",
                   "assets", "admin", "portal", "staging", "vpn", "remote"):
        subs.add(f"{prefix}.{domain}")

    # Filter to target domain only
    subs = {s for s in subs if s.endswith(f".{domain}") or s == domain}
    logger.info(f"Passive collection complete — {len(subs)} candidates")
    return subs
