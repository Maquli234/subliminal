"""
subliminal/modules/active.py — Active enrichment: TLS SAN, DNS brute-force
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from pathlib import Path
from typing import Set

logger = logging.getLogger("subliminal")

# ─── TLS SAN Extraction ───────────────────────────────────────────────────────

def _tls_sans_sync(host: str) -> Set[str]:
    """Synchronously pull Subject Alt Names from a host's TLS certificate."""
    sans: Set[str] = set()
    try:
        socket.gethostbyname(host)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                for _type, name in cert.get("subjectAltName", []):
                    if _type == "DNS":
                        sans.add(name.lower())
    except Exception:
        pass
    return sans


async def enrich_tls_sans(
    hosts: Set[str],
    domain: str,
    concurrency: int = 50,
) -> Set[str]:
    """
    For every host in *hosts*, fetch TLS SANs in a thread pool.
    Returns the set of NEW subdomains discovered (filtered to target domain).
    """
    logger.info(f"TLS-SAN enrichment on {len(hosts)} hosts (concurrency={concurrency})")
    sem = asyncio.Semaphore(concurrency)
    extra: Set[str] = set()
    loop = asyncio.get_event_loop()

    async def _fetch(host: str) -> None:
        async with sem:
            found = await loop.run_in_executor(None, _tls_sans_sync, host)
            for s in found:
                if s.endswith(f".{domain}") or s == domain:
                    extra.add(s)

    await asyncio.gather(*[_fetch(h) for h in hosts])
    logger.info(f"TLS-SAN enrichment found {len(extra)} additional candidates")
    return extra


# ─── DNS Brute-force ──────────────────────────────────────────────────────────

_DEFAULT_WORDLIST = Path(__file__).parent.parent / "data" / "wordlist.txt"


async def bruteforce_dns(
    domain: str,
    wordlist_path: str | Path | None = None,
    concurrency: int = 100,
) -> Set[str]:
    """
    Attempt DNS resolution for each word in *wordlist_path* prepended to *domain*.
    Returns the set of hosts that resolved.
    """
    wl_path = Path(wordlist_path) if wordlist_path else _DEFAULT_WORDLIST
    if not wl_path.exists():
        logger.warning(f"Wordlist not found at {wl_path} — skipping brute-force")
        return set()

    words = [line.strip() for line in wl_path.read_text().splitlines() if line.strip()]
    logger.info(f"DNS brute-force: {len(words)} words from {wl_path.name}")

    sem = asyncio.Semaphore(concurrency)
    resolved: Set[str] = set()
    loop = asyncio.get_event_loop()

    def _resolve(host: str) -> bool:
        try:
            socket.gethostbyname(host)
            return True
        except Exception:
            return False

    async def _check(word: str) -> None:
        candidate = f"{word}.{domain}"
        async with sem:
            hit = await loop.run_in_executor(None, _resolve, candidate)
            if hit:
                resolved.add(candidate)

    await asyncio.gather(*[_check(w) for w in words])
    logger.info(f"DNS brute-force resolved {len(resolved)} hosts")
    return resolved
