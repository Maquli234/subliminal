"""
subliminal/modules/probe.py — Async HTTP probing with status filtering
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set

import httpx

logger = logging.getLogger("subliminal")


@dataclass
class ProbeResult:
    host: str
    url: str
    status: int
    redirect_url: Optional[str] = None
    title: Optional[str] = None
    content_length: Optional[int] = None
    tls: bool = False
    error: Optional[str] = None

    def is_alive(self) -> bool:
        return self.error is None and self.status > 0


async def _probe_host(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    host: str,
    status_filter: List[int],
    on_found: Optional[Callable[[ProbeResult], None]],
    stop_event: asyncio.Event,
) -> Optional[ProbeResult]:
    if stop_event.is_set():
        return None

    async with sem:
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{host}", follow_redirects=True)
                if status_filter and r.status_code not in status_filter:
                    continue

                # Extract <title> if HTML
                title = None
                ct = r.headers.get("content-type", "")
                if "html" in ct:
                    import re
                    m = re.search(r"<title[^>]*>([^<]{0,200})", r.text, re.IGNORECASE)
                    if m:
                        title = m.group(1).strip()

                result = ProbeResult(
                    host=host,
                    url=str(r.url),
                    status=r.status_code,
                    redirect_url=str(r.url) if str(r.url) != f"{scheme}://{host}/" else None,
                    title=title,
                    content_length=int(r.headers.get("content-length", 0) or 0),
                    tls=(scheme == "https"),
                )
                if on_found:
                    on_found(result)
                return result
            except Exception:
                continue

    return None


async def probe_all(
    hosts: Set[str],
    timeout: int = 3,
    concurrency: int = 150,
    user_agent: str = "SUBLIMINAL/2.0",
    status_filter: Optional[List[int]] = None,
    follow_redirects: bool = True,
    on_found: Optional[Callable[[ProbeResult], None]] = None,
    stop_event: Optional[asyncio.Event] = None,
) -> List[ProbeResult]:
    """
    Probe every host in *hosts* for HTTP(S) liveness.
    Calls *on_found* for each alive result (useful for streaming to GUI/CLI).
    Returns a sorted list of ProbeResult objects.
    """
    if stop_event is None:
        stop_event = asyncio.Event()

    headers = {"User-Agent": user_agent}
    limits = httpx.Limits(max_connections=concurrency + 50, max_keepalive_connections=concurrency)
    http_timeout = httpx.Timeout(timeout)

    alive: List[ProbeResult] = []
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        headers=headers,
        timeout=http_timeout,
        limits=limits,
        follow_redirects=follow_redirects,
    ) as client:
        tasks = [
            _probe_host(client, sem, h, status_filter or [], on_found, stop_event)
            for h in hosts
        ]
        results = await asyncio.gather(*tasks)

    alive = [r for r in results if r and r.is_alive()]
    alive.sort(key=lambda r: r.url)
    logger.info(f"Probing complete — {len(alive)} alive host(s)")
    return alive
