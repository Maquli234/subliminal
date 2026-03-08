"""
subliminal/engine.py — Orchestrates the full scan pipeline
"""

from __future__ import annotations

import asyncio
import signal
from typing import Callable, List, Optional

import httpx

from subliminal.modules.active import bruteforce_dns, enrich_tls_sans
from subliminal.modules.passive import collect_passive
from subliminal.modules.probe import ProbeResult, probe_all
from subliminal.modules.report import save_csv, save_html, save_json, save_txt
from subliminal.utils.config import SubliminalConfig
from subliminal.utils.logger import get_logger, found as print_found


async def run_scan(
    cfg: SubliminalConfig,
    on_found: Optional[Callable[[ProbeResult], None]] = None,
    stop_event: Optional[asyncio.Event] = None,
) -> List[ProbeResult]:
    """
    Full scan pipeline.
    *on_found* is called for each alive host as soon as it is discovered.
    *stop_event* can be set externally to abort the scan gracefully.
    """
    logger = get_logger(verbose=cfg.verbose)
    if stop_event is None:
        stop_event = asyncio.Event()

    # Graceful Ctrl-C
    def _handle_signal(sig, frame):
        logger.warning("Interrupt received — stopping after current tasks...")
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    headers = {"User-Agent": cfg.user_agent}
    limits = httpx.Limits(max_connections=400, max_keepalive_connections=200)
    timeout = httpx.Timeout(cfg.timeout)

    async with httpx.AsyncClient(headers=headers, timeout=timeout, limits=limits) as client:

        # ── 1. Passive discovery ───────────────────────────────────────────
        subs = await collect_passive(client, cfg.domain, enabled_sources=cfg.sources)

        # ── 2. Active TLS-SAN enrichment ──────────────────────────────────
        if cfg.active and not stop_event.is_set():
            extra = await enrich_tls_sans(subs, cfg.domain, concurrency=cfg.concurrency // 3)
            subs |= extra

        # ── 3. DNS brute-force ────────────────────────────────────────────
        if cfg.bruteforce and not stop_event.is_set():
            bf_hosts = await bruteforce_dns(
                cfg.domain,
                wordlist_path=cfg.wordlist,
                concurrency=cfg.concurrency,
            )
            subs |= bf_hosts

    if stop_event.is_set():
        logger.warning("Scan aborted — skipping HTTP probing")
        return []

    # ── 4. HTTP probing ────────────────────────────────────────────────────
    if not cfg.probe:
        logger.info("Probing disabled — returning raw subdomain list")
        return [ProbeResult(host=s, url=s, status=0) for s in sorted(subs)]

    # Default on_found handler: print to stdout
    _on_found = on_found or (lambda r: print_found(r.url))

    logger.info(f"Probing {len(subs)} subdomains (concurrency={cfg.concurrency})...")
    results = await probe_all(
        subs,
        timeout=cfg.timeout,
        concurrency=cfg.concurrency,
        user_agent=cfg.user_agent,
        status_filter=cfg.status_filter,
        follow_redirects=cfg.follow_redirects,
        on_found=_on_found,
        stop_event=stop_event,
    )

    # ── 5. Save outputs ────────────────────────────────────────────────────
    if cfg.output_txt:
        save_txt(results, cfg.output_txt)
        logger.info(f"TXT saved → {cfg.output_txt}")
    if cfg.output_json:
        save_json(results, cfg.output_json)
        logger.info(f"JSON saved → {cfg.output_json}")
    if cfg.output_csv:
        save_csv(results, cfg.output_csv)
        logger.info(f"CSV saved → {cfg.output_csv}")
    if cfg.output_html:
        save_html(results, cfg.domain, cfg.output_html)
        logger.info(f"HTML report saved → {cfg.output_html}")

    return results
