#!/usr/bin/env python3
"""
SUBLIMINAL — passive & limited active subdomain reconnaissance

Creator: Maquli
Purpose: Educational purposes only
"""

import argparse
import asyncio
import json
import ssl
import socket
import signal
import httpx

# =======================
#        CONFIG
# =======================

class Config:
    CONCURRENCY = 150
    TIMEOUT = httpx.Timeout(3)
    USER_AGENT = "SUBLIMINAL/1.1"

STOP_REQUESTED = False

def handle_exit(sig, frame):
    global STOP_REQUESTED
    STOP_REQUESTED = True
    print("\n[!] Interrupted — exiting cleanly...")

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# =======================
#        BANNER
# =======================

BANNER = r"""
███████╗██╗   ██╗██████╗ ██╗     ██╗███╗   ███╗██╗███╗   ██╗ █████╗ ██╗     
██╔════╝██║   ██║██╔══██╗██║     ██║████╗ ████║██║████╗  ██║██╔══██╗██║     
███████╗██║   ██║██████╔╝██║     ██║██╔████╔██║██║██╔██╗ ██║███████║██║     
╚════██║██║   ██║██╔══██╗██║     ██║██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║     
███████║╚██████╔╝██████╔╝███████╗██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝

                           SUBLIMINAL
              passive • precise • silent reconnaissance
                        👁 observe only
"""

print(BANNER)

# =======================
#    HTTP CLIENT SETUP
# =======================

async def create_client():
    headers = {"User-Agent": Config.USER_AGENT}
    limits = httpx.Limits(max_connections=400, max_keepalive_connections=200)
    return httpx.AsyncClient(headers=headers, timeout=Config.TIMEOUT, limits=limits)

# =======================
#     PASSIVE SOURCES
# =======================

async def fetch_crtsh(client, domain):
    out = set()
    try:
        r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        for e in json.loads(r.text):
            for n in e.get("name_value", "").splitlines():
                if n and "*" not in n:
                    out.add(n.strip().lower())
    except Exception:
        return set()
    return out

async def fetch_certspotter(client, domain):
    out = set()
    try:
        r = await client.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names")
        for e in r.json():
            for n in e.get("dns_names", []):
                if n and "*" not in n:
                    out.add(n.strip().lower())
    except Exception:
        return set()
    return out

async def fetch_bufferover(client, domain):
    out = set()
    try:
        r = await client.get(f"https://dns.bufferover.run/dns?q=.{domain}")
        for rec in r.json().get("FDNS_A", []) + r.json().get("RDNS", []):
            try:
                out.add(rec.split(",")[1].strip().lower())
            except Exception:
                continue
    except Exception:
        return set()
    return out

async def fetch_threatcrowd(client, domain):
    out = set()
    try:
        r = await client.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}")
        for s in r.json().get("subdomains", []):
            if s:
                out.add(s.strip().lower())
    except Exception:
        return set()
    return out

async def fetch_hackertarget(client, domain):
    out = set()
    try:
        r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if "error" not in r.text.lower():
            for line in r.text.splitlines():
                try:
                    out.add(line.split(",")[0].strip().lower())
                except Exception:
                    continue
    except Exception:
        return set()
    return out

PASSIVE_SOURCES = {
    "crt.sh": fetch_crtsh,
    "certspotter": fetch_certspotter,
    "bufferover": fetch_bufferover,
    "threatcrowd": fetch_threatcrowd,
    "hackertarget": fetch_hackertarget,
}

# =======================
#     ACTIVE ENRICHMENT
# =======================

def tls_sans(host):
    sans = set()
    try:
        socket.gethostbyname(host)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                for _, name in cert.get("subjectAltName", []):
                    sans.add(name.lower())
    except Exception:
        pass
    return sans

# =======================
#     HTTP PROBING
# =======================

async def probe_http(client, sem, host, alive):
    if STOP_REQUESTED:
        return

    async with sem:
        for scheme in ("https", "http"):
            try:
                await client.get(f"{scheme}://{host}", follow_redirects=True)
                url = f"{scheme}://{host}"
                if url not in alive:
                    alive.add(url)
                    print(url)
                return
            except Exception:
                continue

# =======================
#        ENGINE
# =======================

async def run(domain, output, active, json_out, verbose):
    async with await create_client() as client:
        if verbose:
            print(f"[*] Collecting passive subdomains for: {domain}")
        results = await asyncio.gather(*[fn(client, domain) for fn in PASSIVE_SOURCES.values()])
        subs = set().union(*results)

        for w in ["www", "api", "mail", "dev", "test", "beta", "cdn", "assets"]:
            subs.add(f"{w}.{domain}")

        subs = {s for s in subs if s.endswith(domain)}

        if active and not STOP_REQUESTED:
            if verbose:
                print("[*] Enriching subdomains with TLS SAN entries...")
            extra = set()
            for h in list(subs):
                for s in tls_sans(h):
                    if s.endswith(domain):
                        extra.add(s)
            subs |= extra

        sem = asyncio.Semaphore(Config.CONCURRENCY)
        alive = set()

        if verbose:
            print("[*] Probing subdomains for alive hosts...")
        await asyncio.gather(*[probe_http(client, sem, h, alive) for h in subs])

    if output:
        with open(output, "w") as f:
            for url in sorted(alive):
                f.write(url + "\n")
    if json_out:
        with open(json_out, "w") as f:
            json.dump(sorted(alive), f, indent=2)

# =======================
#        ENTRYPOINT
# =======================

def main():
    parser = argparse.ArgumentParser(description="SUBLIMINAL — silent subdomain recon")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Write alive URLs to file")
    parser.add_argument("--json", help="Write alive URLs as JSON")
    parser.add_argument("--active", action="store_true", help="Enable limited active TLS SAN enrichment")
    parser.add_argument("--verbose", action="store_true", help="Print detailed process steps")

    args = parser.parse_args()
    asyncio.run(run(args.domain, args.output, args.active, args.json, args.verbose))

if __name__ == "__main__":
    main()
