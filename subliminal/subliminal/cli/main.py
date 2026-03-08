"""
subliminal/cli/main.py — Rich CLI interface
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from subliminal import __version__
from subliminal.engine import run_scan
from subliminal.utils.config import PROFILES, SubliminalConfig

BANNER = r"""
███████╗██╗   ██╗██████╗ ██╗     ██╗███╗   ███╗██╗███╗   ██╗ █████╗ ██╗
██╔════╝██║   ██║██╔══██╗██║     ██║████╗ ████║██║████╗  ██║██╔══██╗██║
███████╗██║   ██║██████╔╝██║     ██║██╔████╔██║██║██╔██╗ ██║███████║██║
╚════██║██║   ██║██╔══██╗██║     ██║██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║
███████║╚██████╔╝██████╔╝███████╗██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
                       passive • precise • silent  v{version}
""".format(version=__version__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subliminal",
        description="SUBLIMINAL — passive & active subdomain reconnaissance",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Target
    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    target.add_argument("-w", "--wordlist", help="Path to DNS brute-force wordlist")

    # Profile / Config
    cfg_grp = parser.add_argument_group("Configuration")
    cfg_grp.add_argument(
        "-p", "--profile",
        choices=list(PROFILES),
        default="deep",
        help="\n".join(f"  {k}: {v['description']}" for k, v in PROFILES.items()),
    )
    cfg_grp.add_argument("-c", "--config", metavar="FILE", help="YAML/JSON config file")

    # Discovery
    disc = parser.add_argument_group("Discovery")
    disc.add_argument(
        "--sources",
        nargs="+",
        metavar="SRC",
        help="Passive sources to use (default: all)",
    )
    disc.add_argument("--active", action="store_true", help="Enable TLS-SAN enrichment")
    disc.add_argument("--bruteforce", action="store_true", help="Enable DNS brute-force")
    disc.add_argument("--no-probe", action="store_true", help="Skip HTTP probing — list subdomains only")

    # Tuning
    tune = parser.add_argument_group("Tuning")
    tune.add_argument("-t", "--timeout", type=int, default=3, help="Per-request timeout in seconds (default: 3)")
    tune.add_argument("-n", "--concurrency", type=int, default=150, help="Max concurrent probes (default: 150)")
    tune.add_argument(
        "--status",
        nargs="+",
        type=int,
        metavar="CODE",
        help="Only show responses with these HTTP status codes",
    )

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", metavar="FILE", help="Save alive URLs to plain text file")
    out.add_argument("--json", metavar="FILE", help="Save results as JSON")
    out.add_argument("--csv", metavar="FILE", help="Save results as CSV")
    out.add_argument("--html", metavar="FILE", help="Save HTML report")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # GUI
    parser.add_argument("--gui", action="store_true", help="Launch the graphical interface")
    parser.add_argument("--version", action="version", version=f"SUBLIMINAL {__version__}")

    return parser


def main() -> None:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    if args.gui:
        try:
            from subliminal.gui.app import launch_gui
            launch_gui()
        except ImportError as e:
            print(f"[!] GUI dependencies not installed: {e}")
            print("    Run: pip install subliminal[gui]")
        return

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    # Build config
    if args.config:
        cfg = SubliminalConfig.from_file(args.config)
        cfg.domain = args.domain or cfg.domain
    else:
        cfg = SubliminalConfig.from_profile(args.profile, domain=args.domain)

    # CLI overrides
    if args.sources:
        cfg.sources = args.sources
    if args.active:
        cfg.active = True
    if args.bruteforce:
        cfg.bruteforce = True
    if args.no_probe:
        cfg.probe = False
    if args.timeout != 3:
        cfg.timeout = args.timeout
    if args.concurrency != 150:
        cfg.concurrency = args.concurrency
    if args.status:
        cfg.status_filter = args.status
    if args.wordlist:
        cfg.wordlist = args.wordlist
    if args.verbose:
        cfg.verbose = True
    cfg.output_txt = args.output
    cfg.output_json = args.json
    cfg.output_csv = args.csv
    cfg.output_html = args.html

    cfg.apply_env()

    asyncio.run(run_scan(cfg))


if __name__ == "__main__":
    main()
