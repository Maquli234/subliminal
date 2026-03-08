"""
subliminal/utils/logger.py — Structured, coloured logging
"""

from __future__ import annotations

import logging
import sys
from typing import Optional


# ANSI colours (fall back gracefully on Windows)
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREY   = "\033[90m"


class _ColouredFormatter(logging.Formatter):
    LEVEL_COLOURS = {
        logging.DEBUG:    _GREY,
        logging.INFO:     _CYAN,
        logging.WARNING:  _YELLOW,
        logging.ERROR:    _RED,
        logging.CRITICAL: _RED + _BOLD,
    }
    PREFIX = {
        logging.DEBUG:    "[~]",
        logging.INFO:     "[*]",
        logging.WARNING:  "[!]",
        logging.ERROR:    "[✗]",
        logging.CRITICAL: "[✗✗]",
    }

    def format(self, record: logging.LogRecord) -> str:
        colour = self.LEVEL_COLOURS.get(record.levelno, "")
        prefix = self.PREFIX.get(record.levelno, "")
        msg = super().format(record)
        return f"{colour}{prefix} {msg}{_RESET}"


def get_logger(name: str = "subliminal", verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_ColouredFormatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def found(url: str) -> None:
    """Print a discovered alive URL to stdout."""
    print(f"{_GREEN}{_BOLD}[+]{_RESET} {_GREEN}{url}{_RESET}", flush=True)
