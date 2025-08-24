# ⚠️ DISCLAIMER
# This software communicates directly with live vehicle systems.
# You use this software entirely at your own risk.
#
# The developers, contributors, and any associated parties accept no liability for:
# - Damage to vehicles, ECUs, batteries, or electronics
# - Data loss, unintended resets, or corrupted configurations
# - Physical injury, legal consequences, or financial loss
#
# This tool is intended only for qualified professionals who
# understand the risks of direct OBD/CAN access.

# File: snapcore/logger.py
"""
Unified logging for Snapcore-Python.

- Creates logs/ directory if missing
- Console: INFO by default (DEBUG if DEBUG_MODE = True in config.py)
- File: Timed rotating logs (daily), keeps last 7 days, full DEBUG detail
- Safe to import from any module without duplicating handlers
"""

from __future__ import annotations
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

# Local config
try:
    from config import LOG_DIR, DEBUG_MODE
except Exception:
    # Sensible fallbacks if config.py is missing during early dev
    LOG_DIR = "logs"
    DEBUG_MODE = True


# Internal module-level guard so we don't add handlers twice
_INITIALIZED = False


def _ensure_log_dir() -> Path:
    log_dir = Path(LOG_DIR).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def _build_console_handler() -> logging.Handler:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
    ch.set_name("console")
    ch.setFormatter(logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    ))
    return ch


def _build_file_handler(log_path: Path) -> logging.Handler:
    fh = TimedRotatingFileHandler(
        filename=str(log_path / "snapcore.log"),
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8",
        delay=True,              # don't create file until first log
        utc=False
    )
    fh.setLevel(logging.DEBUG)   # always keep full detail in file
    fh.set_name("file")
    fh.setFormatter(logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(filename)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    return fh


def setup_logging() -> None:
    """
    Idempotent setup: safe to call multiple times.
    Attaches console + rotating file handlers to the root logger.
    """
    global _INITIALIZED
    if _INITIALIZED:
        return

    log_dir = _ensure_log_dir()
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # let handlers filter levels

    # Remove any pre-existing handlers to avoid duplicates (e.g., when reloading)
    for h in list(root.handlers):
        root.removeHandler(h)

    root.addHandler(_build_console_handler())
    root.addHandler(_build_file_handler(log_dir))

    _INITIALIZED = True


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Returns a logger with unified configuration.
    Ensures logging is configured before returning the logger.
    """
    setup_logging()
    return logging.getLogger(name if name else "snapcore")


# Eagerly configure on import so you get logs immediately
setup_logging()


# ---------------------------
# Example usage (remove or keep as reference):
# ---------------------------
if __name__ == "__main__":
    log = get_logger(__name__)
    log.debug("Debug message (always in file, console if DEBUG_MODE=True).")
    log.info("Info message.")
    log.warning("Warning message.")
    log.error("Error message.")
