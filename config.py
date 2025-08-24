# File: config.py
# Snapcore-Python — runtime configuration (refined)

from __future__ import annotations
import os
from pathlib import Path

try:
    # optional: allows overrides from a .env file
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# -------- helpers --------
def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v not in (None, "") else default

def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default

def _env_bool(name: str, default: bool) -> bool:
    v = _env(name, str(default)).strip().lower()
    return v in ("1", "true", "yes", "y", "on") if v else default

def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if not raw:
        return default
    return [s.strip() for s in raw.split(",") if s.strip()]

# ---- Transport / Link ----
# Windows: "COM5", "COM3" etc.
# Linux/macOS: "/dev/ttyUSB0", "/dev/tty.SLAB_USBtoUART", etc.
SERIAL_PORT  = _env("SERIAL_PORT", "COM5")
BAUD_RATE    = _env_int("BAUD_RATE", 500000)         # 115200 also common
CAN_PROTOCOL = _env("CAN_PROTOCOL", "ISO15765")      # e.g., J1850_VPW, ISO9141

# ---- Feature Flags ----
TESLA_MODE = _env_bool("TESLA_MODE", True)           # OEM/Tesla features where available
SAVE_JSON  = _env_bool("SAVE_JSON", True)            # persist snapshots to vlink_storage/db.json
DEBUG_MODE = _env_bool("DEBUG_MODE", True)           # verbose logs

# VIN is read live (Mode 09). Do not hardcode unless testing offline.
DEFAULT_VIN = os.getenv("DEFAULT_VIN") or None

# ---- Paths ----
VLINK_STORAGE_DIR = Path(_env("VLINK_STORAGE_DIR", "vlink_storage")).expanduser()
LOG_DIR           = Path(_env("LOG_DIR", "logs")).expanduser()

# ensure directories exist at import time (safe + idempotent)
VLINK_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ---- Timeouts / Retries ----
CONNECT_TIMEOUT_SEC = float(_env("CONNECT_TIMEOUT_SEC", "3"))
COMMAND_TIMEOUT_SEC = float(_env("COMMAND_TIMEOUT_SEC", "1.2"))
RETRY_COUNT         = _env_int("RETRY_COUNT", 1)

# ---- Live Loop PIDs (Mode 01 defaults) ----
LIVE_PIDS = _env_list("LIVE_PIDS", [
    "010C",  # Engine RPM
    "010D",  # Vehicle Speed
    # Add more PIDs you want to poll every cycle
])

# ---- Logging ----
LOG_LEVEL = "DEBUG" if DEBUG_MODE else "INFO"
