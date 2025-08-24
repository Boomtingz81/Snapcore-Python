#!/usr/bin/env python3
# File: cli/healthcheck.py
"""
Snapcore-Python — Environment & Adapter Health Check (safe, non-destructive)

Checks:
  • Python version & required packages (pyserial)
  • Presence/writability of logs/ and vlink_storage/
  • Shows config snapshot (port, baud, protocol)
  • Lists available serial ports
  • Optional SAFE adapter probe (ATZ/ATE0/ATL0/ATS0/ATH0/ATSP0/ATI/ATDP/ATDPN)

Usage:
  python -m cli.healthcheck --quick
  python -m cli.healthcheck --port COM5 --baud 500000 --probe
  python -m cli.healthcheck --json
  python -m cli.healthcheck --verbose
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------- colors (pretty console) ----------
GREEN = "\x1b[32m"; RED = "\x1b[31m"; YELLOW = "\x1b[33m"; DIM = "\x1b[2m"; RESET = "\x1b[0m"
def ok(msg: str) -> None: print(f"{GREEN}✓{RESET} {msg}")
def warn(msg: str) -> None: print(f"{YELLOW}!{RESET} {msg}")
def fail(msg: str) -> None: print(f"{RED}✗ {msg}{RESET}")

# ---------- config snapshot with fallbacks ----------
def _load_config() -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "SERIAL_PORT": "COM5",
        "BAUD_RATE": 500000,
        "CAN_PROTOCOL": "ISO15765",
        "LOG_DIR": "logs",
        "VLINK_STORAGE_DIR": "vlink_storage",
        "DEBUG_MODE": True,
    }
    try:
        import config as _cfg # type: ignore
        for k in cfg:
            if hasattr(_cfg, k):
                cfg[k] = getattr(_cfg, k)
    except Exception:
        warn("config.py not found or had import errors – using defaults")
    return cfg

CFG = _load_config()

# ---------- optional logger (fallback to no-op) ----------
try:
    from snapcore.logger import get_logger # type: ignore
    log = get_logger("Health")
except Exception:
    class _Dummy:
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
        def debug(self, *a, **k): pass
    log = _Dummy()

# ---------- pyserial presence / listing ----------
def _have_pyserial() -> bool:
    try:
        import serial # noqa: F401
        return True
    except Exception:
        return False

def _list_ports() -> List[Tuple[str, str]]:
    if not _have_pyserial():
        return []
    try:
        from serial.tools.list_ports import comports # type: ignore
        return [(p.device, p.description or "") for p in comports()]
    except Exception:
        return []

# ---------- safe adapter probe (AT only) ----------
@dataclass
class AdapterInfo:
    port: str
    baud: int
    firmware: Optional[str] = None
    protocol: Optional[str] = None
    dpn: Optional[str] = None

def _read_until_prompt(ser, timeout: float = 2.0) -> str:
    out: List[str] = []
    t0 = time.time()
    while True:
        chunk = ser.read(ser.in_waiting or 1).decode(errors="ignore")
        if chunk:
            out.append(chunk)
            if ">" in chunk:
                break
        if time.time() - t0 > timeout:
            break
    return "".join(out)

def _send(ser, cmd: bytes, delay: float = 0.12, timeout: float = 2.0) -> str:
    if not cmd.endswith(b"\r"):
        cmd += b"\r"
    ser.reset_input_buffer()
    ser.write(cmd)
    ser.flush()
    time.sleep(delay)
    return _read_until_prompt(ser, timeout=timeout)

def _safe_adapter_probe(port: str, baud: int) -> Tuple[bool, Optional[AdapterInfo], str]:
    if not _have_pyserial():
        return False, None, "pyserial not installed"
    import serial # type: ignore
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=2, write_timeout=2) as ser:
            for cmd in (b"ATZ", b"ATE0", b"ATL0", b"ATS0", b"ATH0", b"ATSP0"):
                _send(ser, cmd)
            fw = _send(ser, b"ATI").replace(">", "").strip() or None
            dp = _send(ser, b"ATDP").replace(">", "").strip() or None
            dpn = _send(ser, b"ATDPN").replace(">", "").strip() or None
            info = AdapterInfo(port=port, baud=baud, firmware=fw, protocol=dp, dpn=dpn)
            return True, info, "Adapter responded"
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"

# ---------- fs helpers ----------
def _writable_dir(path: str) -> bool:
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        test = Path(path) / ".write_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink(missing_ok=True)
        return True
    except Exception:
        return False

# ---------- top-level health ----------
def run_health(port: Optional[str], baud: int, quick: bool, as_json: bool, verbose: bool) -> int:
    report: Dict[str, Any] = {
        "python": {}, "packages": {}, "project": {}, "paths": {},
        "serial": {}, "adapter": {}, "ok": False,
    }

    # Python version
    py_ok = sys.version_info >= (3, 10)
    report["python"]["version"] = sys.version.split()[0]
    report["python"]["meets_3_10_plus"] = py_ok
    ok(f"Python {report['python']['version']} (>= 3.10)") if py_ok \
        else fail(f"Python {report['python']['version']} — need 3.10 or newer")

    # Packages
    needs = ["pyserial"]
    pk_ok = True
    for pkg in needs:
        try:
            __import__(pkg)
            report["packages"][pkg] = True
            if verbose: ok(f"Package available: {pkg}")
        except Exception:
            report["packages"][pkg] = False
            pk_ok = False
            fail(f"Missing package: {pkg} (pip install {pkg})")

    # Project files
    expected = ["config.py", "README.md"]
    missing = [p for p in expected if not Path(p).exists()]
    report["project"]["missing"] = missing
    ok("Project files present (config.py, README.md)") if not missing \
        else warn("Missing project files: " + ", ".join(missing))

    # Paths
    log_dir = str(CFG.get("LOG_DIR", "logs"))
    store_dir = str(CFG.get("VLINK_STORAGE_DIR", "vlink_storage"))
    logs_ok = _writable_dir(log_dir)
    store_ok = _writable_dir(store_dir)
    report["paths"]["log_dir"] = {"path": log_dir, "writable": logs_ok}
    report["paths"]["vlink_storage"] = {"path": store_dir, "writable": store_ok}
    ok(f"Log dir '{log_dir}' writable") if logs_ok else fail(f"Log dir '{log_dir}' NOT writable")
    ok(f"Storage dir '{store_dir}' writable") if store_ok else fail(f"Storage dir '{store_dir}' NOT writable")

    # Serial ports
    ports = _list_ports()
    report["serial"]["ports"] = [{"device": d, "desc": desc} for d, desc in ports]
    if ports: ok("Serial ports: " + ", ".join(p[0] for p in ports))
    else: warn("No serial ports detected")

    # Adapter probe (optional)
    adapter_ok = False
    if not quick and pk_ok:
        use_port = port or str(CFG.get("SERIAL_PORT"))
        use_baud = int(baud or int(CFG.get("BAUD_RATE", 500000)))
        print(f"\n{DIM}Probing adapter on {use_port} @ {use_baud} (safe)…{RESET}")
        ok_flag, info, msg = _safe_adapter_probe(use_port, use_baud)
        report["adapter"]["ok"] = ok_flag
        report["adapter"]["message"] = msg
        report["adapter"]["info"] = asdict(info) if info else None
        if ok_flag:
            ok(f"Adapter OK — fw: {info.firmware or 'unknown'} | protocol: {info.protocol or 'unknown'} | DPN: {info.dpn or '-'}")
            adapter_ok = True
        else:
            warn(f"Adapter probe failed: {msg}")

    overall = py_ok and pk_ok and logs_ok and store_ok and (adapter_ok or quick)
    report["ok"] = overall
    print()
    ok("Health check PASSED") if overall else fail("Health check FAILED")

    if as_json:
        print(json.dumps(report, indent=2))

    return 0 if overall else 1

# ---------- CLI ----------
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Snapcore health check (safe, read-only)")
    p.add_argument("--port", help="Serial port (e.g., COM5 or /dev/ttyUSB0)")
    p.add_argument("--baud", type=int, default=int(CFG.get("BAUD_RATE", 500000)))
    p.add_argument("--quick", action="store_true", help="Skip adapter probe")
    p.add_argument("--json", action="store_true", help="Print JSON report")
    p.add_argument("--verbose", action="store_true", help="More package/info output")
    args = p.parse_args(argv)
    return run_health(args.port, args.baud, args.quick, args.json, args.verbose)

if __name__ == "__main__":
    sys.exit(main())
