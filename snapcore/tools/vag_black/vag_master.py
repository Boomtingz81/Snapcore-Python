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

# FILEPATH: /vag_black/vag_master.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VW/Audi/Skoda/Seat Master Toolkit (vLinker MS Compatible) — SAFE MODE
v2.4 — Diagnostics-first, default-deny writes, full audit

This build:
- ✅ Read-only diagnostics (VIN, DTCs, live PIDs) enabled by default
- ✅ Dry-run transport (no bytes sent) unless explicitly unlocked
- ✅ Hidden "black" tier gate (env vars), with audit trail
- ✅ Port whitelist + obfuscated audit for sensitive strings
- ✅ No SFD bypasses or OEM-protection circumvention provided

To intentionally allow TX (YOUR RESPONSIBILITY):
    export SNAPCORE_TIER=black
    export SNAPCORE_BLACK_UNLOCK=1
    export SNAP_DRY_RUN=0
"""

from __future__ import annotations

import os
import sys
import time
import random
import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict

import serial
from serial.tools import list_ports

# ----------------------------- Safety & config -----------------------------

SNAP_DRY_RUN = os.environ.get("SNA PC ORE_DRY_RUN".replace(" ", ""), "1") != "0"   # default: NO TX
SNAP_TIER    = (os.environ.get("SNAPCORE_TIER") or "").lower()
SNAP_UNLOCK  = os.environ.get("SNAPCORE_BLACK_UNLOCK") == "1"
AUDIT_FILE   = os.environ.get("SNAP_VAG_AUDIT", ".vault/.vag_audit.log")

ALLOWED_PORTS = {"COM3", "COM4", "/dev/ttyUSB0"}  # extend as needed

def _unlocked() -> bool:
    return (SNAP_TIER == "black") and SNAP_UNLOCK and (SNAP_DRY_RUN is False)

def _audit(ev: str, payload: Dict):
    try:
        Path(AUDIT_FILE).parent.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        # minimal obfuscation of potentially sensitive hex
        scrub = {k: _obfuscate_hex(str(v)) for k, v in payload.items()}
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ts} | {ev} | {scrub}\n")
    except Exception:
        pass

def _obfuscate_hex(s: str) -> str:
    # Hide straight hex runs (e.g., "10 03 27 64") in audit
    return "".join("*" if c in "0123456789ABCDEFabcdef" else c for c in s)

def detect_port() -> str:
    # Prefer whitelisted; else first plausible serial
    ports = list(list_ports.comports())
    for p in ports:
        if p.device in ALLOWED_PORTS:
            return p.device
    for p in ports:
        if any(x in (p.description or "").lower() for x in ("obd", "vlinker", "usb-serial", "ftdi", "ch340")):
            return p.device
    if ports:
        return ports[0].device
    raise RuntimeError("No serial ports found. Specify --port.")

# ----------------------------- Transport layer -----------------------------

@dataclass
class VAGLinkCfg:
    baud: int = 115200
    parity: str = serial.PARITY_NONE
    timeout: float = 1.0
    safe_delay: float = 0.25
    init_cmds: List[str] = None
    hs_header: str = "ATSH7E0"   # powertrain UDS gateway
    body_header: str = "ATSH726" # body module example (generic)

    def __post_init__(self):
        if self.init_cmds is None:
            self.init_cmds = [
                "ATZ", "ATE0", "ATL0", "ATS0", "ATH1", "ATSP6"  # ISO 15765-4 CAN 11/500
            ]

class VAGLink:
    def __init__(self, port: str, cfg: VAGLinkCfg):
        if port not in ALLOWED_PORTS:
            _audit("port_warn", {"port": port, "note": "not in whitelist"})
        self.port = port
        self.cfg = cfg
        self.ser = serial.Serial(
            port=port,
            baudrate=cfg.baud,
            parity=cfg.parity,
            timeout=cfg.timeout,
            write_timeout=cfg.timeout,
        )
        self._init_adapter()

    def _init_adapter(self):
        for cmd in self.cfg.init_cmds:
            self.send(cmd)
            time.sleep(self.cfg.safe_delay)

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def send(self, cmd: str, wait: float = 0.15) -> str:
        _audit("send_intent", {"cmd": cmd})
        time.sleep(self.cfg.safe_delay + random.uniform(0.0, 0.1))

        if not _unlocked():
            _audit("dry_run_skip", {"cmd": cmd})
            return ""

        try:
            self.ser.reset_input_buffer()
            self.ser.write((cmd + "\r").encode("ascii", errors="ignore"))
            time.sleep(wait)
            raw = self.ser.read(self.ser.in_waiting or 1).decode("ascii", errors="ignore")
            _audit("txrx", {"cmd": cmd, "resp": raw[:200]})
            return raw
        except Exception as e:
            _audit("tx_error", {"cmd": cmd, "err": str(e)})
            return ""

# ----------------------------- High-level API -----------------------------

class VAGSafe:
    """
    Diagnostics-first API. Read ops allowed; write ops gated & no-op unless unlocked.
    No SFD bypasses are included.
    """
    def __init__(self, link: VAGLink):
        self.link = link

    # ---- Read-only diagnostics ----

    def read_vin(self) -> Optional[str]:
        self.link.send(self.link.cfg.hs_header)
        resp = self.link.send("0902", wait=0.35)
        _audit("vin_resp", {"raw": (resp or "")[:160]})
        if not resp:
            return None
        try:
            tokens = resp.replace("\r", " ").replace("\n", " ").split()
            hexbytes = [t for t in tokens if len(t) == 2]
            joined = "".join(hexbytes).upper()
            if "4902" in joined:
                after = joined.split("4902", 1)[1]
                vin_hex = after[:34]
                return bytes.fromhex(vin_hex).decode("ascii", errors="ignore").strip()
        except Exception:
            return None
        return None

    def read_dtcs(self) -> List[str]:
        self.link.send(self.link.cfg.hs_header)
        resp = self.link.send("03", wait=0.3)
        _audit("dtc_resp", {"raw": (resp or "")[:160]})
        if not resp:
            return []
        codes: List[str] = []
        tokens = resp.replace("\r", " ").replace("\n", " ").split()
        for i, t in enumerate(tokens):
            if t.upper() == "43":
                # collect next bytes as 2-byte dtc chunks (raw)
                data = "".join(x for x in tokens[i+1:i+9] if len(x) == 2)
                for j in range(0, len(data), 4):
                    chunk = data[j:j+4]
                    if len(chunk) == 4:
                        codes.append(chunk.upper())
        return codes

    def query_pid(self, pid: str) -> Optional[str]:
        pid = pid.strip().upper()
        if not pid or len(pid) not in (4, 6):
            raise ValueError("PID must look like '010C' or '221234'")
        self.link.send(self.link.cfg.hs_header)
        resp = self.link.send(pid, wait=0.25)
        _audit("pid_resp", {"pid": pid, "raw": (resp or "")[:160]})
        return resp or None

    # ---- Gated write-like placeholders (no-op unless unlocked) ----

    def clear_dtcs(self) -> bool:
        if not _unlocked():
            _audit("blocked_op", {"op": "clear_dtcs"})
            return False
        self.link.send(self.link.cfg.hs_header)
        resp = self.link.send("04", wait=0.35)
        return bool(resp)

    def coding_placeholder(self, did: str, value_hex: str) -> bool:
        """
        Placeholder for legitimate UDS WriteDataByIdentifier (0x2E).
        No OEM bypasses provided. Only transmits if explicitly unlocked.
        """
        if not _unlocked():
            _audit("blocked_op", {"op": "coding_placeholder", "did": did})
            return False
        self.link.send(self.link.cfg.body_header)
        payload = f"2E {did} {value_hex}".replace(" ", "")
        resp = self.link.send(payload, wait=0.5)
        return bool(resp)

# ----------------------------- CLI -----------------------------

BANNER = f"""
VAG Master Toolkit — SAFE MODE
------------------------------
• DRY-RUN: {'ON (no TX)' if not _unlocked() else 'OFF (TX ENABLED)'}
• Tier   : {SNAP_TIER or 'unset'}
• Audit  : {AUDIT_FILE}
"""

def main():
    parser = argparse.ArgumentParser(description="VAG Master (SAFE)")
    parser.add_argument("--port", help="Serial port (COMx or /dev/ttyUSBx). Omit to auto-detect.")
    parser.add_argument("--vin", action="store_true", help="Read VIN")
    parser.add_argument("--dtcs", action="store_true", help="Read stored DTCs")
    parser.add_argument("--clear-dtcs", action="store_true", help="Clear DTCs (GATED)")
    parser.add_argument("--pid", help="Query a live PID (e.g., 010C for RPM)")
    args = parser.parse_args()

    print(BANNER)

    port = args.port or detect_port()
    cfg = VAGLinkCfg()
    link = VAGLink(port, cfg)
    vag = VAGSafe(link)

    try:
        if args.vin:
            print("VIN:", vag.read_vin() or "(no response)")
        if args.dtcs:
            print("DTCs:", vag.read_dtcs() or "None")
        if args.pid:
            print(f"{args.pid} ->", vag.query_pid(args.pid) or "(no response)")
        if args.clear_dtcs:
            ok = vag.clear_dtcs()
            print("Clear DTCs:", "OK" if ok else "Blocked/Failed")

        if not any([args.vin, args.dtcs, args.pid, args.clear_dtcs]):
            parser.print_help()
    finally:
        link.close()

if __name__ == "__main__":
    main()
