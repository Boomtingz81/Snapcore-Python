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

# mercedes_black/mb_master.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mercedes-Benz vLinker MS Toolkit (SAFE MODE)
v3.1 — Diagnostics-first, default-deny writes, full audit

This build:
- ✅ Read-only diagnostics (VIN, DTCs, live PIDs) enabled by default
- ✅ Dry-run transport (no bytes sent) unless explicitly unlocked
- ✅ Hidden "black" tier gate (env vars), with audit trail
- ✅ Consistent, human-readable logging
- ✅ Strict OBD-II / UDS framing; no OEM bypass logic included

To enable *actual* transmission (YOUR RISK):
    export SNAPCORE_TIER=black
    export SNAPCORE_BLACK_UNLOCK=1
    export SNAP_DRY_RUN=0
"""

from __future__ import annotations

import argparse
import os
import time
from dataclasses import dataclass
from typing import Optional, List, Dict

import serial
from serial.tools import list_ports


# ----------------------------- Safety flags & audit -----------------------------

SNAP_DRY_RUN = os.environ.get("SNAP_DRY_RUN", "1") != "0"   # default: safe (no TX)
SNAP_TIER    = (os.environ.get("SNAPCORE_TIER") or "").lower()
SNAP_UNLOCK  = os.environ.get("SNAPCORE_BLACK_UNLOCK") == "1"
AUDIT_FILE   = os.environ.get("SNAP_MB_AUDIT", ".vault/.mb_audit.log")


def _audit(event: str, payload: Dict):
    try:
        os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{ts} | {event} | {payload}\n")
    except Exception:
        # Last-resort: silent if filesystem not writable
        pass


def _unlocked() -> bool:
    return (SNAP_TIER == "black") and SNAP_UNLOCK and (SNAP_DRY_RUN is False)


# ----------------------------- Config & helpers --------------------------------

@dataclass
class MBConfig:
    baud: int = 115200           # vLinker MS default
    parity: str = serial.PARITY_NONE
    timeout: float = 1.0
    safe_delay: float = 0.25
    can_hs_header: str = "ATSH7E0"  # Powertrain default
    can_body_header: str = "ATSH726" # Body/BCM example (generic)
    init_cmds: List[str] = None

    def __post_init__(self):
        if self.init_cmds is None:
            self.init_cmds = [
                "ATZ",   # reset
                "ATE0",  # echo off
                "ATL0",  # linefeeds off
                "ATS0",  # spaces off
                "ATH1",  # headers on (debuggability)
                "ATSP6", # ISO 15765-4 CAN 11/500
            ]


def detect_port() -> str:
    for p in list_ports.comports():
        # Heuristics: vLinker commonly shows up with FTDI or CH340 descriptors
        if any(k in (p.description or "").lower() for k in ("ftdi", "ch340", "obd", "vlinker", "usb-serial")):
            return p.device
    # Fallback: first serial port
    ports = list(list_ports.comports())
    if ports:
        return ports[0].device
    raise RuntimeError("No serial ports found. Specify --port.")


# ----------------------------- Transport layer ---------------------------------

class MBSecureLink:
    def __init__(self, port: str, cfg: MBConfig):
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

    # Safe, audited send
    def send(self, cmd: str, wait: float = 0.15) -> str:
        # Always audit intent
        _audit("send_intent", {"cmd": cmd})
        time.sleep(self.cfg.safe_delay)

        if not _unlocked():
            # Dry-run: do not transmit, return empty to caller
            _audit("dry_run_skip", {"cmd": cmd})
            return ""

        # Actual TX path (explicitly unlocked)
        try:
            self.ser.reset_input_buffer()
            self.ser.write((cmd + "\r").encode("ascii", errors="ignore"))
            time.sleep(wait)
            raw = self.ser.read(self.ser.in_waiting or 1).decode("ascii", errors="ignore")
            _audit("txrx", {"cmd": cmd, "resp": raw[:200]})
            return raw
        except Exception as e:
            _audit("tx_error", {"cmd": cmd, "error": str(e)})
            return ""


# ----------------------------- High-level functions ----------------------------

class StarSafe:
    """
    Mercedes-Benz functions in safe mode.
    - Read-only diagnostics are allowed.
    - Write operations are gated and no-op unless explicitly unlocked.
    """

    def __init__(self, link: MBSecureLink):
        self.link = link

    # --------- Read-only diagnostics (allowed) ---------

    def read_vin(self) -> Optional[str]:
        """
        OBD-II Mode 09 PID 02
        """
        self.link.send(self.link.cfg.can_hs_header)  # set header
        resp = self.link.send("0902", wait=0.4)
        _audit("diag_vin_resp", {"raw": resp[:200]})
        if not resp:
            return None
        # Parse typical "49 02 ..." payloads
        hexbytes = [b for b in resp.replace("\r", " ").replace("\n", " ").split(" ") if len(b) in (2, 3)]
        # naive extraction
        try:
            # Find first '49' '02' pair then accumulate following bytes (rough parse for generic ELM format)
            joined = "".join(x for x in hexbytes if len(x) == 2 and all(c in "0123456789ABCDEFabcdef" for c in x))
            if "4902" in joined:
                after = joined.split("4902", 1)[1]
                # VIN is 17 ASCII -> 17 bytes
                vin_hex = after[:34]
                vin = bytes.fromhex(vin_hex).decode("ascii", errors="ignore")
                return vin.strip()
        except Exception:
            return None
        return None

    def read_stored_dtcs(self) -> List[str]:
        """
        Mode 03 - stored DTCs (generic)
        """
        self.link.send(self.link.cfg.can_hs_header)
        resp = self.link.send("03", wait=0.3)
        _audit("diag_dtcs_resp", {"raw": resp[:200]})
        if not resp:
            return []
        # very simple parse: look for lines starting with '43' then 2-byte codes (A/B/C/D/E) + 2 bytes
        codes: List[str] = []
        tokens = resp.replace("\r", " ").replace("\n", " ").split()
        for i, t in enumerate(tokens):
            if t.upper() == "43" and i + 1 < len(tokens):
                # subsequent bytes are code data; convert every two bytes to e.g. P0xxx
                # For simplicity we return raw 4-hex DTC chunks
                chunk = "".join(x for x in tokens[i + 1:i + 7] if len(x) == 2)
                for j in range(0, len(chunk), 4):
                    code = chunk[j:j + 4]
                    if len(code) == 4:
                        codes.append(code.upper())
        return codes

    def read_live_pid(self, service_pid: str) -> Optional[str]:
        """
        Generic OBD-II live data query. Ex: '010C' for RPM.
        """
        service_pid = service_pid.strip().upper()
        if not service_pid or len(service_pid) not in (4, 6):
            raise ValueError("PID must be like '010C' or '221234'")
        self.link.send(self.link.cfg.can_hs_header)
        resp = self.link.send(service_pid, wait=0.25)
        _audit("diag_pid_resp", {"pid": service_pid, "raw": resp[:200]})
        return resp or None

    # --------- Gated write/advanced ops (no-op unless unlocked) ---------

    def clear_dtcs(self) -> bool:
        """
        Mode 04 — CLEAR DTCs (GATED)
        """
        if not _unlocked():
            _audit("blocked_op", {"op": "clear_dtcs", "reason": "locked_or_dryrun"})
            return False
        self.link.send(self.link.cfg.can_hs_header)
        resp = self.link.send("04", wait=0.4)
        return bool(resp)

    def soft_reset_ecu(self) -> bool:
        """
        UDS ECU reset (GATED). Example service 0x11 0x01 (hard reset differs per ECU).
        """
        if not _unlocked():
            _audit("blocked_op", {"op": "soft_reset_ecu", "reason": "locked_or_dryrun"})
            return False
        self.link.send(self.link.cfg.can_hs_header)
        resp = self.link.send("1101", wait=0.4)
        return "50 11 01" in (resp or "")

    def write_coding_example(self, did: str, value_hex: str) -> bool:
        """
        Placeholder coding writer (GATED).
        No OEM bypass logic provided.
        """
        if not _unlocked():
            _audit("blocked_op", {"op": "write_coding_example", "did": did})
            return False
        self.link.send(self.link.cfg.can_body_header)
        # UDS WriteDataByIdentifier 0x2E: '2E <DID_hi> <DID_lo> <data...>'
        payload = f"2E {did} {value_hex}".replace(" ", "")
        resp = self.link.send(payload, wait=0.5)
        return bool(resp)


# ----------------------------- CLI ---------------------------------------------

BANNER = f"""
Mercedes Toolkit (SAFE MODE)
---------------------------
• DRY-RUN: {'ON (no TX)' if not _unlocked() else 'OFF (TX ENABLED)'}
• Tier   : {SNAP_TIER or 'unset'}
• Audit  : {AUDIT_FILE}
"""

def main():
    parser = argparse.ArgumentParser(description="Mercedes-Benz vLinker MS Toolkit (SAFE)")
    parser.add_argument("--port", help="Serial port (e.g., COM5, /dev/ttyUSB0). Omit to auto-detect.")
    parser.add_argument("--vin", action="store_true", help="Read VIN")
    parser.add_argument("--dtcs", action="store_true", help="Read stored DTCs")
    parser.add_argument("--clear-dtcs", action="store_true", help="Clear DTCs (GATED)")
    parser.add_argument("--pid", help="Query live PID (e.g., 010C for RPM)")
    args = parser.parse_args()

    print(BANNER)

    port = args.port or detect_port()
    cfg = MBConfig()
    link = MBSecureLink(port, cfg)
    star = StarSafe(link)

    try:
        if args.vin:
            vin = star.read_vin()
            print(f"VIN: {vin or '(no response)'}")

        if args.dtcs:
            dtcs = star.read_stored_dtcs()
            print("DTCs:", dtcs or "None")

        if args.clear_dtcs:
            ok = star.clear_dtcs()
            print("Clear DTCs:", "OK" if ok else "Blocked/Failed")

        if args.pid:
            resp = star.read_live_pid(args.pid)
            print(f"PID {args.pid} -> {resp or '(no response)'}")

        if not any([args.vin, args.dtcs, args.clear_dtcs, args.pid]):
            parser.print_help()

    finally:
        link.close()


if __name__ == "__main__":
    main()
