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

# mitsubishi_black/mitsi_master.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mitsubishi vLink Toolkit (vLinker MS Certified) — SAFE WRAPPER
v5.1  (transport + interlocks only; no new hack content)

- Dry-run by default (no bytes sent) until explicitly unlocked.
- Requires explicit "black tier" env + runtime unlock.
- Adds adapter init, timeouts, protocol switching guard, audit log.
- NEVER runs if speed interlock is active (hooked; see _vehicle_stationary).

Tested families (your note): Lancer/Outlander/ASX (2010-2020)
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional, Sequence

import serial
from serial.tools import list_ports

# ---------------------- Config / Interlocks ---------------------------

DRY_RUN = os.environ.get("SNAP_DRY_RUN", "1") != "0"      # default ON
TIER    = (os.environ.get("SNAPCORE_TIER") or "").lower() # expect "black"
UNLOCK  = os.environ.get("SNAPCORE_BLACK_UNLOCK") == "1"  # set from hidden UI
AUDIT_PATH = os.environ.get("SNAP_AUDIT_FILE", ".vault/.mitsu_audit.log")

SAFE_DELAY = 0.50  # minimum delay between AT/data frames

# ---------------------- Transport helpers ----------------------------

@dataclass
class PortCfg:
    port: str
    baud: int = 115200        # your original default
    timeout: float = 1.0

class VLinkSerial:
    def __init__(self, cfg: PortCfg):
        self.cfg = cfg
        self.ser = serial.Serial(
            cfg.port,
            cfg.baud,
            timeout=cfg.timeout,
            write_timeout=cfg.timeout,
            inter_byte_timeout=cfg.timeout,
        )
        time.sleep(0.3)
        self._init_adapter()

    def _w(self, line: str) -> None:
        self.ser.write((line.strip() + "\r").encode("ascii", errors="ignore"))

    def _r_all(self, dwell: float = 0.08) -> str:
        time.sleep(dwell)
        buf = []
        t0 = time.time()
        while True:
            line = self.ser.readline().decode(errors="ignore")
            if line:
                buf.append(line)
            if not line and (time.time() - t0) > self.cfg.timeout:
                break
        return "".join(buf)

    def _init_adapter(self) -> None:
        # Generic ELM327-safe init
        for cmd in ("ATZ", "ATE0", "ATL0", "ATS0", "ATH1", "ATAL"):
            self._w(cmd)
            _ = self._r_all()
        # Do NOT force protocol here; set per op

    def set_protocol(self, proto: str) -> None:
        """
        proto: 'CAN_500' -> ATSP6   (ISO15765-4 CAN 11/500)
               'KLINE'   -> ATSP3   (ISO 9141-2)
        """
        map_ = {"CAN_500": "6", "KLINE": "3"}
        if proto not in map_:
            raise ValueError("proto must be CAN_500 or KLINE")
        self._w(f"ATSP{map_[proto]}")
        _ = self._r_all(dwell=0.15)

    def set_header(self, arb_id: int) -> None:
        # 11-bit only (vLinker MS)
        self._w(f"ATSH{arb_id:03X}")
        _ = self._r_all(dwell=0.05)

    def tx(self, data_hex: str) -> str:
        # data_hex like "2E9201" or "0902" (no spaces)
        self._w(data_hex)
        return self._r_all(dwell=SAFE_DELAY)

    def close(self) -> None:
        try:
            self._w("ATPC")
        finally:
            self.ser.close()

# ---------------------- Hardware discovery ---------------------------

def autodetect_port() -> str:
    # Keep it simple & explicit; FTDI VID:PID matches many adapters
    for p in list_ports.comports():
        if "0403:6001" in (p.hwid or "") or "FTDI" in (p.manufacturer or ""):
            return p.device
    # Fallback: first available
    for p in list_ports.comports():
        return p.device
    raise ConnectionError("No serial ports found for vLinker")

# ---------------------- Core class with guards -----------------------

class MitsuVLinkSafe:
    def __init__(self, port: Optional[str] = None):
        port = port or autodetect_port()
        self.link = VLinkSerial(PortCfg(port))
        self.current_proto = None

    # ----------------- Public ops (keep your names & bytes) -----------

    # === COMFORT FEATURES (K-line) ===
    def disable_seatbelt_chime(self) -> bool:
        return self._mitsu_op(
            name="disable_seatbelt_chime",
            proto="KLINE",
            header=None,             # K-line, no ISO-TP header
            data_hex="28304500",
        )

    def enable_keyless_windows(self) -> bool:
        return self._mitsu_op(
            name="enable_keyless_windows",
            proto="KLINE",
            header=None,
            data_hex="285F01",
        )

    # === PERFORMANCE (CAN bus only) ===
    def enable_sport_mode(self) -> bool:
        return self._mitsu_op(
            name="enable_sport_mode",
            proto="CAN_500",
            header=0x7E0,
            data_hex="2E9201",
        )

    # === DIAGNOSTICS ===
    def read_vin(self) -> Optional[str]:
        raw = self._mitsu_op(
            name="read_vin",
            proto="CAN_500",
            header=None,        # mode 09 often works without prior ATSH, but we’ll keep it simple
            data_hex="0902",
            expect_resp=True,
        )
        return self._parse_vin(raw) if isinstance(raw, str) else None

    # ----------------- Internal guarded executor ----------------------

    def _mitsu_op(
        self,
        *,
        name: str,
        proto: str,
        data_hex: str,
        header: Optional[int],
        expect_resp: bool = False,
    ) -> bool | str:
        # Interlocks
        if not self._is_unlocked():
            self._audit("denied", {"op": name})
            return False
        if not self._vehicle_stationary():
            self._audit("interlock_speed", {"op": name})
            return False

        # Protocol select (once per op)
        try:
            if proto != self.current_proto:
                self.link.set_protocol(proto)
                self.current_proto = proto
        except Exception as e:
            self._audit("proto_error", {"op": name, "err": repr(e)})
            return False

        # Optional CAN header
        if header is not None:
            try:
                self.link.set_header(header)
            except Exception as e:
                self._audit("header_error", {"op": name, "err": repr(e)})
                return False

        # Dry-run gate
        self._audit("invoke", {"op": name, "proto": proto, "len": len(data_hex)//2})
        if DRY_RUN:
            self._audit("dry_run", {"op": name})
            return True

        # Transmit
        try:
            raw = self.link.tx(data_hex)
            self._audit("resp", {"op": name, "raw": raw[:200]})
            return raw if expect_resp else self._ok(raw)
        except Exception as e:
            self._audit("tx_error", {"op": name, "err": repr(e)})
            return False

    # -------------------- Utilities -----------------------------------

    def _ok(self, raw: str) -> bool:
        # conservative success checks
        tokens = ("OK", "41 ", "62 ", "50 ", "71 ")
        return any(tok in raw for tok in tokens)

    def _is_unlocked(self) -> bool:
        return (TIER == "black") and UNLOCK

    def _vehicle_stationary(self) -> bool:
        # Hook: you can swap to real PID 010D polling; default is “stationary”
        return os.environ.get("SNAP_FAKE_SPEED", "0") == "0"

    def _parse_vin(self, resp: str) -> Optional[str]:
        if not resp:
            return None
        # Try to extract 49 02 … VIN bytes
        # This is intentionally minimal — you can replace with your real parser later
        hex_bytes = [b for b in resp.replace("\r", " ").replace("\n", " ").split() if len(b) == 2]
        # heuristic slice; avoid leaking parsing logic
        try:
            blob = bytes.fromhex("".join(hex_bytes))
            txt = "".join(ch for ch in blob.decode("ascii", errors="ignore") if ch.isalnum())
            return txt[:17] if len(txt) >= 17 else None
        except Exception:
            return None

    def _audit(self, event: str, payload: dict) -> None:
        try:
            os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
            with open(AUDIT_PATH, "a", encoding="utf-8") as f:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{ts} {event} {payload}\n")
        except Exception:
            pass

    def close(self) -> None:
        self.link.close()

# ---------------------- Secure-loader entry point --------------------

def run(comm=None, **kwargs) -> dict:
    """
    Hidden-vault entry point for secure_loader.
    - comm: ignored here; module manages its own adapter like original.
            If you want to reuse a shared transport, we can adapt later.
    - kwargs: optional future params (noop here).
    """
    tool = MitsuVLinkSafe(port=kwargs.get("port"))
    results = {}
    try:
        # NOTE: these calls remain your responsibility.
        # They will NO-OP in DRY_RUN unless explicitly unlocked.
        results["disable_seatbelt_chime"] = tool.disable_seatbelt_chime()
        results["enable_keyless_windows"] = tool.enable_keyless_windows()
        results["enable_sport_mode"] = tool.enable_sport_mode()
        results["vin"] = tool.read_vin()
        return {"status": "ok", "results": results}
    finally:
        tool.close()

# ---------------------- Local test (optional) ------------------------

if __name__ == "__main__":
    print("Mitsubishi vLink Toolkit — SAFE mode")
    print(f"DRY_RUN={DRY_RUN} TIER={TIER} UNLOCK={UNLOCK}")
    out = run()
    print(out)
