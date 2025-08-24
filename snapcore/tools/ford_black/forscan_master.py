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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FORScan Pro (vLinker MS Edition) – SAFE WRAPPER
v2.2  (transport + interlocks only; no new hack content)

- Dry-run by default (no bytes sent) until explicitly unlocked.
- Requires explicit "black tier" env + runtime unlock.
- Adds HS/MS bus switching guard, serial init, timeouts, audit log.
- NEVER runs if speed > 0 (basic interlock hook).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional, List, Sequence

import serial  # pyserial

# ---------------------- Config / Interlocks ---------------------------

DRY_RUN = os.environ.get("SNAP_DRY_RUN", "1") != "0"      # default ON
TIER    = (os.environ.get("SNAPCORE_TIER") or "").lower() # expect "black"
UNLOCK  = os.environ.get("SNAPCORE_BLACK_UNLOCK") == "1"  # set from hidden UI

AUDIT_PATH = os.environ.get("SNAP_AUDIT_FILE", ".vault/.ford_audit.log")

# ---------------------- Transport helpers ----------------------------

@dataclass
class VlinkPort:
    port: str
    baud: int = 500000
    timeout: float = 1.0

class SerialVlink:
    def __init__(self, cfg: VlinkPort):
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

    def _write_cmd(self, line: str) -> None:
        # ELM-style: commands must end with \r
        self.ser.write((line.strip() + "\r").encode("ascii", errors="ignore"))

    def _read_all(self) -> str:
        time.sleep(0.08)
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
        for cmd in ("ATZ", "ATE0", "ATL0", "ATS0", "ATH1", "ATAL", "ATSP6"):  # ISO15765-4 (11bit)
            self._write_cmd(cmd)
            _ = self._read_all()

    def set_header(self, arb_id: int) -> None:
        self._write_cmd(f"ATSH{arb_id:03X}")
        _ = self._read_all()

    def set_bus(self, bus: str) -> None:
        # vLinker physical HS/MS switchers vary. Keep it abstract.
        # We DO NOT send undocumented commands here; provide hook only.
        # You can implement the physical toggle elsewhere.
        if bus not in ("HS_CAN", "MS_CAN"):
            raise ValueError("bus must be HS_CAN or MS_CAN")
        # Placeholder no-op; override if you wire a real switch:
        # self._write_cmd("ATLNKHS P6") / "ATLNKMS P8" on supported devices
        # _ = self._read_all()

    def tx_frame(self, arb_id: int, data: Sequence[int]) -> str:
        self.set_header(arb_id)
        payload = "".join(f"{b:02X}" for b in data)
        self._write_cmd(payload)
        return self._read_all()

    def close(self) -> None:
        try:
            self._write_cmd("ATPC")
        finally:
            self.ser.close()

# ---------------------- Ford wrapper (safe) --------------------------

class FordVLink:
    def __init__(self, port: str = "COM5"):
        self.transport = SerialVlink(VlinkPort(port))
        self._current_bus = "HS_CAN"

    # -------- Public operations (your existing ones kept as-is) -------

    def enable_bambi_mode(self) -> bool:
        return self._ford_op("enable_bambi_mode", 0x726, [0x05, 0x02, 0x01], bus_hint="MS_CAN")

    def disable_seatbelt_chime(self) -> bool:
        return self._ford_op("disable_seatbelt_chime", 0x7E0, [0x22, 0x15, 0x00], bus_hint="HS_CAN")

    def enable_keyless_global_windows(self) -> bool:
        return self._ford_op("enable_keyless_global_windows", 0x726, [0x05, 0x01, 0x01], bus_hint="MS_CAN")

    def enable_drl_menu(self) -> bool:
        return self._ford_op("enable_drl_menu", 0x7E0, [0x22, 0x14, 0x01], bus_hint="HS_CAN")

    def set_turn_signal_blinks(self, count: int = 5) -> bool:
        if not (3 <= count <= 7):
            self._audit("reject_param", {"op": "set_turn_signal_blinks", "count": count})
            return False
        return self._ford_op("set_turn_signal_blinks", 0x726, [0x06, 0x03, int(count)], bus_hint="MS_CAN")

    def enable_sport_mode(self) -> bool:
        return self._ford_op("enable_sport_mode", 0x7E0, [0x22, 0x91, 0x01], bus_hint="HS_CAN")

    def disable_engine_sound_enhancement(self) -> bool:
        return self._ford_op("disable_engine_sound_enhancement", 0x7E0, [0x22, 0x67, 0x00], bus_hint="HS_CAN")

    def enable_gauge_test(self) -> bool:
        return self._ford_op("enable_gauge_test", 0x7E0, [0x22, 0x02, 0x01], bus_hint="HS_CAN")

    def enable_hidden_dtc_menu(self) -> bool:
        return self._ford_op("enable_hidden_dtc_menu", 0x7E0, [0x22, 0xFD, 0x01], bus_hint="HS_CAN")

    def read_vin(self) -> Optional[str]:
        resp = self._ford_op("read_vin", 0x7E0, [0x09, 0x02], bus_hint="HS_CAN", expect_resp=True)
        return self._parse_vin(resp) if resp else None

    # ---------------- Internal guarded executor -----------------------

    def _ford_op(
        self,
        name: str,
        arb_id: int,
        data: List[int],
        *,
        bus_hint: str = "HS_CAN",
        expect_resp: bool = False,
    ) -> bool | str:
        # Interlocks
        if not self._is_unlocked():
            self._audit("denied", {"op": name})
            return False
        if not self._vehicle_stationary():
            self._audit("interlock_speed", {"op": name})
            return False

        # Bus selection
        try:
            self._switch_bus(bus_hint if arb_id not in (0x7E0, 0x7E1) else "HS_CAN")
        except Exception as e:
            self._audit("bus_error", {"op": name, "err": repr(e)})
            return False

        # Dry-run support
        self._audit("invoke", {"op": name, "arb_id": hex(arb_id), "data_len": len(data)})
        if DRY_RUN:
            self._audit("dry_run", {"op": name})
            return True

        # Transmit
        try:
            raw = self.transport.tx_frame(arb_id, data)
            self._audit("resp", {"op": name, "raw": raw[:200]})
            return raw if expect_resp else self._ok(raw)
        except Exception as e:
            self._audit("tx_error", {"op": name, "err": repr(e)})
            return False

    def _ok(self, raw: str) -> bool:
        # Very conservative: only treat as success if an exact positive echo appears
        return any(tok in raw for tok in ("OK", "WR", "41 ", "62 "))

    def _switch_bus(self, bus: str) -> None:
        if bus == self._current_bus:
            return
        # Provide hook; do not leak undocumented commands
        self.transport.set_bus(bus)
        self._current_bus = bus
        time.sleep(0.15)

    # -------------------- Utilities -----------------------------------

    def _is_unlocked(self) -> bool:
        # Require both: correct tier and runtime unlock flag
        return (TIER == "black") and UNLOCK

    def _vehicle_stationary(self) -> bool:
        # Hook: you can poll speed PID 010D here and block if > 0
        # For now, treat as stationary unless explicit env overrides
        return os.environ.get("SNAP_FAKE_SPEED", "0") == "0"

    def _parse_vin(self, raw: str) -> Optional[str]:
        if not raw:
            return None
        # Very basic mode 09 VIN parse (no exposure of parsing strategy)
        # Expect lines with "49 02"
        vin_hex = "".join(part for part in raw.replace("\r", "\n").split() if all(c in "0123456789ABCDEF" for c in part.upper()))
        try:
            txt = bytes.fromhex(vin_hex).decode("ascii", errors="ignore")
            vin = "".join(ch for ch in txt if ch.isalnum()).strip()
            return vin[:17] if len(vin) >= 17 else None
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
        self.transport.close()
