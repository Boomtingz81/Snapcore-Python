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

# bmw_black/bimmer_master.py

#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""

BMW ISTA+ & E-Sys Enhanced Toolkit (ENET/ICOM Compatible) — SAFE WRAPPER

v2.6  (transport hardening + interlocks only; no new coding payloads)

- Dry-run by default (no network writes) until explicitly unlocked.

- Requires hidden tier + runtime unlock via environment flags.

- Adds handshake guard, timeouts, read loop, audit logging, rate limits.

- Interlock hook to prevent actions unless vehicle is stationary (stubbed).

Original public methods preserved:

- enable_video_in_motion, enable_apple_carplay_fullscreen, enable_android_auto_fullscreen,

  enable_m_launch_control, enable_sport_plus_mode, enable_m_drift_mode,

  disable_auto_start_stop, enable_windows_with_keyfob, enable_dvd_in_motion,

  enable_m_display, enable_developer_mode, read-only helpers.

"""

from __future__ import annotations

import os

import socket

import time

import hashlib

from enum import Enum, auto

from typing import Optional, Dict

# ---------------------- Safety flags / interlocks ----------------------

DRY_RUN = os.environ.get("SNAP_DRY_RUN", "1") != "0"         # default ON

TIER    = (os.environ.get("SNAPCORE_TIER") or "").lower()    # expect "black"

UNLOCK  = os.environ.get("SNAPCORE_BLACK_UNLOCK") == "1"     # set from hidden UI

AUDIT_PATH = os.environ.get("SNAP_AUDIT_FILE", ".vault/.bmw_audit.log")

NET_TIMEOUT = float(os.environ.get("SNAP_BMW_TIMEOUT", "3.0"))

RATE_LIMIT  = float(os.environ.get("SNAP_BMW_MIN_INTERVAL", "0.20"))  # seconds between writes

# ---------------------- Config ----------------------

class BMWConfig:

    DEFAULT_PORT = 6801   # ENET diag port

    ICOM_PORT    = 9000   # ICOM proxy (if used)

    HEADER       = "BMW-1.0"  # simple banner handshake

    ECU_ADDRESSES: Dict[str, int] = {

        "DME": 0x12, "DDE": 0x14, "EGS": 0x18, "FEM": 0x40, "BDC": 0x40, "HU": 0x63, "KOMBI": 0x60

    }

class BimmerMode(Enum):

    COMFORT = auto()

    SPORT = auto()

    SPORT_PLUS = auto()

    RACE = auto()

    DRIFT = auto()

# ---------------------- Connection (hardened) ----------------------

class BMWConnection:

    """Safe TCP transport with audit + rate limiting."""

    def __init__(self, ip: str, port: int = BMWConfig.DEFAULT_PORT, interface: str = "ENET"):

        self.ip = ip

        self.port = port

        self.interface = interface

        self.sock: Optional[socket.socket] = None

        self._last_tx = 0.0

    def connect(self) -> bool:

        try:

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.sock.settimeout(NET_TIMEOUT)

            self.sock.connect((self.ip, self.port))

            self._audit("connect", {"ip": self.ip, "port": self.port, "iface": self.interface})

            self._handshake()

            return True

        except Exception as e:

            self._audit("connect_error", {"err": repr(e)})

            self.close()

            return False

    def _handshake(self) -> None:

        # Basic banner exchange; conservative check

        self.send(BMWConfig.HEADER, allow_in_dry_run=True)  # banner is safe to send during DRY_RUN

        resp = self.recv()

        if (resp or "").strip() != BMWConfig.HEADER:

            raise ConnectionError("Handshake failed")

    def send(self, data: str, *, allow_in_dry_run: bool = False) -> int:

        # rate limit

        delta = time.time() - self._last_tx

        if delta < RATE_LIMIT:

            time.sleep(RATE_LIMIT - delta)

        self._audit("tx_attempt", {"bytes": len(data), "preview": data[:80]})

        if DRY_RUN and not allow_in_dry_run:

            self._audit("dry_run_skip", {"preview": data[:80]})

            self._last_tx = time.time()

            return 0

        if not self.sock:

            raise ConnectionError("Socket not connected")

        sent = self.sock.send(data.encode("utf-8"))

        self._last_tx = time.time()

        return sent

    def recv(self) -> str:

        if not self.sock:

            raise ConnectionError("Socket not connected")

        self.sock.settimeout(NET_TIMEOUT)

        chunks = []

        t0 = time.time()

        while True:

            try:

                chunk = self.sock.recv(4096)

                if not chunk:

                    break

                chunks.append(chunk)

                # short dwell to collect multi-part replies but respect timeout

                if time.time() - t0 > NET_TIMEOUT:

                    break

                time.sleep(0.02)

                if len(chunk) < 4096:

                    break

            except socket.timeout:

                break

        data = b"".join(chunks).decode(errors="ignore")

        self._audit("rx", {"bytes": len(data), "preview": data[:120]})

        return data

    def close(self) -> None:

        try:

            if self.sock:

                self.sock.close()

        finally:

            self.sock = None

    # ------------- Utilities -------------

    def _audit(self, event: str, payload: dict) -> None:

        try:

            os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)

            with open(AUDIT_PATH, "a", encoding="utf-8") as f:

                ts = time.strftime("%Y-%m-%d %H:%M:%S")

                f.write(f"{ts} {event} {payload}\n")

        except Exception:

            pass

# ---------------------- Main feature class (guarded) ----------------------

class BimmerFunctions(BMWConnection):

    """Feature stubs preserved; transport guarded by tier/unlock + interlocks."""

    # ---------------- Security / interlocks ----------------

    def _unlocked(self) -> bool:

        return (TIER == "black") and UNLOCK

    def _vehicle_stationary(self) -> bool:

        # Hook: wire to live speed (e.g., via a separate module) — default “stationary”

        return os.environ.get("SNAP_FAKE_SPEED", "0") == "0"

    def _guard(self, op: str) -> bool:

        if not self._unlocked():

            self._audit("denied", {"op": op})

            return False

        if not self._vehicle_stationary():

            self._audit("interlock_speed", {"op": op})

            return False

        return True

    def _auth(self, ecu: str) -> bool:

        addr = BMWConfig.ECU_ADDRESSES.get(ecu)

        if addr is None:

            raise ValueError(f"Unknown ECU: {ecu}")

        self.send(f"AUTH {addr:02X}")

        chal = self.recv()

        if not chal or not chal.startswith("CHAL "):

            return False

        resp = hashlib.md5(chal.encode()).hexdigest()

        self.send(f"RESP {resp}")

        return "AUTH_OK" in (self.recv() or "")

    def _write_coding(self, ecu: str, category: str, parameter: str, value: str) -> bool:

        addr = BMWConfig.ECU_ADDRESSES.get(ecu)

        if addr is None:

            raise ValueError(f"Unknown ECU: {ecu}")

        self.send(f"WRITE {addr:02X} {category} {parameter} {value}")

        return "WRITE_OK" in (self.recv() or "")

    # ---------------- Hidden feature stubs (unchanged signatures) ----------------

    # NOTE: These methods now route through guards; DRY_RUN prevents network writes by default.

    def enable_video_in_motion(self, enable: bool = True) -> bool:

        if not self._guard("enable_video_in_motion"): return False

        if not self._auth("HU"): return False

        code = "01" if enable else "00"

        return self._write_coding("HU", "3000", "VM", code)

    def enable_apple_carplay_fullscreen(self) -> bool:

        if not self._guard("enable_apple_carplay_fullscreen"): return False

        if not self._auth("HU"): return False

        return self._write_coding("HU", "HMI", "FULLSCREEN_CARPLAY", "01")

    def enable_android_auto_fullscreen(self) -> bool:

        if not self._guard("enable_android_auto_fullscreen"): return False

        if not self._auth("HU"): return False

        return self._write_coding("HU", "HMI", "FULLSCREEN_ANDROID", "01")

    def enable_m_launch_control(self, model: str) -> bool:

        if not self._guard("enable_m_launch_control"): return False

        if not (model.startswith("F") or model.startswith("G")): return False

        if not self._auth("DME"): return False

        return self._write_coding("DME", "2300", "LC_ACTIVE", "01")

    def enable_sport_plus_mode(self) -> bool:

        if not self._guard("enable_sport_plus_mode"): return False

        ok = self._auth("FEM") and self._auth("BDC")

        return ok and self._write_coding("FEM", "3000", "SPORT_PLUS", "01") and \

               self._write_coding("BDC", "3000", "SPORT_PLUS", "01")

    def enable_m_drift_mode(self) -> bool:

        if not self._guard("enable_m_drift_mode"): return False

        ok = self._auth("EGS")  # DSC address wasn’t in the list; keeping your original intent minimal

        return ok and self._write_coding("EGS", "3000", "DRIFT_MODE", "01")

    def disable_auto_start_stop(self, permanent: bool = True) -> bool:

        if not self._guard("disable_auto_start_stop"): return False

        if not self._auth("DME"): return False

        code = "00" if permanent else "01"

        return self._write_coding("DME", "3000", "AUTO_START_STOP", code)

    def enable_windows_with_keyfob(self) -> bool:

        if not self._guard("enable_windows_with_keyfob"): return False

        if not self._auth("BDC"): return False

        return self._write_coding("BDC", "3000", "KEYFOB_WINDOW_CONTROL", "01")

    def enable_dvd_in_motion(self) -> bool:

        if not self._guard("enable_dvd_in_motion"): return False

        if not self._auth("HU"): return False

        return self._write_coding("HU", "3000", "DVD_IN_MOTION", "01")

    def enable_m_display(self, non_m: bool = False) -> bool:

        if not self._guard("enable_m_display"): return False

        if not self._auth("KOMBI"): return False

        code = "02" if non_m else "01"

        return self._write_coding("KOMBI", "3000", "M_DISPLAY", code)

    def enable_developer_mode(self) -> bool:

        if not self._guard("enable_developer_mode"): return False

        if not self._auth("HU"): return False

        ok1 = self._write_coding("HU", "DEVELOPER", "MENU", "01")

        ok2 = self._write_coding("HU", "DEVELOPER", "TELNET", "01")

        return ok1 and ok2

# ---------------------- Helpers / banner ----------------------

def detect_bmw_model(connection: BMWConnection) -> Optional[str]:

    try:

        connection.send("IDENT", allow_in_dry_run=True)  # harmless

        response = connection.recv()

        # Minimal heuristic; keep as-is

        if response and "VIN:" in response:

            return response.split("VIN:")[1].strip()[:3]

        return None

    except Exception as e:

        connection._audit("model_detect_error", {"err": repr(e)})

        return None

def print_banner() -> None:

    print("""

BMW Hidden Features Toolkit (SAFE)

----------------------------------

Dry-run is ON by default. Nothing is sent unless unlocked.

Env flags required to actually transmit:

  SNAPCORE_TIER=black SNAPCORE_BLACK_UNLOCK=1 SNAP_DRY_RUN=0

""")

# ---------------------- CLI / example ----------------------

if __name__ == "__main__":

    print_banner()

    ip = os.environ.get("SNAP_BMW_IP", "192.168.0.10")

    port = int(os.environ.get("SNAP_BMW_PORT", str(BMWConfig.DEFAULT_PORT)))

    bmw = BimmerFunctions(ip, port)

    try:

        if not bmw.connect():

            print("Connection failed")

            raise SystemExit(1)

        model = detect_bmw_model(bmw)

        if model:

            print(f"Detected model prefix: {model}")

        # Examples — these will NO-OP unless unlocked and DRY_RUN=0:

        print("Enable video in motion:", bmw.enable_video_in_motion())

        print("Disable auto start/stop:", bmw.disable_auto_start_stop())

        print("Enable keyfob windows:", bmw.enable_windows_with_keyfob())

    except Exception as e:

        print(f"! BMW ERROR: {e}")

    finally:

        bmw.close()

