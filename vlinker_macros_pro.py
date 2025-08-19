"""
vlinker_macros_pro.py
A clean-room re-implementation of the VLinker “pro” command set.
Python ≥3.8
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import serial

# ---------- Low-level serial wrapper ---------------------------------

class RawAdapter:
    """
    Talks to the ELM327-compatible adapter at the lowest possible level.
    Only ELM327 AT/ST/VT commands should be sent through this class.
    """

    def __init__(self, port: str, baud: int = 115200, timeout: float = 1.0) -> None:
        self.ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.5)
        self._cmd("ATZ", wait=1)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _cmd(self, cmd: str, wait: float = 0.2) -> List[str]:
        """Send a command and return the unprompted response lines."""
        self.ser.write((cmd + "\r").encode())
        time.sleep(wait)

        lines: List[str] = []
        while self.ser.in_waiting:
            line = self.ser.readline().decode(errors="ignore").strip()
            if line and not line.startswith(">"):
                lines.append(line.upper())
        return lines

    # ------------------------------------------------------------------
    # Basic setup
    # ------------------------------------------------------------------
    def init_obd(self) -> None:
        for c in ("ATE0", "ATL0", "ATS0", "ATAL"):
            self._cmd(c)

    # ------------------------------------------------------------------
    # Thin wrappers
    # ------------------------------------------------------------------
    def query(self, pid: str) -> List[str]:
        return self._cmd(pid, wait=0.5)

    def send_raw(self, cmd: str) -> List[str]:
        return self._cmd(cmd)

    def close(self) -> None:
        self.ser.close()


# ---------- Macro layer ----------------------------------------------

class VLinkerMacros:
    """
    High-level convenience functions built on top of RawAdapter.
    """

    PID_MAP: Dict[str, Tuple[str, Callable[[str], float]]] = {
        "rpm":         ("010C", lambda h: int(h[:4], 16) // 4),
        "speed":       ("010D", lambda h: int(h[:2], 16)),
        "coolant":     ("0105", lambda h: int(h[:2], 16) - 40),
        "throttle":    ("0111", lambda h: int(h[:2], 16) * 100 / 255),
        "maf":         ("0110", lambda h: int(h[:4], 16) / 100),
        "fuel_level":  ("2F05", lambda h: int(h[:2], 16) * 100 / 255),
        "engine_load": ("0104", lambda h: int(h[:2], 16) * 100 / 255),
        "intake_temp": ("010F", lambda h: int(h[:2], 16) - 40),
        "fuel_trim":   ("0106", lambda h: (int(h[:2], 16) - 128) * 100 / 128),
    }

    def __init__(self, port: str) -> None:
        self.raw = RawAdapter(port)
        self.raw.init_obd()
        self._thread: Optional[threading.Thread] = None

    # --------------------------------------------------------------
    # VIN
    # --------------------------------------------------------------
    def read_vin(self) -> str:
        """Return the 17-character VIN or an empty string on failure."""
        lines = self.raw.query("0902")
        vin_hex = "".join("".join(line.split()[2:]) for line in lines if line.startswith("49 02"))
        try:
            return bytes.fromhex(vin_hex).decode("ascii", errors="ignore").strip()
        except Exception:
            return ""

    # --------------------------------------------------------------
    # DTCs
    # --------------------------------------------------------------
    def read_dtcs(self) -> List[str]:
        """Return a list of 5-character DTCs (e.g. P0123)."""
        lines = self.raw.query("03")
        dtc_hex = "".join("".join(line.split()[2:]) for line in lines if line.startswith("43"))
        if not dtc_hex or len(dtc_hex) % 4:
            return []

        codes: List[str] = []
        for i in range(0, len(dtc_hex), 4):
            codes.append(dtc_hex[i:i + 4].upper())
        return codes

    def clear_dtcs(self) -> bool:
        """Return True if DTCs were cleared successfully."""
        resp = self.raw.query("04")
        return any(line == "44" for line in resp)

    # --------------------------------------------------------------
    # Live data helpers
    # --------------------------------------------------------------
    def live_snapshot(self) -> Dict[str, Optional[float]]:
        """Return a dict with the latest values for all known PIDs."""
        snapshot: Dict[str, Optional[float]] = {}
        for name, (pid, conv) in self.PID_MAP.items():
            resp = self.raw.query(pid)
            if resp and resp[0].startswith("41"):
                hex_val = "".join(resp[0].split()[2:])
                try:
                    snapshot[name] = conv(hex_val)
                except Exception:
                    snapshot[name] = None
            else:
                snapshot[name] = None
        return snapshot

    def start_live_data(
        self,
        fields: List[str],
        csv_file: Optional[str] = None,
        interval: float = 1.0,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> threading.Event:
        """
        Start a background thread that polls requested <fields> every <interval> seconds.
        Returns a threading.Event which you can .set() to stop the thread.
        """
        stop_event = threading.Event()

        def worker() -> None:
            writer: Optional[csv.DictWriter[str]] = None
            f: Any = None
            if csv_file:
                f = open(csv_file, "w", newline="")
                writer = csv.DictWriter(f, fieldnames=["timestamp", *fields])
                writer.writeheader()

            while not stop_event.is_set():
                snap = self.live_snapshot()
                snap["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                if writer:
                    writer.writerow({k: snap.get(k) for k in ["timestamp", *fields]})
                    f.flush()
                if callback:
                    callback(snap)
                time.sleep(interval)

            if f:
                f.close()

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()
        return stop_event

    # --------------------------------------------------------------
    # CAN bus switching
    # --------------------------------------------------------------
    def switch_to_can_bus(self, bus_type: str) -> None:
        """Switch between HS-CAN and MS-CAN."""
        if bus_type.upper() == "HS":
            self.raw.send_raw("ATLNKHS P6")
        elif bus_type.upper() == "MS":
            self.raw.send_raw("ATLNKMS P8")
        else:
            raise ValueError("bus_type must be 'HS' or 'MS'")

    def try_dual_bus(self) -> str:
        """
        Try HS first, fall back to MS.  Return the bus that worked.
        Raises RuntimeError if neither bus is active.
        """
        for bus in ("HS", "MS"):
            try:
                self.switch_to_can_bus(bus)
                # quick sanity check: ask for RPM
                self.raw.query("010C")
                return bus
            except Exception:
                pass
        raise RuntimeError("No active CAN bus detected")

    # --------------------------------------------------------------
    # Power management (wake-up) helpers
    # --------------------------------------------------------------
    def enable_wake_up(self, bus_type: str, enabled: bool) -> None:
        if bus_type.upper() == "HS":
            if enabled:
                self.raw.send_raw("VTCAN_WM 1,101,7DF,013E000000000000,64,2")
            else:
                self.raw.send_raw("VTDEL_CAN_WM 1")
        elif bus_type.upper() == "MS":
            if enabled:
                self.raw.send_raw("VTISO_WM 1,103,C133F1,3E00,64,1")
            else:
                self.raw.send_raw("VTDEL_ISO_WM 1")
        else:
            raise ValueError("bus_type must be 'HS' or 'MS'")

    # --------------------------------------------------------------
    # Secure logging helpers
    # --------------------------------------------------------------
    @staticmethod
    def finalize_log(csv_file: str, private_key: str) -> None:
        """Create a SHA-256 HMAC signature file (*.sig) for <csv_file>."""
        csv_path = Path(csv_file)
        if not csv_path.exists():
            raise FileNotFoundError(csv_path)

        with csv_path.open("rb") as f:
            data = f.read()

        sig = hmac.new(private_key.encode(), data, hashlib.sha256).hexdigest()
        csv_path.with_suffix(csv_path.suffix + ".sig").write_text(sig)

    @staticmethod
    def alert_if(
        field: str,
        condition: Callable[[float], bool],
        message: str,
    ) -> Callable[[Dict[str, Any]], None]:
        """
        Factory that returns a callback suitable for start_live_data().
        The callback prints an alert when <condition> is True for <field>.
        """

        def _cb(data: Dict[str, Any]) -> None:
            val = data.get(field)
            if val is not None and condition(val):
                print(f"⚠️  ALERT: {message} → {val}")

        return _cb

    # --------------------------------------------------------------
    # House-keeping
    # --------------------------------------------------------------
    def close(self) -> None:
        self.raw.close()


# ---------------------- Example usage ---------------------------------
if __name__ == "__main__":
    import time

    vl = VLinkerMacros("COM5")

    print("VIN :", vl.read_vin())
    print("DTCs:", vl.read_dtcs())

    # Uncomment to clear DTCs
    # print("DTC clear:", vl.clear_dtcs())

    # Decide which bus to use
    bus = vl.try_dual_bus()
    print("Active bus:", bus)

    # Start secure live capture
    stop = vl.start_live_data(
        ["rpm", "speed", "coolant"],
        csv_file="drive.csv",
        callback=vl.alert_if("rpm", lambda r: r > 4000, "Over-rev detected"),
    )

    time.sleep(10)
    stop.set()
    vl.finalize_log("drive.csv", private_key="my-secret-key")
    vl.close()

