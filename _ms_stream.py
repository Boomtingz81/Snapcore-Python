#!/usr/bin/env python3
"""
Enhanced vLinker MS / ELM327 live-data reader & VIN grabber
"""
import serial, time, json, sys, argparse
from datetime import datetime
from typing import List, Optional

# ---------- CONFIG ----------
DEFAULT_PORT  = "COM5"
DEFAULT_BAUD  = 115200
DEFAULT_PIDS  = ["010C", "010D", "0105"]   # RPM, Speed, Coolant Temp
STREAM_DELAY  = 1.0
# ----------------------------

class VLinker:
    def __init__(self, port: str, baud: int = 115200, timeout: float = 1.0):
        self.ser = serial.Serial(port, baud, timeout=timeout)
        self.ser.flush()
        time.sleep(0.5)

    # --- low-level ----------------------------------------------------------
    def _cmd(self, cmd: str, wait: float = 0.2) -> List[str]:
        """Send command and return non-empty, non-prompt lines."""
        self.ser.write((cmd + "\r").encode())
        time.sleep(wait)
        lines = []
        while self.ser.in_waiting:
            line = self.ser.readline().decode(errors="ignore").strip()
            if line and not line.startswith(">"):
                lines.append(line.upper())
        return lines

    def init(self) -> bool:
        """Basic ELM327 initialisation."""
        self._cmd("ATZ", wait=1.0)            # Reset
        for c in ("ATE0", "ATL0", "ATS0", "ATAL"):
            if not self._cmd(c) or "OK" not in self._cmd(c)[-1]:
                return False
        # Auto-detect protocol (STN-type)
        self._cmd("ATSP0")                    # Auto protocol
        self._cmd("ATST32")                   # 50 ms timeout
        return True

    # --- high-level ---------------------------------------------------------
    def vin(self) -> Optional[str]:
        """Try ISO-TP Mode $09 PID 0x02 for VIN."""
        lines = self._cmd("0902", wait=1.0)
        if any("NO DATA" in l for l in lines):
            return None
        hex_str = "".join("".join(l.split()[2:]) for l in lines if l.startswith("49 02"))
        try:
            return bytes.fromhex(hex_str).decode("ascii", errors="ignore").strip()
        except Exception:
            return None

    def pid(self, pid: str) -> Optional[str]:
        """Return raw hex payload for a PID (single frame)."""
        lines = self._cmd(pid)
        if not lines or "NO DATA" in lines[0]:
            return None
        # Expect 41 xx ...  (mode 0x41 = response to mode 0x01)
        line = lines[0]
        if not line.startswith("41"):
            return None
        parts = line.split()
        return "".join(parts[2:]) if len(parts) >= 3 else None


# ---------- Parsers ----------
def parse_rpm(hex_str: str) -> Optional[int]:
    try:
        a, b = int(hex_str[:2], 16), int(hex_str[2:4], 16)
        return (a * 256 + b) // 4
    except Exception:
        return None

def parse_speed(hex_str: str) -> Optional[int]:
    try:
        return int(hex_str[:2], 16)
    except Exception:
        return None

def parse_temp(hex_str: str) -> Optional[int]:
    try:
        return int(hex_str[:2], 16) - 40
    except Exception:
        return None


# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", default=DEFAULT_PORT, help="Serial port")
    ap.add_argument("-b", "--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("-d", "--debug", action="store_true", help="Show raw I/O")
    args = ap.parse_args()

    try:
        print("🔄 Initialising vLinker MS...")
        elm = VLinker(args.port, args.baud)
        if not elm.init():
            print("❌ Initialisation failed")
            return

        print("📡 Reading VIN...")
        vin = elm.vin()
        print(f"✅ VIN: {vin or 'N/A'}")

        print("📊 Streaming live data (Ctrl+C to stop)...")
        parsers = {
            "010C": parse_rpm,
            "010D": parse_speed,
            "0105": parse_temp,
        }
        keys = {"010C": "rpm", "010D": "speed_kph", "0105": "coolant_temp_c"}

        while True:
            data = {"timestamp": datetime.utcnow().isoformat(), "vin": vin}
            for pid in DEFAULT_PIDS:
                raw = elm.pid(pid)
                val = parsers[pid](raw) if raw else None
                data[keys[pid]] = val
            print(json.dumps(data))
            time.sleep(STREAM_DELAY)

    except serial.SerialException as e:
        sys.stderr.write(f"❌ Serial error: {e}\n")
    except KeyboardInterrupt:
        print("\n⏹ Streaming stopped.")

if __name__ == "__main__":
    main()





