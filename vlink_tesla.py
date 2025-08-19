# ------------------------------------------------------------------
#  vlink_tesla.py  –  Enhanced Tesla & SAE PID reader
# ------------------------------------------------------------------
from __future__ import annotations
import os
import time
import csv
import threading
import logging
from typing import Dict, Callable, Tuple, Optional, List

import serial

# ------------------------------------------------------------------
#  Logging
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s – %(levelname)s – %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("VLinkerTesla")

# ------------------------------------------------------------------
#  Serial Layer
# ------------------------------------------------------------------
class RawAdapter:
    def __init__(self, port: str, baud: int = 115200, timeout: float = 1.0) -> None:
        self.ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.5)
        self._cmd("ATZ", wait=1)

    def _cmd(self, cmd: str, wait: float = 0.2) -> List[str]:
        self.ser.write((cmd + "\r").encode())
        time.sleep(wait)
        lines = []
        while self.ser.in_waiting:
            line = self.ser.readline().decode(errors="ignore").strip()
            if line and not line.startswith(">"):
                lines.append(line.upper())
        return lines

    def query(self, pid: str) -> List[str]:
        return self._cmd(pid, wait=0.5)

    def send_raw(self, cmd: str) -> List[str]:
        return self._cmd(cmd)

    def close(self) -> None:
        self.ser.close()

# ------------------------------------------------------------------
#  PID Maps
# ------------------------------------------------------------------
SAE_PID_MAP: Dict[str, Tuple[str, Callable[[str], float]]] = {
    "rpm": ("010C", lambda h: int(h[:4], 16) / 4),
    "speed": ("010D", lambda h: int(h[:2], 16)),
    "coolant": ("0105", lambda h: int(h[:2], 16) - 40),
    "throttle": ("0111", lambda h: int(h[:2], 16) * 100 / 255),
}

TESLA_PID_MAP: Dict[str, Tuple[str, Callable[[str], float]]] = {
    "battery_voltage": ("019A", lambda h: int(h[:8], 16) / 1000),     # 4-byte little-endian mV → V
    "battery_current": ("01A3", lambda h: (int(h[:8], 16) - 2**31) / 1000),  # mA → A (signed)
    "soc": ("01A7", lambda h: int(h[:8], 16) / 100),                 # 0.01 % → %
    "power_kw": ("01A4", lambda h: int(h[:8], 16) / 1000),           # 0.1 kW → kW
    "torque_nm": ("01A6", lambda h: (int(h[:8], 16) - 2**31) / 2),   # 0.5 N·m → N·m (signed)
    "motor_rpm": ("019B", lambda h: int(h[:4], 16)),                 # raw RPM
    "motor_temp": ("019C", lambda h: int(h[:2], 16) - 40),           # °C
}

ALL_PID_MAP = {**SAE_PID_MAP, **TESLA_PID_MAP}

# ------------------------------------------------------------------
#  Main Class
# ------------------------------------------------------------------
class VLinkerTesla:
    def __init__(
        self,
        port: str,
        log_dir: str = "tesla_logs",
        headers: List[str] | None = None,
    ) -> None:
        self.raw = RawAdapter(port)
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.session_id = int(time.time())
        self.headers = headers or ["ATSP6", "ATSH7E0", "ATAL"]
        self._thread: Optional[threading.Thread] = None

    def init_headers(self) -> None:
        for cmd in self.headers:
            self.raw.send_raw(cmd)
            log.debug("Sent %s", cmd)

    # ----------------------------------------------------------
    def live_snapshot(self) -> Dict[str, Optional[float]]:
        snap: Dict[str, Optional[float]] = {}
        for name, (pid, conv) in ALL_PID_MAP.items():
            try:
                resp = self.raw.query(pid)
                prefix = "41" if name in SAE_PID_MAP else "7E8"
                if resp and len(resp) > 0 and resp[0].startswith(prefix):
                    hex_val = "".join(resp[0].split()[2:])
                    snap[name] = conv(hex_val)
                else:
                    snap[name] = None
            except Exception as ex:
                log.warning("PID %s failed: %s", pid, ex)
                snap[name] = None
        return snap

    # ----------------------------------------------------------
    def start_live_data(
        self,
        fields: List[str],
        interval: float = 1.0,
        alerts: Optional[List[Tuple[str, Callable[[float], bool], str]]] = None,
        to_csv: bool = True,
        print_output: bool = True,
    ) -> threading.Event:
        stop_event = threading.Event()
        filename = os.path.join(self.log_dir, f"{self.session_id}.csv")
        writer = None

        # Validate requested fields
        invalid = set(fields) - set(ALL_PID_MAP.keys())
        if invalid:
            raise ValueError(f"Unknown fields: {invalid}")

        def worker() -> None:
            nonlocal writer
            self.init_headers()
            if to_csv:
                f = open(filename, "w", newline="")
                writer = csv.DictWriter(f, fieldnames=["timestamp"] + fields)
                writer.writeheader()

            while not stop_event.is_set():
                snap = self.live_snapshot()
                row = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
                for f in fields:
                    row[f] = snap.get(f)

                if writer:
                    writer.writerow(row)
                    f.flush()
                if print_output:
                    log.info(row)

                # Alerts
                if alerts:
                    for field, cond, msg in alerts:
                        val = row.get(field)
                        if val is not None and cond(val):
                            log.warning("⚠️  ALERT: %s → %s", msg, val)

                time.sleep(interval)

            if writer:
                f.close()
                log.info("Log saved to %s", filename)

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()
        return stop_event

    # ----------------------------------------------------------
    def close(self) -> None:
        self.raw.close()

# ------------------------------------------------------------------
#  Demo
# ------------------------------------------------------------------
if __name__ == "__main__":
    vl = VLinkerTesla("COM5")
    try:
        stop = vl.start_live_data(
            fields=["battery_voltage", "soc", "power_kw", "motor_rpm", "motor_temp"],
            interval=1.0,
            alerts=[
                ("soc", lambda s: s < 10, "Battery low"),
                ("motor_temp", lambda t: t > 100, "Motor overheating"),
            ],
        )
        input("Press ENTER to stop logging...\n")
    finally:
        stop.set()
        vl.close()


