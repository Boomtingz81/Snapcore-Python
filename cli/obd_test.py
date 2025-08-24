#!/usr/bin/env python3
# File: cli/obd_test.py
"""
Snapcore-Python — Enhanced Live Data Poller (Mode 01)

Features
- Robust shared ELM init (snapcore.elm_init.initialize_adapter), safe fallback if missing
- Polls one or more Mode 01 PIDs in a loop (RPM, Speed, Coolant, etc.)
- Optional CSV logging with basic size-based rotation
- Optional raw frame printing and ELM headers
- PID list defaults to config.LIVE_PIDS; override with --pid
- Simple formula-based decoders for common PIDs
- Optional ASCII "chart" view for one PID
- Automatic supported-PID discovery via 0100/0120/0140/0160 bitmaps

Examples:
  python -m cli.obd_test list
  python -m cli.obd_test run --port COM5 --baud 500000
  python -m cli.obd_test run --pid 010C --pid 010D --hz 2 --csv logs/live.csv
  python -m cli.obd_test run --raw --headers
  python -m cli.obd_test run --pid 010C --display chart --window 40
  python -m cli.obd_test info --pid 010C
  python -m cli.obd_test discover
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import signal
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---- Defaults from config (fallback if missing) ----
try:
    from config import SERIAL_PORT, BAUD_RATE, LIVE_PIDS
except Exception:
    SERIAL_PORT = "COM5"
    BAUD_RATE = 500000
    LIVE_PIDS = ["010C", "010D", "0105"]

# ---- pyserial (required) ----
try:
    import serial # type: ignore
except ImportError:
    print("ERROR: pyserial is not installed. Run: pip install pyserial", file=sys.stderr)
    sys.exit(1)

# ---- Optional colors (colorama) ----
try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init()
    COK = Fore.GREEN + "✓" + Style.RESET_ALL
    CWARN = Fore.YELLOW + "!" + Style.RESET_ALL
    CERR = Fore.RED + "✗" + Style.RESET_ALL
    CVAL = Fore.CYAN
    CRESET = Style.RESET_ALL
except Exception:
    COK = "✓"
    CWARN = "!"
    CERR = "✗"
    CVAL = ""
    CRESET = ""

# ---- Robust init from shared helper (fallback provided) ----
try:
    from snapcore.elm_init import initialize_adapter as _elm_init
    def initialize_adapter(ser: serial.Serial, *, headers: bool = False) -> bool:
        _elm_init(ser, headers=headers) # raises on hard error
        return True
except Exception:
    def initialize_adapter(ser: serial.Serial, *, headers: bool = False) -> bool:
        """Minimal adapter initialization (fallback)."""
        cmds = [b"ATZ", b"ATE0", b"ATL0", b"ATS0", b"ATSP0"]
        if headers:
            cmds.insert(4, b"ATH1")
        else:
            cmds.insert(4, b"ATH0")
        for c in cmds:
            try:
                if not c.endswith(b"\r"):
                    c += b"\r"
                ser.reset_input_buffer()
                ser.write(c)
                ser.flush()
                time.sleep(0.15)
                _ = ser.read(ser.in_waiting or 1)
            except Exception as e:
                print(f"{CERR} Adapter init failed on {c!r}: {e}", file=sys.stderr)
                return False
        return True

# ------------------------------- Constants -------------------------------
DEFAULT_CMD_DELAY = 0.12
ADAPTER_TIMEOUT = 2.0
RETRIES = 2
MAX_CSV_SIZE_MB = 10 # rotate CSV when exceeding this size

ERROR_RESPONSES = {
    "NO DATA", "STOPPED", "CAN ERROR", "UNABLE", "TIMEOUT",
    "ERROR", "BUS", "?", "BUFFER", "BUSY"
}

# Friendly meta for common Mode 01 PIDs (you can extend freely)
PID_META: Dict[str, Dict[str, str]] = {
    "0100": {"name": "Supported PIDs 01-20", "units": "", "formula": "bitmap"},
    "0120": {"name": "Supported PIDs 21-40", "units": "", "formula": "bitmap"},
    "0140": {"name": "Supported PIDs 41-60", "units": "", "formula": "bitmap"},
    "0160": {"name": "Supported PIDs 61-80", "units": "", "formula": "bitmap"},

    "010C": {"name": "Engine RPM", "units": "rpm", "formula": "(A*256+B)/4"},
    "010D": {"name": "Vehicle Speed", "units": "km/h", "formula": "A"},
    "0105": {"name": "Coolant Temp", "units": "°C", "formula": "A-40"},
    "010F": {"name": "Intake Air Temp", "units": "°C", "formula": "A-40"},
    "010B": {"name": "Intake MAP", "units": "kPa", "formula": "A"},
    "0111": {"name": "Throttle Pos", "units": "%", "formula": "A*100/255"},
    "0110": {"name": "MAF Rate", "units": "g/s", "formula": "(A*256+B)/100"},
    "0142": {"name": "Control Module Voltage", "units": "V", "formula": "(A*256+B)/1000"},
}

# ------------------------------- I/O helpers -------------------------------
def _read_until_prompt(ser: serial.Serial, *, timeout: float) -> str:
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

def write_cmd(ser: serial.Serial, cmd: bytes, delay: float = DEFAULT_CMD_DELAY) -> str:
    """Send a command and collect reply until '>' or timeout."""
    if not cmd.endswith(b"\r"):
        cmd += b"\r"
    try:
        ser.reset_input_buffer()
        ser.write(cmd)
        ser.flush()
        time.sleep(delay)
        return _read_until_prompt(ser, timeout=ser.timeout or ADAPTER_TIMEOUT)
    except serial.SerialException as e:
        return f"ERROR:{e}"

def retry_cmd(ser: serial.Serial, cmd: bytes, delay: float = DEFAULT_CMD_DELAY, retries: int = RETRIES) -> str:
    """Send a command with retry on blank or error-ish responses."""
    raw = ""
    for attempt in range(retries + 1):
        raw = write_cmd(ser, cmd, delay)
        up = raw.upper()
        if raw.strip() and not any(err in up for err in ERROR_RESPONSES):
            break
        if attempt < retries:
            time.sleep(0.1 * (attempt + 1))
    return raw

def clean_hex_stream(s: str) -> List[str]:
    """Normalize adapter text -> list of hex byte tokens."""
    s = s.upper().replace("SEARCHING...", " ")
    s = s.replace("\r", " ").replace("\n", " ").replace(">", " ")
    return re.findall(r"\b[0-9A-F]{2}\b", s)

# ------------------------------- PID decoding -------------------------------
def evaluate_formula(formula: str, data: List[int]) -> Optional[float]:
    """Evaluate a simple PID formula with vars A..D. Special 'bitmap' returns None."""
    try:
        A = data[0] if len(data) > 0 else 0
        B = data[1] if len(data) > 1 else 0
        C = data[2] if len(data) > 2 else 0
        D = data[3] if len(data) > 3 else 0

        if formula == "bitmap":
            return None # handled elsewhere
        # keep eval sandboxed: only A,B,C,D, math ops
        return eval(formula, {"__builtins__": {}}, {"A": A, "B": B, "C": C, "D": D})
    except Exception:
        return None

def parse_bitmap_to_supported(base_pid_hex: int, data: List[int]) -> List[str]:
    """
    Map 4 bytes of bitmap into supported PID strings in the 0x?? window.
    base_pid_hex is the FIRST PID of the 0x?? window (e.g., 0x01 for 0x0100).
    """
    if len(data) < 4:
        return []
    supported: List[str] = []
    # Each bit (MSB first) flags support for PID base..base+31
    for byte_idx, byte_val in enumerate(data[:4]):
        for bit in range(8):
            mask = 1 << (7 - bit) # MSB first
            if byte_val & mask:
                pid_num = base_pid_hex + byte_idx * 8 + bit
                supported.append(f"01{pid_num:02X}")
    return supported

def decode_pid(pid: string, tokens: List[str]) -> Optional[float]: # type: ignore[name-defined]
    """
    Given PID and token stream from adapter (e.g., '41 0C AA BB'),
    return the numeric value if recognized; else None.
    """
    pid = pid.upper()
    if len(pid) != 4 or not pid.startswith("01"):
        return None
    pid_byte = pid[2:]

    # Find first '41 <pid_byte>'
    for i in range(len(tokens) - 2):
        if tokens[i] == "41" and tokens[i + 1] == pid_byte:
            data = [int(x, 16) for x in tokens[i + 2 : i + 6]]
            meta = PID_META.get(pid, {})
            f = meta.get("formula")
            if f:
                val = evaluate_formula(f, data)
                if val is not None:
                    return float(val)

            # Safe fallbacks for a few very common PIDs
            A = data[0] if len(data) > 0 else 0
            B = data[1] if len(data) > 1 else 0
            if pid == "010C": # RPM
                return ((A * 256) + B) / 4.0
            if pid == "010D": # Speed
                return float(A)
            if pid == "0105": # Coolant °C
                return float(A - 40)
            if pid == "010F": # IAT °C
                return float(A - 40)
            if pid == "010B": # MAP
                return float(A)
            if pid == "0111": # Throttle %
                return (100.0 / 255.0) * A

            # As a last resort, show first byte
            return float(A)
    return None

# ------------------------------- Table / Chart output -------------------------------
def _render_table(rows: List[Tuple[str, str, str]]) -> str:
    name_w = max(10, max((len(r[0]) for r in rows), default=10))
    val_w = max(6, max((len(r[1]) for r in rows), default=6))
    unit_w = max(4, max((len(r[2]) for r in rows), default=4))
    line = "+" + "-"*(name_w+2) + "+" + "-"*(val_w+2) + "+" + "-"*(unit_w+2) + "+\n"
    out = [line, f"| {'Signal'.ljust(name_w)} | {'Value'.ljust(val_w)} | {'Unit'.ljust(unit_w)} |\n", line]
    for n, v, u in rows:
        out.append(f"| {n.ljust(name_w)} | {v.rjust(val_w)} | {u.ljust(unit_w)} |\n")
    out.append(line)
    return "".join(out)

def _clear_screen() -> None:
    print("\x1b[2J\x1b[H", end="")

def _draw_ascii_chart(values: List[Optional[float]], width: int = 60, height: int = 12) -> str:
    """Very small ASCII chart for a single stream of values."""
    pts = [v for v in values if isinstance(v, (int, float))]
    if not pts:
        return "(no data)"
    lo, hi = min(pts), max(pts)
    if hi == lo:
        hi = lo + 1.0
    # take last 'width' points
    series = values[-width:]
    lines = []
    for row in range(height, -1, -1):
        y = lo + (hi - lo) * (row / height)
        line = []
        for v in series:
            if v is None:
                line.append(" ")
            else:
                line.append("█" if v >= y else " ")
        lines.append("".join(line))
    scale = f"{lo:.1f} .. {hi:.1f}"
    return "\n".join(lines) + "\n" + scale

# ------------------------------- Serial ports -------------------------------
def list_ports() -> int:
    try:
        from serial.tools.list_ports import comports
        ports = comports()
        if not ports:
            print("No serial ports found.")
            return 0
        print("Available serial ports:")
        for p in ports:
            desc = p.description or "Unknown device"
            print(f" • {p.device}: {desc}")
        return 0
    except Exception as e:
        print(f"Could not list ports: {e}", file=sys.stderr)
        return 1

# ------------------------------- Discovery -------------------------------
def discover_supported_pids(ser: serial.Serial) -> List[str]:
    """
    Discover Mode 01 supported PIDs via 0100 / 0120 / 0140 / 0160.
    Returns a deduplicated list like ['010C','010D',...].
    """
    windows = [("0100", 0x01), ("0120", 0x21), ("0140", 0x41), ("0160", 0x61)]
    discovered: List[str] = []
    for req, base in windows:
        raw = retry_cmd(ser, f"{req}".encode())
        tokens = clean_hex_stream(raw)
        # find '41 00' / '41 20' / ...
        if len(tokens) >= 6 and tokens[0] == "41":
            # generic parsing: find first "41" matching request PID byte
            pid_byte = req[2:]
            idx = None
            for i in range(len(tokens)-1):
                if tokens[i] == "41" and tokens[i+1] == pid_byte:
                    idx = i + 2
                    break
            if idx is not None:
                data = [int(x, 16) for x in tokens[idx:idx+4]]
                discovered += parse_bitmap_to_supported(int(req[2:], 16)+1, data)
    # dedupe preserving order
    seen = set()
    uniq = []
    for p in discovered:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq

# ------------------------------- Poll loop -------------------------------
def run_poll(
    port: str,
    baud: int,
    pids: List[str],
    hz: float,
    csv_path: Optional[str],
    show_raw: bool,
    headers: bool,
    display: str,
    window: int,
) -> int:
    period = 1.0 / max(0.1, hz) # cap at 10 Hz
    csv_file = None
    csv_writer = None
    value_history: Dict[str, List[Optional[float]]] = {pid: [] for pid in pids}

    # CSV open (append) + header
    if csv_path:
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        is_new = not os.path.exists(csv_path)
        csv_file = open(csv_path, "a", newline="", encoding="utf-8")
        csv_writer = csv.writer(csv_file)
        if is_new:
            csv_writer.writerow(["timestamp"] + pids)

    # graceful Ctrl+C
    stop = False
    def _sigint(_sig, _frm):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, _sigint)

    try:
        with serial.Serial(port=port, baudrate=baud, timeout=ADAPTER_TIMEOUT, write_timeout=ADAPTER_TIMEOUT) as ser:
            if not initialize_adapter(ser, headers=headers):
                print(f"{CERR} Failed to initialize adapter.", file=sys.stderr)
                return 1

            print(f"{COK} Polling {len(pids)} PID(s) at {hz} Hz. Ctrl+C to stop.")
            last_screen = 0.0

            while not stop:
                t0 = time.time()
                vals: Dict[str, Optional[float]] = {}

                for pid in pids:
                    req = f"01 {pid[2:]}".encode()
                    raw = retry_cmd(ser, req, delay=DEFAULT_CMD_DELAY, retries=RETRIES)
                    if show_raw:
                        print(raw.strip())
                    tokens = clean_hex_stream(raw)
                    up = raw.upper()
                    if not tokens or any(tag in up for tag in ERROR_RESPONSES):
                        vals[pid] = None
                    else:
                        vals[pid] = decode_pid(pid, tokens)

                    # keep history (for chart mode)
                    value_history[pid].append(vals[pid])
                    if len(value_history[pid]) > max(window, 60):
                        value_history[pid].pop(0)

                # display
                now = time.time()
                if display in ("table", "combined") and (now - last_screen > 0.2):
                    _clear_screen()
                    rows: List[Tuple[str, str, str]] = []
                    for pid in pids:
                        meta = PID_META.get(pid, {"name": pid, "units": ""})
                        v = vals.get(pid)
                        sval = f"{CVAL}{v:.2f}{CRESET}" if isinstance(v, (int, float)) else "—"
                        rows.append((meta["name"], sval, meta.get("units", "")))
                    print(_render_table(rows))
                    last_screen = now

                if display in ("chart", "combined") and len(pids) == 1:
                    pid = pids[0]
                    print("\n" + _draw_ascii_chart(value_history[pid], width=max(20, window), height=10))

                # CSV write + rotate
                if csv_writer:
                    csv_writer.writerow([datetime.utcnow().isoformat()] + [
                        vals.get(pid, "") if isinstance(vals.get(pid), (int, float)) else "" for pid in pids
                    ])
                    csv_file.flush()
                    try:
                        if os.path.getsize(csv_path) > MAX_CSV_SIZE_MB * 1024 * 1024:
                            # rotate: rename to .1 and reopen
                            csv_file.close()
                            rot = csv_path + ".1"
                            if os.path.exists(rot):
                                os.remove(rot)
                            os.rename(csv_path, rot)
                            csv_file = open(csv_path, "a", newline="", encoding="utf-8")
                            csv_writer = csv.writer(csv_file)
                            csv_writer.writerow(["timestamp"] + pids)
                    except Exception:
                        pass

                # pacing
                elapsed = time.time() - t0
                sleep_left = period - elapsed
                if sleep_left > 0:
                    time.sleep(sleep_left)

        return 0
    except serial.SerialException as e:
        print(f"{CERR} Serial error on {port}: {e}", file=sys.stderr)
        return 1
    finally:
        if csv_file:
            csv_file.close()

# ------------------------------- Info helper -------------------------------
def get_pid_info(pid: str) -> Dict[str, str]:
    return PID_META.get(pid.upper(), {"name": pid.upper(), "units": "", "formula": ""})

# ------------------------------- CLI -----------------------------
-------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Snapcore live data poller (Mode 01)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List available serial ports")

    runp = sub.add_parser("run", help="Start live polling")
    runp.add_argument("--port", default=SERIAL_PORT, help="Serial port (e.g., COM5 or /dev/ttyUSB0)")
    runp.add_argument("--baud", type=int, default=BAUD_RATE, help="Baud rate (e.g., 115200, 500000)")
    runp.add_argument("--pid", action="append", help="PID(s) like 010C; can repeat. If omitted, uses config.LIVE_PIDS")
    runp.add_argument("--hz", type=float, default=2.0, help="Polling frequency (Hz)")
    runp.add_argument("--csv", help="Optional CSV log path (e.g., logs/live.csv)")
    runp.add_argument("--raw", action="store_true", help="Print raw adapter frames")
    runp.add_argument("--headers", action="store_true", help="Enable ELM headers (ATH1)")
    runp.add_argument("--display", choices=["table", "chart", "combined"], default="table", help="Output mode")
    runp.add_argument("--window", type=int, default=40, help="Chart width / history window")

    infp = sub.add_parser("info", help="Show metadata for a PID")
    infp.add_argument("--pid", required=True, help="PID like 010C")

    sub.add_parser("discover", help="Query adapter for supported Mode 01 PIDs")

    args = p.parse_args(argv)

    if args.cmd == "list":
        return list_ports()

    if args.cmd == "info":
        meta = get_pid_info(args.pid)
        print(f"PID: {args.pid.upper()}")
        print(f"Name: {meta.get('name','')}")
        print(f"Units: {meta.get('units','')}")
        print(f"Formula: {meta.get('formula','')}")
        return 0

    if args.cmd == "discover":
        try:
            with serial.Serial(port=SERIAL_PORT, baudrate=BAUD_RATE, timeout=ADAPTER_TIMEOUT) as ser:
                if not initialize_adapter(ser):
                    print(f"{CERR} Adapter init failed.", file=sys.stderr)
                    return 1
                pids = discover_supported_pids(ser)
                if not pids:
                    print("No supported PIDs discovered (or adapter gave empty reply).")
                    return 0
                print("Supported Mode 01 PIDs:")
                print(" ".join(pids))
                return 0
        except serial.SerialException as e:
            print(f"{CERR} Serial error on {SERIAL_PORT}: {e}", file=sys.stderr)
            return 1

    if args.cmd == "run":
        pids = [pid.strip().upper().replace(" ", "") for pid in (args.pid or list(LIVE_PIDS))]
        for pid in pids:
            if not (len(pid) == 4 and pid.startswith("01")):
                print(f"{CERR}
Serial error on {SERIAL_PORT}: {e}", file=sys.stderr)
            return 1

    if args.cmd == "run":
        pids = [pid.strip().upper().replace(" ", "") for pid in (args.pid or list(LIVE_PIDS))]
        for pid in pids:
            if not (len(pid) == 4 and pid.startswith("01")):
                print(f"{CERR} Invalid PID '{pid}'. Use 4 hex chars like 010C.", file=sys.stderr)
                return 2
        return run_poll(
            args.port, args.baud, pids, args.hz,
            args.csv, args.raw, args.headers,
            args.display, args.window
        )

    return 2


if __name__ == "__main__":
    sys.exit(main())
