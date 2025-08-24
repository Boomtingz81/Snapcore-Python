bin/env python3
# File: cli/dtc.py
"""
Snapcore-Python — DTC (Mode 03/04/07/0A) Reader & Clear Tool

Reads and clears diagnostic trouble codes:
- Mode 03: Stored DTCs (current)
- Mode 04: Clear DTCs and MIL
- Mode 07: Pending DTCs (not yet mature)
- Mode 0A: Permanent DTCs (cannot be cleared)

Uses direct ELM327 serial so it's fast and independent of the async stack.

Usage:
  python -m cli.dtc read
  python -m cli.dtc read --port COM4 --baud 115200
  python -m cli.dtc pending        # read pending DTCs
  python -m cli.dtc permanent      # read permanent DTCs
  python -m cli.dtc clear          # clears MIL + stored codes
  python -m cli.dtc read --raw     # also prints raw adapter frames
  python -m cli.dtc list           # list available serial ports
"""

from __future__ import annotations

import re
import time
import argparse
import sys
from typing import List, Tuple, Optional

# Configuration with fallbacks
try:
    # Use repo config if available
    from config import SERIAL_PORT, BAUD_RATE
except ImportError:
    SERIAL_PORT = "COM5"
    BAUD_RATE = 500000  # safe default for many adapters

# Lazy import to give nice error if pyserial is missing
try:
    import serial  # type: ignore
except ImportError:  # pragma: no cover
    print("ERROR: pyserial is not installed. Run: pip install pyserial", file=sys.stderr)
    sys.exit(1)


# ------------------------------- Constants -------------------------------

ELM_INIT_CMDS: Tuple[bytes, ...] = (
    b"ATZ",     # reset
    b"ATE0",    # echo off
    b"ATL0",    # linefeeds off
    b"ATS0",    # printing of spaces off
    b"ATH0",    # headers off (simpler parsing by default)
    b"ATSP0",   # auto-select protocol
)

SYSTEM_LETTER = ("P", "C", "B", "U")

# Additional adapter “no data”/error phrases we’ll recognize
MORE_NO_DATA = ("NO DATA", "STOPPED", "CAN ERROR", "UNABLE", "TIMEOUT")

# Timeouts
DEFAULT_CMD_TIMEOUT = 0.15
DTC_READ_TIMEOUT = 0.30
DTC_CLEAR_TIMEOUT = 0.50
ADAPTER_PAUSE = 0.20


# ------------------------------- ELM helpers -------------------------------

def _write_cmd(ser: serial.Serial, cmd: bytes, sleep: float = DEFAULT_CMD_TIMEOUT) -> str:
    """
    Write an AT/OBD command and return the adapter's reply (string).
    """
    if not cmd.endswith(b"\r"):
        cmd += b"\r"

    try:
        ser.reset_input_buffer()
        ser.write(cmd)
        ser.flush()
        time.sleep(sleep)

        # Read until we see '>' prompt or timeout occurs
        out = []
        t0 = time.time()
        while True:
            chunk = ser.read(ser.in_waiting or 1).decode(errors="ignore")
            if chunk:
                out.append(chunk)
                if ">" in chunk:
                    break
            if time.time() - t0 > ser.timeout:
                break
        return "".join(out)
    except serial.SerialException as e:
        print(f"Serial communication error: {e}", file=sys.stderr)
        return ""


def _clean_hex_stream(s: str) -> List[str]:
    """
    Take raw ELM output and return a flat list of hex byte tokens.
    Removes 'SEARCHING...', whitespace, '>', and non-hex noise.
    """
    s = s.upper()
    s = s.replace("SEARCHING...", " ")
    s = s.replace("\r", " ").replace("\n", " ").replace(">", " ")
    # keep only hex byte tokens
    return re.findall(r"\b[0-9A-F]{2}\b", s)


def initialize_adapter(ser: serial.Serial, use_headers: bool = False) -> bool:
    """
    Initialize the ELM adapter with standard settings.
    Accepts either 'OK' or a banner (e.g., 'ELM327') as success for each step.
    """
    for cmd in ELM_INIT_CMDS:
        resp = _write_cmd(ser, cmd)
        upper = resp.upper()
        if any(bad in upper for bad in ("ERROR", "UNABLE", "BUS", "?")):
            print(f"Adapter rejected {cmd.decode()}: {resp.strip()}", file=sys.stderr)
            return False
        if ("OK" not in upper) and ("ELM" not in upper):
            # Not a hard failure: some firmwares are terse; keep going but warn
            print(f"Warning: {cmd.decode()} returned non-standard reply: {resp.strip()}", file=sys.stderr)
    if use_headers:
        _write_cmd(ser, b"ATH1")
    # Print detected protocol (ATDPN)
    proto = _write_cmd(ser, b"ATDPN").strip()
    if proto:
        print(f"Adapter protocol: {proto.replace('>','').strip()}")
    return True


# ------------------------------- DTC parsing -------------------------------

def _decode_dtc_word(hi: int, lo: int) -> str:
    """
    Convert two bytes into a 5-char OBD-II DTC like P0301.
    """
    sys_idx = (hi & 0xC0) >> 6           # top 2 bits
    first_digit = (hi & 0x30) >> 4       # next 2 bits (0..3)
    d2 = (hi & 0x0F)                     # low 4 bits
    d3 = (lo & 0xF0) >> 4
    d4 = (lo & 0x0F)
    return f"{SYSTEM_LETTER[sys_idx]}{first_digit:X}{d2:X}{d3:X}{d4:X}"


def parse_mode03(tokens: List[str]) -> List[str]:
    """
    Parse a flat list of hex tokens from a Mode 03/07/0A reply.
    Expect frames beginning with '43'/'47'/'4A' followed by pairs of bytes,
    where each pair encodes one DTC. '00 00' pairs are padding and ignored.
    """
    dtcs: List[str] = []

    i = 0
    while i < len(tokens):
        if tokens[i] in ("43", "47", "4A"):
            i += 1
            while i + 1 < len(tokens) and tokens[i] not in ("43", "47", "4A"):
                try:
                    hi = int(tokens[i], 16)
                    lo = int(tokens[i + 1], 16)
                    i += 2
                    if hi == 0 and lo == 0:
                        continue  # padding
                    dtc = _decode_dtc_word(hi, lo)
                    dtcs.append(dtc)
                except (ValueError, IndexError):
                    i += 1
        else:
            i += 1

    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for d in dtcs:
        if d not in seen:
            uniq.append(d)
            seen.add(d)
    return uniq


def _read_mode(ser: serial.Serial, mode_hex: bytes, sleep: float, retries: int = 1) -> List[str]:
    """Send a mode (b'03', b'07', b'0A') and return decoded DTC list."""
    attempt = 0
    raw = ""
    while attempt <= retries:
        raw = _write_cmd(ser, mode_hex, sleep=sleep)
        if raw.strip():
            break
        attempt += 1
        time.sleep(0.15)

    tokens = _clean_hex_stream(raw)
    if not tokens:
        up = raw.upper()
        if any(tag in up for tag in MORE_NO_DATA):
            print("No DTC data (adapter reported no data).")
            return []
        print("No response from adapter. Check connection.")
        return []

    hdr = f"4{mode_hex.decode()}"  # 03->43, 07->47, 0A->4A
    up = raw.upper()
    if hdr not in tokens:
        if any(tag in up for tag in MORE_NO_DATA):
            print("No DTC data returned (NO DATA).")
            return []
        print(f"No DTC header '{hdr}' found.")
        return []
    return parse_mode03(tokens)


# ------------------------------- CLI actions -------------------------------

def action_read(port: str, baud: int, show_raw: bool, use_headers: bool) -> int:
    """Read and display stored DTCs (Mode 03)."""
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=2) as ser:
            if not initialize_adapter(ser, use_headers=use_headers):
                print("Failed to initialize adapter. Check connection and settings.", file=sys.stderr)
                return 1
            raw = _write_cmd(ser, b"03", sleep=DTC_READ_TIMEOUT)
            if show_raw:
                print("\n--- RAW ---")
                print(raw.strip(), "\n-----------")
            tokens = _clean_hex_stream(raw)
            if not tokens:
                print("No response from adapter. Check connection.", file=sys.stderr)
                return 1
            if "43" not in tokens:
                if any(tag in raw.upper() for tag in MORE_NO_DATA):
                    print("No stored DTCs. 🎉")
                    return 0
                print("No DTC data returned (no '43' header).")
                return 0
            dtcs = parse_mode03(tokens)
            if not dtcs:
                print("No stored DTCs. 🎉")
                return 0
            print("Stored DTCs:")
            for d in dtcs:
                print(f"  • {d}")
            return 0
    except serial.SerialException as e:
        print(f"Error opening serial port {port}: {e}", file=sys.stderr)
        return 1


def action_pending(port: str, baud: int, use_headers: bool) -> int:
    """Read and display pending DTCs (Mode 07)."""
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=2) as ser:
            if not initialize_adapter(ser, use_headers=use_headers):
                print("Failed to initialize adapter.", file=sys.stderr)
                return 1
            dtcs = _read_mode(ser, b"07", sleep=DTC_READ_TIMEOUT)
            if not dtcs:
                print("No pending DTCs.")
                return 0
            print("Pending DTCs:")
            for d in dtcs:
                print(f"  • {d}")
            return 0
    except serial.SerialException as e:
        print(f"Error opening serial port {port}: {e}", file=sys.stderr)
        return 1


def action_permanent(port: str, baud: int, use_headers: bool) -> int:
    """Read and display permanent DTCs (Mode 0A)."""
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=2) as ser:
            if not initialize_adapter(ser, use_headers=use_headers):
                print("Failed to initialize adapter.", file=sys.stderr)
                return 1
            dtcs = _read_mode(ser, b"0A", sleep=DTC_READ_TIMEOUT)
            if not dtcs:
                print("No permanent DTCs.")
                return 0
            print("Permanent DTCs:")
            for d in dtcs:
                print(f"  • {d}")
            return 0
    except serial.SerialException as e:
        print(f"Error opening serial port {port}: {e}", file=sys.stderr)
        return 1


def action_clear(port: str, baud: int, use_headers: bool) -> int:
    """Clear stored DTCs and reset MIL (Mode 04)."""
    print("⚠️  This will clear stored codes and may turn off the MIL.")
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=2) as ser:
            if not initialize_adapter(ser, use_headers=use_headers):
                print("Failed to initialize adapter. Check connection and settings.", file=sys.stderr)
                return 1

            time.sleep(ADAPTER_PAUSE)
            raw = _write_cmd(ser, b"04", sleep=DTC_CLEAR_TIMEOUT)
            tokens = _clean_hex_stream(raw)

            if "44" in tokens:
                print("Clear DTCs command acknowledged (44). ✅")
            elif "OK" in raw.upper():
                print("Clear command accepted (OK). ✅")
            else:
                print("Sent clear command. Check MIL and re-scan to confirm.")
        return 0
    except serial.SerialException as e:
        print(f"Error opening serial port {port}: {e}", file=sys.stderr)
        return 1


def list_ports() -> int:
    """List available serial ports."""
    try:
        from serial.tools.list_ports import comports
        ports = comports()
        if not ports:
            print("No serial ports found.")
            return 0

        print("Available serial ports:")
        for port in ports:
            desc = f"{port.description}" if port.description else "Unknown device"
            print(f"  • {port.device}: {desc}")
        return 0
    except ImportError:
        print("Cannot list ports: serial.tools.list_ports not available", file=sys.stderr)
        return 1


# ------------------------------- CLI -------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Snapcore DTC tool (Mode 03/04/07/0A)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_read = sub.add_parser("read", help="Read stored DTCs (Mode 03)")
    p_read.add_argument("--port", default=SERIAL_PORT, help="Serial port (e.g., COM5 or /dev/ttyUSB0)")
    p_read.add_argument("--baud", type=int, default=BAUD_RATE, help="Baud rate (e.g., 115200, 500000)")
    p_read.add_argument("--raw", action="store_true", help="Show raw adapter frames")
    p_read.add_argument("--headers", action="store_true", help="Enable ELM headers (ATH1)")

    p_pending = sub.add_parser("pending", help="Read pending DTCs (Mode 07)")
    p_pending.add_argument("--port", default=SERIAL_PORT)
    p_pending.add_argument("--baud", type=int, default=BAUD_RATE)
    p_pending.add_argument("--headers", action="store_true")

    p_perm = sub.add_parser("permanent", help="Read permanent DTCs (Mode 0A)")
    p_perm.add_argument("--port", default=SERIAL_PORT)
    p_perm.add_argument("--baud", type=int, default=BAUD_RATE)
    p_perm.add_argument("--headers", action="store_true")

    p_clear = sub.add_parser("clear", help="Clear DTCs / MIL (Mode 04)")
    p_clear.add_argument("--port", default=SERIAL_PORT)
    p_clear.add_argument("--baud", type=int, default=BAUD_RATE)
    p_clear.add_argument("--headers", action="store_true")

    p_list = sub.add_parser("list", help="List available serial ports")

    args = p.parse_args(argv)

    if args.cmd == "read":
        return action_read(args.port, args.baud, args.raw, args.headers)
    if args.cmd == "pending":
        return action_pending(args.port, args.baud, args.headers)
    if args.cmd == "permanent":
        return action_permanent(args.port, args.baud, args.headers)
    if args.cmd == "clear":
        return action_clear(args.port, args.baud, args.headers)
    if args.cmd == "list":
        return list_ports()

    return 2


if __name__ == "__main__":
    sys.exit(main())




