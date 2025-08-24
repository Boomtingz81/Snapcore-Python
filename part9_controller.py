#!/usr/bin/env python3
# File: cli/mode09.py
"""
Snapcore-Python — OBD-II Mode 09 (Vehicle Info)

Supported actions:
  • vin        -> Read VIN (09 02)
  • calib      -> Read Calibration ID(s) (09 04)
  • cvn        -> Read Calibration Verification Number(s) (09 06)
  • summary    -> VIN + CALID + CVN quick summary
  • supported  -> Show which Mode 09 PIDs are supported (09 00)
  • list       -> List available serial ports

Examples:
  python -m cli.mode09 vin
  python -m cli.mode09 calib --port COM4 --baud 115200
  python -m cli.mode09 summary --headers   # enable ATH1 for raw headers
"""

from __future__ import annotations

import argparse
import sys
import time
import re
from typing import List, Tuple, Optional, Dict

# Pull defaults from repo config if present
try:
    from config import SERIAL_PORT, BAUD_RATE
except ImportError:
    SERIAL_PORT = "COM5"
    BAUD_RATE = 500000

# Lazy pyserial import with friendly error
try:
    import serial  # type: ignore
except ImportError:
    print("ERROR: pyserial is not installed. Run: pip install pyserial", file=sys.stderr)
    sys.exit(1)

# ------------------------------- ELM/OBD constants -------------------------------

ELM_INIT_CMDS: Tuple[bytes, ...] = (
    b"ATZ",
    b"ATE0",
    b"ATL0",
    b"ATS0",
    b"ATH0",   # default: headers off (we allow --headers to flip)
    b"ATSP0",  # auto protocol
)

DEFAULT_CMD_DELAY = 0.20
ADAPTER_TIMEOUT = 2.0

MORE_NO_DATA = ("NO DATA", "STOPPED", "CAN ERROR", "UNABLE", "TIMEOUT")

# ------------------------------- Low-level helpers -------------------------------

def _write_cmd(ser: serial.Serial, cmd: bytes, delay: float = DEFAULT_CMD_DELAY) -> str:
    """Send a command and collect reply until '>' or timeout."""
    if not cmd.endswith(b"\r"):
        cmd += b"\r"
    try:
        ser.reset_input_buffer()
        ser.write(cmd)
        ser.flush()
        time.sleep(delay)
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
    """Normalize adapter text -> list of hex byte tokens."""
    s = s.upper().replace("SEARCHING...", " ")
    s = s.replace("\r", " ").replace("\n", " ").replace(">", " ")
    return re.findall(r"\b[0-9A-F]{2}\b", s)

def initialize_adapter(ser: serial.Serial, use_headers: bool = False) -> bool:
    """Standard ELM init; tolerate terse firmwares; optionally enable headers."""
    for cmd in ELM_INIT_CMDS:
        resp = _write_cmd(ser, cmd)
        up = resp.upper()
        if any(bad in up for bad in ("ERROR", "UNABLE", "BUS", "?")):
            print(f"Adapter rejected {cmd.decode()}: {resp.strip()}", file=sys.stderr)
            return False
        if ("OK" not in up) and ("ELM" not in up):
            # not fatal—many firmwares respond minimally
            pass
    if use_headers:
        _write_cmd(ser, b"ATH1")
    proto = _write_cmd(ser, b"ATDPN").strip()
    if proto:
        print(f"Adapter protocol: {proto.replace('>','').strip()}")
    return True

def _retry_cmd(ser: serial.Serial, cmd: bytes, delay: float = DEFAULT_CMD_DELAY, retries: int = 1) -> str:
    """Send a command with minimal retry on blank responses."""
    attempt = 0
    raw = ""
    while attempt <= retries:
        raw = _write_cmd(ser, cmd, delay)
        if raw.strip():
            break
        attempt += 1
        time.sleep(0.15)
    return raw

# ------------------------------- Mode 09 parsers -------------------------------

def _tokens_after_headers(tokens: List[str], headers: Tuple[str, ...]) -> List[str]:
    """
    Given a token stream and one or more response headers (e.g., '49 02'),
    collect all bytes that belong to those responses, concatenated in order.
    Works with multi-frame segmented responses (01/02/03 segment index).
    """
    out: List[str] = []
    i = 0
    while i < len(tokens):
        # find any of our headers
        if i + 1 < len(tokens) and (tokens[i], tokens[i+1]) in {tuple(h.split()) for h in headers}:
            # For Mode 09 replies, the third byte is often a "record index" like 01,02,03
            # We'll skip first 3 bytes (e.g., 49 02 01) and take the rest of that line
            # until the next header appears.
            i += 3
            while i < len(tokens):
                # stop if we encounter another response header start
                if i + 1 < len(tokens) and (tokens[i], tokens[i+1]) in {tuple(h.split()) for h in headers}:
                    break
                out.append(tokens[i])
                i += 1
        else:
            i += 1
    return out

def parse_vin_from_tokens(tokens: List[str]) -> Optional[str]:
    """
    Extract VIN from a 49 02 ... response. Returns 17-char VIN or None.
    """
    # Gather bytes belonging to 49 02
    payload = _tokens_after_headers(tokens, headers=("49 02",))
    if not payload:
        return None
    try:
        b = bytes(int(x, 16) for x in payload)
        vin = b.decode("ascii", "ignore").strip().replace("\x00", "")
        vin = "".join(ch for ch in vin if 32 <= ord(ch) <= 126)  # printable
        if len(vin) >= 17:
            return vin[:17]
        return None
    except Exception:
        return None

def parse_calids(tokens: List[str]) -> List[str]:
    """
    Extract one or more Calibration IDs from 49 04 ... responses (ASCII).
    Some ECUs return multiple CALIDs split across records; we join and split on nulls/spaces.
    """
    payload = _tokens_after_headers(tokens, headers=("49 04",))
    if not payload:
        return []
    b = bytes(int(x, 16) for x in payload)
    text = b.decode("ascii", "ignore")
    # Split on NULs and whitespace runs; filter empties
    parts = [p.strip() for p in re.split(r"[\x00\r\n\t ]+", text) if p.strip()]
    # Deduplicate & keep order
    seen = set()
    out: List[str] = []
    for p in parts:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out

def parse_cvns(tokens: List[str]) -> List[str]:
    """
    Extract one or more CVNs (Calibration Verification Numbers) from 49 06 ... responses.
    CVN is typically 4 bytes per record (8 hex chars).
    """
    # For CVN, 49 06 01 <4 bytes> 49 06 02 <4 bytes> ...
    # We'll collect all payload bytes and group by 4.
    payload = _tokens_after_headers(tokens, headers=("49 06",))
    if not payload:
        return []
    # Group payload into 4-byte blocks
    cvns: List[str] = []
    block: List[str] = []
    for tok in payload:
        block.append(tok)
        if len(block) == 4:
            cvns.append("".join(block))
            block = []
    # Dedup while preserving order
    seen = set()
    uniq: List[str] = []
    for c in cvns:
        if c not in seen:
            uniq.append(c)
            seen.add(c)
    return uniq

def parse_supported_pids(tokens: List[str]) -> Dict[int, bool]:
    """
    Parse 49 00 response (supported Mode 09 PIDs) big-endian bitmask.
    Returns mapping {pid: supported(bool)} for PIDs 0x00..0x20-ish depending on length.
    """
    # Gather bytes after 49 00
    payload = _tokens_after_headers(tokens, headers=("49 00",))
    if not payload:
        return {}
    bits = bytes(int(x, 16) for x in payload)
    mask = int.from_bytes(bits, "big")
    # SAE typically defines 0x00..0x20 window in first mask; we map generously
    supported: Dict[int, bool] = {}
    total_bits = len(bits) * 8
    # Map bit N (MSB-first) to PID number
    for idx in range(total_bits):
        bit = (mask >> (total_bits - 1 - idx)) & 1
        pid_num = idx  # this aligns PID offset from 0x00 upward
        supported[pid_num] = bool(bit)
    return supported

# ------------------------------- Actions -------------------------------

def _send_and_tokens(ser: serial.Serial, cmd_hex: bytes, delay: float = DEFAULT_CMD_DELAY, retries: int = 1) -> List[str]:
    raw = _retry_cmd(ser, cmd_hex, delay=delay, retries=retries)
    tokens = _clean_hex_stream(raw)
    if not tokens:
        up = raw.upper()
        if any(tag in up for tag in MORE_NO_DATA):
            print("No data returned (adapter reported NO DATA).")
            return []
        print("No response from adapter. Check connection.")
        return []
    return tokens

def action_vin(port: str, baud: int, headers: bool) -> int:
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=ADAPTER_TIMEOUT) as ser:
            if not initialize_adapter(ser, use_headers=headers):
                print("Failed to initialize adapter.", file=sys.stderr)
                return 1
            tokens = _send_and_tokens(ser, b"09 02")
            if not tokens:
                return 1
            vin = parse_vin_from_tokens(tokens)
            if vin:
                print(f"VIN: {vin}")
                return 0
            print("VIN not found in response.")
            return 1
    except serial.SerialException as e:
        print(f"Serial error on {port}: {e}", file=sys.stderr)
        return 1

def action_calib(port: str, baud: int, headers: bool) -> int:
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=ADAPTER_TIMEOUT) as ser:
            if not initialize_adapter(ser, use_headers=headers):
                print("Failed to initialize adapter.", file=sys.stderr)
                return 1
            tokens = _send_and_tokens(ser, b"09 04")
            if not tokens:
                return 1
            calids = parse_calids(tokens)
            if not calids:
                print("No Calibration IDs returned.")
                return 0
            print("Calibration ID(s):")
            for c in calids:
                print(f"  • {c}")
            return 0
    except serial.SerialException as e:
        print(f"Serial error on {port}: {e}", file=sys.stderr)
        return 1

def action_cvn(port: str, baud: int, headers: bool) -> int:
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=ADAPTER_TIMEOUT) as ser:
            if not initialize_adapter(ser, use_headers=headers):
                print("Failed to initialize adapter.", file=sys.stderr)
                return 1
            tokens = _send_and_tokens(ser, b"09 06")
            if not tokens:
                return 1
            cvns = parse_cvns(tokens)
            if not cvns:
                print("No CVNs returned.")
                return 0
            print("CVN(s):")
            for c in cvns:
                print(f"  • {c}")
            return 0
    except serial.SerialException as e:
        print(f"Serial error on {port}: {e}", file=sys.stderr)
        return 1

def action_supported(port: str, baud: int, headers: bool) -> int:
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=ADAPTER_TIMEOUT) as ser:
            if not initialize_adapter(ser, use_headers=headers):
                print("Failed to initialize adapter.", file=sys.stderr)
                return 1
            tokens = _send_and_tokens(ser, b"09 00")
            if not tokens:
                return 1
            sup = parse_supported_pids(tokens)
            if not sup:
                print("Could not parse supported PID bitmask.")
                return 1
            # Show a friendly subset we care about
            names = {
                0x00: "Supported list",
                0x02: "VIN",
                0x04: "CALID",
                0x06: "CVN",
                0x0A: "ECU Name",
            }
            print("Mode 09 PID support (bitmask):")
            for pid, ok in sorted(sup.items()):
                if pid in names:
                    print(f"  0x{pid:02X}  {names[pid]:<12} : {'YES' if ok else 'no'}")
            return 0
    except serial.SerialException as e:
        print(f"Serial error on {port}: {e}", file=sys.stderr)
        return 1

def action_summary(port: str, baud: int, headers: bool) -> int:
    try:
        with serial.Serial(port=port, baudrate=baud, timeout=ADAPTER_TIMEOUT) as ser:
            if not initialize_adapter(ser, use_headers=headers):
                print("Failed to initialize adapter.", file=sys.stderr)
                return 1

            # VIN
            tokens = _send_and_tokens(ser, b"09 02")
            vin = parse_vin_from_tokens(tokens) if tokens else None

            # CALIDs
            tokens = _send_and_tokens(ser, b"09 04")
            calids = parse_calids(tokens) if tokens else []

            # CVNs
            tokens = _send_and_tokens(ser, b"09 06")
            cvns = parse_cvns(tokens) if tokens else []

            print("\n=== Vehicle Info (Mode 09) ===")
            print(f"VIN : {vin or '—'}")
            if calids:
                print("CALID(s):")
                for c in calids:
                    print(f"  • {c}")
            else:
                print("CALID(s): —")
            if cvns:
                print("CVN(s):")
                for c in cvns:
                    print(f"  • {c}")
            else:
                print("CVN(s): —")
            print("==============================\n")
            return 0
    except serial.SerialException as e:
        print(f"Serial error on {port}: {e}", file=sys.stderr)
        return 1

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
            print(f"  • {p.device}: {desc}")
        return 0
    except Exception as e:
        print(f"Could not list ports: {e}", file=sys.stderr)
        return 1

# ------------------------------- CLI -------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Snapcore Mode 09 tool (VIN/CALID/CVN)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--port", default=SERIAL_PORT, help="Serial port (e.g., COM5 or /dev/ttyUSB0)")
        sp.add_argument("--baud", type=int, default=BAUD_RATE, help="Baud rate (e.g., 115200, 500000)")
        sp.add_argument("--headers", action="store_true", help="Enable ELM headers (ATH1)")

    sp_vin = sub.add_parser("vin", help="Read VIN (09 02)")
    add_common(sp_vin)

    sp_cal = sub.add_parser("calib", help="Read Calibration ID(s) (09 04)")
    add_common(sp_cal)

    sp_cvn = sub.add_parser("cvn", help="Read CVN(s) (09 06)")
    add_common(sp_cvn)

    sp_sum = sub.add_parser("summary", help="VIN + CALID + CVN quick summary")
    add_common(sp_sum)

    sp_sup = sub.add_parser("supported", help="Show supported Mode 09 PIDs (09 00)")
    add_common(sp_sup)

    sub.add_parser("list", help="List available serial ports")

    args = p.parse_args(argv)

    if args.cmd == "vin":
        return action_vin(args.port, args.baud, args.headers)
    if args.cmd == "calib":
        return action_calib(args.port, args.baud, args.headers)
    if args.cmd == "cvn":
        return action_cvn(args.port, args.baud, args.headers)
    if args.cmd == "summary":
        return action_summary(args.port, args.baud, args.headers)
    if args.cmd == "supported":
        return action_supported(args.port, args.baud, args.headers)
    if args.cmd == "list":
        return list_ports()

    return 2

if __name__ == "__main__":
    sys.exit(main())



