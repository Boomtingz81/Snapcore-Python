#!/usr/bin/env python3
"""
Snapcore-Python — ELM Adapter Info Probe

Quickly opens the adapter, runs the production-grade initializer, and prints
firmware/protocol details as a sanity check.

Usage:
  python -m cli.elm_info --port COM5 --baud 500000
  python -m cli.elm_info --port /dev/ttyUSB0 --headers
  python -m cli.elm_info --port COM5 --protocol 6   # force CAN 11/500
"""

from __future__ import annotations
import argparse
import sys

# Defaults from repo config if available
try:
    from config import SERIAL_PORT as DEFAULT_PORT, BAUD_RATE as DEFAULT_BAUD
except Exception:
    DEFAULT_PORT = "COM5"
    DEFAULT_BAUD = 500000

try:
    import serial  # type: ignore
except ImportError:
    print("ERROR: pyserial is required. Install with: pip install pyserial", file=sys.stderr)
    sys.exit(1)

from snapcore.elm_init import initialize_adapter, ElmInfo  # our production init

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Probe ELM327/STN adapter and print firmware/protocol info"
    )
    p.add_argument("--port", default=DEFAULT_PORT, help="Serial port (e.g., COM5 or /dev/ttyUSB0)")
    p.add_argument("--baud", type=int, default=DEFAULT_BAUD, help="Baud rate (e.g., 115200, 500000)")
    p.add_argument("--headers", action="store_true", help="Turn headers on (ATH1)")
    p.add_argument("--protocol", default="0",
                   help='ELM protocol code: "0"=auto (default), or hex digit like "6","7","8","9","A"')
    p.add_argument("--no-adaptive", action="store_true", help="Disable adaptive timing (AT AT2)")
    p.add_argument("--st", type=int, default=None,
                   help="Set ST timeout in milliseconds (ELM units are 4ms; e.g., 100 -> AT ST19)")
    p.add_argument("--timeout", type=float, default=2.0, help="Per-command read timeout (sec)")
    p.add_argument("--delay", type=float, default=0.12, help="Per-command settle delay (sec)")
    p.add_argument("--retries", type=int, default=2, help="Retries on blank responses")

    args = p.parse_args(argv)

    try:
        with serial.Serial(port=args.port, baudrate=args.baud, timeout=args.timeout) as ser:
            info: ElmInfo = initialize_adapter(
                ser,
                headers=args.headers,
                protocol=args.protocol,
                adaptive_timing=not args.no_adaptive,
                st_min_ms=args.st,
                delay=args.delay,
                timeout=args.timeout,
                retries=args.retries,
                quiet=False,
            )
    except serial.SerialException as e:
        print(f"Serial error opening {args.port}: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"Adapter initialization failed: {e}", file=sys.stderr)
        return 2

    # Pretty print
    print("\n=== ELM/STN Adapter Info ===")
    print(f"Port           : {info.port}")
    print(f"Baud           : {info.baud}")
    print(f"Firmware       : {info.firmware or '—'}")
    print(f"Device Desc    : {info.device_desc or '—'}")
    print(f"Device ID      : {info.device_id or '—'}")
    print(f"Protocol Name  : {info.protocol_name or '—'}")
    print(f"Protocol Auto  : {'Yes' if info.protocol_auto else 'No'}")
    print(f"Protocol Num   : {info.protocol_num if info.protocol_num is not None else '—'}")
    print(f"Headers On     : {'Yes' if info.headers_on else 'No'}")
    print("============================\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
