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
# File: snapcore/elm_init.py
"""
Snapcore-Python — Production-grade ELM327/STN adapter initialization.

- Talks directly to a serial ELM327/STN adapter.
- Clean init sequence (reset, echo/space/lf off, protocol auto, optional headers).
- Robust I/O with retries, prompt detection, and tolerant parsing.
- Detects firmware and selected protocol (AT I, AT DP/DPN).
- Returns a structured ElmInfo object with useful metadata.

Usage (example):
    import serial
    from snapcore.elm_init import initialize_adapter

    with serial.Serial("COM5", 500000, timeout=2) as ser:
        info = initialize_adapter(
            ser,
            headers=False,
            protocol="0",           # "0"=auto, otherwise hex protocol id, e.g. "6" for CAN 11/500
            adaptive_timing=True,
            st_min_ms=None,         # set ST (timeout) in ms if needed, e.g. 100
            retries=2,
            quiet=False
        )
        print(info)
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from typing import Optional, Tuple, List

try:
    import serial  # type: ignore
except ImportError as e:  # pragma: no cover
    raise RuntimeError("pyserial is required. Install with: pip install pyserial") from e


# ---- Common adapter “no data”/error phrases we normalize ---------------------------------
MORE_NO_DATA = ("NO DATA", "STOPPED", "CAN ERROR", "UNABLE", "TIMEOUT")
BAD_KEYWORDS = ("ERROR", "UNABLE", "BUS", "BUFFER FULL", "FB ERROR", "RX ERROR", "CAN ERROR", "?")

# ---- Protocol mapping (ELM327 AT DP/DPN) -------------------------------------------------
# ELM doc protocol numbers (1..9,A..C); keep brief, common ones first.
PROTOCOL_MAP = {
    0x01: "SAE J1850 PWM",
    0x02: "SAE J1850 VPW",
    0x03: "ISO 9141-2",
    0x04: "KWP2000 (5 baud init)",
    0x05: "KWP2000 (fast init)",
    0x06: "CAN 11bit 500k",
    0x07: "CAN 29bit 500k",
    0x08: "CAN 11bit 250k",
    0x09: "CAN 29bit 250k",
    0x0A: "CAN (user1)",
    0x0B: "CAN (user2)",
    0x0C: "CAN (user3)",
}

# ---- Default initialization sequence (may be extended below) -----------------------------
BASE_INIT_CMDS: Tuple[bytes, ...] = (
    b"ATZ",     # full reset
    b"ATE0",    # echo off
    b"ATL0",    # linefeeds off
    b"ATS0",    # printing spaces off
    b"ATH0",    # headers off by default (can be switched to ATH1 later)
    b"ATSP0",   # auto protocol
)

# ---- Data class for successful initialization --------------------------------------------
@dataclass(slots=True)
class ElmInfo:
    port: str
    baud: int
    firmware: Optional[str]
    device_desc: Optional[str]
    device_id: Optional[str]
    protocol_name: Optional[str]
    protocol_auto: bool
    protocol_num: Optional[int]
    headers_on: bool


# ---- Low-level I/O helpers ---------------------------------------------------------------
def _read_until_prompt(ser: serial.Serial, *, timeout: float) -> str:
    """
    Read from serial until '>' prompt is seen OR timeout expires.
    Returns the full decoded string (may include CR/LF and '>' if present).
    """
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


def _write_cmd(ser: serial.Serial, cmd: bytes, *, delay: float, timeout: float) -> str:
    """
    Send an AT/OBD command and return adapter reply.
    - Ensures trailing CR.
    - Clears input buffer before sending.
    - Waits 'delay' (give adapter time to compute).
    - Reads until '>' or 'timeout'.
    """
    if not cmd.endswith(b"\r"):
        cmd += b"\r"
    ser.reset_input_buffer()
    ser.write(cmd)
    ser.flush()
    time.sleep(delay)  # small settle time
    return _read_until_prompt(ser, timeout=timeout)


def _query(
    ser: serial.Serial,
    cmd: bytes,
    *,
    delay: float,
    timeout: float,
    retries: int = 0,
    quiet: bool = False,
) -> str:
    """
    Robust query wrapper with minimal retries and normalized response.
    Returns the raw string (may contain CR/LF and '>').
    """
    attempt = 0
    last = ""
    while attempt <= retries:
        resp = _write_cmd(ser, cmd, delay=delay, timeout=timeout)
        last = resp
        text = resp.strip()
        if text:  # non-empty
            return resp
        attempt += 1
        if not quiet:
            print(f"retry {attempt} for {cmd!r} (blank response)", file=sys.stderr)
        time.sleep(0.15)
    return last


def _has_bad(resp: str) -> bool:
    up = resp.upper()
    return any(bad in up for bad in BAD_KEYWORDS)


def _clean_lines(resp: str) -> str:
    """Trim prompt and whitespace; keep useful text for prints/parsing."""
    return resp.replace(">", "").strip()


def _parse_dpn(dpn: str) -> tuple[bool, Optional[int], Optional[str]]:
    """
    Parse ATDPN style reply (e.g., 'A6', '6', 'A7').
    Returns (auto?, proto_num, proto_name).
    """
    s = dpn.replace(">", "").strip().upper()
    if not s:
        return (False, None, None)
    auto = s.startswith("A")
    hex_digit = s[1] if auto and len(s) > 1 else s[0]
    try:
        num = int(hex_digit, 16)
    except ValueError:
        return (auto, None, None)
    return (auto, num, PROTOCOL_MAP.get(num))


# ---- Public initializer -------------------------------------------------------------------
def initialize_adapter(
    ser: serial.Serial,
    *,
    headers: bool = False,
    protocol: str = "0",           # "0"=auto; otherwise hex digit "1".."9","A".."C"
    adaptive_timing: bool = True,  # AT AT2 (ELM adaptive timing)
    st_min_ms: Optional[int] = None,  # AT STxx (timeout) — 1 unit = 4 ms; e.g. 100ms -> 0x19
    delay: float = 0.12,
    timeout: float = 2.0,
    retries: int = 2,
    quiet: bool = False,
) -> ElmInfo:
    """
    Run a robust ELM327/STN init sequence on an OPEN serial port.

    Parameters
    ----------
    ser : serial.Serial
        An **open** serial port.
    headers : bool
        If True, turns headers on (ATH1) after base init.
    protocol : str
        ELM protocol selection. "0" = auto, or hex id string like "6".
    adaptive_timing : bool
        If True, enables adaptive timing (AT AT2) — generally recommended.
    st_min_ms : Optional[int]
        Optional timeout override in milliseconds for AT STxx (units of 4ms).
    delay : float
        Per-command settle delay before reading.
    timeout : float
        Per-command read timeout (until '>' or elapsed).
    retries : int
        Retries for blank responses.
    quiet : bool
        Suppress retry prints.

    Returns
    -------
    ElmInfo
        Structured info about the adapter and selected protocol.

    Raises
    ------
    RuntimeError on hard adapter errors (bad responses).
    """
    # Base init sequence
    for cmd in BASE_INIT_CMDS:
        resp = _query(ser, cmd, delay=delay, timeout=timeout, retries=retries, quiet=quiet)
        if _has_bad(resp):
            raise RuntimeError(f"Adapter rejected {cmd!r}: {_clean_lines(resp)}")

    # Optional: explicitly set protocol (keeps ATSP0 default if protocol == "0")
    protocol = protocol.strip().upper()
    if protocol != "0":
        # e.g., AT SP 6
        resp = _query(ser, f"ATSP{protocol}".encode(), delay=delay, timeout=timeout, retries=retries, quiet=quiet)
        if _has_bad(resp):
            raise RuntimeError(f"Failed to set protocol SP{protocol}: {_clean_lines(resp)}")

    # Adaptive timing for ELM (AT AT2) — improves reliability on many vehicles
    if adaptive_timing:
        _query(ser, b"ATAT2", delay=delay, timeout=timeout, retries=retries, quiet=True)

    # STN devices: optional "STSLCS" etc — we keep it generic/safe here.

    # Optional timeout tweak (AT STxx; 1 unit = 4ms)
    if st_min_ms is not None and st_min_ms >= 0:
        # Convert ms -> 4ms units, clamp 0..0xFF
        units = max(0, min(255, round(st_min_ms / 4)))
        resp = _query(ser, f"ATST{units:02X}".encode(), delay=delay, timeout=timeout, retries=retries, quiet=quiet)
        if _has_bad(resp):
            raise RuntimeError(f"Failed to set ST timeout: {_clean_lines(resp)}")

    # Headers preference
    resp = _query(ser, (b"ATH1" if headers else b"ATH0"), delay=delay, timeout=timeout, retries=retries, quiet=quiet)
    if _has_bad(resp):
        raise RuntimeError(f"Failed to set headers {'on' if headers else 'off'}: {_clean_lines(resp)}")

    # Identify adapter
    firmware = _clean_lines(_query(ser, b"ATI", delay=delay, timeout=timeout, retries=retries, quiet=True)) or None
    device_desc = _clean_lines(_query(ser, b"AT@1", delay=delay, timeout=timeout, retries=retries, quiet=True)) or None
    device_id = _clean_lines(_query(ser, b"AT@2", delay=delay, timeout=timeout, retries=retries, quiet=True)) or None

    # Protocol (human-readable)
    dp = _clean_lines(_query(ser, b"ATDP", delay=delay, timeout=timeout, retries=retries, quiet=True)) or None
    dpn_raw = _clean_lines(_query(ser, b"ATDPN", delay=delay, timeout=timeout, retries=retries, quiet=True)) or ""
    proto_auto, proto_num, proto_name = _parse_dpn(dpn_raw)

    # Fallback name if ATDP gave us something meaningful
    if (not proto_name) and dp and dp.upper() not in MORE_NO_DATA:
        proto_name = dp

    return ElmInfo(
        port=getattr(ser, "port", "?"),
        baud=getattr(ser, "baudrate", 0),
        firmware=firmware,
        device_desc=device_desc,
        device_id=device_id,
        protocol_name=proto_name,
        protocol_auto=proto_auto,
        protocol_num=proto_num,
        headers_on=headers,
    )
