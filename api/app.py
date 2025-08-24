#!/usr/bin/env python3
# File: api/app.py
# FastAPI wrapper around Snapcore-Python primitives (read-only endpoints)

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---- project config fallbacks -------------------------------------------------
try:
    from config import SERIAL_PORT, BAUD_RATE
except Exception:
    SERIAL_PORT = "COM5"
    BAUD_RATE = 500000

# ---- serial layer -------------------------------------------------------------
try:
    import serial # type: ignore
except Exception as e: # pragma: no cover
    raise RuntimeError("pyserial is required. Run: pip install pyserial") from e

# Prefer shared initializer if present
try:
    from snapcore.elm_init import initialize_adapter as _elm_init # type: ignore
    HAVE_SHARED_INIT = True
except Exception:
    HAVE_SHARED_INIT = False

# ---- helpers ------------------------------------------------------------------
ELM_INIT_CMDS: Tuple[bytes, ...] = (
    b"ATZ", b"ATE0", b"ATL0", b"ATS0", b"ATH0", b"ATSP0"
)
ERROR_WORDS = ("NO DATA", "STOPPED", "CAN ERROR", "UNABLE", "TIMEOUT", "ERROR", "BUS", "?")

def _read_until_prompt(ser: serial.Serial, timeout: float = 2.0) -> str:
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

def _send(ser: serial.Serial, cmd: bytes, delay: float = 0.12, timeout: float = 2.0) -> str:
    if not cmd.endswith(b"\r"):
        cmd += b"\r"
    ser.reset_input_buffer()
    ser.write(cmd)
    ser.flush()
    time.sleep(delay)
    return _read_until_prompt(ser, timeout=timeout)

def _init_adapter(ser: serial.Serial) -> None:
    """Use shared init if available; else minimal safe sequence."""
    if HAVE_SHARED_INIT:
        _elm_init(ser, headers=False) # raises on hard error
        return
    for c in ELM_INIT_CMDS:
        _send(ser, c)

def _hex_tokens(s: str) -> List[str]:
    s = s.upper().replace("SEARCHING...", " ")
    s = s.replace("\r", " ").replace("\n", " ").replace(">", " ")
    return re.findall(r"\b[0-9A-F]{2}\b", s)

def _decode_pid_value(pid: str, tokens: List[str]) -> Optional[float]:
    """Simple Mode 01 decoders for common PIDs. Extend as needed."""
    if len(pid) != 4 or not pid.startswith("01"):
        return None
    pb = pid[2:]
    for i in range(len(tokens) - 2):
        if tokens[i] == "41" and tokens[i + 1] == pb:
            data = [int(x, 16) for x in tokens[i + 2 : i + 6]]
            A = data[0] if len(data) > 0 else 0
            B = data[1] if len(data) > 1 else 0
            if pid == "010C": # RPM
                return ((A * 256) + B) / 4.0
            if pid == "010D": # Speed
                return float(A)
            if pid == "0105": # Coolant
                return float(A - 40)
            if pid == "0142": # Control module voltage
                return (A * 256 + B) / 1000.0
            return float(A) # fallback
    return None

def _read_vin(tokens: List[str]) -> Optional[str]:
    # Collect ASCII following 49 02 frames
    out: List[str] = []
    i = 0
    while i < len(tokens) - 2:
        if tokens[i] == "49" and tokens[i + 1] == "02":
            i += 3 # skip 49 02 <record#>
            while i < len(tokens):
                if i + 1 < len(tokens) and tokens[i] == "49" and tokens[i + 1] in ("02", "04", "06"):
                    break
                out.append(tokens[i])
                i += 1
        else:
            i += 1
    try:
        vin = bytes(int(b, 16) for b in out).decode("ascii", "ignore").strip().replace("\x00", "")
        vin = "".join(ch for ch in vin if 32 <= ord(ch) <= 126)
        return vin[:17] if len(vin) >= 17 else None
    except Exception:
        return None

# ---- FastAPI app --------------------------------------------------------------
app = FastAPI(title="Snapcore OBD Local API", version="0.1.0")

# Allow your PWA / localhost to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # tighten later
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- models ------------------------------------------------------------------
class LiveResponse(BaseModel):
    port: str
    baud: int
    values: Dict[str, Optional[float]]

class DtcResponse(BaseModel):
    port: str
    baud: int
    dtcs: List[str]

class VinResponse(BaseModel):
    port: str
    baud: int
    vin: Optional[str]

class AdapterInfo(BaseModel):
    port: str
    baud: int
    firmware: Optional[str] = None
    protocol: Optional[str] = None
    dpn: Optional[str] = None

# ---- routes ------------------------------------------------------------------
@app.get("/")
def root() -> Dict[str, str]:
    return {"ok": True, "service": "snapcore-api", "hint": "see /health and /docs"}

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "port": SERIAL_PORT, "baud": BAUD_RATE}

@app.get("/ports")
def ports():
    try:
        from serial.tools.list_ports import comports # type: ignore
        return [{"device": p.device, "desc": p.description} for p in comports()]
    except Exception as e:
        raise HTTPException(500, f"list_ports failed: {e}")

@app.get("/adapter/info", response_model=AdapterInfo)
def adapter_info(port: Optional[str] = None, baud: Optional[int] = None):
    use_port = port or SERIAL_PORT
    use_baud = baud or BAUD_RATE
    try:
        with serial.Serial(use_port, use_baud, timeout=2, write_timeout=2) as ser:
            _init_adapter(ser)
            fw = _send(ser, b"ATI").replace(">", "").strip() or None
            dp = _send(ser, b"ATDP").replace(">", "").strip() or None
            dpn = _send(ser, b"ATDPN").replace(">", "").strip() or None
            return AdapterInfo(port=use_port, baud=use_baud, firmware=fw, protocol=dp, dpn=dpn)
    except Exception as e:
        raise HTTPException(500, f"adapter open/init failed: {e}")

@app.get("/mode09/vin", response_model=VinResponse)
def mode09_vin(port: Optional[str] = None, baud: Optional[int] = None):
    use_port = port or SERIAL_PORT
    use_baud = baud or BAUD_RATE
    try:
        with serial.Serial(use_port, use_baud, timeout=2, write_timeout=2) as ser:
            _init_adapter(ser)
            raw = _send(ser, b"09 02")
            toks = _hex_tokens(raw)
            vin = _read_vin(toks)
            return VinResponse(port=use_port, baud=use_baud, vin=vin)
    except Exception as e:
        raise HTTPException(500, f"mode09 vin failed: {e}")

@app.get("/dtc/stored", response_model=DtcResponse)
def dtc_stored(port: Optional[str] = None, baud: Optional[int] = None):
    use_port = port or SERIAL_PORT
    use_baud = baud or BAUD_RATE
    try:
        with serial.Serial(use_port, use_baud, timeout=2, write_timeout=2) as ser:
            _init_adapter(ser)
            raw = _send(ser, b"03")
            toks = _hex_tokens(raw)
            dtcs: List[str] = []
            i = 0
            while i < len(toks):
                if toks[i] == "43":
                    i += 1
                    while i + 1 < len(toks) and toks[i] != "43":
                        hi = int(toks[i], 16); lo = int(toks[i + 1], 16)
                        i += 2
                        if hi == 0 and lo == 0:
                            continue
                        sys_letter = "PCBU"[(hi & 0xC0) >> 6]
                        first = (hi & 0x30) >> 4
                        d2 = hi & 0x0F
                        d3 = (lo & 0xF0) >> 4
                        d4 = lo & 0x0F
                        dtcs.append(f"{sys_letter}{first:X}{d2:X}{d3:X}{d4:X}")
                else:
                    i += 1
            # dedupe preserving order
            seen = set()
            uniq = [d for d in dtcs if not (d in seen or seen.add(d))]
            return DtcResponse(port=use_port, baud=use_baud, dtcs=uniq)
    except Exception as e:
        raise HTTPException(500, f"dtc read failed: {e}")

@app.get("/live", response_model=LiveResponse)
def live(
    pid: List[str] = Query(..., description="Repeat ?pid=010C&pid=010D"),
    port: Optional[str] = None,
    baud: Optional[int] = None,
):
    use_port = port or SERIAL_PORT
    use_baud = baud or BAUD_RATE
    pids = [p.strip().upper().replace(" ", "") for p in pid]
    for p in pids:
        if not (len(p) == 4 and p.startswith("01")):
            raise HTTPException(400, f"Invalid PID: {p}")
    try:
        with serial.Serial(use_port, use_baud, timeout=2, write_timeout=2) as ser:
            _init_adapter(ser)
            values: Dict[str, Optional[float]] = {}
            for p in pids:
                req = f"01 {p[2:]}".encode()
                raw = _send(ser, req)
                if any(w in raw.upper() for w in ERROR_WORDS):
                    values[p] = None
                    continue
                toks = _hex_tokens(raw)
                values[p] = _decode_pid_value(p, toks)
            return LiveResponse(port=use_port, baud=use_baud, values=values)
    except Exception as e:
        raise HTTPException(500, f"live read failed: {e}")
