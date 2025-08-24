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

# File: snapcore/pids_loader.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import jsonschema  # type: ignore
except ImportError:
    jsonschema = None  # Optional: validate if lib is installed

# ---- Safe formula support -------------------------------------------------
# Allowed tokens: A,B,C,D (bytes 0..3), numbers, + - * / ( )
_TOKEN_RE = re.compile(r"\s*([ABCD]|\d+|[+\-*/()])\s*")

def _compile_formula(expr: str) -> Callable[[bytes], float]:
    """Compile a tiny arithmetic expression into a callable on bytes."""
    tokens = _TOKEN_RE.findall(expr)
    if not tokens:
        raise ValueError(f"Empty or invalid formula: {expr!r}")

    # Rebuild sanitized expression replacing A..D with b[0..3]
    mapped = []
    for t in tokens:
        if t in ("A", "B", "C", "D"):
            idx = ord(t) - ord("A")
            mapped.append(f"b[{idx}]")
        elif t.isdigit() or t in "+-*/()":
            mapped.append(t)
        else:
            raise ValueError(f"Illegal token in formula: {t}")
    safe_expr = "".join(mapped)

    def fn(data: bytes) -> float:
        b = list(data) + [0, 0, 0, 0]  # pad up to 4
        # Evaluate with no builtins; only numbers/ops used
        return float(eval(safe_expr, {"__builtins__": {}}, {"b": b}))
    return fn

# ---- Public dataclass -----------------------------------------------------
@dataclass(slots=True)
class OemSignal:
    id: str               # e.g., "F190" or "010C"
    service: str          # "22", "01", "09"
    ecu: str              # hint (powertrain/gateway/body/...)
    can_header: Optional[str]
    name: str
    units: str
    category: str
    min: Optional[float]
    max: Optional[float]
    refresh_ms: int
    decoder: Callable[[bytes], Any]  # returns str|float|dict depending on type

# ---- Loader ---------------------------------------------------------------
def _validate(doc: dict, schema_path: Path) -> None:
    if jsonschema is None:
        return  # best-effort if jsonschema not installed
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema)

def load_oem_pack(json_path: Path, schema_path: Optional[Path] = None) -> List[OemSignal]:
    """
    Load an OEM PID/DID pack (validated if schema is provided).
    """
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    if schema_path and schema_path.exists():
        _validate(doc, schema_path)

    out: List[OemSignal] = []
    for sig in doc.get("signals", []):
        dec = sig.get("decoder", {})
        dec_type = dec.get("type")

        if dec_type == "ascii":
            length = dec.get("length")
            trim = bool(dec.get("trim", True))
            def _ascii_decoder(data: bytes, _length=length, _trim=trim):
                s = data[:_length].decode("ascii", "ignore") if _length else data.decode("ascii", "ignore")
                return s.strip() if _trim else s
            decode_fn = _ascii_decoder

        elif dec_type == "formula":
            formula = dec.get("formula", "")
            bytes_expected = int(dec.get("bytes", 1))
            f = _compile_formula(formula)
            def _formula_decoder(data: bytes, _len=bytes_expected, _f=f):
                return _f(data[:_len])
            decode_fn = _formula_decoder

        elif dec_type == "bitfield":
            bits = sig["decoder"]["bits"]
            def _bitfield_decoder(data: bytes, _bits=bits):
                mask = int.from_bytes(data, "big")
                return {entry["name"]: bool((mask >> entry["bit"]) & 1) for entry in _bits}
            decode_fn = _bitfield_decoder

        else:
            raise ValueError(f"Unsupported decoder type: {dec_type}")

        out.append(
            OemSignal(
                id=sig["id"].upper(),
                service=sig["service"],
                ecu=sig.get("ecu", "unknown"),
                can_header=sig.get("can_header"),
                name=sig["name"],
                units=sig.get("units", ""),
                category=sig["category"],
                min=sig.get("min"),
                max=sig.get("max"),
                refresh_ms=int(sig.get("refresh_ms", 1000)),
                decoder=decode_fn,
            )
        )
    return out

def index_by_key(signals: List[OemSignal]) -> Dict[Tuple[str, str], OemSignal]:
    """
    Build a quick index: key = (service, id). Example: ('22', 'F190').
    """
    return {(s.service.upper(), s.id.upper()): s for s in signals}
