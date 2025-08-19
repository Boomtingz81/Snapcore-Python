# ------------------------------------------------------------------
#  part7_decoders.py  –  bullet-proof decoders (drop-in)
# ------------------------------------------------------------------
from typing import Dict

def decode_bitmask(data: bytes) -> Dict[int, bool]:
    """Big-endian bit mask → {bit_pos: True/False}."""
    mask = int.from_bytes(data, "big")
    return {i: bool(mask >> i & 1) for i in range(len(data) * 8)}

def decode_temp(data: bytes) -> float:
    """SAE J1979 temperature (°C)."""
    if not data:
        raise ValueError("Empty data")
    return data[0] - 40

def decode_vin(data: bytes) -> str:
    """17-char ASCII VIN."""
    vin = data.decode("ascii", "ignore").strip()
    if len(vin) != 17:
        raise ValueError("VIN length != 17")
    return vin




