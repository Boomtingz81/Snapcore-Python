# ------------------------------------------------------------------
#  part3_dataclasses.py  –  cleaned & extended dataclasses
# ------------------------------------------------------------------
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List
from part1_core import PidCategory, ResetType, ProtocolType, VehicleType

# ----------------------------------------------------------
#  Reset procedure – immutable & validation
# ----------------------------------------------------------
@dataclass(slots=True, frozen=True)
class ResetProcedure:
    name: str
    command: bytes
    reset_type: ResetType
    estimated_sec: int = 30
    preconditions: List[str] = field(default_factory=tuple)
    steps: List[tuple[str, bytes, Dict[str, Any]]] = field(default_factory=tuple)

    def __post_init__(self):
        if self.estimated_sec < 0:
            raise ValueError("estimated_sec must be ≥ 0")

# ----------------------------------------------------------
#  Vehicle profile – frozen & hashable
# ----------------------------------------------------------
@dataclass(slots=True, frozen=True)
class VehicleProfile:
    vin: str
    year: int
    make: str
    model: str
    vehicle_type: VehicleType
    ecus: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if len(self.vin) != 17:
            raise ValueError("VIN must be 17 characters")

