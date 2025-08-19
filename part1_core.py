# ------------------------------------------------------------------
#  part1_core.py  –  cleaned & future-proof core enums
# ------------------------------------------------------------------
from __future__ import annotations
from enum import IntEnum, Flag, auto
from dataclasses import dataclass
from typing import Literal, List, Dict, Any

# ------------------------------------------------------------------
#  Hierarchical PID categories (bit-mask friendly)
# ------------------------------------------------------------------
class PidCategory(Flag):
    """Bit-mask categories for PID tagging."""
    ENGINE         = 0x0001
    TRANSMISSION   = 0x0002
    HYBRID         = 0x0004
    CHASSIS        = 0x0008
    BODY           = 0x0010
    CLIMATE        = 0x0020
    INFO           = 0x0040
    DIAGNOSTIC     = 0x0080
    NETWORK        = 0x0100

# ------------------------------------------------------------------
#  Reset / adaptation types
# ------------------------------------------------------------------
class ResetType(IntEnum):
    """Reset/adaptation procedures."""
    MAINTENANCE = 0
    BATTERY     = auto()
    THROTTLE    = auto()
    TRANSMISSION = auto()
    BRAKE       = auto()
    STEERING    = auto()
    TIRE        = auto()

# ------------------------------------------------------------------
#  Physical layer protocols (extendable)
# ------------------------------------------------------------------
class ProtocolType(IntEnum):
    """Supported physical-layer protocols."""
    J1850_VPW      = 0
    J1850_PWM      = auto()
    ISO9141        = auto()
    ISO14230_KWP   = auto()
    ISO15765_CAN_11 = auto()
    ISO15765_CAN_29 = auto()
    J1939          = auto()
    UDS            = auto()

# ------------------------------------------------------------------
#  Vehicle classification
# ------------------------------------------------------------------
class VehicleType(IntEnum):
    """Vehicle classification for filtering."""
    PASSENGER   = 0
    COMMERCIAL  = auto()
    MOTORCYCLE  = auto()
    BEV         = auto()

# ------------------------------------------------------------------
#  Diagnostic trouble code – frozen & hashable
# ------------------------------------------------------------------
@dataclass(slots=True, frozen=True)
class DiagnosticTroubleCode:
    code: str
    description: str
    severity: int  # 0-5
    systems: List[PidCategory]
    conditions: Dict[str, Any]
    corrective_actions: List[str]

    def __post_init__(self) -> None:
        if self.severity < 0 or self.severity > 5:
            raise ValueError("severity must be 0-5")
        if not self.code:
            raise ValueError("code is required")

