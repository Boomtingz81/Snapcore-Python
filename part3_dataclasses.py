# snapcore_python/part3_dataclasses.py
# ------------------------------------------------------------------
#  part3_dataclasses.py — cleaned & extended dataclasses
# ------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional

from part1_core import (
    PidCategory,
    ResetType,
    ProtocolType,
    VehicleType,
)


# ----------------------------------------------------------
#  Reset procedure — immutable & validated
# ----------------------------------------------------------
@dataclass(slots=True, frozen=True)
class ResetStep:
    """
    A single atomic step of a reset/adaptation procedure.
    - description: human-readable action
    - command: bytes to transmit to the ECU (already encoded)
    - expect: optional expectations (e.g., {"positive_response_sid": 0x51})
    """
    description: str
    command: bytes
    expect: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class ResetProcedure:
    name: str
    command: bytes
    reset_type: ResetType
    estimated_sec: int = 30
    preconditions: Tuple[str, ...] = field(default_factory=tuple)
    steps: Tuple[ResetStep, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.estimated_sec < 0:
            raise ValueError("estimated_sec must be ≥ 0")
        if not self.name.strip():
            raise ValueError("name is required")
        if not isinstance(self.command, (bytes, bytearray)):
            raise TypeError("command must be bytes")


# ----------------------------------------------------------
#  Vehicle profile — frozen & hashable
# ----------------------------------------------------------
@dataclass(slots=True, frozen=True)
class VehicleProfile:
    vin: str
    year: int
    make: str
    model: str
    vehicle_type: VehicleType
    ecus: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        vin = self.vin.upper()
        if len(vin) != 17:
            raise ValueError("VIN must be exactly 17 characters")
        # VIN must not contain I, O, Q
        forbidden = {"I", "O", "Q"}
        if any(ch in forbidden for ch in vin):
            raise ValueError("VIN contains invalid characters (I, O, Q)")

        # Basic year sanity (supports classic/near-future)
        if not (1950 <= self.year <= datetime.utcnow().year + 2):
            raise ValueError("year is out of reasonable range")

        if not self.make.strip():
            raise ValueError("make is required")
        if not self.model.strip():
            raise ValueError("model is required")


# ----------------------------------------------------------
#  Adapter / connection configuration
# ----------------------------------------------------------
@dataclass(slots=True, frozen=True)
class AdapterConfig:
    """
    Connection/transport configuration.
    - port: e.g. 'COM3' (Windows) or '/dev/ttyUSB0' (Linux)
    - baud: typical ELM327 38400/500000/921600 etc.
    - protocol: optional preselected protocol; None = auto
    - timeout_s: read timeout seconds
    - fast_init: enable faster adapter init sequence (if supported)
    """
    port: str
    baud: int = 115200
    protocol: Optional[ProtocolType] = None
    timeout_s: float = 3.0
    fast_init: bool = True

    def __post_init__(self) -> None:
        if not self.port:
            raise ValueError("port is required")
        if self.baud <= 0:
            raise ValueError("baud must be > 0")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")


# ----------------------------------------------------------
#  PID request/response wrappers
# ----------------------------------------------------------
@dataclass(slots=True, frozen=True)
class PidRequest:
    """
    A single PID poll request.
    - pid: key from FULL_PID_MAP (e.g., '010C')
    - timestamp: when we *asked* (UTC)
    - raw_frame: optional prebuilt frame; otherwise constructed upstream
    """
    pid: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    raw_frame: Optional[bytes] = None


@dataclass(slots=True, frozen=True)
class PidResult:
    """
    Outcome of a PID request.
    - pid: which PID
    - ok: success flag
    - value: decoded numeric/string value (if ok)
    - units: engineering units (if ok)
    - raw_hex: raw payload as hex (no spaces)
    - error: error info if not ok
    - latency_ms: measured round-trip
    """
    pid: str
    ok: bool
    value: Optional[Any] = None
    units: Optional[str] = None
    raw_hex: Optional[str] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


# ----------------------------------------------------------
#  Time-series sample (for streaming graphs/logs)
# ----------------------------------------------------------
@dataclass(slots=True, frozen=True)
class PidSample:
    """
    A normalized sample used for logging/plotting.
    - pid, name, units
    - value: already-decoded
    - t: sample time (UTC)
    """
    pid: str
    name: str
    value: Any
    units: Optional[str]
    t: datetime = field(default_factory=datetime.utcnow)
    category: Optional[PidCategory] = None


# ----------------------------------------------------------
#  Diagnostic session — one scan run
# ----------------------------------------------------------
@dataclass(slots=True)
class DiagnosticSession:
    """
    High-level container for a scan session.
    Holds the vehicle, adapter config, chosen protocol,
    samples and DTCs collected during the run.
    """
    vehicle: VehicleProfile
    adapter: AdapterConfig
    protocol: Optional[ProtocolType] = None
    started_utc: datetime = field(default_factory=datetime.utcnow)
    ended_utc: Optional[datetime] = None
    notes: str = ""
    samples: List[PidSample] = field(default_factory=list)
    pid_results: List[PidResult] = field(default_factory=list)
    dtcs: List[str] = field(default_factory=list)

    def end(self) -> None:
        """Mark session as finished."""
        self.ended_utc = datetime.utcnow()

    def add_sample(self, sample: PidSample) -> None:
        self.samples.append(sample)

    def add_result(self, result: PidResult) -> None:
        self.pid_results.append(result)

    def add_dtcs(self, codes: List[str]) -> None:
        self.dtcs.extend(codes)

    @property
    def duration_s(self) -> Optional[float]:
        if not self.ended_utc:
            return None
        return (self.ended_utc - self.started_utc).total_seconds()
