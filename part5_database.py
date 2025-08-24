# ------------------------------------------------------------------
#  part5_database.py — cleaned & extendable DB (drop-in)
# ------------------------------------------------------------------
from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, Type, TypeVar, Optional

from part1_core import PidCategory, ResetType, VehicleType  # enums
from part2_pids import FULL_PID_MAP, PidDefinition          # dataclass
from part3_dataclasses import ResetProcedure, VehicleProfile

T = TypeVar("T")

# ------------------------- JSON helpers -------------------------

def _enum_to_stable(value: Any) -> Any:
    # Store enums as their names for readability & stability.
    if hasattr(value, "name") and hasattr(value, "value") and value.__class__.__name__.endswith(("Enum",)):
        return value.name
    # PidCategory is a Flag; store its integer value and also name list for readability.
    if isinstance(value, PidCategory):
        return {"__flag__": "PidCategory", "value": int(value)}
    return value

def _stable_to_enum(enum_type: Type[T], raw: Any) -> T:
    if isinstance(raw, dict) and raw.get("__flag__") == "PidCategory":
        return PidCategory(raw["value"])  # type: ignore[return-value]
    if isinstance(raw, str):
        return enum_type[raw]
    if isinstance(raw, int):
        # allow integer to enum for robustness
        return enum_type(raw)
    raise TypeError(f"Cannot restore enum {enum_type.__name__} from {raw!r}")

def _dataclass_to_dict(obj: Any) -> Any:
    """
    Convert dataclasses (including sets/enums) into JSON-safe dicts.
    """
    if is_dataclass(obj):
        d = asdict(obj)
        for k, v in list(d.items()):
            d[k] = _dataclass_to_dict(v)
        # Tag type for lossless round-trip of specific dataclasses.
        d["__type__"] = obj.__class__.__name__
        return d
    if isinstance(obj, set):
        return {"__set__": True, "items": [_dataclass_to_dict(x) for x in sorted(obj)]}
    if isinstance(obj, (list, tuple)):
        return [_dataclass_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _dataclass_to_dict(v) for k, v in obj.items()}
    # enums / flags
    v = _enum_to_stable(obj)
    return v

def _from_dict_pid(d: Dict[str, Any]) -> PidDefinition:
    # Reverse the markers we added in _dataclass_to_dict
    def _restore_sets(x: Any) -> Any:
        if isinstance(x, dict) and x.get("__set__"):
            return set(_restore_sets(i) for i in x["items"])
        if isinstance(x, list):
            return [_restore_sets(i) for i in x]
        if isinstance(x, dict):
            return {k: _restore_sets(v) for k, v in x.items()}
        return x

    d = dict(d)  # copy
    d.pop("__type__", None)

    # restore enums / flags
    if "category" in d:
        d["category"] = _stable_to_enum(PidCategory, d["category"])
    if "protocols" in d:
        d["protocols"] = _restore_sets({ "__set__": True, "items": [
            _stable_to_enum(ProtocolType, p) if not isinstance(p, dict) else p
            for p in d["protocols"]
        ]})
    if "manufacturers" in d:
        d["manufacturers"] = _restore_sets(d["manufacturers"])
    return PidDefinition(**d)

def _from_dict_reset(d: Dict[str, Any]) -> ResetProcedure:
    d = dict(d)
    d.pop("__type__", None)
    if "reset_type" in d:
        d["reset_type"] = _stable_to_enum(ResetType, d["reset_type"])
    return ResetProcedure(**d)

def _from_dict_vehicle(d: Dict[str, Any]) -> VehicleProfile:
    d = dict(d)
    d.pop("__type__", None)
    if "vehicle_type" in d:
        d["vehicle_type"] = _stable_to_enum(VehicleType, d["vehicle_type"])
    return VehicleProfile(**d)

# Optional import guarded for ProtocolType mapping in _from_dict_pid
try:
    from part1_core import ProtocolType
except Exception:
    class ProtocolType:  # minimal fallback to avoid import issues at load time
        pass

# ---------------------------- DB ----------------------------

class VlinkDatabase:
    """
    Small, JSON-backed store for:
      • PIDs (PidDefinition)
      • Reset procedures
      • Vehicle profiles

    Features:
      • Atomic save (no partial files)
      • Versioned payload for forward-compat
      • Merge on load: keeps code defaults, overlays user DB
      • Full fidelity: sets/enums/flags round-trip
    """

    VERSION = 1

    def __init__(self, root: Path = Path("vlink_storage")) -> None:
        self.root = root.expanduser()
        self.root.mkdir(parents=True, exist_ok=True)

        # Start with code-defined PIDs
        self.pids: Dict[str, PidDefinition] = dict(FULL_PID_MAP)
        self.resets: Dict[str, ResetProcedure] = {}
        self.vehicles: Dict[str, VehicleProfile] = {}

    # ---------- CRUD (convenience) ----------
    def upsert_pid(self, pid_key: str, definition: PidDefinition) -> None:
        self.pids[pid_key] = definition

    def get_pid(self, pid_key: str) -> Optional[PidDefinition]:
        return self.pids.get(pid_key)

    def delete_pid(self, pid_key: str) -> bool:
        return self.pids.pop(pid_key, None) is not None

    def upsert_reset(self, name: str, proc: ResetProcedure) -> None:
        self.resets[name] = proc

    def get_reset(self, name: str) -> Optional[ResetProcedure]:
        return self.resets.get(name)

    def delete_reset(self, name: str) -> bool:
        return self.resets.pop(name, None) is not None

    def upsert_vehicle(self, vin: str, profile: VehicleProfile) -> None:
        self.vehicles[vin] = profile

    def get_vehicle(self, vin: str) -> Optional[VehicleProfile]:
        return self.vehicles.get(vin)

    def delete_vehicle(self, vin: str) -> bool:
        return self.vehicles.pop(vin, None) is not None

    # ---------- Persistence ----------
    def save(self, file_name: str = "db.json") -> None:
        file_path = self.root / file_name
        payload = {
            "version": self.VERSION,
            "pids": {k: _dataclass_to_dict(v) for k, v in self.pids.items()},
            "resets": {k: _dataclass_to_dict(v) for k, v in self.resets.items()},
            "vehicles": {k: _dataclass_to_dict(v) for k, v in self.vehicles.items()},
        }

        # Atomic write
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="vlink_db_", suffix=".json", dir=str(self.root))
        try:
            with open(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            shutil.replace(tmp_path, file_path)
        except Exception:
            # on failure, remove temp
            Path(tmp_path).unlink(missing_ok=True)
            raise

    def load(self, file_name: str = "db.json") -> None:
        file_path = self.root / file_name
        if not file_path.exists():
            return

        data = json.loads(file_path.read_text(encoding="utf-8"))
        # Version can be used for migrations later
        _version = data.get("version", 0)

        # Merge (user entries override / extend)
        for k, v in data.get("pids", {}).items():
            try:
                self.pids[k] = _from_dict_pid(v)
            except Exception:
                # If old/partial format: keep existing or skip
                continue

        for k, v in data.get("resets", {}).items():
            try:
                self.resets[k] = _from_dict_reset(v)
            except Exception:
                continue

        for k, v in data.get("vehicles", {}).items():
            try:
                self.vehicles[k] = _from_dict_vehicle(v)
            except Exception:
                continue
