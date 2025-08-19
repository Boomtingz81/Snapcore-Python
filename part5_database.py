# ------------------------------------------------------------------
#  part5_database.py  –  cleaned & extendable DB
# ------------------------------------------------------------------
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any
from part2_pids import FULL_PID_MAP
from part3_dataclasses import ResetProcedure, VehicleProfile
from part1_core import PidCategory, ResetType, VehicleType

class VlinkDatabase:
    def __init__(self, root: Path = Path("vlink_storage")) -> None:
        self.root = root.expanduser()
        self.root.mkdir(exist_ok=True)
        self.pids: Dict[str, Any] = dict(FULL_PID_MAP)  # shallow copy
        self.resets: Dict[str, ResetProcedure] = {}
        self.vehicles: Dict[str, VehicleProfile] = {}

    # ---------- CRUD ----------
    def save(self, file_name: str = "db.json") -> None:
        payload = {
            "pids": {k: {"pid": v.pid, "name": v.name, "decode": v.decode} for k, v in self.pids.items()},
            "resets": {k: v.__dict__ for k, v in self.resets.items()},
            "vehicles": {k: v.__dict__ for k, v in self.vehicles.items()},
        }
        (self.root / file_name).write_text(json.dumps(payload, indent=2))

    def load(self, file_name: str = "db.json") -> None:
        file = self.root / file_name
        if not file.exists():
            return
        data = json.loads(file.read_text())
        # merge instead of overwrite
        self.resets.update({k: ResetProcedure(**v) for k, v in data.get("resets", {}).items()})
        self.vehicles.update({k: VehicleProfile(**v) for k, v in data.get("vehicles", {}).items()})



