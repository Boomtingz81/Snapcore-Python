# ------------------------------------------------------------------
#  part6_operations.py  –  thin CRUD helpers (drop-in)
# ------------------------------------------------------------------
from typing import Dict, Any
from part5_database import VlinkDatabase
from part1_core import PidCategory, ProtocolType

class VlinkOps:
    def __init__(self, db: VlinkDatabase) -> None:
        self.db = db

    # ---------------- PID helpers ----------------
    def get_pids_by_category(self, cat: PidCategory) -> Dict[str, Any]:
        return {k: v for k, v in self.db.pids.items() if v.category == cat}

    # ---------------- Reset helpers ----------------
    def get_resets_by_type(self, t: any) -> Dict[str, Any]:
        return {k: v for k, v in self.db.resets.items() if v.reset_type == t}

    # ---------------- Vehicle helpers ----------------
    def get_vehicles_by_make(self, make: str) -> Dict[str, Any]:
        return {k: v for k, v in self.db.vehicles.items() if v.make == make}



