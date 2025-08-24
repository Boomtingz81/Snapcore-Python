# ------------------------------------------------------------------
#  part6_operations.py — VlinkOps: Lightweight CRUD & Query Helpers
# ------------------------------------------------------------------

from __future__ import annotations

from typing import Dict, Optional, Iterable, List

from part1_core import PidCategory, ResetType, VehicleType, ProtocolType
from part2_pids import PidDefinition
from part3_dataclasses import ResetProcedure, VehicleProfile
from part5_database import VlinkDatabase


class VlinkOps:
    """
    Thin convenience layer over VlinkDatabase with common, fast queries.

    Notes
    -----
    • PidCategory is a Flag → use bitwise checks for category filtering.
    • Methods generally return dicts keyed by their natural IDs to keep it composable.
    """

    def __init__(self, db: VlinkDatabase) -> None:
        self.db = db

    # ------------------------------
    # PID helpers
    # ------------------------------
    def get_pids_by_category(self, cat: PidCategory) -> Dict[str, PidDefinition]:
        """
        Return all PIDs that include the given category bit(s).

        Example: get_pids_by_category(PidCategory.ENGINE | PidCategory.HYBRID)
        """
        out: Dict[str, PidDefinition] = {}
        for pid_code, pid in self.db.pids.items():
            pid_cat = getattr(pid, "category", None)
            if isinstance(pid_cat, PidCategory) and (pid_cat & cat):
                out[pid_code] = pid
        return out

    def get_pids_by_protocol(self, *protocols: ProtocolType) -> Dict[str, PidDefinition]:
        """
        Filter PIDs that support ANY of the given protocols.
        """
        wanted = set(protocols)
        out: Dict[str, PidDefinition] = {}
        for k, pid in self.db.pids.items():
            if not hasattr(pid, "protocols"):
                continue
            if pid.protocols and (pid.protocols & wanted):
                out[k] = pid
        return out

    def get_pids_by_manufacturer(self, *manufacturers: str) -> Dict[str, PidDefinition]:
        """
        Filter PIDs that are tagged with ANY of the given manufacturers (case-insensitive).
        """
        wanted = {m.lower() for m in manufacturers}
        out: Dict[str, PidDefinition] = {}
        for k, pid in self.db.pids.items():
            if not hasattr(pid, "manufacturers"):
                continue
            if any(m.lower() in wanted for m in pid.manufacturers):
                out[k] = pid
        return out

    def search_pids(self, keyword: str) -> Dict[str, PidDefinition]:
        """
        Simple name/code contains search (case-insensitive).
        """
        q = keyword.lower()
        return {
            code: pid
            for code, pid in self.db.pids.items()
            if q in code.lower() or q in getattr(pid, "name", "").lower()
        }

    # Basic PID CRUD passthroughs (handy for UIs / scripts)
    def upsert_pid(self, code: str, definition: PidDefinition) -> None:
        self.db.upsert_pid(code, definition)

    def delete_pid(self, code: str) -> bool:
        return self.db.delete_pid(code)

    def get_pid(self, code: str) -> Optional[PidDefinition]:
        return self.db.get_pid(code)

    # ------------------------------
    # Reset helpers
    # ------------------------------
    def get_resets_by_type(self, reset_type: ResetType) -> Dict[str, ResetProcedure]:
        """
        Return all reset procedures of a specific type.
        """
        return {
            name: proc
            for name, proc in self.db.resets.items()
            if getattr(proc, "reset_type", None) == reset_type
        }

    def upsert_reset(self, name: str, proc: ResetProcedure) -> None:
        self.db.upsert_reset(name, proc)

    def delete_reset(self, name: str) -> bool:
        return self.db.delete_reset(name)

    def get_reset(self, name: str) -> Optional[ResetProcedure]:
        return self.db.get_reset(name)

    # ------------------------------
    # Vehicle helpers
    # ------------------------------
    def get_vehicles_by_make(self, make: str) -> Dict[str, VehicleProfile]:
        """
        Case-insensitive make match.
        """
        m = make.lower()
        return {
            vin: v
            for vin, v in self.db.vehicles.items()
            if getattr(v, "make", "").lower() == m
        }

    def get_vehicles_by_type(self, vehicle_type: VehicleType) -> Dict[str, VehicleProfile]:
        return {
            vin: v
            for vin, v in self.db.vehicles.items()
            if getattr(v, "vehicle_type", None) == vehicle_type
        }

    def get_vehicle_by_vin(self, vin: str) -> Optional[VehicleProfile]:
        """
        VIN lookup (normalized to uppercase).
        """
        return self.db.get_vehicle(vin.upper())

    def upsert_vehicle(self, profile: VehicleProfile) -> None:
        self.db.upsert_vehicle(profile.vin.upper(), profile)

    def delete_vehicle(self, vin: str) -> bool:
        return self.db.delete_vehicle(vin.upper())

    # ------------------------------
    # Snapshots (for quick UI dumps)
    # ------------------------------
    def snapshot(self) -> dict:
        """
        Lightweight dictionary snapshot for UIs/logging.
        """
        return {
            "pids": len(self.db.pids),
            "resets": len(self.db.resets),
            "vehicles": len(self.db.vehicles),
            "categories_present": self._present_categories(),
        }

    def _present_categories(self) -> List[str]:
        cats: set[PidCategory] = set()
        for pid in self.db.pids.values():
            c = getattr(pid, "category", None)
            if isinstance(c, PidCategory):
                # Decompose combined flags into individuals
                for single in PidCategory:
                    if c & single:
                        cats.add(single)
        return [c.name for c in sorted(cats, key=lambda x: x.value)]
