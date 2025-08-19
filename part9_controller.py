# ------------------------------------------------------------------
# part9_controller.py – robust async controller
# ------------------------------------------------------------------
import asyncio, logging
from part5_database import VlinkDatabase
from part4_comm import ELM327Driver

class VLinkController:
    def __init__(self, db: VlinkDatabase, port: str) -> None:
        self.db = db
        self.driver = ELM327Driver(port)
        self._logger = logging.getLogger("VLink")

    async def connect(self) -> bool:
        ok = await self.driver.connect()
        if ok:
            # quick sanity check
            await self.driver.send_command(b"01 00")
        return ok

    async def disconnect(self) -> bool:
        return await self.driver.disconnect()

    async def read_pid(self, pid: str) -> dict:
        if pid not in self.db.pids:
            return {"error": "Unknown PID"}
        raw = await self.driver.send_command(pid.encode())
        if not raw:
            return {"error": "No response"}
        try:
            value = eval(self.db.pids[pid].decode, {"int": int, "h": raw.hex()})
            return {"pid": pid, "value": value, "units": self.db.pids[pid].units}
        except Exception as e:
            self._logger.warning("Decode failed: %s", e)
            return {"error": str(e), "raw": raw.hex()}




