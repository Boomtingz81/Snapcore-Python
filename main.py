# ------------------------------------------------------------------
#  main.py  –  Entry point for the 10-part diagnostic suite
# ------------------------------------------------------------------
import asyncio
import logging
from pathlib import Path

# ------------------------------------------------------------------
#  Import the 10 suite parts (they must be in the same folder)
# ------------------------------------------------------------------
from part1_core import PidCategory, VehicleType, ProtocolType, DiagnosticTroubleCode
from part2_pids import FULL_PID_MAP
from part3_dataclasses import PidDefinition, ResetProcedure, VehicleProfile
from part4_comm import ELM327Driver
from part5_database import VlinkDatabase
from part6_operations import VlinkOps
from part7_decoders import decode_bitmask, decode_temp, decode_vin
from part8_persistence import VlinkPersistence
from part9_controller import VLinkController
from part10_usage import main  # optional demo stub

# ------------------------------------------------------------------
#  CONFIG – EDIT THESE TWO LINES ONLY
# ------------------------------------------------------------------
SERIAL_PORT = "COM5"       # Linux/macOS: "/dev/ttyUSB0"
BAUD_RATE   = 115200

# ------------------------------------------------------------------
#  BOOTSTRAP
# ------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)

async def run_diagnostics() -> None:
    """
    1. Build database
    2. Attach serial driver
    3. Start live read loop
    """
    db = VlinkDatabase()
    db.load_builtin()

    # persistence helper (optional)
    persist = VlinkPersistence(Path("vlink_storage"))
    persist.load()  # load any saved state

    # high-level controller
    ctrl = VLinkController(db, SERIAL_PORT)

    try:
        if not await ctrl.connect():
            logging.error("Adapter not found.")
            return

        logging.info("Connected. Reading live data…")
        while True:
            for pid in ["010C", "010D", "019A"]:
                result = await ctrl.read_pid(pid)
                logging.info(result)
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down…")
    finally:
        await ctrl.disconnect()

# ------------------------------------------------------------------
#  RUN
# ------------------------------------------------------------------
if __name__ == "__main__":
    asyncio.run(run_diagnostics())






