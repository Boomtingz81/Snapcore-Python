# ------------------------------------------------------------------
#  main.py — Entry point for the 10-part diagnostic suite
# ------------------------------------------------------------------
from __future__ import annotations

import asyncio
import logging
import signal
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import List

# ---- Suite parts ----
from part1_core import PidCategory, VehicleType, ProtocolType, DiagnosticTroubleCode  # noqa
from part2_pids import FULL_PID_MAP  # noqa
from part3_dataclasses import ResetProcedure, VehicleProfile  # noqa
from part4_comm import ELM327Driver  # noqa
from part5_database import VlinkDatabase
from part6_operations import VlinkOps  # noqa
from part7_decoders import decode_bitmask, decode_temp, decode_vin  # noqa
from part8_persistence import VlinkPersistence
from part9_controller import VLinkController

# ------------------------------------------------------------------
#  Defaults (override via CLI flags)
# ------------------------------------------------------------------
DEFAULT_PORT = "COM5"      # Linux/macOS: "/dev/ttyUSB0" or "/dev/tty.SLAB_USBtoUART"
DEFAULT_BAUD = 115200
DEFAULT_PIDS: List[str] = ["010C", "010D", "019A"]  # RPM, Speed, Battery Voltage (if supported)

# ------------------------------------------------------------------
#  Logging
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("main")

# ------------------------------------------------------------------
#  Graceful cancellation helper
# ------------------------------------------------------------------
def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, loop.stop)
        except NotImplementedError:
            # Windows on older Python may not support this; ignore.
            pass

# ------------------------------------------------------------------
#  Core run
# ------------------------------------------------------------------
async def run(port: str, baud: int, pids: List[str], loop_forever: bool) -> None:
    # Database + (optional) persistence merge
    db = VlinkDatabase()
    db.load()  # merges any saved resets/vehicles from vlink_storage/db.json

    # (Optional) separate persistence helper if you want atomic saves elsewhere
    persist = VlinkPersistence(Path("vlink_storage"))
    _ = persist.load()  # load-but-ignore here; db.load() already merged file

    ctrl = VLinkController(db, port)
    connected = await ctrl.connect()
    if not connected:
        log.error("Failed to connect on %s @ %d", port, baud)
        return

    log.info("Connected to adapter on %s @ %d", port, baud)

    try:
        if loop_forever:
            log.info("Starting live read loop… (Ctrl+C to stop)")
            while True:
                results = await ctrl.read_many(pids, per_timeout=1.0, concurrency=3)
                for code in pids:
                    res = results.get(code, {})
                    log.info("%s -> %s", code, res)
                await asyncio.sleep(1.0)
        else:
            log.info("Single sweep read…")
            results = await ctrl.read_many(pids, per_timeout=1.0, concurrency=3)
            for code in pids:
                res = results.get(code, {})
                log.info("%s -> %s", code, res)
    finally:
        await ctrl.disconnect()
        log.info("Disconnected.")

# ------------------------------------------------------------------
#  CLI
# ------------------------------------------------------------------
def parse_args():
    ap = ArgumentParser(description="Snapcore / VLink Diagnostic Runner")
    ap.add_argument("--port", default=DEFAULT_PORT, help="Serial port (e.g., COM5 or /dev/ttyUSB0)")
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD, help="Baud rate (default 115200)")
    ap.add_argument("--pid", action="append", help="PID to read (repeatable). If omitted, uses defaults.")
    ap.add_argument("--once", action="store_true", help="Read once and exit (no loop).")
    return ap.parse_args()

if __name__ == "__main__":
    args = parse_args()
    pids = args.pid if args.pid else DEFAULT_PIDS

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _install_signal_handlers(loop)

    try:
        loop.run_until_complete(run(args.port, args.baud, pids, loop_forever=not args.once))
    finally:
        try:
            loop.run_until_complete(asyncio.sleep(0))  # flush tasks
        except Exception:
            pass
        loop.close()
