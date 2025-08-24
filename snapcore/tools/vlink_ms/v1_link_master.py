# ⚠️ DISCLAIMER
# This software communicates directly with live vehicle systems.
# You use this software entirely at your own risk.
#
# The developers, contributors, and any associated parties accept no liability for:
# - Damage to vehicles, ECUs, batteries, or electronics
# - Data loss, unintended resets, or corrupted configurations
# - Physical injury, legal consequences, or financial loss
#
# This tool is intended only for qualified professionals who
# understand the risks of direct OBD/CAN access.

# ------------------------------------------------------------------
#  vl_link_master.py – Real-Time Diagnostic Master Runner
#  Author: SnapCore AI | Mode: LIVE ONLY | No Simulation
# ------------------------------------------------------------------

import argparse
import json
import time
from part4_comm import VlinkComm
from part2_pids import PID_LIST
from part7_decoders import decode_pid
from part8_persistence import save_log_entry
from config import SERIAL_PORT, BAUD_RATE, DEBUG_MODE, SAVE_JSON
from vl_link_macros import MODE_09_VIN_REQUEST, parse_vin_response

# Optional: if WebSocket server exists
try:
    from ws_server import broadcast_message
    WS_ENABLED = True
except ImportError:
    WS_ENABLED = False


# ------------------------------------------------------------------
# 🛡️ Legal Disclaimer (Runtime)
# ------------------------------------------------------------------
def show_disclaimer():
    print("\n" + "=" * 60)
    print("⚠️  DISCLAIMER – READ CAREFULLY")
    print("This software communicates directly with live vehicle systems.")
    print("By using it, you acknowledge and accept the following terms:\n")
    print("• You use this software entirely at your own risk.")
    print("• The developers and contributors accept no liability for:")
    print("  - Damage to vehicles, ECUs, or electronics")
    print("  - Data loss, resets, or corrupted configurations")
    print("  - Legal, financial, or physical consequences\n")
    print("This tool is intended only for professionals, engineers, or")
    print("technicians who understand the risks of OBD and CAN access.\n")
    print("⚠️  If unsure what a command does — DO NOT run it.")
    print("⚠️  Always test on a safe, non-critical system first.")
    print("=" * 60 + "\n")


def fetch_vin(comm: VlinkComm) -> str:
    """
    Requests VIN using Mode 09 PID 02 and decodes it.
    """
    comm.send_raw_hex(MODE_09_VIN_REQUEST)
    raw_response = comm.read_raw()
    vin = parse_vin_response(raw_response)
    if DEBUG_MODE:
        print(f"[VIN DETECTED] → {vin}")
    return vin


def poll_live_data(comm: VlinkComm, vin: str):
    """
    Poll all active PIDs in real-time and decode output.
    """
    print("\n[Live Scan] Starting real-time data stream...\n")
    while True:
        for pid in PID_LIST:
            try:
                comm.send_pid(pid)
                raw = comm.read_raw()
                decoded = decode_pid(pid, raw)

                log_entry = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "vin": vin,
                    "pid": pid.code,
                    "label": pid.label,
                    "value": decoded.value,
                    "units": decoded.units
                }

                # Console display
                print(f"{log_entry['timestamp']} | {pid.label}: {decoded.value} {decoded.units}")

                # Save to JSON log
                if SAVE_JSON:
                    save_log_entry(log_entry)

                # WebSocket stream
                if WS_ENABLED:
                    broadcast_message(log_entry)

            except Exception as e:
                if DEBUG_MODE:
                    print(f"[ERROR] PID {pid.code}: {e}")
        time.sleep(1)


def main():
    show_disclaimer()  # 🔥 Show legal disclaimer before running

    parser = argparse.ArgumentParser(description="SnapCore vLinker Master Diagnostic Tool")
    parser.add_argument("--port", default=SERIAL_PORT, help="OBD port (COM or BLE:xx:xx:xx)")
    args = parser.parse_args()

    # Step 1: Connect
    print(f"[CONNECTING] to {args.port} @ {BAUD_RATE} baud...")
    comm = VlinkComm(port=args.port, baudrate=BAUD_RATE)

    if not comm.connect():
        print("[❌] Connection failed. Exiting.")
        return

    print("[✅] Connection established.")

    # Step 2: Fetch VIN
    vin = fetch_vin(comm)
    if not vin:
        print("[❌] Failed to retrieve VIN. Exiting.")
        return

    # Step 3: Begin Live Data Polling
    poll_live_data(comm, vin)


if __name__ == "__main__":
    main()
