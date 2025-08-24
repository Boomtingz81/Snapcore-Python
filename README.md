# Snapcore-Python Diagnostic Suite

Lightweight but powerful Python diagnostic stack for OBD-II and CAN-based vehicles.  
Designed for **true fault analysis** — no simulations, no dummy VINs, no mock data.  
Every output is 100% live from the vehicle.

---

## 📁 Structure

| File                      | Purpose                          |
|---------------------------|----------------------------------|
| `main.py`                 | CLI entry point for the suite    |
| `part1_core.py`           | Core enums, CAN base handlers    |
| `part2_pids.py`           | SAE + Tesla-specific PID map     |
| `part3_dataclasses.py`    | Payload structures via classes   |
| `part4_comm.py`           | Serial/BLE driver interface      |
| `part5_database.py`       | Fault code DB & mappings         |
| `part6_operations.py`     | Request builder / CRUD helpers   |
| `part7_decoders.py`       | Raw hex → readable data          |
| `part8_persistence.py`    | Save / load local DB             |
| `part9_controller.py`     | Async command + logic engine     |
| `cli/obd_test.py`         | Basic live OBD session runner    |
| `cli/dtc.py`              | DTC read/clear helper            |
| `cli/mode09.py`           | Mode 09 VIN & ECU ID fetch       |
| `logs/`                   | Runtime logs (ignored in Git)    |

---

## ⚙️ Configuration

All runtime options are inside **`config.py`**:

```python
SERIAL_PORT = "COM5"              # Windows example
# Linux/macOS: "/dev/ttyUSB0"
# BLE: "00:15:83:XX:XX:XX"

BAUD_RATE   = 500000
CAN_PROTOCOL = "ISO15765"

TESLA_MODE  = True
SAVE_JSON   = True
DEBUG_MODE  = True

DEFAULT_VIN = None  # auto-detected via Mode 09
