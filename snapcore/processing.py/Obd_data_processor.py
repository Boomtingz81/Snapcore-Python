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

MIC3X2X OBD Data Processor Module

Processes, analyzes, and manages OBD-II diagnostic data from the MIC3X2X device.
Handles data logging, real-time monitoring, fault analysis, and diagnostic reporting.

Features:
- Real-time data streaming and buffering
- DTC (Diagnostic Trouble Code) management
- Data logging and export
- Statistical analysis and trending
- Fault detection and alerting
- Freeze frame data processing
"""

import time
import threading
import queue
import logging
import json
import csv
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import statistics

from protocol_handler import ProtocolHandler, OBDCommand, OBDResponse, interpret_pid_value

logger = logging.getLogger(__name__)


class DTCType(Enum):
    """Diagnostic Trouble Code types"""
    POWERTRAIN = "P"
    CHASSIS = "C"
    BODY = "B"
    NETWORK = "U"


class DTCStatus(Enum):
    """DTC status types"""
    CURRENT = "current"
    PENDING = "pending"
    PERMANENT = "permanent"
    STORED = "stored"


@dataclass
class DiagnosticTroubleCode:
    """Diagnostic Trouble Code structure"""
    code: str
    description: str
    status: DTCStatus
    timestamp: datetime
    freeze_frame_data: Optional[Dict[str, Any]] = None
    occurrence_count: int = 1
   
    def __post_init__(self):
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)


@dataclass
class OBDDataPoint:
    """Single OBD data measurement"""
    timestamp: datetime
    pid: int
    mode: int
    raw_value: List[int]
    interpreted_value: Optional[float]
    unit: Optional[str]
    name: str
    response_time_ms: int
    protocol: Optional[str] = None
   
    def __post_init__(self):
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)


@dataclass
class VehicleSnapshot:
    """Complete vehicle state at a point in time"""
    timestamp: datetime
    data_points: List[OBDDataPoint]
    voltage: Optional[float] = None
    dtcs: List[DiagnosticTroubleCode] = None
   
    def __post_init__(self):
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)
        if self.dtcs is None:
            self.dtcs = []


class DataLogger:
    """Handles data logging to various formats"""
   
    def __init__(self, log_directory: str = "logs"):
        self.log_dir = Path(log_directory)
        self.log_dir.mkdir(exist_ok=True)
       
        # Database for structured storage
        self.db_path = self.log_dir / "obd_data.sqlite"
        self._init_database()
       
    def _init_database(self):
        """Initialize SQLite database for data storage"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
           
            # Create tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS obd_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    mode INTEGER NOT NULL,
                    raw_value TEXT NOT NULL,
                    interpreted_value REAL,
                    unit TEXT,
                    name TEXT,
                    response_time_ms INTEGER,
                    protocol TEXT
                )
            """)
           
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dtc_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    code TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    freeze_frame_data TEXT
                )
            """)
           
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vehicle_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    voltage REAL,
                    data_points TEXT NOT NULL,
                    dtcs TEXT
                )
            """)
           
            # Create indexes for faster queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_obd_timestamp ON obd_data(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_obd_pid ON obd_data(pid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dtc_code ON dtc_data(code)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dtc_timestamp ON dtc_data(timestamp)")
           
            conn.commit()
            conn.close()
            logger.info(f"Database initialized: {self.db_path}")
           
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
   
    def log_data_point(self, data_point: OBDDataPoint):
        """Log a single OBD data point"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
           
            cursor.execute("""
                INSERT INTO obd_data
                (timestamp, pid, mode, raw_value, interpreted_value, unit, name, response_time_ms, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data_point.timestamp.isoformat(),
                data_point.pid,
                data_point.mode,
                json.dumps(data_point.raw_value),
                data_point.interpreted_value,
                data_point.unit,
                data_point.name,
                data_point.response_time_ms,
                data_point.protocol
            ))
           
            conn.commit()
            conn.close()
           
        except Exception as e:
            logger.error(f"Error logging data point: {e}")
   
    def log_dtc(self, dtc: DiagnosticTroubleCode):
        """Log a diagnostic trouble code"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
           
            cursor.execute("""
                INSERT OR REPLACE INTO dtc_data
                (timestamp, code, description, status, occurrence_count, freeze_frame_data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                dtc.timestamp.isoformat(),
                dtc.code,
                dtc.description,
                dtc.status.value,
                dtc.occurrence_count,
                json.dumps(dtc.freeze_frame_data) if dtc.freeze_frame_data else None
            ))
           
            conn.commit()
            conn.close()
           
        except Exception as e:
            logger.error(f"Error logging DTC: {e}")
   
    def log_snapshot(self, snapshot: VehicleSnapshot):
        """Log a complete vehicle snapshot"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
           
            # Convert data points to JSON
            data_points_json = json.dumps([asdict(dp) for dp in snapshot.data_points], default=str)
            dtcs_json = json.dumps([asdict(dtc) for dtc in snapshot.dtcs], default=str)
           
            cursor.execute("""
                INSERT INTO vehicle_snapshots
                (timestamp, voltage, data_points, dtcs)
                VALUES (?, ?, ?, ?)
            """, (
                snapshot.timestamp.isoformat(),
                snapshot.voltage,
                data_points_json,
                dtcs_json
            ))
           
            conn.commit()
            conn.close()
           
        except Exception as e:
            logger.error(f"Error logging snapshot: {e}")
   
    def export_to_csv(self, start_time: datetime = None, end_time: datetime = None,
                     filename: str = None) -> str:
        """Export OBD data to CSV file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"obd_export_{timestamp}.csv"
       
        csv_path = self.log_dir / filename
       
        try:
            conn = sqlite3.connect(str(self.db_path))
           
            query = "SELECT * FROM obd_data"
            params = []
           
            if start_time or end_time:
                conditions = []
                if start_time:
                    conditions.append("timestamp >= ?")
                    params.append(start_time.isoformat())
                if end_time:
                    conditions.append("timestamp <= ?")
                    params.append(end_time.isoformat())
                query += " WHERE " + " AND ".join(conditions)
           
            query += " ORDER BY timestamp"
           
            cursor = conn.cursor()
            cursor.execute(query, params)
           
            with open(csv_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Write header
                writer.writerow([desc[0] for desc in cursor.description])
                # Write data
                writer.writerows(cursor.fetchall())
           
            conn.close()
            logger.info(f"Data exported to {csv_path}")
            return str(csv_path)
           
        except Exception as e:
            logger.error(f"CSV export failed: {e}")
            return ""


class RealTimeMonitor:
    """Real-time OBD data monitoring and alerting"""
   
    def __init__(self, protocol_handler: ProtocolHandler):
        self.protocol_handler = protocol_handler
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.data_queue = queue.Queue(maxsize=1000)
        self.alert_callbacks: List[Callable] = []
       
        # Monitoring configuration
        self.monitor_pids = []  # PIDs to monitor
        self.poll_interval = 1.0  # seconds
        self.alert_thresholds = {}  # PID -> threshold config
       
        # Data buffers for analysis
        self.data_buffers = {}  # PID -> circular buffer
        self.buffer_size = 100
       
    def add_alert_callback(self, callback: Callable[[str, Dict], None]):
        """Add callback for alert notifications"""
        self.alert_callbacks.append(callback)
       
    def set_alert_threshold(self, pid: int, threshold_config: Dict[str, Any]):
        """Set alert threshold for a PID
       
        threshold_config example:
        {
            'min': 0,
            'max': 100,
            'rate_limit': 5,  # Max alerts per minute
            'message': 'Temperature too high'
        }
        """
        self.alert_thresholds[pid] = threshold_config
       
    def set_monitor_pids(self, pids: List[int], poll_interval: float = 1.0):
        """Set PIDs to monitor and polling interval"""
        self.monitor_pids = pids
        self.poll_interval = poll_interval
        logger.info(f"Monitor PIDs set to: {[f'{pid:02X}' for pid in pids]}")
       
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.monitoring:
            logger.warning("Monitoring already active")
            return
           
        if not self.monitor_pids:
            logger.warning("No PIDs configured for monitoring")
            return
           
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_worker, daemon=True)
        self.monitor_thread.start()
        logger.info("Real-time monitoring started")
       
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        logger.info("Real-time monitoring stopped")
       
    def _monitor_worker(self):
        """Background monitoring worker"""
        logger.info("Monitor worker started")
       
        while self.monitoring:
            start_time = time.time()
           
            for pid in self.monitor_pids:
                if not self.monitoring:
                    break
                   
                try:
                    # Query the PID
                    command = OBDCommand(mode=1, pid=pid, description=f"Monitor PID {pid:02X}")
                    response = self.protocol_handler.send_obd_command(command)
                   
                    if response.success:
                        # Interpret the data
                        interpreted = interpret_pid_value(pid, response.data)
                       
                        # Create data point
                        data_point = OBDDataPoint(
                            timestamp=datetime.now(),
                            pid=pid,
                            mode=1,
                            raw_value=response.data,
                            interpreted_value=interpreted.get('interpreted_value'),
                            unit=interpreted.get('unit'),
                            name=interpreted.get('name', f'PID_{pid:02X}'),
                            response_time_ms=response.response_time_ms or 0,
                            protocol=response.protocol_used
                        )
                       
                        # Add to queue for consumers
                        try:
                            self.data_queue.put_nowait(data_point)
                        except queue.Full:
                            # Remove oldest item and add new one
                            try:
                                self.data_queue.get_nowait()
                                self.data_queue.put_nowait(data_point)
                            except queue.Empty:
                                pass
                       
                        # Update data buffer
                        if pid not in self.data_buffers:
                            self.data_buffers[pid] = []
                       
                        buffer = self.data_buffers[pid]
                        buffer.append(data_point)
                        if len(buffer) > self.buffer_size:
                            buffer.pop(0)  # Remove oldest
                       
                        # Check for alerts
                        self._check_alerts(data_point)
                       
                except Exception as e:
                    logger.error(f"Error monitoring PID {pid:02X}: {e}")
                   
            # Maintain polling interval
            elapsed = time.time() - start_time
            sleep_time = max(0, self.poll_interval - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)
               
        logger.info("Monitor worker stopped")
       
    def _check_alerts(self, data_point: OBDDataPoint):
        """Check if data point triggers any alerts"""
        pid = data_point.pid
       
        if pid not in self.alert_thresholds:
            return
           
        config = self.alert_thresholds[pid]
        value = data_point.interpreted_value
       
        if value is None:
            return
           
        alert_triggered = False
        alert_message = ""
       
        # Check min/max thresholds
        if 'min' in config and value < config['min']:
            alert_triggered = True
            alert_message = f"{data_point.name} below minimum ({value} < {config['min']})"
           
        elif 'max' in config and value > config['max']:
            alert_triggered = True 
            alert_message = f"{data_point.name} above maximum ({value} > {config['max']})"
       
        if alert_triggered:
            alert_data = {
                'pid': pid,
                'value': value,
                'threshold': config,
                'data_point': data_point,
                'timestamp': data_point.timestamp
            }
           
            # Send to all registered callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert_message, alert_data)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")
                   
    def get_latest_data(self, timeout: float = 1.0) -> Optional[OBDDataPoint]:
        """Get latest data point from monitoring"""
        try:
            return self.data_queue.get(timeout=timeout)
        except queue.Empty:
            return None
           
    def get_buffer_stats(self, pid: int) -> Dict[str, Any]:
        """Get statistical analysis of buffered data for a PID"""
        if pid not in self.data_buffers or not self.data_buffers[pid]:
            return {}
           
        buffer = self.data_buffers[pid]
        values = [dp.interpreted_value for dp in buffer if dp.interpreted_value is not None]
       
        if not values:
            return {}
           
        try:
            return {
                'count': len(values),
                'min': min(values),
                'max': max(values),
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'stdev': statistics.stdev(values) if len(values) > 1 else 0,
                'latest': values[-1],
                'trend': self._calculate_trend(values),
                'unit': buffer[-1].unit
            }
        except Exception as e:
            logger.error(f"Error calculating stats for PID {pid:02X}: {e}")
            return {}
           
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction from recent values"""
        if len(values) < 3:
            return "stable"
           
        # Look at recent vs older values
        recent = values[-3:]
        older = values[-6:-3] if len(values) >= 6 else values[:-3]
       
        if not older:
            return "stable"
           
        recent_avg = statistics.mean(recent)
        older_avg = statistics.mean(older)
       
        change_pct = ((recent_avg - older_avg) / older_avg) * 100 if older_avg != 0 else 0
       
        if change_pct > 5:
            return "increasing"
        elif change_pct < -5:
            return "decreasing"
        else:
            return "stable"


class DTCManager:
    """Manages diagnostic trouble codes"""
   
    def __init__(self, protocol_handler: ProtocolHandler):
        self.protocol_handler = protocol_handler
        self.dtc_database = self._load_dtc_database()
       
    def _load_dtc_database(self) -> Dict[str, str]:
        """Load DTC code descriptions from database/file"""
        # Basic DTC descriptions - in production, this would be loaded from a comprehensive database
        return {
            "P0000": "No faults detected",
            "P0100": "Mass Air Flow Circuit Malfunction",
            "P0101": "Mass Air Flow Circuit Range/Performance Problem",
            "P0102": "Mass Air Flow Circuit Low Input",
            "P0103": "Mass Air Flow Circuit High Input",
            "P0104": "Mass Air Flow Circuit Intermittent",
            "P0105": "Manifold Absolute Pressure/Barometric Pressure Circuit Malfunction",
            "P0106": "Manifold Absolute Pressure/Barometric Pressure Circuit Range/Performance Problem",
            "P0107": "Manifold Absolute Pressure/Barometric Pressure Circuit Low Input",
            "P0108": "Manifold Absolute Pressure/Barometric Pressure Circuit High Input",
            "P0109": "Manifold Absolute Pressure/Barometric Pressure Circuit Intermittent",
            "P0110": "Intake Air Temperature Circuit Malfunction",
            "P0111": "Intake Air Temperature Circuit Range/Performance Problem",
            "P0112": "Intake Air Temperature Circuit Low Input",
            "P0113": "Intake Air Temperature Circuit High Input",
            "P0114": "Intake Air Temperature Circuit Intermittent",
            "P0115": "Engine Coolant Temperature Circuit Malfunction",
            "P0116": "Engine Coolant Temperature Circuit Range/Performance Problem",
            "P0117": "Engine Coolant Temperature Circuit Low Input",
            "P0118": "Engine Coolant Temperature Circuit High Input",
            "P0119": "Engine Coolant Temperature Circuit Intermittent",
            "P0120": "Throttle Position Sensor Circuit Malfunction",
            "P0130": "O2 Sensor Circuit Malfunction (Bank 1 Sensor 1)",
            "P0171": "System too Lean (Bank 1)",
            "P0172": "System too Rich (Bank 1)",
            "P0300": "Random/Multiple Cylinder Misfire Detected",
            "P0301": "Cylinder 1 Misfire Detected",
            "P0302": "Cylinder 2 Misfire Detected",
            "P0420": "Catalyst System Efficiency Below Threshold (Bank 1)",
            "P0430": "Catalyst System Efficiency Below Threshold (Bank 2)",
            # Add more codes as needed...
        }
       
    def read_stored_dtcs(self) -> List[DiagnosticTroubleCode]:
        """Read stored DTCs (Mode 3)"""
        return self._read_dtcs_by_mode(3, DTCStatus.STORED)
       
    def read_pending_dtcs(self) -> List[DiagnosticTroubleCode]:
        """Read pending DTCs (Mode 7)"""
        return self._read_dtcs_by_mode(7, DTCStatus.PENDING)
       
    def read_permanent_dtcs(self) -> List[DiagnosticTroubleCode]:
        """Read permanent DTCs (Mode 10)"""
        return self._read_dtcs_by_mode(10, DTCStatus.PERMANENT)
       
    def _read_dtcs_by_mode(self, mode: int, status: DTCStatus) -> List[DiagnosticTroubleCode]:
        """Read DTCs using specified mode"""
        dtcs = []
       
        try:
            command = OBDCommand(mode=mode, pid=0, description=f"Read DTCs Mode {mode}")
            response = self.protocol_handler.send_obd_command(command)
           
            if not response.success or not response.data:
                return dtcs
               
            # Parse DTC data
            dtc_data = response.data
            num_dtcs = dtc_data[0] if dtc_data else 0
           
            # Each DTC is 2 bytes
            for i in range(1, len(dtc_data) - 1, 2):
                if i + 1 < len(dtc_data):
                    dtc_bytes = [dtc_data[i], dtc_data[i + 1]]
                    dtc_code = self._decode_dtc(dtc_bytes)
                   
                    if dtc_code and dtc_code != "P0000":
                        dtc = DiagnosticTroubleCode(
                            code=dtc_code,
                            description=self.dtc_database.get(dtc_code, "Unknown DTC"),
                            status=status,
                            timestamp=datetime.now()
                        )
                        dtcs.append(dtc)
                       
        except Exception as e:
            logger.error(f"Error reading DTCs (mode {mode}): {e}")
           
        return dtcs
       
    def _decode_dtc(self, dtc_bytes: List[int]) -> str:
        """Decode DTC from 2-byte format"""
        if len(dtc_bytes) != 2:
            return ""
           
        byte1, byte2 = dtc_bytes
       
        # Extract DTC type from upper 2 bits
        dtc_type_code = (byte1 >> 6) & 0x03
        dtc_types = {0: "P", 1: "C", 2: "B", 3: "U"}
        dtc_type = dtc_types.get(dtc_type_code, "P")
       
        # Extract digits
        digit1 = (byte1 >> 4) & 0x03
        digit2 = byte1 & 0x0F
        digit3 = (byte2 >> 4) & 0x0F
        digit4 = byte2 & 0x0F
       
        return f"{dtc_type}{digit1}{digit2:X}{digit3:X}{digit4:X}"
       
    def clear_dtcs(self) -> bool:
        """Clear all DTCs (Mode 4)"""
        try:
            command = OBDCommand(mode=4, pid=0, description="Clear DTCs")
            response = self.protocol_handler.send_obd_command(command)
            return response.success
           
        except Exception as e:
            logger.error(f"Error clearing DTCs: {e}")
            return False
           
    def read_freeze_frame_data(self, dtc_number: int = 0) -> Optional[Dict[str, Any]]:
        """Read freeze frame data (Mode 2)"""
        try:
            # Read freeze frame PIDs (Mode 2, PID 0)
            command = OBDCommand(mode=2, pid=0, description="Freeze frame supported PIDs")
            response = self.protocol_handler.send_obd_command(command)
           
            if not response.success:
                return None
               
            freeze_frame_data = {}
           
            # Read common freeze frame PIDs
            common_pids = [0x02, 0x04, 0x05, 0x0C, 0x0D, 0x0F, 0x11]  # Common freeze frame PIDs
           
            for pid in common_pids:
                try:
                    cmd = OBDCommand(mode=2, pid=pid, description=f"Freeze frame PID {pid:02X}")
                    resp = self.protocol_handler.send_obd_command(cmd)
                   
                    if resp.success:
                        interpreted = interpret_pid_value(pid, resp.data)
                        freeze_frame_data[f"pid_{pid:02X}"] = {
                            'raw_value': resp.data,
                            'interpreted_value': interpreted.get('interpreted_value'),
                            'unit': interpreted.get('unit'),
                            'name': interpreted.get('name')
                        }
                except Exception as e:
                    logger.debug(f"Error reading freeze frame PID {pid:02X}: {e}")
                    continue
                   
            return freeze_frame_data if freeze_frame_data else None
           
        except Exception as e:
            logger.error(f"Error reading freeze frame data: {e}")
            return None


class OBDDataProcessor:
    """Main OBD data processor coordinating all components"""
   
    def __init__(self, protocol_handler: ProtocolHandler, log_directory: str = "logs"):
        self.protocol_handler = protocol_handler
        self.logger = DataLogger(log_directory)
        self.monitor = RealTimeMonitor(protocol_handler)
        self.dtc_manager = DTCManager(protocol_handler)
       
        # Processing state
        self.processing_active = False
        self.last_snapshot: Optional[VehicleSnapshot] = None
       
        # Add alert callback
        self.monitor.add_alert_callback(self._handle_alert)
       
    def _handle_alert(self, message: str, data: Dict[str, Any]):
        """Handle monitoring alerts"""
        logger.warning(f"OBD Alert: {message}")
       
        # Log alert data point
        if 'data_point' in data:
            self.logger.log_data_point(data['data_point'])
           
    def start_processing(self, monitor_pids: List[int] = None, poll_interval: float = 1.0):
        """Start data processing and monitoring"""
        if monitor_pids is None:
            # Default monitoring PIDs
            monitor_pids = [0x05, 0x0C, 0x0D, 0x0F, 0x11]  # Coolant temp, RPM, speed, intake temp, throttle
           
        self.monitor.set_monitor_pids(monitor_pids, poll_interval)
        self.monitor.start_monitoring()
        self.processing_active = True
       
        logger.info(f"OBD data processing started, monitoring PIDs: {[f'{pid:02X}' for pid in monitor_pids]}")
       
    def stop_processing(self):
        """Stop data processing and monitoring"""
        self.monitor.stop_monitoring()
        self.processing_active = False
        logger.info("OBD data processing stopped")
       
    def take_snapshot(self) -> VehicleSnapshot:
        """Take a complete vehicle snapshot"""
        timestamp = datetime.now()
        data_points = []
       
        # Read basic engine parameters
        basic_pids = [0x05, 0x0C, 0x0D, 0x0F, 0x11, 0x21, 0x2F]  # Common PIDs
       
        for pid in basic_pids:
            try:
                command = OBDCommand(mode=1, pid=pid, description=f"Snapshot PID {pid:02X}")
                response = self.protocol_handler.send_obd_command(command)
               
                if response.success:
                    interpreted = interpret_pid_value(pid, response.data)
                   
                    data_point = OBDDataPoint(
                        timestamp=timestamp,
                        pid=pid,
                        mode=1,
                        raw_value=response.data,
                        interpreted_value=interpreted.get('interpreted_value'),
                        unit=interpreted.get('unit'),
                        name=interpreted.get('name', f'PID_{pid:02X}'),
                        response_time_ms=response.response_time_ms or 0,
                        protocol=response.protocol_used
                    )
                   
                    data_points.append(data_point)
                   
            except Exception as e:
                logger.debug(f"Error reading PID {pid:02X} for snapshot: {e}")
               
        # Get voltage
        voltage = None
        try:
            voltage_resp = self.protocol_handler.device.get_voltage()
            if voltage_resp.success and voltage_resp.data_lines:
                voltage_str = voltage_resp.data_lines[0].replace('V', '').strip()
                voltage = float(voltage_str)
        except Exception as e:
            logger.debug(f"Error reading voltage: {e}")
           
        # Get current DTCs
        dtcs = self.dtc_manager.read_stored_dtcs()
       
        snapshot = VehicleSnapshot(
            timestamp=timestamp,
            data_points=data_points,
            voltage=voltage,
            dtcs=dtcs
        )
       
        # Log the snapshot
        self.logger.log_snapshot(snapshot)
        self.last_snapshot = snapshot
       
        return snapshot
       
    def get_diagnostic_report(self) -> Dict[str, Any]:
        """Generate comprehensive diagnostic report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'vehicle_info': {},
            'dtcs': {
                'stored': [],
                'pending': [],
                'permanent': []
            },
            'current_data': {},
            'statistics': {},
            'alerts': []
        }
       
        try:
            # Vehicle information
            report['vehicle_info'] = self.protocol_handler.get_vehicle_info()
           
            # DTCs
            report['dtcs']['store 
