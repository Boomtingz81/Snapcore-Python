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

MIC3X2X Device Manager Module

High-level device management and orchestration for MIC3X2X OBD-II diagnostics.
Coordinates all components and provides a unified interface for applications.

Features:
- Device discovery and connection management
- Configuration management and persistence
- Session management and state tracking
- Error handling and recovery
- Multi-device support
- Background task coordination
"""

import time
import threading
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import queue

from communication_interface import (
    MIC3X2XDevice, SerialInterface, BluetoothInterface,
    discover_serial_devices, discover_bluetooth_devices,
    CommunicationError, DeviceNotFoundError, CommandTimeoutError
)
from device_config import DeviceConfig, ConfigManager, ProtocolType, CANPhysicalLayer
from protocol_handler import ProtocolHandler, OBDCommand, OBDResponse
from obd_data_processor import OBDDataProcessor, OBDDataPoint, DiagnosticTroubleCode

logger = logging.getLogger(__name__)


class DeviceState(Enum):
    """Device connection and operational states"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    INITIALIZING = "initializing"
    READY = "ready"
    ERROR = "error"
    BUSY = "busy"


class SessionState(Enum):
    """Diagnostic session states"""
    IDLE = "idle"
    ACTIVE = "active"
    MONITORING = "monitoring"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


@dataclass
class DeviceInfo:
    """Device identification and status information"""
    device_id: str
    interface_type: str
    connection_params: Dict[str, Any]
    firmware_version: Optional[str] = None
    protocol_capabilities: List[str] = None
    last_seen: Optional[datetime] = None
    state: DeviceState = DeviceState.DISCONNECTED
    error_message: Optional[str] = None
   
    def __post_init__(self):
        if self.protocol_capabilities is None:
            self.protocol_capabilities = []
        if isinstance(self.last_seen, str):
            self.last_seen = datetime.fromisoformat(self.last_seen)


@dataclass
class DiagnosticSession:
    """Diagnostic session information"""
    session_id: str
    device_id: str
    start_time: datetime
    vehicle_info: Dict[str, Any]
    supported_pids: List[int]
    state: SessionState = SessionState.IDLE
    end_time: Optional[datetime] = None
    data_points_collected: int = 0
    dtcs_found: int = 0
   
    def __post_init__(self):
        if isinstance(self.start_time, str):
            self.start_time = datetime.fromisoformat(self.start_time)
        if isinstance(self.end_time, str) and self.end_time:
            self.end_time = datetime.fromisoformat(self.end_time)


class ConnectionManager:
    """Manages device connections and discovery"""
   
    def __init__(self):
        self.discovered_devices: Dict[str, DeviceInfo] = {}
        self.active_connections: Dict[str, MIC3X2XDevice] = {}
        self.connection_lock = threading.RLock()
       
    def discover_devices(self, timeout: float = 10.0) -> List[DeviceInfo]:
        """Discover available MIC3X2X devices"""
        discovered = []
       
        # Discover serial devices
        try:
            serial_ports = discover_serial_devices()
            for port in serial_ports:
                device_info = DeviceInfo(
                    device_id=f"serial_{port.replace('/', '_').replace('\\', '_')}",
                    interface_type="serial",
                    connection_params={"port": port, "baudrate": 115200},
                    last_seen=datetime.now()
                )
                discovered.append(device_info)
                self.discovered_devices[device_info.device_id] = device_info
               
        except Exception as e:
            logger.error(f"Serial device discovery failed: {e}")
       
        # Discover Bluetooth devices 
        try:
            bt_devices = discover_bluetooth_devices()
            for bt_dev in bt_devices:
                device_info = DeviceInfo(
                    device_id=f"bluetooth_{bt_dev['address'].replace(':', '_')}",
                    interface_type="bluetooth",
                    connection_params={"device_address": bt_dev['address']},
                    last_seen=datetime.now()
                )
                discovered.append(device_info)
                self.discovered_devices[device_info.device_id] = device_info
               
        except Exception as e:
            logger.debug(f"Bluetooth device discovery failed: {e}")
       
        logger.info(f"Discovered {len(discovered)} potential MIC3X2X devices")
        return discovered
   
    def connect_device(self, device_id: str, timeout: float = 10.0) -> Optional[MIC3X2XDevice]:
        """Connect to a specific device"""
        with self.connection_lock:
            if device_id in self.active_connections:
                return self.active_connections[device_id]
           
            if device_id not in self.discovered_devices:
                logger.error(f"Device {device_id} not found in discovered devices")
                return None
           
            device_info = self.discovered_devices[device_id]
            device_info.state = DeviceState.CONNECTING
           
            try:
                # Create appropriate interface
                if device_info.interface_type == "serial":
                    interface = SerialInterface()
                elif device_info.interface_type == "bluetooth":
                    interface = BluetoothInterface()
                else:
                    raise ValueError(f"Unsupported interface type: {device_info.interface_type}")
               
                # Connect interface
                if not interface.connect(**device_info.connection_params, timeout=timeout):
                    device_info.state = DeviceState.ERROR
                    device_info.error_message = "Failed to establish connection"
                    return None
               
                # Create MIC3X2X device wrapper
                device = MIC3X2XDevice(interface)
               
                # Test communication
                response = device.get_version()
                if not response.success:
                    interface.disconnect()
                    device_info.state = DeviceState.ERROR
                    device_info.error_message = "Device not responding"
                    return None
               
                # Extract firmware version
                if response.data_lines:
                    device_info.firmware_version = response.data_lines[0]
               
                device_info.state = DeviceState.CONNECTED
                device_info.last_seen = datetime.now()
                device_info.error_message = None
               
                self.active_connections[device_id] = device
                logger.info(f"Successfully connected to device {device_id}")
               
                return device
               
            except Exception as e:
                device_info.state = DeviceState.ERROR
                device_info.error_message = str(e)
                logger.error(f"Failed to connect to device {device_id}: {e}")
                return None
   
    def disconnect_device(self, device_id: str):
        """Disconnect from a device"""
        with self.connection_lock:
            if device_id in self.active_connections:
                try:
                    device = self.active_connections[device_id]
                    device.disconnect()
                    del self.active_connections[device_id]
                   
                    if device_id in self.discovered_devices:
                        self.discovered_devices[device_id].state = DeviceState.DISCONNECTED
                       
                    logger.info(f"Disconnected from device {device_id}")
                   
                except Exception as e:
                    logger.error(f"Error disconnecting from device {device_id}: {e}")
   
    def disconnect_all(self):
        """Disconnect from all devices"""
        device_ids = list(self.active_connections.keys())
        for device_id in device_ids:
            self.disconnect_device(device_id)
   
    def get_connection_status(self, device_id: str) -> DeviceState:
        """Get current connection status for a device"""
        if device_id in self.discovered_devices:
            return self.discovered_devices[device_id].state
        return DeviceState.DISCONNECTED
   
    def is_connected(self, device_id: str) -> bool:
        """Check if device is connected and responding"""
        with self.connection_lock:
            if device_id not in self.active_connections:
                return False
           
            device = self.active_connections[device_id]
            return device.is_connected()


class MIC3X2XDeviceManager:
    """Main device manager coordinating all MIC3X2X functionality"""
   
    def __init__(self, config_dir: str = "config", log_dir: str = "logs"):
        self.config_manager = ConfigManager(config_dir)
        self.connection_manager = ConnectionManager()
       
        # Active components
        self.protocol_handlers: Dict[str, ProtocolHandler] = {}
        self.data_processors: Dict[str, OBDDataProcessor] = {}
       
        # Session management
        self.active_sessions: Dict[str, DiagnosticSession] = {}
        self.session_counter = 0
       
        # State tracking
        self.current_device_id: Optional[str] = None
        self.device_configs: Dict[str, DeviceConfig] = {}
       
        # Background tasks
        self.background_tasks: Dict[str, threading.Thread] = {}
        self.task_stop_events: Dict[str, threading.Event] = {}
       
        # Event callbacks
        self.event_callbacks: Dict[str, List[Callable]] = {
            'device_connected': [],
            'device_disconnected': [],
            'data_received': [],
            'alert_triggered': [],
            'error_occurred': []
        }
       
        logger.info("MIC3X2X Device Manager initialized")
   
    def add_event_callback(self, event_type: str, callback: Callable):
        """Add callback for device events"""
        if event_type in self.event_callbacks:
            self.event_callbacks[event_type].append(callback)
        else:
            logger.warning(f"Unknown event type: {event_type}")
   
    def _trigger_event(self, event_type: str, data: Any = None):
        """Trigger event callbacks"""
        if event_type in self.event_callbacks:
            for callback in self.event_callbacks[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Event callback error ({event_type}): {e}")
   
    def discover_devices(self, timeout: float = 10.0) -> List[DeviceInfo]:
        """Discover available MIC3X2X devices"""
        return self.connection_manager.discover_devices(timeout)
   
    def connect_to_device(self, device_id: str = None, auto_discover: bool = True) -> bool:
        """Connect to MIC3X2X device"""
        try:
            # Auto-discover if no device specified
            if device_id is None and auto_discover:
                discovered = self.discover_devices()
                if not discovered:
                    logger.error("No devices discovered")
                    return False
                device_id = discovered[0].device_id
                logger.info(f"Auto-selected device: {device_id}")
           
            if device_id is None:
                logger.error("No device ID provided")
                return False
           
            # Connect to device
            device = self.connection_manager.connect_device(device_id)
            if not device:
                return False
           
            # Load or create device configuration
            config = self.config_manager.load_config("default")
            self.device_configs[device_id] = config
           
            # Initialize protocol handler
            protocol_handler = ProtocolHandler(device, config)
            if not protocol_handler.initialize():
                logger.error("Protocol handler initialization failed")
                self.connection_manager.disconnect_device(device_id)
                return False
           
            self.protocol_handlers[device_id] = protocol_handler
           
            # Initialize data processor
            data_processor = OBDDataProcessor(protocol_handler, log_dir="logs")
            self.data_processors[device_id] = data_processor
           
            self.current_device_id = device_id
           
            # Update device info
            device_info = self.connection_manager.discovered_devices[device_id]
            device_info.state = DeviceState.READY
           
            self._trigger_event('device_connected', device_info)
            logger.info(f"Successfully connected and initialized device {device_id}")
           
            return True
           
        except Exception as e:
            logger.error(f"Failed to connect to device {device_id}: {e}")
            self._trigger_event('error_occurred', str(e))
            return False
   
    def disconnect_device(self, device_id: str = None):
        """Disconnect from device"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None:
            return
       
        try:
            # Stop any background tasks
            self.stop_monitoring(device_id)
           
            # Cleanup components
            if device_id in self.data_processors:
                self.data_processors[device_id].cleanup()
                del self.data_processors[device_id]
           
            if device_id in self.protocol_handlers:
                self.protocol_handlers[device_id].cleanup()
                del self.protocol_handlers[device_id]
           
            # Disconnect from device
            self.connection_manager.disconnect_device(device_id)
           
            # Clean up sessions
            sessions_to_end = [sid for sid, session in self.active_sessions.items()
                             if session.device_id == device_id]
            for session_id in sessions_to_end:
                self.end_session(session_id)
           
            if device_id == self.current_device_id:
                self.current_device_id = None
           
            self._trigger_event('device_disconnected', device_id)
            logger.info(f"Disconnected from device {device_id}")
           
        except Exception as e:
            logger.error(f"Error disconnecting from device {device_id}: {e}")
   
    def start_diagnostic_session(self, device_id: str = None) -> Optional[str]:
        """Start a new diagnostic session"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None or device_id not in self.protocol_handlers:
            logger.error("No active device for diagnostic session")
            return None
       
        try:
            protocol_handler = self.protocol_handlers[device_id]
           
            # Auto-detect protocol if needed
            if not protocol_handler.current_protocol:
                detected_protocol = protocol_handler.auto_detect_protocol()
                if not detected_protocol:
                    logger.error("Failed to detect vehicle protocol")
                    return None
           
            # Get vehicle information
            vehicle_info = protocol_handler.get_vehicle_info()
           
            # Get supported PIDs
            supported_pids = protocol_handler.get_supported_pids()
           
            # Create session
            self.session_counter += 1
            session_id = f"session_{self.session_counter:04d}_{int(time.time())}"
           
            session = DiagnosticSession(
                session_id=session_id,
                device_id=device_id,
                start_time=datetime.now(),
                vehicle_info=vehicle_info,
                supported_pids=supported_pids,
                state=SessionState.ACTIVE
            )
           
            self.active_sessions[session_id] = session
           
            logger.info(f"Started diagnostic session {session_id} with {len(supported_pids)} supported PIDs")
            return session_id
           
        except Exception as e:
            logger.error(f"Failed to start diagnostic session: {e}")
            return None
   
    def end_session(self, session_id: str):
        """End a diagnostic session"""
        if session_id not in self.active_sessions:
            return
       
        session = self.active_sessions[session_id]
        session.state = SessionState.TERMINATED
        session.end_time = datetime.now()
       
        # Stop monitoring if active
        self.stop_monitoring(session.device_id)
       
        logger.info(f"Ended diagnostic session {session_id}")
        del self.active_sessions[session_id]
   
    def start_monitoring(self, device_id: str = None, pids: List[int] = None,
                        interval: float = 1.0) -> bool:
        """Start real-time data monitoring"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None or device_id not in self.data_processors:
            logger.error("No active device for monitoring")
            return False
       
        try:
            data_processor = self.data_processors[device_id]
           
            # Use default PIDs if none specified
            if pids is None:
                # Common monitoring PIDs: coolant temp, RPM, speed, throttle, MAF
                pids = [0x05, 0x0C, 0x0D, 0x11, 0x10]
           
            data_processor.start_processing(pids, interval)
           
            # Start background monitoring task
            self._start_monitoring_task(device_id)
           
            # Update session state
            for session in self.active_sessions.values():
                if session.device_id == device_id:
                    session.state = SessionState.MONITORING
           
            logger.info(f"Started monitoring on device {device_id}")
            return True
           
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            return False
   
    def stop_monitoring(self, device_id: str = None):
        """Stop real-time monitoring"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None:
            return
       
        # Stop background task
        task_name = f"monitor_{device_id}"
        if task_name in self.task_stop_events:
            self.task_stop_events[task_name].set()
           
        if task_name in self.background_tasks:
            self.background_tasks[task_name].join(timeout=5.0)
            del self.background_tasks[task_name]
            del self.task_stop_events[task_name]
       
        # Stop data processor
        if device_id in self.data_processors:
            self.data_processors[device_id].stop_processing()
       
        # Update session states
        for session in self.active_sessions.values():
            if session.device_id == device_id and session.state == SessionState.MONITORING:
                session.state = SessionState.ACTIVE
       
        logger.info(f"Stopped monitoring on device {device_id}")
   
    def _start_monitoring_task(self, device_id: str):
        """Start background monitoring task"""
        task_name = f"monitor_{device_id}"
       
        if task_name in self.background_tasks:
            return  # Already running
       
        stop_event = threading.Event()
        self.task_stop_events[task_name] = stop_event
       
        task = threading.Thread(
            target=self._monitoring_worker,
            args=(device_id, stop_event),
            daemon=True,
            name=task_name
        )
       
        self.background_tasks[task_name] = task
        task.start()
   
    def _monitoring_worker(self, device_id: str, stop_event: threading.Event):
        """Background monitoring worker thread"""
        logger.info(f"Started monitoring worker for device {device_id}")
       
        data_processor = self.data_processors.get(device_id)
        if not data_processor:
            return
       
        try:
            while not stop_event.is_set():
                # Get latest data
                data_points = data_processor.get_live_data_stream()
               
                if data_points:
                    # Update session statistics
                    for session in self.active_sessions.values():
                        if session.device_id == device_id:
                            session.data_points_collected += len(data_points)
                   
                    # Trigger data event
                    self._trigger_event('data_received', {
                        'device_id': device_id,
                        'data_points': data_points
                    })
               
                # Check for alerts and issues
                try:
                    # This would be expanded to include more sophisticated analysis
                    pass
                except Exception as e:
                    logger.debug(f"Error in monitoring analysis: {e}")
               
                # Sleep briefly
                stop_event.wait(0.5)
               
        except Exception as e:
            logger.error(f"Monitoring worker error for device {device_id}: {e}")
        finally:
            logger.info(f"Monitoring worker stopped for device {device_id}")
   
    def send_obd_command(self, mode: int, pid: int, device_id: str = None) -> Optional[OBDResponse]:
        """Send OBD command to device"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None or device_id not in self.protocol_handlers:
            logger.error("No active device for OBD command")
            return None
       
        try:
            protocol_handler = self.protocol_handlers[device_id]
            command = OBDCommand(mode=mode, pid=pid, description=f"Mode {mode:02X} PID {pid:02X}")
           
            response = protocol_handler.send_obd_command(command)
           
            # Update session statistics
            for session in self.active_sessions.values():
                if session.device_id == device_id:
                    session.data_points_collected += 1
           
            return response
           
        except Exception as e:
            logger.error(f"Error sending OBD command: {e}")
            return None
   
    def read_dtcs(self, device_id: str = None) -> Dict[str, List[DiagnosticTroubleCode]]:
        """Read diagnostic trouble codes"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None or device_id not in self.data_processors:
            return {}
       
        try:
            data_processor = self.data_processors[device_id]
            dtc_manager = data_processor.dtc_manager
           
            dtcs = {
                'stored': dtc_manager.read_stored_dtcs(),
                'pending': dtc_manager.read_pending_dtcs(),
                'permanent': dtc_manager.read_permanent_dtcs()
            }
           
            # Update session statistics
            total_dtcs = sum(len(dtc_list) for dtc_list in dtcs.values())
            for session in self.active_sessions.values():
                if session.device_id == device_id:
                    session.dtcs_found = total_dtcs
           
            return dtcs
           
        except Exception as e:
            logger.error(f"Error reading DTCs: {e}")
            return {}
   
    def clear_dtcs(self, device_id: str = None) -> bool:
        """Clear diagnostic trouble codes"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None or device_id not in self.data_processors:
            return False
       
        try:
            data_processor = self.data_processors[device_id]
            return data_processor.dtc_manager.clear_dtcs()
           
        except Exception as e:
            logger.error(f"Error clearing DTCs: {e}")
            return False
   
    def take_vehicle_snapshot(self, device_id: str = None) -> Optional[Dict[str, Any]]:
        """Take complete vehicle data snapshot"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None or device_id not in self.data_processors:
            return None
       
        try:
            data_processor = self.data_processors[device_id]
            snapshot = data_processor.take_snapshot()
           
            return {
                'timestamp': snapshot.timestamp.isoformat(),
                'voltage': snapshot.voltage,
                'data_points': [asdict(dp) for dp in snapshot.data_points],
                'dtcs': [asdict(dtc) for dtc in snapshot.dtcs],
                'device_id': device_id
            }
           
        except Exception as e:
            logger.error(f"Error taking vehicle snapshot: {e}")
            return None
   
    def generate_diagnostic_report(self, device_id: str = None) -> Optional[Dict[str, Any]]:
        """Generate comprehensive diagnostic report"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is None or device_id not in self.data_processors:
            return None
       
        try:
            data_processor = self.data_processors[device_id]
            report = data_processor.get_diagnostic_report()
           
            # Add device and session information
            report['device_info'] = asdict(self.connection_manager.discovered_devices.get(device_id, DeviceInfo("unknown", "unknown", {})))
           
            active_session = None
            for session in self.active_sessions.values():
                if session.device_id == device_id:
                    active_session = session
                    break
           
            if active_session:
                report['session_info'] = asdict(active_session)
           
            return report
           
        except Exception as e:
            logger.error(f"Error generating diagnostic report: {e}")
            return None
   
    def get_device_status(self, device_id: str = None) -> Dict[str, Any]:
        """Get current device status and information"""
        if device_id is None:
            device_id = self.current_device_id
       
        status = {
            'device_id': device_id,
            'connected': False,
            'state': DeviceState.DISCONNECTED.value,
            'sessions': [],
            'monitoring_active': False
        }
       
        if device_id is None:
            return status
       
        # Connection status
        status['connected'] = self.connection_manager.is_connected(device_id)
        status['state'] = self.connection_manager.get_connection_status(device_id).value
       
        # Device information
        if device_id in self.connection_manager.discovered_devices:
            device_info = self.connection_manager.discovered_devices[device_id]
            status['device_info'] = asdict(device_info)
       
        # Active sessions
        device_sessions = [asdict(session) for session in self.active_sessions.values()
                          if session.device_id == device_id]
        status['sessions'] = device_sessions
       
        # Monitoring status
        task_name = f"monitor_{device_id}"
        status['monitoring_active'] = task_name in self.background_tasks
       
        return status
   
    def get_all_device_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status for all known devices"""
        all_status = {}
       
        for device_id in self.connection_manager.discovered_devices:
            all_status[device_id] = self.get_device_status(device_id)
       
        return all_status
   
    def save_device_config(self, config: DeviceConfig, device_id: str = None, config_name: str = "default"):
        """Save device configuration"""
        if device_id is None:
            device_id = self.current_device_id
       
        if device_id is not None:
            self.device_configs[device_id] = config
       
        self.config_manager.save_config(config, config_name)
        logger.info(f"Saved device configuration: {config_name}")
   
    def load_device_config(self, config_name: str = "default") -> DeviceConfig:
        """Load device configuration"""
        return self.config_manager.load_config(config_name)
   
    def cleanup(self):
        """Cleanup all resources"""
        logger.info("Cleaning up MIC3X2X Device Manager")
       
        # Stop all background tasks
        for task_name, stop_event in self.task_stop_events.items():
            stop_event.set()
       
        for task_name, task in self.background_tasks.items():
            task.join(timeout=5.0)
       
        # End all sessions
        session_ids = list(self.active_sessions.keys())
        for session_id in session_ids:
            self.end_session(session_id)
       
        # Disconnect all devices
        self.connection_manager.disconnect_all()
       
        logger.info("Device Manager cleanup complete") 
