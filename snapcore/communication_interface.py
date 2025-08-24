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

MIC3X2X Communication Interface Module

Handles low-level communication with MIC3X2X devices over various transport layers:
- UART/USB (primary interface)
- Bluetooth (wireless modules)
- Network (future expansion)

Implements the three command sets: AT, ST, and VT commands as documented
in the MIC3X2X datasheet v2.3.08
"""

import serial
import time
import threading
import queue
import logging
import re
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Union, Callable, Any
from dataclasses import dataclass
from enum import Enum
import struct

try:
    import bluetooth
    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False

try:
    import bleak
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

logger = logging.getLogger(__name__)


class CommandSet(Enum):
    """MIC3X2X command set types"""
    AT = "AT"    # ELM327 compatible commands
    ST = "ST"    # STN compatible commands 
    VT = "VT"    # MIC3X2X macro commands


class ResponseType(Enum):
    """Types of responses from MIC3X2X"""
    OK = "OK"
    ERROR = "?"
    NO_DATA = "NO DATA"
    DATA = "DATA"
    PROMPT = ">"
    BUFFER_FULL = "BUFFER FULL"
    BUFFER_SMALL = "BUFFER SMALL"
    SEARCHING = "SEARCHING..."
    UNABLE_TO_CONNECT = "UNABLE TO CONNECT"
    BUS_INIT_ERROR = "BUS INIT: ...ERROR"


@dataclass
class MICResponse:
    """Structured response from MIC3X2X device"""
    raw_data: str
    response_type: ResponseType
    data_lines: List[str]
    success: bool
    error_message: Optional[str] = None
    execution_time_ms: Optional[int] = None
   

class CommunicationError(Exception):
    """Base exception for communication errors"""
    pass


class DeviceNotFoundError(CommunicationError):
    """Device not found or not responding"""
    pass


class CommandTimeoutError(CommunicationError):
    """Command timed out waiting for response"""
    pass


class InvalidResponseError(CommunicationError):
    """Invalid or unexpected response from device"""
    pass


class CommunicationInterface(ABC):
    """Abstract base class for MIC3X2X communication interfaces"""
   
    def __init__(self):
        self.connected = False
        self.device_info = {}
        self.response_callbacks: List[Callable] = []
       
    @abstractmethod
    def connect(self, **kwargs) -> bool:
        """Connect to the device"""
        pass
   
    @abstractmethod
    def disconnect(self):
        """Disconnect from the device"""
        pass
   
    @abstractmethod
    def send_raw(self, data: bytes) -> int:
        """Send raw bytes to device"""
        pass
   
    @abstractmethod
    def read_raw(self, timeout: float = 1.0) -> bytes:
        """Read raw bytes from device"""
        pass
   
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connected to device"""
        pass


class SerialInterface(CommunicationInterface):
    """Serial/UART communication interface for MIC3X2X"""
   
    def __init__(self, port: str = None, baudrate: int = 115200):
        super().__init__()
        self.port = port
        self.baudrate = baudrate
        self.serial_conn: Optional[serial.Serial] = None
        self.read_buffer = queue.Queue()
        self.read_thread: Optional[threading.Thread] = None
        self.read_thread_running = False
       
    def connect(self, port: str = None, baudrate: int = None, timeout: float = 2.0) -> bool:
        """Connect to MIC3X2X via serial port"""
        if port:
            self.port = port
        if baudrate:
            self.baudrate = baudrate
           
        if not self.port:
            raise ValueError("Serial port must be specified")
           
        try:
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False
            )
           
            # Start read thread
            self.read_thread_running = True
            self.read_thread = threading.Thread(target=self._read_worker, daemon=True)
            self.read_thread.start()
           
            self.connected = True
            logger.info(f"Connected to MIC3X2X on {self.port} at {self.baudrate} baud")
            return True
           
        except serial.SerialException as e:
            logger.error(f"Failed to connect to {self.port}: {e}")
            self.connected = False
            return False
   
    def disconnect(self):
        """Disconnect from serial port"""
        self.read_thread_running = False
       
        if self.read_thread and self.read_thread.is_alive():
            self.read_thread.join(timeout=1.0)
           
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
           
        self.connected = False
        logger.info("Disconnected from MIC3X2X")
   
    def send_raw(self, data: bytes) -> int:
        """Send raw bytes to device"""
        if not self.is_connected():
            raise CommunicationError("Not connected to device")
           
        try:
            bytes_sent = self.serial_conn.write(data)
            self.serial_conn.flush()
            return bytes_sent
        except serial.SerialException as e:
            logger.error(f"Error sending data: {e}")
            raise CommunicationError(f"Send failed: {e}")
   
    def read_raw(self, timeout: float = 1.0) -> bytes:
        """Read raw bytes from device"""
        if not self.is_connected():
            raise CommunicationError("Not connected to device")
           
        try:
            return self.read_buffer.get(timeout=timeout)
        except queue.Empty:
            return b''
   
    def is_connected(self) -> bool:
        """Check if connected"""
        return self.connected and self.serial_conn and self.serial_conn.is_open
   
    def _read_worker(self):
        """Background thread to read data from serial port"""
        while self.read_thread_running and self.serial_conn and self.serial_conn.is_open:
            try:
                if self.serial_conn.in_waiting > 0:
                    data = self.serial_conn.read(self.serial_conn.in_waiting)
                    if data:
                        self.read_buffer.put(data)
                else:
                    time.sleep(0.01)  # Small delay to prevent busy waiting
                   
            except serial.SerialException as e:
                logger.error(f"Read error: {e}")
                break
            except Exception as e:
                logger.error(f"Unexpected error in read worker: {e}")
                break


class BluetoothInterface(CommunicationInterface):
    """Bluetooth communication interface for wireless MIC3X2X modules"""
   
    def __init__(self, device_address: str = None):
        super().__init__()
        self.device_address = device_address
        self.socket = None
        self.read_buffer = queue.Queue()
        self.read_thread: Optional[threading.Thread] = None
        self.read_thread_running = False
       
        if not BLUETOOTH_AVAILABLE:
            raise ImportError("Bluetooth support not available. Install pybluez.")
   
    def connect(self, device_address: str = None, port: int = 1, timeout: float = 10.0) -> bool:
        """Connect to MIC3X2X via Bluetooth"""
        if device_address:
            self.device_address = device_address
           
        if not self.device_address:
            raise ValueError("Bluetooth device address must be specified")
       
        try:
            self.socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self.socket.settimeout(timeout)
            self.socket.connect((self.device_address, port))
           
            # Start read thread
            self.read_thread_running = True
            self.read_thread = threading.Thread(target=self._bt_read_worker, daemon=True)
            self.read_thread.start()
           
            self.connected = True
            logger.info(f"Connected to MIC3X2X via Bluetooth: {self.device_address}")
            return True
           
        except bluetooth.btcommon.BluetoothError as e:
            logger.error(f"Bluetooth connection failed: {e}")
            self.connected = False
            return False
   
    def disconnect(self):
        """Disconnect Bluetooth connection"""
        self.read_thread_running = False
       
        if self.read_thread and self.read_thread.is_alive():
            self.read_thread.join(timeout=1.0)
           
        if self.socket:
            self.socket.close()
            self.socket = None
           
        self.connected = False
        logger.info("Disconnected Bluetooth")
   
    def send_raw(self, data: bytes) -> int:
        """Send raw bytes via Bluetooth"""
        if not self.is_connected():
            raise CommunicationError("Not connected to device")
           
        try:
            return self.socket.send(data)
        except bluetooth.btcommon.BluetoothError as e:
            logger.error(f"Bluetooth send error: {e}")
            raise CommunicationError(f"Send failed: {e}")
   
    def read_raw(self, timeout: float = 1.0) -> bytes:
        """Read raw bytes via Bluetooth"""
        if not self.is_connected():
            raise CommunicationError("Not connected to device")
           
        try:
            return self.read_buffer.get(timeout=timeout)
        except queue.Empty:
            return b''
   
    def is_connected(self) -> bool:
        """Check Bluetooth connection status"""
        return self.connected and self.socket is not None
   
    def _bt_read_worker(self):
        """Background thread for Bluetooth reading"""
        while self.read_thread_running and self.socket:
            try:
                data = self.socket.recv(1024)
                if data:
                    self.read_buffer.put(data)
                else:
                    break  # Connection closed
                   
            except bluetooth.btcommon.BluetoothError as e:
                logger.error(f"Bluetooth read error: {e}")
                break
            except Exception as e:
                logger.error(f"Unexpected Bluetooth error: {e}")
                break


class MIC3X2XDevice:
    """High-level interface to MIC3X2X device with command processing"""
   
    # MIC3X2X response patterns
    PROMPT_PATTERN = re.compile(rb'>')
    OK_PATTERN = re.compile(rb'OK\r')
    ERROR_PATTERN = re.compile(rb'\?\r')
    NO_DATA_PATTERN = re.compile(rb'NO DATA\r')
    SEARCHING_PATTERN = re.compile(rb'SEARCHING\.\.\.')
   
    def __init__(self, interface: CommunicationInterface):
        self.interface = interface
        self.command_lock = threading.RLock()
        self.default_timeout = 5.0
        self.echo_enabled = False
        self.line_terminator = '\r'
        self.response_buffer = b''
       
    def connect(self, **kwargs) -> bool:
        """Connect to MIC3X2X device"""
        return self.interface.connect(**kwargs)
   
    def disconnect(self):
        """Disconnect from device"""
        self.interface.disconnect()
   
    def is_connected(self) -> bool:
        """Check connection status"""
        return self.interface.is_connected()
   
    def send_command(self, command: str, timeout: float = None) -> MICResponse:
        """Send a command and wait for response"""
        if timeout is None:
            timeout = self.default_timeout
           
        with self.command_lock:
            return self._execute_command(command, timeout)
   
    def _execute_command(self, command: str, timeout: float) -> MICResponse:
        """Execute command with proper response handling"""
        start_time = time.time()
       
        # Prepare command
        if not command.endswith(self.line_terminator):
            command += self.line_terminator
           
        cmd_bytes = command.encode('ascii', errors='ignore')
       
        try:
            # Send command
            self.interface.send_raw(cmd_bytes)
            logger.debug(f"Sent command: {command.strip()}")
           
            # Read response
            response_data = self._read_response(timeout)
            execution_time = int((time.time() - start_time) * 1000)
           
            # Parse response
            response = self._parse_response(response_data, execution_time)
            logger.debug(f"Response: {response.raw_data[:100]}...")
           
            return response
           
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return MICResponse(
                raw_data="",
                response_type=ResponseType.ERROR,
                data_lines=[],
                success=False,
                error_message=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000)
            )
   
    def _read_response(self, timeout: float) -> bytes:
        """Read complete response from device"""
        response_data = b''
        end_time = time.time() + timeout
        prompt_received = False
       
        while time.time() < end_time and not prompt_received:
            try:
                chunk = self.interface.read_raw(timeout=0.1)
                if chunk:
                    response_data += chunk
                   
                    # Check for prompt indicating command completion
                    if self.PROMPT_PATTERN.search(response_data):
                        prompt_received = True
                        break
                       
            except Exception as e:
                logger.error(f"Error reading response: {e}")
                break
       
        if not prompt_received and not response_data:
            raise CommandTimeoutError(f"No response received within {timeout}s")
           
        return response_data
   
    def _parse_response(self, data: bytes, execution_time: int) -> MICResponse:
        """Parse raw response data into structured format"""
        try:
            # Decode to string
            text = data.decode('ascii', errors='ignore')
           
            # Split into lines and clean
            lines = [line.strip() for line in text.split('\r') if line.strip()]
           
            # Remove echo if present
            if self.echo_enabled and lines:
                lines = lines[1:]  # Remove echoed command
           
            # Remove prompt
            if lines and lines[-1] == '>':
                lines = lines[:-1]
               
            # Determine response type
            response_type = ResponseType.DATA
            success = True
            error_msg = None
           
            if not lines:
                response_type = ResponseType.OK
            elif any('?' in line for line in lines):
                response_type = ResponseType.ERROR
                success = False
                error_msg = "Command error"
            elif any('NO DATA' in line for line in lines):
                response_type = ResponseType.NO_DATA
                success = False
                error_msg = "No data available"
            elif any('UNABLE TO CONNECT' in line for line in lines):
                response_type = ResponseType.UNABLE_TO_CONNECT
                success = False
                error_msg = "Unable to connect to vehicle"
            elif any('SEARCHING' in line for line in lines):
                response_type = ResponseType.SEARCHING
               
            return MICResponse(
                raw_data=text,
                response_type=response_type,
                data_lines=lines,
                success=success,
                error_message=error_msg,
                execution_time_ms=execution_time
            )
           
        except Exception as e:
            logger.error(f"Response parsing error: {e}")
            return MICResponse(
                raw_data=data.decode('ascii', errors='ignore'),
                response_type=ResponseType.ERROR,
                data_lines=[],
                success=False,
                error_message=f"Parse error: {e}",
                execution_time_ms=execution_time
            )
   
    # High-level command methods
    def reset(self) -> MICResponse:
        """Reset the MIC3X2X device (ATZ command)"""
        response = self.send_command("ATZ", timeout=10.0)
        if response.success:
            time.sleep(2.0)  # Allow device to initialize
        return response
   
    def get_version(self) -> MICResponse:
        """Get device version (ATI command)"""
        return self.send_command("ATI")
   
    def get_voltage(self) -> MICResponse:
        """Read vehicle voltage (ATRV command)"""
        return self.send_command("ATRV")
   
    def set_echo(self, enabled: bool) -> MICResponse:
        """Enable/disable command echo"""
        command = "ATE1" if enabled else "ATE0"
        response = self.send_command(command)
        if response.success:
            self.echo_enabled = enabled
        return response
   
    def set_headers(self, enabled: bool) -> MICResponse:
        """Enable/disable header display"""
        command = "ATH1" if enabled else "ATH0"
        return self.send_command(command)
   
    def set_protocol(self, protocol: Union[str, int]) -> MICResponse:
        """Set OBD protocol"""
        return self.send_command(f"ATSP{protocol}")
   
    def describe_protocol(self) -> MICResponse:
        """Get current protocol description"""
        return self.send_command("ATDP")
   
    def describe_protocol_number(self) -> MICResponse:
        """Get current protocol number"""
        return self.send_command("ATDPN")
   
    # VT (MIC3X2X specific) commands
    def vt_get_version(self) -> MICResponse:
        """Get MIC3X2X firmware version (VTVERS command)"""
        return self.send_command("VTVERS")
   
    def vt_set_protocol(self, protocol_type: int, protocol_id: str) -> MICResponse:
        """Set protocol using VT commands (VTP1xx or VTP2xx)"""
        return self.send_command(f"VTP{protocol_type}{protocol_id}")
   
    def vt_show_bus(self, can_type: str = None) -> MICResponse:
        """Measure bus activity and estimate protocols"""
        if can_type:
            return self.send_command(f"VTSHOW_BUS {can_type}")
        else:
            return self.send_command("VTSHOW_BUS")
   
    def vt_configure_can(self, protocol: str, option: str, baudrate: str,
                        physical_type: str, tm_mode: str = None) -> MICResponse:
        """Configure CAN protocol (VTCFG_CAN command)"""
        cmd = f"VTCFG_CAN {protocol},{option},{baudrate},{physical_type}"
        if tm_mode:
            cmd += f",{tm_mode}"
        return self.send_command(cmd)
   
    # ST (STN compatible) commands 
    def st_set_protocol(self, protocol: str) -> MICResponse:
        """Set protocol using ST command"""
        return self.send_command(f"STP{protocol}")
   
    def st_get_protocol(self) -> MICResponse:
        """Get current protocol (ST format)"""
        return self.send_command("STPR")
   
    def st_monitor(self) -> MICResponse:
        """Start monitoring bus (STM command)"""
        return self.send_command("STM")


def discover_serial_devices() -> List[str]:
    """Discover available serial ports that might be MIC3X2X devices"""
    import serial.tools.list_ports
   
    ports = []
    for port in serial.tools.list_ports.comports():
        # Look for common USB-serial adapters and OBD interfaces
        if any(keyword in (port.description or '').lower() for keyword in
               ['usb', 'serial', 'obd', 'elm', 'mic', 'uart']):
            ports.append(port.device)
        # Also include all COM/tty ports as fallback
        elif port.device.startswith(('/dev/tty', 'COM')):
            ports.append(port.device)
   
    return sorted(ports)


def discover_bluetooth_devices() -> List[Dict[str, str]]:
    """Discover nearby Bluetooth devices that might be MIC3X2X"""
    if not BLUETOOTH_AVAILABLE:
        return []
   
    try:
        nearby_devices = bluetooth.discover_devices(lookup_names=True, duration=8)
        obd_devices = []
       
        for addr, name in nearby_devices:
            if name and any(keyword in name.lower() for keyword in
                          ['obd', 'elm', 'mic', 'vgate', 'obdlink']):
                obd_devices.append({
                    'address': addr,
                    'name': name
                })
       
        return obd_devices
       
    except Exception as e:
        logger.error(f"Bluetooth discovery failed: {e}")
        return [] 
