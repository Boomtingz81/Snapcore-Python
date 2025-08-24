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

MIC3X2X Protocol Handler Module

Handles high-level protocol management and OBD-II data interpretation
for the MIC3X2X multi-protocol OBD to UART interpreter.

Supports all protocols documented in MIC3X2X datasheet v2.3.08:
- SAE J1850 VPW/PWM
- ISO 9141-2 / ISO 14230-4 (KWP2000)
- ISO 15765-4 CAN (11-bit/29-bit, various speeds)
- SAE J1939 CAN
- GM Single Wire CAN (GMLAN)
- Ford Medium Speed CAN (MS CAN)
- GM Chassis CAN (CH CAN)
- Fiat Low Speed CAN (LS CAN)
"""

import time
import logging
import struct
from typing import Dict, List, Optional, Union, Tuple, Any
from dataclasses import dataclass
from enum import Enum, IntEnum
import re

from communication_interface import MIC3X2XDevice, MICResponse, ResponseType
from device_config import DeviceConfig, ProtocolType, CANPhysicalLayer, WakeupMode

logger = logging.getLogger(__name__)


class OBDMode(IntEnum):
    """Standard OBD-II modes"""
    SHOW_CURRENT_DATA = 0x01
    SHOW_FREEZE_FRAME_DATA = 0x02
    SHOW_STORED_DTCS = 0x03
    CLEAR_DTCS = 0x04
    TEST_RESULTS_OXYGEN = 0x05
    TEST_RESULTS_OTHER = 0x06
    SHOW_PENDING_DTCS = 0x07
    CONTROL_OPERATION = 0x08
    REQUEST_VEHICLE_INFO = 0x09
    PERMANENT_DTCS = 0x0A


class CANFrameType(Enum):
    """CAN frame types for ISO 15765"""
    SINGLE_FRAME = "SF"        # 0
    FIRST_FRAME = "FF"         # 1
    CONSECUTIVE_FRAME = "CF"   # 2
    FLOW_CONTROL = "FC"        # 3


class FlowControlStatus(IntEnum):
    """ISO 15765 flow control status"""
    CONTINUE_TO_SEND = 0x30
    WAIT = 0x31
    OVERFLOW_ABORT = 0x32


@dataclass
class OBDCommand:
    """OBD command structure"""
    mode: int
    pid: int
    data: Optional[List[int]] = None
    description: str = ""
   
    def to_hex_string(self) -> str:
        """Convert to hex string for transmission"""
        cmd = f"{self.mode:02X}{self.pid:02X}"
        if self.data:
            for byte in self.data:
                cmd += f"{byte:02X}"
        return cmd


@dataclass
class OBDResponse:
    """Structured OBD response"""
    mode: int
    pid: int
    data: List[int]
    raw_data: str
    success: bool
    error_code: Optional[str] = None
    protocol_used: Optional[str] = None
    response_time_ms: Optional[int] = None


@dataclass
class CANFrame:
    """CAN frame structure for ISO 15765"""
    can_id: int
    dlc: int
    data: List[int]
    frame_type: CANFrameType
    sequence_number: Optional[int] = None
    data_length: Optional[int] = None  # For first frame
   
    @classmethod
    def parse_from_response(cls, response_line: str) -> 'CANFrame':
        """Parse CAN frame from MIC3X2X response line"""
        # Expected format: "7E8 06 41 00 BE 3F A8 13"
        parts = response_line.strip().split()
       
        if len(parts) < 2:
            raise ValueError(f"Invalid CAN frame format: {response_line}")
       
        can_id = int(parts[0], 16)
        dlc = int(parts[1], 16)
        data = [int(byte, 16) for byte in parts[2:2+dlc]]
       
        # Determine frame type from PCI (Protocol Control Information)
        if data:
            pci = data[0]
            frame_type_code = (pci >> 4) & 0x0F
           
            if frame_type_code == 0:
                frame_type = CANFrameType.SINGLE_FRAME
            elif frame_type_code == 1:
                frame_type = CANFrameType.FIRST_FRAME
            elif frame_type_code == 2:
                frame_type = CANFrameType.CONSECUTIVE_FRAME
            elif frame_type_code == 3:
                frame_type = CANFrameType.FLOW_CONTROL
            else:
                frame_type = CANFrameType.SINGLE_FRAME
        else:
            frame_type = CANFrameType.SINGLE_FRAME
       
        return cls(
            can_id=can_id,
            dlc=dlc,
            data=data,
            frame_type=frame_type
        )


class ProtocolHandler:
    """High-level protocol handler for MIC3X2X"""
   
    def __init__(self, device: MIC3X2XDevice, config: DeviceConfig):
        self.device = device
        self.config = config
        self.current_protocol: Optional[str] = None
        self.protocol_info: Dict[str, Any] = {}
        self.initialized = False
       
        # Protocol-specific settings
        self.can_flow_control_enabled = True
        self.iso_tp_timeout = 5.0  # ISO-TP timeout in seconds
        self.max_consecutive_frames = 0x0F
       
        # Multi-frame handling
        self.pending_multiframe: Optional[Dict[str, Any]] = None
        self.multiframe_buffer: List[int] = []
       
    def initialize(self) -> bool:
        """Initialize the protocol handler and device"""
        try:
            logger.info("Initializing MIC3X2X protocol handler")
           
            # Reset device to known state
            response = self.device.reset()
            if not response.success:
                logger.error("Device reset failed")
                return False
           
            # Get device information
            version_resp = self.device.get_version()
            if version_resp.success and version_resp.data_lines:
                self.protocol_info['device_version'] = version_resp.data_lines[0]
                logger.info(f"Device version: {self.protocol_info['device_version']}")
           
            # Configure basic settings
            self._configure_basic_settings()
           
            # Set default protocol
            if not self._set_protocol(self.config.default_protocol):
                logger.warning("Failed to set default protocol")
           
            self.initialized = True
            logger.info("Protocol handler initialization complete")
            return True
           
        except Exception as e:
            logger.error(f"Protocol handler initialization failed: {e}")
            return False
   
    def _configure_basic_settings(self):
        """Configure basic MIC3X2X settings"""
        # Disable echo for cleaner responses
        self.device.set_echo(False)
       
        # Enable headers for protocol identification
        self.device.set_headers(True)
       
        # Set adaptive timing
        if self.config.adaptive_timing == 0:
            self.device.send_command("ATAT0")
        elif self.config.adaptive_timing == 1:
            self.device.send_command("ATAT1")
        elif self.config.adaptive_timing == 2:
            self.device.send_command("ATAT2")
       
        # Configure response timeout
        timeout_val = min(255, max(1, self.config.response_timeout))
        self.device.send_command(f"ATST{timeout_val:02X}")
       
        # Set CAN auto-formatting if enabled
        if self.config.can_auto_formatting:
            self.device.send_command("ATCAF1")
        else:
            self.device.send_command("ATCAF0")
       
        # Set flow control
        if self.config.can_flow_control:
            self.device.send_command("ATCFC1")
        else:
            self.device.send_command("ATCFC0")
   
    def _set_protocol(self, protocol: ProtocolType) -> bool:
        """Set the active protocol"""
        try:
            response = self.device.set_protocol(protocol.value)
            if response.success:
                self.current_protocol = protocol.value
               
                # Get protocol description
                desc_resp = self.device.describe_protocol()
                if desc_resp.success and desc_resp.data_lines:
                    self.protocol_info['description'] = desc_resp.data_lines[0]
               
                logger.info(f"Protocol set to: {protocol.value} - {self.protocol_info.get('description', 'Unknown')}")
                return True
            else:
                logger.error(f"Failed to set protocol {protocol.value}: {response.error_message}")
                return False
               
        except Exception as e:
            logger.error(f"Error setting protocol: {e}")
            return False
   
    def auto_detect_protocol(self) -> Optional[str]:
        """Automatically detect the vehicle's protocol"""
        logger.info("Starting automatic protocol detection")
       
        # Try automatic protocol detection
        response = self.device.send_command("ATSP0")  # Auto protocol
        if response.success:
            # Send a test command to trigger protocol detection
            test_resp = self.send_obd_command(OBDCommand(mode=1, pid=0, description="Supported PIDs"))
            if test_resp.success:
                # Get the detected protocol
                proto_resp = self.device.describe_protocol_number()
                if proto_resp.success and proto_resp.data_lines:
                    detected_protocol = proto_resp.data_lines[0]
                    self.current_protocol = detected_protocol
                    logger.info(f"Auto-detected protocol: {detected_protocol}")
                    return detected_protocol
       
        # If auto-detection fails, try protocols in order
        for protocol in self.config.protocol_search_order:
            logger.debug(f"Trying protocol: {protocol.value}")
            if self._set_protocol(protocol):
                # Test with a simple command
                test_resp = self.send_obd_command(OBDCommand(mode=1, pid=0, description="Test"))
                if test_resp.success:
                    logger.info(f"Successfully connected using protocol: {protocol.value}")
                    return protocol.value
       
        logger.warning("No compatible protocol found")
        return None
   
    def send_obd_command(self, command: OBDCommand, timeout: float = None) -> OBDResponse:
        """Send an OBD command and parse the response"""
        if not self.initialized:
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data="",
                success=False,
                error_code="Handler not initialized"
            )
       
        if timeout is None:
            timeout = self.config.response_timeout / 1000.0 * 4.096  # Convert to seconds
       
        try:
            start_time = time.time()
           
            # Send the command
            cmd_str = command.to_hex_string()
            response = self.device.send_command(cmd_str, timeout)
           
            response_time = int((time.time() - start_time) * 1000)
           
            if not response.success:
                return OBDResponse(
                    mode=command.mode,
                    pid=command.pid,
                    data=[],
                    raw_data=response.raw_data,
                    success=False,
                    error_code=response.error_message,
                    response_time_ms=response_time
                )
           
            # Parse the response based on current protocol
            return self._parse_obd_response(command, response, response_time)
           
        except Exception as e:
            logger.error(f"Error sending OBD command {cmd_str}: {e}")
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data="",
                success=False,
                error_code=str(e)
            )
   
    def _parse_obd_response(self, command: OBDCommand, response: MICResponse, response_time: int) -> OBDResponse:
        """Parse OBD response based on protocol type"""
        if not response.data_lines:
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=response.raw_data,
                success=False,
                error_code="No data received",
                response_time_ms=response_time
            )
       
        try:
            # Check if this is a CAN protocol response
            if self._is_can_protocol():
                return self._parse_can_response(command, response, response_time)
            else:
                return self._parse_legacy_response(command, response, response_time)
               
        except Exception as e:
            logger.error(f"Error parsing OBD response: {e}")
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=response.raw_data,
                success=False,
                error_code=f"Parse error: {e}",
                response_time_ms=response_time
            )
   
    def _is_can_protocol(self) -> bool:
        """Check if current protocol is CAN-based"""
        if not self.current_protocol:
            return False
       
        can_protocols = ['6', '7', '8', '9', 'A', 'B', 'C']  # AT protocols
        can_protocols.extend(['33', '34', '35', '36', '53', '54', '63', '64'])  # ST protocols
       
        return self.current_protocol in can_protocols
   
    def _parse_can_response(self, command: OBDCommand, response: MICResponse, response_time: int) -> OBDResponse:
        """Parse CAN protocol response (ISO 15765)"""
        frames = []
       
        # Parse each response line as a CAN frame
        for line in response.data_lines:
            if line and not line.startswith('>'):
                try:
                    frame = CANFrame.parse_from_response(line)
                    frames.append(frame)
                except ValueError as e:
                    logger.warning(f"Failed to parse CAN frame: {line} - {e}")
                    continue
       
        if not frames:
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=response.raw_data,
                success=False,
                error_code="No valid CAN frames received",
                response_time_ms=response_time
            )
       
        # Handle single frame response
        if len(frames) == 1 and frames[0].frame_type == CANFrameType.SINGLE_FRAME:
            return self._parse_single_frame(command, frames[0], response.raw_data, response_time)
       
        # Handle multi-frame response
        elif len(frames) > 1:
            return self._parse_multiframe_response(command, frames, response.raw_data, response_time)
       
        else:
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=response.raw_data,
                success=False,
                error_code="Unsupported frame type",
                response_time_ms=response_time
            )
   
    def _parse_single_frame(self, command: OBDCommand, frame: CANFrame, raw_data: str, response_time: int) -> OBDResponse:
        """Parse single CAN frame response"""
        if len(frame.data) < 3:
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=raw_data,
                success=False,
                error_code="Frame too short",
                response_time_ms=response_time
            )
       
        # Extract OBD data from frame
        # Frame format: [PCI, Response_Mode, PID, Data...]
        data_length = frame.data[0] & 0x0F  # Lower 4 bits of PCI
        response_mode = frame.data[1]
        response_pid = frame.data[2]
        obd_data = frame.data[3:3+data_length-2]  # Subtract 2 for mode and PID
       
        # Verify response matches request
        if response_mode != (command.mode + 0x40):
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=raw_data,
                success=False,
                error_code=f"Mode mismatch: expected {command.mode + 0x40:02X}, got {response_mode:02X}",
                response_time_ms=response_time
            )
       
        if response_pid != command.pid:
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=raw_data,
                success=False,
                error_code=f"PID mismatch: expected {command.pid:02X}, got {response_pid:02X}",
                response_time_ms=response_time
            )
       
        return OBDResponse(
            mode=command.mode,
            pid=command.pid,
            data=obd_data,
            raw_data=raw_data,
            success=True,
            protocol_used=self.current_protocol,
            response_time_ms=response_time
        )
   
    def _parse_multiframe_response(self, command: OBDCommand, frames: List[CANFrame], raw_data: str, response_time: int) -> OBDResponse:
        """Parse multi-frame CAN response"""
        # Sort frames and reassemble data
        first_frame = None
        consecutive_frames = []
       
        for frame in frames:
            if frame.frame_type == CANFrameType.FIRST_FRAME:
                first_frame = frame
            elif frame.frame_type == CANFrameType.CONSECUTIVE_FRAME:
                consecutive_frames.append(frame)
       
        if not first_frame:
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=raw_data,
                success=False,
                error_code="No first frame found in multi-frame response",
                response_time_ms=response_time
            )
       
        # Extract total length from first frame
        total_length = ((first_frame.data[0] & 0x0F) << 8) | first_frame.data[1]
       
        # Start with data from first frame (skip FF length bytes, mode, PID)
        assembled_data = first_frame.data[4:]  # Skip PCI bytes, mode, PID
       
        # Sort consecutive frames by sequence number
        consecutive_frames.sort(key=lambda f: f.data[0] & 0x0F)
       
        # Add data from consecutive frames
        for frame in consecutive_frames:
            assembled_data.extend(frame.data[1:])  # Skip PCI byte
       
        # Trim to actual data length (subtract mode and PID bytes)
        obd_data = assembled_data[:total_length-2]
       
        return OBDResponse(
            mode=command.mode,
            pid=command.pid,
            data=obd_data,
            raw_data=raw_data,
            success=True,
            protocol_used=self.current_protocol,
            response_time_ms=response_time
        )
   
    def _parse_legacy_response(self, command: OBDCommand, response: MICResponse, response_time: int) -> OBDResponse:
        """Parse legacy protocol response (J1850, ISO 9141, KWP2000)"""
        # Legacy protocols typically return data in hex format
        # Format: "41 00 BE 3F A8 13" (for mode 1 PID 0)
       
        data_bytes = []
        for line in response.data_lines:
            # Split line into hex bytes
            hex_parts = line.strip().split()
            for part in hex_parts:
                try:
                    if len(part) == 2:  # Valid hex byte
                        data_bytes.append(int(part, 16))
                except ValueError:
                    continue
       
        if len(data_bytes) < 2:
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=response.raw_data,
                success=False,
                error_code="Insufficient data received",
                response_time_ms=response_time
            )
       
        # Verify response mode and PID
        response_mode = data_bytes[0]
        response_pid = data_bytes[1]
        obd_data = data_bytes[2:]
       
        if response_mode != (command.mode + 0x40):
            return OBDResponse(
                mode=command.mode,
                pid=command.pid,
                data=[],
                raw_data=response.raw_data,
                success=False,
                error_code=f"Mode mismatch: expected {command.mode + 0x40:02X}, got {response_mode:02X}",
                response_time_ms=response_time
            )
       
        return OBDResponse(
            mode=command.mode,
            pid=command.pid,
            data=obd_data,
            raw_data=response.raw_data,
            success=True,
            protocol_used=self.current_protocol,
            response_time_ms=response_time
        )
   
    def setup_wakeup_messages(self, sequences: Dict[int, Any]) -> bool:
        """Setup wake-up/keep-alive message sequences"""
        try:
            for seq_id, config in sequences.items():
                if self._is_can_protocol():
                    # Use VT CAN_WM command for CAN protocols
                    cmd = f"VTCAN_WM {seq_id},{config.get('protocol', 'XX')},{config['header']}"
                    cmd += f",{' '.join([f'{b:02X}' for b in config['data']])}"
                    cmd += f",{config['period_ms'] // 20},{config.get('mode', 2)}"
                else:
                    # Use VT ISO_WM command for ISO protocols
                    cmd = f"VTISO_WM {seq_id},{config.get('protocol', 'XX')},{config['header']}"
                    cmd += f",{' '.join([f'{b:02X}' for b in config['data']])}"
                    cmd += f",{config['period_ms'] // 20},{config.get('enabled', 1)}"
               
                response = self.device.send_command(cmd)
                if not response.success:
                    logger.warning(f"Failed to set wakeup sequence {seq_id}: {response.error_message}")
                    return False
                   
            logger.info(f"Configured {len(sequences)} wakeup sequences")
            return True
           
        except Exception as e:
            logger.error(f"Error setting up wakeup messages: {e}")
            return False
   
    def get_supported_pids(self, mode: int = 1) -> List[int]:
        """Get list of supported PIDs for a given mode"""
        supported_pids = []
        pid_groups = [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0]
       
        for group_pid in pid_groups:
            command = OBDCommand(mode=mode, pid=group_pid, description=f"Supported PIDs {group_pid:02X}-{group_pid+31:02X}")
            response = self.send_obd_command(command)
           
            if response.success and len(response.data) >= 4:
                # Each bit represents a PID
                for byte_idx, byte_val in enumerate(response.data[:4]):
                    for bit_idx in range(8):
                        if byte_val & (0x80 >> bit_idx):
                            pid = group_pid + byte_idx * 8 + bit_idx + 1
                            if pid <= 0xFF:
                                supported_pids.append(pid)
            else:
                break  # No more PID groups supported
       
        return supported_pids
   
    def get_vehicle_info(self) -> Dict[str, Any]:
        """Get basic vehicle information"""
        info = {}
       
        # Get VIN (Mode 9, PID 2)
        vin_cmd = OBDCommand(mode=9, pid=2, description="VIN")
        vin_resp = self.send_obd_command(vin_cmd)
        if vin_resp.success:
            # VIN is ASCII encoded
            try:
                vin = ''.join([chr(b) for b in vin_resp.data if 32 <= b <= 126])
                info['vin'] = vin.strip()
            except:
                info['vin'] = "Unknown"
       
        # Get calibration ID (Mode 9, PID 4)
        cal_cmd = OBDCommand(mode=9, pid=4, description="Calibration ID")
        cal_resp = self.send_obd_command(cal_cmd)
        if cal_resp.success:
            try:
                cal_id = ''.join([chr(b) for b in cal_resp.data if 32 <= b <= 126])
                info['calibration_id'] = cal_id.strip()
            except:
                info['calibration_id'] = "Unknown"
       
        # Get ECU name (Mode 9, PID 10)
        ecu_cmd = OBDCommand(mode=9, pid=10, description="ECU Name")
        ecu_resp = self.send_obd_command(ecu_cmd)
        if ecu_resp.success:
            try:
                ecu_name = ''.join([chr(b) for b in ecu_resp.data if 32 <= b <= 126])
                info['ecu_name'] = ecu_name.strip()
            except:
                info['ecu_name'] = "Unknown"
       
        # Add protocol information
        info['protocol'] = self.current_protocol
        info['protocol_description'] = self.protocol_info.get('description', 'Unknown')
       
        return info
   
    def cleanup(self):
        """Cleanup protocol handler resources"""
        logger.info("Cleaning up protocol handler")
        self.initialized = False
        self.current_protocol = None
        self.protocol_info.clear()


# Common OBD-II PID definitions
COMMON_PIDS = {
    # Mode 1 - Show current data
    0x00: {"name": "PIDs supported [01-20]", "formula": None},
    0x01: {"name": "Monitor status since DTCs cleared", "formula": None},
    0x02: {"name": "Freeze DTC", "formula": None},
    0x03: {"name": "Fuel system status", "formula": None},
    0x04: {"name": "Calculated engine load", "formula": "A*100/255", "unit": "%"},
    0x05: {"name": "Engine coolant temperature", "formula": "A-40", "unit": "°C"},
    0x06: {"name": "Short term fuel trim—Bank 1", "formula": "(A-128)*100/128", "unit": "%"},
    0x07: {"name": "Long term fuel trim—Bank 1", "formula": "(A-128)*100/128", "unit": "%"},
    0x08: {"name": "Short term fuel trim—Bank 2", "formula": "(A-128)*100/128", "unit": "%"},
    0x09: {"name": "Long term fuel trim—Bank 2", "formula": "(A-128)*100/128", "unit": "%"},
    0x0A: {"name": "Fuel pressure", "formula": "A*3", "unit": "kPa"},
    0x0B: {"name": "Intake manifold absolute pressure", "formula": "A", "unit": "kPa"},
    0x0C: {"name": "Engine RPM", "formula": "((A*256)+B)/4", "unit": "rpm"},
    0x0D: {"name": "Vehicle speed", "formula": "A", "unit": "km/h"},
    0x0E: {"name": "Timing advance", "formula": "(A-128)/2", "unit": "° before TDC"},
    0x0F: {"name": "Intake air temperature", "formula": "A-40", "unit": "°C"},
    0x10: {"name": "MAF air flow rate", "formula": "((A*256)+B)/100", "unit": "g/s"},
    0x11: {"name": "Throttle position", "formula": "A*100/255", "unit": "%"},
    0x12: {"name": "Commanded secondary air status", "formula": None},
    0x13: {"name": "Oxygen sensors present", "formula": None},
    0x14: {"name": "Oxygen Sensor 1", "formula": None},
    0x15: {"name": "Oxygen Sensor 2", "formula": None},
    # Add more PIDs as needed...
}


def interpret_pid_value(pid: int, data: List[int]) -> Dict[str, Any]:
    """Interpret PID data using standard formulas"""
    if pid not in COMMON_PIDS or not data:
        return {"raw_value": data, "interpreted_value": None, "unit": None}
   
    pid_info = COMMON_PIDS[pid]
    formula = pid_info.get("formula")
   
    if not formula:
        return {
            "raw_value": data,
            "interpreted_value": data,
            "unit": pid_info.get("unit"),
            "name": pid_info["name"]
        }
   
    try:
        # Simple formula evaluation
        A = data[0] if len(data) > 0 else 0
        B = data[1] if len(data) > 1 else 0
        C = data[2] if len(data) > 2 else 0
        D = data[3] if len(data) > 3 else 0
       
        # Evaluate formula (basic math operations only for security)
        result = eval(formula, {"__builtins__": {}}, {"A": A, "B": B, "C": C, "D": D})
       
        return {
            "raw_value": data,
            "interpreted_value": round(result, 2),
            "unit": pid_info.get("unit"),
            "name": pid_info["name"]
        }
       
    except Exception as e:
        logger.warning(f"Error interpreting PID {pid:02X}: {e}")
        return {
            "raw_value": data,
            "interpreted_value": None,
            "unit": pid_info.get("unit"), 
