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

import re
from typing import Dict, List, Optional, Union, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import struct
import logging

class MessageType(Enum):
    """OBD message types"""
    SINGLE_FRAME = "SF"
    FIRST_FRAME = "FF"
    CONSECUTIVE_FRAME = "CF"
    FLOW_CONTROL = "FC"
    ERROR_RESPONSE = "ERROR"
    NO_DATA = "NO_DATA"

class ProtocolFormat(Enum):
    """Protocol data formats"""
    J1850 = "J1850"
    ISO_9141 = "ISO9141"
    ISO_14230 = "ISO14230"
    ISO_15765 = "ISO15765"  # CAN
    SAE_J1939 = "J1939"
    RAW_CAN = "RAW_CAN"

@dataclass
class ParsedMessage:
    """Parsed OBD message structure"""
    raw_data: str
    message_type: MessageType
    protocol: Optional[ProtocolFormat] = None
    header: Optional[str] = None
    data: Optional[List[int]] = None
    pid: Optional[int] = None
    mode: Optional[int] = None
    dlc: Optional[int] = None
    extended_address: Optional[int] = None
    error_code: Optional[str] = None
    frame_sequence: Optional[int] = None
    total_length: Optional[int] = None

@dataclass
class OBDParameter:
    """OBD parameter definition"""
    pid: int
    name: str
    description: str
    formula: str
    units: str
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    data_bytes: int = 1

class DataParser:
    """
    Data parser and interpreter for MIC3X2X OBD responses
    Handles multi-frame messages, various protocols, and OBD-II parameter conversion
    """
   
    def __init__(self):
        self.logger = logging.getLogger(__name__)
       
        # Multi-frame message assembly
        self.multi_frame_buffer = {}
       
        # OBD parameter definitions
        self.obd_parameters = self._initialize_obd_parameters()
       
        # Protocol-specific patterns
        self.message_patterns = {
            ProtocolFormat.ISO_15765: {
                'single_frame': re.compile(r'^([0-9A-F]{2,6})\s([0-7])([0-9A-F]+)$'),
                'first_frame': re.compile(r'^([0-9A-F]{2,6})\s1([0-9A-F])([0-9A-F]+)$'),
                'consecutive_frame': re.compile(r'^([0-9A-F]{2,6})\s2([0-9A-F])([0-9A-F]+)$'),
                'flow_control': re.compile(r'^([0-9A-F]{2,6})\s3([0-9A-F])([0-9A-F]+)$'),
            },
            ProtocolFormat.J1850: {
                'message': re.compile(r'^([0-9A-F]{2}\s[0-9A-F]{2}\s[0-9A-F]{2})(.*)$'),
            },
            ProtocolFormat.ISO_9141: {
                'message': re.compile(r'^([0-9A-F]{2}\s[0-9A-F]{2}\s[0-9A-F]{2})(.*)$'),
            }
        }
       
    def parse_response(self, response: str, protocol: Optional[ProtocolFormat] = None) -> List[ParsedMessage]:
        """Parse OBD response into structured messages"""
        if not response or not response.strip():
            return []
       
        response = response.strip().upper()
       
        # Handle common error responses
        if self._is_error_response(response):
            return [ParsedMessage(
                raw_data=response,
                message_type=MessageType.ERROR_RESPONSE,
                error_code=response
            )]
       
        # Handle "NO DATA" response
        if "NO DATA" in response:
            return [ParsedMessage(
                raw_data=response,
                message_type=MessageType.NO_DATA
            )]
       
        # Split multi-line responses
        lines = [line.strip() for line in response.split('\n') if line.strip()]
        parsed_messages = []
       
        for line in lines:
            message = self._parse_single_line(line, protocol)
            if message:
                parsed_messages.append(message)
       
        # Attempt to assemble multi-frame messages
        return self._assemble_multi_frame_messages(parsed_messages)
   
    def extract_obd_data(self, messages: List[ParsedMessage]) -> Dict[str, Any]:
        """Extract and convert OBD parameter values from parsed messages"""
        results = {}
       
        for message in messages:
            if message.mode is None or message.pid is None or not message.data:
                continue
           
            # Only process mode 1 (current data) responses for now
            if message.mode == 0x41:  # Response to mode 1
                pid = message.pid
                data_bytes = message.data[2:]  # Skip mode and PID response bytes
               
                if pid in self.obd_parameters:
                    param = self.obd_parameters[pid]
                    try:
                        value = self._convert_obd_value(param, data_bytes)
                        results[param.name] = {
                            'value': value,
                            'units': param.units,
                            'pid': f"0x{pid:02X}",
                            'description': param.description,
                            'raw_data': data_bytes
                        }
                    except Exception as e:
                        self.logger.error(f"Error converting PID {pid:02X}: {e}")
       
        return results
   
    def parse_dtc_response(self, response: str) -> List[Dict[str, str]]:
        """Parse Diagnostic Trouble Code response"""
        dtcs = []
       
        if "NO DATA" in response.upper() or not response.strip():
            return dtcs
       
        # Remove headers and clean up response
        cleaned_response = re.sub(r'^[0-9A-F]{2,6}\s+', '', response, flags=re.MULTILINE)
        hex_data = ''.join(cleaned_response.split())
       
        # Skip mode response (43) and DTC count
        if len(hex_data) >= 4:
            dtc_data = hex_data[4:]  # Skip "43XX" where XX is count
           
            # Each DTC is 2 bytes
            for i in range(0, len(dtc_data), 4):
                if i + 4 <= len(dtc_data):
                    dtc_bytes = dtc_data[i:i+4]
                    dtc_code = self._decode_dtc(dtc_bytes)
                    if dtc_code != "P0000":  # Skip empty codes
                        dtcs.append({
                            'code': dtc_code,
                            'description': self._get_dtc_description(dtc_code),
                            'raw_bytes': dtc_bytes
                        })
       
        return dtcs
   
    def parse_vin_response(self, response: str) -> Optional[str]:
        """Parse Vehicle Identification Number response"""
        # VIN is typically returned in response to mode 9, PID 2
        lines = [line.strip() for line in response.split('\n') if line.strip()]
        vin_data = ""
       
        for line in lines:
            # Remove header information
            cleaned_line = re.sub(r'^[0-9A-F]{2,6}\s+', '', line)
            hex_bytes = ''.join(cleaned_line.split())
           
            # Convert hex to ASCII
            try:
                for i in range(0, len(hex_bytes), 2):
                    if i + 2 <= len(hex_bytes):
                        byte_val = int(hex_bytes[i:i+2], 16)
                        if 32 <= byte_val <= 126:  # Printable ASCII
                            vin_data += chr(byte_val)
            except ValueError:
                continue
       
        # Clean and validate VIN (17 characters, alphanumeric)
        vin = re.sub(r'[^A-Z0-9]', '', vin_data.upper())
        if len(vin) == 17:
            return vin
       
        return None
   
    def format_for_display(self, messages: List[ParsedMessage],
                          show_headers: bool = True,
                          show_raw: bool = False) -> str:
        """Format parsed messages for display"""
        output = []
       
        for message in messages:
            line_parts = []
           
            if show_headers and message.header:
                line_parts.append(f"[{message.header}]")
           
            if message.message_type == MessageType.ERROR_RESPONSE:
                line_parts.append(f"ERROR: {message.error_code}")
            elif message.message_type == MessageType.NO_DATA:
                line_parts.append("NO DATA")
            elif message.data:
                # Format data bytes
                data_str = ' '.join(f"{b:02X}" for b in message.data)
                line_parts.append(data_str)
               
                # Add interpretation if available
                if message.mode and message.pid:
                    if message.pid in self.obd_parameters:
                        param = self.obd_parameters[message.pid]
                        try:
                            value = self._convert_obd_value(param, message.data[2:])
                            line_parts.append(f"({param.name}: {value} {param.units})")
                        except:
                            pass
           
            if show_raw:
                line_parts.append(f"[RAW: {message.raw_data}]")
           
            output.append(' '.join(line_parts))
       
        return '\n'.join(output)
   
    def _parse_single_line(self, line: str, protocol: Optional[ProtocolFormat]) -> Optional[ParsedMessage]:
        """Parse a single line of response data"""
        line = line.strip().upper()
       
        # Try to detect protocol if not specified
        if protocol is None:
            protocol = self._detect_protocol(line)
       
        # Parse based on protocol
        if protocol == ProtocolFormat.ISO_15765:
            return self._parse_can_message(line)
        elif protocol in [ProtocolFormat.J1850, ProtocolFormat.ISO_9141, ProtocolFormat.ISO_14230]:
            return self._parse_legacy_message(line, protocol)
        else:
            # Generic parsing
            return self._parse_generic_message(line)
   
    def _parse_can_message(self, line: str) -> Optional[ParsedMessage]:
        """Parse CAN (ISO 15765) message"""
        # Match pattern: "7E8 06 41 00 BE 3F A8 13"
        parts = line.split()
        if len(parts) < 3:
            return None
       
        try:
            header = parts[0]
            dlc = int(parts[1], 16) if len(parts) > 1 else None
            data_bytes = [int(b, 16) for b in parts[2:]]
           
            # Determine message type from PCI (first data byte)
            message_type = MessageType.SINGLE_FRAME
            frame_sequence = None
            total_length = None
           
            if data_bytes:
                pci = data_bytes[0]
                if (pci & 0xF0) == 0x00:  # Single frame
                    message_type = MessageType.SINGLE_FRAME
                elif (pci & 0xF0) == 0x10:  # First frame
                    message_type = MessageType.FIRST_FRAME
                    total_length = ((pci & 0x0F) << 8) | (data_bytes[1] if len(data_bytes) > 1 else 0)
                elif (pci & 0xF0) == 0x20:  # Consecutive frame
                    message_type = MessageType.CONSECUTIVE_FRAME
                    frame_sequence = pci & 0x0F
                elif (pci & 0xF0) == 0x30:  # Flow control
                    message_type = MessageType.FLOW_CONTROL
           
            # Extract mode and PID for single frames
            mode = None
            pid = None
            if message_type == MessageType.SINGLE_FRAME and len(data_bytes) >= 3:
                mode = data_bytes[1]
                pid = data_bytes[2]
           
            return ParsedMessage(
                raw_data=line,
                message_type=message_type,
                protocol=ProtocolFormat.ISO_15765,
                header=header,
                data=data_bytes,
                dlc=dlc,
                mode=mode,
                pid=pid,
                frame_sequence=frame_sequence,
                total_length=total_length
            )
           
        except ValueError as e:
            self.logger.error(f"Error parsing CAN message: {e}")
            return None
   
    def _parse_legacy_message(self, line: str, protocol: ProtocolFormat) -> Optional[ParsedMessage]:
        """Parse J1850 or ISO 9141/14230 message"""
        parts = line.split()
        if len(parts) < 4:
            return None
       
        try:
            # J1850/ISO format: "48 6B 10 41 00 BE 3F A8 13"
            header_bytes = parts[:3]
            data_bytes = [int(b, 16) for b in parts[3:]]
           
            header = ' '.join(header_bytes)
           
            # Extract mode and PID
            mode = data_bytes[0] if data_bytes else None
            pid = data_bytes[1] if len(data_bytes) > 1 else None
           
            return ParsedMessage(
                raw_data=line,
                message_type=MessageType.SINGLE_FRAME,
                protocol=protocol,
                header=header,
                data=data_bytes,
                mode=mode,
                pid=pid
            )
           
        except ValueError as e:
            self.logger.error(f"Error parsing legacy message: {e}")
            return None
   
    def _parse_generic_message(self, line: str) -> ParsedMessage:
        """Parse generic message when protocol is unknown"""
        parts = line.split()
       
        try:
            data_bytes = [int(b, 16) for b in parts if self._is_hex_byte(b)]
           
            return ParsedMessage(
                raw_data=line,
                message_type=MessageType.SINGLE_FRAME,
                data=data_bytes if data_bytes else None
            )
        except ValueError:
            return ParsedMessage(
                raw_data=line,
                message_type=MessageType.ERROR_RESPONSE,
                error_code="PARSE_ERROR"
            )
   
    def _assemble_multi_frame_messages(self, messages: List[ParsedMessage]) -> List[ParsedMessage]:
        """Assemble multi-frame CAN messages"""
        assembled = []
        multi_frame_sessions = {}
       
        for message in messages:
            if message.message_type == MessageType.FIRST_FRAME:
                # Start new multi-frame session
                session_id = message.header
                multi_frame_sessions[session_id] = {
                    'total_length': message.total_length,
                    'received_data': message.data[2:] if message.data else [],
                    'expected_sequence': 1,
                    'complete': False
                }
            elif message.message_type == MessageType.CONSECUTIVE_FRAME:
                # Add to existing session
                session_id = message.header
                if session_id in multi_frame_sessions:
                    session = multi_frame_sessions[session_id]
                    if message.frame_sequence == session['expected_sequence']:
                        session['received_data'].extend(message.data[1:] if message.data else [])
                        session['expected_sequence'] = (session['expected_sequence'] + 1) % 16
                       
                        # Check if complete
                        if len(session['received_data']) >= session['total_length']:
                            session['complete'] = True
            else:
                # Single frame or other message types
                assembled.append(message)
       
        # Add completed multi-frame messages
        for session_id, session in multi_frame_sessions.items():
            if session['complete']:
                # Create assembled message
                data = session['received_data'][:session['total_length']]
                mode = data[0] if data else None
                pid = data[1] if len(data) > 1 else None
               
                assembled.append(ParsedMessage(
                    raw_data=f"ASSEMBLED_{session_id}",
                    message_type=MessageType.SINGLE_FRAME,
                    protocol=ProtocolFormat.ISO_15765,
                    header=session_id,
                    data=data,
                    mode=mode,
                    pid=pid
                ))
       
        return assembled
   
    def _convert_obd_value(self, param: OBDParameter, data_bytes: List[int]) -> float:
        """Convert raw OBD data to engineering units"""
        if not data_bytes:
            raise ValueError("No data bytes provided")
       
        # Handle different PID calculations
        pid = param.pid
       
        if pid == 0x05:  # Engine coolant temperature
            return data_bytes[0] - 40
        elif pid == 0x06:  # Short term fuel trim
            return (data_bytes[0] - 128) * 100.0 / 128.0
        elif pid == 0x0B:  # Intake manifold absolute pressure
            return data_bytes[0]
        elif pid == 0x0C:  # Engine RPM
            if len(data_bytes) >= 2:
                return ((data_bytes[0] * 256) + data_bytes[1]) / 4.0
            return 0
        elif pid == 0x0D:  # Vehicle speed
            return data_bytes[0]
        elif pid == 0x0E:  # Timing advance
            return (data_bytes[0] - 128) / 2.0
        elif pid == 0x0F:  # Intake air temperature
            return data_bytes[0] - 40
        elif pid == 0x10:  # Mass air flow rate
            if len(data_bytes) >= 2:
                return ((data_bytes[0] * 256) + data_bytes[1]) / 100.0
            return 0
        elif pid == 0x11:  # Throttle position
            return data_bytes[0] * 100.0 / 255.0
        elif pid == 0x1F:  # Run time since engine start
            if len(data_bytes) >= 2:
                return (data_bytes[0] * 256) + data_bytes[1]
            return 0
        elif pid == 0x21:  # Distance traveled with MIL on
            if len(data_bytes) >= 2:
                return (data_bytes[0] * 256) + data_bytes[1]
            return 0
        elif pid == 0x2F:  # Fuel tank level input
            return data_bytes[0] * 100.0 / 255.0
        elif pid == 0x42:  # Control module voltage
            if len(data_bytes) >= 2:
                return ((data_bytes[0] * 256) + data_bytes[1]) / 1000.0
            return 0
        elif pid == 0x43:  # Absolute load value
            if len(data_bytes) >= 2:
                return ((data_bytes[0] * 256) + data_bytes[1]) * 100.0 / 65535.0
            return 0
        elif pid == 0x44:  # Fuel-air equivalence ratio
            if len(data_bytes) >= 2:
                return ((data_bytes[0] * 256) + data_bytes[1]) / 32768.0
            return 0
        else:
            # Generic single byte percentage
            return data_bytes[0] * 100.0 / 255.0
   
    def _decode_dtc(self, dtc_bytes: str) -> str:
        """Decode DTC from hex bytes"""
        if len(dtc_bytes) != 4:
            return "INVALID"
       
        try:
            first_byte = int(dtc_bytes[:2], 16)
            second_byte = int(dtc_bytes[2:4], 16)
           
            # Determine prefix
            prefix_map = {0: 'P', 1: 'C', 2: 'B', 3: 'U'}
            prefix = prefix_map.get((first_byte >> 6) & 0x03, 'P')
           
            # Format code
            code_num = ((first_byte & 0x3F) << 8) | second_byte
            return f"{prefix}{code_num:04d}"
           
        except ValueError:
            return "INVALID"
   
    def _detect_protocol(self, line: str) -> Optional[ProtocolFormat]:
        """Detect protocol from message format"""
        parts = line.split()
       
        if len(parts) >= 3:
            # Check for CAN format (short header + DLC + data)
            try:
                int(parts[0], 16)  # Header
                dlc = int(parts[1], 16)  # DLC
                if 0 <= dlc <= 8:
                    return ProtocolFormat.ISO_15765
            except ValueError:
                pass
       
        # Default to generic
        return None
   
    def _is_error_response(self, response: str) -> bool:
        """Check if response is an error"""
        error_patterns = [
            r'\?', r'ERROR', r'BUS ERROR', r'CAN ERROR',
            r'DATA ERROR', r'UNABLE TO CONNECT', r'TIMEOUT'
        ]
       
        return any(re.search(pattern, response, re.IGNORECASE) for pattern in error_patterns)
   
    def _is_hex_byte(self, text: str) -> bool:
        """Check if text is a valid hex byte"""
        return len(text) == 2 and all(c in '0123456789ABCDEF' for c in text.upper())
   
    def _get_dtc_description(self, dtc_code: str) -> str:
        """Get basic DTC description"""
        # Basic DTC descriptions - in practice, this would be a comprehensive database
        dtc_descriptions = {
            'P0000': 'No fault',
            'P0100': 'Mass Air Flow Circuit Malfunction',
            'P0101': 'Mass Air Flow Circuit Range/Performance Problem',
            'P0102': 'Mass Air Flow Circuit Low Input',
            'P0103': 'Mass Air Flow Circuit High Input',
            'P0171': 'System Too Lean (Bank 1)',
            'P0172': 'System Too Rich (Bank 1)',
            'P0300': 'Random/Multiple Cylinder Misfire Detected',
            'P0301': 'Cylinder 1 Misfire Detected',
            'P0302': 'Cylinder 2 Misfire Detected',
            'P0420': 'Catalyst System Efficiency Below Threshold (Bank 1)',
        }
       
        return dtc_descriptions.get(dtc_code, 'Unknown DTC')
   
    def _initialize_obd_parameters(self) -> Dict[int, OBDParameter]:
        """Initialize OBD parameter definitions"""
        return {
            0x05: OBDParameter(0x05, "Engine Coolant Temperature", "Engine coolant temperature", "A-40", "°C"),
            0x06: OBDParameter(0x06, "Short Term Fuel Trim Bank 1", "Short term fuel trim", "(A-128)*100/128", "%"),
            0x0B: OBDParameter(0x0B, "Intake Manifold Pressure", "Intake manifold absolute pressure", "A", "kPa"),
            0x0C: OBDParameter(0x0C, "Engine RPM", "Engine speed", "((A*256)+B)/4", "RPM", data_bytes=2),
            0x0D: OBDParameter(0x0D, "Vehicle Speed", "Vehicle speed", "A", "km/h"),
            0x0E: OBDParameter(0x0E, "Timing Advance", "Timing advance", "(A-128)/2", "°"),
            0x0F: OBDParameter(0x0F, "Intake Air Temperature", "Intake air temperature", "A-40", "°C"),
            0x10: OBDParameter(0x10, "Mass Air Flow", "Mass air flow rate", "((A*256)+B)/100", "g/s", data_bytes=2),
            0x11: OBDParameter(0x11, "Throttle Position", "Throttle position", "A*100/255", "%"),
            0x1F: OBDParameter(0x1F, "Run Time", "Run time since engine start", "(A*256)+B", "seconds", data_bytes=2),
            0x21: OBDParameter(0x21, "Distance with MIL", "Distance traveled with MIL on", "(A*256)+B", "km", data_bytes=2),
            0x2F: OBDParameter(0x2F, "Fuel Level", "Fuel tank level input", "A*100/255", "%"),
            0x42: OBDParameter(0x42, "Control Module Voltage", "Control module voltage", "((A*256)+B)/1000", "V", data_bytes=2),
            0x43: OBDParameter(0x43, "Absolute Load", "Absolute load value", "((A*256)+B)*100/65535", "%", data_bytes=2),
            0x44: OBDParameter(0x44, "Fuel-Air Ratio", "Fuel-air equivalence ratio", "((A*256)+B)/32768", "ratio", data_bytes=2),
        } 
