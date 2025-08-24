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

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any, Tuple
from enum import Enum
import json
import logging
import os

class PPParameterType(Enum):
    """Programmable Parameter types"""
    READ_ONLY = "R"      # Read only
    DEFAULT = "D"        # Default changeable 
    PERMANENT = "P"      # Permanent (requires power cycle)
    INTERNAL = "I"       # Internal use

@dataclass
class PPParameter:
    """Programmable Parameter definition"""
    address: int
    name: str
    description: str
    param_type: PPParameterType
    default_value: int
    current_value: Optional[int] = None
    valid_range: Optional[Tuple[int, int]] = None
    valid_values: Optional[List[int]] = None
    units: Optional[str] = None
    formula: Optional[str] = None

@dataclass
class DeviceConfiguration:
    """Complete device configuration"""
    device_info: Dict[str, str] = field(default_factory=dict)
    pp_parameters: Dict[int, PPParameter] = field(default_factory=dict)
    user_settings: Dict[str, Any] = field(default_factory=dict)
    protocol_configs: Dict[str, Dict] = field(default_factory=dict)
    custom_commands: List[str] = field(default_factory=list)
    last_updated: Optional[float] = None

class ConfigManager:
    """
    Configuration manager for MIC3X2X device
    Handles 53 programmable parameters (PP area) and device settings
    Based on MIC3X2X datasheet PP area specifications
    """
   
    def __init__(self, command_handler):
        self.cmd_handler = command_handler
        self.logger = logging.getLogger(__name__)
       
        # Configuration
        self.config = DeviceConfiguration()
        self.config_file_path = "mic3x2x_config.json"
       
        # Initialize PP parameter definitions from datasheet
        self.pp_definitions = self._initialize_pp_definitions()
       
        # User EEPROM storage (256 bytes)
        self.user_eeprom = {}
       
    def load_configuration(self, file_path: Optional[str] = None) -> bool:
        """Load configuration from file"""
        file_path = file_path or self.config_file_path
       
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    config_data = json.load(f)
                   
                # Restore PP parameters
                if 'pp_parameters' in config_data:
                    for addr_str, pp_data in config_data['pp_parameters'].items():
                        addr = int(addr_str)
                        if addr in self.pp_definitions:
                            self.pp_definitions[addr].current_value = pp_data.get('current_value')
               
                # Restore other settings
                self.config.user_settings = config_data.get('user_settings', {})
                self.config.protocol_configs = config_data.get('protocol_configs', {})
                self.config.custom_commands = config_data.get('custom_commands', [])
               
                self.logger.info(f"Configuration loaded from {file_path}")
                return True
            else:
                self.logger.info("No existing configuration file found")
                return True
               
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return False
   
    def save_configuration(self, file_path: Optional[str] = None) -> bool:
        """Save configuration to file"""
        file_path = file_path or self.config_file_path
       
        try:
            config_data = {
                'device_info': self.config.device_info,
                'pp_parameters': {},
                'user_settings': self.config.user_settings,
                'protocol_configs': self.config.protocol_configs,
                'custom_commands': self.config.custom_commands,
                'last_updated': self.config.last_updated
            }
           
            # Save PP parameters
            for addr, pp in self.pp_definitions.items():
                config_data['pp_parameters'][str(addr)] = {
                    'name': pp.name,
                    'current_value': pp.current_value,
                    'default_value': pp.default_value
                }
           
            with open(file_path, 'w') as f:
                json.dump(config_data, f, indent=2)
           
            self.logger.info(f"Configuration saved to {file_path}")
            return True
           
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            return False
   
    def read_all_pp_parameters(self) -> bool:
        """Read all programmable parameters from device"""
        self.logger.info("Reading all PP parameters from device")
       
        success = True
        for addr in self.pp_definitions.keys():
            if not self.read_pp_parameter(addr):
                success = False
       
        return success
   
    def read_pp_parameter(self, address: int) -> bool:
        """Read specific PP parameter from device"""
        if address not in self.pp_definitions:
            self.logger.error(f"Unknown PP parameter address: 0x{address:02X}")
            return False
       
        # Read parameter value
        response = self.cmd_handler.send_raw_command(f"ATPP{address:02X}")
       
        if response.success:
            try:
                # Parse response (typically "PP 0A: 0D")
                if ':' in response.response:
                    value_str = response.response.split(':')[1].strip()
                    value = int(value_str, 16)
                    self.pp_definitions[address].current_value = value
                    return True
            except ValueError as e:
                self.logger.error(f"Failed to parse PP response: {e}")
       
        return False
   
    def write_pp_parameter(self, address: int, value: int) -> bool:
        """Write PP parameter to device"""
        if address not in self.pp_definitions:
            self.logger.error(f"Unknown PP parameter address: 0x{address:02X}")
            return False
       
        pp = self.pp_definitions[address]
       
        # Validate parameter type
        if pp.param_type == PPParameterType.READ_ONLY:
            self.logger.error(f"PP {address:02X} is read-only")
            return False
       
        # Validate value range
        if pp.valid_range and not (pp.valid_range[0] <= value <= pp.valid_range[1]):
            self.logger.error(f"PP {address:02X} value {value} out of range {pp.valid_range}")
            return False
       
        if pp.valid_values and value not in pp.valid_values:
            self.logger.error(f"PP {address:02X} value {value} not in valid values {pp.valid_values}")
            return False
       
        # Write parameter
        response = self.cmd_handler.send_raw_command(f"ATPP{address:02X}SV{value:02X}")
       
        if response.success:
            pp.current_value = value
            self.logger.info(f"Set PP {address:02X} ({pp.name}) = 0x{value:02X}")
            return True
        else:
            self.logger.error(f"Failed to write PP {address:02X}: {response.error}")
            return False
   
    def reset_pp_parameter(self, address: int) -> bool:
        """Reset PP parameter to default value"""
        if address not in self.pp_definitions:
            return False
       
        pp = self.pp_definitions[address]
        return self.write_pp_parameter(address, pp.default_value)
   
    def reset_all_pp_parameters(self) -> bool:
        """Reset all PP parameters to default values"""
        self.logger.info("Resetting all PP parameters to defaults")
       
        success = True
        for address, pp in self.pp_definitions.items():
            if pp.param_type != PPParameterType.READ_ONLY:
                if not self.reset_pp_parameter(address):
                    success = False
       
        return success
   
    def get_pp_summary(self) -> Dict[str, Any]:
        """Get summary of all PP parameters"""
        summary = {}
       
        for addr, pp in self.pp_definitions.items():
            summary[f"0x{addr:02X}"] = {
                'name': pp.name,
                'type': pp.param_type.value,
                'default': f"0x{pp.default_value:02X}",
                'current': f"0x{pp.current_value:02X}" if pp.current_value is not None else "Unknown",
                'description': pp.description
            }
       
        return summary
   
    def configure_can_settings(self, auto_formatting: bool = True,
                              flow_control: bool = True,
                              silent_monitoring: bool = False) -> bool:
        """Configure basic CAN settings"""
        self.logger.info("Configuring CAN settings")
       
        success = True
       
        # PP 24: CAN Auto Formatting (CAF)
        success &= self.write_pp_parameter(0x24, 0x00 if auto_formatting else 0xFF)
       
        # PP 25: CAN Auto Flow Control (CFC) 
        success &= self.write_pp_parameter(0x25, 0x00 if flow_control else 0xFF)
       
        # PP 21: CAN Silent Monitoring (CSM)
        success &= self.write_pp_parameter(0x21, 0xFF if silent_monitoring else 0x00)
       
        return success
   
    def configure_timeouts(self, obd_timeout: Optional[int] = None,
                          j1850_voltage_time: Optional[int] = None,
                          iso_p3_time: Optional[int] = None) -> bool:
        """Configure timeout parameters"""
        success = True
       
        if obd_timeout is not None:
            # PP 03: NO DATA timeout (4.096ms units)
            timeout_val = min(255, max(0, int(obd_timeout / 4.096)))
            success &= self.write_pp_parameter(0x03, timeout_val)
       
        if j1850_voltage_time is not None:
            # PP 10: J1850 voltage setting time (4.096ms units)
            voltage_time = min(255, max(0, int(j1850_voltage_time / 4.096)))
            success &= self.write_pp_parameter(0x10, voltage_time)
       
        if iso_p3_time is not None:
            # PP 1D: ISO/KWP P3 time (4.096ms units)
            p3_time = min(255, max(0, int((iso_p3_time + 0.5) / 4.096)))
            success &= self.write_pp_parameter(0x1D, p3_time)
       
        return success
   
    def write_user_eeprom(self, position: int, data: List[int]) -> bool:
        """Write data to user EEPROM (256 byte area)"""
        if not (0 <= position <= 255):
            self.logger.error("EEPROM position must be 0-255")
            return False
       
        if len(data) > 8 or len(data) == 0:
            self.logger.error("Data length must be 1-8 bytes")
            return False
       
        if position + len(data) > 256:
            self.logger.error("Data would exceed EEPROM boundary")
            return False
       
        # Format data as hex string
        data_str = ' '.join(f"{b:02X}" for b in data)
       
        response = self.cmd_handler.send_raw_command(f"VTWT_EE{position:02X},{data_str}")
       
        if response.success:
            # Update local cache
            for i, byte in enumerate(data):
                self.user_eeprom[position + i] = byte
            return True
       
        return False
   
    def read_user_eeprom(self, position: int, length: int) -> Optional[List[int]]:
        """Read data from user EEPROM"""
        if not (0 <= position <= 255):
            self.logger.error("EEPROM position must be 0-255")
            return None
       
        if not (1 <= length <= 255):
            self.logger.error("Length must be 1-255 bytes")
            return None
       
        if position + length > 256:
            self.logger.error("Read would exceed EEPROM boundary")
            return None
       
        response = self.cmd_handler.send_raw_command(f"VTRD_EE{position:02X},{length:02X}")
       
        if response.success:
            try:
                # Parse hex response
                hex_bytes = response.response.strip().split()
                data = [int(b, 16) for b in hex_bytes if b]
               
                # Update local cache
                for i, byte in enumerate(data):
                    self.user_eeprom[position + i] = byte
               
                return data[:length]  # Ensure correct length
            except ValueError as e:
                self.logger.error(f"Failed to parse EEPROM data: {e}")
       
        return None
   
    def get_device_info(self) -> Dict[str, str]:
        """Get comprehensive device information"""
        info = {}
       
        # Basic device info
        response = self.cmd_handler.at_identify()
        if response.success:
            info['device_id'] = response.response
       
        response = self.cmd_handler.at_device_description()
        if response.success:
            info['device_description'] = response.response
       
        # VT specific info
        response = self.cmd_handler.vt_version()
        if response.success:
            info['firmware_version'] = response.response
       
        response = self.cmd_handler.vt_manufacturer()
        if response.success:
            info['manufacturer'] = response.response
       
        response = self.cmd_handler.vt_read_serial()
        if response.success:
            info['serial_number'] = response.response
       
        response = self.cmd_handler.vt_read_mac()
        if response.success:
            info['mac_address'] = response.response
       
        # Update config
        self.config.device_info = info
        return info
   
    def validate_configuration(self) -> Dict[str, List[str]]:
        """Validate current configuration"""
        issues = {'errors': [], 'warnings': []}
       
        # Check PP parameters
        for addr, pp in self.pp_definitions.items():
            if pp.current_value is None:
                issues['warnings'].append(f"PP {addr:02X} ({pp.name}) value unknown")
                continue
           
            # Validate ranges
            if pp.valid_range:
                min_val, max_val = pp.valid_range
                if not (min_val <= pp.current_value <= max_val):
                    issues['errors'].append(
                        f"PP {addr:02X} ({pp.name}) value {pp.current_value} out of range [{min_val}, {max_val}]"
                    )
           
            # Validate discrete values
            if pp.valid_values and pp.current_value not in pp.valid_values:
                issues['errors'].append(
                    f"PP {addr:02X} ({pp.name}) value {pp.current_value} not in valid set {pp.valid_values}"
                )
       
        return issues
   
    def export_configuration(self, include_defaults: bool = False) -> Dict[str, Any]:
        """Export configuration for backup/sharing"""
        export_data = {
            'device_info': self.config.device_info,
            'pp_parameters': {},
            'user_settings': self.config.user_settings,
            'eeprom_data': dict(self.user_eeprom)
        }
       
        # Export PP parameters
        for addr, pp in self.pp_definitions.items():
            if pp.current_value is not None and (include_defaults or pp.current_value != pp.default_value):
                export_data['pp_parameters'][f"0x{addr:02X}"] = {
                    'name': pp.name,
                    'value': pp.current_value,
                    'hex': f"0x{pp.current_value:02X}"
                }
       
        return export_data
   
    def _initialize_pp_definitions(self) -> Dict[int, PPParameter]:
        """Initialize PP parameter definitions from datasheet"""
        # Based on MIC3X2X datasheet PP area table
        pp_params = {
            0x00: PPParameter(0x00, "MA_DEFAULT", "Auto MA command after reset", PPParameterType.READ_ONLY, 0xFF),
            0x01: PPParameter(0x01, "HEADERS_DEFAULT", "Header display default", PPParameterType.DEFAULT, 0xFF, valid_values=[0x00, 0xFF]),
            0x02: PPParameter(0x02, "LONG_MSG_DEFAULT", "Allow long messages default", PPParameterType.DEFAULT, 0xFF, valid_values=[0x00, 0xFF]),
            0x03: PPParameter(0x03, "TIMEOUT_DEFAULT", "NO DATA timeout", PPParameterType.DEFAULT, 0x32, valid_range=(0x00, 0xFF), units="4.096ms"),
            0x04: PPParameter(0x04, "ADAPTIVE_TIMING", "Adaptive timing mode", PPParameterType.DEFAULT, 0x01, valid_range=(0x00, 0x02)),
           
            0x06: PPParameter(0x06, "TESTER_ADDRESS", "OBD tester address", PPParameterType.READ_ONLY, 0xF1),
            0x07: PPParameter(0x07, "LAST_PROTOCOL", "Last protocol in auto search", PPParameterType.INTERNAL, 0x09),
            0x08: PPParameter(0x08, "FALSE_ID", "Display false ELM327 ID", PPParameterType.READ_ONLY, 0xFF),
            0x09: PPParameter(0x09, "ECHO_DEFAULT", "Echo default setting", PPParameterType.READ_ONLY, 0x00),
            0x0A: PPParameter(0x0A, "LINEFEED_CHAR", "Linefeed character", PPParameterType.READ_ONLY, 0x0A),
           
            0x0C: PPParameter(0x0C, "BAUD_DIVISOR", "RS232 baud divisor", PPParameterType.PERMANENT, 0x68),
            0x0D: PPParameter(0x0D, "CR_CHAR", "Carriage return character", PPParameterType.READ_ONLY, 0x0D),
            0x0E: PPParameter(0x0E, "POWER_CONTROL", "Power control options", PPParameterType.READ_ONLY, 0x9A, valid_range=(0x00, 0xFF)),
            0x0F: PPParameter(0x0F, "ACTIVITY_MONITOR", "Activity monitor options", PPParameterType.DEFAULT, 0xD5, valid_range=(0x00, 0xFF)),
           
            0x10: PPParameter(0x10, "J1850_VOLTAGE_TIME", "J1850 voltage setting time", PPParameterType.DEFAULT, 0x0D, valid_range=(0x00, 0xFF), units="4.096ms"),
            0x11: PPParameter(0x11, "J1850_BREAK_MONITOR", "J1850 break signal monitor", PPParameterType.DEFAULT, 0x00, valid_values=[0x00, 0xFF]),
            0x12: PPParameter(0x12, "J1850_POLARITY", "J1850 output polarity", PPParameterType.READ_ONLY, 0xFF),
            0x13: PPParameter(0x13, "PROTOCOL_DELAY", "Inter-protocol delay", PPParameterType.INTERNAL, 0x55, units="4.096ms + 150ms"),
            0x14: PPParameter(0x14, "ISO_STOP_WIDTH", "ISO final stop bit width", PPParameterType.DEFAULT, 0x50, valid_range=(0x00, 0xFF), units="64μs + 98μs"),
            0x15: PPParameter(0x15, "ISO_INTERBYTE", "ISO max interbyte time", PPParameterType.DEFAULT, 0x0A, valid_range=(0x00, 0xFF), units="2.112ms"),
            0x16: PPParameter(0x16, "ISO_BAUDRATE", "Default ISO baud rate", PPParameterType.READ_ONLY, 0xFF),
            0x17: PPParameter(0x17, "ISO_WAKEUP_RATE", "ISO wakeup message rate", PPParameterType.DEFAULT, 0x92, valid_range=(0x00, 0xFF), units="20.48ms"),
            0x18: PPParameter(0x18, "FAST_INIT_DELAY", "Delay before fast init", PPParameterType.INTERNAL, 0x31, units="20.48ms + 1000ms"),
            0x19: PPParameter(0x19, "SLOW_INIT_DELAY", "Delay before slow init", PPParameterType.INTERNAL, 0x31, units="20.48ms + 1000ms"),
            0x1A: PPParameter(0x1A, "FAST_INIT_LOW", "Fast init low time", PPParameterType.DEFAULT, 0x0A, valid_range=(0x00, 0xFF), units="2.5ms"),
            0x1B: PPParameter(0x1B, "FAST_INIT_HIGH", "Fast init high time", PPParameterType.DEFAULT, 0x0A, valid_range=(0x00, 0xFF), units="2.5ms"),
            0x1C: PPParameter(0x1C, "ISO_OUTPUTS", "ISO init outputs used", PPParameterType.DEFAULT, 0x03, valid_range=(0x00, 0xFF)),
            0x1D: PPParameter(0x1D, "ISO_P3_TIME", "ISO P3 delay time", PPParameterType.DEFAULT, 0x0F, valid_range=(0x00, 0xFF), units="4.096ms"),
            0x1E: PPParameter(0x1E, "ISO_W5_TIME", "ISO W5 quiet time", PPParameterType.DEFAULT, 0x4A, valid_range=(0x00, 0xFF), units="4.096ms"),
            0x1F: PPParameter(0x1F, "KWP_CHECKSUM", "KWP checksum includes byte count", PPParameterType.READ_ONLY, 0xFF),
           
            0x20: PPParameter(0x20, "SW_TRANSCEIVER", "Single wire transceiver mode", PPParameterType.DEFAULT, 0x03, valid_range=(0x00, 0x03)),
            0x21: PPParameter(0x21, "CAN_SILENT", "CAN silent monitoring default", PPParameterType.READ_ONLY, 0xFF, valid_values=[0x00, 0xFF]),
            0x22: PPParameter(0x22, "CAN_WAKEUP_RATE", "CAN wakeup message rate", PPParameterType.DEFAULT, 0x62, valid_range=(0x00, 0xFF), units="20.48ms"),
            0x23: PPParameter(0x23, "WAKEUP_MODE", "Default wakeup mode", PPParameterType.DEFAULT, 0x00, valid_range=(0x00, 0x02)),
            0x24: PPParameter(0x24, "CAN_AUTO_FORMAT", "CAN auto formatting default", PPParameterType.DEFAULT, 0x00, valid_values=[0x00, 0xFF]),
            0x25: PPParameter(0x25, "CAN_AUTO_FLOW", "CAN auto flow control default", PPParameterType.DEFAULT, 0x00, valid_values=[0x00, 0xFF]),
            0x26: PPParameter(0x26, "CAN_FILLER", "CAN filler byte", PPParameterType.DEFAULT, 0x00, valid_range=(0x00, 0xFF)),
           
            0x28: PPParameter(0x28, "CAN_FILTER", "CAN filter settings", PPParameterType.DEFAULT, 0xFF, valid_range=(0x00, 0xFF)),
            0x29: PPParameter(0x29, "CAN_DLC_DISPLAY", "CAN DLC display default", PPParameterType.DEFAULT, 0xFF, valid_values=[0x00, 0xFF]),
            0x2A: PPParameter(0x2A, "CAN_ERROR_CHECK", "CAN error checking options", PPParameterType.DEFAULT, 0x3C, valid_range=(0x00, 0xFF)),
            0x2B: PPParameter(0x2B, "J1939_BAUDRATE", "J1939 baud rate divisor", PPParameterType.READ_ONLY, 0x02, valid_range=(0x01, 0x40)),
           
            # User protocol definitions (PP 2C-35)
            0x2C: PPParameter(0x2C, "PROTOCOL_B_OPTIONS", "Protocol B CAN options", PPParameterType.READ_ONLY, 0xE0, valid_range=(0x00, 0xFF)),
            0x2D: PPParameter(0x2D, "PROTOCOL_B_BAUD", "Protocol B baud divisor", PPParameterType.READ_ONLY, 0x04, valid_range=(0x01, 0x40)),
            0x2E: PPParameter(0x2E, "PROTOCOL_C_OPTIONS", "Protocol C CAN options", PPParameterType.READ_ONLY, 0x80, valid_range=(0x00, 0xFF)),
            0x2F: PPParameter(0x2F, "PROTOCOL_C_BAUD", "Protocol C baud divisor", PPParameterType.READ_ONLY, 0x0A, valid_range=(0x01, 0x40)),
            0x30: PPParameter(0x30, "PROTOCOL_D_OPTIONS", "Protocol D CAN options", PPParameterType.READ_ONLY, 0x42, valid_range=(0x00, 0xFF)),
            0x31: PPParameter(0x31, "PROTOCOL_D_BAUD", "Protocol D baud divisor", PPParameterType.READ_ONLY, 0x01, valid_range=(0x01, 0x40)),
            0x32: PPParameter(0x32, "PROTOCOL_E_OPTIONS", "Protocol E CAN options", PPParameterType.READ_ONLY, 0xF0, valid_range=(0x00, 0xFF)),
            0x33: PPParameter(0x33, "PROTOCOL_E_BAUD", "Protocol E baud divisor", PPParameterType.READ_ONLY, 0x06, valid_range=(0x01, 0x40)),
            0x34: PPParameter(0x34, "PROTOCOL_F_OPTIONS", "Protocol F CAN options", PPParameterType.READ_ONLY, 0xE0, valid_range=(0x00, 0xFF)),
            0x35: PPParameter(0x35, "PROTOCOL_F_BAUD", "Protocol F baud divisor", PPParameterType.READ_ONLY, 0x0F, valid_range=(0x01, 0x40)),
        }
       
        return pp_params 
