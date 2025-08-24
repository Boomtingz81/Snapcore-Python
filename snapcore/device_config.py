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

MIC3X2X Device Configuration Module

Handles device-specific configurations, protocol settings, and parameter management
for the MIC3X2X OBD-II to UART interpreter IC.

Based on MIC3X2X datasheet v2.3.08
"""

from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    """Supported protocol types"""
    # AT Command Protocols (ELM327 compatible)
    SAE_J1850_PWM = "1"
    SAE_J1850_VPW = "2"
    ISO_9141_2 = "3"
    ISO_14230_4_5BAUD = "4"
    ISO_14230_4_FAST = "5"
    ISO_15765_11BIT_500K = "6"
    ISO_15765_29BIT_500K = "7"
    ISO_15765_11BIT_250K = "8"
    ISO_15765_29BIT_250K = "9"
    SAE_J1939_250K = "A"
    USER1_CAN = "B"
    USER2_CAN = "C"
   
    # ST Command Protocols (STN compatible)
    ST_J1850_PWM = "11"
    ST_J1850_VPW = "12"
    ST_ISO_9141_NO_HEADER = "21"
    ST_ISO_9141_5BAUD = "22"
    ST_ISO_14230_NO_INIT = "23"
    ST_ISO_14230_5BAUD = "24"
    ST_ISO_14230_FAST = "25"
    ST_HS_CAN_11BIT_500K = "33"
    ST_HS_CAN_29BIT_500K = "34"
    ST_HS_CAN_11BIT_250K = "35"
    ST_HS_CAN_29BIT_250K = "36"
    ST_MS_CAN_11BIT_125K = "53"
    ST_MS_CAN_29BIT_125K = "54"
    ST_SW_CAN_11BIT_33K = "63"
    ST_SW_CAN_29BIT_33K = "64"
   
    # VT Command Protocols (Custom ranges 101-140)
    VT_CUSTOM_BASE = "101"


class CANPhysicalLayer(Enum):
    """CAN physical layer types"""
    HS_CAN = "HS_CAN"      # High Speed CAN
    MS_CAN = "MS_CAN"      # Medium Speed CAN 
    SW_CAN = "SW_CAN"      # Single Wire CAN
    CH_CAN = "CH_CAN"      # Chassis CAN
    LS_CAN = "LS_CAN"      # Low Speed CAN


class SWCANMode(IntEnum):
    """Single Wire CAN transceiver modes"""
    SLEEP = 0
    HIGH_SPEED = 1
    HIGH_VOLTAGE_WAKEUP = 2
    NORMAL = 3


class WakeupMode(IntEnum):
    """Wakeup message modes"""
    OFF = 0
    CONDITIONAL = 1
    ALWAYS = 2
    CONSTANT_RATE = 3


@dataclass
class ProtocolConfig:
    """Configuration for a specific protocol"""
    protocol_id: str
    name: str
    description: str
    baudrate: int = 38400
    physical_layer: Optional[CANPhysicalLayer] = None
    can_options: int = 0xE0  # Default CAN options (11-bit, fixed 8-byte, ISO15765)
    can_baudrate_divisor: int = 0x01  # 500kbps default
    swcan_mode: SWCANMode = SWCANMode.NORMAL
    supports_extended_addressing: bool = False
    supports_flow_control: bool = False
    auto_formatting: bool = True
    variable_dlc: bool = False


@dataclass
class WakeupSequence:
    """Wake-up/keep-alive message sequence"""
    sequence_id: int
    protocol_id: str
    header: str
    data: List[int]
    period_ms: int = 2000
    mode: WakeupMode = WakeupMode.CONDITIONAL
    enabled: bool = True


@dataclass
class FilterMask:
    """CAN ID filter and mask configuration"""
    filter_id: str
    mask: str
    extended_address: Optional[str] = None
    filter_type: str = "pass"  # "pass", "block", "flow_control"


@dataclass
class PowerConfig:
    """Power management configuration"""
    low_power_enabled: bool = True
    uart_timeout_enabled: bool = False
    uart_timeout_minutes: int = 5
    obd_timeout_enabled: bool = True
    obd_timeout_seconds: int = 30
    voltage_sleep_threshold: float = 6.0
    voltage_sleep_duration: int = 20  # seconds
    voltage_wakeup_drop: float = 2.5
    voltage_wakeup_duration: int = 20  # milliseconds
    ignition_monitoring: bool = False
    power_control_polarity: bool = True


@dataclass
class BluetoothConfig:
    """Bluetooth module configuration"""
    enabled: bool = False
    device_name: str = "MIC3X2X-OBD"
    pin_code: str = "1234"
    class_of_device: str = "001F00"
    discovery_mode: int = 1  # 0=disabled, 1=always, 2=300s on power
    pairing_mode: int = 2    # 1=PIN required, 2=simple pairing
    work_mode: int = 1       # 1=BT3.0, 3=BT3.0+MFI, 5=BT3.0+BLE
    hci_baudrate: int = 2000000


@dataclass
class DeviceConfig:
    """Complete MIC3X2X device configuration"""
    # Device identification
    device_id: str = "MIC3X2X"
    firmware_version: str = "v2.3.08"
    manufacturer: str = "JINXUSOLU"
    serial_number: str = ""
   
    # Communication settings
    uart_baudrate: int = 115200
    uart_timeout: float = 2.0
    echo_enabled: bool = False
    headers_enabled: bool = True
    spaces_enabled: bool = False
    linefeeds_enabled: bool = True
   
    # Protocol settings
    default_protocol: ProtocolType = ProtocolType.ISO_15765_11BIT_500K
    auto_protocol_search: bool = True
    protocol_search_order: List[ProtocolType] = field(default_factory=list)
    custom_protocols: Dict[str, ProtocolConfig] = field(default_factory=dict)
   
    # Timing settings
    response_timeout: int = 200  # 200 * 4ms = 800ms
    inter_message_delay: int = 5  # milliseconds
    adaptive_timing: int = 1     # 0=off, 1=auto1, 2=auto2
   
    # CAN specific settings
    can_auto_formatting: bool = True
    can_flow_control: bool = True
    can_silent_monitoring: bool = False
    can_filler_byte: int = 0x00
    can_error_checking: int = 0x3C
   
    # Wake-up sequences
    wakeup_sequences: Dict[int, WakeupSequence] = field(default_factory=dict)
    wakeup_interval: int = 2000  # milliseconds
    wakeup_enabled: bool = False
   
    # Filtering
    filters: List[FilterMask] = field(default_factory=list)
    automatic_filtering: bool = False
   
    # Power management
    power_config: PowerConfig = field(default_factory=PowerConfig)
   
    # Bluetooth configuration
    bluetooth_config: BluetoothConfig = field(default_factory=BluetoothConfig)
   
    # Storage settings
    memory_enabled: bool = False
    user_eeprom_data: Dict[int, List[int]] = field(default_factory=dict)
   
    # Advanced features
    long_messages_enabled: bool = False
    mixed_id_sending: bool = False
    segmentation_enabled: bool = False
    hex_format_enabled: bool = False


class ConfigManager:
    """Manages device configuration loading, saving, and validation"""
   
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.current_config: Optional[DeviceConfig] = None
       
    def create_default_config(self) -> DeviceConfig:
        """Create default configuration with common protocols"""
        config = DeviceConfig()
       
        # Set up default protocol search order
        config.protocol_search_order = [
            ProtocolType.ISO_15765_11BIT_500K,
            ProtocolType.ISO_15765_29BIT_500K,
            ProtocolType.ISO_15765_11BIT_250K,
            ProtocolType.ISO_15765_29BIT_250K,
            ProtocolType.SAE_J1850_VPW,
            ProtocolType.SAE_J1850_PWM,
            ProtocolType.ISO_14230_4_FAST,
            ProtocolType.ISO_9141_2
        ]
       
        # Add common custom protocols
        config.custom_protocols = {
            "101": ProtocolConfig(
                protocol_id="101",
                name="SW_CAN_33K",
                description="Single Wire CAN 33.3K ISO15765",
                physical_layer=CANPhysicalLayer.SW_CAN,
                baudrate=33300,
                can_options=0x81,
                can_baudrate_divisor=0x0F,
                swcan_mode=SWCANMode.NORMAL
            ),
            "102": ProtocolConfig(
                protocol_id="102",
                name="MS_CAN_125K",
                description="Medium Speed CAN 125K ISO15765",
                physical_layer=CANPhysicalLayer.MS_CAN,
                baudrate=125000,
                can_options=0x81,
                can_baudrate_divisor=0x04
            )
        }
       
        return config
   
    def load_config(self, config_name: str = "default") -> DeviceConfig:
        """Load configuration from file"""
        config_file = self.config_dir / f"{config_name}.json"
       
        if not config_file.exists():
            logger.info(f"Config file {config_file} not found, creating default")
            config = self.create_default_config()
            self.save_config(config, config_name)
            return config
       
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
           
            config = self._dict_to_config(data)
            self.current_config = config
            logger.info(f"Loaded configuration from {config_file}")
            return config
           
        except Exception as e:
            logger.error(f"Error loading config {config_file}: {e}")
            return self.create_default_config()
   
    def save_config(self, config: DeviceConfig, config_name: str = "default"):
        """Save configuration to file"""
        config_file = self.config_dir / f"{config_name}.json"
       
        try:
            data = self._config_to_dict(config)
            with open(config_file, 'w') as f:
                json.dump(data, f, indent=2)
           
            logger.info(f"Saved configuration to {config_file}")
           
        except Exception as e:
            logger.error(f"Error saving config {config_file}: {e}")
   
    def _config_to_dict(self, config: DeviceConfig) -> Dict[str, Any]:
        """Convert DeviceConfig to dictionary for JSON serialization"""
        def convert_value(value):
            if isinstance(value, Enum):
                return value.value
            elif hasattr(value, '__dict__'):
                return {k: convert_value(v) for k, v in value.__dict__.items()}
            elif isinstance(value, (list, tuple)):
                return [convert_value(item) for item in value]
            elif isinstance(value, dict):
                return {k: convert_value(v) for k, v in value.items()}
            else:
                return value
       
        return convert_value(config)
   
    def _dict_to_config(self, data: Dict[str, Any]) -> DeviceConfig:
        """Convert dictionary to DeviceConfig"""
        # This would need more sophisticated conversion logic
        # For now, create default and update specific fields
        config = self.create_default_config()
       
        # Update basic fields
        if 'uart_baudrate' in data:
            config.uart_baudrate = data['uart_baudrate']
        if 'echo_enabled' in data:
            config.echo_enabled = data['echo_enabled']
        if 'response_timeout' in data:
            config.response_timeout = data['response_timeout']
           
        return config
   
    def validate_config(self, config: DeviceConfig) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
       
        # Validate baudrate
        valid_baudrates = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600, 1000000, 2000000, 3000000]
        if config.uart_baudrate not in valid_baudrates:
            errors.append(f"Invalid UART baudrate: {config.uart_baudrate}")
       
        # Validate timeout range
        if not (1 <= config.response_timeout <= 255):
            errors.append(f"Response timeout must be 1-255: {config.response_timeout}")
       
        # Validate custom protocols
        for proto_id, proto_config in config.custom_protocols.items():
            if not (101 <= int(proto_id) <= 140):
                errors.append(f"Custom protocol ID must be 101-140: {proto_id}")
       
        # Validate wakeup sequences
        for seq_id, wakeup in config.wakeup_sequences.items():
            if not (0 <= seq_id <= 8):
                errors.append(f"Wakeup sequence ID must be 0-8: {seq_id}")
            if len(wakeup.data) > 8:
                errors.append(f"Wakeup data too long (max 8 bytes): {len(wakeup.data)}")
       
        return errors
   
    def get_protocol_commands(self, protocol: Union[str, ProtocolType]) -> List[str]:
        """Get initialization commands for a specific protocol"""
        commands = []
       
        if isinstance(protocol, ProtocolType):
            protocol_id = protocol.value
        else:
            protocol_id = protocol
       
        # Standard AT protocol selection
        if protocol_id in ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C']:
            commands.append(f"ATSP{protocol_id}")
       
        # ST protocol selection 
        elif protocol_id.startswith('1') or protocol_id.startswith('2'):
            commands.append(f"STP{protocol_id}")
           
        # VT custom protocol
        elif 101 <= int(protocol_id) <= 140:
            commands.append(f"VTP1{protocol_id}")
           
        return commands


# Pre-defined configurations for common vehicle types
VEHICLE_CONFIGS = {
    "generic_obd2": {
        "description": "Generic OBD-II compatible vehicle",
        "protocols": [ProtocolType.ISO_15765_11BIT_500K, ProtocolType.ISO_15765_29BIT_500K]
    },
    "gm_vehicle": {
        "description": "GM vehicle with GMLAN support",
        "protocols": [ProtocolType.SW_CAN],
        "custom_protocols": ["101"]  # SW CAN configuration
    },
    "ford_vehicle": {
        "description": "Ford vehicle with MS-CAN",
        "protocols": [ProtocolType.MS_CAN],
        "custom_protocols": ["102"]  # MS CAN configuration
    }
}


def get_pp_parameter_info() -> Dict[int, Dict[str, Any]]:
    """Get information about programmable parameters (PP area)"""
    return {
        0x00: {"name": "Auto MA after reset", "default": 0xFF, "type": "R"},
        0x01: {"name": "Header display default", "default": 0xFF, "type": "D"},
        0x02: {"name": "Allow long messages", "default": 0xFF, "type": "D"},
        0x03: {"name": "NO DATA timeout", "default": 0x32, "type": "D"},
        0x04: {"name": "Adaptive timing mode", "default": 0x01, "type": "D"},
        0x06: {"name": "OBD source address", "default": 0xF1, "type": "R"},
        0x07: {"name": "Last protocol to try", "default": 0x09, "type": "I"},
        0x08: {"name": "Display false ID", "default": 0xFF, "type": "R"},
        0x09: {"name": "Character echo", "default": 0x00, "type": "R"},
        0x0A: {"name": "Linefeed character", "default": 0x0A, "type": "R"},
        0x0C: {"name": "RS232 baudrate divisor", "default": 0x68, "type": "P"},
        0x0D: {"name": "Carriage return", "default": 0x0D, "type": "R"},
        0x0E: {"name": "Power control options", "default": 0x9A, "type": "R"},
        0x0F: {"name": "Activity monitor options", "default": 0xD5, "type": "D"},
        # Add more PP parameters as needed
    } 
