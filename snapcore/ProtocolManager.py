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

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Tuple
import logging
import time

class ProtocolFamily(Enum):
    """Protocol families supported by MIC3X2X"""
    J1850 = "J1850"
    ISO = "ISO"
    CAN = "CAN"
    J1939 = "J1939"
    USER_DEFINED = "USER"

class ProtocolType(Enum):
    """Specific protocol types from MIC3X2X datasheet"""
    # AT Protocol definitions (15 protocols)
    AUTO = 0
    SAE_J1850_PWM = 1
    SAE_J1850_VPW = 2
    ISO_9141_2 = 3
    ISO_14230_KWP2000_5BAUD = 4
    ISO_14230_KWP2000_FAST = 5
    ISO_15765_CAN_11BIT_500K = 6
    ISO_15765_CAN_29BIT_500K = 7
    ISO_15765_CAN_11BIT_250K = 8
    ISO_15765_CAN_29BIT_250K = 9
    SAE_J1939_CAN = 10
    USER_CAN_11BIT = 11  # Protocol B
    USER_CAN_29BIT = 12  # Protocol C
    USER_CAN_BOTH = 13   # Protocol D/E/F variations
   
class CANType(Enum):
    """CAN bus types supported by MIC3X2X"""
    HS_CAN = "HS_CAN"      # High Speed CAN (500K typical)
    MS_CAN = "MS_CAN"      # Medium Speed CAN (125K typical)
    SW_CAN = "SW_CAN"      # Single Wire CAN (33.3K typical)
    CH_CAN = "CH_CAN"      # GM Chassis CAN
    LS_CAN = "LS_CAN"      # Low Speed CAN

@dataclass
class ProtocolInfo:
    """Protocol information structure"""
    protocol_id: Union[int, str]
    name: str
    family: ProtocolFamily
    description: str
    baudrate: Optional[int] = None
    can_type: Optional[CANType] = None
    supports_extended_address: bool = False
    supports_flow_control: bool = False
    max_data_length: int = 8
    initialization_required: bool = False

@dataclass
class ProtocolStatus:
    """Current protocol status"""
    active_protocol: Optional[ProtocolInfo] = None
    is_connected: bool = False
    last_activity: Optional[float] = None
    error_count: int = 0
    initialization_time: Optional[float] = None

class ProtocolManager:
    """
    Manages protocol selection, switching, and configuration for MIC3X2X
    Based on datasheet specifications for 15 ELM + 23 STN + 64 VT protocols
    """
   
    def __init__(self, command_handler):
        self.cmd_handler = command_handler
        self.logger = logging.getLogger(__name__)
       
        # Current status
        self.status = ProtocolStatus()
       
        # Protocol definitions from MIC3X2X datasheet
        self.at_protocols = self._init_at_protocols()
        self.st_protocols = self._init_st_protocols()
        self.vt_protocols = {}  # User-configurable, loaded dynamically
       
        # Default settings
        self.auto_connect_timeout = 30.0
        self.protocol_switch_delay = 2.0
       
    def get_current_protocol(self) -> Optional[ProtocolInfo]:
        """Get currently active protocol"""
        if not self.status.active_protocol:
            self._refresh_protocol_status()
        return self.status.active_protocol
   
    def list_available_protocols(self, family: Optional[ProtocolFamily] = None) -> Dict[str, ProtocolInfo]:
        """List all available protocols, optionally filtered by family"""
        all_protocols = {}
        all_protocols.update(self.at_protocols)
        all_protocols.update(self.st_protocols)
        all_protocols.update(self.vt_protocols)
       
        if family:
            return {k: v for k, v in all_protocols.items() if v.family == family}
       
        return all_protocols
   
    def set_protocol_at(self, protocol_id: int) -> bool:
        """Set AT protocol (0-15)"""
        if protocol_id not in range(0, 16):
            self.logger.error(f"Invalid AT protocol ID: {protocol_id}")
            return False
       
        self.logger.info(f"Setting AT protocol {protocol_id}")
       
        # Send AT command
        response = self.cmd_handler.at_set_protocol(f"{protocol_id:X}")
       
        if response.success:
            # Wait for protocol initialization
            time.sleep(self.protocol_switch_delay)
           
            # Verify protocol set correctly
            if self._verify_protocol_switch():
                self.status.initialization_time = time.time()
                return True
       
        self.logger.error(f"Failed to set AT protocol {protocol_id}: {response.error}")
        return False
   
    def set_protocol_st(self, protocol_id: Union[int, str]) -> bool:
        """Set ST protocol (11-64, C1-D6, etc.)"""
        self.logger.info(f"Setting ST protocol {protocol_id}")
       
        response = self.cmd_handler.st_set_protocol(protocol_id)
       
        if response.success:
            time.sleep(self.protocol_switch_delay)
           
            if self._verify_protocol_switch():
                self.status.initialization_time = time.time()
                return True
       
        self.logger.error(f"Failed to set ST protocol {protocol_id}: {response.error}")
        return False
   
    def set_protocol_vt(self, protocol_id: Union[int, str], protocol_type: int = 1) -> bool:
        """Set VT protocol (101-140)"""
        self.logger.info(f"Setting VT protocol {protocol_id}")
       
        if protocol_type == 1:
            response = self.cmd_handler.vt_set_protocol_1(str(protocol_id))
        else:
            response = self.cmd_handler.vt_set_protocol_2(str(protocol_id))
       
        if response.success:
            time.sleep(self.protocol_switch_delay)
           
            if self._verify_protocol_switch():
                self.status.initialization_time = time.time()
                return True
       
        self.logger.error(f"Failed to set VT protocol {protocol_id}: {response.error}")
        return False
   
    def auto_detect_protocol(self) -> Optional[ProtocolInfo]:
        """Auto-detect vehicle protocol"""
        self.logger.info("Starting automatic protocol detection")
       
        start_time = time.time()
       
        # Set to auto mode (protocol 0)
        response = self.cmd_handler.at_set_protocol("0")
        if not response.success:
            self.logger.error("Failed to set auto protocol mode")
            return None
       
        # Try a basic OBD request to trigger protocol detection
        test_response = self.cmd_handler.send_raw_command("0100")  # Supported PIDs
       
        # Wait for auto-detection with timeout
        while time.time() - start_time < self.auto_connect_timeout:
            current_protocol = self._get_current_protocol_info()
            if current_protocol and current_protocol.protocol_id != 0:
                self.logger.info(f"Auto-detected protocol: {current_protocol.name}")
                self.status.active_protocol = current_protocol
                self.status.is_connected = True
                return current_protocol
           
            time.sleep(1.0)
       
        self.logger.warning("Auto-detection timeout")
        return None
   
    def configure_can_protocol(self, protocol_id: str, option: str, baudrate: str,
                              can_type: CANType, tm_mode: Optional[str] = None) -> bool:
        """Configure custom CAN protocol using VT commands"""
        self.logger.info(f"Configuring CAN protocol {protocol_id}")
       
        response = self.cmd_handler.vt_configure_can(
            protocol_id, option, baudrate, can_type.value, tm_mode
        )
       
        if response.success:
            # Add to VT protocols registry
            protocol_info = ProtocolInfo(
                protocol_id=protocol_id,
                name=f"Custom CAN {protocol_id}",
                family=ProtocolFamily.CAN,
                description=f"User configured CAN protocol",
                can_type=can_type,
                supports_extended_address=True,
                supports_flow_control=True
            )
            self.vt_protocols[protocol_id] = protocol_info
            return True
       
        self.logger.error(f"Failed to configure CAN protocol: {response.error}")
        return False
   
    def get_protocol_capabilities(self, protocol_info: ProtocolInfo) -> Dict[str, bool]:
        """Get capabilities of a specific protocol"""
        capabilities = {
            'supports_headers': False,
            'supports_extended_addressing': protocol_info.supports_extended_address,
            'supports_flow_control': protocol_info.supports_flow_control,
            'supports_monitoring': True,
            'supports_filters': False,
            'requires_initialization': protocol_info.initialization_required,
            'supports_wakeup_messages': False
        }
       
        # Set capabilities based on protocol family
        if protocol_info.family == ProtocolFamily.CAN:
            capabilities.update({
                'supports_headers': True,
                'supports_filters': True,
                'supports_wakeup_messages': True,
                'max_data_bytes': 8
            })
        elif protocol_info.family == ProtocolFamily.ISO:
            capabilities.update({
                'supports_headers': True,
                'requires_initialization': True,
                'supports_wakeup_messages': True,
                'max_data_bytes': 255
            })
        elif protocol_info.family == ProtocolFamily.J1850:
            capabilities.update({
                'supports_headers': True,
                'max_data_bytes': 12
            })
       
        return capabilities
   
    def optimize_for_vehicle(self, make: str, model: str, year: int) -> bool:
        """Optimize protocol settings for specific vehicle"""
        self.logger.info(f"Optimizing for {year} {make} {model}")
       
        # Vehicle-specific optimizations based on common configurations
        optimizations = self._get_vehicle_optimizations(make, model, year)
       
        success = True
        for setting, value in optimizations.items():
            if setting == "protocol":
                success &= self.set_protocol_at(value)
            elif setting == "headers":
                response = self.cmd_handler.at_headers(value)
                success &= response.success
            elif setting == "adaptive_timing":
                response = self.cmd_handler.at_adaptive_timing(value)
                success &= response.success
       
        return success
   
    def get_bus_activity(self, can_type: Optional[CANType] = None) -> Dict[str, any]:
        """Check bus activity and estimate protocols"""
        if can_type:
            response = self.cmd_handler.vt_show_bus(can_type.value)
        else:
            response = self.cmd_handler.vt_show_bus()
       
        if not response.success:
            return {"active": False, "error": response.error}
       
        # Parse response for protocol and frequency info
        activity_info = self._parse_bus_activity(response.response)
        return activity_info
   
    def close_protocol(self) -> bool:
        """Close current protocol connection"""
        self.logger.info("Closing protocol connection")
       
        response = self.cmd_handler.st_protocol_close()
        if response.success:
            self.status.is_connected = False
            self.status.last_activity = time.time()
            return True
       
        return False
   
    def open_protocol(self) -> bool:
        """Open/reopen protocol connection"""
        self.logger.info("Opening protocol connection")
       
        response = self.cmd_handler.st_protocol_open()
        if response.success:
            self.status.is_connected = True
            self.status.last_activity = time.time()
            return True
       
        return False
   
    def _refresh_protocol_status(self):
        """Refresh current protocol status"""
        # Get protocol description
        response = self.cmd_handler.at_describe_protocol()
        if response.success:
            protocol_info = self._parse_protocol_description(response.response)
            self.status.active_protocol = protocol_info
   
    def _verify_protocol_switch(self) -> bool:
        """Verify that protocol switch was successful"""
        response = self.cmd_handler.at_describe_protocol()
        if response.success and "UNABLE" not in response.response.upper():
            self._refresh_protocol_status()
            return True
        return False
   
    def _get_current_protocol_info(self) -> Optional[ProtocolInfo]:
        """Get current protocol information from device"""
        response = self.cmd_handler.at_describe_protocol_number()
        if not response.success:
            return None
       
        try:
            protocol_id = int(response.response.strip(), 16)
            if str(protocol_id) in self.at_protocols:
                return self.at_protocols[str(protocol_id)]
        except ValueError:
            pass
       
        return None
   
    def _parse_protocol_description(self, description: str) -> Optional[ProtocolInfo]:
        """Parse protocol description string into ProtocolInfo"""
        # This would parse strings like "ISO 15765-4 (CAN 11/500)"
        # Implementation depends on exact format from device
       
        if "J1850" in description:
            family = ProtocolFamily.J1850
        elif "ISO" in description:
            if "15765" in description:
                family = ProtocolFamily.CAN
            else:
                family = ProtocolFamily.ISO
        elif "CAN" in description:
            family = ProtocolFamily.CAN
        else:
            family = ProtocolFamily.USER_DEFINED
       
        return ProtocolInfo(
            protocol_id="unknown",
            name=description.strip(),
            family=family,
            description=description.strip()
        )
   
    def _parse_bus_activity(self, response: str) -> Dict[str, any]:
        """Parse VTSHOW_BUS response"""
        if "Inactivly" in response:
            return {"active": False, "protocols": []}
       
        activity = {"active": True, "protocols": []}
       
        if "P:" in response and "F:" in response:
            # Extract protocol and frequency
            parts = response.split(";")
            for part in parts:
                if part.strip().startswith("P:"):
                    activity["protocol"] = part.split(":")[1].strip()
                elif part.strip().startswith("F:"):
                    activity["frequency"] = part.split(":")[1].strip()
       
        return activity
   
    def _get_vehicle_optimizations(self, make: str, model: str, year: int) -> Dict[str, any]:
        """Get vehicle-specific optimizations"""
        make = make.upper()
       
        # Common optimizations by manufacturer
        optimizations = {}
       
        if make in ["FORD", "LINCOLN", "MERCURY"]:
            if year >= 2008:
                optimizations["protocol"] = 6  # CAN 11-bit
                optimizations["headers"] = True
                optimizations["adaptive_timing"] = 1
        elif make in ["GM", "CHEVROLET", "BUICK", "CADILLAC", "GMC"]:
            if year >= 2008:
                optimizations["protocol"] = 6  # CAN 11-bit
            else:
                optimizations["protocol"] = 2  # VPW
        elif make in ["CHRYSLER", "DODGE", "JEEP", "RAM"]:
            if year >= 2008:
                optimizations["protocol"] = 6  # CAN 11-bit
            else:
                optimizations["protocol"] = 1  # PWM
        elif make in ["TOYOTA", "LEXUS", "SCION"]:
            optimizations["protocol"] = 6  # CAN 11-bit
            optimizations["adaptive_timing"] = 2
        elif make in ["HONDA", "ACURA"]:
            optimizations["protocol"] = 6  # CAN 11-bit
       
        return optimizations
   
    def _init_at_protocols(self) -> Dict[str, ProtocolInfo]:
        """Initialize AT protocol definitions"""
        return {
            "0": ProtocolInfo(0, "Automatic", ProtocolFamily.USER_DEFINED, "Auto-detect protocol"),
            "1": ProtocolInfo(1, "SAE J1850 PWM", ProtocolFamily.J1850, "41.6K baud PWM", 41600),
            "2": ProtocolInfo(2, "SAE J1850 VPW", ProtocolFamily.J1850, "10.4K baud VPW", 10400),
            "3": ProtocolInfo(3, "ISO 9141-2", ProtocolFamily.ISO, "5 baud init", 10400,
                            initialization_required=True),
            "4": ProtocolInfo(4, "ISO 14230-4 (KWP)", ProtocolFamily.ISO, "5 baud init", 10400,
                            initialization_required=True),
            "5": ProtocolInfo(5, "ISO 14230-4 (KWP)", ProtocolFamily.ISO, "Fast init", 10400,
                            initialization_required=True),
            "6": ProtocolInfo(6, "ISO 15765-4 (CAN)", ProtocolFamily.CAN, "11-bit 500K", 500000,
                            CANType.HS_CAN, supports_extended_address=True, supports_flow_control=True),
            "7": ProtocolInfo(7, "ISO 15765-4 (CAN)", ProtocolFamily.CAN, "29-bit 500K", 500000,
                            CANType.HS_CAN, supports_extended_address=True, supports_flow_control=True),
            "8": ProtocolInfo(8, "ISO 15765-4 (CAN)", ProtocolFamily.CAN, "11-bit 250K", 250000,
                            CANType.HS_CAN, supports_extended_address=True, supports_flow_control=True),
            "9": ProtocolInfo(9, "ISO 15765-4 (CAN)", ProtocolFamily.CAN, "29-bit 250K", 250000,
                            CANType.HS_CAN, supports_extended_address=True, supports_flow_control=True),
            "A": ProtocolInfo(10, "SAE J1939 (CAN)", ProtocolFamily.J1939, "29-bit 250K", 250000,
                            CANType.HS_CAN, max_data_length=1785),
            "B": ProtocolInfo(11, "User CAN 11-bit", ProtocolFamily.USER_DEFINED, "Configurable"),
            "C": ProtocolInfo(12, "User CAN 29-bit", ProtocolFamily.USER_DEFINED, "Configurable"),
            "D": ProtocolInfo(13, "User CAN", ProtocolFamily.USER_DEFINED, "Configurable"),
            "E": ProtocolInfo(14, "User CAN", ProtocolFamily.USER_DEFINED, "Configurable"),
            "F": ProtocolInfo(15, "User CAN", ProtocolFamily.USER_DEFINED, "Configurable"),
        }
   
    def _init_st_protocols(self) -> Dict[str, ProtocolInfo]:
        """Initialize ST protocol definitions from datasheet"""
        protocols = {}
       
        # J1850 protocols
        protocols["211"] = ProtocolInfo("211", "J1850 PWM", ProtocolFamily.J1850, "PWM format")
        protocols["212"] = ProtocolInfo("212", "J1850 VPW", ProtocolFamily.J1850, "VPW format")
       
        # ISO protocols
        protocols["221"] = ProtocolInfo("221", "ISO 9141", ProtocolFamily.ISO, "No header, no autoinit")
        protocols["222"] = ProtocolInfo("222", "ISO 9141-2", ProtocolFamily.ISO, "5 baud autoinit")
        protocols["223"] = ProtocolInfo("223", "ISO 14230", ProtocolFamily.ISO, "No autoinit")
        protocols["224"] = ProtocolInfo("224", "ISO 14230", ProtocolFamily.ISO, "5 baud autoinit")
        protocols["225"] = ProtocolInfo("225", "ISO 14230", ProtocolFamily.ISO, "Fast autoinit")
       
        # HS CAN protocols
        protocols["231"] = ProtocolInfo("231", "HS CAN", ProtocolFamily.CAN, "ISO 11898, 11-bit, 500K", 500000, CANType.HS_CAN)
        protocols["232"] = ProtocolInfo("232", "HS CAN", ProtocolFamily.CAN, "ISO 11898, 29-bit, 500K", 500000, CANType.HS_CAN)
        protocols["233"] = ProtocolInfo("233", "HS CAN", ProtocolFamily.CAN, "ISO 15765, 11-bit, 500K", 500000, CANType.HS_CAN)
        protocols["234"] = ProtocolInfo("234", "HS CAN", ProtocolFamily.CAN, "ISO 15765, 29-bit, 500K", 500000, CANType.HS_CAN)
        protocols["235"] = ProtocolInfo("235", "HS CAN", ProtocolFamily.CAN, "ISO 15765, 11-bit, 250K", 250000, CANType.HS_CAN)
        protocols["236"] = ProtocolInfo("236", "HS CAN", ProtocolFamily.CAN, "ISO 15765, 29-bit, 250K", 250000, CANType.HS_CAN)
       
        # MS CAN protocols
        protocols["251"] = ProtocolInfo("251", "MS CAN", ProtocolFamily.CAN, "ISO 11898, 11-bit, 125K", 125000, CANType.MS_CAN)
        protocols["252"] = ProtocolInfo("252", "MS CAN", ProtocolFamily.CAN, "ISO 11898, 29-bit, 125K", 125000, CANType.MS_CAN)
        protocols["253"] = ProtocolInfo("253", "MS CAN", ProtocolFamily.CAN, "ISO 15765, 11-bit, 125K", 125000, CANType.MS_CAN)
        protocols["254"] = ProtocolInfo("254", "MS CAN", ProtocolFamily.CAN, "ISO 15765, 29-bit, 125K", 125000, CANType.MS_CAN)
       
        # SW CAN protocols
        protocols["261"] = ProtocolInfo("261", "SW CAN", ProtocolFamily.CAN, "ISO 11898, 11-bit, 33.3K", 33300, CANType.SW_CAN)
        protocols["262"] = ProtocolInfo("262", "SW CAN", ProtocolFamily.CAN, "ISO 11898, 29-bit, 33.3K", 33300, CANType.SW_CAN)
        protocols["263"] = ProtocolInfo("263", "SW CAN", ProtocolFamily.CAN, "ISO 15765, 11-bit, 33.3K", 33300, CANType.SW_CAN)
        protocols["264"] = ProtocolInfo("264", "SW CAN", ProtocolFamily.CAN, "ISO 15765, 29-bit, 33.3K", 33300, CANType.SW_CAN)
       
        # CH CAN protocols (GM Chassis)
        protocols["2C1"] = ProtocolInfo("2C1", "CH CAN", ProtocolFamily.CAN, "ISO 11898, 11-bit, 500K", 500000, CANType.CH_CAN)
        protocols["2C2"] = ProtocolInfo("2C2", "CH CAN", ProtocolFamily.CAN, "ISO 11898, 29-bit, 500K", 500000, CANType.CH_CAN)
        protocols["2C3"] = ProtocolInfo("2C3", "CH CAN", ProtocolFamily.CAN, "ISO 15765, 11-bit, 500K", 500000, CANType.CH_CAN)
        protocols["2C4"] = ProtocolInfo("2C4", "CH CAN", ProtocolFamily.CAN, "ISO 15765, 29-bit, 500K", 500000, CANType.CH_CAN)
       
        # LS CAN protocols
        protocols["2D1"] = ProtocolInfo("2D1", "LS CAN", ProtocolFamily.CAN, "ISO 11898, 11-bit, 500K", 500000, CANType.LS_CAN)
        protocols["2D2"] = ProtocolInfo("2D2", "LS CAN", ProtocolFamily.CAN, "ISO 11898, 29-bit, 500K", 500000, CANType.LS_CAN)
        protocols["2D3"] = ProtocolInfo("2D3", "LS CAN", ProtocolFamily.CAN, "ISO 15765, 11-bit, 500K", 500000, CANType.LS_CAN)
       
        # J1939 protocols
        protocols["241"] = ProtocolInfo("241", "J1939", ProtocolFamily.J1939, "29-bit, 250K", 250000)
        protocols["242"] = ProtocolInfo("242", "J1939", ProtocolFamily.J1939, "29-bit, 500K", 500000)
       
        return protocols 
