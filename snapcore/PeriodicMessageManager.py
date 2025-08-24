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

from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Callable
from enum import Enum
import threading
import time
import logging

class MessageMode(Enum):
    """Message transmission modes from MIC3X2X datasheet"""
    OFF = 0                    # WM0 - Off
    CONDITIONAL = 1            # WM1 - Send if no other message in SW time
    CONDITIONAL_NO_RX = 2      # WM2 - Send if no message and not receiving
    CONTINUOUS = 3             # WM3 - Send at constant rate
    AUTO_HEADER_CONDITIONAL = 9      # Mode 1 with automatic header formatting
    AUTO_HEADER_NO_RX = 10          # Mode 2 with automatic header formatting
    AUTO_HEADER_CONTINUOUS = 11     # Mode 3 with automatic header formatting
    ISO15765_CONDITIONAL = 17       # Mode 1 with ISO15765 formatting
    ISO15765_NO_RX = 18            # Mode 2 with ISO15765 formatting
    ISO15765_CONTINUOUS = 19       # Mode 3 with ISO15765 formatting

class ProtocolType(Enum):
    """Protocol types for periodic messages"""
    CAN = "CAN"
    ISO_KWP = "ISO_KWP"
    J1850 = "J1850"

@dataclass
class PeriodicMessage:
    """Periodic message configuration"""
    sequence_number: int
    protocol: Optional[str] = None
    header: Optional[str] = None
    data: List[int] = None
    period_ms: int = 2000
    mode: MessageMode = MessageMode.CONDITIONAL
    protocol_type: ProtocolType = ProtocolType.CAN
    baudrate: Optional[int] = None
    enabled: bool = False
   
    def __post_init__(self):
        if self.data is None:
            self.data = []

@dataclass
class MessageStatistics:
    """Message transmission statistics"""
    messages_sent: int = 0
    last_sent_time: Optional[float] = None
    errors: int = 0
    success_rate: float = 100.0
    average_interval: float = 0.0

class PeriodicMessageManager:
    """
    Manages periodic messages (wake-up/keep-alive) for MIC3X2X
    Supports CAN WM, ISO WM, PMQE, and WMGP commands from datasheet
    """
   
    def __init__(self, command_handler):
        self.cmd_handler = command_handler
        self.logger = logging.getLogger(__name__)
       
        # Message storage (up to 8 groups per type as per datasheet)
        self.can_wm_messages: Dict[int, PeriodicMessage] = {}  # 1-8
        self.iso_wm_messages: Dict[int, PeriodicMessage] = {}  # 1-8
        self.pmqe_messages: Dict[int, PeriodicMessage] = {}    # 1-8
        self.wmgp_messages: Dict[int, PeriodicMessage] = {}    # 1-8
       
        # Statistics
        self.message_stats: Dict[str, MessageStatistics] = {}
       
        # Monitoring
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.status_callback: Optional[Callable] = None
       
        # Default settings from datasheet
        self.default_period_ms = 2000  # 2 seconds
        self.max_data_bytes_can = 8
        self.max_data_bytes_iso = 5
       
    def configure_can_wakeup_message(self, sequence_number: int,
                                   protocol: Optional[str] = None,
                                   header: str = "7DF",
                                   data: List[int] = None,
                                   period_ms: int = 2000,
                                   mode: MessageMode = MessageMode.CONDITIONAL,
                                   store: bool = False) -> bool:
        """Configure CAN wake-up/keep-alive message (VTCAN_WM command)"""
       
        if not (0 <= sequence_number <= 8):
            self.logger.error("Sequence number must be 0-8")
            return False
       
        if data is None:
            data = [0x01, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
       
        if len(data) > self.max_data_bytes_can:
            self.logger.error(f"CAN data cannot exceed {self.max_data_bytes_can} bytes")
            return False
       
        # Pad data to 8 bytes
        while len(data) < 8:
            data.append(0x00)
       
        # Format period in 20ms units as required by datasheet
        period_units = max(1, period_ms // 20)
       
        # Build command
        if sequence_number == 0:
            # Temporary message (not stored)
            if protocol:
                cmd = f"VTCAN_WM0,{protocol},{header},{' '.join(f'{b:02X}' for b in data)},{period_units:02X},{mode.value}"
            else:
                cmd = f"VTCAN_WM0,XX,{header},{' '.join(f'{b:02X}' for b in data)},{period_units:02X},{mode.value}"
        else:
            # Stored message
            if not protocol:
                self.logger.error("Protocol must be specified for stored messages")
                return False
            cmd = f"VTCAN_WM{sequence_number},{protocol},{header},{' '.join(f'{b:02X}' for b in data)},{period_units:02X},{mode.value}"
       
        response = self.cmd_handler.send_raw_command(cmd)
       
        if response.success:
            message = PeriodicMessage(
                sequence_number=sequence_number,
                protocol=protocol,
                header=header,
                data=data,
                period_ms=period_ms,
                mode=mode,
                protocol_type=ProtocolType.CAN,
                enabled=True
            )
           
            self.can_wm_messages[sequence_number] = message
            self.message_stats[f"CAN_WM_{sequence_number}"] = MessageStatistics()
           
            self.logger.info(f"Configured CAN WM message {sequence_number}")
            return True
       
        self.logger.error(f"Failed to configure CAN WM message: {response.error}")
        return False
   
    def configure_iso_wakeup_message(self, sequence_number: int,
                                   protocol: Optional[str] = None,
                                   header: str = "C133F1",
                                   data: List[int] = None,
                                   period_ms: int = 2000,
                                   enabled: bool = True) -> bool:
        """Configure ISO/KWP wake-up message (VTISO_WM command)"""
       
        if not (0 <= sequence_number <= 8):
            self.logger.error("Sequence number must be 0-8")
            return False
       
        if data is None:
            data = [0x3E, 0x00]
       
        if len(data) > self.max_data_bytes_iso:
            self.logger.error(f"ISO data cannot exceed {self.max_data_bytes_iso} bytes")
            return False
       
        # Format period in 20ms units
        period_units = max(1, period_ms // 20)
       
        # Build command
        if sequence_number == 0:
            # Temporary message
            cmd = f"VTISO_WM0,XX,{header},{' '.join(f'{b:02X}' for b in data)},{period_units:02X},{1 if enabled else 0}"
        else:
            # Stored message
            if not protocol:
                self.logger.error("Protocol must be specified for stored messages")
                return False
            cmd = f"VTISO_WM{sequence_number},{protocol},{header},{' '.join(f'{b:02X}' for b in data)},{period_units:02X},{1 if enabled else 0}"
       
        response = self.cmd_handler.send_raw_command(cmd)
       
        if response.success:
            message = PeriodicMessage(
                sequence_number=sequence_number,
                protocol=protocol,
                header=header,
                data=data,
                period_ms=period_ms,
                mode=MessageMode.CONDITIONAL if enabled else MessageMode.OFF,
                protocol_type=ProtocolType.ISO_KWP,
                enabled=enabled
            )
           
            self.iso_wm_messages[sequence_number] = message
            self.message_stats[f"ISO_WM_{sequence_number}"] = MessageStatistics()
           
            self.logger.info(f"Configured ISO WM message {sequence_number}")
            return True
       
        self.logger.error(f"Failed to configure ISO WM message: {response.error}")
        return False
   
    def configure_pmqe_message(self, sequence_number: int,
                             header: str = "710",
                             data: List[int] = None,
                             period_ms: int = 1000,
                             mode: MessageMode = MessageMode.CONDITIONAL) -> bool:
        """Configure PMQE periodic message (VTPMQE command)"""
       
        if not (1 <= sequence_number <= 8):
            self.logger.error("PMQE sequence number must be 1-8")
            return False
       
        if data is None:
            data = [0x3E, 0x80]
       
        if len(data) > 8:
            self.logger.error("PMQE data cannot exceed 8 bytes")
            return False
       
        # Build command
        data_str = ' '.join(f'{b:02X}' for b in data)
        cmd = f"VTPMQE{sequence_number},{header},{data_str},{period_ms},{mode.value:02X}"
       
        response = self.cmd_handler.send_raw_command(cmd)
       
        if response.success:
            message = PeriodicMessage(
                sequence_number=sequence_number,
                header=header,
                data=data,
                period_ms=period_ms,
                mode=mode,
                protocol_type=ProtocolType.CAN,
                enabled=True
            )
           
            self.pmqe_messages[sequence_number] = message
            self.message_stats[f"PMQE_{sequence_number}"] = MessageStatistics()
           
            self.logger.info(f"Configured PMQE message {sequence_number}")
            return True
       
        self.logger.error(f"Failed to configure PMQE message: {response.error}")
        return False
   
    def configure_wmgp_message(self, sequence_number: int,
                             protocol: str,
                             baudrate: int,
                             header: str,
                             data: List[int],
                             period_ms: int,
                             mode: MessageMode) -> bool:
        """Configure WMGP periodic message group (VTWMGP command)"""
       
        if not (1 <= sequence_number <= 8):
            self.logger.error("WMGP sequence number must be 1-8")
            return False
       
        if len(data) > 8:
            self.logger.error("WMGP data cannot exceed 8 bytes")
            return False
       
        # Build command
        data_str = ' '.join(f'{b:02X}' for b in data)
        cmd = f"VTWMGP{sequence_number},{protocol},{baudrate},{header},{data_str},{period_ms},{mode.value:02X}"
       
        response = self.cmd_handler.send_raw_command(cmd)
       
        if response.success:
            message = PeriodicMessage(
                sequence_number=sequence_number,
                protocol=protocol,
                header=header,
                data=data,
                period_ms=period_ms,
                mode=mode,
                protocol_type=ProtocolType.CAN,
                baudrate=baudrate,
                enabled=True
            )
           
            self.wmgp_messages[sequence_number] = message
            self.message_stats[f"WMGP_{sequence_number}"] = MessageStatistics()
           
            self.logger.info(f"Configured WMGP message {sequence_number}")
            return True
       
        self.logger.error(f"Failed to configure WMGP message: {response.error}")
        return False
   
    def delete_message(self, message_type: str, sequence_number: int) -> bool:
        """Delete a specific periodic message"""
       
        if message_type.upper() == "CAN_WM":
            cmd = f"VTDEL_CAN_WM{sequence_number if sequence_number > 0 else ''}"
            if sequence_number in self.can_wm_messages:
                del self.can_wm_messages[sequence_number]
        elif message_type.upper() == "ISO_WM":
            cmd = f"VTDEL_ISO_WM{sequence_number if sequence_number > 0 else ''}"
            if sequence_number in self.iso_wm_messages:
                del self.iso_wm_messages[sequence_number]
        elif message_type.upper() == "PMQE":
            cmd = f"VTPMQE{sequence_number}"
            if sequence_number in self.pmqe_messages:
                del self.pmqe_messages[sequence_number]
        elif message_type.upper() == "WMGP":
            cmd = f"VTWMGP{sequence_number}"
            if sequence_number in self.wmgp_messages:
                del self.wmgp_messages[sequence_number]
        else:
            self.logger.error(f"Unknown message type: {message_type}")
            return False
       
        response = self.cmd_handler.send_raw_command(cmd)
       
        if response.success:
            # Remove from statistics
            stats_key = f"{message_type.upper()}_{sequence_number}"
            if stats_key in self.message_stats:
                del self.message_stats[stats_key]
           
            self.logger.info(f"Deleted {message_type} message {sequence_number}")
            return True
       
        return False
   
    def delete_all_messages(self, message_type: Optional[str] = None) -> bool:
        """Delete all periodic messages of a specific type or all types"""
       
        success = True
       
        if message_type is None or message_type.upper() == "PMQE":
            response = self.cmd_handler.send_raw_command("VTPMQEFF")
            success &= response.success
            self.pmqe_messages.clear()
       
        if message_type is None or message_type.upper() == "WMGP":
            response = self.cmd_handler.send_raw_command("VTWMGPFF")
            success &= response.success
            self.wmgp_messages.clear()
       
        # Clear statistics for deleted messages
        if message_type:
            keys_to_remove = [k for k in self.message_stats.keys() if k.startswith(message_type.upper())]
            for key in keys_to_remove:
                del self.message_stats[key]
        else:
            self.message_stats.clear()
       
        return success
   
    def display_message_config(self, message_type: str, sequence_number: int) -> Optional[str]:
        """Display configuration of a specific message"""
       
        if message_type.upper() == "CAN_WM":
            cmd = f"VTDISP_CAN_WM{sequence_number if sequence_number > 0 else ''}"
        elif message_type.upper() == "ISO_WM":
            cmd = f"VTDISP_ISO_WM{sequence_number if sequence_number > 0 else ''}"
        elif message_type.upper() == "PMQE":
            cmd = f"VTPMQE_PRT{sequence_number if sequence_number > 0 else 'FF'}"
        elif message_type.upper() == "WMGP":
            cmd = f"VTWMGP_PRT{sequence_number if sequence_number > 0 else 'FF'}"
        else:
            return None
       
        response = self.cmd_handler.send_raw_command(cmd)
        return response.response if response.success else None
   
    def get_all_messages(self) -> Dict[str, Dict[int, PeriodicMessage]]:
        """Get all configured periodic messages"""
        return {
            'CAN_WM': dict(self.can_wm_messages),
            'ISO_WM': dict(self.iso_wm_messages),
            'PMQE': dict(self.pmqe_messages),
            'WMGP': dict(self.wmgp_messages)
        }
   
    def get_message_statistics(self) -> Dict[str, MessageStatistics]:
        """Get statistics for all periodic messages"""
        return dict(self.message_stats)
   
    def start_monitoring(self) -> bool:
        """Start monitoring periodic message status"""
        if self.monitoring_active:
            return False
       
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
       
        self.logger.info("Started periodic message monitoring")
        return True
   
    def stop_monitoring(self):
        """Stop monitoring periodic message status"""
        self.monitoring_active = False
       
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)
       
        self.logger.info("Stopped periodic message monitoring")
   
    def set_status_callback(self, callback: Callable):
        """Set callback for status updates"""
        self.status_callback = callback
   
    def configure_obd_keepalive(self, enable: bool = True,
                              period_ms: int = 2000) -> bool:
        """Configure standard OBD keep-alive message"""
        if enable:
            # Standard OBD keep-alive: Mode 1 PID 0 (supported PIDs)
            return self.configure_can_wakeup_message(
                sequence_number=1,
                protocol="233",  # ISO 15765 500K/11B
                header="7DF",
                data=[0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                period_ms=period_ms,
                mode=MessageMode.CONDITIONAL,
                store=True
            )
        else:
            return self.delete_message("CAN_WM", 1)
   
    def configure_gm_keepalive(self, enable: bool = True) -> bool:
        """Configure GM-specific keep-alive message"""
        if enable:
            # GM tester present message
            return self.configure_can_wakeup_message(
                sequence_number=2,
                protocol="263",  # SW-CAN for GM
                header="7E0",
                data=[0x01, 0x3E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00],
                period_ms=3000,
                mode=MessageMode.CONDITIONAL_NO_RX,
                store=True
            )
        else:
            return self.delete_message("CAN_WM", 2)
   
    def configure_ford_keepalive(self, enable: bool = True) -> bool:
        """Configure Ford-specific keep-alive message"""
        if enable:
            # Ford tester present message
            return self.configure_can_wakeup_message(
                sequence_number=3,
                protocol="233",  # HS-CAN for Ford
                header="7E0",
                data=[0x02, 0x3E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00],
                period_ms=2000,
                mode=MessageMode.CONDITIONAL,
                store=True
            )
        else:
            return self.delete_message("CAN_WM", 3)
   
    def get_active_message_count(self) -> Dict[str, int]:
        """Get count of active messages by type"""
        return {
            'CAN_WM': len([m for m in self.can_wm_messages.values() if m.enabled]),
            'ISO_WM': len([m for m in self.iso_wm_messages.values() if m.enabled]),
            'PMQE': len([m for m in self.pmqe_messages.values() if m.enabled]),
            'WMGP': len([m for m in self.wmgp_messages.values() if m.enabled])
        }
   
    def _monitor_loop(self):
        """Monitor periodic message status"""
        while self.monitoring_active:
            try:
                # Update statistics
                for msg_type, messages in self.get_all_messages().items():
                    for seq_num, message in messages.items():
                        if message.enabled:
                            stats_key = f"{msg_type}_{seq_num}"
                            if stats_key in self.message_stats:
                                # Update statistics (simplified)
                                stats = self.message_stats[stats_key]
                                current_time = time.time()
                               
                                if stats.last_sent_time:
                                    interval = current_time - stats.last_sent_time
                                    stats.average_interval = (stats.average_interval + interval) / 2
                               
                                stats.last_sent_time = current_time
               
                # Call status callback if set
                if self.status_callback:
                    try:
                        self.status_callback(self.get_active_message_count())
                    except Exception as e:
                        self.logger.error(f"Error in status callback: {e}")
               
                time.sleep(5.0)  # Check every 5 seconds
               
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                time.sleep(5.0)
   
    def __enter__(self):
        """Context manager entry"""
        return self
   
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_monitoring() 
