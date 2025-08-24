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
import time
from typing import Dict, List, Optional, Union, Tuple
from enum import Enum
import logging

class CommandType(Enum):
    AT = "AT"
    ST = "ST"
    VT = "VT"

class CommandResponse:
    """Container for command responses"""
    def __init__(self, command: str, response: str, success: bool = True,
                 error: Optional[str] = None, execution_time: float = 0.0):
        self.command = command
        self.response = response
        self.success = success
        self.error = error
        self.execution_time = execution_time
        self.timestamp = time.time()

class CommandHandler:
    """
    Handles AT, ST, and VT commands for MIC3X2X OBD adapter
    Based on MIC3X2X datasheet command specifications
    """
   
    def __init__(self, bluetooth_manager):
        self.bt_manager = bluetooth_manager
        self.logger = logging.getLogger(__name__)
       
        # Command validation patterns
        self.command_patterns = {
            CommandType.AT: self._get_at_patterns(),
            CommandType.ST: self._get_st_patterns(),
            CommandType.VT: self._get_vt_patterns()
        }
       
        # Response timeout settings
        self.timeouts = {
            'default': 5.0,
            'reset': 10.0,
            'protocol_switch': 8.0,
            'initialization': 15.0,
            'long_response': 30.0
        }
       
    # =========================================================================
    # AT COMMANDS (ELM327 Compatible)
    # =========================================================================
   
    def at_reset(self) -> CommandResponse:
        """ATZ - Reset all"""
        return self._send_command("ATZ", CommandType.AT, timeout=self.timeouts['reset'])
   
    def at_identify(self) -> CommandResponse:
        """ATI - Print version ID"""
        return self._send_command("ATI", CommandType.AT)
   
    def at_device_description(self) -> CommandResponse:
        """AT@1 - Display device description"""
        return self._send_command("AT@1", CommandType.AT)
   
    def at_echo(self, enable: bool) -> CommandResponse:
        """ATE0/ATE1 - Echo off/on"""
        cmd = "ATE1" if enable else "ATE0"
        return self._send_command(cmd, CommandType.AT)
   
    def at_headers(self, enable: bool) -> CommandResponse:
        """ATH0/ATH1 - Headers off/on"""
        cmd = "ATH1" if enable else "ATH0"
        return self._send_command(cmd, CommandType.AT)
   
    def at_linefeeds(self, enable: bool) -> CommandResponse:
        """ATL0/ATL1 - Linefeeds off/on"""
        cmd = "ATL1" if enable else "ATL0"
        return self._send_command(cmd, CommandType.AT)
   
    def at_memory(self, enable: bool) -> CommandResponse:
        """ATM0/ATM1 - Memory off/on"""
        cmd = "ATM1" if enable else "ATM0"
        return self._send_command(cmd, CommandType.AT)
   
    def at_read_voltage(self) -> CommandResponse:
        """ATRV - Read input voltage"""
        return self._send_command("ATRV", CommandType.AT)
   
    def at_set_protocol(self, protocol: Union[int, str]) -> CommandResponse:
        """ATSP h - Set protocol"""
        cmd = f"ATSP{protocol}"
        return self._send_command(cmd, CommandType.AT, timeout=self.timeouts['protocol_switch'])
   
    def at_describe_protocol(self) -> CommandResponse:
        """ATDP - Describe current protocol"""
        return self._send_command("ATDP", CommandType.AT)
   
    def at_describe_protocol_number(self) -> CommandResponse:
        """ATDPN - Describe protocol by number"""
        return self._send_command("ATDPN", CommandType.AT)
   
    def at_set_header(self, header: str) -> CommandResponse:
        """ATSH xxx - Set header"""
        cmd = f"ATSH{header.upper()}"
        return self._send_command(cmd, CommandType.AT)
   
    def at_can_filter(self, filter_id: str) -> CommandResponse:
        """ATCF xxx - Set CAN ID filter"""
        cmd = f"ATCF{filter_id.upper()}"
        return self._send_command(cmd, CommandType.AT)
   
    def at_can_mask(self, mask: str) -> CommandResponse:
        """ATCM xxx - Set CAN ID mask"""
        cmd = f"ATCM{mask.upper()}"
        return self._send_command(cmd, CommandType.AT)
   
    def at_can_receive_address(self, address: str) -> CommandResponse:
        """ATCRA xxx - Set CAN receive address"""
        cmd = f"ATCRA{address.upper()}"
        return self._send_command(cmd, CommandType.AT)
   
    def at_adaptive_timing(self, mode: int) -> CommandResponse:
        """ATAT0/1/2 - Adaptive timing"""
        if mode not in [0, 1, 2]:
            return CommandResponse("", "", False, "Invalid adaptive timing mode")
        cmd = f"ATAT{mode}"
        return self._send_command(cmd, CommandType.AT)
   
    def at_set_timeout(self, timeout_val: int) -> CommandResponse:
        """ATST xx - Set timeout"""
        cmd = f"ATST{timeout_val:02X}"
        return self._send_command(cmd, CommandType.AT)
   
    def at_monitor_all(self) -> CommandResponse:
        """ATMA - Monitor all"""
        return self._send_command("ATMA", CommandType.AT, timeout=self.timeouts['long_response'])
   
    def at_can_extended_address(self, address: Optional[str] = None) -> CommandResponse:
        """ATCEA xx - CAN extended addressing"""
        if address is None:
            cmd = "ATCEA"
        else:
            cmd = f"ATCEA{address.upper()}"
        return self._send_command(cmd, CommandType.AT)
   
    # =========================================================================
    # ST COMMANDS (STN Compatible)
    # =========================================================================
   
    def st_identify(self) -> CommandResponse:
        """STI - Print firmware ID string"""
        return self._send_command("STI", CommandType.ST)
   
    def st_device_info(self) -> CommandResponse:
        """STDI - Print device hardware ID"""
        return self._send_command("STDI", CommandType.ST)
   
    def st_manufacturer(self) -> CommandResponse:
        """STMFR - Print manufacturer ID"""
        return self._send_command("STMFR", CommandType.ST)
   
    def st_serial_number(self) -> CommandResponse:
        """STSN - Print device serial number"""
        return self._send_command("STSN", CommandType.ST)
   
    def st_set_protocol(self, protocol: Union[int, str]) -> CommandResponse:
        """STP hh - Set protocol"""
        cmd = f"STP{protocol}"
        return self._send_command(cmd, CommandType.ST, timeout=self.timeouts['protocol_switch'])
   
    def st_protocol_number(self) -> CommandResponse:
        """STPR - Report current protocol number"""
        return self._send_command("STPR", CommandType.ST)
   
    def st_protocol_string(self) -> CommandResponse:
        """STPRS - Report current protocol string"""
        return self._send_command("STPRS", CommandType.ST)
   
    def st_protocol_baudrate(self, baudrate: Optional[int] = None) -> CommandResponse:
        """STPBR baud - Set/read OBD protocol baud rate"""
        if baudrate is None:
            cmd = "STPBRR"
        else:
            cmd = f"STPBR{baudrate}"
        return self._send_command(cmd, CommandType.ST)
   
    def st_protocol_close(self) -> CommandResponse:
        """STPC - Close current protocol"""
        return self._send_command("STPC", CommandType.ST)
   
    def st_protocol_open(self) -> CommandResponse:
        """STPO - Open current protocol"""
        return self._send_command("STPO", CommandType.ST)
   
    def st_monitor(self) -> CommandResponse:
        """STM - Monitor OBD bus using current filters"""
        return self._send_command("STM", CommandType.ST, timeout=self.timeouts['long_response'])
   
    def st_filter_pass_add(self, pattern: str, mask: str = None) -> CommandResponse:
        """STFPA pattern, mask - Add pass filter"""
        if mask:
            cmd = f"STFPA {pattern},{mask}"
        else:
            cmd = f"STFPA {pattern}"
        return self._send_command(cmd, CommandType.ST)
   
    def st_filter_pass_clear(self) -> CommandResponse:
        """STFPC - Clear all pass filters"""
        return self._send_command("STFPC", CommandType.ST)
   
    def st_filter_block_add(self, pattern: str, mask: str = None) -> CommandResponse:
        """STFBA pattern, mask - Add block filter"""
        if mask:
            cmd = f"STFBA {pattern},{mask}"
        else:
            cmd = f"STFBA {pattern}"
        return self._send_command(cmd, CommandType.ST)
   
    def st_filter_block_clear(self) -> CommandResponse:
        """STFBC - Clear all block filters"""
        return self._send_command("STFBC", CommandType.ST)
   
    # =========================================================================
    # VT COMMANDS (MIC3X2X Specific)
    # =========================================================================
   
    def vt_identify(self) -> CommandResponse:
        """VTI - Display adapter device name"""
        return self._send_command("VTI", CommandType.VT)
   
    def vt_version(self) -> CommandResponse:
        """VTVERS - Display firmware version"""
        return self._send_command("VTVERS", CommandType.VT)
   
    def vt_manufacturer(self) -> CommandResponse:
        """VTPROI - Display manufacturer name"""
        return self._send_command("VTPROI", CommandType.VT)
   
    def vt_designer(self) -> CommandResponse:
        """VTD - Display solution designer"""
        return self._send_command("VTD", CommandType.VT)
   
    def vt_set_protocol_1(self, protocol: str) -> CommandResponse:
        """VTP1hh - Switch to VT defined protocol"""
        cmd = f"VTP1{protocol}"
        return self._send_command(cmd, CommandType.VT, timeout=self.timeouts['protocol_switch'])
   
    def vt_set_protocol_2(self, protocol: str) -> CommandResponse:
        """VTP2hh - Switch to ST defined protocol"""
        cmd = f"VTP2{protocol}"
        return self._send_command(cmd, CommandType.VT, timeout=self.timeouts['protocol_switch'])
   
    def vt_protocol_number(self) -> CommandResponse:
        """VTPRON - Display current protocol number"""
        return self._send_command("VTPRON", CommandType.VT)
   
    def vt_protocol_description(self) -> CommandResponse:
        """VTPROT - Display current protocol description"""
        return self._send_command("VTPROT", CommandType.VT)
   
    def vt_set_baudrate(self, baudrate: int) -> CommandResponse:
        """VTPBR baud - Set OBD protocol baud rate"""
        cmd = f"VTPBR{baudrate}"
        return self._send_command(cmd, CommandType.VT)
   
    def vt_read_baudrate(self) -> CommandResponse:
        """VTPBRD - Display OBD protocol baud rate"""
        return self._send_command("VTPBRD", CommandType.VT)
   
    def vt_uart_baudrate_set(self, baudrate: int, timeout_ms: int) -> CommandResponse:
        """VTUART_BUAD_SET baud,timeout - Set serial baud rate"""
        cmd = f"VTUART_BUAD_SET{baudrate},{timeout_ms}"
        return self._send_command(cmd, CommandType.VT)
   
    def vt_show_bus(self, can_type: Optional[str] = None) -> CommandResponse:
        """VTSHOW_BUS [CAN_TYPE] - Measure bus activity"""
        if can_type:
            cmd = f"VTSHOW_BUS{can_type}"
        else:
            cmd = "VTSHOW_BUS"
        return self._send_command(cmd, CommandType.VT, timeout=self.timeouts['long_response'])
   
    def vt_power_manage(self) -> CommandResponse:
        """VTPOWERMANAGE - Read power management settings"""
        return self._send_command("VTPOWERMANAGE", CommandType.VT)
   
    def vt_read_voltage(self) -> CommandResponse:
        """VTVLRD - Display battery voltage every 4ms"""
        return self._send_command("VTVLRD", CommandType.VT, timeout=self.timeouts['long_response'])
   
    def vt_read_mac(self) -> CommandResponse:
        """VTRD_MAC - Read MAC address contents"""
        return self._send_command("VTRD_MAC", CommandType.VT)
   
    def vt_read_serial(self) -> CommandResponse:
        """VTRDSN - Read manufacturer serial number"""
        return self._send_command("VTRDSN", CommandType.VT)
   
    def vt_read_uds(self) -> CommandResponse:
        """VTRD_UDS - Read unique device ID"""
        return self._send_command("VTRD_UDS", CommandType.VT)
   
    def vt_switch_group(self, switches: List[str]) -> CommandResponse:
        """VTSWGP switch1,...,switchN - Set batch switch commands"""
        cmd = f"VTSWGP{','.join(switches)}"
        return self._send_command(cmd, CommandType.VT)
   
    def vt_all_protocols_at(self) -> CommandResponse:
        """VTAT_PROTOCOL_ALL - Display all AT protocols"""
        return self._send_command("VTAT_PROTOCOL_ALL", CommandType.VT)
   
    def vt_all_protocols_st(self) -> CommandResponse:
        """VTST_PROTOCOL_ALL - Display all ST protocols"""
        return self._send_command("VTST_PROTOCOL_ALL", CommandType.VT)
   
    def vt_all_protocols_vt(self) -> CommandResponse:
        """VTVT_PROTOCOL_ALL - Display all VT protocols"""
        return self._send_command("VTVT_PROTOCOL_ALL", CommandType.VT)
   
    def vt_configure_can(self, protocol: str, option: str, baudrate: str,
                        can_type: str, tm: Optional[str] = None) -> CommandResponse:
        """VTCFG_CAN - Configure CAN protocol"""
        if tm:
            cmd = f"VTCFG_CAN{protocol},{option},{baudrate},{can_type},{tm}"
        else:
            cmd = f"VTCFG_CAN{protocol},{option},{baudrate},{can_type}"
        return self._send_command(cmd, CommandType.VT)
   
    def vt_set_header(self, header: str, receiver: Optional[str] = None,
                     timeout: Optional[str] = None) -> CommandResponse:
        """VTSET_HD - Set header and receiver address"""
        cmd = f"VTSET_HD{header}"
        if receiver:
            cmd += f",{receiver}"
        if timeout:
            cmd += f",{timeout}"
        return self._send_command(cmd, CommandType.VT)
   
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
   
    def send_raw_command(self, command: str, timeout: float = None) -> CommandResponse:
        """Send raw command without validation"""
        start_time = time.time()
       
        if not self.bt_manager.is_connected():
            return CommandResponse(command, "", False, "Not connected to device")
       
        try:
            response = self.bt_manager.send_command(command, timeout=timeout)
            execution_time = time.time() - start_time
           
            if response is None:
                return CommandResponse(command, "", False, "No response received", execution_time)
           
            return CommandResponse(command, response, True, None, execution_time)
           
        except Exception as e:
            execution_time = time.time() - start_time
            return CommandResponse(command, "", False, str(e), execution_time)
   
    def validate_command(self, command: str) -> Tuple[bool, Optional[str]]:
        """Validate command format"""
        command = command.upper().strip()
       
        # Determine command type
        if command.startswith('AT'):
            cmd_type = CommandType.AT
            cmd_part = command[2:]
        elif command.startswith('ST'):
            cmd_type = CommandType.ST
            cmd_part = command[2:]
        elif command.startswith('VT'):
            cmd_type = CommandType.VT
            cmd_part = command[2:]
        else:
            return False, "Command must start with AT, ST, or VT"
       
        # Check against patterns
        patterns = self.command_patterns.get(cmd_type, [])
        for pattern in patterns:
            if re.match(pattern, cmd_part):
                return True, None
       
        return False, f"Invalid {cmd_type.value} command format"
   
    def _send_command(self, command: str, cmd_type: CommandType,
                     timeout: Optional[float] = None) -> CommandResponse:
        """Internal method to send commands with validation and timing"""
        start_time = time.time()
       
        if not self.bt_manager.is_connected():
            return CommandResponse(command, "", False, "Not connected to device")
       
        # Use appropriate timeout
        if timeout is None:
            timeout = self.timeouts['default']
       
        try:
            # Validate command format
            is_valid, error = self.validate_command(command)
            if not is_valid:
                return CommandResponse(command, "", False, f"Validation error: {error}")
           
            # Send command
            response = self.bt_manager.send_command(command, timeout=timeout)
            execution_time = time.time() - start_time
           
            if response is None:
                return CommandResponse(command, "", False, "Command timeout", execution_time)
           
            # Check for error responses
            if self._is_error_response(response):
                return CommandResponse(command, response, False, f"Device error: {response}", execution_time)
           
            return CommandResponse(command, response, True, None, execution_time)
           
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Command execution error: {e}")
            return CommandResponse(command, "", False, str(e), execution_time)
   
    def _is_error_response(self, response: str) -> bool:
        """Check if response indicates an error"""
        error_indicators = [
            "?", "ERROR", "NO DATA", "CAN ERROR", "BUS ERROR",
            "DATA ERROR", "UNABLE TO CONNECT", "TIMEOUT"
        ]
        return any(indicator in response.upper() for indicator in error_indicators)
   
    def _get_at_patterns(self) -> List[str]:
        """Get AT command validation patterns"""
        return [
            r'^Z$',  # ATZ
            r'^I$',  # ATI
            r'^@1$',  # AT@1
            r'^E[01]$',  # ATE0/1
            r'^H[01]$',  # ATH0/1
            r'^L[01]$',  # ATL0/1
            r'^M[01]$',  # ATM0/1
            r'^RV$',  # ATRV
            r'^SP[0-9A-F]+$',  # ATSP
            r'^DP$',  # ATDP
            r'^DPN$',  # ATDPN
            r'^SH[0-9A-F]+$',  # ATSH
            r'^CF[0-9A-F]+$',  # ATCF
            r'^CM[0-9A-F]+$',  # ATCM
            r'^CRA[0-9A-F]*$',  # ATCRA
            r'^AT[0-2]$',  # ATAT0/1/2
            r'^ST[0-9A-F]{2}$',  # ATST
            r'^MA$',  # ATMA
            r'^CEA[0-9A-F]*$',  # ATCEA
        ]
   
    def _get_st_patterns(self) -> List[str]:
        """Get ST command validation patterns"""
        return [
            r'^I$',  # STI
            r'^DI$',  # STDI
            r'^MFR$',  # STMFR
            r'^SN$',  # STSN
            r'^P[0-9A-F]+$',  # STP
            r'^PR$',  # STPR
            r'^PRS$',  # STPRS
            r'^PBR[0-9]*$',  # STPBR
            r'^PBRR$',  # STPBRR
            r'^PC$',  # STPC
            r'^PO$',  # STPO
            r'^M$',  # STM
            r'^F[PB]A.*$',  # STFPA, STFBA
            r'^F[PB]C$',  # STFPC, STFBC
        ]
   
    def _get_vt_patterns(self) -> List[str]:
        """Get VT command validation patterns"""
        return [
            r'^I$',  # VTI
            r'^VERS$',  # VTVERS
            r'^PROI$',  # VTPROI
            r'^D$',  # VTD
            r'^P1[0-9A-F]+$',  # VTP1
            r'^P2[0-9A-F]+$',  # VTP2
            r'^PRON$',  # VTPRON
            r'^PROT$',  # VTPROT
            r'^PBR[0-9]*$',  # VTPBR
            r'^PBRD$',  # VTPBRD
            r'^UART_BUAD_SET.*$',  # VTUART_BUAD_SET
            r'^SHOW_BUS.*$',  # VTSHOW_BUS
            r'^POWERMANAGE$',  # VTPOWERMANAGE
            r'^VLRD$',  # VTVLRD
            r'^RD_MAC$',  # VTRD_MAC
            r'^RDSN$',  # VTRDSN
            r'^RD_UDS$',  # VTRD_UDS
            r'^SWGP.*$',  # VTSWGP
            r'^.*_PROTOCOL_ALL$',  # Protocol display commands
            r'^CFG_CAN.*$',  # VTCFG_CAN
            r'^SET_HD.*$',  # VTSET_HD
        ] 
