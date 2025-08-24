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
from typing import Dict, List, Optional, Union, Callable
import threading
import time
import logging

class SleepTrigger(Enum):
    """Sleep triggers supported by MIC3X2X"""
    UART_SILENCE = "UART"
    OBD_SILENCE = "OBD" 
    LOW_VOLTAGE = "VOLTAGE"
    IGN_PIN = "IGN"
    MANUAL = "MANUAL"

class WakeTrigger(Enum):
    """Wake triggers supported by MIC3X2X"""
    UART_ACTIVE = "UART"
    OBD_ACTIVE = "OBD"
    VOLTAGE_DROP = "VOL_DEEP_DROP"
    IGN_PIN = "IGN"
    EXTERNAL = "EXTERNAL"

class PowerState(Enum):
    """Device power states"""
    ACTIVE = "ACTIVE"
    LOW_POWER = "LOW_POWER"
    SLEEP = "SLEEP"
    WAKE_PENDING = "WAKE_PENDING"
    UNKNOWN = "UNKNOWN"

@dataclass
class PowerConfiguration:
    """Power management configuration"""
    # Sleep triggers
    uart_sleep_enabled: bool = False
    obd_sleep_enabled: bool = False
    voltage_sleep_enabled: bool = False
    ign_sleep_enabled: bool = False
   
    # Wake triggers 
    uart_wake_enabled: bool = False
    obd_wake_enabled: bool = True
    voltage_wake_enabled: bool = False
    ign_wake_enabled: bool = False
   
    # Voltage thresholds (volts)
    sleep_voltage_threshold: float = 0.0
    sleep_voltage_duration: int = 0  # seconds
    wake_voltage_drop: float = 4.0
    wake_voltage_duration: int = 20  # milliseconds
   
    # Timing parameters
    uart_idle_timeout: int = 0  # seconds (0 = disabled)
    obd_idle_timeout: int = 0   # seconds (0 = disabled)
   
@dataclass
class PowerStatus:
    """Current power management status"""
    current_state: PowerState = PowerState.UNKNOWN
    last_sleep_trigger: Optional[SleepTrigger] = None
    last_wake_trigger: Optional[WakeTrigger] = None
    voltage_reading: Optional[float] = None
    sleep_count: int = 0
    wake_count: int = 0
    last_state_change: Optional[float] = None
    sleep_duration: Optional[float] = None

class PowerManager:
    """
    Power management for MIC3X2X device
    Based on datasheet power control features and PP area settings
    """
   
    def __init__(self, command_handler):
        self.cmd_handler = command_handler
        self.logger = logging.getLogger(__name__)
       
        # Current configuration and status
        self.config = PowerConfiguration()
        self.status = PowerStatus()
       
        # Monitoring
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.voltage_callback: Optional[Callable] = None
        self.state_change_callback: Optional[Callable] = None
       
        # Constants from datasheet
        self.SLEEP_CURRENT_MA = 3  # Less than 3mA in sleep
        self.WAKE_PULSE_DURATION_MS = 3  # Minimum 3ms wake pulse
        self.IGN_DEBOUNCE_TIME_MS = 65  # Ignition debounce time
       
    def get_power_status(self) -> PowerStatus:
        """Get current power management status from device"""
        self.logger.debug("Reading power management status")
       
        response = self.cmd_handler.vt_power_manage()
        if response.success:
            self._parse_power_status(response.response)
        else:
            self.logger.error(f"Failed to read power status: {response.error}")
           
        return self.status
   
    def read_voltage(self) -> Optional[float]:
        """Read current battery voltage"""
        response = self.cmd_handler.at_read_voltage()
        if response.success:
            try:
                # Parse voltage from response (typically "12.1V")
                voltage_str = response.response.replace('V', '').strip()
                voltage = float(voltage_str)
                self.status.voltage_reading = voltage
                return voltage
            except ValueError:
                self.logger.error(f"Invalid voltage response: {response.response}")
       
        return None
   
    def configure_sleep_voltage(self, threshold_volts: float, duration_seconds: int) -> bool:
        """Configure voltage-based sleep trigger (VTPDVS command)"""
        self.logger.info(f"Configuring sleep voltage: {threshold_volts}V for {duration_seconds}s")
       
        response = self.cmd_handler.send_raw_command(
            f"VTPDVS{threshold_volts},{duration_seconds}"
        )
       
        if response.success:
            self.config.voltage_sleep_enabled = True
            self.config.sleep_voltage_threshold = threshold_volts
            self.config.sleep_voltage_duration = duration_seconds
            return True
       
        self.logger.error(f"Failed to configure sleep voltage: {response.error}")
        return False
   
    def configure_wake_voltage(self, drop_volts: float, duration_ms: int) -> bool:
        """Configure voltage drop wake trigger (VTVDWK command)"""
        self.logger.info(f"Configuring wake voltage drop: {drop_volts}V for {duration_ms}ms")
       
        response = self.cmd_handler.send_raw_command(
            f"VTVDWK{drop_volts},{duration_ms}"
        )
       
        if response.success:
            self.config.voltage_wake_enabled = True
            self.config.wake_voltage_drop = drop_volts
            self.config.wake_voltage_duration = duration_ms
            return True
       
        self.logger.error(f"Failed to configure wake voltage: {response.error}")
        return False
   
    def configure_voltage_change_wake(self, voltage_change: float,
                                    sample_interval_ms: int,
                                    rising: bool = True) -> bool:
        """Configure voltage change wake trigger (VTVLCW command)"""
        direction = "+" if rising else "-"
        self.logger.info(f"Configuring voltage change wake: {direction}{voltage_change}V")
       
        response = self.cmd_handler.send_raw_command(
            f"VTVLCW{direction}{voltage_change},{sample_interval_ms}"
        )
       
        return response.success
   
    def enter_low_power_mode(self) -> bool:
        """Manually enter low power mode"""
        self.logger.info("Entering low power mode")
       
        response = self.cmd_handler.send_raw_command("ATLP")
       
        if response.success:
            self.status.current_state = PowerState.LOW_POWER
            self.status.last_state_change = time.time()
            self.status.sleep_count += 1
           
            if self.state_change_callback:
                self.state_change_callback(PowerState.LOW_POWER)
           
            return True
       
        return False
   
    def wake_device(self) -> bool:
        """Wake device from low power mode"""
        self.logger.info("Attempting to wake device")
       
        # Try sending a simple command to wake
        response = self.cmd_handler.send_raw_command("ATI", timeout=2.0)
       
        if response.success:
            self.status.current_state = PowerState.ACTIVE
            self.status.last_state_change = time.time()
            self.status.wake_count += 1
           
            if self.state_change_callback:
                self.state_change_callback(PowerState.ACTIVE)
           
            return True
       
        return False
   
    def start_voltage_monitoring(self, interval_seconds: float = 5.0) -> bool:
        """Start continuous voltage monitoring"""
        if self.monitoring_active:
            self.logger.warning("Voltage monitoring already active")
            return False
       
        self.logger.info(f"Starting voltage monitoring (interval: {interval_seconds}s)")
        self.monitoring_active = True
       
        self.monitor_thread = threading.Thread(
            target=self._voltage_monitor_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self.monitor_thread.start()
       
        return True
   
    def stop_voltage_monitoring(self):
        """Stop voltage monitoring"""
        if not self.monitoring_active:
            return
       
        self.logger.info("Stopping voltage monitoring")
        self.monitoring_active = False
       
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)
   
    def get_battery_health_estimate(self) -> Dict[str, any]:
        """Estimate battery health based on voltage readings"""
        voltage = self.read_voltage()
        if voltage is None:
            return {"status": "unknown", "error": "Cannot read voltage"}
       
        # Basic battery health assessment
        if voltage >= 12.6:
            status = "excellent"
            percentage = 100
        elif voltage >= 12.4:
            status = "good" 
            percentage = 75
        elif voltage >= 12.2:
            status = "fair"
            percentage = 50
        elif voltage >= 12.0:
            status = "poor"
            percentage = 25
        elif voltage >= 11.8:
            status = "critical"
            percentage = 10
        else:
            status = "failing"
            percentage = 0
       
        return {
            "voltage": voltage,
            "status": status,
            "percentage": percentage,
            "recommendation": self._get_battery_recommendation(voltage)
        }
   
    def configure_programmable_parameters(self, pp_settings: Dict[str, int]) -> bool:
        """Configure power-related programmable parameters"""
        success = True
       
        for pp_address, value in pp_settings.items():
            try:
                # Convert hex address if needed
                if isinstance(pp_address, str):
                    addr = int(pp_address, 16)
                else:
                    addr = pp_address
               
                response = self.cmd_handler.send_raw_command(
                    f"ATPP{addr:02X}SV{value:02X}"
                )
               
                if not response.success:
                    self.logger.error(f"Failed to set PP {addr:02X}: {response.error}")
                    success = False
                   
            except ValueError as e:
                self.logger.error(f"Invalid PP parameter: {pp_address}, {value}")
                success = False
       
        return success
   
    def get_power_consumption_estimate(self) -> Dict[str, float]:
        """Estimate current power consumption"""
        voltage = self.read_voltage()
       
        # These are estimates based on datasheet specifications
        consumption = {
            "active_current_ma": 34,  # Typical active current from datasheet
            "sleep_current_ma": 3,    # Maximum sleep current
            "active_power_mw": 0,
            "sleep_power_mw": 0
        }
       
        if voltage:
            consumption["active_power_mw"] = voltage * consumption["active_current_ma"]
            consumption["sleep_power_mw"] = voltage * consumption["sleep_current_ma"]
       
        return consumption
   
    def optimize_for_vehicle_off(self) -> bool:
        """Optimize settings for when vehicle is turned off"""
        self.logger.info("Optimizing for vehicle-off condition")
       
        success = True
       
        # Configure low voltage sleep (typical car battery at rest)
        success &= self.configure_sleep_voltage(11.8, 300)  # 11.8V for 5 minutes
       
        # Configure voltage drop wake (engine start)
        success &= self.configure_wake_voltage(2.5, 50)  # 2.5V drop for 50ms
       
        # Enable OBD bus wake
        self.config.obd_wake_enabled = True
       
        return success
   
    def set_voltage_callback(self, callback: Callable[[float], None]):
        """Set callback for voltage readings"""
        self.voltage_callback = callback
   
    def set_state_change_callback(self, callback: Callable[[PowerState], None]):
        """Set callback for power state changes""" 
        self.state_change_callback = callback
   
    def _voltage_monitor_loop(self, interval: float):
        """Voltage monitoring loop"""
        while self.monitoring_active:
            try:
                voltage = self.read_voltage()
                if voltage and self.voltage_callback:
                    self.voltage_callback(voltage)
               
                # Check for critical voltage
                if voltage and voltage < 10.0:
                    self.logger.warning(f"Critical battery voltage: {voltage}V")
                   
                time.sleep(interval)
               
            except Exception as e:
                self.logger.error(f"Error in voltage monitoring: {e}")
                time.sleep(interval)
   
    def _parse_power_status(self, status_response: str):
        """Parse VTPOWERMANAGE response"""
        try:
            lines = status_response.strip().split('\n')
            current_section = None
           
            for line in lines:
                line = line.strip()
               
                if line.startswith("SLEEP:"):
                    current_section = "sleep"
                elif line.startswith("WAKE:"):
                    current_section = "wake"
                elif current_section == "sleep":
                    self._parse_sleep_config(line)
                elif current_section == "wake":
                    self._parse_wake_config(line)
                   
        except Exception as e:
            self.logger.error(f"Error parsing power status: {e}")
   
    def _parse_sleep_config(self, line: str):
        """Parse sleep configuration line"""
        if "UART" in line:
            self.config.uart_sleep_enabled = "ON" in line
        elif "OBD" in line:
            self.config.obd_sleep_enabled = "ON" in line
        elif "VOLTAGE" in line and "(" in line:
            # Extract voltage value: "VOLTAGE (12.5V)"
            try:
                voltage_str = line.split("(")[1].split("V")[0]
                self.config.sleep_voltage_threshold = float(voltage_str)
                self.config.voltage_sleep_enabled = True
            except (IndexError, ValueError):
                pass
        elif "IGN" in line:
            self.config.ign_sleep_enabled = "ON" in line
   
    def _parse_wake_config(self, line: str):
        """Parse wake configuration line"""
        if "UART" in line:
            self.config.uart_wake_enabled = "ON" in line
        elif "OBD" in line:
            self.config.obd_wake_enabled = "ON" in line 
        elif "VOL DEEP DROP" in line and "(" in line:
            # Extract voltage: "VOL DEEP DROP (4.0V)"
            try:
                voltage_str = line.split("(")[1].split("V")[0]
                self.config.wake_voltage_drop = float(voltage_str)
                self.config.voltage_wake_enabled = True
            except (IndexError, ValueError):
                pass
        elif "IGN" in line:
            self.config.ign_wake_enabled = "ON" in line
   
    def _get_battery_recommendation(self, voltage: float) -> str:
        """Get battery health recommendation"""
        if voltage >= 12.6:
            return "Battery is in excellent condition"
        elif voltage >= 12.4:
            return "Battery is in good condition"
        elif voltage >= 12.2:
            return "Battery is fair - monitor condition"
        elif voltage >= 12.0:
            return "Battery is poor - consider testing"
        elif voltage >= 11.8:
            return "Battery is critical - replacement recommended"
        else:
            return "Battery is failing - immediate replacement required"
   
    def __enter__(self):
        """Context manager entry"""
        return self
   
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_voltage_monitoring()
 
