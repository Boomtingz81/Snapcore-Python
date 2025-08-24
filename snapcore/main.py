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

#!/usr/bin/env python3
"""
MIC3X2X OBD Bluetooth Interface - Main Application
Demonstrates complete usage of all system components
"""

import sys
import time
import signal
import logging
from typing import Dict, Any, Optional

# Import our MIC3X2X components
from bluetooth_manager import BluetoothManager
from command_handler import CommandHandler, CommandResponse
from protocol_manager import ProtocolManager, ProtocolFamily
from power_manager import PowerManager, PowerState
from config_manager import ConfigManager
from data_parser import DataParser, ParsedMessage
from periodic_message_manager import PeriodicMessageManager, MessageMode

class MIC3X2XApplication:
    """
    Main application class that orchestrates all MIC3X2X components
    """
   
    def __init__(self):
        self.logger = logging.getLogger(__name__)
       
        # Initialize components
        self.bt_manager = None
        self.cmd_handler = None
        self.protocol_manager = None
        self.power_manager = None
        self.config_manager = None
        self.data_parser = DataParser()
        self.periodic_manager = None
       
        # Application state
        self.connected = False
        self.running = False
       
        # Statistics
        self.stats = {
            'commands_sent': 0,
            'responses_received': 0,
            'errors': 0,
            'connection_time': None
        }
       
        # Setup signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
   
    def initialize(self) -> bool:
        """Initialize all components"""
        try:
            self.logger.info("Initializing MIC3X2X application...")
           
            # Initialize Bluetooth manager
            self.bt_manager = BluetoothManager()
            self.bt_manager.set_error_callback(self._handle_bluetooth_error)
            self.bt_manager.set_data_callback(self._handle_incoming_data)
           
            # Initialize command handler
            self.cmd_handler = CommandHandler(self.bt_manager)
           
            # Initialize other managers
            self.protocol_manager = ProtocolManager(self.cmd_handler)
            self.power_manager = PowerManager(self.cmd_handler)
            self.config_manager = ConfigManager(self.cmd_handler)
            self.periodic_manager = PeriodicMessageManager(self.cmd_handler)
           
            # Setup power management callbacks
            self.power_manager.set_voltage_callback(self._handle_voltage_reading)
            self.power_manager.set_state_change_callback(self._handle_power_state_change)
           
            # Setup periodic message callback
            self.periodic_manager.set_status_callback(self._handle_periodic_status)
           
            self.logger.info("Application initialized successfully")
            return True
           
        except Exception as e:
            self.logger.error(f"Failed to initialize application: {e}")
            return False
   
    def discover_and_connect(self, device_address: Optional[str] = None) -> bool:
        """Discover and connect to MIC3X2X device"""
        try:
            if not device_address:
                self.logger.info("Scanning for MIC3X2X devices...")
                devices = self.bt_manager.discover_devices(duration=15)
               
                if not devices:
                    self.logger.error("No Bluetooth devices found")
                    return False
               
                # Show discovered devices
                print("\nDiscovered Bluetooth devices:")
                for addr, name in devices.items():
                    print(f"  {addr} - {name}")
               
                # Use auto-selected device or prompt user
                if self.bt_manager.device_address:
                    device_address = self.bt_manager.device_address
                else:
                    print("\nNo MIC3X2X device auto-detected.")
                    device_address = input("Enter device address to connect: ").strip()
           
            # Connect to device
            self.logger.info(f"Connecting to {device_address}...")
            start_time = time.time()
           
            if self.bt_manager.connect(device_address):
                self.connected = True
                self.stats['connection_time'] = time.time() - start_time
                self.logger.info(f"Connected successfully in {self.stats['connection_time']:.2f} seconds")
                return True
            else:
                self.logger.error("Failed to connect to device")
                return False
               
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            return False
   
    def run_device_initialization(self) -> bool:
        """Initialize device with optimal settings"""
        try:
            self.logger.info("Initializing device settings...")
           
            # Get device information
            device_info = self.config_manager.get_device_info()
            print("\nDevice Information:")
            for key, value in device_info.items():
                print(f"  {key}: {value}")
           
            # Read current configuration
            self.logger.info("Reading device configuration...")
            self.config_manager.read_all_pp_parameters()
           
            # Setup optimal CAN settings
            self.config_manager.configure_can_settings(
                auto_formatting=True,
                flow_control=True,
                silent_monitoring=False
            )
           
            # Configure reasonable timeouts
            self.config_manager.configure_timeouts(
                obd_timeout=205,  # 5 seconds (205 * 4.096ms ≈ 5000ms)
                iso_p3_time=59    # ~59ms
            )
           
            # Setup power management for vehicle operation
            self.power_manager.optimize_for_vehicle_off()
           
            # Start voltage monitoring
            self.power_manager.start_voltage_monitoring(interval_seconds=10.0)
           
            self.logger.info("Device initialization completed")
            return True
           
        except Exception as e:
            self.logger.error(f"Device initialization failed: {e}")
            return False
   
    def run_protocol_detection(self) -> bool:
        """Detect and configure vehicle protocol"""
        try:
            self.logger.info("Detecting vehicle protocol...")
           
            # First, try to detect active protocol
            protocol_info = self.protocol_manager.auto_detect_protocol()
           
            if protocol_info:
                print(f"\nDetected Protocol: {protocol_info.name}")
                print(f"Description: {protocol_info.description}")
                print(f"Family: {protocol_info.family.value}")
               
                if protocol_info.baudrate:
                    print(f"Baud Rate: {protocol_info.baudrate}")
               
                # Get protocol capabilities
                capabilities = self.protocol_manager.get_protocol_capabilities(protocol_info)
                print("\nProtocol Capabilities:")
                for cap, enabled in capabilities.items():
                    print(f"  {cap}: {'Yes' if enabled else 'No'}")
               
                return True
            else:
                self.logger.warning("Protocol auto-detection failed")
               
                # Try manual protocol selection
                print("\nAvailable protocols:")
                protocols = self.protocol_manager.list_available_protocols()
               
                for pid, pinfo in list(protocols.items())[:10]:  # Show first 10
                    print(f"  {pid}: {pinfo.name} - {pinfo.description}")
               
                # Default to most common OBD protocol
                if self.protocol_manager.set_protocol_at(6):  # ISO 15765-4 CAN 11/500
                    self.logger.info("Set default CAN protocol")
                    return True
               
                return False
               
        except Exception as e:
            self.logger.error(f"Protocol detection failed: {e}")
            return False
   
    def run_obd_testing(self) -> bool:
        """Test OBD communication with common PIDs"""
        try:
            self.logger.info("Testing OBD communication...")
           
            # Test PIDs in order of importance
            test_pids = [
                ("0100", "Supported PIDs 01-20"),
                ("0101", "Monitor Status"),
                ("010C", "Engine RPM"),
                ("010D", "Vehicle Speed"),
                ("0105", "Engine Coolant Temperature"),
                ("0111", "Throttle Position")
            ]
           
            successful_tests = 0
            print("\nOBD Test Results:")
            print("-" * 50)
           
            for pid_request, description in test_pids:
                try:
                    response = self.cmd_handler.send_raw_command(pid_request, timeout=3.0)
                   
                    if response.success and response.response:
                        # Parse the response
                        parsed_messages = self.data_parser.parse_response(response.response)
                       
                        if parsed_messages:
                            obd_data = self.data_parser.extract_obd_data(parsed_messages)
                           
                            print(f"✓ {description}: {response.response}")
                           
                            # Show interpreted data if available
                            for param_name, param_data in obd_data.items():
                                print(f"    {param_name}: {param_data['value']} {param_data['units']}")
                           
                            successful_tests += 1
                        else:
                            print(f"✗ {description}: Parse failed")
                    else:
                        print(f"✗ {description}: {response.error or 'No response'}")
               
                except Exception as e:
                    print(f"✗ {description}: Error - {e}")
               
                time.sleep(0.5)  # Brief delay between tests
           
            success_rate = (successful_tests / len(test_pids)) * 100
            print(f"\nOBD Test Summary: {successful_tests}/{len(test_pids)} successful ({success_rate:.1f}%)")
           
            return successful_tests > 0
           
        except Exception as e:
            self.logger.error(f"OBD testing failed: {e}")
            return False
   
    def run_interactive_mode(self):
        """Run interactive command mode"""
        print("\n" + "="*60)
        print("MIC3X2X Interactive Mode")
        print("="*60)
        print("Available commands:")
        print("  help              - Show this help")
        print("  info              - Show device information")
        print("  voltage           - Read battery voltage")
        print("  protocols         - List available protocols")
        print("  status            - Show connection status")
        print("  test <pid>        - Test OBD PID (e.g., test 010C)")
        print("  raw <command>     - Send raw AT/ST/VT command")
        print("  keepalive on/off  - Enable/disable keep-alive messages")
        print("  save              - Save current configuration")
        print("  quit              - Exit application")
        print("-"*60)
       
        while self.running and self.connected:
            try:
                user_input = input("\nMIC3X2X> ").strip()
               
                if not user_input:
                    continue
               
                parts = user_input.split()
                command = parts[0].lower()
               
                if command == "quit" or command == "exit":
                    break
                elif command == "help":
                    self._show_help()
                elif command == "info":
                    self._show_device_info()
                elif command == "voltage":
                    self._show_voltage()
                elif command == "protocols":
                    self._show_protocols()
                elif command == "status":
                    self._show_status()
                elif command == "test" and len(parts) > 1:
                    self._test_pid(parts[1])
                elif command == "raw" and len(parts) > 1:
                    self._send_raw_command(" ".join(parts[1:]))
                elif command == "keepalive":
                    if len(parts) > 1:
                        self._configure_keepalive(parts[1].lower() == "on")
                    else:
                        print("Usage: keepalive on/off")
                elif command == "save":
                    self._save_configuration()
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
           
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Interactive mode error: {e}")
                print(f"Error: {e}")
   
    def cleanup(self):
        """Clean up resources"""
        try:
            self.logger.info("Cleaning up resources...")
           
            if self.periodic_manager:
                self.periodic_manager.stop_monitoring()
           
            if self.power_manager:
                self.power_manager.stop_voltage_monitoring()
           
            if self.bt_manager and self.connected:
                self.bt_manager.disconnect()
                self.connected = False
           
            self.logger.info("Cleanup completed")
           
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")
   
    def _signal_handler(self, signum, frame):
        """Handle system signals for graceful shutdown"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
   
    def _handle_bluetooth_error(self, error_message: str):
        """Handle Bluetooth errors"""
        self.logger.error(f"Bluetooth error: {error_message}")
        self.stats['errors'] += 1
   
    def _handle_incoming_data(self, data: str):
        """Handle incoming data from device"""
        self.stats['responses_received'] += 1
        # Data is already queued by BluetoothManager, just log if needed
        self.logger.debug(f"Received: {data}")
   
    def _handle_voltage_reading(self, voltage: float):
        """Handle voltage readings"""
        if voltage < 11.0:
            self.logger.warning(f"Low battery voltage: {voltage:.1f}V")
        elif voltage > 15.0:
            self.logger.warning(f"High voltage detected: {voltage:.1f}V")
   
    def _handle_power_state_change(self, new_state: PowerState):
        """Handle power state changes"""
        self.logger.info(f"Power state changed to: {new_state.value}")
   
    def _handle_periodic_status(self, status: Dict[str, int]):
        """Handle periodic message status"""
        total_active = sum(status.values())
        if total_active > 0:
            self.logger.debug(f"Periodic messages active: {total_active}")
   
    def _show_help(self):
        """Show detailed help"""
        print("\nDetailed Command Help:")
        print("  info     - Display device ID, version, voltage, protocol")
        print("  voltage  - Read current battery voltage")
        print("  test PID - Test specific OBD PID (hex format, e.g., 010C)")
        print("  raw CMD  - Send raw command (e.g., 'raw ATZ' or 'raw VTVERS')")
   
    def _show_device_info(self):
        """Show current device information"""
        try:
            device_info = self.cmd_handler.at_identify()
            voltage = self.cmd_handler.at_read_voltage()
            protocol = self.cmd_handler.at_describe_protocol()
           
            print(f"\nDevice: {device_info.response if device_info.success else 'Unknown'}")
            print(f"Voltage: {voltage.response if voltage.success else 'Unknown'}")
            print(f"Protocol: {protocol.response if protocol.success else 'Unknown'}")
        except Exception as e:
            print(f"Error getting device info: {e}")
   
    def _show_voltage(self):
        """Show battery voltage and health"""
        try:
            voltage = self.power_manager.read_voltage()
            if voltage:
                health = self.power_manager.get_battery_health_estimate()
                print(f"\nBattery Voltage: {voltage:.2f}V")
                print(f"Battery Health: {health['status']} ({health['percentage']}%)")
                print(f"Recommendation: {health['recommendation']}")
            else:
                print("Unable to read voltage")
        except Exception as e:
            print(f"Error reading voltage: {e}")
   
    def _show_protocols(self):
        """Show available protocols"""
        try:
            protocols = self.protocol_manager.list_available_protocols()
            print(f"\nAvailable Protocols ({len(protocols)} total):")
           
            for family in ProtocolFamily:
                family_protocols = [p for p in protocols.values() if p.family == family]
                if family_protocols:
                    print(f"\n{family.value}:")
                    for protocol in family_protocols[:5]:  # Show first 5 per family
                        print(f"  {protocol.protocol_id}: {protocol.name}")
        except Exception as e:
            print(f"Error listing protocols: {e}")
   
    def _show_status(self):
        """Show connection and system status"""
        print(f"\nConnection Status: {'Connected' if self.connected else 'Disconnected'}")
        print(f"Commands Sent: {self.stats['commands_sent']}")
        print(f"Responses Received: {self.stats['responses_received']}")
        print(f"Errors: {self.stats['errors']}")
       
        if self.stats['connection_time']:
            print(f"Connection Time: {self.stats['connection_time']:.2f}s")
   
    def _test_pid(self, pid: str):
        """Test specific OBD PID"""
        try:
            if len(pid) != 4 or not all(c in '0123456789ABCDEFabcdef' for c in pid):
                print("PID must be 4 hex characters (e.g., 010C)")
                return
           
            response = self.cmd_handler.send_raw_command(pid.upper())
            self.stats['commands_sent'] += 1
           
            if response.success:
                print(f"Response: {response.response}")
               
                # Try to parse and interpret
                parsed = self.data_parser.parse_response(response.response)
                obd_data = self.data_parser.extract_obd_data(parsed)
               
                for param_name, param_data in obd_data.items():
                    print(f"  {param_name}: {param_data['value']} {param_data['units']}")
            else:
                print(f"Error: {response.error}")
        except Exception as e:
            print(f"Test error: {e}")
   
    def _send_raw_command(self, command: str):
        """Send raw command"""
        try:
            response = self.cmd_handler.send_raw_command(command)
            self.stats['commands_sent'] += 1
           
            if response.success:
                print(f"Response: {response.response}")
            else:
                print(f"Error: {response.error}")
        except Exception as e:
            print(f"Command error: {e}")
   
    def _configure_keepalive(self, enable: bool):
        """Configure keep-alive messages"""
        try:
            if enable:
                success = self.periodic_manager.configure_obd_keepalive(True, 2000)
                print(f"Keep-alive {'enabled' if success else 'failed'}")
            else:
                success = self.periodic_manager.configure_obd_keepalive(False)
                print(f"Keep-alive {'disabled' if success else 'failed'}")
        except Exception as e:
            print(f"Keep-alive error: {e}")
   
    def _save_configuration(self):
        """Save current configuration"""
        try:
            if self.config_manager.save_configuration():
                print("Configuration saved successfully")
            else:
                print("Failed to save configuration")
        except Exception as e:
            print(f"Save error: {e}")

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('mic3x2x.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Main application entry point"""
    print("MIC3X2X OBD Bluetooth Interface v1.0")
    print("====================================")
   
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
   
    # Create and initialize application
    app = MIC3X2XApplication()
   
    try:
        # Initialize application
        if not app.initialize():
            print("Failed to initialize application")
            return 1
       
        # Discover and connect to device
        if not app.discover_and_connect():
            print("Failed to connect to device")
            return 1
       
        app.running = True
       
        # Initialize device
        if not app.run_device_initialization():
            print("Device initialization failed")
            return 1
       
        # Detect protocol
        if not app.run_protocol_detection():
            print("Warning: Protocol detection failed, continuing anyway...")
       
        # Test OBD communication
        if not app.run_obd_testing():
            print("Warning: OBD testing failed, continuing anyway...")
       
        # Run interactive mode
        app.run_interactive_mode()
       
        print("\nApplication terminated by user")
        return 0
       
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Application error: {e}")
        print(f"Application error: {e}")
        return 1
    finally:
        app.cleanup()

if __name__ == "__main__":
    sys.exit(main()) 
