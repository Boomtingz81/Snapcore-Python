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

import bluetooth
import threading
import time
import queue
from typing import Optional, Callable, Dict, Any
import logging

class BluetoothManager:
    """
    Bluetooth connection manager for MIC3X2X OBD adapter
    Handles connection, communication, and command processing
    """
   
    def __init__(self, device_address: Optional[str] = None, device_name: str = "MIC3X2X"):
        self.device_address = device_address
        self.device_name = device_name
        self.socket: Optional[bluetooth.BluetoothSocket] = None
        self.connected = False
        self.receiving = False
       
        # Communication queues
        self.command_queue = queue.Queue()
        self.response_queue = queue.Queue()
       
        # Threading
        self.receive_thread: Optional[threading.Thread] = None
        self.command_thread: Optional[threading.Thread] = None
       
        # Callbacks
        self.data_callback: Optional[Callable] = None
        self.error_callback: Optional[Callable] = None
       
        # Default settings from MIC3X2X datasheet
        self.default_baudrate = 115200
        self.command_timeout = 5.0  # seconds
        self.max_retries = 3
       
        # Setup logging
        self.logger = logging.getLogger(__name__)
       
    def discover_devices(self, duration: int = 10) -> Dict[str, str]:
        """
        Discover nearby Bluetooth devices
        Returns dict of {address: name}
        """
        self.logger.info(f"Scanning for Bluetooth devices for {duration} seconds...")
       
        devices = {}
        try:
            nearby_devices = bluetooth.discover_devices(
                duration=duration,
                lookup_names=True,
                flush_cache=True
            )
           
            for addr, name in nearby_devices:
                devices[addr] = name
                self.logger.info(f"Found device: {name} ({addr})")
               
                # Auto-select MIC3X2X device if found
                if self.device_name.lower() in name.lower() or "mic3" in name.lower():
                    self.device_address = addr
                    self.logger.info(f"Auto-selected MIC3X2X device: {name} ({addr})")
                   
        except Exception as e:
            self.logger.error(f"Error during device discovery: {e}")
            if self.error_callback:
                self.error_callback(f"Discovery error: {e}")
               
        return devices
   
    def connect(self, address: Optional[str] = None) -> bool:
        """
        Connect to MIC3X2X Bluetooth device
        """
        if address:
            self.device_address = address
           
        if not self.device_address:
            self.logger.error("No device address specified")
            return False
           
        try:
            self.logger.info(f"Connecting to {self.device_address}...")
           
            # Create Bluetooth socket
            self.socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
           
            # Connect with timeout
            self.socket.settimeout(10.0)
            self.socket.connect((self.device_address, 1))  # RFCOMM port 1
            self.socket.settimeout(None)
           
            self.connected = True
            self.logger.info("Connected successfully")
           
            # Start communication threads
            self._start_threads()
           
            # Send initial setup commands
            self._initialize_device()
           
            return True
           
        except bluetooth.BluetoothError as e:
            self.logger.error(f"Bluetooth connection error: {e}")
            if self.error_callback:
                self.error_callback(f"Connection error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected connection error: {e}")
            if self.error_callback:
                self.error_callback(f"Connection error: {e}")
            return False
   
    def disconnect(self):
        """
        Disconnect from the device and cleanup
        """
        self.logger.info("Disconnecting...")
       
        self.connected = False
        self.receiving = False
       
        # Stop threads
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=2.0)
           
        if self.command_thread and self.command_thread.is_alive():
            self.command_thread.join(timeout=2.0)
       
        # Close socket
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                self.logger.error(f"Error closing socket: {e}")
            finally:
                self.socket = None
               
        self.logger.info("Disconnected")
   
    def send_command(self, command: str, wait_response: bool = True, timeout: float = None) -> Optional[str]:
        """
        Send AT/ST/VT command to MIC3X2X device
        """
        if not self.connected or not self.socket:
            self.logger.error("Not connected to device")
            return None
           
        timeout = timeout or self.command_timeout
       
        try:
            # Format command (ensure it ends with \r)
            if not command.endswith('\r'):
                command += '\r'
               
            self.logger.debug(f"Sending command: {command.strip()}")
           
            # Send command
            self.socket.send(command.encode('utf-8'))
           
            if not wait_response:
                return None
               
            # Wait for response
            try:
                response = self.response_queue.get(timeout=timeout)
                self.logger.debug(f"Received response: {response}")
                return response
            except queue.Empty:
                self.logger.warning(f"Command timeout: {command.strip()}")
                return None
               
        except Exception as e:
            self.logger.error(f"Error sending command: {e}")
            if self.error_callback:
                self.error_callback(f"Send error: {e}")
            return None
   
    def send_obd_request(self, pid: str, mode: str = "01") -> Optional[str]:
        """
        Send OBD-II request and get response
        """
        command = f"{mode}{pid}"
        return self.send_command(command)
   
    def _start_threads(self):
        """
        Start communication threads
        """
        self.receiving = True
       
        # Start receive thread
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()
       
        # Start command processing thread
        self.command_thread = threading.Thread(target=self._command_loop, daemon=True)
        self.command_thread.start()
   
    def _receive_loop(self):
        """
        Continuously receive data from device
        """
        buffer = ""
       
        while self.receiving and self.connected:
            try:
                data = self.socket.recv(1024).decode('utf-8')
                if not data:
                    break
                   
                buffer += data
               
                # Process complete lines
                while '\r' in buffer:
                    line, buffer = buffer.split('\r', 1)
                    line = line.strip()
                   
                    if line:
                        self.logger.debug(f"Received: {line}")
                       
                        # Put response in queue
                        try:
                            self.response_queue.put(line, timeout=1.0)
                        except queue.Full:
                            self.logger.warning("Response queue full, dropping message")
                       
                        # Call data callback if set
                        if self.data_callback:
                            try:
                                self.data_callback(line)
                            except Exception as e:
                                self.logger.error(f"Error in data callback: {e}")
                               
            except bluetooth.BluetoothError as e:
                if self.receiving:  # Only log if we're still supposed to be receiving
                    self.logger.error(f"Bluetooth receive error: {e}")
                    if self.error_callback:
                        self.error_callback(f"Receive error: {e}")
                break
            except Exception as e:
                if self.receiving:
                    self.logger.error(f"Unexpected receive error: {e}")
                break
               
        self.logger.info("Receive loop ended")
   
    def _command_loop(self):
        """
        Process queued commands
        """
        while self.connected:
            try:
                # Get command from queue (blocking with timeout)
                command_data = self.command_queue.get(timeout=1.0)
               
                if command_data is None:  # Shutdown signal
                    break
                   
                # Process command
                # This is where you'd add command-specific processing
                # For now, just log
                self.logger.debug(f"Processing command: {command_data}")
               
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in command loop: {e}")
               
        self.logger.info("Command loop ended")
   
    def _initialize_device(self):
        """
        Initialize MIC3X2X device with default settings
        """
        self.logger.info("Initializing device...")
       
        # Reset device
        self.send_command("ATZ", wait_response=True, timeout=3.0)
        time.sleep(1.0)
       
        # Get device info
        device_info = self.send_command("ATI")
        if device_info:
            self.logger.info(f"Device info: {device_info}")
       
        # Set echo off for cleaner communication
        self.send_command("ATE0")
       
        # Enable headers for better data parsing
        self.send_command("ATH1")
       
        # Set adaptive timing mode
        self.send_command("ATAT1")
       
        self.logger.info("Device initialized")
   
    def get_device_info(self) -> Dict[str, Any]:
        """
        Get comprehensive device information
        """
        info = {}
       
        # Basic device info
        info['device_id'] = self.send_command("ATI")
        info['device_description'] = self.send_command("AT@1")
        info['voltage'] = self.send_command("ATRV")
       
        # VT commands for MIC3X2X specific info
        info['vt_version'] = self.send_command("VTVERS")
        info['vt_device'] = self.send_command("VTI")
        info['vt_manufacturer'] = self.send_command("VTPROI")
       
        # Current protocol
        info['protocol'] = self.send_command("ATDP")
        info['protocol_number'] = self.send_command("ATDPN")
       
        return {k: v for k, v in info.items() if v is not None}
   
    def set_data_callback(self, callback: Callable[[str], None]):
        """
        Set callback function for received data
        """
        self.data_callback = callback
   
    def set_error_callback(self, callback: Callable[[str], None]):
        """
        Set callback function for errors
        """
        self.error_callback = callback
   
    def is_connected(self) -> bool:
        """
        Check if device is connected
        """
        return self.connected and self.socket is not None
   
    def __enter__(self):
        """
        Context manager entry
        """
        return self
   
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit
        """
        self.disconnect() 
