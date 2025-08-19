import serial
import time
from vlinker_commands import commands

class VLinkerInterface:
    def __init__(self, port="COM5", baudrate=115200, timeout=1.0):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser = None

    def connect(self):
        """Open serial connection to VLinker MS."""
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
            print(f"✅ Connected to {self.port} at {self.baudrate} baud.")
        except serial.SerialException as e:
            print(f"❌ Serial error: {e}")

    def disconnect(self):
        """Close serial connection."""
        if self.ser and self.ser.is_open:
            self.ser.close()
            print("🔌 Disconnected.")

    def send_command(self, cmd, delay=0.3):
        """Send command string to VLinker MS and return response lines."""
        if not self.ser or not self.ser.is_open:
            print("❌ Not connected.")
            return []
        
        # Send with CR
        self.ser.write((cmd + "\r").encode())
        time.sleep(delay)
        
        # Read available lines
        lines = []
        while self.ser.in_waiting:
            line = self.ser.readline().decode(errors="ignore").strip()
            if line and not line.startswith(">"):
                lines.append(line)
        return lines

    def list_commands(self):
        """Print all available commands from vlinker_commands.py."""
        for cmd in commands:
            print(f"[{cmd['index']}] {cmd['command']} - {cmd['description']}")

    def get_command_by_index(self, index):
        """Return command dictionary by index number."""
        for cmd in commands:
            if cmd['index'] == index:
                return cmd
        return None
