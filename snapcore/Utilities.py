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

MIC3X2X Utilities Module

Common utilities, helpers, and support functions for MIC3X2X operations.
Includes data conversion, validation, formatting, mathematical calculations,
and other utility functions used across the application.

Features:
- Data format conversion and validation
- Mathematical calculations for OBD parameters
- String formatting and parsing utilities
- File I/O helpers
- Network and system utilities
- Diagnostic data analysis helpers
"""

import re
import math
import struct
import binascii
import hashlib
import zlib
import base64
import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import ipaddress
import socket
import platform
import subprocess
import threading
import time


class DataFormat(Enum):
    """Supported data formats"""
    HEX = "hex"
    BINARY = "binary"
    DECIMAL = "decimal"
    ASCII = "ascii"
    JSON = "json"
    XML = "xml"
    CSV = "csv"


class ByteOrder(Enum):
    """Byte order for multi-byte values"""
    BIG_ENDIAN = "big"
    LITTLE_ENDIAN = "little"


@dataclass
class ConversionResult:
    """Result of data conversion operation"""
    success: bool
    data: Any
    original_format: str
    target_format: str
    error_message: Optional[str] = None


class DataConverter:
    """Data format conversion utilities"""
   
    @staticmethod
    def hex_to_bytes(hex_string: str) -> bytes:
        """Convert hex string to bytes"""
        # Remove spaces, colons, and other separators
        clean_hex = re.sub(r'[^0-9A-Fa-f]', '', hex_string)
       
        # Ensure even length
        if len(clean_hex) % 2:
            clean_hex = '0' + clean_hex
           
        return bytes.fromhex(clean_hex)
   
    @staticmethod
    def bytes_to_hex(data: bytes, separator: str = ' ', uppercase: bool = True) -> str:
        """Convert bytes to hex string"""
        hex_str = data.hex()
        if uppercase:
            hex_str = hex_str.upper()
       
        if separator:
            # Insert separator every 2 characters
            return separator.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
       
        return hex_str
   
    @staticmethod
    def int_to_bytes(value: int, length: int, byte_order: ByteOrder = ByteOrder.BIG_ENDIAN) -> bytes:
        """Convert integer to bytes with specified length and byte order"""
        return value.to_bytes(length, byte_order.value)
   
    @staticmethod
    def bytes_to_int(data: bytes, byte_order: ByteOrder = ByteOrder.BIG_ENDIAN) -> int:
        """Convert bytes to integer"""
        return int.from_bytes(data, byte_order.value)
   
    @staticmethod
    def ascii_to_bytes(text: str) -> bytes:
        """Convert ASCII text to bytes"""
        return text.encode('ascii', errors='ignore')
   
    @staticmethod
    def bytes_to_ascii(data: bytes) -> str:
        """Convert bytes to ASCII text"""
        return data.decode('ascii', errors='ignore')
   
    @staticmethod
    def obd_response_to_dict(response_line: str) -> Dict[str, Any]:
        """Convert OBD response line to structured dictionary"""
        parts = response_line.strip().split()
       
        if len(parts) < 2:
            return {'error': 'Invalid response format'}
       
        try:
            result = {
                'header': parts[0] if len(parts[0]) in [3, 8] else None,
                'length': int(parts[1], 16) if len(parts) > 1 else None,
                'data': [int(p, 16) for p in parts[2:]] if len(parts) > 2 else []
            }
           
            # Detect if first part is CAN ID
            if len(parts[0]) in [3, 8]:
                result['can_id'] = int(parts[0], 16)
                result['is_can'] = True
            else:
                result['is_can'] = False
                result['data'] = [int(p, 16) for p in parts]
           
            return result
           
        except ValueError as e:
            return {'error': f'Parse error: {e}'}
   
    @staticmethod
    def format_vin(vin_bytes: List[int]) -> str:
        """Format VIN from byte array"""
        if len(vin_bytes) < 17:
            return "Invalid VIN"
       
        # VIN is ASCII encoded
        vin_chars = [chr(b) for b in vin_bytes[:17] if 32 <= b <= 126]
        return ''.join(vin_chars)
   
    @staticmethod
    def checksum_8bit(data: List[int]) -> int:
        """Calculate 8-bit checksum"""
        return sum(data) & 0xFF
   
    @staticmethod
    def checksum_complement(data: List[int]) -> int:
        """Calculate two's complement checksum"""
        return (256 - (sum(data) & 0xFF)) & 0xFF
   
    @staticmethod
    def crc16(data: bytes, polynomial: int = 0x1021) -> int:
        """Calculate CRC-16 checksum"""
        crc = 0xFFFF
       
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ polynomial
                else:
                    crc <<= 1
                crc &= 0xFFFF
       
        return crc


class OBDCalculator:
    """OBD parameter calculation utilities"""
   
    @staticmethod
    def engine_load(raw_value: int) -> float:
        """Calculate engine load percentage from raw value"""
        return (raw_value * 100.0) / 255.0
   
    @staticmethod
    def coolant_temperature(raw_value: int) -> float:
        """Calculate coolant temperature in Celsius"""
        return raw_value - 40.0
   
    @staticmethod
    def engine_rpm(raw_bytes: List[int]) -> float:
        """Calculate engine RPM from two bytes"""
        if len(raw_bytes) < 2:
            return 0.0
        return ((raw_bytes[0] * 256.0) + raw_bytes[1]) / 4.0
   
    @staticmethod
    def vehicle_speed(raw_value: int) -> float:
        """Calculate vehicle speed in km/h"""
        return float(raw_value)
   
    @staticmethod
    def timing_advance(raw_value: int) -> float:
        """Calculate timing advance in degrees before TDC"""
        return (raw_value - 128.0) / 2.0
   
    @staticmethod
    def maf_flow_rate(raw_bytes: List[int]) -> float:
        """Calculate MAF air flow rate in g/s"""
        if len(raw_bytes) < 2:
            return 0.0
        return ((raw_bytes[0] * 256.0) + raw_bytes[1]) / 100.0
   
    @staticmethod
    def throttle_position(raw_value: int) -> float:
        """Calculate throttle position percentage"""
        return (raw_value * 100.0) / 255.0
   
    @staticmethod
    def fuel_trim(raw_value: int) -> float:
        """Calculate fuel trim percentage"""
        return ((raw_value - 128.0) * 100.0) / 128.0
   
    @staticmethod
    def fuel_pressure(raw_value: int) -> float:
        """Calculate fuel pressure in kPa"""
        return raw_value * 3.0
   
    @staticmethod
    def intake_pressure(raw_value: int) -> float:
        """Calculate intake manifold pressure in kPa"""
        return float(raw_value)
   
    @staticmethod
    def oxygen_sensor_voltage(raw_bytes: List[int]) -> Tuple[float, float]:
        """Calculate oxygen sensor voltage and fuel trim"""
        if len(raw_bytes) < 2:
            return 0.0, 0.0
       
        voltage = raw_bytes[0] / 200.0  # Convert to volts
        fuel_trim = ((raw_bytes[1] - 128.0) * 100.0) / 128.0
       
        return voltage, fuel_trim
   
    @staticmethod
    def calculate_fuel_economy(speed_kmh: float, maf_gps: float) -> Optional[float]:
        """Calculate approximate fuel economy in MPG"""
        if speed_kmh <= 0 or maf_gps <= 0:
            return None
       
        # Simplified calculation: MPG ≈ (Speed * 7.107) / MAF
        # This is an approximation and actual calculation may vary
        mpg = (speed_kmh * 7.107) / maf_gps
        return max(0, mpg)  # Ensure non-negative result
   
    @staticmethod
    def calculate_horsepower(maf_gps: float, efficiency: float = 0.85) -> float:
        """Calculate approximate horsepower from MAF"""
        # Simplified calculation: HP ≈ (MAF * efficiency) / 0.5
        return (maf_gps * efficiency) / 0.5


class StringFormatter:
    """String formatting utilities"""
   
    @staticmethod
    def format_hex_dump(data: bytes, width: int = 16) -> str:
        """Format data as hex dump with ASCII representation"""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
           
            # Format hex bytes
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            hex_part = hex_part.ljust(width * 3 - 1)  # Pad to fixed width
           
            # Format ASCII representation
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
           
            lines.append(f'{i:08X}  {hex_part}  |{ascii_part}|')
       
        return '\n'.join(lines)
   
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 1:
            return f"{seconds*1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
   
    @staticmethod
    def format_byte_size(bytes_count: int) -> str:
        """Format byte count in human-readable format"""
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        size = float(bytes_count)
        unit_index = 0
       
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
       
        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        else:
            return f"{size:.1f} {units[unit_index]}"
   
    @staticmethod
    def format_table(headers: List[str], rows: List[List[str]],
                    alignment: List[str] = None) -> str:
        """Format data as ASCII table"""
        if not headers or not rows:
            return ""
       
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
       
        # Default alignment
        if alignment is None:
            alignment = ['left'] * len(headers)
       
        # Format rows
        formatted_rows = []
       
        # Header
        header_row = []
        separator_row = []
        for i, (header, width, align) in enumerate(zip(headers, col_widths, alignment)):
            if align == 'center':
                formatted_header = header.center(width)
            elif align == 'right':
                formatted_header = header.rjust(width)
            else:
                formatted_header = header.ljust(width)
           
            header_row.append(formatted_header)
            separator_row.append('-' * width)
       
        formatted_rows.append('| ' + ' | '.join(header_row) + ' |')
        formatted_rows.append('|-' + '-|-'.join(separator_row) + '-|')
       
        # Data rows
        for row in rows:
            formatted_row = []
            for i, (cell, width, align) in enumerate(zip(row, col_widths, alignment)):
                cell_str = str(cell)
                if align == 'center':
                    formatted_cell = cell_str.center(width)
                elif align == 'right':
                    formatted_cell = cell_str.rjust(width)
                else:
                    formatted_cell = cell_str.ljust(width)
               
                formatted_row.append(formatted_cell)
           
            formatted_rows.append('| ' + ' | '.join(formatted_row) + ' |')
       
        return '\n'.join(formatted_rows)
   
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for filesystem compatibility"""
        # Remove or replace invalid characters
        invalid_chars = r'<>:"/\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
       
        # Remove control characters
        filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)
       
        # Trim whitespace and dots
        filename = filename.strip(' .')
       
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
       
        return filename or 'untitled'


class FileUtils:
    """File I/O utility functions"""
   
    @staticmethod
    def read_json_safe(file_path: Union[str, Path]) -> Dict[str, Any]:
        """Safely read JSON file with error handling"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, PermissionError) as e:
            return {'error': str(e)}
   
    @staticmethod
    def write_json_safe(file_path: Union[str, Path], data: Dict[str, Any]) -> bool:
        """Safely write JSON file with error handling"""
        try:
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
           
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except (PermissionError, OSError) as e:
            return False
   
    @staticmethod
    def read_csv_safe(file_path: Union[str, Path]) -> List[Dict[str, str]]:
        """Safely read CSV file with error handling"""
        try:
            with open(file_path, 'r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                return list(reader)
        except (FileNotFoundError, PermissionError, csv.Error) as e:
            return []
   
    @staticmethod
    def write_csv_safe(file_path: Union[str, Path], data: List[Dict[str, Any]],
                      fieldnames: List[str] = None) -> bool:
        """Safely write CSV file with error handling"""
        try:
            if not data:
                return True
           
            # Auto-detect fieldnames if not provided
            if fieldnames is None:
                fieldnames = list(data[0].keys())
           
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
           
            with open(file_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            return True
        except (PermissionError, OSError, csv.Error) as e:
            return False
   
    @staticmethod
    def backup_file(file_path: Union[str, Path], backup_suffix: str = '.bak') -> bool:
        """Create backup of existing file"""
        try:
            source = Path(file_path)
            if not source.exists():
                return True  # Nothing to backup
           
            backup = source.with_suffix(source.suffix + backup_suffix)
           
            import shutil
            shutil.copy2(source, backup)
            return True
        except (OSError, PermissionError):
            return False
   
    @staticmethod
    def ensure_directory(dir_path: Union[str, Path]) -> bool:
        """Ensure directory exists, create if necessary"""
        try:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            return True
        except (OSError, PermissionError):
            return False
   
    @staticmethod
    def get_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (FileNotFoundError, PermissionError, ValueError):
            return None


class NetworkUtils:
    """Network utility functions"""
   
    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
        """Check if a port is open on a host"""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, socket.error, OSError):
            return False
   
    @staticmethod
    def get_local_ip() -> Optional[str]:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except (socket.error, OSError):
            return None
   
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
   
    @staticmethod
    def ping_host(host: str, timeout: int = 3) -> bool:
        """Ping a host to check connectivity"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), host]
           
            result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False


class SystemUtils:
    """System utility functions"""
   
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get basic system information"""
        return {
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
        }
   
    @staticmethod
    def is_admin() -> bool:
        """Check if running with administrator/root privileges"""
        try:
            if platform.system().lower() == 'windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except (AttributeError, OSError):
            return False
   
    @staticmethod
    def get_process_info() -> Dict[str, Any]:
        """Get current process information"""
        import psutil
        process = psutil.Process()
       
        return {
            'pid': process.pid,
            'name': process.name(),
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'memory_info': process.memory_info()._asdict(),
            'num_threads': process.num_threads(),
            'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
            'status': process.status(),
        }


class ValidationUtils:
    """Data validation utilities"""
   
    @staticmethod
    def validate_hex_string(hex_str: str) -> bool:
        """Validate hex string format"""
        # Remove common separators
        clean_hex = re.sub(r'[^0-9A-Fa-f]', '', hex_str)
        return bool(re.match(r'^[0-9A-Fa-f]*$', clean_hex))
   
    @staticmethod
    def validate_can_id(can_id: Union[str, int]) -> bool:
        """Validate CAN ID format and range"""
        try:
            if isinstance(can_id, str):
                # Remove '0x' prefix if present
                clean_id = can_id.replace('0x', '').replace('0X', '')
                id_value = int(clean_id, 16)
            else:
                id_value = int(can_id)
           
            # Check ranges: 11-bit (0-0x7FF) or 29-bit (0-0x1FFFFFFF)
            return (0 <= id_value <= 0x7FF) or (0 <= id_value <= 0x1FFFFFFF)
        except (ValueError, TypeError):
            return False
   
    @staticmethod
    def validate_obd_mode(mode: Union[str, int]) -> bool:
        """Validate OBD mode range"""
        try:
            mode_int = int(mode, 16) if isinstance(mode, str) else int(mode)
            return 1 <= mode_int <= 10
        except (ValueError, TypeError):
            return False
   
    @staticmethod
    def validate_obd_pid(pid: Union[str, int]) -> bool:
        """Validate OBD PID range"""
        try:
            pid_int = int(pid, 16) if isinstance(pid, str) else int(pid)
            return 0 <= pid_int <= 255
        except (ValueError, TypeError):
            return False
   
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
   
    @staticmethod
    def validate_phone_number(phone: str) -> bool:
        """Validate phone number format (basic validation)"""
        # Remove all non-digits
        digits = re.sub(r'[^\d]', '', phone)
        return 10 <= len(digits) <= 15  # International phone number range


class MathUtils:
    """Mathematical utility functions"""
   
    @staticmethod
    def interpolate(x: float, x1: float, y1: float, x2: float, y2: float) -> float:
        """Linear interpolation between two points"""
        if x2 == x1:
            return y1
        return y1 + (y2 - y1) * (x - x1) / (x2 - x1)
   
    @staticmethod
    def moving_average(values: List[float], window_size: int) -> List[float]:
        """Calculate moving average"""
        if window_size <= 0 or window_size > len(values):
            return values
       
        result = []
        for i in range(len(values)):
            start = max(0, i - window_size + 1)
            end = i + 1
            avg = sum(values[start:end]) / (end - start)
            result.append(avg)
       
        return result
   
    @staticmethod
    def clamp(value: float, min_val: float, max_val: float) -> float:
        """Clamp value to specified range"""
        return max(min_val, min(max_val, value))
   
    @staticmethod
    def percentage_change(old_value: float, new_value: float) -> float:
        """Calculate percentage change"""
        if old_value == 0:
            return 100.0 if new_value > 0 else 0.0
        return ((new_value - old_value) / old_value) * 100.0
   
    @staticmethod
    def round_to_significant_figures(value: float, sig_figs: int) -> float:
        """Round to specified number of significant figures"""
        if value == 0:
            return 0
       
        return round(value, -int(math.floor(math.log10(abs(value)))) + (sig_figs - 1))


class CacheManager:
    """Simple thread-safe cache manager"""
   
    def __init__(self, max_size: int = 1000, ttl_seconds: float = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.lock = threading.RLock()
   
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl_seconds:
                    return value
                else:
                    del self.cache[key]
            return None
   
    def set(self, key: str, value: Any):
        """Set value in cache"""
        with self.lock:
            # Clean up expired entries if cache is full
            if len(self.cache) >= self.max_size:
                self._cleanup_expired()
           
            # Remove oldest entry if still full
            if len(self.cache) >= self.max_size:
                oldest_key = min(self.cache.keys(),
                               key=lambda k: self.cache[k][1])
                del self.cache[oldest_key]
           
            self.cache[key] = (value, time.time())
   
    def _cleanup_expired(self):
        """Remove expired entries"""
        current_time = time.time()
        expired_keys = [
            key for key, (_, timestamp) in self.cache.items()
            if current_time - timestamp >= self.ttl_seconds
        ]
       
        for key in expired_keys:
            del self.cache[key]
   
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()


# Global cache instance
_global_cache = CacheManager()


def get_cache() -> CacheManager:
    """Get global cache instance"""
    return _global_cache


def retry_on_failure(max_retries: int = 3, delay: float = 1.0,
                    backoff_factor: float = 2.0):
    """Decorator for retrying functions on failure"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
           
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                   
                    if attempt < max_retries:
                        wait_time = delay * (backoff_factor ** attempt)
                        time.sleep(wait_time)
                   
            # If all retries failed, raise the last exception
            raise last_exception
       
        return wrapper
    return decorator


def timeout(seconds: float):
    """Decorator to add timeout to functions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = [None]
            exception = [None]
           
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e
           
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(seconds)
           
            if thread.is_alive():
                # Thread is still running, timeout occurred
                raise TimeoutError(f"Function {func.__name__} timed out after {seconds} seconds")
           
            if exception[0]:
                raise exception[0]
           
            return result[0]
       
        return wrapper
    return decorator 
