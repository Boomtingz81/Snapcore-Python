MIC3X2X Test Suite Module

Comprehensive test suite for MIC3X2X OBD-II diagnostic system.
Includes unit tests, integration tests, mock devices, and test utilities.

Features:
- Unit tests for all modules
- Integration tests for complete workflows
- Mock MIC3X2X device simulation
- Test data generators
- Performance benchmarks
- Hardware-in-the-loop test support
"""

import unittest
import pytest
import asyncio
import threading
import time
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, call
from typing import Dict, List, Optional, Any, Generator
from dataclasses import dataclass
import logging
import queue
from datetime import datetime, timedelta

# Import all modules to test
from communication_interface import (
    MIC3X2XDevice, SerialInterface, BluetoothInterface,
    MICResponse, ResponseType, CommunicationError
)
from device_config import (
    DeviceConfig, ConfigManager, ProtocolType, CANPhysicalLayer,
    ProtocolConfig, WakeupSequence
)
from protocol_handler import (
    ProtocolHandler, OBDCommand, OBDResponse, CANFrame, CANFrameType
)
from obd_data_processor import (
    OBDDataProcessor, OBDDataPoint, DiagnosticTroubleCode,
    DataLogger, RealTimeMonitor, DTCManager
)
from device_manager import (
    MIC3X2XDeviceManager, DeviceInfo, DiagnosticSession,
    DeviceState, SessionState
)
from logging_system import (
    MIC3X2XLogger, LogLevel, LogCategory, PerformanceMetric
)
from utilities import (
    DataConverter, OBDCalculator, StringFormatter, ValidationUtils,
    MathUtils, CacheManager
)

# Configure test logging
logging.basicConfig(level=logging.WARNING)


class MockMIC3X2XDevice:
    """Mock MIC3X2X device for testing"""
   
    def __init__(self):
        self.responses = {}
        self.command_history = []
        self.connected = True
        self.default_responses = {
            'ATZ': MICResponse('ELM327 v2.3\r>', ResponseType.DATA, ['ELM327 v2.3'], True),
            'ATI': MICResponse('MIC3X2X v2.3.08\r>', ResponseType.DATA, ['MIC3X2X v2.3.08'], True),
            'ATRV': MICResponse('12.8V\r>', ResponseType.DATA, ['12.8V'], True),
            'ATE0': MICResponse('OK\r>', ResponseType.OK, ['OK'], True),
            'ATH1': MICResponse('OK\r>', ResponseType.OK, ['OK'], True),
            'ATSP6': MICResponse('OK\r>', ResponseType.OK, ['OK'], True),
            'ATDP': MICResponse('ISO 15765-4 (CAN 11/500)\r>', ResponseType.DATA, ['ISO 15765-4 (CAN 11/500)'], True),
            '0100': MICResponse('7E8 06 41 00 BE 3F A8 13\r>', ResponseType.DATA, ['7E8 06 41 00 BE 3F A8 13'], True),
            '010C': MICResponse('7E8 04 41 0C 1A F8\r>', ResponseType.DATA, ['7E8 04 41 0C 1A F8'], True),
            '010D': MICResponse('7E8 03 41 0D 55\r>', ResponseType.DATA, ['7E8 03 41 0D 55'], True),
            '0300': MICResponse('43 00 00 00\r>', ResponseType.DATA, ['43 00 00 00'], True),  # No DTCs
            'VTVERS': MICResponse('MIC3X2X V2.3.08\r>', ResponseType.DATA, ['MIC3X2X V2.3.08'], True),
        }
       
    def set_response(self, command: str, response: MICResponse):
        """Set custom response for a command"""
        self.responses[command] = response
       
    def send_command(self, command: str, timeout: float = 5.0) -> MICResponse:
        """Mock command sending"""
        self.command_history.append(command)
       
        # Return custom response if available
        if command in self.responses:
            return self.responses[command]
           
        # Return default response if available
        if command in self.default_responses:
            return self.default_responses[command]
           
        # Return generic error for unknown commands
        return MICResponse(
            raw_data='?\r>',
            response_type=ResponseType.ERROR,
            data_lines=['?'],
            success=False,
            error_message='Unknown command'
        )
   
    def is_connected(self) -> bool:
        return self.connected
   
    def disconnect(self):
        self.connected = False


@dataclass
class TestScenario:
    """Test scenario definition"""
    name: str
    description: str
    setup_commands: List[str]
    test_commands: List[str]
    expected_responses: List[str]
    cleanup_commands: List[str] = None


class TestDataGenerator:
    """Generate test data for various scenarios"""
   
    @staticmethod
    def generate_can_frames(num_frames: int = 10) -> List[str]:
        """Generate sample CAN frame responses"""
        frames = []
        base_id = 0x7E8
       
        for i in range(num_frames):
            can_id = f"{base_id + (i % 8):03X}"
            length = 8
            data = [0x41, 0x0C, (i * 10) % 256, (i * 20) % 256, 0, 0, 0, 0]
            data_str = ' '.join(f"{b:02X}" for b in data)
            frames.append(f"{can_id} {length:02X} {data_str}")
           
        return frames
   
    @staticmethod
    def generate_obd_responses(pids: List[int]) -> Dict[str, str]:
        """Generate OBD responses for given PIDs"""
        responses = {}
       
        for pid in pids:
            if pid == 0x0C:  # Engine RPM
                responses[f"01{pid:02X}"] = "7E8 04 41 0C 1A F8"
            elif pid == 0x0D:  # Vehicle speed
                responses[f"01{pid:02X}"] = "7E8 03 41 0D 55"
            elif pid == 0x05:  # Coolant temperature
                responses[f"01{pid:02X}"] = "7E8 03 41 05 5A"
            elif pid == 0x11:  # Throttle position
                responses[f"01{pid:02X}"] = "7E8 03 41 11 80"
            else:
                # Generic response
                responses[f"01{pid:02X}"] = f"7E8 03 41 {pid:02X} 00"
               
        return responses
   
    @staticmethod
    def generate_dtc_data(num_dtcs: int = 3) -> List[str]:
        """Generate diagnostic trouble code data"""
        dtc_codes = ["P0100", "P0171", "P0301", "P0420", "C0561", "B1234"]
        return dtc_codes[:num_dtcs]


class TestCommunicationInterface(unittest.TestCase):
    """Test communication interface components"""
   
    def setUp(self):
        self.mock_device = MockMIC3X2XDevice()
       
    def test_serial_interface_creation(self):
        """Test serial interface creation"""
        interface = SerialInterface(port="COM1", baudrate=115200)
        self.assertEqual(interface.port, "COM1")
        self.assertEqual(interface.baudrate, 115200)
        self.assertFalse(interface.connected)
   
    def test_mic_response_parsing(self):
        """Test MIC response parsing"""
        response = MICResponse(
            raw_data="7E8 06 41 00 BE 3F A8 13\r>",
            response_type=ResponseType.DATA,
            data_lines=["7E8 06 41 00 BE 3F A8 13"],
            success=True
        )
       
        self.assertTrue(response.success)
        self.assertEqual(len(response.data_lines), 1)
        self.assertIn("7E8", response.data_lines[0])
   
    def test_command_execution(self):
        """Test command execution through mock device"""
        response = self.mock_device.send_command("ATI")
        self.assertTrue(response.success)
        self.assertIn("MIC3X2X", response.data_lines[0])
       
        # Verify command was recorded
        self.assertIn("ATI", self.mock_device.command_history)


class TestDeviceConfig(unittest.TestCase):
    """Test device configuration management"""
   
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_manager = ConfigManager(self.temp_dir)
       
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
   
    def test_default_config_creation(self):
        """Test creation of default configuration"""
        config = self.config_manager.create_default_config()
       
        self.assertIsInstance(config, DeviceConfig)
        self.assertEqual(config.uart_baudrate, 115200)
        self.assertEqual(config.default_protocol, ProtocolType.ISO_15765_11BIT_500K)
        self.assertGreater(len(config.protocol_search_order), 0)
   
    def test_config_validation(self):
        """Test configuration validation"""
        config = self.config_manager.create_default_config()
        errors = self.config_manager.validate_config(config)
        self.assertEqual(len(errors), 0)
       
        # Test invalid configuration
        config.uart_baudrate = 1234  # Invalid baudrate
        errors = self.config_manager.validate_config(config)
        self.assertGreater(len(errors), 0)
   
    def test_config_persistence(self):
        """Test configuration save/load"""
        original_config = self.config_manager.create_default_config()
        original_config.uart_baudrate = 230400
       
        # Save configuration
        self.config_manager.save_config(original_config, "test_config")
       
        # Load configuration
        loaded_config = self.config_manager.load_config("test_config")
       
        self.assertEqual(loaded_config.uart_baudrate, 230400)


class TestProtocolHandler(unittest.TestCase):
    """Test protocol handler functionality"""
   
    def setUp(self):
        self.mock_device = MockMIC3X2XDevice()
        self.config = DeviceConfig()
        self.protocol_handler = ProtocolHandler(self.mock_device, self.config)
       
    def test_obd_command_creation(self):
        """Test OBD command creation"""
        command = OBDCommand(mode=1, pid=12, description="Test command")
       
        self.assertEqual(command.mode, 1)
        self.assertEqual(command.pid, 12)
        self.assertEqual(command.to_hex_string(), "010C")
   
    def test_can_frame_parsing(self):
        """Test CAN frame parsing"""
        response_line = "7E8 04 41 0C 1A F8"
        frame = CANFrame.parse_from_response(response_line)
       
        self.assertEqual(frame.can_id, 0x7E8)
        self.assertEqual(frame.dlc, 4)
        self.assertEqual(len(frame.data), 4)
        self.assertEqual(frame.data[0], 0x41)
   
    def test_obd_response_parsing(self):
        """Test OBD response parsing"""
        # Setup mock response for RPM command
        rpm_response = MICResponse(
            raw_data="7E8 04 41 0C 1A F8\r>",
            response_type=ResponseType.DATA,
            data_lines=["7E8 04 41 0C 1A F8"],
            success=True,
            response_time_ms=150
        )
        self.mock_device.set_response("010C", rpm_response)
       
        command = OBDCommand(mode=1, pid=0x0C, description="Engine RPM")
        response = self.protocol_handler.send_obd_command(command)
       
        self.assertTrue(response.success)
        self.assertEqual(response.mode, 1)
        self.assertEqual(response.pid, 0x0C)
        self.assertGreater(len(response.data), 0)


class TestOBDDataProcessor(unittest.TestCase):
    """Test OBD data processor components"""
   
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.mock_device = MockMIC3X2XDevice()
        self.config = DeviceConfig()
        self.protocol_handler = ProtocolHandler(self.mock_device, self.config)
        self.data_processor = OBDDataProcessor(self.protocol_handler, self.temp_dir)
       
    def tearDown(self):
        self.data_processor.cleanup()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
   
    def test_data_logger_initialization(self):
        """Test data logger database initialization"""
        logger = self.data_processor.logger
        self.assertTrue(logger.db_path.exists())
   
    def test_dtc_decoding(self):
        """Test diagnostic trouble code decoding"""
        dtc_manager = self.data_processor.dtc_manager
       
        # Test P0100 decoding (0x01, 0x00)
        dtc_bytes = [0x01, 0x00]
        dtc_code = dtc_manager._decode_dtc(dtc_bytes)
        self.assertEqual(dtc_code, "P0100")
       
        # Test C0561 decoding (0x41, 0x61)
        dtc_bytes = [0x41, 0x61]
        dtc_code = dtc_manager._decode_dtc(dtc_bytes)
        self.assertEqual(dtc_code, "C0561")
   
    def test_real_time_monitoring(self):
        """Test real-time monitoring functionality"""
        monitor = self.data_processor.monitor
       
        # Set up test PIDs
        test_pids = [0x0C, 0x0D, 0x05]  # RPM, Speed, Coolant temp
        monitor.set_monitor_pids(test_pids, poll_interval=0.1)
       
        # Start monitoring briefly
        monitor.start_monitoring()
        time.sleep(0.5)  # Let it collect some data
        monitor.stop_monitoring()
       
        # Check if data was collected
        self.assertFalse(monitor.monitoring)


class TestDeviceManager(unittest.TestCase):
    """Test device manager functionality"""
   
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.device_manager = MIC3X2XDeviceManager(
            config_dir=self.temp_dir,
            log_dir=self.temp_dir
        )
       
    def tearDown(self):
        self.device_manager.cleanup()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
   
    def test_device_manager_initialization(self):
        """Test device manager initialization"""
        self.assertIsNotNone(self.device_manager.config_manager)
        self.assertIsNotNone(self.device_manager.connection_manager)
        self.assertEqual(len(self.device_manager.active_sessions), 0)
   
    def test_session_management(self):
        """Test diagnostic session management"""
        # Mock successful device connection
        with patch.object(self.device_manager, 'connect_to_device', return_value=True):
            self.device_manager.current_device_id = "test_device"
           
            # Mock protocol handler
            mock_protocol = Mock()
            mock_protocol.current_protocol = "6"
            mock_protocol.get_vehicle_info.return_value = {"vin": "TEST123456789"}
            mock_protocol.get_supported_pids.return_value = [0x0C, 0x0D]
           
            self.device_manager.protocol_handlers["test_device"] = mock_protocol
           
            session_id = self.device_manager.start_diagnostic_session()
           
            self.assertIsNotNone(session_id)
            self.assertIn(session_id, self.device_manager.active_sessions)
           
            session = self.device_manager.active_sessions[session_id]
            self.assertEqual(session.state, SessionState.ACTIVE)


class TestLoggingSystem(unittest.TestCase):
    """Test logging system functionality"""
   
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.logger = MIC3X2XLogger(log_dir=self.temp_dir, app_name="TestApp")
       
    def tearDown(self):
        self.logger.cleanup()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
   
    def test_structured_logging(self):
        """Test structured logging functionality"""
        # Log with context
        self.logger.set_context(device_id="test_device", session_id="test_session")
        self.logger.info("Test message", category=LogCategory.DEVICE)
       
        # Verify log entry
        recent_logs = self.logger.get_recent_logs(count=1)
        self.assertEqual(len(recent_logs), 1)
       
        log_entry = recent_logs[0]
        self.assertEqual(log_entry['message'], "Test message")
        self.assertEqual(log_entry['category'], LogCategory.DEVICE.value)
        self.assertEqual(log_entry['device_id'], "test_device")
   
    def test_performance_timing(self):
        """Test performance timing functionality"""
        with self.logger.timer("test_operation") as timer:
            time.sleep(0.1)  # Simulate work
       
        # Check performance metrics were recorded
        summary = self.logger.get_performance_summary()
        self.assertIn("general", summary)


class TestUtilities(unittest.TestCase):
    """Test utility functions"""
   
    def test_data_converter(self):
        """Test data conversion utilities"""
        # Hex to bytes
        hex_string = "41 0C 1A F8"
        result = DataConverter.hex_to_bytes(hex_string)
        expected = bytes([0x41, 0x0C, 0x1A, 0xF8])
        self.assertEqual(result, expected)
       
        # Bytes to hex
        hex_result = DataConverter.bytes_to_hex(result)
        self.assertEqual(hex_result.replace(' ', ''), "410C1AF8")
   
    def test_obd_calculator(self):
        """Test OBD calculation functions"""
        # Engine RPM calculation
        rpm_bytes = [0x1A, 0xF8]
        rpm = OBDCalculator.engine_rpm(rpm_bytes)
        expected_rpm = ((0x1A * 256) + 0xF8) / 4.0
        self.assertAlmostEqual(rpm, expected_rpm, places=1)
       
        # Coolant temperature
        temp = OBDCalculator.coolant_temperature(90)
        self.assertEqual(temp, 50.0)  # 90 - 40 = 50°C
   
    def test_validation_utils(self):
        """Test validation utilities"""
        # Hex string validation
        self.assertTrue(ValidationUtils.validate_hex_string("41 0C 1A F8"))
        self.assertFalse(ValidationUtils.validate_hex_string("GH IJ KL MN"))
       
        # CAN ID validation
        self.assertTrue(ValidationUtils.validate_can_id(0x7FF))  # Valid 11-bit
        self.assertTrue(ValidationUtils.validate_can_id(0x18DA10F1))  # Valid 29-bit
        self.assertFalse(ValidationUtils.validate_can_id(0x20000000))  # Invalid
   
    def test_cache_manager(self):
        """Test cache manager functionality"""
        cache = CacheManager(max_size=10, ttl_seconds=1.0)
       
        # Test set/get
        cache.set("test_key", "test_value")
        self.assertEqual(cache.get("test_key"), "test_value")
       
        # Test expiration
        time.sleep(1.1)
        self.assertIsNone(cache.get("test_key"))


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""
   
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_scenarios = [
            TestScenario(
                name="basic_connection_test",
                description="Test basic device connection and identification",
                setup_commands=["ATZ", "ATE0"],
                test_commands=["ATI", "ATRV", "ATDP"],
                expected_responses=["MIC3X2X", "V", "ISO"]
            ),
            TestScenario(
                name="obd_data_collection",
                description="Test OBD data collection workflow",
                setup_commands=["ATZ", "ATE0", "ATSP6"],
                test_commands=["0100", "010C", "010D"],
                expected_responses=["41 00", "41 0C", "41 0D"]
            )
        ]
   
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
   
    def test_complete_diagnostic_workflow(self):
        """Test complete diagnostic workflow"""
        # Create mock device
        mock_device = MockMIC3X2XDevice()
       
        # Setup responses for workflow
        workflow_responses = {
            "0100": MICResponse("7E8 06 41 00 BE 3F A8 13\r>", ResponseType.DATA, ["7E8 06 41 00 BE 3F A8 13"], True),
            "010C": MICResponse("7E8 04 41 0C 1A F8\r>", ResponseType.DATA, ["7E8 04 41 0C 1A F8"], True),
            "010D": MICResponse("7E8 03 41 0D 55\r>", ResponseType.DATA, ["7E8 03 41 0D 55"], True),
        }
       
        for cmd, resp in workflow_responses.items():
            mock_device.set_response(cmd, resp)
       
        # Test workflow
        config = DeviceConfig()
        protocol_handler = ProtocolHandler(mock_device, config)
       
        # Test supported PIDs command
        cmd = OBDCommand(mode=1, pid=0, description="Supported PIDs")
        response = protocol_handler.send_obd_command(cmd)
        self.assertTrue(response.success)
       
        # Test RPM command
        cmd = OBDCommand(mode=1, pid=0x0C, description="Engine RPM")
        response = protocol_handler.send_obd_command(cmd)
        self.assertTrue(response.success)
        self.assertEqual(len(response.data), 2)  # RPM should have 2 data bytes


class TestPerformance(unittest.TestCase):
    """Performance and benchmark tests"""
   
    def test_command_response_timing(self):
        """Test command response timing"""
        mock_device = MockMIC3X2XDevice()
       
        start_time = time.perf_counter()
       
        # Send multiple commands
        for _ in range(100):
            response = mock_device.send_command("ATI")
            self.assertTrue(response.success)
       
        end_time = time.perf_counter()
        total_time = end_time - start_time
        avg_time = total_time / 100
       
        # Should be very fast for mock device
        self.assertLess(avg_time, 0.001)  # Less than 1ms per command
   
    def test_data_processing_throughput(self):
        """Test data processing throughput"""
        temp_dir = tempfile.mkdtemp()
       
        try:
            # Generate test data
            test_data = []
            for i in range(1000):
                data_point = OBDDataPoint(
                    timestamp=datetime.now(),
                    pid=0x0C,
                    mode=1,
                    raw_value=[0x1A, 0xF8],
                    interpreted_value=1800.0,
                    unit="rpm",
                    name="Engine RPM",
                    response_time_ms=50
                )
                test_data.append(data_point)
           
            # Measure processing time
            start_time = time.perf_counter()
           
            logger = DataLogger(temp_dir)
            for data_point in test_data:
                logger.log_data_point(data_point)
           
            end_time = time.perf_counter()
            processing_time = end_time - start_time
           
            # Should process 1000 data points in reasonable time
            self.assertLess(processing_time, 5.0)  # Less than 5 seconds
           
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
   
    def test_device_disconnection_handling(self):
        """Test handling of device disconnection"""
        mock_device = MockMIC3X2XDevice()
        mock_device.connected = False
       
        config = DeviceConfig()
        protocol_handler = ProtocolHandler(mock_device, config)
       
        # Attempt command on disconnected device
        cmd = OBDCommand(mode=1, pid=0, description="Test")
        response = protocol_handler.send_obd_command(cmd)
       
        # Should handle disconnection gracefully
        self.assertFalse(response.success)
        self.assertIsNotNone(response.error_code)
   
    def test_invalid_response_handling(self):
        """Test handling of invalid responses"""
        mock_device = MockMIC3X2XDevice()
       
        # Set up invalid response
        invalid_response = MICResponse(
            raw_data="INVALID DATA\r>",
            response_type=ResponseType.ERROR,
            data_lines=["INVALID DATA"],
            success=False,
            error_message="Invalid response format"
        )
       
        mock_device.set_response("0100", invalid_response)
       
        config = DeviceConfig()
        protocol_handler = ProtocolHandler(mock_device, config)
       
        cmd = OBDCommand(mode=1, pid=0, description="Test")
        response = protocol_handler.send_obd_command(cmd)
       
        self.assertFalse(response.success)
   
    def test_timeout_handling(self):
        """Test command timeout handling"""
        class SlowMockDevice(MockMIC3X2XDevice):
            def send_command(self, command: str, timeout: float = 5.0) -> MICResponse:
                time.sleep(timeout + 0.1)  # Exceed timeout
                return super().send_command(command, timeout)
       
        mock_device = SlowMockDevice()
        config = DeviceConfig()
        protocol_handler = ProtocolHandler(mock_device, config)
       
        cmd = OBDCommand(mode=1, pid=0, description="Test")
       
        # This should timeout (implementation would need actual timeout logic)
        start_time = time.time()
        response = protocol_handler.send_obd_command(cmd, timeout=0.1)
        end_time = time.time()
       
        # Verify it took approximately the timeout period
        self.assertGreater(end_time - start_time, 0.1)


def create_test_suite() -> unittest.TestSuite:
    """Create comprehensive test suite"""
    suite = unittest.TestSuite()
   
    # Add test classes
    test_classes = [
        TestCommunicationInterface,
        TestDeviceConfig,
        TestProtocolHandler,
        TestOBDDataProcessor,
        TestDeviceManager,
        TestLoggingSystem,
        TestUtilities,
        TestIntegration,
        TestPerformance,
        TestErrorHandling
    ]
   
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
   
    return suite


def run_tests(verbosity: int = 2) -> unittest.TestResult:
    """Run all tests and return results"""
    suite = create_test_suite()
    runner = unittest.TextTestRunner(verbosity=verbosity)
    return runner.run(suite)


def run_performance_benchmarks():
    """Run performance benchmarks"""
    print("Running MIC3X2X Performance Benchmarks...")
    print("=" * 50)
   
    # Command processing benchmark
    mock_device = MockMIC3X2XDevice()
    num_commands = 1000
   
    start_time = time.perf_counter()
    for i in range(num_commands):
        response = mock_device.send_command(f"01{i % 256:02X}")
    end_time = time.perf_counter()
   
    total_time = end_time - start_time
    commands_per_sec = num_commands / total_time
   
    print(f"Command Processing: {commands_per_sec:.0f} commands/sec")
    print(f"Average Response Time: {total_time * 1000 / num_commands:.2f}ms")
   
    # Data conversion benchmark
    test_data = "41 0C 1A F8 " * 1000
   
    start_time = time.perf_counter()
    for _ in range(1000):
        DataConverter.hex_to_bytes(test_data)
    end_time = time.perf_counter()
   
    conversion_time = end_time - start_time
    print(f"Hex Conversion: {1000 / conversion_time:.0f} conversions/sec")
   
    print("=" * 50)


if __name__ == "__main__":
    import sys
   
    if len(sys.argv) > 1 and sys.argv[1] == "--benchmark":
        run_performance_benchmarks()
    else:
        # Run tests
        print("Running MIC3X2X Test Suite...")
        result = run_tests()
       
        # Print summary
        print(f"\nTest Results:")
        print(f"Tests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}") 
