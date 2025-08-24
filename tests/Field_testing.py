MIC3X2X Field Testing Framework

Real hardware validation system for MIC3X2X diagnostic operations.
Tests across multiple vehicle types to validate policy coverage and system reliability.

Features:
- Real hardware integration testing
- Multi-vehicle test protocols
- Policy coverage validation
- Performance benchmarking
- Error pattern analysis
- Test report generation
"""

import time
import threading
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import statistics
import json

from device_manager import MIC3X2XDeviceManager, DeviceState, SessionState
from policy_manager import MIC3X2XPolicyManager
from obd_data_processor import OBDDataPoint, DiagnosticTroubleCode
from communication_interface import discover_serial_devices, discover_bluetooth_devices
from utilities import ValidationUtils, FileUtils, StringFormatter
from logging_system import get_logger, LogCategory, LoggingContext

logger = get_logger()


class TestResult(Enum):
    """Test execution results"""
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"
    TIMEOUT = "timeout"


class TestSeverity(Enum):
    """Test failure severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VehicleTestProfile:
    """Test profile for a specific vehicle"""
    profile_id: str
    make: str
    model: str
    year: int
    engine: str
    transmission: str
    market: str
    expected_protocols: List[str]
    expected_pids: List[int]
    known_issues: List[str] = field(default_factory=list)
    test_timeout: int = 300  # seconds
    notes: str = ""


@dataclass
class TestCase:
    """Individual test case definition"""
    test_id: str
    name: str
    description: str
    category: str
    setup_commands: List[str]
    test_commands: List[str]
    expected_results: Dict[str, Any]
    cleanup_commands: List[str] = field(default_factory=list)
    timeout: int = 30
    retries: int = 2
    severity: TestSeverity = TestSeverity.MEDIUM


@dataclass
class TestExecution:
    """Test execution record"""
    test_case: TestCase
    vehicle_profile: VehicleTestProfile
    start_time: datetime
    end_time: Optional[datetime]
    result: TestResult
    actual_results: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    raw_logs: List[str] = field(default_factory=list)


@dataclass
class PolicyCoverageReport:
    """Policy coverage analysis"""
    vehicle_profile: VehicleTestProfile
    policy_found: bool
    policy_name: Optional[str]
    policy_confidence: float
    dtc_coverage: Dict[str, bool]  # DTC code -> covered
    parameter_coverage: Dict[int, bool]  # PID -> covered
    missing_interpretations: List[str]
    recommendations: List[str]


class VehicleTestSuite:
    """Test suite for specific vehicle type"""
   
    def __init__(self, vehicle_profile: VehicleTestProfile):
        self.vehicle_profile = vehicle_profile
        self.test_cases = self._create_standard_test_cases()
       
    def _create_standard_test_cases(self) -> List[TestCase]:
        """Create standard test cases for vehicle testing"""
        test_cases = []
       
        # Basic connectivity test
        test_cases.append(TestCase(
            test_id="basic_connectivity",
            name="Basic Device Connectivity",
            description="Test basic communication with MIC3X2X device",
            category="connectivity",
            setup_commands=["ATZ", "ATE0"],
            test_commands=["ATI", "ATRV"],
            expected_results={
                "ATI": "contains:MIC3X2X",
                "ATRV": "regex:[0-9]+\.[0-9]+V"
            }
        ))
       
        # Protocol detection test
        test_cases.append(TestCase(
            test_id="protocol_detection",
            name="Vehicle Protocol Detection",
            description="Test automatic protocol detection for vehicle",
            category="protocol",
            setup_commands=["ATZ", "ATE0"],
            test_commands=["ATSP0", "0100", "ATDP", "ATDPN"],
            expected_results={
                "0100": "not_empty",
                "ATDP": "contains_any:ISO,CAN,J1850",
                "ATDPN": "is_hex"
            }
        ))
       
        # Supported PIDs test
        test_cases.append(TestCase(
            test_id="supported_pids",
            name="Supported PIDs Discovery",
            description="Test discovery of supported OBD PIDs",
            category="obd",
            setup_commands=["ATZ", "ATE0", "ATSP0"],
            test_commands=["0100", "0120", "0140"],
            expected_results={
                "0100": "response_format:obd",
                "response_count": "min:1"
            }
        ))
       
        # Live data test
        test_cases.append(TestCase(
            test_id="live_data",
            name="Live Data Acquisition",
            description="Test acquisition of live engine data",
            category="data",
            setup_commands=["ATZ", "ATE0", "ATSP0"],
            test_commands=["010C", "010D", "0105"],  # RPM, Speed, Coolant temp
            expected_results={
                "data_points": "min:1",
                "response_time": "max:2000"  # milliseconds
            }
        ))
       
        # DTC reading test
        test_cases.append(TestCase(
            test_id="dtc_reading",
            name="Diagnostic Trouble Codes",
            description="Test reading and clearing DTCs",
            category="diagnostics",
            setup_commands=["ATZ", "ATE0", "ATSP0"],
            test_commands=["0300", "0700"],  # Stored and pending DTCs
            expected_results={
                "0300": "response_format:dtc",
                "0700": "response_format:dtc"
            }
        ))
       
        # Performance stress test
        test_cases.append(TestCase(
            test_id="performance_stress",
            name="Performance Under Load",
            description="Test system performance with rapid commands",
            category="performance",
            setup_commands=["ATZ", "ATE0", "ATSP0"],
            test_commands=["010C"] * 50,  # 50 RPM requests
            expected_results={
                "success_rate": "min:90",  # 90% success rate
                "avg_response_time": "max:500"  # 500ms average
            },
            timeout=60
        ))
       
        return test_cases
   
    def add_custom_test(self, test_case: TestCase):
        """Add custom test case to suite"""
        self.test_cases.append(test_case)
       
    def get_tests_by_category(self, category: str) -> List[TestCase]:
        """Get test cases by category"""
        return [tc for tc in self.test_cases if tc.category == category]


class FieldTestExecutor:
    """Executes field tests on real hardware"""
   
    def __init__(self, device_manager: MIC3X2XDeviceManager,
                 policy_manager: MIC3X2XPolicyManager):
        self.device_manager = device_manager
        self.policy_manager = policy_manager
        self.test_results: List[TestExecution] = []
        self.current_session_id: Optional[str] = None
       
    def execute_test_suite(self, test_suite: VehicleTestSuite,
                          device_id: str = None) -> List[TestExecution]:
        """Execute complete test suite on vehicle"""
        logger.info(f"Starting test suite for {test_suite.vehicle_profile.make} {test_suite.vehicle_profile.model}",
                   category=LogCategory.SYSTEM)
       
        suite_results = []
       
        # Setup test environment
        if not self._setup_test_environment(device_id):
            logger.error("Failed to setup test environment")
            return suite_results
       
        try:
            # Execute each test case
            for test_case in test_suite.test_cases:
                with LoggingContext(test_id=test_case.test_id,
                                  vehicle=f"{test_suite.vehicle_profile.make}_{test_suite.vehicle_profile.model}"):
                   
                    logger.info(f"Executing test: {test_case.name}")
                   
                    execution = self._execute_single_test(test_case, test_suite.vehicle_profile)
                    suite_results.append(execution)
                    self.test_results.append(execution)
                   
                    # Log immediate result
                    if execution.result == TestResult.PASS:
                        logger.info(f"Test PASSED: {test_case.name}")
                    else:
                        logger.warning(f"Test {execution.result.value.upper()}: {test_case.name} - {execution.error_message}")
                   
                    # Brief pause between tests
                    time.sleep(1.0)
           
        finally:
            self._cleanup_test_environment()
       
        # Generate summary
        passed = len([r for r in suite_results if r.result == TestResult.PASS])
        total = len(suite_results)
        logger.info(f"Test suite completed: {passed}/{total} tests passed")
       
        return suite_results
   
    def _setup_test_environment(self, device_id: str = None) -> bool:
        """Setup test environment"""
        try:
            # Connect to device
            if not self.device_manager.connect_to_device(device_id, auto_discover=True):
                logger.error("Failed to connect to MIC3X2X device")
                return False
           
            # Start diagnostic session
            self.current_session_id = self.device_manager.start_diagnostic_session()
            if not self.current_session_id:
                logger.error("Failed to start diagnostic session")
                return False
           
            logger.info("Test environment setup complete")
            return True
           
        except Exception as e:
            logger.error(f"Test environment setup failed: {e}")
            return False
   
    def _cleanup_test_environment(self):
        """Cleanup test environment"""
        try:
            if self.current_session_id:
                self.device_manager.end_session(self.current_session_id)
                self.current_session_id = None
           
            # Stop any monitoring
            if self.device_manager.current_device_id:
                self.device_manager.stop_monitoring(self.device_manager.current_device_id)
           
            logger.info("Test environment cleanup complete")
           
        except Exception as e:
            logger.warning(f"Test cleanup error: {e}")
   
    def _execute_single_test(self, test_case: TestCase,
                           vehicle_profile: VehicleTestProfile) -> TestExecution:
        """Execute a single test case"""
        execution = TestExecution(
            test_case=test_case,
            vehicle_profile=vehicle_profile,
            start_time=datetime.now(),
            end_time=None,
            result=TestResult.ERROR
        )
       
        try:
            # Execute setup commands
            for cmd in test_case.setup_commands:
                response = self.device_manager.protocol_handlers[self.device_manager.current_device_id].device.send_command(cmd)
                execution.raw_logs.append(f"SETUP: {cmd} -> {response.raw_data}")
               
                if not response.success:
                    execution.result = TestResult.FAIL
                    execution.error_message = f"Setup command failed: {cmd}"
                    return execution
           
            # Execute test commands with timing
            start_time = time.perf_counter()
            command_results = {}
           
            for cmd in test_case.test_commands:
                cmd_start = time.perf_counter()
                response = self.device_manager.protocol_handlers[self.device_manager.current_device_id].device.send_command(cmd, timeout=test_case.timeout)
                cmd_end = time.perf_counter()
               
                command_results[cmd] = {
                    'success': response.success,
                    'data': response.raw_data,
                    'response_time_ms': (cmd_end - cmd_start) * 1000
                }
               
                execution.raw_logs.append(f"TEST: {cmd} -> {response.raw_data}")
               
                if not response.success and test_case.severity == TestSeverity.CRITICAL:
                    execution.result = TestResult.FAIL
                    execution.error_message = f"Critical test command failed: {cmd}"
                    return execution
           
            end_time = time.perf_counter()
            total_time = (end_time - start_time) * 1000
           
            # Store performance metrics
            execution.performance_metrics = {
                'total_execution_time_ms': total_time,
                'average_command_time_ms': total_time / len(test_case.test_commands) if test_case.test_commands else 0,
                'command_count': len(test_case.test_commands)
            }
           
            # Validate results
            execution.actual_results = command_results
            validation_result = self._validate_test_results(test_case, command_results)
           
            if validation_result['passed']:
                execution.result = TestResult.PASS
            else:
                execution.result = TestResult.FAIL
                execution.error_message = validation_result['error']
           
            # Execute cleanup commands
            for cmd in test_case.cleanup_commands:
                response = self.device_manager.protocol_handlers[self.device_manager.current_device_id].device.send_command(cmd)
                execution.raw_logs.append(f"CLEANUP: {cmd} -> {response.raw_data}")
           
        except Exception as e:
            execution.result = TestResult.ERROR
            execution.error_message = str(e)
            logger.error(f"Test execution error: {e}")
       
        finally:
            execution.end_time = datetime.now()
       
        return execution
   
    def _validate_test_results(self, test_case: TestCase,
                             command_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate test results against expected outcomes"""
        validation_errors = []
       
        for expected_key, expected_value in test_case.expected_results.items():
            if expected_key == "response_count":
                # Check minimum response count
                actual_count = len([r for r in command_results.values() if r['success']])
                min_count = int(expected_value.split(':')[1])
                if actual_count < min_count:
                    validation_errors.append(f"Expected min {min_count} responses, got {actual_count}")
           
            elif expected_key == "success_rate":
                # Check success rate percentage
                total = len(command_results)
                successful = len([r for r in command_results.values() if r['success']])
                success_rate = (successful / total * 100) if total > 0 else 0
                min_rate = float(expected_value.split(':')[1])
                if success_rate < min_rate:
                    validation_errors.append(f"Success rate {success_rate:.1f}% below minimum {min_rate}%")
           
            elif expected_key == "avg_response_time":
                # Check average response time
                response_times = [r['response_time_ms'] for r in command_results.values() if r['success']]
                if response_times:
                    avg_time = statistics.mean(response_times)
                    max_time = float(expected_value.split(':')[1])
                    if avg_time > max_time:
                        validation_errors.append(f"Average response time {avg_time:.1f}ms exceeds {max_time}ms")
           
            elif expected_key in command_results:
                # Validate specific command result
                actual_result = command_results[expected_key]
                if not self._validate_single_result(expected_value, actual_result['data']):
                    validation_errors.append(f"Command {expected_key} validation failed: expected {expected_value}")
       
        return {
            'passed': len(validation_errors) == 0,
            'error': '; '.join(validation_errors) if validation_errors else None
        }
   
    def _validate_single_result(self, expected: str, actual: str) -> bool:
        """Validate single command result"""
        if expected.startswith("contains:"):
            search_term = expected.split(':', 1)[1]
            return search_term.upper() in actual.upper()
       
        elif expected.startswith("regex:"):
            import re
            pattern = expected.split(':', 1)[1]
            return bool(re.search(pattern, actual))
       
        elif expected.startswith("contains_any:"):
            terms = expected.split(':', 1)[1].split(',')
            return any(term.strip().upper() in actual.upper() for term in terms)
       
        elif expected == "not_empty":
            return len(actual.strip()) > 0
       
        elif expected == "is_hex":
            return ValidationUtils.validate_hex_string(actual.strip())
       
        elif expected == "response_format:obd":
            # Basic OBD response format validation
            return ' ' in actual and len(actual.split()) >= 3
       
        elif expected == "response_format:dtc":
            # DTC response format validation
            return actual.startswith('43') or 'NO DATA' in actual
       
        return str(expected) == str(actual)


class PolicyCoverageAnalyzer:
    """Analyzes policy coverage across test vehicles"""
   
    def __init__(self, policy_manager: MIC3X2XPolicyManager):
        self.policy_manager = policy_manager
   
    def analyze_coverage(self, vehicle_profile: VehicleTestProfile,
                        test_results: List[TestExecution]) -> PolicyCoverageReport:
        """Analyze policy coverage for vehicle"""
        logger.info(f"Analyzing policy coverage for {vehicle_profile.make} {vehicle_profile.model}")
       
        vehicle_info = {
            'make': vehicle_profile.make,
            'model': vehicle_profile.model,
            'year': vehicle_profile.year,
            'engine': vehicle_profile.engine
        }
       
        # Find matching policy
        policy = self.policy_manager.get_policy_for_vehicle(vehicle_info)
        matches = self.policy_manager.policy_matcher.find_matching_policies(vehicle_info)
       
        policy_confidence = matches[0].confidence if matches else 0.0
       
        # Analyze DTC coverage
        dtc_coverage = self._analyze_dtc_coverage(policy, test_results)
       
        # Analyze parameter coverage 
        parameter_coverage = self._analyze_parameter_coverage(policy, test_results)
       
        # Generate recommendations
        recommendations = self._generate_recommendations(policy, vehicle_profile, dtc_coverage, parameter_coverage)
       
        return PolicyCoverageReport(
            vehicle_profile=vehicle_profile,
            policy_found=policy is not None,
            policy_name=policy.name if policy else None,
            policy_confidence=policy_confidence,
            dtc_coverage=dtc_coverage,
            parameter_coverage=parameter_coverage,
            missing_interpretations=self._find_missing_interpretations(policy, test_results),
            recommendations=recommendations
        )
   
    def _analyze_dtc_coverage(self, policy, test_results: List[TestExecution]) -> Dict[str, bool]:
        """Analyze DTC interpretation coverage"""
        dtc_coverage = {}
       
        # Extract DTCs found in test results
        found_dtcs = set()
        for execution in test_results:
            if execution.test_case.category == "diagnostics":
                for cmd, result in execution.actual_results.items():
                    if result['success'] and cmd in ['0300', '0700']:  # DTC commands
                        # Parse DTCs from response (simplified)
                        dtcs = self._extract_dtcs_from_response(result['data'])
                        found_dtcs.update(dtcs)
       
        # Check policy coverage for found DTCs
        if policy:
            for dtc in found_dtcs:
                dtc_coverage[dtc] = dtc in policy.dtc_mappings
       
        return dtc_coverage
   
    def _analyze_parameter_coverage(self, policy, test_results: List[TestExecution]) -> Dict[int, bool]:
        """Analyze parameter interpretation coverage"""
        parameter_coverage = {}
       
        # Extract PIDs tested
        tested_pids = set()
        for execution in test_results:
            for cmd in execution.test_case.test_commands:
                if cmd.startswith('01') and len(cmd) == 4:  # Mode 1 PID
                    try:
                        pid = int(cmd[2:4], 16)
                        tested_pids.add(pid)
                    except ValueError:
                        continue
       
        # Check policy coverage for tested PIDs
        if policy:
            for pid in tested_pids:
                pid_hex = f"{pid:02X}"
                parameter_coverage[pid] = pid_hex in policy.parameter_ranges
       
        return parameter_coverage
   
    def _extract_dtcs_from_response(self, response: str) -> List[str]:
        """Extract DTC codes from OBD response"""
        # Simplified DTC extraction - would need proper implementation
        dtcs = []
       
        if response.startswith('43'):  # DTC response
            # Basic DTC parsing logic would go here
            pass
       
        return dtcs
   
    def _find_missing_interpretations(self, policy, test_results: List[TestExecution]) -> List[str]:
        """Find areas lacking manufacturer-specific interpretation"""
        missing = []
       
        if not policy:
            missing.append("No manufacturer-specific policy found")
            return missing
       
        # Check for gaps in policy coverage
        if not policy.dtc_mappings:
            missing.append("No DTC interpretations available")
       
        if not policy.parameter_ranges:
            missing.append("No parameter range definitions")
       
        if not policy.diagnostic_procedures:
            missing.append("No diagnostic procedures defined")
       
        return missing
   
    def _generate_recommendations(self, policy, vehicle_profile: VehicleTestProfile,
                                dtc_coverage: Dict[str, bool],
                                parameter_coverage: Dict[int, bool]) -> List[str]:
        """Generate recommendations for improving policy coverage"""
        recommendations = []
       
        if not policy:
            recommendations.append(f"Create diagnostic policy for {vehicle_profile.make} {vehicle_profile.model}")
            recommendations.append("Define manufacturer-specific DTC interpretations")
            recommendations.append("Set vehicle-appropriate parameter ranges")
            return recommendations
       
        # Check DTC coverage
        uncovered_dtcs = [dtc for dtc, covered in dtc_coverage.items() if not covered]
        if uncovered_dtcs:
            recommendations.append(f"Add DTC interpretations for: {', '.join(uncovered_dtcs)}")
       
        # Check parameter coverage
        uncovered_pids = [f"0x{pid:02X}" for pid, covered in parameter_coverage.items() if not covered]
        if uncovered_pids:
            recommendations.append(f"Add parameter ranges for PIDs: {', '.join(uncovered_pids)}")
       
        # Check for missing procedures
        if not policy.diagnostic_procedures:
            recommendations.append("Add vehicle-specific diagnostic procedures")
       
        return recommendations


class FieldTestReport:
    """Generates comprehensive field test reports"""
   
    def __init__(self, test_results: List[TestExecution],
                 coverage_reports: List[PolicyCoverageReport]):
        self.test_results = test_results
        self.coverage_reports = coverage_reports
   
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate executive summary report"""
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r.result == TestResult.PASS])
        failed_tests = len([r for r in self.test_results if r.result == TestResult.FAIL])
        error_tests = len([r for r in self.test_results if r.result == TestResult.ERROR])
       
        # Calculate average performance metrics
        response_times = []
        for result in self.test_results:
            if 'average_command_time_ms' in result.performance_metrics:
                response_times.append(result.performance_metrics['average_command_time_ms'])
       
        avg_response_time = statistics.mean(response_times) if response_times else 0
       
        # Policy coverage summary
        vehicles_with_policies = len([r for r in self.coverage_reports if r.policy_found])
        total_vehicles = len(self.coverage_reports)
       
        summary = {
            'test_summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'errors': error_tests,
                'pass_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            'performance_summary': {
                'average_response_time_ms': avg_response_time,
                'total_test_time': sum(r.performance_metrics.get('total_execution_time_ms', 0) for r in self.test_results)
            },
            'policy_coverage': {
                'vehicles_tested': total_vehicles,
                'vehicles_with_policies': vehicles_with_policies,
                'coverage_rate': (vehicles_with_policies / total_vehicles * 100) if total_vehicles > 0 else 0
            },
            'recommendations': self._generate_overall_recommendations()
        }
       
        return summary
   
    def _generate_overall_recommendations(self) -> List[str]:
        """Generate overall system recommendations"""
        recommendations = []
       
        # Test failure analysis
        failed_tests = [r for r in self.test_results if r.result == TestResult.FAIL]
        if failed_tests:
            failure_categories = {}
            for test in failed_tests:
                category = test.test_case.category
                failure_categories[category] = failure_categories.get(category, 0) + 1
           
            top_failure_category = max(failure_categories, key=failure_categories.get)
            recommendations.append(f"Address {top_failure_category} test failures ({failure_categories[top_failure_category]} failures)")
       
        # Policy coverage recommendations
        vehicles_without_policies = [r for r in self.coverage_reports if not r.policy_found]
        if vehicles_without_policies:
            makes = set(r.vehicle_profile.make for r in vehicles_without_policies)
            recommendations.append(f"Create diagnostic policies for: {', '.join(makes)}")
       
        # Performance recommendations
        slow_tests = [r for r in self.test_results if r.performance_metrics.get('average_command_time_ms', 0) > 1000]
        if slow_tests:
            recommendations.append(f"Optimize performance for {len(slow_tests)} slow test cases")
       
        return recommendations
   
    def export_detailed_report(self, output_path: str) -> str:
        """Export detailed report to file"""
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'test_count': len(self.test_results),
                'vehicle_count': len(set(r.vehicle_profile.profile_id for r in self.test_results))
            },
            'summary': self.generate_summary_report(),
            'test_results': [
                {
                    'test_id': r.test_case.test_id,
                    'test_name': r.test_case.name,
                    'vehicle': f"{r.vehicle_profile.make} {r.vehicle_profile.model}",
                    'result': r.result.value,
                    'execution_time_ms': r.performance_metrics.get('total_execution_time_ms', 0),
                    'error_message': r.error_message
                }
                for r in self.test_results
            ],
            'policy_coverage': [
                {
                    'vehicle': f"{r.vehicle_profile.make} {r.vehicle_profile.model}",
                    'policy_found': r.policy_found,
                    'policy_name': r.policy_name,
                    'confidence': r.policy_confidence,
                    'recommendations': r.recommendations
                }
                for r in self.coverage_reports
            ]
        }
       
        output_file = Path(output_path)
        FileUtils.write_json_safe(output_file, report_data)
       
        logger.info(f"Detailed test report exported to: {output_file}")
        return str(output_file)


def create_standard_vehicle_profiles() -> List[VehicleTestProfile]:
    """Create standard vehicle test profiles"""
    profiles = [
        VehicleTestProfile(
            profile_id="nissan_leaf_2018",
            make="Nissan",
            model="Leaf",
            year=2018,
            engine="Electric",
            transmission="CVT",
            market="US",
            expected_protocols=["CAN 11/500", "ISO 15765"],
            expected_pids=[0x0C, 0x0D, 0x2F, 0x21],  # Electric vehicle PIDs
            known_issues=["Battery temperature may not be available via standard OBD"],
            notes="Electric vehicle with unique diagnostic requirements"
        ),
       
        VehicleTestProfile(
            profile_id="toyota_prius_2020",
            make="Toyota",
            model="Prius",
            year=2020,
            engine="Hybrid",
            transmission="CVT",
            market="US",
            expected_protocols=["CAN 11/500"],
            expected_pids=[0x05, 0x0C, 0x0D, 0x11, 0x21],
            known_issues=["Hybrid system data may require manufacturer tools"],
            notes="Hybrid vehicle requiring both ICE and electric diagnostics"
        ),
       
        VehicleTestProfile(
            profile_id="ford_f150_2019",
            make="Ford",
            model="F-150",
            year=2019,
            engine="V8",
            transmission="Automatic",
            market="US",
            expected_protocols=["CAN 11/500", "MS-CAN"],
            expected_pids=[0x05, 0x0C, 0x0D, 0x10, 0x11, 0x21, 0x33],
            known_issues=["May require Ford-specific protocols for full diagnostics"],
            notes="Traditional ICE vehicle with Ford-specific features"
        )
    ]
   
    return profiles


if __name__ == "__main__":
    # Example field testing workflow
    from device_manager 
