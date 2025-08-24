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

MIC3X2X Policy Manager

Manufacturer-specific diagnostic policy management system.
Translates generic OBD-II data into vehicle-specific context using JSON policy files.

Features:
- Manufacturer-specific DTC interpretation
- Parameter range validation per vehicle type
- Custom diagnostic procedures
- Policy file loading and validation
- Context-aware data interpretation
- Extensible policy framework
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re

from obd_data_processor import OBDDataPoint, DiagnosticTroubleCode
from utilities import ValidationUtils, FileUtils
from logging_system import get_logger, LogCategory

logger = get_logger()


class PolicySeverity(Enum):
    """Policy rule severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    MAINTENANCE = "maintenance"


class PolicyRuleType(Enum):
    """Types of policy rules"""
    PARAMETER_RANGE = "parameter_range"
    DTC_INTERPRETATION = "dtc_interpretation"
    DIAGNOSTIC_PROCEDURE = "diagnostic_procedure"
    MAINTENANCE_SCHEDULE = "maintenance_schedule"
    COMPATIBILITY_CHECK = "compatibility_check"


@dataclass
class PolicyRule:
    """Individual policy rule definition"""
    rule_id: str
    rule_type: PolicyRuleType
    name: str
    description: str
    conditions: Dict[str, Any]
    actions: Dict[str, Any]
    severity: PolicySeverity = PolicySeverity.INFO
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VehicleIdentifier:
    """Vehicle identification information"""
    make: str
    model: Optional[str] = None
    year: Optional[int] = None
    engine: Optional[str] = None
    trim: Optional[str] = None
    vin_pattern: Optional[str] = None
    market: Optional[str] = None  # US, EU, JP, etc.
   
    def matches(self, other: 'VehicleIdentifier') -> bool:
        """Check if this identifier matches another"""
        if self.make.lower() != other.make.lower():
            return False
       
        if self.model and other.model:
            if self.model.lower() != other.model.lower():
                return False
       
        if self.year and other.year:
            if self.year != other.year:
                return False
       
        if self.engine and other.engine:
            if self.engine.lower() != other.engine.lower():
                return False
       
        if self.vin_pattern and other.vin_pattern:
            if not re.match(self.vin_pattern, other.vin_pattern):
                return False
       
        return True


@dataclass
class DiagnosticPolicy:
    """Complete diagnostic policy for a vehicle type"""
    policy_id: str
    name: str
    version: str
    vehicle_identifier: VehicleIdentifier
    rules: List[PolicyRule]
    dtc_mappings: Dict[str, Dict[str, Any]]
    parameter_ranges: Dict[int, Dict[str, Any]]  # PID -> range info
    diagnostic_procedures: Dict[str, Dict[str, Any]]
    maintenance_schedules: Dict[str, List[Dict[str, Any]]]
    created_date: datetime
    updated_date: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyMatch:
    """Result of policy matching"""
    policy: DiagnosticPolicy
    confidence: float  # 0.0 to 1.0
    match_reasons: List[str]


@dataclass
class InterpretationResult:
    """Result of data interpretation using policies"""
    original_value: Any
    interpreted_value: Any
    context: Dict[str, Any]
    severity: PolicySeverity
    recommendations: List[str]
    applicable_rules: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolicyValidator:
    """Validates policy file structure and content"""
   
    REQUIRED_FIELDS = {
        'policy_id', 'name', 'version', 'vehicle_identifier',
        'rules', 'dtc_mappings', 'parameter_ranges'
    }
   
    @staticmethod
    def validate_policy_structure(policy_data: Dict[str, Any]) -> List[str]:
        """Validate basic policy structure"""
        errors = []
       
        # Check required fields
        missing_fields = PolicyValidator.REQUIRED_FIELDS - set(policy_data.keys())
        if missing_fields:
            errors.append(f"Missing required fields: {missing_fields}")
       
        # Validate vehicle identifier
        if 'vehicle_identifier' in policy_data:
            vehicle_id = policy_data['vehicle_identifier']
            if not isinstance(vehicle_id, dict) or 'make' not in vehicle_id:
                errors.append("vehicle_identifier must be a dict with 'make' field")
       
        # Validate rules structure
        if 'rules' in policy_data:
            if not isinstance(policy_data['rules'], list):
                errors.append("rules must be a list")
            else:
                for i, rule in enumerate(policy_data['rules']):
                    rule_errors = PolicyValidator._validate_rule(rule, i)
                    errors.extend(rule_errors)
       
        # Validate DTC mappings
        if 'dtc_mappings' in policy_data:
            if not isinstance(policy_data['dtc_mappings'], dict):
                errors.append("dtc_mappings must be a dictionary")
       
        # Validate parameter ranges
        if 'parameter_ranges' in policy_data:
            if not isinstance(policy_data['parameter_ranges'], dict):
                errors.append("parameter_ranges must be a dictionary")
            else:
                for pid, range_data in policy_data['parameter_ranges'].items():
                    try:
                        int(pid, 16)  # Should be hex PID
                    except ValueError:
                        errors.append(f"Invalid PID format: {pid}")
       
        return errors
   
    @staticmethod
    def _validate_rule(rule: Dict[str, Any], index: int) -> List[str]:
        """Validate individual rule structure"""
        errors = []
        rule_required = {'rule_id', 'rule_type', 'name', 'conditions', 'actions'}
       
        missing = rule_required - set(rule.keys())
        if missing:
            errors.append(f"Rule {index}: missing fields {missing}")
       
        # Validate rule_type
        if 'rule_type' in rule:
            try:
                PolicyRuleType(rule['rule_type'])
            except ValueError:
                errors.append(f"Rule {index}: invalid rule_type '{rule['rule_type']}'")
       
        # Validate severity
        if 'severity' in rule:
            try:
                PolicySeverity(rule['severity'])
            except ValueError:
                errors.append(f"Rule {index}: invalid severity '{rule['severity']}'")
       
        return errors


class PolicyLoader:
    """Loads and manages policy files"""
   
    def __init__(self, policy_directory: str = "policies"):
        self.policy_dir = Path(policy_directory)
        self.policy_dir.mkdir(exist_ok=True)
        self.loaded_policies: Dict[str, DiagnosticPolicy] = {}
       
    def load_policy(self, policy_file: Union[str, Path]) -> Optional[DiagnosticPolicy]:
        """Load a single policy file"""
        try:
            policy_path = Path(policy_file)
            if not policy_path.is_absolute():
                policy_path = self.policy_dir / policy_path
           
            logger.info(f"Loading policy: {policy_path}", category=LogCategory.SYSTEM)
           
            policy_data = FileUtils.read_json_safe(policy_path)
            if 'error' in policy_data:
                logger.error(f"Failed to read policy file: {policy_data['error']}")
                return None
           
            # Validate structure
            validation_errors = PolicyValidator.validate_policy_structure(policy_data)
            if validation_errors:
                logger.error(f"Policy validation failed: {validation_errors}")
                return None
           
            # Convert to policy object
            policy = self._convert_to_policy_object(policy_data)
            if policy:
                self.loaded_policies[policy.policy_id] = policy
                logger.info(f"Successfully loaded policy: {policy.name}")
           
            return policy
           
        except Exception as e:
            logger.error(f"Error loading policy {policy_file}: {e}")
            return None
   
    def load_all_policies(self) -> Dict[str, DiagnosticPolicy]:
        """Load all policy files from directory"""
        policy_files = list(self.policy_dir.glob("*.json"))
       
        logger.info(f"Loading {len(policy_files)} policy files")
       
        for policy_file in policy_files:
            self.load_policy(policy_file)
       
        return self.loaded_policies
   
    def _convert_to_policy_object(self, policy_data: Dict[str, Any]) -> Optional[DiagnosticPolicy]:
        """Convert JSON data to DiagnosticPolicy object"""
        try:
            # Parse vehicle identifier
            vehicle_data = policy_data['vehicle_identifier']
            vehicle_id = VehicleIdentifier(
                make=vehicle_data['make'],
                model=vehicle_data.get('model'),
                year=vehicle_data.get('year'),
                engine=vehicle_data.get('engine'),
                trim=vehicle_data.get('trim'),
                vin_pattern=vehicle_data.get('vin_pattern'),
                market=vehicle_data.get('market')
            )
           
            # Parse rules
            rules = []
            for rule_data in policy_data.get('rules', []):
                rule = PolicyRule(
                    rule_id=rule_data['rule_id'],
                    rule_type=PolicyRuleType(rule_data['rule_type']),
                    name=rule_data['name'],
                    description=rule_data.get('description', ''),
                    conditions=rule_data['conditions'],
                    actions=rule_data['actions'],
                    severity=PolicySeverity(rule_data.get('severity', 'info')),
                    enabled=rule_data.get('enabled', True),
                    metadata=rule_data.get('metadata', {})
                )
                rules.append(rule)
           
            # Create policy object
            policy = DiagnosticPolicy(
                policy_id=policy_data['policy_id'],
                name=policy_data['name'],
                version=policy_data['version'],
                vehicle_identifier=vehicle_id,
                rules=rules,
                dtc_mappings=policy_data.get('dtc_mappings', {}),
                parameter_ranges=policy_data.get('parameter_ranges', {}),
                diagnostic_procedures=policy_data.get('diagnostic_procedures', {}),
                maintenance_schedules=policy_data.get('maintenance_schedules', {}),
                created_date=datetime.fromisoformat(policy_data.get('created_date', datetime.now().isoformat())),
                updated_date=datetime.fromisoformat(policy_data.get('updated_date', datetime.now().isoformat())),
                metadata=policy_data.get('metadata', {})
            )
           
            return policy
           
        except Exception as e:
            logger.error(f"Error converting policy data: {e}")
            return None


class PolicyMatcher:
    """Matches vehicles to appropriate policies"""
   
    def __init__(self, policies: Dict[str, DiagnosticPolicy]):
        self.policies = policies
   
    def find_matching_policies(self, vehicle_info: Dict[str, Any]) -> List[PolicyMatch]:
        """Find policies matching vehicle information"""
        matches = []
       
        # Extract vehicle identifier from info
        target_vehicle = self._extract_vehicle_identifier(vehicle_info)
        if not target_vehicle:
            return matches
       
        # Score each policy
        for policy in self.policies.values():
            confidence, reasons = self._calculate_match_confidence(target_vehicle, policy.vehicle_identifier)
           
            if confidence > 0.0:
                match = PolicyMatch(
                    policy=policy,
                    confidence=confidence,
                    match_reasons=reasons
                )
                matches.append(match)
       
        # Sort by confidence
        matches.sort(key=lambda m: m.confidence, reverse=True)
       
        return matches
   
    def get_best_policy(self, vehicle_info: Dict[str, Any]) -> Optional[DiagnosticPolicy]:
        """Get the best matching policy for a vehicle"""
        matches = self.find_matching_policies(vehicle_info)
       
        if matches and matches[0].confidence >= 0.7:  # Require high confidence
            return matches[0].policy
       
        return None
   
    def _extract_vehicle_identifier(self, vehicle_info: Dict[str, Any]) -> Optional[VehicleIdentifier]:
        """Extract vehicle identifier from vehicle info"""
        try:
            # Try to extract from VIN first
            vin = vehicle_info.get('vin', '')
            if vin and len(vin) >= 17:
                make = self._decode_make_from_vin(vin)
                year = self._decode_year_from_vin(vin)
               
                return VehicleIdentifier(
                    make=make or vehicle_info.get('make', ''),
                    year=year,
                    vin_pattern=vin[:3] if vin else None  # WMI (World Manufacturer Identifier)
                )
           
            # Fall back to explicit fields
            make = vehicle_info.get('make')
            if not make:
                return None
           
            return VehicleIdentifier(
                make=make,
                model=vehicle_info.get('model'),
                year=vehicle_info.get('year'),
                engine=vehicle_info.get('engine'),
                trim=vehicle_info.get('trim')
            )
           
        except Exception as e:
            logger.error(f"Error extracting vehicle identifier: {e}")
            return None
   
    def _decode_make_from_vin(self, vin: str) -> Optional[str]:
        """Decode manufacturer from VIN"""
        if len(vin) < 3:
            return None
       
        # WMI (World Manufacturer Identifier) mapping - partial list
        wmi_map = {
            '1G1': 'Chevrolet', '1G6': 'Cadillac', '1GM': 'Pontiac',
            '1N4': 'Nissan', '1N6': 'Nissan',
            'JM1': 'Mazda', 'JN1': 'Nissan', 'JH4': 'Acura',
            'WBA': 'BMW', 'WBS': 'BMW', 'WDD': 'Mercedes-Benz',
            'VF1': 'Renault', 'VF7': 'Citroën', 'VWV': 'Volkswagen',
            'YV1': 'Volvo', 'YS3': 'Saab',
            'KMH': 'Hyundai', 'KNA': 'Kia',
            'SJN': 'Nissan', 'SCC': 'Lotus',
            'WAU': 'Audi', 'WVW': 'Volkswagen'
        }
       
        wmi = vin[:3]
        return wmi_map.get(wmi)
   
    def _decode_year_from_vin(self, vin: str) -> Optional[int]:
        """Decode model year from VIN"""
        if len(vin) < 10:
            return None
       
        year_char = vin[9]
       
        # Year encoding for 10th position
        year_map = {
            'A': 2010, 'B': 2011, 'C': 2012, 'D': 2013, 'E': 2014,
            'F': 2015, 'G': 2016, 'H': 2017, 'J': 2018, 'K': 2019,
            'L': 2020, 'M': 2021, 'N': 2022, 'P': 2023, 'R': 2024,
            '1': 2001, '2': 2002, '3': 2003, '4': 2004, '5': 2005,
            '6': 2006, '7': 2007, '8': 2008, '9': 2009
        }
       
        return year_map.get(year_char)
   
    def _calculate_match_confidence(self, target: VehicleIdentifier, policy_vehicle: VehicleIdentifier) -> Tuple[float, List[str]]:
        """Calculate confidence score for vehicle match"""
        score = 0.0
        reasons = []
        max_score = 0.0
       
        # Make match (required)
        max_score += 40
        if target.make and policy_vehicle.make:
            if target.make.lower() == policy_vehicle.make.lower():
                score += 40
                reasons.append(f"Make match: {target.make}")
            else:
                return 0.0, ["Make mismatch"]
       
        # Model match
        max_score += 20
        if target.model and policy_vehicle.model:
            if target.model.lower() == policy_vehicle.model.lower():
                score += 20
                reasons.append(f"Model match: {target.model}")
            else:
                score += 5  # Partial credit for having model info
        elif not policy_vehicle.model:  # Policy covers all models
            score += 15
            reasons.append("Generic model coverage")
       
        # Year match
        max_score += 15
        if target.year and policy_vehicle.year:
            year_diff = abs(target.year - policy_vehicle.year)
            if year_diff == 0:
                score += 15
                reasons.append(f"Exact year match: {target.year}")
            elif year_diff <= 2:
                score += 10
                reasons.append(f"Close year match: {target.year} vs {policy_vehicle.year}")
            elif year_diff <= 5:
                score += 5
                reasons.append(f"Approximate year match: {target.year} vs {policy_vehicle.year}")
        elif not policy_vehicle.year:  # Policy covers all years
            score += 10
            reasons.append("Generic year coverage")
       
        # Engine match
        max_score += 10
        if target.engine and policy_vehicle.engine:
            if target.engine.lower() == policy_vehicle.engine.lower():
                score += 10
                reasons.append(f"Engine match: {target.engine}")
        elif not policy_vehicle.engine:
            score += 5
       
        # VIN pattern match
        max_score += 15
        if target.vin_pattern and policy_vehicle.vin_pattern:
            if re.match(policy_vehicle.vin_pattern, target.vin_pattern):
                score += 15
                reasons.append("VIN pattern match")
       
        # Normalize score
        confidence = score / max_score if max_score > 0 else 0.0
       
        return confidence, reasons


class PolicyInterpreter:
    """Interprets diagnostic data using policies"""
   
    def __init__(self, policy: DiagnosticPolicy):
        self.policy = policy
   
    def interpret_dtc(self, dtc_code: str) -> InterpretationResult:
        """Interpret diagnostic trouble code using policy"""
        # Look up manufacturer-specific interpretation
        dtc_info = self.policy.dtc_mappings.get(dtc_code, {})
       
        if dtc_info:
            # Apply manufacturer-specific context
            interpreted_value = {
                'code': dtc_code,
                'manufacturer_description': dtc_info.get('description', ''),
                'severity': dtc_info.get('severity', 'warning'),
                'category': dtc_info.get('category', 'generic'),
                'system': dtc_info.get('system', 'unknown'),
                'common_causes': dtc_info.get('common_causes', []),
                'diagnostic_steps': dtc_info.get('diagnostic_steps', [])
            }
           
            severity = PolicySeverity(dtc_info.get('severity', 'warning'))
            recommendations = dtc_info.get('recommendations', [])
           
        else:
            # Fall back to generic interpretation
            interpreted_value = {
                'code': dtc_code,
                'generic_description': self._get_generic_dtc_description(dtc_code),
                'severity': 'warning',
                'category': 'generic'
            }
           
            severity = PolicySeverity.WARNING
            recommendations = ["Consult service manual for manufacturer-specific information"]
       
        return InterpretationResult(
            original_value=dtc_code,
            interpreted_value=interpreted_value,
            context={'policy_id': self.policy.policy_id, 'vehicle': self.policy.vehicle_identifier.make},
            severity=severity,
            recommendations=recommendations,
            applicable_rules=[],
            metadata={'source': 'policy_interpretation'}
        )
   
    def interpret_parameter(self, pid: int, value: float, unit: str = None) -> InterpretationResult:
        """Interpret parameter value using policy"""
        pid_hex = f"{pid:02X}"
        param_info = self.policy.parameter_ranges.get(pid_hex, {})
       
        if param_info:
            # Check against manufacturer-specific ranges
            normal_min = param_info.get('normal_min')
            normal_max = param_info.get('normal_max')
            warning_min = param_info.get('warning_min')
            warning_max = param_info.get('warning_max')
            critical_min = param_info.get('critical_min')
            critical_max = param_info.get('critical_max')
           
            severity = PolicySeverity.INFO
            recommendations = []
           
            # Determine severity based on ranges
            if (critical_min is not None and value < critical_min) or \
               (critical_max is not None and value > critical_max):
                severity = PolicySeverity.CRITICAL
                recommendations.append(f"Critical {param_info.get('name', f'PID {pid_hex}')} reading")
                recommendations.extend(param_info.get('critical_actions', []))
               
            elif (warning_min is not None and value < warning_min) or \
                 (warning_max is not None and value > warning_max):
                severity = PolicySeverity.WARNING
                recommendations.append(f"Warning {param_info.get('name', f'PID {pid_hex}')} reading")
                recommendations.extend(param_info.get('warning_actions', []))
           
            interpreted_value = {
                'pid': pid,
                'value': value,
                'unit': unit or param_info.get('unit'),
                'parameter_name': param_info.get('name', f'PID_{pid_hex}'),
                'status': severity.value,
                'normal_range': {
                    'min': normal_min,
                    'max': normal_max
                },
                'context': param_info.get('context', '')
            }
           
        else:
            # No policy-specific information
            interpreted_value = {
                'pid': pid,
                'value': value,
                'unit': unit,
                'status': 'unknown',
                'note': 'No manufacturer-specific interpretation available'
            }
           
            severity = PolicySeverity.INFO
            recommendations = []
       
        return InterpretationResult(
            original_value=value,
            interpreted_value=interpreted_value,
            context={'policy_id': self.policy.policy_id, 'pid': pid},
            severity=severity,
            recommendations=recommendations,
            applicable_rules=[],
            metadata={'source': 'policy_interpretation'}
        )
   
    def _get_generic_dtc_description(self, dtc_code: str) -> str:
        """Get generic DTC description"""
        # Basic DTC patterns
        if dtc_code.startswith('P0'):
            return "Powertrain - Generic (SAE J2012)"
        elif dtc_code.startswith('P1') or dtc_code.startswith('P2'):
            return "Powertrain - Manufacturer specific"
        elif dtc_code.startswith('C0'):
            return "Chassis - Generic (SAE J2012)"
        elif dtc_code.startswith('B0'):
            return "Body - Generic (SAE J2012)"
        elif dtc_code.startswith('U0'):
            return "Network - Generic (SAE J2012)"
        else:
            return f"Diagnostic Trouble Code: {dtc_code}"


class MIC3X2XPolicyManager:
    """Main policy management system for MIC3X2X"""
   
    def __init__(self, policy_directory: str = "policies"):
        self.policy_loader = PolicyLoader(policy_directory)
        self.policies: Dict[str, DiagnosticPolicy] = {}
        self.policy_matcher = PolicyMatcher(self.policies)
        self.active_interpreters: Dict[str, PolicyInterpreter] = {}
       
        # Load all policies
        self.reload_policies()
   
    def reload_policies(self) -> int:
        """Reload all policy files"""
        logger.info("Reloading diagnostic policies", category=LogCategory.SYSTEM)
       
        self.policies = self.policy_loader.load_all_policies()
        self.policy_matcher = PolicyMatcher(self.policies)
       
        logger.info(f"Loaded {len(self.policies)} diagnostic policies")
        return len(self.policies)
   
    def get_policy_for_vehicle(self, vehicle_info: Dict[str, Any]) -> Optional[DiagnosticPolicy]:
        """Get best matching policy for vehicle"""
        return self.policy_matcher.get_best_policy(vehicle_info)
   
    def create_interpreter(self, vehicle_info: Dict[str, Any]) -> Optional[PolicyInterpreter]:
        """Create policy interpreter for vehicle"""
        policy = self.get_policy_for_vehicle(vehicle_info)
       
        if policy:
            interpreter = PolicyInterpreter(policy)
            # Cache interpreter for reuse
            vehicle_key = f"{vehicle_info.get('make', 'unknown')}_{vehicle_info.get('model', 'unknown')}"
            self.active_interpreters[vehicle_key] = interpreter
            return interpreter
       
        return None
   
    def interpret_diagnostic_data(self, vehicle_info: Dict[str, Any],
                                data_points: List[OBDDataPoint],
                                dtcs: List[DiagnosticTroubleCode]) -> Dict[str, Any]:
        """Interpret diagnostic data using appropriate policy"""
        interpreter = self.create_interpreter(vehicle_info)
       
        if not interpreter:
            logger.warning("No policy found for vehicle", category=LogCategory.DATA)
            return {
                'interpreted_data': [],
                'interpreted_dtcs': [],
                'policy_info': None,
                'warnings': ['No manufacturer-specific policy available']
            }
       
        interpreted_data = []
        interpreted_dtcs = []
       
        # Interpret data points
        for data_point in data_points:
            if data_point.interpreted_value is not None:
                result = interpreter.interpret_parameter(
                    data_point.pid,
                    data_point.interpreted_value,
                    data_point.unit
                )
                interpreted_data.append({
                    'original': {
                        'pid': data_point.pid,
                        'name': data_point.name,
                        'value': data_point.interpreted_value,
                        'unit': data_point.unit
                    },
                    'interpretation': result.interpreted_value,
                    'severity': result.severity.value,
                    'recommendations': result.recommendations
                })
       
        # Interpret DTCs
        for dtc in dtcs:
            result = interpreter.interpret_dtc(dtc.code)
            interpreted_dtcs.append({
                'original': {
                    'code': dtc.code,
                    'description': dtc.description,
                    'status': dtc.status.value
                },
                'interpretation': result.interpreted_value,
                'severity': result.severity.value,
                'recommendations': result.recommendations
            })
       
        return {
            'interpreted_data': interpreted_data,
            'interpreted_dtcs': interpreted_dtcs,
            'policy_info': {
                'policy_id': interpreter.policy.policy_id,
                'policy_name': interpreter.policy.name,
                'vehicle_coverage': interpreter.policy.vehicle_identifier.make
            },
            'warnings': []
        }
   
    def list_available_policies(self) -> List[Dict[str, Any]]:
        """List all available policies"""
        policy_list = []
       
        for policy in self.policies.values():
            policy_list.append({
                'policy_id': policy.policy_id,
                'name': policy.name,
                'version': policy.version,
                'make': policy.vehicle_identifier.make,
                'model': policy.vehicle_identifier.model,
                'year_range': policy.vehicle_identifier.year,
                'rules_count': len(policy.rules),
                'dtc_mappings_count': len(policy.dtc_mappings),
                'parameter_ranges_count': len(policy.parameter_ranges)
            })
       
        return policy_list


def create_sample_policy() -> Dict[str, Any]:
    """Create sample policy file structure"""
    return {
        "policy_id": "nissan_leaf_2018_2022",
        "name": "Nissan Leaf 2018-2022 Diagnostic Policy",
        "version": "1.0.0",
        "vehicle_identifier": {
            "make": "Nissan",
            "model": "Leaf",
            "year": 2020,
            "engine": "Electric",
            "vin_pattern": "1N4.*",
            "market": "US"
        },
        "rules": [
            {
                "rule_id": "battery_temp_critical",
                "rule_type": "parameter_range",
                "name": "Battery Temperature Critical",
                "description": "Monitor lithium-ion battery temperature",
                "conditions": {
                    "pid": "0x2E",
                    "operator": ">",
                    "value": 60,
                    "unit": "celsius"
                },
                "actions": {
                    "alert": "Critical battery temperature",
                    "recommendation": "Stop vehicle immediately"
                },
                "severity": "critical",
                "enabled": True
            }
        ],
        "dtc_mappings": {
            "P3101": {
                "description": "Electric Motor Control Module Performance",
                "severity": "warning",
                "category": "electric_drivetrain",
                "system": "motor_control",
                "common_causes": [
                    "Motor control module fault",
                    "High voltage system issue",
                    "Temperature sensor fault"
                ],
                "recommendations": [
                    "Check high voltage connections",
                    "Verify motor temperature sensors",
                    "Update motor control module software"
                ]
            }
        },
        "parameter_ranges": { 
