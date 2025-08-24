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

MIC3X2X Logging System Module

Comprehensive logging, monitoring, and diagnostics system for MIC3X2X operations.
Provides structured logging, performance metrics, error tracking, and system health monitoring.

Features:
- Multi-level structured logging with context
- Performance metrics and timing analysis
- Error tracking and categorization
- System health monitoring
- Log rotation and archival
- Real-time log streaming
- Configurable output formats
"""

import logging
import logging.handlers
import time
import threading
import queue
import json
import traceback
import psutil
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import struct
import gzip

try:
    import colorlog
    COLORLOG_AVAILABLE = True
except ImportError:
    COLORLOG_AVAILABLE = False


class LogLevel(Enum):
    """Extended log levels for MIC3X2X operations"""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class LogCategory(Enum):
    """Log categories for filtering and analysis"""
    SYSTEM = "system"
    DEVICE = "device"
    PROTOCOL = "protocol"
    DATA = "data"
    COMMUNICATION = "communication"
    PERFORMANCE = "performance"
    ERROR = "error"
    SECURITY = "security"
    USER = "user"


@dataclass
class LogEntry:
    """Structured log entry"""
    timestamp: datetime
    level: str
    category: LogCategory
    module: str
    message: str
    context: Dict[str, Any]
    thread_id: int
    process_id: int
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
   
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'category': self.category.value,
            'module': self.module,
            'message': self.message,
            'context': self.context,
            'thread_id': self.thread_id,
            'process_id': self.process_id,
            'device_id': self.device_id,
            'session_id': self.session_id,
            'correlation_id': self.correlation_id
        }


@dataclass
class PerformanceMetric:
    """Performance measurement data"""
    name: str
    value: float
    unit: str
    timestamp: datetime
    category: str
    context: Dict[str, Any]
   
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value': self.value,
            'unit': self.unit,
            'timestamp': self.timestamp.isoformat(),
            'category': self.category,
            'context': self.context
        }


@dataclass
class SystemHealth:
    """System health metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_available: int
    disk_usage_percent: float
    thread_count: int
    open_files: int
    network_connections: int
    uptime_seconds: float
   
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging"""
   
    def __init__(self, include_context: bool = True):
        super().__init__()
        self.include_context = include_context
       
    def format(self, record: logging.LogRecord) -> str:
        # Create base log entry
        timestamp = datetime.fromtimestamp(record.created)
       
        # Extract context from record
        context = {}
        if hasattr(record, 'context'):
            context = record.context
       
        # Extract additional fields
        device_id = getattr(record, 'device_id', None)
        session_id = getattr(record, 'session_id', None)
        correlation_id = getattr(record, 'correlation_id', None)
        category = getattr(record, 'category', LogCategory.SYSTEM)
       
        log_entry = LogEntry(
            timestamp=timestamp,
            level=record.levelname,
            category=category,
            module=record.name,
            message=record.getMessage(),
            context=context,
            thread_id=record.thread,
            process_id=record.process,
            device_id=device_id,
            session_id=session_id,
            correlation_id=correlation_id
        )
       
        return json.dumps(log_entry.to_dict(), default=str)


class ColoredConsoleFormatter(logging.Formatter):
    """Colored console formatter for development"""
   
    def __init__(self):
        if COLORLOG_AVAILABLE:
            super().__init__()
            self.formatter = colorlog.ColoredFormatter(
                '%(log_color)s%(asctime)s [%(levelname)-8s] %(name)-20s: %(message)s',
                datefmt='%H:%M:%S',
                log_colors={
                    'DEBUG': 'cyan',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'bold_red',
                }
            )
        else:
            super().__init__(
                '%(asctime)s [%(levelname)-8s] %(name)-20s: %(message)s',
                datefmt='%H:%M:%S'
            )
            self.formatter = self
   
    def format(self, record: logging.LogRecord) -> str:
        return self.formatter.format(record)


class PerformanceTimer:
    """Context manager for timing operations"""
   
    def __init__(self, name: str, logger: 'MIC3X2XLogger', category: str = "general",
                 context: Dict[str, Any] = None):
        self.name = name
        self.logger = logger
        self.category = category
        self.context = context or {}
        self.start_time = None
        self.end_time = None
   
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
   
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        duration = (self.end_time - self.start_time) * 1000  # Convert to milliseconds
       
        # Log performance metric
        metric = PerformanceMetric(
            name=self.name,
            value=duration,
            unit="ms",
            timestamp=datetime.now(),
            category=self.category,
            context=self.context
        )
       
        self.logger.log_performance(metric)
       
        # Also log as regular message if duration is significant
        if duration > 1000:  # More than 1 second
            self.logger.warning(f"Slow operation: {self.name} took {duration:.1f}ms",
                              category=LogCategory.PERFORMANCE,
                              context={'duration_ms': duration})


class LogBuffer:
    """Thread-safe circular buffer for log entries"""
   
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.buffer = []
        self.lock = threading.RLock()
        self.index = 0
   
    def add(self, entry: LogEntry):
        """Add entry to buffer"""
        with self.lock:
            if len(self.buffer) < self.max_size:
                self.buffer.append(entry)
            else:
                self.buffer[self.index] = entry
                self.index = (self.index + 1) % self.max_size
   
    def get_recent(self, count: int = 100) -> List[LogEntry]:
        """Get recent entries"""
        with self.lock:
            if len(self.buffer) <= count:
                return self.buffer.copy()
            else:
                if self.index == 0:
                    return self.buffer[-count:]
                else:
                    # Handle circular buffer
                    return (self.buffer[self.index:] + self.buffer[:self.index])[-count:]
   
    def filter_by_level(self, min_level: LogLevel) -> List[LogEntry]:
        """Filter entries by minimum level"""
        with self.lock:
            filtered = []
            level_values = {
                'TRACE': 5, 'DEBUG': 10, 'INFO': 20,
                'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50
            }
            min_value = level_values.get(min_level.name, 20)
           
            for entry in self.buffer:
                entry_value = level_values.get(entry.level, 20)
                if entry_value >= min_value:
                    filtered.append(entry)
           
            return filtered
   
    def filter_by_category(self, category: LogCategory) -> List[LogEntry]:
        """Filter entries by category"""
        with self.lock:
            return [entry for entry in self.buffer if entry.category == category]


class SystemMonitor:
    """System health monitoring"""
   
    def __init__(self, logger: 'MIC3X2XLogger'):
        self.logger = logger
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.monitor_interval = 60.0  # seconds
        self.start_time = time.time()
       
    def start_monitoring(self, interval: float = 60.0):
        """Start system monitoring"""
        if self.monitoring:
            return
       
        self.monitor_interval = interval
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_worker, daemon=True)
        self.monitor_thread.start()
        self.logger.info("System monitoring started", category=LogCategory.SYSTEM)
   
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        self.logger.info("System monitoring stopped", category=LogCategory.SYSTEM)
   
    def _monitor_worker(self):
        """Background monitoring worker"""
        while self.monitoring:
            try:
                health = self._collect_health_metrics()
                self.logger.log_system_health(health)
               
                # Check for critical conditions
                self._check_health_thresholds(health)
               
            except Exception as e:
                self.logger.error(f"System monitoring error: {e}",
                                category=LogCategory.ERROR,
                                context={'error': str(e), 'traceback': traceback.format_exc()})
           
            # Sleep with monitoring check
            for _ in range(int(self.monitor_interval)):
                if not self.monitoring:
                    break
                time.sleep(1.0)
   
    def _collect_health_metrics(self) -> SystemHealth:
        """Collect system health metrics"""
        process = psutil.Process()
       
        return SystemHealth(
            timestamp=datetime.now(),
            cpu_percent=psutil.cpu_percent(interval=1),
            memory_percent=psutil.virtual_memory().percent,
            memory_available=psutil.virtual_memory().available,
            disk_usage_percent=psutil.disk_usage('/').percent,
            thread_count=process.num_threads(),
            open_files=len(process.open_files()),
            network_connections=len(process.connections()),
            uptime_seconds=time.time() - self.start_time
        )
   
    def _check_health_thresholds(self, health: SystemHealth):
        """Check for critical system conditions"""
        warnings = []
       
        if health.cpu_percent > 90:
            warnings.append(f"High CPU usage: {health.cpu_percent:.1f}%")
       
        if health.memory_percent > 90:
            warnings.append(f"High memory usage: {health.memory_percent:.1f}%")
       
        if health.disk_usage_percent > 95:
            warnings.append(f"Low disk space: {health.disk_usage_percent:.1f}% used")
       
        if health.thread_count > 100:
            warnings.append(f"High thread count: {health.thread_count}")
       
        if health.open_files > 500:
            warnings.append(f"High open file count: {health.open_files}")
       
        for warning in warnings:
            self.logger.warning(warning, category=LogCategory.SYSTEM,
                              context=health.to_dict())


class MIC3X2XLogger:
    """Main logging system for MIC3X2X operations"""
   
    def __init__(self, log_dir: str = "logs", app_name: str = "MIC3X2X"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.app_name = app_name
       
        # Internal state
        self.loggers: Dict[str, logging.Logger] = {}
        self.log_buffer = LogBuffer()
        self.performance_metrics: List[PerformanceMetric] = []
        self.system_monitor = SystemMonitor(self)
       
        # Thread-local storage for context
        self.local_context = threading.local()
       
        # Setup main logger
        self._setup_loggers()
       
        # Start system monitoring
        self.system_monitor.start_monitoring()
       
        self.info("MIC3X2X Logging System initialized", category=LogCategory.SYSTEM)
   
    def _setup_loggers(self):
        """Setup logging infrastructure"""
        # Create main application logger
        main_logger = self._create_logger(self.app_name, logging.INFO)
        self.loggers['main'] = main_logger
       
        # Create category-specific loggers
        for category in LogCategory:
            logger_name = f"{self.app_name}.{category.value}"
            logger = self._create_logger(logger_name, logging.DEBUG)
            self.loggers[category.value] = logger
   
    def _create_logger(self, name: str, level: int) -> logging.Logger:
        """Create configured logger"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
       
        # Remove existing handlers
        logger.handlers.clear()
       
        # Console handler with colors (for development)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(ColoredConsoleFormatter())
        console_handler.setLevel(logging.INFO)
        logger.addHandler(console_handler)
       
        # File handler with JSON format
        log_file = self.log_dir / f"{name.replace('.', '_')}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setFormatter(StructuredFormatter())
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)
       
        # Compressed archive handler for long-term storage
        archive_file = self.log_dir / f"{name.replace('.', '_')}_archive.log.gz"
        archive_handler = logging.handlers.RotatingFileHandler(
            archive_file, maxBytes=50*1024*1024, backupCount=10
        )
        archive_handler.setFormatter(StructuredFormatter())
        archive_handler.setLevel(logging.INFO)
        logger.addHandler(archive_handler)
       
        # Custom handler for log buffer
        buffer_handler = LogBufferHandler(self.log_buffer)
        buffer_handler.setLevel(logging.DEBUG)
        logger.addHandler(buffer_handler)
       
        logger.propagate = False
        return logger
   
    def set_context(self, **context):
        """Set thread-local logging context"""
        if not hasattr(self.local_context, 'data'):
            self.local_context.data = {}
        self.local_context.data.update(context)
   
    def clear_context(self):
        """Clear thread-local logging context"""
        if hasattr(self.local_context, 'data'):
            self.local_context.data.clear()
   
    def get_context(self) -> Dict[str, Any]:
        """Get current thread-local context"""
        if hasattr(self.local_context, 'data'):
            return self.local_context.data.copy()
        return {}
   
    def _log_with_context(self, logger: logging.Logger, level: int, message: str,
                         category: LogCategory, context: Dict[str, Any] = None,
                         device_id: str = None, session_id: str = None,
                         correlation_id: str = None):
        """Log message with context"""
        # Merge contexts
        full_context = self.get_context()
        if context:
            full_context.update(context)
       
        # Create log record
        record = logger.makeRecord(
            logger.name, level, __file__, 0, message, (), None
        )
       
        # Add custom attributes
        record.context = full_context
        record.category = category
        record.device_id = device_id
        record.session_id = session_id
        record.correlation_id = correlation_id
       
        logger.handle(record)
   
    def trace(self, message: str, category: LogCategory = LogCategory.SYSTEM,
             context: Dict[str, Any] = None, **kwargs):
        """Log trace message"""
        logger = self.loggers.get(category.value, self.loggers['main'])
        self._log_with_context(logger, 5, message, category, context, **kwargs)
   
    def debug(self, message: str, category: LogCategory = LogCategory.SYSTEM,
             context: Dict[str, Any] = None, **kwargs):
        """Log debug message"""
        logger = self.loggers.get(category.value, self.loggers['main'])
        self._log_with_context(logger, logging.DEBUG, message, category, context, **kwargs)
   
    def info(self, message: str, category: LogCategory = LogCategory.SYSTEM,
            context: Dict[str, Any] = None, **kwargs):
        """Log info message"""
        logger = self.loggers.get(category.value, self.loggers['main'])
        self._log_with_context(logger, logging.INFO, message, category, context, **kwargs)
   
    def warning(self, message: str, category: LogCategory = LogCategory.SYSTEM,
               context: Dict[str, Any] = None, **kwargs):
        """Log warning message"""
        logger = self.loggers.get(category.value, self.loggers['main'])
        self._log_with_context(logger, logging.WARNING, message, category, context, **kwargs)
   
    def error(self, message: str, category: LogCategory = LogCategory.ERROR,
             context: Dict[str, Any] = None, **kwargs):
        """Log error message"""
        logger = self.loggers.get(category.value, self.loggers['main'])
        self._log_with_context(logger, logging.ERROR, message, category, context, **kwargs)
   
    def critical(self, message: str, category: LogCategory = LogCategory.ERROR,
                context: Dict[str, Any] = None, **kwargs):
        """Log critical message"""
        logger = self.loggers.get(category.value, self.loggers['main'])
        self._log_with_context(logger, logging.CRITICAL, message, category, context, **kwargs)
   
    def log_performance(self, metric: PerformanceMetric):
        """Log performance metric"""
        self.performance_metrics.append(metric)
       
        # Keep only recent metrics (last hour)
        cutoff_time = datetime.now() - timedelta(hours=1)
        self.performance_metrics = [m for m in self.performance_metrics if m.timestamp >= cutoff_time]
       
        # Log significant metrics
        if metric.value > 1000 or metric.category in ['critical', 'slow']:
            self.warning(f"Performance metric: {metric.name} = {metric.value}{metric.unit}",
                        category=LogCategory.PERFORMANCE,
                        context=metric.to_dict())
   
    def log_system_health(self, health: SystemHealth):
        """Log system health metrics"""
        self.debug(f"System health: CPU {health.cpu_percent:.1f}%, "
                  f"Memory {health.memory_percent:.1f}%, "
                  f"Threads {health.thread_count}",
                  category=LogCategory.SYSTEM,
                  context=health.to_dict())
   
    def timer(self, name: str, category: str = "general",
             context: Dict[str, Any] = None) -> PerformanceTimer:
        """Create performance timer context manager"""
        return PerformanceTimer(name, self, category, context)
   
    def log_device_event(self, event: str, device_id: str,
                        context: Dict[str, Any] = None):
        """Log device-specific event"""
        self.info(f"Device event: {event}",
                 category=LogCategory.DEVICE,
                 context=context,
                 device_id=device_id)
   
    def log_protocol_event(self, event: str, protocol: str,
                          context: Dict[str, Any] = None):
        """Log protocol-specific event"""
        self.info(f"Protocol event: {event} ({protocol})",
                 category=LogCategory.PROTOCOL,
                 context=context)
   
    def log_communication_event(self, event: str, direction: str, data_size: int,
                               context: Dict[str, Any] = None):
        """Log communication event"""
        self.debug(f"Communication: {event} ({direction}, {data_size} bytes)",
                  category=LogCategory.COMMUNICATION,
                  context=context)
   
    def get_recent_logs(self, count: int = 100,
                       min_level: LogLevel = LogLevel.INFO) -> List[Dict[str, Any]]:
        """Get recent log entries"""
        entries = self.log_buffer.get_recent(count)
        filtered = [e for e in entries if self._level_value(e.level) >= min_level.value]
        return [entry.to_dict() for entry in filtered]
   
    def get_logs_by_category(self, category: LogCategory,
                            count: int = 100) -> List[Dict[str, Any]]:
        """Get logs filtered by category"""
        entries = self.log_buffer.filter_by_category(category)[-count:]
        return [entry.to_dict() for entry in entries]
   
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance metrics summary"""
        if not self.performance_metrics:
            return {}
       
        # Group by category
        by_category = {}
        for metric in self.performance_metrics:
            if metric.category not in by_category:
                by_category[metric.category] = []
            by_category[metric.category].append(metric.value)
       
        # Calculate statistics
        summary = {}
        for category, values in by_category.items():
            if values:
                summary[category] = {
                    'count': len(values),
                    'avg': sum(values) / len(values),
                    'min': min(values),
                    'max': max(values),
                    'recent': values[-10:]  # Last 10 values
                }
       
        return summary
   
    def _level_value(self, level_name: str) -> int:
        """Convert level name to numeric value"""
        level_map = {
            'TRACE': 5, 'DEBUG': 10, 'INFO': 20,
            'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50
        }
        return level_map.get(level_name, 20)
   
    def export_logs(self, filename: str, start_time: datetime = None,
                   end_time: datetime = None, categories: List[LogCategory] = None):
        """Export logs to file"""
        entries = self.log_buffer.get_recent(10000)  # Get more entries for export
       
        # Filter by time range
        if start_time or end_time:
            filtered = []
            for entry in entries:
                if start_time and entry.timestamp < start_time:
                    continue
                if end_time and entry.timestamp > end_time:
                    continue
                filtered.append(entry)
            entries = filtered
       
        # Filter by categories
        if categories:
            entries = [e for e in entries if e.category in categories]
       
        # Write to file
        export_path = self.log_dir / filename
        with open(export_path, 'w') as f:
            for entry in entries:
                json.dump(entry.to_dict(), f, default=str)
                f.write('\n')
       
        self.info(f"Exported {len(entries)} log entries to {export_path}",
                 category=LogCategory.SYSTEM)
       
        return str(export_path)
   
    def cleanup(self):
        """Cleanup logging system"""
        self.info("Shutting down logging system", category=LogCategory.SYSTEM)
       
        # Stop monitoring
        self.system_monitor.stop_monitoring()
       
        # Close all handlers
        for logger in self.loggers.values():
            for handler in logger.handlers:
                handler.close()
       
        # Clear loggers
        self.loggers.clear()


class LogBufferHandler(logging.Handler):
    """Custom handler for log buffer"""
   
    def __init__(self, log_buffer: LogBuffer):
        super().__init__()
        self.log_buffer = log_buffer
   
    def emit(self, record: logging.LogRecord):
        """Emit log record to buffer"""
        try:
            # Extract context
            context = getattr(record, 'context', {})
            category = getattr(record, 'category', LogCategory.SYSTEM)
            device_id = getattr(record, 'device_id', None)
            session_id = getattr(record, 'session_id', None)
            correlation_id = getattr(record, 'correlation_id', None)
           
            # Create log entry
            entry = LogEntry(
                timestamp=datetime.fromtimestamp(record.created),
                level=record.levelname,
                category=category,
                module=record.name,
                message=record.getMessage(),
                context=context,
                thread_id=record.thread,
                process_id=record.process,
                device_id=device_id,
                session_id=session_id,
                correlation_id=correlation_id
            )
           
            self.log_buffer.add(entry)
           
        except Exception:
            self.handleError(record)


# Singleton instance
_logger_instance: Optional[MIC3X2XLogger] = None


def get_logger(log_dir: str = "logs", app_name: str = "MIC3X2X") -> MIC3X2XLogger:
    """Get singleton logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = MIC3X2XLogger(log_dir, app_name)
    return _logger_instance


def setup_logging(log_dir: str = "logs", app_name: str = "MIC3X2X",
                 console_level: str = "INFO") -> MIC3X2XLogger:
    """Setup logging system with configuration"""
    logger_instance = get_logger(log_dir, app_name)
   
    # Adjust console logging level
    level_map = {
        'TRACE': 5, 'DEBUG': logging.DEBUG, 'INFO': logging.INFO,
        'WARNING': logging.WARNING, 'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL
    }
   
    console_log_level = level_map.get(console_level.upper(), logging.INFO)
   
    # Update console handlers
    for logger in logger_instance.loggers.values():
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                handler.setLevel(console_log_level)
   
    return logger_instance


# Context manager for logging context
class LoggingContext:
    """Context manager for setting logging context"""
   
    def __init__(self, **context):
        self.context = context
        self.logger = get_logger()
        self.previous_context = None
   
    def __enter__(self):
        self.previous_context = self.logger.get_context()
        self.logger.set_context(**self.context)
        return self
   
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.clear_context()
        if self.previous_context:
            self.logger.set_context(**self.previous_context) 
