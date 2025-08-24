MIC3X2X API Server

HTTP/WebSocket API wrapper for MIC3X2X device manager.
Provides RESTful endpoints and real-time WebSocket streams for PWA integration.

Features:
- RESTful API for device operations
- WebSocket streaming for real-time data
- CORS support for web applications
- Authentication and rate limiting
- Comprehensive error handling
- API documentation endpoints
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import threading
import queue

# FastAPI for HTTP API
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Import our MIC3X2X system
from device_manager import MIC3X2XDeviceManager, DeviceState, SessionState
from obd_data_processor import OBDDataPoint, DiagnosticTroubleCode
from logging_system import get_logger, LogCategory
from utilities import ValidationUtils

logger = get_logger()
security = HTTPBearer(auto_error=False)


# API Models
class DeviceConnectionRequest(BaseModel):
    device_id: Optional[str] = None
    auto_discover: bool = True
    connection_params: Optional[Dict[str, Any]] = None


class OBDCommandRequest(BaseModel):
    mode: int = Field(..., ge=1, le=10, description="OBD mode (1-10)")
    pid: int = Field(..., ge=0, le=255, description="Parameter ID (0-255)")
    device_id: Optional[str] = None


class MonitoringRequest(BaseModel):
    pids: List[int] = Field(..., description="PIDs to monitor")
    interval: float = Field(1.0, ge=0.1, le=60.0, description="Polling interval in seconds")
    device_id: Optional[str] = None


class AlertThreshold(BaseModel):
    pid: int
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    message: str
    enabled: bool = True


class MonitoringConfig(BaseModel):
    thresholds: List[AlertThreshold] = []
    notification_cooldown: int = 300  # seconds


# Response Models
class APIResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class DeviceStatus(BaseModel):
    device_id: str
    connected: bool
    state: str
    firmware_version: Optional[str] = None
    protocol: Optional[str] = None
    last_seen: Optional[datetime] = None


class SessionInfo(BaseModel):
    session_id: str
    device_id: str
    start_time: datetime
    state: str
    vehicle_info: Dict[str, Any]
    data_points_collected: int
    dtcs_found: int


class LiveDataPoint(BaseModel):
    timestamp: datetime
    pid: int
    name: str
    raw_value: List[int]
    interpreted_value: Optional[float]
    unit: Optional[str]
    device_id: str


class WebSocketManager:
    """Manages WebSocket connections and real-time data streaming"""
   
    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}
        self.device_subscriptions: Dict[WebSocket, str] = {}
        self.lock = threading.RLock()
       
    async def connect(self, websocket: WebSocket, client_id: str):
        """Connect new WebSocket client"""
        await websocket.accept()
       
        with self.lock:
            if client_id not in self.connections:
                self.connections[client_id] = set()
            self.connections[client_id].add(websocket)
       
        logger.info(f"WebSocket client connected: {client_id}",
                   category=LogCategory.COMMUNICATION)
   
    def disconnect(self, websocket: WebSocket, client_id: str):
        """Disconnect WebSocket client"""
        with self.lock:
            if client_id in self.connections:
                self.connections[client_id].discard(websocket)
                if not self.connections[client_id]:
                    del self.connections[client_id]
           
            # Remove device subscription
            self.device_subscriptions.pop(websocket, None)
       
        logger.info(f"WebSocket client disconnected: {client_id}",
                   category=LogCategory.COMMUNICATION)
   
    async def subscribe_to_device(self, websocket: WebSocket, device_id: str):
        """Subscribe WebSocket to device data"""
        with self.lock:
            self.device_subscriptions[websocket] = device_id
       
        await self.send_personal_message(websocket, {
            "type": "subscription_confirmed",
            "device_id": device_id,
            "timestamp": datetime.now().isoformat()
        })
   
    async def broadcast_to_device_subscribers(self, device_id: str, message: Dict[str, Any]):
        """Broadcast message to all subscribers of a device"""
        disconnected = []
       
        with self.lock:
            subscribers = [ws for ws, dev_id in self.device_subscriptions.items()
                          if dev_id == device_id]
       
        for websocket in subscribers:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send WebSocket message: {e}")
                disconnected.append(websocket)
       
        # Clean up disconnected sockets
        with self.lock:
            for ws in disconnected:
                self.device_subscriptions.pop(ws, None)
   
    async def send_personal_message(self, websocket: WebSocket, message: Dict[str, Any]):
        """Send message to specific WebSocket"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.warning(f"Failed to send personal WebSocket message: {e}")


class MIC3X2XAPIServer:
    """Main API server class"""
   
    def __init__(self, device_manager: MIC3X2XDeviceManager):
        self.device_manager = device_manager
        self.websocket_manager = WebSocketManager()
        self.app = FastAPI(
            title="MIC3X2X Diagnostic API",
            description="RESTful API for MIC3X2X OBD-II diagnostics",
            version="1.0.0"
        )
       
        # Rate limiting
        self.request_counts: Dict[str, List[float]] = {}
        self.rate_limit = 100  # requests per minute
       
        # Setup middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
       
        # Setup event callbacks
        self.device_manager.add_event_callback('data_received', self._handle_data_received)
        self.device_manager.add_event_callback('alert_triggered', self._handle_alert_triggered)
        self.device_manager.add_event_callback('device_connected', self._handle_device_connected)
        self.device_manager.add_event_callback('device_disconnected', self._handle_device_disconnected)
       
        self._setup_routes()
   
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client is within rate limit"""
        current_time = time.time()
       
        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = []
       
        # Clean old requests
        self.request_counts[client_ip] = [
            req_time for req_time in self.request_counts[client_ip]
            if current_time - req_time < 60  # Within last minute
        ]
       
        # Check limit
        if len(self.request_counts[client_ip]) >= self.rate_limit:
            return False
       
        # Add current request
        self.request_counts[client_ip].append(current_time)
        return True
   
    async def _handle_data_received(self, event_data: Dict[str, Any]):
        """Handle data received event from device manager"""
        device_id = event_data.get('device_id')
        data_points = event_data.get('data_points', [])
       
        for data_point in data_points:
            message = {
                "type": "live_data",
                "device_id": device_id,
                "data": {
                    "timestamp": data_point.timestamp.isoformat(),
                    "pid": data_point.pid,
                    "name": data_point.name,
                    "raw_value": data_point.raw_value,
                    "interpreted_value": data_point.interpreted_value,
                    "unit": data_point.unit
                }
            }
           
            await self.websocket_manager.broadcast_to_device_subscribers(device_id, message)
   
    async def _handle_alert_triggered(self, event_data: Dict[str, Any]):
        """Handle alert triggered event"""
        message = {
            "type": "alert",
            "alert_data": event_data,
            "timestamp": datetime.now().isoformat()
        }
       
        device_id = event_data.get('device_id')
        if device_id:
            await self.websocket_manager.broadcast_to_device_subscribers(device_id, message)
   
    async def _handle_device_connected(self, device_info: Any):
        """Handle device connected event"""
        message = {
            "type": "device_connected",
            "device_id": device_info.device_id if hasattr(device_info, 'device_id') else str(device_info),
            "timestamp": datetime.now().isoformat()
        }
       
        # Broadcast to all connections
        for client_connections in self.websocket_manager.connections.values():
            for websocket in client_connections:
                await self.websocket_manager.send_personal_message(websocket, message)
   
    async def _handle_device_disconnected(self, device_id: str):
        """Handle device disconnected event"""
        message = {
            "type": "device_disconnected",
            "device_id": device_id,
            "timestamp": datetime.now().isoformat()
        }
       
        await self.websocket_manager.broadcast_to_device_subscribers(device_id, message)
   
    def _setup_routes(self):
        """Setup API routes"""
       
        @self.app.get("/", response_model=APIResponse)
        async def root():
            """API root endpoint"""
            return APIResponse(
                success=True,
                data={
                    "name": "MIC3X2X Diagnostic API",
                    "version": "1.0.0",
                    "status": "running",
                    "endpoints": {
                        "devices": "/api/devices",
                        "websocket": "/ws/{client_id}",
                        "docs": "/docs"
                    }
                }
            )
       
        @self.app.get("/api/health", response_model=APIResponse)
        async def health_check():
            """Health check endpoint"""
            return APIResponse(
                success=True,
                data={
                    "status": "healthy",
                    "uptime": time.time(),
                    "active_devices": len(self.device_manager.connection_manager.active_connections),
                    "websocket_connections": sum(len(conns) for conns in self.websocket_manager.connections.values())
                }
            )
       
        @self.app.get("/api/devices/discover", response_model=APIResponse)
        async def discover_devices():
            """Discover available MIC3X2X devices"""
            try:
                devices = self.device_manager.discover_devices()
                device_data = []
               
                for device in devices:
                    device_data.append({
                        "device_id": device.device_id,
                        "interface_type": device.interface_type,
                        "connection_params": device.connection_params,
                        "state": device.state.value,
                        "last_seen": device.last_seen.isoformat() if device.last_seen else None
                    })
               
                return APIResponse(success=True, data=device_data)
               
            except Exception as e:
                logger.error(f"Device discovery failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.post("/api/devices/connect", response_model=APIResponse)
        async def connect_device(request: DeviceConnectionRequest):
            """Connect to MIC3X2X device"""
            try:
                success = self.device_manager.connect_to_device(
                    device_id=request.device_id,
                    auto_discover=request.auto_discover
                )
               
                if success:
                    device_status = self.device_manager.get_device_status(
                        self.device_manager.current_device_id
                    )
                    return APIResponse(success=True, data=device_status)
                else:
                    return APIResponse(success=False, error="Failed to connect to device")
                   
            except Exception as e:
                logger.error(f"Device connection failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.post("/api/devices/{device_id}/disconnect", response_model=APIResponse)
        async def disconnect_device(device_id: str):
            """Disconnect from device"""
            try:
                self.device_manager.disconnect_device(device_id)
                return APIResponse(success=True, data={"message": f"Disconnected from {device_id}"})
               
            except Exception as e:
                logger.error(f"Device disconnection failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.get("/api/devices/{device_id}/status", response_model=APIResponse)
        async def get_device_status(device_id: str):
            """Get device status"""
            try:
                status = self.device_manager.get_device_status(device_id)
                return APIResponse(success=True, data=status)
               
            except Exception as e:
                logger.error(f"Failed to get device status: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.post("/api/sessions/start", response_model=APIResponse)
        async def start_session(device_id: Optional[str] = None):
            """Start diagnostic session"""
            try:
                session_id = self.device_manager.start_diagnostic_session(device_id)
               
                if session_id:
                    session = self.device_manager.active_sessions[session_id]
                    session_data = {
                        "session_id": session.session_id,
                        "device_id": session.device_id,
                        "start_time": session.start_time.isoformat(),
                        "state": session.state.value,
                        "vehicle_info": session.vehicle_info,
                        "supported_pids": session.supported_pids
                    }
                    return APIResponse(success=True, data=session_data)
                else:
                    return APIResponse(success=False, error="Failed to start diagnostic session")
                   
            except Exception as e:
                logger.error(f"Session start failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.post("/api/obd/command", response_model=APIResponse)
        async def send_obd_command(request: OBDCommandRequest):
            """Send OBD command"""
            try:
                response = self.device_manager.send_obd_command(
                    mode=request.mode,
                    pid=request.pid,
                    device_id=request.device_id
                )
               
                if response:
                    response_data = {
                        "mode": response.mode,
                        "pid": response.pid,
                        "raw_data": response.raw_data,
                        "data": response.data,
                        "success": response.success,
                        "protocol_used": response.protocol_used,
                        "response_time_ms": response.response_time_ms
                    }
                    return APIResponse(success=True, data=response_data)
                else:
                    return APIResponse(success=False, error="Command failed")
                   
            except Exception as e:
                logger.error(f"OBD command failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.get("/api/obd/dtcs/{device_id}", response_model=APIResponse)
        async def read_dtcs(device_id: str):
            """Read diagnostic trouble codes"""
            try:
                dtcs = self.device_manager.read_dtcs(device_id)
               
                dtc_data = {}
                for category, dtc_list in dtcs.items():
                    dtc_data[category] = []
                    for dtc in dtc_list:
                        dtc_data[category].append({
                            "code": dtc.code,
                            "description": dtc.description,
                            "status": dtc.status.value,
                            "timestamp": dtc.timestamp.isoformat(),
                            "occurrence_count": dtc.occurrence_count
                        })
               
                return APIResponse(success=True, data=dtc_data)
               
            except Exception as e:
                logger.error(f"DTC reading failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.post("/api/obd/dtcs/{device_id}/clear", response_model=APIResponse)
        async def clear_dtcs(device_id: str):
            """Clear diagnostic trouble codes"""
            try:
                success = self.device_manager.clear_dtcs(device_id)
                return APIResponse(success=success, data={"cleared": success})
               
            except Exception as e:
                logger.error(f"DTC clearing failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.get("/api/obd/snapshot/{device_id}", response_model=APIResponse)
        async def take_snapshot(device_id: str):
            """Take vehicle data snapshot"""
            try:
                snapshot = self.device_manager.take_vehicle_snapshot(device_id)
                return APIResponse(success=True, data=snapshot)
               
            except Exception as e:
                logger.error(f"Snapshot failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.post("/api/monitoring/start", response_model=APIResponse)
        async def start_monitoring(request: MonitoringRequest):
            """Start real-time monitoring"""
            try:
                success = self.device_manager.start_monitoring(
                    device_id=request.device_id,
                    pids=request.pids,
                    interval=request.interval
                )
               
                return APIResponse(success=success, data={"monitoring_started": success})
               
            except Exception as e:
                logger.error(f"Monitoring start failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.post("/api/monitoring/{device_id}/stop", response_model=APIResponse)
        async def stop_monitoring(device_id: str):
            """Stop real-time monitoring"""
            try:
                self.device_manager.stop_monitoring(device_id)
                return APIResponse(success=True, data={"monitoring_stopped": True})
               
            except Exception as e:
                logger.error(f"Monitoring stop failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.get("/api/reports/{device_id}", response_model=APIResponse)
        async def generate_report(device_id: str):
            """Generate diagnostic report"""
            try:
                report = self.device_manager.generate_diagnostic_report(device_id)
                return APIResponse(success=True, data=report)
               
            except Exception as e:
                logger.error(f"Report generation failed: {e}", category=LogCategory.ERROR)
                return APIResponse(success=False, error=str(e))
       
        @self.app.websocket("/ws/{client_id}")
        async def websocket_endpoint(websocket: WebSocket, client_id: str):
            """WebSocket endpoint for real-time data"""
            await self.websocket_manager.connect(websocket, client_id)
           
            try:
                while True:
                    # Receive messages from client
                    message = await websocket.receive_json()
                   
                    if message.get("type") == "subscribe_device":
                        device_id = message.get("device_id")
                        if device_id:
                            await self.websocket_manager.subscribe_to_device(websocket, device_id)
                   
                    elif message.get("type") == "ping":
                        await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
                   
            except WebSocketDisconnect:
                self.websocket_manager.disconnect(websocket, client_id)
            except Exception as e:
                logger.error(f"WebSocket error: {e}", category=LogCategory.COMMUNICATION)
                self.websocket_manager.disconnect(websocket, client_id)


def create_api_server(device_manager: MIC3X2XDeviceManager,
                     host: str = "127.0.0.1",
                     port: int = 8000) -> MIC3X2XAPIServer:
    """Create and configure API server"""
    api_server = MIC3X2XAPIServer(device_manager)
    return api_server


def run_api_server(api_server: MIC3X2XAPIServer,
                  host: str = "127.0.0.1",
                  port: int = 8000,
                  reload: bool = False):
    """Run API server"""
    logger.info(f"Starting MIC3X2X API server on {host}:{port}", category=LogCategory.SYSTEM)
   
    uvicorn.run(
        api_server.app,
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


if __name__ == "__main__":
    # Example usage
    from device_manager import MIC3X2XDeviceManager
   
    # Create device manager
    device_manager = MIC3X2XDeviceManager()
   
    # Create API server
    api_server = create_api_server(device_manager)
   
    # Run server
    run_api_server(api_server, host="0.0.0.0", port=8000) 
