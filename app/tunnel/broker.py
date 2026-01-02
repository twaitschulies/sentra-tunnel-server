"""
Tunnel Broker

Manages WebSocket connections from Raspberry Pi devices.
Handles authentication, routing, and command dispatch.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, Optional, Any, Set
from dataclasses import dataclass, field

from fastapi import WebSocket, WebSocketDisconnect

from .protocol import (
    MessageType,
    parse_message,
    create_auth_success,
    create_auth_failed,
    create_command,
    create_disconnect,
    create_ping
)

logger = logging.getLogger(__name__)


@dataclass
class DeviceConnection:
    """Represents a connected device."""
    device_id: str
    websocket: WebSocket
    session_id: str
    shop_id: Optional[str] = None
    mac_address: Optional[str] = None
    fingerprint: Optional[str] = None
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)
    last_status: Dict[str, Any] = field(default_factory=dict)
    authenticated: bool = False

    def update_heartbeat(self, status: Dict[str, Any] = None):
        """Update heartbeat timestamp and status."""
        self.last_heartbeat = datetime.utcnow()
        if status:
            self.last_status = status


@dataclass
class PendingCommand:
    """A command waiting for response."""
    command_id: str
    device_id: str
    action: str
    params: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)
    future: asyncio.Future = None


class TunnelBroker:
    """
    Central broker for device tunnel connections.

    Manages:
    - Device authentication and sessions
    - Command routing to devices
    - Response handling
    - Connection health monitoring
    """

    def __init__(self):
        # Active device connections: device_id -> DeviceConnection
        self._connections: Dict[str, DeviceConnection] = {}

        # Pending command responses: command_id -> PendingCommand
        self._pending_commands: Dict[str, PendingCommand] = {}

        # Device API keys for authentication (loaded from database)
        self._device_keys: Dict[str, Dict[str, Any]] = {}

        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = True

    async def start(self):
        """Start the broker background tasks."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def shutdown(self):
        """Shutdown the broker."""
        self._running = False

        # Cancel cleanup task
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Disconnect all devices
        for device_id in list(self._connections.keys()):
            await self.disconnect_device(device_id, "Server shutdown")

    async def _cleanup_loop(self):
        """Periodic cleanup of stale connections and pending commands."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Run every minute

                now = datetime.utcnow()

                # Check for stale connections (no heartbeat for 2 minutes)
                for device_id, conn in list(self._connections.items()):
                    age = (now - conn.last_heartbeat).total_seconds()
                    if age > 120:
                        logger.warning(f"Device {device_id} heartbeat timeout ({age}s)")
                        await self.disconnect_device(device_id, "Heartbeat timeout")

                # Clean up old pending commands (older than 60 seconds)
                for cmd_id, cmd in list(self._pending_commands.items()):
                    age = (now - cmd.created_at).total_seconds()
                    if age > 60:
                        logger.warning(f"Command {cmd_id} timed out")
                        if cmd.future and not cmd.future.done():
                            cmd.future.set_exception(TimeoutError("Command timeout"))
                        del self._pending_commands[cmd_id]

            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")

    async def handle_connection(self, websocket: WebSocket):
        """
        Handle a new WebSocket connection from a device.

        Args:
            websocket: FastAPI WebSocket connection
        """
        await websocket.accept()
        device_id = None
        session_id = f"sess_{uuid.uuid4().hex[:12]}"

        try:
            # Wait for authentication message
            auth_data = await asyncio.wait_for(
                websocket.receive_text(),
                timeout=30
            )

            message = parse_message(auth_data)

            if message.get('type') != MessageType.AUTH.value:
                await websocket.send_text(
                    create_auth_failed("Expected auth message")
                )
                return

            # Authenticate device
            device_id = message.get('device_id')
            api_key = message.get('api_key')

            if not await self._authenticate_device(device_id, api_key):
                logger.warning(f"Auth failed for device: {device_id}")
                await websocket.send_text(
                    create_auth_failed("Invalid device credentials")
                )
                return

            # Get device info from database
            device_info = await self._get_device_info(device_id)

            # Create connection record
            conn = DeviceConnection(
                device_id=device_id,
                websocket=websocket,
                session_id=session_id,
                shop_id=device_info.get('shop_id'),
                mac_address=message.get('mac_address'),
                fingerprint=message.get('fingerprint'),
                authenticated=True
            )
            self._connections[device_id] = conn

            logger.info(f"Device connected: {device_id} (session: {session_id})")

            # Send auth success
            await websocket.send_text(
                create_auth_success(
                    session_id=session_id,
                    device_name=device_info.get('name', device_id)
                )
            )

            # Update device last_seen in database
            await self._update_device_status(device_id, 'online')

            # Handle messages
            await self._message_loop(conn)

        except asyncio.TimeoutError:
            logger.warning(f"Connection timeout waiting for auth")
            await websocket.send_text(
                create_auth_failed("Authentication timeout")
            )

        except WebSocketDisconnect:
            logger.info(f"Device disconnected: {device_id}")

        except Exception as e:
            logger.error(f"Connection error for {device_id}: {e}")

        finally:
            # Cleanup
            if device_id and device_id in self._connections:
                del self._connections[device_id]
                await self._update_device_status(device_id, 'offline')
                logger.info(f"Device cleaned up: {device_id}")

    async def _message_loop(self, conn: DeviceConnection):
        """Process messages from connected device."""
        while self._running:
            try:
                data = await conn.websocket.receive_text()
                message = parse_message(data)
                msg_type = message.get('type')

                if msg_type == MessageType.HEARTBEAT.value:
                    status = message.get('status', {})
                    conn.update_heartbeat(status)
                    logger.debug(f"Heartbeat from {conn.device_id}")

                elif msg_type == MessageType.RESPONSE.value:
                    await self._handle_response(message)

                elif msg_type == MessageType.PONG.value:
                    # Pong response to our ping
                    pass

                else:
                    logger.warning(f"Unknown message type: {msg_type}")

            except WebSocketDisconnect:
                raise

            except Exception as e:
                logger.error(f"Message handling error: {e}")

    async def _handle_response(self, message: Dict[str, Any]):
        """Handle command response from device."""
        command_id = message.get('command_id')

        if command_id not in self._pending_commands:
            logger.warning(f"Response for unknown command: {command_id}")
            return

        pending = self._pending_commands.pop(command_id)

        if pending.future and not pending.future.done():
            pending.future.set_result({
                'success': message.get('success', False),
                'data': message.get('data'),
                'error': message.get('error'),
                'executed_at': message.get('executed_at')
            })

        logger.info(f"Command {command_id} completed: success={message.get('success')}")

    async def _authenticate_device(self, device_id: str, api_key: str) -> bool:
        """
        Authenticate a device by API key.

        Args:
            device_id: Device identifier
            api_key: Device API key

        Returns:
            True if authenticated
        """
        # Load from database
        from ..models.database import get_device_by_id
        device = await get_device_by_id(device_id)

        if not device:
            logger.warning(f"Unknown device: {device_id}")
            return False

        if device.get('api_key') != api_key:
            logger.warning(f"Invalid API key for device: {device_id}")
            return False

        return True

    async def _get_device_info(self, device_id: str) -> Dict[str, Any]:
        """Get device info from database."""
        from ..models.database import get_device_by_id
        return await get_device_by_id(device_id) or {}

    async def _update_device_status(self, device_id: str, status: str):
        """Update device status in database."""
        from ..models.database import update_device_status
        await update_device_status(device_id, status)

    async def send_command(
        self,
        device_id: str,
        action: str,
        params: Dict[str, Any] = None,
        timeout: float = 30.0
    ) -> Dict[str, Any]:
        """
        Send a command to a device and wait for response.

        Args:
            device_id: Target device ID
            action: Command action name
            params: Command parameters
            timeout: Response timeout in seconds

        Returns:
            Response dict with success, data, error

        Raises:
            ValueError: If device not connected
            TimeoutError: If no response within timeout
        """
        if device_id not in self._connections:
            raise ValueError(f"Device not connected: {device_id}")

        conn = self._connections[device_id]

        # Create command
        message, command_id = create_command(action, params)

        # Create future for response
        loop = asyncio.get_event_loop()
        future = loop.create_future()

        pending = PendingCommand(
            command_id=command_id,
            device_id=device_id,
            action=action,
            params=params or {},
            future=future
        )
        self._pending_commands[command_id] = pending

        try:
            # Send command
            await conn.websocket.send_text(message)
            logger.info(f"Sent command {command_id} to {device_id}: {action}")

            # Wait for response
            result = await asyncio.wait_for(future, timeout=timeout)
            return result

        except asyncio.TimeoutError:
            # Cleanup
            if command_id in self._pending_commands:
                del self._pending_commands[command_id]
            raise TimeoutError(f"Command {action} timed out")

        except Exception as e:
            # Cleanup
            if command_id in self._pending_commands:
                del self._pending_commands[command_id]
            raise

    async def disconnect_device(self, device_id: str, reason: str = "Disconnected"):
        """Disconnect a device."""
        if device_id not in self._connections:
            return

        conn = self._connections[device_id]

        try:
            await conn.websocket.send_text(create_disconnect(reason))
            await conn.websocket.close()
        except:
            pass

        del self._connections[device_id]
        await self._update_device_status(device_id, 'offline')
        logger.info(f"Disconnected device {device_id}: {reason}")

    def get_connected_devices(self, shop_id: str = None) -> list[Dict[str, Any]]:
        """
        Get list of connected devices.

        Args:
            shop_id: Optional filter by shop ID

        Returns:
            List of device status dicts
        """
        devices = []

        for device_id, conn in self._connections.items():
            if shop_id and conn.shop_id != shop_id:
                continue

            devices.append({
                'device_id': device_id,
                'shop_id': conn.shop_id,
                'session_id': conn.session_id,
                'connected_at': conn.connected_at.isoformat(),
                'last_heartbeat': conn.last_heartbeat.isoformat(),
                'last_status': conn.last_status,
                'online': True
            })

        return devices

    def is_device_online(self, device_id: str) -> bool:
        """Check if device is currently connected."""
        return device_id in self._connections

    def get_device_status(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a connected device."""
        if device_id not in self._connections:
            return None

        conn = self._connections[device_id]
        return {
            'device_id': device_id,
            'online': True,
            'session_id': conn.session_id,
            'connected_at': conn.connected_at.isoformat(),
            'last_heartbeat': conn.last_heartbeat.isoformat(),
            'last_status': conn.last_status
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get broker statistics."""
        return {
            'connected_devices': len(self._connections),
            'pending_commands': len(self._pending_commands),
            'device_ids': list(self._connections.keys())
        }

    def register_demo_device(self, device_id: str, shop_id: str, name: str):
        """
        Register a simulated demo device (for testing without real hardware).

        Args:
            device_id: Demo device identifier
            shop_id: Shop ID the device belongs to
            name: Device name
        """
        if device_id in self._connections:
            return  # Already registered

        # Create a virtual connection (no real websocket)
        conn = DeviceConnection(
            device_id=device_id,
            websocket=None,  # No real connection
            session_id=f"demo_{device_id}",
            shop_id=shop_id,
            authenticated=True,
            last_status={
                "current_mode": "normal",
                "gpio_state": False,
                "temperature": 22.5,
                "uptime": 86400,
                "is_demo": True
            }
        )
        self._connections[device_id] = conn
        logger.info(f"Registered demo device: {device_id}")

    def is_demo_device(self, device_id: str) -> bool:
        """Check if device is a demo device (virtual connection)."""
        if device_id not in self._connections:
            return False
        conn = self._connections[device_id]
        return conn.websocket is None

    async def simulate_demo_command(self, device_id: str, action: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Simulate a command execution for demo devices.

        Args:
            device_id: Demo device identifier
            action: Command action name
            params: Command parameters

        Returns:
            Simulated response
        """
        if device_id not in self._connections:
            return {"success": False, "error": "Device not connected"}

        conn = self._connections[device_id]

        if conn.websocket is not None:
            return {"success": False, "error": "Not a demo device"}

        # Simulate different commands
        await asyncio.sleep(0.5)  # Simulate network latency

        if action == "open_door":
            # Simulate door opening
            conn.last_status["gpio_state"] = True
            logger.info(f"Demo: Door opened on {device_id}")

            # Auto-close after 3 seconds
            async def auto_close():
                await asyncio.sleep(3)
                if device_id in self._connections:
                    self._connections[device_id].last_status["gpio_state"] = False
                    logger.info(f"Demo: Door auto-closed on {device_id}")

            asyncio.create_task(auto_close())

            return {
                "success": True,
                "data": {"message": "Demo: Tür wird geöffnet (simuliert)"},
                "executed_at": datetime.utcnow().isoformat()
            }

        elif action == "set_mode":
            mode = params.get("mode", "normal") if params else "normal"
            conn.last_status["current_mode"] = mode
            return {
                "success": True,
                "data": {"mode": mode},
                "executed_at": datetime.utcnow().isoformat()
            }

        elif action == "get_status":
            return {
                "success": True,
                "data": conn.last_status,
                "executed_at": datetime.utcnow().isoformat()
            }

        return {"success": True, "data": {"action": action}}
