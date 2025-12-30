"""
Tunnel Protocol

Defines message formats for communication between server and devices.
"""

import json
import uuid
from enum import Enum
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


class MessageType(Enum):
    """Message types for tunnel protocol."""

    # Device -> Server
    AUTH = 'auth'
    HEARTBEAT = 'heartbeat'
    RESPONSE = 'response'
    PONG = 'pong'

    # Server -> Device
    AUTH_SUCCESS = 'auth_success'
    AUTH_FAILED = 'auth_failed'
    COMMAND = 'command'
    PING = 'ping'
    DISCONNECT = 'disconnect'


@dataclass
class AuthMessage:
    """Authentication message from device."""
    device_id: str
    api_key: str
    mac_address: Optional[str] = None
    fingerprint: Optional[str] = None
    timestamp: Optional[str] = None
    version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': MessageType.AUTH.value,
            **{k: v for k, v in asdict(self).items() if v is not None}
        }


@dataclass
class HeartbeatMessage:
    """Heartbeat message from device."""
    device_id: str
    timestamp: str
    status: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': MessageType.HEARTBEAT.value,
            'device_id': self.device_id,
            'timestamp': self.timestamp,
            'status': self.status
        }


@dataclass
class CommandMessage:
    """Command message from server to device."""
    action: str
    params: Dict[str, Any] = None
    command_id: str = None

    def __post_init__(self):
        if self.command_id is None:
            self.command_id = f"cmd_{uuid.uuid4().hex[:12]}"
        if self.params is None:
            self.params = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': MessageType.COMMAND.value,
            'command_id': self.command_id,
            'action': self.action,
            'params': self.params
        }


@dataclass
class ResponseMessage:
    """Response message from device."""
    command_id: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    executed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': MessageType.RESPONSE.value,
            'command_id': self.command_id,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'executed_at': self.executed_at
        }


def create_message(msg_type: MessageType, **kwargs) -> str:
    """
    Create a JSON message string.

    Args:
        msg_type: Message type
        **kwargs: Message-specific fields

    Returns:
        JSON string
    """
    message = {'type': msg_type.value, **kwargs}
    return json.dumps(message)


def create_auth_success(session_id: str, device_name: str = None) -> str:
    """Create auth success response."""
    return create_message(
        MessageType.AUTH_SUCCESS,
        session_id=session_id,
        device_name=device_name,
        timestamp=datetime.utcnow().isoformat()
    )


def create_auth_failed(error: str) -> str:
    """Create auth failed response."""
    return create_message(
        MessageType.AUTH_FAILED,
        error=error,
        timestamp=datetime.utcnow().isoformat()
    )


def create_command(action: str, params: Dict[str, Any] = None, command_id: str = None) -> tuple[str, str]:
    """
    Create a command message.

    Args:
        action: Command action name
        params: Command parameters
        command_id: Optional specific command ID

    Returns:
        Tuple of (json_message, command_id)
    """
    cmd = CommandMessage(action=action, params=params, command_id=command_id)
    return json.dumps(cmd.to_dict()), cmd.command_id


def create_disconnect(reason: str) -> str:
    """Create disconnect message."""
    return create_message(
        MessageType.DISCONNECT,
        reason=reason,
        timestamp=datetime.utcnow().isoformat()
    )


def create_ping() -> str:
    """Create ping message."""
    return create_message(
        MessageType.PING,
        timestamp=datetime.utcnow().isoformat()
    )


def parse_message(data: str) -> Dict[str, Any]:
    """
    Parse incoming message.

    Args:
        data: JSON string

    Returns:
        Parsed message dict

    Raises:
        ValueError: If message is invalid
    """
    try:
        message = json.loads(data)

        if 'type' not in message:
            raise ValueError("Message missing 'type' field")

        return message

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
