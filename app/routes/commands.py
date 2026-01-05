"""
Command API Routes

Send commands to devices through the tunnel.
"""

import logging
from typing import Optional, Dict, Any

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel

from .auth import require_auth
from ..models.database import get_device_by_id, get_user_shops, log_audit

logger = logging.getLogger(__name__)

router = APIRouter()


class CommandRequest(BaseModel):
    """Command request model."""
    action: str
    params: Optional[Dict[str, Any]] = None


class CommandResponse(BaseModel):
    """Command response model."""
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    executed_at: Optional[str] = None


@router.post("/{device_id}/execute")
async def execute_command(
    request: Request,
    device_id: str,
    command: CommandRequest,
    user: dict = Depends(require_auth)
):
    """
    Execute a command on a device.

    Args:
        device_id: Target device
        command: Command to execute
    """
    # Verify device exists
    device = await get_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Verify access and control permission
    if user.get('role') != 'admin':
        user_shops = await get_user_shops(user['id'])
        shop_access = next(
            (s for s in user_shops if s['id'] == device.get('shop_id')),
            None
        )
        if not shop_access:
            raise HTTPException(status_code=403, detail="Access denied")
        if shop_access.get('permission') != 'control':
            raise HTTPException(status_code=403, detail="No control permission")

    # Get broker
    broker = request.app.state.tunnel_broker
    if not broker:
        raise HTTPException(status_code=503, detail="Tunnel broker not available")

    # Check device is online
    if not broker.is_device_online(device_id):
        raise HTTPException(status_code=503, detail="Device offline")

    # Execute command (check for demo device first)
    try:
        if broker.is_demo_device(device_id):
            # Use simulated command for demo devices
            result = await broker.simulate_demo_command(
                device_id=device_id,
                action=command.action,
                params=command.params
            )
        else:
            # Real device - send through websocket
            result = await broker.send_command(
                device_id=device_id,
                action=command.action,
                params=command.params,
                timeout=30.0
            )

        # Log command
        await log_audit(
            action=f"command_{command.action}",
            user_id=user['id'],
            device_id=device_id,
            shop_id=device.get('shop_id'),
            details=str(command.params),
            result="success" if result.get('success') else "failed",
            ip_address=request.client.host
        )

        return CommandResponse(
            success=result.get('success', False),
            data=result.get('data'),
            error=result.get('error'),
            executed_at=result.get('executed_at')
        )

    except TimeoutError:
        await log_audit(
            action=f"command_{command.action}",
            user_id=user['id'],
            device_id=device_id,
            result="timeout",
            ip_address=request.client.host
        )
        raise HTTPException(status_code=504, detail="Command timeout")

    except Exception as e:
        logger.error(f"Command execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Convenience endpoints for common commands

@router.post("/{device_id}/status")
async def get_device_door_status(
    request: Request,
    device_id: str,
    user: dict = Depends(require_auth)
):
    """Get current door status from device."""
    command = CommandRequest(action="get_status")
    return await execute_command(request, device_id, command, user)


@router.post("/{device_id}/open")
async def open_door(
    request: Request,
    device_id: str,
    duration: Optional[int] = 3,
    user: dict = Depends(require_auth)
):
    """Open the door (trigger GPIO pulse)."""
    command = CommandRequest(
        action="open_door",
        params={"duration": duration}
    )
    return await execute_command(request, device_id, command, user)


@router.get("/{device_id}/config")
async def get_door_config(
    request: Request,
    device_id: str,
    user: dict = Depends(require_auth)
):
    """Get door control configuration."""
    command = CommandRequest(action="get_config")
    return await execute_command(request, device_id, command, user)


@router.post("/{device_id}/config")
async def set_door_config(
    request: Request,
    device_id: str,
    config: Dict[str, Any],
    user: dict = Depends(require_auth)
):
    """Update door control configuration."""
    command = CommandRequest(
        action="set_config",
        params=config
    )
    return await execute_command(request, device_id, command, user)


@router.post("/{device_id}/override")
async def set_override(
    request: Request,
    device_id: str,
    mode: str,
    duration_hours: float = 1.0,
    user: dict = Depends(require_auth)
):
    """Set temporary door mode override."""
    command = CommandRequest(
        action="set_override",
        params={
            "mode": mode,
            "duration_hours": duration_hours
        }
    )
    return await execute_command(request, device_id, command, user)


@router.delete("/{device_id}/override")
async def clear_override(
    request: Request,
    device_id: str,
    user: dict = Depends(require_auth)
):
    """Clear door mode override and return to normal operation."""
    command = CommandRequest(action="clear_override")
    return await execute_command(request, device_id, command, user)
