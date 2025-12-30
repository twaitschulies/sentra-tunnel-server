"""
Device API Routes

REST API for device management and registration.
"""

import uuid
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, Depends
import aiosqlite

from .auth import require_auth, require_admin
from ..models.device import (
    Device, DeviceStatus, DeviceRegistration, DeviceRegistrationResponse,
    CreateDeviceRequest, CreateDeviceResponse
)
from ..models.database import (
    get_device_by_id, get_devices_by_shop, log_audit,
    DB_PATH
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/")
async def list_devices(
    request: Request,
    shop_id: Optional[str] = None,
    user: dict = Depends(require_auth)
):
    """
    List devices accessible by user.

    Args:
        shop_id: Optional filter by shop
    """
    from ..models.database import get_user_shops, get_all_shops

    # Get accessible shops
    if user.get('role') == 'admin':
        shops = await get_all_shops() if not shop_id else [{'id': shop_id}]
    else:
        shops = await get_user_shops(user['id'])
        if shop_id:
            shops = [s for s in shops if s['id'] == shop_id]

    # Get devices from each shop
    devices = []
    broker = request.app.state.tunnel_broker

    for shop in shops:
        shop_devices = await get_devices_by_shop(shop['id'])
        for device in shop_devices:
            # Add online status from broker
            if broker:
                status = broker.get_device_status(device['device_id'])
                device['online'] = status is not None
                device['last_status'] = status.get('last_status', {}) if status else {}
            else:
                device['online'] = False
            devices.append(device)

    return {"devices": devices}


@router.get("/{device_id}")
async def get_device(
    request: Request,
    device_id: str,
    user: dict = Depends(require_auth)
):
    """Get device details."""
    device = await get_device_by_id(device_id)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Check access
    if user.get('role') != 'admin':
        from ..models.database import get_user_shops
        user_shops = await get_user_shops(user['id'])
        if not any(s['id'] == device.get('shop_id') for s in user_shops):
            raise HTTPException(status_code=403, detail="Access denied")

    # Add online status
    broker = request.app.state.tunnel_broker
    if broker:
        status = broker.get_device_status(device_id)
        device['online'] = status is not None
        device['last_status'] = status.get('last_status', {}) if status else {}
    else:
        device['online'] = False

    return device


@router.get("/{device_id}/status")
async def get_device_status(
    request: Request,
    device_id: str,
    user: dict = Depends(require_auth)
):
    """Get real-time device status."""
    device = await get_device_by_id(device_id)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    broker = request.app.state.tunnel_broker
    if not broker:
        raise HTTPException(status_code=503, detail="Tunnel broker not available")

    status = broker.get_device_status(device_id)

    return DeviceStatus(
        device_id=device_id,
        name=device.get('name'),
        shop_id=device.get('shop_id'),
        online=status is not None,
        status=device.get('status', 'offline'),
        last_seen=device.get('last_seen'),
        last_heartbeat=status.get('last_heartbeat') if status else None,
        door_status=status.get('last_status', {}) if status else None
    )


@router.post("/create")
async def create_device(
    request: Request,
    data: CreateDeviceRequest,
    user: dict = Depends(require_admin)
):
    """
    Create a new device (generates registration token).

    Admins use this to prepare a device for registration.
    """
    # Generate device ID and registration token
    device_id = f"sentra-guard-{secrets.token_hex(4)}"
    registration_token = f"reg_{secrets.token_urlsafe(32)}"
    expires_at = datetime.utcnow() + timedelta(hours=24)

    # Store registration token
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO registration_tokens
               (token, shop_id, device_name, expires_at)
               VALUES (?, ?, ?, ?)""",
            (registration_token, data.shop_id, data.device_name, expires_at.isoformat())
        )
        await db.commit()

    await log_audit(
        action="device_created",
        user_id=user['id'],
        shop_id=data.shop_id,
        details=f"Created device: {data.device_name}",
        ip_address=request.client.host
    )

    logger.info(f"Device created by {user['username']}: {data.device_name}")

    return CreateDeviceResponse(
        device_id=device_id,
        registration_token=registration_token,
        expires_at=expires_at.isoformat()
    )


@router.post("/register")
async def register_device(request: Request, data: DeviceRegistration):
    """
    Register a device using a registration token.

    Called by the Raspberry Pi during setup.
    """
    try:
        # Validate token
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row

            # Check if device already exists
            async with db.execute(
                "SELECT device_id, api_key, shop_id FROM devices WHERE device_id = ?",
                (data.device_id,)
            ) as cursor:
                existing_device = await cursor.fetchone()

            if existing_device:
                existing_device = dict(existing_device)
                logger.info(f"Device {data.device_id} already registered, returning existing credentials")

                # Device already registered - return existing API key
                host = request.headers.get('host', 'localhost:8000')
                scheme = 'wss' if request.url.scheme == 'https' else 'ws'
                tunnel_url = f"{scheme}://{host}/ws"

                return DeviceRegistrationResponse(
                    success=True,
                    device_id=data.device_id,
                    api_key=existing_device['api_key'],
                    tunnel_url=tunnel_url
                )

            # Find valid registration token
            async with db.execute(
                """SELECT * FROM registration_tokens
                   WHERE token = ? AND used_at IS NULL""",
                (data.registration_token,)
            ) as cursor:
                token_data = await cursor.fetchone()

        if not token_data:
            return DeviceRegistrationResponse(
                success=False,
                error="Invalid or used registration token"
            )

        token_data = dict(token_data)

        # Check expiry
        expires_at = datetime.fromisoformat(token_data['expires_at'])
        if datetime.utcnow() > expires_at:
            return DeviceRegistrationResponse(
                success=False,
                error="Registration token expired"
            )

        # Generate API key
        api_key = f"sk_{secrets.token_urlsafe(32)}"

        # Create device record
        async with aiosqlite.connect(DB_PATH) as db:
            try:
                # Insert device
                await db.execute(
                    """INSERT INTO devices
                       (device_id, shop_id, name, mac_address, api_key, fingerprint, registered_at, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        data.device_id,
                        token_data['shop_id'],
                        token_data['device_name'],
                        data.mac_address,
                        api_key,
                        data.fingerprint,
                        datetime.utcnow().isoformat(),
                        'offline'
                    )
                )

                # Mark token as used
                await db.execute(
                    """UPDATE registration_tokens
                       SET used_at = ?, used_by_device = ?
                       WHERE token = ?""",
                    (datetime.utcnow().isoformat(), data.device_id, data.registration_token)
                )

                await db.commit()
            except aiosqlite.IntegrityError as e:
                logger.warning(f"Device registration integrity error: {e}")
                return DeviceRegistrationResponse(
                    success=False,
                    error=f"Device or MAC address already registered"
                )

        # Log audit (don't fail registration if audit fails)
        try:
            await log_audit(
                action="device_registered",
                device_id=data.device_id,
                shop_id=token_data['shop_id'],
                details=f"MAC: {data.mac_address}",
                ip_address=request.client.host
            )
        except Exception as audit_error:
            logger.warning(f"Audit log failed (non-critical): {audit_error}")

        logger.info(f"Device registered: {data.device_id}")

        # Construct tunnel URL
        host = request.headers.get('host', 'localhost:8000')
        scheme = 'wss' if request.url.scheme == 'https' else 'ws'
        tunnel_url = f"{scheme}://{host}/ws"

        return DeviceRegistrationResponse(
            success=True,
            device_id=data.device_id,
            api_key=api_key,
            tunnel_url=tunnel_url
        )

    except Exception as e:
        logger.error(f"Registration error for {data.device_id}: {e}", exc_info=True)
        return DeviceRegistrationResponse(
            success=False,
            error=f"Registration failed: {str(e)}"
        )


@router.delete("/{device_id}")
async def delete_device(
    request: Request,
    device_id: str,
    user: dict = Depends(require_admin)
):
    """Delete a device."""
    device = await get_device_by_id(device_id)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Disconnect if online
    broker = request.app.state.tunnel_broker
    if broker and broker.is_device_online(device_id):
        await broker.disconnect_device(device_id, "Device deleted")

    # Delete from database
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        await db.commit()

    await log_audit(
        action="device_deleted",
        user_id=user['id'],
        device_id=device_id,
        ip_address=request.client.host
    )

    logger.info(f"Device deleted by {user['username']}: {device_id}")

    return {"success": True}
