"""
Portal Routes

Web interface routes for the management portal.
"""

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .auth import get_current_user, require_auth
from ..models.database import (
    get_user_shops, get_devices_by_shop, get_all_shops,
    create_shop, delete_shop, create_registration_token, get_shop_by_id,
    log_audit
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Templates
TEMPLATES_DIR = Path(__file__).parent.parent / 'templates'
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, session_id: Optional[str] = Cookie(None)):
    """
    Homepage - redirects to dashboard or login.
    """
    user = await get_current_user(session_id)

    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, session_id: Optional[str] = Cookie(None)):
    """
    Login page.
    """
    user = await get_current_user(session_id)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)

    return templates.TemplateResponse(
        "pages/login.html",
        {"request": request}
    )


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(require_auth)):
    """
    Main dashboard - shows user's shops.
    """
    # Get shops accessible by user
    if user.get('role') == 'admin':
        shops = await get_all_shops()
    else:
        shops = await get_user_shops(user['id'])

    # Enrich with device counts and online status
    for shop in shops:
        devices = await get_devices_by_shop(shop['id'])
        shop['device_count'] = len(devices)
        shop['online_count'] = sum(1 for d in devices if d.get('status') == 'online')

        # Get tunnel broker status
        broker = request.app.state.tunnel_broker
        if broker:
            online_devices = broker.get_connected_devices(shop['id'])
            shop['online_count'] = len(online_devices)

    return templates.TemplateResponse(
        "pages/dashboard.html",
        {
            "request": request,
            "user": user,
            "shops": shops
        }
    )


@router.get("/shop/{shop_id}", response_class=HTMLResponse)
async def shop_view(request: Request, shop_id: str, user: dict = Depends(require_auth)):
    """
    Shop detail view - shows devices in shop.
    """
    try:
        # Check if shop exists
        shop = await get_shop_by_id(shop_id)
        if not shop:
            logger.warning(f"Shop not found: {shop_id}")
            return RedirectResponse(url="/dashboard", status_code=302)

        # Verify access
        if user.get('role') != 'admin':
            user_shops = await get_user_shops(user['id'])
            if not any(s['id'] == shop_id for s in user_shops):
                return RedirectResponse(url="/dashboard", status_code=302)

        # Get devices
        devices = await get_devices_by_shop(shop_id)

        # Enrich with real-time status
        broker = request.app.state.tunnel_broker
        if broker:
            for device in devices:
                device_id = device.get('device_id')
                if device_id:
                    status = broker.get_device_status(device_id)
                    if status:
                        device['online'] = True
                        device['last_status'] = status.get('last_status', {})
                    else:
                        device['online'] = False
                        device['last_status'] = {}
                else:
                    device['online'] = False
                    device['last_status'] = {}
        else:
            # No broker available, mark all devices as offline
            for device in devices:
                device['online'] = False
                device['last_status'] = {}

        return templates.TemplateResponse(
            "pages/shop.html",
            {
                "request": request,
                "user": user,
                "shop_id": shop_id,
                "shop": shop,
                "devices": devices
            }
        )
    except Exception as e:
        logger.error(f"Error in shop_view for {shop_id}: {e}", exc_info=True)
        return templates.TemplateResponse(
            "pages/error.html",
            {
                "request": request,
                "user": user,
                "error": str(e),
                "error_code": 500
            },
            status_code=500
        )


@router.get("/device/{device_id}", response_class=HTMLResponse)
async def device_view(request: Request, device_id: str, user: dict = Depends(require_auth)):
    """
    Device control view - main door control interface.
    """
    from ..models.database import get_device_by_id

    # Get device
    device = await get_device_by_id(device_id)
    if not device:
        return RedirectResponse(url="/dashboard", status_code=302)

    # Verify access
    if user.get('role') != 'admin':
        user_shops = await get_user_shops(user['id'])
        if not any(s['id'] == device.get('shop_id') for s in user_shops):
            return RedirectResponse(url="/dashboard", status_code=302)

    # Get real-time status
    broker = request.app.state.tunnel_broker
    device['online'] = False
    device['last_status'] = {}

    if broker:
        status = broker.get_device_status(device_id)
        if status:
            device['online'] = True
            device['last_status'] = status.get('last_status', {})

    return templates.TemplateResponse(
        "pages/device.html",
        {
            "request": request,
            "user": user,
            "device": device
        }
    )


# Admin routes
@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, user: dict = Depends(require_auth)):
    """
    Admin page - manage shops and devices.
    """
    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    shops = await get_all_shops()

    # Enrich with device counts
    for shop in shops:
        devices = await get_devices_by_shop(shop['id'])
        shop['device_count'] = len(devices)
        shop['devices'] = devices

    return templates.TemplateResponse(
        "pages/admin.html",
        {
            "request": request,
            "user": user,
            "shops": shops
        }
    )


@router.post("/admin/shop/create")
async def create_shop_route(request: Request, user: dict = Depends(require_auth)):
    """Create a new shop."""
    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    form = await request.form()
    shop_id = form.get('shop_id', '').strip().lower().replace(' ', '_')
    shop_name = form.get('shop_name', '').strip()

    if shop_id and shop_name:
        try:
            await create_shop(shop_id, shop_name)
            logger.info(f"Shop created: {shop_id} ({shop_name})")
        except Exception as e:
            logger.error(f"Failed to create shop: {e}")

    return RedirectResponse(url="/admin", status_code=302)


@router.post("/admin/device/create")
async def create_device_route(request: Request, user: dict = Depends(require_auth)):
    """Create a device and registration token."""
    import secrets
    from datetime import datetime, timedelta

    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    form = await request.form()
    shop_id = form.get('shop_id', '').strip()
    device_name = form.get('device_name', '').strip()

    if shop_id and device_name:
        # Generate registration token
        token = f"reg_{secrets.token_urlsafe(24)}"
        expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat()

        try:
            await create_registration_token(token, shop_id, device_name, expires_at)
            logger.info(f"Registration token created for {device_name} in shop {shop_id}")

            # Show the token to the admin
            shop = await get_shop_by_id(shop_id)
            shops = await get_all_shops()
            for s in shops:
                devices = await get_devices_by_shop(s['id'])
                s['device_count'] = len(devices)
                s['devices'] = devices

            return templates.TemplateResponse(
                "pages/admin.html",
                {
                    "request": request,
                    "user": user,
                    "shops": shops,
                    "new_token": token,
                    "new_device_name": device_name,
                    "new_shop_name": shop['name'] if shop else shop_id
                }
            )
        except Exception as e:
            logger.error(f"Failed to create device: {e}")

    return RedirectResponse(url="/admin", status_code=302)


@router.get("/diagnostics", response_class=HTMLResponse)
async def diagnostics_page(request: Request, user: dict = Depends(require_auth)):
    """
    Comprehensive diagnostics and troubleshooting page.
    """
    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    import aiosqlite
    from ..models.database import DB_PATH
    from datetime import datetime, timedelta

    diagnostics = {
        "server": {},
        "broker": {},
        "database": {},
        "devices": [],
        "recent_errors": [],
        "pending_tokens": [],
        "audit_log": []
    }

    # Server info
    diagnostics["server"] = {
        "status": "running",
        "time": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

    # Broker info
    broker = request.app.state.tunnel_broker
    if broker:
        stats = broker.get_stats()
        diagnostics["broker"] = {
            "status": "running",
            "connected_devices": stats.get("connected_devices", 0),
            "pending_commands": stats.get("pending_commands", 0),
            "device_ids": stats.get("device_ids", [])
        }

        # Get detailed connection info for each connected device
        for device_id in stats.get("device_ids", []):
            device_status = broker.get_device_status(device_id)
            if device_status:
                diagnostics["devices"].append({
                    "device_id": device_id,
                    "online": True,
                    "session_id": device_status.get("session_id"),
                    "connected_at": device_status.get("connected_at"),
                    "last_heartbeat": device_status.get("last_heartbeat"),
                    "last_status": device_status.get("last_status", {})
                })
    else:
        diagnostics["broker"] = {
            "status": "not running",
            "error": "Tunnel broker not initialized"
        }

    # Database info
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row

            # Count totals
            async with db.execute("SELECT COUNT(*) FROM shops") as cursor:
                diagnostics["database"]["shops"] = (await cursor.fetchone())[0]

            async with db.execute("SELECT COUNT(*) FROM devices") as cursor:
                diagnostics["database"]["devices"] = (await cursor.fetchone())[0]

            async with db.execute("SELECT COUNT(*) FROM users") as cursor:
                diagnostics["database"]["users"] = (await cursor.fetchone())[0]

            # Get offline devices
            async with db.execute(
                """SELECT d.*, s.name as shop_name FROM devices d
                   LEFT JOIN shops s ON d.shop_id = s.id
                   WHERE d.status != 'online'
                   ORDER BY d.last_seen DESC"""
            ) as cursor:
                offline_devices = await cursor.fetchall()
                for device in offline_devices:
                    device_dict = dict(device)
                    device_dict["online"] = False
                    # Check if device is actually online via broker
                    if broker and broker.is_device_online(device_dict["device_id"]):
                        device_dict["online"] = True
                        device_dict["status"] = "online"
                    diagnostics["devices"].append(device_dict)

            # Get pending registration tokens
            async with db.execute(
                """SELECT * FROM registration_tokens
                   WHERE used_at IS NULL
                   ORDER BY expires_at ASC"""
            ) as cursor:
                tokens = await cursor.fetchall()
                for token in tokens:
                    token_dict = dict(token)
                    expires_at = datetime.fromisoformat(token_dict["expires_at"])
                    token_dict["expired"] = datetime.utcnow() > expires_at
                    token_dict["expires_in"] = str(expires_at - datetime.utcnow()) if not token_dict["expired"] else "Expired"
                    diagnostics["pending_tokens"].append(token_dict)

            # Get recent audit log
            async with db.execute(
                """SELECT * FROM audit_log
                   ORDER BY timestamp DESC
                   LIMIT 50"""
            ) as cursor:
                logs = await cursor.fetchall()
                diagnostics["audit_log"] = [dict(log) for log in logs]

            # Check for errors in audit log
            async with db.execute(
                """SELECT * FROM audit_log
                   WHERE result LIKE '%error%' OR result LIKE '%fail%'
                   ORDER BY timestamp DESC
                   LIMIT 20"""
            ) as cursor:
                errors = await cursor.fetchall()
                diagnostics["recent_errors"] = [dict(err) for err in errors]

            diagnostics["database"]["status"] = "connected"
            diagnostics["database"]["path"] = str(DB_PATH)

    except Exception as e:
        diagnostics["database"]["status"] = "error"
        diagnostics["database"]["error"] = str(e)

    return templates.TemplateResponse(
        "pages/diagnostics.html",
        {
            "request": request,
            "user": user,
            "diagnostics": diagnostics
        }
    )


@router.post("/admin/shop/{shop_id}/delete")
async def delete_shop_route(request: Request, shop_id: str, user: dict = Depends(require_auth)):
    """Delete a shop and all its devices."""
    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    # Check if shop exists
    shop = await get_shop_by_id(shop_id)
    if not shop:
        logger.warning(f"Attempted to delete non-existent shop: {shop_id}")
        return RedirectResponse(url="/admin", status_code=302)

    # Disconnect all online devices in this shop
    broker = request.app.state.tunnel_broker
    if broker:
        devices = await get_devices_by_shop(shop_id)
        for device in devices:
            device_id = device.get('device_id')
            if device_id and broker.is_device_online(device_id):
                await broker.disconnect_device(device_id, "Shop deleted")

    # Delete shop (cascades to devices, tokens, user_shops)
    try:
        result = await delete_shop(shop_id)

        await log_audit(
            action="shop_deleted",
            user_id=user['id'],
            shop_id=shop_id,
            details=f"Deleted shop '{shop['name']}' with {result['devices_deleted']} devices",
            ip_address=request.client.host
        )

        logger.info(f"Shop deleted by {user['username']}: {shop_id} ({result['devices_deleted']} devices)")
    except Exception as e:
        logger.error(f"Failed to delete shop {shop_id}: {e}")

    return RedirectResponse(url="/admin", status_code=302)


@router.post("/admin/device/{device_id}/delete")
async def delete_device_route(request: Request, device_id: str, user: dict = Depends(require_auth)):
    """Delete a device from the admin panel."""
    from ..models.database import get_device_by_id

    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    device = await get_device_by_id(device_id)
    if not device:
        return RedirectResponse(url="/admin", status_code=302)

    shop_id = device.get('shop_id')

    # Disconnect if online
    broker = request.app.state.tunnel_broker
    if broker and broker.is_device_online(device_id):
        await broker.disconnect_device(device_id, "Device deleted")

    # Delete device
    import aiosqlite
    from ..models.database import DB_PATH

    async with aiosqlite.connect(DB_PATH) as db:
        # Delete associated registration tokens
        await db.execute(
            "DELETE FROM registration_tokens WHERE used_by_device = ?", (device_id,)
        )
        # Delete device
        await db.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        await db.commit()

    await log_audit(
        action="device_deleted",
        user_id=user['id'],
        device_id=device_id,
        shop_id=shop_id,
        details=f"Deleted device '{device.get('name')}'",
        ip_address=request.client.host
    )

    logger.info(f"Device deleted by {user['username']}: {device_id}")

    # Redirect back to shop or admin
    if shop_id:
        return RedirectResponse(url=f"/shop/{shop_id}", status_code=302)
    return RedirectResponse(url="/admin", status_code=302)
