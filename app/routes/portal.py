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

    # Verify access and get permission
    can_control = True
    if user.get('role') != 'admin':
        user_shops = await get_user_shops(user['id'])
        shop_access = next(
            (s for s in user_shops if s['id'] == device.get('shop_id')),
            None
        )
        if not shop_access:
            return RedirectResponse(url="/dashboard", status_code=302)
        can_control = shop_access.get('permission') == 'control'

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
            "device": device,
            "can_control": can_control
        }
    )


# Admin routes
@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, user: dict = Depends(require_auth)):
    """
    Admin page - manage shops, devices, and users.
    """
    from ..models.database import get_all_users, get_user_shop_assignments

    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    shops = await get_all_shops()

    # Enrich shops with device counts
    for shop in shops:
        devices = await get_devices_by_shop(shop['id'])
        shop['device_count'] = len(devices)
        shop['devices'] = devices

    # Get all users with their shop assignments
    users = await get_all_users()
    for u in users:
        u['shops'] = await get_user_shop_assignments(u['id'])

    return templates.TemplateResponse(
        "pages/admin.html",
        {
            "request": request,
            "user": user,
            "shops": shops,
            "users": users
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


# =============================================================================
# User Management Routes
# =============================================================================

@router.post("/admin/user/create")
async def create_user_route(request: Request, user: dict = Depends(require_auth)):
    """Create a new user."""
    from ..models.database import create_user, get_user_by_username

    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    form = await request.form()
    username = form.get('username', '').strip().lower()
    password = form.get('password', '').strip()
    role = form.get('role', 'operator')
    email = form.get('email', '').strip() or None

    if not username or not password:
        logger.warning("User creation failed: missing username or password")
        return RedirectResponse(url="/admin", status_code=302)

    # Check if username already exists
    existing = await get_user_by_username(username)
    if existing:
        logger.warning(f"User creation failed: username '{username}' already exists")
        return RedirectResponse(url="/admin", status_code=302)

    try:
        new_user_id = await create_user(username, password, role, email)

        await log_audit(
            action="user_created",
            user_id=user['id'],
            details=f"Created user '{username}' with role '{role}'",
            ip_address=request.client.host
        )

        logger.info(f"User created by {user['username']}: {username} (role: {role})")
    except Exception as e:
        logger.error(f"Failed to create user: {e}")

    return RedirectResponse(url="/admin", status_code=302)


@router.post("/admin/user/{user_id}/delete")
async def delete_user_route(request: Request, user_id: int, user: dict = Depends(require_auth)):
    """Delete a user."""
    from ..models.database import delete_user, get_user_by_id

    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    # Prevent self-deletion
    if user['id'] == user_id:
        logger.warning(f"User {user['username']} tried to delete themselves")
        return RedirectResponse(url="/admin", status_code=302)

    target_user = await get_user_by_id(user_id)
    if not target_user:
        return RedirectResponse(url="/admin", status_code=302)

    try:
        await delete_user(user_id)

        await log_audit(
            action="user_deleted",
            user_id=user['id'],
            details=f"Deleted user '{target_user['username']}'",
            ip_address=request.client.host
        )

        logger.info(f"User deleted by {user['username']}: {target_user['username']}")
    except Exception as e:
        logger.error(f"Failed to delete user: {e}")

    return RedirectResponse(url="/admin", status_code=302)


@router.post("/admin/user/{user_id}/update")
async def update_user_route(request: Request, user_id: int, user: dict = Depends(require_auth)):
    """Update a user."""
    from ..models.database import update_user, get_user_by_id

    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    target_user = await get_user_by_id(user_id)
    if not target_user:
        return RedirectResponse(url="/admin", status_code=302)

    form = await request.form()
    password = form.get('password', '').strip() or None
    role = form.get('role', '').strip() or None
    email = form.get('email', '').strip()

    # Only update email if provided (allow empty to clear)
    email_update = email if 'email' in form.keys() else None

    try:
        await update_user(user_id, password=password, role=role, email=email_update)

        changes = []
        if password:
            changes.append("password")
        if role:
            changes.append(f"role={role}")
        if email_update is not None:
            changes.append(f"email={email_update or 'cleared'}")

        await log_audit(
            action="user_updated",
            user_id=user['id'],
            details=f"Updated user '{target_user['username']}': {', '.join(changes)}",
            ip_address=request.client.host
        )

        logger.info(f"User updated by {user['username']}: {target_user['username']}")
    except Exception as e:
        logger.error(f"Failed to update user: {e}")

    return RedirectResponse(url="/admin", status_code=302)


@router.post("/admin/user/{user_id}/assign-shop")
async def assign_shop_route(request: Request, user_id: int, user: dict = Depends(require_auth)):
    """Assign a user to a shop."""
    from ..models.database import assign_user_to_shop, get_user_by_id, get_shop_by_id

    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    form = await request.form()
    shop_id = form.get('shop_id', '').strip()
    permission = form.get('permission', 'control')

    target_user = await get_user_by_id(user_id)
    shop = await get_shop_by_id(shop_id)

    if not target_user or not shop:
        return RedirectResponse(url="/admin", status_code=302)

    try:
        await assign_user_to_shop(user_id, shop_id, permission)

        await log_audit(
            action="user_shop_assigned",
            user_id=user['id'],
            shop_id=shop_id,
            details=f"Assigned user '{target_user['username']}' to shop '{shop['name']}' ({permission})",
            ip_address=request.client.host
        )

        logger.info(f"User {target_user['username']} assigned to shop {shop_id} by {user['username']}")
    except Exception as e:
        logger.error(f"Failed to assign user to shop: {e}")

    return RedirectResponse(url="/admin", status_code=302)


@router.post("/admin/user/{user_id}/remove-shop/{shop_id}")
async def remove_shop_route(request: Request, user_id: int, shop_id: str, user: dict = Depends(require_auth)):
    """Remove a user from a shop."""
    from ..models.database import remove_user_from_shop, get_user_by_id

    if user.get('role') != 'admin':
        return RedirectResponse(url="/dashboard", status_code=302)

    target_user = await get_user_by_id(user_id)
    if not target_user:
        return RedirectResponse(url="/admin", status_code=302)

    try:
        await remove_user_from_shop(user_id, shop_id)

        await log_audit(
            action="user_shop_removed",
            user_id=user['id'],
            shop_id=shop_id,
            details=f"Removed user '{target_user['username']}' from shop '{shop_id}'",
            ip_address=request.client.host
        )

        logger.info(f"User {target_user['username']} removed from shop {shop_id} by {user['username']}")
    except Exception as e:
        logger.error(f"Failed to remove user from shop: {e}")

    return RedirectResponse(url="/admin", status_code=302)
