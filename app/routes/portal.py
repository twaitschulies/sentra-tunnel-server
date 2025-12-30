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
    create_shop, create_registration_token, get_shop_by_id
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
                else:
                    device['online'] = False

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
