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
from ..models.database import get_user_shops, get_devices_by_shop, get_all_shops

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
            status = broker.get_device_status(device['device_id'])
            if status:
                device['online'] = True
                device['last_status'] = status.get('last_status', {})
            else:
                device['online'] = False

    return templates.TemplateResponse(
        "pages/shop.html",
        {
            "request": request,
            "user": user,
            "shop_id": shop_id,
            "devices": devices
        }
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
