"""
Database Helper Functions for Tunnel Module

Provides async database access for device authentication and status.
"""

import aiosqlite
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Database path
DATA_DIR = Path(__file__).parent.parent.parent / 'data'
DB_PATH = DATA_DIR / 'tunnel.db'


async def get_device_by_id(device_id: str) -> Optional[Dict[str, Any]]:
    """
    Get device by ID from database.

    Args:
        device_id: Device identifier

    Returns:
        Device dict or None
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM devices WHERE device_id = ?",
            (device_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def update_device_status(device_id: str, status: str):
    """
    Update device online status.

    Args:
        device_id: Device identifier
        status: New status ('online' or 'offline')
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE devices SET status = ?, last_seen = ? WHERE device_id = ?",
            (status, datetime.utcnow().isoformat(), device_id)
        )
        await db.commit()


async def get_devices_by_shop(shop_id: str) -> list[Dict[str, Any]]:
    """
    Get all devices for a shop.

    Args:
        shop_id: Shop identifier

    Returns:
        List of device dicts
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM devices WHERE shop_id = ?",
            (shop_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
