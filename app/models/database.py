"""
Database Module

SQLite database initialization and connection management.
"""

import aiosqlite
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

# Database path
DATA_DIR = Path(__file__).parent.parent.parent / 'data'
DB_PATH = DATA_DIR / 'tunnel.db'

# SQL Schema
SCHEMA = """
-- Shops (Mandanten/Tenants)
CREATE TABLE IF NOT EXISTS shops (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Devices (Raspberry Pi door controllers)
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    shop_id TEXT REFERENCES shops(id),
    name TEXT,
    mac_address TEXT UNIQUE,
    api_key TEXT NOT NULL,
    fingerprint TEXT,
    registered_at TIMESTAMP,
    last_seen TIMESTAMP,
    status TEXT DEFAULT 'offline'
);

-- Portal Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'operator',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- User-Shop Access (many-to-many)
CREATE TABLE IF NOT EXISTS user_shops (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    shop_id TEXT REFERENCES shops(id) ON DELETE CASCADE,
    permission TEXT DEFAULT 'view',
    PRIMARY KEY (user_id, shop_id)
);

-- Registration Tokens (one-time use)
CREATE TABLE IF NOT EXISTS registration_tokens (
    token TEXT PRIMARY KEY,
    shop_id TEXT REFERENCES shops(id),
    device_name TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    used_by_device TEXT
);

-- Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER REFERENCES users(id),
    device_id TEXT,
    shop_id TEXT,
    action TEXT NOT NULL,
    details TEXT,
    result TEXT,
    ip_address TEXT
);

-- Sessions (for portal login)
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_devices_shop ON devices(shop_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_user_shops_user ON user_shops(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
"""


async def init_database():
    """Initialize database with schema."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    logger.info(f"Database initialized at {DB_PATH}")

    # Create default admin user if not exists
    await create_default_admin()


async def create_default_admin():
    """Create default admin user if no users exist."""
    from passlib.hash import bcrypt

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            count = (await cursor.fetchone())[0]

        if count == 0:
            # Create default admin
            password_hash = bcrypt.hash("admin")
            await db.execute(
                """INSERT INTO users (username, password_hash, role, email)
                   VALUES (?, ?, ?, ?)""",
                ("admin", password_hash, "admin", "admin@localhost")
            )
            await db.commit()
            logger.info("Created default admin user (username: admin, password: admin)")


async def get_db():
    """Get database connection (async context manager)."""
    return aiosqlite.connect(DB_PATH)


# Device operations
async def get_device_by_id(device_id: str):
    """Get device by ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def update_device_status(device_id: str, status: str):
    """Update device status."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE devices SET status = ?, last_seen = ? WHERE device_id = ?",
            (status, datetime.utcnow().isoformat(), device_id)
        )
        await db.commit()


async def get_devices_by_shop(shop_id: str):
    """Get all devices for a shop."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM devices WHERE shop_id = ?", (shop_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


# User operations
async def get_user_by_username(username: str):
    """Get user by username."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def get_user_shops(user_id: int):
    """Get shops accessible by user."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT s.*, us.permission
               FROM shops s
               JOIN user_shops us ON s.id = us.shop_id
               WHERE us.user_id = ?""",
            (user_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


# Shop operations
async def get_all_shops():
    """Get all shops."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM shops") as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def create_shop(shop_id: str, name: str):
    """Create a new shop."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO shops (id, name) VALUES (?, ?)",
            (shop_id, name)
        )
        await db.commit()


# Device creation
async def create_device(device_id: str, shop_id: str, name: str, api_key: str):
    """Create a new device."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO devices (device_id, shop_id, name, api_key, status)
               VALUES (?, ?, ?, ?, 'pending')""",
            (device_id, shop_id, name, api_key)
        )
        await db.commit()


async def get_shop_by_id(shop_id: str):
    """Get shop by ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM shops WHERE id = ?", (shop_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


# Registration token operations
async def create_registration_token(token: str, shop_id: str, device_name: str, expires_at: str):
    """Create a registration token."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO registration_tokens (token, shop_id, device_name, expires_at)
               VALUES (?, ?, ?, ?)""",
            (token, shop_id, device_name, expires_at)
        )
        await db.commit()


async def get_registration_token(token: str):
    """Get registration token."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM registration_tokens WHERE token = ?", (token,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def mark_token_used(token: str, device_id: str):
    """Mark token as used."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE registration_tokens SET used_at = ?, used_by_device = ? WHERE token = ?",
            (datetime.utcnow().isoformat(), device_id, token)
        )
        await db.commit()


async def register_device(device_id: str, shop_id: str, name: str, api_key: str, mac_address: str = None, fingerprint: str = None):
    """Register a device (from Pi registration)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT OR REPLACE INTO devices
               (device_id, shop_id, name, api_key, mac_address, fingerprint, registered_at, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'offline')""",
            (device_id, shop_id, name, api_key, mac_address, fingerprint, datetime.utcnow().isoformat())
        )
        await db.commit()


async def get_device_by_api_key(api_key: str):
    """Get device by API key."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM devices WHERE api_key = ?", (api_key,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


# Audit logging
async def log_audit(
    action: str,
    user_id: int = None,
    device_id: str = None,
    shop_id: str = None,
    details: str = None,
    result: str = None,
    ip_address: str = None
):
    """Log an audit event."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO audit_log
               (user_id, device_id, shop_id, action, details, result, ip_address)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, device_id, shop_id, action, details, result, ip_address)
        )
        await db.commit()
