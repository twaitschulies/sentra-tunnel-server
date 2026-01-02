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
    import bcrypt

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            count = (await cursor.fetchone())[0]

        if count == 0:
            # Create default admin
            password_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode('utf-8')
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


async def delete_shop(shop_id: str) -> dict:
    """
    Delete a shop and all related data (cascade).

    Returns dict with counts of deleted items for audit purposes.
    """
    result = {
        "shop_id": shop_id,
        "devices_deleted": 0,
        "tokens_deleted": 0,
        "user_access_deleted": 0
    }

    async with aiosqlite.connect(DB_PATH) as db:
        # Count and delete devices
        async with db.execute(
            "SELECT COUNT(*) FROM devices WHERE shop_id = ?", (shop_id,)
        ) as cursor:
            result["devices_deleted"] = (await cursor.fetchone())[0]

        await db.execute("DELETE FROM devices WHERE shop_id = ?", (shop_id,))

        # Count and delete registration tokens
        async with db.execute(
            "SELECT COUNT(*) FROM registration_tokens WHERE shop_id = ?", (shop_id,)
        ) as cursor:
            result["tokens_deleted"] = (await cursor.fetchone())[0]

        await db.execute("DELETE FROM registration_tokens WHERE shop_id = ?", (shop_id,))

        # Count and delete user access
        async with db.execute(
            "SELECT COUNT(*) FROM user_shops WHERE shop_id = ?", (shop_id,)
        ) as cursor:
            result["user_access_deleted"] = (await cursor.fetchone())[0]

        await db.execute("DELETE FROM user_shops WHERE shop_id = ?", (shop_id,))

        # Delete the shop itself
        await db.execute("DELETE FROM shops WHERE id = ?", (shop_id,))

        await db.commit()

    logger.info(f"Shop deleted: {shop_id} (devices: {result['devices_deleted']}, tokens: {result['tokens_deleted']})")
    return result


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


# Demo Shop Setup
DEMO_SHOP_ID = "demo_store"
DEMO_DEVICES = [
    {
        "device_id": "demo_haupteingang_001",
        "name": "Haupteingang",
        "api_key": "demo_key_haupteingang_001"
    },
    {
        "device_id": "demo_hintereingang_002",
        "name": "Hintereingang",
        "api_key": "demo_key_hintereingang_002"
    }
]


async def create_demo_shop():
    """Create demo shop with devices for testing."""
    async with aiosqlite.connect(DB_PATH) as db:
        # Check if demo shop exists
        async with db.execute(
            "SELECT id FROM shops WHERE id = ?", (DEMO_SHOP_ID,)
        ) as cursor:
            if await cursor.fetchone():
                logger.debug("Demo shop already exists")
                return

        # Create demo shop
        await db.execute(
            "INSERT INTO shops (id, name) VALUES (?, ?)",
            (DEMO_SHOP_ID, "Demo Store Berlin")
        )

        # Create demo devices
        for device in DEMO_DEVICES:
            await db.execute(
                """INSERT OR REPLACE INTO devices
                   (device_id, shop_id, name, api_key, status, registered_at)
                   VALUES (?, ?, ?, ?, 'online', ?)""",
                (device["device_id"], DEMO_SHOP_ID, device["name"],
                 device["api_key"], datetime.utcnow().isoformat())
            )

        # Give admin user access to demo shop
        async with db.execute(
            "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
        ) as cursor:
            admin = await cursor.fetchone()
            if admin:
                await db.execute(
                    """INSERT OR IGNORE INTO user_shops (user_id, shop_id, permission)
                       VALUES (?, ?, 'control')""",
                    (admin[0], DEMO_SHOP_ID)
                )

        await db.commit()
        logger.info(f"Created demo shop '{DEMO_SHOP_ID}' with {len(DEMO_DEVICES)} devices")


def get_demo_device_ids() -> list[str]:
    """Get list of demo device IDs."""
    return [d["device_id"] for d in DEMO_DEVICES]


def is_demo_device(device_id: str) -> bool:
    """Check if device is a demo device."""
    return device_id in get_demo_device_ids()


# =============================================================================
# User Management Functions
# =============================================================================

async def get_all_users():
    """Get all users with their shop assignments."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT u.*,
                      (SELECT COUNT(*) FROM user_shops WHERE user_id = u.id) as shop_count
               FROM users u
               ORDER BY u.role DESC, u.username ASC"""
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_user_by_id(user_id: int):
    """Get user by ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def create_user(username: str, password: str, role: str = "operator", email: str = None):
    """
    Create a new user.

    Args:
        username: Unique username
        password: Plain text password (will be hashed)
        role: User role (admin or operator)
        email: Optional email address

    Returns:
        New user ID
    """
    import bcrypt

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO users (username, password_hash, role, email)
               VALUES (?, ?, ?, ?)""",
            (username, password_hash, role, email)
        )
        await db.commit()
        return cursor.lastrowid


async def update_user(user_id: int, username: str = None, password: str = None,
                      role: str = None, email: str = None):
    """Update user details."""
    import bcrypt

    async with aiosqlite.connect(DB_PATH) as db:
        if username:
            await db.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (username, user_id)
            )
        if password:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            await db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id)
            )
        if role:
            await db.execute(
                "UPDATE users SET role = ? WHERE id = ?",
                (role, user_id)
            )
        if email is not None:
            await db.execute(
                "UPDATE users SET email = ? WHERE id = ?",
                (email, user_id)
            )
        await db.commit()


async def delete_user(user_id: int) -> bool:
    """
    Delete a user and all their shop assignments.

    Returns:
        True if user was deleted
    """
    async with aiosqlite.connect(DB_PATH) as db:
        # Check if user exists
        async with db.execute(
            "SELECT id FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            if not await cursor.fetchone():
                return False

        # Delete user (cascades to user_shops and sessions)
        await db.execute("DELETE FROM user_shops WHERE user_id = ?", (user_id,))
        await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()
        return True


async def get_user_shop_assignments(user_id: int):
    """Get all shop assignments for a user."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT s.*, us.permission
               FROM shops s
               JOIN user_shops us ON s.id = us.shop_id
               WHERE us.user_id = ?
               ORDER BY s.name""",
            (user_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def assign_user_to_shop(user_id: int, shop_id: str, permission: str = "control"):
    """
    Assign a user to a shop.

    Args:
        user_id: User ID
        shop_id: Shop ID
        permission: Permission level (view, control)
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT OR REPLACE INTO user_shops (user_id, shop_id, permission)
               VALUES (?, ?, ?)""",
            (user_id, shop_id, permission)
        )
        await db.commit()


async def remove_user_from_shop(user_id: int, shop_id: str):
    """Remove a user's access to a shop."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM user_shops WHERE user_id = ? AND shop_id = ?",
            (user_id, shop_id)
        )
        await db.commit()


async def get_shop_users(shop_id: str):
    """Get all users assigned to a shop."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT u.id, u.username, u.email, u.role, us.permission
               FROM users u
               JOIN user_shops us ON u.id = us.user_id
               WHERE us.shop_id = ?
               ORDER BY u.username""",
            (shop_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
