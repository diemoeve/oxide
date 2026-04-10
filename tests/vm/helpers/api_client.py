"""Panel REST API client for tests."""

import asyncio
import json
import logging
from typing import Any

import httpx
import websockets

logger = logging.getLogger(__name__)


class PanelAPIClient:
    """Async HTTP client for the Oxide panel API."""

    def __init__(self, base_url: str = "http://10.10.100.10:8080"):
        self.base_url = base_url.rstrip("/")
        self.token: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Client not initialized. Use 'async with' context.")
        return self._client

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Cookie"] = f"session={self.token}"
        return headers

    async def login(self, username: str = "admin", password: str = "oxide") -> bool:
        """Login to the panel."""
        resp = await self.client.post(
            f"{self.base_url}/api/auth/login",
            json={"username": username, "password": password},
        )
        if resp.status_code == 200:
            data = resp.json()
            self.token = data.get("token")
            logger.info(f"Logged in as {username}")
            return True
        logger.error(f"Login failed: {resp.text}")
        return False

    async def logout(self) -> None:
        """Logout from the panel."""
        if self.token:
            await self.client.post(
                f"{self.base_url}/api/auth/logout",
                headers=self._headers(),
            )
            self.token = None

    async def get_bots(self) -> list[dict]:
        """Get all bots."""
        resp = await self.client.get(
            f"{self.base_url}/api/bots",
            headers=self._headers(),
        )
        if resp.status_code == 200:
            return resp.json().get("bots", [])
        return []

    async def get_bot(self, hwid: str) -> dict | None:
        """Get a specific bot by HWID."""
        resp = await self.client.get(
            f"{self.base_url}/api/bots/{hwid}",
            headers=self._headers(),
        )
        if resp.status_code == 200:
            return resp.json()
        return None

    async def send_command(
        self,
        hwid: str,
        command_type: str,
        args: dict[str, Any] | None = None,
    ) -> dict:
        """Send a command to a bot."""
        resp = await self.client.post(
            f"{self.base_url}/api/bots/{hwid}/commands",
            headers=self._headers(),
            json={"command_type": command_type, "args": args or {}},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_command(self, command_id: str) -> dict | None:
        """Get command status and response."""
        resp = await self.client.get(
            f"{self.base_url}/api/commands",
            headers=self._headers(),
        )
        if resp.status_code == 200:
            commands = resp.json().get("commands", [])
            for cmd in commands:
                if cmd.get("id") == command_id:
                    return cmd
        return None

    async def get_commands(self, hwid: str | None = None) -> list[dict]:
        """Get command history."""
        url = f"{self.base_url}/api/bots/{hwid}/commands" if hwid else f"{self.base_url}/api/commands"
        resp = await self.client.get(url, headers=self._headers())
        if resp.status_code == 200:
            return resp.json().get("commands", [])
        return []

    async def health_check(self) -> bool:
        """Check if panel is healthy."""
        try:
            resp = await self.client.get(f"{self.base_url}/api/health", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False

    async def connect_websocket(self):
        """Connect to the panel's WebSocket endpoint."""
        ws_url = self.base_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = f"{ws_url}/api/ws"

        extra_headers = {}
        if self.token:
            extra_headers["Cookie"] = f"session={self.token}"

        ws = await websockets.connect(ws_url, additional_headers=extra_headers)
        logger.info(f"Connected to WebSocket at {ws_url}")
        return ws

    async def get_websocket_events(self, ws, timeout: float = 10.0) -> list[dict]:
        """Collect events from WebSocket until timeout."""
        events = []
        try:
            async with asyncio.timeout(timeout):
                while True:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        event = json.loads(msg)
                        events.append(event)
                    except asyncio.TimeoutError:
                        continue
        except asyncio.TimeoutError:
            pass
        except websockets.exceptions.ConnectionClosed:
            pass
        return events
