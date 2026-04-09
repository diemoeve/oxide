import asyncio
import ssl
import logging
from .crypto import CryptoContext

logger = logging.getLogger(__name__)


class Listener:
    def __init__(self, host: str, port: int, cert_path: str, key_path: str,
                 psk: str, salt: bytes, on_client_connected):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.psk = psk
        self.salt = salt
        self.on_client_connected = on_client_connected

    async def start(self):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(self.cert_path, self.key_path)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        server = await asyncio.start_server(
            self._handle_client,
            self.host, self.port, ssl=ssl_ctx,
        )
        addr = server.sockets[0].getsockname()
        logger.info(f"Listening on {addr[0]}:{addr[1]}")
        async with server:
            await server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        crypto = CryptoContext(self.psk, self.salt, is_initiator=False)
        logger.info(f"Client connected: {addr}")
        try:
            await self.on_client_connected(reader, writer, crypto, addr)
        except Exception as e:
            logger.error(f"Client {addr} error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            logger.info(f"Client disconnected: {addr}")
