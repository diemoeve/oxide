import asyncio
import logging
from pathlib import Path
from .listener import Listener
from .handler import handle_client_session
from .registry import Registry
from .storage import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PSK = "oxide-lab-psk"
CERTS_DIR = Path(__file__).parent.parent.parent / "certs"
registry = Registry()


def load_salt() -> bytes:
    return bytes.fromhex((CERTS_DIR / "salt.hex").read_text().strip())


async def on_client(reader, writer, crypto, addr):
    await handle_client_session(reader, writer, crypto, addr, registry)


async def main():
    await init_db()
    salt = load_salt()
    listener = Listener(
        host="0.0.0.0", port=4444,
        cert_path=str(CERTS_DIR / "server.crt"),
        key_path=str(CERTS_DIR / "server.key"),
        psk=PSK, salt=salt,
        on_client_connected=on_client,
    )
    await listener.start()


if __name__ == "__main__":
    asyncio.run(main())
