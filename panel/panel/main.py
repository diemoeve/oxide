import asyncio
import logging
from pathlib import Path
from .listener import Listener
from .protocol import read_packet, write_packet

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger(__name__)

PSK = "oxide-lab-psk"
CERTS_DIR = Path(__file__).parent.parent.parent / "certs"


def load_salt() -> bytes:
    salt_hex = (CERTS_DIR / "salt.hex").read_text().strip()
    return bytes.fromhex(salt_hex)


async def handle_client(reader, writer, crypto, addr):
    logger.info(f"Waiting for packet from {addr}...")
    packet = await read_packet(reader, crypto)
    logger.info(f"Received: {packet}")
    ack = {
        "id": packet.get("id", ""),
        "seq": 0,
        "timestamp": int(asyncio.get_event_loop().time()),
        "type": "checkin_ack",
        "data": {"session_id": "skeleton-session", "heartbeat_interval": 30},
    }
    await write_packet(writer, crypto, ack)
    logger.info(f"Sent ack to {addr}")


async def main():
    salt = load_salt()
    listener = Listener(
        host="0.0.0.0",
        port=4444,
        cert_path=str(CERTS_DIR / "server.crt"),
        key_path=str(CERTS_DIR / "server.key"),
        psk=PSK,
        salt=salt,
        on_client_connected=handle_client,
    )
    await listener.start()


if __name__ == "__main__":
    asyncio.run(main())
