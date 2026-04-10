"""Polling helpers for test conditions."""

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class TimeoutError(Exception):
    """Raised when a wait condition times out."""

    pass


async def wait_for(
    condition: Callable[[], Awaitable[T]],
    timeout: float = 30.0,
    interval: float = 1.0,
    description: str = "condition",
) -> T:
    """Wait for an async condition to return a truthy value."""
    start = time.monotonic()
    last_result = None

    while time.monotonic() - start < timeout:
        try:
            result = await condition()
            if result:
                return result
            last_result = result
        except Exception as e:
            logger.debug(f"Condition check failed: {e}")
            last_result = e

        await asyncio.sleep(interval)

    raise TimeoutError(
        f"Timeout waiting for {description} after {timeout}s. Last result: {last_result}"
    )


async def wait_for_bot_online(
    api_client,
    hwid: str,
    timeout: float = 90.0,
) -> dict:
    """Wait for a bot to appear online in the panel."""

    async def check():
        bot = await api_client.get_bot(hwid)
        return bot if bot and bot.get("status") == "online" else None

    return await wait_for(check, timeout=timeout, description=f"bot {hwid[:16]} online")


async def wait_for_bot_status(
    api_client,
    hwid: str,
    status: str,
    timeout: float = 90.0,
) -> dict:
    """Wait for a bot to reach a specific status."""

    async def check():
        bot = await api_client.get_bot(hwid)
        return bot if bot and bot.get("status") == status else None

    return await wait_for(
        check, timeout=timeout, description=f"bot {hwid[:16]} status={status}"
    )


async def wait_for_response(
    api_client,
    command_id: str,
    timeout: float = 30.0,
) -> dict:
    """Wait for a command response."""

    async def check():
        cmd = await api_client.get_command(command_id)
        if cmd and cmd.get("response_status"):
            return {
                "command_id": command_id,
                "status": cmd.get("response_status"),
                "data": cmd.get("response_data"),
            }
        return None

    return await wait_for(
        check, timeout=timeout, description=f"response for {command_id[:8]}"
    )


async def wait_for_bot_count(
    api_client,
    count: int,
    status: str = "online",
    timeout: float = 60.0,
) -> list[dict]:
    """Wait for a specific number of bots to be online."""

    async def check():
        bots = await api_client.get_bots()
        matching = [b for b in bots if b.get("status") == status]
        return matching if len(matching) >= count else None

    return await wait_for(
        check, timeout=timeout, description=f"{count} bots with status={status}"
    )


def sync_wait_for(
    condition: Callable[[], T],
    timeout: float = 30.0,
    interval: float = 1.0,
    description: str = "condition",
) -> T:
    """Wait for a sync condition to return a truthy value."""
    start = time.monotonic()
    last_result = None

    while time.monotonic() - start < timeout:
        try:
            result = condition()
            if result:
                return result
            last_result = result
        except Exception as e:
            logger.debug(f"Condition check failed: {e}")
            last_result = e

        time.sleep(interval)

    raise TimeoutError(
        f"Timeout waiting for {description} after {timeout}s. Last result: {last_result}"
    )
