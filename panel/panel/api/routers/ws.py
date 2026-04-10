"""WebSocket router for real-time events."""

import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from ..deps import get_current_user_ws
from ..events import EventBus

router = APIRouter(tags=["websocket"])
logger = logging.getLogger(__name__)


@router.websocket("/api/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(None),
):
    """
    WebSocket endpoint for real-time events.

    Connect with ?token=<session_token> for authentication.
    Events are pushed as JSON messages.
    """
    # Validate authentication
    user = await get_current_user_ws(token)
    if not user:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await websocket.accept()
    logger.info(f"WebSocket connected: {user['username']}")

    # Get event bus from app state
    event_bus: EventBus = websocket.app.state.event_bus
    queue = await event_bus.subscribe()

    try:
        while True:
            # Wait for events from the bus
            event = await queue.get()
            try:
                await websocket.send_json(event.to_dict())
            except Exception as e:
                logger.warning(f"Failed to send WebSocket message: {e}")
                break
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {user['username']}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await event_bus.unsubscribe(queue)
