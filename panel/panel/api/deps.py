"""Dependency injection for FastAPI routes."""

from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Query, Request, status

from ..registry import Registry
from ..storage import get_session
from .events import EventBus


async def get_registry(request: Request) -> Registry:
    """Get the registry from app state."""
    return request.app.state.registry


async def get_event_bus(request: Request) -> EventBus:
    """Get the event bus from app state."""
    return request.app.state.event_bus


async def get_current_user(
    oxide_session: Annotated[str | None, Cookie()] = None,
) -> dict:
    """
    Get the current authenticated user from session cookie.

    Raises HTTPException 401 if not authenticated.
    """
    if not oxide_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session = await get_session(oxide_session)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    return {
        "id": session["operator_id"],
        "username": session["username"],
    }


async def get_current_user_ws(token: str = Query(...)) -> dict:
    """
    Get the current authenticated user from WebSocket query param.

    For WebSocket connections, we pass the token as a query parameter.
    """
    if not token:
        return None

    session = await get_session(token)
    if not session:
        return None

    return {
        "id": session["operator_id"],
        "username": session["username"],
    }


# Type aliases for dependency injection
CurrentUser = Annotated[dict, Depends(get_current_user)]
RegistryDep = Annotated[Registry, Depends(get_registry)]
EventBusDep = Annotated[EventBus, Depends(get_event_bus)]
