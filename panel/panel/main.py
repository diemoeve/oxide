import argparse
import asyncio
import logging
import threading
from pathlib import Path

import uvicorn

from .api.app import create_app
from .api.auth import ensure_admin_exists
from .api.events import EventBus
from .cli import run_cli
from .handler import handle_client_session
from .listener import Listener
from .registry import Registry
from .storage import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PSK = "lab-changeme-2026"
CERTS_DIR = Path(__file__).parent.parent.parent / "certs"


def load_salt() -> bytes:
    return bytes.fromhex((CERTS_DIR / "salt.hex").read_text().strip())


async def main():
    parser = argparse.ArgumentParser(description="Oxide C2 Panel")
    parser.add_argument("--cli", action="store_true", help="Run CLI interface instead of web panel")
    parser.add_argument("--web-host", default="0.0.0.0", help="Web panel bind address")
    parser.add_argument("--web-port", type=int, default=8080, help="Web panel port")
    parser.add_argument("--c2-host", default="0.0.0.0", help="C2 listener bind address")
    parser.add_argument("--c2-port", type=int, default=4444, help="C2 listener port")
    parser.add_argument("--http-c2", action="store_true",
                        help="Enable HTTPS on uvicorn for HTTP-mode implants")
    parser.add_argument("--http-c2-port", type=int, default=443,
                        help="HTTPS port for HTTP-mode implants (default 443)")
    parser.add_argument("--dns-port", type=int, default=10053)
    args = parser.parse_args()

    # Initialize database
    await init_db()
    await ensure_admin_exists()

    # Create shared components
    registry = Registry()
    event_bus = EventBus()
    salt = load_salt()

    from .dns_server import DnsServer as _DnsServer
    _ds = _DnsServer(port=args.dns_port, psk=PSK, salt=salt, registry=registry)
    threading.Thread(target=_ds.start, daemon=True, name="dns-c2").start()

    # Client connection handler with event bus
    async def on_client(reader, writer, crypto, addr):
        await handle_client_session(reader, writer, crypto, addr, registry, event_bus)

    # Create TLS listener
    listener = Listener(
        host=args.c2_host,
        port=args.c2_port,
        cert_path=str(CERTS_DIR / "server.crt"),
        key_path=str(CERTS_DIR / "server.key"),
        psk=PSK,
        salt=salt,
        on_client_connected=on_client,
    )

    if args.cli:
        # CLI mode - run listener and CLI
        logger.info(f"Starting Oxide C2 (CLI mode) - C2 on {args.c2_host}:{args.c2_port}")
        await asyncio.gather(
            listener.start(),
            run_cli(registry),
        )
    else:
        # Web mode - run listener and FastAPI
        logger.info(f"Starting Oxide C2 - Web on {args.web_host}:{args.web_port}, C2 on {args.c2_host}:{args.c2_port}")
        app = create_app(registry, event_bus)

        # Configure uvicorn to share the event loop
        config = uvicorn.Config(
            app,
            host=args.web_host,
            port=args.http_c2_port if args.http_c2 else args.web_port,
            ssl_certfile=str(CERTS_DIR / "server.crt") if args.http_c2 else None,
            ssl_keyfile=str(CERTS_DIR / "server.key") if args.http_c2 else None,
            loop="none",
            log_level="info",
        )
        server = uvicorn.Server(config)

        await asyncio.gather(
            listener.start(),
            server.serve(),
        )


if __name__ == "__main__":
    asyncio.run(main())
