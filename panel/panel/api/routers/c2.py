"""C2 HTTP beacon endpoint for HTTP-mode implants."""

import logging
from fastapi import APIRouter, Request, Response

router = APIRouter(tags=["c2"])
logger = logging.getLogger(__name__)


@router.post("/c2/beacon")
async def beacon(request: Request) -> Response:
    from ...http_handler import handle_beacon
    body = await request.body()
    if not body:
        return Response(status_code=400)
    result = await handle_beacon(
        body, request.app.state.stateless_crypto,
        request.app.state.registry, request.app.state.event_bus,
    )
    if result is None:
        return Response(status_code=204)
    return Response(content=result, media_type="application/octet-stream", status_code=200)
