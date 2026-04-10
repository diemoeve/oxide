"""Screenshots router."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

from ...storage import get_screenshot, list_screenshots
from ..deps import CurrentUser
from ..schemas import Screenshot, ScreenshotListResponse

router = APIRouter(prefix="/api/screenshots", tags=["screenshots"])

DATA_DIR = Path(__file__).parent.parent.parent.parent.parent / "data"


@router.get("", response_model=ScreenshotListResponse)
async def get_screenshots(
    current_user: CurrentUser,
    bot_hwid: str = None,
    limit: int = 100,
):
    """List screenshots, optionally filtered by bot."""
    screenshots = await list_screenshots(bot_hwid=bot_hwid, limit=limit)
    return ScreenshotListResponse(
        screenshots=[Screenshot(**s) for s in screenshots],
        total=len(screenshots),
    )


@router.get("/{screenshot_id}")
async def get_screenshot_info(
    screenshot_id: str,
    current_user: CurrentUser,
):
    """Get information about a specific screenshot."""
    screenshot = await get_screenshot(screenshot_id)
    if not screenshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Screenshot not found",
        )
    return Screenshot(**screenshot)


@router.get("/{screenshot_id}/full")
async def get_screenshot_full(
    screenshot_id: str,
    current_user: CurrentUser,
):
    """Get the full-resolution screenshot image."""
    screenshot = await get_screenshot(screenshot_id)
    if not screenshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Screenshot not found",
        )

    file_path = DATA_DIR / screenshot["local_path"]
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Screenshot file not found on disk",
        )

    return FileResponse(
        path=file_path,
        media_type="image/png",
    )


@router.get("/{screenshot_id}/thumbnail")
async def get_screenshot_thumbnail(
    screenshot_id: str,
    current_user: CurrentUser,
):
    """Get the thumbnail of a screenshot."""
    screenshot = await get_screenshot(screenshot_id)
    if not screenshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Screenshot not found",
        )

    if not screenshot.get("thumbnail_path"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Thumbnail not available",
        )

    file_path = DATA_DIR / screenshot["thumbnail_path"]
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Thumbnail file not found on disk",
        )

    return FileResponse(
        path=file_path,
        media_type="image/png",
    )
