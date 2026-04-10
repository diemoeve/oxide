"""Downloads router."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

from ...storage import get_download, list_downloads
from ..deps import CurrentUser
from ..schemas import Download, DownloadListResponse

router = APIRouter(prefix="/api/downloads", tags=["downloads"])

DATA_DIR = Path(__file__).parent.parent.parent.parent.parent / "data"


@router.get("", response_model=DownloadListResponse)
async def get_downloads(
    current_user: CurrentUser,
    bot_hwid: str = None,
    limit: int = 100,
):
    """List downloaded files, optionally filtered by bot."""
    downloads = await list_downloads(bot_hwid=bot_hwid, limit=limit)
    return DownloadListResponse(
        downloads=[Download(**d) for d in downloads],
        total=len(downloads),
    )


@router.get("/{download_id}")
async def get_download_info(
    download_id: str,
    current_user: CurrentUser,
):
    """Get information about a specific download."""
    download = await get_download(download_id)
    if not download:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Download not found",
        )
    return Download(**download)


@router.get("/{download_id}/file")
async def download_file(
    download_id: str,
    current_user: CurrentUser,
):
    """Download the actual file."""
    download = await get_download(download_id)
    if not download:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Download not found",
        )

    file_path = DATA_DIR / download["local_path"]
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on disk",
        )

    return FileResponse(
        path=file_path,
        filename=download["filename"],
        media_type="application/octet-stream",
    )
