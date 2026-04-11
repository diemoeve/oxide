"""Builder router for generating implant configurations."""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..deps import CurrentUser
from ..schemas import BuilderConfig, BuilderResponse

router = APIRouter(prefix="/api/builder", tags=["builder"])

CERTS_DIR = Path(__file__).parent.parent.parent.parent.parent / "certs"


@router.get("/defaults")
async def get_defaults(current_user: CurrentUser):
    """Get default configuration values."""
    defaults = {
        "c2_host": "127.0.0.1",
        "c2_port": 4444,
        "psk": "oxide-lab-psk",
        "salt_hex": "",
        "cert_hash_hex": "",
        "heartbeat_interval": 30,
    }

    # Try to load salt and cert hash from certs directory
    salt_file = CERTS_DIR / "salt.hex"
    if salt_file.exists():
        defaults["salt_hex"] = salt_file.read_text().strip()

    cert_hash_file = CERTS_DIR / "cert_hash.hex"
    if cert_hash_file.exists():
        defaults["cert_hash_hex"] = cert_hash_file.read_text().strip()

    return defaults


@router.post("", response_model=BuilderResponse)
async def generate_config(
    config: BuilderConfig,
    current_user: CurrentUser,
):
    """
    Generate an implant configuration file.

    This creates a JSON config that can be used with the implant.
    Binary patching is not implemented in this version.
    """
    config_dict = {
        "c2_host": config.c2_host,
        "c2_port": config.c2_port,
        "psk": config.psk,
        "salt_hex": config.salt_hex,
        "cert_hash_hex": config.cert_hash_hex,
        "heartbeat_interval": config.heartbeat_interval,
    }

    return BuilderResponse(
        config=config_dict,
        filename="oxide_config.json",
    )


@router.post("/download")
async def download_config(
    config: BuilderConfig,
    current_user: CurrentUser,
):
    """Download the configuration as a JSON file."""
    config_dict = {
        "c2_host": config.c2_host,
        "c2_port": config.c2_port,
        "psk": config.psk,
        "salt_hex": config.salt_hex,
        "cert_hash_hex": config.cert_hash_hex,
        "heartbeat_interval": config.heartbeat_interval,
    }

    return JSONResponse(
        content=config_dict,
        headers={
            "Content-Disposition": "attachment; filename=oxide_config.json",
        },
    )
