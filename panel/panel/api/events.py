"""Event system for WebSocket broadcasting."""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Event types for WebSocket broadcasting."""
    BOT_CONNECTED = "bot_connected"
    BOT_DISCONNECTED = "bot_disconnected"
    BOT_HEARTBEAT = "bot_heartbeat"
    COMMAND_QUEUED = "command_queued"
    COMMAND_DISPATCHED = "command_dispatched"
    COMMAND_COMPLETED = "command_completed"
    RESPONSE_RECEIVED = "response_received"
    FILE_EXTRACTED = "file_extracted"
    SCREENSHOT_EXTRACTED = "screenshot_extracted"
    STEAL_COMPLETED = "steal_completed"


@dataclass
class Event:
    """Event to broadcast via WebSocket."""
    type: EventType
    data: dict
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp,
        }


class EventBus:
    """
    Pub/sub event bus for WebSocket broadcasting.

    Each WebSocket client subscribes and gets an async queue.
    Events are published to all subscriber queues.
    Slow clients (queue full) are dropped to prevent backpressure.
    """

    def __init__(self, max_queue_size: int = 100):
        self._subscribers: set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()
        self._max_queue_size = max_queue_size
        self._last_heartbeat: dict[str, int] = {}  # hwid -> timestamp
        self._heartbeat_throttle = 30  # seconds

    async def subscribe(self) -> asyncio.Queue:
        """Subscribe to events, returns a queue to read from."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue_size)
        async with self._lock:
            self._subscribers.add(queue)
            logger.debug(f"New subscriber, total: {len(self._subscribers)}")
        return queue

    async def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe from events."""
        async with self._lock:
            self._subscribers.discard(queue)
            logger.debug(f"Subscriber removed, total: {len(self._subscribers)}")

    async def publish(self, event: Event):
        """
        Publish an event to all subscribers.

        Heartbeat events are throttled per-bot to reduce noise.
        Slow clients that can't keep up are dropped.
        """
        # Throttle heartbeat events
        if event.type == EventType.BOT_HEARTBEAT:
            hwid = event.data.get("hwid", "")
            now = int(time.time())
            last = self._last_heartbeat.get(hwid, 0)
            if now - last < self._heartbeat_throttle:
                return  # Skip this heartbeat
            self._last_heartbeat[hwid] = now

        async with self._lock:
            dead_queues = []
            for queue in self._subscribers:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    dead_queues.append(queue)
                    logger.warning("Dropping slow WebSocket client")

            for q in dead_queues:
                self._subscribers.discard(q)

    @property
    def subscriber_count(self) -> int:
        """Number of active subscribers."""
        return len(self._subscribers)


# Global event bus instance (set during app startup)
_event_bus: EventBus | None = None


def get_event_bus() -> EventBus | None:
    """Get the global event bus instance."""
    return _event_bus


def set_event_bus(bus: EventBus):
    """Set the global event bus instance."""
    global _event_bus
    _event_bus = bus
