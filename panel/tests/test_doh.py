import struct
import pytest
from httpx import AsyncClient, ASGITransport
from panel.api.app import create_app
from panel.api.events import EventBus
from panel.registry import Registry


@pytest.mark.asyncio
async def test_doh_valid_response():
    app = create_app(Registry(), EventBus())
    name = b"\x04test\x05oxide\x03lab\x00"
    pkt = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 16, 1)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as c:
        r = await c.post(
            "/dns-query",
            content=pkt,
            headers={"Content-Type": "application/dns-message"},
        )
    assert r.status_code == 200
    assert "dns-message" in r.headers["content-type"]
    assert len(r.content) >= 12
    assert r.content[2] & 0x80  # QR bit set
