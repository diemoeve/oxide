import json
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from panel.crypto import StatelessCrypto
from panel.api.events import EventBus
from panel.registry import Registry
from panel.storage import init_db

PSK = "oxide-lab-psk"
SALT = b"test-salt-must-be-32-bytes-long!"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def client():
    from panel.api.app import create_app
    registry = Registry()
    event_bus = EventBus()
    app = create_app(registry, event_bus)
    app.state.stateless_crypto = StatelessCrypto(PSK, SALT)
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.anyio
async def test_beacon_checkin_returns_ack(client):
    sc = StatelessCrypto(PSK, SALT)
    packet = {
        "id": "t001", "seq": 0, "timestamp": 0, "type": "checkin",
        "data": {"hwid": "test-hwid-beacon", "os": "linux", "hostname": "h",
                 "username": "u", "arch": "x86_64", "privileges": "user", "av": []},
    }
    resp = await client.post("/c2/beacon",
                             content=sc.encrypt(json.dumps(packet).encode()),
                             headers={"Content-Type": "application/octet-stream"})
    assert resp.status_code == 200
    ack = json.loads(sc.decrypt(resp.content))
    assert ack["type"] == "checkin_ack"
    assert "session_id" in ack["data"]


@pytest.mark.anyio
async def test_beacon_heartbeat_no_commands_returns_204(client):
    sc = StatelessCrypto(PSK, SALT)
    checkin = {"id": "ci002", "seq": 0, "timestamp": 0, "type": "checkin",
               "data": {"hwid": "hb-hwid", "os": "linux", "hostname": "h",
                        "username": "u", "arch": "x86_64", "privileges": "user", "av": []}}
    await client.post("/c2/beacon", content=sc.encrypt(json.dumps(checkin).encode()),
                      headers={"Content-Type": "application/octet-stream"})
    hb = {"id": "hb003", "seq": 1, "timestamp": 0, "type": "heartbeat",
          "data": {"hwid": "hb-hwid"}}
    resp = await client.post("/c2/beacon", content=sc.encrypt(json.dumps(hb).encode()),
                             headers={"Content-Type": "application/octet-stream"})
    assert resp.status_code == 204


@pytest.mark.anyio
async def test_beacon_empty_body_returns_400(client):
    resp = await client.post("/c2/beacon", content=b"",
                             headers={"Content-Type": "application/octet-stream"})
    assert resp.status_code == 400
