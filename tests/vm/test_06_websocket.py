"""WebSocket scaling and event broadcasting tests."""

import asyncio
import pytest

from .helpers.wait_conditions import wait_for_bot_count


@pytest.mark.asyncio
async def test_multiple_websocket_clients_receive_events(panel_client, target_vm_1, vm_manager):
    """Multiple WebSocket clients all receive bot events."""
    # Create 5 additional WebSocket connections
    ws_clients = []
    for _ in range(5):
        ws = await panel_client.connect_websocket()
        ws_clients.append(ws)

    # Start implant to trigger BOT_CONNECTED event
    vm_manager.run_ssh_command(
        target_vm_1,
        "pkill -9 oxide-implant; sleep 1; OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    # Wait for bot to connect via API
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Give WebSocket events time to propagate
    await asyncio.sleep(2)

    # Check each WebSocket client received the event
    events_received = 0
    for ws in ws_clients:
        events = await panel_client.get_websocket_events(ws, timeout=5)
        for event in events:
            if event.get("type") == "bot_connected" and event.get("hwid") == hwid:
                events_received += 1
                break

    # Close WebSocket connections
    for ws in ws_clients:
        await ws.close()

    # All clients should have received the event
    assert events_received == 5, f"Only {events_received}/5 clients received bot_connected event"


@pytest.mark.asyncio
async def test_websocket_receives_command_responses(panel_client, target_vm_1, vm_manager):
    """WebSocket client receives command response events."""
    # Connect WebSocket
    ws = await panel_client.connect_websocket()

    # Start implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Send a command
    result = await panel_client.send_command(hwid, "shell", {"command": "echo ws-test"})
    cmd_id = result["command_id"]

    # Wait for response event via WebSocket
    events = await panel_client.get_websocket_events(ws, timeout=30)
    await ws.close()

    # Find command response event
    response_event = None
    for event in events:
        if event.get("type") == "command_response" and event.get("command_id") == cmd_id:
            response_event = event
            break

    assert response_event is not None, "Did not receive command_response event"
    assert response_event.get("status") == "success"


@pytest.mark.asyncio
async def test_websocket_bot_disconnect_event(panel_client, target_vm_1, vm_manager):
    """WebSocket receives bot disconnect events."""
    # Start implant first
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Connect WebSocket after bot is online
    ws = await panel_client.connect_websocket()

    # Kill the implant
    vm_manager.run_ssh_command(target_vm_1, "pkill -9 oxide-implant", check=False)

    # Wait for disconnect event (may take up to heartbeat timeout)
    events = await panel_client.get_websocket_events(ws, timeout=90)
    await ws.close()

    # Find disconnect event
    disconnect_event = None
    for event in events:
        if event.get("type") == "bot_disconnected" and event.get("hwid") == hwid:
            disconnect_event = event
            break

    assert disconnect_event is not None, "Did not receive bot_disconnected event"


@pytest.mark.asyncio
async def test_slow_websocket_client_does_not_block_others(panel_client, target_vm_1, vm_manager):
    """A slow WebSocket client doesn't block event delivery to fast clients."""
    # Create fast and slow clients
    fast_ws = await panel_client.connect_websocket()
    slow_ws = await panel_client.connect_websocket()

    # Start implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "pkill -9 oxide-implant; sleep 1; OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Don't read from slow_ws (simulating slow client)
    # Fast client should still receive events

    # Check fast client gets events
    events = await panel_client.get_websocket_events(fast_ws, timeout=10)

    await fast_ws.close()
    await slow_ws.close()

    # Fast client should have received bot_connected
    bot_event = None
    for event in events:
        if event.get("type") == "bot_connected" and event.get("hwid") == hwid:
            bot_event = event
            break

    assert bot_event is not None, "Fast client did not receive event (slow client may have blocked)"


@pytest.mark.asyncio
async def test_websocket_reconnect(panel_client, target_vm_1, vm_manager):
    """WebSocket client can reconnect and continue receiving events."""
    # Start implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Connect, disconnect, reconnect
    ws1 = await panel_client.connect_websocket()
    await ws1.close()

    ws2 = await panel_client.connect_websocket()

    # Send a command to generate an event
    from .helpers.wait_conditions import wait_for_response
    result = await panel_client.send_command(hwid, "shell", {"command": "echo reconnect-test"})
    await wait_for_response(panel_client, result["command_id"], timeout=30)

    # Check reconnected WebSocket receives events
    events = await panel_client.get_websocket_events(ws2, timeout=10)
    await ws2.close()

    # Should have received command_response event
    response_event = None
    for event in events:
        if event.get("type") == "command_response":
            response_event = event
            break

    assert response_event is not None, "Reconnected WebSocket did not receive events"


@pytest.mark.asyncio
async def test_ten_concurrent_websocket_clients(panel_client, target_vm_1, vm_manager):
    """Ten WebSocket clients can connect and receive events concurrently."""
    # Create 10 WebSocket connections
    ws_clients = []
    for _ in range(10):
        ws = await panel_client.connect_websocket()
        ws_clients.append(ws)

    # Start implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "pkill -9 oxide-implant; sleep 1; OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Give events time to propagate
    await asyncio.sleep(3)

    # Count how many clients received the event
    async def check_client(ws):
        events = await panel_client.get_websocket_events(ws, timeout=5)
        for event in events:
            if event.get("type") == "bot_connected" and event.get("hwid") == hwid:
                return True
        return False

    results = await asyncio.gather(*[check_client(ws) for ws in ws_clients])

    # Close all connections
    for ws in ws_clients:
        await ws.close()

    received_count = sum(results)
    assert received_count >= 8, f"Only {received_count}/10 clients received event (expected >=8)"
