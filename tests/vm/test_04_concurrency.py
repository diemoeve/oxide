"""Database concurrency under load."""

import asyncio
import pytest

from .helpers.wait_conditions import wait_for_response, wait_for_bot_count


@pytest.mark.asyncio
async def test_concurrent_commands_to_multiple_bots(panel_client, target_vms, vm_manager):
    """Send commands to multiple bots simultaneously."""
    # Start implants on both targets
    for vm in target_vms:
        vm_manager.run_ssh_command(
            vm,
            "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
            check=False,
        )

    # Wait for both bots
    bots = await wait_for_bot_count(panel_client, 2, timeout=90)
    hwids = [b["hwid"] for b in bots]

    # Send 10 commands to each bot concurrently
    tasks = []
    for hwid in hwids:
        for i in range(10):
            task = panel_client.send_command(hwid, "shell", {"command": f"echo {i}"})
            tasks.append(task)

    results = await asyncio.gather(*tasks)

    # All should succeed (dispatched or pending)
    assert all(r["status"] in ("dispatched", "pending") for r in results)

    # Wait for all responses
    response_tasks = [
        wait_for_response(panel_client, r["command_id"], timeout=60)
        for r in results
    ]
    responses = await asyncio.gather(*response_tasks, return_exceptions=True)

    # Count successes (some may timeout)
    successes = sum(1 for r in responses if isinstance(r, dict) and r.get("status") == "success")
    assert successes >= len(results) * 0.8, f"Only {successes}/{len(results)} commands succeeded"


@pytest.mark.asyncio
async def test_concurrent_registration(target_vms, vm_manager, panel_client):
    """Two implants checking in at the exact same moment."""
    # Stop any running implants
    for vm in target_vms:
        vm_manager.run_ssh_command(vm, "pkill -9 oxide-implant", check=False)

    await asyncio.sleep(2)

    # Start both implants at the same time
    for vm in target_vms:
        vm_manager.run_ssh_command(
            vm,
            "OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
            check=False,
        )

    # Wait for both bots to register
    bots = await wait_for_bot_count(panel_client, 2, timeout=90)

    # Verify both registered with unique HWIDs
    hwids = [b["hwid"] for b in bots]
    assert len(set(hwids)) == 2, "Duplicate HWIDs detected"

    # Verify both are functional
    for hwid in hwids:
        result = await panel_client.send_command(hwid, "shell", {"command": "hostname"})
        response = await wait_for_response(panel_client, result["command_id"], timeout=30)
        assert response["status"] == "success"


@pytest.mark.asyncio
async def test_rapid_command_sequence(panel_client, target_vm_1, vm_manager):
    """Send commands in rapid succession to stress the database."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Send 20 commands as fast as possible
    tasks = [
        panel_client.send_command(hwid, "shell", {"command": f"echo rapid-{i}"})
        for i in range(20)
    ]
    results = await asyncio.gather(*tasks)

    # All should be accepted
    assert len(results) == 20
    assert all(r["command_id"] for r in results)

    # Verify no duplicate command IDs
    cmd_ids = [r["command_id"] for r in results]
    assert len(set(cmd_ids)) == 20, "Duplicate command IDs detected"
