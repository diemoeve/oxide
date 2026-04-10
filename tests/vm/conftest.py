"""Pytest fixtures for VM integration tests."""

import asyncio
import logging
from pathlib import Path
from typing import Generator

import pytest

from .infrastructure.virsh_wrapper import VirshWrapper
from .infrastructure.vm_manager import VMManager
from .infrastructure.network import NetworkManager, NetworkInterruption
from .infrastructure.provisioner import ensure_base_image
from .helpers.api_client import PanelAPIClient
from .helpers.ssh_executor import SSHExecutor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

OXIDE_ROOT = Path(__file__).parent.parent.parent
VM_CONFIG = OXIDE_ROOT / "vm-config"
VM_IMAGES = OXIDE_ROOT / "vm-images"


# =============================================================================
# Session-scoped fixtures (setup once per test session)
# =============================================================================


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def virsh() -> VirshWrapper:
    """Virsh wrapper instance."""
    return VirshWrapper()


@pytest.fixture(scope="session")
def ssh() -> SSHExecutor:
    """SSH executor instance."""
    return SSHExecutor()


@pytest.fixture(scope="session")
def network_manager(virsh) -> Generator[NetworkManager, None, None]:
    """Setup and teardown the oxide-testnet network."""
    nm = NetworkManager(virsh, VM_CONFIG / "oxide-network.xml")
    nm.ensure_network()
    yield nm
    # Don't destroy network on teardown - leave for inspection


@pytest.fixture(scope="session")
def base_image() -> Path:
    """Ensure Ubuntu 24.04 cloud image is downloaded."""
    return ensure_base_image()


@pytest.fixture(scope="session")
def vm_manager(virsh) -> VMManager:
    """VM manager for creating/managing test VMs."""
    return VMManager(virsh)


# =============================================================================
# Module-scoped fixtures (setup once per test module)
# =============================================================================


@pytest.fixture(scope="module")
def c2_vm(vm_manager, network_manager, base_image) -> Generator[str, None, None]:
    """Provision and start the C2 panel VM."""
    vm_name = "oxide-c2"

    # Check if already running
    if vm_manager.is_running(vm_name):
        logger.info(f"VM {vm_name} already running")
        yield vm_name
        return

    # Provision and start
    vm_manager.provision_c2()
    vm_manager.start(vm_name)

    # Wait for SSH
    if not vm_manager.wait_for_ssh(vm_name, timeout=180):
        pytest.fail(f"Timeout waiting for SSH on {vm_name}")

    yield vm_name

    # Don't stop - leave for inspection


@pytest.fixture(scope="module")
def target_vm_1(vm_manager, network_manager, base_image, c2_vm) -> Generator[str, None, None]:
    """Provision and start target VM 1."""
    vm_name = "oxide-target-1"
    implant = OXIDE_ROOT / "target" / "release" / "oxide-implant"

    # Check if already running
    if vm_manager.is_running(vm_name):
        logger.info(f"VM {vm_name} already running")
        yield vm_name
        return

    # Provision and start
    vm_manager.provision_target(
        vm_name,
        c2_host="10.10.100.10",
        implant_binary=implant if implant.exists() else None,
    )
    vm_manager.start(vm_name)

    # Wait for SSH
    if not vm_manager.wait_for_ssh(vm_name, timeout=180):
        pytest.fail(f"Timeout waiting for SSH on {vm_name}")

    yield vm_name


@pytest.fixture(scope="module")
def target_vm_2(vm_manager, network_manager, base_image, c2_vm) -> Generator[str, None, None]:
    """Provision and start target VM 2."""
    vm_name = "oxide-target-2"
    implant = OXIDE_ROOT / "target" / "release" / "oxide-implant"

    # Check if already running
    if vm_manager.is_running(vm_name):
        logger.info(f"VM {vm_name} already running")
        yield vm_name
        return

    # Provision and start
    vm_manager.provision_target(
        vm_name,
        c2_host="10.10.100.10",
        implant_binary=implant if implant.exists() else None,
    )
    vm_manager.start(vm_name)

    # Wait for SSH
    if not vm_manager.wait_for_ssh(vm_name, timeout=180):
        pytest.fail(f"Timeout waiting for SSH on {vm_name}")

    yield vm_name


@pytest.fixture(scope="module")
def target_vms(target_vm_1, target_vm_2) -> list[str]:
    """Both target VMs."""
    return [target_vm_1, target_vm_2]


@pytest.fixture(scope="module")
async def panel_client(c2_vm) -> PanelAPIClient:
    """Authenticated API client for the panel."""
    async with PanelAPIClient(base_url="http://10.10.100.10:8080") as client:
        # Wait for panel to be ready
        for _ in range(30):
            if await client.health_check():
                break
            await asyncio.sleep(1)
        else:
            pytest.fail("Panel not responding")

        # Login
        if not await client.login("admin", "oxide"):
            pytest.fail("Failed to login to panel")

        yield client


# =============================================================================
# Function-scoped fixtures (per-test setup)
# =============================================================================


@pytest.fixture
def network_interruption(virsh, ssh) -> NetworkInterruption:
    """Network interruption helpers."""
    return NetworkInterruption(virsh, ssh)


@pytest.fixture
def clean_snapshot(vm_manager, target_vms):
    """Create snapshots before test, restore after."""
    for vm in target_vms:
        vm_manager.snapshot_create(vm, "pre-test")

    yield

    for vm in target_vms:
        vm_manager.snapshot_revert(vm, "pre-test")
        vm_manager.snapshot_delete(vm, "pre-test")


# =============================================================================
# Pytest configuration
# =============================================================================


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "requires_reboot: marks tests that require VM reboot"
    )


def pytest_collection_modifyitems(config, items):
    """Add markers based on test names."""
    for item in items:
        if "reboot" in item.name.lower() or "persistence" in item.name.lower():
            item.add_marker(pytest.mark.slow)
            item.add_marker(pytest.mark.requires_reboot)
