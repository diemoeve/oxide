"""VM lifecycle management.

Security note: All subprocess calls use list arguments (shell=False).
SSH commands are intentionally passed to remote hosts for execution.
"""

import logging
from pathlib import Path

from .virsh_wrapper import VirshWrapper
from .provisioner import (
    provision_c2_vm,
    provision_target_vm,
)
from ..helpers.ssh_executor import SSHExecutor

logger = logging.getLogger(__name__)

OXIDE_ROOT = Path(__file__).parent.parent.parent.parent
VM_CONFIG = OXIDE_ROOT / "vm-config"


# VM configuration
VM_CONFIG_MAP = {
    "oxide-c2": {
        "ip": "10.10.100.10",
        "mac": "52:54:00:00:c2:01",
        "role": "c2",
    },
    "oxide-target-1": {
        "ip": "10.10.100.11",
        "mac": "52:54:00:00:a1:01",
        "role": "target",
    },
    "oxide-target-2": {
        "ip": "10.10.100.12",
        "mac": "52:54:00:00:a2:01",
        "role": "target",
    },
}


class VMManager:
    """Manage VM lifecycle for integration tests."""

    def __init__(self, virsh: VirshWrapper | None = None):
        self.virsh = virsh or VirshWrapper()
        self.ssh = SSHExecutor()

    def get_vm_ip(self, vm_name: str) -> str:
        """Get IP address for a VM."""
        return VM_CONFIG_MAP[vm_name]["ip"]

    def provision_c2(self, implant_binary: Path | None = None) -> str:
        """Provision the C2 panel VM."""
        return provision_c2_vm(self.virsh, implant_binary=implant_binary)

    def provision_target(
        self,
        vm_name: str,
        c2_host: str = "10.10.100.10",
        c2_port: int = 4444,
        implant_binary: Path | None = None,
    ) -> str:
        """Provision a target VM."""
        config = VM_CONFIG_MAP[vm_name]
        return provision_target_vm(
            self.virsh,
            vm_name=vm_name,
            ip_address=config["ip"],
            mac_address=config["mac"],
            c2_host=c2_host,
            c2_port=c2_port,
            implant_binary=implant_binary,
        )

    def start(self, vm_name: str) -> None:
        """Start a VM."""
        if not self.virsh.is_running(vm_name):
            logger.info(f"Starting VM {vm_name}")
            self.virsh.start(vm_name)

    def stop(self, vm_name: str, force: bool = False) -> None:
        """Stop a VM."""
        if self.virsh.is_running(vm_name):
            logger.info(f"Stopping VM {vm_name}")
            if force:
                self.virsh.destroy(vm_name)
            else:
                self.virsh.shutdown(vm_name)

    def reboot(self, vm_name: str) -> None:
        """Reboot a VM."""
        logger.info(f"Rebooting VM {vm_name}")
        self.virsh.reboot(vm_name)

    def is_running(self, vm_name: str) -> bool:
        """Check if VM is running."""
        return self.virsh.is_running(vm_name)

    def wait_for_ssh(self, vm_name: str, timeout: int = 120) -> bool:
        """Wait for SSH to be available on a VM."""
        ip = self.get_vm_ip(vm_name)
        return self.ssh.wait_for_ssh(ip, timeout=timeout)

    def run_ssh_command(self, vm_name: str, command: str, **kwargs):
        """Run a command on a VM via SSH."""
        ip = self.get_vm_ip(vm_name)
        return self.ssh.exec(ip, command, **kwargs)

    def upload_file(self, vm_name: str, local_path: Path, remote_path: str) -> None:
        """Upload a file to a VM."""
        ip = self.get_vm_ip(vm_name)
        self.ssh.upload(ip, local_path, remote_path)

    def download_file(self, vm_name: str, remote_path: str, local_path: Path) -> None:
        """Download a file from a VM."""
        ip = self.get_vm_ip(vm_name)
        self.ssh.download(ip, remote_path, local_path)

    # Snapshot operations
    def snapshot_create(self, vm_name: str, snap_name: str) -> None:
        """Create a snapshot."""
        logger.info(f"Creating snapshot {snap_name} for {vm_name}")
        self.virsh.snapshot_create(vm_name, snap_name)

    def snapshot_revert(self, vm_name: str, snap_name: str) -> None:
        """Revert to a snapshot."""
        logger.info(f"Reverting {vm_name} to snapshot {snap_name}")
        self.virsh.snapshot_revert(vm_name, snap_name)

    def snapshot_delete(self, vm_name: str, snap_name: str) -> None:
        """Delete a snapshot."""
        logger.info(f"Deleting snapshot {snap_name} from {vm_name}")
        self.virsh.snapshot_delete(vm_name, snap_name)

    def snapshot_list(self, vm_name: str) -> list[str]:
        """List snapshots for a VM."""
        return self.virsh.snapshot_list(vm_name)

    # Cleanup
    def cleanup_vm(self, vm_name: str, remove_storage: bool = True) -> None:
        """Stop and undefine a VM."""
        logger.info(f"Cleaning up VM {vm_name}")
        self.virsh.destroy(vm_name)
        self.virsh.undefine(vm_name, remove_storage=remove_storage)

    def cleanup_all(self) -> None:
        """Clean up all oxide VMs."""
        for vm_name in VM_CONFIG_MAP:
            try:
                self.cleanup_vm(vm_name)
            except Exception as e:
                logger.warning(f"Failed to cleanup {vm_name}: {e}")
