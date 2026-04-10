"""Thin wrapper around virsh for VM operations."""

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


class VirshError(Exception):
    """Raised when virsh command fails."""

    pass


@dataclass
class VMState:
    name: str
    state: str  # running, shut off, paused
    autostart: bool


class VirshWrapper:
    """Wrapper around virsh commands with error handling."""

    def __init__(self, connect_uri: str = "qemu:///system"):
        self.connect_uri = connect_uri

    def _run(
        self, args: list[str], check: bool = True, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        cmd = ["virsh", "-c", self.connect_uri] + args
        logger.debug(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode != 0:
            raise VirshError(f"virsh {args[0]} failed: {result.stderr}")
        return result

    # Domain operations
    def define(self, xml_path: Path) -> str:
        """Define a domain from XML, return domain name."""
        result = self._run(["define", str(xml_path)])
        # Parse "Domain oxide-c2 defined from /path/to/file.xml"
        return result.stdout.split()[1]

    def undefine(self, name: str, remove_storage: bool = False):
        """Undefine a domain."""
        args = ["undefine", name]
        if remove_storage:
            args.append("--remove-all-storage")
        self._run(args, check=False)

    def start(self, name: str):
        """Start a domain."""
        self._run(["start", name])

    def shutdown(self, name: str, timeout: int = 30):
        """Graceful shutdown with timeout fallback to destroy."""
        import time

        self._run(["shutdown", name], check=False)
        for _ in range(timeout):
            if self.get_state(name) == "shut off":
                return
            time.sleep(1)
        self.destroy(name)

    def destroy(self, name: str):
        """Force stop a VM."""
        self._run(["destroy", name], check=False)

    def reboot(self, name: str):
        """Reboot a domain."""
        self._run(["reboot", name])

    def get_state(self, name: str) -> str:
        """Get domain state."""
        result = self._run(["domstate", name], check=False)
        return result.stdout.strip() if result.returncode == 0 else "undefined"

    def is_running(self, name: str) -> bool:
        """Check if domain is running."""
        return self.get_state(name) == "running"

    def list_all(self) -> list[VMState]:
        """List all domains."""
        result = self._run(["list", "--all", "--name"])
        vms = []
        for line in result.stdout.strip().split("\n"):
            name = line.strip()
            if name:
                state = self.get_state(name)
                vms.append(VMState(name=name, state=state, autostart=False))
        return vms

    # Snapshot operations
    def snapshot_create(self, name: str, snap_name: str):
        """Create a snapshot."""
        self._run(["snapshot-create-as", name, snap_name])

    def snapshot_revert(self, name: str, snap_name: str):
        """Revert to a snapshot."""
        self._run(["snapshot-revert", name, snap_name])

    def snapshot_delete(self, name: str, snap_name: str):
        """Delete a snapshot."""
        self._run(["snapshot-delete", name, snap_name], check=False)

    def snapshot_list(self, name: str) -> list[str]:
        """List snapshots for a domain."""
        result = self._run(["snapshot-list", name, "--name"], check=False)
        if result.returncode != 0:
            return []
        return [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]

    # Network operations
    def net_define(self, xml_path: Path) -> str:
        """Define a network from XML."""
        result = self._run(["net-define", str(xml_path)])
        # Parse "Network oxide-testnet defined from /path/to/file.xml"
        return result.stdout.split()[1]

    def net_start(self, name: str):
        """Start a network."""
        self._run(["net-start", name], check=False)

    def net_destroy(self, name: str):
        """Destroy a network."""
        self._run(["net-destroy", name], check=False)

    def net_undefine(self, name: str):
        """Undefine a network."""
        self._run(["net-undefine", name], check=False)

    def net_is_active(self, name: str) -> bool:
        """Check if network is active."""
        result = self._run(["net-info", name], check=False)
        return "Active:         yes" in result.stdout

    def net_autostart(self, name: str, enable: bool = True):
        """Set network autostart."""
        flag = "--autostart" if enable else "--disable"
        self._run(["net-autostart", name, flag], check=False)

    # Interface operations
    def domif_setlink(self, name: str, interface: str, state: str):
        """Set domain interface link state (up/down)."""
        self._run(["domif-setlink", name, interface, state])

    def domiflist(self, name: str) -> list[str]:
        """List domain interfaces."""
        result = self._run(["domiflist", name], check=False)
        interfaces = []
        for line in result.stdout.strip().split("\n")[2:]:  # Skip header
            parts = line.split()
            if parts:
                interfaces.append(parts[0])
        return interfaces
