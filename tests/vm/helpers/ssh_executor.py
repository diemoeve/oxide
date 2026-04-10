"""SSH command execution on VMs."""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class SSHError(Exception):
    """Raised when SSH command fails."""

    pass


class SSHExecutor:
    """Execute commands on VMs via SSH.

    Uses subprocess with list args (not shell=True) to prevent injection.
    """

    def __init__(
        self,
        user: str = "root",
        identity_file: Path | None = None,
        connect_timeout: int = 10,
    ):
        self.user = user
        self.identity_file = identity_file or self._find_identity()
        self.connect_timeout = connect_timeout

    def _find_identity(self) -> Path:
        """Find default SSH identity file."""
        for name in ["id_ed25519", "id_rsa"]:
            path = Path.home() / ".ssh" / name
            if path.exists():
                return path
        raise SSHError("No SSH identity file found")

    def _ssh_opts(self) -> list[str]:
        """Common SSH options."""
        return [
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            f"ConnectTimeout={self.connect_timeout}",
            "-o",
            "BatchMode=yes",
            "-i",
            str(self.identity_file),
        ]

    def exec(
        self,
        host: str,
        command: str,
        timeout: int = 60,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Execute a command on a remote host.

        Note: command is passed as a single string to SSH, which then
        executes it on the remote. The local subprocess call uses a
        list to avoid local shell injection.
        """
        cmd = ["ssh"] + self._ssh_opts() + [f"{self.user}@{host}", command]
        logger.debug(f"SSH: {self.user}@{host} $ {command}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if check and result.returncode != 0:
            raise SSHError(
                f"SSH command failed on {host}: {result.stderr or result.stdout}"
            )

        return result

    def upload(
        self,
        host: str,
        local_path: Path,
        remote_path: str,
        timeout: int = 120,
    ) -> None:
        """Upload a file to a remote host."""
        cmd = (
            ["scp"]
            + self._ssh_opts()
            + [str(local_path), f"{self.user}@{host}:{remote_path}"]
        )
        logger.debug(f"SCP: {local_path} -> {self.user}@{host}:{remote_path}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise SSHError(f"SCP failed: {result.stderr}")

    def download(
        self,
        host: str,
        remote_path: str,
        local_path: Path,
        timeout: int = 120,
    ) -> None:
        """Download a file from a remote host."""
        cmd = (
            ["scp"]
            + self._ssh_opts()
            + [f"{self.user}@{host}:{remote_path}", str(local_path)]
        )
        logger.debug(f"SCP: {self.user}@{host}:{remote_path} -> {local_path}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise SSHError(f"SCP failed: {result.stderr}")

    def is_reachable(self, host: str) -> bool:
        """Check if host is reachable via SSH."""
        try:
            self.exec(host, "true", timeout=self.connect_timeout, check=True)
            return True
        except (SSHError, subprocess.TimeoutExpired):
            return False

    def wait_for_ssh(self, host: str, timeout: int = 120, interval: int = 5) -> bool:
        """Wait for SSH to become available."""
        import time

        start = time.time()
        while time.time() - start < timeout:
            if self.is_reachable(host):
                logger.info(f"SSH available on {host}")
                return True
            logger.debug(f"Waiting for SSH on {host}...")
            time.sleep(interval)
        return False
