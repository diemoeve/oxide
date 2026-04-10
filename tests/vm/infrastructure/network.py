"""Network manipulation helpers for testing.

Note: SSH commands pass shell strings to remote hosts intentionally.
The local subprocess calls use list args (no shell=True) to prevent
local command injection.
"""

import logging

from .virsh_wrapper import VirshWrapper
from ..helpers.ssh_executor import SSHExecutor

logger = logging.getLogger(__name__)


class NetworkInterruption:
    """Helpers for network interruption testing."""

    # Map VM names to their IPs for SSH access
    VM_IPS = {
        "oxide-target-1": "10.10.100.11",
        "oxide-target-2": "10.10.100.12",
        "oxide-c2": "10.10.100.10",
    }

    def __init__(self, virsh: VirshWrapper, ssh: SSHExecutor):
        self.virsh = virsh
        self.ssh = ssh

    def _get_ip(self, vm_name: str) -> str:
        """Get IP address for a VM name."""
        return self.VM_IPS.get(vm_name, vm_name)

    def interface_down(self, vm_name: str, interface: str = "enp1s0"):
        """Disconnect VM's network interface at hypervisor level."""
        logger.info(f"Disconnecting {interface} on {vm_name}")
        self.virsh.domif_setlink(vm_name, interface, "down")

    def interface_up(self, vm_name: str, interface: str = "enp1s0"):
        """Reconnect VM's network interface."""
        logger.info(f"Reconnecting {interface} on {vm_name}")
        self.virsh.domif_setlink(vm_name, interface, "up")

    # Aliases for backwards compatibility
    disconnect_interface = interface_down
    reconnect_interface = interface_up

    def add_packet_loss(
        self, vm_name: str, percent: int = 50, interface: str = "enp1s0"
    ):
        """Add packet loss on VM's interface using tc."""
        host = self._get_ip(vm_name)
        logger.info(f"Adding {percent}% packet loss on {vm_name} ({host})")
        cmd = f"tc qdisc add dev {interface} root netem loss {percent}%"
        self.ssh.exec(host, cmd, check=False)

    def remove_packet_loss(self, vm_name: str, interface: str = "enp1s0"):
        """Remove packet loss from VM's interface."""
        host = self._get_ip(vm_name)
        logger.info(f"Removing packet loss on {vm_name} ({host})")
        self.clear_tc_rules(vm_name, interface)

    def add_latency(
        self, vm_name: str, delay_ms: int = 100, interface: str = "enp1s0"
    ):
        """Add latency on VM's interface using tc."""
        host = self._get_ip(vm_name)
        logger.info(f"Adding {delay_ms}ms latency on {vm_name} ({host})")
        cmd = f"tc qdisc add dev {interface} root netem delay {delay_ms}ms"
        self.ssh.exec(host, cmd, check=False)

    def remove_latency(self, vm_name: str, interface: str = "enp1s0"):
        """Remove latency from VM's interface."""
        host = self._get_ip(vm_name)
        logger.info(f"Removing latency on {vm_name} ({host})")
        self.clear_tc_rules(vm_name, interface)

    # Aliases for backwards compatibility
    simulate_packet_loss = add_packet_loss
    simulate_latency = add_latency

    def clear_tc_rules(self, vm_name: str, interface: str = "enp1s0"):
        """Clear all tc rules on interface."""
        host = self._get_ip(vm_name)
        logger.info(f"Clearing tc rules on {vm_name} ({host})")
        cmd = f"tc qdisc del dev {interface} root 2>/dev/null || true"
        self.ssh.exec(host, cmd, check=False)

    def block_port(self, vm_name: str, port: int):
        """Block incoming connections to a port using iptables."""
        host = self._get_ip(vm_name)
        logger.info(f"Blocking port {port} on {vm_name} ({host})")
        cmd = f"iptables -A INPUT -p tcp --dport {port} -j DROP"
        self.ssh.exec(host, cmd)

    def unblock_port(self, vm_name: str, port: int):
        """Unblock a port."""
        host = self._get_ip(vm_name)
        logger.info(f"Unblocking port {port} on {vm_name} ({host})")
        cmd = f"iptables -D INPUT -p tcp --dport {port} -j DROP"
        self.ssh.exec(host, cmd, check=False)

    def block_host(self, vm_name: str, target_ip: str):
        """Block all traffic to a specific IP."""
        host = self._get_ip(vm_name)
        logger.info(f"Blocking traffic to {target_ip} from {vm_name} ({host})")
        cmd = f"iptables -A OUTPUT -d {target_ip} -j DROP"
        self.ssh.exec(host, cmd)

    def unblock_host(self, vm_name: str, target_ip: str):
        """Unblock traffic to an IP."""
        host = self._get_ip(vm_name)
        logger.info(f"Unblocking traffic to {target_ip} from {vm_name} ({host})")
        cmd = f"iptables -D OUTPUT -d {target_ip} -j DROP"
        self.ssh.exec(host, cmd, check=False)

    def flush_iptables(self, vm_name: str):
        """Flush all iptables rules."""
        host = self._get_ip(vm_name)
        logger.info(f"Flushing iptables on {vm_name} ({host})")
        self.ssh.exec(host, "iptables -F", check=False)


class NetworkManager:
    """Manage the oxide-testnet libvirt network."""

    def __init__(self, virsh: VirshWrapper, network_xml_path):
        self.virsh = virsh
        self.network_xml_path = network_xml_path
        self.network_name = "oxide-testnet"

    def ensure_network(self) -> bool:
        """Ensure the network exists and is active."""
        if self.virsh.net_is_active(self.network_name):
            logger.info(f"Network {self.network_name} already active")
            return True

        # Try to start existing network
        self.virsh.net_start(self.network_name)
        if self.virsh.net_is_active(self.network_name):
            logger.info(f"Started existing network {self.network_name}")
            return True

        # Define and start new network
        logger.info(f"Defining network from {self.network_xml_path}")
        self.virsh.net_define(self.network_xml_path)
        self.virsh.net_start(self.network_name)
        self.virsh.net_autostart(self.network_name, enable=True)

        return self.virsh.net_is_active(self.network_name)

    def destroy(self):
        """Destroy the network."""
        logger.info(f"Destroying network {self.network_name}")
        self.virsh.net_destroy(self.network_name)
        self.virsh.net_undefine(self.network_name)
