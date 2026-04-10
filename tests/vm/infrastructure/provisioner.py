"""VM provisioning using virt-customize."""

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

OXIDE_ROOT = Path(__file__).parent.parent.parent.parent
VM_CONFIG = OXIDE_ROOT / "vm-config"
VM_IMAGES = OXIDE_ROOT / "vm-images"

UBUNTU_CLOUD_IMAGE_URL = (
    "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
)
BASE_IMAGE_NAME = "ubuntu-24.04-server-cloudimg-amd64.qcow2"


class ProvisionerError(Exception):
    """Raised when provisioning fails."""

    pass


def ensure_base_image() -> Path:
    """Ensure Ubuntu cloud image exists, download if not."""
    base_image = VM_IMAGES / BASE_IMAGE_NAME
    if base_image.exists():
        logger.info(f"Base image exists: {base_image}")
        return base_image

    logger.info(f"Downloading Ubuntu cloud image to {base_image}...")
    VM_IMAGES.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["curl", "-L", "-o", str(base_image), UBUNTU_CLOUD_IMAGE_URL],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ProvisionerError(f"Failed to download image: {result.stderr}")

    logger.info("Download complete")
    return base_image


def create_disk_overlay(base_image: Path, vm_name: str) -> Path:
    """Create a COW overlay disk from base image."""
    overlay_path = VM_IMAGES / f"{vm_name}.qcow2"
    if overlay_path.exists():
        overlay_path.unlink()

    result = subprocess.run(
        [
            "qemu-img",
            "create",
            "-b",
            str(base_image),
            "-F",
            "qcow2",
            "-f",
            "qcow2",
            str(overlay_path),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ProvisionerError(f"Failed to create overlay: {result.stderr}")

    logger.info(f"Created disk overlay: {overlay_path}")
    return overlay_path


def customize_vm(
    disk_path: Path,
    hostname: str,
    ip_address: str,
    ssh_pubkey_path: Path | None = None,
    root_password: str = "oxide",
    extra_files: list[tuple[Path, str]] | None = None,
    firstboot_commands: list[str] | None = None,
) -> None:
    """Customize a VM disk image using virt-customize."""
    cmd = [
        "virt-customize",
        "-a",
        str(disk_path),
        "--hostname",
        hostname,
        "--root-password",
        f"password:{root_password}",
        "--run-command",
        "ssh-keygen -A",  # Generate SSH host keys
    ]

    # Add SSH public key
    if ssh_pubkey_path and ssh_pubkey_path.exists():
        cmd.extend(["--ssh-inject", f"root:file:{ssh_pubkey_path}"])
    else:
        # Use default SSH key if available
        default_key = Path.home() / ".ssh" / "id_ed25519.pub"
        if not default_key.exists():
            default_key = Path.home() / ".ssh" / "id_rsa.pub"
        if default_key.exists():
            cmd.extend(["--ssh-inject", f"root:file:{default_key}"])

    # Create netplan config for static IP
    netplan_config = f"""network:
  version: 2
  ethernets:
    enp1s0:
      addresses:
        - {ip_address}/24
      routes:
        - to: default
          via: 10.10.100.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(netplan_config)
        netplan_path = f.name

    cmd.extend(
        [
            "--upload",
            f"{netplan_path}:/etc/netplan/99-oxide.yaml",
            "--run-command",
            "chmod 600 /etc/netplan/99-oxide.yaml",
        ]
    )

    # Copy extra files
    if extra_files:
        for local_path, remote_path in extra_files:
            cmd.extend(["--copy-in", f"{local_path}:{Path(remote_path).parent}"])

    # Add firstboot commands
    if firstboot_commands:
        for command in firstboot_commands:
            cmd.extend(["--firstboot-command", command])

    # Always apply netplan on first boot
    cmd.extend(["--firstboot-command", "netplan apply"])

    logger.info(f"Customizing {disk_path}...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Clean up temp file
    Path(netplan_path).unlink()

    if result.returncode != 0:
        raise ProvisionerError(f"virt-customize failed: {result.stderr}")

    logger.info("Customization complete")


def create_domain_xml(
    template_path: Path,
    vm_name: str,
    disk_path: Path,
    mac_address: str | None = None,
) -> Path:
    """Create domain XML from template with substitutions."""
    template = template_path.read_text()

    xml = template.replace("{{VM_NAME}}", vm_name)
    xml = xml.replace("{{DISK_PATH}}", str(disk_path))
    if mac_address:
        xml = xml.replace("{{MAC_ADDRESS}}", mac_address)

    output_path = VM_IMAGES / f"{vm_name}-domain.xml"
    output_path.write_text(xml)
    return output_path


def provision_c2_vm(
    virsh,
    c2_host: str = "10.10.100.10",
    implant_binary: Path | None = None,
) -> str:
    """Provision the C2 panel VM."""
    vm_name = "oxide-c2"

    base_image = ensure_base_image()
    disk = create_disk_overlay(base_image, vm_name)

    # Create panel setup script
    panel_setup = """#!/bin/bash
set -e
apt-get update
apt-get install -y python3-pip python3-venv git
cd /opt
git clone --depth 1 file:///mnt/oxide oxide || true
cd /opt/oxide/panel
python3 -m venv .venv
.venv/bin/pip install -e .
"""

    # For now, just set up basic VM without panel (panel will be started manually or via systemd)
    customize_vm(
        disk_path=disk,
        hostname=vm_name,
        ip_address=c2_host,
        firstboot_commands=[
            "apt-get update",
            "apt-get install -y python3-pip python3-venv",
        ],
    )

    # Create domain XML
    domain_xml = create_domain_xml(
        VM_CONFIG / "oxide-c2.xml",
        vm_name,
        disk,
    )

    # Define the domain
    virsh.undefine(vm_name, remove_storage=False)
    virsh.define(domain_xml)

    return vm_name


def provision_target_vm(
    virsh,
    vm_name: str,
    ip_address: str,
    mac_address: str,
    c2_host: str = "10.10.100.10",
    c2_port: int = 4444,
    implant_binary: Path | None = None,
) -> str:
    """Provision a target VM with implant."""
    base_image = ensure_base_image()
    disk = create_disk_overlay(base_image, vm_name)

    extra_files = []
    firstboot_commands = []

    if implant_binary and implant_binary.exists():
        extra_files.append((implant_binary, "/opt/oxide/oxide-implant"))
        firstboot_commands.extend(
            [
                "chmod +x /opt/oxide/oxide-implant",
                f"OXIDE_C2_HOST={c2_host} OXIDE_C2_PORT={c2_port} /opt/oxide/oxide-implant &",
            ]
        )

    customize_vm(
        disk_path=disk,
        hostname=vm_name,
        ip_address=ip_address,
        extra_files=extra_files if extra_files else None,
        firstboot_commands=firstboot_commands if firstboot_commands else None,
    )

    # Create domain XML
    domain_xml = create_domain_xml(
        VM_CONFIG / "oxide-target.xml",
        vm_name,
        disk,
        mac_address=mac_address,
    )

    # Define the domain
    virsh.undefine(vm_name, remove_storage=False)
    virsh.define(domain_xml)

    return vm_name
