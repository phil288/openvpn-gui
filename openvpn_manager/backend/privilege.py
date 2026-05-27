"""Elevation for OpenVPN: sudo with ticket cache (TUN requires root/CAP_NET_ADMIN)."""

from __future__ import annotations

import shutil
import subprocess
from os import getuid
from pathlib import Path


def openvpn_binary() -> str:
    found = shutil.which("openvpn")
    if found:
        return found
    default = Path("/usr/bin/openvpn")
    if default.is_file():
        return str(default)
    raise FileNotFoundError(
        "openvpn not found in PATH; install it (e.g. dnf install openvpn)"
    )


def needs_elevation() -> bool:
    """Creating a TUN device requires root; writable /dev/net/tun is not enough."""
    return getuid() != 0


def sudo_ticket_valid() -> bool:
    """True if sudo has a cached credential (no password needed)."""
    result = subprocess.run(
        ["sudo", "-n", "-v"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.returncode == 0


def cache_sudo_password(password: str) -> bool:
    """Validate password and extend sudo timestamp cache."""
    if not password:
        return False
    result = subprocess.run(
        ["sudo", "-S", "-v"],
        input=f"{password}\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result.returncode == 0


def ensure_sudo_cached(admin_password: str | None = None) -> bool:
    """Ensure sudo can run non-interactively (cached ticket or supplied password)."""
    if not needs_elevation():
        return True
    if sudo_ticket_valid():
        return True
    if admin_password and cache_sudo_password(admin_password):
        return True
    return False


def wrap_openvpn_command(openvpn_args: list[str]) -> list[str]:
    """
    Prefix openvpn invocation with sudo -n when elevation is required.
    openvpn_args must start with the openvpn binary path.
    """
    if not needs_elevation():
        return openvpn_args
    return ["sudo", "-n", *openvpn_args]
