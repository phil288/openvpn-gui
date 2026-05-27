"""Unit tests for privilege / command wrapping."""

from __future__ import annotations

from unittest.mock import patch

from openvpn_manager.backend import privilege


def test_wrap_openvpn_command_without_elevation() -> None:
    with patch.object(privilege, "needs_elevation", return_value=False):
        cmd = privilege.wrap_openvpn_command(["/usr/bin/openvpn", "--config", "x"])
    assert cmd == ["/usr/bin/openvpn", "--config", "x"]


def test_needs_elevation_when_not_root() -> None:
    with patch.object(privilege, "getuid", return_value=1000):
        assert privilege.needs_elevation() is True


def test_needs_elevation_when_root() -> None:
    with patch.object(privilege, "getuid", return_value=0):
        assert privilege.needs_elevation() is False


def test_wrap_openvpn_command_with_elevation() -> None:
    with patch.object(privilege, "needs_elevation", return_value=True):
        cmd = privilege.wrap_openvpn_command(["/usr/bin/openvpn", "--verb", "3"])
    assert cmd == ["sudo", "-n", "/usr/bin/openvpn", "--verb", "3"]
