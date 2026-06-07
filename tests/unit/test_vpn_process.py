"""Unit tests for VPN process / OpenVPN command building."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from unittest.mock import patch

from openvpn_manager.backend.vpn_process import VpnWorker, _runtime_dir


@pytest.fixture
def runtime_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENVPN_MANAGER_RUNTIME_DIR", str(tmp_path))
    return tmp_path


def test_build_command_with_credentials(runtime_dir: Path) -> None:
    """Regression: must not raise UnboundLocalError for os."""
    sock = runtime_dir / "mgmt.sock"
    worker = VpnWorker(Path("/tmp/profile.ovpn"), 0, "alice", "secret")
    with patch(
        "openvpn_manager.backend.vpn_process.wrap_openvpn_command",
        side_effect=lambda args: args,
    ):
        cmd = worker._build_command(sock)

    assert "pkexec" not in cmd
    assert "openvpn" in cmd[0] or cmd[0].endswith("openvpn")
    assert "--disable-dco" in cmd
    assert "unix" in cmd
    assert "--management-client-user" in cmd
    idx = cmd.index("--management-client-user")
    assert cmd[idx + 1]
    assert "--auth-user-pass" in cmd
    assert str(sock) in cmd


def test_build_command_without_credentials(runtime_dir: Path) -> None:
    sock = runtime_dir / "mgmt.sock"
    worker = VpnWorker(Path("/tmp/profile.ovpn"), 0)
    cmd = worker._build_command(sock)

    assert "--auth-user-pass" not in cmd
    assert cmd[cmd.index("--management") + 1] == str(sock)


def test_runtime_dir_uses_override(runtime_dir: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENVPN_MANAGER_RUNTIME_DIR", str(runtime_dir / "rt"))
    assert _runtime_dir() == runtime_dir / "rt"


def _worker() -> VpnWorker:
    return VpnWorker(Path("/tmp/profile.ovpn"), 0)


def test_parse_state_from_command_response() -> None:
    """The `state` command response has no `>STATE:` prefix and ends with END."""
    resp = (
        "1700000000,CONNECTING,,,,,,\n"
        "1700000005,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,\n"
        "END\n"
    )
    assert _worker()._parse_state(resp) == "CONNECTED"


def test_parse_state_returns_most_recent() -> None:
    resp = (
        "1700000005,CONNECTED,SUCCESS,10.8.0.2,,,,\n"
        "1700000010,RECONNECTING,ping-restart,,,,,\n"
        "END\n"
    )
    assert _worker()._parse_state(resp) == "RECONNECTING"


def test_parse_state_realtime_notification() -> None:
    resp = ">STATE:1700000005,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,\n"
    assert _worker()._parse_state(resp) == "CONNECTED"


def test_parse_state_not_connected_while_connecting() -> None:
    """Regression: must not report CONNECTED before the tunnel is up."""
    resp = "1700000000,WAIT,,,,,,\nEND\n"
    assert _worker()._parse_state(resp) == "WAIT"


def test_parse_state_ignores_bytecount_noise() -> None:
    resp = "1700000005,CONNECTED,SUCCESS,10.8.0.2,,,,\nEND\n>BYTECOUNT:123,456\n"
    assert _worker()._parse_state(resp) == "CONNECTED"
