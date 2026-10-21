"""Unit tests for VPN process / OpenVPN command building."""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path

import pytest

from unittest.mock import patch

from openvpn_manager.backend.vpn_process import (
    HANDSHAKE_STALL_SEC,
    HandshakeMonitor,
    ManagementClient,
    VpnWorker,
    _runtime_dir,
)


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


def test_build_command_forces_script_security_by_default(runtime_dir: Path) -> None:
    """Untrusted configs must not be able to run scripts as root."""
    worker = VpnWorker(Path("/tmp/profile.ovpn"), 0)
    cmd = worker._build_command(runtime_dir / "mgmt.sock")
    assert "--script-security" in cmd
    assert cmd[cmd.index("--script-security") + 1] == "1"


def test_build_command_allows_scripts_when_consented(runtime_dir: Path) -> None:
    worker = VpnWorker(Path("/tmp/profile.ovpn"), 0, allow_scripts=True)
    cmd = worker._build_command(runtime_dir / "mgmt.sock")
    assert "--script-security" not in cmd


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



def test_parse_virtual_ip_from_connected_state_line() -> None:
    resp = (
        "1700000000,ASSIGN_IP,,10.8.0.6,,,,\n"
        "1700000005,CONNECTED,SUCCESS,10.8.0.6,203.0.113.5,1196,,,\n"
        "END"
    )
    assert _worker()._parse_virtual_ip(resp) == "10.8.0.6"


def test_parse_virtual_ip_uses_ipv6_when_no_ipv4() -> None:
    resp = "1700000005,CONNECTED,SUCCESS,,203.0.113.5,1196,,,fd00::2\nEND"
    assert _worker()._parse_virtual_ip(resp) == "fd00::2"


def test_parse_virtual_ip_empty_before_connected() -> None:
    resp = "1700000000,ASSIGN_IP,,10.8.0.6,,,,\n>BYTECOUNT:1,2\nEND"
    assert _worker()._parse_virtual_ip(resp) == ""

def _write_config(tmp_path: Path, body: str) -> Path:
    cfg = tmp_path / "profile.ovpn"
    cfg.write_text(body, encoding="utf-8")
    return cfg


def test_force_ipv4_when_native_route_available(tmp_path: Path) -> None:
    cfg = _write_config(tmp_path, "remote vpn.example.com 1194 udp\n")
    worker = VpnWorker(cfg, 0)
    with patch(
        "openvpn_manager.backend.vpn_process._resolve_ipv4",
        return_value="31.33.155.5",
    ), patch(
        "openvpn_manager.backend.vpn_process._ipv4_route_available",
        return_value=True,
    ):
        assert worker._preferred_ipv4_proto() == "udp4"


def test_force_ipv4_uses_tcp_family_for_tcp(tmp_path: Path) -> None:
    cfg = _write_config(tmp_path, "remote vpn.example.com 443\nproto tcp\n")
    worker = VpnWorker(cfg, 0)
    with patch(
        "openvpn_manager.backend.vpn_process._resolve_ipv4",
        return_value="31.33.155.5",
    ), patch(
        "openvpn_manager.backend.vpn_process._ipv4_route_available",
        return_value=True,
    ):
        assert worker._preferred_ipv4_proto() == "tcp4"


def test_no_force_when_no_ipv4_route(tmp_path: Path) -> None:
    """IPv6-only / NAT64-only host: leave the working path untouched."""
    cfg = _write_config(tmp_path, "remote vpn.example.com 1194 udp\n")
    worker = VpnWorker(cfg, 0)
    with patch(
        "openvpn_manager.backend.vpn_process._resolve_ipv4",
        return_value="31.33.155.5",
    ), patch(
        "openvpn_manager.backend.vpn_process._ipv4_route_available",
        return_value=False,
    ):
        assert worker._preferred_ipv4_proto() is None


def test_no_force_when_server_has_no_a_record(tmp_path: Path) -> None:
    cfg = _write_config(tmp_path, "remote vpn.example.com 1194 udp\n")
    worker = VpnWorker(cfg, 0)
    with patch(
        "openvpn_manager.backend.vpn_process._resolve_ipv4", return_value=None
    ):
        assert worker._preferred_ipv4_proto() is None


def test_no_force_for_ip_literal_remote(tmp_path: Path) -> None:
    cfg = _write_config(tmp_path, "remote 203.0.113.9 1194 udp\n")
    worker = VpnWorker(cfg, 0)
    # Must not even attempt resolution for a literal address.
    with patch(
        "openvpn_manager.backend.vpn_process._resolve_ipv4"
    ) as resolve:
        assert worker._preferred_ipv4_proto() is None
        resolve.assert_not_called()


@pytest.fixture
def mgmt_pair():
    """A ManagementClient wired to one end of a socketpair (the "server")."""
    ours, theirs = socket.socketpair()
    client = ManagementClient()
    client._sock = ours
    yield client, theirs
    client.close()
    theirs.close()


def test_command_returns_on_success_without_waiting(mgmt_pair) -> None:
    """Regression: replies have no prompt, so waiting for '>' cost 5 s each."""
    client, server = mgmt_pair
    server.sendall(
        b">HOLD:Waiting for hold release:0\r\n"
        b"SUCCESS: hold release succeeded\r\n"
    )
    start = time.monotonic()
    resp = client.command("hold release")
    assert time.monotonic() - start < 1.0
    assert resp.splitlines()[-1] == "SUCCESS: hold release succeeded"
    assert server.recv(64) == b"hold release\n"


def test_command_reads_multiline_reply_until_end(mgmt_pair) -> None:
    client, server = mgmt_pair
    server.sendall(
        b"1700000000,CONNECTING,,,,,,\r\n"
        b">BYTECOUNT:123,456\r\n"
        b"1700000005,CONNECTED,SUCCESS,10.8.0.2,,,,\r\n"
        b"END\r\n"
    )
    start = time.monotonic()
    resp = client.command("state")
    assert time.monotonic() - start < 1.0
    assert resp.splitlines()[-1] == "END"
    assert ">BYTECOUNT:123,456" in resp


def test_command_keeps_bytes_after_terminator_for_next_reply(mgmt_pair) -> None:
    client, server = mgmt_pair
    server.sendall(b"SUCCESS: first\r\nERROR: second\r\n")
    assert client.command("one") == "SUCCESS: first"
    assert client.command("two") == "ERROR: second"


def test_command_returns_partial_reply_on_eof(mgmt_pair) -> None:
    client, server = mgmt_pair
    server.sendall(b">INFO:bye\r\n")
    server.shutdown(socket.SHUT_WR)
    assert client.command("state") == ">INFO:bye"


def test_parse_bytecount_from_notification() -> None:
    resp = "1700000005,CONNECTED,SUCCESS,10.8.0.2,,,,\n>BYTECOUNT:123,456\nEND"
    assert _worker()._parse_bytecount(resp) == (123, 456)


def test_parse_bytecount_absent_returns_none() -> None:
    """Missing counts must not reset the displayed totals to zero."""
    assert _worker()._parse_bytecount("1700000005,CONNECTED,,,,,,\nEND") is None


def _feed(monitor: HandshakeMonitor, *lines: str, now: float = 0.0) -> None:
    for line in lines:
        monitor.feed(f"2026-10-21 22:50:21 {line}", now)


def test_handshake_rejected_client_cert_is_explained() -> None:
    m = HandshakeMonitor()
    _feed(
        m,
        "TLS: Initial packet from [AF_INET]203.0.113.5:1196, sid=aaf0ba55 d830acf4",
        "VERIFY OK: depth=1, CN=Easy-RSA CA",
        "VERIFY OK: depth=0, CN=server",
    )
    assert not m.failed
    _feed(
        m,
        "TLS Error: TLS key negotiation failed to occur within 60 seconds "
        "(check your network connectivity)",
    )
    assert m.failed
    msg = m.failure_message()
    assert "client certificate" in msg
    assert "CRL" in msg


def test_handshake_no_reply_points_at_reachability() -> None:
    m = HandshakeMonitor()
    _feed(m, "TLS Error: TLS handshake failed")
    assert m.failed
    assert "no reply from the server" in m.failure_message()


def test_handshake_partial_reply() -> None:
    m = HandshakeMonitor()
    _feed(m, "TLS: Initial packet from [AF_INET]203.0.113.5:1196, sid=1 2")
    assert m.phase == HandshakeMonitor.SERVER_REPLIED
    assert "did not complete" in m.failure_message()


def test_handshake_stall_detected_after_server_verified() -> None:
    m = HandshakeMonitor()
    _feed(m, "VERIFY OK: depth=0, CN=server", now=100.0)
    assert not m.stalled(100.0 + HANDSHAKE_STALL_SEC - 0.1)
    assert m.stalled(100.0 + HANDSHAKE_STALL_SEC)


def test_handshake_not_stalled_once_peer_connected() -> None:
    m = HandshakeMonitor()
    _feed(m, "VERIFY OK: depth=0, CN=server", now=0.0)
    _feed(m, "[server] Peer Connection Initiated with [AF_INET]203.0.113.5:1196")
    assert m.phase == HandshakeMonitor.DONE
    assert not m.stalled(1000.0)


def _pull_filters(cmd: list[str]) -> list[str]:
    return [
        cmd[i + 2]
        for i, arg in enumerate(cmd)
        if arg == "--pull-filter" and cmd[i + 1] == "ignore"
    ]


def test_build_command_split_tunnel_by_default(runtime_dir: Path) -> None:
    """Server-pushed default routes must not hijack the host's internet."""
    worker = VpnWorker(Path("/tmp/profile.ovpn"), 0)
    cmd = worker._build_command(runtime_dir / "mgmt.sock")
    filters = _pull_filters(cmd)
    assert "redirect-gateway" in filters
    assert "route 0.0.0.0 0.0.0.0" in filters
    assert "route-ipv6 2000::/3" in filters
    # Must come after --config so it applies to what the server pushes.
    assert cmd.index("--pull-filter") > cmd.index("--config")


def test_build_command_full_tunnel_when_opted_in(runtime_dir: Path) -> None:
    worker = VpnWorker(Path("/tmp/profile.ovpn"), 0, route_all_traffic=True)
    cmd = worker._build_command(runtime_dir / "mgmt.sock")
    assert "--pull-filter" not in cmd
