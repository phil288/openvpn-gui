"""Unit tests for WireGuard config handling, import, and the wg-quick worker."""

from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from openvpn_manager.backend import profile_store
from openvpn_manager.backend import vpn_process
from openvpn_manager.backend.vpn_process import (
    WireGuardWorker,
    wireguard_interface_name,
)
from openvpn_manager.backend.wireguard_config import (
    build_runtime_config,
    is_wireguard_config,
    parse_wireguard_config,
    scan_wireguard_risks,
)

FULL_TUNNEL = """\
[Interface]
PrivateKey = cGxhY2Vob2xkZXJwbGFjZWhvbGRlcnBsYWNlaG9sZGU=
Address = 10.8.0.2/24, fd00::2/64
DNS = 10.8.0.1, 1.1.1.1, corp.example

[Peer]
PublicKey = c2VydmVyc2VydmVyc2VydmVyc2VydmVyc2VydmVyc2U=
Endpoint = wg.example.com:51821
AllowedIPs = 0.0.0.0/0, ::/0, 10.8.0.0/24
"""


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    profiles = cfg / "profiles"
    profiles.mkdir(parents=True)
    monkeypatch.setattr(profile_store, "CONFIG_DIR", cfg)
    monkeypatch.setattr(profile_store, "PROFILES_DIR", profiles)
    monkeypatch.setattr(profile_store, "INDEX_FILE", cfg / "profiles.json")
    return cfg


def test_detects_wireguard_config() -> None:
    assert is_wireguard_config(FULL_TUNNEL)
    assert not is_wireguard_config("[Interface]\nAddress = 10.0.0.2/24\n")
    assert not is_wireguard_config("remote vpn.example.com 1194 udp\n")


def test_parse_wireguard_config() -> None:
    meta = parse_wireguard_config(FULL_TUNNEL)
    assert meta["server"] == "wg.example.com"
    assert meta["port"] == 51821
    assert meta["protocol"] == "wireguard"
    assert meta["needs_auth"] is False
    assert meta["full_tunnel"] is True
    assert meta["addresses"] == ["10.8.0.2/24", "fd00::2/64"]


def test_parse_ipv6_endpoint() -> None:
    meta = parse_wireguard_config(
        FULL_TUNNEL.replace("wg.example.com:51821", "[2001:db8::1]:4500")
    )
    assert (meta["server"], meta["port"]) == ("2001:db8::1", 4500)


def test_scan_wireguard_hooks() -> None:
    content = FULL_TUNNEL.replace(
        "DNS =", "PostUp = iptables -A FORWARD -j ACCEPT\nDNS ="
    )
    risks = scan_wireguard_risks(content)
    assert [k for k, _ in risks] == ["postup"]


def test_split_tunnel_drops_default_routes_and_outside_dns() -> None:
    text, notes = build_runtime_config(
        FULL_TUNNEL, route_all_traffic=False, allow_scripts=False
    )
    assert "AllowedIPs = 10.8.0.0/24" in text
    assert "0.0.0.0/0" not in text and "::/0" not in text
    # 10.8.0.1 is inside the tunnel's networks; 1.1.1.1 is not.
    assert "DNS = 10.8.0.1, corp.example" in text
    assert any("1.1.1.1" in n for n in notes)


def test_split_tunnel_warns_when_nothing_left() -> None:
    content = FULL_TUNNEL.replace(", 10.8.0.0/24", "")
    text, notes = build_runtime_config(
        content, route_all_traffic=False, allow_scripts=False
    )
    assert "DNS" not in text  # no VPN resolver reachable any more
    assert any(n.startswith("Warning:") for n in notes)


def test_full_tunnel_keeps_config_routing() -> None:
    text, notes = build_runtime_config(
        FULL_TUNNEL, route_all_traffic=True, allow_scripts=False
    )
    assert "AllowedIPs = 0.0.0.0/0, ::/0, 10.8.0.0/24" in text
    assert "DNS = 10.8.0.1, 1.1.1.1, corp.example" in text
    assert notes == []


def test_hooks_stripped_unless_allowed() -> None:
    content = FULL_TUNNEL.replace("DNS =", "PostUp = touch /root/pwned\nDNS =")
    text, _ = build_runtime_config(content, True, allow_scripts=False)
    assert "PostUp" not in text
    text, _ = build_runtime_config(content, True, allow_scripts=True)
    assert "PostUp = touch /root/pwned" in text


def test_import_wireguard_profile(isolated_store: Path, tmp_path: Path) -> None:
    conf = tmp_path / "office.conf"
    conf.write_text(FULL_TUNNEL, encoding="utf-8")
    profile = profile_store.import_profile(conf)

    assert profile.is_wireguard
    assert profile.name == "wg.example.com"
    assert profile.server == "wg.example.com"
    assert profile.config_path.endswith(".conf")
    assert profile.route_all_traffic is True  # honours the config's 0.0.0.0/0
    # The stored copy holds the private key: owner-only.
    mode = stat.S_IMODE(Path(profile.config_path).stat().st_mode)
    assert mode == 0o600


def test_import_rejects_non_wireguard_conf(
    isolated_store: Path, tmp_path: Path
) -> None:
    conf = tmp_path / "nginx.conf"
    conf.write_text("server { listen 80; }\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Not a WireGuard config"):
        profile_store.import_profile(conf)


def test_import_wireguard_hooks_need_consent(
    isolated_store: Path, tmp_path: Path
) -> None:
    conf = tmp_path / "hooks.conf"
    conf.write_text(
        FULL_TUNNEL.replace("DNS =", "PreUp = echo hi\nDNS ="), encoding="utf-8"
    )
    with pytest.raises(profile_store.RiskyConfigError):
        profile_store.import_profile(conf)
    profile = profile_store.import_profile(conf, allow_risky=True)
    assert profile.allow_scripts is True


def test_wireguard_and_openvpn_same_host_do_not_replace(
    isolated_store: Path, tmp_path: Path
) -> None:
    conf = tmp_path / "a.conf"
    conf.write_text(FULL_TUNNEL, encoding="utf-8")
    ovpn = tmp_path / "a.ovpn"
    ovpn.write_text("remote wg.example.com 51821 udp\n", encoding="utf-8")
    profile_store.import_profile(conf)
    profile_store.import_profile(ovpn)
    assert len(profile_store.list_profiles()) == 2


def test_export_wireguard_profile(isolated_store: Path, tmp_path: Path) -> None:
    conf = tmp_path / "office.conf"
    conf.write_text(FULL_TUNNEL, encoding="utf-8")
    profile = profile_store.import_profile(conf, "Office WG")

    assert profile_store.suggested_export_filename(profile) == "Office_WG.conf"
    dest = profile_store.export_profile(profile.id, tmp_path / "out")
    assert dest.name == "out.conf"

    reimported = profile_store.import_profile(dest)
    assert reimported.id == profile.id  # same endpoint → replaced in place
    assert reimported.name == "Office WG"


def test_old_profiles_load_as_openvpn() -> None:
    p = profile_store.Profile.from_dict(
        {
            "id": "x",
            "name": "n",
            "server": "s",
            "port": 1,
            "protocol": "udp",
            "config_path": "/c.ovpn",
        }
    )
    assert p.vpn_type == "openvpn" and not p.is_wireguard


def test_interface_name_fits_kernel_limit() -> None:
    name = wireguard_interface_name("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
    assert name == "wgm-0f1e2d3c"
    assert len(name) <= 15


def test_wireguard_worker_up_and_down(tmp_path: Path, monkeypatch) -> None:
    """Runs wg-quick up, reports CONNECTED with the config address, and
    always runs wg-quick down on stop."""
    conf = tmp_path / "p.conf"
    conf.write_text(FULL_TUNNEL, encoding="utf-8")
    worker = WireGuardWorker("abcdef12-0000", conf)

    sysfs = tmp_path / "sys"
    monkeypatch.setattr(vpn_process, "SYS_CLASS_NET", sysfs)
    # Run the real install/rm unprivileged into a temp "/etc/wireguard".
    wg_dir = tmp_path / "etc-wireguard"
    monkeypatch.setattr(vpn_process, "WG_CONFIG_DIR", wg_dir)
    monkeypatch.setattr(vpn_process, "wrap_root_command", lambda args: args)
    calls: list[str] = []
    installed: list[tuple[str, int]] = []

    def fake_wg_quick(action: str) -> bool:
        calls.append(action)
        conf_path = wg_dir / f"{worker._ifname}.conf"
        installed.append(
            (conf_path.read_text(), stat.S_IMODE(conf_path.stat().st_mode))
        )
        stats_dir = sysfs / worker._ifname / "statistics"
        if action == "up":
            stats_dir.mkdir(parents=True)
            (stats_dir / "rx_bytes").write_text("100")
            (stats_dir / "tx_bytes").write_text("50")
        return True

    events: list[object] = []
    worker.connected.connect(lambda: (events.append("connected"), worker.request_stop()))
    worker.stats_updated.connect(events.append)
    worker.error.connect(lambda m: events.append(("error", m)))

    with patch.object(worker, "_wg_quick", side_effect=fake_wg_quick), patch(
        "openvpn_manager.backend.vpn_process.needs_elevation", return_value=False
    ):
        worker.run()

    assert calls == ["up", "down"]
    assert "connected" in events
    assert not any(isinstance(e, tuple) for e in events)
    # wg-quick read a 0600 copy from the WireGuard config dir (Ubuntu's
    # AppArmor profile only allows /etc/wireguard), with split-tunnel applied.
    text, mode = installed[0]
    assert mode == 0o600
    assert "AllowedIPs = 10.8.0.0/24" in text
    assert stat.S_IMODE(wg_dir.stat().st_mode) == 0o700
    # It holds the private key, so it is removed after the session.
    assert not list(wg_dir.glob("*.conf"))
    assert not list(Path(vpn_process._runtime_dir()).glob("wgm-*.conf"))


def test_wireguard_worker_reports_failed_up(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(vpn_process, "WG_CONFIG_DIR", tmp_path / "etc-wireguard")
    monkeypatch.setattr(vpn_process, "wrap_root_command", lambda args: args)
    conf = tmp_path / "p.conf"
    conf.write_text(FULL_TUNNEL, encoding="utf-8")
    worker = WireGuardWorker("abcdef12", conf)
    errors: list[str] = []
    worker.error.connect(errors.append)
    with patch.object(worker, "_wg_quick", return_value=False) as wg, patch(
        "openvpn_manager.backend.vpn_process.needs_elevation", return_value=False
    ), patch.object(vpn_process, "SYS_CLASS_NET", tmp_path / "none"):
        worker.run()
    assert [c.args[0] for c in wg.call_args_list] == ["up"]  # no down
    assert errors and "wg-quick" in errors[0]
    assert not list((tmp_path / "etc-wireguard").glob("*.conf"))  # cleaned up


def test_import_pasted_wireguard_text(isolated_store: Path) -> None:
    profile = profile_store.import_profile_text(FULL_TUNNEL.rstrip("\n"), "Pasted")
    assert profile.is_wireguard
    assert profile.name == "Pasted"
    assert profile.source_path == ""
    stored = Path(profile.config_path)
    assert stored.suffix == ".conf"
    assert stored.read_text() == FULL_TUNNEL  # trailing newline restored
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600


def test_import_pasted_openvpn_text(isolated_store: Path) -> None:
    profile = profile_store.import_profile_text(
        "client\nremote vpn.example.com 443 tcp\nauth-user-pass\n"
    )
    assert profile.vpn_type == "openvpn"
    assert profile.server == "vpn.example.com"
    assert profile.needs_auth is True
    assert profile.config_path.endswith(".ovpn")


def test_import_pasted_text_dedupes_with_file(
    isolated_store: Path, tmp_path: Path
) -> None:
    conf = tmp_path / "office.conf"
    conf.write_text(FULL_TUNNEL, encoding="utf-8")
    first = profile_store.import_profile(conf)
    again = profile_store.import_profile_text(FULL_TUNNEL)
    assert again.id == first.id
    assert len(profile_store.list_profiles()) == 1


def test_import_pasted_text_risky_needs_consent(isolated_store: Path) -> None:
    text = "remote vpn.example.com 1194 udp\nup /tmp/x.sh\n"
    with pytest.raises(profile_store.RiskyConfigError):
        profile_store.import_profile_text(text)
    assert profile_store.import_profile_text(text, allow_risky=True).allow_scripts


def test_import_pasted_garbage_rejected(isolated_store: Path) -> None:
    with pytest.raises(ValueError, match="not a WireGuard config"):
        profile_store.import_profile_text("hello world\n")
    assert profile_store.list_profiles() == []


def test_detect_config_suffix() -> None:
    assert profile_store.detect_config_suffix(FULL_TUNNEL) == ".conf"
    assert profile_store.detect_config_suffix("  remote a.b 1194\n") == ".ovpn"
    assert profile_store.detect_config_suffix("[Interface]\n") is None
