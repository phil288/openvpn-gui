"""Unit tests for profile import and parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from openvpn_manager.backend import profile_store


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    profiles = cfg / "profiles"
    profiles.mkdir(parents=True)
    monkeypatch.setattr(profile_store, "CONFIG_DIR", cfg)
    monkeypatch.setattr(profile_store, "PROFILES_DIR", profiles)
    monkeypatch.setattr(profile_store, "INDEX_FILE", cfg / "profiles.json")
    return cfg


def test_parse_ovpn_config() -> None:
    content = "remote vpn.example.com 1194 udp\nauth-user-pass\n"
    meta = profile_store.parse_ovpn_config(content)
    assert meta["server"] == "vpn.example.com"
    assert meta["port"] == 1194
    assert meta["needs_auth"] is True


def test_import_profile(isolated_store: Path, tmp_path: Path) -> None:
    ovpn = tmp_path / "test.ovpn"
    ovpn.write_text("remote my.vpn.test 443 tcp\n", encoding="utf-8")
    profile = profile_store.import_profile(ovpn, "My VPN")
    assert profile.name == "My VPN"
    assert profile.server == "my.vpn.test"
    assert len(profile_store.list_profiles()) == 1
