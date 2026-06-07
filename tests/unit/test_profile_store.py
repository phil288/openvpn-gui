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


def test_reimport_replaces_existing_profile(
    isolated_store: Path, tmp_path: Path
) -> None:
    """Re-importing the same connection replaces it instead of duplicating."""
    first = tmp_path / "a.ovpn"
    first.write_text("remote my.vpn.test 1194 udp\n", encoding="utf-8")
    original = profile_store.import_profile(first, "My VPN")

    second = tmp_path / "b.ovpn"
    second.write_text(
        "remote my.vpn.test 1194 udp\nauth-user-pass\n", encoding="utf-8"
    )
    replaced = profile_store.import_profile(second)

    profiles = profile_store.list_profiles()
    assert len(profiles) == 1  # not duplicated
    assert replaced.id == original.id  # same id → credentials stay attached
    assert replaced.name == "My VPN"  # name preserved when none supplied
    assert replaced.needs_auth is True  # refreshed metadata from new config
    # The stored config file reflects the latest import.
    assert "auth-user-pass" in Path(replaced.config_path).read_text()


def test_reimport_updates_name_when_supplied(
    isolated_store: Path, tmp_path: Path
) -> None:
    ovpn = tmp_path / "a.ovpn"
    ovpn.write_text("remote my.vpn.test 1194 udp\n", encoding="utf-8")
    profile_store.import_profile(ovpn, "Old Name")
    replaced = profile_store.import_profile(ovpn, "New Name")
    assert len(profile_store.list_profiles()) == 1
    assert replaced.name == "New Name"


def test_different_server_creates_new_profile(
    isolated_store: Path, tmp_path: Path
) -> None:
    a = tmp_path / "a.ovpn"
    a.write_text("remote a.vpn.test 1194 udp\n", encoding="utf-8")
    b = tmp_path / "b.ovpn"
    b.write_text("remote b.vpn.test 1194 udp\n", encoding="utf-8")
    profile_store.import_profile(a)
    profile_store.import_profile(b)
    assert len(profile_store.list_profiles()) == 2
