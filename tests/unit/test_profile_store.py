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


def test_scan_config_risks_detects_dangerous_directives() -> None:
    content = (
        "remote vpn.test 1194 udp\n"
        "script-security 2\n"
        "up '/bin/sh -c id'\n"
        "# down commented-out should be ignored\n"
        "plugin /tmp/evil.so\n"
    )
    risks = profile_store.scan_config_risks(content)
    directives = {d for d, _ in risks}
    assert directives == {"script-security", "up", "plugin"}


def test_import_blocks_risky_config_without_consent(
    isolated_store: Path, tmp_path: Path
) -> None:
    ovpn = tmp_path / "evil.ovpn"
    ovpn.write_text(
        "remote vpn.test 1194 udp\nscript-security 2\nup /tmp/x.sh\n",
        encoding="utf-8",
    )
    with pytest.raises(profile_store.RiskyConfigError) as exc:
        profile_store.import_profile(ovpn)
    assert exc.value.risks  # carries the offending directives
    assert profile_store.list_profiles() == []  # nothing imported


def test_import_allows_risky_with_consent_sets_allow_scripts(
    isolated_store: Path, tmp_path: Path
) -> None:
    ovpn = tmp_path / "evil.ovpn"
    ovpn.write_text(
        "remote vpn.test 1194 udp\nup /tmp/x.sh\n", encoding="utf-8"
    )
    profile = profile_store.import_profile(ovpn, allow_risky=True)
    assert profile.allow_scripts is True


def test_import_clean_config_has_scripts_disabled(
    isolated_store: Path, tmp_path: Path
) -> None:
    ovpn = tmp_path / "clean.ovpn"
    ovpn.write_text("remote vpn.test 1194 udp\nauth-user-pass\n", encoding="utf-8")
    profile = profile_store.import_profile(ovpn)
    assert profile.allow_scripts is False


def test_parse_reads_name_header() -> None:
    content = "# ovpn-profile: Office VPN\nremote vpn.example.com 1194 udp\n"
    assert profile_store.parse_ovpn_config(content)["name"] == "Office VPN"


def test_export_profile_writes_config_with_name_header(
    isolated_store: Path, tmp_path: Path
) -> None:
    ovpn = tmp_path / "src.ovpn"
    ovpn.write_text(
        "# ovpn-profile: Old Name\nremote my.vpn.test 443 tcp\nauth-user-pass\n",
        encoding="utf-8",
    )
    profile = profile_store.import_profile(ovpn, "My VPN")

    dest = profile_store.export_profile(profile.id, tmp_path / "export")

    assert dest.name == "export.ovpn"  # suffix added
    text = dest.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0] == "# ovpn-profile: My VPN"
    assert "Old Name" not in text  # stale header replaced, not duplicated
    assert "remote my.vpn.test 443 tcp" in lines
    assert dest.stat().st_mode & 0o777 == 0o600  # may hold private keys


def test_export_tightens_existing_file_permissions(
    isolated_store: Path, tmp_path: Path
) -> None:
    ovpn = tmp_path / "src.ovpn"
    ovpn.write_text("remote my.vpn.test 1194 udp\n", encoding="utf-8")
    profile = profile_store.import_profile(ovpn)
    dest = tmp_path / "existing.ovpn"
    dest.write_text("old", encoding="utf-8")
    dest.chmod(0o644)

    profile_store.export_profile(profile.id, dest)

    assert dest.stat().st_mode & 0o777 == 0o600
    assert "old" not in dest.read_text(encoding="utf-8")


def test_export_roundtrip_restores_name(
    isolated_store: Path, tmp_path: Path
) -> None:
    ovpn = tmp_path / "src.ovpn"
    ovpn.write_text("remote my.vpn.test 1194 udp\n", encoding="utf-8")
    profile = profile_store.import_profile(ovpn, "Home VPN")
    dest = profile_store.export_profile(profile.id, tmp_path / "home.ovpn")

    profile_store.delete_profile(profile.id)
    reimported = profile_store.import_profile(dest)

    assert reimported.name == "Home VPN"
    assert reimported.server == "my.vpn.test"


def test_export_unknown_profile_raises(isolated_store: Path, tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        profile_store.export_profile("nope", tmp_path / "x.ovpn")


def test_suggested_export_filename() -> None:
    p = profile_store.Profile(
        id="1", name="Office / VPN: EU", server="s", port=1, protocol="udp",
        config_path="",
    )
    assert profile_store.suggested_export_filename(p) == "Office_VPN_EU.ovpn"
    p.name = "///"
    assert profile_store.suggested_export_filename(p) == "profile.ovpn"
