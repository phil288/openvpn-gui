"""Unit tests for CLI argument parsing."""

from __future__ import annotations

from pathlib import Path

from openvpn_manager.single_instance import ovpn_paths_from_argv


def test_ovpn_paths_from_argv(tmp_path: Path) -> None:
    f = tmp_path / "a.ovpn"
    f.write_text("remote x 1194\n", encoding="utf-8")
    paths = ovpn_paths_from_argv(["openvpn-manager", str(f), "--help"])
    assert len(paths) == 1
    assert paths[0].name == "a.ovpn"
