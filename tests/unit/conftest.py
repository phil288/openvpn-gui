"""Shared pytest fixtures."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolated_runtime_dir(monkeypatch, tmp_path):
    """Avoid writing management sockets under /run/user in unit tests."""
    rt = tmp_path / "runtime"
    rt.mkdir()
    monkeypatch.setenv("OPENVPN_MANAGER_RUNTIME_DIR", str(rt))
