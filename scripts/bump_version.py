#!/usr/bin/env python3
"""PostToolUse hook: bump the app patch version when its source is modified.

Reads the Claude Code hook JSON payload on stdin. If the edited file lives
inside this project's ``openvpn_manager`` package (a real source change, not
docs/tests/config churn), the patch component of the version is incremented in
both ``openvpn_manager/__init__.py`` (the value shown in the UI) and
``pyproject.toml`` (kept in sync for packaging).

The hook is intentionally forgiving: any problem results in a clean exit 0 so a
version bump can never block or fail the editing tool that triggered it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INIT_FILE = PROJECT_ROOT / "openvpn_manager" / "__init__.py"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"

# Only these source extensions under openvpn_manager/ count as an app change.
SOURCE_SUFFIXES = {".py", ".qss"}


def _edited_path(payload: dict) -> Path | None:
    tool_input = payload.get("tool_input") or {}
    raw = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not raw:
        return None
    try:
        return Path(raw).resolve()
    except OSError:
        return None


def _is_app_source(path: Path | None) -> bool:
    if path is None:
        return False
    try:
        rel = path.relative_to(PROJECT_ROOT)
    except ValueError:
        return False  # edit outside this repo
    if not rel.parts or rel.parts[0] != "openvpn_manager":
        return False
    if path == INIT_FILE:
        return False  # the version file itself must not trigger a bump
    return path.suffix in SOURCE_SUFFIXES


def _bump_init() -> str | None:
    """Increment the patch in __init__.py; return the new version string."""
    text = INIT_FILE.read_text(encoding="utf-8")
    m = re.search(r'(__version__\s*=\s*")(\d+)\.(\d+)\.(\d+)(")', text)
    if not m:
        return None
    major, minor, patch = int(m.group(2)), int(m.group(3)), int(m.group(4))
    new_version = f"{major}.{minor}.{patch + 1}"
    updated = f"{m.group(1)}{new_version}{m.group(5)}"
    INIT_FILE.write_text(text[: m.start()] + updated + text[m.end():], encoding="utf-8")
    return new_version


def _sync_pyproject(new_version: str) -> None:
    if not PYPROJECT.is_file():
        return
    text = PYPROJECT.read_text(encoding="utf-8")
    updated = re.sub(
        r'(?m)^(version\s*=\s*")\d+\.\d+\.\d+(")',
        rf"\g<1>{new_version}\g<2>",
        text,
        count=1,
    )
    if updated != text:
        PYPROJECT.write_text(updated, encoding="utf-8")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if not _is_app_source(_edited_path(payload)):
        return 0
    try:
        new_version = _bump_init()
        if new_version:
            _sync_pyproject(new_version)
            print(f"Version bumped to {new_version}")
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
