#!/usr/bin/env python3
"""Bump the app patch version when its source changes.

Two trigger modes share the same bump logic:

* **PostToolUse hook** (default): reads the Claude Code hook JSON payload on
  stdin and bumps when the *edited* file is real app source. Fires only on
  Claude's own edits.
* **git pre-commit** (``--git``): bumps when a commit *stages* app source,
  catching manual/IDE edits too, then re-stages the version files so the bump
  rides along in the same commit.

A "real source change" means a ``.py``/``.qss`` file under the
``openvpn_manager`` package — not docs, tests, config, or the version file
itself. The patch component is incremented in both
``openvpn_manager/__init__.py`` (shown in the UI) and ``pyproject.toml`` (kept
in sync for packaging).

The two modes compose without double-bumping: ``--git`` skips when the version
has already moved past HEAD (e.g. the PostToolUse hook bumped it during the
session). Everything is intentionally forgiving — any problem results in a
clean exit 0 so a version bump can never block an edit or a commit.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INIT_FILE = PROJECT_ROOT / "openvpn_manager" / "__init__.py"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"

# Only these source extensions under openvpn_manager/ count as an app change.
SOURCE_SUFFIXES = {".py", ".qss"}

_VERSION_RE = re.compile(r'__version__\s*=\s*"(\d+\.\d+\.\d+)"')


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


def _do_bump() -> str | None:
    try:
        new_version = _bump_init()
        if new_version:
            _sync_pyproject(new_version)
        return new_version
    except OSError:
        return None


def _git(*args: str) -> str | None:
    """Run a git command in the project; return stdout, or None on any error."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout


def _staged_touches_app_source() -> bool:
    out = _git("diff", "--cached", "--name-only", "--diff-filter=ACM")
    if out is None:
        return False
    for name in out.splitlines():
        name = name.strip()
        if not name:
            continue
        if _is_app_source((PROJECT_ROOT / name).resolve()):
            return True
    return False


def _version_in(text: str | None) -> str | None:
    if not text:
        return None
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def _already_bumped_since_head() -> bool:
    """True if __init__.py's version already differs from the committed HEAD."""
    head = _version_in(_git("show", "HEAD:openvpn_manager/__init__.py"))
    if head is None:
        return False  # no HEAD yet (first commit) — fine to bump
    try:
        current = _version_in(INIT_FILE.read_text(encoding="utf-8"))
    except OSError:
        return False
    return current is not None and current != head


def run_stdin() -> int:
    """PostToolUse mode: bump when Claude edited an app source file."""
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if not _is_app_source(_edited_path(payload)):
        return 0
    new_version = _do_bump()
    if new_version:
        print(f"Version bumped to {new_version}")
    return 0


def run_git() -> int:
    """pre-commit mode: bump once per commit that stages app source."""
    if not _staged_touches_app_source():
        return 0
    if _already_bumped_since_head():
        return 0  # the PostToolUse hook already bumped it this session
    new_version = _do_bump()
    if new_version:
        _git("add", str(INIT_FILE), str(PYPROJECT))
        print(f"Version bumped to {new_version}")
    return 0


def main() -> int:
    if "--git" in sys.argv[1:]:
        return run_git()
    return run_stdin()


if __name__ == "__main__":
    sys.exit(main())
