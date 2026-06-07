"""Profile storage: import .ovpn files and persist metadata."""

from __future__ import annotations

import json
import re
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONFIG_DIR = Path.home() / ".config" / "openvpn-manager"
PROFILES_DIR = CONFIG_DIR / "profiles"
INDEX_FILE = CONFIG_DIR / "profiles.json"


@dataclass
class Profile:
    """A saved OpenVPN profile."""

    id: str
    name: str
    server: str
    port: int
    protocol: str
    config_path: str
    needs_auth: bool = False
    last_used: str | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Profile:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ensure_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)


def _load_index() -> list[dict[str, Any]]:
    _ensure_dirs()
    if not INDEX_FILE.exists():
        return []
    with INDEX_FILE.open(encoding="utf-8") as f:
        return json.load(f)


def _save_index(entries: list[dict[str, Any]]) -> None:
    _ensure_dirs()
    with INDEX_FILE.open("w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def parse_ovpn_config(content: str) -> dict[str, Any]:
    """Extract display metadata from .ovpn content."""
    name = "OpenVPN Profile"
    server = ""
    port = 1194
    protocol = "udp"
    needs_auth = False

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        lower = line.lower()
        if lower.startswith("remote "):
            parts = line.split()
            if len(parts) >= 2:
                server = parts[1]
            if len(parts) >= 3:
                try:
                    port = int(parts[2])
                except ValueError:
                    pass
            if len(parts) >= 4:
                protocol = parts[3].lower()
        elif lower.startswith("auth-user-pass"):
            needs_auth = True
        elif lower.startswith("# ovpn-profile:"):
            name = line.split(":", 1)[1].strip() or name

    if server and name == "OpenVPN Profile":
        name = server

    return {
        "name": name,
        "server": server,
        "port": port,
        "protocol": protocol,
        "needs_auth": needs_auth,
    }


def list_profiles() -> list[Profile]:
    """Return all saved profiles."""
    return [Profile.from_dict(e) for e in _load_index()]


def get_profile(profile_id: str) -> Profile | None:
    for p in list_profiles():
        if p.id == profile_id:
            return p
    return None


def _identity_key(server: str, port: int, protocol: str) -> tuple[str, int, str] | None:
    """Stable key identifying "the same connection". None when unmatchable."""
    if not server:
        return None
    return (server.strip().lower(), int(port), protocol.strip().lower())


def import_profile(source_path: Path, display_name: str | None = None) -> Profile:
    """Import a .ovpn file.

    If a profile for the same connection (server + port + protocol) already
    exists, it is replaced in place — the config is refreshed and metadata
    updated while the existing id, saved credentials, and history are kept —
    instead of creating a duplicate entry.
    """
    source_path = source_path.resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"Profile not found: {source_path}")
    if source_path.suffix.lower() != ".ovpn":
        raise ValueError("Only .ovpn files are supported")

    content = source_path.read_text(encoding="utf-8", errors="replace")
    meta = parse_ovpn_config(content)

    entries = _load_index()
    new_key = _identity_key(meta["server"], meta["port"], meta["protocol"])
    existing = None
    if new_key is not None:
        for e in entries:
            if (
                _identity_key(e.get("server", ""), e.get("port", 0), e.get("protocol", ""))
                == new_key
            ):
                existing = e
                break

    if existing is not None:
        # Replace: reuse id + config path so credentials stay associated.
        profile_id = existing["id"]
        dest = Path(existing.get("config_path") or PROFILES_DIR / f"{profile_id}.ovpn")
        shutil.copy2(source_path, dest)
        existing.update(
            {
                "name": display_name or existing.get("name") or meta["name"],
                "server": meta["server"],
                "port": meta["port"],
                "protocol": meta["protocol"],
                "config_path": str(dest),
                "needs_auth": meta["needs_auth"],
            }
        )
        _save_index(entries)
        return Profile.from_dict(existing)

    profile_id = str(uuid.uuid4())
    dest = PROFILES_DIR / f"{profile_id}.ovpn"
    shutil.copy2(source_path, dest)

    name = display_name or meta["name"] or source_path.stem
    profile = Profile(
        id=profile_id,
        name=name,
        server=meta["server"],
        port=meta["port"],
        protocol=meta["protocol"],
        config_path=str(dest),
        needs_auth=meta["needs_auth"],
    )
    entries.append(profile.to_dict())
    _save_index(entries)
    return profile


def delete_profile(profile_id: str) -> bool:
    """Remove profile from index and delete config file."""
    entries = _load_index()
    new_entries = []
    removed = False
    for e in entries:
        if e.get("id") == profile_id:
            removed = True
            config = Path(e.get("config_path", ""))
            if config.is_file():
                config.unlink(missing_ok=True)
        else:
            new_entries.append(e)
    if removed:
        _save_index(new_entries)
    return removed


def rename_profile(profile_id: str, new_name: str) -> Profile | None:
    entries = _load_index()
    for e in entries:
        if e.get("id") == profile_id:
            e["name"] = new_name.strip() or e["name"]
            _save_index(entries)
            return Profile.from_dict(e)
    return None


def touch_last_used(profile_id: str) -> None:
    """Update last_used timestamp for a profile."""
    entries = _load_index()
    now = datetime.now(timezone.utc).isoformat()
    for e in entries:
        if e.get("id") == profile_id:
            e["last_used"] = now
            _save_index(entries)
            return


def profile_needs_auth(config_path: Path) -> bool:
    """Check if config requires username/password."""
    if not config_path.is_file():
        return False
    content = config_path.read_text(encoding="utf-8", errors="replace")
    return bool(
        re.search(r"^\s*auth-user-pass\b", content, re.MULTILINE | re.IGNORECASE)
    )
