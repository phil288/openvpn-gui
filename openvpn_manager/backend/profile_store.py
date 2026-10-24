"""Profile storage: import .ovpn / WireGuard .conf files and persist metadata."""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openvpn_manager.backend.wireguard_config import (
    WIREGUARD_SUFFIX,
    is_wireguard_config,
    parse_wireguard_config,
    scan_wireguard_risks,
)

CONFIG_DIR = Path.home() / ".config" / "openvpn-manager"
PROFILES_DIR = CONFIG_DIR / "profiles"
INDEX_FILE = CONFIG_DIR / "profiles.json"

VPN_OPENVPN = "openvpn"
VPN_WIREGUARD = "wireguard"
OVPN_SUFFIX = ".ovpn"
PROFILE_SUFFIXES = (OVPN_SUFFIX, WIREGUARD_SUFFIX)


@dataclass
class Profile:
    """A saved VPN profile (OpenVPN or WireGuard)."""

    id: str
    name: str
    server: str
    port: int
    protocol: str
    config_path: str
    needs_auth: bool = False
    allow_scripts: bool = False
    # Original .ovpn the stored copy was imported from ("" for profiles
    # imported before this was tracked).
    source_path: str = ""
    # Off = split tunnel: server-pushed default routes are ignored so only the
    # VPN's own networks go through the tunnel.
    route_all_traffic: bool = False
    # "openvpn" or "wireguard"; profiles saved before WireGuard support
    # have no key and load as OpenVPN.
    vpn_type: str = VPN_OPENVPN
    last_used: str | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Profile:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def is_wireguard(self) -> bool:
        return self.vpn_type == VPN_WIREGUARD


# OpenVPN config directives that cause command, script, or shared-object
# execution. Because the tunnel runs as root, any of these in an untrusted
# profile is a root code-execution vector and must require explicit consent.
RISKY_DIRECTIVES = frozenset(
    {
        "up",
        "down",
        "route-up",
        "route-pre-down",
        "ipchange",
        "tls-verify",
        "tls-crypt-v2-verify",
        "auth-user-pass-verify",
        "client-connect",
        "client-disconnect",
        "learn-address",
        "plugin",
        "script-security",
    }
)


class RiskyConfigError(ValueError):
    """Raised when a profile contains root-executing directives without consent."""

    def __init__(self, risks: list[tuple[str, str]]) -> None:
        self.risks = risks
        super().__init__("Config contains directives that execute as root")


def scan_config_risks(content: str) -> list[tuple[str, str]]:
    """Return (directive, full line) for each risky directive in the config."""
    found: list[tuple[str, str]] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        token = line.split(None, 1)[0].lstrip("-").lower()
        if token in RISKY_DIRECTIVES:
            found.append((token, line))
    return found


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


# Comment header carrying the display name, so an exported profile keeps its
# name when imported elsewhere.
_NAME_HEADER = "# ovpn-profile:"


def _header_name(content: str) -> str | None:
    """Display name from an export header, if present."""
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith(_NAME_HEADER):
            return line.split(":", 1)[1].strip() or None
    return None


def parse_ovpn_config(content: str) -> dict[str, Any]:
    """Extract display metadata from .ovpn content."""
    name = "OpenVPN Profile"
    server = ""
    port = 1194
    protocol = "udp"
    needs_auth = False

    for line in content.splitlines():
        line = line.strip()
        lower = line.lower()
        # Name header written by export_profile(); checked before the comment
        # skip below because it is itself a comment line.
        if lower.startswith(_NAME_HEADER):
            name = line.split(":", 1)[1].strip() or name
            continue
        if not line or line.startswith("#") or line.startswith(";"):
            continue
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


def import_profile(
    source_path: Path,
    display_name: str | None = None,
    allow_risky: bool = False,
) -> Profile:
    """Import a .ovpn file.

    If a profile for the same connection (server + port + protocol) already
    exists, it is replaced in place — the config is refreshed and metadata
    updated while the existing id, saved credentials, and history are kept —
    instead of creating a duplicate entry.

    Because the tunnel runs as root, configs containing directives that execute
    commands/scripts/plugins as root (see ``RISKY_DIRECTIVES``) raise
    ``RiskyConfigError`` unless ``allow_risky`` is set — the caller must obtain
    explicit user consent first. A consented risky import is recorded on the
    profile as ``allow_scripts`` so the tunnel is allowed to run those scripts.
    """
    source_path = source_path.resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"Profile not found: {source_path}")
    suffix = source_path.suffix.lower()
    if suffix not in PROFILE_SUFFIXES:
        raise ValueError("Only .ovpn (OpenVPN) and .conf (WireGuard) files are supported")

    content = source_path.read_text(encoding="utf-8", errors="replace")
    return _import_content(
        content,
        suffix,
        str(source_path),
        display_name or None,
        source_path.stem,
        allow_risky,
    )


_OVPN_REMOTE_RE = re.compile(r"^\s*remote\s+\S", re.MULTILINE | re.IGNORECASE)


def detect_config_suffix(content: str) -> str | None:
    """Profile suffix for pasted config text, or None if unrecognised."""
    if is_wireguard_config(content):
        return WIREGUARD_SUFFIX
    if _OVPN_REMOTE_RE.search(content):
        return OVPN_SUFFIX
    return None


def import_profile_text(
    content: str,
    display_name: str | None = None,
    allow_risky: bool = False,
) -> Profile:
    """Import a profile from pasted config text (WireGuard or OpenVPN).

    The type is detected from the content: a WireGuard ``[Interface]`` with a
    ``PrivateKey``, or an OpenVPN config with a ``remote`` directive. Otherwise
    behaves exactly like ``import_profile`` (dedupe, risk consent).
    """
    suffix = detect_config_suffix(content)
    if suffix is None:
        raise ValueError(
            "Text is not a WireGuard config ([Interface] with a PrivateKey) "
            "or an OpenVPN config (with a remote line)"
        )
    if not content.endswith("\n"):
        content += "\n"
    return _import_content(content, suffix, "", display_name, "", allow_risky)


def _import_content(
    content: str,
    suffix: str,
    source_label: str,
    display_name: str | None,
    fallback_name: str,
    allow_risky: bool,
) -> Profile:
    if suffix == WIREGUARD_SUFFIX:
        if not is_wireguard_config(content):
            raise ValueError(
                "Not a WireGuard config: expected an [Interface] section "
                "with a PrivateKey"
            )
        vpn_type = VPN_WIREGUARD
        risks = scan_wireguard_risks(content)
        meta = parse_wireguard_config(content)
        meta["name"] = _header_name(content) or meta["name"]
    else:
        vpn_type = VPN_OPENVPN
        risks = scan_config_risks(content)
        meta = parse_ovpn_config(content)
    if risks and not allow_risky:
        raise RiskyConfigError(risks)
    allow_scripts = bool(risks)  # consented script execution for this profile

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
        dest = Path(existing.get("config_path") or PROFILES_DIR / f"{profile_id}{suffix}")
        _store_config(content, dest)
        existing.update(
            {
                "name": display_name or existing.get("name") or meta["name"],
                "server": meta["server"],
                "port": meta["port"],
                "protocol": meta["protocol"],
                "config_path": str(dest),
                "needs_auth": meta["needs_auth"],
                "allow_scripts": allow_scripts,
                "source_path": source_label,
                "vpn_type": vpn_type,
            }
        )
        _save_index(entries)
        return Profile.from_dict(existing)

    profile_id = str(uuid.uuid4())
    dest = PROFILES_DIR / f"{profile_id}{suffix}"
    _store_config(content, dest)

    name = display_name or meta["name"] or fallback_name
    profile = Profile(
        id=profile_id,
        name=name,
        server=meta["server"],
        port=meta["port"],
        protocol=meta["protocol"],
        config_path=str(dest),
        needs_auth=meta["needs_auth"],
        allow_scripts=allow_scripts,
        source_path=source_label,
        vpn_type=vpn_type,
        # A WireGuard config states its routing itself (AllowedIPs), unlike
        # OpenVPN where the server pushes it — honour a full-tunnel config.
        route_all_traffic=bool(meta.get("full_tunnel")),
    )
    entries.append(profile.to_dict())
    _save_index(entries)
    return profile


def _store_config(content: str, dest: Path) -> None:
    """Write the stored config owner-only: WireGuard configs hold the
    PrivateKey and .ovpn files often embed <key>/<tls-auth> material."""
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(content)


def profile_suffix(profile: Profile) -> str:
    return WIREGUARD_SUFFIX if profile.is_wireguard else OVPN_SUFFIX


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


def suggested_export_filename(profile: Profile) -> str:
    """Filesystem-safe ``<name>.ovpn`` / ``<name>.conf`` for the save dialog."""
    stem = re.sub(r"[^\w.-]+", "_", profile.name).strip("._")
    return f"{stem or 'profile'}{profile_suffix(profile)}"


def export_profile(profile_id: str, dest: Path) -> Path:
    """Write a profile's connection settings to ``dest`` (.ovpn or .conf).

    The stored config is written verbatim with a ``# ovpn-profile: <name>``
    header prepended (replacing any existing one) so re-importing it restores
    the display name (wg-quick ignores it as a comment). The profile type's
    suffix is added when missing.

    Saved VPN credentials live in the keyring and are never exported. The
    config itself may embed private keys (``<key>``, ``<tls-auth>`` …), so the
    file is created owner-only (0600).
    """
    profile = get_profile(profile_id)
    if profile is None:
        raise KeyError(f"Unknown profile: {profile_id}")
    source = Path(profile.config_path)
    if not source.is_file():
        raise FileNotFoundError(f"Profile config missing: {source}")

    dest = Path(dest)
    suffix = profile_suffix(profile)
    if dest.suffix.lower() != suffix:
        dest = dest.with_name(dest.name + suffix)

    content = source.read_text(encoding="utf-8", errors="replace")
    body = "".join(
        line
        for line in content.splitlines(keepends=True)
        if not line.strip().lower().startswith(_NAME_HEADER)
    )
    name = " ".join(profile.name.split())
    data = f"{_NAME_HEADER} {name}\n{body}"

    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)  # also tighten a pre-existing file
        f.write(data)
    return dest


def set_route_all_traffic(profile_id: str, enabled: bool) -> Profile | None:
    """Choose whether the profile sends all traffic through the tunnel."""
    entries = _load_index()
    for e in entries:
        if e.get("id") == profile_id:
            e["route_all_traffic"] = bool(enabled)
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
