"""WireGuard (wg-quick) config parsing and runtime rewriting."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

WIREGUARD_SUFFIX = ".conf"
WIREGUARD_PROTOCOL = "wireguard"
DEFAULT_PORT = 51820

# wg-quick keys that run arbitrary shell commands as root on up/down.
WIREGUARD_HOOK_KEYS = frozenset({"preup", "postup", "predown", "postdown"})

# AllowedIPs entries that send all traffic into the tunnel (wg-quick installs
# policy routing for the /0 forms; the /1 pairs are the classic override).
DEFAULT_ROUTE_NETS = frozenset(
    {
        ipaddress.ip_network(n)
        for n in (
            "0.0.0.0/0",
            "0.0.0.0/1",
            "128.0.0.0/1",
            "::/0",
            "::/1",
            "8000::/1",
            "2000::/3",
        )
    }
)

_SECTION_RE = re.compile(r"^\s*\[\s*(\w+)\s*\]\s*$")


def _split_line(line: str) -> tuple[str, str] | None:
    """Return (lowercased key, value) for a ``Key = Value`` line."""
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
        return None
    key, _, value = stripped.partition("=")
    # wg-quick strips trailing comments from values.
    value = value.split("#", 1)[0].strip()
    return key.strip().lower(), value


def is_wireguard_config(content: str) -> bool:
    """True if content looks like a wg-quick config ([Interface] + PrivateKey)."""
    section = ""
    has_interface = has_key = False
    for line in content.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1).lower()
            has_interface = has_interface or section == "interface"
            continue
        kv = _split_line(line)
        if kv and section == "interface" and kv[0] == "privatekey" and kv[1]:
            has_key = True
    return has_interface and has_key


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    """Split ``host:port`` / ``[v6]:port`` into (host, port)."""
    host, port = endpoint, DEFAULT_PORT
    if endpoint.startswith("["):
        close = endpoint.find("]")
        if close != -1:
            host = endpoint[1:close]
            rest = endpoint[close + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
    elif endpoint.count(":") == 1:
        h, _, p = endpoint.partition(":")
        host = h
        if p.isdigit():
            port = int(p)
    return host, port


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def parse_wireguard_config(content: str) -> dict[str, Any]:
    """Extract display metadata from a wg-quick config.

    Shares the shape of ``parse_ovpn_config`` so profiles store it the same
    way; ``protocol`` is always ``"wireguard"`` and ``server``/``port`` come
    from the first peer's ``Endpoint``.
    """
    name = "WireGuard Profile"
    server = ""
    port = DEFAULT_PORT
    addresses: list[str] = []
    allowed_ips: list[str] = []
    section = ""

    for line in content.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1).lower()
            continue
        kv = _split_line(line)
        if not kv:
            continue
        key, value = kv
        if section == "interface" and key == "address":
            addresses.extend(_csv(value))
        elif section == "peer" and key == "endpoint" and not server:
            server, port = _split_endpoint(value)
        elif section == "peer" and key == "allowedips":
            allowed_ips.extend(_csv(value))

    if server and name == "WireGuard Profile":
        name = server

    return {
        "name": name,
        "server": server,
        "port": port,
        "protocol": WIREGUARD_PROTOCOL,
        "needs_auth": False,
        "addresses": addresses,
        "allowed_ips": allowed_ips,
        "full_tunnel": any(_is_default_route(n) for n in allowed_ips),
    }


def scan_wireguard_risks(content: str) -> list[tuple[str, str]]:
    """Return (key, full line) for each PreUp/PostUp/PreDown/PostDown hook."""
    found: list[tuple[str, str]] = []
    for line in content.splitlines():
        kv = _split_line(line)
        if kv and kv[0] in WIREGUARD_HOOK_KEYS:
            found.append((kv[0], line.strip()))
    return found


def _network(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _is_default_route(entry: str) -> bool:
    net = _network(entry)
    return net is not None and net in DEFAULT_ROUTE_NETS


def build_runtime_config(
    content: str, route_all_traffic: bool, allow_scripts: bool
) -> tuple[str, list[str]]:
    """Rewrite a stored config for ``wg-quick up``.

    - Without ``allow_scripts``, PreUp/PostUp/PreDown/PostDown hooks are
      dropped so the root-run tunnel can't execute config-embedded commands.
    - Without ``route_all_traffic`` (split tunnel), default-route entries are
      removed from every peer's ``AllowedIPs`` and ``DNS`` servers that are no
      longer reachable through the tunnel are dropped, so internet traffic and
      name resolution stay on the local connection.

    Returns the new config text and human-readable notes for the log.
    """
    out: list[str] = []
    notes: list[str] = []
    section = ""
    remaining_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    dns_lines: list[tuple[int, str]] = []
    dropped_hooks = 0
    dropped_routes: list[str] = []

    for line in content.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1).lower()
            out.append(line)
            continue
        kv = _split_line(line)
        if kv is None:
            out.append(line)
            continue
        key, value = kv
        if key in WIREGUARD_HOOK_KEYS and not allow_scripts:
            dropped_hooks += 1
            continue
        if section == "peer" and key == "allowedips":
            entries = _csv(value)
            if not route_all_traffic:
                kept = [e for e in entries if not _is_default_route(e)]
                dropped_routes.extend(e for e in entries if _is_default_route(e))
                entries = kept
            remaining_nets.extend(n for n in map(_network, entries) if n)
            out.append(f"AllowedIPs = {', '.join(entries)}")
            continue
        if section == "interface" and key == "dns" and not route_all_traffic:
            dns_lines.append((len(out), value))
            out.append(line)
            continue
        out.append(line)

    # Resolve DNS after all peers are seen: keep only servers inside the
    # networks still routed through the tunnel (search domains always kept).
    for index, value in reversed(dns_lines):
        kept, dropped = [], []
        for entry in _csv(value):
            try:
                addr = ipaddress.ip_address(entry)
            except ValueError:
                kept.append(entry)  # search domain
                continue
            if any(addr in net for net in remaining_nets):
                kept.append(entry)
            else:
                dropped.append(entry)
        if dropped:
            notes.append(
                "Split tunnel: not using VPN DNS server(s) outside the tunnel's "
                "networks: " + ", ".join(dropped)
            )
        if any(_is_ip(e) for e in kept):
            out[index] = f"DNS = {', '.join(kept)}"
        else:
            del out[index]  # search domains alone would break resolvconf

    if dropped_hooks:
        notes.append(
            f"Ignoring {dropped_hooks} PreUp/PostUp/PreDown/PostDown command(s) "
            "(not allowed for this profile)"
        )
    if dropped_routes:
        notes.append(
            "Split tunnel: ignoring default route(s) "
            + ", ".join(dropped_routes)
            + " — internet traffic stays on the local connection"
        )
        if not remaining_nets:
            notes.append(
                "Warning: this profile only routes the internet through the "
                "VPN, so split tunnel leaves no networks in the tunnel. Enable "
                "“Route all internet traffic through the VPN” to use it."
            )

    return "\n".join(out) + "\n", notes


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def first_address(content: str) -> str:
    """First ``Address`` of the interface without its prefix length."""
    for addr in parse_wireguard_config(content)["addresses"]:
        return addr.split("/", 1)[0]
    return ""
