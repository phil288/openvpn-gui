# WireGuard profiles — import and connect

- **Date:** 2026-10-24
- **Branch:** `feat/wireguard`
- **Status:** done (not yet tested against a live WireGuard server)

## Context

Request: add an option to connect to a WireGuard VPN, and import WireGuard
connections. The app was OpenVPN-only: profiles were `.ovpn` files and the
worker drove `openvpn` through its management socket.

## Decisions

- **Chosen: `wg-quick` under `sudo -n`.** Same elevation path as OpenVPN
  (`wrap_root_command`), reuses the sudo-ticket UX. `wg-quick` already handles
  addresses, routes, policy routing for `/0`, MTU and DNS.
  - **Rejected: NetworkManager (`nmcli connection import type wireguard`).**
    No root prompt needed, but it persists connections in NM outside the app's
    profile store, behaves differently on non-NM systems, and the split-tunnel
    rewriting would have to be expressed as NM properties.
  - **Rejected: driving `ip`/`wg` directly.** Re-implements `wg-quick`.
- **Profile type field** `vpn_type` (`"openvpn"` default, so old
  `profiles.json` entries load unchanged). WireGuard files are `.conf`; since
  that suffix is generic, import requires `[Interface]` + `PrivateKey` and
  rejects anything else with a clear message.
- **Stored copy chmod 0600** — it contains the interface private key. Runtime
  config (installed per connect in `/etc/wireguard`, see Corrections) is 0600 too and deleted
  after the session.
- **PreUp/PostUp/PreDown/PostDown = risky**, same consent dialog as OpenVPN
  `up`/`down`. Without consent they are stripped from the runtime config
  (mirrors `--script-security 1`).
- **Split tunnel = rewrite AllowedIPs.** When "Route all traffic" is off,
  default-route entries (`0.0.0.0/0`, `::/0`, `/1` pairs, `2000::/3`) are
  removed, and `DNS` servers not inside the remaining AllowedIPs are dropped
  (otherwise name resolution would break). A note warns when nothing is left.
- **Default for imported WireGuard profiles: honour the config.**
  `route_all_traffic = True` if AllowedIPs contains a default route. Unlike
  OpenVPN (where the *server* pushes routes and split is the safe default), a
  WireGuard config states its routing explicitly; most consumer configs are
  `AllowedIPs = 0.0.0.0/0` only and would be useless split.
- **Status from sysfs, not `wg show`.** `/sys/class/net/<if>/statistics` is
  readable without root, so stats keep working after the sudo ticket expires.
  WireGuard has no connect handshake, so CONNECTED = `wg-quick up` succeeded;
  a log warning fires when nothing is received 15 s after coming up.
- **Runtime config lives in `/etc/wireguard`** (see Corrections — distro
  AppArmor/SELinux policies only let wg-quick read there).
- **Stopping needs root** (`wg-quick down`), unlike OpenVPN (management
  `signal SIGTERM`). `VpnController.active_needs_root_to_stop` lets the
  Disconnect button, the tray action, and app exit refresh the sudo ticket
  first. Interface name `wgm-<first 8 id chars>` (kernel limit 15); a stale one
  from a crash is torn down before `up`.
- **Re-import dedupe** keys on endpoint host + port + protocol `"wireguard"`, so
  a WireGuard and OpenVPN profile on the same host never replace each other.
- **Export** writes `.conf` with the existing `# ovpn-profile: <name>` header
  (a comment to `wg-quick`), so names survive re-import.

## What changed

- `backend/wireguard_config.py` (new): detection, metadata parsing, hook scan,
  runtime-config rewriting (hooks / split tunnel / DNS).
- `backend/profile_store.py`: `vpn_type`, `.conf` import, 0600 storage, export
  suffix per type.
- `backend/privilege.py`: `wg_quick_binary()`, generic `wrap_root_command`.
- `backend/vpn_process.py`: `WireGuardWorker` (same signals as `VpnWorker`),
  controller picks the worker by type.
- UI: import dialog / drag-drop / CLI / single-instance accept `.conf`;
  subtitle shows "WireGuard"; disconnect paths refresh sudo for WireGuard.
- README: requirements and usage.
- `tests/unit/test_wireguard.py` (new, 19 tests).

## Evidence

- `.venv/bin/pytest tests/unit -q` → 72 passed.
- Offscreen Qt smoke test: importing a full-tunnel `.conf` through
  `MainWindow.open_ovpn_files` → `vpn_type=wireguard`, route-all checked,
  subtitle `wg.example.com:51820 (WireGuard)`, Credentials disabled.
- Worker up/down path tested with `_wg_quick` mocked; **no real `wg-quick up`
  was run** (would change host networking as root).

## Follow-up: paste config as text

Request: copy-paste a WireGuard or OpenVPN connection as text, not only files.

- **Chosen:** `import_profile_text()` detects the type from content —
  WireGuard if `[Interface]` + `PrivateKey`, OpenVPN if a `remote` line —
  and goes through the same `_import_content()` as file import (dedupe by
  endpoint, risky-directive consent, credentials prompt). Entry points: a
  monospace text box in **Import…** (live "Detected: …" hint, OK disabled until
  recognised; a chosen file and pasted text replace each other) and **Ctrl+V**
  on the main window (clipboard file URLs first, then text).
- **Rejected:** a separate "Paste" dialog/button — the Import dialog already
  holds the name field and is where users look; Ctrl+V covers the fast path.
- **Rejected:** requiring `client` for OpenVPN detection — many valid client
  configs omit it; `remote` is what the app needs anyway (server/port).
- Pasted profiles have `source_path = ""` (panel shows "Unknown").
- **Side change:** stored configs are now written with content (not
  `shutil.copy2`) and **all** are 0600, not just WireGuard — `.ovpn` files
  often embed `<key>`/`<tls-auth>` too. Previously `.ovpn` copies kept the
  source file's mode.
- Tests: 6 more in `test_wireguard.py` (78 total pass); offscreen smoke test
  of the dialog hint/OK state, `_paste_profile()` with an OpenVPN clipboard,
  and `_import_text()` with WireGuard text.

## Corrections

- **Wrong: "runtime config in the 0700 runtime dir works because root bypasses
  permissions."** First real connect on Ubuntu 26.04 failed with
  `/usr/bin/wg-quick: line 40: /run/user/1000/openvpn-manager/wgm-….conf:
  Permission denied`. Kernel log: `apparmor="DENIED" operation="open"
  profile="wg-quick" name="/run/user/1000/…"`. Ubuntu ships
  `/etc/apparmor.d/wg-quick`, which confines wg-quick to
  `@{etc_rw}/wireguard/{,**}` — DAC doesn't matter, MAC denies it.
  - **Fix:** the worker now pipes the runtime config through
    `sudo -n install -m 600 /dev/stdin /etc/wireguard/wgm-<id>.conf` (after
    `install -d -m 700 /etc/wireguard`), runs `wg-quick up` on that path, and
    `sudo -n rm -f` it on disconnect or failed up. Piping via stdin means the
    private key is never written to a user-owned file.
  - **Rejected:** adding an AppArmor local override
    (`/etc/apparmor.d/local/wg-quick`) — system security config change, needs
    install-time root, and Fedora's SELinux policy has a similar confinement;
    `/etc/wireguard` is the location every distro policy allows.
  - **Rejected:** passing the config on `/dev/stdin` to wg-quick — it derives
    the interface name from the file name and the profile wouldn't allow it.
  - Trade-off: a crash leaves `/etc/wireguard/wgm-<id>.conf` (root, 0600)
    until the next connect of that profile overwrites and removes it.
  - Test now runs the real `install`/`rm` unprivileged into a temp dir
    (`wrap_root_command` and `WG_CONFIG_DIR` patched) and asserts 0600 file,
    0700 dir, split-tunnel content, and removal.

## Left undone

- Live test against a real WireGuard peer.
- MIME/default-handler registration for `.conf` — too generic a suffix to
  claim; `.conf` files open via Import or drag-and-drop.
- Peer handshake age (`wg show latest-handshakes`) — needs root on every poll.
- If the sudo ticket can't be refreshed at exit, the interface outlives the
  app (an error with the `ip link delete` command is logged).

## How to verify

1. `sudo dnf install wireguard-tools` (or apt).
2. Import a working `.conf` (Import… or drag-drop), confirm a 0600 copy under
   `~/.config/openvpn-manager/profiles/`.
3. Connect → log shows `wg-quick up wgm-…`, badge Connected, VPN IP = config
   `Address`, bytes increase. `ip link show wgm-…` exists, and
   `sudo ls -l /etc/wireguard/` shows `wgm-….conf` (0600).
4. Disconnect → `wg-quick down`, interface and `/etc/wireguard/wgm-….conf`
   gone.
5. Uncheck "Route all internet traffic", connect → log notes ignored default
   routes; `ip route get 1.1.1.1` uses the local gateway.
