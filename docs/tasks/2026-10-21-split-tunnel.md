# Split tunnel by default — keep internet while connected

- **Date:** 2026-10-21
- **Branch:** `feat/split-tunnel`

## Context
User report: "when I connect, I lose the internet connection on my PC".
The only profile (`ha.computing-technologies.com:1196/udp`) has no
`redirect-gateway` of its own, but `ignore-unknown-option block-outside-dns` +
`auth SHA512` are hallmarks of the angristan/openvpn-install server script,
which by default pushes `redirect-gateway def1 bypass-dhcp` (plus
`route-ipv6 2000::/3` / `redirect-gateway ipv6` when IPv6 is on) and DNS. So all
host traffic is routed into the tunnel; when the server doesn't forward/NAT it,
the host loses the internet. The pushed DNS is also never applied, because the
app forces `--script-security 1` (no `update-resolv-conf` /
`update-systemd-resolved` hook).

## Decisions (made and rejected)
- **Chosen (user's pick):** per-profile split tunnel, **on by default**. Unless
  the profile opts into full tunnelling, the worker passes
  `--pull-filter ignore <opt>` for every push option that would capture all
  traffic (`FULL_TUNNEL_PUSH_OPTIONS` in `vpn_process.py`): `redirect-gateway`,
  `block-ipv6`, the `0.0.0.0/0`, `def1` halves, `::/0`, `::/1`, `8000::/1` and
  `2000::/3` routes. The server's explicit LAN routes still apply.
- New `Profile.route_all_traffic` (default `False`) + checkbox "Route all
  internet traffic through the VPN" in the connection panel. Disabled while a
  session for that profile runs; takes effect on next connect. Re-import keeps
  the choice.
- Rejected: keep full tunnel and apply pushed DNS via systemd-resolved — would
  not fix a server that does not NAT, and needs script execution as root.
- Rejected: stripping `redirect-gateway` written in the user's own `.ovpn`.
  `pull-filter` only affects pushed options; a local directive is intentional.
- Not a guaranteed match: user-set `pull-filter accept …` in the config wins
  (first match wins and config options come before CLI options). Acceptable.

## What changed
- `openvpn_manager/backend/vpn_process.py`: `FULL_TUNNEL_PUSH_OPTIONS`,
  `route_all_traffic` on `VpnWorker` / `VpnController.connect_profile`,
  pull-filters + a log line in `_build_command`; pending-connect tuple carries
  the flag.
- `openvpn_manager/backend/profile_store.py`: `route_all_traffic` field,
  `set_route_all_traffic()`.
- `openvpn_manager/widgets/connection_panel.py`: checkbox + `route_all_toggled`.
- `openvpn_manager/main_window.py`: persist toggle, pass flag on connect.
- Tests: `test_vpn_process.py` (filters present by default, absent when opted
  in, placed after `--config`), `test_profile_store.py` (default, persist,
  survives re-import).

## Evidence / measurements
- Could not connect from the agent sandbox (sudo blocked by "no new
  privileges"; connecting would also drop the agent's own network), so the
  pushed options were inferred from the server script, not captured.
- `openvpn` 2.6 parses the added `--pull-filter ignore "route 0.0.0.0 0.0.0.0"`
  etc. without an options error.
- Unit suite: 33 passed. Offscreen Qt check: checkbox reflects profile,
  emits on click, disabled while active.

## Corrections along the way
- First edit anchored on `HANDSHAKE_STALL_SEC`, which exists only on the
  unmerged `fix/mgmt-reads-handshake-timeout` branch, not `main`; moved anchor.
  Expect a trivial merge with that branch in `vpn_process.py`.

## Deliberately left undone
- Applying server-pushed DNS (systemd-resolved) for full-tunnel users.
- Server-side NAT/forwarding check.

## How to verify
1. `pytest tests/unit`.
2. Connect the profile with the checkbox off; log shows "Split tunnel: …".
   `ip route` keeps `default via 192.168.0.1`; no `0.0.0.0/1` / `128.0.0.0/1`
   via `tun0`; `curl -I https://example.com` works; the home LAN is reachable
   if the server pushes a route for it.
3. Tick the checkbox, reconnect: the server's default route is applied again.
