# Management read stalls and TLS handshake failure reporting

- **Date:** 2026-10-21
- **Branch:** `fix/mgmt-reads-handshake-timeout`
- **Status:** done

## Context

The `ha.computing-technologies.com` profile would not connect. The log stopped at
`VERIFY OK: depth=0, CN=server` and the app showed nothing else until the user
pressed Disconnect. Two problems came out of the investigation:

1. **The server rejected the client.** Running plain `openvpn` unprivileged
   (`--dev null --ifconfig-noexec --route-noexec`) with the same profile stopped
   at the same line. It then failed with `TLS key negotiation failed`. The client
   cert (`CN=lg-fedora`), the key and the CA were all valid and consistent
   (`openssl verify` OK, pubkey match, dates fine). So the server was dropping
   the handshake after receiving the client cert: revoked cert, expired CRL or
   regenerated PKI. The user then re-imported a profile with a new client cert
   (`CN=lg`, issued 2026-10-21 20:55 UTC), and that profile connects.
2. **The app had two weaknesses that hid the problem:**
   - Every management command waited out the 5 s socket timeout. The old
     `_read_until_prompt` waited for a `>` that OpenVPN never sends, because the
     management protocol has no prompt. This caused the 5 s gap between
     `hold release` and `bytecount 2`, and roughly 10 s per poll iteration.
   - A stalled TLS handshake was never reported. OpenVPN only gives up when its
     `hand-window` expires (60 s by default) and then retries forever, so the
     UI just sat there.

## Decisions

- **Chosen: read replies until a protocol terminator.** A reply ends at a
  `SUCCESS:` or `ERROR:` line, or at `END` for multi-line replies. Interleaved
  `>` notifications are kept in the returned text so the existing parsers still
  see `>BYTECOUNT:` lines. Leftover bytes after a terminator are buffered for
  the next reply.
- **Rejected: lowering the socket timeout.** It would only shrink the stall and
  would risk cutting slow replies short.
- **Chosen: drop the bare `bytecount` and second `state` commands in the poll
  loop.** The bare `bytecount` (no argument) always returned `ERROR:` and only
  "worked" by draining queued `>BYTECOUNT:` notifications. Counts are now parsed
  from the notifications that arrive with the `state` reply. When none arrive,
  the totals are kept instead of being reset to 0. The second `state` call
  duplicated the first.
- **Chosen: watch OpenVPN's stdout for handshake progress (`HandshakeMonitor`).**
  It tracks `TLS: Initial packet from`, `VERIFY OK: depth=0`,
  `Peer Connection Initiated` and `TLS key negotiation failed` / `TLS handshake failed`.
  - If the server has been quiet for 10 s after its cert verified, the app logs
    a hint.
  - On a TLS failure **before the first CONNECTED**, the app stops the session
    and shows an error that matches where the handshake stopped:
    - rejected client cert, if the server cert had verified
    - incomplete handshake, if the server replied but its cert never verified
    - no reply, if nothing came back (unreachable host or port, or a
      tls-auth/tls-crypt mismatch)
- **Rejected: stopping on TLS failures after the tunnel was once up.** Transient
  reconnect failures are normal, so OpenVPN is left to retry those.
- **Rejected: forcing a shorter `--hand-window`.** That would override the
  profile's own configuration.
- **Chosen: read the VPN IP from the `CONNECTED` state line (follow-up in the
  same branch).** The old `_parse_virtual_ip` searched for `ifconfig`/`ROUTE`
  or `PUSH_REPLY`, none of which appear in a `state` reply, so "VPN IP" was
  always empty. State lines are
  `time,state,desc,local-tun-ipv4,remote-addr,remote-port,local-addr,local-port,local-tun-ipv6`.
  The parser takes field 4 (IPv4), or field 9 (IPv6) when there is no IPv4
  address, from the newest `CONNECTED` line. The now-unused `re` import was
  dropped.

## What changed

- `openvpn_manager/backend/vpn_process.py`:
  - `ManagementClient` now uses `_read_line`, `_read_greeting` and
    `_read_response` in place of `_read_until_prompt`.
  - New `HandshakeMonitor` class and `HANDSHAKE_STALL_SEC` constant.
  - `VpnWorker` feeds stdout lines to the monitor and checks it in the poll
    loop.
  - `_parse_bytecount` returns `None` when no counts are present.
  - `_parse_virtual_ip` now reads the tunnel address from the `CONNECTED`
    state line.
- `tests/unit/test_vpn_process.py`: socketpair tests for reply framing (fast
  return, `END` blocks, buffered leftovers, EOF), bytecount parsing,
  handshake phase, stall and message tests, and VPN IP parsing (IPv4, IPv6
  fallback, empty before CONNECTED).

## Evidence

- `pytest tests/unit`: 43 passed.
- Live run after the VPN IP fix: the `stats_updated` signal reported
  `CONNECTED '10.8.0.7'` at 2.6 s, with byte counts of `4857 / 4678` from 4.6 s
  onward.
- End-to-end run of the real `VpnWorker` (needs_elevation patched off, extra
  args `--dev null --ifconfig-noexec --route-noexec --hand-window 15`) against
  the live server:
  - Re-imported profile: `hold release`, `bytecount 2` and the first `state` all
    completed within 0.5 s of launch. Polling ran every 2 s and the session
    reached `State: CONNECTED` at 2.5 s. Before the fix there was a 5 s gap
    after each command.
  - Same profile pointed at an unused port (1197): OpenVPN logged
    `TLS key negotiation failed` at 15.6 s, and the worker emitted the "no reply
    from the server" error at 16.6 s and stopped.

## Corrections

- The first assumption was that the app was at fault. A plain `openvpn` run
  showed the identical stall, so the connection failure itself was on the
  server side. The app only hid it.

## Left undone

- The stall hint covers only the "server went quiet after its cert" case. That
  is the only phase where the cause is specific enough to suggest one.
- Playwright E2E tests were not run (they need npm). The HTTP harness only
  builds commands and is unaffected.

## How to verify

1. Run `.venv/bin/pytest tests/unit -q`.
2. Connect a working profile and check that the log shows `hold release`,
   `bytecount 2` and `state` without multi-second gaps.
3. Edit a copy of a profile to point at a closed UDP port and connect. After the
   handshake window, the app should show "TLS handshake failed: no reply from
   the server…" and stop.
