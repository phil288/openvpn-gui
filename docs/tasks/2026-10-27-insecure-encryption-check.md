# Refuse insecure OpenVPN encryption settings

- **Date:** 2026-10-27
- **Branch:** `fix/insecure-encryption-check`
- **Status:** done

## Context

Question: "are transfers encrypted with OpenVPN?" Yes by default (TLS control
channel + AEAD data channel), but a profile can weaken or disable that
(`cipher none`, `BF-CBC`, `auth none`, static keys, TLS 1.0…). The app did not
check any of it: whatever the `.ovpn` or server negotiated was used silently.
Requested: when the app detects anything insecure, output an error.

## Decisions

- **Chosen: two layers.**
  1. `audit_config()` runs before OpenVPN launches (no sudo, no network). An
     insecure profile raises → existing `error` signal → "Connection error"
     dialog listing every problem. The tunnel is never started.
  2. `SecurityMonitor` reads OpenVPN's log during the session. The config alone
     can't show what the server actually negotiates (e.g. a fallback cipher), so
     an insecure negotiation emits an error and tears the tunnel down. It is
     checked before `connected` is emitted, so such a tunnel is never shown as up.
- **Flagged as insecure:** cipher `none` / 64-bit block ciphers (BF, DES, 3DES,
  CAST5, IDEA, RC2) in `cipher`, `data-ciphers`, `ncp-ciphers`,
  `data-ciphers-fallback`; `auth none|MD4|MD5`; `tls-cipher` allowing
  NULL/EXPORT/RC4/DES/MD5 suites; `tls-version-min|max 1.0|1.1`; static-key
  `secret` mode (no TLS, no forward secrecy); a client config with no server
  identity check (`remote-cert-tls`, `verify-x509-name`, `tls-verify`,
  `peer-fingerprint`, `ns-cert-type`), which allows MITM by another client of the same CA.
- **On success** the negotiated cipher is logged ("Data channel encryption: AES-256-GCM").
- **Rejected: warning only / per-profile override.** The request was an error.
  An override checkbox would bring back the silent-insecure path. Add one only
  if a real server can't be fixed.
- **Rejected: auditing at import time.** It would miss configs imported before
  this change, and it can't see what the server negotiates. Connect time covers both.
- WireGuard untouched: its crypto is fixed (Noise, ChaCha20-Poly1305), with nothing to configure weakly.

## What changed

- `openvpn_manager/backend/openvpn_security.py` (new): `audit_config`, `SecurityMonitor`.
- `openvpn_manager/backend/vpn_process.py`: `VpnWorker._check_config_security()`
  before building the command, monitor fed from the output reader, checks in the poll loop.
- `tests/unit/test_openvpn_security.py` (new).

## Evidence

- `.venv/bin/pytest tests/unit -q` → 112 passed.
- Audited the locally imported OpenVPN profile with `audit_config` → OK, so the
  existing connection is not blocked.

## Corrections

None.

## Left undone

- Runtime log patterns follow OpenVPN 2.4–2.6 message texts. They are tested against those
  strings only, not against a live server negotiating a weak cipher.
- `config` includes of other files are not followed by the static audit (the
  runtime monitor still sees the result).
- DNS-leak and split-tunnel exposure are by design and are not treated as "insecure encryption".

## How to verify

1. `.venv/bin/pytest tests/unit/test_openvpn_security.py -v`
2. Copy a working profile, add `cipher BF-CBC` (or remove `remote-cert-tls server`),
   import it, then connect: a "Connection error" dialog lists the problem and nothing launches.
3. Connect a good profile: the log shows `Data channel encryption: <cipher>`.
