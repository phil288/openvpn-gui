# Export connection settings

- **Date:** 2026-10-21
- **Branch:** `feat/export-connection-settings`
- **Status:** done (not committed)

## Context

Profiles could be imported but not exported back out — no way to back up a
profile or move it to another machine except digging the `<uuid>.ovpn` file
out of `~/.config/openvpn-manager/profiles/` and losing the display name.

## Decisions

- **Export the selected profile as a single `.ovpn` file.** Re-importable by
  this app and usable by any other OpenVPN client. Rejected: a custom JSON/zip
  bundle of all profiles — not portable, and needs a matching bulk-import path.
- **Embed the display name as a `# ovpn-profile: <name>` header.** Any
  existing header is replaced, not duplicated. It is a comment, so other
  clients ignore it.
- **Never export saved VPN credentials.** They live in the system keyring;
  writing them to a plaintext file would undo that. Tooltip on the button says
  credentials are not included.
- **Create the file 0600** (and `fchmod` an existing file being overwritten):
  configs often embed private keys (`<key>`, `<tls-auth>`, `<tls-crypt>`).
- **Append `.ovpn` if the chosen name lacks it**, so the file re-imports
  (import rejects other suffixes).
- **No parent-directory creation.** The save dialog always returns an existing
  directory; silently creating directories would mask typos.

## What changed

- `openvpn_manager/backend/profile_store.py`
  - `export_profile(profile_id, dest) -> Path` — writes the config with the
    name header; raises `KeyError` (unknown profile) / `FileNotFoundError`
    (stored config missing) / `OSError`.
  - `suggested_export_filename(profile)` — filesystem-safe default name.
  - `parse_ovpn_config` now honours the `# ovpn-profile:` header (see
    Corrections). Header prefix moved to `_NAME_HEADER`.
- `openvpn_manager/widgets/connection_panel.py` — **Export…** button +
  `export_clicked` signal, enabled only while a profile is selected.
- `openvpn_manager/main_window.py` — `_export_profile`: save dialog defaulting
  to `~/<name>.ovpn`, error dialog on failure, log line on success.
- `tests/unit/test_profile_store.py` — 6 tests: header parsing, export
  content/permissions/suffix, tightening a pre-existing file, export→delete→
  re-import restores name, unknown id, filename sanitising.

## Evidence

- `pytest tests/unit` → 35 passed.
- Offscreen Qt smoke check: Export button disabled with no profile, enabled
  after `set_profile`; `main_window` imports cleanly.
- Not run: Playwright E2E, manual click-through in the real app.

## Corrections

- `parse_ovpn_config` already had a `# ovpn-profile:` branch, but it was dead
  code: comment lines were skipped *before* that check, so the header never
  set the name. Reordered so the header is read first. Side effect: an
  imported `.ovpn` that already carries this header now gets that name instead
  of the server hostname (intended behaviour of the original code).

## Left undone

- Bulk "export all profiles".
- Export entry in the tray menu.
- Carrying `allow_scripts` consent across machines — on re-import, risky
  directives prompt again, which is the safe default.

## How to verify

```bash
.venv/bin/pytest tests/unit -v -k "export or name_header"
```

Manual: select a profile → **Export…** → save → check `ls -l` shows
`-rw-------`, first line is `# ovpn-profile: <name>`; delete the profile and
import the file — name comes back, credentials must be re-entered.
