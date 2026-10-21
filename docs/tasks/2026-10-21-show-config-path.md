# Show imported profile file location

- **Date:** 2026-10-21
- **Branch:** `feat/show-config-path`
- **Status:** done (not committed)

## Context

Users could not see where an imported `.ovpn` lives. Import copies the file to
`~/.config/openvpn-manager/profiles/<uuid>.ovpn` (`Profile.config_path`), and the
original source path was discarded.

## Decisions

- Show **both** the stored copy (what OpenVPN actually runs) and the original
  source file, since "imported file location" can mean either.
- Record source as new `Profile.source_path` field (default `""`). `from_dict`
  already ignores/defaults missing keys, so old `profiles.json` entries load
  unchanged and show "Unknown"; no migration needed.
- Re-import of the same connection overwrites `source_path` with the latest
  source (matches how the stored config is refreshed).
- "Show in folder" opens the **stored copy's** directory via
  `QDesktopServices.openUrl` (xdg-open). Rejected: selecting the file in a
  file manager (`org.freedesktop.FileManager1.ShowItems` over D-Bus) — more
  code, not supported by every file manager; folder only has `<uuid>.ovpn`
  files so locating it is easy given the path is shown.
- Paths are selectable labels so they can be copied; no separate "Copy path"
  button (rejected as clutter).
- Rejected: opening the `.ovpn` in a text editor — profiles may hold inline
  keys; opening/editing is a separate feature.

## What changed

- `openvpn_manager/backend/profile_store.py` — `source_path` field; set on new
  import and on in-place re-import.
- `openvpn_manager/widgets/connection_panel.py` — "Profile file" group: Stored
  at, Imported from, Show in folder button (`show_config_clicked` signal).
- `openvpn_manager/main_window.py` — `_show_config_file` opens the folder; warns
  if the file is missing or the folder cannot be opened.
- `tests/unit/test_profile_store.py` — source path recorded/updated on
  re-import; legacy entry without the field loads.

## Evidence

- `pytest tests/unit` — 31 passed.
- Offscreen render of the panel (`QT_QPA_PLATFORM=offscreen`) checked: long
  stored path wraps, button compact, cleared to "—"/disabled when no profile.

## Corrections

- First smoke run imported the main checkout's package (editable install
  resolves to `../openvpn-connect`), not the worktree. Run with
  `PYTHONPATH=<worktree>` when checking from a worktree. `python -m pytest`
  from the worktree root was unaffected (cwd first on `sys.path`).

## Left undone

- "Show in folder" not clicked in a real desktop session (offscreen only).
- Source path for profiles imported before this change stays unknown until
  re-imported.

## How to verify

1. `python -m pytest -q tests/unit`
2. Launch app, import a `.ovpn`, select it: "Profile file" shows both paths;
   "Show in folder" opens `~/.config/openvpn-manager/profiles/`.
3. Older profile (from before this change) shows "Imported from: Unknown".
