# Message box icon gap

- **Date:** 2026-10-24
- **Branch:** `fix/popups`
- **Status:** done

## Context

Every popup (error, warning, yes/no, kill-all) showed the icon on the far left
and the message text pushed ~300px to the right, leaving a wide empty gap
(seen on the WireGuard "Connection error" box).

Cause: the global `resources/style.qss` rule `QMessageBox QLabel { min-width: 300px; }`
matches *every* label inside a `QMessageBox`, including the icon label
`qt_msgboxex_icon_label`. The per-box stylesheet in `widgets/message_boxes.py`
already scoped `min-width` to `#qt_msgbox_label`, but Qt merges the app and
widget sheets, so the unscoped app rule still applied to the icon label.

## Decisions

- **Chosen:** scope the global `min-width` to `QMessageBox QLabel#qt_msgbox_label`,
  matching the per-box style. One rule change fixes all popups since all go
  through the same stylesheet.
- **Rejected:** forcing `setWordWrap(True)` on the text label in `_prepare` —
  `QMessageBox::updateSize()` resets word wrap on show, so it had no effect.
- **Rejected:** removing the duplicate QMessageBox rules from one of the two
  stylesheets — not needed for the fix; kept the diff minimal.

## What changed

- `openvpn_manager/resources/style.qss`: `min-width: 300px` moved from
  `QMessageBox QLabel` to `QMessageBox QLabel#qt_msgbox_label`.

## Evidence

Rendered the "Connection error" critical box offscreen with the app stylesheet
and printed label geometry:

| Label | Before (x, w) | After (x, w) |
|-------|---------------|--------------|
| `qt_msgboxex_icon_label` | 11, **300** | 11, 48 |
| `qt_msgbox_label` | **330**, 300 | 78, 300 |

`pytest`: 55 passed.

## Corrections

None.

## Left undone

- Not checked on a live X11/Wayland session; the offscreen platform does not
  apply the box's size hint, so the offscreen grab clips text on the right.
  That clipping is an offscreen artifact, not a real-display bug.

## How to verify

Trigger any popup (e.g. connect a profile that fails, or "Kill all instances")
— the text should sit right next to the icon.
