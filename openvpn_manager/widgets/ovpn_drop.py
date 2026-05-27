"""Shared drag-and-drop helpers for .ovpn profile files."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal, QMimeData
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDragMoveEvent, QDropEvent
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from openvpn_manager.widgets.theme import enable_styled_background

OVPN_SUFFIX = ".ovpn"


def paths_from_mime(mime: QMimeData) -> list[Path]:
    """Return existing .ovpn file paths from a drag-and-drop mime payload."""
    if not mime.hasUrls():
        return []
    paths: list[Path] = []
    seen: set[Path] = set()
    for url in mime.urls():
        local = url.toLocalFile()
        if not local:
            continue
        path = Path(local)
        if path.suffix.lower() != OVPN_SUFFIX or not path.is_file():
            continue
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            paths.append(resolved)
    return paths


def mime_has_ovpn(mime: QMimeData) -> bool:
    return bool(paths_from_mime(mime))


class OvpnDropMixin:
    """Mixin: accept .ovpn drops on any QWidget."""

    def _ovpn_drag_enter(self, event: QDragEnterEvent) -> None:
        if mime_has_ovpn(event.mimeData()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def _ovpn_drag_move(self, event: QDragMoveEvent) -> None:
        if mime_has_ovpn(event.mimeData()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def _ovpn_drop_paths(self, event: QDropEvent) -> list[Path]:
        paths = paths_from_mime(event.mimeData())
        if paths:
            event.acceptProposedAction()
        else:
            event.ignore()
        return paths


class DropOverlay(QWidget):
    """Full-window overlay shown while dragging .ovpn files."""

    files_dropped = Signal(list)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        enable_styled_background(self)
        self.setObjectName("dropOverlay")
        self.setAcceptDrops(True)
        self.hide()

        layout = QVBoxLayout(self)
        self._hint = QLabel("Drop .ovpn file(s) to import")
        self._hint.setObjectName("dropOverlayHint")
        self._hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._hint)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if mime_has_ovpn(event.mimeData()):
            self.show()
            self.raise_()
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        if mime_has_ovpn(event.mimeData()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self.hide()
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        paths = paths_from_mime(event.mimeData())
        self.hide()
        if paths:
            event.acceptProposedAction()
            self.files_dropped.emit(paths)
        else:
            event.ignore()
