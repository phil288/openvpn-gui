"""Import .ovpn profile dialog with drag-and-drop."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from openvpn_manager.backend.profile_store import parse_ovpn_config
from openvpn_manager.widgets.ovpn_drop import OvpnDropMixin
from openvpn_manager.widgets.theme import enable_styled_background


class DropZone(OvpnDropMixin, QWidget):
    """Area accepting .ovpn file drops."""

    file_dropped = Signal(Path)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        enable_styled_background(self)
        self.setAcceptDrops(True)
        self.setMinimumHeight(120)
        self.setObjectName("dropZone")
        layout = QVBoxLayout(self)
        self._label = QLabel(
            "Drag and drop a <b>.ovpn</b> file here\nor use Browse below"
        )
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._label)

    def dragEnterEvent(self, event) -> None:
        self._ovpn_drag_enter(event)

    def dragMoveEvent(self, event) -> None:
        self._ovpn_drag_move(event)

    def dropEvent(self, event) -> None:
        paths = self._ovpn_drop_paths(event)
        if paths:
            self.file_dropped.emit(paths[0])


class ImportDialog(QDialog):
    """Import a new OpenVPN profile."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        enable_styled_background(self)
        self.setWindowTitle("Import Profile")
        self.setMinimumWidth(480)
        self._source_path: Path | None = None

        layout = QVBoxLayout(self)
        self._drop = DropZone()
        self._drop.file_dropped.connect(self._set_file)
        layout.addWidget(self._drop)

        browse_row = QHBoxLayout()
        self._path_label = QLabel("No file selected")
        self._path_label.setWordWrap(True)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse)
        browse_row.addWidget(self._path_label, 1)
        browse_row.addWidget(browse_btn)
        layout.addLayout(browse_row)

        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Display name"))
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("Auto-detected from profile")
        name_row.addWidget(self._name_edit)
        layout.addLayout(name_row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select OpenVPN profile",
            str(Path.home()),
            "OpenVPN profiles (*.ovpn)",
        )
        if path:
            self._set_file(Path(path))

    def _set_file(self, path: Path) -> None:
        self._source_path = path
        self._path_label.setText(str(path))
        self._ok_button.setEnabled(True)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            meta = parse_ovpn_config(content)
            if not self._name_edit.text():
                self._name_edit.setText(meta.get("name") or path.stem)
        except OSError:
            pass

    def source_path(self) -> Path | None:
        return self._source_path

    def display_name(self) -> str | None:
        text = self._name_edit.text().strip()
        return text or None
