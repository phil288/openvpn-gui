"""Import .ovpn / WireGuard .conf profile dialog with drag-and-drop."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from openvpn_manager.backend.profile_store import (
    detect_config_suffix,
    parse_ovpn_config,
)
from openvpn_manager.backend.wireguard_config import (
    WIREGUARD_SUFFIX,
    parse_wireguard_config,
)
from openvpn_manager.widgets.ovpn_drop import OvpnDropMixin
from openvpn_manager.widgets.theme import enable_styled_background


class DropZone(OvpnDropMixin, QWidget):
    """Area accepting profile file drops."""

    file_dropped = Signal(Path)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        enable_styled_background(self)
        self.setAcceptDrops(True)
        self.setMinimumHeight(120)
        self.setObjectName("dropZone")
        layout = QVBoxLayout(self)
        self._label = QLabel(
            "Drag and drop a <b>.ovpn</b> or WireGuard <b>.conf</b> file here\n"
            "or use Browse below"
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
    """Import a new OpenVPN or WireGuard profile."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        enable_styled_background(self)
        self.setWindowTitle("Import Profile")
        self.setMinimumWidth(480)
        self._source_path: Path | None = None
        self._auto_name = ""  # last name we filled in; user edits win

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

        layout.addWidget(QLabel("Or paste a WireGuard or OpenVPN config:"))
        self._text_edit = QPlainTextEdit()
        self._text_edit.setPlaceholderText(
            "[Interface]\nPrivateKey = …\n\n— or —\n\nclient\nremote vpn.example.com 1194 udp\n…"
        )
        self._text_edit.setFont(
            QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        )
        self._text_edit.setMinimumHeight(140)
        self._text_edit.textChanged.connect(self._on_text_changed)
        layout.addWidget(self._text_edit)
        self._text_hint = QLabel("")
        self._text_hint.setObjectName("profileSubtitle")
        layout.addWidget(self._text_hint)

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
            "Select VPN profile",
            str(Path.home()),
            "VPN profiles (*.ovpn *.conf);;OpenVPN profiles (*.ovpn);;"
            "WireGuard configs (*.conf)",
        )
        if path:
            self._set_file(Path(path))

    def _set_file(self, path: Path) -> None:
        self._source_path = path
        self._path_label.setText(str(path))
        if self._text_edit.toPlainText():
            self._text_edit.clear()  # a chosen file replaces pasted text
        self._ok_button.setEnabled(True)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix.lower() == WIREGUARD_SUFFIX:
                meta = parse_wireguard_config(content)
            else:
                meta = parse_ovpn_config(content)
            self._suggest_name(meta.get("name") or path.stem)
        except OSError:
            pass

    def _on_text_changed(self) -> None:
        text = self._text_edit.toPlainText()
        if not text.strip():
            self._text_hint.setText("")
            self._ok_button.setEnabled(self._source_path is not None)
            return
        # Pasted text takes over from any chosen file.
        self._source_path = None
        self._path_label.setText("No file selected")
        suffix = detect_config_suffix(text)
        if suffix == WIREGUARD_SUFFIX:
            meta = parse_wireguard_config(text)
            self._text_hint.setText("Detected: WireGuard config")
        elif suffix:
            meta = parse_ovpn_config(text)
            self._text_hint.setText("Detected: OpenVPN config")
        else:
            meta = None
            self._text_hint.setText(
                "Not recognised yet — need [Interface] with PrivateKey "
                "(WireGuard) or a remote line (OpenVPN)"
            )
        self._ok_button.setEnabled(meta is not None)
        if meta:
            self._suggest_name(meta.get("name") or "")

    def _suggest_name(self, name: str) -> None:
        if self._name_edit.text() in ("", self._auto_name):
            self._name_edit.setText(name)
            self._auto_name = name

    def source_path(self) -> Path | None:
        return self._source_path

    def pasted_text(self) -> str | None:
        text = self._text_edit.toPlainText()
        return text if text.strip() else None

    def display_name(self) -> str | None:
        text = self._name_edit.text().strip()
        return text or None
