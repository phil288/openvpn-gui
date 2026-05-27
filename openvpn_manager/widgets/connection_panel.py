"""Right panel: connection controls, stats, and log."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from openvpn_manager.backend.profile_store import Profile
from openvpn_manager.backend.vpn_process import ConnectionStats
from openvpn_manager.widgets.theme import enable_styled_background


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _format_duration(seconds: float) -> str:
    s = int(seconds)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


class ConnectionPanel(QWidget):
    """Detail view for selected profile."""

    connect_clicked = Signal()
    disconnect_clicked = Signal()
    import_clicked = Signal()
    delete_clicked = Signal()
    edit_credentials_clicked = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        enable_styled_background(self)
        self._profile: Profile | None = None
        self._connected = False
        self._connected_since: float | None = None

        layout = QVBoxLayout(self)

        header = QHBoxLayout()
        self._title = QLabel("Select a profile")
        self._title.setObjectName("profileTitle")
        self._title.setWordWrap(True)
        header.addWidget(self._title, 1)
        self._status_badge = QLabel("Disconnected")
        self._status_badge.setObjectName("statusBadge")
        header.addWidget(self._status_badge)
        layout.addLayout(header)

        self._subtitle = QLabel("")
        self._subtitle.setObjectName("profileSubtitle")
        layout.addWidget(self._subtitle)

        btn_row = QHBoxLayout()
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.setObjectName("connectButton")
        self._connect_btn.clicked.connect(self._on_connect_btn)
        self._connect_btn.setEnabled(False)
        btn_row.addWidget(self._connect_btn)

        self._cred_btn = QPushButton("Credentials…")
        self._cred_btn.clicked.connect(self.edit_credentials_clicked.emit)
        self._cred_btn.setEnabled(False)
        btn_row.addWidget(self._cred_btn)

        import_btn = QPushButton("Import…")
        import_btn.clicked.connect(self.import_clicked.emit)
        btn_row.addWidget(import_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self.delete_clicked.emit)
        delete_btn.setEnabled(False)
        self._delete_btn = delete_btn
        btn_row.addWidget(delete_btn)
        layout.addLayout(btn_row)

        stats_box = QGroupBox("Connection")
        stats_form = QFormLayout(stats_box)
        self._vpn_ip = QLabel("—")
        self._bytes_in = QLabel("—")
        self._bytes_out = QLabel("—")
        self._duration = QLabel("—")
        stats_form.addRow("VPN IP", self._vpn_ip)
        stats_form.addRow("Downloaded", self._bytes_in)
        stats_form.addRow("Uploaded", self._bytes_out)
        stats_form.addRow("Duration", self._duration)
        layout.addWidget(stats_box)

        log_box = QGroupBox("Log")
        log_layout = QVBoxLayout(log_box)
        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumBlockCount(500)
        log_layout.addWidget(self._log)
        layout.addWidget(log_box, 1)

    def _on_connect_btn(self) -> None:
        if self._connected:
            self.disconnect_clicked.emit()
        else:
            self.connect_clicked.emit()

    def set_profile(self, profile: Profile | None, is_active: bool = False) -> None:
        self._profile = profile
        if not profile:
            self._title.setText("Select a profile")
            self._subtitle.setText(
                "Drag and drop a .ovpn file here, or click Import…"
            )
            self._connect_btn.setEnabled(False)
            self._cred_btn.setEnabled(False)
            self._delete_btn.setEnabled(False)
            return

        self._title.setText(profile.name)
        server = profile.server or "—"
        self._subtitle.setText(
            f"{server}:{profile.port} ({profile.protocol.upper()})"
        )
        self._connect_btn.setEnabled(True)
        self._cred_btn.setEnabled(profile.needs_auth)
        self._delete_btn.setEnabled(not is_active)
        self._set_connected_ui(is_active)

    def _set_connected_ui(self, connected: bool) -> None:
        self._connected = connected
        if connected:
            self._connect_btn.setText("Disconnect")
            self._status_badge.setText("Connected")
            self._status_badge.setProperty("status", "connected")
        else:
            self._connect_btn.setText("Connect")
            self._status_badge.setText("Disconnected")
            self._status_badge.setProperty("status", "disconnected")
        self._status_badge.style().unpolish(self._status_badge)
        self._status_badge.style().polish(self._status_badge)

    def set_connection_state(
        self, connected: bool, state_label: str | None = None
    ) -> None:
        self._set_connected_ui(connected)
        if state_label and not connected:
            self._status_badge.setText(state_label)

    def update_stats(self, stats: ConnectionStats) -> None:
        import time

        self._vpn_ip.setText(stats.virtual_ip or "—")
        self._bytes_in.setText(_format_bytes(stats.bytes_in))
        self._bytes_out.setText(_format_bytes(stats.bytes_out))
        if stats.connected_since:
            elapsed = time.monotonic() - stats.connected_since
            self._duration.setText(_format_duration(elapsed))
        elif stats.state == "CONNECTED":
            self._duration.setText("—")
        else:
            self._duration.setText("—")

    def append_log(self, line: str) -> None:
        self._log.appendPlainText(line)

    def clear_log(self) -> None:
        self._log.clear()

    def reset_stats(self) -> None:
        self._vpn_ip.setText("—")
        self._bytes_in.setText("—")
        self._bytes_out.setText("—")
        self._duration.setText("—")
