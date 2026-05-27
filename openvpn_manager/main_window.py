"""Main application window."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDragMoveEvent, QDropEvent, QResizeEvent
from PySide6.QtWidgets import QHBoxLayout, QSplitter, QWidget

from openvpn_manager.backend import credentials as cred_store
from openvpn_manager.backend.profile_store import (
    Profile,
    delete_profile,
    get_profile,
    import_profile,
    list_profiles,
    profile_needs_auth,
    touch_last_used,
)
from openvpn_manager.backend.vpn_process import ConnectionStats, VpnController
from openvpn_manager.widgets.connection_panel import ConnectionPanel
from openvpn_manager.widgets.credentials_dialog import CredentialsDialog
from openvpn_manager.widgets.import_dialog import ImportDialog
from openvpn_manager.widgets.message_boxes import critical, question_yes_no, warning
from openvpn_manager.widgets.ovpn_drop import DropOverlay, OvpnDropMixin, paths_from_mime
from openvpn_manager.widgets.profile_list import ProfileListWidget


class MainWindow(OvpnDropMixin, QWidget):
    """Primary window with profile list and connection panel."""

    profiles_changed = Signal()

    def __init__(self, vpn: VpnController, parent=None) -> None:
        super().__init__(parent)
        self._vpn = vpn
        self._selected_id: str | None = None
        self.setWindowTitle("OpenVPN Manager")
        self.setMinimumSize(820, 520)
        self.setAcceptDrops(True)

        layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._profile_list = ProfileListWidget()
        self._profile_list.profile_selected.connect(self._on_profile_selected)
        self._profile_list.profile_activated.connect(
            lambda pid: self._connect_profile(pid)
        )
        splitter.addWidget(self._profile_list)

        self._panel = ConnectionPanel()
        self._panel.connect_clicked.connect(self._on_connect_clicked)
        self._panel.disconnect_clicked.connect(self._on_disconnect_clicked)
        self._panel.import_clicked.connect(self._import_profile)
        self._panel.delete_clicked.connect(self._delete_profile)
        self._panel.edit_credentials_clicked.connect(self._edit_credentials)
        splitter.addWidget(self._panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([280, 540])

        layout.addWidget(splitter)

        self._drop_overlay = DropOverlay(self)
        self._drop_overlay.files_dropped.connect(self._import_dropped_files)
        self._sync_drop_overlay_geometry()

        self._vpn.status_changed.connect(self._on_status)
        self._vpn.stats_updated.connect(self._on_stats)
        self._vpn.log_line.connect(self._panel.append_log)
        self._vpn.connected.connect(self._on_connected)
        self._vpn.disconnected.connect(self._on_disconnected)
        self._vpn.error.connect(self._on_error)

        self.refresh_profiles()

    def refresh_profiles(self) -> None:
        active = self._vpn.active_profile_id
        profiles = list_profiles()
        self._profile_list.set_profiles(profiles, active)
        if self._selected_id:
            self._profile_list.select_profile(self._selected_id)
            p = get_profile(self._selected_id)
            self._panel.set_profile(p, self._selected_id == active)
        elif profiles:
            self._profile_list.select_profile(profiles[0].id)
        self.profiles_changed.emit()

    def _on_profile_selected(self, profile_id: str) -> None:
        self._selected_id = profile_id
        p = get_profile(profile_id)
        active = self._vpn.active_profile_id == profile_id
        self._panel.set_profile(p, active)
        if active:
            self._panel.set_connection_state(True)

    def _on_connect_clicked(self) -> None:
        if self._selected_id:
            self._connect_profile(self._selected_id)

    def _on_disconnect_clicked(self) -> None:
        if self._vpn.is_connected:
            self._panel.set_connection_state(False, "Disconnecting…")
            self._panel.append_log("Disconnecting…")
        self._vpn.disconnect()

    def _connect_profile(self, profile_id: str) -> None:
        profile = get_profile(profile_id)
        if not profile:
            return

        username, password = "", ""
        needs = profile.needs_auth or profile_needs_auth(Path(profile.config_path))
        if needs:
            stored = cred_store.load_credentials(profile_id)
            if stored:
                username, password = stored
            else:
                dlg = CredentialsDialog(profile.name, parent=self)
                if dlg.exec() != CredentialsDialog.DialogCode.Accepted:
                    return
                username, password = dlg.username(), dlg.password()
                if dlg.remember():
                    cred_store.save_credentials(profile_id, username, password)

        self._panel.clear_log()
        self._panel.reset_stats()
        self._panel.append_log(f"Connecting to {profile.name}…")
        self._panel.set_connection_state(False, "Connecting…")
        self._vpn.connect_profile(
            profile_id,
            Path(profile.config_path),
            username,
            password,
        )
        self._selected_id = profile_id
        touch_last_used(profile_id)

    def _sync_drop_overlay_geometry(self) -> None:
        self._drop_overlay.setGeometry(self.rect())

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._sync_drop_overlay_geometry()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if paths_from_mime(event.mimeData()):
            self._drop_overlay.show()
            self._drop_overlay.raise_()
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        self._ovpn_drag_move(event)

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self._drop_overlay.hide()
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        paths = self._ovpn_drop_paths(event)
        self._drop_overlay.hide()
        if paths:
            self._import_dropped_files(paths)

    def open_ovpn_files(self, paths: list[Path]) -> None:
        """Import profiles from file paths (CLI or second instance)."""
        ovpn = [p for p in paths if p.suffix.lower() == ".ovpn" and p.is_file()]
        if ovpn:
            self.showNormal()
            self.raise_()
            self.activateWindow()
            self._import_dropped_files(ovpn)

    def _import_dropped_files(
        self,
        paths: list[Path],
        display_names: dict[Path, str | None] | None = None,
    ) -> None:
        """Import one or more .ovpn files dropped onto the window."""
        imported: list[Profile] = []
        errors: list[str] = []
        names = display_names or {}

        for path in paths:
            try:
                profile = import_profile(path, names.get(path))
                imported.append(profile)
            except (OSError, ValueError) as e:
                errors.append(f"{path.name}: {e}")

        if not imported and errors:
            critical(self, "Import failed", "\n".join(errors))
            return

        self.refresh_profiles()
        last = imported[-1]
        self._selected_id = last.id
        self._profile_list.select_profile(last.id)
        self._panel.set_profile(last, False)

        for profile in imported:
            if profile.needs_auth and not cred_store.has_credentials(profile.id):
                self._edit_credentials_for(profile)

        if len(imported) == 1:
            self._panel.append_log(f"Imported profile: {imported[0].name}")
        else:
            self._panel.append_log(
                f"Imported {len(imported)} profiles: "
                + ", ".join(p.name for p in imported)
            )

        if errors:
            warning(
                self,
                "Partial import",
                f"Imported {len(imported)} profile(s).\n\nFailed:\n"
                + "\n".join(errors),
            )

    def _import_profile(self) -> None:
        dlg = ImportDialog(self)
        if dlg.exec() != ImportDialog.DialogCode.Accepted:
            return
        path = dlg.source_path()
        if not path:
            return
        self._import_dropped_files([path], {path: dlg.display_name()})

    def _delete_profile(self) -> None:
        if not self._selected_id:
            return
        profile = get_profile(self._selected_id)
        if not profile:
            return
        if self._vpn.active_profile_id == self._selected_id:
            warning(
                self, "Cannot delete", "Disconnect before deleting this profile."
            )
            return
        if question_yes_no(
            self,
            "Delete profile",
            f"Delete profile “{profile.name}”?",
            default_no=True,
        ):
            cred_store.delete_credentials(self._selected_id)
            delete_profile(self._selected_id)
            self._selected_id = None
            self.refresh_profiles()

    def _edit_credentials(self) -> None:
        if self._selected_id:
            p = get_profile(self._selected_id)
            if p:
                self._edit_credentials_for(p)

    def _edit_credentials_for(self, profile: Profile) -> None:
        stored = cred_store.load_credentials(profile.id)
        u, p = ("", "")
        if stored:
            u, p = stored
        dlg = CredentialsDialog(profile.name, u, p, parent=self)
        if dlg.exec() == CredentialsDialog.DialogCode.Accepted:
            if dlg.remember():
                cred_store.save_credentials(
                    profile.id, dlg.username(), dlg.password()
                )
            else:
                cred_store.delete_credentials(profile.id)

    def _on_status(self, state: str) -> None:
        active = self._vpn.active_profile_id == self._selected_id
        if active:
            if state == "DISCONNECTING":
                self._panel.set_connection_state(False, "Disconnecting…")
            else:
                connected = state == "CONNECTED"
                self._panel.set_connection_state(connected, state)
            self.refresh_profiles()

    def _on_stats(self, stats: ConnectionStats) -> None:
        if self._vpn.active_profile_id == self._selected_id:
            self._panel.update_stats(stats)

    def _on_connected(self) -> None:
        self._panel.set_connection_state(True)
        self.refresh_profiles()

    def _on_disconnected(self) -> None:
        self._panel.set_connection_state(False)
        self._panel.reset_stats()
        self.refresh_profiles()

    def _on_error(self, message: str) -> None:
        self._panel.append_log(f"Error: {message}")
        self._panel.set_connection_state(False, "Error")
        warning(self, "Connection error", message)
        self.refresh_profiles()

    def connect_selected_or_first(self) -> None:
        pid = self._profile_list.current_profile_id() or self._selected_id
        if pid:
            self._connect_profile(pid)
        else:
            profiles = list_profiles()
            if profiles:
                self._connect_profile(profiles[0].id)

    def disconnect_active(self) -> None:
        self._vpn.disconnect()

    def closeEvent(self, event) -> None:
        """Minimize to tray when tray is available."""
        from PySide6.QtWidgets import QApplication, QSystemTrayIcon

        app = QApplication.instance()
        if QSystemTrayIcon.isSystemTrayAvailable():
            event.ignore()
            self.hide()
        else:
            if self._vpn.is_connected:
                self._vpn.disconnect(wait_ms=1500)
            app = QApplication.instance()
            if hasattr(app, "shutdown"):
                app.shutdown()
            else:
                super().closeEvent(event)
