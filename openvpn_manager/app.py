"""Application bootstrap, system tray, and main entry."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QCursor, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QMenu,
    QSystemTrayIcon,
)

from openvpn_manager.backend import credentials as cred_store
from openvpn_manager.backend import privilege
from openvpn_manager.backend.profile_store import list_profiles
from openvpn_manager.backend.vpn_process import VpnController
from openvpn_manager.main_window import MainWindow
from openvpn_manager.widgets.message_boxes import confirm_kill_all
from openvpn_manager.single_instance import (
    SingleInstanceServer,
    find_manager_pids,
    is_instance_running,
    kill_all_manager_processes,
    ovpn_paths_from_argv,
    try_forward_files,
)

RESOURCES = Path(__file__).resolve().parent / "resources"


def _resource_path(name: str) -> Path:
    return RESOURCES / name


def _load_stylesheet(app: QApplication) -> None:
    # Fusion renders application QSS reliably on Linux (native themes often do not).
    app.setStyle("Fusion")
    qss = _resource_path("style.qss")
    if qss.is_file():
        app.setStyleSheet(qss.read_text(encoding="utf-8"))


def _icon(name: str) -> QIcon:
    path = _resource_path(f"icons/{name}")
    if path.is_file():
        return QIcon(str(path))
    return QIcon()


class TrayController:
    """System tray icon and quick actions."""

    def __init__(
        self,
        app: QApplication,
        window: MainWindow,
        vpn: VpnController,
        on_exit,
    ) -> None:
        self._app = app
        self._window = window
        self._vpn = vpn
        self._on_exit = on_exit
        self._menu: QMenu | None = None
        self._disconnect_action: QAction | None = None
        self._connect_menu: QMenu | None = None
        self._tray: QSystemTrayIcon | None = None

        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self._tray = QSystemTrayIcon(_icon("tray-disconnected.svg"))
        self._tray.setToolTip("OpenVPN Manager")

        self._menu = QMenu()
        show_action = QAction("Show window", self._menu)
        show_action.triggered.connect(self._show_window)
        self._menu.addAction(show_action)

        self._menu.addSeparator()
        self._connect_menu = self._menu.addMenu("Connect")
        self._disconnect_action = QAction("Disconnect VPN", self._menu)
        self._disconnect_action.triggered.connect(window.disconnect_active)
        self._disconnect_action.setEnabled(False)
        self._menu.addAction(self._disconnect_action)

        self._menu.addSeparator()
        exit_action = QAction("Exit application", self._menu)
        exit_action.triggered.connect(self._exit_application)
        self._menu.addAction(exit_action)

        kill_action = QAction("Kill all instances…", self._menu)
        kill_action.triggered.connect(self._kill_all_instances)
        self._menu.addAction(kill_action)

        self._tray.setContextMenu(self._menu)
        self._tray.activated.connect(self._on_activated)
        self._tray.show()

        self._rebuild_connect_menu()
        vpn.connected.connect(self._on_vpn_connected)
        vpn.disconnected.connect(self._on_vpn_disconnected)

    def _rebuild_connect_menu(self) -> None:
        if not self._tray or not self._connect_menu:
            return
        self._connect_menu.clear()
        profiles = list_profiles()
        if not profiles:
            empty = QAction("(No profiles)", self._connect_menu)
            empty.setEnabled(False)
            self._connect_menu.addAction(empty)
            return
        for p in profiles:
            action = QAction(p.name, self._connect_menu)
            action.setData(p.id)

            def _make_connect(pid: str):
                def connect():
                    self._window._profile_list.select_profile(pid)
                    self._window._connect_profile(pid)
                    self._show_window()

                return connect

            action.triggered.connect(_make_connect(p.id))
            self._connect_menu.addAction(action)

    def _show_window(self) -> None:
        self._window.showNormal()
        self._window.raise_()
        self._window.activateWindow()

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Context:
            if self._menu:
                self._menu.popup(QCursor.pos())
        elif reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._show_window()

    def _on_vpn_connected(self) -> None:
        if self._tray:
            self._tray.setIcon(_icon("tray-connected.svg"))
            self._tray.setToolTip("OpenVPN Manager — Connected")
        if self._disconnect_action:
            self._disconnect_action.setEnabled(True)

    def _on_vpn_disconnected(self) -> None:
        if self._tray:
            self._tray.setIcon(_icon("tray-disconnected.svg"))
            self._tray.setToolTip("OpenVPN Manager")
        if self._disconnect_action:
            self._disconnect_action.setEnabled(False)
        self._rebuild_connect_menu()

    def refresh(self) -> None:
        self._rebuild_connect_menu()

    def _exit_application(self) -> None:
        self._on_exit()

    def _kill_all_instances(self) -> None:
        count = len(find_manager_pids())
        if not confirm_kill_all(self._window, count):
            return
        kill_all_manager_processes()
        os._exit(0)

    def notify(self, title: str, message: str) -> None:
        if self._tray:
            self._tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 4000)


class OpenVpnManagerApp(QApplication):
    """Custom QApplication with tray-minimize behavior."""

    def __init__(self, argv: list[str]) -> None:
        super().__init__(argv)
        self.setApplicationName("OpenVPN Manager")
        self.setOrganizationName("openvpn-manager")
        self.setQuitOnLastWindowClosed(False)
        _load_stylesheet(self)

        self._vpn = VpnController()
        self._window = MainWindow(self._vpn)
        self._instance_server = SingleInstanceServer(self._on_files_opened)
        self._tray = TrayController(
            self, self._window, self._vpn, on_exit=self.shutdown
        )
        self._pending_ovpn = ovpn_paths_from_argv(argv)
        QTimer.singleShot(0, self._warm_sudo_cache)

        def _on_connected_notify() -> None:
            if self._tray and self._tray._tray:
                self._tray.notify("Connected", "VPN connection established")

        self._window._vpn.connected.connect(_on_connected_notify)
        self._window.profiles_changed.connect(self._on_profiles_changed)

    def _on_profiles_changed(self) -> None:
        if self._tray:
            self._tray.refresh()

    def _warm_sudo_cache(self) -> None:
        """Restore sudo timestamp from keyring on startup when possible."""
        if not privilege.needs_elevation():
            return
        stored = cred_store.load_admin_password()
        if stored and not privilege.cache_sudo_password(stored):
            cred_store.delete_admin_password()

    def shutdown(self) -> None:
        """Clean exit: disconnect VPN, release tray, stop event loop."""
        if self._tray and self._tray._tray:
            self._tray._tray.hide()
        if self._vpn.is_connected:
            self._vpn.disconnect(wait_ms=1500)
        self._instance_server.close()
        self.quit()
        QTimer.singleShot(500, lambda: os._exit(0))

    def _on_files_opened(self, paths: list[Path]) -> None:
        if paths:
            self._window.open_ovpn_files(paths)
        else:
            self._window.showNormal()
            self._window.raise_()
            self._window.activateWindow()

    @property
    def main_window(self) -> MainWindow:
        return self._window

    def run(self) -> int:
        self._window.show()
        if self._pending_ovpn:
            QTimer.singleShot(0, lambda: self._window.open_ovpn_files(self._pending_ovpn))
        return self.exec()


def main() -> int:
    # High DPI
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    pending = ovpn_paths_from_argv(sys.argv)
    if is_instance_running():
        try_forward_files(pending)
        return 0
    app = OpenVpnManagerApp(sys.argv)
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
