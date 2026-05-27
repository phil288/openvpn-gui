"""Left panel: list of VPN profiles."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from openvpn_manager.backend.profile_store import Profile


class ProfileListWidget(QWidget):
    """Profile list with selection signal."""

    profile_selected = Signal(str)
    profile_activated = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._list = QListWidget()
        self._list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._list.setSpacing(4)
        self._list.currentItemChanged.connect(self._on_selection)
        self._list.itemDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self._list)

        self._profiles: dict[str, Profile] = {}

    def set_profiles(
        self, profiles: list[Profile], active_id: str | None = None
    ) -> None:
        self._profiles.clear()
        self._list.clear()
        for p in sorted(profiles, key=lambda x: x.name.lower()):
            self._profiles[p.id] = p
            status = ""
            if p.id == active_id:
                status = " ● Connected"
            elif p.last_used:
                status = " ○"
            item = QListWidgetItem(f"{p.name}\n{p.server or '—'}{status}")
            item.setData(Qt.ItemDataRole.UserRole, p.id)
            if p.id == active_id:
                item.setData(Qt.ItemDataRole.UserRole + 1, "connected")
            self._list.addItem(item)

    def select_profile(self, profile_id: str) -> None:
        for i in range(self._list.count()):
            item = self._list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == profile_id:
                self._list.setCurrentItem(item)
                return

    def current_profile_id(self) -> str | None:
        item = self._list.currentItem()
        if item:
            return item.data(Qt.ItemDataRole.UserRole)
        return None

    def _on_selection(self, current: QListWidgetItem | None, _prev) -> None:
        if current:
            pid = current.data(Qt.ItemDataRole.UserRole)
            if pid:
                self.profile_selected.emit(pid)

    def _on_double_click(self, item: QListWidgetItem) -> None:
        pid = item.data(Qt.ItemDataRole.UserRole)
        if pid:
            self.profile_activated.emit(pid)
