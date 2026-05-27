"""Dialog to collect or edit VPN credentials."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)


class CredentialsDialog(QDialog):
    """Username/password entry with optional remember."""

    def __init__(
        self,
        profile_name: str,
        username: str = "",
        password: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("VPN Credentials")
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)
        layout.addWidget(
            QLabel(f"Enter credentials for <b>{profile_name}</b>")
        )

        form = QFormLayout()
        self._username = QLineEdit(username)
        self._password = QLineEdit(password)
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Username", self._username)
        form.addRow("Password", self._password)
        layout.addLayout(form)

        self._remember = QCheckBox("Remember in system keyring")
        self._remember.setChecked(True)
        layout.addWidget(self._remember)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def username(self) -> str:
        return self._username.text().strip()

    def password(self) -> str:
        return self._password.text()

    def remember(self) -> bool:
        return self._remember.isChecked()
