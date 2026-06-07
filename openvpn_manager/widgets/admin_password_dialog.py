"""Dialog to collect the login password for sudo caching."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)


class AdminPasswordDialog(QDialog):
    """Ask for the user password once to cache sudo credentials."""

    def __init__(self, parent=None, *, error_message: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Administrator access")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        label = QLabel(
            "OpenVPN needs permission to create the VPN tunnel.\n"
            "Enter your <b>login password</b>. It is used only to authorize "
            "sudo for this session and is never stored.\n"
            "For passwordless connects, install the PolicyKit policy "
            "(./install.sh --polkit)."
        )
        label.setWordWrap(True)
        layout.addWidget(label)

        self._error = QLabel()
        self._error.setObjectName("adminPasswordError")
        self._error.setWordWrap(True)
        self._error.setVisible(bool(error_message))
        if error_message:
            self._error.setText(error_message)
        layout.addWidget(self._error)

        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setPlaceholderText("Login password")
        layout.addWidget(self._password)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def password(self) -> str:
        return self._password.text()

    def set_error(self, message: str) -> None:
        self._error.setText(message)
        self._error.setVisible(bool(message))
        self._password.clear()
        self._password.setFocus()
