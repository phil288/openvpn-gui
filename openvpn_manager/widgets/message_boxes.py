"""Message boxes with readable text on the application dark theme."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QMessageBox, QWidget

# Applied per-dialog so label text stays visible regardless of global QSS quirks.
_MESSAGE_BOX_STYLE = """
QMessageBox {
    background-color: #2b2f38;
    color: #e8eaed;
}
QMessageBox QLabel {
    color: #e8eaed;
    background-color: transparent;
}
/* Width only on the text label — never the icon label, or it forces a
   wide empty gap between the icon and the message text. */
QMessageBox QLabel#qt_msgbox_label {
    min-width: 300px;
}
QMessageBox QPushButton {
    background-color: #3a3f4b;
    color: #e8eaed;
    border: 1px solid #4a5060;
    border-radius: 6px;
    padding: 6px 16px;
    min-width: 72px;
}
QMessageBox QPushButton:hover {
    background-color: #4a5060;
}
"""


def _prepare(box: QMessageBox) -> QMessageBox:
    box.setOption(QMessageBox.Option.DontUseNativeDialog, True)
    box.setStyleSheet(_MESSAGE_BOX_STYLE)
    for label in box.findChildren(QLabel):
        label.setStyleSheet("color: #e8eaed; background: transparent;")
    return box


def warning(parent: QWidget | None, title: str, text: str) -> None:
    box = _prepare(QMessageBox(QMessageBox.Icon.Warning, title, text, QMessageBox.StandardButton.Ok, parent))
    box.exec()


def critical(parent: QWidget | None, title: str, text: str) -> None:
    box = _prepare(QMessageBox(QMessageBox.Icon.Critical, title, text, QMessageBox.StandardButton.Ok, parent))
    box.exec()


def question_yes_no(
    parent: QWidget | None,
    title: str,
    text: str,
    *,
    default_no: bool = True,
) -> bool:
    buttons = QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
    default = (
        QMessageBox.StandardButton.No
        if default_no
        else QMessageBox.StandardButton.Yes
    )
    box = _prepare(
        QMessageBox(QMessageBox.Icon.Question, title, text, buttons, parent)
    )
    box.setDefaultButton(default)
    return box.exec() == QMessageBox.StandardButton.Yes


def confirm_kill_all(parent: QWidget | None, process_count: int) -> bool:
    if process_count == 1:
        target = "the running OpenVPN Manager process"
    else:
        target = f"all {process_count} OpenVPN Manager processes"
    text = (
        f"This will force-stop {target} for your user.\n\n"
        "Any active VPN connection will be dropped."
    )
    buttons = QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
    box = _prepare(
        QMessageBox(QMessageBox.Icon.Warning, "Kill all instances", text, buttons, parent)
    )
    box.setDefaultButton(QMessageBox.StandardButton.No)
    return box.exec() == QMessageBox.StandardButton.Yes
