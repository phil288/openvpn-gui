"""Theme helpers for Qt stylesheet-backed widgets."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget


def enable_styled_background(widget: QWidget) -> None:
    """Allow QSS background-color on plain QWidget subclasses."""
    widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
