"""Small, layout-safe motion helpers shared by the interface."""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QTimer
from PySide6.QtWidgets import QGraphicsOpacityEffect, QWidget

_UNBOUNDED = 16_777_215


def fade_in(
    widget: QWidget, duration: int = 240, delay: int = 0, start: float = 0.0
) -> QPropertyAnimation:
    """Fade a widget up from `start` opacity, then drop the effect again."""
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(start)
    widget.setGraphicsEffect(effect)

    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(duration)
    animation.setStartValue(start)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def clear() -> None:
        widget.setGraphicsEffect(None)
        animation.deleteLater()

    animation.finished.connect(clear)

    if delay > 0:
        QTimer.singleShot(delay, animation.start)
    else:
        animation.start()
    return animation


def slide_in(widget: QWidget, duration: int = 260) -> None:
    """Grow a row into the layout while it fades in."""
    target = max(widget.sizeHint().height(), 1)
    widget.setMaximumHeight(0)

    animation = QPropertyAnimation(widget, b"maximumHeight", widget)
    animation.setDuration(duration)
    animation.setStartValue(0)
    animation.setEndValue(target)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    animation.finished.connect(lambda: widget.setMaximumHeight(_UNBOUNDED))
    animation.start()

    fade_in(widget, duration)


def flash(widget: QWidget, duration: int = 320) -> QPropertyAnimation:
    """A quick dip and recover, used to draw the eye to a status change."""
    return fade_in(widget, duration, start=0.35)
