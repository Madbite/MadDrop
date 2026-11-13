"""Swipe gesture and the animation used when files leave the device."""

from __future__ import annotations

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QWidget,
)

SWIPE_THRESHOLD = 0.72


class SwipeToSend(QWidget):
    """A rail you drag to the right; releasing past the threshold sends."""

    swiped = Signal()

    def __init__(self, label: str = "Swipe to send", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._label = label
        self._progress = 0.0
        self._dragging = False
        self.setFixedHeight(58)
        self.setMinimumWidth(230)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._animation = QPropertyAnimation(self, b"progress", self)
        self._animation.setDuration(260)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def _get_progress(self) -> float:
        return self._progress

    def _set_progress(self, value: float) -> None:
        self._progress = max(0.0, min(1.0, float(value)))
        self.update()

    progress = Property(float, _get_progress, _set_progress)

    def _knob_diameter(self) -> float:
        return self.height() - 12.0

    def _travel(self) -> float:
        return self.width() - 6.0 - self._knob_diameter()

    def _progress_from_x(self, x: float) -> float:
        travel = self._travel()
        if travel <= 0:
            return 0.0
        start = 3.0 + self._knob_diameter() / 2.0
        return max(0.0, min(1.0, (x - start) / travel))

    def _animate_to(self, value: float) -> None:
        self._animation.stop()
        self._animation.setStartValue(self._progress)
        self._animation.setEndValue(value)
        self._animation.start()

    def _reset_and_fire(self) -> None:
        self._animate_to(0.0)
        if self.isEnabled():
            self.swiped.emit()

    def mousePressEvent(self, event) -> None:
        if not self.isEnabled() or event.button() != Qt.MouseButton.LeftButton:
            super().mousePressEvent(event)
            return
        self._animation.stop()
        self._dragging = True
        self.setFocus()
        self._set_progress(self._progress_from_x(event.position().x()))

    def mouseMoveEvent(self, event) -> None:
        if not self._dragging:
            super().mouseMoveEvent(event)
            return
        self._set_progress(self._progress_from_x(event.position().x()))

    def mouseReleaseEvent(self, event) -> None:
        if not self._dragging:
            super().mouseReleaseEvent(event)
            return
        self._dragging = False
        if self._progress >= SWIPE_THRESHOLD:
            self._animate_to(1.0)
            QTimer.singleShot(220, self._reset_and_fire)
        else:
            self._animate_to(0.0)

    def keyPressEvent(self, event) -> None:
        if self.isEnabled() and event.key() in (
            Qt.Key.Key_Return,
            Qt.Key.Key_Enter,
            Qt.Key.Key_Space,
            Qt.Key.Key_Right,
        ):
            self._animate_to(1.0)
            QTimer.singleShot(220, self._reset_and_fire)
            return
        super().keyPressEvent(event)

    def setEnabled(self, enabled: bool) -> None:  # noqa: N802 (Qt naming)
        super().setEnabled(enabled)
        if not enabled:
            self._dragging = False
            self._set_progress(0.0)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        track = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        radius = track.height() / 2.0

        painter.setPen(QPen(QColor("#263548"), 1))
        painter.setBrush(QColor("#0d131c") if self.isEnabled() else QColor("#0b0f16"))
        painter.drawRoundedRect(track, radius, radius)

        if self._progress > 0:
            glow = QColor("#006fff")
            glow.setAlphaF(0.18 + 0.5 * self._progress)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glow)
            painter.drawRoundedRect(track, radius, radius)

        label = self._label if self.isEnabled() else "Choose files and a device"
        painter.setPen(QColor("#dbe7f7") if self.isEnabled() else QColor("#5d6b7e"))
        font = QFont(painter.font())
        font.setPointSizeF(10.0)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(track, Qt.AlignmentFlag.AlignCenter, label)

        diameter = self._knob_diameter()
        offset = max(0.0, self._travel()) * self._progress
        knob = QRectF(track.left() + 3.0 + offset, track.top() + 3.0, diameter, diameter)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#006fff") if self.isEnabled() else QColor("#1b2634"))
        painter.drawEllipse(knob)

        painter.setPen(
            QPen(
                QColor("#ffffff"),
                2.0,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
                Qt.PenJoinStyle.RoundJoin,
            )
        )
        center = knob.center()
        for shift in (-4.0, 2.0):
            path = QPainterPath()
            path.moveTo(center.x() + shift - 3.0, center.y() - 5.0)
            path.lineTo(center.x() + shift + 2.0, center.y())
            path.lineTo(center.x() + shift - 3.0, center.y() + 5.0)
            painter.drawPath(path)


class FlyingChip(QWidget):
    """A file chip that flies from the file list into a device row."""

    def __init__(
        self,
        parent: QWidget,
        text: str,
        start: QPoint,
        end: QPoint,
        duration: int = 620,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setObjectName("flyingChip")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel(self._elide(text), self)
        label.setStyleSheet(
            "color: #eaf3ff;"
            "background: #16283f;"
            "border: 1px solid #2f5581;"
            "border-radius: 15px;"
            "padding: 6px 14px;"
            "font-weight: 600;"
        )
        layout.addWidget(label)
        self.adjustSize()

        self.move(start)
        self._effect = QGraphicsOpacityEffect(self)
        self._effect.setOpacity(1.0)
        self.setGraphicsEffect(self._effect)

        self._move = QPropertyAnimation(self, b"pos", self)
        self._move.setDuration(duration)
        self._move.setStartValue(start)
        self._move.setEndValue(end - QPoint(self.width() // 2, self.height() // 2))
        self._move.setEasingCurve(QEasingCurve.Type.InOutCubic)

        self._fade = QPropertyAnimation(self._effect, b"opacity", self)
        self._fade.setDuration(duration)
        self._fade.setStartValue(1.0)
        self._fade.setKeyValueAt(0.62, 1.0)
        self._fade.setEndValue(0.0)

        self._move.finished.connect(self.deleteLater)

    @staticmethod
    def _elide(text: str, limit: int = 26) -> str:
        name = text.strip() or "file"
        return name if len(name) <= limit else f"{name[: limit - 1]}…"

    def launch(self, delay: int = 0) -> None:
        QTimer.singleShot(max(0, delay), self._start)

    def _start(self) -> None:
        self.show()
        self.raise_()
        self._move.start()
        self._fade.start()

    def sizeHint(self) -> QSize:
        return super().sizeHint()
