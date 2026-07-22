"""Accessible animated companion surface for Leucoform."""

from __future__ import annotations

from math import cos, pi, sin

from PySide6.QtCore import QPoint, QPointF, QRectF, QSettings, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QContextMenuEvent,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPen,
    QPolygon,
    QPolygonF,
    QRegion,
)
from PySide6.QtWidgets import QApplication, QMenu, QPushButton, QWidget

from .geometry import RHOMBIC_TRIACONTAHEDRON, rotate
from .state import OrbState, appearance_for

MIN_COMPANION_SIZE = 200
DEFAULT_COMPANION_SIZE = 240
MAX_COMPANION_SIZE = 300


def clamp_companion_size(value: object) -> int:
    try:
        requested = int(str(value))
    except (TypeError, ValueError):
        requested = DEFAULT_COMPANION_SIZE
    return max(MIN_COMPANION_SIZE, min(MAX_COMPANION_SIZE, requested))


class _SolidCanvas(QWidget):
    activated = Signal()

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.state = OrbState.IDLE
        self.reduced_motion = False
        self.phase = 0.0
        self._press: QPoint | None = None
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.TimerType.CoarseTimer)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._advance)
        self._timer.start()

    def _advance(self) -> None:
        if not self.isVisible() or self.reduced_motion:
            return
        speed = 0.009 if self.state == OrbState.INTEGRATED else 0.006
        self.phase = (self.phase + speed) % (2.0 * pi)
        self.update()

    def set_state(self, state: OrbState) -> None:
        self.state = state
        self.update()

    def set_reduced_motion(self, enabled: bool) -> None:
        self.reduced_motion = enabled
        if enabled:
            self.phase = 0.42
        self.update()

    def _projected_faces(self) -> list[tuple[float, QPolygonF, float]]:
        side = min(self.width(), self.height())
        scale = side * 0.205
        cx, cy = self.width() / 2.0, self.height() / 2.0
        rotated = [
            rotate(vertex, 0.44 + self.phase * 0.71, -0.52 + self.phase, 0.18 + self.phase * 0.37)
            for vertex in RHOMBIC_TRIACONTAHEDRON.vertices
        ]
        result: list[tuple[float, QPolygonF, float]] = []
        exploded = appearance_for(self.state).shape.startswith("exploded")
        for face in RHOMBIC_TRIACONTAHEDRON.faces:
            points = [rotated[index] for index in face]
            depth = sum(point[2] for point in points) / 4.0
            polygon = QPolygonF(
                [QPointF(cx + point[0] * scale, cy - point[1] * scale) for point in points]
            )
            if exploded:
                bounds = polygon.boundingRect()
                direction = QPointF(bounds.center().x() - cx, bounds.center().y() - cy)
                magnitude = max(1.0, (direction.x() ** 2 + direction.y() ** 2) ** 0.5)
                polygon.translate(direction.x() * 7.0 / magnitude, direction.y() * 7.0 / magnitude)
            result.append((depth, polygon, max(-1.0, min(1.0, depth / 1.7))))
        return sorted(result, key=lambda item: item[0])

    def _paint_orbits(self, painter: QPainter) -> None:
        side = min(self.width(), self.height())
        center = QPointF(self.width() / 2.0, self.height() / 2.0)
        painter.setPen(QPen(QColor(231, 245, 255, 185), max(1.4, side / 150.0)))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        rings = ((0.0, 0.76, 0.32), (58.0, 0.71, 0.28), (-61.0, 0.68, 0.27))
        for index, (angle, width_ratio, height_ratio) in enumerate(rings):
            painter.save()
            painter.translate(center)
            painter.rotate(angle)
            rect = QRectF(
                -side * width_ratio / 2,
                -side * height_ratio / 2,
                side * width_ratio,
                side * height_ratio,
            )
            painter.drawEllipse(rect)
            electron_angle = self.phase * (1.4 + index * 0.28) + index * 2.0
            point = QPointF(
                cos(electron_angle) * rect.width() / 2, sin(electron_angle) * rect.height() / 2
            )
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(255, 255, 255, 235))
            painter.drawEllipse(point, 3.4, 3.4)
            painter.restore()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        appearance = appearance_for(self.state)
        if appearance.luminous:
            self._paint_orbits(painter)
            glow = QPainterPath()
            glow.addEllipse(QRectF(self.rect()).adjusted(44, 44, -44, -44))
            painter.fillPath(glow, QColor(225, 243, 255, 34))
        base = QColor(appearance.color)
        for _depth, polygon, light in self._projected_faces():
            face_color = QColor(base).lighter(int(112 + light * 22))
            face_color.setAlpha(132 if appearance.luminous else 108)
            painter.setBrush(face_color)
            edge = QColor(245, 251, 255) if appearance.luminous else base.darker(165)
            edge.setAlpha(215)
            painter.setPen(QPen(edge, 1.35))
            painter.drawPolygon(polygon)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._press = event.position().toPoint()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if (
            self._press is not None
            and (event.position().toPoint() - self._press).manhattanLength() < 5
        ):
            self.activated.emit()
        self._press = None


class ConsentFaceButton(QPushButton):
    """A real accessible control painted as one separated rhombic face."""

    def __init__(self, number: int, label: str, parent: QWidget) -> None:
        super().__init__(str(number), parent)
        self.number, self.label, self.selected = number, label, False
        self.setAccessibleName(f"Grant face {number}: {label}")
        self.setAccessibleDescription("Activate this distinct face once during the Grant ceremony.")
        self.setToolTip(f"{number}. {label}")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setFixedSize(62, 48)

    def resizeEvent(self, event: object) -> None:  # noqa: N802
        del event
        polygon = QPolygon(
            [
                QPoint(self.width() // 2, 0),
                QPoint(self.width(), self.height() // 2),
                QPoint(self.width() // 2, self.height()),
                QPoint(0, self.height() // 2),
            ]
        )
        self.setMask(QRegion(polygon))

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        polygon = QPolygonF(
            [
                QPointF(self.width() / 2, 1),
                QPointF(self.width() - 1, self.height() / 2),
                QPointF(self.width() / 2, self.height() - 1),
                QPointF(1, self.height() / 2),
            ]
        )
        colors = (QColor("#ff6b76"), QColor("#f1b83b"), QColor("#8a77df"))
        painter.setBrush(QColor("#f7fbff") if self.selected else colors[self.number - 1])
        painter.setPen(QPen(QColor("#172033"), 2.0))
        painter.drawPolygon(polygon)
        painter.setPen(QPen(QColor(23, 32, 51, 150), 1.2))
        for offset in range(self.number):
            x = self.width() / 2 - 8 + offset * 8
            painter.drawLine(QPointF(x, 12), QPointF(x + 8, self.height() - 12))
        painter.setPen(QColor("#172033"))
        font = painter.font()
        font.setBold(True)
        font.setPixelSize(17)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, str(self.number))


class CompanionWidget(QWidget):
    activated = Signal()
    recovery_requested = Signal()
    quit_requested = Signal()
    consent_completed = Signal()

    def __init__(self, settings: QSettings) -> None:
        super().__init__()
        self._settings, self._state = settings, OrbState.IDLE
        self._drag_origin: QPoint | None = None
        self._window_origin: QPoint | None = None
        self._reduced_motion = self._setting_bool("ui/reduced_motion", False)
        size = clamp_companion_size(settings.value("ui/companion_size", DEFAULT_COMPANION_SIZE))
        self.setFixedSize(QSize(size, size))
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAccessibleName("Leucoform provenance companion")
        self.canvas = _SolidCanvas(self)
        self.canvas.setGeometry(self.rect())
        self.canvas.activated.connect(self.activated)
        self._context_menu = QMenu(self)
        recovery_action = self._context_menu.addAction("Open recovery tools")
        recovery_action.triggered.connect(self.recovery_requested)
        self._context_menu.addSeparator()
        quit_action = self._context_menu.addAction("Quit Leucoform")
        quit_action.triggered.connect(self.quit_requested)
        labels = ("Review bound work", "Confirm protected baseline", "Grant exact Tug")
        self.consent_faces = tuple(
            ConsentFaceButton(index + 1, label, self) for index, label in enumerate(labels)
        )
        for button in self.consent_faces:
            button.clicked.connect(lambda _checked=False, face=button: self._select_face(face))
            button.hide()
        self.set_reduced_motion(self._reduced_motion)
        self.set_state(OrbState.IDLE)

    def _setting_bool(self, key: str, default: bool) -> bool:
        value = self._settings.value(key, default)
        return value if isinstance(value, bool) else str(value).casefold() in {"1", "true", "yes"}

    def resizeEvent(self, event: object) -> None:  # noqa: N802
        del event
        self.canvas.setGeometry(self.rect())
        cx, cy = self.width() // 2, self.height() // 2
        positions = ((cx - 88, cy - 88), (cx + 26, cy - 58), (cx - 31, cy + 48))
        for button, position in zip(self.consent_faces, positions, strict=True):
            button.move(*position)

    def set_reduced_motion(self, enabled: bool) -> None:
        self._reduced_motion = enabled
        self._settings.setValue("ui/reduced_motion", enabled)
        self.canvas.set_reduced_motion(enabled)

    def set_state(self, state: OrbState) -> None:
        self._state = state
        appearance = appearance_for(state)
        self.setAccessibleDescription(appearance.label)
        self.setToolTip(f"Leucoform — {appearance.label}")
        self.canvas.set_state(state)
        ceremony = state == OrbState.REVIEW
        self.setWindowFlag(Qt.WindowType.WindowDoesNotAcceptFocus, not ceremony)
        for button in self.consent_faces:
            button.selected = False
            button.setEnabled(ceremony)
            button.setVisible(ceremony)
            button.update()
        if self.isVisible():
            self.show()

    def _select_face(self, face: ConsentFaceButton) -> None:
        if self._state != OrbState.REVIEW or face.selected:
            return
        expected = next((item for item in self.consent_faces if not item.selected), None)
        if face is not expected:
            QApplication.beep()
            if expected is not None:
                expected.setFocus()
            return
        face.selected = True
        face.setAccessibleDescription("Selected; this face cannot be counted twice.")
        face.update()
        remaining = [item for item in self.consent_faces if not item.selected]
        if remaining:
            remaining[0].setFocus()
        else:
            self.consent_completed.emit()

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_origin, self._window_origin = event.globalPosition().toPoint(), self.pos()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if self._drag_origin is not None and self._window_origin is not None:
            self.move(self._window_origin + event.globalPosition().toPoint() - self._drag_origin)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if self._drag_origin is not None:
            self._drag_origin, self._window_origin = None, None
            self.snap_to_corner()

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:  # noqa: N802
        self._context_menu.exec(event.globalPos())

    def snap_to_corner(self) -> None:
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        area, center, margin = screen.availableGeometry(), self.geometry().center(), 14
        x = (
            area.left() + margin
            if center.x() < area.center().x()
            else area.right() - self.width() - margin
        )
        y = (
            area.top() + margin
            if center.y() < area.center().y()
            else area.bottom() - self.height() - margin
        )
        self.move(x, y)
        self._settings.setValue("orb/position", self.pos())

    def restore_position(self) -> None:
        position = self._settings.value("orb/position")
        self.move(position) if isinstance(position, QPoint) else self.snap_to_corner()
