"""Developer-only visual state harness.

The harness previews presentation states without creating sessions, receipts, Tugs,
or Grants. It must never be presented as protocol evidence.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from PySide6.QtCore import QPoint, QRect, QSettings, Qt
from PySide6.QtGui import QColor, QFont, QImage, QPainter
from PySide6.QtWidgets import QApplication

from .companion import DEFAULT_COMPANION_SIZE, CompanionWidget
from .state import OrbState, appearance_for


def render_state_sheet(output: Path) -> bool:
    columns = 4
    states = tuple(OrbState)
    cell_width, cell_height = 300, 300
    rows = (len(states) + columns - 1) // columns
    image = QImage(columns * cell_width, rows * cell_height, QImage.Format.Format_ARGB32)
    image.fill(QColor("#101522"))
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QColor("#f7fbff"))
    font = QFont()
    font.setPixelSize(14)
    font.setBold(True)
    painter.setFont(font)
    with tempfile.TemporaryDirectory(prefix="leucoform-state-harness-") as temporary:
        settings = QSettings(str(Path(temporary) / "settings.ini"), QSettings.Format.IniFormat)
        settings.setValue("ui/reduced_motion", True)
        settings.setValue("ui/companion_size", DEFAULT_COMPANION_SIZE)
        for index, state in enumerate(states):
            row, column = divmod(index, columns)
            origin = QPoint(column * cell_width + 30, row * cell_height + 8)
            widget = CompanionWidget(settings)
            widget.setWindowFlags(Qt.WindowType.Widget)
            widget.set_state(state)
            widget.show()
            QApplication.processEvents()
            widget.render(painter, origin)
            painter.drawText(
                QRect(column * cell_width, row * cell_height + 252, cell_width, 42),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                appearance_for(state).label,
            )
            widget.close()
    painter.end()
    output.parent.mkdir(parents=True, exist_ok=True)
    return bool(image.save(str(output)))


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print("usage: python -m notug_protocol.desktop.harness OUTPUT.png", file=sys.stderr)
        return 2
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _app = QApplication.instance() or QApplication([])
    return 0 if render_state_sheet(Path(arguments[0])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
