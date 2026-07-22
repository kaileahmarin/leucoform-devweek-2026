"""Qt Widgets entry point for Leucoform, powered by NoTUG."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path

from PySide6.QtCore import (
    QCoreApplication,
    QObject,
    QPoint,
    QSettings,
    QSize,
    Qt,
    QThread,
    QTimer,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QColor,
    QIcon,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPixmap,
)
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..application import (
    AgentRunResult,
    ReviewSummaryResult,
    abandon_unchanged_session,
    archive_disposed_session,
    create_session,
    deny_reviewed_tug,
    get_review_summary,
    grant_reviewed_tug,
    list_repository_sessions,
    protect_repository,
    repository_status,
    run_agent_task,
    session_change_status,
    submit_session,
)
from ..brand import DESKTOP_TAGLINE, VERSION
from ..errors import NoTugError
from ..git import terminate_active_git_processes
from ..util import sanitize_terminal
from .activity import JsonlNormalizer
from .codex import CodexInstallation, build_codex_command, discover_codex
from .companion import CompanionWidget
from .packaged_selftest import run_packaged_governed_self_test
from .state import OrbState, appearance_for

INSTANCE_NAME = "org.openai.leucoform.notug.v1"
MAX_RECENT_REPOSITORIES = 8


def _safe_error(exc: BaseException) -> str:
    if isinstance(exc, NoTugError):
        return f"{exc.code}: {exc.message}"
    return f"{type(exc).__name__}: {exc}"


def _make_icon(state: OrbState, size: int = 64) -> QIcon:
    appearance = appearance_for(state)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(appearance.color))
    painter.drawEllipse(3, 3, size - 6, size - 6)
    painter.end()
    return QIcon(pixmap)


class AgentWorker(QObject):
    """One background adapter around the typed, locking Core runner."""

    activity = Signal(str)
    warning = Signal(str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        session_id: str,
        command: tuple[str, ...],
        prompt: bytes,
        cancel_event: threading.Event,
    ) -> None:
        super().__init__()
        self._session_id = session_id
        self._command = command
        self._prompt = prompt
        self._cancel_event = cancel_event
        self._normalizer = JsonlNormalizer()

    def _stdout(self, chunk: str) -> None:
        for event in self._normalizer.feed(chunk):
            self.activity.emit(event.text)

    def _stderr(self, chunk: str) -> None:
        text = sanitize_terminal(chunk).strip()
        if text:
            self.warning.emit(text[:2_000])

    def run(self) -> None:
        try:
            result = run_agent_task(
                self._session_id,
                self._command,
                input_bytes=self._prompt,
                stdout_callback=self._stdout,
                stderr_callback=self._stderr,
                cancel_event=self._cancel_event,
            )
            for event in self._normalizer.finish():
                self.activity.emit(event.text)
            self.completed.emit(result)
        except BaseException as exc:
            self.failed.emit(_safe_error(exc))
        finally:
            self._prompt = b""


class LegacyOrbWidget(QWidget):
    activated = Signal()

    def __init__(self, settings: QSettings) -> None:
        super().__init__()
        self._settings = settings
        self._state = OrbState.IDLE
        self._drag_origin: QPoint | None = None
        self._window_origin: QPoint | None = None
        self._reduced_motion = self._setting_bool("ui/reduced_motion", False)
        self._pulse_on = False
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(650)
        self._pulse_timer.timeout.connect(self._advance_pulse)
        self.setFixedSize(QSize(72, 72))
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAccessibleName("Leucoform status orb")
        self.set_state(OrbState.IDLE)

    def _setting_bool(self, key: str, default: bool) -> bool:
        value = self._settings.value(key, default)
        if isinstance(value, bool):
            return value
        return str(value).casefold() in {"1", "true", "yes"}

    def set_reduced_motion(self, enabled: bool) -> None:
        self._reduced_motion = enabled
        self._settings.setValue("ui/reduced_motion", enabled)
        self.set_state(self._state)

    def _advance_pulse(self) -> None:
        self._pulse_on = not self._pulse_on
        self.update()

    def set_state(self, state: OrbState) -> None:
        self._state = state
        appearance = appearance_for(state)
        self.setAccessibleDescription(appearance.label)
        self.setToolTip(f"Leucoform — {appearance.label}")
        if appearance.pulse and not self._reduced_motion:
            self._pulse_timer.start()
        else:
            self._pulse_timer.stop()
            self._pulse_on = False
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        del event
        appearance = appearance_for(self._state)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 65))
        painter.drawEllipse(7, 9, 60, 60)
        orb_color = QColor(appearance.color)
        if self._pulse_on:
            orb_color = orb_color.lighter(125)
        painter.setBrush(orb_color)
        painter.drawEllipse(5, 5, 60, 60)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_origin = event.globalPosition().toPoint()
            self._window_origin = self.pos()
            event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if self._drag_origin is not None and self._window_origin is not None:
            self.move(self._window_origin + event.globalPosition().toPoint() - self._drag_origin)
            event.accept()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if self._drag_origin is None or self._window_origin is None:
            return
        distance = (event.globalPosition().toPoint() - self._drag_origin).manhattanLength()
        self._drag_origin = None
        self._window_origin = None
        if distance < QApplication.startDragDistance():
            self.activated.emit()
        self.snap_to_corner()

    def snap_to_corner(self) -> None:
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        area = screen.availableGeometry()
        center = self.geometry().center()
        margin = 14
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
        if isinstance(position, QPoint):
            self.move(position)
        else:
            self.snap_to_corner()


class OrbWidget(CompanionWidget):
    """Compatibility name for the Leucoform companion window."""


class AboutDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About Leucoform")
        layout = QVBoxLayout(self)
        title = QLabel(DESKTOP_TAGLINE)
        title.setObjectName("title")
        title.setAccessibleName(DESKTOP_TAGLINE)
        layout.addWidget(title)
        layout.addWidget(QLabel(f"Version {VERSION}"))
        body = QLabel(
            "A local desktop companion for governed Codex work. No telemetry, automatic "
            "updates, merge, push, or background network checks are included. Codex is "
            "discovered locally and is never bundled or downloaded by Leucoform."
        )
        body.setWordWrap(True)
        body.setMinimumWidth(420)
        layout.addWidget(body)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        layout.addWidget(close, alignment=Qt.AlignmentFlag.AlignRight)


@dataclass(slots=True)
class ActiveReview:
    session_id: str
    tug_id: str
    tug_hash: str


class MainWindow(QMainWindow):
    state_changed = Signal(object)
    reduced_motion_changed = Signal(bool)

    def __init__(
        self,
        settings: QSettings,
        *,
        tray_available: bool,
        companion_owned: bool = False,
        verify_codex_on_start: bool = True,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.tray_available = tray_available
        self.companion_owned = companion_owned
        self.repository: Path | None = None
        self.codex: CodexInstallation | None = None
        self.session_id: str | None = None
        self.active_review: ActiveReview | None = None
        self.cancel_event: threading.Event | None = None
        self.worker_thread: QThread | None = None
        self.worker: AgentWorker | None = None
        self._repository_verification_active = False
        self._session_refresh_active = False
        self._repository_initialized: bool | None = None
        self._session_refresh_timer = QTimer(self)
        self._session_refresh_timer.setSingleShot(True)
        self._session_refresh_timer.setInterval(200)
        self._session_refresh_timer.timeout.connect(self._refresh_sessions)
        self._state = OrbState.IDLE
        self.setWindowTitle(DESKTOP_TAGLINE)
        self.setMinimumSize(760, 620)
        self.resize(980, 760)
        self._build_ui()
        self._restore_settings(verify_codex=verify_codex_on_start)
        self._set_state(OrbState.IDLE)

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(20, 18, 20, 18)
        header = QHBoxLayout()
        title = QLabel("Leucoform")
        title.setObjectName("title")
        subtitle = QLabel("powered by NoTUG · local mutation governance")
        subtitle.setObjectName("subtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        header.addStretch()
        self.status_label = QLabel()
        self.status_label.setObjectName("statusPill")
        self.status_label.setAccessibleName("Leucoform status")
        header.addWidget(self.status_label)
        root_layout.addLayout(header)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._composer_page())
        self.pages.addWidget(self._review_page())
        root_layout.addWidget(self.pages, 1)
        self.setCentralWidget(root)

        file_menu = self.menuBar().addMenu("Leucoform")
        show_composer = QAction("Composer", self)
        show_composer.setShortcut("Ctrl+N")
        show_composer.triggered.connect(lambda: self.pages.setCurrentIndex(0))
        file_menu.addAction(show_composer)
        about = QAction("About", self)
        about.triggered.connect(lambda: AboutDialog(self).exec())
        file_menu.addAction(about)
        quit_action = QAction("Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(QCoreApplication.quit)
        file_menu.addAction(quit_action)

        view_menu = self.menuBar().addMenu("Accessibility")
        reduced_motion = QAction("Reduce motion", self)
        reduced_motion.setCheckable(True)
        current_motion = self.settings.value("ui/reduced_motion", False)
        reduced_motion.setChecked(
            current_motion if isinstance(current_motion, bool) else str(current_motion) == "true"
        )
        reduced_motion.toggled.connect(self._set_reduced_motion)
        view_menu.addAction(reduced_motion)

    def _composer_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        repository_group = QGroupBox("1 · Protected repository")
        repository_layout = QGridLayout(repository_group)
        self.recent_repositories = QComboBox()
        self.recent_repositories.setAccessibleName("Recent repositories")
        self.recent_repositories.currentTextChanged.connect(self._recent_selected)
        self.browse_repository_button = QPushButton("Choose folder…")
        self.browse_repository_button.clicked.connect(self._choose_repository)
        self.protection_label = QLabel("Choose a Git repository to begin.")
        self.protection_label.setWordWrap(True)
        self.protect_button = QPushButton("Enable NoTUG protection")
        self.protect_button.clicked.connect(self._protect_repository)
        self.protect_button.hide()
        repository_layout.addWidget(self.recent_repositories, 0, 0)
        repository_layout.addWidget(self.browse_repository_button, 0, 1)
        repository_layout.addWidget(self.protection_label, 1, 0)
        repository_layout.addWidget(self.protect_button, 1, 1)
        layout.addWidget(repository_group)

        codex_group = QGroupBox("2 · Local Codex")
        codex_layout = QHBoxLayout(codex_group)
        self.codex_label = QLabel("Codex has not been verified yet.")
        self.codex_label.setWordWrap(True)
        select_codex = QPushButton("Select Codex…")
        select_codex.clicked.connect(self._choose_codex)
        codex_layout.addWidget(self.codex_label, 1)
        codex_layout.addWidget(select_codex)
        layout.addWidget(codex_group)

        prompt_group = QGroupBox("3 · Compose one governed run")
        prompt_layout = QVBoxLayout(prompt_group)
        self.prompt = QPlainTextEdit()
        self.prompt.setPlaceholderText(
            "Describe the change for Codex. The prompt is sent through stdin and is not "
            "stored by Leucoform or NoTUG."
        )
        self.prompt.setAccessibleName("Codex prompt")
        self.prompt.setMinimumHeight(120)
        prompt_layout.addWidget(self.prompt)
        self.transfer_ack = QCheckBox(
            "I understand this prompt and relevant workspace data may be sent to my "
            "configured AI provider."
        )
        self.transfer_ack.setAccessibleName("Provider data transfer acknowledgement")
        prompt_layout.addWidget(self.transfer_ack)
        actions = QHBoxLayout()
        self.run_button = QPushButton("Create protected session and run")
        self.run_button.setObjectName("primaryButton")
        self.run_button.clicked.connect(self._start_run)
        self.cancel_button = QPushButton("Cancel agent")
        self.cancel_button.clicked.connect(self._cancel_run)
        self.cancel_button.setEnabled(False)
        actions.addWidget(self.run_button)
        actions.addWidget(self.cancel_button)
        actions.addStretch()
        prompt_layout.addLayout(actions)
        layout.addWidget(prompt_group)

        lifecycle = QGroupBox("Activity and recovery")
        lifecycle_layout = QVBoxLayout(lifecycle)
        self.activity = QPlainTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setAccessibleName("Normalized Codex activity")
        self.activity.setPlaceholderText(
            "Normalized progress appears here. Raw JSONL is not persisted."
        )
        self.activity.document().setMaximumBlockCount(300)
        lifecycle_layout.addWidget(self.activity)
        recovery = QHBoxLayout()
        self.freeze_button = QPushButton("Freeze partial work for review")
        self.freeze_button.clicked.connect(self._freeze_session)
        self.freeze_button.setEnabled(False)
        self.abandon_button = QPushButton("Close unchanged session")
        self.abandon_button.clicked.connect(self._abandon_session)
        self.abandon_button.setEnabled(False)
        self.retry_button = QPushButton("Retry in this session")
        self.retry_button.clicked.connect(self._retry_run)
        self.retry_button.setEnabled(False)
        recovery.addWidget(self.freeze_button)
        recovery.addWidget(self.abandon_button)
        recovery.addWidget(self.retry_button)
        recovery.addStretch()
        lifecycle_layout.addLayout(recovery)
        layout.addWidget(lifecycle, 1)

        pending_group = QGroupBox("Pending and recent sessions")
        pending_layout = QHBoxLayout(pending_group)
        self.sessions = QComboBox()
        self.sessions.setAccessibleName("Pending and recent sessions")
        self.sessions.currentIndexChanged.connect(self._session_selected)
        self.refresh_sessions_button = QPushButton("Refresh")
        self.refresh_sessions_button.clicked.connect(self._request_session_refresh)
        pending_layout.addWidget(self.sessions, 1)
        pending_layout.addWidget(self.refresh_sessions_button)
        layout.addWidget(pending_group)
        return page

    def _review_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        top = QHBoxLayout()
        back = QPushButton("← Composer")
        back.clicked.connect(lambda: self.pages.setCurrentIndex(0))
        title = QLabel("Verified Tug review")
        title.setObjectName("sectionTitle")
        top.addWidget(back)
        top.addWidget(title)
        top.addStretch()
        layout.addLayout(top)

        self.review_tabs = QTabWidget()
        self.review_summary = QTextBrowser()
        self.review_summary.setAccessibleName("Tug review summary")
        self.review_diff = QPlainTextEdit()
        self.review_diff.setReadOnly(True)
        self.review_diff.setAccessibleName("Sanitized Tug diff")
        self.review_tabs.addTab(self.review_summary, "Evidence")
        self.review_tabs.addTab(self.review_diff, "Diff")
        layout.addWidget(self.review_tabs, 1)

        ceremony = QGroupBox("Accessible three-face Grant ceremony")
        form = QVBoxLayout(ceremony)
        self.required_phrase = QLabel(
            "Review the evidence, then activate the three numbered companion faces in order. "
            "No single click can Grant a Tug."
        )
        self.required_phrase.setWordWrap(True)
        self.required_phrase.setAccessibleName("Three-face Grant instructions")
        form.addWidget(self.required_phrase)
        layout.addWidget(ceremony)

        actions = QHBoxLayout()
        self.grant_button = QPushButton("Begin three-face Grant")
        self.grant_button.setObjectName("primaryButton")
        self.grant_button.clicked.connect(self._begin_grant_ceremony)
        self.grant_button.setEnabled(False)
        self.deny_button = QPushButton("Deny Tug")
        self.deny_button.clicked.connect(self._deny)
        self.deny_button.setEnabled(False)
        self.archive_button = QPushButton("Archive disposed session")
        self.archive_button.clicked.connect(self._archive)
        self.archive_button.setEnabled(False)
        actions.addWidget(self.grant_button)
        actions.addWidget(self.deny_button)
        actions.addWidget(self.archive_button)
        actions.addStretch()
        layout.addLayout(actions)
        self.disposition_label = QLabel()
        self.disposition_label.setWordWrap(True)
        self.disposition_label.setAccessibleName("Disposition result")
        layout.addWidget(self.disposition_label)
        return page

    def _restore_settings(self, *, verify_codex: bool) -> None:
        recent = self.settings.value("repositories/recent", [])
        if isinstance(recent, str):
            recent = [recent]
        self.recent_repositories.blockSignals(True)
        try:
            for item in recent if isinstance(recent, list) else []:
                if isinstance(item, str):
                    self.recent_repositories.addItem(item)
        finally:
            self.recent_repositories.blockSignals(False)
        if verify_codex:
            selected_codex = self.settings.value("codex/path")
            try:
                self.codex = discover_codex(
                    Path(selected_codex) if isinstance(selected_codex, str) else None
                )
                self.codex_label.setText(
                    f"{self.codex.version} · {self.codex.source}\n{self.codex.display_path}"
                )
            except NoTugError as exc:
                self.codex_label.setText(exc.message)
        if self.recent_repositories.count():
            self._load_repository(Path(self.recent_repositories.itemText(0)))

    def _remember_repository(self, repository: Path) -> None:
        value = str(repository)
        values = [value]
        values.extend(
            self.recent_repositories.itemText(index)
            for index in range(self.recent_repositories.count())
            if self.recent_repositories.itemText(index) != value
        )
        values = values[:MAX_RECENT_REPOSITORIES]
        self.recent_repositories.blockSignals(True)
        self.recent_repositories.clear()
        self.recent_repositories.addItems(values)
        self.recent_repositories.setCurrentIndex(0)
        self.recent_repositories.blockSignals(False)
        self.settings.setValue("repositories/recent", values)

    def _represent_repository(self, repository: Path) -> Path:
        candidate = repository.expanduser().resolve()
        value = str(candidate)
        self.recent_repositories.blockSignals(True)
        try:
            index = self.recent_repositories.findText(value)
            if index < 0:
                self.recent_repositories.insertItem(0, value)
                index = 0
            self.recent_repositories.setCurrentIndex(index)
        finally:
            self.recent_repositories.blockSignals(False)
        return candidate

    def _recent_selected(self, value: str) -> None:
        if value:
            self._load_repository(Path(value))

    def _choose_repository(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Choose a Git repository")
        if selected:
            self._load_repository(Path(selected))

    def _load_repository(self, path: Path) -> None:
        if self._repository_verification_active:
            return
        self._session_refresh_timer.stop()
        self._repository_verification_active = True
        self.recent_repositories.setEnabled(False)
        self.browse_repository_button.setEnabled(False)
        try:
            candidate = self._represent_repository(path)
            self._repository_initialized = None
            status = repository_status(candidate)
            self.repository = candidate
            self._repository_initialized = status.initialized
            self._remember_repository(self.repository)
            if not status.clean:
                self.protection_label.setText(
                    "Repository recognized, but the protected checkout is dirty. "
                    "Commit, stash, or remove local changes before starting a governed run."
                )
                self.protect_button.hide()
                self._set_state(OrbState.ERROR)
                if status.initialized:
                    self._refresh_sessions()
                else:
                    self._clear_sessions()
                return
            if status.initialized:
                receipt = "verified" if status.receipt_chain_verified else "unavailable"
                self.protection_label.setText(
                    f"Protected · baseline {status.baseline_commit[:12]} · receipt chain {receipt}"
                )
                self.protect_button.hide()
                self._set_state(OrbState.READY)
                self._refresh_sessions()
            else:
                self.protection_label.setText(
                    "This repository is not protected yet. Initialization records its clean "
                    "baseline; it does not alter commits."
                )
                self.protect_button.show()
                self._set_state(OrbState.IDLE)
                self._clear_sessions()
        except NoTugError as exc:
            self.repository = None
            self._repository_initialized = None
            self._clear_sessions()
            self.protection_label.setText(_safe_error(exc))
            self.protect_button.hide()
            self._set_state(OrbState.ERROR)
        finally:
            self.recent_repositories.setEnabled(True)
            self.browse_repository_button.setEnabled(True)
            self._repository_verification_active = False

    def _protect_repository(self) -> None:
        if self.repository is None:
            return
        if (
            QMessageBox.question(
                self,
                "Enable NoTUG protection?",
                "Record this repository's current clean HEAD and policy as the protected baseline?",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            protect_repository(self.repository)
            self._load_repository(self.repository)
        except NoTugError as exc:
            self._show_error(exc)

    def _choose_codex(self) -> None:
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Select an existing Codex executable or codex.js",
            filter="Codex (codex codex.exe codex.cmd codex.ps1 codex.js);;All files (*)",
        )
        if not selected:
            return
        try:
            self.codex = discover_codex(Path(selected))
            self.codex_label.setText(
                f"{self.codex.version} · {self.codex.source}\n{self.codex.display_path}"
            )
            self.settings.setValue("codex/path", selected)
        except NoTugError as exc:
            self._show_error(exc)

    def _validate_composer(self) -> str | None:
        if self.repository is None:
            return "Choose a valid Git repository."
        try:
            status = repository_status(self.repository)
        except NoTugError as exc:
            return _safe_error(exc)
        if not status.initialized:
            return "Explicitly enable NoTUG protection first."
        if not status.clean:
            return "The protected checkout must be clean before a session starts."
        if self.codex is None:
            return "Select and verify a local Codex installation."
        if not self.prompt.toPlainText().strip():
            return "Enter a prompt for Codex."
        if not self.transfer_ack.isChecked():
            return "Acknowledge provider data transfer before launching Codex."
        return None

    def _start_run(self) -> None:
        if self.worker_thread is not None:
            self._show_message("One Leucoform-launched agent run is already active.")
            return
        problem = self._validate_composer()
        if problem:
            self._show_message(problem)
            return
        repository = self.repository
        codex = self.codex
        if repository is None or codex is None:
            self._show_message("Repository or Codex selection changed; validate again.")
            return
        prompt = self.prompt.toPlainText().strip().encode("utf-8")
        self.prompt.clear()
        self.transfer_ack.setChecked(False)
        try:
            name = f"leucoform-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
            session = create_session(repository, name)
            self.session_id = session.session_id
            self.activity.clear()
            self._append_activity(f"Protected session created: {session.session_id}")
            self._launch_worker(prompt)
        except NoTugError as exc:
            self._show_error(exc)

    def _retry_run(self) -> None:
        if self.session_id is None or self.worker_thread is not None:
            return
        if (
            self.codex is None
            or not self.prompt.toPlainText().strip()
            or not self.transfer_ack.isChecked()
        ):
            self._show_message("Enter the retry prompt and acknowledge provider data transfer.")
            return
        prompt = self.prompt.toPlainText().strip().encode("utf-8")
        self.prompt.clear()
        self.transfer_ack.setChecked(False)
        self._launch_worker(prompt)

    def _launch_worker(self, prompt: bytes) -> None:
        if self.session_id is None or self.codex is None:
            self._show_message("No protected session and verified Codex are available.")
            return
        self.cancel_event = threading.Event()
        self.worker_thread = QThread(self)
        self.worker = AgentWorker(
            self.session_id,
            build_codex_command(self.codex),
            prompt,
            self.cancel_event,
        )
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.activity.connect(self._append_activity)
        self.worker.warning.connect(lambda text: self._append_activity(f"Warning: {text}"))
        self.worker.completed.connect(self._run_completed)
        self.worker.failed.connect(self._run_failed)
        self.worker.completed.connect(self.worker_thread.quit)
        self.worker.failed.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self._worker_finished)
        self.cancel_button.setEnabled(True)
        self.run_button.setEnabled(False)
        self.freeze_button.setEnabled(False)
        self.abandon_button.setEnabled(False)
        self.retry_button.setEnabled(False)
        self._set_state(OrbState.WORKING)
        self.worker_thread.start()

    def _cancel_run(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.cancel_button.setEnabled(False)
            self._append_activity("Cancellation requested; NoTUG will record RUN_CANCELLED.")

    def _worker_finished(self) -> None:
        if self.worker is not None:
            self.worker.deleteLater()
        if self.worker_thread is not None:
            self.worker_thread.deleteLater()
        self.worker = None
        self.worker_thread = None
        self.cancel_event = None
        self.cancel_button.setEnabled(False)
        self.run_button.setEnabled(True)
        self._refresh_sessions()

    def _run_completed(self, result_object: object) -> None:
        if not isinstance(result_object, AgentRunResult):
            self._run_failed("Leucoform received an invalid Core result.")
            return
        if result_object.cancelled:
            self._append_activity(
                "Run cancelled. Any partial work remains retained for an explicit decision."
            )
            self._offer_recovery(OrbState.CANCELLED)
            return
        if result_object.exit_status != 0:
            self._append_activity(f"Codex exited with status {result_object.exit_status}.")
            self._offer_recovery()
            return
        if self.session_id is None:
            self._run_failed("The active protected session is unavailable.")
            return
        try:
            changes = session_change_status(self.session_id)
            if changes.changed:
                self._append_activity(
                    "Codex completed with changes; freezing verified evidence now."
                )
                self._freeze_session()
            else:
                self._append_activity(
                    "Codex completed without changes. Close as clean abandonment or retry."
                )
                self.freeze_button.setEnabled(False)
                self.abandon_button.setEnabled(True)
                self.retry_button.setEnabled(True)
                self._set_state(OrbState.READY)
        except NoTugError as exc:
            self._run_failed(_safe_error(exc))

    def _run_failed(self, message: str) -> None:
        self._append_activity(f"Evidence alert: {message}")
        self._offer_recovery()

    def _offer_recovery(self, state: OrbState = OrbState.ERROR) -> None:
        if self.session_id is None:
            self._set_state(OrbState.ERROR)
            return
        try:
            changed = session_change_status(self.session_id).changed
        except NoTugError:
            changed = True
        self.freeze_button.setEnabled(changed)
        self.abandon_button.setEnabled(not changed)
        self.retry_button.setEnabled(True)
        self._set_state(state)

    def _freeze_session(self) -> None:
        if self.session_id is None:
            return
        self._set_state(OrbState.VERIFYING)
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            result = submit_session(self.session_id)
            tug_id = str(result.tug["tug_id"])
            tug_hash = str(result.tug["tug_hash"])
            self.active_review = ActiveReview(self.session_id, tug_id, tug_hash)
            review = get_review_summary(tug_id, include_diff=True)
            self._render_review(review)
            self.pages.setCurrentIndex(1)
            self._set_state(OrbState.REVIEW)
            self.freeze_button.setEnabled(False)
            self.abandon_button.setEnabled(False)
            self.retry_button.setEnabled(False)
        except NoTugError as exc:
            self._show_error(exc)
            self._offer_recovery()
        finally:
            QApplication.restoreOverrideCursor()

    def _render_review(self, review: ReviewSummaryResult) -> None:
        tug = review.tug
        summary = tug["evidence"]["summary"]
        risk = tug["risk_summary"]
        findings = tug["policy"]["findings"]
        paths = tug["affected_paths"]
        changes = tug.get("changes", [])
        added_lines = sum(
            int(change.get("added_lines") or 0) for change in changes if isinstance(change, dict)
        )
        deleted_lines = sum(
            int(change.get("deleted_lines") or 0) for change in changes if isinstance(change, dict)
        )
        baseline = escape(str(tug["baseline"]["commit"]))
        receipt_count = escape(str(review.receipt_verification["event_count"]))
        receipt_hash = escape(str(review.receipt_verification["head_hash"]))
        grantable = "yes" if tug["grant"]["grantable"] else "no"
        baseline_verified = "yes" if review.baseline_verification.verified else "no"
        lines = [
            f"<h2>Tug {escape(str(tug['tug_id']))}</h2>",
            f"<p><b>Risk:</b> {escape(str(risk['overall_severity']))} &nbsp; "
            f"<b>Grantable:</b> {grantable}</p>",
            f"<p><b>Changes:</b> {summary['file_count']} files · "
            f"{summary['bytes_touched']} bytes touched · "
            f"{summary['patch_bytes']} patch bytes · "
            f"+{added_lines}/−{deleted_lines} lines</p>",
            f"<p><b>Protected baseline:</b> <code>{baseline}</code><br>",
            f"<b>Baseline verified:</b> {baseline_verified}<br>",
            f"<b>Receipt chain:</b> verified · {receipt_count} events · "
            f"<code>{receipt_hash}</code></p>",
            "<h3>Affected paths</h3><ul>",
            *(f"<li><code>{escape(sanitize_terminal(str(path)))}</code></li>" for path in paths),
            "</ul><h3>Policy findings</h3><ul>",
        ]
        if findings:
            lines.extend(
                f"<li><b>{escape(str(finding['severity']))}</b> · "
                f"{escape(str(finding['code']))}: "
                f"{escape(sanitize_terminal(str(finding['message'])))}</li>"
                for finding in findings
            )
        else:
            lines.append("<li>None</li>")
        lines.extend(
            [
                "</ul>",
                f"<h3>Tug hash</h3><p><code>{escape(str(tug['tug_hash']))}</code></p>",
            ]
        )
        self.review_summary.setHtml("".join(lines))
        self.review_diff.setPlainText(review.diff or "No textual diff available.")
        short_hash = str(tug["tug_hash"])
        self.required_phrase.setText(
            "Activate the three numbered companion faces in order to Grant this exact Tug: "
            f"{short_hash[:12]}…{short_hash[-8:]}"
        )
        self.required_phrase.setAccessibleDescription(
            "The companion binds all three accessible face activations to the complete "
            "exact Tug hash."
        )
        self.grant_button.setEnabled(True)
        self.deny_button.setEnabled(True)
        self.archive_button.setEnabled(False)
        self.disposition_label.clear()

    def _begin_grant_ceremony(self) -> None:
        if self.active_review is None or not self.deny_button.isEnabled():
            return
        self._set_state(OrbState.REVIEW)
        self.disposition_label.setText(
            "Grant is not issued yet. Activate companion faces 1, 2, and 3 in order."
        )

    def _grant_from_faces(self) -> None:
        if self.active_review is None:
            return
        self._set_state(OrbState.VERIFYING)
        try:
            confirmation = f"GRANT {self.active_review.tug_hash}"
            result = grant_reviewed_tug(self.active_review.tug_id, confirmation)
            branch = result.data.get("integration_branch", result.data.get("branch", "created"))
            commit = result.data.get("integration_commit", result.data.get("commit", "verified"))
            self.disposition_label.setText(
                f"Integrated and verified. Branch: {branch} · commit: {commit}"
            )
            self.grant_button.setEnabled(False)
            self.deny_button.setEnabled(False)
            self.archive_button.setEnabled(True)
            self._set_state(OrbState.INTEGRATED)
        except NoTugError as exc:
            self._show_error(exc)

    def _deny(self) -> None:
        if self.active_review is None:
            return
        if (
            QMessageBox.warning(
                self,
                "Deny this Tug?",
                "Record a final denial for this exact Tug? The disposable worktree "
                "remains until separately archived.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            deny_reviewed_tug(self.active_review.tug_id)
            self.disposition_label.setText(
                "Tug denied. Archive remains a separate explicit action."
            )
            self.grant_button.setEnabled(False)
            self.deny_button.setEnabled(False)
            self.archive_button.setEnabled(True)
            self._set_state(OrbState.DENIED)
        except NoTugError as exc:
            self._show_error(exc)

    def _abandon_session(self) -> None:
        if self.session_id is None:
            return
        if (
            QMessageBox.question(
                self,
                "Close unchanged session?",
                "Verify the managed worktree is unchanged and record the ABANDONED "
                "disposition? Archival remains separate.",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            abandon_unchanged_session(self.session_id)
            self.abandon_button.setEnabled(False)
            self.retry_button.setEnabled(False)
            self.archive_button.setEnabled(True)
            self.disposition_label.setText(
                "Clean session marked ABANDONED. It has not been archived yet."
            )
            self.pages.setCurrentIndex(1)
            self._set_state(OrbState.ABANDONED)
        except NoTugError as exc:
            self._show_error(exc)

    def _archive(self) -> None:
        session_id = self.active_review.session_id if self.active_review else self.session_id
        if session_id is None:
            return
        if (
            QMessageBox.question(
                self,
                "Archive disposed session?",
                "Remove this already disposed managed worktree? Authoritative receipts "
                "and review evidence are retained.",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            archive_disposed_session(session_id)
            self.archive_button.setEnabled(False)
            self.disposition_label.setText(
                f"Session {session_id} explicitly archived; evidence retained."
            )
            self._refresh_sessions()
        except NoTugError as exc:
            self._show_error(exc)

    def _clear_sessions(self) -> None:
        self.sessions.blockSignals(True)
        try:
            self.sessions.clear()
        finally:
            self.sessions.blockSignals(False)

    def _request_session_refresh(self) -> None:
        if self._repository_verification_active or self._session_refresh_active:
            return
        self._session_refresh_timer.start()

    def _refresh_sessions(self) -> None:
        if self._session_refresh_active:
            return
        self._session_refresh_active = True
        self.refresh_sessions_button.setEnabled(False)
        self.sessions.blockSignals(True)
        try:
            self.sessions.clear()
            if self.repository is not None and self._repository_initialized is not False:
                result = list_repository_sessions(self.repository)
                self.sessions.addItem("Choose a session…", None)
                for item in result.sessions:
                    status = item.status
                    label = (
                        f"{item.name} · {status.state}{' · archived' if status.archived else ''}"
                    )
                    self.sessions.addItem(label, status.to_dict())
        except NoTugError:
            pass
        finally:
            self.sessions.blockSignals(False)
            self.refresh_sessions_button.setEnabled(True)
            self._session_refresh_active = False

    def _session_selected(self, index: int) -> None:
        data = self.sessions.itemData(index)
        if not isinstance(data, dict):
            return
        self.session_id = str(data["session_id"])
        tug_id = data.get("tug_id")
        if isinstance(tug_id, str):
            try:
                review = get_review_summary(tug_id, include_diff=True)
                self.active_review = ActiveReview(
                    self.session_id, tug_id, str(review.tug["tug_hash"])
                )
                self._render_review(review)
                protocol_state = str(data["state"])
                disposed = protocol_state in {"APPLIED", "DENIED", "REVOKED"}
                self.archive_button.setEnabled(disposed and not bool(data["archived"]))
                self.deny_button.setEnabled(protocol_state == "TUGGED")
                self.pages.setCurrentIndex(1)
                presentation = {
                    "TUGGED": OrbState.REVIEW,
                    "GRANTED": OrbState.VERIFYING,
                    "APPLIED": OrbState.INTEGRATED,
                    "DENIED": OrbState.DENIED,
                    "REVOKED": OrbState.DENIED,
                    "DIVERGED": OrbState.DIVERGED,
                    "FAILED": OrbState.ERROR,
                }.get(protocol_state, OrbState.READY)
                self._set_state(presentation)
            except NoTugError as exc:
                self._show_error(exc)
        elif str(data["state"]) == "ABANDONED":
            self.active_review = None
            self.archive_button.setEnabled(not bool(data["archived"]))
            self.disposition_label.setText(
                "Clean session is ABANDONED. Archival remains a separate explicit action."
            )
            self.pages.setCurrentIndex(1)
            self._set_state(OrbState.ABANDONED)

    def _append_activity(self, text: str) -> None:
        self.activity.appendPlainText(sanitize_terminal(text))

    def _set_state(self, state: OrbState) -> None:
        self._state = state
        appearance = appearance_for(state)
        self.status_label.setText(f"{appearance.glyph}  {appearance.label}")
        self.status_label.setAccessibleDescription(appearance.label)
        foreground = "#172033" if appearance.luminous else "white"
        self.status_label.setStyleSheet(
            f"background:{appearance.color}; color:{foreground}; border-radius:12px; "
            "padding:5px 10px; font-weight:600;"
        )
        self.state_changed.emit(state)

    def _set_reduced_motion(self, enabled: bool) -> None:
        self.settings.setValue("ui/reduced_motion", enabled)
        self.reduced_motion_changed.emit(enabled)

    def _show_error(self, exc: BaseException) -> None:
        divergent_codes = {
            "PROVENANCE_DIVERGENCE",
            "REPOSITORY_DIVERGED",
            "SESSION_DIVERGED",
        }
        state = (
            OrbState.DIVERGED
            if isinstance(exc, NoTugError) and exc.code in divergent_codes
            else OrbState.ERROR
        )
        self._set_state(state)
        QMessageBox.critical(self, "Leucoform", _safe_error(exc))

    def _show_message(self, message: str) -> None:
        QMessageBox.information(self, "Leucoform", message)

    def activate(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self.tray_available or self.companion_owned:
            event.ignore()
            self.hide()
        else:
            event.accept()


class SingleInstanceServer(QObject):
    activated = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.server = QLocalServer(self)
        QLocalServer.removeServer(INSTANCE_NAME)
        if not self.server.listen(INSTANCE_NAME):
            raise RuntimeError(self.server.errorString())
        self.server.newConnection.connect(self._read_activation)

    def _read_activation(self) -> None:
        socket = self.server.nextPendingConnection()
        if socket is not None:
            socket.waitForReadyRead(250)
            socket.readAll()
            socket.disconnectFromServer()
        self.activated.emit()


def _notify_existing_instance() -> bool:
    socket = QLocalSocket()
    socket.connectToServer(INSTANCE_NAME)
    if not socket.waitForConnected(300):
        return False
    socket.write(b"activate")
    socket.flush()
    socket.waitForBytesWritten(300)
    socket.disconnectFromServer()
    return True


def _stylesheet() -> str:
    return """
    QWidget { font-size: 13px; }
    QMainWindow { background: palette(window); }
    QLabel#title { font-size: 27px; font-weight: 700; }
    QLabel#subtitle { color: palette(mid); margin-left: 8px; }
    QLabel#sectionTitle { font-size: 20px; font-weight: 650; }
    QGroupBox { font-weight: 650; border: 1px solid palette(mid);
                border-radius: 10px; margin-top: 9px; padding-top: 10px; }
    QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; }
    QPushButton { min-height: 30px; padding: 3px 12px; }
    QPushButton#primaryButton { font-weight: 700; }
    QPlainTextEdit, QTextBrowser, QLineEdit, QComboBox {
        border: 1px solid palette(mid); border-radius: 6px; padding: 5px;
    }
    """


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv if argv is None else argv)
    self_test = "--self-test" in arguments
    self_test_repository: Path | None = None
    if "--self-test-repository" in arguments:
        repository_index = arguments.index("--self-test-repository")
        if repository_index + 1 >= len(arguments):
            return 2
        self_test_repository = Path(arguments[repository_index + 1])
        del arguments[repository_index : repository_index + 2]
        self_test = True
    if self_test:
        if "--self-test" in arguments:
            arguments.remove("--self-test")
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    QCoreApplication.setOrganizationName("Leucoform")
    QCoreApplication.setOrganizationDomain("local.leucoform")
    QCoreApplication.setApplicationName("Leucoform")
    app = QApplication(arguments)
    app.aboutToQuit.connect(terminate_active_git_processes)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationDisplayName(DESKTOP_TAGLINE)
    app.setApplicationVersion(VERSION)
    app.setWindowIcon(_make_icon(OrbState.IDLE))
    app.setStyleSheet(_stylesheet())
    if self_test:
        with tempfile.TemporaryDirectory(prefix="leucoform-self-test-") as temporary:
            settings = QSettings(
                str(Path(temporary) / "settings.ini"),
                QSettings.Format.IniFormat,
            )
            window = MainWindow(
                settings,
                tray_available=False,
                companion_owned=True,
                verify_codex_on_start=False,
            )
            self_test_orb = OrbWidget(settings)
            self_test_orb.show()
            window.show()
            app.processEvents()
            window.close()
            app.processEvents()
            ok = (
                window.prompt.accessibleName() == "Codex prompt"
                and "Leucoform" in window.windowTitle()
                and not window.isVisible()
                and self_test_orb.isVisible()
            )
            if self_test_repository is not None:
                expected = str(self_test_repository.expanduser().resolve())
                window._load_repository(self_test_repository)
                represented = window.recent_repositories.currentText() == expected
                if not represented:
                    ok = False
                elif window.repository is None:
                    self_test_orb.close()
                    window.companion_owned = False
                    window.close()
                    return 2
            self_test_orb.close()
            window.companion_owned = False
            window.close()
            if not ok:
                return 1
            if (
                self_test_repository is not None
                and os.environ.get("LEUCOFORM_GOVERNED_SELF_TEST") == "1"
            ):
                return run_packaged_governed_self_test(self_test_repository.expanduser().resolve())
            return 0
    if _notify_existing_instance():
        return 0
    instance = SingleInstanceServer()
    tray_available = QSystemTrayIcon.isSystemTrayAvailable()
    platform = QApplication.platformName().casefold()
    compact_fallback = (
        platform in {"offscreen", "minimal"} or os.environ.get("LEUCOFORM_COMPACT_WINDOW") == "1"
    )
    test_settings_file = os.environ.get("LEUCOFORM_TEST_SETTINGS_FILE")
    settings = (
        QSettings(str(Path(test_settings_file).expanduser().resolve()), QSettings.Format.IniFormat)
        if test_settings_file
        else QSettings()
    )
    window = MainWindow(
        settings,
        tray_available=tray_available,
        companion_owned=not compact_fallback,
    )
    instance.activated.connect(window.activate)

    tray: QSystemTrayIcon | None = None
    orb: OrbWidget | None = None
    if compact_fallback and not tray_available:
        app.setQuitOnLastWindowClosed(True)
    if tray_available:
        tray = QSystemTrayIcon(_make_icon(OrbState.IDLE), app)
        tray.setToolTip(DESKTOP_TAGLINE)
        tray.activated.connect(lambda _reason: window.activate())
        tray_menu = QMenu()
        open_action = tray_menu.addAction("Open recovery tools")
        open_action.triggered.connect(window.activate)
        quit_action = tray_menu.addAction("Quit Leucoform")
        quit_action.triggered.connect(app.quit)
        tray.setContextMenu(tray_menu)
        tray.show()
        window.state_changed.connect(lambda state: tray.setIcon(_make_icon(state)))
        window.state_changed.connect(
            lambda state: tray.setToolTip(f"Leucoform — {appearance_for(state).label}")
        )
    if not compact_fallback:
        orb = OrbWidget(settings)
        orb.activated.connect(window.activate)
        orb.recovery_requested.connect(window.activate)
        orb.quit_requested.connect(app.quit)
        orb.consent_completed.connect(window._grant_from_faces)
        window.state_changed.connect(orb.set_state)
        window.reduced_motion_changed.connect(orb.set_reduced_motion)
        orb.restore_position()
        orb.show()
    else:
        window.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        window.resize(760, 620)
        window.show()
    # Locals intentionally remain in scope for the duration of the native event loop.
    _retained = (instance, window, tray, orb)
    del _retained
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
