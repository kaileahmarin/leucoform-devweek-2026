from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QSettings
    from PySide6.QtGui import QFont
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
except ImportError as exc:  # pragma: no cover - Core-only environments intentionally skip Qt.
    raise unittest.SkipTest("PySide6 desktop extra is not installed") from exc

from notug_protocol.application import (
    AgentRunResult,
    RepositorySessionsResult,
    RepositoryStatusResult,
    SessionChangeResult,
)
from notug_protocol.desktop.main import (
    ActiveReview,
    AgentWorker,
    LegacyOrbWidget,
    MainWindow,
    OrbWidget,
    _make_icon,
)
from notug_protocol.desktop.state import OrbState, appearance_for
from notug_protocol.errors import NoTugError


class DesktopQtTests(unittest.TestCase):
    app: QApplication

    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="leucoform-qt-")
        self.settings = QSettings(
            str(Path(self.temporary.name) / "settings.ini"),
            QSettings.Format.IniFormat,
        )
        with patch(
            "notug_protocol.desktop.main.discover_codex",
            side_effect=NoTugError("CODEX_NOT_FOUND", "not configured"),
        ):
            self.window = MainWindow(self.settings, tray_available=False)

    def tearDown(self) -> None:
        self.window.companion_owned = False
        self.window.close()
        self.settings.clear()
        self.settings.sync()
        self.temporary.cleanup()

    def test_composer_has_keyboard_and_screen_reader_labels(self) -> None:
        self.assertEqual(self.window.prompt.accessibleName(), "Codex prompt")
        self.assertEqual(
            self.window.transfer_ack.accessibleName(),
            "Provider data transfer acknowledgement",
        )
        self.assertIn("Leucoform", self.window.windowTitle())
        self.assertFalse(self.window.cancel_button.isEnabled())
        self.assertEqual(self.window._validate_composer(), "Choose a valid Git repository.")

    def test_review_exposes_three_face_ceremony_without_hash_entry(self) -> None:
        tug_hash = "a" * 64
        self.window.active_review = ActiveReview("session_test", "tug_test", tug_hash)
        self.window.deny_button.setEnabled(True)
        self.window.grant_button.setEnabled(True)
        self.window._begin_grant_ceremony()
        self.assertEqual(self.window._state, OrbState.REVIEW)
        self.assertFalse(hasattr(self.window, "grant_phrase"))

    def test_orb_exposes_glyph_label_and_reduced_motion(self) -> None:
        orb = OrbWidget(self.settings)
        try:
            orb.set_state(OrbState.REVIEW)
            self.assertEqual(
                orb.accessibleDescription(),
                "Human review required; three-part Grant ceremony available",
            )
            self.assertTrue(all(not button.isHidden() for button in orb.consent_faces))
            orb.set_reduced_motion(True)
            self.assertTrue(orb.canvas.reduced_motion)
            self.assertTrue(self.settings.value("ui/reduced_motion", type=bool))
        finally:
            orb.close()

    def test_companion_and_fallback_renderers_never_draw_a_central_status_glyph(self) -> None:
        text_calls: list[tuple[object, ...]] = []

        class RecordingPainter:
            class RenderHint:
                Antialiasing = object()

            def __init__(self, device: object) -> None:
                self.device = device

            def font(self) -> QFont:
                return QFont()

            def drawText(self, *arguments: object) -> None:  # noqa: N802
                text_calls.append(arguments)

            def __getattr__(self, _name: str) -> object:
                return lambda *_arguments, **_keywords: None

        orb = OrbWidget(self.settings)
        legacy_orb = LegacyOrbWidget(self.settings)
        try:
            with (
                patch("notug_protocol.desktop.companion.QPainter", RecordingPainter),
                patch("notug_protocol.desktop.main.QPainter", RecordingPainter),
            ):
                for state in OrbState:
                    orb.canvas.set_state(state)
                    orb.canvas.paintEvent(None)
                    legacy_orb.set_state(state)
                    legacy_orb.paintEvent(None)
                    _make_icon(state)
            self.assertEqual(text_calls, [])
        finally:
            orb.close()
            legacy_orb.close()

    def test_status_meaning_remains_in_accessibility_tooltips_and_recovery_text(self) -> None:
        orb = OrbWidget(self.settings)
        try:
            self.assertEqual(orb.accessibleName(), "Leucoform provenance companion")
            for state in OrbState:
                appearance = appearance_for(state)
                orb.set_state(state)
                self.window._set_state(state)
                self.assertEqual(orb.accessibleDescription(), appearance.label)
                self.assertIn(appearance.label, orb.toolTip())
                self.assertIn(appearance.glyph, self.window.status_label.text())
                self.assertIn(appearance.label, self.window.status_label.text())
        finally:
            orb.close()

    def test_agent_worker_keeps_stderr_diagnostics_out_of_jsonl_activity(self) -> None:
        worker = AgentWorker(
            "session_aaaaaaaaaaaaaaaa",
            ("codex.exe",),
            b"prompt",
            threading.Event(),
        )
        activity: list[str] = []
        warnings: list[str] = []
        worker.activity.connect(activity.append)
        worker.warning.connect(warnings.append)

        worker._stdout(
            '{"type":"item.completed","item":{"text":"structured progress"}}\n'
            '{"type":"turn.completed"}\n'
        )
        worker._stderr("model-cache warning\n")

        self.assertIn("structured progress", activity)
        self.assertTrue(all("malformed" not in item.casefold() for item in activity))
        self.assertTrue(all("model-cache warning" not in item for item in activity))
        self.assertEqual(warnings, [r"model-cache warning\u000a"])

    def test_agent_no_changes_message_cannot_override_authoritative_git_changes(self) -> None:
        self.window.session_id = "session_aaaaaaaaaaaaaaaa"
        self.window._append_activity("Codex reported completion without changes.")
        result = AgentRunResult(1, "operation_aaaaaaaaaaaaaaaa", 0, False)
        authoritative = SessionChangeResult(1, self.window.session_id, True)

        with (
            patch(
                "notug_protocol.desktop.main.session_change_status",
                return_value=authoritative,
            ) as status,
            patch.object(self.window, "_freeze_session") as freeze,
        ):
            self.window._run_completed(result)

        status.assert_called_once_with(self.window.session_id)
        freeze.assert_called_once_with()
        self.assertIn("freezing verified evidence", self.window.activity.toPlainText())

    def test_failed_changed_session_enables_freeze_and_disables_clean_abandonment(self) -> None:
        self.window.session_id = "session_aaaaaaaaaaaaaaaa"
        result = AgentRunResult(1, "operation_aaaaaaaaaaaaaaaa", 7, False)
        authoritative = SessionChangeResult(1, self.window.session_id, True)

        with patch(
            "notug_protocol.desktop.main.session_change_status",
            return_value=authoritative,
        ):
            self.window._run_completed(result)

        self.assertTrue(self.window.freeze_button.isEnabled())
        self.assertFalse(self.window.abandon_button.isEnabled())
        self.assertTrue(self.window.retry_button.isEnabled())
        self.assertEqual(self.window._state, OrbState.ERROR)

    def test_failed_freeze_reconciles_changed_session_actions(self) -> None:
        self.window.session_id = "session_aaaaaaaaaaaaaaaa"
        authoritative = SessionChangeResult(1, self.window.session_id, True)

        with (
            patch(
                "notug_protocol.desktop.main.submit_session",
                side_effect=NoTugError("WORKSPACE_SCAN_FAILED", "unreadable proposal"),
            ),
            patch(
                "notug_protocol.desktop.main.session_change_status",
                return_value=authoritative,
            ),
            patch("notug_protocol.desktop.main.QMessageBox.critical"),
        ):
            self.window._freeze_session()

        self.assertTrue(self.window.freeze_button.isEnabled())
        self.assertFalse(self.window.abandon_button.isEnabled())
        self.assertTrue(self.window.retry_button.isEnabled())

    def test_three_distinct_faces_are_required_in_order(self) -> None:
        orb = OrbWidget(self.settings)
        completions: list[bool] = []
        orb.consent_completed.connect(lambda: completions.append(True))
        try:
            orb.set_state(OrbState.REVIEW)
            first, second, third = orb.consent_faces
            orb._select_face(second)
            self.assertFalse(second.selected)
            orb._select_face(first)
            orb._select_face(first)
            self.assertEqual(completions, [])
            orb._select_face(second)
            orb._select_face(third)
            self.assertEqual(completions, [True])
            self.assertTrue(all(face.selected for face in orb.consent_faces))
        finally:
            orb.close()

    def test_companion_size_is_clamped_to_accessible_range(self) -> None:
        self.settings.setValue("ui/companion_size", 999)
        orb = OrbWidget(self.settings)
        try:
            self.assertEqual(orb.width(), 300)
            self.assertEqual(orb.height(), 300)
        finally:
            orb.close()

    def test_recovery_window_close_hides_only_window_when_companion_owns_app(self) -> None:
        orb = OrbWidget(self.settings)
        try:
            self.window.companion_owned = True
            orb.show()
            self.window.show()
            self.app.processEvents()

            self.window.close()
            self.app.processEvents()

            self.assertFalse(self.window.isVisible())
            self.assertTrue(orb.isVisible())
        finally:
            orb.close()

    def test_companion_context_menu_exposes_recovery_and_explicit_quit(self) -> None:
        orb = OrbWidget(self.settings)
        recovery_requests: list[bool] = []
        quit_requests: list[bool] = []
        orb.recovery_requested.connect(lambda: recovery_requests.append(True))
        orb.quit_requested.connect(lambda: quit_requests.append(True))
        try:
            actions = [action for action in orb._context_menu.actions() if not action.isSeparator()]
            self.assertEqual(
                [action.text() for action in actions],
                ["Open recovery tools", "Quit Leucoform"],
            )
            actions[0].trigger()
            actions[1].trigger()
            self.assertEqual(recovery_requests, [True])
            self.assertEqual(quit_requests, [True])
        finally:
            orb.close()

    def test_failed_repository_selection_remains_visible_and_unavailable(self) -> None:
        selected = Path(self.temporary.name) / "not-a-repository"
        selected.mkdir()
        with patch(
            "notug_protocol.desktop.main.repository_status",
            side_effect=NoTugError(
                "NOT_A_GIT_REPOSITORY", "NoTUG 0.1.0 requires a Git working tree"
            ),
        ):
            self.window._load_repository(selected)

        self.assertEqual(self.window.recent_repositories.currentText(), str(selected.resolve()))
        self.assertIsNone(self.window.repository)
        self.assertIn("NOT_A_GIT_REPOSITORY", self.window.protection_label.text())
        self.assertEqual(self.window._state, OrbState.ERROR)
        self.assertEqual(self.window._validate_composer(), "Choose a valid Git repository.")

    def test_real_clean_git_repository_is_accepted_by_repository_control(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git is not installed")
        repository = Path(self.temporary.name) / "repository"
        repository.mkdir()

        def run_git(*arguments: str) -> None:
            subprocess.run(
                (git, "-C", str(repository), *arguments),
                check=True,
                capture_output=True,
                shell=False,
            )

        run_git("init", "--initial-branch=main")
        run_git("config", "user.name", "Leucoform Test")
        run_git("config", "user.email", "leucoform@example.invalid")
        (repository / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        run_git("add", "--all")
        run_git("commit", "-m", "baseline")
        vault = Path(self.temporary.name) / "vault"
        with patch.dict(os.environ, {"NOTUG_HOME": str(vault)}, clear=False):
            self.window._load_repository(repository)

        self.assertEqual(self.window.repository, repository.resolve())
        self.assertEqual(self.window.recent_repositories.currentText(), str(repository.resolve()))
        self.assertIn("not protected yet", self.window.protection_label.text())
        self.assertEqual(self.window._state, OrbState.IDLE)

    @staticmethod
    def repository_status_result(
        *, clean: bool = True, initialized: bool = False
    ) -> RepositoryStatusResult:
        return RepositoryStatusResult(
            schema_version=1,
            repository_id="repository_test" if initialized else None,
            initialized=initialized,
            baseline_commit="a" * 40,
            branch="main",
            clean=clean,
            worktree_count=1,
            receipt_chain_verified=True if initialized else None,
            receipt_event_count=1 if initialized else None,
        )

    def test_remembered_repository_is_verified_once_at_startup(self) -> None:
        repository = Path(self.temporary.name) / "remembered"
        repository.mkdir()
        settings = QSettings(
            str(Path(self.temporary.name) / "remembered-settings.ini"),
            QSettings.Format.IniFormat,
        )
        settings.setValue("repositories/recent", [str(repository)])
        settings.sync()
        with patch(
            "notug_protocol.desktop.main.repository_status",
            return_value=self.repository_status_result(),
        ) as status_probe:
            remembered_window = MainWindow(
                settings,
                tray_available=False,
                verify_codex_on_start=False,
            )
        try:
            status_probe.assert_called_once_with(repository.resolve())
            self.assertEqual(
                remembered_window.recent_repositories.currentText(), str(repository.resolve())
            )
        finally:
            remembered_window.companion_owned = False
            remembered_window.close()

    def test_repository_verification_cannot_recursively_trigger_itself(self) -> None:
        repository = Path(self.temporary.name) / "outer"
        nested = Path(self.temporary.name) / "nested"
        repository.mkdir()
        nested.mkdir()

        def probe(_candidate: Path) -> RepositoryStatusResult:
            self.window._load_repository(nested)
            return self.repository_status_result()

        with patch("notug_protocol.desktop.main.repository_status", side_effect=probe) as status:
            self.window._load_repository(repository)

        status.assert_called_once_with(repository.resolve())
        self.assertEqual(self.window.repository, repository.resolve())
        self.assertEqual(self.window.recent_repositories.currentText(), str(repository.resolve()))

    def test_dirty_unprotected_repository_does_not_start_session_refresh(self) -> None:
        repository = Path(self.temporary.name) / "dirty"
        repository.mkdir()
        with (
            patch(
                "notug_protocol.desktop.main.repository_status",
                return_value=self.repository_status_result(clean=False),
            ),
            patch("notug_protocol.desktop.main.list_repository_sessions") as session_probe,
        ):
            self.window._load_repository(repository)

        session_probe.assert_not_called()
        self.assertEqual(self.window.repository, repository.resolve())
        self.assertEqual(self.window._state, OrbState.ERROR)

    def test_repeated_refreshes_are_debounced_and_do_not_overlap(self) -> None:
        repository = Path(self.temporary.name) / "protected"
        repository.mkdir()
        self.window.repository = repository.resolve()
        self.window._repository_initialized = True
        empty = RepositorySessionsResult(1, "repository_test", ())

        def refresh(_repository: Path) -> RepositorySessionsResult:
            self.window._refresh_sessions()
            return empty

        with patch(
            "notug_protocol.desktop.main.list_repository_sessions", side_effect=refresh
        ) as session_probe:
            for _index in range(8):
                self.window.refresh_sessions_button.click()
            QTest.qWait(250)
            self.app.processEvents()

        session_probe.assert_called_once_with(repository.resolve())
        self.assertFalse(self.window._session_refresh_active)

    def test_refresh_of_known_unprotected_repository_launches_no_session_probe(self) -> None:
        repository = Path(self.temporary.name) / "unprotected"
        repository.mkdir()
        self.window.repository = repository.resolve()
        self.window._repository_initialized = False
        with patch("notug_protocol.desktop.main.list_repository_sessions") as session_probe:
            for _index in range(5):
                self.window.refresh_sessions_button.click()
            QTest.qWait(250)
            self.app.processEvents()

        session_probe.assert_not_called()
        self.assertFalse(self.window._session_refresh_active)


if __name__ == "__main__":
    unittest.main()
