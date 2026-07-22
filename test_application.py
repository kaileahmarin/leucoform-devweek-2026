from __future__ import annotations

import inspect
import unittest
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from notug_protocol import application, cli


class ApplicationServiceTests(unittest.TestCase):
    def test_diagnostics_are_typed_without_terminal_formatting(self) -> None:
        raw = {
            "ok": False,
            "mutation_lock": "active",
            "repository": "fixture-repository",
            "findings": [
                {
                    "code": "SOURCE_REPOSITORY_DIRTY",
                    "severity": "error",
                    "message": "Protected repository is dirty",
                }
            ],
        }
        with patch.object(application, "diagnose", return_value=raw):
            result = application.diagnose_repository(Path("."))

        self.assertFalse(result.ok)
        self.assertEqual(result.findings[0].code, "SOURCE_REPOSITORY_DIRTY")
        self.assertEqual(result.to_dict(), raw)

    def test_review_service_returns_only_verified_facts_without_cli_dependency(self) -> None:
        tug = {"tug_id": "tug_aaaaaaaaaaaaaaaa", "session_id": "session_aaaaaaaaaaaaaaaa"}
        session = {"state": "TUGGED"}
        chain = SimpleNamespace(count=3, head_hash="a" * 64, events=(object(),))
        ledger = SimpleNamespace(verify=lambda: chain)

        with (
            patch.object(application, "find_tug", return_value=("repo_aaaaaaaaaaaaaaaa", tug)),
            patch.object(application, "verify_tug_artifacts"),
            patch.object(application, "ledger_for", return_value=ledger),
            patch.object(
                application,
                "find_session",
                return_value=("repo_aaaaaaaaaaaaaaaa", session),
            ),
            patch.object(application, "verify_session_receipt_head") as verify_receipt,
            patch.object(application, "verify_authoritative_baseline"),
        ):
            result = application.get_review_summary("tug_aaaaaaaaaaaaaaaa")

        self.assertNotIn("commands", {field.name for field in fields(type(result))})
        self.assertNotIn("commands", result.to_dict())
        self.assertFalse(hasattr(application, "CLI_NAME"))
        source = inspect.getsource(application)
        self.assertNotIn("from .cli", source)
        self.assertNotIn("CLI_NAME", source)
        self.assertNotIn("notug grant", repr(result.to_dict()))
        self.assertNotIn("notug deny", repr(result.to_dict()))
        self.assertEqual(result.session_state, "TUGGED")
        verify_receipt.assert_called_once_with(session, chain.events)

    def test_create_session_service_returns_exact_core_worktree(self) -> None:
        core_result = SimpleNamespace(
            repository_id="repo_aaaaaaaaaaaaaaaa",
            session_id="session_aaaaaaaaaaaaaaaa",
            worktree=Path("managed-worktree"),
            baseline_commit="a" * 40,
            policy_hash="b" * 64,
        )
        vault = object()
        with patch.object(application, "start_session", return_value=core_result) as service:
            result = application.create_session(Path("fixture-repository"), "proposal", vault)  # type: ignore[arg-type]

        service.assert_called_once_with(Path("fixture-repository"), "proposal", vault)
        self.assertEqual(result.session_id, "session_aaaaaaaaaaaaaaaa")
        self.assertEqual(result.worktree, "managed-worktree")
        self.assertEqual(result.state, "SESSION_OPEN")
        self.assertEqual(result.mutation_lock, "active")

    def test_cli_preserves_legacy_review_shape_and_adds_its_own_commands(self) -> None:
        result = application.ReviewSummaryResult(
            tug={"tug_id": "tug_aaaaaaaaaaaaaaaa"},
            session_state="TUGGED",
            baseline_verification=application.BaselineStatus(verified=True, error_code=None),
            receipt_verification={"verified": True},
        )

        with patch.object(cli, "get_review_summary", return_value=result):
            data = cli._review_data("tug_aaaaaaaaaaaaaaaa", False)

        self.assertNotIn("session_state", data)
        self.assertEqual(
            data["commands"],
            {
                "grant": "notug grant tug_aaaaaaaaaaaaaaaa",
                "deny": "notug deny tug_aaaaaaaaaaaaaaaa",
            },
        )


if __name__ == "__main__":
    unittest.main()
