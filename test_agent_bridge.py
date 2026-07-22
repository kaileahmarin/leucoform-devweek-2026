from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from notug_protocol import agent_bridge
from notug_protocol.application import (
    BaselineStatus,
    RepositoryStatusResult,
    ReviewSummaryResult,
    SessionCreationResult,
    VerificationResult,
)


class AgentBridgeTests(unittest.TestCase):
    def request(
        self,
        operation: str,
        parameters: dict[str, object] | None = None,
        *,
        schema_version: int = 1,
    ) -> dict[str, object]:
        return {
            "schema_version": schema_version,
            "operation_id": "op_test_1",
            "operation": operation,
            "parameters": parameters or {},
        }

    def test_capabilities_are_versioned_and_expose_no_human_authorization(self) -> None:
        response = agent_bridge.handle_request(self.request("capabilities"))

        self.assertTrue(response["ok"])
        self.assertEqual(response["schema_version"], 1)
        self.assertEqual(response["operation_id"], "op_test_1")
        self.assertFalse(response["data"]["human_authorization_operations_exposed"])
        self.assertNotIn("grant", response["data"]["operations"])
        self.assertTrue(response["data"]["operations"]["create_session"]["available"])
        self.assertEqual(
            response["data"]["operations"]["create_session"]["authority"],
            "non_authorizing_write",
        )

    def test_unknown_version_fails_closed(self) -> None:
        response = agent_bridge.handle_request(self.request("capabilities", schema_version=2))

        self.assertFalse(response["ok"])
        self.assertEqual(response["outcome"], "failed_closed")
        self.assertEqual(response["error"]["code"], "BRIDGE_VERSION_UNSUPPORTED")

    def test_unknown_fields_and_malformed_parameters_fail_closed(self) -> None:
        unknown = self.request("capabilities")
        unknown["surprise"] = True
        unknown_response = agent_bridge.handle_request(unknown)
        malformed_response = agent_bridge.handle_request(
            self.request("session_state", {"session_id": 7})
        )

        self.assertEqual(unknown_response["error"]["code"], "BRIDGE_REQUEST_INVALID")
        self.assertEqual(malformed_response["error"]["code"], "BRIDGE_REQUEST_INVALID")
        self.assertEqual(malformed_response["outcome"], "failed_closed")

    def test_foundation_slice_refuses_defined_authority_operation(self) -> None:
        response = agent_bridge.handle_request(
            self.request("submit_changes", {"session_id": "session_aaaaaaaaaaaaaaaa"})
        )

        self.assertFalse(response["ok"])
        self.assertEqual(response["outcome"], "unavailable")
        self.assertEqual(response["error"]["code"], "BRIDGE_OPERATION_UNAVAILABLE")

    def test_create_session_uses_explicit_repo_and_returns_exact_worktree(self) -> None:
        created = SessionCreationResult(
            schema_version=1,
            repository_id="repo_aaaaaaaaaaaaaaaa",
            session_id="session_aaaaaaaaaaaaaaaa",
            worktree="managed-worktree",
            baseline_commit="a" * 40,
            policy_hash="b" * 64,
        )
        with patch.object(agent_bridge, "create_session", return_value=created) as service:
            response = agent_bridge.handle_request(
                self.request(
                    "create_session",
                    {"repo": "fixture-repository", "name": "proposal"},
                )
            )

        service.assert_called_once_with(Path("fixture-repository"), "proposal")
        self.assertTrue(response["ok"])
        self.assertEqual(response["outcome"], "session_created")
        self.assertEqual(response["data"]["worktree"], "managed-worktree")

    def test_create_session_requires_explicit_repo(self) -> None:
        response = agent_bridge.handle_request(self.request("create_session", {"name": "proposal"}))

        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "BRIDGE_REQUEST_INVALID")
        self.assertEqual(response["error"]["details"]["missing_fields"], ["repo"])

    def test_repository_status_uses_typed_application_service(self) -> None:
        status = RepositoryStatusResult(
            schema_version=1,
            repository_id="repo_aaaaaaaaaaaaaaaa",
            initialized=True,
            baseline_commit="a" * 40,
            branch="refs/heads/main",
            clean=True,
            worktree_count=1,
            receipt_chain_verified=True,
            receipt_event_count=3,
        )
        with patch.object(agent_bridge, "repository_status", return_value=status) as service:
            response = agent_bridge.handle_request(
                self.request("repository_status", {"repo": "fixture-repository"})
            )

        service.assert_called_once_with(Path("fixture-repository"))
        self.assertTrue(response["ok"])
        self.assertEqual(response["outcome"], "ok")
        self.assertEqual(response["data"]["repository_id"], "repo_aaaaaaaaaaaaaaaa")

    def test_repository_operations_require_explicit_repo(self) -> None:
        for operation in ("repository_status", "verify"):
            with self.subTest(operation=operation):
                response = agent_bridge.handle_request(self.request(operation))

                self.assertFalse(response["ok"])
                self.assertEqual(response["outcome"], "failed_closed")
                self.assertEqual(response["error"]["code"], "BRIDGE_REQUEST_INVALID")
                self.assertEqual(response["error"]["details"]["missing_fields"], ["repo"])

    def test_verify_passes_explicit_repo_to_application_service(self) -> None:
        verification = VerificationResult(
            ok=True,
            schema_version=1,
            repository_id="repo_aaaaaaaaaaaaaaaa",
            mutation_lock="active",
            checks={},
            issues=[],
        )
        with patch.object(
            agent_bridge, "verify_repository_evidence", return_value=verification
        ) as service:
            response = agent_bridge.handle_request(
                self.request("verify", {"repo": "fixture-repository"})
            )

        service.assert_called_once_with(Path("fixture-repository"))
        self.assertTrue(response["ok"])
        self.assertEqual(response["outcome"], "verified")

    def test_protocol_identifiers_use_core_validation(self) -> None:
        cases = (
            ("session_state", {"session_id": "arbitrary-session"}),
            ("review_summary", {"tug_id": "arbitrary-tug"}),
        )
        for operation, parameters in cases:
            with self.subTest(operation=operation):
                response = agent_bridge.handle_request(self.request(operation, parameters))

                self.assertFalse(response["ok"])
                self.assertEqual(response["error"]["code"], "BRIDGE_REQUEST_INVALID")

    def test_review_summary_outcome_tracks_receipt_bound_session_state(self) -> None:
        cases = (
            ("TUGGED", "awaiting_human"),
            ("DENIED", "denied"),
            ("GRANTED", "granted"),
            ("APPLIED", "integrated"),
        )
        for state, expected_outcome in cases:
            with self.subTest(state=state):
                summary = ReviewSummaryResult(
                    tug={"tug_id": "tug_aaaaaaaaaaaaaaaa"},
                    session_state=state,
                    baseline_verification=BaselineStatus(verified=True, error_code=None),
                    receipt_verification={"verified": True},
                )
                with patch.object(
                    agent_bridge, "get_review_summary", return_value=summary
                ) as service:
                    response = agent_bridge.handle_request(
                        self.request("review_summary", {"tug_id": "tug_aaaaaaaaaaaaaaaa"})
                    )

                service.assert_called_once_with("tug_aaaaaaaaaaaaaaaa", include_diff=False)
                self.assertTrue(response["ok"])
                self.assertEqual(response["outcome"], expected_outcome)
                self.assertEqual(response["data"]["session_state"], state)


if __name__ == "__main__":
    unittest.main()
