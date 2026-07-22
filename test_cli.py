from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from notug_protocol import cli
from notug_protocol.errors import NoTugError


class CliHardeningTests(unittest.TestCase):
    def test_child_json_argument_does_not_select_cli_json_error_mode(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        failure = NoTugError("AGENT_COMMAND_FAILED", "Synthetic child-command failure")

        with (
            patch.object(cli, "run_agent_command", side_effect=failure),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            returncode = cli.main(["run", "session_aaaaaaaaaaaaaaaa", "--", "tool", "--json"])

        self.assertEqual(returncode, failure.exit_code)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Error [AGENT_COMMAND_FAILED]", stderr.getvalue())

    def test_parsed_json_option_still_selects_json_error_mode(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        failure = NoTugError("VERIFY_FAILED", "Synthetic verification failure")

        with (
            patch.object(cli, "verify_repository", side_effect=failure),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            returncode = cli.main(["verify", ".", "--json"])

        self.assertEqual(returncode, failure.exit_code)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["error"]["code"], "VERIFY_FAILED")

    def test_grant_prints_unambiguous_worktree_location_for_paths_with_spaces(self) -> None:
        stdout = io.StringIO()
        worktree = "C:\\review roots\\grant-1"
        grant = {
            "tug_hash": "a" * 64,
            "branch": "notug/grant/aaaaaaaaaa",
            "worktree": worktree,
        }

        with patch.object(cli, "grant_tug", return_value=grant), redirect_stdout(stdout):
            returncode = cli.main(["grant", "tug_aaaaaaaaaaaaaaaa"])

        output = stdout.getvalue()
        self.assertEqual(returncode, 0)
        self.assertIn(f"Integration worktree: {worktree}", output)
        self.assertIn("Review command (run from that worktree): git log -1 --stat", output)
        self.assertNotIn("git -C", output)


if __name__ == "__main__":
    unittest.main()
