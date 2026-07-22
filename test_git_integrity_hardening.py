from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from notug_protocol.errors import NoTugError
from notug_protocol.grants import grant_tug, revoke_grant
from notug_protocol.sessions import initialize_repository, start_session
from notug_protocol.tug import generate_tug
from notug_protocol.vault import Vault


class GitIntegrityHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.fail("Git is required for integration tests")
        self.git_executable = git
        self.temporary = tempfile.TemporaryDirectory(prefix="notug-git-integrity-")
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.empty_hooks = self.root / "empty-hooks"
        self.empty_hooks.mkdir()
        self.vault = Vault(self.root / "vault" / "v1")

        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "NoTUG Integration Test")
        self.git("config", "user.email", "notug-integration@localhost.invalid")
        self.git("config", "commit.gpgSign", "false")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "core.fileMode", "false")
        self.git("config", "core.hooksPath", self.empty_hooks.resolve().as_posix())
        (self.repository / "baseline.txt").write_bytes(b"baseline\n")
        self.git("add", "--all")
        self.git("commit", "-m", "baseline")
        initialize_repository(self.repository, self.vault)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git_result(
        self,
        *arguments: str,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            (self.git_executable, "-C", str(self.repository), *arguments),
            input=input_bytes,
            capture_output=True,
            check=False,
            shell=False,
            env={
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
            },
        )

    def git(self, *arguments: str, input_bytes: bytes | None = None) -> bytes:
        completed = self.git_result(*arguments, input_bytes=input_bytes)
        if completed.returncode != 0:
            self.fail(completed.stderr.decode("utf-8", errors="replace"))
        return completed.stdout

    def rev_parse(self, revision: str) -> str:
        return self.git("rev-parse", "--verify", revision).decode("ascii").strip()

    def grant(self, tug: dict[str, object]) -> dict[str, object]:
        with (
            mock.patch.dict(os.environ, {"NOTUG_AGENT_SESSION": ""}),
            mock.patch("notug_protocol.grants._interactive_confirmation", return_value=True),
        ):
            return grant_tug(str(tug["tug_id"]), self.vault)

    def test_critical_index_writes_neutralize_post_index_change_hook(self) -> None:
        marker = self.root / "post-index-change-ran"
        configured_hooks = self.root / "configured-hooks"
        configured_hooks.mkdir()
        hook = configured_hooks / "post-index-change"
        marker_for_shell = marker.resolve().as_posix().replace("'", "'\"'\"'")
        hook.write_bytes(f"#!/bin/sh\nprintf 'ran\\n' >> '{marker_for_shell}'\n".encode())
        hook.chmod(0o755)
        self.git("config", "core.hooksPath", configured_hooks.resolve().as_posix())

        session = start_session(self.repository, "hook-neutralization", self.vault)
        (session.worktree / "proposal.txt").write_bytes(b"reviewed proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        self.grant(tug)

        self.assertFalse(
            marker.exists(),
            marker.read_text(encoding="utf-8") if marker.exists() else "",
        )

    def test_contaminated_replacement_hooks_directory_fails_closed(self) -> None:
        session = start_session(self.repository, "contaminated-hooks", self.vault)
        marker = self.root / "contaminated-hook-ran"
        selected_hooks = self.vault.root / "trusted" / "empty-hooks"
        hook = selected_hooks / "post-index-change"
        marker_for_shell = marker.resolve().as_posix().replace("'", "'\"'\"'")
        hook.write_bytes(f"#!/bin/sh\nprintf 'ran\\n' >> '{marker_for_shell}'\n".encode())
        hook.chmod(0o755)
        (session.worktree / "proposal.txt").write_bytes(b"reviewed proposal\n")

        with self.assertRaises(NoTugError) as caught:
            generate_tug(session.session_id, self.vault)

        self.assertEqual(caught.exception.code, "GIT_HOOKS_PATH_UNSAFE")
        self.assertFalse(marker.exists())

    def test_custom_ref_prevents_unmerged_revocation_cleanup(self) -> None:
        session = start_session(self.repository, "custom-ref-reachability", self.vault)
        (session.worktree / "proposal.txt").write_bytes(b"approved proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        commit = str(grant["commit"])
        branch_ref = f"refs/heads/{grant['branch']}"
        worktree = Path(str(grant["worktree"]))
        custom_ref = "refs/custom/deployed"
        self.git("update-ref", custom_ref, commit)

        with self.assertRaises(NoTugError) as caught:
            revoke_grant(str(tug["tug_id"]), self.vault)

        self.assertEqual(caught.exception.code, "REVERT_TARGET_REQUIRED")
        self.assertTrue(worktree.is_dir())
        self.assertEqual(self.rev_parse(branch_ref), commit)
        self.assertEqual(self.rev_parse(custom_ref), commit)


if __name__ == "__main__":
    unittest.main()
