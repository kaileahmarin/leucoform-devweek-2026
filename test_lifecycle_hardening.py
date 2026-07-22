from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from notug_protocol.errors import NoTugError
from notug_protocol.git import worktree_list
from notug_protocol.sessions import archive_session, initialize_repository, start_session
from notug_protocol.tug import deny_tug, generate_tug
from notug_protocol.vault import Vault


class LifecycleHardeningIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.fail("Git is required for integration tests")
        self.git_executable = git
        self.temporary = tempfile.TemporaryDirectory(prefix="notug-lifecycle-hardening-")
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.hooks = self.root / "empty-hooks"
        self.hooks.mkdir()
        self.excludes = self.root / "global-excludes"
        self.excludes.write_bytes(b"")
        self.vault = Vault(self.root / "vault" / "v1")

        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "NoTUG Lifecycle Test")
        self.git("config", "user.email", "notug-lifecycle@localhost.invalid")
        self.git("config", "commit.gpgSign", "false")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "core.fileMode", "false")
        self.git("config", "core.hooksPath", self.hooks.resolve().as_posix())
        self.git("config", "core.excludesFile", self.excludes.resolve().as_posix())
        (self.repository / "alpha.txt").write_bytes(b"alpha baseline\n")
        self.git("add", "--all")
        self.git("commit", "-m", "baseline")
        self.initialized = initialize_repository(self.repository, self.vault)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> bytes:
        completed = subprocess.run(
            (self.git_executable, "-C", str(self.repository), *arguments),
            capture_output=True,
            check=False,
            shell=False,
            env={
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
            },
        )
        if completed.returncode != 0:
            self.fail(completed.stderr.decode("utf-8", errors="replace"))
        return completed.stdout

    def assert_error(self, code: str, operation: Callable[[], object]) -> NoTugError:
        with self.assertRaises(NoTugError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def artifact_inventory(self) -> tuple[str, ...]:
        repository_dir = self.vault.repository_dir(self.initialized.repository_id)
        paths: list[str] = []
        for name in ("tugs", "patches", "changes"):
            root = repository_dir / name
            paths.extend(path.relative_to(repository_dir).as_posix() for path in root.rglob("*"))
        return tuple(sorted(paths))

    def test_archive_refuses_post_review_untracked_drift_without_deleting_it(self) -> None:
        session = start_session(self.repository, "archive-drift", self.vault)
        (session.worktree / "alpha.txt").write_bytes(b"reviewed proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        deny_tug(str(tug["tug_id"]), self.vault)
        post_review = session.worktree / "unreviewed-user-work.txt"
        post_review.write_bytes(b"must not be deleted\n")

        self.assert_error(
            "WORKSPACE_POST_REVIEW_DRIFT",
            lambda: archive_session(session.session_id, self.vault),
        )

        self.assertTrue(session.worktree.is_dir())
        self.assertEqual(post_review.read_bytes(), b"must not be deleted\n")
        registered = {item.path.resolve() for item in worktree_list(self.repository)}
        self.assertIn(session.worktree.resolve(), registered)

    def test_archive_refuses_post_review_empty_directory_drift(self) -> None:
        session = start_session(self.repository, "archive-empty-directory-drift", self.vault)
        (session.worktree / "alpha.txt").write_bytes(b"reviewed proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        deny_tug(str(tug["tug_id"]), self.vault)
        post_review = session.worktree / "unreviewed-empty-directory"
        post_review.mkdir()

        self.assert_error(
            "WORKSPACE_POST_REVIEW_DRIFT",
            lambda: archive_session(session.session_id, self.vault),
        )

        self.assertTrue(post_review.is_dir())
        self.assertTrue(session.worktree.is_dir())

    def test_no_changes_leaves_no_unclaimed_tug_artifacts(self) -> None:
        session = start_session(self.repository, "no-changes", self.vault)
        before = self.artifact_inventory()

        self.assert_error("NO_CHANGES", lambda: generate_tug(session.session_id, self.vault))

        self.assertEqual(self.artifact_inventory(), before)

    def test_prepublication_tug_failure_cleans_staged_artifacts(self) -> None:
        session = start_session(self.repository, "failed-tug", self.vault)
        (session.worktree / "alpha.txt").write_bytes(b"proposal before failure\n")
        before = self.artifact_inventory()

        with (
            mock.patch(
                "notug_protocol.tug._merge_ignored_findings",
                side_effect=RuntimeError("simulated policy evaluation failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "simulated policy evaluation failure"),
        ):
            generate_tug(session.session_id, self.vault)

        self.assertEqual(self.artifact_inventory(), before)

    def test_staging_cleanup_preserves_unexpected_content_and_fails_closed(self) -> None:
        session = start_session(self.repository, "unexpected-staging", self.vault)
        (session.worktree / "alpha.txt").write_bytes(b"proposal before unsafe cleanup\n")
        tug_id = "tug_aaaaaaaaaaaaaaaa"
        operation_dir = (
            self.vault.tug_path(self.initialized.repository_id, tug_id).parent / ".work" / tug_id
        )
        sentinel = operation_dir / "unexpected" / "must-survive.txt"

        def fail_with_unexpected_content(*_arguments: object) -> object:
            sentinel.parent.mkdir(parents=True)
            sentinel.write_bytes(b"not owned by narrow cleanup\n")
            raise RuntimeError("simulated policy evaluation failure")

        with (
            mock.patch("notug_protocol.tug.new_identifier", return_value=tug_id),
            mock.patch(
                "notug_protocol.tug._merge_ignored_findings",
                side_effect=fail_with_unexpected_content,
            ),
            self.assertRaises(NoTugError) as caught,
        ):
            generate_tug(session.session_id, self.vault)

        self.assertEqual(caught.exception.code, "TUG_STAGING_CLEANUP_FAILED")
        self.assertEqual(sentinel.read_bytes(), b"not owned by narrow cleanup\n")
        self.assertFalse(self.vault.patch_path(self.initialized.repository_id, tug_id).exists())
        self.assertFalse(self.vault.tug_path(self.initialized.repository_id, tug_id).exists())

    def test_policy_snapshot_collision_fails_closed_without_overwrite(self) -> None:
        snapshot = self.vault.policy_snapshot_path(
            self.initialized.repository_id, self.initialized.policy_hash
        )
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(b"untrusted bytes at a trusted content address\n")
        worktrees_before = tuple(item.path for item in worktree_list(self.repository))

        self.assert_error(
            "POLICY_SNAPSHOT_DIVERGENCE",
            lambda: start_session(self.repository, "policy-collision", self.vault),
        )

        self.assertEqual(snapshot.read_bytes(), b"untrusted bytes at a trusted content address\n")
        self.assertEqual(
            tuple(item.path for item in worktree_list(self.repository)), worktrees_before
        )


if __name__ == "__main__":
    unittest.main()
