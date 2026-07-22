from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from notug_protocol import git as git_module
from notug_protocol.application import repository_status
from notug_protocol.errors import NoTugError
from notug_protocol.git import (
    GIT_COMMAND_TIMEOUT_SECONDS,
    GitResult,
    _run_git_child,
    discover_repository,
    run_git,
    terminate_active_git_processes,
)
from notug_protocol.resources import ResourceMeter


class GitErrorMappingTests(unittest.TestCase):
    def test_non_repository_is_the_only_probe_failure_mapped_to_not_git(self) -> None:
        with tempfile.TemporaryDirectory(prefix="notug-probe-") as temporary:
            candidate = Path(temporary)
            not_git = GitResult(
                ("rev-parse",),
                128,
                b"",
                b"fatal: not a git repository (or any parent directory): .git\n",
            )
            with (
                patch("notug_protocol.git.run_git", return_value=not_git),
                self.assertRaises(NoTugError) as caught,
            ):
                discover_repository(candidate)
            self.assertEqual(caught.exception.code, "NOT_A_GIT_REPOSITORY")

            unavailable = GitResult(
                ("rev-parse",),
                128,
                b"",
                b"fatal: detected dubious ownership in repository\n",
            )
            with (
                patch("notug_protocol.git.run_git", return_value=unavailable),
                self.assertRaises(NoTugError) as caught,
            ):
                discover_repository(candidate)
            self.assertEqual(caught.exception.code, "GIT_REPOSITORY_PROBE_FAILED")
            self.assertNotIn("stderr", caught.exception.details)

    def test_git_not_found_and_execution_failure_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory(prefix="notug-git-errors-") as temporary:
            candidate = Path(temporary)
            with (
                patch("notug_protocol.git.shutil.which", return_value=None),
                self.assertRaises(NoTugError) as caught,
            ):
                run_git(candidate, ["status"])
            self.assertEqual(caught.exception.code, "GIT_NOT_FOUND")

            with (
                patch("notug_protocol.git.shutil.which", return_value="git.exe"),
                patch("notug_protocol.git.subprocess.Popen", side_effect=OSError("blocked")),
                self.assertRaises(NoTugError) as caught,
            ):
                run_git(candidate, ["status"])
            self.assertEqual(caught.exception.code, "GIT_EXECUTION_FAILED")

    def test_git_child_trusts_only_the_exact_process_local_repository_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="notug-safe-directory-") as temporary:
            candidate = Path(temporary).resolve()
            completed = subprocess.CompletedProcess((), 0, stdout=b"ok", stderr=b"")
            with (
                patch("notug_protocol.git._git_executable", return_value="git.exe"),
                patch("notug_protocol.git._run_git_child", return_value=completed) as runner,
            ):
                run_git(candidate, ["status"])

        command = runner.call_args.args[0]
        self.assertIn(f"safe.directory={candidate}", command)
        self.assertNotIn("safe.directory=*", command)

    def test_git_child_is_awaited_hidden_and_removed_from_active_registry(self) -> None:
        process = MagicMock()
        process.communicate.return_value = (b"ok", b"")
        process.returncode = 0
        process.pid = 1234
        with patch("notug_protocol.git.subprocess.Popen", return_value=process) as popen:
            completed = _run_git_child(
                ("git.exe", "status"),
                env={"GIT_TERMINAL_PROMPT": "0"},
                input_bytes=None,
                operation="status",
            )

        self.assertEqual(completed.returncode, 0)
        process.communicate.assert_called_once_with(
            input=None, timeout=GIT_COMMAND_TIMEOUT_SECONDS
        )
        options = popen.call_args.kwargs
        self.assertFalse(options["shell"])
        if os.name == "nt":
            self.assertNotEqual(
                options["creationflags"] & int(subprocess.CREATE_NO_WINDOW), 0
            )
            self.assertFalse(options["start_new_session"])
        else:
            self.assertEqual(options["creationflags"], 0)
            self.assertTrue(options["start_new_session"])
        with git_module._ACTIVE_GIT_PROCESSES_LOCK:
            self.assertEqual(git_module._ACTIVE_GIT_PROCESSES, set())

    def test_timed_out_git_child_is_terminated_reaped_and_unregistered(self) -> None:
        process = MagicMock()
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(("git.exe", "status"), 30),
            (b"", b""),
        ]
        process.returncode = None
        process.pid = 1234
        with (
            patch("notug_protocol.git.subprocess.Popen", return_value=process),
            patch("notug_protocol.git._terminate_git_process_tree") as terminate,
            self.assertRaises(NoTugError) as caught,
        ):
            _run_git_child(
                ("git.exe", "status"),
                env=None,
                input_bytes=None,
                operation="status",
            )

        self.assertEqual(caught.exception.code, "GIT_COMMAND_TIMEOUT")
        terminate.assert_called_once_with(process)
        self.assertEqual(process.communicate.call_count, 2)
        with git_module._ACTIVE_GIT_PROCESSES_LOCK:
            self.assertEqual(git_module._ACTIVE_GIT_PROCESSES, set())

    def test_quit_cleanup_terminates_only_registered_git_children(self) -> None:
        first = MagicMock()
        second = MagicMock()

        with git_module._ACTIVE_GIT_PROCESSES_LOCK:
            git_module._ACTIVE_GIT_PROCESSES.update((first, second))
        with patch("notug_protocol.git._terminate_git_process_tree") as terminate:
            terminate_active_git_processes()

        self.assertEqual(terminate.call_count, 2)
        terminated = [call.args[0] for call in terminate.call_args_list]
        self.assertTrue(any(process is first for process in terminated))
        self.assertTrue(any(process is second for process in terminated))
        with git_module._ACTIVE_GIT_PROCESSES_LOCK:
            self.assertEqual(git_module._ACTIVE_GIT_PROCESSES, set())


class RealGitRepositoryDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git is not installed")
        self.git_executable = git
        self.temporary = tempfile.TemporaryDirectory(prefix="notug-real-repository-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, repository: Path, *arguments: str) -> None:
        subprocess.run(
            (self.git_executable, "-C", str(repository), *arguments),
            check=True,
            capture_output=True,
            shell=False,
        )

    def initialized_repository(self) -> Path:
        repository = self.root / "repository"
        repository.mkdir()
        self.git(repository, "init", "--initial-branch=main")
        self.git(repository, "config", "user.name", "NoTUG Test")
        self.git(repository, "config", "user.email", "notug@example.invalid")
        (repository / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        self.git(repository, "add", "--all")
        self.git(repository, "commit", "-m", "baseline")
        return repository

    def test_clean_repository_is_accepted_and_dirty_repository_is_refused(self) -> None:
        repository = self.initialized_repository()
        discovered = discover_repository(repository, require_clean=True)
        self.assertEqual(discovered.root, repository.resolve())

        (repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(NoTugError) as caught:
            discover_repository(repository, require_clean=True)
        self.assertEqual(caught.exception.code, "SOURCE_REPOSITORY_DIRTY")

    def test_repository_status_has_a_bounded_git_invocation_count(self) -> None:
        repository = self.initialized_repository()
        vault = self.root / "vault"
        with (
            patch.dict(os.environ, {"NOTUG_HOME": str(vault)}, clear=False),
            ResourceMeter("repository_status_test", "repository.status") as meter,
        ):
            status = repository_status(repository)

        self.assertFalse(status.initialized)
        self.assertEqual(meter.receipt().git_launch_attempt_count, 12)

    def test_non_git_bare_and_unborn_repositories_remain_fail_closed(self) -> None:
        non_git = self.root / "non-git"
        non_git.mkdir()
        with (
            patch.dict(
                os.environ,
                {"GIT_CEILING_DIRECTORIES": str(self.root.resolve())},
                clear=False,
            ),
            self.assertRaises(NoTugError) as caught,
        ):
            discover_repository(non_git)
        self.assertEqual(caught.exception.code, "NOT_A_GIT_REPOSITORY")

        bare = self.root / "bare.git"
        bare.mkdir()
        self.git(bare, "init", "--bare")
        with self.assertRaises(NoTugError) as caught:
            discover_repository(bare)
        self.assertEqual(caught.exception.code, "BARE_REPOSITORY_UNSUPPORTED")

        unborn = self.root / "unborn"
        unborn.mkdir()
        self.git(unborn, "init", "--initial-branch=main")
        with self.assertRaises(NoTugError) as caught:
            discover_repository(unborn)
        self.assertEqual(caught.exception.code, "UNBORN_HEAD_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
