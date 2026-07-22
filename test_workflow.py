from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from notug_protocol import changes, cli
from notug_protocol.application import session_change_status
from notug_protocol.errors import NoTugError
from notug_protocol.events import ledger_for
from notug_protocol.exports import export_tug_receipt
from notug_protocol.grants import grant_tug, grant_tug_with_phrase, revoke_grant
from notug_protocol.identity import repository_key
from notug_protocol.process import CancellableProcessResult
from notug_protocol.sessions import (
    abandon_session,
    archive_session,
    find_session,
    initialize_repository,
    load_session,
    run_agent_command,
    run_agent_command_streaming,
    start_session,
)
from notug_protocol.tug import deny_tug, generate_tug, tug_hash
from notug_protocol.util import atomic_write_json
from notug_protocol.vault import Vault
from notug_protocol.verification import verify_repository


class WorkflowIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.fail("Git is required for integration tests")
        self.git_executable = git
        self.temporary = tempfile.TemporaryDirectory(prefix="notug-workflow-")
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.hooks = self.root / "empty-hooks"
        self.hooks.mkdir()
        self.excludes = self.root / "global-excludes"
        self.excludes.write_bytes(b"")
        self.vault = Vault(self.root / "vault" / "v1")

        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "NoTUG Integration Test")
        self.git("config", "user.email", "notug-integration@localhost.invalid")
        self.git("config", "commit.gpgSign", "false")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "core.fileMode", "false")
        self.git("config", "core.hooksPath", self.hooks.resolve().as_posix())
        self.git("config", "core.excludesFile", self.excludes.resolve().as_posix())

        (self.repository / "alpha.txt").write_bytes(b"alpha baseline\n")
        (self.repository / "obsolete.txt").write_bytes(b"remove only in session\n")
        (self.repository / "rename-me.txt").write_bytes(b"rename content is stable\n")
        (self.repository / "binary.bin").write_bytes(b"\x00\x01baseline\xff\x00")
        (self.repository / "binary-delete.bin").write_bytes(b"\x00delete-me\xff")
        self.git("add", "--all")
        self.git("commit", "-m", "baseline")
        self.baseline = self.rev_parse("HEAD")
        self.initialized = initialize_repository(self.repository, self.vault)

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

    def primary_snapshot(self) -> dict[str, object]:
        paths = [raw.decode("utf-8") for raw in self.git("ls-files", "-z").split(b"\0") if raw]
        return {
            "head": self.rev_parse("HEAD"),
            "branch": self.git("symbolic-ref", "--short", "HEAD").decode("utf-8").strip(),
            "status": self.git("status", "--porcelain=v1", "--untracked-files=all"),
            "files": tuple((path, (self.repository / path).read_bytes()) for path in paths),
        }

    def assert_error(
        self,
        expected_code: str,
        operation: Callable[[], object],
    ) -> NoTugError:
        with self.assertRaises(NoTugError) as caught:
            operation()
        self.assertEqual(caught.exception.code, expected_code)
        return caught.exception

    def open_session(self, name: str) -> object:
        return start_session(self.repository, name, self.vault)

    def create_directory_link(self, target: Path, link: Path) -> None:
        symlink_failure: OSError | None = None
        try:
            os.symlink(target, link, target_is_directory=True)
            return
        except OSError as symlink_error:
            if os.name != "nt":
                raise symlink_error
            symlink_failure = symlink_error
        junction = subprocess.run(
            ("cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)),
            capture_output=True,
            check=False,
            shell=False,
        )
        if junction.returncode != 0:
            raise OSError(junction.stderr.decode("utf-8", errors="replace")) from symlink_failure

    @staticmethod
    def remove_directory_link(link: Path) -> None:
        if link.is_symlink():
            link.unlink()
        else:
            link.rmdir()

    def grant(self, tug: dict[str, object]) -> dict[str, object]:
        seen: list[str] = []

        def confirm(value: str) -> bool:
            seen.append(value)
            return value == tug["tug_hash"]

        with (
            mock.patch.dict(os.environ, {"NOTUG_AGENT_SESSION": ""}),
            mock.patch("notug_protocol.grants._interactive_confirmation", side_effect=confirm),
        ):
            result = grant_tug(str(tug["tug_id"]), self.vault)
        self.assertEqual(seen, [tug["tug_hash"]])
        return result

    def test_dirty_source_is_refused_without_changing_or_stashing_it(self) -> None:
        dirty = self.repository / "untracked-user-work.txt"
        dirty.write_bytes(b"preserve me exactly\n")
        status_before = self.git("status", "--porcelain=v2", "-z", "--untracked-files=all")
        worktrees_before = self.git("worktree", "list", "--porcelain")

        self.assert_error(
            "SOURCE_REPOSITORY_DIRTY",
            lambda: start_session(self.repository, "must-refuse", self.vault),
        )

        self.assertEqual(dirty.read_bytes(), b"preserve me exactly\n")
        self.assertEqual(
            self.git("status", "--porcelain=v2", "-z", "--untracked-files=all"),
            status_before,
        )
        self.assertEqual(self.git("worktree", "list", "--porcelain"), worktrees_before)
        self.assertEqual(self.rev_parse("HEAD"), self.baseline)

    def test_native_exact_phrase_grants_without_a_terminal_or_bridge_authority(self) -> None:
        session = self.open_session("native-phrase")
        (session.worktree / "alpha.txt").write_bytes(b"native phrase proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        phrase = f"GRANT {tug['tug_hash']}"

        with mock.patch.dict(os.environ, {"NOTUG_AGENT_SESSION": ""}):
            self.assert_error(
                "GRANT_CONFIRMATION_FAILED",
                lambda: grant_tug_with_phrase(str(tug["tug_id"]), phrase + "x", self.vault),
            )
            grant = grant_tug_with_phrase(str(tug["tug_id"]), phrase, self.vault)

        self.assertEqual(grant["tug_hash"], tug["tug_hash"])
        self.assertEqual(grant["state"], "APPLIED")
        self.assertEqual(self.primary_snapshot()["head"], self.baseline)
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_native_phrase_is_rejected_from_an_agent_context(self) -> None:
        session = self.open_session("native-agent-refusal")
        (session.worktree / "alpha.txt").write_bytes(b"agent context proposal\n")
        tug = generate_tug(session.session_id, self.vault)

        with mock.patch.dict(os.environ, {"NOTUG_AGENT_SESSION": session.session_id}):
            self.assert_error(
                "GRANT_FROM_AGENT_CONTEXT",
                lambda: grant_tug_with_phrase(
                    str(tug["tug_id"]),
                    f"GRANT {tug['tug_hash']}",
                    self.vault,
                ),
            )

        self.assertEqual(
            load_session(self.vault, session.repository_id, session.session_id)["state"], "TUGGED"
        )

    def test_unchanged_session_can_be_abandoned_and_explicitly_archived(self) -> None:
        session = self.open_session("clean-abandonment")

        abandon_session(session.session_id, self.vault)
        abandoned = load_session(self.vault, session.repository_id, session.session_id)
        self.assertEqual(abandoned["state"], "ABANDONED")
        self.assertTrue(session.worktree.is_dir())
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

        archive_session(session.session_id, self.vault)
        self.assertFalse(session.worktree.exists())
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_changed_session_cannot_be_silently_abandoned(self) -> None:
        session = self.open_session("changed-abandonment")
        (session.worktree / "alpha.txt").write_bytes(b"valuable partial work\n")

        self.assert_error(
            "SESSION_HAS_CHANGES",
            lambda: abandon_session(session.session_id, self.vault),
        )

        retained = load_session(self.vault, session.repository_id, session.session_id)
        self.assertEqual(retained["state"], "SESSION_OPEN")
        self.assertEqual((session.worktree / "alpha.txt").read_bytes(), b"valuable partial work\n")

    def test_application_change_status_uses_session_not_protected_checkout(self) -> None:
        session = self.open_session("application-change-status")
        self.assertFalse(session_change_status(session.session_id, self.vault).changed)

        (session.worktree / "agent-proposal.txt").write_bytes(b"authoritative session change\n")

        self.assertTrue(session_change_status(session.session_id, self.vault).changed)
        self.assertEqual(self.primary_snapshot()["status"], b"")

    def test_streaming_runner_uses_bounded_stdin_without_persisting_prompt(self) -> None:
        session = self.open_session("streaming-input")
        prompt = b"private composer prompt"
        stdout: list[str] = []
        stderr: list[str] = []
        script = (
            "import json, pathlib, sys; "
            "value=sys.stdin.buffer.read(); "
            "pathlib.Path('prompt-size.txt').write_text(str(len(value))); "
            "print(json.dumps({'type':'turn.completed'})); "
            "print('diagnostic', file=sys.stderr)"
        )

        result = run_agent_command_streaming(
            session.session_id,
            [sys.executable, "-c", script],
            input_bytes=prompt,
            stdout_callback=stdout.append,
            stderr_callback=stderr.append,
            cancel_event=threading.Event(),
            vault=self.vault,
        )

        self.assertFalse(result.cancelled)
        self.assertEqual(result.exit_status, 0)
        self.assertEqual((session.worktree / "prompt-size.txt").read_text(), str(len(prompt)))
        operation = json.loads(
            self.vault.operation_path(session.repository_id, result.operation_id).read_text()
        )
        self.assertNotIn(prompt.decode(), json.dumps(operation))
        self.assertIn("turn.completed", "".join(stdout))
        self.assertIn("diagnostic", "".join(stderr))
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_streaming_runner_records_explicit_cancellation(self) -> None:
        session = self.open_session("streaming-cancel")
        cancel = threading.Event()
        timer = threading.Timer(0.2, cancel.set)
        timer.start()
        try:
            result = run_agent_command_streaming(
                session.session_id,
                [sys.executable, "-c", "import time; time.sleep(30)"],
                input_bytes=b"",
                stdout_callback=lambda _value: None,
                stderr_callback=lambda _value: None,
                cancel_event=cancel,
                vault=self.vault,
            )
        finally:
            timer.cancel()

        self.assertTrue(result.cancelled)
        operation = json.loads(
            self.vault.operation_path(session.repository_id, result.operation_id).read_text()
        )
        self.assertEqual(operation["state"], "CANCELLED")
        self.assertEqual(
            ledger_for(self.vault, session.repository_id).verify().events[-1]["event_type"],
            "RUN_CANCELLED",
        )
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_session_refuses_tracked_baseline_symlink_before_worktree_creation(self) -> None:
        sentinel = self.root / "protected-sentinel.txt"
        sentinel.write_bytes(b"protected bytes must remain unchanged\n")
        absolute_target = sentinel.resolve().as_posix().encode("utf-8")
        self.git("config", "core.symlinks", "false")
        symlink_oid = (
            self.git("hash-object", "-w", "--stdin", input_bytes=absolute_target)
            .decode("ascii")
            .strip()
        )
        self.git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{symlink_oid},absolute-protected-link",
        )
        self.git("commit", "-m", "add tracked absolute symlink")
        (self.repository / "absolute-protected-link").write_bytes(absolute_target)
        self.assertEqual(self.git("status", "--porcelain=v1", "--untracked-files=all"), b"")
        worktrees_before = self.git("worktree", "list", "--porcelain")
        sessions_before = tuple(
            sorted(self.vault.repository_dir(self.initialized.repository_id).glob("sessions/*"))
        )
        session_worktrees = self.vault.worktrees_dir / self.initialized.repository_id / "s"
        worktree_paths_before = tuple(sorted(session_worktrees.iterdir()))

        self.assert_error(
            "UNSAFE_BASELINE_SYMLINK",
            lambda: start_session(self.repository, "unsafe-baseline", self.vault),
        )

        self.assertEqual(sentinel.read_bytes(), b"protected bytes must remain unchanged\n")
        self.assertEqual(self.git("worktree", "list", "--porcelain"), worktrees_before)
        self.assertEqual(
            tuple(
                sorted(self.vault.repository_dir(self.initialized.repository_id).glob("sessions/*"))
            ),
            sessions_before,
        )
        self.assertEqual(tuple(sorted(session_worktrees.iterdir())), worktree_paths_before)

    def test_in_repository_vault_is_rejected_before_any_protected_write(self) -> None:
        protected_before = self.primary_snapshot()
        inside_vault = Vault(self.repository / "forbidden-vault" / "v1")

        self.assert_error(
            "VAULT_INSIDE_REPOSITORY",
            lambda: initialize_repository(self.repository, inside_vault),
        )

        self.assertFalse(inside_vault.root.exists())
        self.assertEqual(self.primary_snapshot(), protected_before)

    def test_repository_identity_is_bound_to_index_location_and_initial_receipt(self) -> None:
        open_session = self.open_session("identity-run-tug-binding")
        grant_session = self.open_session("identity-grant-binding")
        (grant_session.worktree / "alpha.txt").write_bytes(b"identity-bound proposal\n")
        tug = generate_tug(grant_session.session_id, self.vault)
        metadata_path = (
            self.vault.repository_dir(self.initialized.repository_id) / "repository.json"
        )
        original = json.loads(metadata_path.read_text(encoding="utf-8"))
        changed_timestamp = dict(original)
        changed_timestamp["created_at"] = "2026-07-14T00:00:00.000Z"
        atomic_write_json(metadata_path, changed_timestamp)

        self.assert_error(
            "REPOSITORY_INITIALIZATION_INVALID",
            lambda: run_agent_command(
                open_session.session_id, [sys.executable, "-c", "pass"], self.vault
            ),
        )
        self.assert_error(
            "REPOSITORY_INITIALIZATION_INVALID",
            lambda: generate_tug(open_session.session_id, self.vault),
        )
        with mock.patch(
            "notug_protocol.grants._interactive_confirmation", return_value=True
        ) as confirmation:
            self.assert_error(
                "REPOSITORY_INITIALIZATION_INVALID",
                lambda: grant_tug(str(tug["tug_id"]), self.vault),
            )
        confirmation.assert_not_called()

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn(
            "REPOSITORY_INITIALIZATION_INVALID",
            {issue["code"] for issue in report["issues"]},
        )

        alternate = self.root / "alternate-repository"
        alternate.mkdir()
        completed = subprocess.run(
            (self.git_executable, "-C", str(alternate), "init", "--initial-branch=main"),
            capture_output=True,
            check=False,
            shell=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        redirected = dict(original)
        redirected["root"] = str(alternate.resolve())
        redirected["common_git_dir"] = str((alternate / ".git").resolve())
        redirected["repository_key"] = repository_key(
            alternate.resolve(), (alternate / ".git").resolve()
        )
        atomic_write_json(metadata_path, redirected)

        self.assert_error(
            "REPOSITORY_METADATA_DIVERGENCE",
            lambda: verify_repository(self.repository, self.vault),
        )
        atomic_write_json(metadata_path, original)

    def test_session_worktree_must_remain_detached_at_recorded_baseline(self) -> None:
        session = self.open_session("worktree-head-drift")
        completed = subprocess.run(
            (
                self.git_executable,
                "-C",
                str(session.worktree),
                "switch",
                "-c",
                "agent-created-branch",
            ),
            capture_output=True,
            check=False,
            shell=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))

        self.assert_error(
            "WORKTREE_ADMIN_DIVERGENCE",
            lambda: generate_tug(session.session_id, self.vault),
        )

    def test_tug_structurally_classifies_delete_rewrite_and_rename(self) -> None:
        protected_before = self.primary_snapshot()
        session = self.open_session("structural-evidence")
        (session.worktree / "obsolete.txt").unlink()
        (session.worktree / "alpha.txt").write_bytes(
            b"claimed formatting only\nsemantic behaviour changed\n"
        )
        (session.worktree / "rename-me.txt").rename(session.worktree / "renamed.txt")

        self.assertEqual(self.primary_snapshot(), protected_before)
        tug = generate_tug(session.session_id, self.vault)
        changes = {change["path"]: change for change in tug["changes"]}

        self.assertEqual(changes["obsolete.txt"]["kind"], "delete")
        self.assertEqual(changes["alpha.txt"]["kind"], "modify")
        self.assertNotEqual(changes["alpha.txt"]["old_oid"], changes["alpha.txt"]["new_oid"])
        self.assertGreater(changes["alpha.txt"]["added_lines"], 0)
        self.assertGreater(changes["alpha.txt"]["deleted_lines"], 0)
        self.assertEqual(changes["renamed.txt"]["kind"], "rename")
        self.assertEqual(changes["renamed.txt"]["old_path"], "rename-me.txt")
        self.assertEqual(tug["evidence"]["summary"]["deletion_count"], 1)
        self.assertEqual(tug["evidence"]["summary"]["rename_count"], 1)
        self.assertEqual(tug["risk_summary"]["affected_path_count"], 4)
        patch = self.vault.patch_path(session.repository_id, str(tug["tug_id"])).read_bytes()
        self.assertIn(b"semantic behaviour changed", patch)
        self.assertEqual(self.primary_snapshot(), protected_before)

    def test_binary_modification_and_deletion_are_exactly_reported(self) -> None:
        protected_before = self.primary_snapshot()
        session = self.open_session("binary-evidence")
        (session.worktree / "binary.bin").write_bytes(b"\x00\x10modified\xfe\x00")
        (session.worktree / "binary-delete.bin").unlink()

        tug = generate_tug(session.session_id, self.vault)
        changes = {change["path"]: change for change in tug["changes"]}

        self.assertEqual(changes["binary.bin"]["kind"], "modify")
        self.assertTrue(changes["binary.bin"]["binary"])
        self.assertEqual(changes["binary-delete.bin"]["kind"], "delete")
        self.assertTrue(changes["binary-delete.bin"]["binary"])
        self.assertEqual(tug["evidence"]["summary"]["binary_count"], 2)
        self.assertEqual(tug["evidence"]["summary"]["deletion_count"], 1)
        self.assertIn("BINARY_FILE", tug["risk_summary"]["finding_codes"])
        review_output = io.StringIO()
        with contextlib.redirect_stdout(review_output):
            cli._print_review(  # noqa: SLF001 - integration coverage of human review output
                {
                    "tug": tug,
                    "baseline_verification": {"verified": True, "error_code": None},
                    "commands": {"grant": "grant", "deny": "deny"},
                }
            )
        rendered = review_output.getvalue()
        self.assertIn("binary metadata:", rendered)
        self.assertIn(f"old_size={changes['binary.bin']['old_size']}", rendered)
        self.assertIn(f"new_oid={changes['binary.bin']['new_oid']}", rendered)
        self.assertEqual(self.primary_snapshot(), protected_before)

    def test_sensitive_and_governance_paths_are_policy_findings(self) -> None:
        session = self.open_session("sensitive-paths")
        workflow = session.worktree / ".github" / "workflows"
        workflow.mkdir(parents=True)
        proposed = {
            ".env": b"SYNTHETIC=value\n",
            "id_rsa": b"synthetic fixture only\n",
            "credentials.json": b"{}\n",
            "notug.toml": b"schema_version = 1\n",
            "package-lock.json": b"{}\n",
            ".github/workflows/deploy.yml": b"name: synthetic\n",
        }
        for path, content in proposed.items():
            destination = session.worktree / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)

        tug = generate_tug(session.session_id, self.vault)
        codes = set(tug["risk_summary"]["finding_codes"])

        self.assertTrue(
            {
                "ENVIRONMENT_FILE",
                "PRIVATE_KEY_FILE",
                "CREDENTIAL_FILE",
                "NOTUG_METADATA",
                "LOCKFILE",
                "CI_DEPLOYMENT",
            }.issubset(codes)
        )
        self.assertTrue(tug["risk_summary"]["blocked"])
        self.assertFalse(tug["grant"]["grantable"])

    def test_ignored_sensitive_only_tug_is_review_only_and_cannot_be_granted(self) -> None:
        (self.repository / ".gitignore").write_bytes(b".env\n")
        self.git("add", ".gitignore")
        self.git("commit", "-m", "ignore synthetic environment fixture")
        session = self.open_session("ignored-sensitive-only")
        (session.worktree / ".env").write_bytes(b"SYNTHETIC=value\n")

        tug = generate_tug(session.session_id, self.vault)

        self.assertEqual(tug["evidence"]["summary"]["file_count"], 0)
        self.assertEqual(tug["evidence"]["patch_bytes"], 0)
        self.assertEqual(tug["ignored_sensitive_paths"], [".env"])
        self.assertIn("NO_PROPOSABLE_CHANGES", tug["risk_summary"]["finding_codes"])
        self.assertTrue(tug["risk_summary"]["blocked"])
        self.assertFalse(tug["grant"]["grantable"])
        with mock.patch(
            "notug_protocol.grants._interactive_confirmation", return_value=True
        ) as confirmation:
            self.assert_error(
                "POLICY_BLOCKED",
                lambda: grant_tug(str(tug["tug_id"]), self.vault),
            )
        confirmation.assert_not_called()

    def test_receipt_export_redacts_paths_and_never_includes_patch_bytes(self) -> None:
        session = self.open_session("redacted-export")
        sensitive_name = "src/customer-secret-name.txt"
        destination = session.worktree / sensitive_name
        destination.parent.mkdir()
        destination.write_bytes(b"synthetic content must remain in the patch only\n")
        tug = generate_tug(session.session_id, self.vault)

        exported = export_tug_receipt(str(tug["tug_id"]), self.vault)
        encoded = json.dumps(exported, sort_keys=True)

        self.assertEqual(exported["paths"], "redacted-scoped-aliases")
        self.assertNotIn(sensitive_name, encoded)
        self.assertNotIn("synthetic content", encoded)
        self.assertFalse(exported["source"]["patch_included"])
        self.assertRegex(exported["changes"][0]["path"], r"^path-[a-f0-9]{16}$")

        included = export_tug_receipt(str(tug["tug_id"]), self.vault, include_paths=True)
        self.assertIn(sensitive_name, json.dumps(included, sort_keys=True))

    def test_receipt_export_never_overwrites_or_targets_managed_storage(self) -> None:
        session = self.open_session("safe-export-destination")
        (session.worktree / "proposal.txt").write_bytes(b"synthetic export proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        events_path = self.vault.events_path(session.repository_id)
        head_path = self.vault.chain_head_path(session.repository_id)
        events_before = events_path.read_bytes()
        head_before = head_path.read_bytes()
        sentinel = self.root / "existing-unrelated.json"
        sentinel.write_bytes(b"preserve unrelated bytes\n")
        forbidden_new = self.vault.root / "exports" / "receipt.json"

        def local_export(tug_id: str, *, include_paths: bool = False) -> dict[str, object]:
            return export_tug_receipt(tug_id, self.vault, include_paths=include_paths)

        def invoke(output: Path) -> int:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch("notug_protocol.cli.Vault", return_value=self.vault),
                mock.patch("notug_protocol.cli.export_tug_receipt", side_effect=local_export),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                return cli.main(["export", str(tug["tug_id"]), "--output", str(output)])

        self.assertEqual(invoke(events_path), 2)
        self.assertEqual(invoke(sentinel), 2)
        self.assertEqual(invoke(forbidden_new), 2)
        self.assertEqual(events_path.read_bytes(), events_before)
        self.assertEqual(head_path.read_bytes(), head_before)
        self.assertEqual(sentinel.read_bytes(), b"preserve unrelated bytes\n")
        self.assertFalse(forbidden_new.exists())

    def test_repository_hooks_and_content_selected_clean_filters_remain_inert(self) -> None:
        hook_marker = self.root / "hook-ran"
        configured_hooks = self.root / "configured-hooks"
        configured_hooks.mkdir()
        post_checkout = configured_hooks / "post-checkout"
        post_checkout.write_text(
            f"#!/bin/sh\necho ran > '{hook_marker.as_posix()}'\n",
            encoding="utf-8",
        )
        post_checkout.chmod(0o755)
        self.git("config", "core.hooksPath", configured_hooks.as_posix())

        filter_marker = self.root / "filter-ran"
        filter_command = f"echo %f > '{filter_marker.as_posix()}'; cat"
        self.git("config", "filter.adversarial.clean", filter_command)
        self.git("config", "filter.adversarial.required", "true")
        replacement_marker = self.root / "replacement-filter-ran"
        trap_bin = self.root / "trap-bin"
        trap_bin.mkdir()
        cat_trap = trap_bin / "cat"
        cat_trap.write_text(
            f"#!/bin/sh\necho ran > '{replacement_marker.as_posix()}'\nexec /bin/cat \"$@\"\n",
            encoding="utf-8",
        )
        cat_trap.chmod(0o755)

        session = self.open_session("inert-git-instructions")
        self.assertFalse(hook_marker.exists())
        self.assertFalse(
            filter_marker.exists(),
            filter_marker.read_text(encoding="utf-8") if filter_marker.exists() else "",
        )
        (session.worktree / ".gitattributes").write_text(
            "*.trap filter=adversarial\n", encoding="utf-8"
        )
        (session.worktree / "payload.trap").write_text("proposal bytes\n", encoding="utf-8")
        self.assertFalse(
            filter_marker.exists(),
            filter_marker.read_text(encoding="utf-8") if filter_marker.exists() else "",
        )

        with mock.patch.dict(
            os.environ,
            {"PATH": str(trap_bin) + os.pathsep + os.environ.get("PATH", "")},
        ):
            tug = generate_tug(session.session_id, self.vault)

        self.assertFalse(
            filter_marker.exists(),
            filter_marker.read_text(encoding="utf-8") if filter_marker.exists() else "",
        )
        self.assertFalse(replacement_marker.exists())
        self.assertIn("payload.trap", tug["affected_paths"])
        patch = self.vault.patch_path(session.repository_id, str(tug["tug_id"])).read_bytes()
        self.assertIn(b"proposal bytes", patch)

    def test_baseline_selected_smudge_filter_is_inert_during_session_checkout(self) -> None:
        marker = self.root / "smudge-ran"
        self.git("config", "filter.adversarial.clean", "cat")
        self.git(
            "config",
            "filter.adversarial.smudge",
            f"echo %f > '{marker.as_posix()}'; cat",
        )
        self.git("config", "filter.adversarial.required", "true")
        (self.repository / ".gitattributes").write_text(
            "*.trap filter=adversarial\n", encoding="utf-8"
        )
        (self.repository / "baseline.trap").write_text("baseline bytes\n", encoding="utf-8")
        expected_bytes = (self.repository / "baseline.trap").read_bytes()
        self.git("add", ".gitattributes", "baseline.trap")
        self.git("commit", "-m", "baseline filter fixture")
        self.assertFalse(marker.exists())

        session = self.open_session("inert-smudge")

        self.assertFalse(marker.exists())
        self.assertEqual((session.worktree / "baseline.trap").read_bytes(), expected_bytes)

    def test_builtin_attribute_normalization_binds_raw_and_staged_bytes(self) -> None:
        protected_before = self.primary_snapshot()
        session = self.open_session("attribute-normalization")
        (session.worktree / ".gitattributes").write_bytes(b"*.normalize text eol=lf\n")
        raw_payload = b"first\r\nsecond\r\n"
        (session.worktree / "payload.normalize").write_bytes(raw_payload)

        tug = generate_tug(session.session_id, self.vault)

        evidence = tug["evidence"]
        self.assertIsInstance(evidence, dict)
        staged_payload = self.git("show", f"{evidence['snapshot_tree']}:payload.normalize")
        self.assertEqual(staged_payload, b"first\nsecond\n")
        workspace_manifest = json.loads(
            self.vault.changes_path(session.repository_id, str(tug["tug_id"]))
            .with_suffix(".workspace.json")
            .read_text(encoding="utf-8")
        )
        entries = {entry["path"]: entry for entry in workspace_manifest["entries"]}
        self.assertEqual(
            entries["payload.normalize"]["sha256"], hashlib.sha256(raw_payload).hexdigest()
        )
        self.assertEqual(self.primary_snapshot(), protected_before)

    def test_post_capture_workspace_mutation_fails_reconciliation(self) -> None:
        session = self.open_session("post-capture-mutation")
        payload = session.worktree / "mutation.txt"
        payload.write_bytes(b"captured bytes\n")
        original_manifest = changes._workspace_manifest

        def capture_then_mutate(worktree: Path) -> dict[str, object]:
            manifest = original_manifest(worktree)
            payload.write_bytes(b"mutated after capture\n")
            return manifest

        with mock.patch(
            "notug_protocol.changes._workspace_manifest",
            side_effect=capture_then_mutate,
        ):
            error = self.assert_error(
                "PROVENANCE_DIVERGENCE",
                lambda: generate_tug(session.session_id, self.vault),
            )

        self.assertIn("changed after", error.message)

    def test_ignored_untracked_file_may_remain_manifest_only(self) -> None:
        session = self.open_session("ignored-manifest-entry")
        (session.worktree / ".gitignore").write_bytes(b"*.local\n")
        (session.worktree / ".env.local").write_bytes(b"SYNTHETIC=value\n")

        tug = generate_tug(session.session_id, self.vault)

        self.assertIn(".gitignore", tug["affected_paths"])
        self.assertNotIn(".env.local", tug["affected_paths"])
        self.assertIn(".env.local", tug["ignored_sensitive_paths"])

    def test_populated_gitlink_must_match_its_pointer_and_remain_clean(self) -> None:
        dependency = self.root / "dependency-source"
        dependency.mkdir()

        def dependency_git(*arguments: str) -> bytes:
            completed = subprocess.run(
                (self.git_executable, "-C", str(dependency), *arguments),
                capture_output=True,
                check=False,
                shell=False,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            return completed.stdout

        dependency_git("init", "--initial-branch=main")
        dependency_git("config", "user.name", "NoTUG Integration Test")
        dependency_git("config", "user.email", "notug-integration@localhost.invalid")
        (dependency / "dependency.txt").write_bytes(b"pinned dependency bytes\n")
        dependency_git("add", "--all")
        dependency_git("commit", "-m", "dependency baseline")
        self.git(
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--",
            str(dependency),
            "vendor/dependency",
        )
        self.git("commit", "-m", "add pinned dependency")

        def populate(session_worktree: Path) -> None:
            completed = subprocess.run(
                (
                    self.git_executable,
                    "-C",
                    str(session_worktree),
                    "-c",
                    "protocol.file.allow=always",
                    "submodule",
                    "update",
                    "--init",
                    "--",
                    "vendor/dependency",
                ),
                capture_output=True,
                check=False,
                shell=False,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )

        clean_session = self.open_session("clean-populated-gitlink")
        populate(clean_session.worktree)
        (clean_session.worktree / "alpha.txt").write_bytes(b"main proposal\n")
        clean_tug = generate_tug(clean_session.session_id, self.vault)
        self.assertIn("alpha.txt", clean_tug["affected_paths"])

        dirty_session = self.open_session("dirty-populated-gitlink")
        populate(dirty_session.worktree)
        (dirty_session.worktree / "vendor" / "dependency" / "dependency.txt").write_bytes(
            b"unrepresented nested mutation\n"
        )
        (dirty_session.worktree / "alpha.txt").write_bytes(b"another main proposal\n")

        self.assert_error(
            "PROVENANCE_DIVERGENCE",
            lambda: generate_tug(dirty_session.session_id, self.vault),
        )

    def test_failed_agent_command_records_failure_and_keeps_session_open(self) -> None:
        protected_before = self.primary_snapshot()
        session = self.open_session("failed-command")
        script = (
            "from pathlib import Path; "
            "Path('partial.txt').write_bytes(b'partial\\n'); "
            "raise SystemExit(7)"
        )

        returncode = run_agent_command(
            session.session_id,
            [sys.executable, "-c", script],
            self.vault,
        )

        self.assertEqual(returncode, 7)
        stored = load_session(self.vault, session.repository_id, session.session_id)
        self.assertEqual(stored["state"], "SESSION_OPEN")
        self.assertEqual((session.worktree / "partial.txt").read_bytes(), b"partial\n")
        chain = ledger_for(self.vault, session.repository_id).verify()
        self.assertEqual(chain.events[-1]["event_type"], "RUN_FAILED")
        self.assertEqual(chain.events[-1]["payload"]["exit_status"], 7)
        self.assertEqual(self.primary_snapshot(), protected_before)

    def test_agent_command_streams_only_sanitized_child_output(self) -> None:
        session = self.open_session("hostile-agent-output")
        script = (
            "import os;"
            "os.write(1, b'agent-out\\n\\x1b]0;pwned\\x07\\xc2\\x9b\\xff');"
            "os.write(2, b'agent-err\\xe2\\x80\\xae\\n')"
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            returncode = run_agent_command(
                session.session_id,
                [sys.executable, "-c", script],
                self.vault,
            )

        self.assertEqual(returncode, 0)
        self.assertIn("agent-out", stdout.getvalue())
        self.assertIn(r"\u000a\u001b]0;pwned\u0007\u009b", stdout.getvalue())
        self.assertIn("\ufffd", stdout.getvalue())
        self.assertIn(r"agent-err\u202e\u000a", stderr.getvalue())
        for raw_control in ("\n", "\x07", "\x1b", "\x9b", "\u202e"):
            self.assertNotIn(raw_control, stdout.getvalue())
            self.assertNotIn(raw_control, stderr.getvalue())

    def test_node_codex_launch_is_bound_to_exact_session_worktree(self) -> None:
        session = self.open_session("codex-worktree-binding")
        codex_js = self.root / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
        command = ["node.exe", str(codex_js), "exec", "read-only prompt"]

        with (
            mock.patch(
                "notug_protocol.sessions.prepare_codex_workspace_access"
            ) as workspace_access,
            mock.patch("notug_protocol.sessions.run_sanitized_process", return_value=0) as runner,
        ):
            returncode = run_agent_command(session.session_id, command, self.vault)

        self.assertEqual(returncode, 0)
        effective = runner.call_args.args[0]
        self.assertEqual(
            effective,
            [
                command[0],
                command[1],
                "-C",
                str(session.worktree.resolve()),
                *command[2:],
            ],
        )
        self.assertEqual(runner.call_args.kwargs["cwd"], session.worktree)
        workspace_access.assert_called_once_with(
            self.vault,
            session.repository_id,
            session.worktree,
        )

    def test_streaming_codex_launch_uses_exact_process_cwd_and_workspace_access(self) -> None:
        session = self.open_session("streaming-codex-worktree-binding")
        codex_js = self.root / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
        command = ["node.exe", str(codex_js), "exec", "-"]

        with (
            mock.patch(
                "notug_protocol.sessions.prepare_codex_workspace_access"
            ) as workspace_access,
            mock.patch(
                "notug_protocol.sessions.run_cancellable_process",
                return_value=CancellableProcessResult(returncode=0, cancelled=False),
            ) as runner,
        ):
            result = run_agent_command_streaming(
                session.session_id,
                command,
                input_bytes=b"private prompt",
                stdout_callback=lambda _value: None,
                stderr_callback=lambda _value: None,
                cancel_event=threading.Event(),
                vault=self.vault,
            )

        self.assertEqual(result.exit_status, 0)
        self.assertEqual(
            runner.call_args.args[0],
            [
                command[0],
                command[1],
                "-C",
                str(session.worktree.resolve()),
                *command[2:],
            ],
        )
        self.assertEqual(runner.call_args.kwargs["cwd"], session.worktree)
        workspace_access.assert_called_once_with(
            self.vault,
            session.repository_id,
            session.worktree,
        )

    def test_codex_workspace_access_failure_prevents_launch_and_run_receipt(self) -> None:
        session = self.open_session("codex-worktree-access-failure")
        codex_js = self.root / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
        event_count = ledger_for(self.vault, session.repository_id).verify().count

        with (
            mock.patch(
                "notug_protocol.sessions.prepare_codex_workspace_access",
                side_effect=NoTugError(
                    "AGENT_WORKSPACE_ACCESS_FAILED",
                    "Windows session access could not be prepared",
                ),
            ),
            mock.patch("notug_protocol.sessions.run_sanitized_process") as runner,
        ):
            self.assert_error(
                "AGENT_WORKSPACE_ACCESS_FAILED",
                lambda: run_agent_command(
                    session.session_id,
                    ["node.exe", str(codex_js), "exec", "read-only prompt"],
                    self.vault,
                ),
            )

        runner.assert_not_called()
        self.assertEqual(
            ledger_for(self.vault, session.repository_id).verify().count,
            event_count,
        )

    def test_conflicting_codex_worktree_fails_without_run_receipt(self) -> None:
        session = self.open_session("codex-worktree-mismatch")
        codex_js = self.root / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
        event_count = ledger_for(self.vault, session.repository_id).verify().count

        self.assert_error(
            "AGENT_WORKSPACE_MISMATCH",
            lambda: run_agent_command(
                session.session_id,
                ["node.exe", str(codex_js), "-C", str(self.repository), "exec"],
                self.vault,
            ),
        )

        self.assertEqual(
            ledger_for(self.vault, session.repository_id).verify().count,
            event_count,
        )

    def test_validation_streams_only_sanitized_child_output(self) -> None:
        validation_script = (
            "import os;"
            "os.write(1, b'validation-out\\n\\x1b[31m\\xff');"
            "os.write(2, b'validation-err\\x07\\xe2\\x80\\xae')"
        )
        commands = json.dumps([[sys.executable, "-c", validation_script]])
        policy_path = self.vault.policy_path(self.initialized.repository_id)
        policy_path.write_bytes(
            policy_path.read_bytes().replace(
                b"commands = []",
                f"commands = {commands}".encode(),
            )
        )
        session = self.open_session("hostile-validation-output")
        (session.worktree / "alpha.txt").write_bytes(b"proposal with validation\n")
        tug = generate_tug(session.session_id, self.vault)
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            grant = self.grant(tug)

        self.assertEqual(len(grant["validation"]), 1)
        self.assertIn(r"validation-out\u000a\u001b[31m", stdout.getvalue())
        self.assertIn("\ufffd", stdout.getvalue())
        self.assertIn(r"validation-err\u0007\u202e", stderr.getvalue())
        for raw_control in ("\n", "\x07", "\x1b", "\u202e"):
            self.assertNotIn(raw_control, stdout.getvalue())
            self.assertNotIn(raw_control, stderr.getvalue())

    def test_agent_command_start_failure_keeps_verifiable_failure_evidence(self) -> None:
        session = self.open_session("command-start-failure")
        missing = self.root / "executable-that-does-not-exist"

        self.assert_error(
            "COMMAND_START_FAILED",
            lambda: run_agent_command(session.session_id, [str(missing)], self.vault),
        )

        report = verify_repository(self.repository, self.vault)
        self.assertTrue(report["ok"], report)

    @unittest.skipUnless(os.name == "nt", "Windows batch parsing is platform-specific")
    def test_direct_batch_agent_command_fails_closed_with_verifiable_evidence(self) -> None:
        session = self.open_session("direct-batch-command")
        batch = session.worktree / "probe.cmd"
        marker = session.worktree / "injected.txt"
        batch.write_bytes(b"@echo off\r\necho ARGS=[%*]\r\n")

        self.assert_error(
            "WINDOWS_BATCH_REQUIRES_EXPLICIT_SHELL",
            lambda: run_agent_command(
                session.session_id,
                [str(batch), "safe&echo.INJECTED>injected.txt"],
                self.vault,
            ),
        )

        self.assertFalse(marker.exists())
        report = verify_repository(self.repository, self.vault)
        self.assertTrue(report["ok"], report)

    def test_deny_records_disposition_without_repository_mutation(self) -> None:
        protected_before = self.primary_snapshot()
        session = self.open_session("deny-path")
        (session.worktree / "alpha.txt").write_bytes(b"denied proposal\n")
        tug = generate_tug(session.session_id, self.vault)

        denial = deny_tug(str(tug["tug_id"]), self.vault)

        self.assertEqual(denial["state"], "DENIED")
        stored = load_session(self.vault, session.repository_id, session.session_id)
        self.assertEqual(stored["state"], "DENIED")
        self.assertEqual(self.primary_snapshot(), protected_before)
        report = verify_repository(self.repository, self.vault)
        self.assertTrue(report["ok"], report)

    def test_grant_binds_only_selected_tug_and_preserves_primary_checkout(self) -> None:
        protected_before = self.primary_snapshot()
        first = self.open_session("unselected-tug")
        (first.worktree / "alpha.txt").write_bytes(b"first proposal\n")
        first_tug = generate_tug(first.session_id, self.vault)
        selected = self.open_session("selected-tug")
        (selected.worktree / "alpha.txt").write_bytes(b"selected proposal\n")
        selected_tug = generate_tug(selected.session_id, self.vault)

        grant = self.grant(selected_tug)

        self.assertEqual(grant["tug_id"], selected_tug["tug_id"])
        self.assertEqual(grant["tug_hash"], selected_tug["tug_hash"])
        self.assertNotEqual(grant["tug_hash"], first_tug["tug_hash"])
        self.assertEqual(grant["state"], "APPLIED")
        self.assertEqual(
            self.rev_parse(f"{grant['commit']}^{{tree}}"),
            selected_tug["evidence"]["snapshot_tree"],
        )
        self.assertEqual(
            self.git("show", f"{grant['commit']}:alpha.txt"),
            b"selected proposal\n",
        )
        self.assertEqual(self.git("status", "--porcelain", "--", "."), b"")
        self.assertEqual(self.primary_snapshot(), protected_before)
        _, pending = find_session(self.vault, first.session_id)
        self.assertEqual(pending["state"], "TUGGED")
        self.assertEqual(pending["tug_id"], first_tug["tug_id"])
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_baseline_branch_drift_blocks_grant_before_confirmation(self) -> None:
        session = self.open_session("baseline-drift")
        (session.worktree / "alpha.txt").write_bytes(b"proposal before drift\n")
        tug = generate_tug(session.session_id, self.vault)
        (self.repository / "advance.txt").write_bytes(b"authoritative advance\n")
        self.git("add", "--", "advance.txt")
        self.git("commit", "-m", "advance baseline branch")
        confirmations: list[str] = []

        with mock.patch(
            "notug_protocol.grants._interactive_confirmation",
            side_effect=lambda value: confirmations.append(value) is None,
        ):
            self.assert_error(
                "BASELINE_REF_DRIFT",
                lambda: grant_tug(str(tug["tug_id"]), self.vault),
            )

        self.assertEqual(confirmations, [])
        self.assertNotEqual(self.rev_parse("HEAD"), self.baseline)
        self.assertEqual(
            self.git_result(
                "show-ref",
                "--verify",
                "--quiet",
                f"refs/heads/notug/grant/{str(tug['tug_id']).split('_', 1)[1][:10]}",
            ).returncode,
            1,
        )

    def test_patch_tamper_blocks_grant_before_confirmation(self) -> None:
        session = self.open_session("patch-tamper")
        (session.worktree / "alpha.txt").write_bytes(b"reviewed proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        patch_path = self.vault.patch_path(session.repository_id, str(tug["tug_id"]))
        patch_path.write_bytes(patch_path.read_bytes() + b"\n# tampered\n")
        confirmations: list[str] = []

        with mock.patch(
            "notug_protocol.grants._interactive_confirmation",
            side_effect=lambda value: confirmations.append(value) is None,
        ):
            self.assert_error(
                "PATCH_HASH_MISMATCH",
                lambda: grant_tug(str(tug["tug_id"]), self.vault),
            )

        self.assertEqual(confirmations, [])
        stored = load_session(self.vault, session.repository_id, session.session_id)
        self.assertEqual(stored["state"], "TUGGED")

    def test_existing_branch_is_preserved_and_collision_safe_suffix_is_used(self) -> None:
        protected_before = self.primary_snapshot()
        session = self.open_session("branch-collision")
        (session.worktree / "alpha.txt").write_bytes(b"collision-safe proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        short = str(tug["tug_id"]).split("_", 1)[1][:10]
        occupied = f"notug/grant/{short}"
        self.git("branch", occupied, self.baseline)
        occupied_before = self.rev_parse(f"refs/heads/{occupied}")

        grant = self.grant(tug)

        self.assertEqual(grant["branch"], f"{occupied}-2")
        self.assertEqual(self.rev_parse(f"refs/heads/{occupied}"), occupied_before)
        self.assertEqual(self.primary_snapshot(), protected_before)

    def test_existing_integration_path_fails_closed_and_is_not_removed(self) -> None:
        session = self.open_session("path-collision")
        (session.worktree / "alpha.txt").write_bytes(b"path collision proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        grant_id = "grant_aaaaaaaaaaaaaaaa"
        collision = self.vault.worktree_path(session.repository_id, "integration", grant_id)
        collision.mkdir(parents=True)
        sentinel = collision / "unrelated.txt"
        sentinel.write_bytes(b"preserve unrelated path\n")
        confirmations: list[str] = []

        with (
            mock.patch("notug_protocol.grants.new_identifier", return_value=grant_id),
            mock.patch(
                "notug_protocol.grants._interactive_confirmation",
                side_effect=lambda value: confirmations.append(value) is None,
            ),
        ):
            self.assert_error(
                "WORKTREE_PATH_COLLISION",
                lambda: grant_tug(str(tug["tug_id"]), self.vault),
            )

        self.assertEqual(confirmations, [])
        self.assertEqual(sentinel.read_bytes(), b"preserve unrelated path\n")
        self.assertEqual(
            self.git_result(
                "show-ref",
                "--verify",
                "--quiet",
                f"refs/heads/notug/grant/{str(tug['tug_id']).split('_', 1)[1][:10]}",
            ).returncode,
            1,
        )

    def test_revoke_removes_only_unmerged_generated_branch_and_worktree(self) -> None:
        protected_before = self.primary_snapshot()
        session = self.open_session("revoke-unmerged")
        (session.worktree / "alpha.txt").write_bytes(b"approved then revoked\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        integration_worktree = Path(str(grant["worktree"]))
        self.assertTrue(integration_worktree.is_dir())

        disposition = revoke_grant(str(tug["tug_id"]), self.vault)

        self.assertEqual(disposition["kind"], "unmerged_branch_removed")
        self.assertFalse(integration_worktree.exists())
        self.assertEqual(
            self.git_result(
                "show-ref", "--verify", "--quiet", f"refs/heads/{grant['branch']}"
            ).returncode,
            1,
        )
        _, stored = find_session(self.vault, session.session_id)
        self.assertEqual(stored["state"], "REVOKED")
        self.assertEqual(self.primary_snapshot(), protected_before)
        report = verify_repository(self.repository, self.vault)
        self.assertTrue(report["ok"], report)

    def test_revoke_tampering_cannot_redirect_cleanup_to_unrelated_git_resources(self) -> None:
        session = self.open_session("revoke-selector-tamper")
        (session.worktree / "alpha.txt").write_bytes(b"approved safety proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        grant_path = self.vault.grant_path(session.repository_id, str(grant["grant_id"]))
        original = grant_path.read_bytes()
        integration_worktree = Path(str(grant["worktree"]))

        unrelated_branch = "unrelated-user-branch"
        unrelated_worktree = self.root / "unrelated-user-worktree"
        self.git(
            "worktree",
            "add",
            "-b",
            unrelated_branch,
            str(unrelated_worktree),
            self.baseline,
        )
        sentinel = unrelated_worktree / "user-data.txt"
        sentinel.write_bytes(b"must remain untouched\n")

        edits = (
            ("worktree", str(unrelated_worktree.resolve()), "GRANT_WORKTREE_DIVERGENCE"),
            ("branch", unrelated_branch, "GRANT_RECEIPT_DIVERGENCE"),
            ("commit", self.baseline, "GRANT_RECEIPT_DIVERGENCE"),
        )
        for field, replacement, expected_code in edits:
            with self.subTest(field=field):
                altered = json.loads(original)
                altered[field] = replacement
                atomic_write_json(grant_path, altered)

                self.assert_error(
                    expected_code,
                    lambda: revoke_grant(str(tug["tug_id"]), self.vault),
                )

                self.assertTrue(integration_worktree.is_dir())
                self.assertEqual(self.rev_parse(f"refs/heads/{grant['branch']}"), grant["commit"])
                self.assertTrue(unrelated_worktree.is_dir())
                self.assertEqual(sentinel.read_bytes(), b"must remain untouched\n")
                self.assertEqual(self.rev_parse(f"refs/heads/{unrelated_branch}"), self.baseline)
                grant_path.write_bytes(original)

        revoke_grant(str(tug["tug_id"]), self.vault)
        self.git("worktree", "remove", "--force", str(unrelated_worktree))
        self.git("branch", "-D", unrelated_branch)

    def test_revoke_rejects_link_redirect_after_managed_worktree_is_moved(self) -> None:
        session = self.open_session("revoke-link-redirect")
        (session.worktree / "alpha.txt").write_bytes(b"approved link safety proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        managed = Path(str(grant["worktree"]))
        external = self.root / "moved-integration-worktree"
        shutil.move(str(managed), str(external))
        try:
            self.create_directory_link(external, managed)
        except OSError as exc:
            shutil.move(str(external), str(managed))
            self.skipTest(f"Directory links are unavailable: {exc}")
        sentinel = external / "unrelated-user-data.txt"
        sentinel.write_bytes(b"must survive linked revoke\n")
        try:
            self.assert_error(
                "GRANT_WORKTREE_DIVERGENCE",
                lambda: revoke_grant(str(tug["tug_id"]), self.vault),
            )
            self.assertEqual(sentinel.read_bytes(), b"must survive linked revoke\n")
            self.assertEqual(self.rev_parse(f"refs/heads/{grant['branch']}"), grant["commit"])
        finally:
            self.remove_directory_link(managed)
            shutil.move(str(external), str(managed))
        (managed / "unrelated-user-data.txt").unlink()
        revoke_grant(str(tug["tug_id"]), self.vault)

    def test_applied_session_can_be_archived_then_grant_revoked_and_verified(self) -> None:
        session = self.open_session("archive-before-revoke")
        (session.worktree / "alpha.txt").write_bytes(b"archive then revoke proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        self.grant(tug)

        archive_session(session.session_id, self.vault)
        self.assertFalse(session.worktree.exists())
        disposition = revoke_grant(str(tug["tug_id"]), self.vault)

        self.assertEqual(disposition["kind"], "unmerged_branch_removed")
        stored = load_session(self.vault, session.repository_id, session.session_id)
        self.assertEqual(stored["state"], "REVOKED")
        self.assertIsNotNone(stored["archived_at"])
        report = verify_repository(self.repository, self.vault)
        self.assertTrue(report["ok"], report)

    def test_duplicate_archive_has_precise_error_and_no_durable_mutation(self) -> None:
        session = self.open_session("duplicate-archive")
        (session.worktree / "alpha.txt").write_bytes(b"denied archive proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        deny_tug(str(tug["tug_id"]), self.vault)
        archive_session(session.session_id, self.vault)
        events_before = ledger_for(self.vault, session.repository_id).verify().count
        worktrees_before = self.git("worktree", "list", "--porcelain")

        self.assert_error(
            "SESSION_ALREADY_ARCHIVED",
            lambda: archive_session(session.session_id, self.vault),
        )

        self.assertEqual(
            ledger_for(self.vault, session.repository_id).verify().count,
            events_before,
        )
        self.assertEqual(self.git("worktree", "list", "--porcelain"), worktrees_before)
        report = verify_repository(self.repository, self.vault)
        self.assertTrue(report["ok"], report)

    def test_archive_tampering_cannot_redirect_removal_to_another_session(self) -> None:
        first = self.open_session("archive-selector-first")
        (first.worktree / "alpha.txt").write_bytes(b"first denied proposal\n")
        first_tug = generate_tug(first.session_id, self.vault)
        deny_tug(str(first_tug["tug_id"]), self.vault)

        second = self.open_session("archive-selector-second")
        (second.worktree / "alpha.txt").write_bytes(b"second denied proposal\n")
        second_tug = generate_tug(second.session_id, self.vault)
        deny_tug(str(second_tug["tug_id"]), self.vault)
        second_sentinel = second.worktree / "unrelated-user-data.txt"
        second_sentinel.write_bytes(b"must survive redirected archive\n")

        first_path = self.vault.session_path(first.repository_id, first.session_id)
        original = first_path.read_bytes()
        first_metadata = json.loads(original)
        second_metadata = load_session(self.vault, second.repository_id, second.session_id)
        edits = (
            (
                "worktree",
                lambda value: value.__setitem__("worktree", str(second.worktree.resolve())),
                "WORKTREE_ADMIN_DIVERGENCE",
            ),
            (
                "internal-id",
                lambda value: (
                    value.__setitem__("session_id", second.session_id),
                    value.__setitem__("worktree", str(second.worktree.resolve())),
                ),
                "SESSION_ID_MISMATCH",
            ),
            (
                "disposition",
                lambda value: (
                    value.__setitem__("tug_id", second_metadata["tug_id"]),
                    value.__setitem__("last_event_hash", second_metadata["last_event_hash"]),
                ),
                "SESSION_RECEIPT_DIVERGENCE",
            ),
        )
        for label, edit, expected_code in edits:
            with self.subTest(edit=label):
                altered = dict(first_metadata)
                edit(altered)
                atomic_write_json(first_path, altered)

                self.assert_error(
                    expected_code,
                    lambda: archive_session(first.session_id, self.vault),
                )

                self.assertTrue(first.worktree.is_dir())
                self.assertTrue(second.worktree.is_dir())
                self.assertEqual(second_sentinel.read_bytes(), b"must survive redirected archive\n")
                first_path.write_bytes(original)

        archive_session(first.session_id, self.vault)
        self.assertFalse(first.worktree.exists())
        self.assertTrue(second.worktree.is_dir())
        self.assertEqual(second_sentinel.read_bytes(), b"must survive redirected archive\n")
        self.assert_error(
            "WORKSPACE_POST_REVIEW_DRIFT",
            lambda: archive_session(second.session_id, self.vault),
        )
        self.assertEqual(second_sentinel.read_bytes(), b"must survive redirected archive\n")
        second_sentinel.unlink()
        archive_session(second.session_id, self.vault)

    def test_archive_rejects_link_redirect_after_managed_worktree_is_moved(self) -> None:
        session = self.open_session("archive-link-redirect")
        (session.worktree / "alpha.txt").write_bytes(b"denied link safety proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        deny_tug(str(tug["tug_id"]), self.vault)
        managed = session.worktree
        external = self.root / "moved-session-worktree"
        shutil.move(str(managed), str(external))
        try:
            self.create_directory_link(external, managed)
        except OSError as exc:
            shutil.move(str(external), str(managed))
            self.skipTest(f"Directory links are unavailable: {exc}")
        sentinel = external / "unrelated-user-data.txt"
        sentinel.write_bytes(b"must survive linked archive\n")
        try:
            self.assert_error(
                "WORKTREE_ADMIN_DIVERGENCE",
                lambda: archive_session(session.session_id, self.vault),
            )
            self.assertEqual(sentinel.read_bytes(), b"must survive linked archive\n")
        finally:
            self.remove_directory_link(managed)
            shutil.move(str(external), str(managed))
        restored_sentinel = managed / sentinel.name
        self.assert_error(
            "WORKSPACE_POST_REVIEW_DRIFT",
            lambda: archive_session(session.session_id, self.vault),
        )
        self.assertEqual(restored_sentinel.read_bytes(), b"must survive linked archive\n")
        restored_sentinel.unlink()
        archive_session(session.session_id, self.vault)

    def test_merged_grant_creates_revert_branch_without_rewriting_source(self) -> None:
        merge_marker = self.root / "merge-driver-ran"
        self.git(
            "config",
            "merge.adversarial.driver",
            f"echo ran > '{merge_marker.as_posix()}'; cp %B %A",
        )
        session = self.open_session("revoke-merged")
        (session.worktree / "alpha.txt").write_bytes(b"merged approved proposal\n")
        (session.worktree / ".gitattributes").write_bytes(b"alpha.txt merge=adversarial\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        self.git("merge", "--ff-only", str(grant["branch"]))
        merged_head = self.rev_parse("HEAD")

        disposition = revoke_grant(str(tug["tug_id"]), self.vault)

        self.assertEqual(disposition["kind"], "revert_branch_created")
        self.assertEqual(self.rev_parse("HEAD"), merged_head)
        self.assertEqual(merged_head, grant["commit"])
        self.assertEqual(
            self.rev_parse(f"{disposition['commit']}^{{tree}}"),
            self.rev_parse(f"{self.baseline}^{{tree}}"),
        )
        self.assertFalse(merge_marker.exists())
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_self_consistent_tug_rewrite_is_rejected_by_generation_receipt(self) -> None:
        session = self.open_session("receipt-bound-tug")
        (session.worktree / "alpha.txt").write_bytes(b"receipt-bound proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        tug_path = self.vault.tug_path(session.repository_id, str(tug["tug_id"]))
        original = tug_path.read_bytes()
        altered = json.loads(original)
        altered["risk_summary"]["overall_severity"] = "low"
        altered["tug_hash"] = tug_hash(altered)
        atomic_write_json(tug_path, altered)

        self.assert_error(
            "TUG_RECEIPT_MISMATCH",
            lambda: deny_tug(str(tug["tug_id"]), self.vault),
        )

        tug_path.write_bytes(original)
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_tug_artifact_cannot_be_substituted_under_another_tug_filename(self) -> None:
        first = self.open_session("tug-substitution-first")
        (first.worktree / "alpha.txt").write_bytes(b"first proposal\n")
        first_tug = generate_tug(first.session_id, self.vault)
        second = self.open_session("tug-substitution-second")
        (second.worktree / "alpha.txt").write_bytes(b"second proposal\n")
        second_tug = generate_tug(second.session_id, self.vault)
        first_path = self.vault.tug_path(first.repository_id, str(first_tug["tug_id"]))
        second_path = self.vault.tug_path(second.repository_id, str(second_tug["tug_id"]))
        original = first_path.read_bytes()
        first_path.write_bytes(second_path.read_bytes())

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn("TUG_ID_MISMATCH", {issue["code"] for issue in report["issues"]})
        self.assert_error(
            "TUG_ID_MISMATCH",
            lambda: export_tug_receipt(str(first_tug["tug_id"]), self.vault),
        )
        first_path.write_bytes(original)
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_denial_receipt_remains_authoritative_when_session_save_is_interrupted(self) -> None:
        session = self.open_session("interrupted-denial")
        (session.worktree / "alpha.txt").write_bytes(b"proposal denied before crash\n")
        tug = generate_tug(session.session_id, self.vault)

        with (
            mock.patch(
                "notug_protocol.tug.save_session",
                side_effect=RuntimeError("simulated snapshot interruption"),
            ),
            self.assertRaises(RuntimeError),
        ):
            deny_tug(str(tug["tug_id"]), self.vault)

        stored = load_session(self.vault, session.repository_id, session.session_id)
        self.assertEqual(stored["state"], "TUGGED")
        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn("SESSION_RECEIPT_DIVERGENCE", {issue["code"] for issue in report["issues"]})
        with mock.patch(
            "notug_protocol.grants._interactive_confirmation", return_value=True
        ) as confirmation:
            self.assert_error(
                "TUG_ALREADY_DENIED",
                lambda: grant_tug(str(tug["tug_id"]), self.vault),
            )
        confirmation.assert_not_called()

    def test_divergence_receipt_blocks_retries_when_session_save_is_interrupted(self) -> None:
        session = self.open_session("interrupted-divergence")
        (self.repository / "source-advanced.txt").write_bytes(b"new protected baseline\n")
        self.git("add", "source-advanced.txt")
        self.git("commit", "-m", "advance protected source")

        with (
            mock.patch(
                "notug_protocol.tug.save_session",
                side_effect=RuntimeError("simulated snapshot interruption"),
            ),
            self.assertRaises(RuntimeError),
        ):
            generate_tug(session.session_id, self.vault)

        stored = load_session(self.vault, session.repository_id, session.session_id)
        self.assertEqual(stored["state"], "SESSION_OPEN")
        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn("SESSION_RECEIPT_DIVERGENCE", {issue["code"] for issue in report["issues"]})
        self.assert_error(
            "SESSION_RECEIPT_DIVERGENCE",
            lambda: generate_tug(session.session_id, self.vault),
        )
        self.assert_error(
            "SESSION_RECEIPT_DIVERGENCE",
            lambda: run_agent_command(
                session.session_id, [sys.executable, "-c", "pass"], self.vault
            ),
        )

    def test_verify_fails_closed_for_interrupted_running_operation(self) -> None:
        session = self.open_session("interrupted-run")
        real_run = subprocess.run

        def interrupt_agent(command: object, *args: object, **kwargs: object) -> object:
            if isinstance(command, list) and command and command[0] == sys.executable:
                raise KeyboardInterrupt
            return real_run(command, *args, **kwargs)  # type: ignore[arg-type]

        with (
            mock.patch("notug_protocol.sessions.subprocess.run", side_effect=interrupt_agent),
            self.assertRaises(KeyboardInterrupt),
        ):
            run_agent_command(session.session_id, [sys.executable, "-c", "pass"], self.vault)

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn(
            "OPERATION_TRANSITION_INCOMPLETE",
            {issue["code"] for issue in report["issues"]},
        )

    def test_verify_fails_closed_for_interrupted_granted_transition(self) -> None:
        session = self.open_session("interrupted-grant")
        (session.worktree / "alpha.txt").write_bytes(b"grant interrupted after issuance\n")
        tug = generate_tug(session.session_id, self.vault)

        with (
            mock.patch("notug_protocol.grants._interactive_confirmation", return_value=True),
            mock.patch(
                "notug_protocol.grants._validation_commands",
                side_effect=KeyboardInterrupt,
            ),
            mock.patch("notug_protocol.grants._record_grant_failure"),
        ):
            self.assert_error(
                "GRANT_APPLICATION_FAILED",
                lambda: grant_tug(str(tug["tug_id"]), self.vault),
            )

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        codes = {issue["code"] for issue in report["issues"]}
        self.assertIn("SESSION_TRANSITION_INCOMPLETE", codes)
        self.assertIn("GRANT_TRANSITION_INCOMPLETE", codes)

    def test_verify_detects_orphan_session_worktree_before_creation_receipt(self) -> None:
        orphan_id = "session_aaaaaaaaaaaaaaaa"
        orphan = self.vault.worktree_path(self.initialized.repository_id, "session", orphan_id)
        self.git("worktree", "add", "--detach", str(orphan), self.baseline)
        try:
            report = verify_repository(self.repository, self.vault)
            self.assertFalse(report["ok"])
            self.assertIn(
                "UNCLAIMED_SESSION_WORKTREE",
                {issue["code"] for issue in report["issues"]},
            )
        finally:
            self.git("worktree", "remove", "--force", str(orphan))

    def test_verify_detects_partial_revert_branch_and_worktree_without_receipt(self) -> None:
        session = self.open_session("partial-revert-resources")
        (session.worktree / "alpha.txt").write_bytes(b"approved before partial revert\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        revoke_id = "revoke_aaaaaaaaaaaaaaaa"
        revert = self.vault.worktree_path(session.repository_id, "revert", revoke_id)
        revert_branch = "notug/revert/interrupted"
        self.git(
            "worktree",
            "add",
            "-b",
            revert_branch,
            str(revert),
            str(grant["commit"]),
        )
        try:
            report = verify_repository(self.repository, self.vault)
            self.assertFalse(report["ok"])
            codes = {issue["code"] for issue in report["issues"]}
            self.assertIn("UNCLAIMED_REVERT_WORKTREE", codes)
            self.assertIn("UNCLAIMED_NOTUG_BRANCH", codes)
        finally:
            self.git("worktree", "remove", "--force", str(revert))
            self.git("branch", "-D", revert_branch)

    def test_verify_detects_premature_revocation_evidence_ref(self) -> None:
        session = self.open_session("premature-evidence-ref")
        (session.worktree / "alpha.txt").write_bytes(b"approved before evidence ref\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        evidence_ref = f"refs/notug/revoked/{grant['grant_id']}"
        self.git("update-ref", evidence_ref, str(grant["commit"]))
        try:
            report = verify_repository(self.repository, self.vault)
            self.assertFalse(report["ok"])
            self.assertIn(
                "UNCLAIMED_REVOCATION_EVIDENCE_REF",
                {issue["code"] for issue in report["issues"]},
            )
        finally:
            self.git("update-ref", "-d", evidence_ref)

    def test_verify_detects_failed_grant_resource_residue(self) -> None:
        session = self.open_session("failed-grant-residue")
        (session.worktree / "alpha.txt").write_bytes(b"proposal that fails validation\n")
        tug = generate_tug(session.session_id, self.vault)
        with (
            mock.patch("notug_protocol.grants._interactive_confirmation", return_value=True),
            mock.patch(
                "notug_protocol.grants._validation_commands",
                side_effect=NoTugError("VALIDATION_FAILED", "synthetic validation failure"),
            ),
        ):
            self.assert_error(
                "VALIDATION_FAILED",
                lambda: grant_tug(str(tug["tug_id"]), self.vault),
            )

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn(
            "FAILED_GRANT_RESOURCE_RESIDUE",
            {issue["code"] for issue in report["issues"]},
        )

    def test_verify_rejects_managed_worktree_link_alias_between_two_grants(self) -> None:
        first = self.open_session("alias-first-grant")
        (first.worktree / "alpha.txt").write_bytes(b"first approved proposal\n")
        first_grant = self.grant(generate_tug(first.session_id, self.vault))
        second = self.open_session("alias-second-grant")
        (second.worktree / "alpha.txt").write_bytes(b"second approved proposal\n")
        second_grant = self.grant(generate_tug(second.session_id, self.vault))
        first_worktree = Path(str(first_grant["worktree"]))
        second_worktree = Path(str(second_grant["worktree"]))
        backup = self.root / "first-integration-backup"
        shutil.move(str(first_worktree), str(backup))
        try:
            self.create_directory_link(second_worktree, first_worktree)
        except OSError as exc:
            shutil.move(str(backup), str(first_worktree))
            self.skipTest(f"Directory links are unavailable: {exc}")
        try:
            report = verify_repository(self.repository, self.vault)
            self.assertFalse(report["ok"])
            codes = {issue["code"] for issue in report["issues"]}
            self.assertTrue({"GRANT_WORKTREE_DIVERGENCE", "MANAGED_WORKTREE_PATH_REDIRECT"} & codes)
            self.assertEqual(
                (second_worktree / "alpha.txt").read_bytes(), b"second approved proposal\n"
            )
        finally:
            self.remove_directory_link(first_worktree)
            shutil.move(str(backup), str(first_worktree))
        self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_verify_detects_interrupted_unclaimed_tug_artifacts(self) -> None:
        session = self.open_session("interrupted-tug-artifacts")
        (session.worktree / "alpha.txt").write_bytes(b"proposal before tug receipt\n")
        real_ledger = ledger_for(self.vault, session.repository_id)
        with (
            mock.patch("notug_protocol.tug.ledger_for", return_value=real_ledger),
            mock.patch.object(real_ledger, "append_transition", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            generate_tug(session.session_id, self.vault)

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        codes = {issue["code"] for issue in report["issues"]}
        self.assertTrue(
            {
                "UNCLAIMED_TUG_ARTIFACT",
                "UNCLAIMED_TUG_PATCH",
                "UNCLAIMED_TUG_CHANGES",
                "UNCLAIMED_TUG_WORKSPACE_MANIFEST",
                "UNCLAIMED_TUG_WORK_DIRECTORY",
            }.issubset(codes)
        )
        self.assertNotIn("proposal before tug receipt", json.dumps(report))

    def test_verify_detects_preconfirmation_grant_operation_directory(self) -> None:
        operation = (
            self.vault.repository_dir(self.initialized.repository_id)
            / "operations"
            / "grant_aaaaaaaaaaaaaaaa"
        )
        operation.mkdir()
        (operation / "proposal.patch").write_bytes(b"sensitive interrupted proposal bytes\n")

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn(
            "UNCLAIMED_GRANT_OPERATION_DIRECTORY",
            {issue["code"] for issue in report["issues"]},
        )
        self.assertNotIn("sensitive interrupted proposal bytes", json.dumps(report))

    def test_verify_detects_advanced_protected_branch_for_open_session(self) -> None:
        self.open_session("verify-branch-advance")
        (self.repository / "alpha.txt").write_bytes(b"protected branch advanced\n")
        self.git("add", "alpha.txt")
        self.git("commit", "-m", "advance protected branch")

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn(
            "BASELINE_REF_DRIFT",
            {issue["code"] for issue in report["issues"]},
        )

    def test_verify_detects_dirty_protected_checkout_for_open_session(self) -> None:
        self.open_session("verify-dirty-checkout")
        dirty = self.repository / "untracked-protected-work.txt"
        dirty.write_bytes(b"must remain untouched\n")

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn(
            "SOURCE_DIRTY_DRIFT",
            {issue["code"] for issue in report["issues"]},
        )
        self.assertEqual(dirty.read_bytes(), b"must remain untouched\n")

    def test_verify_reports_receipt_consistent_diverged_session_as_non_ok(self) -> None:
        session = self.open_session("verify-diverged-state")
        (self.repository / "alpha.txt").write_bytes(b"protected branch diverged\n")
        self.git("add", "alpha.txt")
        self.git("commit", "-m", "diverge protected branch")
        self.assert_error(
            "BASELINE_REF_DRIFT",
            lambda: generate_tug(session.session_id, self.vault),
        )

        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn(
            "SESSION_DIVERGED_STATE",
            {issue["code"] for issue in report["issues"]},
        )

    def test_verify_detects_deleted_required_artifacts(self) -> None:
        session = self.open_session("missing-artifacts")
        run_agent_command(session.session_id, [sys.executable, "-c", "pass"], self.vault)
        (session.worktree / "alpha.txt").write_bytes(b"artifact proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        operation_path = next(
            self.vault.repository_dir(session.repository_id).glob("operations/*.json")
        )
        artifacts = {
            self.vault.session_path(session.repository_id, session.session_id): (
                "SESSION_ARTIFACT_MISSING"
            ),
            operation_path: "OPERATION_ARTIFACT_MISSING",
            self.vault.tug_path(session.repository_id, str(tug["tug_id"])): (
                "TUG_ARTIFACT_MISSING"
            ),
            self.vault.grant_path(session.repository_id, str(grant["grant_id"])): (
                "GRANT_ARTIFACT_MISSING"
            ),
        }

        for path, expected_code in artifacts.items():
            with self.subTest(artifact=path.name):
                original = path.read_bytes()
                path.unlink()
                report = verify_repository(self.repository, self.vault)
                self.assertFalse(report["ok"])
                self.assertIn(expected_code, {issue["code"] for issue in report["issues"]})
                path.write_bytes(original)
                self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_verify_detects_session_operation_and_grant_metadata_edits(self) -> None:
        session = self.open_session("metadata-tamper")
        run_agent_command(session.session_id, [sys.executable, "-c", "pass"], self.vault)
        (session.worktree / "alpha.txt").write_bytes(b"metadata-bound proposal\n")
        tug = generate_tug(session.session_id, self.vault)
        grant = self.grant(tug)
        operation_path = next(
            self.vault.repository_dir(session.repository_id).glob("operations/*.json")
        )
        session_path = self.vault.session_path(session.repository_id, session.session_id)
        grant_path = self.vault.grant_path(session.repository_id, str(grant["grant_id"]))

        edits = (
            (session_path, lambda value: value.__setitem__("name", "altered-name")),
            (
                operation_path,
                lambda value: (
                    value["command"]["arguments"].append("altered"),
                    value["command"].__setitem__(
                        "argument_count", len(value["command"]["arguments"])
                    ),
                ),
            ),
            (
                grant_path,
                lambda value: value.__setitem__("issued_at", "2026-01-01T00:00:00.000Z"),
            ),
            (operation_path, lambda value: value.__setitem__("schema_version", True)),
            (grant_path, lambda value: value.__setitem__("schema_version", True)),
        )
        for path, edit in edits:
            with self.subTest(artifact=path.name):
                original = path.read_bytes()
                value = json.loads(original)
                edit(value)
                atomic_write_json(path, value)
                report = verify_repository(self.repository, self.vault)
                self.assertFalse(report["ok"])
                path.write_bytes(original)
                self.assertTrue(verify_repository(self.repository, self.vault)["ok"])

    def test_verify_reports_corrupt_receipt_and_cli_json_remains_valid(self) -> None:
        events = self.vault.events_path(self.initialized.repository_id)
        events.write_bytes(
            events.read_bytes().replace(
                b"REPOSITORY_INITIALIZED",
                b"REPOSITORY_CORRUPTED",
                1,
            )
        )
        report = verify_repository(self.repository, self.vault)
        self.assertFalse(report["ok"])
        self.assertIn(
            report["issues"][0]["code"],
            {"RECEIPT_CHAIN_INVALID", "RECEIPT_CHAIN_HEAD_MISMATCH"},
        )

        output = io.StringIO()
        with (
            mock.patch.object(
                cli,
                "verify_repository",
                side_effect=lambda path: verify_repository(path, self.vault),
            ),
            contextlib.redirect_stdout(output),
        ):
            returncode = cli.main(["verify", str(self.repository), "--json"])

        payload = json.loads(output.getvalue())
        self.assertEqual(returncode, 3)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["mutation_lock"], "active")
        self.assertTrue(payload["issues"])


if __name__ == "__main__":
    unittest.main()
