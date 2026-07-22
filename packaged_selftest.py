"""Opt-in governed acceptance exercised from the frozen desktop executable."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from ..application import (
    create_session,
    protect_repository,
    repository_status,
    run_agent_task,
    session_change_status,
    submit_session,
)
from .codex import build_codex_command, discover_codex

PACKAGED_SELF_TEST_FILE = "LEUCOFORM-PACKAGED-E2E.md"
PACKAGED_SELF_TEST_BYTES = b"packaged evidence\n"


class _JsonlProbe:
    def __init__(self, expected_worktree: Path) -> None:
        self._expected = str(expected_worktree.resolve())
        self._pending = ""
        self.malformed = False
        self.command_count = 0
        self.cwd_verified = False
        self.relative_command_verified = False

    def feed(self, chunk: str) -> None:
        self._pending += chunk
        lines = self._pending.splitlines(keepends=True)
        self._pending = ""
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._pending = lines.pop()
        for line in lines:
            self._inspect(line.rstrip("\r\n"))

    def finish(self) -> None:
        if self._pending:
            self._inspect(self._pending)
            self._pending = ""

    def _inspect(self, line: str) -> None:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            self.malformed = True
            return
        if not isinstance(event, dict):
            return
        item = event.get("item")
        if not isinstance(item, dict) or item.get("type") != "command_execution":
            return
        command = item.get("command")
        output = item.get("aggregated_output")
        exit_code = item.get("exit_code")
        if not isinstance(command, str) or not isinstance(output, str) or exit_code is None:
            return
        self.command_count += 1
        if exit_code != 0:
            return
        forbidden = (self._expected, "set-location", "push-location", "-workingdirectory")
        self.relative_command_verified = all(
            value.casefold() not in command.casefold() for value in forbidden
        )
        if self._expected.casefold() in output.casefold():
            self.cwd_verified = True


def _affected_paths(tug: dict[str, Any]) -> tuple[str, ...]:
    paths = tug.get("affected_paths")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        return ()
    return tuple(paths)


def run_packaged_governed_self_test(repository: Path) -> int:
    """Create one real Codex proposal and Tug without granting or disposing it."""

    before = repository_status(repository)
    if not before.clean or (repository / PACKAGED_SELF_TEST_FILE).exists():
        return 10
    if not before.initialized:
        protect_repository(repository)
    installation = discover_codex()
    session = create_session(repository, f"packaged-self-test-{os.getpid()}")
    worktree = Path(session.worktree)
    probe = _JsonlProbe(worktree)
    prompt = (
        "Use exactly one PowerShell command without Set-Location, Push-Location, "
        "-WorkingDirectory, an absolute workspace path, or a file-editing tool. "
        f"From the current working directory, write exactly the bytes {PACKAGED_SELF_TEST_BYTES!r} "
        f"to .\\{PACKAGED_SELF_TEST_FILE}, read that same relative path, run git status "
        "--short, and print (Get-Location).Path. Make no other changes."
    ).encode()
    result = run_agent_task(
        session.session_id,
        build_codex_command(installation),
        input_bytes=prompt,
        stdout_callback=probe.feed,
        stderr_callback=lambda _chunk: None,
        cancel_event=threading.Event(),
    )
    probe.finish()
    if result.cancelled or result.exit_status != 0:
        return 11
    if (
        probe.malformed
        or probe.command_count != 1
        or not probe.cwd_verified
        or not probe.relative_command_verified
    ):
        return 12
    if not session_change_status(session.session_id).changed:
        return 13
    try:
        if not (worktree / PACKAGED_SELF_TEST_FILE).read_bytes():
            return 14
    except OSError:
        return 14
    submission = submit_session(session.session_id)
    if _affected_paths(submission.tug) != (PACKAGED_SELF_TEST_FILE,):
        return 15
    after = repository_status(repository)
    if (
        not after.clean
        or after.baseline_commit != before.baseline_commit
        or after.branch != before.branch
    ):
        return 16
    return 0
