"""Narrow Windows access preparation for Codex-managed session worktrees."""

from __future__ import annotations

import csv
import io
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from .errors import NoTugError
from .vault import Vault

AclRunner = Callable[..., subprocess.CompletedProcess[bytes]]
CODEX_SANDBOX_ACCOUNT = "CodexSandboxUsers"
WINDOWS_ACL_TIMEOUT_SECONDS = 10
_SID_RE = re.compile(r"S-1-(?:\d+-)+\d+")


def _windows_creation_flags() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _windows_system_tool(name: str) -> str:
    system_root = os.environ.get("SYSTEMROOT")
    if system_root:
        candidate = Path(system_root) / "System32" / name
        if candidate.is_file():
            return str(candidate)
    resolved = shutil.which(name)
    if resolved is not None:
        return resolved
    raise NoTugError(
        "AGENT_WORKSPACE_ACCESS_UNAVAILABLE",
        "A required Windows access-control tool is unavailable",
    )


def _run_windows_tool(
    command: list[str],
    *,
    runner: AclRunner,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=WINDOWS_ACL_TIMEOUT_SECONDS,
            creationflags=_windows_creation_flags(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NoTugError(
            "AGENT_WORKSPACE_ACCESS_FAILED",
            "Windows session access could not be prepared",
        ) from exc
    if completed.returncode != 0:
        raise NoTugError(
            "AGENT_WORKSPACE_ACCESS_FAILED",
            "Windows session access could not be prepared",
        )
    return completed


def _current_windows_user_sid(*, runner: AclRunner) -> str:
    completed = _run_windows_tool(
        [_windows_system_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"],
        runner=runner,
    )
    try:
        rows = list(csv.reader(io.StringIO(completed.stdout.decode("utf-8", errors="strict"))))
    except (UnicodeError, csv.Error) as exc:
        raise NoTugError(
            "AGENT_WORKSPACE_ACCESS_UNAVAILABLE",
            "The current Windows account could not be identified",
        ) from exc
    if len(rows) != 1 or len(rows[0]) < 2 or _SID_RE.fullmatch(rows[0][1]) is None:
        raise NoTugError(
            "AGENT_WORKSPACE_ACCESS_UNAVAILABLE",
            "The current Windows account could not be identified",
        )
    return f"*{rows[0][1]}"


def _grant_windows_access(
    path: Path,
    trustee: str,
    rights: str,
    *,
    runner: AclRunner,
) -> None:
    _run_windows_tool(
        [
            _windows_system_tool("icacls.exe"),
            str(path),
            "/grant:r",
            f"{trustee}:{rights}",
            "/q",
        ],
        runner=runner,
    )


def prepare_codex_workspace_access(
    vault: Vault,
    repository_id: str,
    worktree: Path,
    *,
    runner: AclRunner | None = None,
    platform_name: str | None = None,
) -> None:
    """Prepare only the exact Windows session path for Codex's restricted token.

    Python's Windows ``0o700`` directory mode uses ``OWNER RIGHTS``. A Codex
    sandbox-created file has a different owner, so the desktop user then loses
    access. The restricted shell also needs traverse plus read-attributes on
    each private ancestor in order to adopt the session directory as its cwd.

    No recursive or global ACL operation is used: the desktop SID and Codex
    sandbox group receive inheritable Modify only on this session worktree;
    the Codex group receives only traverse/read-attributes on its exact private
    ancestor chain.
    """

    selected_platform = os.name if platform_name is None else platform_name
    if selected_platform != "nt":
        return
    selected_runner = subprocess.run if runner is None else runner

    vault_root = Path(os.path.abspath(vault.root))
    worktrees_root = Path(os.path.abspath(vault.worktrees_dir))
    repository_root = worktrees_root / repository_id
    sessions_root = repository_root / "s"
    candidate = Path(os.path.abspath(worktree))
    expected_ancestors = (vault_root, worktrees_root, repository_root, sessions_root)
    if candidate.parent != sessions_root:
        raise NoTugError(
            "AGENT_WORKSPACE_ACCESS_SCOPE_INVALID",
            "Windows access preparation was refused outside the exact session path",
        )
    try:
        candidate.relative_to(worktrees_root)
    except ValueError as exc:
        raise NoTugError(
            "AGENT_WORKSPACE_ACCESS_SCOPE_INVALID",
            "Windows access preparation was refused outside the managed worktree root",
        ) from exc
    if not candidate.is_dir() or any(not path.is_dir() for path in expected_ancestors):
        raise NoTugError(
            "AGENT_WORKSPACE_ACCESS_SCOPE_INVALID",
            "Windows access preparation requires the exact existing session path",
        )

    current_user = _current_windows_user_sid(runner=selected_runner)
    _grant_windows_access(
        candidate,
        current_user,
        "(OI)(CI)(M)",
        runner=selected_runner,
    )
    _grant_windows_access(
        candidate,
        CODEX_SANDBOX_ACCOUNT,
        "(OI)(CI)(M)",
        runner=selected_runner,
    )
    for ancestor in expected_ancestors:
        _grant_windows_access(
            ancestor,
            CODEX_SANDBOX_ACCOUNT,
            "(X,RA)",
            runner=selected_runner,
        )
