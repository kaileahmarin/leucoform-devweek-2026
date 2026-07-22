"""Read-only and temporary-probe diagnostics; findings are never auto-fixed."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from .brand import CLI_NAME, PRODUCT_SHORT_NAME
from .errors import NoTugError
from .events import ledger_for
from .git import discover_repository, git_version, is_clean, worktree_list
from .sessions import load_session
from .vault import Vault


def _vault_confidentiality_finding(
    root: Path,
    *,
    platform_name: str | None = None,
    mode: int | None = None,
) -> tuple[str, str, str]:
    """Report only the confidentiality property that this host can establish."""

    if not root.is_dir():
        return (
            "VAULT_CONFIDENTIALITY_NOT_ASSESSED",
            "info",
            "Vault confidentiality was not assessed because the vault does not yet exist",
        )
    selected_platform = os.name if platform_name is None else platform_name
    if selected_platform != "posix":
        return (
            "VAULT_CONFIDENTIALITY_NOT_ASSESSED",
            "info",
            "Vault confidentiality ACLs were not assessed on this platform",
        )
    try:
        permissions = stat.S_IMODE(root.stat().st_mode if mode is None else mode)
    except OSError:
        return (
            "VAULT_CONFIDENTIALITY_NOT_ASSESSED",
            "warning",
            "Vault confidentiality mode could not be assessed",
        )
    if permissions & 0o077:
        return (
            "VAULT_ROOT_MODE_EXPOSED",
            "warning",
            f"Existing vault root mode {permissions:#05o} permits group or other access",
        )
    return (
        "VAULT_ROOT_MODE_PRIVATE",
        "info",
        f"Existing vault root mode {permissions:#05o} has no group or other permission bits",
    )


def diagnose(path: Path, vault: Vault | None = None) -> dict[str, Any]:
    vault = vault or Vault()
    findings: list[dict[str, Any]] = []

    def add(code: str, severity: str, message: str) -> None:
        findings.append({"code": code, "severity": severity, "message": message})

    if sys.version_info >= (3, 11):  # noqa: UP036 - doctor reports this explicit requirement
        add(
            "PYTHON_VERSION_OK",
            "info",
            f"Python {sys.version_info.major}.{sys.version_info.minor} is supported",
        )
    else:
        add("PYTHON_VERSION_UNSUPPORTED", "error", "Python 3.11 or newer is required")
    try:
        add("GIT_AVAILABLE", "info", git_version())
    except NoTugError as exc:
        add(exc.code, "error", exc.message)
        return {"ok": False, "mutation_lock": "active", "findings": findings}
    try:
        repository = discover_repository(path)
    except NoTugError as exc:
        add(exc.code, "error", exc.message)
        return {"ok": False, "mutation_lock": "active", "findings": findings}
    repository_clean = is_clean(repository)
    add(
        "REPOSITORY_CLEAN" if repository_clean else "SOURCE_REPOSITORY_DIRTY",
        "info" if repository_clean else "error",
        "Protected repository is clean"
        if repository_clean
        else "Session creation would be refused while repository is dirty",
    )
    try:
        trees = worktree_list(repository)
        add("WORKTREE_SUPPORT_OK", "info", f"Git reports {len(trees)} registered worktree(s)")
    except NoTugError as exc:
        add(exc.code, "error", exc.message)
    identity = vault.find_repository(repository) if vault.root.is_dir() else None
    if identity is None:
        add(
            "REPOSITORY_NOT_INITIALIZED",
            "warning",
            f"Repository is not initialized with {PRODUCT_SHORT_NAME}",
        )
    else:
        try:
            chain = ledger_for(vault, identity.repository_id).verify()
            add("RECEIPT_CHAIN_OK", "info", f"Receipt chain contains {chain.count} event(s)")
        except NoTugError as exc:
            add(exc.code, "error", exc.message)
        stale = 0
        for session_path in vault.repository_dir(identity.repository_id).glob("sessions/*.json"):
            try:
                session = load_session(vault, identity.repository_id, session_path.stem)
                if session["archived_at"] is None and not Path(str(session["worktree"])).is_dir():
                    stale += 1
            except NoTugError:
                stale += 1
        add(
            "STALE_SESSIONS_NONE" if stale == 0 else "STALE_SESSIONS_FOUND",
            "info" if stale == 0 else "warning",
            "No stale sessions detected"
            if stale == 0
            else f"{stale} session artifact(s) need review",
        )
    probe_candidate = vault.root
    while not probe_candidate.exists() and probe_candidate.parent != probe_candidate:
        probe_candidate = probe_candidate.parent
    probe_parent: Path | None = probe_candidate
    if not probe_candidate.is_dir():
        add(
            "VAULT_PERMISSION_DENIED",
            "error",
            "Vault path crosses an existing non-directory component",
        )
        probe_parent = None
    try:
        vault.ensure_external(repository.root)
    except NoTugError as exc:
        add(exc.code, "error", exc.message)
        probe_parent = None
    if probe_parent is not None:
        try:
            with tempfile.TemporaryDirectory(prefix=f"{CLI_NAME}-doctor-", dir=probe_parent) as raw:
                probe = Path(raw) / "CaseProbe"
                probe.write_bytes(b"probe")
                case_sensitive = not (Path(raw) / "caseprobe").exists()
            add(
                "FILESYSTEM_CASE_SENSITIVE" if case_sensitive else "FILESYSTEM_CASE_INSENSITIVE",
                "info",
                "Filesystem path comparison behavior was detected",
            )
            add(
                "VAULT_WRITABILITY_OK",
                "info",
                "Temporary write and removal succeeded in the nearest vault ancestor",
            )
        except OSError:
            add("VAULT_PERMISSION_DENIED", "error", "Vault location is not writable")
    add(*_vault_confidentiality_finding(vault.root))
    longest = max(len(str(repository.root)), len(str(vault.root)))
    if os.name == "nt" and longest > 200:
        add("PATH_LENGTH_RISK", "warning", f"Base paths are long ({longest} characters)")
    else:
        add("PATH_LENGTH_OK", "info", f"Longest base path is {longest} characters")
    return {
        "ok": not any(finding["severity"] == "error" for finding in findings),
        "mutation_lock": "active",
        "repository": str(repository.root),
        "findings": findings,
    }
