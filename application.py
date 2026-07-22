"""Typed, non-authorizing application services shared by local adapters."""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .doctor import diagnose
from .errors import NoTugError
from .events import ledger_for
from .git import discover_repository, is_clean, worktree_list
from .grants import grant_tug_with_phrase
from .sessions import (
    abandon_session,
    archive_session,
    find_session,
    initialize_repository,
    load_session,
    run_agent_command_streaming,
    start_session,
    verify_authoritative_baseline,
    verify_session_receipt_head,
    verify_session_worktree,
)
from .tug import deny_tug, find_tug, full_diff_text, generate_tug, verify_tug_artifacts
from .vault import Vault
from .verification import verify_repository

APPLICATION_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class DiagnosticFinding:
    code: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DiagnosticResult:
    ok: bool
    mutation_lock: str
    repository: str | None
    findings: tuple[DiagnosticFinding, ...]

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": self.ok,
            "mutation_lock": self.mutation_lock,
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if self.repository is not None:
            result["repository"] = self.repository
        return result


@dataclass(frozen=True, slots=True)
class RepositoryStatusResult:
    schema_version: int
    repository_id: str | None
    initialized: bool
    baseline_commit: str
    branch: str | None
    clean: bool
    worktree_count: int
    receipt_chain_verified: bool | None
    receipt_event_count: int | None
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BaselineStatus:
    verified: bool
    error_code: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SessionStatusResult:
    schema_version: int
    repository_id: str
    session_id: str
    state: str
    worktree: str
    worktree_available: bool
    archived: bool
    baseline_commit: str
    baseline: BaselineStatus
    tug_id: str | None
    grant_id: str | None
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["baseline"] = self.baseline.to_dict()
        return result


@dataclass(frozen=True, slots=True)
class SessionCreationResult:
    schema_version: int
    repository_id: str
    session_id: str
    worktree: str
    baseline_commit: str
    policy_hash: str
    state: str = "SESSION_OPEN"
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProtectionResult:
    schema_version: int
    repository_id: str
    repository_root: str
    policy_hash: str
    baseline_commit: str
    receipt_head: str
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SessionListItem:
    name: str
    created_at: str
    status: SessionStatusResult

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "created_at": self.created_at, **self.status.to_dict()}


@dataclass(frozen=True, slots=True)
class RepositorySessionsResult:
    schema_version: int
    repository_id: str
    sessions: tuple[SessionListItem, ...]
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "repository_id": self.repository_id,
            "sessions": [session.to_dict() for session in self.sessions],
            "mutation_lock": self.mutation_lock,
        }


@dataclass(frozen=True, slots=True)
class AgentRunResult:
    schema_version: int
    operation_id: str
    exit_status: int
    cancelled: bool
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SessionChangeResult:
    schema_version: int
    session_id: str
    changed: bool
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TugSubmissionResult:
    schema_version: int
    tug: dict[str, Any]
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DispositionResult:
    schema_version: int
    kind: str
    session_id: str
    data: dict[str, Any]
    mutation_lock: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ReviewSummaryResult:
    tug: dict[str, Any]
    session_state: str
    baseline_verification: BaselineStatus
    receipt_verification: dict[str, Any]
    mutation_lock: str = "active"
    diff: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "tug": self.tug,
            "session_state": self.session_state,
            "baseline_verification": self.baseline_verification.to_dict(),
            "receipt_verification": self.receipt_verification,
            "mutation_lock": self.mutation_lock,
        }
        if self.diff is not None:
            result["diff"] = self.diff
        return result


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    schema_version: int
    repository_id: str
    mutation_lock: str
    checks: dict[str, Any]
    issues: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def diagnose_repository(path: Path, vault: Vault | None = None) -> DiagnosticResult:
    """Run existing diagnostics and convert their terminal-neutral data to typed results."""

    raw = diagnose(path, vault)
    findings = tuple(
        DiagnosticFinding(
            code=str(finding["code"]),
            severity=str(finding["severity"]),
            message=str(finding["message"]),
        )
        for finding in raw["findings"]
    )
    repository = raw.get("repository")
    return DiagnosticResult(
        ok=bool(raw["ok"]),
        mutation_lock=str(raw["mutation_lock"]),
        repository=str(repository) if repository is not None else None,
        findings=findings,
    )


def repository_status(path: Path, vault: Vault | None = None) -> RepositoryStatusResult:
    """Return a read-only status view without formatting or process-exit behavior."""

    selected_vault = vault or Vault()
    repository = discover_repository(path)
    clean = is_clean(repository)
    trees = worktree_list(repository)
    identity = selected_vault.find_repository(repository) if selected_vault.root.is_dir() else None
    if identity is None:
        repository_id = None
        receipt_verified = None
        event_count = None
    else:
        chain = ledger_for(selected_vault, identity.repository_id).verify()
        repository_id = identity.repository_id
        receipt_verified = True
        event_count = chain.count
    return RepositoryStatusResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        repository_id=repository_id,
        initialized=identity is not None,
        baseline_commit=repository.head,
        branch=repository.branch,
        clean=clean,
        worktree_count=len(trees),
        receipt_chain_verified=receipt_verified,
        receipt_event_count=event_count,
    )


def create_session(path: Path, name: str, vault: Vault | None = None) -> SessionCreationResult:
    """Create one non-authorizing session and return its exact managed worktree."""

    result = start_session(path, name, vault)
    return SessionCreationResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        repository_id=result.repository_id,
        session_id=result.session_id,
        worktree=str(result.worktree),
        baseline_commit=result.baseline_commit,
        policy_hash=result.policy_hash,
    )


def protect_repository(path: Path, vault: Vault | None = None) -> ProtectionResult:
    """Explicitly initialize NoTUG protection for one selected repository."""

    result = initialize_repository(path, vault)
    return ProtectionResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        repository_id=result.repository_id,
        repository_root=str(result.repository_root),
        policy_hash=result.policy_hash,
        baseline_commit=result.baseline_commit,
        receipt_head=result.receipt_head,
    )


def session_status(session_id: str, vault: Vault | None = None) -> SessionStatusResult:
    """Return receipt-bound session state and a non-mutating baseline assessment."""

    selected_vault = vault or Vault()
    repository_id, session = find_session(selected_vault, session_id)
    chain = ledger_for(selected_vault, repository_id).verify()
    verify_session_receipt_head(session, chain.events)
    baseline = BaselineStatus(verified=True, error_code=None)
    try:
        verify_authoritative_baseline(selected_vault, session)
    except NoTugError as exc:
        baseline = BaselineStatus(verified=False, error_code=exc.code)
    worktree = Path(str(session["worktree"]))
    return SessionStatusResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        repository_id=repository_id,
        session_id=str(session["session_id"]),
        state=str(session["state"]),
        worktree=str(worktree),
        worktree_available=worktree.is_dir(),
        archived=session["archived_at"] is not None,
        baseline_commit=str(session["baseline_commit"]),
        baseline=baseline,
        tug_id=str(session["tug_id"]) if session["tug_id"] is not None else None,
        grant_id=str(session["grant_id"]) if session["grant_id"] is not None else None,
    )


def list_repository_sessions(
    path: Path,
    vault: Vault | None = None,
) -> RepositorySessionsResult:
    """List receipt-bound sessions for one explicitly selected protected repository."""

    selected_vault = vault or Vault()
    repository = discover_repository(path)
    identity = selected_vault.find_repository(repository)
    if identity is None:
        raise NoTugError("REPOSITORY_NOT_INITIALIZED", "Repository is not protected by NoTUG")
    session_dir = selected_vault.repository_dir(identity.repository_id) / "sessions"
    items: list[SessionListItem] = []
    for session_path in sorted(session_dir.glob("session_*.json")):
        session = load_session(selected_vault, identity.repository_id, session_path.stem)
        items.append(
            SessionListItem(
                name=str(session["name"]),
                created_at=str(session["created_at"]),
                status=session_status(session_path.stem, selected_vault),
            )
        )
    items.sort(key=lambda item: item.created_at, reverse=True)
    return RepositorySessionsResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        repository_id=identity.repository_id,
        sessions=tuple(items),
    )


def run_agent_task(
    session_id: str,
    command: Sequence[str],
    *,
    input_bytes: bytes,
    stdout_callback: Callable[[str], None],
    stderr_callback: Callable[[str], None],
    cancel_event: threading.Event,
    vault: Vault | None = None,
) -> AgentRunResult:
    """Run one bounded desktop-owned agent command without terminal formatting."""

    result = run_agent_command_streaming(
        session_id,
        command,
        input_bytes=input_bytes,
        stdout_callback=stdout_callback,
        stderr_callback=stderr_callback,
        cancel_event=cancel_event,
        vault=vault,
    )
    return AgentRunResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        operation_id=result.operation_id,
        exit_status=result.exit_status,
        cancelled=result.cancelled,
    )


def session_change_status(
    session_id: str,
    vault: Vault | None = None,
) -> SessionChangeResult:
    """Report whether an open managed worktree contains proposal changes."""

    selected_vault = vault or Vault()
    repository_id, session = find_session(selected_vault, session_id)
    with selected_vault.locked(repository_id):
        verify_authoritative_baseline(selected_vault, session)
        verify_session_worktree(selected_vault, session)
        worktree = Path(str(session["worktree"]))
        changed = not is_clean(worktree)
    return SessionChangeResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        session_id=session_id,
        changed=changed,
    )


def submit_session(session_id: str, vault: Vault | None = None) -> TugSubmissionResult:
    """Freeze one open session into exact review evidence without authorizing it."""

    return TugSubmissionResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        tug=generate_tug(session_id, vault),
    )


def grant_reviewed_tug(
    tug_id: str,
    confirmation: str,
    vault: Vault | None = None,
) -> DispositionResult:
    """Apply a native exact-hash ceremony through NoTUG Core."""

    grant = grant_tug_with_phrase(tug_id, confirmation, vault)
    return DispositionResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        kind="grant",
        session_id=str(grant["session_id"]),
        data=grant,
    )


def deny_reviewed_tug(tug_id: str, vault: Vault | None = None) -> DispositionResult:
    """Record one explicit denial through NoTUG Core."""

    selected_vault = vault or Vault()
    repository_id, tug = find_tug(selected_vault, tug_id)
    del repository_id
    denial = deny_tug(tug_id, selected_vault)
    return DispositionResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        kind="denial",
        session_id=str(tug["session_id"]),
        data=denial,
    )


def abandon_unchanged_session(
    session_id: str,
    vault: Vault | None = None,
) -> DispositionResult:
    """Explicitly disposition an unchanged open session."""

    abandon_session(session_id, vault)
    return DispositionResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        kind="abandonment",
        session_id=session_id,
        data={"state": "ABANDONED"},
    )


def archive_disposed_session(
    session_id: str,
    vault: Vault | None = None,
) -> DispositionResult:
    """Explicitly archive one already disposed disposable session."""

    archive_session(session_id, vault)
    return DispositionResult(
        schema_version=APPLICATION_SCHEMA_VERSION,
        kind="archive",
        session_id=session_id,
        data={"archived": True},
    )


def get_review_summary(
    tug_id: str,
    *,
    include_diff: bool = False,
    vault: Vault | None = None,
) -> ReviewSummaryResult:
    """Return verified, non-authorizing review facts for presentation by adapters."""

    selected_vault = vault or Vault()
    repository_id, tug = find_tug(selected_vault, tug_id)
    verify_tug_artifacts(selected_vault, repository_id, tug)
    chain = ledger_for(selected_vault, repository_id).verify()
    _, session = find_session(selected_vault, str(tug["session_id"]))
    verify_session_receipt_head(session, chain.events)
    baseline = BaselineStatus(verified=True, error_code=None)
    try:
        verify_authoritative_baseline(selected_vault, session)
    except NoTugError as exc:
        baseline = BaselineStatus(verified=False, error_code=exc.code)
    diff = full_diff_text(selected_vault, repository_id, tug) if include_diff else None
    return ReviewSummaryResult(
        tug=tug,
        session_state=str(session["state"]),
        baseline_verification=baseline,
        receipt_verification={
            "verified": True,
            "event_count": chain.count,
            "head_hash": chain.head_hash,
        },
        diff=diff,
    )


def verify_repository_evidence(path: Path, vault: Vault | None = None) -> VerificationResult:
    """Run full read-only provenance verification and return its typed envelope."""

    raw = verify_repository(path, vault)
    return VerificationResult(
        ok=bool(raw["ok"]),
        schema_version=int(raw["schema_version"]),
        repository_id=str(raw["repository_id"]),
        mutation_lock=str(raw["mutation_lock"]),
        checks=dict(raw["checks"]),
        issues=list(raw["issues"]),
    )
