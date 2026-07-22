"""Repository initialization, disposable sessions, and agent command execution."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .brand import (
    AGENT_SESSION_ENVIRONMENT_VARIABLE,
    CLI_NAME,
    MODULE_NAME,
    MUTATION_LOCK_ACTIVE,
)
from .config import create_or_load_policy
from .errors import NoTugError
from .events import EventVerification, ledger_for
from .git import (
    GitRepository,
    add_detached_worktree,
    discover_repository,
    ensure_trusted_empty_hooks_directory,
    is_clean,
    require_clean,
    resolve_ref,
    run_git,
    worktree_list,
)
from .identity import (
    RepositoryIdentity,
    new_identifier,
    repository_metadata_hash,
    validate_identifier,
)
from .manifests import generate_manifest, verify_manifest, write_manifest
from .models import State
from .process import (
    MAX_STDIN_BYTES,
    WindowsBatchCommandError,
    run_cancellable_process,
    run_sanitized_process,
)
from .util import (
    atomic_write_json,
    canonical_json_bytes,
    read_json,
    redact_command,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from .vault import Vault
from .workspace_access import prepare_codex_workspace_access

SESSION_FIELDS = {
    "schema_version",
    "session_id",
    "repository_id",
    "name",
    "state",
    "created_at",
    "baseline_commit",
    "baseline_tree",
    "source_ref",
    "source_head",
    "policy_hash",
    "baseline_manifest_hash",
    "worktree",
    "git_pointer_hash",
    "tug_id",
    "grant_id",
    "archived_at",
    "last_event_hash",
}
SESSION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CODEX_EXECUTABLE_NAMES = {"codex", "codex.exe", "codex.cmd", "codex.bat"}
NODE_EXECUTABLE_NAMES = {"node", "node.exe"}
SESSION_IMMUTABLE_FIELDS = {
    "session_id",
    "repository_id",
    "name",
    "created_at",
    "baseline_commit",
    "baseline_tree",
    "source_ref",
    "source_head",
    "policy_hash",
    "baseline_manifest_hash",
    "worktree",
    "git_pointer_hash",
}


def _create_or_verify_immutable_bytes(path: Path, data: bytes) -> None:
    """Create hash-addressed bytes once, or verify the existing immutable value."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        try:
            metadata = path.lstat()
            file_attributes = int(getattr(metadata, "st_file_attributes", 0))
            reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or file_attributes & reparse_flag
                or path.read_bytes() != data
            ):
                raise NoTugError(
                    "POLICY_SNAPSHOT_DIVERGENCE",
                    "Existing policy snapshot disagrees with its content address",
                )
        except NoTugError:
            raise
        except OSError as exc:
            raise NoTugError(
                "POLICY_SNAPSHOT_DIVERGENCE",
                "Existing policy snapshot cannot be verified safely",
            ) from exc
        return
    except OSError as exc:
        raise NoTugError(
            "POLICY_SNAPSHOT_DIVERGENCE",
            "Policy snapshot cannot be created safely",
        ) from exc

    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


@dataclass(slots=True)
class InitResult:
    repository_id: str
    repository_root: Path
    vault_root: Path
    policy_hash: str
    baseline_commit: str
    receipt_head: str


@dataclass(slots=True)
class SessionResult:
    session_id: str
    repository_id: str
    worktree: Path
    baseline_commit: str
    policy_hash: str


@dataclass(frozen=True, slots=True)
class AgentCommandResult:
    operation_id: str
    exit_status: int
    cancelled: bool


def _strict_session(data: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(data) - SESSION_FIELDS)
    missing = sorted(SESSION_FIELDS - set(data))
    if unknown or missing:
        raise NoTugError(
            "SESSION_SCHEMA_INVALID",
            "Session metadata does not match schema version 1",
            {"unknown_fields": unknown, "missing_fields": missing},
        )
    if data.get("schema_version") != 1 or isinstance(data.get("schema_version"), bool):
        raise NoTugError("SESSION_SCHEMA_INVALID", "Unsupported session schema version")
    state_value = data.get("state")
    if not isinstance(state_value, str) or state_value not in {state.value for state in State}:
        raise NoTugError("SESSION_SCHEMA_INVALID", "Session state is invalid")
    try:
        validate_identifier(data["session_id"], "session")
        validate_identifier(data["repository_id"], "repo")
        if data["tug_id"] is not None:
            validate_identifier(data["tug_id"], "tug")
        if data["grant_id"] is not None:
            validate_identifier(data["grant_id"], "grant")
    except NoTugError as exc:
        raise NoTugError("SESSION_SCHEMA_INVALID", "Session identifiers are invalid") from exc
    oid_re = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
    hash_re = re.compile(r"^[a-f0-9]{64}$")
    if (
        not isinstance(data["name"], str)
        or SESSION_NAME_RE.fullmatch(data["name"]) is None
        or not isinstance(data["created_at"], str)
        or any(
            not isinstance(data[key], str) or oid_re.fullmatch(data[key]) is None
            for key in ("baseline_commit", "baseline_tree", "source_head")
        )
        or (data["source_ref"] is not None and not isinstance(data["source_ref"], str))
        or any(
            not isinstance(data[key], str) or hash_re.fullmatch(data[key]) is None
            for key in (
                "policy_hash",
                "baseline_manifest_hash",
                "git_pointer_hash",
                "last_event_hash",
            )
        )
        or not isinstance(data["worktree"], str)
        or (data["archived_at"] is not None and not isinstance(data["archived_at"], str))
    ):
        raise NoTugError("SESSION_SCHEMA_INVALID", "Session metadata types are invalid")
    return data


def load_session(vault: Vault, repository_id: str, session_id: str) -> dict[str, Any]:
    session = _strict_session(read_json(vault.session_path(repository_id, session_id)))
    if session["session_id"] != session_id or session["repository_id"] != repository_id:
        raise NoTugError(
            "SESSION_ID_MISMATCH", "Session identifiers disagree with the vault location"
        )
    return session


def save_session(vault: Vault, session: dict[str, Any]) -> None:
    _strict_session(session)
    atomic_write_json(
        vault.session_path(str(session["repository_id"]), str(session["session_id"])), session
    )


def session_metadata_hash(session: dict[str, Any]) -> str:
    """Hash the immutable session envelope without mutable disposition fields."""

    immutable = {field: session[field] for field in sorted(SESSION_IMMUTABLE_FIELDS)}
    return sha256_bytes(b"NoTUG.SessionMetadata.v1\0" + canonical_json_bytes(immutable))


def _exact_managed_worktree_path(
    vault: Vault,
    stored_path: str,
    repository_id: str,
    kind: str,
    entity_id: str,
    *,
    code: str,
) -> Path:
    """Return the exact lexical vault location without resolving attacker-controlled links."""

    supplied = Path(stored_path)
    expected = Path(os.path.abspath(vault.worktree_path(repository_id, kind, entity_id)))
    managed_root = Path(os.path.abspath(vault.worktrees_dir))
    if not supplied.is_absolute() or os.path.normcase(
        os.path.abspath(supplied)
    ) != os.path.normcase(os.path.abspath(expected)):
        raise NoTugError(code, "Managed worktree path is not its exact vault location")
    try:
        expected.relative_to(managed_root)
    except ValueError as exc:
        raise NoTugError(code, "Managed worktree path is outside the vault") from exc
    return expected


def _verified_managed_worktree_path(
    vault: Vault,
    stored_path: str,
    repository_id: str,
    kind: str,
    entity_id: str,
    *,
    code: str,
) -> Path:
    """Return an exact lexical vault path only when no link can redirect it."""

    expected = _exact_managed_worktree_path(
        vault, stored_path, repository_id, kind, entity_id, code=code
    )
    managed_root = Path(os.path.abspath(vault.worktrees_dir))
    relative = expected.relative_to(managed_root)

    current = managed_root
    components = (
        managed_root,
        *(
            managed_root / Path(*relative.parts[:index])
            for index in range(1, len(relative.parts) + 1)
        ),
    )
    try:
        for current in components:
            metadata = current.lstat()
            file_attributes = int(getattr(metadata, "st_file_attributes", 0))
            reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            if stat.S_ISLNK(metadata.st_mode) or file_attributes & reparse_flag:
                raise NoTugError(
                    code,
                    "Managed worktree path contains a symlink, junction, or reparse point",
                )
    except FileNotFoundError as exc:
        raise NoTugError(code, "Managed worktree path is missing") from exc
    except OSError as exc:
        raise NoTugError(code, "Managed worktree path metadata cannot be verified") from exc

    try:
        resolved_root = managed_root.resolve(strict=True)
        resolved_expected = expected.resolve(strict=True)
        resolved_expected.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise NoTugError(code, "Managed worktree path does not resolve inside the vault") from exc
    return expected


def _one_bound_event(
    events: Sequence[dict[str, Any]],
    *,
    repository_id: str,
    event_type: str,
    entity_type: str,
    entity_id: str,
    code: str,
    message: str,
) -> dict[str, Any]:
    matches = [
        event
        for event in events
        if event["event_type"] == event_type and event["entity_id"] == entity_id
    ]
    if len(matches) != 1:
        raise NoTugError(code, message)
    event = matches[0]
    if event["repository_id"] != repository_id or event["entity_type"] != entity_type:
        raise NoTugError(code, message)
    return event


def _verify_session_creation_binding(
    vault: Vault,
    repository_id: str,
    session_id: str,
    session: dict[str, Any],
    events: Sequence[dict[str, Any]],
    *,
    require_worktree: bool = True,
) -> tuple[Path, dict[str, Any]]:
    """Bind mutable session JSON to its vault location and creation receipt."""

    if session["repository_id"] != repository_id or session["session_id"] != session_id:
        raise NoTugError(
            "SESSION_ID_MISMATCH",
            "Session identifiers disagree with the vault metadata location",
        )
    path_verifier = (
        _verified_managed_worktree_path if require_worktree else _exact_managed_worktree_path
    )
    expected_worktree = path_verifier(
        vault,
        str(session["worktree"]),
        repository_id,
        "session",
        session_id,
        code="WORKTREE_ADMIN_DIVERGENCE",
    )
    if not require_worktree and (expected_worktree.exists() or expected_worktree.is_symlink()):
        raise NoTugError(
            "WORKTREE_ADMIN_DIVERGENCE",
            "Archived session worktree unexpectedly still exists",
        )
    created = _one_bound_event(
        events,
        repository_id=repository_id,
        event_type="SESSION_CREATED",
        entity_type="session",
        entity_id=session_id,
        code="SESSION_RECEIPT_DIVERGENCE",
        message="Session has no unique creation receipt binding",
    )
    expected_payload = {
        "baseline_commit": session["baseline_commit"],
        "baseline_manifest_hash": session["baseline_manifest_hash"],
        "policy_hash": session["policy_hash"],
        "session_metadata_sha256": session_metadata_hash(session),
    }
    if (
        created["state_from"] != State.LOCKED.value
        or created["state_to"] != State.SESSION_OPEN.value
        or created["payload"] != expected_payload
    ):
        raise NoTugError(
            "SESSION_RECEIPT_DIVERGENCE",
            "Session metadata disagrees with its creation receipt",
        )
    return expected_worktree, created


def _verify_archive_disposition_binding(
    repository_id: str,
    session_id: str,
    session: dict[str, Any],
    events: Sequence[dict[str, Any]],
    created: dict[str, Any],
) -> None:
    """Verify the exact receipt path from session creation to final disposition."""

    if session["archived_at"] is not None:
        raise NoTugError("SESSION_ALREADY_ARCHIVED", "Session has already been archived")
    if session["state"] == State.ABANDONED.value:
        if session["tug_id"] is not None or session["grant_id"] is not None:
            raise NoTugError(
                "SESSION_RECEIPT_DIVERGENCE",
                "Abandoned session unexpectedly names a Tug Signal or grant",
            )
        disposition = _one_bound_event(
            events,
            repository_id=repository_id,
            event_type="SESSION_ABANDONED",
            entity_type="session",
            entity_id=session_id,
            code="SESSION_RECEIPT_DIVERGENCE",
            message="Abandoned session has no unique disposition receipt",
        )
        if (
            disposition["payload"] != {"session_id": session_id}
            or disposition["state_from"] != State.SESSION_OPEN.value
            or disposition["state_to"] != State.ABANDONED.value
            or disposition["sequence"] <= created["sequence"]
            or session["last_event_hash"] != disposition["event_hash"]
        ):
            raise NoTugError(
                "SESSION_RECEIPT_DIVERGENCE",
                "Session abandonment metadata disagrees with its receipt",
            )
        return
    tug_id = session["tug_id"]
    if not isinstance(tug_id, str):
        raise NoTugError("SESSION_RECEIPT_DIVERGENCE", "Disposed session has no bound Tug Signal")
    generated = _one_bound_event(
        events,
        repository_id=repository_id,
        event_type="TUG_GENERATED",
        entity_type="tug",
        entity_id=tug_id,
        code="SESSION_RECEIPT_DIVERGENCE",
        message="Session Tug Signal has no unique generation receipt",
    )
    generated_payload = generated["payload"]
    if (
        set(generated_payload)
        != {"session_id", "tug_hash", "patch_sha256", "change_count", "policy_hash"}
        or generated_payload["session_id"] != session_id
        or generated["state_from"] != State.SESSION_OPEN.value
        or generated["state_to"] != State.TUGGED.value
        or generated["sequence"] <= created["sequence"]
    ):
        raise NoTugError(
            "SESSION_RECEIPT_DIVERGENCE",
            "Session Tug Signal receipt is not bound to this session",
        )

    if session["state"] == State.DENIED.value:
        if session["grant_id"] is not None:
            raise NoTugError(
                "SESSION_RECEIPT_DIVERGENCE", "Denied session unexpectedly names a grant"
            )
        disposition = _one_bound_event(
            events,
            repository_id=repository_id,
            event_type="TUG_DENIED",
            entity_type="tug",
            entity_id=tug_id,
            code="SESSION_RECEIPT_DIVERGENCE",
            message="Denied session has no unique denial receipt",
        )
        if (
            disposition["payload"]
            != {"session_id": session_id, "tug_hash": generated_payload["tug_hash"]}
            or disposition["state_from"] != State.TUGGED.value
            or disposition["state_to"] != State.DENIED.value
            or disposition["sequence"] <= generated["sequence"]
        ):
            raise NoTugError(
                "SESSION_RECEIPT_DIVERGENCE",
                "Session denial metadata disagrees with its receipt",
            )
    else:
        grant_id = session["grant_id"]
        if not isinstance(grant_id, str):
            raise NoTugError("SESSION_RECEIPT_DIVERGENCE", "Applied session has no bound grant")
        issued = _one_bound_event(
            events,
            repository_id=repository_id,
            event_type="GRANT_ISSUED",
            entity_type="grant",
            entity_id=grant_id,
            code="SESSION_RECEIPT_DIVERGENCE",
            message="Applied session has no unique grant issuance receipt",
        )
        issued_payload = issued["payload"]
        if (
            set(issued_payload)
            != {
                "session_id",
                "tug_id",
                "tug_hash",
                "patch_sha256",
                "binding_hash",
                "grant_metadata_sha256",
            }
            or issued_payload["session_id"] != session_id
            or issued_payload["tug_id"] != tug_id
            or issued_payload["tug_hash"] != generated_payload["tug_hash"]
            or issued_payload["patch_sha256"] != generated_payload["patch_sha256"]
            or issued["state_from"] != State.TUGGED.value
            or issued["state_to"] != State.GRANTED.value
            or issued["sequence"] <= generated["sequence"]
        ):
            raise NoTugError(
                "SESSION_RECEIPT_DIVERGENCE",
                "Session grant issuance is not bound to its Tug Signal",
            )
        applied = _one_bound_event(
            events,
            repository_id=repository_id,
            event_type="GRANT_APPLIED",
            entity_type="grant",
            entity_id=grant_id,
            code="SESSION_RECEIPT_DIVERGENCE",
            message="Applied session has no unique application receipt",
        )
        applied_payload = applied["payload"]
        if (
            set(applied_payload)
            != {
                "tug_id",
                "tug_hash",
                "commit",
                "branch",
                "validation_count",
                "validation_sha256",
                "application_metadata_sha256",
            }
            or applied_payload["tug_id"] != tug_id
            or applied_payload["tug_hash"] != generated_payload["tug_hash"]
            or applied["state_from"] != State.GRANTED.value
            or applied["state_to"] != State.APPLIED.value
            or applied["sequence"] <= issued["sequence"]
        ):
            raise NoTugError(
                "SESSION_RECEIPT_DIVERGENCE",
                "Session application metadata disagrees with its receipt",
            )
        disposition = applied
        if session["state"] == State.REVOKED.value:
            disposition = _one_bound_event(
                events,
                repository_id=repository_id,
                event_type="GRANT_REVOKED",
                entity_type="grant",
                entity_id=grant_id,
                code="SESSION_RECEIPT_DIVERGENCE",
                message="Revoked session has no unique revocation receipt",
            )
            revoked_payload = disposition["payload"]
            if (
                set(revoked_payload)
                != {
                    "tug_id",
                    "revoke_id",
                    "disposition",
                    "commit",
                    "branch",
                    "revoke_metadata_sha256",
                }
                or revoked_payload["tug_id"] != tug_id
                or disposition["state_from"] != State.APPLIED.value
                or disposition["state_to"] != State.REVOKED.value
                or disposition["sequence"] <= applied["sequence"]
            ):
                raise NoTugError(
                    "SESSION_RECEIPT_DIVERGENCE",
                    "Session revocation metadata disagrees with its receipt",
                )
    if session["last_event_hash"] != disposition["event_hash"]:
        raise NoTugError(
            "SESSION_RECEIPT_DIVERGENCE",
            "Session disposition does not match its last receipt",
        )


def verify_session_receipt_head(
    session: dict[str, Any], events: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    """Reconcile mutable session state with its latest authoritative transition receipt."""

    session_id = str(session["session_id"])
    tug_id = session["tug_id"]
    grant_id = session["grant_id"]
    related: list[dict[str, Any]] = []
    for event in events:
        event_type = event["event_type"]
        entity_id = event["entity_id"]
        payload = event["payload"]
        if event_type in {
            "SESSION_CREATED",
            "SESSION_ABANDONED",
            "SESSION_DIVERGED",
            "SESSION_ARCHIVED",
        }:
            matches = entity_id == session_id
        elif event_type in {"TUG_GENERATED", "TUG_DENIED"}:
            matches = payload.get("session_id") == session_id or (
                isinstance(tug_id, str) and entity_id == tug_id
            )
        elif event_type == "GRANT_ISSUED":
            matches = payload.get("session_id") == session_id or (
                isinstance(grant_id, str) and entity_id == grant_id
            )
        elif event_type in {"GRANT_APPLIED", "GRANT_FAILED", "GRANT_REVOKED"}:
            matches = isinstance(grant_id, str) and entity_id == grant_id
        else:
            matches = False
        if matches:
            related.append(event)
    if not related:
        raise NoTugError(
            "SESSION_RECEIPT_MISSING", "Session has no authoritative transition receipt"
        )
    authoritative = max(related, key=lambda event: int(event["sequence"]))
    event_type = authoritative["event_type"]
    expected_state = (
        authoritative["payload"].get("disposition_state")
        if event_type == "SESSION_ARCHIVED"
        else authoritative["state_to"]
    )
    if (
        authoritative["event_hash"] != session["last_event_hash"]
        or expected_state != session["state"]
    ):
        raise NoTugError(
            "SESSION_RECEIPT_DIVERGENCE",
            "Session metadata lags or contradicts its authoritative transition receipt",
        )
    if event_type in {"TUG_GENERATED", "TUG_DENIED"} and authoritative["entity_id"] != tug_id:
        raise NoTugError(
            "SESSION_RECEIPT_DIVERGENCE", "Session Tug identifier contradicts its receipt"
        )
    if event_type in {"GRANT_ISSUED", "GRANT_APPLIED", "GRANT_FAILED", "GRANT_REVOKED"} and (
        authoritative["entity_id"] != grant_id
    ):
        raise NoTugError(
            "SESSION_RECEIPT_DIVERGENCE", "Session grant identifier contradicts its receipt"
        )
    return authoritative


def find_session(vault: Vault, session_id: str) -> tuple[str, dict[str, Any]]:
    validate_identifier(session_id, "session")
    matches: list[tuple[str, Path]] = []
    repositories = vault.root / "r"
    if repositories.is_dir():
        for repository in repositories.iterdir():
            candidate = repository / "sessions" / f"{session_id}.json"
            if candidate.is_file():
                matches.append((repository.name, candidate))
    if not matches:
        raise NoTugError("SESSION_NOT_FOUND", "No session matches the exact identifier")
    if len(matches) != 1:
        raise NoTugError("SESSION_ID_AMBIGUOUS", "Session identifier is not unique")
    repository_id, _path = matches[0]
    return repository_id, load_session(vault, repository_id, session_id)


def _repository_for_identity(vault: Vault, repository_id: str) -> GitRepository:
    identity = vault.load_repository(repository_id)
    verification = ledger_for(vault, repository_id).verify()
    _validate_initialization_receipt(verification, identity)
    repository = discover_repository(Path(identity.root))
    if repository.common_git_dir.resolve() != Path(identity.common_git_dir).resolve():
        raise NoTugError(
            "REPOSITORY_IDENTITY_MISMATCH", "The authoritative Git common directory has changed"
        )
    return repository


def _validate_initialization_receipt(
    verification: EventVerification, identity: RepositoryIdentity
) -> None:
    repository_id = identity.repository_id
    initialized = [
        event for event in verification.events if event["event_type"] == "REPOSITORY_INITIALIZED"
    ]
    if (
        len(initialized) != 1
        or initialized[0]["sequence"] != 1
        or initialized[0]["previous_event_hash"] is not None
        or initialized[0]["repository_id"] != repository_id
        or initialized[0]["entity_type"] != "repository"
        or initialized[0]["entity_id"] != repository_id
        or initialized[0]["state_to"] != State.LOCKED.value
        or initialized[0]["payload"].get("repository_key") != identity.repository_key
        or initialized[0]["payload"].get("repository_metadata_sha256")
        != repository_metadata_hash(identity)
    ):
        raise NoTugError(
            "REPOSITORY_INITIALIZATION_INVALID",
            "Receipt chain does not begin with one valid repository initialization",
        )


def initialize_repository(path: Path, vault: Vault | None = None) -> InitResult:
    repository = discover_repository(path)
    require_clean(repository)
    vault = vault or Vault()
    vault.ensure_external(repository.root)
    vault.ensure()
    identity = vault.register_repository(repository)
    policy = create_or_load_policy(vault.policy_path(identity.repository_id))
    manifest = generate_manifest(repository, repository.head, repository_id=identity.repository_id)
    write_manifest(vault.manifest_path(identity.repository_id, manifest.manifest_hash), manifest)
    with vault.locked(identity.repository_id):
        ledger = ledger_for(vault, identity.repository_id)
        verification = ledger.verify()
        if verification.count == 0:
            event = ledger.append(
                repository_id=identity.repository_id,
                event_type="REPOSITORY_INITIALIZED",
                entity_type="repository",
                entity_id=identity.repository_id,
                state_to=State.LOCKED.value,
                payload={
                    "baseline_commit": repository.head,
                    "baseline_manifest_hash": manifest.manifest_hash,
                    "policy_hash": policy.sha256,
                    "repository_key": identity.repository_key,
                    "repository_metadata_sha256": repository_metadata_hash(identity),
                },
            )
            head_hash = str(event["event_hash"])
        else:
            _validate_initialization_receipt(verification, identity)
            if verification.head_hash is None:
                raise NoTugError("RECEIPT_CHAIN_INVALID", "Non-empty receipt chain has no head")
            head_hash = verification.head_hash
    return InitResult(
        repository_id=identity.repository_id,
        repository_root=repository.root,
        vault_root=vault.root,
        policy_hash=policy.sha256,
        baseline_commit=repository.head,
        receipt_head=head_hash,
    )


def _ensure_initialized(repository: GitRepository, vault: Vault) -> str:
    identity = vault.find_repository(repository)
    if identity is None:
        raise NoTugError(
            "REPOSITORY_NOT_INITIALIZED",
            f"Run '{CLI_NAME} init' before creating a session",
        )
    verification = ledger_for(vault, identity.repository_id).verify()
    if verification.count == 0:
        raise NoTugError(
            "REPOSITORY_INITIALIZATION_INCOMPLETE",
            "Repository registration exists but initialization has not completed",
        )
    _validate_initialization_receipt(verification, identity)
    return identity.repository_id


def _git_pointer_hash(worktree: Path) -> str:
    pointer = worktree / ".git"
    if not pointer.is_file():
        raise NoTugError(
            "WORKTREE_ADMIN_DIVERGENCE", "Session .git administrative pointer is missing"
        )
    return sha256_file(pointer)


def verify_session_worktree(vault: Vault, session: dict[str, Any]) -> GitRepository:
    repository_id = str(session["repository_id"])
    repository = _repository_for_identity(vault, repository_id)
    worktree = _verified_managed_worktree_path(
        vault,
        str(session["worktree"]),
        repository_id,
        "session",
        str(session["session_id"]),
        code="WORKTREE_ADMIN_DIVERGENCE",
    )
    if not worktree.is_dir():
        raise NoTugError("WORKTREE_ADMIN_DIVERGENCE", "Session worktree is missing")
    if _git_pointer_hash(worktree) != session["git_pointer_hash"]:
        raise NoTugError("WORKTREE_ADMIN_DIVERGENCE", "Session .git pointer was altered")
    registered = [
        item for item in worktree_list(repository) if item.path.resolve() == worktree.resolve()
    ]
    if len(registered) != 1:
        raise NoTugError("WORKTREE_ADMIN_DIVERGENCE", "Session worktree is not registered by Git")
    record = registered[0]
    if (
        not record.detached
        or record.branch is not None
        or record.head != session["baseline_commit"]
    ):
        raise NoTugError(
            "WORKTREE_ADMIN_DIVERGENCE",
            "Session worktree HEAD no longer matches its detached baseline",
        )
    return repository


def verify_authoritative_baseline(
    vault: Vault,
    session: dict[str, Any],
    *,
    require_source_clean: bool = True,
    require_source_unchanged: bool = True,
) -> GitRepository:
    repository = _repository_for_identity(vault, str(session["repository_id"]))
    baseline = str(session["baseline_commit"])
    try:
        current = run_git(repository.root, ["rev-parse", "--verify", f"{baseline}^{{commit}}"])
    except NoTugError as exc:
        raise NoTugError("BASELINE_MISSING", "Recorded baseline commit no longer exists") from exc
    if current.stdout.decode("ascii").strip() != baseline:
        raise NoTugError("BASELINE_MISSING", "Recorded baseline resolved unexpectedly")
    if require_source_unchanged:
        source_ref = session["source_ref"]
        if source_ref:
            ref_value = resolve_ref(repository, str(source_ref))
            if ref_value is None:
                raise NoTugError("BASELINE_REF_DRIFT", "Recorded baseline branch no longer exists")
            if ref_value != baseline:
                raise NoTugError(
                    "BASELINE_REF_DRIFT", "Recorded baseline branch advanced or changed"
                )
        if repository.head != session["source_head"] or repository.branch != source_ref:
            raise NoTugError(
                "SOURCE_HEAD_DRIFT", "Protected checkout HEAD changed after session creation"
            )
    if require_source_clean:
        try:
            require_clean(repository)
        except NoTugError as exc:
            raise NoTugError("SOURCE_DIRTY_DRIFT", "Protected checkout is no longer clean") from exc
    stored = verify_manifest(
        repository,
        # load_manifest is imported lazily to avoid a circular-looking public surface.
        __import__(f"{MODULE_NAME}.manifests", fromlist=["load_manifest"]).load_manifest(
            vault.manifest_path(
                str(session["repository_id"]), str(session["baseline_manifest_hash"])
            ),
            expected_hash=str(session["baseline_manifest_hash"]),
            expected_repository_id=str(session["repository_id"]),
        ),
    )
    if stored.manifest_hash != session["baseline_manifest_hash"]:
        raise NoTugError("SOURCE_MANIFEST_DRIFT", "Baseline SHA-256 manifest does not match")
    return repository


def start_session(path: Path, name: str, vault: Vault | None = None) -> SessionResult:
    if not SESSION_NAME_RE.fullmatch(name):
        raise NoTugError(
            "SESSION_NAME_INVALID",
            "Session names must be 1-64 safe letters, digits, dots, dashes, or underscores",
        )
    repository = discover_repository(path, require_clean=True, require_attached=True)
    require_clean(repository)
    vault = vault or Vault()
    repository_id = _ensure_initialized(repository, vault)
    policy = create_or_load_policy(vault.policy_path(repository_id))
    session_id = new_identifier("session")
    worktree = vault.worktree_path(repository_id, "session", session_id)
    if worktree.exists():
        raise NoTugError("WORKTREE_COLLISION", "Generated session worktree path already exists")
    manifest = generate_manifest(repository, repository.head, repository_id=repository_id)
    tracked_symlinks = [entry.path for entry in manifest.entries if entry.mode == "120000"]
    if tracked_symlinks:
        raise NoTugError(
            "UNSAFE_BASELINE_SYMLINK",
            "Session creation refuses baselines containing tracked symbolic links",
            {"path": tracked_symlinks[0], "count": len(tracked_symlinks)},
        )
    write_manifest(vault.manifest_path(repository_id, manifest.manifest_hash), manifest)
    with vault.locked(repository_id):
        _create_or_verify_immutable_bytes(
            vault.policy_snapshot_path(repository_id, policy.sha256), policy.raw_bytes
        )
        add_detached_worktree(
            repository,
            worktree,
            repository.head,
            hooks_path=vault.root / "trusted" / "empty-hooks",
        )
        session: dict[str, Any] = {
            "schema_version": 1,
            "session_id": session_id,
            "repository_id": repository_id,
            "name": name,
            "state": State.SESSION_OPEN.value,
            "created_at": utc_now(),
            "baseline_commit": repository.head,
            "baseline_tree": repository.head_tree,
            "source_ref": repository.branch,
            "source_head": repository.head,
            "policy_hash": policy.sha256,
            "baseline_manifest_hash": manifest.manifest_hash,
            "worktree": str(worktree.resolve()),
            "git_pointer_hash": _git_pointer_hash(worktree),
            "tug_id": None,
            "grant_id": None,
            "archived_at": None,
            "last_event_hash": None,
        }
        event = ledger_for(vault, repository_id).append_transition(
            repository_id=repository_id,
            event_type="SESSION_CREATED",
            entity_type="session",
            entity_id=session_id,
            state_from=State.LOCKED.value,
            state_to=State.SESSION_OPEN.value,
            payload={
                "baseline_commit": repository.head,
                "baseline_manifest_hash": manifest.manifest_hash,
                "policy_hash": policy.sha256,
                "session_metadata_sha256": session_metadata_hash(session),
            },
        )
        session["last_event_hash"] = event["event_hash"]
        save_session(vault, session)
    return SessionResult(
        session_id, repository_id, worktree.resolve(), repository.head, policy.sha256
    )


def run_agent_command(session_id: str, command: Sequence[str], vault: Vault | None = None) -> int:
    if not command:
        raise NoTugError("COMMAND_REQUIRED", "An executable and its arguments are required")
    selected_vault = vault or Vault()
    repository_id, _ = find_session(selected_vault, session_id)
    with selected_vault.locked(repository_id):
        return _run_agent_command_locked(session_id, command, selected_vault)


def run_agent_command_streaming(
    session_id: str,
    command: Sequence[str],
    *,
    input_bytes: bytes,
    stdout_callback: Callable[[str], None],
    stderr_callback: Callable[[str], None],
    cancel_event: threading.Event,
    vault: Vault | None = None,
) -> AgentCommandResult:
    """Run one GUI-owned child with bounded stdin, sanitized streaming, and cancellation."""

    if not command:
        raise NoTugError("COMMAND_REQUIRED", "An executable and its arguments are required")
    if len(input_bytes) > MAX_STDIN_BYTES:
        raise NoTugError("COMMAND_INPUT_TOO_LARGE", "Agent input exceeds one megabyte")
    selected_vault = vault or Vault()
    repository_id, _ = find_session(selected_vault, session_id)
    with selected_vault.locked(repository_id):
        return _run_agent_command_streaming_locked(
            session_id,
            command,
            input_bytes=input_bytes,
            stdout_callback=stdout_callback,
            stderr_callback=stderr_callback,
            cancel_event=cancel_event,
            vault=selected_vault,
        )


def _resolved_agent_worktree_argument(value: str, worktree: Path) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = worktree / candidate
    return candidate.resolve(strict=False)


def _portable_command_basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _is_codex_node_entrypoint(value: str) -> bool:
    normalized = value.replace("\\", "/").casefold()
    return normalized.endswith("/@openai/codex/bin/codex.js")


def _codex_argument_offset(command: Sequence[str]) -> int | None:
    executable = _portable_command_basename(command[0])
    if executable in CODEX_EXECUTABLE_NAMES:
        return 1
    if (
        executable in NODE_EXECUTABLE_NAMES
        and len(command) > 1
        and _is_codex_node_entrypoint(command[1])
    ):
        return 2
    return None


def _bind_codex_worktree(command: Sequence[str], worktree: Path) -> list[str]:
    """Bind recognized Codex CLI launches to the verified managed worktree."""

    effective = list(command)
    argument_offset = _codex_argument_offset(effective)
    if argument_offset is None:
        return effective

    expected = worktree.resolve()
    for index in range(argument_offset, len(effective)):
        argument = effective[index]
        supplied: str | None = None
        if argument in {"-C", "--cd"}:
            if index + 1 >= len(effective):
                raise NoTugError(
                    "AGENT_WORKSPACE_MISMATCH",
                    "Codex worktree option is missing its path",
                )
            supplied = effective[index + 1]
        elif argument.startswith("--cd=") or argument.startswith("-C="):
            supplied = argument.split("=", 1)[1]
        if supplied is None:
            continue
        if _resolved_agent_worktree_argument(supplied, expected) != expected:
            raise NoTugError(
                "AGENT_WORKSPACE_MISMATCH",
                "Codex worktree option does not match the managed session",
            )
        return effective

    return [*effective[:argument_offset], "-C", str(expected), *effective[argument_offset:]]


def _prepare_agent_command(
    command: Sequence[str],
    *,
    vault: Vault,
    repository_id: str,
    worktree: Path,
) -> list[str]:
    effective = _bind_codex_worktree(command, worktree)
    if _codex_argument_offset(command) is not None:
        prepare_codex_workspace_access(vault, repository_id, worktree)
    return effective


def _run_agent_command_locked(session_id: str, command: Sequence[str], vault: Vault) -> int:
    repository_id, session = find_session(vault, session_id)
    ledger = ledger_for(vault, repository_id)
    chain = ledger.verify()
    verify_session_receipt_head(session, chain.events)
    if session["state"] != State.SESSION_OPEN.value:
        raise NoTugError(
            "STATE_TRANSITION_INVALID",
            "Commands may run only while a session is open",
            {"state": session["state"]},
        )
    verify_session_worktree(vault, session)
    worktree = Path(str(session["worktree"]))
    effective_command = _prepare_agent_command(
        command,
        vault=vault,
        repository_id=repository_id,
        worktree=worktree,
    )
    operation_id = new_identifier("operation")
    command_record = redact_command(effective_command)
    started = utc_now()
    operation: dict[str, Any] = {
        "schema_version": 1,
        "operation_id": operation_id,
        "kind": "agent-command",
        "session_id": session_id,
        "state": "RUNNING",
        "started_at": started,
        "ended_at": None,
        "exit_status": None,
        "command": command_record,
    }
    atomic_write_json(vault.operation_path(repository_id, operation_id), operation)
    ledger.append(
        repository_id=repository_id,
        event_type="RUN_STARTED",
        entity_type="run",
        entity_id=operation_id,
        payload={
            "session_id": session_id,
            "executable": command_record["executable"],
            "argument_count": command_record["argument_count"],
            "command_sha256": sha256_bytes(canonical_json_bytes(command_record)),
            "started_at": started,
        },
    )
    environment = os.environ.copy()
    environment[AGENT_SESSION_ENVIRONMENT_VARIABLE] = session_id
    try:
        exit_status = run_sanitized_process(
            effective_command,
            cwd=worktree,
            env=environment,
            runner=subprocess.run,
        )
    except OSError as exc:
        ended_at = utc_now()
        ledger.append(
            repository_id=repository_id,
            event_type="RUN_FAILED",
            entity_type="run",
            entity_id=operation_id,
            payload={"session_id": session_id, "exit_status": None, "ended_at": ended_at},
        )
        operation["state"] = "FAILED"
        operation["ended_at"] = ended_at
        atomic_write_json(vault.operation_path(repository_id, operation_id), operation)
        if isinstance(exc, WindowsBatchCommandError):
            raise NoTugError(
                "WINDOWS_BATCH_REQUIRES_EXPLICIT_SHELL",
                "Direct .bat/.cmd execution is refused; invoke cmd.exe explicitly if "
                "shell parsing is intended",
            ) from exc
        raise NoTugError("COMMAND_START_FAILED", "Agent command could not be started") from exc
    ended_at = utc_now()
    ledger.append(
        repository_id=repository_id,
        event_type="RUN_SUCCEEDED" if exit_status == 0 else "RUN_FAILED",
        entity_type="run",
        entity_id=operation_id,
        payload={"session_id": session_id, "exit_status": exit_status, "ended_at": ended_at},
    )
    operation["state"] = "SUCCEEDED" if exit_status == 0 else "FAILED"
    operation["ended_at"] = ended_at
    operation["exit_status"] = exit_status
    atomic_write_json(vault.operation_path(repository_id, operation_id), operation)
    return exit_status


def _run_agent_command_streaming_locked(
    session_id: str,
    command: Sequence[str],
    *,
    input_bytes: bytes,
    stdout_callback: Callable[[str], None],
    stderr_callback: Callable[[str], None],
    cancel_event: threading.Event,
    vault: Vault,
) -> AgentCommandResult:
    repository_id, session = find_session(vault, session_id)
    ledger = ledger_for(vault, repository_id)
    chain = ledger.verify()
    verify_session_receipt_head(session, chain.events)
    if session["state"] != State.SESSION_OPEN.value:
        raise NoTugError(
            "STATE_TRANSITION_INVALID",
            "Commands may run only while a session is open",
            {"state": session["state"]},
        )
    verify_session_worktree(vault, session)
    worktree = Path(str(session["worktree"]))
    effective_command = _prepare_agent_command(
        command,
        vault=vault,
        repository_id=repository_id,
        worktree=worktree,
    )
    operation_id = new_identifier("operation")
    command_record = redact_command(effective_command)
    started = utc_now()
    operation: dict[str, Any] = {
        "schema_version": 1,
        "operation_id": operation_id,
        "kind": "agent-command",
        "session_id": session_id,
        "state": "RUNNING",
        "started_at": started,
        "ended_at": None,
        "exit_status": None,
        "command": command_record,
    }
    atomic_write_json(vault.operation_path(repository_id, operation_id), operation)
    ledger.append(
        repository_id=repository_id,
        event_type="RUN_STARTED",
        entity_type="run",
        entity_id=operation_id,
        payload={
            "session_id": session_id,
            "executable": command_record["executable"],
            "argument_count": command_record["argument_count"],
            "command_sha256": sha256_bytes(canonical_json_bytes(command_record)),
            "started_at": started,
        },
    )
    environment = os.environ.copy()
    environment[AGENT_SESSION_ENVIRONMENT_VARIABLE] = session_id
    try:
        outcome = run_cancellable_process(
            effective_command,
            cwd=worktree,
            env=environment,
            input_bytes=input_bytes,
            stdout_callback=stdout_callback,
            stderr_callback=stderr_callback,
            cancel_event=cancel_event,
            hide_window=True,
        )
    except OSError as exc:
        ended_at = utc_now()
        ledger.append(
            repository_id=repository_id,
            event_type="RUN_FAILED",
            entity_type="run",
            entity_id=operation_id,
            payload={"session_id": session_id, "exit_status": None, "ended_at": ended_at},
        )
        operation["state"] = "FAILED"
        operation["ended_at"] = ended_at
        atomic_write_json(vault.operation_path(repository_id, operation_id), operation)
        if isinstance(exc, WindowsBatchCommandError):
            raise NoTugError(
                "WINDOWS_BATCH_REQUIRES_EXPLICIT_SHELL",
                "Direct .bat/.cmd execution is refused; invoke cmd.exe explicitly if "
                "shell parsing is intended",
            ) from exc
        raise NoTugError("COMMAND_START_FAILED", "Agent command could not be started") from exc
    ended_at = utc_now()
    event_type = (
        "RUN_CANCELLED"
        if outcome.cancelled
        else ("RUN_SUCCEEDED" if outcome.returncode == 0 else "RUN_FAILED")
    )
    ledger.append(
        repository_id=repository_id,
        event_type=event_type,
        entity_type="run",
        entity_id=operation_id,
        payload={
            "session_id": session_id,
            "exit_status": outcome.returncode,
            "ended_at": ended_at,
        },
    )
    operation["state"] = (
        "CANCELLED" if outcome.cancelled else ("SUCCEEDED" if outcome.returncode == 0 else "FAILED")
    )
    operation["ended_at"] = ended_at
    operation["exit_status"] = outcome.returncode
    atomic_write_json(vault.operation_path(repository_id, operation_id), operation)
    return AgentCommandResult(
        operation_id=operation_id,
        exit_status=outcome.returncode,
        cancelled=outcome.cancelled,
    )


def _verify_reviewed_workspace_unchanged(
    vault: Vault,
    repository_id: str,
    session: dict[str, Any],
    worktree: Path,
) -> None:
    """Refuse destructive archival when live bytes differ from reviewed evidence."""

    from .changes import _workspace_manifest
    from .tug import load_tug, verify_tug_artifacts

    tug_id = str(session["tug_id"])
    tug = load_tug(vault, repository_id, tug_id)
    if tug["session_id"] != session["session_id"]:
        raise NoTugError(
            "SESSION_RECEIPT_DIVERGENCE",
            "Reviewed Tug Signal is not bound to the archived session",
        )
    verify_tug_artifacts(vault, repository_id, tug)
    reviewed_manifest = read_json(
        vault.changes_path(repository_id, tug_id).with_suffix(".workspace.json")
    )
    try:
        current_manifest = _workspace_manifest(worktree)
    except NoTugError as exc:
        raise NoTugError(
            "WORKSPACE_POST_REVIEW_DRIFT",
            "Session workspace cannot be reconciled with its reviewed bytes",
        ) from exc
    if current_manifest != reviewed_manifest:
        raise NoTugError(
            "WORKSPACE_POST_REVIEW_DRIFT",
            "Session workspace changed after Tug review; archival refused",
        )


def archive_session(session_id: str, vault: Vault | None = None) -> None:
    selected_vault = vault or Vault()
    repository_id, _ = find_session(selected_vault, session_id)
    with selected_vault.locked(repository_id):
        _archive_session_locked(session_id, selected_vault)


def abandon_session(session_id: str, vault: Vault | None = None) -> None:
    """Disposition an exact unchanged open session without inventing a Tug Signal."""

    selected_vault = vault or Vault()
    repository_id, _ = find_session(selected_vault, session_id)
    with selected_vault.locked(repository_id):
        repository_id, session = find_session(selected_vault, session_id)
        chain = ledger_for(selected_vault, repository_id).verify()
        verify_session_receipt_head(session, chain.events)
        if session["state"] != State.SESSION_OPEN.value:
            raise NoTugError(
                "STATE_TRANSITION_INVALID",
                "Only an unchanged open session can be abandoned",
            )
        if session["tug_id"] is not None or session["grant_id"] is not None:
            raise NoTugError(
                "SESSION_RECEIPT_DIVERGENCE",
                "Open session unexpectedly names a Tug Signal or grant",
            )
        verify_session_worktree(selected_vault, session)
        verify_authoritative_baseline(selected_vault, session)
        worktree = Path(str(session["worktree"]))
        if not is_clean(discover_repository(worktree)):
            raise NoTugError(
                "SESSION_HAS_CHANGES",
                "Changed session work must be reviewed and denied or retained",
            )
        event = ledger_for(selected_vault, repository_id).append_transition(
            repository_id=repository_id,
            event_type="SESSION_ABANDONED",
            entity_type="session",
            entity_id=session_id,
            state_from=State.SESSION_OPEN.value,
            state_to=State.ABANDONED.value,
            payload={"session_id": session_id},
        )
        session["state"] = State.ABANDONED.value
        session["last_event_hash"] = event["event_hash"]
        save_session(selected_vault, session)


def _archive_session_locked(session_id: str, vault: Vault) -> None:
    repository_id, session = find_session(vault, session_id)
    if session["archived_at"] is not None:
        raise NoTugError(
            "SESSION_ALREADY_ARCHIVED",
            "Session workspace was already archived",
        )
    if session["state"] not in {
        State.ABANDONED.value,
        State.DENIED.value,
        State.APPLIED.value,
        State.REVOKED.value,
    }:
        raise NoTugError(
            "SESSION_DISPOSITION_REQUIRED",
            "A session can be archived only after denial or completed application",
        )
    ledger = ledger_for(vault, repository_id)
    verification = ledger.verify()
    worktree, created = _verify_session_creation_binding(
        vault, repository_id, session_id, session, verification.events
    )
    verify_session_receipt_head(session, verification.events)
    _verify_archive_disposition_binding(
        repository_id, session_id, session, verification.events, created
    )
    repository = verify_session_worktree(vault, session)
    if session["state"] == State.ABANDONED.value:
        if not is_clean(discover_repository(worktree)):
            raise NoTugError(
                "WORKSPACE_POST_REVIEW_DRIFT",
                "Abandoned session changed after its disposition",
            )
    else:
        _verify_reviewed_workspace_unchanged(vault, repository_id, session, worktree)
    # The user explicitly requested this exact NoTUG-owned disposable worktree's removal.
    hooks = ensure_trusted_empty_hooks_directory(vault.root / "trusted" / "empty-hooks")
    run_git(
        repository.root,
        [
            "-c",
            f"core.hooksPath={hooks}",
            "worktree",
            "remove",
            "--force",
            str(worktree),
        ],
    )
    session["archived_at"] = utc_now()
    event = ledger.append(
        repository_id=repository_id,
        event_type="SESSION_ARCHIVED",
        entity_type="session",
        entity_id=session_id,
        payload={
            "archived_at": session["archived_at"],
            "disposition_state": session["state"],
        },
    )
    session["last_event_hash"] = event["event_hash"]
    save_session(vault, session)


def mutation_lock_line() -> str:
    return MUTATION_LOCK_ACTIVE
