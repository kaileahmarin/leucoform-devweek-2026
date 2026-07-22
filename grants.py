"""Exact Tug-bound human grants, transactional integration, and revocation."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

from .brand import (
    AGENT_SESSION_ENVIRONMENT_VARIABLE,
    BRANCH_NAMESPACE,
    COMMIT_EMAIL,
    COMMIT_TRAILER_PREFIX,
    EVIDENCE_REF_NAMESPACE,
    PRODUCT_NAME,
    VALIDATION_CONTEXT_ENVIRONMENT_VARIABLE,
)
from .changes import prepare_snapshot
from .config import load_policy
from .errors import NoTugError
from .events import ledger_for
from .git import (
    discover_repository,
    ensure_trusted_empty_hooks_directory,
    inert_filter_config_arguments,
    is_clean,
    run_git,
    worktree_list,
)
from .identity import new_identifier, validate_identifier
from .models import State, assert_transition
from .process import WindowsBatchCommandError, run_sanitized_process
from .sessions import (
    _verified_managed_worktree_path,
    _verify_session_creation_binding,
    find_session,
    save_session,
    verify_authoritative_baseline,
    verify_session_receipt_head,
    verify_session_worktree,
)
from .tug import find_tug, verify_tug_artifacts
from .util import (
    atomic_write_json,
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    utc_now,
)
from .vault import Vault

GRANT_FIELDS = {
    "schema_version",
    "grant_id",
    "repository_id",
    "session_id",
    "tug_id",
    "tug_hash",
    "patch_sha256",
    "binding_hash",
    "state",
    "issued_at",
    "grant_event_hash",
    "branch",
    "worktree",
    "validation",
    "commit",
    "applied_at",
    "revoke",
}
GRANT_METADATA_FIELDS = (
    "grant_id",
    "repository_id",
    "session_id",
    "tug_id",
    "tug_hash",
    "patch_sha256",
    "binding_hash",
    "issued_at",
    "branch",
    "worktree",
)
APPLICATION_METADATA_FIELDS = (
    "grant_id",
    "tug_id",
    "tug_hash",
    "patch_sha256",
    "branch",
    "worktree",
    "validation",
    "commit",
    "applied_at",
)


def _binding_hash(
    repository_id: str,
    session_id: str,
    tug_id: str,
    tug_hash_value: str,
    patch_hash: str,
) -> str:
    binding = {
        "repository_id": repository_id,
        "session_id": session_id,
        "tug_id": tug_id,
        "tug_hash": tug_hash_value,
        "patch_sha256": patch_hash,
    }
    return sha256_bytes(b"NoTUG.GrantBinding.v1\0" + canonical_json_bytes(binding))


def grant_metadata_hash(grant: dict[str, Any]) -> str:
    metadata = {field: grant[field] for field in GRANT_METADATA_FIELDS}
    return sha256_bytes(b"NoTUG.GrantMetadata.v1\0" + canonical_json_bytes(metadata))


def application_metadata_hash(grant: dict[str, Any]) -> str:
    metadata = {field: grant[field] for field in APPLICATION_METADATA_FIELDS}
    return sha256_bytes(b"NoTUG.ApplicationMetadata.v1\0" + canonical_json_bytes(metadata))


def validation_results_hash(results: list[dict[str, Any]]) -> str:
    return sha256_bytes(b"NoTUG.ValidationResults.v1\0" + canonical_json_bytes(results))


def revoke_metadata_hash(disposition: dict[str, Any]) -> str:
    return sha256_bytes(b"NoTUG.RevokeMetadata.v1\0" + canonical_json_bytes(disposition))


def validate_grant(grant: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(grant) - GRANT_FIELDS)
    missing = sorted(GRANT_FIELDS - set(grant))
    schema_version = grant.get("schema_version")
    if (
        unknown
        or missing
        or not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        raise NoTugError(
            "GRANT_SCHEMA_INVALID",
            "Grant artifact fields do not match schema version 1",
            {"unknown_fields": unknown, "missing_fields": missing},
        )
    expected = _binding_hash(
        str(grant["repository_id"]),
        str(grant["session_id"]),
        str(grant["tug_id"]),
        str(grant["tug_hash"]),
        str(grant["patch_sha256"]),
    )
    if grant["binding_hash"] != expected:
        raise NoTugError("GRANT_BINDING_MISMATCH", "Grant is not bound to its exact Tug Signal")
    if not isinstance(grant["state"], str) or grant["state"] not in {
        State.GRANTED.value,
        State.APPLIED.value,
        State.FAILED.value,
        State.REVOKED.value,
    }:
        raise NoTugError("GRANT_SCHEMA_INVALID", "Grant state is invalid")
    if not isinstance(grant["validation"], list):
        raise NoTugError("GRANT_SCHEMA_INVALID", "Grant validation results must be an array")
    try:
        validate_identifier(grant["grant_id"], "grant")
        validate_identifier(grant["repository_id"], "repo")
        validate_identifier(grant["session_id"], "session")
        validate_identifier(grant["tug_id"], "tug")
    except NoTugError as exc:
        raise NoTugError("GRANT_SCHEMA_INVALID", "Grant identifiers are invalid") from exc
    hash_re = re.compile(r"^[a-f0-9]{64}$")
    oid_re = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
    if (
        any(
            not isinstance(grant[key], str) or hash_re.fullmatch(grant[key]) is None
            for key in ("tug_hash", "patch_sha256", "binding_hash", "grant_event_hash")
        )
        or not isinstance(grant["issued_at"], str)
        or not isinstance(grant["branch"], str)
        or not isinstance(grant["worktree"], str)
        or (
            grant["commit"] is not None
            and (not isinstance(grant["commit"], str) or oid_re.fullmatch(grant["commit"]) is None)
        )
        or (grant["applied_at"] is not None and not isinstance(grant["applied_at"], str))
        or (grant["revoke"] is not None and not isinstance(grant["revoke"], dict))
    ):
        raise NoTugError("GRANT_SCHEMA_INVALID", "Grant metadata types are invalid")
    validation_fields = {"index", "executable", "returncode", "started_at", "ended_at"}
    if any(
        not isinstance(result, dict)
        or set(result) != validation_fields
        or not isinstance(result["index"], int)
        or isinstance(result["index"], bool)
        or not isinstance(result["executable"], str)
        or not isinstance(result["returncode"], int)
        or isinstance(result["returncode"], bool)
        or not isinstance(result["started_at"], str)
        or not isinstance(result["ended_at"], str)
        for result in grant["validation"]
    ):
        raise NoTugError("GRANT_SCHEMA_INVALID", "Grant validation result schema is invalid")
    return grant


def _assert_human_context(vault: Vault) -> None:
    if os.environ.get(AGENT_SESSION_ENVIRONMENT_VARIABLE) or os.environ.get(
        VALIDATION_CONTEXT_ENVIRONMENT_VARIABLE
    ):
        raise NoTugError(
            "GRANT_FROM_AGENT_CONTEXT",
            "Agent and validation commands cannot issue a human grant",
        )
    current = Path.cwd().resolve()
    try:
        current.relative_to(vault.worktrees_dir.resolve())
    except ValueError:
        return
    raise NoTugError(
        "GRANT_FROM_AGENT_CONTEXT",
        "Run the grant from outside every vault-managed worktree",
    )


def _interactive_confirmation(tug_hash_value: str) -> bool:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise NoTugError(
            "HUMAN_GRANT_REQUIRED",
            "Grant requires an interactive terminal and exact Tug Signal hash confirmation",
            {"tug_hash": tug_hash_value},
        )
    expected = f"GRANT {tug_hash_value}"
    print(f"Type exactly: {expected}", file=sys.stderr)
    print("> ", end="", file=sys.stderr, flush=True)
    try:
        entered = sys.stdin.readline()
    except (EOFError, KeyboardInterrupt) as exc:
        raise NoTugError("GRANT_CONFIRMATION_FAILED", "Grant confirmation was cancelled") from exc
    if entered == "":
        raise NoTugError("GRANT_CONFIRMATION_FAILED", "Grant confirmation was cancelled")
    return entered.rstrip("\r\n") == expected


def _branch_name(repository: Path, category: str, short_id: str) -> str:
    base = f"{BRANCH_NAMESPACE}/{category}/{short_id}"
    for suffix in range(1, 10_000):
        candidate = base if suffix == 1 else f"{base}-{suffix}"
        exists = run_git(
            repository, ["show-ref", "--verify", "--quiet", f"refs/heads/{candidate}"], check=False
        )
        if exists.returncode == 1:
            return candidate
        if exists.returncode not in {0, 1}:
            raise NoTugError("GIT_COMMAND_FAILED", "Could not inspect integration branch names")
    raise NoTugError("BRANCH_COLLISION", "No collision-safe generated branch name is available")


def _preflight_patch(
    repository: Path,
    baseline: str,
    patch: bytes,
    operation_dir: Path,
    expected_tree: str,
    *,
    hooks_path: Path,
) -> None:
    operation_dir.mkdir(parents=True, exist_ok=False)
    index_path = operation_dir / "preflight.index"
    env = {"GIT_INDEX_FILE": str(index_path)}
    inert_arguments = inert_filter_config_arguments(repository, hooks_path=hooks_path)
    try:
        run_git(repository, [*inert_arguments, "read-tree", baseline], env=env)
        run_git(
            repository,
            [*inert_arguments, "apply", "--check", "--cached", "--binary", "-"],
            env=env,
            input_bytes=patch,
        )
        run_git(
            repository,
            [*inert_arguments, "apply", "--cached", "--binary", "-"],
            env=env,
            input_bytes=patch,
        )
        actual_tree = (
            run_git(repository, [*inert_arguments, "write-tree"], env=env)
            .stdout.decode("ascii")
            .strip()
        )
        if actual_tree != expected_tree:
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "Preflight patch did not reproduce the reviewed snapshot tree",
            )
    finally:
        index_path.unlink(missing_ok=True)
        index_path.with_name(index_path.name + ".lock").unlink(missing_ok=True)
        with suppress(FileNotFoundError):
            operation_dir.rmdir()


def _reverify_session_snapshot(
    vault: Vault,
    repository: Any,
    session: dict[str, Any],
    tug: dict[str, Any],
    operation_dir: Path,
) -> None:
    try:
        fresh = prepare_snapshot(
            repository,
            Path(str(session["worktree"])),
            str(session["baseline_commit"]),
            operation_dir,
            vault.root,
        )
        if (
            fresh.snapshot_tree != tug["evidence"]["snapshot_tree"]
            or fresh.patch_sha256 != tug["evidence"]["patch_sha256"]
            or fresh.workspace_manifest_hash != tug["evidence"]["workspace_manifest_hash"]
        ):
            raise NoTugError("WORKTREE_DRIFT", "Disposable session changed after Tug review")
    finally:
        for name in ("proposal.patch", "workspace-manifest.json", "snapshot.index"):
            (operation_dir / name).unlink(missing_ok=True)
        (operation_dir / "snapshot.index.lock").unlink(missing_ok=True)
        with suppress(FileNotFoundError):
            operation_dir.rmdir()


def _validation_commands(
    worktree: Path,
    commands: list[list[str]],
    results: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    results = results if results is not None else []
    environment = os.environ.copy()
    environment[VALIDATION_CONTEXT_ENVIRONMENT_VARIABLE] = "1"
    for index, command in enumerate(commands, start=1):
        started_at = utc_now()
        try:
            returncode = run_sanitized_process(
                command,
                cwd=worktree,
                env=environment,
                runner=subprocess.run,
            )
        except OSError as exc:
            if isinstance(exc, WindowsBatchCommandError):
                raise NoTugError(
                    "WINDOWS_BATCH_REQUIRES_EXPLICIT_SHELL",
                    "Direct .bat/.cmd validation is refused; invoke cmd.exe explicitly "
                    "if shell parsing is intended",
                    {"index": index},
                ) from exc
            raise NoTugError(
                "VALIDATION_COMMAND_FAILED",
                "A configured validation command could not start",
                {"index": index},
            ) from exc
        results.append(
            {
                "index": index,
                "executable": Path(command[0]).name,
                "returncode": returncode,
                "started_at": started_at,
                "ended_at": utc_now(),
            }
        )
        if returncode != 0:
            raise NoTugError(
                "VALIDATION_FAILED",
                "A configured validation command returned nonzero",
                {"index": index, "returncode": returncode},
            )
    return results


def _commit_message(tug: dict[str, Any], grant_event_hash: str) -> bytes:
    return (
        f"Apply approved agent change ({tug['tug_id']})\n\n"
        f"{COMMIT_TRAILER_PREFIX}-Tug: {tug['tug_id']}\n"
        f"{COMMIT_TRAILER_PREFIX}-Tug-SHA256: {tug['tug_hash']}\n"
        f"{COMMIT_TRAILER_PREFIX}-Patch-SHA256: {tug['evidence']['patch_sha256']}\n"
        f"{COMMIT_TRAILER_PREFIX}-Grant-Receipt: {grant_event_hash}\n"
    ).encode()


def _binary_diff(repository: Path, old: str, new: str) -> bytes:
    return run_git(
        repository,
        [
            *inert_filter_config_arguments(repository),
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            old,
            new,
            "--",
        ],
    ).stdout


def _record_grant_failure(
    vault: Vault,
    repository_id: str,
    session: dict[str, Any],
    grant: dict[str, Any],
    error: NoTugError,
) -> None:
    if session["state"] != State.GRANTED.value:
        return
    event = ledger_for(vault, repository_id).append_transition(
        repository_id=repository_id,
        event_type="GRANT_FAILED",
        entity_type="grant",
        entity_id=str(grant["grant_id"]),
        state_from=State.GRANTED.value,
        state_to=State.FAILED.value,
        payload={
            "tug_id": grant["tug_id"],
            "reason_code": error.code,
            "failure_metadata_sha256": application_metadata_hash(grant),
        },
    )
    grant["state"] = State.FAILED.value
    session["state"] = State.FAILED.value
    session["last_event_hash"] = event["event_hash"]
    atomic_write_json(vault.grant_path(repository_id, str(grant["grant_id"])), grant)
    save_session(vault, session)


def grant_tug(tug_id: str, vault: Vault | None = None) -> dict[str, Any]:
    """Grant one exact Tug Signal through an interactive terminal ceremony."""

    selected_vault = vault or Vault()
    _assert_human_context(selected_vault)
    repository_id, _ = find_tug(selected_vault, tug_id)
    with selected_vault.locked(repository_id):
        return _grant_tug_locked(tug_id, selected_vault)


def _grant_tug_locked(tug_id: str, vault: Vault) -> dict[str, Any]:
    return _grant_tug_locked_with_confirmation(tug_id, vault, _interactive_confirmation)


def grant_tug_with_phrase(
    tug_id: str,
    confirmation: str,
    vault: Vault | None = None,
) -> dict[str, Any]:
    """Grant one exact Tug Signal through a native human-entered phrase."""

    selected_vault = vault or Vault()
    _assert_human_context(selected_vault)
    repository_id, _ = find_tug(selected_vault, tug_id)

    def confirm(tug_hash_value: str) -> bool:
        return confirmation == f"GRANT {tug_hash_value}"

    with selected_vault.locked(repository_id):
        return _grant_tug_locked_with_confirmation(tug_id, selected_vault, confirm)


def _grant_tug_locked_with_confirmation(
    tug_id: str,
    vault: Vault,
    confirmation: Callable[[str], bool],
) -> dict[str, Any]:
    repository_id, tug = find_tug(vault, tug_id)
    _, session = find_session(vault, str(tug["session_id"]))
    ledger = ledger_for(vault, repository_id)
    chain = ledger.verify()
    if any(
        event["event_type"] == "TUG_DENIED" and event["entity_id"] == tug_id
        for event in chain.events
    ):
        raise NoTugError("TUG_ALREADY_DENIED", "Tug Signal has an authoritative denial receipt")
    verify_session_receipt_head(session, chain.events)
    if session["tug_id"] != tug_id or session["state"] != State.TUGGED.value:
        raise NoTugError("STATE_TRANSITION_INVALID", "Tug Signal is not pending an exact grant")
    if not tug["grant"]["grantable"]:
        raise NoTugError(
            "POLICY_BLOCKED", "Blocking policy findings prevent application", {"tug_id": tug_id}
        )
    assert_transition(str(session["state"]), State.GRANTED.value)
    receipt_sequence = int(tug["receipt_chain"]["sequence"])
    if receipt_sequence > chain.count:
        raise NoTugError("RECEIPT_BINDING_MISMATCH", "Tug Signal names a future receipt head")
    if receipt_sequence:
        receipt = chain.events[receipt_sequence - 1]
        if receipt["event_hash"] != tug["receipt_chain"]["head_hash"]:
            raise NoTugError("RECEIPT_BINDING_MISMATCH", "Tug receipt-chain binding is invalid")
    verify_tug_artifacts(vault, repository_id, tug)
    repository = verify_session_worktree(vault, session)
    verify_authoritative_baseline(vault, session)
    policy = load_policy(
        vault.policy_snapshot_path(repository_id, str(session["policy_hash"])),
        str(session["policy_hash"]),
    )
    hooks = ensure_trusted_empty_hooks_directory(vault.root / "trusted" / "empty-hooks")
    grant_id = new_identifier("grant")
    worktree = vault.worktree_path(repository_id, "integration", grant_id)
    if worktree.exists():
        raise NoTugError("WORKTREE_PATH_COLLISION", "Generated integration worktree path exists")
    operation_root = vault.repository_dir(repository_id) / "operations" / grant_id
    if operation_root.exists() or operation_root.is_symlink():
        raise NoTugError("OPERATION_PATH_COLLISION", "Grant preflight path already exists")
    operation_root.mkdir(parents=True, exist_ok=False)
    try:
        _reverify_session_snapshot(vault, repository, session, tug, operation_root / "snapshot")
        patch = vault.patch_path(repository_id, tug_id).read_bytes()
        _preflight_patch(
            repository.root,
            str(tug["baseline"]["commit"]),
            patch,
            operation_root / "preflight",
            str(tug["evidence"]["snapshot_tree"]),
            hooks_path=hooks,
        )
    finally:
        with suppress(FileNotFoundError):
            operation_root.rmdir()
    if not confirmation(str(tug["tug_hash"])):
        raise NoTugError("GRANT_CONFIRMATION_FAILED", "Exact Tug Signal confirmation did not match")
    branch = _branch_name(repository.root, "grant", tug_id.split("_", 1)[-1][:10])
    binding_hash = _binding_hash(
        repository_id,
        str(session["session_id"]),
        tug_id,
        str(tug["tug_hash"]),
        str(tug["evidence"]["patch_sha256"]),
    )
    issued_at = utc_now()
    grant_metadata: dict[str, Any] = {
        "grant_id": grant_id,
        "repository_id": repository_id,
        "session_id": session["session_id"],
        "tug_id": tug_id,
        "tug_hash": tug["tug_hash"],
        "patch_sha256": tug["evidence"]["patch_sha256"],
        "binding_hash": binding_hash,
        "issued_at": issued_at,
        "branch": branch,
        "worktree": str(worktree.resolve()),
    }
    event = ledger.append_transition(
        repository_id=repository_id,
        event_type="GRANT_ISSUED",
        entity_type="grant",
        entity_id=grant_id,
        state_from=State.TUGGED.value,
        state_to=State.GRANTED.value,
        payload={
            "session_id": session["session_id"],
            "tug_id": tug_id,
            "tug_hash": tug["tug_hash"],
            "patch_sha256": tug["evidence"]["patch_sha256"],
            "binding_hash": binding_hash,
            "grant_metadata_sha256": grant_metadata_hash(grant_metadata),
        },
    )
    grant: dict[str, Any] = {
        "schema_version": 1,
        "grant_id": grant_id,
        "repository_id": repository_id,
        "session_id": session["session_id"],
        "tug_id": tug_id,
        "tug_hash": tug["tug_hash"],
        "patch_sha256": tug["evidence"]["patch_sha256"],
        "binding_hash": binding_hash,
        "state": State.GRANTED.value,
        "issued_at": issued_at,
        "grant_event_hash": event["event_hash"],
        "branch": branch,
        "worktree": str(worktree.resolve()),
        "validation": [],
        "commit": None,
        "applied_at": None,
        "revoke": None,
    }
    validate_grant(grant)
    atomic_write_json(vault.grant_path(repository_id, grant_id), grant)
    session["state"] = State.GRANTED.value
    session["grant_id"] = grant_id
    session["last_event_hash"] = event["event_hash"]
    save_session(vault, session)
    try:
        worktree.parent.mkdir(parents=True, exist_ok=True)
        worktree_arguments = inert_filter_config_arguments(repository.root)
        worktree_arguments.extend(
            [
                "-c",
                f"core.hooksPath={hooks}",
                "worktree",
                "add",
                "-b",
                branch,
                str(worktree),
                str(tug["baseline"]["commit"]),
            ]
        )
        run_git(
            repository.root,
            worktree_arguments,
        )
        integration_inert = inert_filter_config_arguments(worktree, hooks_path=hooks)
        run_git(
            worktree,
            [*integration_inert, "apply", "--index", "--binary", "-"],
            input_bytes=patch,
        )
        applied_tree = (
            run_git(worktree, [*integration_inert, "write-tree"]).stdout.decode("ascii").strip()
        )
        if applied_tree != tug["evidence"]["snapshot_tree"]:
            raise NoTugError(
                "PROVENANCE_DIVERGENCE", "Applied index tree differs from the reviewed snapshot"
            )
        grant["validation"] = []
        _validation_commands(worktree, policy.validation_commands, grant["validation"])
        post_validation_tree = (
            run_git(worktree, [*integration_inert, "write-tree"]).stdout.decode("ascii").strip()
        )
        unstaged = run_git(
            worktree,
            [
                *integration_inert,
                "diff",
                "--quiet",
                "--no-ext-diff",
                "--no-textconv",
                "--",
            ],
            check=False,
        )
        untracked = run_git(
            worktree,
            [*integration_inert, "ls-files", "--others", "--exclude-standard", "-z"],
        ).stdout
        if (
            post_validation_tree != tug["evidence"]["snapshot_tree"]
            or unstaged.returncode != 0
            or untracked
        ):
            raise NoTugError(
                "VALIDATION_MUTATED_SNAPSHOT",
                "Validation changed the reviewed integration snapshot",
            )
        hooks = ensure_trusted_empty_hooks_directory(vault.root / "trusted" / "empty-hooks")
        integration_inert = inert_filter_config_arguments(worktree, hooks_path=hooks)
        run_git(
            worktree,
            [
                *integration_inert,
                "-c",
                f"user.name={PRODUCT_NAME}",
                "-c",
                f"user.email={COMMIT_EMAIL}",
                "-c",
                "commit.gpgSign=false",
                "-c",
                f"core.hooksPath={hooks}",
                "commit",
                "--no-verify",
                "-F",
                "-",
            ],
            input_bytes=_commit_message(tug, str(event["event_hash"])),
        )
        commit = run_git(worktree, ["rev-parse", "HEAD"]).stdout.decode("ascii").strip()
        parent = run_git(worktree, ["rev-parse", "HEAD^"]).stdout.decode("ascii").strip()
        tree = run_git(worktree, ["rev-parse", "HEAD^{tree}"]).stdout.decode("ascii").strip()
        branch_head = run_git(repository.root, ["rev-parse", branch]).stdout.decode("ascii").strip()
        if (
            parent != tug["baseline"]["commit"]
            or tree != tug["evidence"]["snapshot_tree"]
            or branch_head != commit
        ):
            raise NoTugError(
                "APPLICATION_VERIFICATION_FAILED",
                "Integration commit structure does not match the grant",
            )
        verify_authoritative_baseline(vault, session)
        grant["commit"] = commit
        grant["applied_at"] = utc_now()
        applied_event = ledger.append_transition(
            repository_id=repository_id,
            event_type="GRANT_APPLIED",
            entity_type="grant",
            entity_id=grant_id,
            state_from=State.GRANTED.value,
            state_to=State.APPLIED.value,
            payload={
                "tug_id": tug_id,
                "tug_hash": tug["tug_hash"],
                "commit": commit,
                "branch": branch,
                "validation_count": len(grant["validation"]),
                "validation_sha256": validation_results_hash(grant["validation"]),
                "application_metadata_sha256": application_metadata_hash(grant),
            },
        )
        grant["state"] = State.APPLIED.value
        session["state"] = State.APPLIED.value
        session["last_event_hash"] = applied_event["event_hash"]
        atomic_write_json(vault.grant_path(repository_id, grant_id), grant)
        save_session(vault, session)
        return grant
    except NoTugError as exc:
        _record_grant_failure(vault, repository_id, session, grant, exc)
        raise
    except BaseException as exc:
        error = NoTugError(
            "GRANT_APPLICATION_FAILED", "Unexpected failure during isolated application"
        )
        _record_grant_failure(vault, repository_id, session, grant, error)
        raise error from exc


def find_grant_for_tug(vault: Vault, tug_id: str) -> tuple[str, dict[str, Any]]:
    validate_identifier(tug_id, "tug")
    matches: list[tuple[str, dict[str, Any]]] = []
    repositories = vault.root / "r"
    if repositories.is_dir():
        for path in repositories.glob("*/grants/*.json"):
            grant = validate_grant(read_json(path))
            if grant["tug_id"] == tug_id:
                repository_id = path.parents[1].name
                if grant["grant_id"] != path.stem or grant["repository_id"] != repository_id:
                    raise NoTugError(
                        "GRANT_ID_MISMATCH",
                        "Grant identifiers disagree with the vault metadata location",
                    )
                matches.append((repository_id, grant))
    if not matches:
        raise NoTugError("GRANT_NOT_FOUND", "No applied grant matches the exact Tug Signal")
    if len(matches) != 1:
        raise NoTugError("GRANT_ID_AMBIGUOUS", "Multiple grants unexpectedly match the Tug Signal")
    return matches[0]


def _one_grant_event(
    events: tuple[dict[str, Any], ...],
    *,
    repository_id: str,
    event_type: str,
    grant_id: str,
) -> dict[str, Any]:
    matches = [
        event
        for event in events
        if event["event_type"] == event_type and event["entity_id"] == grant_id
    ]
    if len(matches) != 1:
        raise NoTugError(
            "GRANT_RECEIPT_DIVERGENCE",
            f"Grant has no unique {event_type.lower()} receipt",
        )
    event = matches[0]
    if event["repository_id"] != repository_id or event["entity_type"] != "grant":
        raise NoTugError(
            "GRANT_RECEIPT_DIVERGENCE",
            "Grant receipt belongs to another repository or entity type",
        )
    return event


def _verify_revoke_preconditions(
    vault: Vault,
    repository_id: str,
    tug_id: str,
    grant: dict[str, Any],
    session: dict[str, Any],
    events: tuple[dict[str, Any], ...],
    repository: Any,
) -> Path:
    """Verify every mutable cleanup selector before revocation mutates Git."""

    grant_id = str(grant["grant_id"])
    expected_worktree = _verified_managed_worktree_path(
        vault,
        str(grant["worktree"]),
        repository_id,
        "integration",
        grant_id,
        code="GRANT_WORKTREE_DIVERGENCE",
    )
    if not expected_worktree.is_dir():
        raise NoTugError("GRANT_WORKTREE_DIVERGENCE", "Grant integration worktree is missing")

    if (
        session["repository_id"] != repository_id
        or session["session_id"] != grant["session_id"]
        or session["grant_id"] != grant_id
        or session["tug_id"] != tug_id
        or session["state"] != State.APPLIED.value
    ):
        raise NoTugError(
            "GRANT_SESSION_MISMATCH", "Grant and session metadata do not match exactly"
        )

    issued = _one_grant_event(
        events,
        repository_id=repository_id,
        event_type="GRANT_ISSUED",
        grant_id=grant_id,
    )
    expected_issued_payload = {
        "session_id": grant["session_id"],
        "tug_id": grant["tug_id"],
        "tug_hash": grant["tug_hash"],
        "patch_sha256": grant["patch_sha256"],
        "binding_hash": grant["binding_hash"],
        "grant_metadata_sha256": grant_metadata_hash(grant),
    }
    if (
        issued["event_hash"] != grant["grant_event_hash"]
        or issued["payload"] != expected_issued_payload
        or issued["state_from"] != State.TUGGED.value
        or issued["state_to"] != State.GRANTED.value
    ):
        raise NoTugError(
            "GRANT_RECEIPT_DIVERGENCE",
            "Grant metadata disagrees with its authoritative issuance receipt",
        )

    applied = _one_grant_event(
        events,
        repository_id=repository_id,
        event_type="GRANT_APPLIED",
        grant_id=grant_id,
    )
    expected_applied_payload = {
        "tug_id": grant["tug_id"],
        "tug_hash": grant["tug_hash"],
        "commit": grant["commit"],
        "branch": grant["branch"],
        "validation_count": len(grant["validation"]),
        "validation_sha256": validation_results_hash(grant["validation"]),
        "application_metadata_sha256": application_metadata_hash(grant),
    }
    if (
        applied["payload"] != expected_applied_payload
        or applied["state_from"] != State.GRANTED.value
        or applied["state_to"] != State.APPLIED.value
        or applied["sequence"] <= issued["sequence"]
        or any(
            event["entity_id"] == grant_id
            and event["event_type"] in {"GRANT_FAILED", "GRANT_REVOKED"}
            for event in events
        )
    ):
        raise NoTugError(
            "GRANT_RECEIPT_DIVERGENCE",
            "Grant application metadata disagrees with its authoritative receipt",
        )

    tug_repository_id, tug = find_tug(vault, tug_id)
    if (
        tug_repository_id != repository_id
        or tug["repository_id"] != repository_id
        or tug["tug_id"] != tug_id
        or tug["session_id"] != grant["session_id"]
        or tug["tug_hash"] != grant["tug_hash"]
        or tug["evidence"]["patch_sha256"] != grant["patch_sha256"]
    ):
        raise NoTugError("GRANT_BINDING_MISMATCH", "Grant is not bound to its exact Tug Signal")
    verify_tug_artifacts(vault, repository_id, tug)

    commit = grant["commit"]
    if not isinstance(commit, str) or grant["applied_at"] is None or grant["revoke"] is not None:
        raise NoTugError("GRANT_STATE_DIVERGENCE", "Applied grant metadata is incomplete")
    base_branch = f"{BRANCH_NAMESPACE}/grant/{tug_id.split('_', 1)[-1][:10]}"
    branch = str(grant["branch"])
    if (
        branch != base_branch
        and re.fullmatch(rf"{re.escape(base_branch)}-(?:[2-9]|[1-9][0-9]{{1,3}})", branch) is None
    ):
        raise NoTugError(
            "GRANT_BRANCH_DIVERGENCE", "Grant branch is not a generated integration branch"
        )
    branch_ref = f"refs/heads/{branch}"
    branch_head = run_git(
        repository.root, ["rev-parse", "--verify", f"{branch_ref}^{{commit}}"], check=False
    )
    if branch_head.returncode != 0 or branch_head.stdout.decode("ascii").strip() != commit:
        raise NoTugError(
            "GRANT_BRANCH_DRIFT", "Generated integration branch changed after application"
        )
    records = [
        item for item in worktree_list(repository) if item.path.resolve() == expected_worktree
    ]
    if (
        len(records) != 1
        or records[0].detached
        or records[0].branch != branch_ref
        or records[0].head != commit
    ):
        raise NoTugError(
            "GRANT_WORKTREE_DIVERGENCE",
            "Grant worktree registration does not match its branch and commit",
        )
    parent = run_git(repository.root, ["rev-parse", f"{commit}^"]).stdout.decode("ascii").strip()
    tree = (
        run_git(repository.root, ["rev-parse", f"{commit}^{{tree}}"]).stdout.decode("ascii").strip()
    )
    if parent != tug["baseline"]["commit"] or tree != tug["evidence"]["snapshot_tree"]:
        raise NoTugError(
            "GRANT_TREE_DIVERGENCE", "Integration commit structure differs from the Tug Signal"
        )
    return expected_worktree


def _containing_refs(repository: Path, commit: str) -> list[str]:
    result = run_git(
        repository,
        [
            "for-each-ref",
            f"--contains={commit}",
            "--format=%(refname)",
        ],
    )
    return sorted(line for line in result.stdout.decode("utf-8").splitlines() if line)


def revoke_grant(tug_id: str, vault: Vault | None = None) -> dict[str, Any]:
    selected_vault = vault or Vault()
    repository_id, _ = find_grant_for_tug(selected_vault, tug_id)
    with selected_vault.locked(repository_id):
        return _revoke_grant_locked(tug_id, selected_vault)


def _revoke_grant_locked(tug_id: str, vault: Vault) -> dict[str, Any]:
    repository_id, grant = find_grant_for_tug(vault, tug_id)
    if grant["state"] != State.APPLIED.value:
        raise NoTugError("STATE_TRANSITION_INVALID", "Only an applied grant can be revoked")
    session_repository_id, session = find_session(vault, str(grant["session_id"]))
    if session_repository_id != repository_id:
        raise NoTugError("GRANT_SESSION_MISMATCH", "Grant session belongs to another repository")
    ledger = ledger_for(vault, repository_id)
    chain = ledger.verify()
    _verify_session_creation_binding(
        vault,
        repository_id,
        str(grant["session_id"]),
        session,
        chain.events,
        require_worktree=session["archived_at"] is None,
    )
    verify_session_receipt_head(session, chain.events)
    repository = verify_authoritative_baseline(vault, session, require_source_unchanged=False)
    worktree = _verify_revoke_preconditions(
        vault,
        repository_id,
        tug_id,
        grant,
        session,
        chain.events,
        repository,
    )
    branch_ref = f"refs/heads/{grant['branch']}"
    refs = _containing_refs(repository.root, str(grant["commit"]))
    other_refs = [ref for ref in refs if ref != branch_ref]
    revoke_id = new_identifier("revoke")
    if not other_refs:
        if not is_clean(discover_repository(worktree)):
            raise NoTugError("GRANT_WORKTREE_DIRTY", "Integration worktree has uncommitted changes")
        hooks = ensure_trusted_empty_hooks_directory(vault.root / "trusted" / "empty-hooks")
        evidence_ref = f"{EVIDENCE_REF_NAMESPACE}/revoked/{grant['grant_id']}"
        preserved = run_git(
            repository.root,
            [
                "-c",
                f"core.hooksPath={hooks}",
                "update-ref",
                evidence_ref,
                str(grant["commit"]),
                "0" * len(str(grant["commit"])),
            ],
            check=False,
        )
        if preserved.returncode != 0:
            raise NoTugError(
                "REVOKE_EVIDENCE_REF_COLLISION",
                "A collision-safe revocation evidence ref could not be created",
            )
        run_git(
            repository.root,
            ["-c", f"core.hooksPath={hooks}", "worktree", "remove", "--", str(worktree)],
        )
        deleted = run_git(
            repository.root,
            [
                "-c",
                f"core.hooksPath={hooks}",
                "update-ref",
                "-d",
                branch_ref,
                str(grant["commit"]),
            ],
            check=False,
        )
        if deleted.returncode != 0:
            raise NoTugError(
                "GRANT_BRANCH_DRIFT", "Integration branch could not be compare-and-swap deleted"
            )
        disposition: dict[str, Any] = {
            "revoke_id": revoke_id,
            "kind": "unmerged_branch_removed",
            "branch": grant["branch"],
            "commit": grant["commit"],
            "evidence_ref": evidence_ref,
        }
    else:
        local_refs = [ref for ref in other_refs if ref.startswith("refs/heads/")]
        source_ref = str(session["source_ref"]) if session["source_ref"] else None
        target_ref = (
            source_ref if source_ref in local_refs else (local_refs[0] if local_refs else None)
        )
        if target_ref is None:
            raise NoTugError(
                "REVERT_TARGET_REQUIRED",
                "Grant is reachable elsewhere but no safe local revert target exists",
            )
        target_commit = (
            run_git(repository.root, ["rev-parse", target_ref]).stdout.decode("ascii").strip()
        )
        revert_branch = _branch_name(repository.root, "revert", tug_id.split("_", 1)[-1][:10])
        revert_worktree = vault.worktree_path(repository_id, "revert", revoke_id)
        if revert_worktree.exists():
            raise NoTugError("WORKTREE_PATH_COLLISION", "Generated revert worktree path exists")
        revert_worktree.parent.mkdir(parents=True, exist_ok=True)
        hooks = ensure_trusted_empty_hooks_directory(vault.root / "trusted" / "empty-hooks")
        revert_worktree_arguments = inert_filter_config_arguments(repository.root)
        revert_worktree_arguments.extend(
            [
                "-c",
                f"core.hooksPath={hooks}",
                "worktree",
                "add",
                "-b",
                revert_branch,
                str(revert_worktree),
                target_commit,
            ]
        )
        run_git(
            repository.root,
            revert_worktree_arguments,
        )
        revert_arguments = inert_filter_config_arguments(revert_worktree)
        revert_arguments.extend(
            [
                "-c",
                f"core.hooksPath={hooks}",
                "revert",
                "--no-commit",
                str(grant["commit"]),
            ]
        )
        run_git(
            revert_worktree,
            revert_arguments,
        )
        message = (
            f"Revert approved agent change ({tug_id})\n\n"
            f"{COMMIT_TRAILER_PREFIX}-Reverts-Tug: {tug_id}\n"
            f"{COMMIT_TRAILER_PREFIX}-Original-Commit: {grant['commit']}\n"
        ).encode()
        run_git(
            revert_worktree,
            [
                *inert_filter_config_arguments(revert_worktree),
                "-c",
                f"user.name={PRODUCT_NAME}",
                "-c",
                f"user.email={COMMIT_EMAIL}",
                "-c",
                "commit.gpgSign=false",
                "-c",
                f"core.hooksPath={hooks}",
                "commit",
                "--no-verify",
                "-F",
                "-",
            ],
            input_bytes=message,
        )
        revert_commit = (
            run_git(revert_worktree, ["rev-parse", "HEAD"]).stdout.decode("ascii").strip()
        )
        revert_tree = (
            run_git(revert_worktree, ["rev-parse", "HEAD^{tree}"]).stdout.decode("ascii").strip()
        )
        original_parent = (
            run_git(repository.root, ["rev-parse", f"{grant['commit']}^"])
            .stdout.decode("ascii")
            .strip()
        )
        disposition = {
            "revoke_id": revoke_id,
            "kind": "revert_branch_created",
            "branch": revert_branch,
            "commit": revert_commit,
            "target_ref": target_ref,
            "target_commit": target_commit,
            "revert_tree": revert_tree,
            "inverse_patch_sha256": sha256_bytes(
                _binary_diff(repository.root, str(grant["commit"]), original_parent)
            ),
            "applied_inverse_patch_sha256": sha256_bytes(
                _binary_diff(repository.root, target_commit, revert_commit)
            ),
        }
    event = ledger.append_transition(
        repository_id=repository_id,
        event_type="GRANT_REVOKED",
        entity_type="grant",
        entity_id=str(grant["grant_id"]),
        state_from=State.APPLIED.value,
        state_to=State.REVOKED.value,
        payload={
            "tug_id": tug_id,
            "revoke_id": revoke_id,
            "disposition": disposition["kind"],
            "commit": disposition["commit"],
            "branch": disposition["branch"],
            "revoke_metadata_sha256": revoke_metadata_hash(disposition),
        },
    )
    grant["state"] = State.REVOKED.value
    grant["revoke"] = disposition
    session["state"] = State.REVOKED.value
    session["last_event_hash"] = event["event_hash"]
    atomic_write_json(vault.grant_path(repository_id, str(grant["grant_id"])), grant)
    save_session(vault, session)
    return disposition
