"""Offline structural verification of local NoTUG evidence."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

from .brand import BRANCH_NAMESPACE, EVIDENCE_REF_NAMESPACE, PRODUCT_SHORT_NAME
from .config import load_policy
from .errors import NoTugError
from .events import ledger_for
from .git import (
    commit_exists,
    discover_repository,
    inert_filter_config_arguments,
    run_git,
    worktree_list,
)
from .grants import (
    application_metadata_hash,
    grant_metadata_hash,
    revoke_metadata_hash,
    validate_grant,
    validation_results_hash,
)
from .identity import repository_metadata_hash
from .manifests import load_manifest, verify_manifest
from .models import State
from .sessions import (
    _exact_managed_worktree_path,
    _verified_managed_worktree_path,
    load_session,
    session_metadata_hash,
    verify_authoritative_baseline,
    verify_session_receipt_head,
    verify_session_worktree,
)
from .tug import load_tug, verify_tug_artifacts
from .util import canonical_json_bytes, read_json, sha256_bytes
from .vault import Vault


def _issue(error: NoTugError, check: str, artifact: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"check": check, "code": error.code, "message": error.message}
    if artifact is not None:
        result["artifact"] = artifact
    return result


def _one_event(
    events: tuple[dict[str, Any], ...],
    event_type: str,
    entity_id: str,
    *,
    code: str,
    message: str,
) -> dict[str, Any]:
    matching = [
        event
        for event in events
        if event["event_type"] == event_type and event["entity_id"] == entity_id
    ]
    if len(matching) != 1:
        raise NoTugError(code, message)
    return matching[0]


def _event_with_hash(events: tuple[dict[str, Any], ...], event_hash: Any) -> dict[str, Any] | None:
    if not isinstance(event_hash, str):
        return None
    return next((event for event in events if event["event_hash"] == event_hash), None)


def _require_equal(actual: Any, expected: Any, *, code: str, message: str) -> None:
    if actual != expected:
        raise NoTugError(code, message)


SESSION_LAST_EVENT = {
    "SESSION_OPEN": "SESSION_CREATED",
    "ABANDONED": "SESSION_ABANDONED",
    "TUGGED": "TUG_GENERATED",
    "GRANTED": "GRANT_ISSUED",
    "APPLIED": "GRANT_APPLIED",
    "DENIED": "TUG_DENIED",
    "REVOKED": "GRANT_REVOKED",
    "DIVERGED": "SESSION_DIVERGED",
    "FAILED": "GRANT_FAILED",
}


def _ref_commit(repository: Path, ref: str) -> str | None:
    result = run_git(
        repository,
        ["show-ref", "--verify", "--hash", ref],
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.decode("ascii").strip()


def _branch_commit(repository: Path, branch: str) -> str | None:
    return _ref_commit(repository, f"refs/heads/{branch}")


def _verify_application_commit(
    repository: Path,
    grant: dict[str, Any],
    tug: dict[str, Any],
    *,
    require_branch: bool,
) -> None:
    commit = grant["commit"]
    if not isinstance(commit, str) or not commit_exists(repository, commit):
        raise NoTugError("GRANT_COMMIT_MISSING", "Generated integration commit is missing")
    branch = grant["branch"]
    if not isinstance(branch, str) or not branch.startswith(f"{BRANCH_NAMESPACE}/grant/"):
        raise NoTugError("GRANT_SCHEMA_INVALID", "Generated integration branch name is invalid")
    branch_commit = _branch_commit(repository, branch)
    if require_branch and branch_commit != commit:
        raise NoTugError("GRANT_BRANCH_DRIFT", "Generated integration branch does not match")
    if not require_branch and branch_commit is not None:
        raise NoTugError("GRANT_BRANCH_DRIFT", "Revoked integration branch still exists")
    parent = run_git(repository, ["rev-parse", f"{commit}^"]).stdout.decode("ascii").strip()
    tree = run_git(repository, ["rev-parse", f"{commit}^{{tree}}"])
    if (
        parent != tug["baseline"]["commit"]
        or tree.stdout.decode("ascii").strip() != tug["evidence"]["snapshot_tree"]
    ):
        raise NoTugError("GRANT_TREE_DIVERGENCE", "Integration commit structure differs from Tug")


def _verify_exact_worktree_record(
    vault: Vault,
    repository: Any,
    repository_id: str,
    *,
    kind: str,
    entity_id: str,
    stored_path: str,
    branch: str,
    commit: str,
    code: str,
) -> Path:
    expected = _verified_managed_worktree_path(
        vault,
        stored_path,
        repository_id,
        kind,
        entity_id,
        code=code,
    )
    branch_ref = f"refs/heads/{branch}"
    matching = [item for item in worktree_list(repository) if item.path == expected]
    if (
        len(matching) != 1
        or matching[0].detached
        or matching[0].branch != branch_ref
        or matching[0].head != commit
    ):
        raise NoTugError(
            code,
            "Managed worktree registration does not match its exact path, branch, and commit",
        )
    return expected


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


def _refs_with_prefix(repository: Path, prefix: str) -> set[str]:
    result = run_git(
        repository,
        ["for-each-ref", "--format=%(refname)", prefix],
    )
    return {
        ref
        for ref in result.stdout.decode("utf-8", errors="strict").splitlines()
        if ref.startswith(prefix)
    }


def _managed_path_has_redirect(managed_root: Path, path: Path) -> bool:
    try:
        relative = path.absolute().relative_to(managed_root.absolute())
    except ValueError:
        return True
    current = managed_root.absolute()
    for component in (
        current,
        *(current / Path(*relative.parts[:index]) for index in range(1, len(relative.parts) + 1)),
    ):
        try:
            metadata = component.lstat()
        except OSError:
            return True
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if stat.S_ISLNK(metadata.st_mode) or attributes & reparse_flag:
            return True
    return False


def _managed_resource_reconciliation(
    vault: Vault,
    repository_id: str,
    repository: Any,
    events: tuple[dict[str, Any], ...],
    grants: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Reverse-map every NoTUG namespace resource to authoritative evidence."""

    kinds = {
        "session": ("s", "UNCLAIMED_SESSION_WORKTREE"),
        "integration": ("i", "UNCLAIMED_INTEGRATION_WORKTREE"),
        "revert": ("r", "UNCLAIMED_REVERT_WORKTREE"),
    }
    bases = {
        kind: vault.worktrees_dir / repository_id / segment
        for kind, (segment, _code) in kinds.items()
    }
    allowed_paths: dict[str, set[Path]] = {kind: set() for kind in kinds}
    required_paths: dict[str, set[Path]] = {kind: set() for kind in kinds}
    allowed_branches: set[str] = set()
    required_branches: set[str] = set()
    allowed_evidence_refs: set[str] = set()
    required_evidence_refs: set[str] = set()
    failed_residue_paths: set[Path] = set()
    failed_residue_branches: set[str] = set()

    created_sessions = {
        str(event["entity_id"]) for event in events if event["event_type"] == "SESSION_CREATED"
    }
    archived_sessions = {
        str(event["entity_id"]) for event in events if event["event_type"] == "SESSION_ARCHIVED"
    }
    for session_id in created_sessions - archived_sessions:
        path = vault.worktree_path(repository_id, "session", session_id)
        allowed_paths["session"].add(path)
        required_paths["session"].add(path)

    for grant_id, grant in grants.items():
        state = str(grant["state"])
        disposition = grant["revoke"] if isinstance(grant["revoke"], dict) else None
        unmerged_removed = (
            state == State.REVOKED.value
            and disposition is not None
            and disposition.get("kind") == "unmerged_branch_removed"
        )
        integration = vault.worktree_path(repository_id, "integration", grant_id)
        branch_ref = f"refs/heads/{grant['branch']}"
        if state == State.FAILED.value:
            failed_residue_paths.add(integration)
            failed_residue_branches.add(branch_ref)
        elif not unmerged_removed:
            allowed_paths["integration"].add(integration)
            allowed_branches.add(branch_ref)
            if state in {State.APPLIED.value, State.REVOKED.value}:
                required_paths["integration"].add(integration)
                required_branches.add(branch_ref)
        if disposition is not None and disposition.get("kind") == "revert_branch_created":
            revoke_id = disposition.get("revoke_id")
            revert_branch = disposition.get("branch")
            if isinstance(revoke_id, str) and isinstance(revert_branch, str):
                revert = vault.worktree_path(repository_id, "revert", revoke_id)
                branch_ref = f"refs/heads/{revert_branch}"
                allowed_paths["revert"].add(revert)
                required_paths["revert"].add(revert)
                allowed_branches.add(branch_ref)
                required_branches.add(branch_ref)
        if unmerged_removed:
            evidence_ref = f"{EVIDENCE_REF_NAMESPACE}/revoked/{grant_id}"
            allowed_evidence_refs.add(evidence_ref)
            required_evidence_refs.add(evidence_ref)

    actual_paths: dict[str, set[Path]] = {kind: set() for kind in kinds}
    for kind, base in bases.items():
        if base.is_dir():
            actual_paths[kind] = {child.absolute() for child in base.iterdir()}

    issues: list[dict[str, Any]] = []
    extra_lexical_paths: set[Path] = set()
    for kind, (_segment, code) in kinds.items():
        for path in sorted(actual_paths[kind], key=lambda item: str(item).casefold()):
            if _managed_path_has_redirect(vault.worktrees_dir, path):
                issues.append(
                    _issue(
                        NoTugError(
                            "MANAGED_WORKTREE_PATH_REDIRECT",
                            "Managed worktree path contains a link or reparse redirect",
                        ),
                        "managed_resources",
                        f"{kind}/{path.name}",
                    )
                )
        failed_extras = actual_paths[kind] & failed_residue_paths
        for path in sorted(failed_extras, key=lambda item: str(item).casefold()):
            extra_lexical_paths.add(path)
            issues.append(
                _issue(
                    NoTugError(
                        "FAILED_GRANT_RESOURCE_RESIDUE",
                        "Failed grant left a generated worktree resource",
                    ),
                    "managed_resources",
                    f"{kind}/{path.name}",
                )
            )
        extras = actual_paths[kind] - allowed_paths[kind] - failed_residue_paths
        for path in sorted(extras, key=lambda item: str(item).casefold()):
            extra_lexical_paths.add(path)
            issues.append(
                _issue(
                    NoTugError(code, f"Unclaimed {kind} worktree resource exists"),
                    "managed_resources",
                    f"{kind}/{path.name}",
                )
            )
        for path in sorted(required_paths[kind], key=lambda item: str(item).casefold()):
            if not path.is_dir():
                issues.append(
                    _issue(
                        NoTugError(
                            "MANAGED_WORKTREE_MISSING",
                            f"Required {kind} worktree directory is missing",
                        ),
                        "managed_resources",
                        f"{kind}/{path.name}",
                    )
                )
            elif _managed_path_has_redirect(vault.worktrees_dir, path):
                issues.append(
                    _issue(
                        NoTugError(
                            "MANAGED_WORKTREE_PATH_REDIRECT",
                            f"Required {kind} worktree path is redirected",
                        ),
                        "managed_resources",
                        f"{kind}/{path.name}",
                    )
                )

    registered_by_kind: dict[str, set[Path]] = {kind: set() for kind in kinds}
    for item in worktree_list(repository):
        registered = item.path
        for kind, base in bases.items():
            try:
                registered.relative_to(base.absolute())
            except ValueError:
                continue
            registered_by_kind[kind].add(registered)
            break
    for kind in kinds:
        allowed_registered = {path.absolute() for path in allowed_paths[kind]}
        required_registered = {path.absolute() for path in required_paths[kind]}
        failed_registered = {path.absolute() for path in failed_residue_paths}
        for path in sorted(
            registered_by_kind[kind] & failed_registered,
            key=lambda item: str(item).casefold(),
        ):
            if path not in extra_lexical_paths:
                issues.append(
                    _issue(
                        NoTugError(
                            "FAILED_GRANT_RESOURCE_RESIDUE",
                            "Failed grant left a generated worktree registration",
                        ),
                        "managed_resources",
                        f"{kind}/{path.name}",
                    )
                )
        for path in sorted(
            registered_by_kind[kind] - allowed_registered - failed_registered,
            key=lambda item: str(item).casefold(),
        ):
            if path not in extra_lexical_paths:
                issues.append(
                    _issue(
                        NoTugError(
                            "UNCLAIMED_MANAGED_WORKTREE_REGISTRATION",
                            f"Git registers an unclaimed {PRODUCT_SHORT_NAME}-managed worktree",
                        ),
                        "managed_resources",
                        f"{kind}/{path.name}",
                    )
                )
        for path in sorted(
            required_registered - registered_by_kind[kind],
            key=lambda item: str(item).casefold(),
        ):
            issues.append(
                _issue(
                    NoTugError(
                        "MANAGED_WORKTREE_UNREGISTERED",
                        f"Required {kind} worktree is not registered by Git",
                    ),
                    "managed_resources",
                    f"{kind}/{path.name}",
                )
            )

    actual_branches = _refs_with_prefix(repository.root, f"refs/heads/{BRANCH_NAMESPACE}/grant/")
    actual_branches.update(
        _refs_with_prefix(repository.root, f"refs/heads/{BRANCH_NAMESPACE}/revert/")
    )
    for ref in sorted(actual_branches & failed_residue_branches):
        issues.append(
            _issue(
                NoTugError(
                    "FAILED_GRANT_RESOURCE_RESIDUE",
                    "Failed grant left a generated branch resource",
                ),
                "managed_resources",
                ref,
            )
        )
    for ref in sorted(actual_branches - allowed_branches - failed_residue_branches):
        issues.append(
            _issue(
                NoTugError(
                    "UNCLAIMED_NOTUG_BRANCH",
                    f"{PRODUCT_SHORT_NAME} branch has no authoritative "
                    "artifact and receipt binding",
                ),
                "managed_resources",
                ref,
            )
        )
    for ref in sorted(required_branches - actual_branches):
        issues.append(
            _issue(
                NoTugError(
                    "NOTUG_BRANCH_MISSING",
                    f"Required {PRODUCT_SHORT_NAME} branch is missing",
                ),
                "managed_resources",
                ref,
            )
        )

    actual_evidence_refs = _refs_with_prefix(repository.root, f"{EVIDENCE_REF_NAMESPACE}/revoked/")
    for ref in sorted(actual_evidence_refs - allowed_evidence_refs):
        issues.append(
            _issue(
                NoTugError(
                    "UNCLAIMED_REVOCATION_EVIDENCE_REF",
                    "Revocation evidence ref has no completed revocation receipt",
                ),
                "managed_resources",
                ref,
            )
        )
    for ref in sorted(required_evidence_refs - actual_evidence_refs):
        issues.append(
            _issue(
                NoTugError(
                    "REVOCATION_EVIDENCE_REF_MISSING",
                    "Required revocation evidence ref is missing",
                ),
                "managed_resources",
                ref,
            )
        )

    claimed_tug_ids = {
        str(event["entity_id"]) for event in events if event["event_type"] == "TUG_GENERATED"
    }
    repository_dir = vault.repository_dir(repository_id)
    tug_artifact_sets = {
        "UNCLAIMED_TUG_ARTIFACT": {
            path.stem for path in (repository_dir / "tugs").glob("tug_*.json")
        },
        "UNCLAIMED_TUG_PATCH": {
            path.name.removesuffix(".patch")
            for path in (repository_dir / "patches").glob("tug_*.patch")
        },
        "UNCLAIMED_TUG_CHANGES": {
            path.name.removesuffix(".json")
            for path in (repository_dir / "changes").glob("tug_*.json")
            if not path.name.endswith(".workspace.json")
        },
        "UNCLAIMED_TUG_WORKSPACE_MANIFEST": {
            path.name.removesuffix(".workspace.json")
            for path in (repository_dir / "changes").glob("tug_*.workspace.json")
        },
        "UNCLAIMED_TUG_WORK_DIRECTORY": {
            path.name for path in (repository_dir / "tugs" / ".work").glob("tug_*")
        },
    }
    for code, artifact_ids in tug_artifact_sets.items():
        for _artifact_id in sorted(artifact_ids - claimed_tug_ids):
            issues.append(
                _issue(
                    NoTugError(
                        code,
                        "Unclaimed Tug evidence exists without a generation receipt",
                    ),
                    "managed_resources",
                    "tug-artifact/redacted",
                )
            )

    issued_grant_ids = {
        str(event["entity_id"]) for event in events if event["event_type"] == "GRANT_ISSUED"
    }
    grant_operation_dirs = {
        path.name for path in (repository_dir / "operations").glob("grant_*") if path.is_dir()
    }
    for _grant_id in sorted(grant_operation_dirs - issued_grant_ids):
        issues.append(
            _issue(
                NoTugError(
                    "UNCLAIMED_GRANT_OPERATION_DIRECTORY",
                    "Pre-confirmation grant evidence has no issuance receipt",
                ),
                "managed_resources",
                "grant-operation/redacted",
            )
        )

    return issues, {
        "ok": not issues,
        "directory_count": sum(len(paths) for paths in actual_paths.values()),
        "registered_worktree_count": sum(len(paths) for paths in registered_by_kind.values()),
        "branch_count": len(actual_branches),
        "evidence_ref_count": len(actual_evidence_refs),
        "tug_artifact_count": sum(len(values) for values in tug_artifact_sets.values()),
        "grant_operation_directory_count": len(grant_operation_dirs),
    }


def verify_repository(path: Path, vault: Vault | None = None) -> dict[str, Any]:
    """Verify all registered artifacts without mutating the protected repository."""

    vault = vault or Vault()
    repository = discover_repository(path)
    identity = vault.find_repository(repository)
    if identity is None:
        raise NoTugError(
            "REPOSITORY_NOT_INITIALIZED",
            f"Repository is not registered with {PRODUCT_SHORT_NAME}",
        )
    repository_id = identity.repository_id
    issues: list[dict[str, Any]] = []
    checks: dict[str, Any] = {}
    ledger_events: tuple[dict[str, Any], ...] = ()

    try:
        chain = ledger_for(vault, repository_id).verify()
        ledger_events = chain.events
        checks["receipt_chain"] = {
            "ok": True,
            "event_count": chain.count,
            "head_hash": chain.head_hash,
        }
    except NoTugError as exc:
        issues.append(_issue(exc, "receipt_chain"))
        checks["receipt_chain"] = {"ok": False}

    initialization_events = [
        event for event in ledger_events if event["event_type"] == "REPOSITORY_INITIALIZED"
    ]
    initialization_ok = False
    if len(initialization_events) == 1:
        initialization = initialization_events[0]
        initialization_ok = (
            initialization["sequence"] == 1
            and initialization["previous_event_hash"] is None
            and initialization["repository_id"] == repository_id
            and initialization["entity_type"] == "repository"
            and initialization["entity_id"] == repository_id
            and initialization["state_from"] is None
            and initialization["state_to"] == "LOCKED"
            and set(initialization["payload"])
            == {
                "baseline_commit",
                "baseline_manifest_hash",
                "policy_hash",
                "repository_key",
                "repository_metadata_sha256",
            }
            and initialization["payload"]["repository_key"] == identity.repository_key
            and initialization["payload"]["repository_metadata_sha256"]
            == repository_metadata_hash(identity)
        )
    if not initialization_ok:
        issues.append(
            _issue(
                NoTugError(
                    "REPOSITORY_INITIALIZATION_INVALID",
                    "Receipt chain does not begin with one valid repository initialization",
                ),
                "initialization_receipt",
            )
        )
    checks["initialization_receipt"] = {"ok": initialization_ok}

    try:
        if (
            identity.root.resolve() != repository.root.resolve()
            or identity.common_git_dir.resolve() != repository.common_git_dir.resolve()
        ):
            raise NoTugError(
                "REPOSITORY_IDENTITY_MISMATCH", "Registered repository identity changed"
            )
        checks["repository_identity"] = {"ok": True, "repository_id": repository_id}
    except NoTugError as exc:
        issues.append(_issue(exc, "repository_identity"))
        checks["repository_identity"] = {"ok": False}

    try:
        policy = load_policy(vault.policy_path(repository_id))
        checks["active_policy"] = {"ok": True, "policy_hash": policy.sha256}
    except NoTugError as exc:
        issues.append(_issue(exc, "active_policy"))
        checks["active_policy"] = {"ok": False}

    manifest_count = 0
    manifest_paths = sorted(vault.repository_dir(repository_id).glob("manifests/*.json"))
    for manifest_path in manifest_paths:
        manifest_count += 1
        try:
            manifest = load_manifest(
                manifest_path,
                expected_hash=manifest_path.stem,
                expected_repository_id=repository_id,
            )
            if not commit_exists(repository, manifest.commit):
                raise NoTugError("BASELINE_MISSING", "Manifest baseline commit is missing")
            verify_manifest(repository, manifest)
        except NoTugError as exc:
            issues.append(_issue(exc, "manifest", manifest_path.stem))
    expected_manifest_hashes = {
        str(event["payload"]["baseline_manifest_hash"])
        for event in ledger_events
        if event["event_type"] in {"REPOSITORY_INITIALIZED", "SESSION_CREATED"}
        and "baseline_manifest_hash" in event["payload"]
    }
    present_manifest_hashes = {path.stem for path in manifest_paths}
    for missing_hash in sorted(expected_manifest_hashes - present_manifest_hashes):
        issues.append(
            _issue(
                NoTugError("MANIFEST_ARTIFACT_MISSING", "Required baseline manifest is missing"),
                "manifest",
                missing_hash,
            )
        )
    checks["manifests"] = {
        "ok": not any(item["check"] == "manifest" for item in issues),
        "count": manifest_count,
    }

    expected_policy_hashes = {
        str(event["payload"]["policy_hash"])
        for event in ledger_events
        if event["event_type"] == "SESSION_CREATED" and "policy_hash" in event["payload"]
    }
    policy_snapshot_paths = sorted(vault.repository_dir(repository_id).glob("policies/*.toml"))
    present_policy_hashes = {path.stem for path in policy_snapshot_paths}
    for missing_hash in sorted(expected_policy_hashes - present_policy_hashes):
        issues.append(
            _issue(
                NoTugError(
                    "POLICY_SNAPSHOT_MISSING", "Required session policy snapshot is missing"
                ),
                "policy_snapshot",
                missing_hash,
            )
        )
    checks["policy_snapshots"] = {
        "ok": not any(item["check"] == "policy_snapshot" for item in issues),
        "count": len(policy_snapshot_paths),
    }

    sessions: dict[str, dict[str, Any]] = {}
    session_count = 0
    session_paths = sorted(vault.repository_dir(repository_id).glob("sessions/*.json"))
    for session_path in session_paths:
        session_count += 1
        try:
            session = load_session(vault, repository_id, session_path.stem)
            sessions[session_path.stem] = session
            if (
                session["session_id"] != session_path.stem
                or session["repository_id"] != repository_id
            ):
                raise NoTugError(
                    "SESSION_ID_MISMATCH",
                    "Session identifiers disagree with the vault location",
                )
            created = _one_event(
                ledger_events,
                "SESSION_CREATED",
                session_path.stem,
                code="SESSION_RECEIPT_MISSING",
                message="Session has no unique creation receipt",
            )
            creation_payload = created["payload"]
            for key in ("baseline_commit", "baseline_manifest_hash", "policy_hash"):
                _require_equal(
                    creation_payload.get(key),
                    session[key],
                    code="SESSION_PROVENANCE_DIVERGENCE",
                    message="Session metadata disagrees with its creation receipt",
                )
            _require_equal(
                creation_payload.get("session_metadata_sha256"),
                session_metadata_hash(session),
                code="SESSION_METADATA_HASH_MISMATCH",
                message="Immutable session metadata was altered",
            )
            authoritative = verify_session_receipt_head(session, ledger_events)
            state = str(session["state"])
            tug_id = session["tug_id"]
            grant_id = session["grant_id"]
            if state in {"SESSION_OPEN", "ABANDONED"} and (
                tug_id is not None or grant_id is not None
            ):
                raise NoTugError(
                    "SESSION_STATE_DIVERGENCE",
                    "Open or abandoned session has disposition identifiers",
                )
            if state in {"TUGGED", "DENIED"} and (
                not isinstance(tug_id, str) or not tug_id.startswith("tug_") or grant_id is not None
            ):
                raise NoTugError(
                    "SESSION_STATE_DIVERGENCE", "Tug disposition identifiers are inconsistent"
                )
            if state == "DIVERGED" and (tug_id is not None or grant_id is not None):
                raise NoTugError(
                    "SESSION_STATE_DIVERGENCE", "Diverged session identifiers are inconsistent"
                )
            if state in {"GRANTED", "APPLIED", "FAILED", "REVOKED"} and (
                not isinstance(tug_id, str)
                or not tug_id.startswith("tug_")
                or not isinstance(grant_id, str)
                or not grant_id.startswith("grant_")
            ):
                raise NoTugError(
                    "SESSION_STATE_DIVERGENCE", "Grant disposition identifiers are inconsistent"
                )
            snapshot = vault.policy_snapshot_path(repository_id, str(session["policy_hash"]))
            load_policy(snapshot, str(session["policy_hash"]))
            manifest = load_manifest(
                vault.manifest_path(repository_id, str(session["baseline_manifest_hash"])),
                expected_hash=str(session["baseline_manifest_hash"]),
                expected_repository_id=repository_id,
            )
            if manifest.commit != session["baseline_commit"]:
                raise NoTugError(
                    "SESSION_PROVENANCE_DIVERGENCE", "Session and manifest baseline disagree"
                )
            archived = session["archived_at"] is not None
            expected_event_type = SESSION_LAST_EVENT.get(str(session["state"]))
            if expected_event_type is None:
                raise NoTugError(
                    "SESSION_STATE_DIVERGENCE", "Session state has no valid receipt transition"
                )
            expected_entity = session_path.stem
            if expected_event_type in {"TUG_GENERATED", "TUG_DENIED"}:
                expected_entity = str(session["tug_id"])
            elif expected_event_type in {
                "GRANT_ISSUED",
                "GRANT_APPLIED",
                "GRANT_REVOKED",
                "GRANT_FAILED",
            }:
                expected_entity = str(session["grant_id"])
            disposition_event = _one_event(
                ledger_events,
                expected_event_type,
                expected_entity,
                code="SESSION_RECEIPT_DIVERGENCE",
                message="Session has no unique state disposition receipt",
            )
            if disposition_event["state_to"] != session["state"]:
                raise NoTugError(
                    "SESSION_STATE_DIVERGENCE",
                    "Session state disagrees with its disposition receipt",
                )
            archive_events = [
                event
                for event in ledger_events
                if event["event_type"] == "SESSION_ARCHIVED"
                and event["entity_id"] == session_path.stem
            ]
            if archived:
                if len(archive_events) != 1:
                    raise NoTugError(
                        "SESSION_RECEIPT_DIVERGENCE",
                        "Archived session has no unique archive receipt",
                    )
                archive_event = archive_events[0]
                archive_state = archive_event["payload"].get("disposition_state")
                if (
                    archive_event["repository_id"] != repository_id
                    or archive_event["entity_type"] != "session"
                    or archive_event["state_from"] is not None
                    or archive_event["state_to"] is not None
                    or set(archive_event["payload"]) != {"archived_at", "disposition_state"}
                    or archive_event["payload"].get("archived_at") != session["archived_at"]
                ):
                    raise NoTugError(
                        "SESSION_RECEIPT_DIVERGENCE",
                        "Archived session metadata disagrees with its receipt",
                    )
                archive_disposition_type = SESSION_LAST_EVENT.get(str(archive_state))
                archive_entity = session_path.stem
                if archive_disposition_type in {"TUG_GENERATED", "TUG_DENIED"}:
                    archive_entity = str(session["tug_id"])
                elif archive_disposition_type in {
                    "GRANT_ISSUED",
                    "GRANT_APPLIED",
                    "GRANT_REVOKED",
                    "GRANT_FAILED",
                }:
                    archive_entity = str(session["grant_id"])
                if archive_disposition_type is None:
                    raise NoTugError(
                        "SESSION_RECEIPT_DIVERGENCE",
                        "Archive receipt names an invalid disposition state",
                    )
                archive_disposition = _one_event(
                    ledger_events,
                    archive_disposition_type,
                    archive_entity,
                    code="SESSION_RECEIPT_DIVERGENCE",
                    message="Archive receipt has no unique prior disposition",
                )
                if archive_event["sequence"] <= archive_disposition["sequence"]:
                    raise NoTugError(
                        "SESSION_RECEIPT_DIVERGENCE",
                        "Archive receipt precedes its recorded disposition",
                    )
                if archive_state == session["state"]:
                    if authoritative["event_hash"] != archive_event["event_hash"]:
                        raise NoTugError(
                            "SESSION_RECEIPT_DIVERGENCE",
                            "Archived session has an unexpected later transition",
                        )
                elif (
                    archive_state == State.APPLIED.value
                    and session["state"] == State.REVOKED.value
                    and disposition_event["sequence"] > archive_event["sequence"]
                ):
                    if authoritative["event_hash"] != disposition_event["event_hash"]:
                        raise NoTugError(
                            "SESSION_RECEIPT_DIVERGENCE",
                            "Post-archive revocation is not the authoritative session receipt",
                        )
                else:
                    raise NoTugError(
                        "SESSION_RECEIPT_DIVERGENCE",
                        "Archive disposition contradicts the current session state",
                    )
            elif archive_events or authoritative["event_hash"] != disposition_event["event_hash"]:
                raise NoTugError(
                    "SESSION_RECEIPT_DIVERGENCE",
                    "Unarchived session has contradictory archive or disposition receipts",
                )
            if session["archived_at"] is None:
                verify_session_worktree(vault, session)
                if state in {State.SESSION_OPEN.value, State.TUGGED.value, State.GRANTED.value}:
                    verify_authoritative_baseline(vault, session)
            if state == "GRANTED":
                raise NoTugError(
                    "SESSION_TRANSITION_INCOMPLETE",
                    "Session remains in the incomplete GRANTED transition state",
                )
            if state == State.DIVERGED.value:
                raise NoTugError(
                    "SESSION_DIVERGED_STATE",
                    "Session has an authoritative divergence disposition",
                )
            if state == State.FAILED.value:
                raise NoTugError(
                    "SESSION_FAILED_STATE",
                    "Session has an authoritative failed disposition",
                )
        except NoTugError as exc:
            issues.append(_issue(exc, "session", session_path.stem))
    expected_session_ids = {
        str(event["entity_id"])
        for event in ledger_events
        if event["event_type"] == "SESSION_CREATED"
    }
    present_session_ids = {path.stem for path in session_paths}
    for missing_id in sorted(expected_session_ids - present_session_ids):
        issues.append(
            _issue(
                NoTugError("SESSION_ARTIFACT_MISSING", "Session metadata artifact is missing"),
                "session",
                missing_id,
            )
        )
    checks["sessions"] = {
        "ok": not any(item["check"] == "session" for item in issues),
        "count": session_count,
    }

    operation_count = 0
    operation_fields = {
        "schema_version",
        "operation_id",
        "kind",
        "session_id",
        "state",
        "started_at",
        "ended_at",
        "exit_status",
        "command",
    }
    operation_paths = sorted(vault.repository_dir(repository_id).glob("operations/*.json"))
    for operation_path in operation_paths:
        operation_count += 1
        try:
            operation = read_json(operation_path)
            operation_schema = operation.get("schema_version")
            if (
                set(operation) != operation_fields
                or not isinstance(operation_schema, int)
                or isinstance(operation_schema, bool)
                or operation_schema != 1
            ):
                raise NoTugError("OPERATION_SCHEMA_INVALID", "Run operation schema is invalid")
            if (
                operation["operation_id"] != operation_path.stem
                or operation.get("kind") != "agent-command"
                or operation.get("state") not in {"RUNNING", "SUCCEEDED", "FAILED", "CANCELLED"}
            ):
                raise NoTugError("OPERATION_ID_MISMATCH", "Run operation identifier disagrees")
            if operation["session_id"] not in sessions:
                raise NoTugError("OPERATION_SESSION_MISSING", "Run operation session is missing")
            command = operation["command"]
            if not isinstance(command, dict) or set(command) != {
                "executable",
                "arguments",
                "argument_count",
            }:
                raise NoTugError("OPERATION_SCHEMA_INVALID", "Run command record is invalid")
            if (
                not isinstance(command["executable"], str)
                or not isinstance(command["arguments"], list)
                or not all(isinstance(argument, str) for argument in command["arguments"])
                or command["argument_count"] != len(command["arguments"])
            ):
                raise NoTugError("OPERATION_SCHEMA_INVALID", "Run command record is invalid")
            started = _one_event(
                ledger_events,
                "RUN_STARTED",
                str(operation["operation_id"]),
                code="OPERATION_RECEIPT_MISSING",
                message="Run start receipt is missing",
            )
            expected_command_hash = sha256_bytes(canonical_json_bytes(command))
            expected_started_payload = {
                "session_id": operation["session_id"],
                "executable": command["executable"],
                "argument_count": command["argument_count"],
                "command_sha256": expected_command_hash,
                "started_at": operation["started_at"],
            }
            if started["payload"] != expected_started_payload:
                raise NoTugError(
                    "OPERATION_RECEIPT_DIVERGENCE",
                    "Run operation metadata disagrees with its start receipt",
                )
            completed = [
                event
                for event in ledger_events
                if event["event_type"] in {"RUN_SUCCEEDED", "RUN_FAILED", "RUN_CANCELLED"}
                and event["entity_id"] == operation["operation_id"]
            ]
            if operation["state"] == "RUNNING":
                if (
                    completed
                    or operation["ended_at"] is not None
                    or operation["exit_status"] is not None
                ):
                    raise NoTugError(
                        "OPERATION_RECEIPT_DIVERGENCE",
                        "Running operation has contradictory completion evidence",
                    )
                raise NoTugError(
                    "OPERATION_TRANSITION_INCOMPLETE",
                    "Run operation has no authoritative completion receipt",
                )
            else:
                if len(completed) != 1:
                    raise NoTugError(
                        "OPERATION_RECEIPT_MISSING", "Run completion receipt is missing"
                    )
                completion = completed[0]
                expected_type = {
                    "SUCCEEDED": "RUN_SUCCEEDED",
                    "FAILED": "RUN_FAILED",
                    "CANCELLED": "RUN_CANCELLED",
                }[str(operation["state"])]
                if (
                    completion["event_type"] != expected_type
                    or completion["sequence"] <= started["sequence"]
                    or completion["payload"]
                    != {
                        "session_id": operation["session_id"],
                        "exit_status": operation["exit_status"],
                        "ended_at": operation["ended_at"],
                    }
                    or (operation["state"] == "SUCCEEDED" and operation["exit_status"] != 0)
                    or (operation["state"] == "FAILED" and operation["exit_status"] == 0)
                    or (operation["state"] == "CANCELLED" and operation["exit_status"] is None)
                ):
                    raise NoTugError(
                        "OPERATION_RECEIPT_DIVERGENCE",
                        "Run operation completion metadata disagrees with its receipt",
                    )
        except NoTugError as exc:
            issues.append(_issue(exc, "operation", operation_path.stem))
    expected_operation_ids = {
        str(event["entity_id"]) for event in ledger_events if event["event_type"] == "RUN_STARTED"
    }
    present_operation_ids = {path.stem for path in operation_paths}
    for missing_id in sorted(expected_operation_ids - present_operation_ids):
        issues.append(
            _issue(
                NoTugError("OPERATION_ARTIFACT_MISSING", "Run operation artifact is missing"),
                "operation",
                missing_id,
            )
        )
    checks["operations"] = {
        "ok": not any(item["check"] == "operation" for item in issues),
        "count": operation_count,
    }

    tugs: dict[str, dict[str, Any]] = {}
    tug_count = 0
    tug_paths = sorted(vault.repository_dir(repository_id).glob("tugs/*.json"))
    for tug_path in tug_paths:
        tug_count += 1
        try:
            tug = load_tug(vault, repository_id, tug_path.stem)
            tugs[tug_path.stem] = tug
            bound_session = sessions.get(str(tug["session_id"]))
            if bound_session is None:
                raise NoTugError("TUG_SESSION_MISSING", "Tug Signal session metadata is missing")
            if bound_session["tug_id"] != tug["tug_id"]:
                raise NoTugError("TUG_SESSION_MISMATCH", "Tug and session metadata disagree")
            verify_tug_artifacts(vault, repository_id, tug)
            matching = [
                event
                for event in ledger_events
                if event["event_type"] == "TUG_GENERATED"
                and event["entity_id"] == tug["tug_id"]
                and event["payload"].get("tug_hash") == tug["tug_hash"]
            ]
            if len(matching) != 1:
                raise NoTugError("TUG_RECEIPT_MISSING", "Tug Signal has no unique receipt binding")
        except NoTugError as exc:
            issues.append(_issue(exc, "tug", tug_path.stem))
    expected_tug_ids = {
        str(event["entity_id"]) for event in ledger_events if event["event_type"] == "TUG_GENERATED"
    }
    present_tug_ids = {path.stem for path in tug_paths}
    for missing_id in sorted(expected_tug_ids - present_tug_ids):
        issues.append(
            _issue(
                NoTugError("TUG_ARTIFACT_MISSING", "Tug Signal artifact is missing"),
                "tug",
                missing_id,
            )
        )
    checks["tugs"] = {"ok": not any(item["check"] == "tug" for item in issues), "count": tug_count}

    verified_grants: dict[str, dict[str, Any]] = {}
    grant_count = 0
    grant_paths = sorted(vault.repository_dir(repository_id).glob("grants/*.json"))
    for grant_path in grant_paths:
        grant_count += 1
        try:
            grant = validate_grant(read_json(grant_path))
            bound_tug = tugs.get(str(grant["tug_id"]))
            if bound_tug is None:
                raise NoTugError("GRANT_TUG_MISSING", "Grant's exact Tug Signal is missing")
            if (
                grant["tug_hash"] != bound_tug["tug_hash"]
                or grant["patch_sha256"] != bound_tug["evidence"]["patch_sha256"]
            ):
                raise NoTugError("GRANT_BINDING_MISMATCH", "Grant and Tug Signal evidence disagree")
            if grant["grant_id"] != grant_path.stem or grant["repository_id"] != repository_id:
                raise NoTugError(
                    "GRANT_ID_MISMATCH", "Grant identifiers disagree with the vault location"
                )
            bound_session = sessions.get(str(grant["session_id"]))
            if bound_session is None or bound_session["grant_id"] != grant["grant_id"]:
                raise NoTugError("GRANT_SESSION_MISMATCH", "Grant and session metadata disagree")
            expected_worktree = _exact_managed_worktree_path(
                vault,
                str(grant["worktree"]),
                repository_id,
                "integration",
                str(grant["grant_id"]),
                code="GRANT_WORKTREE_DIVERGENCE",
            )
            issued = _one_event(
                ledger_events,
                "GRANT_ISSUED",
                str(grant["grant_id"]),
                code="GRANT_RECEIPT_MISSING",
                message="Grant issuance receipt is missing",
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
                or issued["state_from"] != "TUGGED"
                or issued["state_to"] != "GRANTED"
            ):
                raise NoTugError(
                    "GRANT_RECEIPT_DIVERGENCE",
                    "Grant metadata disagrees with its issuance receipt",
                )
            applied_events = [
                event
                for event in ledger_events
                if event["event_type"] == "GRANT_APPLIED"
                and event["entity_id"] == grant["grant_id"]
            ]
            failed_events = [
                event
                for event in ledger_events
                if event["event_type"] == "GRANT_FAILED" and event["entity_id"] == grant["grant_id"]
            ]
            revoked_events = [
                event
                for event in ledger_events
                if event["event_type"] == "GRANT_REVOKED"
                and event["entity_id"] == grant["grant_id"]
            ]
            state = str(grant["state"])
            if state == "GRANTED":
                if (
                    applied_events
                    or failed_events
                    or revoked_events
                    or bound_session["state"] != state
                ):
                    raise NoTugError(
                        "GRANT_STATE_DIVERGENCE", "Pending grant has contradictory receipts"
                    )
                raise NoTugError(
                    "GRANT_TRANSITION_INCOMPLETE",
                    "Grant remains in the incomplete GRANTED transition state",
                )
            elif state == "FAILED":
                if (
                    len(failed_events) != 1
                    or applied_events
                    or revoked_events
                    or bound_session["state"] != state
                ):
                    raise NoTugError(
                        "GRANT_STATE_DIVERGENCE", "Failed grant has contradictory receipts"
                    )
                failure = failed_events[0]
                if (
                    failure["state_from"] != "GRANTED"
                    or failure["state_to"] != "FAILED"
                    or failure["payload"].get("tug_id") != grant["tug_id"]
                    or failure["payload"].get("failure_metadata_sha256")
                    != application_metadata_hash(grant)
                ):
                    raise NoTugError(
                        "GRANT_RECEIPT_DIVERGENCE",
                        "Failed grant metadata disagrees with its receipt",
                    )
            elif state in {"APPLIED", "REVOKED"}:
                if len(applied_events) != 1 or failed_events or bound_session["state"] != state:
                    raise NoTugError(
                        "GRANT_STATE_DIVERGENCE", "Applied grant has contradictory receipts"
                    )
                applied = applied_events[0]
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
                    or applied["state_from"] != "GRANTED"
                    or applied["state_to"] != "APPLIED"
                ):
                    raise NoTugError(
                        "GRANT_RECEIPT_DIVERGENCE",
                        "Applied grant metadata disagrees with its receipt",
                    )
                if state == "APPLIED":
                    if revoked_events or not expected_worktree.is_dir():
                        raise NoTugError(
                            "GRANT_STATE_DIVERGENCE",
                            "Applied grant worktree or receipts are inconsistent",
                        )
                    _verify_application_commit(
                        repository.root, grant, bound_tug, require_branch=True
                    )
                    _verify_exact_worktree_record(
                        vault,
                        repository,
                        repository_id,
                        kind="integration",
                        entity_id=str(grant["grant_id"]),
                        stored_path=str(grant["worktree"]),
                        branch=str(grant["branch"]),
                        commit=str(grant["commit"]),
                        code="GRANT_WORKTREE_DIVERGENCE",
                    )
                else:
                    if len(revoked_events) != 1 or not isinstance(grant["revoke"], dict):
                        raise NoTugError(
                            "GRANT_STATE_DIVERGENCE", "Revoked grant has no exact receipt"
                        )
                    disposition = grant["revoke"]
                    revoked = revoked_events[0]
                    expected_revoke_payload = {
                        "tug_id": grant["tug_id"],
                        "revoke_id": disposition.get("revoke_id"),
                        "disposition": disposition.get("kind"),
                        "commit": disposition.get("commit"),
                        "branch": disposition.get("branch"),
                        "revoke_metadata_sha256": revoke_metadata_hash(disposition),
                    }
                    if (
                        revoked["payload"] != expected_revoke_payload
                        or revoked["state_from"] != "APPLIED"
                        or revoked["state_to"] != "REVOKED"
                    ):
                        raise NoTugError(
                            "GRANT_RECEIPT_DIVERGENCE",
                            "Revocation metadata disagrees with its receipt",
                        )
                    if disposition.get("kind") == "unmerged_branch_removed":
                        evidence_ref = disposition.get("evidence_ref")
                        if (
                            disposition.get("branch") != grant["branch"]
                            or disposition.get("commit") != grant["commit"]
                            or expected_worktree.exists()
                            or not isinstance(evidence_ref, str)
                            or evidence_ref
                            != f"{EVIDENCE_REF_NAMESPACE}/revoked/{grant['grant_id']}"
                            or _ref_commit(repository.root, evidence_ref) != grant["commit"]
                        ):
                            raise NoTugError(
                                "GRANT_REVOKE_DIVERGENCE",
                                "Removed integration branch disposition is inconsistent",
                            )
                        _verify_application_commit(
                            repository.root, grant, bound_tug, require_branch=False
                        )
                    elif disposition.get("kind") == "revert_branch_created":
                        _verify_application_commit(
                            repository.root, grant, bound_tug, require_branch=True
                        )
                        _verify_exact_worktree_record(
                            vault,
                            repository,
                            repository_id,
                            kind="integration",
                            entity_id=str(grant["grant_id"]),
                            stored_path=str(grant["worktree"]),
                            branch=str(grant["branch"]),
                            commit=str(grant["commit"]),
                            code="GRANT_WORKTREE_DIVERGENCE",
                        )
                        revert_id = disposition.get("revoke_id")
                        revert_branch = disposition.get("branch")
                        revert_commit = disposition.get("commit")
                        target_ref = disposition.get("target_ref")
                        target_commit = disposition.get("target_commit")
                        revert_tree = disposition.get("revert_tree")
                        if (
                            not isinstance(revert_id, str)
                            or not isinstance(revert_branch, str)
                            or not revert_branch.startswith(f"{BRANCH_NAMESPACE}/revert/")
                            or not isinstance(revert_commit, str)
                            or not isinstance(target_ref, str)
                            or not target_ref.startswith("refs/heads/")
                            or not isinstance(target_commit, str)
                            or not commit_exists(repository.root, target_commit)
                            or not isinstance(revert_tree, str)
                            or _branch_commit(repository.root, revert_branch) != revert_commit
                            or not vault.worktree_path(repository_id, "revert", revert_id).is_dir()
                        ):
                            raise NoTugError(
                                "GRANT_REVERT_DIVERGENCE",
                                "Generated revert branch or worktree is missing or altered",
                            )
                        _verify_exact_worktree_record(
                            vault,
                            repository,
                            repository_id,
                            kind="revert",
                            entity_id=revert_id,
                            stored_path=str(
                                vault.worktree_path(repository_id, "revert", revert_id)
                            ),
                            branch=revert_branch,
                            commit=revert_commit,
                            code="GRANT_REVERT_DIVERGENCE",
                        )
                        revert_parent = (
                            run_git(repository.root, ["rev-parse", f"{revert_commit}^"])
                            .stdout.decode("ascii")
                            .strip()
                        )
                        actual_revert_tree = (
                            run_git(repository.root, ["rev-parse", f"{revert_commit}^{{tree}}"])
                            .stdout.decode("ascii")
                            .strip()
                        )
                        original_parent = (
                            run_git(repository.root, ["rev-parse", f"{grant['commit']}^"])
                            .stdout.decode("ascii")
                            .strip()
                        )
                        if (
                            revert_parent != target_commit
                            or actual_revert_tree != revert_tree
                            or disposition.get("inverse_patch_sha256")
                            != sha256_bytes(
                                _binary_diff(repository.root, str(grant["commit"]), original_parent)
                            )
                            or disposition.get("applied_inverse_patch_sha256")
                            != sha256_bytes(
                                _binary_diff(repository.root, target_commit, revert_commit)
                            )
                        ):
                            raise NoTugError(
                                "GRANT_REVERT_DIVERGENCE",
                                "Generated revert commit does not match inverse evidence",
                            )
                    else:
                        raise NoTugError(
                            "GRANT_REVOKE_DIVERGENCE", "Unknown revocation disposition"
                        )
            else:
                raise NoTugError("GRANT_STATE_DIVERGENCE", "Grant state is not verifiable")
            verified_grants[str(grant["grant_id"])] = grant
        except NoTugError as exc:
            issues.append(_issue(exc, "grant", grant_path.stem))
    expected_grant_ids = {
        str(event["entity_id"]) for event in ledger_events if event["event_type"] == "GRANT_ISSUED"
    }
    present_grant_ids = {path.stem for path in grant_paths}
    for missing_id in sorted(expected_grant_ids - present_grant_ids):
        issues.append(
            _issue(
                NoTugError("GRANT_ARTIFACT_MISSING", "Grant artifact is missing"),
                "grant",
                missing_id,
            )
        )
    checks["grants"] = {
        "ok": not any(item["check"] == "grant" for item in issues),
        "count": grant_count,
    }

    resource_issues, resource_check = _managed_resource_reconciliation(
        vault,
        repository_id,
        repository,
        ledger_events,
        verified_grants,
    )
    issues.extend(resource_issues)
    checks["managed_resources"] = resource_check

    return {
        "ok": not issues,
        "schema_version": 1,
        "repository_id": repository_id,
        "mutation_lock": "active",
        "checks": checks,
        "issues": issues,
    }


def require_verified(path: Path, vault: Vault | None = None) -> dict[str, Any]:
    report = verify_repository(path, vault)
    if not report["ok"]:
        raise NoTugError(
            "VERIFICATION_FAILED",
            "One or more provenance checks failed",
            {"report": report},
        )
    return report
