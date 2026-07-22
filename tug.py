"""Tug Signal generation, strict validation, review, and denial."""

from __future__ import annotations

import contextlib
import re
import stat
from dataclasses import fields
from pathlib import Path
from typing import Any

from .brand import VERSION
from .changes import changes_to_dict, prepare_snapshot
from .config import load_policy
from .errors import NoTugError
from .events import ledger_for
from .identity import new_identifier, validate_identifier
from .models import ChangeEntry, PolicyFinding, State, assert_transition
from .policy import evaluate_policy, ignored_sensitive_paths
from .sessions import (
    find_session,
    save_session,
    verify_authoritative_baseline,
    verify_session_receipt_head,
    verify_session_worktree,
)
from .util import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from .vault import Vault

TUG_FIELDS = {
    "schema_version",
    "tug_id",
    "repository_id",
    "session_id",
    "state",
    "created_at",
    "repository",
    "baseline",
    "evidence",
    "changes",
    "affected_paths",
    "ignored_sensitive_paths",
    "policy",
    "risk_summary",
    "divergence_findings",
    "grant",
    "receipt_chain",
    "notug_version",
    "tug_hash",
}
REPOSITORY_FIELDS = {"repository_id", "object_format"}
BASELINE_FIELDS = {
    "commit",
    "tree",
    "source_ref",
    "source_head",
    "manifest_hash",
    "current_verified",
}
EVIDENCE_FIELDS = {
    "snapshot_tree",
    "patch_sha256",
    "patch_bytes",
    "workspace_manifest_hash",
    "changes_sha256",
    "git_diff_format",
    "summary",
}
SUMMARY_FIELDS = {
    "file_count",
    "old_bytes",
    "new_bytes",
    "bytes_touched",
    "patch_bytes",
    "binary_count",
    "deletion_count",
    "rename_count",
}
POLICY_FIELDS = {"schema_version", "policy_hash", "findings", "classifications_by_path"}
RISK_FIELDS = {
    "overall_severity",
    "blocked",
    "finding_count",
    "finding_codes",
    "severity_counts",
    "changed_files",
    "affected_path_count",
    "changed_bytes",
}
GRANT_FIELDS = {"requirement", "grantable", "automatic_approval"}
RECEIPT_FIELDS = {"sequence", "head_hash"}
SEVERITY_COUNT_FIELDS = {"info", "low", "medium", "high", "block"}
CHANGE_FIELDS = {field.name for field in fields(ChangeEntry)}
FINDING_FIELDS = {field.name for field in fields(PolicyFinding)}
HASH_RE = re.compile(r"^[a-f0-9]{64}$")


def _schema_assert(condition: bool, message: str) -> None:
    if not condition:
        raise NoTugError("TUG_SCHEMA_INVALID", message)


def _plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _strict_keys(value: Any, allowed: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NoTugError("TUG_SCHEMA_INVALID", f"{label} must be an object")
    unknown = sorted(set(value) - allowed)
    missing = sorted(allowed - set(value))
    if unknown or missing:
        raise NoTugError(
            "TUG_SCHEMA_INVALID",
            f"{label} fields do not match schema version 1",
            {"section": label, "unknown_fields": unknown, "missing_fields": missing},
        )
    return value


def tug_hash(tug: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in tug.items() if key != "tug_hash"}
    return sha256_bytes(b"NoTUG.Tug.v1\0" + canonical_json_bytes(unsigned))


def validate_tug(data: dict[str, Any]) -> dict[str, Any]:
    _strict_keys(data, TUG_FIELDS, "Tug Signal")
    if (
        not _plain_int(data["schema_version"])
        or data["schema_version"] != 1
        or data["state"] != State.TUGGED.value
    ):
        raise NoTugError("TUG_SCHEMA_INVALID", "Tug Signal schema version or state is invalid")
    repository = _strict_keys(data["repository"], REPOSITORY_FIELDS, "repository")
    baseline = _strict_keys(data["baseline"], BASELINE_FIELDS, "baseline")
    evidence = _strict_keys(data["evidence"], EVIDENCE_FIELDS, "evidence")
    _strict_keys(evidence["summary"], SUMMARY_FIELDS, "evidence.summary")
    policy = _strict_keys(data["policy"], POLICY_FIELDS, "policy")
    risk = _strict_keys(data["risk_summary"], RISK_FIELDS, "risk_summary")
    grant = _strict_keys(data["grant"], GRANT_FIELDS, "grant")
    receipt = _strict_keys(data["receipt_chain"], RECEIPT_FIELDS, "receipt_chain")
    try:
        validate_identifier(data["tug_id"], "tug")
        validate_identifier(data["repository_id"], "repo")
        validate_identifier(data["session_id"], "session")
    except NoTugError as exc:
        raise NoTugError("TUG_SCHEMA_INVALID", "Tug identifiers are invalid") from exc
    _schema_assert(
        repository["repository_id"] == data["repository_id"]
        and isinstance(repository["object_format"], str)
        and repository["object_format"] in {"sha1", "sha256"},
        "Tug repository identity is invalid",
    )
    oid_length = 40 if repository["object_format"] == "sha1" else 64
    oid_re = re.compile(rf"^[a-f0-9]{{{oid_length}}}$")
    _schema_assert(
        all(
            isinstance(baseline[key], str) and oid_re.fullmatch(baseline[key])
            for key in ("commit", "tree", "source_head")
        )
        and (baseline["source_ref"] is None or isinstance(baseline["source_ref"], str))
        and isinstance(baseline["manifest_hash"], str)
        and HASH_RE.fullmatch(baseline["manifest_hash"]) is not None
        and baseline["current_verified"] is True,
        "Tug baseline evidence is invalid",
    )
    _schema_assert(
        isinstance(evidence["snapshot_tree"], str)
        and oid_re.fullmatch(evidence["snapshot_tree"]) is not None
        and all(
            isinstance(evidence[key], str) and HASH_RE.fullmatch(evidence[key]) is not None
            for key in ("patch_sha256", "workspace_manifest_hash", "changes_sha256")
        )
        and _plain_int(evidence["patch_bytes"])
        and evidence["patch_bytes"] >= 0
        and evidence["git_diff_format"] == "git-binary-patch-v1",
        "Tug structural evidence is invalid",
    )
    _schema_assert(
        all(_plain_int(value) and value >= 0 for value in evidence["summary"].values()),
        "Tug summary counts are invalid",
    )
    if not isinstance(data["changes"], list):
        raise NoTugError("TUG_SCHEMA_INVALID", "changes must be an array")
    for change in data["changes"]:
        _strict_keys(change, CHANGE_FIELDS, "change")
        _schema_assert(
            all(isinstance(change[key], str) for key in ("kind", "path", "status"))
            and (change["old_path"] is None or isinstance(change["old_path"], str))
            and all(
                change[key] is None or isinstance(change[key], str)
                for key in ("old_mode", "new_mode", "old_oid", "new_oid", "symlink_target")
            )
            and all(
                isinstance(change[key], bool)
                for key in ("binary", "submodule", "symlink_outside_workspace")
            )
            and all(
                change[key] is None or _plain_int(change[key])
                for key in ("added_lines", "deleted_lines")
            )
            and all(_plain_int(change[key]) for key in ("old_size", "new_size", "byte_delta"))
            and isinstance(change["classifications"], list)
            and all(isinstance(value, str) for value in change["classifications"]),
            "Tug change entry types are invalid",
        )
    if not isinstance(policy["findings"], list):
        raise NoTugError("TUG_SCHEMA_INVALID", "policy findings must be an array")
    for finding in policy["findings"]:
        _strict_keys(finding, FINDING_FIELDS, "policy finding")
        _schema_assert(
            all(isinstance(finding[key], str) for key in ("code", "severity", "message"))
            and isinstance(finding["paths"], list)
            and all(isinstance(path, str) for path in finding["paths"]),
            "Tug policy finding types are invalid",
        )
    _schema_assert(
        _plain_int(policy["schema_version"])
        and policy["schema_version"] == 1
        and isinstance(policy["policy_hash"], str)
        and HASH_RE.fullmatch(policy["policy_hash"]) is not None
        and isinstance(policy["classifications_by_path"], dict)
        and all(
            isinstance(path, str)
            and isinstance(codes, list)
            and all(isinstance(code, str) for code in codes)
            for path, codes in policy["classifications_by_path"].items()
        ),
        "Tug policy evidence is invalid",
    )
    for array_name in ("affected_paths", "ignored_sensitive_paths", "divergence_findings"):
        if not isinstance(data[array_name], list) or not all(
            isinstance(value, str) for value in data[array_name]
        ):
            raise NoTugError("TUG_SCHEMA_INVALID", f"{array_name} must be an array of strings")
    _schema_assert(
        isinstance(risk["overall_severity"], str)
        and risk["overall_severity"] in {"info", "low", "medium", "high", "block"}
        and isinstance(risk["blocked"], bool)
        and all(
            _plain_int(risk[key]) and risk[key] >= 0
            for key in ("finding_count", "changed_files", "affected_path_count", "changed_bytes")
        )
        and isinstance(risk["finding_codes"], list)
        and all(isinstance(code, str) for code in risk["finding_codes"])
        and isinstance(risk["severity_counts"], dict)
        and set(risk["severity_counts"]) == SEVERITY_COUNT_FIELDS
        and all(_plain_int(value) and value >= 0 for value in risk["severity_counts"].values()),
        "Tug risk summary is invalid",
    )
    _schema_assert(
        grant
        == {
            "requirement": "explicit_interactive_human_grant_bound_to_tug_hash",
            "grantable": not bool(risk["blocked"]),
            "automatic_approval": False,
        },
        "Tug grant requirement is invalid",
    )
    _schema_assert(
        _plain_int(receipt["sequence"])
        and receipt["sequence"] >= 0
        and (
            receipt["head_hash"] is None
            or (
                isinstance(receipt["head_hash"], str)
                and HASH_RE.fullmatch(receipt["head_hash"]) is not None
            )
        )
        and isinstance(data["created_at"], str)
        and data["notug_version"] == VERSION,
        "Tug receipt binding or metadata is invalid",
    )
    expected = tug_hash(data)
    if data["tug_hash"] != expected:
        raise NoTugError(
            "TUG_HASH_MISMATCH", "Tug Signal canonical hash does not match", {"expected": expected}
        )
    return data


def load_tug(vault: Vault, repository_id: str, tug_id: str) -> dict[str, Any]:
    validate_identifier(repository_id, "repo")
    validate_identifier(tug_id, "tug")
    tug = validate_tug(read_json(vault.tug_path(repository_id, tug_id)))
    if tug["tug_id"] != tug_id or tug["repository_id"] != repository_id:
        raise NoTugError("TUG_ID_MISMATCH", "Tug identifiers disagree with the vault location")
    return tug


def find_tug(vault: Vault, tug_id: str) -> tuple[str, dict[str, Any]]:
    validate_identifier(tug_id, "tug")
    matches: list[tuple[str, Path]] = []
    repositories = vault.root / "r"
    if repositories.is_dir():
        for repository in repositories.iterdir():
            candidate = repository / "tugs" / f"{tug_id}.json"
            if candidate.is_file():
                matches.append((repository.name, candidate))
    if not matches:
        raise NoTugError("TUG_NOT_FOUND", "No Tug Signal matches the exact identifier")
    if len(matches) != 1:
        raise NoTugError("TUG_ID_AMBIGUOUS", "Tug Signal identifier is not unique")
    repository_id, _path = matches[0]
    return repository_id, load_tug(vault, repository_id, tug_id)


def _merge_ignored_findings(
    changes: list[ChangeEntry], ignored: list[str], policy_config: Any
) -> tuple[dict[str, Any], list[str]]:
    sensitive = ignored_sensitive_paths(ignored)
    # Evaluate names structurally without pretending ignored artifacts are patch entries.
    synthetic = [ChangeEntry(kind="ignored", path=path, status="ignored") for path in sensitive]
    regular = evaluate_policy(changes, policy_config)
    ignored_evaluation = evaluate_policy(synthetic, policy_config)
    findings_by_code: dict[str, PolicyFinding] = {
        finding.code: finding for finding in regular.findings
    }
    for finding in ignored_evaluation.findings:
        existing = findings_by_code.get(finding.code)
        if existing is None:
            findings_by_code[finding.code] = finding
        else:
            existing.paths = sorted(
                set(existing.paths) | set(finding.paths), key=lambda value: value.casefold()
            )
    review_only = not changes and bool(sensitive)
    if review_only:
        findings_by_code["NO_PROPOSABLE_CHANGES"] = PolicyFinding(
            code="NO_PROPOSABLE_CHANGES",
            severity="block",
            message="Only ignored sensitive paths were detected; there is no patch to grant",
            paths=list(sensitive),
        )
    findings = list(findings_by_code.values())
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "block": 4}
    findings.sort(key=lambda finding: (-rank[finding.severity], finding.code))
    overall = max((finding.severity for finding in findings), key=rank.__getitem__, default="info")
    severity_counts = {severity: 0 for severity in rank}
    for finding in findings:
        severity_counts[finding.severity] += 1
    classifications = dict(regular.classifications_by_path)
    classifications.update(ignored_evaluation.classifications_by_path)
    if review_only:
        for path in sensitive:
            classifications[path] = sorted(
                set(classifications.get(path, [])) | {"NO_PROPOSABLE_CHANGES"}
            )
    risk = dict(regular.risk_summary)
    risk.update(
        {
            "overall_severity": overall,
            "blocked": overall == "block",
            "finding_count": len(findings),
            "finding_codes": [finding.code for finding in findings],
            "severity_counts": severity_counts,
            "affected_path_count": len(
                {
                    path
                    for change in changes
                    for path in (
                        [change.path] if change.old_path is None else [change.old_path, change.path]
                    )
                }
                | set(sensitive)
            ),
        }
    )
    return {
        "findings": [finding.to_dict() for finding in findings],
        "classifications_by_path": classifications,
        "risk_summary": risk,
    }, sensitive


def generate_tug(session_id: str, vault: Vault | None = None) -> dict[str, Any]:
    selected_vault = vault or Vault()
    repository_id, _ = find_session(selected_vault, session_id)
    with selected_vault.locked(repository_id):
        return _generate_tug_locked(session_id, selected_vault)


def _staging_path_is_redirected(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & reparse_flag)
        or not stat.S_ISDIR(metadata.st_mode)
    )


def _cleanup_tug_staging(operation_dir: Path, *, required: bool) -> None:
    try:
        boundaries = (operation_dir.parent.parent, operation_dir.parent, operation_dir)
        if any(_staging_path_is_redirected(path) for path in boundaries):
            raise OSError("Tug staging path is redirected or is not a directory")
        if not operation_dir.exists():
            with contextlib.suppress(OSError):
                operation_dir.parent.rmdir()
            return
        for name in (
            "snapshot.index",
            "snapshot.index.lock",
            "proposal.patch",
            "workspace-manifest.json",
            "changes.json",
            "tug.json",
        ):
            artifact = operation_dir / name
            if artifact.is_symlink():
                artifact.unlink()
            elif artifact.exists():
                if not artifact.is_file():
                    raise OSError("Known Tug staging artifact is not a regular file")
                artifact.unlink()
        operation_dir.rmdir()
    except OSError as exc:
        if required:
            raise NoTugError(
                "TUG_STAGING_CLEANUP_FAILED",
                "Incomplete Tug staging artifacts could not be removed safely",
            ) from exc
        return
    with contextlib.suppress(OSError):
        # Other in-flight or retained Tug operations still own the shared parent.
        operation_dir.parent.rmdir()


def _generate_tug_locked(session_id: str, vault: Vault) -> dict[str, Any]:
    repository_id, session = find_session(vault, session_id)
    ledger = ledger_for(vault, repository_id)
    chain = ledger.verify()
    verify_session_receipt_head(session, chain.events)
    if session["state"] != State.SESSION_OPEN.value or session["tug_id"] is not None:
        raise NoTugError(
            "STATE_TRANSITION_INVALID",
            "Exactly one Tug Signal may be generated for an open session",
        )
    assert_transition(str(session["state"]), State.TUGGED.value)
    try:
        repository = verify_session_worktree(vault, session)
        verify_authoritative_baseline(vault, session)
    except NoTugError as exc:
        if exc.code in {
            "BASELINE_MISSING",
            "BASELINE_REF_DRIFT",
            "SOURCE_HEAD_DRIFT",
            "SOURCE_DIRTY_DRIFT",
            "SOURCE_MANIFEST_DRIFT",
            "WORKTREE_ADMIN_DIVERGENCE",
        }:
            session["state"] = State.DIVERGED.value
            event = ledger.append_transition(
                repository_id=repository_id,
                event_type="SESSION_DIVERGED",
                entity_type="session",
                entity_id=session_id,
                state_from=State.SESSION_OPEN.value,
                state_to=State.DIVERGED.value,
                payload={"reason_code": exc.code},
            )
            session["last_event_hash"] = event["event_hash"]
            save_session(vault, session)
        raise
    policy = load_policy(
        vault.policy_snapshot_path(repository_id, str(session["policy_hash"])),
        str(session["policy_hash"]),
    )
    tug_id = new_identifier("tug")
    tug_path = vault.tug_path(repository_id, tug_id)
    operation_dir = tug_path.parent / ".work" / tug_id
    workspace_manifest_path = vault.changes_path(repository_id, tug_id).with_suffix(
        ".workspace.json"
    )
    patch_path = vault.patch_path(repository_id, tug_id)
    changes_path = vault.changes_path(repository_id, tug_id)
    published_paths: list[Path] = []
    artifacts_published = False
    receipt_committed = False
    tug: dict[str, Any]
    try:
        evidence = prepare_snapshot(
            repository,
            Path(str(session["worktree"])),
            str(session["baseline_commit"]),
            operation_dir,
            vault.root,
        )
        policy_result, ignored_sensitive = _merge_ignored_findings(
            evidence.changes, evidence.ignored_paths, policy
        )
        if evidence.file_count == 0 and not ignored_sensitive:
            raise NoTugError("NO_CHANGES", "The disposable session has no proposed changes")
        changes_document = {
            "schema_version": 1,
            "tug_id": tug_id,
            "changes": changes_to_dict(evidence.changes),
        }
        changes_sha = sha256_bytes(canonical_json_bytes(changes_document))
        affected = sorted(
            {
                path
                for change in evidence.changes
                for path in (
                    [change.path] if change.old_path is None else [change.old_path, change.path]
                )
            },
            key=lambda value: value.casefold(),
        )
        tug = {
            "schema_version": 1,
            "tug_id": tug_id,
            "repository_id": repository_id,
            "session_id": session_id,
            "state": State.TUGGED.value,
            "created_at": utc_now(),
            "repository": {
                "repository_id": repository_id,
                "object_format": repository.object_format,
            },
            "baseline": {
                "commit": session["baseline_commit"],
                "tree": session["baseline_tree"],
                "source_ref": session["source_ref"],
                "source_head": session["source_head"],
                "manifest_hash": session["baseline_manifest_hash"],
                "current_verified": True,
            },
            "evidence": {
                "snapshot_tree": evidence.snapshot_tree,
                "patch_sha256": evidence.patch_sha256,
                "patch_bytes": evidence.patch_bytes,
                "workspace_manifest_hash": evidence.workspace_manifest_hash,
                "changes_sha256": changes_sha,
                "git_diff_format": "git-binary-patch-v1",
                "summary": evidence.summary_dict(),
            },
            "changes": changes_to_dict(evidence.changes),
            "affected_paths": affected,
            "ignored_sensitive_paths": ignored_sensitive,
            "policy": {
                "schema_version": policy.schema_version,
                "policy_hash": policy.sha256,
                "findings": policy_result["findings"],
                "classifications_by_path": policy_result["classifications_by_path"],
            },
            "risk_summary": policy_result["risk_summary"],
            "divergence_findings": [],
            "grant": {
                "requirement": "explicit_interactive_human_grant_bound_to_tug_hash",
                "grantable": not bool(policy_result["risk_summary"]["blocked"]),
                "automatic_approval": False,
            },
            "receipt_chain": {"sequence": chain.count, "head_hash": chain.head_hash},
            "notug_version": VERSION,
            "tug_hash": "",
        }
        tug["tug_hash"] = tug_hash(tug)
        validate_tug(tug)

        staged_changes = operation_dir / "changes.json"
        staged_tug = operation_dir / "tug.json"
        atomic_write_json(staged_changes, changes_document)
        atomic_write_json(staged_tug, tug)
        artifacts = (
            (evidence.patch_path, patch_path),
            (evidence.workspace_manifest_path, workspace_manifest_path),
            (staged_changes, changes_path),
            (staged_tug, tug_path),
        )
        if any(target.exists() or target.is_symlink() for _source, target in artifacts):
            raise NoTugError(
                "TUG_ARTIFACT_COLLISION",
                "Generated Tug artifact path already exists",
            )
        for source, target in artifacts:
            atomic_write_bytes(target, source.read_bytes())
            published_paths.append(target)
        artifacts_published = True

        event = ledger.append_transition(
            repository_id=repository_id,
            event_type="TUG_GENERATED",
            entity_type="tug",
            entity_id=tug_id,
            state_from=State.SESSION_OPEN.value,
            state_to=State.TUGGED.value,
            payload={
                "session_id": session_id,
                "tug_hash": tug["tug_hash"],
                "patch_sha256": evidence.patch_sha256,
                "change_count": evidence.file_count,
                "policy_hash": policy.sha256,
            },
        )
        receipt_committed = True
        session["state"] = State.TUGGED.value
        session["tug_id"] = tug_id
        session["last_event_hash"] = event["event_hash"]
        save_session(vault, session)
    except BaseException:
        if not artifacts_published:
            for path in reversed(published_paths):
                path.unlink(missing_ok=True)
            _cleanup_tug_staging(operation_dir, required=True)
        elif receipt_committed:
            _cleanup_tug_staging(operation_dir, required=False)
        # Published-but-unreceipted evidence is retained so verification fails closed.
        raise
    _cleanup_tug_staging(operation_dir, required=False)
    return tug


def verify_tug_artifacts(vault: Vault, repository_id: str, tug: dict[str, Any]) -> None:
    validate_tug(tug)
    verify_tug_receipt(vault, repository_id, tug)
    tug_id = str(tug["tug_id"])
    patch_path = vault.patch_path(repository_id, tug_id)
    if not patch_path.is_file():
        raise NoTugError("PATCH_MISSING", "Reviewed patch artifact is missing")
    actual_patch_hash = sha256_file(patch_path)
    if actual_patch_hash != tug["evidence"]["patch_sha256"]:
        raise NoTugError("PATCH_HASH_MISMATCH", "Reviewed patch artifact was altered")
    changes = read_json(vault.changes_path(repository_id, tug_id))
    if (
        set(changes) != {"schema_version", "tug_id", "changes"}
        or not _plain_int(changes.get("schema_version"))
        or changes.get("schema_version") != 1
    ):
        raise NoTugError("PROVENANCE_DIVERGENCE", "Stored change classification schema is invalid")
    if changes.get("tug_id") != tug_id or changes.get("changes") != tug["changes"]:
        raise NoTugError("PROVENANCE_DIVERGENCE", "Tug and stored change classifications disagree")
    actual_changes_hash = sha256_bytes(canonical_json_bytes(changes))
    if actual_changes_hash != tug["evidence"]["changes_sha256"]:
        raise NoTugError("PROVENANCE_DIVERGENCE", "Stored change classification was altered")
    workspace_path = vault.changes_path(repository_id, tug_id).with_suffix(".workspace.json")
    workspace = read_json(workspace_path)
    if set(workspace) != {"schema_version", "entries", "entry_count", "manifest_hash"}:
        raise NoTugError("PROVENANCE_DIVERGENCE", "Workspace manifest schema is invalid")
    entries = workspace.get("entries")
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise NoTugError("PROVENANCE_DIVERGENCE", "Workspace manifest entries are invalid")
    workspace_core = {key: workspace[key] for key in ("schema_version", "entries", "entry_count")}
    actual_workspace_hash = sha256_bytes(canonical_json_bytes(workspace_core))
    if (
        workspace.get("entry_count") != len(entries)
        or workspace.get("manifest_hash") != actual_workspace_hash
    ):
        raise NoTugError("PROVENANCE_DIVERGENCE", "Workspace manifest content hash is invalid")
    if workspace.get("manifest_hash") != tug["evidence"]["workspace_manifest_hash"]:
        raise NoTugError("PROVENANCE_DIVERGENCE", "Workspace manifest hash does not match")


def verify_tug_receipt(vault: Vault, repository_id: str, tug: dict[str, Any]) -> None:
    """Bind a self-consistent Tug artifact to its exact generation receipt."""

    chain = ledger_for(vault, repository_id).verify()
    matches = [
        event
        for event in chain.events
        if event["event_type"] == "TUG_GENERATED" and event["entity_id"] == tug["tug_id"]
    ]
    if len(matches) != 1:
        raise NoTugError("TUG_RECEIPT_MISSING", "Tug Signal has no unique generation receipt")
    event = matches[0]
    expected_payload = {
        "session_id": tug["session_id"],
        "tug_hash": tug["tug_hash"],
        "patch_sha256": tug["evidence"]["patch_sha256"],
        "change_count": tug["evidence"]["summary"]["file_count"],
        "policy_hash": tug["policy"]["policy_hash"],
    }
    receipt_sequence = tug["receipt_chain"]["sequence"]
    if (
        event["payload"] != expected_payload
        or event["state_from"] != State.SESSION_OPEN.value
        or event["state_to"] != State.TUGGED.value
        or event["sequence"] != receipt_sequence + 1
        or event["previous_event_hash"] != tug["receipt_chain"]["head_hash"]
    ):
        raise NoTugError(
            "TUG_RECEIPT_MISMATCH",
            "Tug Signal does not match its exact generation receipt",
        )


def deny_tug(tug_id: str, vault: Vault | None = None) -> dict[str, Any]:
    selected_vault = vault or Vault()
    repository_id, _ = find_tug(selected_vault, tug_id)
    with selected_vault.locked(repository_id):
        return _deny_tug_locked(tug_id, selected_vault)


def _deny_tug_locked(tug_id: str, vault: Vault) -> dict[str, Any]:
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
        raise NoTugError("STATE_TRANSITION_INVALID", "Tug Signal is not pending disposition")
    assert_transition(str(session["state"]), State.DENIED.value)
    verify_tug_artifacts(vault, repository_id, tug)
    event = ledger.append_transition(
        repository_id=repository_id,
        event_type="TUG_DENIED",
        entity_type="tug",
        entity_id=tug_id,
        state_from=State.TUGGED.value,
        state_to=State.DENIED.value,
        payload={"session_id": session["session_id"], "tug_hash": tug["tug_hash"]},
    )
    session["state"] = State.DENIED.value
    session["last_event_hash"] = event["event_hash"]
    save_session(vault, session)
    return {"tug_id": tug_id, "state": State.DENIED.value, "receipt_hash": event["event_hash"]}


def full_diff_text(vault: Vault, repository_id: str, tug: dict[str, Any]) -> str:
    from .util import sanitize_terminal

    verify_tug_artifacts(vault, repository_id, tug)
    patch = vault.patch_path(repository_id, str(tug["tug_id"])).read_bytes()
    # Binary payload is never decoded/rendered as terminal text. Git's textual binary
    # patch section is replaced with a stable marker after the header.
    decoded = patch.decode("utf-8", errors="replace")
    lines: list[str] = []
    in_binary = False
    for line in decoded.splitlines():
        if line == "GIT binary patch":
            lines.append("[binary patch payload omitted]")
            in_binary = True
            continue
        if in_binary:
            if line.startswith("diff --git "):
                in_binary = False
            else:
                continue
        lines.append(sanitize_terminal(line))
    return "\n".join(lines)
