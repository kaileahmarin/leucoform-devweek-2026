"""Explicit, patch-free Tug receipt exports with scoped path aliases."""

from __future__ import annotations

import copy
from typing import Any

from .events import ledger_for
from .tug import find_tug, verify_tug_artifacts
from .util import canonical_json_bytes, sha256_bytes, utc_now
from .vault import Vault


def _alias(tug_hash: str, path: str) -> str:
    digest = sha256_bytes(
        b"NoTUG.ExportPath.v1\0" + tug_hash.encode("ascii") + b"\0" + path.encode("utf-8")
    )
    return f"path-{digest[:16]}"


def export_tug_receipt(
    tug_id: str, vault: Vault | None = None, *, include_paths: bool = False
) -> dict[str, Any]:
    vault = vault or Vault()
    repository_id, tug = find_tug(vault, tug_id)
    verify_tug_artifacts(vault, repository_id, tug)
    chain = ledger_for(vault, repository_id).verify()
    changes = copy.deepcopy(tug["changes"])
    findings = copy.deepcopy(tug["policy"]["findings"])
    classifications = copy.deepcopy(tug["policy"]["classifications_by_path"])
    affected = list(tug["affected_paths"])
    ignored = list(tug["ignored_sensitive_paths"])
    if not include_paths:
        all_paths = {
            path
            for change in changes
            for path in (change.get("path"), change.get("old_path"))
            if isinstance(path, str)
        }
        all_paths.update(path for finding in findings for path in finding["paths"])
        all_paths.update(classifications)
        all_paths.update(affected)
        all_paths.update(ignored)
        aliases = {path: _alias(str(tug["tug_hash"]), path) for path in sorted(all_paths)}
        for change in changes:
            change["path"] = aliases[str(change["path"])]
            if change["old_path"] is not None:
                change["old_path"] = aliases[str(change["old_path"])]
            if change["symlink_target"] is not None:
                change["symlink_target"] = "<redacted-target>"
        for finding in findings:
            finding["paths"] = [aliases[path] for path in finding["paths"]]
        classifications = {aliases[path]: codes for path, codes in classifications.items()}
        affected = [aliases[path] for path in affected]
        ignored = [aliases[path] for path in ignored]
    body: dict[str, Any] = {
        "schema_version": 1,
        "export_type": "tug-receipt",
        "exported_at": utc_now(),
        "paths": "included" if include_paths else "redacted-scoped-aliases",
        "source": {
            "repository_id": repository_id,
            "session_id": tug["session_id"],
            "tug_id": tug_id,
            "tug_hash": tug["tug_hash"],
            "patch_sha256": tug["evidence"]["patch_sha256"],
            "patch_included": False,
        },
        "baseline": copy.deepcopy(tug["baseline"]),
        "evidence": copy.deepcopy(tug["evidence"]),
        "changes": changes,
        "affected_paths": affected,
        "ignored_sensitive_paths": ignored,
        "policy": {
            "schema_version": tug["policy"]["schema_version"],
            "policy_hash": tug["policy"]["policy_hash"],
            "findings": findings,
            "classifications_by_path": classifications,
        },
        "risk_summary": copy.deepcopy(tug["risk_summary"]),
        "receipt_chain": {"event_count": chain.count, "head_hash": chain.head_hash},
    }
    return {**body, "export_hash": sha256_bytes(b"NoTUG.Export.v1\0" + canonical_json_bytes(body))}
