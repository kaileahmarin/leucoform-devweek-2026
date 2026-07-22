"""Deterministic SHA-256 manifests for a recorded Git commit."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import NoTugError
from .git import GitRepository, resolve_commit, run_git
from .identity import validate_identifier
from .models import ManifestEntry
from .util import atomic_write_json, canonical_json_bytes, safe_git_path, sha256_bytes

MANIFEST_DOMAIN = b"NoTUG.Manifest.v1\0"
MANIFEST_FIELDS = {
    "schema_version",
    "repository_id",
    "commit",
    "tree",
    "object_format",
    "entries",
    "manifest_hash",
}
ENTRY_FIELDS = {"path", "mode", "git_oid", "sha256", "size", "kind"}
HASH_RE = re.compile(r"^[a-f0-9]{64}$")
OID_RE = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
ALLOWED_MODES = {"100644", "100755", "120000", "160000"}


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = child
    return value


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid constant: {constant}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise NoTugError("MANIFEST_INVALID", "Manifest is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise NoTugError("MANIFEST_INVALID", "Manifest must contain a JSON object")
    return value


def _manifest_core(
    *,
    repository_id: str,
    commit: str,
    tree: str,
    object_format: str,
    entries: tuple[ManifestEntry, ...],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "repository_id": repository_id,
        "commit": commit,
        "tree": tree,
        "object_format": object_format,
        "entries": [entry.to_dict() for entry in entries],
    }


@dataclass(frozen=True, slots=True)
class BaselineManifest:
    schema_version: int
    repository_id: str
    commit: str
    tree: str
    object_format: str
    entries: tuple[ManifestEntry, ...]
    manifest_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            **_manifest_core(
                repository_id=self.repository_id,
                commit=self.commit,
                tree=self.tree,
                object_format=self.object_format,
                entries=self.entries,
            ),
            "manifest_hash": self.manifest_hash,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BaselineManifest:
        if not isinstance(value, dict):
            raise NoTugError("MANIFEST_INVALID", "Manifest must be an object")
        unknown = sorted(set(value) - MANIFEST_FIELDS)
        missing = sorted(MANIFEST_FIELDS - set(value))
        if unknown or missing:
            raise NoTugError(
                "MANIFEST_INVALID",
                "Manifest fields do not match schema version 1",
                {"unknown_fields": unknown, "missing_fields": missing},
            )
        schema_version = value.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != 1
        ):
            raise NoTugError("MANIFEST_INVALID", "Unsupported manifest schema version")
        repository_id = value.get("repository_id")
        if not isinstance(repository_id, str):
            raise NoTugError("MANIFEST_INVALID", "Manifest repository identifier is invalid")
        if repository_id:
            validate_identifier(repository_id, "repo")
        commit = value.get("commit")
        tree = value.get("tree")
        object_format = value.get("object_format")
        if (
            not isinstance(commit, str)
            or not OID_RE.fullmatch(commit)
            or not isinstance(tree, str)
            or not OID_RE.fullmatch(tree)
            or object_format not in {"sha1", "sha256"}
        ):
            raise NoTugError("MANIFEST_INVALID", "Manifest Git identity is invalid")
        oid_length = 40 if object_format == "sha1" else 64
        if len(commit) != oid_length or len(tree) != oid_length:
            raise NoTugError(
                "MANIFEST_INVALID", "Manifest object IDs do not match the Git object format"
            )
        raw_entries = value.get("entries")
        if not isinstance(raw_entries, list):
            raise NoTugError("MANIFEST_INVALID", "Manifest entries must be an array")
        entries: list[ManifestEntry] = []
        seen_paths: set[str] = set()
        seen_folded: dict[str, str] = {}
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict) or set(raw_entry) != ENTRY_FIELDS:
                raise NoTugError("MANIFEST_INVALID", "Manifest entry schema is invalid")
            path = raw_entry.get("path")
            mode = raw_entry.get("mode")
            git_oid = raw_entry.get("git_oid")
            digest = raw_entry.get("sha256")
            size = raw_entry.get("size")
            kind = raw_entry.get("kind")
            if not isinstance(path, str) or not path:
                raise NoTugError("MANIFEST_INVALID", "Manifest path is invalid")
            safe, reason = safe_git_path(path)
            if not safe or any(":" in part for part in path.replace("\\", "/").split("/")):
                raise NoTugError(
                    "UNSAFE_REPOSITORY_PATH",
                    "Tracked path is unsafe on supported platforms",
                    {"path": path, "reason": reason or "Windows alternate data stream"},
                )
            if path in seen_paths:
                raise NoTugError("MANIFEST_INVALID", "Manifest contains duplicate paths")
            folded = path.replace("\\", "/").casefold()
            if folded in seen_folded and seen_folded[folded] != path:
                raise NoTugError(
                    "WINDOWS_PATH_COLLISION",
                    "Tracked paths collide on a case-insensitive filesystem",
                    {"first": seen_folded[folded], "second": path},
                )
            seen_paths.add(path)
            seen_folded[folded] = path
            if mode not in ALLOWED_MODES:
                raise NoTugError("MANIFEST_INVALID", "Manifest entry mode is unsupported")
            if not isinstance(git_oid, str) or not OID_RE.fullmatch(git_oid):
                raise NoTugError("MANIFEST_INVALID", "Manifest Git object ID is invalid")
            if len(git_oid) != oid_length:
                raise NoTugError(
                    "MANIFEST_INVALID", "Entry object ID does not match the Git object format"
                )
            if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
                raise NoTugError("MANIFEST_INVALID", "Manifest SHA-256 is invalid")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise NoTugError("MANIFEST_INVALID", "Manifest entry size is invalid")
            expected_kind = {
                "100644": "file",
                "100755": "file",
                "120000": "symlink",
                "160000": "submodule",
            }[mode]
            if kind != expected_kind:
                raise NoTugError("MANIFEST_INVALID", "Manifest entry kind and mode disagree")
            entries.append(ManifestEntry(path, mode, git_oid, digest, size, kind))
        if [entry.path for entry in entries] != sorted(entry.path for entry in entries):
            raise NoTugError("MANIFEST_INVALID", "Manifest entries are not canonically ordered")
        supplied_hash = value.get("manifest_hash")
        if not isinstance(supplied_hash, str) or not HASH_RE.fullmatch(supplied_hash):
            raise NoTugError("MANIFEST_INVALID", "Manifest hash is invalid")
        core = _manifest_core(
            repository_id=repository_id,
            commit=commit,
            tree=tree,
            object_format=object_format,
            entries=tuple(entries),
        )
        expected_hash = sha256_bytes(MANIFEST_DOMAIN + canonical_json_bytes(core))
        if supplied_hash != expected_hash:
            raise NoTugError("MANIFEST_HASH_MISMATCH", "Manifest content hash does not verify")
        return cls(1, repository_id, commit, tree, object_format, tuple(entries), supplied_hash)


def _repo_path(repo: Path | GitRepository) -> Path:
    return repo.root if isinstance(repo, GitRepository) else Path(repo)


def _object_format(repo: Path | GitRepository) -> str:
    if isinstance(repo, GitRepository):
        return repo.object_format
    result = run_git(_repo_path(repo), ["rev-parse", "--show-object-format"], check=False)
    if result.returncode != 0:
        return "sha1"
    value = result.stdout.decode("ascii", errors="strict").strip()
    if value not in {"sha1", "sha256"}:
        raise NoTugError("GIT_OUTPUT_INVALID", "Git object format is unsupported")
    return value


def _parse_tree_record(raw: bytes) -> tuple[str, str, str, str]:
    metadata, separator, raw_path = raw.partition(b"\t")
    if not separator:
        raise NoTugError("GIT_OUTPUT_INVALID", "Git tree record is malformed")
    fields = metadata.split(b" ")
    if len(fields) != 3:
        raise NoTugError("GIT_OUTPUT_INVALID", "Git tree metadata is malformed")
    try:
        mode, object_type, oid = (field.decode("ascii", errors="strict") for field in fields)
        path = raw_path.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise NoTugError(
            "UNSUPPORTED_PATH_ENCODING", "Tracked Git path is not valid UTF-8"
        ) from exc
    return mode, object_type, oid.lower(), path


def generate_manifest(
    repo: Path | GitRepository, commit: str = "HEAD", *, repository_id: str = ""
) -> BaselineManifest:
    if repository_id:
        validate_identifier(repository_id, "repo")
    path = _repo_path(repo)
    resolved_commit = resolve_commit(path, commit)
    tree = run_git(path, ["rev-parse", f"{resolved_commit}^{{tree}}"])
    try:
        tree_oid = tree.stdout.decode("ascii", errors="strict").strip().lower()
    except UnicodeDecodeError as exc:
        raise NoTugError("GIT_OUTPUT_INVALID", "Git tree identifier is invalid") from exc
    raw_tree = run_git(path, ["ls-tree", "-r", "-z", "--full-tree", resolved_commit]).stdout
    entries: list[ManifestEntry] = []
    for raw_record in raw_tree.split(b"\0"):
        if not raw_record:
            continue
        mode, object_type, oid, tracked_path = _parse_tree_record(raw_record)
        if mode not in ALLOWED_MODES:
            raise NoTugError(
                "UNSUPPORTED_GIT_MODE",
                "Tracked Git object has an unsupported mode",
                {"path": tracked_path, "mode": mode},
            )
        if mode == "160000":
            if object_type != "commit":
                raise NoTugError("GIT_OUTPUT_INVALID", "Gitlink entry has an invalid object type")
            digest = sha256_bytes(b"NoTUG.Gitlink.v1\0" + oid.encode("ascii"))
            entries.append(ManifestEntry(tracked_path, mode, oid, digest, 0, "submodule"))
            continue
        if object_type != "blob":
            raise NoTugError("GIT_OUTPUT_INVALID", "Tracked entry is not a Git blob")
        blob = run_git(path, ["cat-file", "blob", oid]).stdout
        kind = "symlink" if mode == "120000" else "file"
        entries.append(ManifestEntry(tracked_path, mode, oid, sha256_bytes(blob), len(blob), kind))
    entries.sort(key=lambda entry: entry.path)
    core = _manifest_core(
        repository_id=repository_id,
        commit=resolved_commit,
        tree=tree_oid,
        object_format=_object_format(repo),
        entries=tuple(entries),
    )
    manifest_hash = sha256_bytes(MANIFEST_DOMAIN + canonical_json_bytes(core))
    # Round-trip through the strict validator so generated and loaded manifests share rules.
    return BaselineManifest.from_dict({**core, "manifest_hash": manifest_hash})


def write_manifest(path: Path, manifest: BaselineManifest) -> None:
    validated = BaselineManifest.from_dict(manifest.to_dict())
    if path.exists():
        existing = load_manifest(
            path,
            expected_hash=validated.manifest_hash,
            expected_repository_id=validated.repository_id,
        )
        if existing.manifest_hash != validated.manifest_hash:
            raise NoTugError(
                "IMMUTABLE_ARTIFACT_COLLISION", "A different manifest already occupies this path"
            )
        return
    atomic_write_json(path, validated.to_dict())


def load_manifest(
    path: Path,
    *,
    expected_hash: str | None = None,
    expected_repository_id: str | None = None,
) -> BaselineManifest:
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError as exc:
        raise NoTugError("MANIFEST_MISSING", "Stored baseline manifest is missing") from exc
    except OSError as exc:
        raise NoTugError("MANIFEST_UNREADABLE", "Stored baseline manifest cannot be read") from exc
    value = _strict_json_object(raw)
    if raw != canonical_json_bytes(value) + b"\n":
        raise NoTugError("MANIFEST_INVALID", "Manifest is not canonically encoded")
    manifest = BaselineManifest.from_dict(value)
    if expected_hash is not None and manifest.manifest_hash != expected_hash:
        raise NoTugError("MANIFEST_ID_MISMATCH", "Manifest hash disagrees with its vault path")
    if expected_repository_id is not None and manifest.repository_id != expected_repository_id:
        raise NoTugError(
            "MANIFEST_ID_MISMATCH", "Manifest repository disagrees with its vault location"
        )
    return manifest


def verify_manifest(repo: Path | GitRepository, manifest: BaselineManifest) -> BaselineManifest:
    validated = BaselineManifest.from_dict(manifest.to_dict())
    rebuilt = generate_manifest(repo, validated.commit, repository_id=validated.repository_id)
    if rebuilt.manifest_hash != validated.manifest_hash:
        raise NoTugError(
            "MANIFEST_DIVERGENCE",
            "Stored SHA-256 manifest does not match the recorded Git commit",
            {"expected": validated.manifest_hash, "actual": rebuilt.manifest_hash},
        )
    return rebuilt


# Convenient lifecycle aliases.
build_manifest = generate_manifest
create_manifest = generate_manifest
