"""Opaque local identifiers and stable repository identity records."""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import NoTugError
from .util import canonical_json_bytes, normalized_local_path, sha256_bytes, utc_now

IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]{1,15}_[a-z2-7]{16,52}$")
IDENTITY_FIELDS = {
    "schema_version",
    "repository_id",
    "repository_key",
    "root",
    "common_git_dir",
    "created_at",
}


def new_identifier(prefix: str, *, byte_length: int = 12) -> str:
    """Return a compact, filesystem-safe opaque identifier."""

    if not re.fullmatch(r"[a-z][a-z0-9]{1,15}", prefix):
        raise ValueError("Identifier prefix must be 2-16 lowercase ASCII characters")
    if byte_length < 10 or byte_length > 32:
        raise ValueError("Opaque identifiers require 10-32 random bytes")
    encoded = base64.b32encode(secrets.token_bytes(byte_length)).decode("ascii").rstrip("=")
    return f"{prefix}_{encoded.lower()}"


def validate_identifier(value: str, prefix: str | None = None) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise NoTugError(
            "IDENTIFIER_INVALID",
            "Local protocol identifier has an invalid format",
            {"expected_prefix": prefix},
        )
    if prefix is not None and not value.startswith(f"{prefix}_"):
        raise NoTugError(
            "IDENTIFIER_INVALID",
            "Local protocol identifier has an unexpected type",
            {"expected_prefix": prefix},
        )
    return value


def repository_key(root: Path, common_git_dir: Path) -> str:
    """Derive a private local lookup key without exposing paths as an identifier."""

    evidence = {
        "common_git_dir": normalized_local_path(common_git_dir),
        "root": normalized_local_path(root),
        "schema_version": 1,
    }
    return sha256_bytes(b"NoTUG.RepositoryKey.v1\0" + canonical_json_bytes(evidence))


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    schema_version: int
    repository_id: str
    repository_key: str
    root: Path
    common_git_dir: Path
    created_at: str

    @classmethod
    def create(cls, root: Path, common_git_dir: Path) -> RepositoryIdentity:
        resolved_root = root.resolve()
        resolved_common = common_git_dir.resolve()
        return cls(
            schema_version=1,
            repository_id=new_identifier("repo"),
            repository_key=repository_key(resolved_root, resolved_common),
            root=resolved_root,
            common_git_dir=resolved_common,
            created_at=utc_now(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "repository_id": self.repository_id,
            "repository_key": self.repository_key,
            "root": str(self.root),
            "common_git_dir": str(self.common_git_dir),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RepositoryIdentity:
        if not isinstance(value, dict):
            raise NoTugError("REPOSITORY_METADATA_INVALID", "Repository metadata must be an object")
        unknown = sorted(set(value) - IDENTITY_FIELDS)
        missing = sorted(IDENTITY_FIELDS - set(value))
        if unknown or missing:
            raise NoTugError(
                "REPOSITORY_METADATA_INVALID",
                "Repository metadata fields do not match schema version 1",
                {"unknown_fields": unknown, "missing_fields": missing},
            )
        schema_version = value.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != 1
        ):
            raise NoTugError(
                "REPOSITORY_METADATA_INVALID", "Unsupported repository metadata schema"
            )
        repository_id_value = value.get("repository_id")
        if not isinstance(repository_id_value, str):
            raise NoTugError("REPOSITORY_METADATA_INVALID", "Repository identifier is invalid")
        repository_id = validate_identifier(repository_id_value, "repo")
        key = value.get("repository_key")
        root = value.get("root")
        common = value.get("common_git_dir")
        created_at = value.get("created_at")
        if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{64}", key):
            raise NoTugError("REPOSITORY_METADATA_INVALID", "Repository key is invalid")
        if (
            not isinstance(root, str)
            or not root
            or not isinstance(common, str)
            or not common
            or not isinstance(created_at, str)
            or not created_at
        ):
            raise NoTugError(
                "REPOSITORY_METADATA_INVALID", "Repository metadata values are invalid"
            )
        identity = cls(
            schema_version=1,
            repository_id=repository_id,
            repository_key=key,
            root=Path(root).resolve(),
            common_git_dir=Path(common).resolve(),
            created_at=created_at,
        )
        if repository_key(identity.root, identity.common_git_dir) != identity.repository_key:
            raise NoTugError(
                "REPOSITORY_METADATA_DIVERGENCE",
                "Stored repository paths do not match their identity binding",
                {"repository_id": repository_id},
            )
        return identity


def repository_metadata_hash(identity: RepositoryIdentity) -> str:
    """Bind the complete canonical repository record without exposing it in receipts."""

    return sha256_bytes(b"NoTUG.RepositoryMetadata.v1\0" + canonical_json_bytes(identity.to_dict()))


# Backwards-friendly name for callers that prefer the noun used by the protocol.
opaque_id = new_identifier
