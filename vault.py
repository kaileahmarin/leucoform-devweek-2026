"""Short, local, strictly validated vault layout and transition locks."""

from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .brand import POLICY_FILENAME, PRODUCT_SHORT_NAME, VAULT_FORMAT
from .config import create_or_load_policy
from .errors import NoTugError
from .git import GitRepository
from .identity import RepositoryIdentity, repository_key, validate_identifier
from .util import atomic_write_json, canonical_json_bytes, data_home, utc_now

VAULT_SCHEMA_FIELDS = {"schema_version", "format"}
INDEX_FIELDS = {"schema_version", "repositories"}


def _schema_one(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == 1


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = child
    return value


def _read_strict_object(path: Path, *, code: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {constant}")
            ),
        )
    except FileNotFoundError as exc:
        raise NoTugError(code, "Required vault metadata is missing", {"path": str(path)}) from exc
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise NoTugError(
            code, "Vault metadata is not strict UTF-8 JSON", {"path": str(path)}
        ) from exc
    if not isinstance(value, dict):
        raise NoTugError(code, "Vault metadata must contain a JSON object", {"path": str(path)})
    if raw != canonical_json_bytes(value) + b"\n":
        raise NoTugError(
            code,
            "Vault metadata is not in its canonical on-disk representation",
            {"path": str(path)},
        )
    return value


class _FileLock:
    def __init__(self, path: Path, *, code: str = "VAULT_LOCKED") -> None:
        self.path = path
        self.code = code
        self._token = secrets.token_hex(16)
        self._owned = False

    def __enter__(self) -> _FileLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = (
            canonical_json_bytes(
                {"pid": os.getpid(), "started_at": utc_now(), "token": self._token}
            )
            + b"\n"
        )
        try:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except FileExistsError as exc:
            raise NoTugError(
                self.code,
                f"Another {PRODUCT_SHORT_NAME} transition holds the local repository lock",
                {"lock_path": str(self.path)},
            ) from exc
        except OSError as exc:
            raise NoTugError("VAULT_PERMISSION_DENIED", "Vault lock could not be created") from exc
        try:
            os.write(descriptor, record)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._owned = True
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if not self._owned:
            return
        try:
            try:
                current = _read_strict_object(self.path, code="VAULT_LOCK_DIVERGENCE")
            except NoTugError:
                if exc_type is None:
                    raise
                return
            if current.get("token") != self._token:
                if exc_type is None:
                    raise NoTugError(
                        "VAULT_LOCK_DIVERGENCE", "Repository lock changed during a transition"
                    )
                return
            self.path.unlink()
        finally:
            self._owned = False


class Vault:
    """Versioned local metadata and worktree paths.

    Passing ``root`` uses that directory directly as the v1 root. The default is
    the OS data directory followed by a short ``v1`` segment.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = (Path(root) if root is not None else data_home() / "v1").expanduser().resolve()

    @property
    def descriptor_path(self) -> Path:
        return self.root / "vault.json"

    @property
    def index_path(self) -> Path:
        return self.root / "index.json"

    @property
    def repositories_dir(self) -> Path:
        return self.root / "r"

    @property
    def worktrees_dir(self) -> Path:
        return self.root / "w"

    def ensure(self) -> Vault:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.repositories_dir.mkdir(exist_ok=True, mode=0o700)
        self.worktrees_dir.mkdir(exist_ok=True, mode=0o700)
        if self.descriptor_path.exists():
            descriptor = _read_strict_object(self.descriptor_path, code="VAULT_METADATA_INVALID")
            if (
                set(descriptor) != VAULT_SCHEMA_FIELDS
                or not _schema_one(descriptor.get("schema_version"))
                or descriptor.get("format") != VAULT_FORMAT
            ):
                raise NoTugError("VAULT_METADATA_INVALID", "Vault descriptor schema is invalid")
        else:
            atomic_write_json(self.descriptor_path, {"schema_version": 1, "format": VAULT_FORMAT})
        if self.index_path.exists():
            self._load_index()
        else:
            atomic_write_json(self.index_path, {"schema_version": 1, "repositories": {}})
        return self

    def _load_index(self) -> dict[str, str]:
        value = _read_strict_object(self.index_path, code="VAULT_INDEX_INVALID")
        if set(value) != INDEX_FIELDS or not _schema_one(value.get("schema_version")):
            raise NoTugError("VAULT_INDEX_INVALID", "Vault repository index schema is invalid")
        repositories = value.get("repositories")
        if not isinstance(repositories, dict):
            raise NoTugError("VAULT_INDEX_INVALID", "Vault repository index is invalid")
        for key, repository_id in repositories.items():
            if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{64}", key):
                raise NoTugError("VAULT_INDEX_INVALID", "Vault repository lookup key is invalid")
            validate_identifier(repository_id, "repo")
        return dict(repositories)

    def ensure_external(self, repository_root: Path) -> None:
        root = repository_root.resolve()
        vault = self.root.resolve()
        try:
            vault.relative_to(root)
        except ValueError:
            pass
        else:
            raise NoTugError(
                "VAULT_INSIDE_REPOSITORY",
                f"The local {PRODUCT_SHORT_NAME} vault must be outside the protected repository",
                {"vault": str(vault)},
            )
        try:
            root.relative_to(vault)
        except ValueError:
            return
        raise NoTugError(
            "REPOSITORY_INSIDE_VAULT",
            f"A {PRODUCT_SHORT_NAME} worktree cannot be initialized as the protected repository",
        )

    def register_repository(self, repository: GitRepository) -> RepositoryIdentity:
        self.ensure_external(repository.root)
        self.ensure()
        key = repository_key(repository.root, repository.common_git_dir)
        with _FileLock(self.root / "locks" / "index.lock", code="VAULT_INDEX_LOCKED"):
            index = self._load_index()
            existing = index.get(key)
            if existing is not None:
                identity = self.load_repository(existing)
                if identity.repository_key != key:
                    raise NoTugError(
                        "REPOSITORY_METADATA_DIVERGENCE",
                        "Repository index and metadata disagree",
                    )
                self._ensure_worktree_parents(existing)
                return identity
            identity = RepositoryIdentity.create(repository.root, repository.common_git_dir)
            directory = self.repository_dir(identity.repository_id)
            directory.mkdir(parents=True, exist_ok=False, mode=0o700)
            for child in (
                "policy",
                "sessions",
                "tugs",
                "patches",
                "changes",
                "grants",
                "operations",
                "manifests",
                "policies",
                "locks",
            ):
                (directory / child).mkdir(mode=0o700)
            atomic_write_json(directory / "repository.json", identity.to_dict())
            create_or_load_policy(self.policy_path(identity.repository_id))
            self._ensure_worktree_parents(identity.repository_id)
            index[key] = identity.repository_id
            atomic_write_json(self.index_path, {"schema_version": 1, "repositories": index})
            return identity

    def _ensure_worktree_parents(self, repository_id: str) -> None:
        validate_identifier(repository_id, "repo")
        base = self.worktrees_dir / repository_id
        for segment in ("s", "i", "r"):
            (base / segment).mkdir(parents=True, exist_ok=True, mode=0o700)

    def find_repository(self, repository: GitRepository) -> RepositoryIdentity | None:
        # Read-only callers (notably doctor and verify) must not initialize or
        # repair a vault as a side effect of inspection.
        if not self.descriptor_path.is_file() or not self.index_path.is_file():
            return None
        descriptor = _read_strict_object(self.descriptor_path, code="VAULT_METADATA_INVALID")
        if (
            set(descriptor) != VAULT_SCHEMA_FIELDS
            or not _schema_one(descriptor.get("schema_version"))
            or descriptor.get("format") != VAULT_FORMAT
        ):
            raise NoTugError("VAULT_METADATA_INVALID", "Vault descriptor schema is invalid")
        key = repository_key(repository.root, repository.common_git_dir)
        repository_id = self._load_index().get(key)
        if repository_id is None:
            return None
        identity = self.load_repository(repository_id)
        if identity.repository_key != key:
            raise NoTugError(
                "REPOSITORY_METADATA_DIVERGENCE",
                "Repository index and identity record disagree",
            )
        return identity

    def load_repository(self, repository_id: str) -> RepositoryIdentity:
        validate_identifier(repository_id, "repo")
        value = _read_strict_object(
            self.repository_dir(repository_id) / "repository.json",
            code="REPOSITORY_METADATA_INVALID",
        )
        identity = RepositoryIdentity.from_dict(value)
        if identity.repository_id != repository_id:
            raise NoTugError(
                "REPOSITORY_METADATA_DIVERGENCE", "Repository directory and metadata disagree"
            )
        return identity

    @contextmanager
    def locked(self, repository_id: str) -> Iterator[None]:
        validate_identifier(repository_id, "repo")
        with _FileLock(self.repository_dir(repository_id) / "locks" / "transition.lock"):
            yield

    def repository_dir(self, repository_id: str) -> Path:
        validate_identifier(repository_id, "repo")
        return self.repositories_dir / repository_id

    def policy_path(self, repository_id: str) -> Path:
        return self.repository_dir(repository_id) / "policy" / POLICY_FILENAME

    def events_path(self, repository_id: str) -> Path:
        return self.repository_dir(repository_id) / "events.jsonl"

    def chain_head_path(self, repository_id: str) -> Path:
        return self.repository_dir(repository_id) / "chain-head.json"

    def event_lock_path(self, repository_id: str) -> Path:
        return self.repository_dir(repository_id) / "locks" / "events.lock"

    def session_path(self, repository_id: str, session_id: str) -> Path:
        validate_identifier(session_id, "session")
        return self.repository_dir(repository_id) / "sessions" / f"{session_id}.json"

    def tug_path(self, repository_id: str, tug_id: str) -> Path:
        validate_identifier(tug_id, "tug")
        return self.repository_dir(repository_id) / "tugs" / f"{tug_id}.json"

    def patch_path(self, repository_id: str, tug_id: str) -> Path:
        validate_identifier(tug_id, "tug")
        return self.repository_dir(repository_id) / "patches" / f"{tug_id}.patch"

    def changes_path(self, repository_id: str, tug_id: str) -> Path:
        validate_identifier(tug_id, "tug")
        return self.repository_dir(repository_id) / "changes" / f"{tug_id}.json"

    def manifest_path(self, repository_id: str, manifest_hash: str) -> Path:
        if not isinstance(manifest_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", manifest_hash):
            raise NoTugError("MANIFEST_HASH_INVALID", "Manifest hash is invalid")
        return self.repository_dir(repository_id) / "manifests" / f"{manifest_hash}.json"

    def policy_snapshot_path(self, repository_id: str, policy_hash: str) -> Path:
        if not isinstance(policy_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", policy_hash):
            raise NoTugError("POLICY_HASH_INVALID", "Policy hash is invalid")
        return self.repository_dir(repository_id) / "policies" / f"{policy_hash}.toml"

    def grant_path(self, repository_id: str, grant_id: str) -> Path:
        validate_identifier(grant_id, "grant")
        return self.repository_dir(repository_id) / "grants" / f"{grant_id}.json"

    def operation_path(self, repository_id: str, operation_id: str) -> Path:
        validate_identifier(operation_id, "operation")
        return self.repository_dir(repository_id) / "operations" / f"{operation_id}.json"

    def worktree_path(self, repository_id: str, kind: str, entity_id: str) -> Path:
        validate_identifier(repository_id, "repo")
        prefixes = {
            "session": ("s", "session"),
            "integration": ("i", "grant"),
            "revert": ("r", "revoke"),
        }
        try:
            segment, prefix = prefixes[kind]
        except KeyError as exc:
            raise NoTugError("WORKTREE_KIND_INVALID", "Unknown managed worktree kind") from exc
        validate_identifier(entity_id, prefix)
        return self.worktrees_dir / repository_id / segment / entity_id


# Name retained for callers that describe the path provider rather than the store.
VaultLayout = Vault
