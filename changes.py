"""Structural change collection from a disposable worktree.

Change classification is derived from Git objects and filesystem metadata.  Patch
text, commit messages, and repository prose are never interpreted as authority.
"""

from __future__ import annotations

import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .errors import NoTugError
from .git import (
    GitRepository,
    discover_repository,
    inert_filter_config_arguments,
    run_git,
    status_porcelain,
)
from .models import ChangeEntry
from .util import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    ensure_within,
    safe_git_path,
    sha256_bytes,
    sha256_file,
)


@dataclass(slots=True)
class SnapshotEvidence:
    baseline_commit: str
    snapshot_tree: str
    patch_path: Path
    patch_sha256: str
    patch_bytes: int
    workspace_manifest_path: Path
    workspace_manifest_hash: str
    changes: list[ChangeEntry]
    ignored_paths: list[str]
    file_count: int
    old_bytes: int
    new_bytes: int
    bytes_touched: int
    binary_count: int
    deletion_count: int
    rename_count: int

    def summary_dict(self) -> dict[str, Any]:
        return {
            "file_count": self.file_count,
            "old_bytes": self.old_bytes,
            "new_bytes": self.new_bytes,
            "bytes_touched": self.bytes_touched,
            "patch_bytes": self.patch_bytes,
            "binary_count": self.binary_count,
            "deletion_count": self.deletion_count,
            "rename_count": self.rename_count,
        }


@dataclass(frozen=True, slots=True)
class _SnapshotTreeEntry:
    mode: str
    object_type: str
    oid: str
    path: str


def _decode_path(raw: bytes) -> str:
    return raw.decode("utf-8", errors="surrogateescape")


def _parse_raw_diff(raw: bytes) -> list[dict[str, str | None]]:
    tokens = raw.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    records: list[dict[str, str | None]] = []
    index = 0
    while index < len(tokens):
        header = tokens[index]
        index += 1
        if not header.startswith(b":"):
            raise NoTugError("PROVENANCE_DIVERGENCE", "Git raw diff evidence is malformed")
        try:
            metadata = header[1:].decode("ascii").split()
        except UnicodeDecodeError as exc:
            raise NoTugError("PROVENANCE_DIVERGENCE", "Git raw metadata is not ASCII") from exc
        if len(metadata) != 5:
            raise NoTugError("PROVENANCE_DIVERGENCE", "Git raw diff header is incomplete")
        old_mode, new_mode, old_oid, new_oid, status = metadata
        if index >= len(tokens):
            raise NoTugError("PROVENANCE_DIVERGENCE", "Git raw diff path is missing")
        first_path = _decode_path(tokens[index])
        index += 1
        old_path: str | None = None
        path = first_path
        if status[:1] in {"R", "C"}:
            if index >= len(tokens):
                raise NoTugError("PROVENANCE_DIVERGENCE", "Git rename target is missing")
            old_path = first_path
            path = _decode_path(tokens[index])
            index += 1
        records.append(
            {
                "old_mode": old_mode,
                "new_mode": new_mode,
                "old_oid": old_oid,
                "new_oid": new_oid,
                "status": status,
                "old_path": old_path,
                "path": path,
            }
        )
    return records


def _parse_numstat(raw: bytes) -> dict[str, tuple[int | None, int | None]]:
    tokens = raw.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    result: dict[str, tuple[int | None, int | None]] = {}
    index = 0
    while index < len(tokens):
        record = tokens[index]
        index += 1
        fields = record.split(b"\t", 2)
        if len(fields) != 3:
            raise NoTugError("PROVENANCE_DIVERGENCE", "Git numstat evidence is malformed")
        added_raw, deleted_raw, path_raw = fields
        if path_raw == b"":
            if index + 1 >= len(tokens):
                raise NoTugError("PROVENANCE_DIVERGENCE", "Git rename numstat is incomplete")
            index += 1  # old path
            path_raw = tokens[index]  # new path
            index += 1
        path = _decode_path(path_raw)
        added = None if added_raw == b"-" else int(added_raw)
        deleted = None if deleted_raw == b"-" else int(deleted_raw)
        result[path] = (added, deleted)
    return result


def _blob_size(repo: Path, oid: str, mode: str) -> int:
    if set(oid) == {"0"} or mode == "000000" or mode == "160000":
        return 0
    raw = run_git(repo, ["cat-file", "-s", oid]).stdout.strip()
    try:
        return int(raw)
    except ValueError as exc:
        raise NoTugError("PROVENANCE_DIVERGENCE", "Git object size is malformed") from exc


def _blob_bytes(repo: Path, oid: str, mode: str) -> bytes:
    if set(oid) == {"0"} or mode in {"000000", "160000"}:
        return b""
    return run_git(repo, ["cat-file", "blob", oid]).stdout


def _parse_snapshot_tree(raw: bytes) -> dict[str, _SnapshotTreeEntry]:
    entries: dict[str, _SnapshotTreeEntry] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, path_raw = record.partition(b"\t")
        if not separator or not path_raw:
            raise NoTugError("PROVENANCE_DIVERGENCE", "Git snapshot tree evidence is malformed")
        try:
            fields = metadata.decode("ascii", errors="strict").split()
        except UnicodeDecodeError as exc:
            raise NoTugError(
                "PROVENANCE_DIVERGENCE", "Git snapshot tree metadata is not ASCII"
            ) from exc
        if len(fields) != 3:
            raise NoTugError("PROVENANCE_DIVERGENCE", "Git snapshot tree metadata is incomplete")
        mode, object_type, oid = fields
        if (
            mode not in {"100644", "100755", "120000", "160000"}
            or object_type != ("commit" if mode == "160000" else "blob")
            or len(oid) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in oid)
        ):
            raise NoTugError("PROVENANCE_DIVERGENCE", "Git snapshot tree entry is invalid")
        path = _decode_path(path_raw)
        if not path or path in entries:
            raise NoTugError(
                "PROVENANCE_DIVERGENCE", "Git snapshot tree contains an invalid path set"
            )
        entries[path] = _SnapshotTreeEntry(mode, object_type, oid, path)
    return entries


def _git_boolean(repo: Path, key: str) -> bool | None:
    result = run_git(repo, ["config", "--bool", "--get", key], check=False)
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        raise NoTugError(
            "PROVENANCE_DIVERGENCE", "Git filesystem capability configuration is invalid"
        )
    value = result.stdout.strip().lower()
    if value == b"true":
        return True
    if value == b"false":
        return False
    raise NoTugError(
        "PROVENANCE_DIVERGENCE", "Git filesystem capability configuration is malformed"
    )


def _is_gitlink_descendant(path: str, gitlinks: set[str]) -> bool:
    return any(path.startswith(f"{gitlink}/") for gitlink in gitlinks)


def _read_captured_workspace_bytes(
    worktree: Path, path: str, manifest_entry: dict[str, Any]
) -> bytes:
    safe, _ = safe_git_path(path)
    if not safe:
        raise NoTugError("PROVENANCE_DIVERGENCE", "A staged entry has an unsafe workspace path")
    candidate = worktree.joinpath(*PurePosixPath(path).parts)
    try:
        before = candidate.lstat()
        attributes = int(getattr(before, "st_file_attributes", 0))
        if attributes & 0x400 and not stat.S_ISLNK(before.st_mode):
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "A captured workspace entry became a reparse point",
            )
        kind = str(manifest_entry["kind"])
        if kind == "symlink":
            if not stat.S_ISLNK(before.st_mode):
                raise NoTugError(
                    "PROVENANCE_DIVERGENCE",
                    "A captured symlink changed kind before reconciliation",
                )
            payload = os.fsencode(os.readlink(candidate))
            after = candidate.lstat()
            if not stat.S_ISLNK(after.st_mode):
                raise NoTugError(
                    "PROVENANCE_DIVERGENCE",
                    "A captured symlink changed during reconciliation",
                )
        elif kind == "file":
            if not stat.S_ISREG(before.st_mode):
                raise NoTugError(
                    "PROVENANCE_DIVERGENCE",
                    "A captured file changed kind before reconciliation",
                )
            flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
            flags |= int(getattr(os, "O_NOFOLLOW", 0))
            descriptor = os.open(candidate, flags)
            try:
                opened_before = os.fstat(descriptor)
                if not stat.S_ISREG(opened_before.st_mode):
                    raise NoTugError(
                        "PROVENANCE_DIVERGENCE",
                        "A captured file changed kind during reconciliation",
                    )
                chunks: list[bytes] = []
                while chunk := os.read(descriptor, 1024 * 1024):
                    chunks.append(chunk)
                payload = b"".join(chunks)
                opened_after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after = candidate.lstat()
            identity_before = (before.st_dev, before.st_ino)
            if (
                identity_before != (opened_before.st_dev, opened_before.st_ino)
                or identity_before != (after.st_dev, after.st_ino)
                or opened_before.st_size != opened_after.st_size
                or opened_before.st_mtime_ns != opened_after.st_mtime_ns
                or not stat.S_ISREG(after.st_mode)
            ):
                raise NoTugError(
                    "PROVENANCE_DIVERGENCE",
                    "A captured file changed during reconciliation",
                )
            if bool(after.st_mode & stat.S_IXUSR) != bool(manifest_entry["executable"]):
                raise NoTugError(
                    "PROVENANCE_DIVERGENCE",
                    "A captured workspace mode changed during reconciliation",
                )
        else:
            raise NoTugError(
                "PROVENANCE_DIVERGENCE", "Captured workspace entry kind is unsupported"
            )
    except OSError as exc:
        raise NoTugError(
            "PROVENANCE_DIVERGENCE", "Captured workspace bytes could not be reconciled"
        ) from exc
    if manifest_entry["sha256"] != sha256_bytes(payload) or manifest_entry["size"] != len(payload):
        raise NoTugError(
            "PROVENANCE_DIVERGENCE",
            "Workspace bytes changed after the evidence manifest was captured",
        )
    return payload


def _filtered_blob_oid(
    worktree: Path,
    tree_entry: _SnapshotTreeEntry,
    payload: bytes,
    inert_arguments: list[str],
    index_environment: dict[str, str],
) -> str:
    arguments = [*inert_arguments, "hash-object"]
    if tree_entry.mode == "120000":
        arguments.append("--no-filters")
    else:
        arguments.append(f"--path={tree_entry.path}")
    arguments.append("--stdin")
    result = run_git(worktree, arguments, env=index_environment, input_bytes=payload)
    try:
        oid = result.stdout.decode("ascii", errors="strict").strip().lower()
    except UnicodeDecodeError as exc:
        raise NoTugError(
            "PROVENANCE_DIVERGENCE", "Git filtered blob identifier is not ASCII"
        ) from exc
    if (
        len(oid) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in oid)
        or oid != tree_entry.oid
    ):
        raise NoTugError(
            "PROVENANCE_DIVERGENCE",
            "Captured workspace bytes do not reproduce the staged Git blob",
        )
    return oid


def _verify_populated_gitlink(
    worktree: Path,
    tree_entry: _SnapshotTreeEntry,
    manifest_entries: dict[str, dict[str, Any]],
) -> None:
    descendants = [path for path in manifest_entries if path.startswith(f"{tree_entry.path}/")]
    nested_path = worktree.joinpath(*PurePosixPath(tree_entry.path).parts)
    nested_git = nested_path / ".git"
    if not descendants and not nested_git.exists() and not nested_git.is_symlink():
        # Uninitialized Gitlinks are normally absent or empty directories and
        # therefore have no file-manifest representation.
        return
    safe, _ = safe_git_path(tree_entry.path)
    if not safe:
        raise NoTugError(
            "PROVENANCE_DIVERGENCE", "A populated Gitlink has an unsafe workspace path"
        )
    try:
        nested = discover_repository(nested_path)
        if nested.root != nested_path.resolve() or nested.head != tree_entry.oid:
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "Populated Gitlink checkout does not match its staged pointer",
            )
        nested_inert_arguments = inert_filter_config_arguments(nested)
        index_records = run_git(
            nested.root,
            [*nested_inert_arguments, "ls-files", "-v", "-z"],
        ).stdout
        if any(
            len(record) < 3 or record[:2] != b"H "
            for record in index_records.split(b"\0")
            if record
        ):
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "Populated Gitlink checkout uses hidden or ambiguous index state",
            )
        if status_porcelain(nested):
            raise NoTugError(
                "PROVENANCE_DIVERGENCE", "Populated Gitlink checkout contains local changes"
            )
        ignored_nested = run_git(
            nested.root,
            [
                *nested_inert_arguments,
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ],
        ).stdout
        if ignored_nested:
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "Populated Gitlink checkout contains ignored local files",
            )
    except NoTugError as exc:
        if exc.code == "PROVENANCE_DIVERGENCE":
            raise
        raise NoTugError(
            "PROVENANCE_DIVERGENCE",
            "Populated Gitlink checkout cannot be reconciled with its staged pointer",
        ) from exc


def _reconcile_workspace_snapshot(
    worktree: Path,
    snapshot_tree: str,
    manifest: dict[str, Any],
    ignored_paths: list[str],
    inert_arguments: list[str],
    index_environment: dict[str, str],
) -> None:
    """Require the staged tree to represent the captured filesystem bytes exactly."""

    raw_tree = run_git(
        worktree,
        [*inert_arguments, "ls-tree", "-r", "--full-tree", "-z", snapshot_tree],
    ).stdout
    tree_entries = _parse_snapshot_tree(raw_tree)
    manifest_entries = {str(entry["path"]): entry for entry in manifest["entries"]}
    gitlinks = {path for path, tree_entry in tree_entries.items() if tree_entry.mode == "160000"}
    ignored = set(ignored_paths)

    for path in manifest_entries:
        if (
            manifest_entries[path].get("kind") != "directory"
            and path not in tree_entries
            and path not in ignored
            and not _is_gitlink_descendant(path, gitlinks)
        ):
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "Captured workspace entry is absent from the staged snapshot",
            )

    # Read symlink materialization in linked-worktree context; repositories
    # using extensions.worktreeConfig may override it per worktree.
    emulate_symlinks = _git_boolean(worktree, "core.symlinks") is False
    for path, tree_entry in tree_entries.items():
        if tree_entry.mode == "160000":
            # A Gitlink is an opaque commit pointer. Its checkout may be an empty
            # directory, an uninitialized path, or a populated nested worktree;
            # only the outer staged pointer is authoritative here.
            manifest_entry = manifest_entries.get(path)
            if manifest_entry is not None and manifest_entry.get("kind") != "directory":
                raise NoTugError(
                    "PROVENANCE_DIVERGENCE",
                    "Captured workspace entry disagrees with a staged Gitlink",
                )
            _verify_populated_gitlink(worktree, tree_entry, manifest_entries)
            continue

        manifest_entry = manifest_entries.get(path)
        if manifest_entry is None:
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "Staged snapshot entry is absent from the captured workspace",
            )
        expected_kind = "symlink" if tree_entry.mode == "120000" else "file"
        actual_kind = str(manifest_entry["kind"])
        if actual_kind != expected_kind and not (
            expected_kind == "symlink" and actual_kind == "file" and emulate_symlinks
        ):
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "Captured workspace entry kind disagrees with the staged snapshot",
            )
        payload = _read_captured_workspace_bytes(worktree, path, manifest_entry)
        _filtered_blob_oid(worktree, tree_entry, payload, inert_arguments, index_environment)
        # Do not trust core.fileMode=false to erase a real workspace mode
        # disagreement: the staged tree must reproduce the captured mode. On a
        # platform that cannot represent 100755 faithfully, ambiguity fails
        # closed instead of claiming byte-and-mode equivalence.
        if tree_entry.mode in {"100644", "100755"} and bool(manifest_entry["executable"]) != (
            tree_entry.mode == "100755"
        ):
            raise NoTugError(
                "PROVENANCE_DIVERGENCE",
                "Captured workspace mode disagrees with the staged snapshot",
            )


def _symlink_outside(worktree: Path, path: str, target: str) -> bool:
    windows_target = PureWindowsPath(target)
    posix_target = PurePosixPath(target)
    if windows_target.drive or windows_target.root or posix_target.is_absolute():
        return True

    def lexically_escapes(parent: tuple[str, ...], parts: tuple[str, ...]) -> bool:
        stack = [part for part in parent if part not in {"", ".", "\\", "/"}]
        for part in parts:
            if part in {"", ".", "\\", "/"}:
                continue
            if part == "..":
                if not stack:
                    return True
                stack.pop()
            else:
                stack.append(part)
        return False

    windows_parent = PureWindowsPath(path.replace("/", "\\")).parent.parts
    posix_parent = PurePosixPath(path.replace("\\", "/")).parent.parts
    if lexically_escapes(windows_parent, windows_target.parts) or lexically_escapes(
        posix_parent, posix_target.parts
    ):
        return True
    target_path = Path(target)
    if target_path.is_absolute():
        return True
    candidate = (worktree / Path(path).parent / target_path).resolve(strict=False)
    try:
        candidate.relative_to(worktree.resolve())
    except ValueError:
        return True
    return False


def _primary_kind(status: str) -> str:
    return {
        "A": "create",
        "M": "modify",
        "D": "delete",
        "R": "rename",
        "C": "copy",
        "T": "modify",
        "U": "modify",
    }.get(status[:1], "modify")


def _classify_record(
    repo: Path,
    worktree: Path,
    record: dict[str, str | None],
    numstat: dict[str, tuple[int | None, int | None]],
) -> ChangeEntry:
    path = str(record["path"])
    old_path = record["old_path"]
    old_mode = str(record["old_mode"])
    new_mode = str(record["new_mode"])
    old_oid = str(record["old_oid"])
    new_oid = str(record["new_oid"])
    status = str(record["status"])
    safe, reason = safe_git_path(path)
    classifications = ["unsafe_path", f"unsafe_path:{reason}"] if not safe else []
    if old_path is not None:
        old_safe, old_reason = safe_git_path(old_path)
        if not old_safe:
            classifications.extend(["unsafe_path", f"unsafe_old_path:{old_reason}"])
    kind = _primary_kind(status)
    classifications.append(kind)
    if old_mode != new_mode and old_mode != "000000" and new_mode != "000000":
        classifications.append("mode")
    if old_mode == "120000" or new_mode == "120000":
        classifications.append("symlink")
    if old_mode == "160000" or new_mode == "160000":
        classifications.append("submodule")
    old_size = _blob_size(repo, old_oid, old_mode)
    new_size = _blob_size(repo, new_oid, new_mode)
    added, deleted = numstat.get(path, (None, None))
    binary = added is None or deleted is None
    if not binary:
        old_blob = _blob_bytes(repo, old_oid, old_mode)[:8192]
        new_blob = _blob_bytes(repo, new_oid, new_mode)[:8192]
        binary = b"\0" in old_blob or b"\0" in new_blob
    if binary:
        classifications.append("binary")
    target: str | None = None
    outside = False
    if new_mode == "120000" and new_oid.strip("0"):
        target = _blob_bytes(repo, new_oid, new_mode).decode("utf-8", errors="surrogateescape")
        outside = _symlink_outside(worktree, path, target)
        if outside:
            classifications.append("outside_symlink")
    return ChangeEntry(
        kind=kind,
        path=path,
        old_path=old_path,
        status=status,
        old_mode=old_mode,
        new_mode=new_mode,
        old_oid=old_oid,
        new_oid=new_oid,
        binary=binary,
        submodule="submodule" in classifications,
        symlink_target=target,
        symlink_outside_workspace=outside,
        added_lines=added,
        deleted_lines=deleted,
        old_size=old_size,
        new_size=new_size,
        byte_delta=new_size - old_size,
        classifications=sorted(set(classifications)),
    )


def _workspace_manifest(worktree: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    root = worktree.resolve()
    for current_raw, directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_raw)
        if current == root:
            directories[:] = [name for name in directories if name != ".git"]
            files = [name for name in files if name != ".git"]
        directories.sort()
        files.sort()
        boundary_directories: list[str] = []
        for directory in list(directories):
            directory_path = current / directory
            info = directory_path.lstat()
            attributes = int(getattr(info, "st_file_attributes", 0))
            is_junction = bool(getattr(directory_path, "is_junction", lambda: False)())
            if directory_path.is_symlink() or attributes & 0x400 or is_junction:
                boundary_directories.append(directory)
                directories.remove(directory)
        names = [
            *(f"{name}/" for name in directories),
            *(f"{name}/" for name in boundary_directories),
            *files,
        ]
        for marked_name in names:
            name = marked_name[:-1] if marked_name.endswith("/") else marked_name
            path = current / name
            relative = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
            except OSError as exc:
                raise NoTugError(
                    "PROVENANCE_DIVERGENCE", "Workspace entry disappeared during evidence capture"
                ) from exc
            attributes = int(getattr(info, "st_file_attributes", 0))
            reparse = bool(attributes & 0x400)
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                payload = os.fsencode(target)
                kind = "symlink"
            elif reparse:
                try:
                    payload = os.fsencode(os.readlink(path))
                except OSError:
                    payload = b""
                kind = "reparse"
            elif stat.S_ISREG(info.st_mode):
                payload = b""
                kind = "file"
            elif stat.S_ISDIR(info.st_mode):
                payload = b""
                kind = "directory"
            else:
                payload = b""
                kind = "special"
            sha = (
                sha256_bytes(payload)
                if kind in {"symlink", "reparse"}
                else (sha256_file(path) if kind == "file" else sha256_bytes(b""))
            )
            entries.append(
                {
                    "path": relative,
                    "kind": kind,
                    "size": (
                        len(payload)
                        if kind == "symlink"
                        else (int(info.st_size) if kind in {"file", "reparse"} else 0)
                    ),
                    "sha256": sha,
                    "executable": bool(info.st_mode & stat.S_IXUSR),
                    "reparse_point": reparse,
                }
            )
    entries.sort(key=lambda item: str(item["path"]).encode("utf-8", errors="surrogateescape"))
    core = {"schema_version": 1, "entries": entries, "entry_count": len(entries)}
    return {**core, "manifest_hash": sha256_bytes(canonical_json_bytes(core))}


def prepare_snapshot(
    repository: GitRepository,
    worktree: Path,
    baseline_commit: str,
    artifact_directory: Path,
    vault_root: Path,
    *,
    patch_output: Path | None = None,
    workspace_manifest_output: Path | None = None,
) -> SnapshotEvidence:
    """Freeze the worktree into an immutable tree and evidence artifacts.

    The temporary index is vault-owned.  No branch or protected checkout is
    changed.  As with all linked worktrees, Git may add unreferenced objects to
    the repository's shared object database; authority remains with refs.
    """

    worktree = ensure_within(worktree, vault_root, code="WORKTREE_OUTSIDE_VAULT")
    artifact_directory.mkdir(parents=True, exist_ok=True)
    manifest = _workspace_manifest(worktree)
    casefolded_paths: dict[str, str] = {}
    for entry in manifest["entries"]:
        path = str(entry["path"])
        portable_key = path.casefold()
        existing = casefolded_paths.get(portable_key)
        if existing is not None and existing != path:
            raise NoTugError(
                "WINDOWS_PATH_COLLISION",
                "Workspace contains paths that collide on a case-insensitive filesystem",
                {"path_count": 2},
            )
        casefolded_paths[portable_key] = path
    unsafe_workspace_entries = [
        entry["path"] for entry in manifest["entries"] if entry["kind"] in {"reparse", "special"}
    ]
    if unsafe_workspace_entries:
        raise NoTugError(
            "UNSAFE_REPARSE_POINT",
            "Workspace contains a reparse point or special file that cannot be safely proposed",
            {"entry_count": len(unsafe_workspace_entries)},
        )
    index_path = artifact_directory / "snapshot.index"
    index_path.unlink(missing_ok=True)
    env = {"GIT_INDEX_FILE": str(index_path)}
    inert_arguments = inert_filter_config_arguments(
        worktree, hooks_path=vault_root / "trusted" / "empty-hooks"
    )
    ignored_raw = run_git(
        worktree,
        [
            *inert_arguments,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ],
    ).stdout
    ignored = sorted(
        (_decode_path(item) for item in ignored_raw.split(b"\0") if item),
        key=lambda value: value.encode("utf-8", errors="surrogateescape"),
    )
    try:
        run_git(worktree, [*inert_arguments, "read-tree", baseline_commit], env=env)
        add_arguments = [*inert_arguments, "add", "-A", "--", "."]
        run_git(worktree, add_arguments, env=env)
        snapshot_tree = (
            run_git(worktree, [*inert_arguments, "write-tree"], env=env)
            .stdout.decode("ascii")
            .strip()
        )
        _reconcile_workspace_snapshot(
            worktree,
            snapshot_tree,
            manifest,
            ignored,
            inert_arguments,
            env,
        )
    finally:
        index_path.unlink(missing_ok=True)
    patch = run_git(
        worktree,
        [
            *inert_arguments,
            "diff",
            "--binary",
            "--full-index",
            "--find-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            baseline_commit,
            snapshot_tree,
            "--",
        ],
    ).stdout
    raw = run_git(
        worktree,
        [
            *inert_arguments,
            "diff",
            "--raw",
            "-z",
            "--no-abbrev",
            "--find-renames",
            "--no-ext-diff",
            "--no-textconv",
            baseline_commit,
            snapshot_tree,
            "--",
        ],
    ).stdout
    numstat_raw = run_git(
        worktree,
        [
            *inert_arguments,
            "diff",
            "--numstat",
            "-z",
            "--find-renames",
            "--no-ext-diff",
            "--no-textconv",
            baseline_commit,
            snapshot_tree,
            "--",
        ],
    ).stdout
    records = _parse_raw_diff(raw)
    numstat = _parse_numstat(numstat_raw)
    changes = [_classify_record(repository.root, worktree, record, numstat) for record in records]
    changes.sort(
        key=lambda change: (change.path.encode("utf-8", errors="surrogateescape"), change.kind)
    )
    manifest_path = workspace_manifest_output or artifact_directory / "workspace-manifest.json"
    patch_path = patch_output or artifact_directory / "proposal.patch"
    atomic_write_json(manifest_path, manifest)
    atomic_write_bytes(patch_path, patch)
    return SnapshotEvidence(
        baseline_commit=baseline_commit,
        snapshot_tree=snapshot_tree,
        patch_path=patch_path,
        patch_sha256=sha256_bytes(patch),
        patch_bytes=len(patch),
        workspace_manifest_path=manifest_path,
        workspace_manifest_hash=str(manifest["manifest_hash"]),
        changes=changes,
        ignored_paths=ignored,
        file_count=len(changes),
        old_bytes=sum(change.old_size for change in changes),
        new_bytes=sum(change.new_size for change in changes),
        bytes_touched=sum(change.old_size + change.new_size for change in changes),
        binary_count=sum(change.binary for change in changes),
        deletion_count=sum(change.kind == "delete" for change in changes),
        rename_count=sum(change.kind == "rename" for change in changes),
    )


def changes_to_dict(changes: list[ChangeEntry]) -> list[dict[str, Any]]:
    return [asdict(change) for change in changes]
