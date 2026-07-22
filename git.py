"""Conservative Git plumbing used by the protocol boundary."""

from __future__ import annotations

import os
import re
import shutil
import signal
import stat
import subprocess
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .brand import PRODUCT_SHORT_NAME, VERSION
from .errors import NoTugError
from .resources import note_git_launch_attempt
from .util import sanitize_terminal

GIT_COMMAND_TIMEOUT_SECONDS = 30.0
_ACTIVE_GIT_PROCESSES: set[subprocess.Popen[bytes]] = set()
_ACTIVE_GIT_PROCESSES_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class GitResult:
    args: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class GitRepository:
    root: Path
    git_dir: Path
    common_git_dir: Path
    head: str
    head_tree: str
    branch: str | None
    object_format: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "git_dir": str(self.git_dir),
            "common_git_dir": str(self.common_git_dir),
            "head": self.head,
            "head_tree": self.head_tree,
            "branch": self.branch,
            "object_format": self.object_format,
        }


@dataclass(frozen=True, slots=True)
class WorktreeInfo:
    path: Path
    head: str | None
    branch: str | None
    detached: bool
    locked: bool
    prunable: bool


def _git_executable() -> str:
    executable = shutil.which("git")
    if executable is None:
        raise NoTugError("GIT_NOT_FOUND", "Git is not available on PATH")
    return executable


def _hidden_process_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) | int(
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    )


def _terminate_git_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Terminate and reap one registered Git child and its descendants."""

    if process.poll() is not None:
        process.wait()
        return
    if os.name == "nt":
        system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
        taskkill = system_root / "System32" / "taskkill.exe"
        if taskkill.is_file():
            with suppress(OSError, subprocess.TimeoutExpired):
                subprocess.run(
                    (str(taskkill), "/PID", str(process.pid), "/T", "/F"),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    shell=False,
                    timeout=5,
                    creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
                )
    else:
        kill_process_group = getattr(os, "killpg", None)
        terminate_signal = getattr(signal, "SIGTERM", None)
        if kill_process_group is not None and terminate_signal is not None:
            with suppress(OSError):
                kill_process_group(process.pid, terminate_signal)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            kill_process_group = getattr(os, "killpg", None)
            kill_signal = getattr(signal, "SIGKILL", None)
            if kill_process_group is not None and kill_signal is not None:
                with suppress(OSError):
                    kill_process_group(process.pid, kill_signal)
        else:
            process.kill()
        process.wait()


def terminate_active_git_processes() -> None:
    """Terminate only Git children launched and still owned by this process."""

    with _ACTIVE_GIT_PROCESSES_LOCK:
        processes = tuple(_ACTIVE_GIT_PROCESSES)
        _ACTIVE_GIT_PROCESSES.difference_update(processes)
    for process in processes:
        _terminate_git_process_tree(process)


def _run_git_child(
    command: tuple[str, ...],
    *,
    env: Mapping[str, str] | None,
    input_bytes: bytes | None,
    operation: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=dict(env) if env is not None else None,
            creationflags=_hidden_process_creation_flags(),
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise NoTugError("GIT_EXECUTION_FAILED", "Git could not be executed") from exc
    with _ACTIVE_GIT_PROCESSES_LOCK:
        _ACTIVE_GIT_PROCESSES.add(process)
    try:
        stdout, stderr = process.communicate(
            input=input_bytes,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        _terminate_git_process_tree(process)
        process.communicate()
        raise NoTugError(
            "GIT_COMMAND_TIMEOUT",
            "Git command exceeded the local execution time limit",
            {
                "operation": operation,
                "timeout_seconds": GIT_COMMAND_TIMEOUT_SECONDS,
            },
        ) from exc
    except BaseException:
        _terminate_git_process_tree(process)
        raise
    finally:
        with _ACTIVE_GIT_PROCESSES_LOCK:
            _ACTIVE_GIT_PROCESSES.discard(process)
    returncode = process.returncode
    if returncode is None:  # pragma: no cover - communicate() sets it for real Popen objects.
        raise NoTugError("GIT_EXECUTION_FAILED", "Git did not report an exit status")
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def run_git(
    repo: Path,
    args: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    input_bytes: bytes | None = None,
) -> GitResult:
    """Run Git without a shell and retain byte-exact output for safe parsers."""

    if isinstance(args, (str, bytes)) or not all(isinstance(argument, str) for argument in args):
        raise TypeError("Git arguments must be a sequence of strings")
    resolved_repo = Path(repo).resolve()
    if not resolved_repo.exists() or not resolved_repo.is_dir():
        raise NoTugError(
            "REPOSITORY_NOT_FOUND",
            "Repository path is not an accessible directory",
            {"path": str(repo)},
        )
    command = (
        _git_executable(),
        "-C",
        str(resolved_repo),
        # Codex-managed Windows workspaces can be owned by the sandbox SID while
        # Leucoform runs as the signed-in desktop user. Trust only this exact,
        # explicitly selected path for this child process; never mutate global
        # Git configuration or disable ownership checks for other repositories.
        "-c",
        f"safe.directory={resolved_repo}",
        "-c",
        "color.ui=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        *tuple(args),
    )
    child_env = os.environ.copy()
    # A caller's ambient Git routing must not silently replace the repository
    # selected by this operation. Explicit values supplied through ``env`` are
    # added after this cleanup (notably a vault-owned temporary index).
    for variable in (
        "GIT_ATTR_SOURCE",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_PREFIX",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_EXTERNAL_DIFF",
        "GIT_GLOB_PATHSPECS",
        "GIT_ICASE_PATHSPECS",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_LITERAL_PATHSPECS",
        "GIT_REPLACE_REF_BASE",
        "GIT_TEMPLATE_DIR",
    ):
        child_env.pop(variable, None)
    for variable in tuple(child_env):
        if variable.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "GIT_TRACE")):
            child_env.pop(variable, None)
    child_env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_LITERAL_PATHSPECS": "1",
            "LC_ALL": "C",
        }
    )
    if env:
        child_env.update({str(key): str(value) for key, value in env.items()})
    note_git_launch_attempt()
    completed = _run_git_child(
        command,
        env=child_env,
        input_bytes=input_bytes,
        operation=args[0] if args else "",
    )
    result = GitResult(tuple(args), completed.returncode, completed.stdout, completed.stderr)
    if check and result.returncode != 0:
        stderr = sanitize_terminal(result.stderr.decode("utf-8", errors="replace"), 1000).strip()
        raise NoTugError(
            "GIT_COMMAND_FAILED",
            "Git command failed",
            {
                "operation": args[0] if args else "",
                "returncode": result.returncode,
                "stderr": stderr,
            },
        )
    return result


def _text_output(result: GitResult, *, code: str = "GIT_OUTPUT_INVALID") -> str:
    try:
        return result.stdout.decode("utf-8", errors="strict").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise NoTugError(code, "Git returned non-UTF-8 structural output") from exc


def git_version() -> str:
    executable = _git_executable()
    note_git_launch_attempt()
    completed = _run_git_child(
        (executable, "--version"),
        env=None,
        input_bytes=None,
        operation="--version",
    )
    if completed.returncode != 0:
        raise NoTugError("GIT_COMMAND_FAILED", "Git version check failed")
    return completed.stdout.decode("utf-8", errors="replace").strip()


def ensure_trusted_empty_hooks_directory(path: Path) -> Path:
    """Create or verify a real, empty directory before selecting it for Git hooks."""

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() and not path.is_symlink():
            with suppress(FileExistsError):
                path.mkdir()
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        for boundary in (path.parent, path):
            metadata = boundary.lstat()
            attributes = int(getattr(metadata, "st_file_attributes", 0))
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or attributes & reparse_flag
            ):
                raise OSError("trusted hooks boundary is redirected or is not a directory")
        if next(path.iterdir(), None) is not None:
            raise OSError("trusted hooks directory is not empty")
        return path.resolve()
    except OSError as exc:
        raise NoTugError(
            "GIT_HOOKS_PATH_UNSAFE",
            "Trusted Git hooks directory is redirected, inaccessible, or not empty",
        ) from exc


def inert_filter_config_arguments(
    repo: Path | GitRepository, *, hooks_path: Path | None = None
) -> list[str]:
    """Disable external drivers and optionally select a trusted hooks directory."""

    result = run_git(
        _repo_path(repo),
        [
            "config",
            "--name-only",
            "--get-regexp",
            r"^(filter\..*\.(clean|smudge|process|required)|merge\..*\.(driver|recursive))$",
        ],
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise NoTugError("GIT_CONFIG_INVALID", "Git filter configuration could not be inspected")
    filter_names: set[str] = set()
    merge_names: set[str] = set()
    for raw_key in result.stdout.decode("utf-8", errors="strict").splitlines():
        filter_match = re.fullmatch(
            r"filter\.(.+)\.(?:clean|smudge|process|required)", raw_key, re.IGNORECASE
        )
        merge_match = re.fullmatch(r"merge\.(.+)\.(?:driver|recursive)", raw_key, re.IGNORECASE)
        match = filter_match or merge_match
        if match is not None:
            name = match.group(1)
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
                raise NoTugError(
                    "GIT_FILTER_CONFIG_UNSAFE",
                    "A configured Git filter or merge-driver name is unsafe",
                )
            (filter_names if filter_match is not None else merge_names).add(name)
    arguments: list[str] = []
    if hooks_path is not None:
        hooks_path = ensure_trusted_empty_hooks_directory(hooks_path)
        arguments.extend(["-c", f"core.hooksPath={hooks_path}"])
    for name in sorted(filter_names, key=str.casefold):
        arguments.extend(["-c", f"filter.{name}.clean="])
        arguments.extend(["-c", f"filter.{name}.smudge="])
        arguments.extend(["-c", f"filter.{name}.process="])
        arguments.extend(["-c", f"filter.{name}.required=false"])
    for name in sorted(merge_names, key=str.casefold):
        arguments.extend(["-c", f"merge.{name}.driver="])
        arguments.extend(["-c", f"merge.{name}.recursive=binary"])
    return arguments


def discover_repository(
    path: Path, *, require_clean: bool = False, require_attached: bool = False
) -> GitRepository:
    candidate = Path(path).expanduser().resolve()
    if not candidate.is_dir():
        raise NoTugError(
            "REPOSITORY_NOT_FOUND",
            "Repository path is not an accessible directory",
            {"path": str(path)},
        )
    probe = run_git(candidate, ["rev-parse", "--is-inside-work-tree"], check=False)
    if probe.returncode != 0:
        stderr = sanitize_terminal(
            probe.stderr.decode("utf-8", errors="replace"), 1000
        ).strip()
        if "not a git repository" in stderr.casefold():
            raise NoTugError(
                "NOT_A_GIT_REPOSITORY",
                f"{PRODUCT_SHORT_NAME} {VERSION} requires a Git working tree",
            )
        raise NoTugError(
            "GIT_REPOSITORY_PROBE_FAILED",
            "Git could not validate the selected working tree",
            {
                "operation": "rev-parse",
                "returncode": probe.returncode,
            },
        )
    inside_work_tree = _text_output(probe)
    if inside_work_tree not in {"true", "false"}:
        raise NoTugError(
            "GIT_OUTPUT_INVALID",
            "Git returned an invalid working-tree probe result",
        )
    bare_probe = run_git(candidate, ["rev-parse", "--is-bare-repository"], check=False)
    if bare_probe.returncode != 0:
        raise NoTugError(
            "GIT_REPOSITORY_PROBE_FAILED",
            "Git could not validate the selected repository type",
            {
                "operation": "rev-parse",
                "returncode": bare_probe.returncode,
            },
        )
    bare_repository = _text_output(bare_probe)
    if bare_repository not in {"true", "false"}:
        raise NoTugError(
            "GIT_OUTPUT_INVALID",
            "Git returned an invalid repository-type probe result",
        )
    if bare_repository == "true":
        raise NoTugError("BARE_REPOSITORY_UNSUPPORTED", "Bare repositories are not supported")
    if inside_work_tree != "true":
        raise NoTugError(
            "NOT_A_GIT_REPOSITORY",
            f"{PRODUCT_SHORT_NAME} {VERSION} requires a Git working tree",
        )
    try:
        root = Path(
            _text_output(
                run_git(candidate, ["rev-parse", "--path-format=absolute", "--show-toplevel"])
            )
        ).resolve()
        git_dir = Path(
            _text_output(run_git(candidate, ["rev-parse", "--path-format=absolute", "--git-dir"]))
        ).resolve()
        common_dir = Path(
            _text_output(
                run_git(candidate, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
            )
        ).resolve()
        head = resolve_commit(root, "HEAD")
        tree = _text_output(run_git(root, ["rev-parse", f"{head}^{{tree}}"])).strip()
    except NoTugError as exc:
        if exc.code in {"GIT_COMMAND_FAILED", "BASELINE_MISSING"}:
            raise NoTugError(
                "UNBORN_HEAD_UNSUPPORTED", "Repository must contain an initial commit"
            ) from exc
        raise
    branch = symbolic_ref(root)
    if require_attached and branch is None:
        raise NoTugError(
            "DETACHED_HEAD_UNSUPPORTED", "Session creation requires an attached branch"
        )
    object_result = run_git(root, ["rev-parse", "--show-object-format"], check=False)
    object_format = _text_output(object_result).strip() if object_result.returncode == 0 else "sha1"
    repository = GitRepository(root, git_dir, common_dir, head, tree, branch, object_format)
    if require_clean:
        require_clean_repository(repository)
    return repository


def _repo_path(repo: Path | GitRepository) -> Path:
    return repo.root if isinstance(repo, GitRepository) else Path(repo)


def status_porcelain(repo: Path | GitRepository) -> bytes:
    arguments = inert_filter_config_arguments(repo)
    arguments.extend(
        [
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ]
    )
    return run_git(
        _repo_path(repo),
        arguments,
    ).stdout


def is_clean(repo: Path | GitRepository) -> bool:
    return status_porcelain(repo) == b""


def require_clean_repository(repo: Path | GitRepository) -> None:
    status = status_porcelain(repo)
    if status:
        records = [entry for entry in status.split(b"\0") if entry]
        raise NoTugError(
            "SOURCE_REPOSITORY_DIRTY",
            "The protected repository has uncommitted or untracked changes",
            {"status_record_count": len(records)},
        )


# Natural shorthand used by lifecycle modules.
require_clean = require_clean_repository


def resolve_commit(repo: Path | GitRepository, revision: str = "HEAD") -> str:
    result = run_git(
        _repo_path(repo), ["rev-parse", "--verify", f"{revision}^{{commit}}"], check=False
    )
    if result.returncode != 0:
        raise NoTugError(
            "BASELINE_MISSING",
            "The requested Git commit does not exist",
            {"revision": sanitize_terminal(revision, 160)},
        )
    value = _text_output(result).strip()
    if not value or any(character not in "0123456789abcdef" for character in value.lower()):
        raise NoTugError("GIT_OUTPUT_INVALID", "Git returned an invalid commit identifier")
    return value.lower()


def commit_exists(repo: Path | GitRepository, commit: str) -> bool:
    result = run_git(_repo_path(repo), ["cat-file", "-e", f"{commit}^{{commit}}"], check=False)
    return result.returncode == 0


def head_commit(repo: Path | GitRepository) -> str:
    return resolve_commit(repo, "HEAD")


def symbolic_ref(repo: Path | GitRepository) -> str | None:
    result = run_git(_repo_path(repo), ["symbolic-ref", "--quiet", "HEAD"], check=False)
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        raise NoTugError("GIT_COMMAND_FAILED", "Git could not determine the current branch")
    return _text_output(result).strip()


def resolve_ref(repo: Path | GitRepository, ref: str) -> str | None:
    result = run_git(_repo_path(repo), ["show-ref", "--verify", "--hash", ref], check=False)
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        raise NoTugError("GIT_COMMAND_FAILED", "Git could not resolve the requested reference")
    return _text_output(result).strip().lower()


def worktree_list(repo: Path | GitRepository) -> list[WorktreeInfo]:
    raw = run_git(_repo_path(repo), ["worktree", "list", "--porcelain", "-z"]).stdout
    records: list[WorktreeInfo] = []
    current: dict[str, str | bool] = {}
    for field_bytes in raw.split(b"\0"):
        if not field_bytes:
            if current:
                records.append(_worktree_from_fields(current))
                current = {}
            continue
        try:
            field = field_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise NoTugError("GIT_OUTPUT_INVALID", "Worktree path is not valid UTF-8") from exc
        key, separator, value = field.partition(" ")
        current[key] = value if separator else True
    if current:
        records.append(_worktree_from_fields(current))
    return records


def _worktree_from_fields(fields: dict[str, str | bool]) -> WorktreeInfo:
    raw_path = fields.get("worktree")
    if not isinstance(raw_path, str) or not raw_path:
        raise NoTugError("GIT_OUTPUT_INVALID", "Git worktree record has no path")
    head = fields.get("HEAD")
    branch = fields.get("branch")
    return WorktreeInfo(
        # Preserve Git's lexical registration path. Callers performing a
        # destructive or provenance-sensitive comparison must not collapse a
        # symlink/junction alias onto another managed worktree.
        path=Path(os.path.abspath(raw_path)),
        head=head if isinstance(head, str) else None,
        branch=branch if isinstance(branch, str) else None,
        detached=bool(fields.get("detached", False)),
        locked=bool(fields.get("locked", False)),
        prunable=bool(fields.get("prunable", False)),
    )


def add_detached_worktree(
    repo: Path | GitRepository,
    destination: Path,
    commit: str,
    *,
    hooks_path: Path | None = None,
) -> None:
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise NoTugError(
            "WORKTREE_PATH_COLLISION",
            "Session worktree destination is not empty",
            {"path": str(destination)},
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    arguments = inert_filter_config_arguments(repo)
    arguments.extend(["-c", "advice.detachedHead=false"])
    if hooks_path is not None:
        hooks_path = ensure_trusted_empty_hooks_directory(hooks_path)
        arguments.extend(["-c", f"core.hooksPath={hooks_path}"])
    arguments.extend(["worktree", "add", "--detach", str(destination), commit])
    run_git(_repo_path(repo), arguments)


def remove_worktree(repo: Path | GitRepository, destination: Path, *, force: bool = False) -> None:
    arguments = ["worktree", "remove"]
    if force:
        arguments.append("--force")
    arguments.extend(["--", str(destination.resolve())])
    run_git(_repo_path(repo), arguments)
