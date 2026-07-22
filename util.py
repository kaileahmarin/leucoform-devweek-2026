"""Small, dependency-free utilities with conservative filesystem behavior."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .brand import HOME_ENVIRONMENT_VARIABLE, VAULT_DIRECTORY_NAME
from .errors import NoTugError

CONTROL_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ud800-\udfff]"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)^(?:sk-[A-Za-z0-9_-]{12,}|gh[opsu]_[A-Za-z0-9]{20,}|xox[baprs]-\S+|bearer\s+\S+)$"
)
SECRET_FLAG_RE = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|private[_-]?key|credential)"
)
WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def read_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("duplicate JSON object key")
            value[key] = child
        return value

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {constant}")
            ),
        )
    except FileNotFoundError as exc:
        raise NoTugError(
            "ARTIFACT_MISSING", "Required local artifact is missing", {"path": str(path)}
        ) from exc
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise NoTugError(
            "ARTIFACT_CORRUPT", "Local JSON artifact is unreadable", {"path": str(path)}
        ) from exc
    if not isinstance(value, dict):
        raise NoTugError(
            "SCHEMA_INVALID", "JSON artifact must contain an object", {"path": str(path)}
        )
    return value


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(raw_temp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_bytes(path, canonical_json_bytes(value) + b"\n")


def atomic_create_json(path: Path, value: Any) -> None:
    """Create a complete JSON file without replacing any existing path."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(raw_temp)
    reserved = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            reservation = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except FileExistsError as exc:
            raise NoTugError(
                "EXPORT_PATH_EXISTS", "Receipt export destination already exists"
            ) from exc
        try:
            os.close(reservation)
            reserved = True
            os.replace(temp, path)
            reserved = False
        except BaseException:
            if reserved:
                path.unlink(missing_ok=True)
            raise
    finally:
        temp.unlink(missing_ok=True)


def data_home() -> Path:
    override = os.environ.get(HOME_ENVIRONMENT_VARIABLE)
    if override:
        try:
            configured = Path(override).expanduser()
        except (OSError, RuntimeError) as exc:
            raise NoTugError(
                "VAULT_HOME_INVALID",
                f"{HOME_ENVIRONMENT_VARIABLE} must expand to an absolute path",
            ) from exc
        if not configured.is_absolute():
            raise NoTugError(
                "VAULT_HOME_INVALID",
                f"{HOME_ENVIRONMENT_VARIABLE} must expand to an absolute path",
            )
        return configured.resolve()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return (Path(base) / VAULT_DIRECTORY_NAME).resolve()
    if sys_platform() == "darwin":
        return (Path.home() / "Library" / "Application Support" / VAULT_DIRECTORY_NAME).resolve()
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return (Path(xdg) / VAULT_DIRECTORY_NAME).resolve()
    return (Path.home() / ".local" / "share" / VAULT_DIRECTORY_NAME).resolve()


def sys_platform() -> str:
    import sys

    return sys.platform


def normalized_local_path(path: Path) -> str:
    value = str(path.resolve()).replace("\\", "/")
    return value.casefold() if os.name == "nt" else value


def ensure_within(path: Path, root: Path, *, code: str = "UNSAFE_PATH") -> Path:
    resolved = path.resolve()
    resolved_root = root.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise NoTugError(code, "Path escapes its permitted root", {"path": str(path)}) from exc
    return resolved


def safe_git_path(path: str) -> tuple[bool, str | None]:
    if not path or "\x00" in path:
        return False, "empty or NUL-containing path"
    if CONTROL_RE.search(path):
        return False, "control, directionality, or surrogate character"
    if "\\" in path:
        return False, "backslash is not portable in a Git path"
    normalized = path.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return False, "absolute path"
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False, "ambiguous path component"
    if parts[0].casefold() == ".git":
        return False, "Git metadata path"
    for part in parts:
        if any(character in '<>:"|?*' for character in part):
            return False, "Windows-forbidden path character"
        stem = part.split(".", 1)[0].upper()
        if stem in WINDOWS_RESERVED:
            return False, "Windows reserved path"
        if part.endswith((" ", ".")):
            return False, "Windows-ambiguous trailing character"
    return True, None


def sanitize_terminal(value: str, limit: int | None = None) -> str:
    def replacement(match: re.Match[str]) -> str:
        return f"\\u{ord(match.group(0)):04x}"

    sanitized = CONTROL_RE.sub(replacement, value)
    if limit is not None and len(sanitized) > limit:
        return sanitized[:limit] + "..."
    return sanitized


def redact_command(argv: list[str]) -> dict[str, Any]:
    redacted: list[str] = []
    hide_next = False
    for argument in argv:
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        if SECRET_VALUE_RE.fullmatch(argument):
            redacted.append("<redacted>")
            continue
        if argument.startswith("-") and SECRET_FLAG_RE.search(argument):
            if "=" in argument:
                redacted.append(argument.split("=", 1)[0] + "=<redacted>")
            else:
                redacted.append(argument)
                hide_next = True
            continue
        if "=" in argument and SECRET_FLAG_RE.search(argument.split("=", 1)[0]):
            redacted.append(argument.split("=", 1)[0] + "=<redacted>")
            continue
        redacted.append(sanitize_terminal(argument, 256))
    return {
        "executable": Path(argv[0]).name if argv else "",
        "arguments": redacted[1:],
        "argument_count": max(len(argv) - 1, 0),
    }
