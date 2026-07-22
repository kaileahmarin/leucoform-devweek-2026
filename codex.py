"""Local-only Codex discovery and fixed Leucoform launch construction."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..errors import NoTugError


@dataclass(frozen=True, slots=True)
class CodexInstallation:
    argv: tuple[str, ...]
    display_path: str
    version: str
    source: str


def _npm_entrypoints() -> Iterable[Path]:
    appdata = os.environ.get("APPDATA")
    if appdata:
        yield Path(appdata) / "npm" / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
    program_files = os.environ.get("PROGRAMFILES")
    if program_files:
        yield (
            Path(program_files)
            / "nodejs"
            / "node_modules"
            / "@openai"
            / "codex"
            / "bin"
            / "codex.js"
        )


def _known_executables() -> Iterable[Path]:
    local = os.environ.get("LOCALAPPDATA")
    if local:
        base = Path(local)
        yield base / "Programs" / "Codex" / "resources" / "codex.exe"
        yield base / "Programs" / "Codex" / "resources" / "app" / "bin" / "codex.exe"
        yield base / "OpenAI" / "Codex" / "codex.exe"
    if os.name == "posix":
        yield Path("/Applications/Codex.app/Contents/Resources/codex")
        yield Path.home() / ".local" / "bin" / "codex"


def _node_command(entrypoint: Path) -> tuple[str, ...] | None:
    node = shutil.which("node") or shutil.which("node.exe")
    if node and entrypoint.is_file():
        return (str(Path(node).resolve()), str(entrypoint.resolve()))
    return None


def _selected_command(path: Path) -> tuple[str, ...] | None:
    suffix = path.suffix.casefold()
    if suffix == ".js":
        return _node_command(path)
    if suffix in {".cmd", ".bat", ".ps1"}:
        candidates = tuple(_npm_entrypoints())
        for entrypoint in candidates:
            command = _node_command(entrypoint)
            if command is not None:
                return command
        return None
    if path.is_file():
        return (str(path.resolve()),)
    return None


def _verify_candidate(command: tuple[str, ...], source: str) -> CodexInstallation | None:
    try:
        completed = subprocess.run(
            [*command, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=8,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = completed.stdout.strip().splitlines()
    version = output[0][:160] if output else "version unavailable"
    if completed.returncode != 0 or "codex" not in version.casefold():
        return None
    return CodexInstallation(command, command[-1], version, source)


def discover_codex(selected_path: Path | None = None) -> CodexInstallation:
    """Find and execute only a verified local Codex installation; never download it."""

    candidates: list[tuple[tuple[str, ...], str]] = []
    if selected_path is not None:
        selected = _selected_command(selected_path.expanduser())
        if selected is not None:
            candidates.append((selected, "selected"))
    path_codex = shutil.which("codex") or shutil.which("codex.exe")
    if path_codex:
        selected = _selected_command(Path(path_codex))
        if selected is not None:
            candidates.append((selected, "PATH"))
    for executable in _known_executables():
        selected = _selected_command(executable)
        if selected is not None:
            candidates.append((selected, "Codex Desktop"))
    for entrypoint in _npm_entrypoints():
        selected = _node_command(entrypoint)
        if selected is not None:
            candidates.append((selected, "official npm package"))
    seen: set[tuple[str, ...]] = set()
    for command, source in candidates:
        normalized = tuple(os.path.normcase(item) for item in command)
        if normalized in seen:
            continue
        seen.add(normalized)
        installation = _verify_candidate(command, source)
        if installation is not None:
            return installation
    raise NoTugError(
        "CODEX_NOT_FOUND",
        "Select an existing Codex executable or install the official Codex CLI; "
        "Leucoform never downloads Codex.",
    )


def build_codex_command(installation: CodexInstallation) -> tuple[str, ...]:
    """Return the fixed, stdin-only command; NoTUG Core inserts the exact -C binding."""

    return (
        *installation.argv,
        "--ask-for-approval",
        "never",
        "exec",
        "--ephemeral",
        "--sandbox",
        "workspace-write",
        "--json",
        "--color",
        "never",
        "-",
    )
