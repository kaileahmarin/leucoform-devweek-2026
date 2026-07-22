"""Explicit protocol state and evidence models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class State(StrEnum):
    LOCKED = "LOCKED"
    SESSION_OPEN = "SESSION_OPEN"
    TUGGED = "TUGGED"
    GRANTED = "GRANTED"
    APPLIED = "APPLIED"
    DENIED = "DENIED"
    ABANDONED = "ABANDONED"
    REVOKED = "REVOKED"
    DIVERGED = "DIVERGED"
    FAILED = "FAILED"


class ChangeKind(StrEnum):
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"
    COPY = "copy"
    MODE = "mode"
    SYMLINK = "symlink"
    SUBMODULE = "submodule"
    BINARY = "binary"


@dataclass(slots=True)
class ManifestEntry:
    path: str
    mode: str
    git_oid: str
    sha256: str
    size: int
    kind: str = "file"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ChangeEntry:
    kind: str
    path: str
    old_path: str | None = None
    status: str = ""
    old_mode: str | None = None
    new_mode: str | None = None
    old_oid: str | None = None
    new_oid: str | None = None
    binary: bool = False
    submodule: bool = False
    symlink_target: str | None = None
    symlink_outside_workspace: bool = False
    added_lines: int | None = None
    deleted_lines: int | None = None
    old_size: int = 0
    new_size: int = 0
    byte_delta: int = 0
    classifications: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PolicyFinding:
    code: str
    severity: str
    message: str
    paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


ALLOWED_TRANSITIONS: dict[State, set[State]] = {
    State.LOCKED: {State.SESSION_OPEN},
    State.SESSION_OPEN: {State.TUGGED, State.ABANDONED, State.DIVERGED, State.FAILED},
    State.TUGGED: {State.GRANTED, State.DENIED, State.DIVERGED, State.FAILED},
    State.GRANTED: {State.APPLIED, State.FAILED},
    State.APPLIED: {State.REVOKED, State.FAILED},
    State.DENIED: set(),
    State.ABANDONED: set(),
    State.REVOKED: set(),
    State.DIVERGED: set(),
    State.FAILED: set(),
}


def assert_transition(current: str, target: str) -> None:
    from .errors import NoTugError

    try:
        current_state = State(current)
        target_state = State(target)
    except ValueError as exc:
        raise NoTugError("STATE_INVALID", "Unknown protocol state") from exc
    if target_state not in ALLOWED_TRANSITIONS[current_state]:
        raise NoTugError(
            "STATE_TRANSITION_INVALID",
            f"Cannot transition from {current_state} to {target_state}",
            {"current": current_state, "target": target_state},
        )
