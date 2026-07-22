"""Authoritative-to-presentation state for the Leucoform companion.

These values are presentation only. They never rename or extend NoTUG's
protocol state machine and they never confer authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class OrbState(StrEnum):
    IDLE = "idle"
    READY = "ready"
    WORKING = "working"
    VERIFYING = "verifying"
    REVIEW = "review"
    BLOCKED = "blocked"
    INTEGRATED = "integrated"
    DENIED = "denied"
    ABANDONED = "abandoned"
    CANCELLED = "cancelled"
    DIVERGED = "diverged"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class OrbAppearance:
    color: str
    glyph: str
    label: str
    shape: str = "rhombic-triacontahedron"
    pulse: bool = False
    luminous: bool = False


APPEARANCES: dict[OrbState, OrbAppearance] = {
    OrbState.IDLE: OrbAppearance("#8b96a8", "O", "Idle; protection available"),
    OrbState.READY: OrbAppearance("#18a8c7", "R", "Protected session ready"),
    OrbState.WORKING: OrbAppearance("#3976e8", ">", "Codex working in a managed session"),
    OrbState.VERIFYING: OrbAppearance("#8566d6", "V", "Freezing and verifying evidence"),
    OrbState.REVIEW: OrbAppearance(
        "#d84a5b",
        "!",
        "Human review required; three-part Grant ceremony available",
        shape="exploded-rhombic-triacontahedron",
        pulse=True,
    ),
    OrbState.BLOCKED: OrbAppearance(
        "#c28a21", "B", "Tug blocked by policy", shape="exploded-rhombic-triacontahedron"
    ),
    OrbState.INTEGRATED: OrbAppearance(
        "#f7fbff", "OK", "Applied and verified; receipt chain complete", luminous=True
    ),
    OrbState.DENIED: OrbAppearance("#c77b9c", "NO", "Tug denied; evidence retained"),
    OrbState.ABANDONED: OrbAppearance("#a9b2c1", "A", "Clean session abandoned; evidence retained"),
    OrbState.CANCELLED: OrbAppearance("#d4a72c", "II", "Agent run cancelled; review retained work"),
    OrbState.DIVERGED: OrbAppearance("#c72f45", "!=", "Protected evidence diverged"),
    OrbState.ERROR: OrbAppearance("#b3263e", "X", "Verification or evidence alert"),
}

STATE_PRECEDENCE: tuple[OrbState, ...] = (
    OrbState.DIVERGED,
    OrbState.ERROR,
    OrbState.BLOCKED,
    OrbState.REVIEW,
    OrbState.VERIFYING,
    OrbState.WORKING,
    OrbState.CANCELLED,
    OrbState.DENIED,
    OrbState.ABANDONED,
    OrbState.INTEGRATED,
    OrbState.READY,
    OrbState.IDLE,
)


def appearance_for(state: OrbState) -> OrbAppearance:
    return APPEARANCES[state]


def highest_priority(states: set[OrbState]) -> OrbState:
    """Choose a stable status when several repositories need attention."""

    for state in STATE_PRECEDENCE:
        if state in states:
            return state
    return OrbState.IDLE
