"""Bounded normalization of Codex JSONL for human-readable live progress."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..util import sanitize_terminal

MAX_LINE_CHARACTERS = 256_000


@dataclass(frozen=True, slots=True)
class ActivityEvent:
    kind: str
    text: str
    raw_type: str | None = None


def _first_text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        for key in ("text", "message", "summary", "name", "command"):
            candidate = _first_text(value.get(key))
            if candidate:
                return candidate
    if isinstance(value, list):
        for item in value:
            candidate = _first_text(item)
            if candidate:
                return candidate
    return None


def normalize_jsonl_line(line: str) -> ActivityEvent:
    if len(line) > MAX_LINE_CHARACTERS:
        return ActivityEvent("warning", "Codex emitted an oversized event; details were omitted.")
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return ActivityEvent("warning", "Codex emitted malformed JSONL output.")
    if not isinstance(payload, dict):
        return ActivityEvent("event", "Codex reported progress.")
    raw_type = payload.get("type")
    event_type = str(raw_type) if isinstance(raw_type, str) else "event"
    text = _first_text(payload.get("item")) or _first_text(payload.get("message"))
    text = text or _first_text(payload.get("error")) or _first_text(payload.get("text"))
    if not text:
        text = event_type.replace("_", " ").replace(".", " · ").strip().capitalize()
    text = sanitize_terminal(text)
    if len(text) > 2_000:
        text = f"{text[:1997]}..."
    lowered = event_type.casefold()
    kind = "error" if "error" in lowered or "fail" in lowered else "event"
    return ActivityEvent(kind, text, event_type)


class JsonlNormalizer:
    """Accept arbitrarily chunked stdout without retaining a raw transcript."""

    def __init__(self) -> None:
        self._pending = ""

    def feed(self, chunk: str) -> tuple[ActivityEvent, ...]:
        self._pending += chunk
        lines = self._pending.splitlines(keepends=True)
        self._pending = ""
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._pending = lines.pop()
        if len(self._pending) > MAX_LINE_CHARACTERS:
            self._pending = ""
            lines.append('{"type":"warning","message":"Oversized partial event omitted"}\n')
        return tuple(normalize_jsonl_line(line.rstrip("\r\n")) for line in lines if line.strip())

    def finish(self) -> tuple[ActivityEvent, ...]:
        if not self._pending.strip():
            self._pending = ""
            return ()
        pending, self._pending = self._pending, ""
        return (normalize_jsonl_line(pending),)
