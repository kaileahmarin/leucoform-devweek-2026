"""Submission-only privacy helpers; runtime receipts do not depend on this module."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

_LOCAL_METADATA_KEYS = frozenset({"metadata_location", "direct_url"})
_PRIVATE_PATH = re.compile(
    r"(?i)(?:[a-z]:[\\/]users[\\/]|/users/|/home/|file:///|onedrive|\.codex[\\/]sessions)"
)


def _without_local_metadata(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _without_local_metadata(item)
            for key, item in value.items()
            if str(key) not in _LOCAL_METADATA_KEYS
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_without_local_metadata(item) for item in value]
    return value


def sanitize_dependency_inventory(data: Mapping[str, Any]) -> dict[str, Any]:
    """Remove local installation provenance and reject remaining profile paths."""

    sanitized = _without_local_metadata(data)
    if not isinstance(sanitized, dict):  # pragma: no cover - mapping input guarantees this.
        raise TypeError("dependency inventory must remain an object")
    encoded = json.dumps(sanitized, ensure_ascii=False, sort_keys=True)
    match = _PRIVATE_PATH.search(encoded)
    if match is not None:
        raise ValueError(f"dependency inventory contains private path marker: {match.group(0)}")
    return sanitized
