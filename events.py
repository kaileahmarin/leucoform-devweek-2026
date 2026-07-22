"""Append-only, domain-separated JSONL event receipts with a tail anchor."""

from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import NoTugError
from .identity import new_identifier, validate_identifier
from .models import assert_transition
from .util import atomic_write_json, canonical_json_bytes, sha256_bytes, utc_now

EVENT_DOMAIN = b"NoTUG.Event.v1\0"
EVENT_FIELDS = {
    "schema_version",
    "sequence",
    "event_id",
    "event_type",
    "occurred_at",
    "repository_id",
    "entity_type",
    "entity_id",
    "state_from",
    "state_to",
    "payload",
    "previous_event_hash",
    "event_hash",
}
HEAD_FIELDS = {"schema_version", "sequence", "event_hash", "file_size"}
HASH_RE = re.compile(r"^[a-f0-9]{64}$")
LABEL_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
ENTITY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
PAYLOAD_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_EVENT_BYTES = 16 * 1024
MAX_PAYLOAD_DEPTH = 4

_PROHIBITED_PAYLOAD_KEYS = {
    "argument",
    "arguments",
    "argv",
    "body",
    "content",
    "contents",
    "credential",
    "diff",
    "environment",
    "env",
    "file_bytes",
    "file_content",
    "patch",
    "password",
    "private_key",
    "prompt",
    "response",
    "secret",
    "stderr",
    "stdout",
    "token",
}
_SAFE_SUMMARY_KEYS = {"argument_count", "arguments_sha256"}
_ALLOWED_PAYLOAD_KEYS = {
    "application_metadata_sha256",
    "argument_count",
    "arguments_sha256",
    "archived_at",
    "baseline_commit",
    "baseline_manifest_hash",
    "binding_hash",
    "branch",
    "change_count",
    "changed_bytes",
    "changed_files",
    "command_sha256",
    "commit",
    "disposition",
    "disposition_state",
    "ended_at",
    "executable",
    "exit_status",
    "failure_metadata_sha256",
    "finding_codes",
    "grant_id",
    "grant_metadata_sha256",
    "manifest_hash",
    "operation_id",
    "patch_sha256",
    "policy_hash",
    "reason_code",
    "receipt_head",
    "repository_key",
    "repository_metadata_sha256",
    "revoke_id",
    "revoke_metadata_sha256",
    "run_id",
    "session_id",
    "session_metadata_sha256",
    "snapshot_tree",
    "started_at",
    "tug_hash",
    "tug_id",
    "validation_count",
    "validation_sha256",
    "workspace_manifest_hash",
}


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = child
    return value


def _strict_json_object(raw: bytes, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid constant: {constant}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise NoTugError(code, "Event evidence is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise NoTugError(code, "Event evidence must contain a JSON object")
    return value


def _validate_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise NoTugError("EVENT_SCHEMA_INVALID", "Event timestamp must be UTC")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise NoTugError("EVENT_SCHEMA_INVALID", "Event timestamp is invalid") from exc
    return value


def _validate_payload_value(value: Any, *, key: str = "payload", depth: int = 0) -> None:
    if depth > MAX_PAYLOAD_DEPTH:
        raise NoTugError("EVENT_MINIMISATION_FAILED", "Event payload is too deeply nested")
    if isinstance(value, dict):
        for child_key, child in value.items():
            if not isinstance(child_key, str) or not PAYLOAD_KEY_RE.fullmatch(child_key):
                raise NoTugError("EVENT_MINIMISATION_FAILED", "Event payload key is invalid")
            lowered = child_key.casefold()
            hash_only = lowered.endswith(("_hash", "_sha256"))
            if (
                lowered not in _SAFE_SUMMARY_KEYS
                and not hash_only
                and (
                    lowered in _PROHIBITED_PAYLOAD_KEYS
                    or any(
                        lowered.startswith(f"{name}_") or lowered.endswith(f"_{name}")
                        for name in _PROHIBITED_PAYLOAD_KEYS
                    )
                )
            ):
                raise NoTugError(
                    "EVENT_MINIMISATION_FAILED",
                    "Raw content and secret-like fields are prohibited in event receipts",
                    {"field": child_key},
                )
            if depth == 0 and lowered not in _ALLOWED_PAYLOAD_KEYS:
                raise NoTugError(
                    "EVENT_SCHEMA_INVALID",
                    "Event payload field is not allowlisted",
                    {"field": child_key},
                )
            _validate_payload_value(child, key=child_key, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise NoTugError("EVENT_MINIMISATION_FAILED", "Event payload list is too large")
        for child in value:
            _validate_payload_value(child, key=key, depth=depth + 1)
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, str):
        if len(value) > 1024 or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise NoTugError(
                "EVENT_MINIMISATION_FAILED",
                "Event payload strings must be short control-free facts",
            )
        return
    raise NoTugError(
        "EVENT_MINIMISATION_FAILED", "Event payload contains an unsupported value type"
    )


def _event_hash(core: dict[str, Any]) -> str:
    return sha256_bytes(EVENT_DOMAIN + canonical_json_bytes(core))


def _validate_event(value: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(value) - EVENT_FIELDS)
    missing = sorted(EVENT_FIELDS - set(value))
    if unknown or missing:
        raise NoTugError(
            "EVENT_SCHEMA_INVALID",
            "Event fields do not match schema version 1",
            {"unknown_fields": unknown, "missing_fields": missing},
        )
    schema_version = value.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        raise NoTugError("EVENT_SCHEMA_INVALID", "Unsupported event schema version")
    sequence = value.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise NoTugError("EVENT_SCHEMA_INVALID", "Event sequence must be positive")
    for field, prefix in (
        ("event_id", "event"),
        ("repository_id", "repo"),
        ("entity_id", None),
    ):
        identifier = value.get(field)
        if not isinstance(identifier, str):
            raise NoTugError("EVENT_SCHEMA_INVALID", f"Event {field} is invalid")
        validate_identifier(identifier, prefix)
    if not isinstance(value.get("event_type"), str) or not LABEL_RE.fullmatch(value["event_type"]):
        raise NoTugError("EVENT_SCHEMA_INVALID", "Event type is invalid")
    if not isinstance(value.get("entity_type"), str) or not ENTITY_RE.fullmatch(
        value["entity_type"]
    ):
        raise NoTugError("EVENT_SCHEMA_INVALID", "Event entity type is invalid")
    _validate_timestamp(value.get("occurred_at"))
    for state_field in ("state_from", "state_to"):
        state = value.get(state_field)
        if state is not None and (not isinstance(state, str) or not LABEL_RE.fullmatch(state)):
            raise NoTugError("EVENT_SCHEMA_INVALID", "Event state label is invalid")
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise NoTugError("EVENT_SCHEMA_INVALID", "Event payload must be an object")
    _validate_payload_value(payload)
    previous = value.get("previous_event_hash")
    if previous is not None and (not isinstance(previous, str) or not HASH_RE.fullmatch(previous)):
        raise NoTugError("EVENT_SCHEMA_INVALID", "Previous event hash is invalid")
    supplied = value.get("event_hash")
    if not isinstance(supplied, str) or not HASH_RE.fullmatch(supplied):
        raise NoTugError("EVENT_SCHEMA_INVALID", "Event hash is invalid")
    core = dict(value)
    del core["event_hash"]
    if _event_hash(core) != supplied:
        raise NoTugError("RECEIPT_CHAIN_INVALID", "Event content hash does not verify")
    if len(canonical_json_bytes(value)) > MAX_EVENT_BYTES:
        raise NoTugError("EVENT_SCHEMA_INVALID", "Event exceeds the local size limit")
    return value


@dataclass(frozen=True, slots=True)
class EventVerification:
    count: int
    head_hash: str | None
    events: tuple[dict[str, Any], ...]
    file_size: int

    @property
    def ok(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "event_count": self.count,
            "head_hash": self.head_hash,
            "file_size": self.file_size,
        }


class EventLedger:
    def __init__(
        self, events_path: Path, head_path: Path | None = None, lock_path: Path | None = None
    ) -> None:
        self.events_path = Path(events_path)
        self.head_path = (
            Path(head_path) if head_path else self.events_path.with_name("chain-head.json")
        )
        self.lock_path = Path(lock_path) if lock_path else self.events_path.with_suffix(".lock")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(16).encode("ascii")
        try:
            descriptor = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise NoTugError(
                "EVENT_LEDGER_LOCKED", "Another process is appending an event"
            ) from exc
        except OSError as exc:
            raise NoTugError(
                "VAULT_PERMISSION_DENIED", "Event ledger lock could not be created"
            ) from exc
        try:
            os.write(descriptor, token)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            yield
        finally:
            try:
                if self.lock_path.read_bytes() == token:
                    self.lock_path.unlink()
            except FileNotFoundError:
                pass

    def verify(self) -> EventVerification:
        events_exists = self.events_path.exists()
        head_exists = self.head_path.exists()
        if not events_exists and not head_exists:
            return EventVerification(0, None, (), 0)
        if head_exists and not events_exists:
            raise NoTugError(
                "RECEIPT_CHAIN_MISSING", "Event ledger is missing but its head remains"
            )
        try:
            raw = self.events_path.read_bytes()
        except OSError as exc:
            raise NoTugError("RECEIPT_CHAIN_UNREADABLE", "Event ledger cannot be read") from exc
        if not raw:
            if head_exists:
                raise NoTugError(
                    "RECEIPT_CHAIN_HEAD_MISMATCH",
                    "Event ledger was truncated after events were recorded",
                )
            return EventVerification(0, None, (), 0)
        if not head_exists:
            raise NoTugError("RECEIPT_CHAIN_HEAD_MISSING", "Event ledger tail anchor is missing")
        if not raw.endswith(b"\n"):
            raise NoTugError(
                "RECEIPT_CHAIN_INVALID", "Event ledger contains a truncated final record"
            )
        lines = raw[:-1].split(b"\n")
        if any(not line for line in lines):
            raise NoTugError("RECEIPT_CHAIN_INVALID", "Event ledger contains an empty record")
        events: list[dict[str, Any]] = []
        previous: str | None = None
        for expected_sequence, line in enumerate(lines, start=1):
            event = _validate_event(_strict_json_object(line, code="RECEIPT_CHAIN_INVALID"))
            if line != canonical_json_bytes(event):
                raise NoTugError("RECEIPT_CHAIN_INVALID", "Event record is not canonically encoded")
            if event["sequence"] != expected_sequence:
                raise NoTugError("RECEIPT_CHAIN_INVALID", "Event sequence is not continuous")
            if event["previous_event_hash"] != previous:
                raise NoTugError("RECEIPT_CHAIN_INVALID", "Event previous-hash link is invalid")
            previous = event["event_hash"]
            events.append(event)
        try:
            head_raw = self.head_path.read_bytes()
            head = _strict_json_object(head_raw, code="RECEIPT_CHAIN_HEAD_INVALID")
        except OSError as exc:
            raise NoTugError(
                "RECEIPT_CHAIN_HEAD_INVALID", "Event chain head cannot be read"
            ) from exc
        if head_raw != canonical_json_bytes(head) + b"\n":
            raise NoTugError(
                "RECEIPT_CHAIN_HEAD_INVALID", "Event chain head is not canonically encoded"
            )
        head_schema = head.get("schema_version")
        head_sequence = head.get("sequence")
        head_hash = head.get("event_hash")
        head_size = head.get("file_size")
        if (
            set(head) != HEAD_FIELDS
            or not isinstance(head_schema, int)
            or isinstance(head_schema, bool)
            or head_schema != 1
            or not isinstance(head_sequence, int)
            or isinstance(head_sequence, bool)
            or head_sequence < 1
            or not isinstance(head_hash, str)
            or not HASH_RE.fullmatch(head_hash)
            or not isinstance(head_size, int)
            or isinstance(head_size, bool)
            or head_size < 1
        ):
            raise NoTugError("RECEIPT_CHAIN_HEAD_INVALID", "Event chain head schema is invalid")
        if head_sequence != len(events) or head_hash != previous or head_size != len(raw):
            raise NoTugError(
                "RECEIPT_CHAIN_HEAD_MISMATCH",
                "Event ledger does not match its separately stored tail anchor",
            )
        return EventVerification(len(events), previous, tuple(events), len(raw))

    def read_events(self) -> list[dict[str, Any]]:
        return [dict(event) for event in self.verify().events]

    def append(
        self,
        *,
        repository_id: str,
        event_type: str,
        entity_type: str,
        entity_id: str,
        state_from: str | None = None,
        state_to: str | None = None,
        payload: dict[str, Any] | None = None,
        occurred_at: str | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        with self._locked():
            verification = self.verify()
            core: dict[str, Any] = {
                "schema_version": 1,
                "sequence": verification.count + 1,
                "event_id": event_id or new_identifier("event"),
                "event_type": event_type,
                "occurred_at": occurred_at or utc_now(),
                "repository_id": repository_id,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "state_from": state_from,
                "state_to": state_to,
                "payload": dict(payload or {}),
                "previous_event_hash": verification.head_hash,
            }
            event = {**core, "event_hash": _event_hash(core)}
            _validate_event(event)
            line = canonical_json_bytes(event) + b"\n"
            self.events_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(
                    self.events_path,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0),
                    0o600,
                )
                try:
                    view = memoryview(line)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("short event ledger write")
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as exc:
                raise NoTugError(
                    "EVENT_APPEND_FAILED", "Event receipt could not be appended"
                ) from exc
            file_size = verification.file_size + len(line)
            atomic_write_json(
                self.head_path,
                {
                    "schema_version": 1,
                    "sequence": event["sequence"],
                    "event_hash": event["event_hash"],
                    "file_size": file_size,
                },
            )
            return event

    def append_transition(
        self,
        *,
        repository_id: str,
        event_type: str,
        entity_type: str,
        entity_id: str,
        state_from: str,
        state_to: str,
        payload: dict[str, Any] | None = None,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        assert_transition(state_from, state_to)
        return self.append(
            repository_id=repository_id,
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            state_from=state_from,
            state_to=state_to,
            payload=payload,
            occurred_at=occurred_at,
        )


def ledger_for(vault: Any, repository_id: str) -> EventLedger:
    """Construct a ledger from the small Vault path-provider interface."""

    return EventLedger(
        vault.events_path(repository_id),
        vault.chain_head_path(repository_id),
        vault.event_lock_path(repository_id),
    )
