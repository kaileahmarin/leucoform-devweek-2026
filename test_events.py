from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from notug_protocol.errors import NoTugError
from notug_protocol.events import EventLedger
from notug_protocol.identity import new_identifier


class EventLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="notug-events-")
        root = Path(self.temporary.name)
        self.ledger = EventLedger(root / "events.jsonl", root / "head.json", root / "events.lock")
        self.repository_id = new_identifier("repo")
        self.session_id = new_identifier("session")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def append(self, event_type: str = "SESSION_STARTED") -> dict[str, object]:
        return self.ledger.append(
            repository_id=self.repository_id,
            event_type=event_type,
            entity_type="session",
            entity_id=self.session_id,
            state_from="LOCKED",
            state_to="SESSION_OPEN",
            payload={"baseline_commit": "a" * 40, "changed_files": 0},
            occurred_at="2026-07-14T20:00:00.000Z",
        )

    def assert_code(self, expected: str, operation: object) -> None:
        with self.assertRaises(NoTugError) as caught:
            if callable(operation):
                operation()
        self.assertEqual(caught.exception.code, expected)

    def test_append_and_verify_hash_chain_and_separate_head(self) -> None:
        first = self.append()
        second = self.ledger.append(
            repository_id=self.repository_id,
            event_type="TUG_CREATED",
            entity_type="session",
            entity_id=self.session_id,
            state_from="SESSION_OPEN",
            state_to="TUGGED",
            payload={"tug_hash": "b" * 64},
            occurred_at="2026-07-14T20:01:00.000Z",
        )
        verification = self.ledger.verify()
        self.assertEqual(verification.count, 2)
        self.assertEqual(verification.head_hash, second["event_hash"])
        self.assertEqual(second["previous_event_hash"], first["event_hash"])
        head = json.loads(self.ledger.head_path.read_text(encoding="utf-8"))
        self.assertEqual(head["event_hash"], second["event_hash"])
        self.assertEqual(head["file_size"], self.ledger.events_path.stat().st_size)

    def test_event_receipts_reject_raw_content_and_secret_fields(self) -> None:
        for payload in (
            {"content": "private source material"},
            {"environment": {"API_TOKEN": "secret"}},
            {"patch": "diff --git a/x b/x"},
            {"stdout": "agent output"},
        ):
            with self.subTest(payload=payload):
                self.assert_code(
                    "EVENT_MINIMISATION_FAILED",
                    lambda payload=payload: self.ledger.append(
                        repository_id=self.repository_id,
                        event_type="SESSION_STARTED",
                        entity_type="session",
                        entity_id=self.session_id,
                        payload=payload,
                    ),
                )
        self.assertFalse(self.ledger.events_path.exists())

    def test_event_payload_rejects_unknown_free_text_fields(self) -> None:
        self.assert_code(
            "EVENT_SCHEMA_INVALID",
            lambda: self.ledger.append(
                repository_id=self.repository_id,
                event_type="SESSION_STARTED",
                entity_type="session",
                entity_id=self.session_id,
                payload={"note": "arbitrary repository prose is not an event fact"},
            ),
        )

    def test_editing_an_event_is_detected(self) -> None:
        self.append()
        raw = self.ledger.events_path.read_bytes()
        self.ledger.events_path.write_bytes(raw.replace(b"SESSION_STARTED", b"SESSION_STOPPED"))
        self.assert_code("RECEIPT_CHAIN_INVALID", self.ledger.verify)

    def test_deleting_an_interior_event_is_detected(self) -> None:
        self.append()
        self.ledger.append(
            repository_id=self.repository_id,
            event_type="RUN_STARTED",
            entity_type="session",
            entity_id=self.session_id,
            payload={"argument_count": 1},
        )
        self.ledger.append(
            repository_id=self.repository_id,
            event_type="RUN_FINISHED",
            entity_type="session",
            entity_id=self.session_id,
            payload={"exit_status": 0},
        )
        lines = self.ledger.events_path.read_bytes().splitlines(keepends=True)
        self.ledger.events_path.write_bytes(lines[0] + lines[2])
        self.assert_code("RECEIPT_CHAIN_INVALID", self.ledger.verify)

    def test_reordering_events_is_detected(self) -> None:
        self.append()
        self.ledger.append(
            repository_id=self.repository_id,
            event_type="RUN_STARTED",
            entity_type="session",
            entity_id=self.session_id,
            payload={},
        )
        lines = self.ledger.events_path.read_bytes().splitlines(keepends=True)
        self.ledger.events_path.write_bytes(lines[1] + lines[0])
        self.assert_code("RECEIPT_CHAIN_INVALID", self.ledger.verify)

    def test_inserting_an_event_is_detected(self) -> None:
        self.append()
        self.ledger.append(
            repository_id=self.repository_id,
            event_type="RUN_STARTED",
            entity_type="session",
            entity_id=self.session_id,
            payload={},
        )
        lines = self.ledger.events_path.read_bytes().splitlines(keepends=True)
        self.ledger.events_path.write_bytes(lines[0] + lines[0] + lines[1])
        self.assert_code("RECEIPT_CHAIN_INVALID", self.ledger.verify)

    def test_deleting_the_tail_is_detected_by_head_anchor(self) -> None:
        self.append()
        self.ledger.append(
            repository_id=self.repository_id,
            event_type="RUN_STARTED",
            entity_type="session",
            entity_id=self.session_id,
            payload={},
        )
        first_line = self.ledger.events_path.read_bytes().splitlines(keepends=True)[0]
        self.ledger.events_path.write_bytes(first_line)
        self.assert_code("RECEIPT_CHAIN_HEAD_MISMATCH", self.ledger.verify)

    def test_duplicate_json_key_fails_closed(self) -> None:
        self.append()
        raw = self.ledger.events_path.read_bytes()
        self.ledger.events_path.write_bytes(
            raw.replace(b'{"entity_id"', b'{"schema_version":1,"entity_id"', 1)
        )
        self.assert_code("RECEIPT_CHAIN_INVALID", self.ledger.verify)

    def test_incomplete_final_line_fails_closed(self) -> None:
        self.append()
        self.ledger.events_path.write_bytes(self.ledger.events_path.read_bytes()[:-1])
        self.assert_code("RECEIPT_CHAIN_INVALID", self.ledger.verify)

    def test_missing_separate_head_fails_closed(self) -> None:
        self.append()
        self.ledger.head_path.unlink()
        self.assert_code("RECEIPT_CHAIN_HEAD_MISSING", self.ledger.verify)


if __name__ == "__main__":
    unittest.main()
