"""Exercise and inspect representative generated event receipts for data minimisation."""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from notug_protocol.errors import NoTugError  # noqa: E402
from notug_protocol.events import EventLedger  # noqa: E402
from notug_protocol.identity import new_identifier  # noqa: E402

PROHIBITED_KEYS = {
    "arguments",
    "argv",
    "body",
    "content",
    "credential",
    "diff",
    "environment",
    "env",
    "file_content",
    "password",
    "patch",
    "private_key",
    "prompt",
    "response",
    "secret",
    "stderr",
    "stdout",
    "token",
}
SECRET_VALUE = re.compile(r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{12,})")


def walk(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = key.casefold()
            hash_only = lowered.endswith(("_hash", "_sha256"))
            if not hash_only and (
                lowered in PROHIBITED_KEYS
                or any(
                    lowered.startswith(name + "_") or lowered.endswith("_" + name)
                    for name in PROHIBITED_KEYS
                )
            ):
                raise AssertionError(f"prohibited receipt field at {path}.{key}")
            walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_VALUE.search(value):
        raise AssertionError(f"secret-like receipt value at {path}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="notug-minimisation-") as raw:
        root = Path(raw)
        ledger = EventLedger(root / "events.jsonl", root / "head.json", root / "lock")
        repository_id = new_identifier("repo")
        session_id = new_identifier("session")
        ledger.append(
            repository_id=repository_id,
            event_type="MINIMISATION_SAMPLE",
            entity_type="session",
            entity_id=session_id,
            payload={
                "baseline_commit": "0" * 40,
                "manifest_hash": "1" * 64,
                "change_count": 2,
            },
        )
        for event in ledger.read_events():
            walk(event)
        parsed = [
            json.loads(line)
            for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        for event in parsed:
            walk(event)
        rejected = 0
        for field in sorted(PROHIBITED_KEYS):
            try:
                ledger.append(
                    repository_id=repository_id,
                    event_type="MINIMISATION_PROBE",
                    entity_type="session",
                    entity_id=session_id,
                    payload={field: "probe"},
                )
            except NoTugError as exc:
                if exc.code != "EVENT_MINIMISATION_FAILED":
                    raise
                rejected += 1
        if rejected != len(PROHIBITED_KEYS):
            raise AssertionError("not every prohibited receipt field was rejected")
    print(
        f"Minimisation lint passed: {rejected} prohibited fields rejected; generated receipt clean"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
