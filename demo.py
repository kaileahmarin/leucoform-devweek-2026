"""Self-contained demonstration using only a newly created temporary repository."""

from __future__ import annotations

import io
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TextIO

from .brand import (
    CHECKOUT_UNCHANGED,
    CLI_NAME,
    COMMIT_EMAIL,
    DIVERGENCE_DETECTED,
    GRANT_BOUND,
    HUMAN_GRANT_REQUIRED,
    INTEGRATION_CREATED,
    MUTATION_LOCK_ACTIVE,
    PRODUCT_NAME,
    TUG_GENERATED,
)
from .errors import NoTugError
from .events import ledger_for
from .git import inert_filter_config_arguments, run_git
from .grants import grant_tug
from .sessions import initialize_repository, start_session
from .tug import deny_tug, generate_tug
from .util import sha256_file
from .vault import Vault
from .verification import verify_repository


def _line(stream: TextIO, number: int, message: str) -> None:
    stream.write(f"{number:>2}. {message}\n")
    stream.flush()


class _DemoTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


@contextmanager
def _synthetic_demo_confirmation(tug_hash: str) -> Iterator[None]:
    """Provide exact terminal input only for the wholly synthetic demo repository."""

    previous_stdin, previous_stderr = sys.stdin, sys.stderr
    sys.stdin = _DemoTTY(f"GRANT {tug_hash}\n")
    sys.stderr = _DemoTTY()
    try:
        yield
    finally:
        sys.stdin, sys.stderr = previous_stdin, previous_stderr


def run_demo(stream: TextIO | None = None) -> dict[str, Any]:
    """Run the complete lifecycle against an isolated, disposable repository."""

    output = stream or __import__("sys").stdout
    with tempfile.TemporaryDirectory(prefix=f"{CLI_NAME}-demo-") as raw:
        root = Path(raw)
        repository = root / "protected"
        repository.mkdir()
        trusted = root / "trusted" / "empty-hooks"
        trusted.mkdir(parents=True)
        run_git(
            repository,
            ["init", f"--template={trusted}", "--initial-branch=main"],
        )
        run_git(repository, ["config", "user.name", f"{PRODUCT_NAME} Demo"])
        run_git(repository, ["config", "user.email", COMMIT_EMAIL])
        protected_file = repository / "README.md"
        deleted_file = repository / "obsolete.txt"
        protected_file.write_text("protected baseline\n", encoding="utf-8")
        deleted_file.write_text("still authoritative\n", encoding="utf-8")
        inert = inert_filter_config_arguments(repository)
        run_git(repository, [*inert, "add", "README.md", "obsolete.txt"])
        run_git(
            repository,
            [
                *inert,
                "-c",
                f"core.hooksPath={trusted}",
                "-c",
                "commit.gpgSign=false",
                "commit",
                "-m",
                "demo baseline",
            ],
        )
        baseline_commit = run_git(repository, ["rev-parse", "HEAD"]).stdout.decode("ascii").strip()
        baseline_readme = sha256_file(protected_file)
        baseline_obsolete = sha256_file(deleted_file)
        _line(output, 1, f"Baseline repository created at {repository} ({baseline_commit[:12]})")

        vault = Vault(root / "vault" / "v1")
        initialized = initialize_repository(repository, vault)
        _line(
            output,
            2,
            f"Protection initialized ({initialized.repository_id}); {MUTATION_LOCK_ACTIVE}",
        )
        first = start_session(repository, "denial-path", vault)
        _line(output, 3, f"Disposable session created ({first.session_id})")
        (first.worktree / "README.md").write_text("agent proposal\n", encoding="utf-8")
        (first.worktree / "obsolete.txt").unlink()
        _line(output, 4, "Simulated agent modified one file and deleted another")
        if (
            sha256_file(protected_file) != baseline_readme
            or sha256_file(deleted_file) != baseline_obsolete
        ):
            raise NoTugError(
                "DEMO_CHECKOUT_CHANGED", "Protected demo checkout changed unexpectedly"
            )
        _line(output, 5, CHECKOUT_UNCHANGED)
        first_tug = generate_tug(first.session_id, vault)
        if first_tug["evidence"]["summary"]["deletion_count"] != 1:
            raise NoTugError("DEMO_CLASSIFICATION_FAILED", "Deletion was not classified")
        _line(
            output,
            6,
            f"{TUG_GENERATED} ({first_tug['tug_id']}); {HUMAN_GRANT_REQUIRED}",
        )
        deny_tug(str(first_tug["tug_id"]), vault)
        _line(output, 7, "First Tug Signal denied; protected checkout remains unchanged")

        second = start_session(repository, "grant-path", vault)
        (second.worktree / "README.md").write_text("reviewed proposal\n", encoding="utf-8")
        second_tug = generate_tug(second.session_id, vault)
        _line(output, 8, f"Second session and Tug Signal created ({second_tug['tug_id']})")
        with _synthetic_demo_confirmation(str(second_tug["tug_hash"])):
            grant = grant_tug(str(second_tug["tug_id"]), vault)
        _line(output, 9, f"{GRANT_BOUND}: {str(grant['tug_hash'])[:12]}")
        _line(output, 10, f"{INTEGRATION_CREATED} ({grant['branch']})")
        if (
            sha256_file(protected_file) != baseline_readme
            or sha256_file(deleted_file) != baseline_obsolete
        ):
            raise NoTugError("DEMO_CHECKOUT_CHANGED", "Grant changed the protected demo checkout")
        report = verify_repository(repository, vault)
        if not report["ok"]:
            raise NoTugError(
                "DEMO_VERIFICATION_FAILED", "Demo receipts did not verify", {"report": report}
            )
        receipt_count = report["checks"]["receipt_chain"]["event_count"]
        _line(output, 11, f"Receipt verification passed ({receipt_count} events)")

        events_path = vault.events_path(initialized.repository_id)
        original_events = events_path.read_bytes()
        tampered = original_events.replace(
            b'"event_type":"SESSION_CREATED"', b'"event_type":"SESSION_EDITED"', 1
        )
        if tampered == original_events:
            raise NoTugError("DEMO_TAMPER_SETUP_FAILED", "Could not prepare isolated tamper test")
        events_path.write_bytes(tampered)
        detected = False
        try:
            ledger_for(vault, initialized.repository_id).verify()
        except NoTugError:
            detected = True
        finally:
            events_path.write_bytes(original_events)
        if not detected:
            raise NoTugError("DEMO_TAMPER_UNDETECTED", "Receipt alteration was not detected")
        if not verify_repository(repository, vault)["ok"]:
            raise NoTugError("DEMO_RESTORE_FAILED", "Demo receipt restoration did not verify")
        _line(
            output,
            12,
            f"{DIVERGENCE_DETECTED}; tamper detection passed; {MUTATION_LOCK_ACTIVE}",
        )
        return {
            "ok": True,
            "baseline_commit": baseline_commit,
            "denied_tug": first_tug["tug_id"],
            "granted_tug": second_tug["tug_id"],
            "integration_branch": grant["branch"],
            "protected_checkout_unchanged": True,
            "receipt_tampering_detected": True,
            "mutation_lock": "active",
        }


def demo_text() -> tuple[str, dict[str, Any]]:
    buffer = io.StringIO()
    result = run_demo(buffer)
    return buffer.getvalue(), result
