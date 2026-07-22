"""Professional, dependency-free command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .application import get_review_summary
from .brand import (
    CHECKOUT_UNCHANGED,
    CLI_NAME,
    DIVERGENCE_DETECTED,
    EXPANSION,
    GRANT_BOUND,
    HUMAN_GRANT_REQUIRED,
    INTEGRATION_CREATED,
    MUTATION_LOCK_ACTIVE,
    PRODUCT_NAME,
    TUG_GENERATED,
    VERSION,
)
from .demo import run_demo
from .doctor import diagnose
from .errors import NoTugError
from .exports import export_tug_receipt
from .git import discover_repository, worktree_list
from .grants import grant_tug, revoke_grant
from .sessions import (
    archive_session,
    initialize_repository,
    run_agent_command,
    start_session,
)
from .tug import deny_tug, find_tug, generate_tug
from .util import atomic_create_json, sanitize_terminal
from .vault import Vault
from .verification import verify_repository


def _repo_argument(value: str | None) -> Path:
    return Path(value or ".").expanduser()


def _json_print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=True, sort_keys=True, default=str))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=CLI_NAME,
        description=f"{PRODUCT_NAME} ({EXPANSION}) - local agent mutation governance",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init = subcommands.add_parser("init", help="initialize local protection")
    init.add_argument("repo", nargs="?", default=".")
    init.add_argument("--json", action="store_true")

    doctor = subcommands.add_parser("doctor", help="diagnose without fixing")
    doctor.add_argument("repo", nargs="?", default=".")
    doctor.add_argument("--json", action="store_true")

    session = subcommands.add_parser("session", help="manage disposable sessions")
    session_commands = session.add_subparsers(dest="session_command", required=True)
    start = session_commands.add_parser("start", help="create a detached disposable worktree")
    start.add_argument("repo", nargs="?", default=".")
    start.add_argument("--name", required=True)
    start.add_argument("--json", action="store_true")
    archive = session_commands.add_parser("archive", help="remove a disposed session worktree")
    archive.add_argument("session_id")
    archive.add_argument("--json", action="store_true")

    run = subcommands.add_parser("run", help="run a command inside a session")
    run.add_argument("session_id")
    run.add_argument("agent_command", nargs=argparse.REMAINDER)

    tug = subcommands.add_parser("tug", help="generate a structured Tug Signal")
    tug.add_argument("session_id")
    tug.add_argument("--json", action="store_true")

    review = subcommands.add_parser("review", help="review a Tug Signal")
    review.add_argument("tug_id")
    review.add_argument("--diff", action="store_true", dest="show_diff")
    review.add_argument("--json", action="store_true")

    grant = subcommands.add_parser("grant", help="issue an exact interactive human grant")
    grant.add_argument("tug_id")
    grant.add_argument("--json", action="store_true")

    deny = subcommands.add_parser("deny", help="deny a Tug Signal")
    deny.add_argument("tug_id")
    deny.add_argument("--json", action="store_true")

    verify = subcommands.add_parser("verify", help="verify all local provenance evidence")
    verify.add_argument("repo", nargs="?", default=".")
    verify.add_argument("--json", action="store_true")

    revoke = subcommands.add_parser("revoke", help="revoke or create a revert for a grant")
    revoke.add_argument("tug_id")
    revoke.add_argument("--json", action="store_true")

    export = subcommands.add_parser("export", help="export a patch-free Tug receipt")
    export.add_argument("tug_id")
    export.add_argument("--include-paths", action="store_true")
    export.add_argument("--output", type=Path)

    demo = subcommands.add_parser("demo", help="run an isolated end-to-end demonstration")
    demo.add_argument("--json", action="store_true")
    return parser


def _review_data(tug_id: str, show_diff: bool) -> dict[str, Any]:
    data = get_review_summary(tug_id, include_diff=show_diff).to_dict()
    data.pop("session_state")
    data["commands"] = {
        "grant": f"{CLI_NAME} grant {tug_id}",
        "deny": f"{CLI_NAME} deny {tug_id}",
    }
    return data


def _print_review(data: dict[str, Any]) -> None:
    tug = data["tug"]
    summary = tug["evidence"]["summary"]
    print(f"Tug Signal: {tug['tug_id']}")
    print(f"Tug hash: {tug['tug_hash']}")
    print(f"Risk: {tug['risk_summary']['overall_severity']}")
    print(
        f"Changes: {summary['file_count']} file(s), {summary['bytes_touched']} bytes touched, "
        f"{summary['deletion_count']} deletion(s), {summary['rename_count']} rename(s), "
        f"{summary['binary_count']} binary"
    )
    baseline = data["baseline_verification"]
    print(
        "Baseline: verified"
        if baseline["verified"]
        else f"Baseline: {DIVERGENCE_DETECTED} ({baseline['error_code']})"
    )
    print("Receipt chain: verified")
    print("Changed paths:")
    for change in tug["changes"]:
        flags = [str(change["kind"])]
        if change["binary"]:
            flags.append("binary")
        if change["old_path"] is not None:
            display = (
                f"{sanitize_terminal(change['old_path'])} -> {sanitize_terminal(change['path'])}"
            )
        else:
            display = sanitize_terminal(change["path"])
        print(f"  [{', '.join(flags)}] {display}")
        if change["binary"]:
            print(
                "    binary metadata: "
                f"old_size={change['old_size']} new_size={change['new_size']} "
                f"old_mode={change['old_mode']} new_mode={change['new_mode']} "
                f"old_oid={change['old_oid']} new_oid={change['new_oid']}"
            )
    if tug["ignored_sensitive_paths"]:
        print("Ignored sensitive paths detected:")
        for path in tug["ignored_sensitive_paths"]:
            print(f"  {sanitize_terminal(path)}")
    print("Policy findings:")
    if not tug["policy"]["findings"]:
        print("  none")
    for finding in tug["policy"]["findings"]:
        print(
            f"  [{finding['severity']}] {finding['code']}: {sanitize_terminal(finding['message'])}"
        )
    print(HUMAN_GRANT_REQUIRED)
    print(f"Grant: {data['commands']['grant']}")
    print(f"Deny:  {data['commands']['deny']}")
    if "diff" in data:
        print("\nSanitized textual diff (binary payloads omitted):")
        print(data["diff"])
    print(MUTATION_LOCK_ACTIVE)


def _validate_export_destination(output_path: Path, vault: Vault, repository_id: str) -> Path:
    if output_path.exists() or output_path.is_symlink():
        raise NoTugError("EXPORT_PATH_EXISTS", "Receipt export destination already exists")
    identity = vault.load_repository(repository_id)
    repository = discover_repository(identity.root)
    protected_roots = {
        vault.root.resolve(),
        repository.root.resolve(),
        repository.git_dir.resolve(),
        repository.common_git_dir.resolve(),
        *(item.path.resolve() for item in worktree_list(repository)),
    }
    for root in protected_roots:
        try:
            output_path.relative_to(root)
        except ValueError:
            continue
        raise NoTugError(
            "EXPORT_PATH_PROTECTED",
            "Receipt exports cannot be written into protected or managed storage",
        )
    return output_path


def _dispatch(arguments: argparse.Namespace) -> int:
    command = arguments.command
    json_mode = bool(getattr(arguments, "json", False))
    if command == "init":
        init_result = initialize_repository(_repo_argument(arguments.repo))
        init_payload: dict[str, Any] = {
            "ok": True,
            "repository_id": init_result.repository_id,
            "baseline_commit": init_result.baseline_commit,
            "policy_hash": init_result.policy_hash,
            "vault": str(init_result.vault_root),
            "mutation_lock": "active",
        }
        if json_mode:
            _json_print(init_payload)
        else:
            print(f"Protection initialized: {init_result.repository_id}")
            print(MUTATION_LOCK_ACTIVE)
        return 0
    if command == "doctor":
        doctor_report = diagnose(_repo_argument(arguments.repo))
        if json_mode:
            _json_print(doctor_report)
        else:
            for finding in doctor_report["findings"]:
                print(f"[{finding['severity']}] {finding['code']}: {finding['message']}")
            print(MUTATION_LOCK_ACTIVE)
        return 0 if doctor_report["ok"] else 2
    if command == "session" and arguments.session_command == "start":
        session_result = start_session(_repo_argument(arguments.repo), arguments.name)
        session_payload: dict[str, Any] = {
            "ok": True,
            "session_id": session_result.session_id,
            "workspace": str(session_result.worktree),
            "baseline_commit": session_result.baseline_commit,
            "mutation_lock": "active",
        }
        if json_mode:
            _json_print(session_payload)
        else:
            print(f"Session: {session_result.session_id}")
            print(f"Workspace: {session_result.worktree}")
            print(
                "Open this exact path in Codex or another local coding agent: "
                f"{session_result.worktree}"
            )
            print(MUTATION_LOCK_ACTIVE)
        return 0
    if command == "session" and arguments.session_command == "archive":
        archive_session(arguments.session_id)
        archive_payload: dict[str, Any] = {
            "ok": True,
            "session_id": arguments.session_id,
            "archived": True,
            "mutation_lock": "active",
        }
        if json_mode:
            _json_print(archive_payload)
        else:
            print(f"Session archived: {arguments.session_id}\n{MUTATION_LOCK_ACTIVE}")
        return 0
    if command == "run":
        child_command = list(arguments.agent_command)
        if child_command and child_command[0] == "--":
            child_command.pop(0)
        exit_status = run_agent_command(arguments.session_id, child_command)
        print(MUTATION_LOCK_ACTIVE)
        return exit_status
    if command == "tug":
        tug = generate_tug(arguments.session_id)
        tug_payload: dict[str, Any] = {"ok": True, "tug": tug, "mutation_lock": "active"}
        if json_mode:
            _json_print(tug_payload)
        else:
            print(f"{TUG_GENERATED}: {tug['tug_id']}")
            print(f"Tug hash: {tug['tug_hash']}")
            print(f"Risk: {tug['risk_summary']['overall_severity']}")
            print(HUMAN_GRANT_REQUIRED)
            print(CHECKOUT_UNCHANGED)
            print(MUTATION_LOCK_ACTIVE)
        return 0
    if command == "review":
        review_data = _review_data(arguments.tug_id, arguments.show_diff)
        if json_mode:
            _json_print({"ok": True, **review_data})
        else:
            _print_review(review_data)
        return 0
    if command == "grant":
        grant = grant_tug(arguments.tug_id)
        grant_payload: dict[str, Any] = {
            "ok": True,
            "grant": grant,
            "mutation_lock": "active",
        }
        if json_mode:
            _json_print(grant_payload)
        else:
            print(f"{GRANT_BOUND}: {grant['tug_hash']}")
            print(f"{INTEGRATION_CREATED}: {grant['branch']}")
            print(f"Integration worktree: {sanitize_terminal(str(grant['worktree']))}")
            print("Review command (run from that worktree): git log -1 --stat")
            print(CHECKOUT_UNCHANGED)
            print(MUTATION_LOCK_ACTIVE)
        return 0
    if command == "deny":
        denial = deny_tug(arguments.tug_id)
        denial_payload: dict[str, Any] = {
            "ok": True,
            **denial,
            "mutation_lock": "active",
        }
        if json_mode:
            _json_print(denial_payload)
        else:
            print(
                f"Tug Signal denied: {denial['tug_id']}\n"
                f"{CHECKOUT_UNCHANGED}\n{MUTATION_LOCK_ACTIVE}"
            )
        return 0
    if command == "verify":
        verify_report = verify_repository(_repo_argument(arguments.repo))
        if json_mode:
            _json_print(verify_report)
        else:
            print(f"Verification: {'passed' if verify_report['ok'] else 'failed'}")
            for issue in verify_report["issues"]:
                print(f"[{issue['code']}] {issue['message']}")
            print(MUTATION_LOCK_ACTIVE)
        return 0 if verify_report["ok"] else 3
    if command == "revoke":
        revoke_result = revoke_grant(arguments.tug_id)
        revoke_payload: dict[str, Any] = {
            "ok": True,
            "revoke": revoke_result,
            "mutation_lock": "active",
        }
        if json_mode:
            _json_print(revoke_payload)
        else:
            if revoke_result["kind"] == "revert_branch_created":
                print(f"Revert branch created: {revoke_result['branch']}")
                print(
                    "Merged change remains authoritative until the revert branch is reviewed "
                    "and merged"
                )
            else:
                print(f"Grant revoked: {revoke_result['kind']}")
                print(f"Branch removed: {revoke_result['branch']}")
            print(MUTATION_LOCK_ACTIVE)
        return 0
    if command == "export":
        export_data = export_tug_receipt(
            arguments.tug_id, include_paths=bool(arguments.include_paths)
        )
        if arguments.output is None:
            _json_print(export_data)
        else:
            output_path = arguments.output.expanduser().resolve()
            vault = Vault()
            repository_id, _tug = find_tug(vault, arguments.tug_id)
            _validate_export_destination(output_path, vault, repository_id)
            atomic_create_json(output_path, export_data)
            print(f"Receipt exported: {output_path}")
            print(MUTATION_LOCK_ACTIVE)
        return 0
    if command == "demo":
        if json_mode:
            import io

            buffer = io.StringIO()
            demo_result = run_demo(buffer)
            _json_print({"ok": True, "demo": demo_result, "transcript": buffer.getvalue()})
        else:
            run_demo()
        return 0
    raise NoTugError("COMMAND_INVALID", "Unknown command")


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    json_requested = False
    parser = _parser()
    try:
        arguments = parser.parse_args(raw_arguments)
        json_requested = bool(getattr(arguments, "json", False))
        return _dispatch(arguments)
    except NoTugError as exc:
        payload = {**exc.as_dict(), "mutation_lock": "active"}
        if json_requested:
            _json_print(payload)
        else:
            print(f"Error [{exc.code}]: {sanitize_terminal(exc.message)}", file=sys.stderr)
            if exc.code in {
                "BASELINE_REF_DRIFT",
                "SOURCE_HEAD_DRIFT",
                "SOURCE_MANIFEST_DRIFT",
                "PROVENANCE_DIVERGENCE",
            }:
                print(DIVERGENCE_DETECTED, file=sys.stderr)
            print(MUTATION_LOCK_ACTIVE, file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        payload = {
            "ok": False,
            "error": {"code": "INTERRUPTED", "message": "Operation interrupted", "details": {}},
            "mutation_lock": "active",
        }
        _json_print(payload) if json_requested else print(
            f"Operation interrupted\n{MUTATION_LOCK_ACTIVE}", file=sys.stderr
        )
        return 130
    except Exception:
        payload = {
            "ok": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "Unexpected internal failure",
                "details": {},
            },
            "mutation_lock": "active",
        }
        _json_print(payload) if json_requested else print(
            f"Error [INTERNAL_ERROR]: Unexpected internal failure\n{MUTATION_LOCK_ACTIVE}",
            file=sys.stderr,
        )
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
