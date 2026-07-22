"""Versioned, fail-closed request/response boundary for local coding agents."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .application import (
    create_session,
    get_review_summary,
    repository_status,
    session_status,
    verify_repository_evidence,
)
from .errors import NoTugError
from .identity import validate_identifier

BRIDGE_SCHEMA_VERSION = 1
OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class BridgeOperation(StrEnum):
    CAPABILITIES = "capabilities"
    REPOSITORY_STATUS = "repository_status"
    CREATE_SESSION = "create_session"
    LOCATE_WORKTREE = "locate_worktree"
    SESSION_STATE = "session_state"
    SUBMIT_CHANGES = "submit_changes"
    REVIEW_SUMMARY = "review_summary"
    WAIT_DECISION = "wait_decision"
    VERIFY = "verify"
    CLEANUP = "cleanup"


class BridgeOutcome(StrEnum):
    OK = "ok"
    UNPROTECTED = "unprotected"
    SESSION_CREATED = "session_created"
    AGENT_RUNNING = "agent_running"
    SUBMITTED = "submitted"
    AWAITING_HUMAN = "awaiting_human"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    DIVERGED = "diverged"
    INTERRUPTED = "interrupted"
    UNAVAILABLE = "unavailable"
    FAILED_CLOSED = "failed_closed"
    INTEGRATED = "integrated"
    VERIFIED = "verified"
    CLEANED = "cleaned"


REQUEST_FIELDS = {"schema_version", "operation_id", "operation", "parameters"}
PARAMETER_FIELDS: dict[BridgeOperation, tuple[set[str], set[str]]] = {
    BridgeOperation.CAPABILITIES: (set(), set()),
    BridgeOperation.REPOSITORY_STATUS: ({"repo"}, set()),
    BridgeOperation.CREATE_SESSION: ({"repo", "name"}, set()),
    BridgeOperation.LOCATE_WORKTREE: ({"session_id"}, set()),
    BridgeOperation.SESSION_STATE: ({"session_id"}, set()),
    BridgeOperation.SUBMIT_CHANGES: ({"session_id"}, set()),
    BridgeOperation.REVIEW_SUMMARY: ({"tug_id"}, {"include_diff"}),
    BridgeOperation.WAIT_DECISION: ({"tug_id"}, {"timeout_seconds"}),
    BridgeOperation.VERIFY: ({"repo"}, set()),
    BridgeOperation.CLEANUP: ({"session_id"}, set()),
}

IMPLEMENTED_OPERATIONS = {
    BridgeOperation.CAPABILITIES,
    BridgeOperation.REPOSITORY_STATUS,
    BridgeOperation.CREATE_SESSION,
    BridgeOperation.LOCATE_WORKTREE,
    BridgeOperation.SESSION_STATE,
    BridgeOperation.REVIEW_SUMMARY,
    BridgeOperation.VERIFY,
}


def _invalid(message: str, **details: Any) -> NoTugError:
    return NoTugError("BRIDGE_REQUEST_INVALID", message, details)


def _string_parameter(parameters: dict[str, Any], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value or len(value) > 32_768:
        raise _invalid(f"Bridge parameter {name} must be a non-empty string")
    return value


def _identifier_parameter(parameters: dict[str, Any], name: str, prefix: str) -> str:
    value = _string_parameter(parameters, name)
    try:
        return validate_identifier(value, prefix)
    except NoTugError as exc:
        raise _invalid(f"Bridge parameter {name} is not a valid {prefix} identifier") from exc


@dataclass(frozen=True, slots=True)
class BridgeRequest:
    schema_version: int
    operation_id: str
    operation: BridgeOperation
    parameters: dict[str, Any]

    @classmethod
    def from_dict(cls, value: Any) -> BridgeRequest:
        if not isinstance(value, dict):
            raise _invalid("Bridge request must be a JSON object")
        unknown = sorted(set(value) - REQUEST_FIELDS)
        missing = sorted(REQUEST_FIELDS - set(value))
        if unknown or missing:
            raise _invalid(
                "Bridge request fields do not match schema version 1",
                unknown_fields=unknown,
                missing_fields=missing,
            )
        schema_version = value["schema_version"]
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != BRIDGE_SCHEMA_VERSION
        ):
            raise NoTugError(
                "BRIDGE_VERSION_UNSUPPORTED", "Unsupported agent-bridge schema version"
            )
        operation_id = value["operation_id"]
        if not isinstance(operation_id, str) or OPERATION_ID_RE.fullmatch(operation_id) is None:
            raise _invalid("operation_id must be a short path-free protocol identifier")
        try:
            operation = BridgeOperation(value["operation"])
        except (TypeError, ValueError) as exc:
            raise _invalid("Unknown bridge operation") from exc
        parameters = value["parameters"]
        if not isinstance(parameters, dict):
            raise _invalid("Bridge parameters must be a JSON object")
        required, optional = PARAMETER_FIELDS[operation]
        parameter_unknown = sorted(set(parameters) - required - optional)
        parameter_missing = sorted(required - set(parameters))
        if parameter_unknown or parameter_missing:
            raise _invalid(
                "Bridge parameters do not match the operation schema",
                unknown_fields=parameter_unknown,
                missing_fields=parameter_missing,
            )
        for name in {"repo", "name"} & set(parameters):
            _string_parameter(parameters, name)
        for name, prefix in (("session_id", "session"), ("tug_id", "tug")):
            if name in parameters:
                _identifier_parameter(parameters, name, prefix)
        include_diff = parameters.get("include_diff")
        if include_diff is not None and not isinstance(include_diff, bool):
            raise _invalid("include_diff must be a boolean")
        timeout = parameters.get("timeout_seconds")
        if timeout is not None and (
            not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or timeout < 0
            or timeout > 86_400
        ):
            raise _invalid("timeout_seconds must be an integer from 0 through 86400")
        return cls(schema_version, operation_id, operation, dict(parameters))

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["operation"] = self.operation.value
        return result


@dataclass(frozen=True, slots=True)
class BridgeResponse:
    schema_version: int
    operation_id: str
    operation: str
    ok: bool
    outcome: BridgeOutcome
    data: dict[str, Any]
    error: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["outcome"] = self.outcome.value
        return result


def _response(
    request: BridgeRequest,
    *,
    outcome: BridgeOutcome,
    data: dict[str, Any] | None = None,
) -> BridgeResponse:
    return BridgeResponse(
        schema_version=BRIDGE_SCHEMA_VERSION,
        operation_id=request.operation_id,
        operation=request.operation.value,
        ok=True,
        outcome=outcome,
        data=data or {},
        error=None,
    )


def _failure(
    operation_id: str,
    operation: str,
    outcome: BridgeOutcome,
    error: NoTugError,
) -> BridgeResponse:
    return BridgeResponse(
        schema_version=BRIDGE_SCHEMA_VERSION,
        operation_id=operation_id,
        operation=operation,
        ok=False,
        outcome=outcome,
        data={},
        error={"code": error.code, "message": error.message, "details": error.details},
    )


def _capabilities() -> dict[str, Any]:
    operations: dict[str, dict[str, Any]] = {}
    for operation in BridgeOperation:
        available = operation in IMPLEMENTED_OPERATIONS
        authority = "not_exposed"
        if available:
            authority = (
                "non_authorizing_write"
                if operation == BridgeOperation.CREATE_SESSION
                else "read_only"
            )
        operations[operation.value] = {
            "available": available,
            "authority": authority,
        }
    return {
        "bridge_schema_versions": [BRIDGE_SCHEMA_VERSION],
        "operations": operations,
        "result_outcomes": [outcome.value for outcome in BridgeOutcome],
        "human_authorization_operations_exposed": False,
        "offline": True,
    }


def _session_outcome(state: str) -> BridgeOutcome:
    return {
        "SESSION_OPEN": BridgeOutcome.AGENT_RUNNING,
        "TUGGED": BridgeOutcome.AWAITING_HUMAN,
        "GRANTED": BridgeOutcome.GRANTED,
        "APPLIED": BridgeOutcome.INTEGRATED,
        "DENIED": BridgeOutcome.DENIED,
        "DIVERGED": BridgeOutcome.DIVERGED,
        "FAILED": BridgeOutcome.FAILED_CLOSED,
        "REVOKED": BridgeOutcome.CLEANED,
    }.get(state, BridgeOutcome.FAILED_CLOSED)


def _dispatch(request: BridgeRequest) -> BridgeResponse:
    parameters = request.parameters
    if request.operation == BridgeOperation.CAPABILITIES:
        return _response(request, outcome=BridgeOutcome.OK, data=_capabilities())
    if request.operation not in IMPLEMENTED_OPERATIONS:
        raise NoTugError(
            "BRIDGE_OPERATION_UNAVAILABLE",
            "This operation is defined by the contract but unavailable in the foundation slice",
        )
    if request.operation == BridgeOperation.REPOSITORY_STATUS:
        repository_result = repository_status(Path(_string_parameter(parameters, "repo")))
        outcome = BridgeOutcome.OK if repository_result.initialized else BridgeOutcome.UNPROTECTED
        return _response(request, outcome=outcome, data=repository_result.to_dict())
    if request.operation == BridgeOperation.CREATE_SESSION:
        created_result = create_session(
            Path(_string_parameter(parameters, "repo")),
            _string_parameter(parameters, "name"),
        )
        return _response(
            request,
            outcome=BridgeOutcome.SESSION_CREATED,
            data=created_result.to_dict(),
        )
    if request.operation in {BridgeOperation.LOCATE_WORKTREE, BridgeOperation.SESSION_STATE}:
        session_result = session_status(_identifier_parameter(parameters, "session_id", "session"))
        data = session_result.to_dict()
        if request.operation == BridgeOperation.LOCATE_WORKTREE:
            data = {
                "session_id": session_result.session_id,
                "state": session_result.state,
                "worktree": session_result.worktree,
                "worktree_available": session_result.worktree_available,
            }
        return _response(request, outcome=_session_outcome(session_result.state), data=data)
    if request.operation == BridgeOperation.REVIEW_SUMMARY:
        summary = get_review_summary(
            _identifier_parameter(parameters, "tug_id", "tug"),
            include_diff=bool(parameters.get("include_diff", False)),
        )
        return _response(
            request, outcome=_session_outcome(summary.session_state), data=summary.to_dict()
        )
    if request.operation == BridgeOperation.VERIFY:
        verification = verify_repository_evidence(Path(_string_parameter(parameters, "repo")))
        if not verification.ok:
            raise NoTugError(
                "VERIFICATION_FAILED",
                "One or more provenance checks failed",
                {"issue_count": len(verification.issues)},
            )
        return _response(request, outcome=BridgeOutcome.VERIFIED, data=verification.to_dict())
    raise NoTugError("BRIDGE_OPERATION_UNAVAILABLE", "Bridge operation is unavailable")


def handle_request(value: Any) -> dict[str, Any]:
    """Validate and execute one bridge request, always returning a bounded response."""

    operation_id = "invalid"
    operation = "invalid"
    if isinstance(value, dict):
        raw_operation_id = value.get("operation_id")
        raw_operation = value.get("operation")
        if isinstance(raw_operation_id, str) and OPERATION_ID_RE.fullmatch(raw_operation_id):
            operation_id = raw_operation_id
        if isinstance(raw_operation, str) and OPERATION_ID_RE.fullmatch(raw_operation):
            operation = raw_operation
    try:
        request = BridgeRequest.from_dict(value)
        operation_id = request.operation_id
        operation = request.operation.value
        return _dispatch(request).to_dict()
    except KeyboardInterrupt:
        error = NoTugError("INTERRUPTED", "Bridge operation was interrupted")
        return _failure(operation_id, operation, BridgeOutcome.INTERRUPTED, error).to_dict()
    except NoTugError as exc:
        if exc.code == "BRIDGE_OPERATION_UNAVAILABLE":
            outcome = BridgeOutcome.UNAVAILABLE
        elif exc.code in {
            "BASELINE_MISSING",
            "BASELINE_REF_DRIFT",
            "SOURCE_HEAD_DRIFT",
            "SOURCE_DIRTY_DRIFT",
            "SOURCE_MANIFEST_DRIFT",
            "PROVENANCE_DIVERGENCE",
            "WORKTREE_ADMIN_DIVERGENCE",
        }:
            outcome = BridgeOutcome.DIVERGED
        else:
            outcome = BridgeOutcome.FAILED_CLOSED
        return _failure(operation_id, operation, outcome, exc).to_dict()
    except Exception:
        error = NoTugError("BRIDGE_INTERNAL_ERROR", "Unexpected bridge failure")
        return _failure(operation_id, operation, BridgeOutcome.FAILED_CLOSED, error).to_dict()
