"""Local-only, content-free resource measurement primitives."""

from __future__ import annotations

import re
import time
from contextvars import ContextVar, Token
from dataclasses import asdict, dataclass, field
from typing import Any

from .errors import NoTugError

RESOURCE_SCHEMA_VERSION = 1
RESOURCE_KIND = "notug.resource-receipt"
SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

PHASE_FIELDS = (
    "notug_active_seconds",
    "agent_execution_seconds",
    "human_review_wait_seconds",
    "integration_verification_seconds",
)

OPTIONAL_METRICS = (
    "peak_working_set_bytes",
    "io_read_bytes",
    "io_write_bytes",
    "files_inspected",
    "bytes_inspected",
    "worktree_apparent_size_bytes",
    "worktree_incremental_disk_bytes",
    "vault_size_before_bytes",
    "vault_size_after_bytes",
    "git_object_store_size_before_bytes",
    "git_object_store_size_after_bytes",
    "cleanup_bytes_reclaimed",
    "protected_checkout_writes_detected",
)

_git_launch_attempt_count: ContextVar[int | None] = ContextVar(
    "notug_resource_git_launch_attempt_count", default=None
)


def _safe_label(value: str, field_name: str) -> str:
    if SAFE_LABEL_RE.fullmatch(value) is None:
        raise NoTugError(
            "RESOURCE_RECEIPT_INVALID",
            f"{field_name} must be a short path-free protocol label",
        )
    return value


def _nonnegative(value: int | float | None, field_name: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise NoTugError(
            "RESOURCE_RECEIPT_INVALID", f"{field_name} must be non-negative or unavailable"
        )


def _nonnegative_int(value: int | None, field_name: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NoTugError(
            "RESOURCE_RECEIPT_INVALID",
            f"{field_name} must be a non-negative integer or unavailable",
        )


def note_git_launch_attempt() -> None:
    """Count a Git launch attempt only while a ResourceMeter is active in this context."""

    current = _git_launch_attempt_count.get()
    if current is not None:
        _git_launch_attempt_count.set(current + 1)


@dataclass(frozen=True, slots=True)
class ResourceReceipt:
    operation_id: str
    operation: str
    durations_seconds: dict[str, float | None]
    process_cpu_seconds: float
    git_launch_attempt_count: int
    peak_working_set_bytes: int | None = None
    io_read_bytes: int | None = None
    io_write_bytes: int | None = None
    files_inspected: int | None = None
    bytes_inspected: int | None = None
    worktree_apparent_size_bytes: int | None = None
    worktree_incremental_disk_bytes: int | None = None
    vault_size_before_bytes: int | None = None
    vault_size_after_bytes: int | None = None
    git_object_store_size_before_bytes: int | None = None
    git_object_store_size_after_bytes: int | None = None
    cleanup_bytes_reclaimed: int | None = None
    protected_checkout_writes_detected: int | None = None
    measurement_availability: dict[str, bool] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    schema_version: int = RESOURCE_SCHEMA_VERSION
    receipt_kind: str = RESOURCE_KIND

    def validate(self) -> None:
        _safe_label(self.operation_id, "operation_id")
        _safe_label(self.operation, "operation")
        if self.schema_version != RESOURCE_SCHEMA_VERSION or self.receipt_kind != RESOURCE_KIND:
            raise NoTugError(
                "RESOURCE_RECEIPT_INVALID", "Resource receipt schema identity is invalid"
            )
        if set(self.durations_seconds) != set(PHASE_FIELDS):
            raise NoTugError(
                "RESOURCE_RECEIPT_INVALID", "Resource receipt phase fields are incomplete"
            )
        for key, value in self.durations_seconds.items():
            _nonnegative(value, key)
        _nonnegative(self.process_cpu_seconds, "process_cpu_seconds")
        _nonnegative_int(self.git_launch_attempt_count, "git_launch_attempt_count")
        for metric in OPTIONAL_METRICS:
            _nonnegative_int(getattr(self, metric), metric)
        expected_availability = {
            *PHASE_FIELDS,
            "process_cpu_seconds",
            "git_launch_attempt_count",
            *OPTIONAL_METRICS,
        }
        if set(self.measurement_availability) != expected_availability or not all(
            isinstance(value, bool) for value in self.measurement_availability.values()
        ):
            raise NoTugError(
                "RESOURCE_RECEIPT_INVALID", "Measurement availability map is incomplete"
            )
        if (
            not self.measurement_availability["process_cpu_seconds"]
            or not (self.measurement_availability["git_launch_attempt_count"])
        ):
            raise NoTugError(
                "RESOURCE_RECEIPT_INVALID",
                "Always-measured process CPU and Git-count markers must be available",
            )
        for metric in OPTIONAL_METRICS:
            available = self.measurement_availability[metric]
            if available != (getattr(self, metric) is not None):
                raise NoTugError(
                    "RESOURCE_RECEIPT_INVALID",
                    "Measurement value and availability marker disagree",
                    {"metric": metric},
                )
        for phase, value in self.durations_seconds.items():
            if self.measurement_availability[phase] != (value is not None):
                raise NoTugError(
                    "RESOURCE_RECEIPT_INVALID",
                    "Phase value and availability marker disagree",
                    {"metric": phase},
                )
        for limitation in self.limitations:
            _safe_label(limitation, "limitation")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        result = asdict(self)
        result["limitations"] = list(self.limitations)
        return result


class ResourceMeter:
    """Measure active NoTUG wall/CPU time and explicitly supplied local metrics."""

    def __init__(self, operation_id: str, operation: str) -> None:
        self.operation_id = _safe_label(operation_id, "operation_id")
        self.operation = _safe_label(operation, "operation")
        self._start_wall: float | None = None
        self._start_cpu: float | None = None
        self._wall_seconds: float | None = None
        self._cpu_seconds: float | None = None
        self._git_count = 0
        self._git_token: Token[int | None] | None = None
        self._phases: dict[str, float | None] = {phase: None for phase in PHASE_FIELDS}
        self._metrics: dict[str, int | None] = {metric: None for metric in OPTIONAL_METRICS}

    def __enter__(self) -> ResourceMeter:
        if self._start_wall is not None:
            raise NoTugError("RESOURCE_METER_INVALID", "Resource meter cannot be entered twice")
        if _git_launch_attempt_count.get() is not None:
            raise NoTugError("RESOURCE_METER_INVALID", "Nested resource meters are not supported")
        self._git_token = _git_launch_attempt_count.set(0)
        self._start_wall = time.perf_counter()
        self._start_cpu = time.process_time()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        if self._start_wall is None or self._start_cpu is None or self._git_token is None:
            raise NoTugError("RESOURCE_METER_INVALID", "Resource meter was not active")
        self._wall_seconds = max(0.0, time.perf_counter() - self._start_wall)
        self._cpu_seconds = max(0.0, time.process_time() - self._start_cpu)
        self._git_count = _git_launch_attempt_count.get() or 0
        _git_launch_attempt_count.reset(self._git_token)
        self._phases["notug_active_seconds"] = self._wall_seconds

    def set_phase_duration(self, phase: str, seconds: float) -> None:
        if phase not in PHASE_FIELDS:
            raise NoTugError("RESOURCE_RECEIPT_INVALID", "Unknown resource phase")
        _nonnegative(seconds, phase)
        self._phases[phase] = float(seconds)

    def record_metric(self, metric: str, value: int) -> None:
        if metric not in OPTIONAL_METRICS:
            raise NoTugError("RESOURCE_RECEIPT_INVALID", "Unknown resource metric")
        _nonnegative_int(value, metric)
        self._metrics[metric] = value

    def receipt(self) -> ResourceReceipt:
        if self._wall_seconds is None or self._cpu_seconds is None:
            raise NoTugError(
                "RESOURCE_METER_INVALID", "Resource receipt is available only after measurement"
            )
        availability = {phase: value is not None for phase, value in self._phases.items()}
        availability.update({"process_cpu_seconds": True, "git_launch_attempt_count": True})
        availability.update({metric: value is not None for metric, value in self._metrics.items()})
        limitations: list[str] = []
        if self._metrics["peak_working_set_bytes"] is None:
            limitations.append("peak_working_set_not_sampled")
        if self._metrics["io_read_bytes"] is None or self._metrics["io_write_bytes"] is None:
            limitations.append("process_io_not_measured")
        if any(
            self._metrics[name] is None
            for name in (
                "worktree_apparent_size_bytes",
                "worktree_incremental_disk_bytes",
                "vault_size_before_bytes",
                "vault_size_after_bytes",
                "git_object_store_size_before_bytes",
                "git_object_store_size_after_bytes",
            )
        ):
            limitations.append("filesystem_sizes_not_measured")
        if self._metrics["protected_checkout_writes_detected"] is None:
            limitations.append("protected_checkout_monitor_not_attached")
        receipt = ResourceReceipt(
            operation_id=self.operation_id,
            operation=self.operation,
            durations_seconds=dict(self._phases),
            process_cpu_seconds=self._cpu_seconds,
            git_launch_attempt_count=self._git_count,
            peak_working_set_bytes=self._metrics["peak_working_set_bytes"],
            io_read_bytes=self._metrics["io_read_bytes"],
            io_write_bytes=self._metrics["io_write_bytes"],
            files_inspected=self._metrics["files_inspected"],
            bytes_inspected=self._metrics["bytes_inspected"],
            worktree_apparent_size_bytes=self._metrics["worktree_apparent_size_bytes"],
            worktree_incremental_disk_bytes=self._metrics["worktree_incremental_disk_bytes"],
            vault_size_before_bytes=self._metrics["vault_size_before_bytes"],
            vault_size_after_bytes=self._metrics["vault_size_after_bytes"],
            git_object_store_size_before_bytes=self._metrics["git_object_store_size_before_bytes"],
            git_object_store_size_after_bytes=self._metrics["git_object_store_size_after_bytes"],
            cleanup_bytes_reclaimed=self._metrics["cleanup_bytes_reclaimed"],
            protected_checkout_writes_detected=self._metrics["protected_checkout_writes_detected"],
            measurement_availability=availability,
            limitations=tuple(limitations),
        )
        receipt.validate()
        return receipt
