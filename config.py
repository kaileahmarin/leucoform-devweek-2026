"""Strict, versioned local policy parsing."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import NoTugError
from .util import atomic_write_bytes, sha256_bytes

DEFAULT_POLICY = b"""schema_version = 1

[thresholds]
max_changed_files = 100
max_changed_bytes = 10000000
expected_roots = []

[findings]
deletions = "high"
renames = "medium"
binary_files = "high"
mode_changes = "high"
symbolic_links = "high"
outside_symbolic_links = "block"
submodules = "block"
git_internals = "block"
notug_metadata = "block"
environment_files = "high"
private_keys = "block"
credentials = "high"
ci_deployment = "high"
lockfiles = "medium"
outside_expected_roots = "high"
threshold_exceeded = "high"
unsafe_paths = "block"

[validation]
commands = []

[privacy]
redact_export_paths = true
"""

TOP_FIELDS = {"schema_version", "thresholds", "findings", "validation", "privacy"}
THRESHOLD_FIELDS = {"max_changed_files", "max_changed_bytes", "expected_roots"}
FINDING_FIELDS = {
    "deletions",
    "renames",
    "binary_files",
    "mode_changes",
    "symbolic_links",
    "outside_symbolic_links",
    "submodules",
    "git_internals",
    "notug_metadata",
    "environment_files",
    "private_keys",
    "credentials",
    "ci_deployment",
    "lockfiles",
    "outside_expected_roots",
    "threshold_exceeded",
    "unsafe_paths",
}
VALIDATION_FIELDS = {"commands"}
PRIVACY_FIELDS = {"redact_export_paths"}
SEVERITIES = {"info", "low", "medium", "high", "block"}


@dataclass(slots=True)
class PolicyConfig:
    schema_version: int
    max_changed_files: int
    max_changed_bytes: int
    expected_roots: list[str]
    findings: dict[str, str]
    validation_commands: list[list[str]] = field(default_factory=list)
    redact_export_paths: bool = True
    raw_bytes: bytes = b""

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.raw_bytes)


def _strict_fields(value: dict[str, Any], allowed: set[str], section: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise NoTugError(
            "POLICY_SCHEMA_INVALID",
            f"Unknown field in {section}",
            {"section": section, "unknown_fields": unknown},
        )


def parse_policy_bytes(raw: bytes) -> PolicyConfig:
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise NoTugError("POLICY_SCHEMA_INVALID", "Policy is not valid UTF-8 TOML") from exc
    _strict_fields(data, TOP_FIELDS, "policy")
    schema_version = data.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        raise NoTugError(
            "POLICY_SCHEMA_INVALID",
            "Unsupported policy schema_version",
            {"schema_version": data.get("schema_version")},
        )
    for section in ("thresholds", "findings", "validation", "privacy"):
        if not isinstance(data.get(section), dict):
            raise NoTugError("POLICY_SCHEMA_INVALID", f"Missing or invalid [{section}] section")
    thresholds = data["thresholds"]
    findings = data["findings"]
    validation = data["validation"]
    privacy = data["privacy"]
    _strict_fields(thresholds, THRESHOLD_FIELDS, "thresholds")
    _strict_fields(findings, FINDING_FIELDS, "findings")
    _strict_fields(validation, VALIDATION_FIELDS, "validation")
    _strict_fields(privacy, PRIVACY_FIELDS, "privacy")
    if set(findings) != FINDING_FIELDS:
        raise NoTugError(
            "POLICY_SCHEMA_INVALID",
            "All finding classifications are required",
            {"missing_fields": sorted(FINDING_FIELDS - set(findings))},
        )
    if any(not isinstance(value, str) or value not in SEVERITIES for value in findings.values()):
        raise NoTugError("POLICY_SCHEMA_INVALID", "Finding severities are invalid")
    max_files = thresholds.get("max_changed_files")
    max_bytes = thresholds.get("max_changed_bytes")
    roots = thresholds.get("expected_roots")
    commands = validation.get("commands")
    redact = privacy.get("redact_export_paths")
    if not isinstance(max_files, int) or isinstance(max_files, bool) or max_files < 1:
        raise NoTugError("POLICY_SCHEMA_INVALID", "max_changed_files must be a positive integer")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise NoTugError("POLICY_SCHEMA_INVALID", "max_changed_bytes must be a positive integer")
    if not isinstance(roots, list) or not all(isinstance(item, str) for item in roots):
        raise NoTugError("POLICY_SCHEMA_INVALID", "expected_roots must be an array of strings")
    if not isinstance(commands, list) or not all(
        isinstance(command, list)
        and command
        and all(isinstance(argument, str) and argument for argument in command)
        for command in commands
    ):
        raise NoTugError("POLICY_SCHEMA_INVALID", "validation.commands must be arrays of arguments")
    if not isinstance(redact, bool):
        raise NoTugError("POLICY_SCHEMA_INVALID", "redact_export_paths must be boolean")
    return PolicyConfig(
        schema_version=1,
        max_changed_files=max_files,
        max_changed_bytes=max_bytes,
        expected_roots=roots,
        findings=dict(findings),
        validation_commands=[list(command) for command in commands],
        redact_export_paths=redact,
        raw_bytes=raw,
    )


def create_or_load_policy(path: Path) -> PolicyConfig:
    if not path.exists():
        atomic_write_bytes(path, DEFAULT_POLICY)
    return parse_policy_bytes(path.read_bytes())


def load_policy(path: Path, expected_hash: str | None = None) -> PolicyConfig:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise NoTugError("POLICY_MISSING", "Authoritative local policy is unavailable") from exc
    policy = parse_policy_bytes(raw)
    if expected_hash is not None and policy.sha256 != expected_hash:
        raise NoTugError(
            "POLICY_HASH_MISMATCH",
            "The session policy has changed since session creation",
            {"expected": expected_hash, "actual": policy.sha256},
        )
    return policy
