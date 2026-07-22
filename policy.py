"""Pure, deterministic policy classification for structural repository changes.

This module never reads changed file content and never grants authority.  It
classifies only paths and structural metadata already established by the Git
and filesystem evidence layers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .brand import (
    CLI_NAME,
    POLICY_FILENAME,
    PRODUCT_SHORT_NAME,
    VAULT_DIRECTORY_NAME,
)
from .config import PolicyConfig
from .models import ChangeEntry, PolicyFinding
from .util import safe_git_path

SEVERITIES = ("info", "low", "medium", "high", "block")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}


@dataclass(frozen=True, slots=True)
class _Rule:
    policy_key: str
    message: str


RULES: dict[str, _Rule] = {
    "DELETION": _Rule("deletions", "Tracked paths are deleted."),
    "RENAME": _Rule("renames", "Tracked paths are renamed or moved."),
    "BINARY_FILE": _Rule("binary_files", "Binary file changes require explicit review."),
    "MODE_CHANGE": _Rule(
        "mode_changes", "Executable-bit or other Git mode changes require explicit review."
    ),
    "SYMBOLIC_LINK": _Rule(
        "symbolic_links", "Symbolic-link changes require explicit target review."
    ),
    "OUTSIDE_SYMBOLIC_LINK": _Rule(
        "outside_symbolic_links",
        "A symbolic link resolves outside the disposable workspace.",
    ),
    "SUBMODULE_CHANGE": _Rule("submodules", "Submodule pointers or configuration are changed."),
    "GIT_INTERNAL": _Rule("git_internals", "A change targets Git internal metadata."),
    "NOTUG_METADATA": _Rule(
        "notug_metadata", f"A change targets {PRODUCT_SHORT_NAME} policy or local metadata."
    ),
    "ENVIRONMENT_FILE": _Rule("environment_files", "An environment-file-like path is changed."),
    "PRIVATE_KEY_FILE": _Rule("private_keys", "A private-key-like path is changed."),
    "CREDENTIAL_FILE": _Rule("credentials", "A credential- or secret-like path is changed."),
    "CI_DEPLOYMENT": _Rule(
        "ci_deployment", "Continuous-integration or deployment configuration is changed."
    ),
    "LOCKFILE": _Rule("lockfiles", "A package or dependency lockfile is changed."),
    "OUTSIDE_EXPECTED_ROOTS": _Rule(
        "outside_expected_roots", "A changed path is outside the configured project roots."
    ),
    "UNSAFE_PATH": _Rule(
        "unsafe_paths", "A changed path is unsafe or ambiguous for portable Git handling."
    ),
    "FILE_THRESHOLD_EXCEEDED": _Rule(
        "threshold_exceeded", "The changed-file count exceeds the configured threshold."
    ),
    "BYTE_THRESHOLD_EXCEEDED": _Rule(
        "threshold_exceeded", "The changed-byte total exceeds the configured threshold."
    ),
}

PRIVATE_KEY_SUFFIXES = {
    ".der",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
    ".pkcs12",
    ".ppk",
}
PRIVATE_KEY_NAMES = {
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
CREDENTIAL_NAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    "_netrc",
    "credentials",
    "credentials.json",
    "service-account.json",
    "service_account.json",
}
CREDENTIAL_COMPONENT = re.compile(
    r"(?:^|[._-])(?:api[-_]?key|credential(?:s)?|password(?:s)?|passwd|secret(?:s)?|"
    r"token(?:s)?)(?:$|[._-])",
    re.IGNORECASE,
)
CI_DIRECTORY_NAMES = {
    ".buildkite",
    ".circleci",
    "ansible",
    "ci",
    "deploy",
    "deployment",
    "deployments",
    "helm",
    "infra",
    "infrastructure",
    "k8s",
    "kubernetes",
    "terraform",
}
CI_FILE_NAMES = {
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "appveyor.yml",
    "appveyor.yaml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "cloudbuild.yaml",
    "cloudbuild.yml",
    "compose.yaml",
    "compose.yml",
    "containerfile",
    "docker-compose.yaml",
    "docker-compose.yml",
    "dockerfile",
    "fly.toml",
    "jenkinsfile",
    "netlify.toml",
    "procfile",
    "render.yaml",
    "render.yml",
    "vercel.json",
}
LOCKFILE_NAMES = {
    "bun.lock",
    "bun.lockb",
    "cargo.lock",
    "composer.lock",
    "flake.lock",
    "gemfile.lock",
    "go.sum",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}
SENSITIVE_CODES = {"ENVIRONMENT_FILE", "PRIVATE_KEY_FILE", "CREDENTIAL_FILE"}
HARD_BLOCK_CODES = {"OUTSIDE_SYMBOLIC_LINK", "UNSAFE_PATH"}


@dataclass(slots=True)
class PolicyEvaluation:
    """Policy findings and summaries produced without mutating input changes."""

    findings: list[PolicyFinding]
    classifications_by_path: dict[str, list[str]]
    risk_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "classifications_by_path": {
                path: list(codes) for path, codes in self.classifications_by_path.items()
            },
            "risk_summary": dict(self.risk_summary),
        }


@dataclass(slots=True)
class _FindingBucket:
    severity: str
    message: str
    paths: set[str]


def _normalise_path(path: str) -> str:
    return path.replace("\\", "/")


def _stable_paths(paths: Iterable[str]) -> list[str]:
    return sorted(set(paths), key=lambda value: (value.casefold(), value))


def _parts(path: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in _normalise_path(path).split("/") if part)


def _is_environment_file(path: str) -> bool:
    parts = _parts(path)
    name = parts[-1] if parts else ""
    return name == ".env" or name == ".envrc" or name.startswith(".env.") or name.endswith(".env")


def _is_private_key_file(path: str) -> bool:
    parts = _parts(path)
    if not parts:
        return False
    name = parts[-1]
    suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    return (
        name in PRIVATE_KEY_NAMES
        or suffix in PRIVATE_KEY_SUFFIXES
        or "private_key" in name
        or "private-key" in name
        or (name.startswith("ssh_host_") and name.endswith("_key"))
    )


def _is_credential_file(path: str) -> bool:
    parts = _parts(path)
    if not parts:
        return False
    name = parts[-1]
    if name in CREDENTIAL_NAMES:
        return True
    if len(parts) >= 2 and parts[-2:] == (".aws", "credentials"):
        return True
    return CREDENTIAL_COMPONENT.search(name) is not None


def _is_ci_or_deployment(path: str) -> bool:
    parts = _parts(path)
    if not parts:
        return False
    name = parts[-1]
    if len(parts) >= 2 and parts[0] == ".github" and parts[1] in {"actions", "workflows"}:
        return True
    if any(part in CI_DIRECTORY_NAMES for part in parts[:-1]):
        return True
    return name in CI_FILE_NAMES or name.endswith((".tf", ".tfvars"))


def _is_lockfile(path: str) -> bool:
    parts = _parts(path)
    if not parts:
        return False
    name = parts[-1]
    return name in LOCKFILE_NAMES or name.endswith(".lock")


def _path_codes(path: str) -> set[str]:
    normalized = _normalise_path(path)
    parts = _parts(normalized)
    codes: set[str] = set()
    safe, _reason = safe_git_path(normalized)
    has_control = any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in path)
    if not safe or has_control:
        codes.add("UNSAFE_PATH")
    if ".git" in parts:
        codes.add("GIT_INTERNAL")
    if parts and (
        any(part in {f".{CLI_NAME}", f".{VAULT_DIRECTORY_NAME}"} for part in parts)
        or parts[-1] in {f".{POLICY_FILENAME}", POLICY_FILENAME}
    ):
        codes.add("NOTUG_METADATA")
    if _is_environment_file(normalized):
        codes.add("ENVIRONMENT_FILE")
    if _is_private_key_file(normalized):
        codes.add("PRIVATE_KEY_FILE")
    if _is_credential_file(normalized):
        codes.add("CREDENTIAL_FILE")
    if _is_ci_or_deployment(normalized):
        codes.add("CI_DEPLOYMENT")
    if _is_lockfile(normalized):
        codes.add("LOCKFILE")
    return codes


def ignored_sensitive_paths(paths: Iterable[str]) -> list[str]:
    """Return ignored paths whose names indicate secret-bearing material.

    The caller supplies paths reported by Git's ignored-file query.  This
    helper performs no filesystem reads and does not inspect file content.
    """

    sensitive = {
        _normalise_path(path) for path in paths if _path_codes(path).intersection(SENSITIVE_CODES)
    }
    return _stable_paths(sensitive)


def find_ignored_sensitive_paths(paths: Iterable[str]) -> list[str]:
    """Compatibility spelling for callers performing ignored-path audits."""

    return ignored_sensitive_paths(paths)


def _change_paths(change: ChangeEntry) -> list[str]:
    paths = [change.path]
    if change.old_path is not None:
        paths.append(change.old_path)
    return _stable_paths(_normalise_path(path) for path in paths)


def _kind(change: ChangeEntry) -> str:
    return str(change.kind).casefold()


def _status_token(change: ChangeEntry) -> str:
    stripped = change.status.strip().upper()
    return stripped.split(maxsplit=1)[0] if stripped else ""


def _is_deletion(change: ChangeEntry) -> bool:
    return _kind(change) == "delete" or _status_token(change) in {"D", "DD"}


def _is_rename(change: ChangeEntry) -> bool:
    return _kind(change) == "rename" or re.fullmatch(r"R\d{0,3}", _status_token(change)) is not None


def _is_mode_change(change: ChangeEntry) -> bool:
    if _kind(change) == "mode":
        return True
    if change.old_mode is not None and change.new_mode is not None:
        return change.old_mode != change.new_mode
    return change.new_mode == "100755" and change.old_mode != "100755"


def _is_symlink(change: ChangeEntry) -> bool:
    return (
        _kind(change) == "symlink"
        or change.old_mode == "120000"
        or change.new_mode == "120000"
        or change.symlink_target is not None
        or change.symlink_outside_workspace
    )


def _is_submodule(change: ChangeEntry) -> bool:
    return (
        _kind(change) == "submodule"
        or change.submodule
        or change.old_mode == "160000"
        or change.new_mode == "160000"
        or _normalise_path(change.path).casefold() == ".gitmodules"
    )


def _expected_roots(config: PolicyConfig) -> tuple[str, ...]:
    roots: set[str] = set()
    for root in config.expected_roots:
        normalized = _normalise_path(root).strip("/")
        safe, _reason = safe_git_path(normalized)
        if safe:
            roots.add(normalized.casefold())
    return tuple(sorted(roots))


def _inside_expected_root(path: str, roots: tuple[str, ...]) -> bool:
    candidate = _normalise_path(path).casefold()
    return any(candidate == root or candidate.startswith(root + "/") for root in roots)


def _changed_bytes(change: ChangeEntry) -> int:
    if change.byte_delta and change.old_size == 0 and change.new_size == 0:
        return abs(change.byte_delta)
    if _is_deletion(change):
        return max(change.old_size, 0)
    if _kind(change) == "create":
        return max(change.new_size, 0)
    return max(change.old_size, 0) + max(change.new_size, 0)


def evaluate_policy(changes: Iterable[ChangeEntry], config: PolicyConfig) -> PolicyEvaluation:
    """Classify structural changes according to the authoritative policy copy.

    Evaluation is deterministic and side-effect free.  No field in a
    ``ChangeEntry`` is interpreted as approval, and pre-existing
    ``classifications`` are ignored rather than trusted.
    """

    entries = tuple(changes)
    buckets: dict[str, _FindingBucket] = {}
    path_codes: dict[str, set[str]] = {}

    def add(code: str, paths: Iterable[str] = ()) -> None:
        rule = RULES[code]
        severity = "block" if code in HARD_BLOCK_CODES else config.findings[rule.policy_key]
        normalized_paths = {_normalise_path(path) for path in paths}
        bucket = buckets.get(code)
        if bucket is None:
            bucket = _FindingBucket(severity, rule.message, set())
            buckets[code] = bucket
        bucket.paths.update(normalized_paths)
        for path in normalized_paths:
            path_codes.setdefault(path, set()).add(code)

    expected_roots = _expected_roots(config)
    expected_roots_enabled = bool(config.expected_roots)

    for change in entries:
        affected_paths = _change_paths(change)
        primary_path = _normalise_path(change.path)

        if _is_deletion(change):
            add("DELETION", [primary_path])
        if _is_rename(change):
            add("RENAME", affected_paths)
        if change.binary or _kind(change) == "binary":
            add("BINARY_FILE", [primary_path])
        if _is_mode_change(change):
            add("MODE_CHANGE", [primary_path])
        if _is_symlink(change):
            add("SYMBOLIC_LINK", [primary_path])
        if change.symlink_outside_workspace:
            add("OUTSIDE_SYMBOLIC_LINK", [primary_path])
        if _is_submodule(change):
            add("SUBMODULE_CHANGE", affected_paths)

        for path in affected_paths:
            for code in _path_codes(path):
                add(code, [path])
            safe, _reason = safe_git_path(path)
            if expected_roots_enabled and safe and not _inside_expected_root(path, expected_roots):
                add("OUTSIDE_EXPECTED_ROOTS", [path])

    changed_bytes = sum(_changed_bytes(change) for change in entries)
    if len(entries) > config.max_changed_files:
        add("FILE_THRESHOLD_EXCEEDED")
    if changed_bytes > config.max_changed_bytes:
        add("BYTE_THRESHOLD_EXCEEDED")

    findings = [
        PolicyFinding(
            code=code,
            severity=bucket.severity,
            message=bucket.message,
            paths=_stable_paths(bucket.paths),
        )
        for code, bucket in buckets.items()
    ]
    findings.sort(
        key=lambda finding: (
            -SEVERITY_RANK[finding.severity],
            finding.code,
            tuple((path.casefold(), path) for path in finding.paths),
        )
    )

    ordered_path_codes = {
        path: sorted(codes)
        for path, codes in sorted(
            path_codes.items(), key=lambda item: (item[0].casefold(), item[0])
        )
    }
    severity_counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity_counts[finding.severity] += 1
    overall = max(
        (finding.severity for finding in findings),
        key=lambda severity: SEVERITY_RANK[severity],
        default="info",
    )
    affected_path_count = len({path for change in entries for path in _change_paths(change)})
    risk_summary: dict[str, Any] = {
        "overall_severity": overall,
        "blocked": overall == "block",
        "finding_count": len(findings),
        "finding_codes": [finding.code for finding in findings],
        "severity_counts": severity_counts,
        "changed_files": len(entries),
        "affected_path_count": affected_path_count,
        "changed_bytes": changed_bytes,
    }
    return PolicyEvaluation(findings, ordered_path_codes, risk_summary)


__all__ = [
    "PolicyEvaluation",
    "evaluate_policy",
    "find_ignored_sensitive_paths",
    "ignored_sensitive_paths",
]
