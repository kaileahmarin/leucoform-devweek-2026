"""Verify built release artifacts without uploading or publishing them."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
import zipfile
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import Any

ARCHIVE_UNSAFE_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ud800-\udfff]"
)
WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
FORBIDDEN_ARCHIVE_COMPONENTS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "__pycache__",
    "dist",
}
SDIST_ROOT_FILES = {
    "AGENTS.md",
    "CHANGELOG.md",
    "LICENSE",
    "MANIFEST.in",
    "PLAN.md",
    "PROMPT.md",
    "README.md",
    "STATUS.md",
    "THIRD-PARTY-NOTICES.md",
    "pyproject.toml",
}
EGG_INFO_FILES = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "requires.txt",
    "top_level.txt",
}


class VerificationError(RuntimeError):
    """A stable release-verification failure."""


class _CaseSensitiveConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


@dataclass(frozen=True, slots=True)
class ProjectMetadata:
    name: str
    normalized_name: str
    version: str
    requires_python: str
    import_name: str
    console_scripts: dict[str, str]
    gui_scripts: dict[str, str]
    description: str
    author_names: tuple[str, ...]
    keywords: tuple[str, ...]
    classifiers: tuple[str, ...]
    license_expression: str
    license_files: tuple[str, ...]
    dependencies: tuple[str, ...]
    optional_dependencies: dict[str, tuple[str, ...]]
    urls: dict[str, str]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _normalized_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).casefold()


def _load_project_metadata(project_root: Path) -> ProjectMetadata:
    try:
        raw = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
        project = raw["project"]
        name = project["name"]
        version = project["version"]
        requires_python = project["requires-python"]
        scripts = project["scripts"]
        gui_scripts = project.get("gui-scripts", {})
        description = project["description"]
        authors = project["authors"]
        keywords = project["keywords"]
        classifiers = project["classifiers"]
        license_expression = project["license"]
        license_files = project["license-files"]
        dependencies = project.get("dependencies", [])
        optional_dependencies = project.get("optional-dependencies", {})
        urls = project.get("urls", {})
    except (KeyError, OSError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError("pyproject.toml has incomplete release metadata") from exc
    _require(isinstance(name, str) and bool(name), "Project name must be a non-empty string")
    _require(
        isinstance(version, str) and bool(version), "Project version must be a non-empty string"
    )
    _require(
        isinstance(requires_python, str) and bool(requires_python),
        "requires-python must be a non-empty string",
    )
    _require(isinstance(scripts, dict) and bool(scripts), "Project console scripts are missing")
    _require(isinstance(description, str) and bool(description), "Project description is missing")
    _require(
        isinstance(authors, list)
        and bool(authors)
        and all(
            isinstance(author, dict)
            and isinstance(author.get("name"), str)
            and bool(author["name"])
            and "email" not in author
            for author in authors
        ),
        "Project authors must be named without unverifiable email metadata",
    )
    _require(
        isinstance(keywords, list) and all(isinstance(value, str) for value in keywords),
        "Project keywords are invalid",
    )
    _require(
        isinstance(classifiers, list) and all(isinstance(value, str) for value in classifiers),
        "Project classifiers are invalid",
    )
    _require(
        isinstance(license_expression, str) and bool(license_expression),
        "Project license expression is missing",
    )
    _require(
        isinstance(license_files, list)
        and bool(license_files)
        and all(isinstance(value, str) and bool(value) for value in license_files),
        "Project license-file metadata is invalid",
    )
    _require(
        isinstance(dependencies, list) and all(isinstance(value, str) for value in dependencies),
        "Project dependencies are invalid",
    )
    _require(
        isinstance(optional_dependencies, dict)
        and all(
            isinstance(extra, str)
            and isinstance(values, list)
            and all(isinstance(value, str) for value in values)
            for extra, values in optional_dependencies.items()
        ),
        "Project optional dependencies are invalid",
    )
    _require(
        isinstance(urls, dict)
        and all(isinstance(label, str) and isinstance(url, str) for label, url in urls.items()),
        "Project URLs are invalid",
    )
    console_scripts: dict[str, str] = {}
    for script_name, target in scripts.items():
        _require(
            isinstance(script_name, str) and isinstance(target, str),
            "Project console-script metadata is invalid",
        )
        console_scripts[script_name] = target
    _require(
        isinstance(gui_scripts, dict)
        and all(
            isinstance(name, str) and isinstance(target, str)
            for name, target in gui_scripts.items()
        ),
        "Project GUI-script metadata is invalid",
    )
    notug_target = console_scripts.get("notug")
    if notug_target is None:
        raise VerificationError("The required notug console entry point is missing")
    module_target, separator, _callable = notug_target.partition(":")
    _require(bool(separator and module_target), "The notug console entry point is invalid")
    import_name = module_target.split(".", 1)[0]
    return ProjectMetadata(
        name=name,
        normalized_name=_normalized_distribution_name(name),
        version=version,
        requires_python=requires_python,
        import_name=import_name,
        console_scripts=console_scripts,
        gui_scripts=dict(gui_scripts),
        description=description,
        author_names=tuple(author["name"] for author in authors),
        keywords=tuple(keywords),
        classifiers=tuple(classifiers),
        license_expression=license_expression,
        license_files=tuple(license_files),
        dependencies=tuple(dependencies),
        optional_dependencies={
            str(extra): tuple(values) for extra, values in optional_dependencies.items()
        },
        urls={str(label): str(url) for label, url in urls.items()},
    )


def _validate_archive_name(name: str) -> tuple[str, ...]:
    _require(bool(name), "Archive contains an empty member name")
    _require("\\" not in name, f"Archive member is not a portable POSIX path: {name!r}")
    _require(not name.startswith("/"), f"Archive member is absolute: {name!r}")
    _require(not re.match(r"^[A-Za-z]:", name), f"Archive member is drive-qualified: {name!r}")
    _require(
        not ARCHIVE_UNSAFE_RE.search(name), "Archive member contains unsafe Unicode or controls"
    )
    stripped = name[:-1] if name.endswith("/") else name
    _require(bool(stripped), "Archive member has no usable path")
    parts = tuple(stripped.split("/"))
    _require(
        all(part not in {"", ".", ".."} for part in parts),
        f"Archive member has an ambiguous path component: {name!r}",
    )
    for part in parts:
        folded = part.casefold()
        _require(
            folded not in FORBIDDEN_ARCHIVE_COMPONENTS,
            f"Archive contains forbidden generated or VCS content: {name!r}",
        )
        _require(not folded.endswith((".pyc", ".pyo")), f"Archive contains bytecode: {name!r}")
        _require(
            not any(character in '<>:"|?*' for character in part),
            f"Archive member is not Windows-portable: {name!r}",
        )
        _require(not part.endswith((" ", ".")), f"Archive member has an unsafe suffix: {name!r}")
        stem = part.split(".", 1)[0].upper()
        _require(stem not in WINDOWS_RESERVED, f"Archive member uses a reserved name: {name!r}")
    return parts


def _sha256_record_value(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + encoded.decode("ascii")


def _verify_wheel_record(files: dict[str, bytes], record_name: str) -> None:
    _require(record_name in files, "Wheel RECORD is missing")
    try:
        rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"), newline="")))
    except (UnicodeError, csv.Error) as exc:
        raise VerificationError("Wheel RECORD is not valid UTF-8 CSV") from exc
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        _require(len(row) == 3, "Wheel RECORD rows must contain exactly three fields")
        path, digest, size = row
        _require(path not in records, f"Wheel RECORD contains a duplicate path: {path!r}")
        records[path] = (digest, size)
    _require(set(records) == set(files), "Wheel RECORD paths do not match wheel members")
    for path, data in files.items():
        digest, size = records[path]
        if path == record_name:
            _require(not digest and not size, "Wheel RECORD must not hash itself")
            continue
        _require(digest == _sha256_record_value(data), f"Wheel RECORD hash mismatch: {path}")
        _require(size == str(len(data)), f"Wheel RECORD size mismatch: {path}")


def _metadata_value(data: bytes, key: str, label: str) -> str:
    try:
        message = BytesParser(policy=default).parsebytes(data)
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"{label} is not valid package metadata") from exc
    value = message.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{label} is missing {key}")
    return value


def _metadata_values(data: bytes, key: str, label: str) -> tuple[str, ...]:
    try:
        message = BytesParser(policy=default).parsebytes(data)
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"{label} is not valid package metadata") from exc
    values = message.get_all(key, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise VerificationError(f"{label} has invalid {key} fields")
    return tuple(values)


def _canonical_requirement(value: str, label: str) -> str:
    compact = re.sub(r"\s+", "", value)
    match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9._,-]+\])?(.*)", compact)
    if match is None:
        raise VerificationError(f"{label} contains an unsupported requirement: {value!r}")
    name = re.sub(r"[-_.]+", "-", match.group(1)).casefold()
    extras_raw = match.group(2)
    extras = ""
    if extras_raw:
        normalized = sorted(
            re.sub(r"[-_.]+", "-", item).casefold() for item in extras_raw[1:-1].split(",")
        )
        extras = f"[{','.join(normalized)}]"
    tail = match.group(3)
    if not tail:
        return name + extras
    _require(
        not tail.startswith("@") and ";" not in tail,
        f"{label} contains an unsupported direct URL or marker",
    )
    specifiers = sorted(item for item in tail.split(",") if item)
    return name + extras + ",".join(specifiers)


def _metadata_requirement_counter(values: Sequence[str], label: str) -> Counter[tuple[str, str]]:
    result: Counter[tuple[str, str]] = Counter()
    marker_pattern = re.compile(r"extra\s*==\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    for value in values:
        requirement, separator, marker = value.partition(";")
        extra = ""
        if separator:
            matched = marker_pattern.fullmatch(marker.strip())
            if matched is None:
                raise VerificationError(f"{label} contains an unsupported dependency marker")
            extra = re.sub(r"[-_.]+", "-", matched.group(1)).casefold()
        result[(extra, _canonical_requirement(requirement, label))] += 1
    return result


def _verify_project_metadata(data: bytes, label: str, metadata: ProjectMetadata) -> None:
    expected_single = {
        "Name": metadata.name,
        "Version": metadata.version,
        "Requires-Python": metadata.requires_python,
        "Summary": metadata.description,
        "Author": ", ".join(metadata.author_names),
        "Keywords": ",".join(metadata.keywords),
        "License-Expression": metadata.license_expression,
    }
    for key, expected in expected_single.items():
        _require(
            _metadata_value(data, key, label) == expected,
            f"{label} {key} does not match pyproject.toml",
        )
    _require(
        not _metadata_values(data, "Author-email", label),
        f"{label} contains undeclared author email metadata",
    )
    _require(
        _metadata_values(data, "Classifier", label) == metadata.classifiers,
        f"{label} classifiers do not match pyproject.toml",
    )
    _require(
        _metadata_values(data, "License-File", label) == metadata.license_files,
        f"{label} license files do not match pyproject.toml",
    )
    project_urls: dict[str, str] = {}
    for value in _metadata_values(data, "Project-URL", label):
        name, separator, url = value.partition(",")
        _require(bool(separator and name.strip() and url.strip()), f"{label} has an invalid URL")
        _require(name.strip() not in project_urls, f"{label} has a duplicate project URL")
        project_urls[name.strip()] = url.strip()
    _require(project_urls == metadata.urls, f"{label} project URLs do not match pyproject.toml")

    expected_requirements: Counter[tuple[str, str]] = Counter()
    for requirement in metadata.dependencies:
        _require(";" not in requirement, "Runtime dependency markers require verifier support")
        expected_requirements[("", _canonical_requirement(requirement, label))] += 1
    for extra, requirements in metadata.optional_dependencies.items():
        normalized_extra = re.sub(r"[-_.]+", "-", extra).casefold()
        for requirement in requirements:
            _require(";" not in requirement, "Optional dependency markers require verifier support")
            expected_requirements[
                (normalized_extra, _canonical_requirement(requirement, label))
            ] += 1
    actual_requirements = _metadata_requirement_counter(
        _metadata_values(data, "Requires-Dist", label), label
    )
    _require(
        actual_requirements == expected_requirements,
        f"{label} dependencies do not match pyproject.toml",
    )
    expected_extras = tuple(
        re.sub(r"[-_.]+", "-", extra).casefold() for extra in metadata.optional_dependencies
    )
    actual_extras = tuple(
        re.sub(r"[-_.]+", "-", extra).casefold()
        for extra in _metadata_values(data, "Provides-Extra", label)
    )
    _require(
        actual_extras == expected_extras,
        f"{label} optional-dependency names do not match pyproject.toml",
    )


def _expected_package_files(project_root: Path, metadata: ProjectMetadata) -> set[str]:
    source_root = project_root / "src"
    package_root = source_root / metadata.import_name
    _require(package_root.is_dir(), f"Source package is missing: {package_root}")
    expected: set[str] = set()
    for path in package_root.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".svg"}:
            _require(not path.is_symlink(), f"Source package file is a symlink: {path}")
            expected.add(path.relative_to(source_root).as_posix())
    return expected


def verify_wheel(wheel_path: Path, project_root: Path, metadata: ProjectMetadata) -> None:
    expected_filename = f"{metadata.normalized_name}-{metadata.version}-py3-none-any.whl"
    _require(wheel_path.name == expected_filename, f"Unexpected wheel filename: {wheel_path.name}")
    dist_info = f"{metadata.normalized_name}-{metadata.version}.dist-info"
    required_metadata_files = {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/top_level.txt",
    }
    try:
        with zipfile.ZipFile(wheel_path) as archive:
            _require(archive.testzip() is None, "Wheel CRC verification failed")
            files: dict[str, bytes] = {}
            seen_paths: set[str] = set()
            for member in archive.infolist():
                parts = _validate_archive_name(member.filename)
                canonical_path = "/".join(parts)
                _require(canonical_path not in seen_paths, "Wheel contains duplicate member paths")
                seen_paths.add(canonical_path)
                _require(not member.flag_bits & 0x1, "Wheel contains an encrypted member")
                member_type = stat.S_IFMT(member.external_attr >> 16)
                if member.create_system == 3:
                    _require(
                        member_type in {0, stat.S_IFREG, stat.S_IFDIR},
                        "Wheel contains a link or special file",
                    )
                if not member.is_dir():
                    files[member.filename] = archive.read(member)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise VerificationError(f"Wheel could not be read safely: {wheel_path.name}") from exc

    expected_package_files = _expected_package_files(project_root, metadata)
    expected_files = expected_package_files | required_metadata_files
    _require(
        set(files) == expected_files, "Wheel members do not exactly match expected package content"
    )
    for relative in expected_package_files:
        source = (project_root / "src" / relative).read_bytes()
        _require(files[relative] == source, f"Wheel source bytes differ: {relative}")

    metadata_name = f"{dist_info}/METADATA"
    _verify_project_metadata(files[metadata_name], "Wheel METADATA", metadata)
    wheel_metadata = f"{dist_info}/WHEEL"
    _require(
        _metadata_value(files[wheel_metadata], "Root-Is-Purelib", "Wheel WHEEL").casefold()
        == "true",
        "Wheel is not marked pure Python",
    )
    _require(
        _metadata_value(files[wheel_metadata], "Tag", "Wheel WHEEL") == "py3-none-any",
        "Wheel tag is not py3-none-any",
    )
    license_name = f"{dist_info}/licenses/LICENSE"
    _require(
        files[license_name] == (project_root / "LICENSE").read_bytes(), "Wheel license differs"
    )
    top_level_name = f"{dist_info}/top_level.txt"
    _require(
        files[top_level_name].decode("utf-8").splitlines() == [metadata.import_name],
        "Wheel top-level package metadata is invalid",
    )
    parser = _CaseSensitiveConfigParser(interpolation=None)
    try:
        parser.read_string(files[f"{dist_info}/entry_points.txt"].decode("utf-8"))
    except (UnicodeError, configparser.Error) as exc:
        raise VerificationError("Wheel entry_points.txt is invalid") from exc
    _require(parser.has_section("console_scripts"), "Wheel console_scripts section is missing")
    _require(
        dict(parser.items("console_scripts")) == metadata.console_scripts,
        "Wheel console scripts do not match pyproject.toml",
    )
    _require(parser.has_section("gui_scripts"), "Wheel gui_scripts section is missing")
    _require(
        dict(parser.items("gui_scripts")) == metadata.gui_scripts,
        "Wheel GUI scripts do not match pyproject.toml",
    )
    _verify_wheel_record(files, f"{dist_info}/RECORD")


def _expected_sdist_sources(project_root: Path, metadata: ProjectMetadata) -> set[str]:
    expected: set[str] = set()
    for relative in SDIST_ROOT_FILES:
        path = project_root / relative
        _require(path.is_file(), f"Required source-distribution input is missing: {relative}")
        _require(not path.is_symlink(), f"Source-distribution input is a symlink: {relative}")
        expected.add(relative)
    inclusions = (
        (project_root / ".github", ("*.yml",)),
        (project_root / "docs", ("*.md",)),
        (project_root / "examples", ("*.toml",)),
        (project_root / "packaging", ("*",)),
        (project_root / "scripts", ("*.py", "*.ps1", "*.sh")),
        (project_root / "tests", ("*.py",)),
        (project_root / "src" / metadata.import_name, ("*.py", "*.svg")),
    )
    for base, patterns in inclusions:
        _require(base.is_dir(), f"Required source-distribution directory is missing: {base}")
        _require(not base.is_symlink(), f"Source-distribution directory is a symlink: {base}")
        for pattern in patterns:
            for path in base.rglob(pattern):
                if path.is_file():
                    _require(
                        not path.is_symlink(),
                        f"Source-distribution input is a symlink: {path}",
                    )
                    expected.add(path.relative_to(project_root).as_posix())
    return expected


def verify_sdist(sdist_path: Path, project_root: Path, metadata: ProjectMetadata) -> None:
    archive_root = f"{metadata.normalized_name}-{metadata.version}"
    expected_filename = f"{archive_root}.tar.gz"
    _require(sdist_path.name == expected_filename, f"Unexpected sdist filename: {sdist_path.name}")
    files: dict[str, bytes] = {}
    seen_paths: set[str] = set()
    try:
        with tarfile.open(sdist_path, mode="r:gz") as archive:
            for member in archive.getmembers():
                parts = _validate_archive_name(member.name)
                _require(parts[0] == archive_root, "Sdist contains more than one top-level root")
                canonical_path = "/".join(parts)
                _require(canonical_path not in seen_paths, "Sdist contains duplicate member paths")
                seen_paths.add(canonical_path)
                if len(parts) == 1:
                    _require(member.isdir(), "Sdist top-level root is not a directory")
                    continue
                relative = "/".join(parts[1:])
                if member.isdir():
                    continue
                _require(member.isfile(), f"Sdist contains a link or special file: {relative}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise VerificationError(f"Sdist member cannot be read: {relative}")
                files[relative] = extracted.read()
    except (OSError, tarfile.TarError) as exc:
        raise VerificationError(f"Sdist could not be read safely: {sdist_path.name}") from exc

    expected_sources = _expected_sdist_sources(project_root, metadata)
    egg_info_root = f"src/{metadata.normalized_name}.egg-info"
    egg_info_sources = {f"{egg_info_root}/{name}" for name in EGG_INFO_FILES}
    expected_files = expected_sources | egg_info_sources | {"PKG-INFO", "setup.cfg"}
    _require(set(files) == expected_files, "Sdist members do not exactly match expected content")
    for relative in expected_sources:
        _require(
            files[relative] == (project_root / relative).read_bytes(),
            f"Sdist source bytes differ: {relative}",
        )
    try:
        listed_sources = {
            line
            for line in files[f"{egg_info_root}/SOURCES.txt"].decode("utf-8").splitlines()
            if line
        }
    except UnicodeError as exc:
        raise VerificationError("Sdist SOURCES.txt is not valid UTF-8") from exc
    _require(
        listed_sources == expected_sources | egg_info_sources,
        "Sdist SOURCES.txt does not match the verified source manifest",
    )
    _verify_project_metadata(files["PKG-INFO"], "Sdist PKG-INFO", metadata)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _run(command: Sequence[str], *, cwd: Path, environment: dict[str, str]) -> str:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        rendered = " ".join(command)
        stdout = completed.stdout[-4000:]
        stderr = completed.stderr[-4000:]
        raise VerificationError(
            f"Command failed ({completed.returncode}): {rendered}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return completed.stdout


def verify_clean_install(wheel_path: Path, project_root: Path, metadata: ProjectMetadata) -> None:
    with tempfile.TemporaryDirectory(prefix="notug-release-verify-") as temporary:
        temporary_root = Path(temporary).resolve()
        _require(
            not _is_within(temporary_root, project_root),
            "Temporary verification environment was created inside the source tree",
        )
        environment_root = temporary_root / "venv"
        run_root = temporary_root / "outside-source"
        run_root.mkdir()
        venv.EnvBuilder(with_pip=True).create(environment_root)
        scripts_directory = environment_root / ("Scripts" if os.name == "nt" else "bin")
        python = scripts_directory / ("python.exe" if os.name == "nt" else "python")
        console = scripts_directory / ("notug.exe" if os.name == "nt" else "notug")
        _require(python.is_file(), "Fresh virtual environment has no Python executable")
        _require(
            console.parent == scripts_directory, "Console path escaped the virtual environment"
        )
        environment = os.environ.copy()
        for key in tuple(environment):
            folded = key.casefold()
            if (
                folded in {"pythonhome", "pythonpath", "virtual_env"}
                or folded.startswith("notug_")
                or folded.startswith("pip_")
            ):
                environment.pop(key, None)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            }
        )
        pip = [
            str(python),
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "--no-cache-dir",
        ]
        _run(
            [
                *pip,
                "install",
                "--no-index",
                "--no-deps",
                str(wheel_path.resolve()),
            ],
            cwd=run_root,
            environment=environment,
        )
        _run([*pip, "check"], cwd=run_root, environment=environment)
        _require(console.is_file(), "Installed wheel did not create the notug console script")
        version_output = _run([str(console), "--version"], cwd=run_root, environment=environment)
        _require(
            version_output.strip() == f"notug {metadata.version}",
            "Installed console version does not match pyproject.toml",
        )
        console_help = _run([str(console), "--help"], cwd=run_root, environment=environment)
        _require("usage: notug" in console_help.casefold(), "Installed console help is invalid")
        module_help = _run(
            [str(python), "-m", metadata.import_name, "--help"],
            cwd=run_root,
            environment=environment,
        )
        _require("usage: notug" in module_help.casefold(), "Installed module help is invalid")
        probe = (
            "import json,pathlib,sysconfig,"
            + metadata.import_name
            + ";print(json.dumps({'module':str(pathlib.Path("
            + metadata.import_name
            + ".__file__).resolve()),'purelib':str(pathlib.Path(sysconfig.get_paths()"
            "['purelib']).resolve())}))"
        )
        try:
            import_data: dict[str, Any] = json.loads(
                _run([str(python), "-c", probe], cwd=run_root, environment=environment)
            )
            module_path = Path(import_data["module"]).resolve()
            purelib = Path(import_data["purelib"]).resolve()
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise VerificationError(
                "Installed import-location probe returned invalid JSON"
            ) from exc
        _require(_is_within(purelib, environment_root), "Venv purelib is outside the fresh venv")
        _require(
            _is_within(module_path, purelib), "Installed import did not resolve from venv purelib"
        )
        _require(
            not _is_within(module_path, project_root), "Installed import leaked from source tree"
        )
        try:
            demo = json.loads(
                _run([str(console), "demo", "--json"], cwd=run_root, environment=environment)
            )
        except json.JSONDecodeError as exc:
            raise VerificationError("Installed demo did not emit valid JSON") from exc
        _require(demo.get("ok") is True, "Installed demo did not report success")
        demo_result = demo.get("demo")
        _require(isinstance(demo_result, dict), "Installed demo result is missing")
        _require(
            demo_result.get("protected_checkout_unchanged") is True,
            "Installed demo did not preserve its protected checkout",
        )
        _require(
            demo_result.get("receipt_tampering_detected") is True,
            "Installed demo did not detect receipt tampering",
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release(project_root: Path, dist_directory: Path) -> tuple[Path, Path]:
    project_root = project_root.resolve()
    dist_directory = dist_directory.resolve()
    metadata = _load_project_metadata(project_root)
    _require(dist_directory.is_dir(), f"Distribution directory does not exist: {dist_directory}")
    wheels = sorted(dist_directory.glob("*.whl"))
    sdists = sorted(dist_directory.glob("*.tar.gz"))
    _require(len(wheels) == 1, "Distribution directory must contain exactly one wheel")
    _require(len(sdists) == 1, "Distribution directory must contain exactly one sdist")
    wheel = wheels[0]
    sdist = sdists[0]
    verify_wheel(wheel, project_root, metadata)
    verify_sdist(sdist, project_root, metadata)
    verify_clean_install(wheel, project_root, metadata)
    return wheel, sdist


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--dist-dir", type=Path)
    arguments = parser.parse_args(argv)
    project_root = arguments.project_root.resolve()
    dist_directory = (
        arguments.dist_dir.resolve() if arguments.dist_dir is not None else project_root / "dist"
    )
    try:
        wheel, sdist = verify_release(project_root, dist_directory)
    except (OSError, UnicodeError, VerificationError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"Release verification failed: {exc}", file=sys.stderr)
        return 1
    print("Release verification passed (no artifacts were uploaded or published).")
    for artifact in (wheel, sdist):
        print(f"{artifact.name}  size={artifact.stat().st_size}  sha256={_sha256_file(artifact)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
