# NoTUG release-readiness record

**Candidate version:** `0.1.0`

**Status date:** 2026-07-17

**Canonical input commit:** `a2516a124a0bd37c32cd7aecafffb1c8edc6ae48`

**Working branch:** `rename/notug`

**Publication state:** not pushed, tagged, uploaded, published, or released

## Outcome

The latest Codex-hardened source was renamed to **NoTUG** (**No Touching Unless Granted**) without
changing its mutation-governance behaviour. Technical identifiers preserve their original separator
conventions: `notug-protocol`, `notug_protocol`, `notug`, `NOTUG_*`, and `notug/`.

Version 1 cryptographic hash domains and canonical compatibility fields remain unchanged where renaming
would invalidate existing evidence. The retained `NoTUG.*.v1` domains, `notug_version` field, and
`notug_metadata` policy key are documented compatibility identifiers, not public branding.

## Validation environment

- Linux `4.4.0-x86_64`
- Python `3.13.5`
- Git `2.47.3`
- Ruff `0.15.22`
- mypy `1.20.2`
- pytest `9.0.2`
- build `1.5.0`
- pip `25.1.1`
- wheel `0.47.0`

## Source validation

The following gates passed:

```text
python -m ruff format --check .
python -m ruff check --no-cache .
python -m mypy --cache-dir <temporary-cache>
python scripts/check_docs.py
python scripts/minimisation_lint.py
git diff --check
```

Measured results:

- Ruff format: 43 files already formatted.
- Ruff lint: all checks passed.
- strict mypy: no issues in 23 source files.
- documentation: 41 relative links across 17 Markdown files passed.
- minimisation: 18 prohibited fields rejected; generated receipt clean.
- pytest collection: 137 tests.
- pytest execution: 134 passed and 3 platform-specific tests skipped. The tests were executed in
  isolated groups in this environment because a single long-running invocation exceeded the session's
  command limit; every collected node was exercised.

## Build and clean-install verification

A clean wheel and source distribution were rebuilt from the renamed source. The strict release verifier
passed archive inspection, metadata and entry-point checks, source-byte comparison, isolated offline
installation, `pip check`, CLI and module help/version checks, and the JSON demonstration. It did not
upload or publish anything.

Artifacts:

- `notug_protocol-0.1.0-py3-none-any.whl`
  - SHA-256: `509a4b7efda23ef5e15487869c2dedc8efa6e0ed505678a9dbdab324434a7192`
- `notug_protocol-0.1.0.tar.gz`
  - SHA-256: `20bafa1b6fabf05f87b47867b3b2fa857b8cb53241b30bd0f4e8937a8b766371`

## Remaining release gates

- verify package, repository, command, and trademark availability for NoTUG;
- run and retain CI evidence on Windows, Linux, and macOS for the claimed Python matrix;
- choose canonical repository and documentation URLs;
- establish a private security contact and supported-version policy;
- perform final human review of public claims and source-distribution contents.

The prior Windows hardening audit is preserved in
[`docs/history/RELEASE-READINESS-NOTUG.md`](docs/history/RELEASE-READINESS-NOTUG.md) as historical
provenance.
