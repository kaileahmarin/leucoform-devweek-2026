# Implementation plan

`STATUS.md` records current completion. This document defines milestone order and exit gates.

## 1. Foundation and trust boundaries

- Establish package layout, centralized identity, stable errors, strict models, and atomic local I/O.
- Define the authority root, Mutation Lock, vault layout, state machine, and privacy boundary.
- Record architecture, naming, licensing, and threat-model decisions.

Exit gate: package imports cleanly; schemas reject unknown fields; formatting, linting, typing, and
foundation tests pass.

## 2. Repository identity and local vault

- Validate clean local Git repositories and derive a stable repository identity.
- Create the external vault and strict versioned policy without changing tracked repository content.
- Implement append-only canonical JSONL receipts with a SHA-256 hash chain.
- Add tracked-file manifests and deterministic verification helpers.

Exit gate: init and doctor tests pass, receipt tampering is detected, and read-only commands leave the
repository byte-for-byte unchanged.

## 3. Disposable sessions

- Create detached worktrees from recorded baseline commits.
- Pin the session policy and baseline manifest by hash.
- Run arbitrary local commands in the session worktree without recording environment secrets.
- Restore Mutation Lock and append a valid receipt after success or failure.

Exit gate: dirty repositories fail without mutation; command failure preserves a valid chain; the
protected checkout remains unchanged.

## 4. Change evidence and Tug Signals

- Reconcile Git object, manifest, diff, and filesystem evidence.
- Classify create, modify, delete, rename, mode, symlink, submodule, and binary changes.
- Evaluate sensitive paths, thresholds, unsafe paths, and repository drift.
- Generate a binary-capable patch and canonical machine-readable Tug Signal.
- Render safe compact reviews with optional textual diffs.

Exit gate: adversarial fixtures prove structural evidence wins, unsafe output is escaped, and evidence
disagreement fails with `PROVENANCE_DIVERGENCE`.

## 5. Human disposition and transactional application

- Bind an explicit grant to one exact Tug Signal hash.
- Reverify receipts, signal, policy, baseline, patch, drift, and apply preflight.
- Apply in a dedicated integration worktree and collision-safe branch.
- Run configured validation and commit with receipt trailers only after structural verification.
- Record denial without repository mutation.
- Revoke unmerged generated branches safely; use a verified revert branch after merge rather than
  rewriting history.

Exit gate: tampered or stale artifacts fail closed; one Tug Signal cannot authorize another; branch or
worktree collisions never remove unrelated data.

## 6. Verification, demo, and documentation

- Verify chains, manifests, sessions, signals, patch hashes, grant bindings, and integration branches.
- Guarantee valid structured output from `verify --json`, including corrupt-input failures.
- Build the self-contained temporary-repository demo with denial, grant, verification, and tamper paths.
- Complete protocol, architecture, privacy, security, threat-model, naming, demo, and decision docs.

Exit gate: the demo never touches a real repository; minimisation checks find no prohibited receipt
fields; documentation links resolve.

## 7. Release validation

- Run Ruff formatting and linting, strict mypy, and the complete pytest suite.
- Build wheel and source distribution.
- Install the wheel in a fresh temporary virtual environment and run CLI smoke tests.
- Run the complete demo, receipt-tampering test, protected-checkout assertion, and applicable Windows
  path suite.
- Review package contents and public files for secrets, private material, and unsupported claims.

Exit gate: all checks pass, artifacts report version `0.1.0`, and remaining limitations are documented
precisely in `STATUS.md` and the security documentation.
