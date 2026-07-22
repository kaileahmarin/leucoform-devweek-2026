# Decision log

These are accepted MVP architecture decisions. Measured release evidence and public-release review items
are tracked in [../STATUS.md](../STATUS.md).

## Pending public-release decisions

The following are deliberately unresolved and are not accepted architecture decisions:

- **P-001 — public identity:** approve the final project, distribution, import-package, and CLI names
  after the review in [NAMING.md](NAMING.md).
- **P-002 — canonical locations:** choose the real source repository, documentation, issue tracker,
  changelog, and package URLs before adding them to metadata or public instructions.
- **P-003 — security reporting:** establish a monitored private security contact and an accurate
  supported-version policy.
- **P-004 — Git support floor:** measure and approve the minimum Git version for every supported
  worktree and porcelain operation.
- **P-005 — source-distribution disclosure:** explicitly approve or revise the current inclusion of
  prompts, plans, tests, scripts, examples, CI configuration, and provenance documentation.

These items require human disposition. A passing local build or CI job does not decide them.

## D-001 — Python 3.11+ with a standard-library-first design

**Status:** accepted
**Decision:** ship an installable Python package and `notug` console command. Prefer `argparse`, `hashlib`,
`json`, `pathlib`, `subprocess`, `tempfile`, and `tomllib`; add small dependencies only when they materially
improve correctness.
**Rationale:** Windows-first local operation, readable implementation, low dependency risk, and practical
Linux/macOS portability.

## D-002 — Clean local Git repositories only in 0.1

**Status:** accepted
**Decision:** refuse session creation for non-Git folders or any tracked/untracked source state that makes
the baseline ambiguous. Refuse every tracked baseline symlink with `UNSAFE_BASELINE_SYMLINK` before
creating the session worktree. Never auto-stash, commit, discard, relocate, or repair user work.
**Rationale:** a narrow fail-closed scope is more honest and recoverable than guessing at authority.

## D-003 — External per-user vault

**Status:** accepted
**Decision:** keep policy, sessions, patches, manifests, receipts, and integration worktrees in an
OS-appropriate vault outside the protected repository. Pin the vault policy hash per session.
**Rationale:** repository content is untrusted and cannot be allowed to redefine governance metadata.

## D-004 — Git linked worktrees, with an explicit shared-storage limitation

**Status:** accepted
**Decision:** create detached disposable worktrees and separate integration worktrees. Document that linked
worktrees share Git's object database and many refs.
**Rationale:** worktrees preserve the primary checkout and avoid copying large repositories, but they are
workflow isolation rather than a storage or malware sandbox.

## D-005 — Three-source evidence lattice

**Status:** accepted
**Decision:** reconcile the Git graph/diff, a raw SHA-256/type/size/mode workspace manifest, and worktree
filesystem facts. Model only Git's built-in attribute normalization when comparing captured bytes to the
staged blob ID. Reconcile populated Gitlinks with their commit pointers and reject dirty or ambiguous
nested checkouts. Disagreement fails with a stable provenance-divergence code.
**Rationale:** no single representation covers content, modes, links, binary state, and lineage reliably.

## D-006 — Canonical append-only JSONL receipts

**Status:** accepted
**Decision:** every event includes the previous event hash and its own SHA-256 canonical-content hash.
Receipts are inert evidence and never execution instructions.
**Rationale:** deterministic verification detects alteration, insertion, removal, and reordering while
remaining locally inspectable.

## D-007 — Strict versioned TOML policy

**Status:** accepted
**Decision:** use a human-readable vault policy with a schema version, required finding classifications,
argv-array validation commands, and fail-closed unknown-field handling.
**Rationale:** silent configuration drift and repository-supplied policy are unacceptable at the authority
boundary.

## D-008 — No automatic grant in 0.1

**Status:** accepted
**Decision:** a Tug Signal is never authority. Grant requires an explicit user command bound to the exact
canonical signal and patch hashes after fresh verification.
**Rationale:** proposal and authority must remain distinct. The CLI does not claim cryptographic human
authentication, so the operating ceremony is documented as part of the boundary.

## D-009 — Apply only on a dedicated integration branch

**Status:** accepted
**Decision:** create a collision-safe `notug/grant/<short-id>`-style branch and worktree, preflight the exact
patch, run pinned validation, verify structure, and commit receipt trailers. Never switch or merge the
primary checkout automatically.
**Rationale:** an explicit branch makes the approved transition reviewable with ordinary Git tools.

## D-010 — Revoke unmerged work; revert merged work

**Status:** accepted
**Decision:** a verified unmerged generated branch may be revoked with narrowly scoped cleanup. Once merged,
create a verified inverse patch or revert branch rather than rewriting history.
**Rationale:** branch deletion is not rollback after merge, and automatic history rewriting risks unrelated
work.

## D-011 — Local-only runtime and minimised receipts

**Status:** accepted
**Decision:** no telemetry, analytics, account, cloud API, content upload, environment capture, or ordinary
receipt file bodies. Store exact patch content only where operationally required. Offer path-redacted
exports and test receipts for prohibited secret-like fields.
**Rationale:** provenance should not create a new data-exfiltration surface. User-supplied subprocesses are
documented as outside the runtime guarantee.

## D-012 — MIT license for the MVP

**Status:** accepted, subject to final human review
**Decision:** use the MIT license.
**Rationale:** it is short, permissive, widely understood, and compatible with local commercial or
open-source evaluation. It provides no warranty, which fits an early security-workflow MVP. Dependency
licenses and the final public-release strategy still require review.

## D-013 — Centralized replaceable product identity

**Status:** accepted
**Decision:** keep runtime constants for the display name, expansion, package/module/CLI labels, vault and
namespace conventions, version, and standard output phrases centralized. Treat `pyproject.toml`
distribution/script metadata, physical Python import paths, stable hash domains, and versioned schemas as
explicit compatibility/migration work rather than a blind rename. Require trademark and package-name
review before public distribution.
**Rationale:** the working codename must be replaceable without changing evidence, state, or grant logic.

## D-014 — Diagnostics report; they do not repair

**Status:** accepted
**Decision:** doctor and verify report stable findings without pruning worktrees, changing Git config,
fixing permissions, rewriting receipts, or modifying repositories. Verify reverse-maps managed worktree
directories and registrations, generated branches, and evidence refs to the strict artifacts and
completed receipts allowed to claim them.
**Rationale:** an audit command that mutates evidence or user state would undermine the protocol it is meant
to verify.

## D-015 — Explicit patch-free exports with redacted paths by default

**Status:** accepted
**Decision:** export a verified Tug receipt only through `notug export`. Never include patch bytes. Replace
paths with aliases scoped to the Tug hash and redact symlink targets unless the user explicitly requests
paths, and refuse to write an export inside the protected repository.
**Rationale:** sharing provenance must not silently disclose source or turn the protected repository into
an output sink. Scoped aliases preserve within-export correlation without becoming integrity evidence.

## D-016 — Neutralize repository Git hooks and discovered filters on critical operations

**Status:** accepted
**Decision:** execute Git with argv and no shell, select a trusted empty hooks directory, and override
discovered clean/smudge filter drivers and custom merge drivers for NoTUG-owned snapshot, worktree,
apply, commit, and revert steps. During Signal reconciliation, bind raw workspace bytes first, then use
Git's inert `hash-object --path` behavior to model built-in text/end-of-line normalization while external
drivers remain disabled.
**Rationale:** evidence collection and application must not implicitly run repository-controlled code.
This hardening is a supported-path control, not a claim that child commands, host configuration, or the
Git executable are trustworthy.

## D-017 — Serialize mutation transitions and retain strict operation artifacts

**Status:** accepted
**Decision:** acquire a per-repository vault lock around supported state-changing operations and re-read
state after acquiring it. Record each `run` as a strict local operation artifact while keeping the receipt
event limited to the executable, argument count, command-record hash, timestamps, and result.
**Rationale:** serialization avoids two cooperative CLI processes acting on the same stale state, while a
separate minimised operation artifact preserves useful local provenance without copying transcripts or
environment maps into the append-only event stream.

## D-018 - Retain verifiable evidence after revocation

**Status:** accepted
**Decision:** when an unmerged generated branch is revoked, preserve its approved commit under the
non-head namespace `refs/notug/revoked/<grant-id>` before deleting the integration branch. When a merged
grant is reverted, bind the target commit, inverse patch, applied patch, and resulting tree by hash.
**Rationale:** ordinary branch cleanup must not make the evidence unverifiable after garbage collection,
and a forward revert must remain structurally auditable without trusting its description.

## D-019 - Bind recognized Codex launches to the managed worktree

**Status:** accepted
**Decision:** preserve generic argv execution for other agents, but identify the Codex executable and
the official Node `codex.js` entry point and add the exact verified session worktree through `-C` when
the caller omitted it. Reject any conflicting `-C` or `--cd` before child launch or run receipts.
Expose session creation through the bridge as a non-authorizing local write that requires an explicit
repository path and returns this same exact worktree.
**Rationale:** Windows evidence showed that NoTUG gave an ordinary child the correct CWD while a Codex
child without explicit workdir binding started at `C:\`. The recognized integration needs a stronger
workspace contract without changing authority, interpreting a shell command, or silently overriding a
caller-selected conflicting directory.

## 2026-07-17: Public identity changed to NoTUG

- Public product name: **NoTUG**.
- Expansion: **No Touching Unless Granted**.
- Distribution/import/CLI identifiers preserve their existing naming conventions:
  `notug-protocol`, `notug_protocol`, and `notug`.
- Public runtime identity, paths, environment variables, generated Git namespaces, documentation,
  package metadata, and examples use the NoTUG name.
- Version 1 cryptographic hash domains and canonical schema keys remain unchanged where altering them
  would invalidate existing evidence. These retained `NoTUG` identifiers are explicitly compatibility
  identifiers, not public branding.
