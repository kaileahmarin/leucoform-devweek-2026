# Reference Architecture Map

## Relevant paths examined

Paths below are workspace-relative beneath a local reference root. No account name or private absolute
path is retained. Only canonical output trees were used; duplicate archive-verification extracts were
excluded.

### `2026-07-13\files-mentioned-by-the-user-build\outputs\provenance-loom`

- `docs\ARCHITECTURE.md`
- `docs\INTEGRITY_MODEL.md`
- `docs\DATA_MINIMISATION.md`
- `docs\DELETION_SEMANTICS.md`
- `docs\LINEAGE_GRAPH.md`
- `docs\REVOCATION_AND_EXPIRY.md`
- `docs\THREAT_MODEL.md`
- `docs\OFFLINE_VERIFICATION.md`
- `docs\REDACTION_AND_EXPORT.md`
- `src\canonical.js`
- `src\integrity.js`
- `src\commitment.js`
- `src\lineage.js`
- `src\minimisation.js`
- `src\loom.js`
- `src\schema.js` (targeted inspection)
- `src\storage.js` (targeted inspection)
- `test\commitment.test.js`
- `test\loom.test.js`
- `test\schema-minimisation.test.js`
- `test\storage.test.js`
- `test\export.test.js` (targeted inspection)

### `2026-07-13\build-the-signal-lattice-router-as\outputs\signal-lattice-router`

- `docs\IMPLEMENTATION_REPORT.md`
- `test\boundaries.test.js`
- `test\adversarial.test.js`

### `2026-07-13\files-mentioned-by-the-user-build-2\outputs\seed-capsule`

- `docs\ARCHITECTURE.md`
- `docs\IMPORT_QUARANTINE.md`
- `docs\PROMPT_INJECTION.md`
- `docs\SEED_POLICY.md`
- `test\policy-smoke.test.js` (targeted inspection)
- `test\schema-container-crypto.test.js` (targeted inspection)
- `test\offline-roundtrip.test.js` (targeted inspection)

### `2026-07-12\files-mentioned-by-the-user-build-2\outputs\raccoon-lantern-one-folder-node`

- `docs\ARCHITECTURE.md`
- `docs\THREAT_MODEL.md`
- `docs\FOLDER_BOUNDARY.md`
- `test\boundary.test.js` (targeted inspection)

## Reusable mechanisms identified

1. **Canonical records.** Deterministic JSON encoding, stable object-key order, preserved array order, and rejection of ambiguous or non-data values make hashes reproducible.
2. **Append-only integrity.** Ordered records carry a sequence, the previous record hash, and a hash of canonical content. Full verification detects alteration, insertion, reordering, and removal within the retained chain. A separately retained head is needed to detect replacement by a valid prefix.
3. **Exact versioned schemas.** Allowlisted fields, bounded strings and collections, explicit required fields, and rejection of unknown fields provide a fail-closed parsing boundary.
4. **Scoped authority.** Grants are action-specific, identity-bound, time-bounded where appropriate, and protected against forgery, mismatch, expiry, and replay.
5. **Independent evidence sources.** Decisions are not trusted merely because one representation or actor reports success. Structural evidence and separately anchored state are rechecked before a protected transition.
6. **Canonical authority roots and containment.** One explicitly selected root defines authority. Paths discovered in untrusted material are not authority. Canonicalisation, link/reparse checks, containment checks, and repeated identity checks reduce path escape and time-of-check/time-of-use risk.
7. **Immutable history with derived state.** Historical records remain unchanged while later revocation, deletion, expiry, and supersession events produce a separate current-state interpretation.
8. **Quarantine before disposition.** Untrusted or not-yet-authorised material is held in an isolated state until an explicit disposition. Cleanup is confirmed before release is claimed, and no forensic-erasure claim is made.
9. **Policy and content isolation.** Instructions embedded in documents, metadata, identifiers, or evidence remain inert data. Policy is held in a separate trusted channel and cannot be rewritten by inspected content.
10. **Data minimisation.** Receipts use typed metadata, bounded explanations, hashes, counts, and opaque references rather than copied source content. Secret-like fields and unnecessary local paths are rejected or redacted.
11. **Transactional failure handling.** A failed validation, provenance append, or downstream operation leaves the protected state and prior evidence unchanged; no fallback silently broadens authority.
12. **Truthful assurance boundaries.** Integrity establishes byte continuity and local attribution, not factual truth, semantic completeness, secure erasure, or operating-system containment.

## Translation into NoTUG

| Mechanism | NoTUG translation |
| --- | --- |
| Canonical records | Tug Signals, policies, manifests, and receipt events use deterministic canonical JSON before SHA-256 hashing. Non-finite numbers, duplicate or unknown fields, unsupported types, and unstable representations fail validation. |
| Append-only integrity | The local vault stores JSONL events with a monotonic sequence, `previous_event_hash`, and `event_hash`. Verification recomputes the complete chain and compares its head with session and repository metadata before any state transition. |
| Exact versioned schemas | Policy, session, Tug Signal, grant, denial, application, revocation, and verification records have explicit schema versions and closed field sets. Invalid input returns a stable machine-readable code; JSON mode remains valid JSON on failure. |
| Scoped authority | A human grant is bound to one exact Tug Signal hash and its exact patch, manifest, policy, repository, session, and baseline hashes. A grant cannot authorise another Tug Signal and cannot be inferred from repository text or agent output. |
| Independent evidence sources | The Signal Lattice is implemented by comparing the Git baseline/object graph, a full SHA-256 manifest of tracked files, and the worktree diff plus filesystem classification. Any disagreement fails with `PROVENANCE_DIVERGENCE`. |
| Canonical authority roots and containment | Node 0 is the authoritative repository plus its recorded baseline commit. Agent work occurs only in a vault-managed disposable worktree. No supported workflow uses the primary checkout as the agent working directory. Symlink, junction, submodule, mode, and path-boundary conditions are classified and unsafe escapes fail closed. |
| Immutable history with derived state | The baseline and protected checkout remain historical source state. Worktree edits, Tug Signals, and integration branches are derived state. Denial, revocation, divergence, and rollback append new receipts rather than rewriting earlier evidence. |
| Quarantine before disposition | The forage worktree is the quarantine boundary. It remains isolated through generation, review, denial, and verification. Archival or removal occurs only after its disposition is recorded and verified, and never targets unrelated branches, worktrees, or user files. |
| Policy and content isolation | The authoritative policy is copied into the local vault and hash-bound when a session starts. Repository policy files, filenames, diffs, commit messages, source comments, and agent output are untrusted data. They cannot grant authority or alter policy, and terminal-facing text is control-character sanitised. |
| Data minimisation | Ordinary events store identifiers, hashes, timestamps, classifications, counts, exit status, and coded findings, not file contents or environment variables. Operational patch bytes remain only in the local vault. Exported receipts can replace paths with export-scoped opaque aliases. |
| Transactional failure handling | Tug generation never applies changes. Grant re-verifies the chain, Tug hash, patch hash, baseline, policy, repository cleanliness, and application preflight before creating a dedicated integration worktree. A failed step restores Mutation Lock to `LOCKED` and leaves the protected checkout unchanged. |
| Truthful assurance boundaries | NoTUG claims workflow isolation, explicit mutation authority, attribution, drift detection, and recoverability. It does not claim to sandbox a malicious process, constrain an administrator, protect a compromised operating system, or securely erase storage media. |

## Intentional exclusions

- No reference source code, fixtures, example content, or proprietary prose was copied into NoTUG.
- Duplicate `work\archive-verify-*` extracts, incomplete continuation folders, audit helpers, and unrelated projects or personal files were not inspected or reused.
- Reference-specific identities, example questions, evidence passages, aliases, private paths, credentials, and synthetic user data were excluded.
- Network services, telemetry, cloud trust, hosted identity, blockchains, remote timestamps, analytics, and update checks were excluded.
- Cryptographic component-identity registries and export-signing infrastructure were not imported into the MVP; NoTUG uses local Git identity, SHA-256 artifact binding, and its receipt chain for the stated version 0.1 boundary.
- Truncated path digests were not reused as integrity evidence. NoTUG uses complete SHA-256 file hashes in manifests; opaque path handles, when used, are only display or export aliases.
- A bare approval boolean was not treated as proof of human authority. NoTUG requires an explicit grant command bound to the selected Tug Signal.
- Automatic approval, automatic stashing, destructive cleanup, history rewriting, forensic-erasure claims, and operating-system sandbox claims were excluded.
- Reference viewers, renderers, and product-specific UI behavior were excluded unless required to keep untrusted terminal output inert and reviewable.

## Provenance and privacy boundaries applied during reuse

- Reconnaissance was read-only and limited to the paths listed above. Reference repositories and all unrelated user state remained unchanged.
- Reuse is architectural and independently reimplemented in Python. The lineage is recorded here as mechanism-level influence, not copied implementation or textual authorship.
- Local account names are redacted from recorded reference roots. No secret, credential, personal content, source passage, or private fixture is reproduced.
- Paths are retained only where necessary to identify the reference source or a reviewed mutation. Exported receipts support scoped path redaction without weakening the vault's local verification evidence.
- Repository content and agent-produced material are always treated as untrusted input. They are never interpreted as policy, approval, a capability grant, a shell command, or an event-stream instruction.
- Ordinary receipts contain metadata and hashes only. Patch content is confined to the local vault because it is operationally necessary for exact review and application.
- Provenance verifies structural consistency within the retained local evidence. It does not prove that an agent was honest, that every event was observed, that a filesystem or clock was uncompromised, or that removed bytes are unrecoverable.
- All reused mechanisms remain local and offline. No reference content, NoTUG state, receipt, manifest, patch, or identifier is uploaded or published by the product.
