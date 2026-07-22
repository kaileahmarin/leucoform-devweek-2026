# Changelog

## Unreleased — Leucoform desktop companion

- Added Leucoform as an optional PySide6 desktop product powered by dependency-free NoTUG Core.
- Added the draggable accessible rhombic-triacontahedron companion, tray fallback, repository/Codex discovery, stdin-only
  composer, normalized JSONL activity, Tug review, native exact-hash ceremony, denial, and explicit
  archival UI.
- Added a cancellable Core runner with truthful `RUN_CANCELLED` receipts and bounded stdin.
- Added Core-owned grant confirmation callbacks while preserving the CLI TTY ceremony and excluding
  grant authority from Agent Bridge.
- Added clean `ABANDONED` session disposition without silent removal of partial work.
- Added PyInstaller, Inno Setup, DMG, AppImage, Debian, SBOM/hash, and manual native CI packaging paths.

All notable changes to this project are documented here. The project follows semantic versioning.

## [0.1.0] - Unreleased

### Changed

- Renamed the public product from the working NoTUG codename to **NoTUG** (**No Touching Unless Granted**).
- Preserved separator conventions across technical identifiers: `notug-protocol`, `notug_protocol`,
  `notug`, `NOTUG_*`, and the `notug/` Git namespace.
- Preserved version 1 cryptographic hash domains and canonical schema keys where changing them would
  invalidate existing evidence; these legacy identifiers are documented as compatibility fields rather
  than public branding.

### Added

- Local initialization and environmental diagnostics for clean Git repositories.
- Disposable worktree sessions and privacy-conscious local command execution.
- Strict command-operation artifacts with minimised receipt events and per-repository transition locks.
- SHA-256 tracked-file manifests and append-only hash-chained receipts.
- Fail-closed refusal of every tracked baseline symlink before session-worktree creation.
- Structured Tug Signals with complete change classification and policy findings.
- Raw workspace byte/type/size/mode binding reconciled against staged blobs with inert built-in Git
  normalization, plus fail-closed populated-Gitlink checks.
- Safe terminal review, explicit exact-signal grant, denial, verification, and revocation workflows.
- Transactional patch application to dedicated collision-safe integration branches.
- Patch-free Tug receipt export with scoped path aliases by default.
- Trusted empty hooks plus inert discovered Git filters and custom merge drivers on critical operations.
- Revocation evidence refs for unmerged grants and hash-bound forward reverts for merged grants.
- Read-only reverse reconciliation of managed worktrees, generated branches, evidence refs, and
  failed-grant crash residue.
- Strict versioned local policy configuration with fail-closed unknown-field handling.
- Self-contained denial, grant, verification, and tamper-detection demonstration.
- Unit, integration, adversarial, minimisation, and cross-platform CI matrix configuration.
- Architecture, protocol, privacy, security, threat-model, naming, decision, and demo documentation.
- Versioned non-authorizing agent-bridge session creation with an exact managed-worktree result.

### Fixed

- Neutralized repository hooks during critical index, preflight, apply, worktree, commit, and revert
  operations.
- Refused destructive archive cleanup when a disposed session has changed since review.
- Made Tug artifact publication transactional with narrow fail-closed staging cleanup.
- Made content-addressed policy snapshots create-once and verify-existing.
- Included every Git ref namespace in revocation reachability decisions.
- Rejected ambiguous vault homes and non-portable control, directionality, and surrogate path characters.
- Separated vault writability from platform-specific confidentiality reporting.
- Corrected CLI JSON option detection and path-with-spaces review guidance.
- Refused implicit Windows `.bat`/`.cmd` interpretation unless the user explicitly selects `cmd.exe`.
- Bound recognized Codex CLI and Node `codex.js` launches to the verified session worktree with an
  explicit `-C`, rejecting conflicting workdir options before child launch or run receipts.
- Distinguished an already archived session from administrative worktree divergence without changing
  the single-receipt, single-removal archive behavior.
- Added offline wheel-install, archive-content, metadata, entry-point, and demo release verification.
