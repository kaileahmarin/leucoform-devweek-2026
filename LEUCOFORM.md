# Leucoform desktop companion

Leucoform is the human-facing desktop product powered by NoTUG Core. It is an optional PySide6 Qt
Widgets adapter; the CLI and Core remain dependency-light when the desktop extra is not installed.

## Authority and privacy boundary

Leucoform may request typed application operations, but Core owns every state transition. Agent Bridge
has no Grant, denial, integration, or revocation capability. The CLI retains its exact TTY ceremony.
Leucoform supplies the complete exact confirmation only after three distinct accessible face controls
are activated in order. Core then repeats agent-context rejection, receipt-chain verification, strict
Tug validation, policy and baseline checks, drift detection, and safe-apply preflight under lock.

Leucoform stores only recent repository paths, selected Codex path, companion position, and UI
preferences. Bounded prompts go to Codex through stdin and are not included in argv, settings, receipts,
operation records, or process listings. Normalized activity is bounded in memory and is not persisted
as a raw transcript. Leucoform has no telemetry, updater, background network check, Codex downloader,
or bundled Codex copy.

## Ambient companion

The draggable 200–300 pixel companion uses a real 32-vertex, 30-face rhombic triacontahedron rendered
locally at no more than 25 frames per second. It combines colour with ASCII glyphs, accessible labels,
numbered patterns, and explicit text. Reduced-motion mode fixes the geometry at a canonical angle.

When a Tug requires a decision, the solid becomes still and separates three accessible rhombic faces:

1. Review bound work.
2. Confirm protected baseline.
3. Grant exact Tug.

Repeated or out-of-order activation cannot advance the ceremony. Any state reset clears all three
faces. After successful application and verification, the companion becomes luminous paper white and
adds three orbital rings with electron markers. Denied, abandoned, cancelled, divergent, blocked, and
failed states retain distinct non-success presentations.

The tray/menu-bar remains a fallback. Environments without supported transparency or tray behavior use
the normal compact window. Only one Leucoform instance and one Leucoform-launched agent run are
supported at a time.

## Run and recovery lifecycle

1. Select and explicitly protect a clean Git repository.
2. Verify a local Codex installation and acknowledge provider data transfer.
3. Core creates the exact managed worktree and binds recognized Codex launches to it.
4. The cancellable runner sends the prompt through stdin and normalizes bounded JSONL progress.
5. Changed work is frozen into a Tug; unchanged work can be abandoned explicitly.
6. Failed, cancelled, or partial work remains available for recovery and is never silently deleted.
7. Review presents affected paths, sanitized diff, totals, policy, risk, baseline, Tug, and receipts.
8. Three accessible face activations request the exact Grant. Denial and archival remain separate.

A crash never fabricates `RUN_CANCELLED` or successful verification. Arbitrary Codex tasks outside a
NoTUG-managed worktree are not represented as protected.

## Packaging

PyInstaller builds natively on Windows, macOS, and Linux. Windows optionally uses Inno Setup; macOS
uses a DMG; Linux definitions produce AppImage and Debian artifacts. Builds run tests and a frozen
self-test, generate a path-sanitized dependency inventory, copy notices, and hash artifacts. Signing,
notarization, installer validation, and publication remain explicit release-operator actions.
