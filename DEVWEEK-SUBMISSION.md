# DevWeek submission guide

## Submission copy

**Leucoform, powered by NoTUG — No Touching Unless Granted** is a local desktop companion and
change-control layer for coding-agent work. An
agent works in a disposable Git worktree, NoTUG freezes the result into a hash-bound Tug Signal, and
only an exact interactive human grant can create the reviewed integration branch. The protected
checkout remains unchanged throughout the supported workflow.

The DevWeek build adds a bounded agent bridge, availability-labelled local Resource Receipts, and a
Windows-first Codex launcher seam. Recognized Codex launches are bound to the verified managed
worktree with explicit `-C`; a conflicting workdir fails before the child starts or a run receipt is
created. NoTUG has no telemetry, cloud service, automatic grant, or background upload.

## Claim ledger

| Claim | Classification | Evidence boundary |
| --- | --- | --- |
| Clean repositories can be initialized, diagnosed, and verified locally. | Implemented | Core CLI, integration suite, deterministic demo. |
| Agent commands run in detached managed worktrees while the protected checkout remains unchanged in the supported workflow. | Implemented | Core runner, protected-checkout assertions, Windows ordinary-child CWD probe. |
| Recognized Codex CLI and official Node entry-point launches receive exact explicit workdir binding. | Implemented | Unit/integration regressions; fresh external Codex proof remains a submission rehearsal gate. |
| A Tug Signal binds the reviewed patch, manifests, policy, baseline, risk, and receipt evidence. | Implemented | Core Tug generation, adversarial and lifecycle tests. |
| Grants require an exact interactive TTY ceremony and apply only the reviewed proposal to a dedicated branch/worktree. | Implemented | Grant/revocation integration tests and synthetic demo. |
| The bridge can report status, create a non-authorizing session, locate its exact worktree, render verified review facts, and verify evidence. | Implemented | Version 1 bridge schema and focused tests. |
| Resource Receipts automatically measure NoTUG active time, current-process CPU, and Git launch attempts; unsupported metrics remain unavailable. | Implemented | Resource schema and tests. |
| Windows working-set, child CPU/I/O, physical disk allocation, and reclaimed-byte attribution are measured. | Designed, not implemented | Values remain `null` with availability `false`. |
| A native companion/composer/review UI, cancellation-safe runner, three-face exact-Tug ceremony, and explicit archival exist. | Implemented | Optional PySide6 source, offscreen UI tests, and native packaging definitions. |
| Expiry/lease state and anonymous aggregate export exist. | Vision | Explicitly outside the current build and authority path. |
| NoTUG is a malware, kernel, privilege, VM, or hostile same-user containment boundary. | Not claimed | Threat model explicitly rejects this claim. |

## Deterministic Windows modes

Run from the source checkout with the quality interpreter:

```powershell
$Python = ".\.venv\Scripts\python.exe"

# Fully isolated synthetic archive truthfulness regression.
powershell -ExecutionPolicy Bypass -File scripts\smoke-windows.ps1 `
  -Mode archive-regression -Python $Python

# Existing session: verifies ordinary-child CWD plus protected HEAD/tree/status.
powershell -ExecutionPolicy Bypass -File scripts\smoke-windows.ps1 `
  -Mode cwd-probe -Python $Python -Repo C:\src\fixture `
  -SessionId session_example -SessionPath C:\path\to\managed-session
```

The managed proof deliberately requires explicit operator inputs:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\smoke-windows.ps1 `
  -Mode managed-grant -Python $Python -Repo C:\src\fixture `
  -CodexJs C:\path\to\node_modules\@openai\codex\bin\codex.js `
  -PromptFile .\prompt.txt -Grant
```

`managed-grant` starts a configured external Codex agent and may send the prompt and accessible
workspace content to that configured provider. Run it only with an approved synthetic fixture. The
`-Grant` switch does not automate authority: it reaches the existing interactive exact-hash TTY
ceremony. Without `-Grant`, the harness stops at human review and reports the Tug ID.

## Demo capture sequence

1. Show clean protected `master`, its HEAD/tree, and active Mutation Lock.
2. Start one session and show the exact external worktree.
3. Run the bounded invoice-filter prompt through the managed Codex lane.
4. Show the three changed paths, status counts, search/filter behavior, and empty state.
5. Generate and review one Tug Signal; show its exact hash and classified paths.
6. Perform the interactive grant from a human-controlled terminal.
7. Show the separate integration branch/worktree and unchanged protected `master`.
8. Verify the receipt chain and Resource Receipt availability markers.
9. Archive the disposed session once, then show precise duplicate refusal and the retained grant.

Keep full transcripts as local attachments. Submission-facing evidence should contain the concise JSON
mode result, exact tool versions, test totals, and this claim ledger—not private repository paths,
prompts, patches, user data, or raw environment details.
