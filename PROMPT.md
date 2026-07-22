# NoTUG implementation charter

Build and maintain a complete, locally usable defensive change-control tool for coding-agent work.
The working codename expands to **No Touching Unless Granted**.

## Objective

An agent may write freely inside a disposable workspace, but no change may cross into the
authoritative Git repository without an explicit human grant bound to the exact reviewed change.
Turn agent mutations into attributable, reversible, structurally verified state transitions.

## Non-negotiable invariants

- Mutation Lock is active by default and after every completed or failed operation.
- The authoritative repository and recorded baseline commit are the authority root.
- A proposing process cannot grant authority to itself; version 0.1 has no automatic grants.
- Supported agent work occurs only in a detached disposable Git worktree under the local vault.
- The protected checkout and its current branch remain unchanged during session work, Tug Signal
  creation, review, denial, grant application, and ordinary verification.
- All policies, receipts, patches, manifests, and logs remain local. There is no telemetry, account,
  cloud service, remote API, or content upload.
- Repository content, filenames, patches, commit messages, and agent output are always inert data,
  never trusted instructions.
- Structural disagreement fails closed with a stable error code. An agent's explanation never
  overrides Git, manifest, patch, or filesystem evidence.
- Ordinary receipts contain no file contents, environment variables, credentials, or unnecessary
  personal paths.
- Version 0.1 supports clean local Git repositories. It never stashes, commits, discards, moves, or
  repairs ambiguous user work automatically.

## Required evidence and state

Triangulate repository state with the Git object graph, a SHA-256 tracked-file manifest, and the
worktree diff plus filesystem state. Store transitions in append-only JSONL receipts whose canonical
event hashes form a verifiable chain. Validate policy and machine-readable artifacts strictly;
unknown fields fail instead of being ignored.

Use explicit states including `LOCKED`, `SESSION_OPEN`, `TUGGED`, `GRANTED`, `APPLIED`, `DENIED`,
`REVOKED`, `DIVERGED`, and `FAILED`. Reject invalid transitions with stable machine-readable codes.

## CLI lifecycle

Implement and maintain these commands:

- `notug init [REPO]`
- `notug doctor [REPO]`
- `notug session start [REPO] --name NAME`
- `notug run SESSION_ID -- COMMAND [ARGS...]`
- `notug tug SESSION_ID`
- `notug review TUG_ID`
- `notug grant TUG_ID`
- `notug deny TUG_ID`
- `notug verify [REPO] [--json]`
- a safe revoke or revert operation for NoTUG-generated grants
- `notug demo`

A Tug Signal requests authority; it does not confer authority. It must bind repository and session
identity, baseline, classified changes, policy findings, Git evidence, SHA-256 evidence, divergence
state, risk, receipt-chain head, version, timestamp, patch hash, and its own canonical hash.

Before a grant, reverify the chain, signal, patch, policy, baseline, repository drift, and apply
preflight. Apply only the exact reviewed patch in a dedicated integration worktree and a predictable,
collision-safe branch. Run configured validation, verify the result structurally, commit receipt
identifiers as trailers, and leave the protected checkout untouched.

## Policy and adversarial behaviour

The vault policy is authoritative for a session and is pinned by hash. Classify deletions, renames,
binaries, modes, symlinks, external symlink targets, submodules, Git internals, product metadata,
environment and credential-like paths, CI/deployment files, lockfiles, large changes, and unexpected
roots. Block unsafe changes where policy requires it; never silently approve.

Regression coverage must include dirty sources, baseline drift, patch tampering, receipt deletion or
reordering, malicious text, terminal escapes, symlink escapes, binary changes, collisions, thresholds,
unknown schema fields, mid-command failure, exact-signal grant binding, Windows path behaviour, and
valid JSON output for verification failures.

## Engineering and delivery

Use Python 3.11 or newer, prefer the standard library, support Windows first, and retain practical
Linux and macOS compatibility. Keep public identity strings centralized. Maintain an installable
package and console entry point at semantic version `0.1.0`.

At every milestone run formatting, linting, strict type checking, relevant unit and integration tests,
and update status and decisions. Final validation includes the full suite, wheel and source build,
fresh-environment install, CLI smoke tests, complete demo, tamper detection, protected-checkout
assertions, minimisation lint, documentation links, and applicable Windows path tests.

Document the security boundary honestly: supported workflows isolate agent work and require an
explicit grant before an integration branch is created. This is not a kernel sandbox, malware
containment system, endpoint security product, or defence against a hostile administrator-level local
process.

Do not publish, upload, create a remote repository, or modify global/user configuration as part of
development or demonstration.
