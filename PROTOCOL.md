# Protocol

This document specifies implemented `0.1` command behaviour for the unpublished source checkout. Consult
[../STATUS.md](../STATUS.md) for measured validation evidence and public-release review items.

## Core terms

- **Node 0:** the protected Git repository identity and its recorded baseline commit.
- **Mutation Lock:** the default condition in which no proposal has authority to create an integration
  branch.
- **Forage workspace:** a disposable detached linked worktree in the local vault.
- **Tug Signal:** a hash-bound request for mutation authority. It is evidence, not authority.
- **Grant:** an explicit user action bound to one exact Tug Signal hash.
- **Integration branch:** a NoTUG-generated branch containing the verified approved patch.

## Lifecycle

### Initialize — `notug init [REPO]`

Initialization validates a local Git repository, requires an unambiguous committed baseline, derives a
stable repository identifier, locates a vault outside the repository, creates or validates strict local
policy, records initial provenance, and reports `Mutation Lock: active`. It does not add or edit tracked
repository files.

### Diagnose — `notug doctor [REPO]`

Doctor reports Python and Git versions, repository cleanliness, worktree support, case behaviour, vault
writability, path length concerns, stale sessions, and receipt-chain integrity. Writability is a temporary
create/remove probe in the nearest existing directory on the vault path; an existing non-directory path
component is an error, not a successful fallback probe. Separately, doctor reports whether an existing
POSIX vault root has group/other mode bits; it does not assess Windows ACLs and says so explicitly.
Findings are diagnostic; the command does not repair, prune, stash, commit, or delete managed resources.

### Start — `notug session start [REPO] --name NAME`

Start refuses tracked or untracked source changes with a stable dirty-repository error. It records the
baseline commit and policy hash and builds a tracked-file SHA-256 manifest. If that baseline contains any
tracked symbolic link, start returns `UNSAFE_BASELINE_SYMLINK` before creating or registering a session
worktree. Otherwise, it creates a detached linked worktree under the vault. The exact session ID and
workspace path are printed for use with a local agent. The primary checkout and its current branch are
not switched.

The authoritative policy is `<vault-root>/r/REPOSITORY_ID/policy/notug.toml`. The default
`[validation]` value is `commands = []`. At session start NoTUG creates or verifies the immutable
content-addressed snapshot `<vault-root>/r/REPOSITORY_ID/policies/<policy-sha256>.toml`; Tug and grant use
that exact snapshot for the session's lifetime. A later policy edit applies only to a later session, and a
conflicting existing snapshot fails closed without being overwritten.

### Run — `notug run SESSION_ID -- COMMAND [ARGS...]`

Run executes the supplied argv directly, without a shell, with the session worktree as its current
directory. It records a strict operation artifact containing session identity, timestamps, the executable
name, locally minimised arguments, and exit status. The receipt stream retains the executable, argument
count, and a hash of that operation command record, not environment variables or complete output. A
failed subprocess produces a failure receipt and restores Mutation Lock; it is not inferred to have
succeeded from output text.

NoTUG does not sandbox the child command. The command can use the network or target other paths if its OS
permissions permit. Do not pass secrets in command arguments.

The typed application runner also accepts bounded stdin bytes, streaming stdout/stderr callbacks, and a
cancellation event. Leucoform uses this path so its Codex prompt is absent from arguments and receipts.
It launches the fixed Codex JSONL command in the exact managed worktree, records `RUN_CANCELLED` with a
`CANCELLED` operation state when cancellation reaches the child, and leaves partial workspace bytes
untouched. A host crash can instead leave an incomplete `RUNNING` operation; startup and verification do
not rewrite that evidence into a cancellation claim.

Arguments are passed directly to the child process. NoTUG does not parse pipelines, redirection, `&&`,
globs, variable expansion, or a shell quoting language. The shell that launches `notug` consumes its own
quotes once. When shell semantics are intentional, make the shell an explicit executable, such as
`pwsh -NoProfile -Command ...` or `sh -c ...`, and treat its expansion and redirection as additional
authority. On Windows, direct `.bat` and `.cmd` targets are refused because the operating system may
route them through its command processor despite a direct-process request. Name `cmd.exe` explicitly
only when that shell parsing is intended; otherwise use a native executable.

### Tug — `notug tug SESSION_ID`

Tug first verifies the receipt chain, policy hash, original baseline object, repository drift, and the
evidence lattice. It then creates a binary-capable patch and strict machine-readable signal, renders a
compact review summary, appends a receipt, and reports:

```text
Tug Signal generated
Human grant required
Protected checkout unchanged
```

No changes are applied by tug.

Tug first constructs its patch, workspace manifest, change record, and signal under a vault-owned staging
directory. Final artifact collisions fail before overwrite. A failure before publication removes only
known staging artifacts and refuses cleanup if an unexpected file or path redirect is present. If the
complete artifact set was published but its receipt could not be committed, it is retained as detectable
residue so verification fails closed.

The evidence lattice captures raw workspace SHA-256, type, size, and executable mode before staging,
then rereads those bytes to detect capture/reconciliation races. It uses Git's inert `hash-object --path`
model to apply only built-in attribute normalization, including text and end-of-line handling, and
requires that result to equal the staged blob ID. Discovered external clean/smudge filters, repository
hooks (including index-write hooks), and custom merge drivers are disabled for these protocol operations.
Proposed symlinks remain classified, and targets outside the session workspace are blocked by default.
Gitlinks are reconciled as opaque commit pointers; a populated nested checkout must match the staged
pointer and contain no tracked, untracked, or ignored local changes.

### Review — `notug review TUG_ID`

Review shows risk, changed paths, file and byte totals, deletes and renames prominently, binary metadata,
policy reasons, divergence state, baseline verification, receipt verification, and the exact grant and
deny commands. `--diff` adds a sanitized textual diff with binary payloads omitted; `--json` exposes the
complete structured Tug, baseline, chain, and command record. Control characters and escape sequences
from untrusted repository text are rendered inert in text mode.

### Deny — `notug deny TUG_ID`

Deny validates the selected signal, records the denial, and does not modify repository state. Archival or
removal of its session may occur only after disposition and receipt preservation, and only for resources
proven to belong to that session.

### Clean abandonment — Leucoform application service

An unchanged `SESSION_OPEN` worktree can be explicitly closed as `ABANDONED`. Core verifies the receipt
head, protected baseline, exact managed worktree, and clean status under the repository lock before
writing `SESSION_ABANDONED`. A changed or partially changed session cannot be abandoned. Grant, denial,
and abandonment are dispositions; worktree archival remains a separate explicit transition.

### Grant — `notug grant TUG_ID`

Grant is an explicit ceremony, not a policy outcome. The user should:

1. leave the agent-controlled session;
2. run review from a user-controlled terminal;
3. inspect paths, deletions, renames, binary metadata, risk, policy reasons, and diff as needed;
4. confirm the repository and baseline identities;
5. type the exact grant command for the selected Tug ID;
6. at the interactive prompt, type `GRANT TUG_HASH` using the full canonical hash shown by review.

Before writing, grant reverifies the receipt chain, strict signal schema, signal hash, patch hash, policy
hash, baseline, repository drift, and safe-apply preflight. A mismatch fails closed. A successful grant
creates a predictable collision-safe branch such as `notug/grant/<short-id>` in a dedicated integration
worktree, applies only the bound patch, runs configured validation, verifies the result structurally,
commits receipt identifiers as trailers, appends grant/application receipts, and reports:

```text
Grant bound to Tug Signal
Integration branch created
Protected checkout unchanged
```

The user then reviews and merges the integration branch through normal Git practice. Grant does not merge
or switch the primary checkout. Because the default policy has `validation.commands = []`, “runs
configured validation” means no project validation until the user adds explicit argv arrays to the
authoritative vault policy before starting the session.

Version `0.1` has no human identity service. A process with the same OS identity may be able to invoke the
CLI, so the human/agent separation is a supported operating ceremony rather than cryptographic personhood
proof. Grant rejects non-interactive input, known agent-session environments, and invocation from a
disposable session worktree, and it exposes no public unattended-confirmation flag. These checks strengthen
the ceremony but do not authenticate personhood. Do not expose grant execution to unattended agents.

Leucoform supplies the complete phrase to the same Core-owned grant path only after three distinct,
ordered, accessible companion faces are activated. The Core performs the same agent-context rejection
and locked revalidation as the CLI path. This is a native form of the supported human-intent ceremony,
not biometric or kernel-backed proof. Grant remains absent from Agent Bridge capabilities.

### Verify — `notug verify [REPO] [--json]`

Verify audits the event chain, stored manifests, session records, strict Tug Signals, signal hashes, patch
hashes, exact grant bindings, generated branches, and missing or altered artifacts. It also reverse-maps
every directory and Git registration in the managed session, integration, and revert worktree namespaces,
the generated grant/revert branch namespaces, and revocation evidence refs to the authoritative artifacts
and completed receipts that may claim them. Missing required resources, unclaimed resources, redirects,
and failed-grant residue are verification failures; verify reports rather than repairs them. Text mode
uses stable codes. JSON mode emits one valid JSON document even when input is corrupt or verification
fails.

### Export — `notug export TUG_ID [--include-paths] [--output FILE]`

Export verifies the Tug artifacts and receipt chain, then emits one patch-free JSON receipt. Without
`--include-paths`, affected paths become deterministic aliases scoped to the Tug hash and symlink targets
are redacted. `--include-paths` deliberately retains the original repository-relative paths and recorded
symlink targets; a target may itself be absolute or sensitive. The receipt contains the source Tug and
patch hashes, evidence and policy summaries, risk, receipt-chain head, and its own export hash; it contains
no patch bytes.

Without `--output`, JSON is written to standard output. With `--output`, the CLI writes one JSON file
atomically and refuses any destination inside the protected repository. Export neither changes protocol
state nor grants authority.

### Revoke or revert

For an unmerged NoTUG integration branch, the revoke operation verifies its grant identity, commit,
branch, worktree, and non-merge status. It retains the approved commit under
`refs/notug/revoked/<grant-id>` before removing only NoTUG-owned integration resources and recording
`REVOKED`. Collisions or ambiguity fail closed.

The reachability query covers every Git ref namespace, including custom refs. If another ref reaches the
approved commit but no safe local branch is available as a revert target, revoke returns
`REVERT_TARGET_REQUIRED` without removing the integration branch or worktree.

Once a change has been merged elsewhere, branch deletion is not rollback and history must not be rewritten.
NoTUG instead prepares a dedicated revert branch and records the target commit, inverse-patch hash,
applied-patch hash, and resulting tree. That branch is another reviewable forward change and follows the
user's normal merge process.

Reachability cannot identify equivalent changes introduced by squash, cherry-pick, or manual copying.
When equivalence is possible, the user must treat the work as merged and review a forward revert instead
of relying on generated-branch removal.

### Archive — `notug session archive SESSION_ID`

Archive is an explicit cleanup command available only after denial or completed application/revocation.
It verifies repository identity, session ownership, the managed worktree, receipt chain, Tug artifacts,
and exact reviewed workspace manifest. If any path, byte, type, size, or mode changed after review—or the
workspace cannot be reconciled—archive returns `WORKSPACE_POST_REVIEW_DRIFT` and preserves the worktree.
Only an unchanged reviewed workspace is removed, after which an archive receipt is appended. Archive does
not remove patches, receipts, integration branches, or unrelated worktrees. The comparison and forced Git
removal are separate operations: a concurrent process with the same OS authority can create content in
between. Quiesce writers and preserve important session work before archive; version `0.1` does not claim
an atomic filesystem snapshot-and-delete primitive.

## Tug Signal contents

A signal binds at least:

- schema and NoTUG version, timestamp, repository identity, session identity, and Tug identity;
- baseline commit, current baseline verification, policy hash, and receipt-chain head;
- every affected path and create/modify/delete/rename/mode/symlink/submodule/binary classification;
- file/byte totals, diff statistics, sensitive-path and policy findings, and risk summary;
- Git evidence, captured raw workspace SHA-256/type/size/mode evidence, staged blob/tree evidence, and
  divergence findings;
- patch artifact hash, grant requirement, and canonical signal hash.

Top-level unknown fields are invalid. Stored patches are never read as commands.

## Receipt chain

Each JSONL event includes its sequence, timestamp, event type, relevant identities, previous event hash,
and its own canonical-content SHA-256 hash. Canonicalization is deterministic and excludes the final hash
field while calculating it. Verification detects edits, insertion, removal, duplication, and reordering.

Receipts are evidence only. A valid receipt does not grant authority, and event strings do not cause
execution. See [PRIVACY.md](PRIVACY.md) for minimisation rules.

## Fail-closed errors

Stable machine-readable codes distinguish conditions such as dirty source state, invalid schema, invalid
state transition, policy hash mismatch, patch hash mismatch, baseline drift,
`POLICY_SNAPSHOT_DIVERGENCE`, `UNSAFE_BASELINE_SYMLINK`, `WORKSPACE_POST_REVIEW_DRIFT`,
`REVERT_TARGET_REQUIRED`, unsafe proposed symlinks, Tug staging collision or residue, corrupt receipt
chain, and `PROVENANCE_DIVERGENCE`. Error text explains recovery without silently altering user data.
