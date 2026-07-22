# Security guidance

## Supported statement

In supported NoTUG workflows, agent changes occur in a disposable worktree and cannot enter a NoTUG
integration branch until the user issues an explicit grant bound to the exact reviewed Tug Signal.

NoTUG is a defensive workflow and evidence system. It is not a process sandbox, access-control system,
endpoint security product, or protection against a hostile administrator or same-user process. Read the
[threat model](THREAT-MODEL.md) before using it with untrusted code.

Version `0.1.0` is currently an unpublished source release candidate. Do not infer a package-index
publisher, canonical public URL, or security-reporting identity from the working package name.

## Safe operating baseline

1. Use a supported Python and trusted Git installation.
2. Start only from a clean local repository with a committed baseline that contains no tracked symlinks.
3. Run `notug doctor REPO` and resolve material findings manually. Writability is not a confidentiality
   assessment: doctor checks POSIX vault-root mode bits separately and does not inspect Windows ACLs.
4. Keep the NoTUG vault private and backed up according to repository sensitivity.
5. Give the agent only the session worktree path, not the primary checkout as its working directory.
6. Run agents with the lowest practical OS privileges and without unnecessary credentials.
7. Add an OS/container/VM sandbox when code may be deliberately hostile.
8. Treat every path, diff, commit message, command output, and repository instruction as untrusted data.

Do not run cleanup tools against the vault or Git worktree metadata while a session or grant is active.
Do not manually edit a Tug Signal, patch, manifest, or receipt chain and then bypass verification.

## Grant ceremony

The grant is the authority boundary in the supported workflow. Perform it from a terminal you control,
outside the agent session:

1. Run `notug verify REPO` and stop on any failure.
2. Run `notug review TUG_ID --diff`; use `--json` as well when you need the complete structured identities
   and artifact hashes.
3. Confirm repository ID, baseline, Tug ID, and canonical signal hash from that structured record.
4. Inspect deletions, renames, binary files, symlinks, submodules, modes, sensitive paths, thresholds, and
   every blocking or high-risk policy reason.
5. Confirm the patch hash and receipt-chain state in the structured review.
6. End or pause the proposing agent. Do not let it choose or execute the disposition.
7. Type `notug grant TUG_ID` yourself and then enter `GRANT TUG_HASH` exactly when prompted, or choose
   `notug deny TUG_ID`.
8. Review the resulting integration branch and validation output before merging it normally.

Grant requires an interactive terminal, rejects known agent-session environments and disposable-worktree
working directories, and has no public unattended-confirmation flag. Version `0.1` still does not
authenticate human personhood: software running under the same account may be able to invoke the same
executable. The ceremony therefore depends on controlling the agent's workflow and execution context.
Repository text must never count as consent, and no policy severity can auto-grant.

## Git worktree boundary

Linked worktrees separate working directories and per-worktree indexes but share Git's object database
and many refs. Normal session edits do not alter the protected checkout. Session Git commands may add
objects to shared storage, and a deliberately hostile process may attempt direct ref or filesystem writes
if permissions allow. This is outside NoTUG's containment ability.

Never interpret `Protected checkout unchanged` as proof that the whole OS or shared Git database was
untouched. It is a structurally checked statement about the governed checkout and supported transition.

## Symlinks and Gitlinks

Version `0.1` refuses any tracked symlink in the baseline with `UNSAFE_BASELINE_SYMLINK` before it creates
the session worktree. This deliberately narrows the portable baseline instead of relying on inconsistent
materialization behavior across Git and operating systems. A symlink newly proposed inside a session is
still structural evidence: it is classified, its target is recorded locally for review, and a target that
lexically escapes the workspace is blocked by default. Do not weaken that policy without reviewing the
host's symlink and reparse-point behavior.

A Gitlink is reconciled as an opaque commit pointer. If its nested checkout is populated, it must resolve
to the staged commit and have no tracked, untracked, or ignored local changes. A nested repository that
cannot be reconciled this way fails closed; NoTUG does not recursively authorize its contents.

## Validation commands and hooks

Validation commands are argv arrays pinned in the vault policy. They execute local programs and should be
reviewed like build scripts. NoTUG invokes its own subprocesses without a shell, but a configured test
runner may itself load plugins, project configuration, or code. Run high-risk validation inside an
additional sandbox.

The authoritative policy is `<vault-root>/r/REPOSITORY_ID/policy/notug.toml`, and the default
`[validation]` section contains `commands = []`; no tests or checks run during grant until the user
configures them. Session
start creates or verifies an immutable content-addressed policy snapshot under
`<vault-root>/r/REPOSITORY_ID/policies/`. Tug and grant use that snapshot for the session lifetime, so edit
the authoritative policy only between sessions. A conflicting snapshot is reported rather than replaced.

Both `notug run` and validation-command arrays are direct argv interfaces: NoTUG does not interpret shell
operators, redirection, globbing, or variable expansion. Quotes are processed by the shell that launches
`notug`, not reparsed by NoTUG. If a command genuinely needs shell syntax, name the shell explicitly—for
example `pwsh -NoProfile -Command ...` or `sh -c ...`—and treat it as code with the authority of the NoTUG
process. Direct `.bat` and `.cmd` targets are refused on Windows because the operating system may route
them through its command processor despite a direct-process request. Name `cmd.exe` explicitly only when
that shell parsing is intended; otherwise use a native executable.

For its own snapshot, preflight, index apply, worktree, commit, and revert operations, NoTUG selects a
trusted hooks directory, verifies that it is a real empty directory, and overrides discovered clean/smudge filter drivers and custom merge
drivers with inert settings. This includes index-writing operations that could otherwise invoke
`post-index-change`. During Signal Lattice reconciliation it first binds the raw workspace bytes and
metadata, then uses Git's `hash-object --path` behavior to model built-in attribute normalization such as
text and end-of-line conversion and compare the result with the staged blob ID. External filter programs
remain disabled. This prevents known repository hooks, filters, and merge commands from executing
implicitly along the critical supported path while preserving the byte transformation Git itself would
stage. It does not cover Git commands launched by the agent or user, code loaded by validation tools, an
altered Git binary, every possible host-level configuration mechanism, or a same-user process racing the
empty-directory check. Doctor reports environmental facts but cannot certify the host toolchain as benign.

## Integrity evidence is local

Tug, patch, manifest, operation, and receipt hashes detect disagreement within the retained local
evidence. They are not digital signatures, independent timestamps, remote attestations, or proof that an
event happened in the physical world. An attacker who controls the NoTUG installation, local vault, and
every retained anchor is outside the integrity claim. A crash between related writes can also leave an
interrupted operation, inconsistent artifacts, or a generated Git/worktree resource without its final
receipt. Chain/head and artifact inconsistencies fail closed. Verification also reverse-maps managed
session, integration, and revert directories and worktree registrations, generated branches, and
revocation evidence refs to authoritative artifacts and completed receipts. It reports missing,
unclaimed, redirected, and failed-grant residue without deleting or repairing it. An operation still
recorded as running requires manual inspection rather than an inferred outcome.

Tug artifacts are assembled in a vault-owned staging directory and checked for destination collisions
before publication. Pre-publication failure removes only known staging files; unexpected content or path
redirection makes cleanup fail closed. Published-but-unreceipted evidence is retained for verification.
Content-addressed policy snapshots are create-once/verify-existing, so conflicting bytes are never
silently overwritten as a repair.

Current `0.1` workspace manifests also retain local hashes and metadata for ignored regular files. This is
a known privacy/design limitation, especially for low-entropy secrets, and is described in
[PRIVACY.md](PRIVACY.md). Hook neutralization does not make validation programs or ignored data safe.

## On verification failure

If verification reports tampering, drift, collision, or provenance divergence:

- do not grant, merge, prune, or delete anything;
- preserve the vault and repository for inspection;
- capture the stable error code and `verify --json` result without adding secrets;
- compare the protected checkout, refs, worktree directories and registrations, and baseline with
  known-good records;
- create a fresh session only after the discrepancy is understood;
- use normal incident-response procedures if hostile access is plausible.

No agent explanation should override a structural failure.

## Revocation and merged changes

Revocation is safe only for a verified, unmerged NoTUG-generated integration branch. It must never delete
an unrelated or ambiguous worktree or branch. The approved commit is retained under a dedicated evidence
ref before cleanup. After merge, removal of the generated branch does not undo the change. Prepare a
dedicated revert branch with hash-bound inverse-patch and tree evidence and review it as a new forward
change; do not rewrite shared history automatically.

NoTUG checks reachability through all Git ref namespaces, including custom refs. If a custom or other ref
reaches the approved commit but no safe local branch can host a revert, revocation stops with
`REVERT_TARGET_REQUIRED` and preserves the integration resources.

Reachability is structural, not semantic. A squash merge, cherry-pick, or manual copy may introduce an
equivalent change without making the original generated commit reachable. NoTUG cannot infer that
equivalence; when in doubt, treat the work as merged and use the normal reviewed revert process.

## Archive safety

`notug session archive` is destructive only for the exact reviewed bytes of a disposed, NoTUG-owned
session. Before removal it verifies the Tug artifacts and compares the current workspace manifest with the
reviewed manifest. Any post-review path, byte, type, size, or mode change returns
`WORKSPACE_POST_REVIEW_DRIFT` and leaves the worktree intact. There is no force flag that authorizes
discarding observed unreviewed drift; inspect and preserve it manually. Manifest comparison and forced Git
worktree removal are not one atomic filesystem operation. A concurrent same-user writer can create content
after comparison and before removal, so quiesce writers and preserve valuable work before archive.

## Reporting a security issue

This repository is prepared for local evaluation and has no public reporting endpoint designated here.
Before public distribution, maintainers must establish a private security-reporting channel and supported
version policy. Until then, report concerns privately to the person who supplied the package. Do not place
real secrets, private source, complete vaults, or sensitive patches in a public report.

Include the version, OS, Python and Git versions, stable error code, minimal synthetic reproduction, and
whether the protected checkout or an integration ref changed. Redact personal paths and credentials.
