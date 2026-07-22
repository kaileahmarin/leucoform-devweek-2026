# Threat model

This is the implemented `0.1` security model. Measured release evidence is recorded in
[../STATUS.md](../STATUS.md). No local test result should be treated as independent certification.

## Security objective

In supported NoTUG workflows, agent changes occur in a disposable worktree and cannot enter a NoTUG
integration branch until the user issues an explicit grant bound to the exact reviewed Tug Signal.

The objective is to prevent accidental, over-eager, inferred, stale, or poorly scoped agent changes from
silently becoming an authorized integration change. NoTUG preserves evidence and recoverability when
policy or provenance checks fail.

## Assets

- the protected checkout, current branch, baseline commit, and authorized integration refs;
- the authoritative vault policy and its recorded hash;
- manifests, patches, Tug Signals, receipts, and grant bindings;
- the user's ability to inspect, deny, revoke unmerged work, or prepare a revert after merge;
- repository content and local secrets that must remain local.

## Trust assumptions

- Git and Python executables, the NoTUG installation, OS filesystem, and cryptographic hash implementation
  behave as expected.
- The user controls the grant ceremony and reviews the intended Tug ID outside the agent session.
- The local vault is writable by NoTUG and protected from unrelated users according to OS permissions.
- The authoritative repository is clean and its committed baseline contains no tracked symlinks when a
  session begins.
- User-supplied commands are not assumed safe; they receive only the containment their OS environment
  provides.

## What version 0.1 supports

| Control | Supported outcome |
| --- | --- |
| Detached session worktree | Normal agent file edits do not edit the protected working directory |
| Clean-baseline requirement | Ambiguous existing work and every tracked baseline symlink are refused before session-worktree creation |
| Evidence lattice | Raw workspace SHA-256/type/size/mode, Git's staged tree, patch, and filesystem disagreement fails closed |
| Strict policy | Repository content cannot redefine the pinned vault policy |
| Exact grant binding | One reviewed Tug Signal does not authorize a different patch or signal |
| Integration worktree | Approved changes are applied on a dedicated branch, not the primary checkout |
| Hash-chained receipts | Receipt deletion, insertion, reordering, and alteration are detectable |
| Sanitized review | Terminal control sequences in untrusted text are rendered inert |
| Controlled critical Git operations | Trusted empty hooks and inert discovered external filters and merge drivers reduce implicit repository code execution; built-in Git normalization is modeled without executing those drivers |
| Managed-resource reconciliation | Verification reverse-maps worktree directories and registrations, generated branches, and evidence refs to authoritative artifacts and receipts |
| Patch-free export | Verified receipt JSON uses scoped path aliases by default and never embeds the patch |
| Local storage | NoTUG runtime has no telemetry, account, cloud API, or content upload |

## Detected, preserved, and best-effort outcomes

- **Detected policy violations:** unsafe or sensitive changes are classified or blocked according to
  the pinned policy. Detection is not containment.
- **Preserved recoverability:** denied sessions and verified receipts retain evidence; generated unmerged
  branches can be revoked; merged work is addressed with a forward revert, not history rewriting.
- **Best-effort environment checks:** doctor reports Python and Git availability, worktree support, case
  handling, vault writability, path length, receipt state, and stale resources. These checks cannot prove
  an OS is secure and are not a complete symlink-capability probe.
- **Detected crash residue:** verify reports unclaimed, missing, redirected, or failed-grant resources in
  NoTUG-managed worktree and ref namespaces. It deliberately does not infer ownership outside those
  namespaces or repair the residue.

## Linked worktrees are not storage sandboxes

A linked worktree has a separate work directory, index, and worktree-local `HEAD`, but it shares Git's
common object database and many refs with the protected repository. Normal source edits remain isolated
from the protected checkout. `git add` and `git commit` in the session may add objects to the common object
database, even when no protected branch advances. A process with the same filesystem authority could try
to alter shared refs or the primary checkout directly.

NoTUG governs the supported promotion path to integration refs; it does not provide storage isolation.
If shared-object writes are unacceptable, use an external sandbox plus an independently copied repository
and import its patch as untrusted evidence through a separately designed workflow. That stronger boundary
is not supplied by version `0.1`.

## Threats and responses

| Threat | Response | Residual limitation |
| --- | --- | --- |
| Agent deletes or rewrites files | Protected checkout remains separate; tug reports structural diff | Hostile process can address other paths directly |
| Agent misdescribes a change | Git/manifest/filesystem evidence overrides prose | Evidence relies on trusted local tools and storage |
| Patch changes after review | Patch and signal hashes are rechecked at grant | Same-user attacker may tamper with both tool and vault |
| Baseline advances | Drift check blocks grant | User must create a new session or resolve explicitly |
| Receipt edited/reordered/removed | Hash-chain verification fails | Truncation plus destruction of all external anchors may be indistinguishable from an older vault |
| Malicious instructions in repository text | Text remains inert and output is escaped | A separately launched vulnerable tool may interpret it |
| Tracked baseline symlink | Session start returns `UNSAFE_BASELINE_SYMLINK` before creating the worktree | Version 0.1 does not support such baselines |
| Proposed external symlink target | Classified and blocked by default | Platform symlink creation and reporting vary; version 0.1 has no complete capability probe |
| Dirty populated Gitlink | Pointer, nested `HEAD`, status, and ignored-file evidence are reconciled and divergence fails closed | Uninitialized Gitlinks remain opaque pointers; nested repositories are not recursively governed |
| Grant confused with another signal | Grant binds exact canonical Tug hash | CLI does not authenticate human personhood |
| Native grant confused with another signal | Leucoform requires the complete phrase and Core revalidates under lock | Same-user hostile input injection is not biometric or kernel-backed human proof |
| Prompt exposed in process listing | Leucoform sends bounded prompt bytes through stdin | Codex/provider processing remains outside NoTUG privacy control after transfer |
| Cancelled run mistaken for success | Runner records `RUN_CANCELLED`; partial bytes are retained | A host crash may leave incomplete evidence rather than a cancellation receipt |
| Integration resource collision | Fail closed; never delete unrelated resource | Manual cleanup may be needed |
| Secret proposed in a patch | Sensitive-path findings and local-only vault | Content-based secret detection cannot be complete |
| Repository hook, filter, or merge driver | Critical NoTUG Git calls require a real empty replacement-hooks directory and neutralize discovered external filters and custom merge drivers; Signal reconciliation models only Git's built-in normalization | Child tools, agent Git calls, altered binaries, same-user check/use races, or undiscovered host configuration remain outside the control |
| Concurrent state transition | Per-repository lock serializes supported mutating operations | Same-user hostile processes can bypass the CLI or attack local lock/state files |
| Concurrent write during archive | Exact file-and-directory manifest comparison catches drift observed before removal | Comparison and forced Git worktree removal are separate; a same-user writer can race them, so callers must quiesce writers and preserve valuable work |
| Crash between evidence and resource writes | Chain/head and artifact inconsistencies fail closed; reverse mapping flags unclaimed/missing worktrees, generated branches, evidence refs, and failed-grant residue; a running operation is not inferred complete | Manual inspection may be required; automatic repair is intentionally absent |
| Squash, cherry-pick, or manual copy | User applies normal review and forward-revert practice | Git reachability cannot infer semantic equivalence |

## Out of scope

Version `0.1` does not claim to:

- contain malware or a deliberately hostile local process;
- resist an attacker with administrator, root, debugger, or same-user filesystem access;
- prevent arbitrary subprocess networking, credential access, or writes outside the worktree;
- isolate the Git object database of a linked worktree;
- authenticate that a human, rather than another same-account process, typed a grant;
- secure a compromised Python runtime, Git executable, OS, filesystem, or NoTUG installation;
- provide remote attestation, hardware-backed signing, multi-party approval, or non-repudiation;
- provide an independent timestamp or protect all evidence when the tool, vault, and retained anchors are
  controlled by the same attacker;
- guarantee detection of every secret, unsafe semantic code change, or malicious binary;
- protect non-Git folders or dirty repositories in version `0.1`.

## Operational guidance

Use a low-privilege account, keep the vault private, review the exact Tug hash and diff, run validation
commands you trust, and merge integration branches through existing repository controls. For untrusted or
hostile code, add an OS/container/VM sandbox with restricted credentials and networking; do not rely on
NoTUG alone.

See [SECURITY.md](SECURITY.md) for the operating ceremony and [ARCHITECTURE.md](ARCHITECTURE.md) for trust
boundaries.
