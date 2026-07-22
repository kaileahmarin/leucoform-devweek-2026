# Privacy

## Commitment

NoTUG is local-first and minimised by design. The runtime has no telemetry, analytics, account,
cloud service, remote API, automatic issue reporting, or content upload. It does not require an OpenAI
API or any other hosted model API.

This commitment applies to NoTUG itself. Commands launched with `notug run`, configured validation
commands, package installers, Git hooks, and coding agents are separate programs and may have their own
networking and data practices. NoTUG does not sandbox or inspect them.

## Local data inventory

| Artifact | Necessary contents | Excluded or minimised contents |
| --- | --- | --- |
| Repository record | Stable repository ID, local association, baseline identity | No repository file bodies |
| Policy | Versioned classifications, thresholds, validation argv, privacy option | No policy loaded from untrusted repository text |
| Session record | Session ID/name, baseline, policy hash, workspace association, state | No environment dump or credential store data |
| Baseline manifest | Tracked paths, modes, Git object IDs, SHA-256 hashes, byte sizes | No tracked file bodies |
| Workspace manifest | Session paths, types, modes, sizes, and SHA-256 hashes, including ignored regular files | No regular-file bodies, but see the ignored-file limitation below |
| Event receipt | IDs, event type, timestamps, state, hashes, result codes, minimised command metadata | No ordinary file bodies or environment variables |
| Tug Signal | Changed paths/classifications, totals, findings, evidence hashes, risk, artifact bindings | No redundant full file contents |
| Patch | Exact proposed content required for review and application | Stored only in the local vault, never ordinary event logs |
| Export | Verified Tug, policy, risk, artifact hashes, and chain head | Patch always excluded; paths use scoped aliases by default |

The patch is the important exception to content minimisation. A text patch can contain source, personal
data, credentials, or secrets proposed by an agent. Binary patches can contain opaque sensitive bytes.
Because exact grant binding requires the exact patch, the local vault must be protected like the source
repository itself.

Tug construction stages its patch, workspace manifest, classifications, and signal under the vault before
publishing the complete artifact set. Known incomplete staging is removed on pre-publication failure, but
unexpected staging content is preserved and cleanup fails closed. Evidence published before an interrupted
receipt is retained for verification rather than silently erased.

## Ignored-file hashing limitation

Current `0.1` workspace capture traverses ignored regular files and stores their repository-relative path,
size, executable mode, and SHA-256 hash in the local workspace manifest. Ignored bytes are not added to the
proposal patch merely because they were observed, and the workspace manifest is not part of receipt
export, but this is still local data access and retention. A hash of a low-entropy value may be vulnerable
to guessing, and hashing a large ignored file can be costly.

This is a known privacy/design limitation, not a fixed defect or a claim that ignored files are secret.
Avoid placing real credentials or unrelated sensitive data in a session worktree, and protect the vault as
strongly as the repository. Ignored sensitive path names may also appear in local Tug findings so the user
can review their presence.

## Command metadata

Run operation artifacts retain the executable name, locally minimised arguments, timestamps, exit status,
and session identity. The hash-chained event stores the executable, argument count, and a hash of that
command record. Environment variables are not recorded. NoTUG redacts common secret-flag and secret-value
forms, but no heuristic recognizes every secret. Secrets should never be placed on a command line: argv
may be visible to NoTUG, the child process, the operating system, or other diagnostic tools. Prefer a
child tool's secure credential mechanism.

NoTUG treats stdout and stderr as untrusted transient terminal data and does not need them in ordinary
receipts. Implementations must not copy complete agent transcripts into the event stream merely for
convenience.

## Paths and exports

Operational vault records need local paths to find repositories and worktrees. `notug export TUG_ID`
replaces repository-relative paths with deterministic aliases scoped to the Tug hash and redacts symlink
targets. `--include-paths` explicitly retains repository-relative paths and recorded symlink targets when
a recipient needs them. Symlink targets can be absolute or sensitive, so inspect that form before sharing.
Redaction affects exports, not the internal records required to operate and verify local sessions.

Receipt exports never contain patch or diff bodies, even with `--include-paths`. They include the patch
hash so a recipient can compare separately governed evidence without receiving source bytes implicitly.
When `--output` is used, NoTUG refuses to write the receipt inside the protected repository.

Default versioned vault roots are `%LOCALAPPDATA%\notug-protocol\v1` on Windows (with `%APPDATA%` as a
fallback), `~/Library/Application Support/notug-protocol/v1` on macOS, and
`${XDG_DATA_HOME}/notug-protocol/v1` or `~/.local/share/notug-protocol/v1` on Linux and other supported
POSIX hosts. `NOTUG_HOME` overrides the unversioned base, producing `<NOTUG_HOME>/v1`; it must expand to an
absolute path. Operational records under that root contain the local repository and worktree paths needed
for verification.

## Retention and deletion

NoTUG does not silently delete vault evidence, session worktrees, branches, or patches. Denial records a
disposition; archival or removal is a separate deliberate action after chain verification. Revocation may
remove only verified NoTUG-owned unmerged integration resources. Merged history is not rewritten.

Archive compares the disposed session with its reviewed workspace manifest before removing it. Any
post-review path, byte, type, size, or mode drift causes `WORKSPACE_POST_REVIEW_DRIFT`; the worktree and its
unexpected content remain for manual inspection.

Users should establish retention appropriate to the repository's sensitivity. Before deleting a vault,
verify all receipts, confirm no pending Tug Signal or integration branch depends on it, and retain any
records required by the user's own change-control policy.

Uninstalling the Python package does not erase local data.

## Filesystem permissions

The vault is outside the protected repository in an OS-appropriate per-user data directory. NoTUG creates
its directories with restrictive modes where the platform supports them. Doctor reports vault writability
from a temporary create/remove probe separately from confidentiality. On POSIX it reports whether the
existing vault root has group or other permission bits; it does not inspect ownership, permissions below
that root, or ACLs. On Windows it explicitly reports that confidentiality ACLs were not assessed. ACL
inheritance, POSIX ownership and modes, backup software, indexing, and disk encryption remain OS and user
responsibilities.

## Minimisation verification

Regression checks generate representative receipts and fail if they contain prohibited fields such as
environment maps, tokens, passwords, secret values, full file bodies, or raw command transcripts. Tests
use synthetic fixtures, never copied credentials or ignored user files. These checks do not remove the
ignored-file workspace hashes described above.

See [SECURITY.md](SECURITY.md) for safe operation and [THREAT-MODEL.md](THREAT-MODEL.md) for limits.
