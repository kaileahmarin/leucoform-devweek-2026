# Leucoform DevWeek project matrix

This repository is a clean-history, privacy-reviewed consolidation of the work that materially built
Leucoform and its NoTUG governance engine. It intentionally excludes raw chats, machine paths,
disposable worktrees, provider transcripts, private fixtures, credentials, and unrelated projects
that merely exercised NoTUG.

| Layer | Public name | Responsibility | Authority |
| --- | --- | --- | --- |
| Product | Leucoform | Ambient status, evidence review, accessible human consent, recovery UI | May request a Core operation; cannot relax verification |
| Engine | NoTUG Core | Managed worktrees, evidence lattice, policy, receipts, lifecycle, Grant application | Sole mutation-governance authority |
| Adapter | NoTUG CLI | Terminal lifecycle and exact typed Grant ceremony | Human-facing Core adapter |
| Adapter | Agent Bridge | Bounded session, run, status, submission, and review services | No Grant, denial, integration, or revocation authority |
| Evidence | Tug | Exact hash-bound proposal, patch, baseline, policy, and receipt facts | Evidence only; never authority |
| Storage | Local NoTUG vault | Policies, manifests, patches, receipts, sessions, integration worktrees | Local and fail-closed |

## Consolidated build streams

1. Dependency-light NoTUG protocol, state machine, CLI, vault, receipt chain, and evidence lattice.
2. Windows-first release hardening, minimisation, adversarial tests, and cross-platform behavior.
3. Bounded Agent Bridge and exact managed-worktree binding for recognized Codex launches.
4. Leucoform application services, cancellable stdin runner, review UI, lifecycle handling, and packaging.
5. Ambient rhombic-triacontahedron companion, three-face Grant ceremony, and sealed-evidence state.

## Submission boundary

The public package is generated from tracked source and reproducible build scripts. Private historical
repositories remain outside this repository. Their contents are not required to operate, test, or
review this submission.
