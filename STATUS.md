# Project status

**Version:** `0.1.0`
**Status date:** 2026-07-20
**Release state:** hardened, privacy-sanitized DevWeek `0.1.0` candidate validated locally on Windows;
installer wrapping, public-release decisions, cross-platform native evidence, and independent audit
remain open; nothing has been published

**Leucoform state:** optional desktop implementation complete in source, including the 200–300 pixel
rhombic-triacontahedron companion, accessible three-face Grant ceremony, Luminous Atom state, and
path-sanitized SBOM generation. The frozen Windows executable passed its self-test. The macOS/Linux
definitions are present but are not executed proof. All artifacts remain unsigned development builds.

The package implements the documented local Git change-control workflow: initialization, diagnostics,
disposable sessions, command receipts, Tug Signal generation and review, explicit denial or interactive
exact-hash grant, dedicated integration branches, verification, revocation or forward revert, patch-free
receipt export, and an isolated demonstration.

## Supported scope

Version `0.1.0` supports clean local Git repositories on Windows, Linux, and macOS with Python 3.11 or
newer. It uses disposable linked worktrees, local SHA-256 evidence, strict vault policy, hash-chained
receipts, Tug Signal review, an explicit human ceremony, and dedicated integration branches.

Non-Git folders, dirty-source recovery, automatic grants, cloud services, telemetry, hostile-process
containment, remote attestation, and automatic merging are outside version `0.1.0`.

## Current validation record

The consolidated clean-history DevWeek source was validated from its exact `src` import on Windows:

- Ruff format: 58 files already formatted; Ruff lint passed.
- strict mypy: no issues in 35 source files.
- pytest: 184 passed in 276.82 seconds.
- documentation: 44 relative links across 27 Markdown files passed.
- minimisation: 18 prohibited fields rejected; generated receipt clean.
- source, SBOM, and executable scans found no excluded legacy naming, personal profile paths, raw task
  markers, credential-shaped strings, or bundled Codex executable.
- the wheel and source archive passed local release verification and clean-install checks.
- PyInstaller produced a 45,735,486-byte unsigned `Leucoform.exe`; its hidden self-test exited 0.
- the state harness rendered every presentation without creating sessions, receipts, Tugs, or Grants.

The prior renamed release-candidate record follows.

The latest Codex-hardened source at commit
`a2516a124a0bd37c32cd7aecafffb1c8edc6ae48` was renamed and validated on Linux with Python 3.13.5 and
Git 2.47.3. The original Windows hardening record is preserved in
[`docs/history/RELEASE-READINESS-NOTUG.md`](docs/history/RELEASE-READINESS-NOTUG.md).

Current renamed-source results:

- Ruff format: 43 files already formatted.
- Ruff lint: all checks passed.
- strict mypy: no issues in 23 source files.
- pytest: 137 collected; 134 passed and 3 platform-specific tests skipped.
- documentation: 41 relative links across 17 Markdown files passed.
- minimisation: 18 prohibited fields rejected; generated receipt clean.
- clean wheel/sdist build and strict release verification passed.
- fresh isolated installation, `pip check`, `notug --version`, CLI/module help, and JSON demo passed.

Artifact hashes and the exact validation boundary are recorded in
[`RELEASE-READINESS.md`](RELEASE-READINESS.md).

### Validation boundary

The current rename validation was performed on Linux with Python 3.13.5. The source also contains prior
Windows validation evidence, but current Windows/macOS execution and the full Python 3.11–3.14 CI matrix
remain public-release gates. Configuration is not execution evidence.

## Known limitations

- NoTUG is workflow isolation, not a kernel, container, VM, privilege, or malware boundary. A process
  with the same OS authority can attempt direct access to the repository, vault, refs, credentials, and
  network.
- Linked worktrees share Git's object database and many refs. Protected-checkout verification is not a
  claim that shared Git storage or the host OS was untouched.
- SHA-256 bindings and the JSONL chain are unsigned local evidence. They do not provide trusted time,
  non-repudiation, independent witnessing, or protection from an attacker who controls the tool and all
  retained anchors.
- Repository hooks, discovered clean/smudge filters, and custom merge drivers are neutralized for
  NoTUG-owned critical Git operations. Signal reconciliation still models Git's built-in text/end-of-line
  normalization when binding captured raw workspace bytes to staged blob IDs. A contaminated replacement
  hooks directory fails closed, but child commands, configured validation tools, the Git/Python
  executables, same-user check/use races, and other host configuration remain trusted dependencies.
- Session start refuses every tracked baseline symlink with `UNSAFE_BASELINE_SYMLINK` before worktree
  creation. Proposed symlinks remain classified and outside-workspace targets are blocked by default.
  Symlink creation and reporting still vary by platform and permissions, especially on Windows.
- Populated Gitlinks must match their staged commit pointers and contain no tracked, untracked, or ignored
  local changes. This is fail-closed reconciliation, not containment of nested repositories.
- Git reachability cannot infer semantic equivalents introduced by squash merge, cherry-pick, or manual
  copying. Users must treat those as merged changes and use a reviewed forward revert.
- Archive compares the exact reviewed file-and-directory manifest immediately before forced worktree
  removal, but comparison and deletion are not atomic against a concurrent same-user filesystem writer.
  Writers must be quiesced and valuable work preserved before archive.
- A crash or storage failure can leave incomplete state. Receipt-chain/head or artifact inconsistencies
  fail closed, and verification reverse-maps managed worktree directories and registrations, generated
  branches, and revocation evidence refs to flag missing, unclaimed, or failed-grant residue. An
  interrupted operation can remain recorded as running and requires manual inspection; audit commands do
  not silently repair evidence or resources.
- Local sensitive-path policy and minimisation checks cannot detect every secret or unsafe semantic code
  change. The vault can contain sensitive patch bytes and must be protected like the source repository.

## Human review required before public release

- NoTUG trademark, confusing similarity, and package/command-name availability;
- README, threat-model, and security claims against the final measured behavior;
- CI results across every claimed Python, Git, and operating-system combination;
- MIT license text, dependency licenses, notices, and public-release policy;
- wheel and source-distribution contents, fixtures, and scans for secrets or private material;
- artifact hashes, reproducibility expectations, installation and uninstall instructions;
- private vulnerability-reporting channel and supported-version policy.

The definitive security boundary is [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Naming-specific release
review is in [docs/NAMING.md](docs/NAMING.md).
