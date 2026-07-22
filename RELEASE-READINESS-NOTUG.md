# NoTUG clean-user validation

**Candidate version:** `0.1.0`

**Validation date:** 2026-07-18

**Validated commit:** `1dd55ae59c767b55d47788670b4f83cebba711fc`

**Validated artifact:** `notug_protocol-0.1.0-py3-none-any.whl`

## Outcome

The validated NoTUG wheel installed successfully into a newly created Python virtual environment outside the repository. The packaged command-line entry point, version reporting, diagnostics, Git integration, and isolated end-to-end demonstration all behaved as expected.

The source repository was clean before testing, and the previously completed source validation reported 137 passing tests.

## Clean-user environment

- Python: `3.14`
- Git for Windows: `2.55.0.windows.3`
- Virtual environment:
  `$env:USERPROFILE\Documents\Codex\2026-07-14\notug-clean-user-test`
- Wheel:
  `$env:USERPROFILE\Documents\Codex\2026-07-14\notug-validated-artifacts-1dd55ae\notug_protocol-0.1.0-py3-none-any.whl`

The virtual environment was not activated because local PowerShell execution policy disabled `Activate.ps1`. Testing instead invoked the environment's executables directly, confirming that activation was not required.

## Measured results

- Wheel installation: passed
- Installed package metadata: `notug-protocol 0.1.0`
- Packaged `notug` entry point: passed
- `notug --version`: returned `notug 0.1.0`
- Missing Git detection: passed
- Non-repository detection: passed
- Repository cleanliness detection: passed
- Git worktree support detection: passed
- Uninitialized-repository warning: passed
- Filesystem and vault preflight checks: passed
- Isolated demonstration: passed
- Receipt verification: passed
- Provenance-divergence detection: passed
- Mutation Lock remained active

## Git ownership observation

The repository was owned by the `CodexSandboxOffline` Windows account rather than the interactive user account. Git correctly rejected the repository as having dubious ownership.

A temporary environment-based `safe.directory` override worked for direct Git commands but was deliberately stripped by NoTUG's hardened Git subprocess environment. A user-level Git `safe.directory` entry was therefore added for the repository, after which NoTUG diagnostics passed.

This behaviour confirms that NoTUG does not silently inherit ambient `GIT_CONFIG_*` routing variables.

## Demonstration result

The packaged demo completed all twelve stages:

1. created an isolated baseline repository;
2. initialized protection;
3. created a disposable session;
4. simulated file modification and deletion;
5. confirmed the protected checkout remained unchanged;
6. generated a Tug Signal requiring human approval;
7. denied the first Tug Signal without changing the protected checkout;
8. created a second session and Tug Signal;
9. bound a human grant to the second Tug Signal;
10. created a separate integration branch;
11. verified eight provenance events;
12. detected deliberate provenance divergence.

## Conclusion

The NoTUG `0.1.0` wheel passed clean-user installation and packaged end-to-end demonstration testing on Windows.
