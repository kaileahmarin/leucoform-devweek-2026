# Demonstration

## Purpose

`notug demo` shows the complete protocol without accepting or modifying a real user repository. It creates
a new temporary directory, initializes its own synthetic Git repository and isolated vault, and uses only
synthetic content. Measured release evidence is recorded in [../STATUS.md](../STATUS.md).

## Run

```text
notug demo
notug demo --json
```

The command takes no repository argument. Refusing a user-supplied repository prevents the demonstration
from being repurposed as a destructive test against real work. Text mode prints a numbered transcript;
JSON mode returns the same transcript plus structured result fields.

## Required sequence

The demo performs these stages:

1. create a new temporary repository with two harmless text files and a baseline commit;
2. initialize NoTUG protection and identify the repository record;
3. create and identify a first disposable session;
4. simulate an agent modifying one file and deleting the other;
5. hash and compare the protected checkout to prove it is unchanged;
6. generate a Tug Signal and check that it classifies the modification and deletion;
7. deny that signal and retain a denial receipt without repository mutation;
8. create a second session and make a small synthetic change;
9. generate a second signal and feed its exact hash through a synthetic in-memory TTY to the same
   interactive confirmation path used by the CLI;
10. create a dedicated integration branch while the protected checkout remains unchanged;
11. verify the receipt chain, signal, patch, grant binding, and integration branch;
12. alter the synthetic receipt stream, demonstrate deterministic verification failure, restore the
    original bytes, and verify the original chain again.

The demo must not auto-grant a real proposal. Its grant stage is safe only because the entire repository,
vault, policy, agent action, and user decision are synthetic and created by the demo itself.

## Reported evidence

The transcript identifies the synthetic baseline, first session, Tug IDs, denial, demo-only grant binding,
integration branch, receipt count, protected-checkout comparison, and tamper-detection result without
printing file bodies. The structured result contains:

- `baseline_commit`, `denied_tug`, `granted_tug`, and `integration_branch`;
- `protected_checkout_unchanged: true`;
- `receipt_tampering_detected: true`;
- `mutation_lock: "active"`.

The final numbered line reports tamper detection and active Mutation Lock. On exit, the temporary-directory
context removes the synthetic repository and vault. The demo never prunes unrelated Git worktrees, deletes
unrelated branches, inspects a user credential store, or intentionally uses network access.

## Manual safety review

The release review verifies that:

- its temporary root is newly allocated and resolved before any removal;
- every recursive cleanup target remains within that root;
- baseline and protected-checkout hashes match before and after both sessions;
- the first Tug Signal records a deletion and the denial changes no protected ref;
- the second grant binds only its own signal and patch;
- the integration commit contains receipt trailers;
- the tamper test alters only synthetic evidence inside the demo vault and restores the exact original
  event bytes before the final verification;
- a failed intermediate command leaves Mutation Lock active and a valid original chain.

The demo is educational evidence, not a substitute for the full test suite or threat-model review.
