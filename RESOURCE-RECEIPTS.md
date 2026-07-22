# Resource Receipts

**Status:** local evidence foundation, schema version 1
**Default:** local only; no telemetry, networking, analytics SDK, or background upload

A Resource Receipt measures the marginal work attributable to NoTUG. It is separate from governance
receipts, which prove state transitions, and separate from any future user-reviewed anonymous export.
It must never imply that the entire coding-agent runtime is NoTUG overhead.

## Measurement boundary

The measurement model separates four clocks:

- `notug_active_seconds`: NoTUG parsing, Git inspection, hashing, evidence generation, service, and
  bridge work;
- `agent_execution_seconds`: time owned by the launched agent or agent command;
- `human_review_wait_seconds`: idle wall time awaiting a human decision;
- `integration_verification_seconds`: exact application, validation, and structural verification.

Cleanup is represented by `cleanup_bytes_reclaimed` and may later receive its own phase receipt. Wall
times must not be summed blindly when phases overlap. Process CPU time is NoTUG's process CPU, not
agent CPU and not whole-machine utilization.

The current `ResourceMeter` automatically measures only:

- NoTUG active wall-clock duration using a monotonic clock;
- current-process CPU duration;
- Git launch-attempt count through NoTUG's hardened adapter while the meter is active.

`note_git_launch_attempt()` is a no-op when no meter is active. An attempt is counted immediately
before `subprocess.run`, including launches that then fail. Nested active `ResourceMeter` contexts are
rejected with `RESOURCE_METER_INVALID`; attribution between nested operations is not defined yet. A
meter still finalizes its receipt when an exception propagates from the measured block.

Other fields are supplied only by an explicit measuring component. Unmeasured values are `null` and
their `measurement_availability` entry is `false`; they are never silently zero-filled.

## Schema version 1

The serialized receipt has this fixed shape:

```json
{
  "schema_version": 1,
  "receipt_kind": "notug.resource-receipt",
  "operation_id": "op_measure_001",
  "operation": "tug.generate",
  "durations_seconds": {
    "notug_active_seconds": 0.125,
    "agent_execution_seconds": null,
    "human_review_wait_seconds": null,
    "integration_verification_seconds": null
  },
  "process_cpu_seconds": 0.031,
  "git_launch_attempt_count": 7,
  "peak_working_set_bytes": null,
  "io_read_bytes": null,
  "io_write_bytes": null,
  "files_inspected": null,
  "bytes_inspected": null,
  "worktree_apparent_size_bytes": null,
  "worktree_incremental_disk_bytes": null,
  "vault_size_before_bytes": null,
  "vault_size_after_bytes": null,
  "git_object_store_size_before_bytes": null,
  "git_object_store_size_after_bytes": null,
  "cleanup_bytes_reclaimed": null,
  "protected_checkout_writes_detected": null,
  "measurement_availability": {
    "notug_active_seconds": true,
    "agent_execution_seconds": false,
    "human_review_wait_seconds": false,
    "integration_verification_seconds": false,
    "process_cpu_seconds": true,
    "git_launch_attempt_count": true,
    "peak_working_set_bytes": false,
    "io_read_bytes": false,
    "io_write_bytes": false,
    "files_inspected": false,
    "bytes_inspected": false,
    "worktree_apparent_size_bytes": false,
    "worktree_incremental_disk_bytes": false,
    "vault_size_before_bytes": false,
    "vault_size_after_bytes": false,
    "git_object_store_size_before_bytes": false,
    "git_object_store_size_after_bytes": false,
    "cleanup_bytes_reclaimed": false,
    "protected_checkout_writes_detected": false
  },
  "limitations": []
}
```

The availability object contains one boolean for every duration and metric. Operation labels and
limitation codes are short path-free protocol labels. The schema contains no field for repository
name, repository identifier, path, user, prompt, diff, Tug content, commit hash, or arbitrary notes.

## Metric definitions

| Metric | Definition and caution |
| --- | --- |
| Wall-clock durations | Monotonic elapsed time for the named boundary. Waiting and active work are separate. |
| Process CPU | CPU consumed by the current NoTUG process during the meter. Child-process CPU is not implied. |
| Peak working set | Highest resident/working-set sample attributable to the measured boundary. A process-lifetime peak is not an operation peak and must be labelled as a limitation. |
| Bytes read/written | OS process-I/O counters where available. They can include metadata and cache behavior and are not repository-content byte counts. |
| Git launch attempt count | Number of Git process launch attempts through NoTUG's hardened Git adapter while the meter is active, including attempts for which process launch fails. |
| Files/bytes inspected | Logical files and file bytes explicitly visited by the measured NoTUG operation. Git object reads need a separate definition. |
| Worktree apparent size | Sum of logical file sizes under the worktree at a defined sample point. Sparse files and shared Git objects make this different from allocated disk. |
| Worktree incremental disk | Allocated-byte delta attributable to the worktree where the platform/filesystem exposes a defensible value. |
| Vault sizes | Apparent or allocated vault bytes before and after, using one declared method for both samples. |
| Git object-store sizes | Before/after size of the shared object store. Concurrent Git activity makes attribution uncertain. |
| Cleanup reclaimed | Defensible before-minus-after allocated bytes for resources removed by one explicit cleanup. |
| Protected writes detected | Count from a separately defined before/after or monitoring method. `0` is valid only when that detector was attached; otherwise use `null`. |

## Platform limitations

### Windows

- `time.perf_counter` and `time.process_time` provide wall and current-process CPU durations.
- Working-set and process-I/O counters require Windows APIs and careful before/after sampling. The
  foundation does not call them yet and reports those metrics unavailable.
- NTFS allocation, compression, sparse files, hard links, reparse points, antivirus activity, and
  filesystem cache behavior make incremental disk use an estimate unless a specific measurement
  method is recorded.
- A child Git process is not included in Python's process CPU or I/O counters. Future measurement must
  sample child processes or use a Windows Job Object if it claims combined NoTUG-plus-Git cost.
- Directory size is not equivalent to physical disk allocation. Do not label apparent size as bytes
  allocated or reclaimed.

### Linux and macOS

- `getrusage`-style maximum RSS is often a process-lifetime maximum and differs in units across
  platforms. It must not be presented as a precise per-operation peak without sampling.
- Copy-on-write filesystems, sparse files, shared objects, hard links, and caches also limit disk-delta
  attribution.

Across platforms, concurrent repository, antivirus, indexer, backup, or user activity can invalidate
before/after attribution. Such a sample must carry a limitation instead of manufactured precision.

## Privacy rules

Resource evidence remains local by default. A local receipt and every future aggregate must exclude:

- repository names and repository identifiers;
- absolute or relative filesystem paths;
- usernames, hostnames, and account identifiers;
- prompts, responses, diffs, file contents, Tug contents, and command output;
- commit, tree, patch, manifest, grant, Tug, or receipt hashes;
- environment variables, credentials, tokens, and network identifiers.

An operation label describes a NoTUG code path such as `repository.status` or `tug.generate`, not a
user project. Limitation values are enumerated codes rather than free text. No resource receipt is
automatically copied into the governance ledger because doing so would mix performance evidence with
authority evidence and enlarge the privacy surface.

## Separation of evidence layers

| Layer | Purpose | Authority | Distribution default |
| --- | --- | --- | --- |
| Governance receipt | Prove repository/session/Tug/grant state and hash-chain transitions | Authoritative local Core evidence | Local only |
| Resource Receipt | Measure availability-labelled marginal NoTUG cost | Non-authorizing local performance evidence | Local only |
| Anonymous usage export | Future user-reviewed aggregate with coarse numeric buckets | Never governance authority | Does not exist in this slice |

Deleting or omitting a Resource Receipt must not change whether a grant is valid. A Resource Receipt
must not contain a grant decision. Governance verification must not depend on an analytics or export
pipeline.

## Local dashboard possibilities

A future local dashboard can read Resource Receipts through a read-only service and show:

- distributions of NoTUG active time by operation label;
- Git launch-attempt counts and inspected-byte totals;
- unavailable-metric rates, so missing data is visible;
- apparent worktree/vault growth and explicit cleanup estimates;
- protected-checkout detector coverage and any nonzero findings;
- phase timelines separating agent execution and human waiting from NoTUG work.

The dashboard should default to per-run and median/percentile summaries. It must retain the availability
denominator; a chart must not turn missing samples into zero.

## Benchmark methodology

1. Use a synthetic or explicitly approved local fixture repository; record fixture class only, not its
   name or path.
2. Warm and cold runs are separate cohorts. Record tool/Python/Git/platform versions in the benchmark
   report, not in an anonymous Resource Receipt unless safely bucketed later.
3. Pin repository state and operation inputs. Run enough repetitions to report median, p90, and spread.
4. Measure a direct baseline operation and the equivalent governed operation on independently reset
   fixtures.
5. Keep agent execution and human review outside `notug_active_seconds`.
6. Report every unavailable metric and known concurrent activity.
7. Verify the protected checkout before and after every run using existing Core evidence; record only
   the detector count in the Resource Receipt.
8. Do not use the validated `0.1.0` wheel as evidence for this new code. Build a new disposable artifact
   only when a later release-validation slice explicitly requests it.

## Marginal NoTUG overhead

For matched runs, calculate active overhead as:

```text
marginal_active_seconds = governed_notug_active_seconds - direct_control_seconds
```

If end-to-end latency is useful, report it separately:

```text
governed_elapsed = notug_active + agent_execution + human_review_wait
                 + integration_verification + non_overlapping_orchestration
```

Never divide by agent time and describe the result as total system efficiency without explaining the
denominator. Human review wait is a workflow latency, not compute overhead. Git child CPU and I/O are
excluded until a platform-specific sampler measures them.

## Future anonymous export gate

There is no exporter or network client in this slice. A future export requires:

1. a separate schema containing only coarse numeric buckets and operation categories;
2. deterministic rejection of paths, identifiers, hashes, free text, and rare fingerprinting values;
3. a local preview showing the exact export bytes;
4. an explicit per-export human confirmation;
5. no background task, retry queue, implicit consent, or governance coupling;
6. tests proving local Resource Receipts remain usable when export is disabled or absent.

That design must receive a separate threat and privacy review before implementation.
