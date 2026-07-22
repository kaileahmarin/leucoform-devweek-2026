# Release procedure

This is a verification and approval checklist. It does not authorize a push, tag, upload, package-index
publication, or hosted release. The CI workflow deliberately stops after inspecting and exercising locally
built artifacts.

## Unresolved public-release gates

Every item in this table is a blocker. Do not replace an unresolved value with a guess merely to make a
build pass.

| Decision or evidence | Current state | Required resolution |
| --- | --- | --- |
| Public product, distribution, import, and command names | **UNRESOLVED** | Complete the review required by `docs/NAMING.md` and record the approved names in `docs/DECISIONS.md`. |
| Public source, documentation, issue, and changelog URLs | **UNRESOLVED** | Select the actual public locations before adding package metadata or rewriting README links. |
| Private security-reporting contact and supported-version policy | **UNRESOLVED** | Establish a monitored private channel and publish an accurate support policy before public distribution. |
| Minimum supported Git version | **UNRESOLVED** | Test the oldest intended Git release against every required worktree and porcelain operation, then document that version. |
| Source-distribution disclosure | **UNRESOLVED** | Approve or change the intentional inclusion of project prompts/plans, provenance documentation, tests, scripts, examples, and CI configuration described below. |
| Cross-platform release evidence | **UNRESOLVED** | Obtain and retain successful CI results for every claimed OS/Python matrix cell; workflow configuration alone is not evidence. |

## Approval gates

A release may advance only in this order:

1. **Public-boundary approval:** all unresolved gates above have recorded human decisions.
2. **Source approval:** the exact commit and complete review diff have been approved.
3. **Artifact approval:** the wheel and source distribution built from that commit have passed every local
   and CI check below, and their hashes have been recorded.
4. **Publication approval:** an authorized human has explicitly approved the exact version, commit, tag,
   package index, source host, release destination, and artifact hashes.

Failure or ambiguity at any gate stops the release. A passing build never implies publication approval.

## 1. Select and inspect the candidate

Use a fresh checkout of the exact candidate commit. Do not clean a dirty checkout by deleting or resetting
files; preserve and review unexpected state.

Run:

```text
git status --short
git diff --check
python --version
git --version
```

Required results:

- `git status --short` prints nothing;
- `git diff --check` exits zero;
- Python is one of the explicitly supported versions;
- the Git version satisfies the approved minimum once that decision exists.

Record the full commit ID with:

```text
git rev-parse HEAD
```

Confirm that `pyproject.toml`, `src/notug_protocol/brand.py`, `CHANGELOG.md`, and `STATUS.md` identify the
same intended version. The changelog date must be the actual release date, not an earlier local-build date.

## 2. Run source-tree gates

From the candidate root, in a clean environment, run exactly:

```text
python -m pip install --upgrade pip ".[dev]"
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m pytest
python scripts/check_docs.py
python scripts/minimisation_lint.py
```

Every command must exit zero. Record the interpreter, Git, Ruff, mypy, pytest, build-backend, setuptools,
and wheel versions with the results. Do not copy totals or versions from an earlier candidate.

## 3. Build and verify without publishing

The distribution directory must begin absent in the fresh checkout. Do not reuse artifacts from another
commit. Run:

```text
python -m build
python scripts/verify_release.py
```

`verify_release.py` uses only the standard library. It must:

- find exactly one wheel and one source distribution for the version in `pyproject.toml`;
- reject archive traversal, absolute paths, links, special files, controls, bidirectional controls,
  surrogate names, VCS data, caches, bytecode, and non-portable Windows names;
- require the wheel's package files to match `src/notug_protocol`, validate all declared core metadata,
  dependencies, extras, URLs, entry points, licence bytes, tags, and every `RECORD` hash and size;
- require the source distribution and its `SOURCES.txt` to match the repository files selected by the
  current packaging rules, with exact source bytes;
- create one temporary virtual environment outside the source tree and remove only that temporary tree;
- strip pip redirection variables, use pip isolated mode, install the wheel with `--no-index --no-deps`,
  run `pip check`, `notug --version`, `notug --help`,
  `python -m notug_protocol --help`, and `notug demo --json`;
- prove that the installed import resolves from that virtual environment's `site-packages`, while the
  current directory is outside the source tree;
- print the actual artifact names, byte sizes, and SHA-256 hashes.

The script does not extract either archive, contact a package index, upload an artifact, create a tag, or
create a hosted release.

## 4. Decide the source-distribution disclosure

The present packaging rules intentionally put more than runtime code in the source distribution. Before
public release, inspect and explicitly approve every category:

- `AGENTS.md`, `PLAN.md`, `PROMPT.md`, `STATUS.md`, and the changelog;
- architecture, protocol, security, privacy, threat-model, naming, decision, demo, and reference-provenance
  documentation under `docs/`;
- examples, verification scripts, the full test suite, and CI workflow;
- Python source and generated package metadata (`PKG-INFO`, `setup.cfg`, and `.egg-info` metadata).

Confirm that these files contain no secret, credential, account name, private absolute path, proprietary
material, or unsupported claim. Record either an approval of this disclosure or a reviewed packaging
change. This decision is currently unresolved.

## 5. Collect cross-platform evidence

The required CI matrix is the matrix declared in `.github/workflows/ci.yml`: Windows, Linux, and macOS on
Python 3.11, 3.12, 3.13, and 3.14. For the exact candidate commit:

- require all matrix jobs to pass the source-tree, documentation, minimisation, build, archive, clean
  installation, CLI, import-location, and demo gates;
- record the CI run location, commit ID, runner images, Python versions, and Git versions;
- investigate a skipped, cancelled, or allowed-to-fail cell as missing evidence, not a pass;
- compare CI artifact names and hashes only when they came from the same controlled build procedure;
- do not claim an operating system or Python version from workflow YAML alone.

The workflow does not upload artifacts. Preserve evidence through the approved release-record mechanism
once its public location has been decided.

## 6. Human artifact and documentation review

Before requesting publication approval, check every box:

- [ ] The working name and all public names have written approval.
- [ ] Real project URLs have been chosen and verified; no placeholder URL is present.
- [ ] A monitored private security contact and supported-version policy exist.
- [ ] The minimum Git version is measured and documented.
- [ ] README installation, usage, limitations, troubleshooting, platform, and uninstall text matches the
      candidate artifacts.
- [ ] The licence and all runtime, build, and development dependency licences have been reviewed.
- [ ] The wheel and source-distribution contents and disclosure categories are approved.
- [ ] The complete CI matrix is green for the exact candidate commit.
- [ ] The verifier's artifact names, sizes, and SHA-256 hashes are retained in the release record.
- [ ] The release diff and commit plan are reviewable and contain no unrelated changes.
- [ ] No artifact has been pushed, tagged, uploaded, or published during verification.

## 7. Publication authorization record

An authorized human must record all of the following before any publication command is run:

- approved version;
- exact commit ID;
- exact tag name;
- public source-host destination;
- package-index destination and project name;
- hosted-release destination;
- wheel filename and SHA-256;
- source-distribution filename and SHA-256;
- approver identity and approval time;
- rollback, yanking, and security-contact owners.

These values are intentionally not prefilled. Until the record is complete and explicit approval is given,
do not run `git tag`, `git push`, an upload client, a package publisher, or a hosted-release command.

After approval, use only the exact destinations and commands separately reviewed for that authorization.
If the published package differs from the approved hashes or a post-publication installation check fails,
stop, preserve the evidence, and follow the approved yanking or incident procedure; do not silently rebuild
under the same version.
