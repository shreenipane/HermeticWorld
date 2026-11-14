# Phase 4 preparation

## Web archive and search review 2026-11-15

Reviewed the three branch commits (`git diff main...phase4-prep` and
`git log main..phase4-prep`), the archive/search implementation and tests,
surrounding package/snapshot and descriptor-based I/O changes, architecture
sections 4 and 6.5, TRD.md and PHASES.md. `.review/` is absent. Existing
uncommitted inventory repairs and their regression tests were preserved.

- Fixed (major): replay selected and accepted captures exactly at the world
  cutoff. The current brief requires captures strictly before it, superseding
  the older inclusive replay contract in architecture section 6.5. Both the
  builder and authenticated reader now enforce that boundary in nanoseconds,
  including timestamp aliases. File loading rejects such an index before
  opening payload files. All five cases in
  `test_phase4_archive_cutoff_review.py` failed before the repair. The existing
  replay fixture's default capture moved one nanosecond before its cutoff and
  an exact-cutoff candidate was added to its excluded inventory. This necessary
  fixture correction preserves every existing assertion.
- OPEN (major): `hermetic_archive` consumes hand-authored recipe records and
  payload mappings; no Common Crawl/Wayback capture import or Stack Exchange
  post-history reconstruction is implemented. A source label and record digest
  alone do not establish capture dates or historical revisions. Completing this
  requires the acquisition/provenance contract and its integration with the D10
  payload-fingerprint and thread/revision checks in the sealing component;
  those checks are outside this preparation change set. No source acquisition
  or reconstruction completion is claimed.
- OPEN (major): `search.py` emits a JSON term inventory and URL-ordered
  conjunctive candidates, with no tantivy BM25 preparation or ranking engine.
  Tantivy is absent from the dependency manifests. Adding the required engine
  conflicts with this review's no-new-dependencies constraint, and substituting
  another engine would cut scope. The monthly BM25 deliverable remains open.

The preserved inventory repairs were independently verified against the committed
branch code, loaded in memory with read-only `git show` (no file or git state
replacement). Together with the new cutoff regressions, all 12 cases failed on
that code and pass on the working tree. These cover count-cap bypass between
validation and copying for archive payloads, mirror blobs and Go info records;
unverified mirror entries returned after inventory growth; and missing snapshot
artifacts or unchecked unknown-role `KeyError` after inventory mutation. The
existing seven tests and repairs were retained without modification.

Archived pages remain private local bytes. This review enables no publication,
redistribution or WorldServer routing. No dependencies or git state changed.

### Web/archive review validation

`cargo fmt --all` and `git diff --check` exited 0. The focused replay/search/
identity/count suite passed 169 tests, exit 0. The first targeted `py-gate` run
containing only the new cutoff regressions ended `5 failed in 0.03s`, exit 1;
the focused post-fix `py-gate` ended `169 passed in 0.18s`, exit 0. The independent
committed-code comparison ended `12 failed in 0.07s`, exit 1, and its working-tree
counterpart ended `12 passed in 0.07s`, exit 0.

The full Rust gate ran from the worktree root and exited 101. Formatting/clippy
and preceding tests passed; four VMM fixtures failed at
`Validation("unsafe ancestor ownership")`. `/proc/self/uid_map` is `1000 0 1`,
and both `/` and `/home` are represented as owned by UID 65534. The ownership
policy correctly refuses them. Repair requires host namespace configuration
outside the worktree, so this prerequisite remains OPEN. No existing test or
ownership check was weakened. Final Rust lines:

```text
test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s

error: test failed, to rerun pass `-p hermetic-vmm --lib`
```

The full Python gate ran after the Rust gate completed and exited 0. Final lines:

```text
-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
2304 passed, 1 skipped, 12 warnings in 237.31s (0:03:57)
```

Both full gates ran in the foreground and were awaited. Logs:
`.phase4-archive-rust-gate-1.log` and `.phase4-archive-py-gate-1.log`.
Verdict remains OPEN for the missing acquisition/history and tantivy deliverables
and the host UID mapping. No full Rust gate success or complete Phase 4 seal is
claimed.

## Branch review 2026-11-15

Reviewed `git diff main...phase4-prep` and `git log main..phase4-prep`:
`ce2c08a`, `dbe40d3` and `3651120`, with 45 changed files. `.review/` is
absent. Read the added preparation boundaries, their tests, the gateway deadline
change, repository sealing requirements and the NetVM HTTP transport/policy.

- Fixed a snapshot inventory check/use race in `verify_snapshot_artifacts`.
  It validated the caller's mapping before collecting a fresh view of that
  mapping. Removing `memory` between those operations returned a verified
  three-artifact bundle; adding an unknown role raised unchecked `KeyError`.
  Retain a private inventory before validating its keys and collecting payloads.
  Both cases of `test_snapshot_inventory_is_retained_before_validation` failed
  before the fix and pass afterward; the targeted snapshot/error suite passes
  120 tests. No existing tests or dependencies changed.
- OPEN (major scope gap): none of these commits implements the requested smart
  Git deliverable. `hermetic-netvm-http::policy::decide` accepts GET/HEAD only;
  an upload-pack POST is rejected. There is no upload-pack v2 shallow/deepen
  implementation, pkt-line parser or corresponding hostile-input tests in the
  branch. No cutoff-bound reachable-object repository service is connected to
  such a handler. Repair requires the NetVM transport and repository-serving
  components outside this preparation change set, so it remains open under the
  review instruction to leave work in another component open. The deliverable
  stays unchecked in PHASES.md; no completed shallow-clone support is claimed.

`cargo fmt --all` passed (exit 0). The full Rust gate passed formatting/clippy
but exited 101 at four VMM fixtures: `publication_is_atomic_no_replace_and_enforces_remaining_copy_budget`,
`launcher_exit_keeps_surviving_vm_child_alive_until_stop_or_drop`,
`output_capture_is_capped_and_silent_child_is_killed_on_drop` and
`real_process_clears_environment_closes_descriptors_and_owns_group`. Each reports
`Validation("unsafe ancestor ownership")`. `/proc/self/uid_map` is `1000 0 1`;
`/` and `/home` appear owned by UID 65534, which the VMM ancestor check correctly
refuses. Changing the host mapping is outside this worktree; this gate blocker
remains open, with no ownership check or test weakened. Exact final Rust lines:

```text
test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s

error: test failed, to rerun pass `-p hermetic-vmm --lib`
```

The full Python gate ran after the Rust gate and exited 0. Its final lines:

```text
-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
2294 passed, 1 skipped, 12 warnings in 183.73s (0:03:03)
```

`git diff --check` passed. No git state mutation commands were run. Current logs:
`.phase4-current-review-rust-gate.log` and `.phase4-current-review-py-gate.log`.

Plan: review the branch and required specifications; implement the first offline
ecosystem filters that need neither an owner decision nor a VM; add hostile-input,
cutoff-boundary and deterministic-output tests; format and run both complete gates.

- Review baseline: `git diff main...phase4-prep` and `git log main..phase4-prep`
  are empty. `.review/` is absent. No pre-existing branch defects to repair.
- Implement crates.io sparse-index filtering by `pubtime`, and Go proxy version
  filtering by the corresponding `.info` `Time`. Unknown dates must be excluded
  and reported. Emit only admitted versions and deterministic bytes, with named
  caps, strict parsers and no network or filesystem access in the filter library.
- Reuse the existing npm cutoff filter; review its public input boundary and fix
  verified defects with regression tests.
- Owner/dependency work: tantivy is absent and new dependencies are forbidden;
  do not substitute another search engine. Archived-page redistribution remains
  an owner decision. Provider selection and pins, TEE platform and aarch64
  hardware need owner input. Preserve all unfinished work in PHASES.md.
- Deferred integration: source acquisition/provenance, archive replay and search,
  frozen artifact publication and resolver installs, smart git in NetVM, state-task
  snapshot grading and split Mode G. These remain Phase 4 deliverables; offline
  metadata filters alone do not establish an operational sealed ecosystem.

Validation results and exact delivered interfaces are recorded below after work.

Later continuation sections supersede the initial deferred-item list only where
they explicitly deliver an offline component. End-to-end deliverables stay open.

## Offline continuation

- [x] Review the existing uncommitted preparation as well as the requested empty
  branch diff/log. `.review/` remains absent. Preserve existing work and tests.
- [x] Add file-level PyPI upload-time admission for both dated JSON sources and
  render consistent simple JSON/HTML pages from admitted files only.
- [x] Fix verified preparation defects with regressions: malformed nested Cargo
  fields, noncanonical Go build aliases and missing output-cap enforcement,
  direct npm NUL keys, and partial npm publication on an unsafe report path.
- [x] Test exact boundaries, malformed/excluded records, unknown dates, stable
  ordering, known answers, output/resource caps and directory substitution.
- [x] Integrate these staging filters into deterministic offline frozen
  publication, including digest verification and denial of excluded direct
  artifact requests (see Offline mirror build below).
- [ ] Integrate live acquisition and cutoff-aware recording/resolver builds.
  The existing yank-only transformer retains undated files by its original
  contract; it must not substitute for upload-time admission.

## Delivered interfaces

`hermetic_ecosystem_cut.cut_crates_index(raw, cutoff)` accepts one crate's HTTP
sparse-index JSON lines and returns `(filtered_bytes, CutReport)`. It preserves
immutable Cargo record fields, refuses unknown fields, rejects duplicate versions
including build-metadata aliases, and excludes missing publication times. All
admitted versions have `yanked=false` and appear in `yank_unknown`: without yank
history the TR-PKG-2 rule serves them as not yanked and lists the uncertainty.

`hermetic_ecosystem_cut.cut_go_versions(raw_list, infos, cutoff)` accepts one
module's `@v/list` bytes and a version-to-`.info`-bytes mapping. It returns
`(filtered_list, admitted_infos, CutReport)`. Missing `.info` or `Time` is unknown
and excluded. Returned `.info` objects contain only `Version` and `Time`; current
proxy `Origin` metadata is removed. Output ordering is lexical and independent of
input ordering. Consumers, rather than list order, select a version by SemVer.

Both filters have a 16 MiB aggregate input cap, 256 KiB record cap, 20,000-record
cap, strict JSON parsing with a 24-level depth cap, and nanosecond UTC comparisons
without host clock, locale, network or file access. These are staging functions,
not a running mirror: the publisher must use only admitted versions for direct
artifact paths and Go `@latest`. Resolver installation and E4 remain unchecked.

Schema references: [Cargo index format](https://doc.rust-lang.org/cargo/reference/registry-index.html)
defines publication time as stable and the yank flag as mutable;
[Go proxy protocol](https://go.dev/ref/mod#goproxy-protocol) defines the version
list and `.info` responses. Tests use local synthetic records only.

The npm filter now bounds its direct object input before sorting or deep copying,
rejects cycles and non-JSON values with typed errors, rejects numeric overflow to
infinity, validates configuration before file access, refuses publication aliases,
and sanitizes a version-manifest error. Existing tests are unchanged.

`hermetic_ecosystem_cut.cut_pypi_simple(raw, cutoff)` accepts PEP 691/700 project
JSON. `cut_pypi_json(raw, cutoff)` accepts the PyPI project JSON API's `releases`
inventory. Both return `(PyPIIndex, CutReport)`; the index contains `simple_json`
and `simple_html` bytes. Report entries identify filenames, since wheels and
sdists from a single release may have different upload times. Admission uses
`upload-time` or `upload_time_iso_8601`, respectively, at or before the cutoff;
missing/null dates are excluded and reported. Invalid dates abort the transform.
There is no fallback to the naive `upload_time`, a filename or host mtime. HTML
has no standard upload-time evidence: render it from one of the dated JSON sources
rather than treating an upstream HTML page as a dated inventory.

The supported artifacts are wheels and sdists. Project names, filenames, PEP 440
versions, SHA-256 digests, sizes and timestamps are validated, including excluded
records. PEP 700 dates use UTC `Z` and at most six fractional digits; comparisons
retain the cutoff's nanosecond precision. Versions come only from admitted files,
with no current version-list or metadata passthrough. Current descriptions,
serials, statuses, vulnerabilities, provenance and yank reasons are removed.
Without yank history, current yank flags are reset and listed per TR-PKG-2.
Artifact links become `/files/<sha256>/<filename>`; acquisition must verify and
publish those admitted artifacts before serving these pages. Existing mirror
and recording-index integration remains open.

Named PyPI caps: 16 MiB project input, 256 KiB file records, 20,000 files/releases,
16 MiB combined JSON/HTML output, 128-byte names/versions, 255-byte filenames,
4 KiB requires-python fields and 1 TiB declared artifact size. Parsing also uses
the shared 24-level JSON depth/token limits. PEP 440 validation reuses the existing
bounded scanner parser; no dependency is added. Pages and reports sort filenames
lexically and tests assert exact bytes and independence from source ordering and
host environment. These functions perform no file or network operations.

References: [simple repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)
and [PyPI project JSON API](https://docs.pypi.org/api/json/).

The review also validates nested Cargo dependencies/features and optional field
types before preserving them. Go accepts canonical versions only (the sole
permitted build suffix is `+incompatible`) and enforces an aggregate output cap.
Npm rejects direct-input NUL keys consistently with its byte parser. Publication
preflights every destination and refuses hardlink/name aliases before writing;
both writes retain inspected parent descriptors, including across directory
renames. Each file is independently atomic and 0600; this does not promise a
two-file transaction under a later I/O failure.

## Open defect requiring provenance

Non-latest npm dist-tags are mutable. The existing contract retains tags that
point to admitted versions but supplies no history for when each tag was created
or retargeted. Verified reproduction: a packument with only a 2020 release and
`dist-tags={"added-after-cutoff-2026":"1.0.0"}` retains that tag at a 2020 cutoff.
Recovering the correct historical tags needs the registry acquisition component's
timestamped captures/history. Removing all such tags would change the existing
preserved-tag contract; that policy change needs the owner. This branch does not
claim npm provenance is solved. The defect is also recorded in PHASES.md.
The new offline publisher refuses retained non-latest tags with a fixed error;
the existing filter's preserved-tag behavior is unchanged. Its regression is
`test_mirror_npm_mutable_tag_refused_until_history_is_available`.

## Offline mirror build

The next offline continuation is implemented in
`python/hermetic_ecosystem_cut/mirror.py`, without new dependencies. The requested
three-dot branch diff and log remain empty; existing uncommitted preparation was
reviewed and preserved. `build_mirror(recipe_bytes, blobs)` returns sorted store
files, a hash manifest and operator reports. `build_mirror_files(recipe_path,
blob_root, output_path)` reads digest-named regular files through the existing
descriptor-pinned bounded I/O and publishes a completed directory by rename.
The command-line interface is:

```sh
PYTHONPATH=python python3 -m hermetic_ecosystem_cut recipe.json blobs private/world
```

The parent `private` must already exist, be caller-owned and mode 0700; `world`
must be absent. Input paths cannot contain symlinks, including ancestors, FIFOs
or devices. All metadata, references and blob digests are validated before
creating a staging directory. Publication holds parent/directory descriptors,
uses 0600 atomic file writes, syncs files/directories and renames the complete
tree. As with WorldServer publication, host root and the caller's own uid are
trusted; no concurrent writer may mutate that private parent. A VM root does
not have access to it. Existing outputs are refused. A pre-rename failure leaves
no published world; a post-rename sync failure can leave a complete world and
returns an error. Never serve staging directories.

Recipe JSON has exactly `cutoff` and `packages`. Each package has `ecosystem`,
`name`, `metadata` (a lowercase SHA-256 blob identifier), and `artifacts` (keys
below mapped to SHA-256 identifiers). Go also requires `infos`, mapping each
version to its raw `.info` blob digest. The accepted ecosystem values and keys:

| Ecosystem | Metadata | Artifact keys |
| --- | --- | --- |
| `crates` | One sparse-index JSON-lines response | Unescaped version |
| `go` | Raw `@v/list` | Unescaped `<version>.mod` and `<version>.zip` |
| `npm` | Packument JSON | Version |
| `pypi-simple` | Dated simple JSON | Filename |
| `pypi-json` | Project JSON API | Filename |

For example, a recipe can contain `{"cutoff":"2023-04-01T00:00:00Z",
"packages":[{"ecosystem":"crates","name":"demo","metadata":"<64 hex>",
"artifacts":{"1.0.0":"<64 hex>"}}]}` with the indicated files in `blobs/`.
All referenced blobs, including any supplied excluded downloads, are verified
against their SHA-256. Missing admitted downloads abort; excluded downloads are
optional and never published. Unrecognized artifact associations and extra blobs
in the in-memory API are refused; the file API opens only referenced blob names.
Crates and PyPI additionally enforce upstream SHA-256; PyPI enforces declared
size. Npm checks supplied SHA-256/SHA-512 integrity and/or SHA-1 shasum against
the bytes, then replaces download URLs and digest fields with local verified
values. Go `.mod`/`.zip` hashes come from the acquisition recipe; this verifies
byte integrity and does not establish Go h1/sumdb or historical provenance.

Serve **only `world/store`** with WorldServer. It contains the fixed authorities
`index.crates.io`, `static.crates.io`, `proxy.golang.org`, `registry.npmjs.org` and
`pypi.org`, as needed. Cargo gets a local download-template config and sparse
index paths. Npm gets packument and admitted per-version endpoints plus rewritten
tarball links, including scoped packages. PyPI gets consistent simple HTML/JSON
pages, a project listing, and digest-addressed files. Go module and version paths
use case escaping; `.info`, `.mod` and `.zip` exist only for admitted versions.
Its list excludes pseudo-versions, and `@latest` prefers admitted releases, then
tagged prereleases, then the newest admitted pseudo-version by `.info` Time with
a lexical tie-break. This last fallback is a frozen-inventory policy; acquiring
the historical default-branch tip remains source-provenance work. Protocol:
[Go proxy protocol](https://go.dev/ref/mod#goproxy-protocol).

`world/manifest.json` hashes every served file/sidecar and `reports.json`, records
input digests and a canonical recipe digest, and contains no filesystem paths,
identity, host clock or environment values. The returned/printed root identifier
is SHA-256 of the exact manifest bytes. Reports include excluded/unknown versions
and yank uncertainty; they remain outside the served root. Bytes and root hashes
are independent of recipe package/key order and the host environment. An artifact
basename too long for an appended sidecar uses DirStore's existing content-type
fallback, preserving valid 255-byte PyPI filenames.

Named builder caps: 4 MiB recipe, 256 packages, 8,192 blobs, 64 MiB per blob,
256 MiB aggregate input, 512 MiB aggregate output, 32,768 store files, 512 store
directories (bounding retained descriptors), 16 MiB combined manifest/reports,
1,024-byte routes, 32 route components, 255-byte components, 128-byte package
names and 128 staging attempts. The existing filter/parser caps also apply.

Verification includes hostile recipes, malformed/unsafe paths, digest and size
mismatches, absent downloads, all named caps, exact known answers, input ordering,
environment independence, private modes, interrupted publication, parent directory
substitution, maximum-length filenames and refusal to overwrite an existing world.
The Rust `offline_mirror_is_served_by_dirstore_and_excluded_routes_miss` test builds
a real offline store and reads it with the production `DirStore`, asserting all
four download types, metadata and direct excluded-version misses.

Review regressions observed failing before fixes:
`test_mirror_manifest_binds_uncertainty_reports`,
`test_mirror_go_version_paths_escape_uppercase`,
`test_mirror_go_list_excludes_pseudo_versions_and_latest_prefers_tag`, and
`test_mirror_maximum_pypi_filename_can_be_published`. Filesystem-error regressions
`test_mirror_directory_inspection_failure_closes_descriptor` and
`test_mirror_root_inspection_failure_removes_stage` also failed before repair:
failed directory inspection must close the new handle and remove an empty stage.
The new empty-store
known-answer test was extended to include the required report digest. No test
present at the start of this continuation was edited, weakened or deleted.

Remaining scope: acquisition and dated immutable-manifest provenance, npm tag
history, cutoff-aware recording/resolver builds (including build dependencies),
real Cargo/Go install fixtures, Go sumdb/h1 provenance, E4, and monthly
baseline sizing. The offline store does not remove any of these deliverables.

## Input identity review and npm install continuation

The requested `git diff main...phase4-prep` and `git log main..phase4-prep`
remain empty. Review therefore also covered the existing uncommitted filters,
publisher, tests and surrounding production DirStore code. `.review/` is absent.
The instruction to leave git state unchanged takes precedence over committing.

An additional major defect was reproduced: npm publication inspected the source
under a retained parent descriptor but then read it by the original path. Moving
that parent and creating a replacement, or replacing the source inode after
preflight, silently published the substituted packument. The input read now uses
the retained parent and verifies the preflight inode before opening it. Directory
renames preserve the original input; inode substitutions abort before either
output is written. Both cases in
`test_npm_input_identity_survives_preflight_path_substitution` failed before the
repair and now pass. The shared regular-file opener retains lstat-before-open,
O_PATH inode pinning, symlink/device/FIFO refusal and bounded reads. No existing
test was edited, weakened or deleted.

A second major defect exposed package existence after the cutoff: a package
with no admitted releases still received successful empty metadata responses.
For example, using a 2000 cutoff with only 2023/2024 releases produced Cargo,
Go, npm and PyPI package routes. The publisher now requires an admitted release
before serving those routes, their sidecars, or a Cargo configuration for an
otherwise empty Cargo store. Unknown-date and empty inventories also remain
absent. Operator reports and all input/digest/artifact-association validation
are retained. Twelve cases in
`test_mirror_unadmitted_package_has_no_served_metadata` failed before repair;
four companion cases assert that invalid artifact associations are still
refused when the admitted inventory is empty.

The next offline resolver fixture is
`test_frozen_npm_transitive_install_excludes_future_and_unknown_releases`.
It creates deterministic real npm tarballs and passes the unmodified builder
output bytes to an in-memory loopback registry. A real npm client, starting with
an empty cache, installs a scoped package and its transitive dependency. Both
resolve to the cutoff release although the acquisition inventory also contains
future and undated releases. Installed versions, lockfile integrity and actual
metadata/tarball requests are checked. Failing lifecycle scripts prove that
`--ignore-scripts` is effective. This complements the existing production
DirStore integration; it does not claim an end-to-end NetVM or recording build.

The client receives an explicit environment and empty user/global configuration;
its cache and home live within the test directory. A Node socket guard refuses
every destination except the local test listener, with denial checks for both
an external DNS name and an IP literal. The listener emits no host clock or
server identity headers. Named fixture caps bound installation time (30 seconds),
requests (64), request paths (1,024 bytes), socket waits (2 seconds), thread join
(5 seconds) and compressed fixture artifacts (256 KiB). Local npm and Node are
required for this fixture; absence skips only this new integration test. It
passed here with npm 9.2.0 and Node v22.22.1; no dependency was added.

Acquisition/provenance, historical npm tags, cutoff-aware build dependencies,
Cargo/Go install fixtures, sumdb/h1, E4 and monthly baseline sizing remain open.
The npm filter's preserved-tag contract still needs history from acquisition or
an owner policy decision; the offline publisher continues to refuse those tags.

## Maven research

The [Apache metadata schema](https://maven.apache.org/ref/3.9.9/maven-repository-metadata/repository-metadata.html)
lists release versions but gives only an aggregate metadata update time; snapshot
entries describe the current snapshot, not a full history. Therefore a release
list plus `lastUpdated` cannot establish publication time for every artifact.
The [Central search guide](https://central.sonatype.org/search/rest-api-guide/)
offers coordinate/version queries, but does not establish historical provenance
for arbitrary repositories. Before supporting Maven, acquire dated, digest-bound
artifact records or a repository snapshot, including POMs, parent POMs, plugins,
classifiers and transitive dependencies. Regenerate version metadata from admitted
artifacts, and never use local mtime, a POM build time or current search ranking as
publication evidence. This is a research conclusion; Maven support remains open.

## Validation

- `cargo fmt --all`: exit 0. `git diff --check`: exit 0.
- Targeted Python suite: 85 passed. The original nine hostile-input regressions,
  both configuration/publication regressions, and the error-secret regression
  were observed failing before their respective fixes. Existing tests were not
  edited, weakened or deleted; no dependency or git-state changes were made.
- `rust-gate`, run 1: exit 101 after successful formatting/clippy and earlier
  workspace tests. The VMM library result was `5 passed; 4 failed` because the
  sandbox reports root-owned filesystem ancestors as UID 65534. Four real
  filesystem/process fixtures fail with `Validation("unsafe ancestor ownership")`.
  `/proc/self/uid_map` is `1000 0 1` and `/` is owned by 65534 as seen here. The
  production check in `crates/hermetic-vmm/src/fs.rs` correctly refuses this;
  relaxing it or skipping the fixtures would weaken the boundary. A passing full
  Rust gate needs execution with normal host UID mappings outside this sandbox.
- `py-gate`, run 1 (after rust-gate): exit 0,
  `1768 passed, 12 warnings in 165.65s (0:02:45)`. Warnings are existing pytest
  configuration deprecations in the assertion recorder.
- Gate output is in `.phase4-rust-gate-1.log` and `.phase4-py-gate-1.log`.
  Both commands ran in the foreground from the worktree root and were awaited.
  The review remains OPEN for npm historical tags and the Rust gate environment.

### Continuation validation

- Targeted offline suite: 171 passed. The initial 17 preparation-regression cases
  all failed before the fixes (`.phase4-review-gate-before.log`); they now pass.
  Additional cases cover descriptor-retained publication after directory swaps,
  hardlink aliases, supported Cargo dependencies and canonical Go versions.
  The PyPI suite covers both dated sources, exact JSON/HTML known answers,
  same-release file boundaries, sub-microsecond cutoff precision, missing dates,
  yank uncertainty, malformed/excluded records, HTML attribute injection, caps,
  legacy sdist names and stable ordering/environment independence.
- Existing test files were not changed, weakened or deleted. No dependencies or
  git-state changes were made.
- `cargo fmt --all`: exit 0. `git diff --check`: exit 0.
- `rust-gate`, run 2: exit 101 after formatting/clippy and earlier workspace tests.
  The same four VMM fixtures fail with `unsafe ancestor ownership`; final result:
  `FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out`.
  Last line: `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
  The UID mapping and production ownership check are unchanged. This needs host
  configuration outside the branch and cannot be repaired by weakening fixtures.
- `py-gate`, run 2 (after Rust exited): exit 0. Last line:
  `1854 passed, 12 warnings in 164.01s (0:02:44)`. Warnings are the existing
  assertion-recorder configuration deprecations. Both gates ran in the foreground
  from the worktree root and were awaited. Logs: `.phase4-rust-gate-2.log` and
  `.phase4-py-gate-2.log`. The review remains OPEN for npm historical tags and
  the Rust gate environment; no full-gate success is claimed.

### Offline mirror continuation validation

- Requested branch diff/log are empty; the existing uncommitted preparation and
  tests were reviewed and preserved. No dependency or git-state changes were made.
- Builder/publication suite: 66 passed. Six new regression tests were observed
  failing before their respective repairs. No test present at the start of this
  continuation was changed, weakened or deleted.
- Production-store integration:
  `cargo test -p hermetic-world-server --test test_offline_mirror`: exit 0,
  `1 passed; 0 failed`. This reads built artifacts and metadata through `DirStore`
  and asserts excluded direct-version routes miss. It was run separately because
  the workspace gate stops at the earlier VMM failures.
- `cargo fmt --all`: exit 0. `git diff --check`: exit 0.
- `rust-gate`, run 3: exit 101. Formatting/clippy passed; the same four VMM
  fixtures fail with `Validation("unsafe ancestor ownership")`. Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
- `py-gate`, run 3 (after Rust exited): exit 0. Last line:
  `1918 passed, 12 warnings in 181.60s (0:03:01)`.
  Both gates ran in the foreground from the worktree root and were awaited.
  Logs: `.phase4-rust-gate-3.log`, `.phase4-py-gate-3.log`.
- The directory-inspection cleanup repairs were then added with failing
  regressions; both gates are rerun below on the final implementation.
- `rust-gate`, run 4 (final implementation): exit 101 after successful
  formatting/clippy and earlier workspace tests. The same four VMM fixtures
  reject the sandbox's unmapped ancestor ownership. Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
  Production ownership checks and existing tests were preserved.
- The production-store integration test was rerun on the final implementation:
  exit 0, `1 passed; 0 failed`.
- `py-gate`, run 4 (after Rust exited, final implementation): exit 0. Last line:
  `1920 passed, 12 warnings in 193.08s (0:03:13)`.
  Both gates ran in the foreground from the worktree root and were awaited.
  Logs: `.phase4-rust-gate-4.log`, `.phase4-py-gate-4.log`. Warnings remain the
  existing assertion-recorder configuration deprecations. No full-gate success
  is claimed: npm historical tags and host UID mapping remain OPEN.

### Input identity, package existence and npm install validation

- Source-identity regressions before repair: `2 failed in 0.03s`, exit 1.
  Related npm/filter/publication suite after repair: `117 passed in 1.43s`,
  exit 0. Standalone real npm install fixture: `1 passed in 1.19s`, exit 0.
- `cargo fmt --all` and `git diff --check`: exit 0.
- Full `rust-gate`, run 5: exit 101 after formatting/clippy passed. Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
- Full `py-gate`, run 5, after Rust exited: exit 0. Last line:
  `1923 passed, 12 warnings in 204.82s (0:03:24)`.
  This run preceded the package-existence repair.
- Package-existence regressions before repair: `12 failed, 4 passed in 0.08s`,
  exit 1. Combined publication, input-identity, package-existence and real npm
  install suite after repair: `85 passed in 2.25s`, exit 0.
- Full `rust-gate`, run 6, on the final code: exit 101 after formatting/clippy
  passed. The same four VMM fixtures fail at the ancestor ownership check.
  Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
- Full `py-gate`, run 6, after Rust exited, on the final code: exit 0. Last line:
  `1939 passed, 12 warnings in 225.06s (0:03:45)`.
  Warnings remain the existing assertion-recorder configuration deprecations.
- Both full gate pairs ran in the foreground from the worktree root and were
  awaited. Logs: `.phase4-rust-gate-5.log`, `.phase4-py-gate-5.log`,
  `.phase4-rust-gate-6.log`, `.phase4-py-gate-6.log`. The first targeted test run
  used pytest's default temporary directory; later test runs used scratch
  directories inside this worktree.
- The root UID mapping was independently checked: `/proc/self/uid_map` is
  `1000 0 1`, and `/` and `/home` appear owned by UID 65534. Changing that host
  configuration is outside this branch. Production ownership validation and all
  existing tests are preserved. No dependencies or git-state changes were made.
  Historical npm tags still require acquisition history or an owner policy
  decision. Verdict remains OPEN; no passing full Rust gate is claimed.

## Offline client configurations, replay and search continuation

Review again confirmed that `git diff main...phase4-prep` and
`git log main..phase4-prep` are empty, with both refs at the same commit.
The uncommitted preparation, its tests, production DirStore, shared safe I/O,
TRD package/WorldServer requirements and architecture §6.5 were also reviewed.
`.review/` is absent. No git state operation was performed; the explicit
prohibition on commits takes precedence over the earlier request to commit.

### Client configuration bundle

`hermetic_ecosystem_cut.install.build_install_configs()` returns four immutable
rootfs-relative files plus a `hermetic-install-configs/v1` manifest containing
each path, byte size and SHA-256. `verify_install_configs(manifest, files)`
validates the whole bundle against this versioned policy before a rootfs writer
uses it. Self-asserted replacement hashes, extra destinations, traversal names,
missing files, non-byte bodies and oversized bundles fail closed. There is no
filesystem access or environment lookup in either function.

The destination files and loader configuration are:

| Rootfs file | Client loader |
| --- | --- |
| `/etc/hermetic/pip.conf` | `PIP_CONFIG_FILE=/etc/hermetic/pip.conf` |
| `/etc/hermetic/npmrc` | npm `--userconfig=/etc/hermetic/npmrc --globalconfig=/dev/null` |
| `/etc/hermetic/cargo-config.toml` | Cargo `--config=/etc/hermetic/cargo-config.toml` |
| `/etc/hermetic/go.env` | `GOENV=/etc/hermetic/go.env` |

Endpoints use `https://pypi.org/simple/`, `https://registry.npmjs.org/`,
`sparse+https://index.crates.io/` and `https://proxy.golang.org`. These are
WorldServer's existing frozen-store authorities intercepted by NetVM; its
framed endpoint is not a client HTTP proxy. The CA and routing must already be
installed. No arbitrary endpoint/credential input is accepted. Npm audit,
funding/update requests and lifecycle scripts are disabled. Pip has no extra
index or find-links source and no version check. Go has no direct proxy fallback,
private-module bypass, VCS transport, sumdb lookup or automatic toolchain fetch.
Existing go.sum checks still apply; disabling sumdb is not historical provenance.

The rootfs assembler still needs to install the authenticated files with the
existing atomic safe writer, choose clean guest homes/caches and pass a clean
client environment/project configuration. These files are preparation artifacts,
not a replacement for NetVM's network boundary, and do not claim rootfs/VM
integration. Caps: 4 files, 16 KiB aggregate configuration and 4 KiB manifest.

### Archive replay interchange format and reader

`hermetic_archive.build_replay_index(recipe_bytes, blobs)` accepts a strict
`hermetic-replay-recipe/v1` JSON object with `schema`, `cutoff` and `captures`.
Each capture has exactly `url`, `captured`, `source`, `record_sha256`,
`payload_sha256`, `size`, `status`, `content_type` and `location`. `source` is
`common-crawl`, `wayback`, `software-heritage` or `stack-exchange`;
`record_sha256` identifies acquisition evidence. `blobs` maps lowercase SHA-256
identifiers to payload bytes. Every supplied capture and payload, including
excluded ones, is validated. Missing/unknown dates, duplicate URL/time pairs
(including timestamp spelling aliases), digest/size mismatches and inventory
extras abort. Acquisition evidence identifiers do not authenticate a claimed
date or replace D10 payload fingerprints/thread/revision provenance.

The result is a `ReplayBuild` with canonical `hermetic-replay-index/v1` bytes
and only the selected payloads. Selection is the latest capture strictly before the
exact nanosecond cutoff for each exact URL. Output sorts URLs and blob digests.
URLs are ASCII canonical HTTP(S) DNS URLs with lowercase scheme/authority,
an explicit `/` path, no credentials, port, fragment, backslash, raw controls or
dot components, and uppercase valid percent escapes. Acquisition must normalize
other URL spellings before this format; lookup does no fuzzy matching, DNS or
network I/O. Query strings remain part of exact identity.

`ReplayIndex(index_bytes, blobs, expected_sha256, cutoff)` authenticates and
validates the index and payloads before exposing `lookup(url, method="GET")`.
A miss returns `None`; GET returns the stored status/content type/location/body
and length; HEAD returns the same fields/length with an empty body. Redirects
return the stored location and are never followed. Only these selected fields
are replayed: raw archive headers, cookies and source-server identity are absent.
Statuses are 200–599 except 304; 204/205 require empty payloads, and the five
redirect statuses require a canonical location. The reader checks the caller's
cutoff and trusted manifest digest instead of trusting an index's own assertion.

`load_replay_files(index_path, blob_root, expected_sha256, cutoff)` validates
configuration before opening files, reads the bounded authenticated index, then
reads only referenced digest-named blobs under a retained root descriptor.
The existing regular-inode pinning refuses symlink ancestors, symlink leaves,
FIFOs and devices, and bounds reads even if a file grows. Directory substitution
cannot redirect blob reads. Errors are fixed and do not expose paths or parser
input. This is an offline reader, not yet a WorldServer Store/router integration.

Named shared caps: 8 MiB index/recipe, 4,096 records and payloads, 2,048-byte
URLs, 8 MiB per payload, 64 MiB aggregate payloads, and 128-byte content types.
The existing JSON depth/token/integer/string caps also apply. Every output is
canonical UTF-8 JSON with sorted object keys and stable record order. Tests cover
exact nanosecond admission, future package/page existence, GET/HEAD/redirects,
query/scheme distinctions, hash/cutoff tampering, timestamp aliases, unsafe files,
directory substitution, every named cap and exact empty-index known answers.

### Deterministic monthly search preparation

`build_search_index(recipe_bytes, blobs)` accepts
`hermetic-search-recipe/v1` with `schema`, `month` (`YYYY-MM`) and `documents`.
Each document has `url`, `captured`, `source`, `record_sha256`, `text_sha256`
and `title`; blobs contain digest-bound UTF-8 extracted text. Source validation,
URL/date identity, payload hashing and shared caps match replay. Text extraction
and reconstruction provenance still belong to acquisition/D10 integration.

Only the latest capture per URL **strictly before the first day of the month**
contributes anything to the index. Canonical `hermetic-search-index/v1` contains
`schema`, `month`, `tokenizer`, URL-ordered `documents` with token `length`, and
lexically ordered `terms`. A term row is `[term, [[document_id, frequency], ...]]`,
with strictly increasing zero-based document IDs. The explicit tokenizer
`ascii-alnum-lower/v1` indexes ASCII alphanumeric runs from title plus text;
it consults no locale, host config or Unicode tables. Excluded and superseded
documents do not contribute postings, lengths or vocabulary. Tests assert that
adding future documents leaves the existing index bytes unchanged.

`SearchIndex(index_bytes, expected_sha256, month)` authenticates the index,
validates all posting references/counts before indexing and checks aggregate
frequencies against document lengths. `lookup_terms(query, limit=100)` returns
URL-ordered conjunctive candidates for inspecting this format. This is an
interchange/preparation reader, not the architecture's BM25 ranking service;
tantivy and production search routing remain open. `load_search_file(...)` uses
the same bounded pinned-inode reader as replay. No pages or indexes are published
to an external service by these APIs, preserving the redistribution decision.

Additional named search caps: 512-byte title, 64-byte term, 32,768 tokens per
document, 262,144 aggregate tokens/postings, 32,768 distinct terms, 1,024 query
bytes, 32 query terms and 100 results. Tests cover malicious negative, boolean,
duplicate and out-of-range posting IDs, inconsistent frequencies/lengths,
noncanonical encodings, forged months/tokenizers, authentication, unsafe files,
invalid queries, caps and known-answer term counts/order.

### Verified fix and resolver fixtures

The shared npm byte parser dereferenced non-byte inputs and compared invalid cap
types before validation. Reproduction produced eight uncontrolled TypeError or
AttributeError failures in the initial regression run. `parse_json_bytes` now
requires exact bytes and a nonnegative integer cap no greater than the named
64 MiB packument maximum, before doing any input processing. Tests are
`test_npm_byte_parser_refuses_nonbytes_with_typed_error` and
`test_npm_byte_parser_refuses_invalid_cap_before_parsing`. No original test was
changed, weakened or deleted.

The real offline Cargo fixture installs and executes a dependency from exact
frozen sparse-index records and deterministic `.crate` bytes, transported through
Cargo's filesystem local-registry layout with `--offline`. It loads the delivered
Cargo configuration and overrides only the transport for this fixture. Lockfile
version and checksum must match the admitted artifact; a second case corrupts
the archive and requires Cargo to reject it. A Go file-proxy fixture is also
implemented with fixed `.mod`/`.zip` bytes and no direct/VCS/sumdb/toolchain
fallback. It skips here because Go is absent; no passing Go client run is claimed.

The real pip fixture installs deterministic wheels for a root and transitive
dependency from the exact frozen artifact bytes, using a private home, the
delivered pip configuration, `--isolated --no-index` and a local wheel directory.
Future and unknown-date wheels are absent. Installed metadata and imported
versions must both match the cutoff. Pip and Cargo use no network in these
fixtures. The existing npm loopback fixture and production DirStore test remain
unchanged; HTTP/NetVM Cargo/Go/pip installs, build dependencies, E4 and real
source provenance remain open.

Targeted review and continuation tests: `444 passed, 1 skipped in 3.42s`, exit 0.
The skip is the new Go fixture. Full gate results on the final code follow below.

### Final continuation gates

- `cargo fmt --all`: exit 0. `git diff --check`: exit 0.
- Full `rust-gate`, run 7: exit 101 after formatting/clippy passed. The four
  unchanged VMM fixtures again reject unmapped ancestor ownership:
  `fs::tests::publication_is_atomic_no_replace_and_enforces_remaining_copy_budget`,
  `runner::tests::launcher_exit_keeps_surviving_vm_child_alive_until_stop_or_drop`,
  `runner::tests::output_capture_is_capped_and_silent_child_is_killed_on_drop`, and
  `runner::tests::real_process_clears_environment_closes_descriptors_and_owns_group`.
  `/` and `/home` are owned by UID 65534 in this sandbox; `/proc/self/uid_map`
  remains `1000 0 1`. Production ownership checks and the tests are preserved.
  Changing host/sandbox UID mappings is outside this branch. Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
- Full `py-gate`, run 7, after Rust exited: exit 0. Last line:
  `2127 passed, 1 skipped, 12 warnings in 216.53s (0:03:36)`.
  The new Go fixture is skipped because the executable is absent; warnings are
  the existing assertion-recorder deprecations. Both gates ran in the foreground
  from the worktree root and were awaited. Logs: `.phase4-rust-gate-7.log` and
  `.phase4-py-gate-7.log`.
- The production-store test, run separately because the Rust workspace gate
  stops before the WorldServer tests: exit 0. Last result:
  `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.46s`.
  Log: `.phase4-offline-store-gate-7.log`.
- The npm tag-history gap was independently reproduced again with a 2020 release
  and a synthetic 2026 tag. The filter retains it; the offline mirror builder
  continues to refuse it. The acquisition/history or owner-policy requirement
  remains OPEN. No passing full Rust gate or complete Phase 4 seal is claimed.

No dependency, commit, staging operation or original test change was made.

## Publication authentication review continuation

The requested three-dot diff and branch log are still empty. Review included
the existing uncommitted Phase 4 interfaces and tests, shared safe I/O, production
DirStore, TR-PKG requirements and architecture §§6.4–6.5 and 13.1. `.review/`
and applicable `AGENTS.md` files are absent. All original tests are preserved;
no dependency or git-state operation is added.

Verified minor defect: `build_mirror_files` reopened the blob-root path for each
digest. Renaming that root after the first read and substituting an empty
directory or symlink caused subsequent reads to leave the original acquisition
directory and abort. Digest checks prevented substituted artifact content from
being admitted, but the read set did not retain its root identity. The builder
now opens that directory once with inspected, symlink-refusing safe I/O and
reads all digest names relative to its retained descriptor. Both cases of
`test_mirror_blob_root_is_pinned_for_entire_acquisition` failed before repair
and now return the original known bundle after substitution.

The next offline publication interface is
`hermetic_ecosystem_cut.mirror.verify_mirror(raw_manifest, files, reports,
expected_sha256, cutoff)`. It authenticates the exact canonical
`hermetic-offline-mirror/v1` manifest against a digest obtained from the trusted
world description, checks its cutoff, and verifies each served file and the
operator reports by size and SHA-256. It validates the strict schema, sorted
unique input/file inventories, regular-file path layout and sidecar names,
parent/file conflicts, and all existing manifest, input-count, output-byte,
file-count and directory-count caps. It returns an immutable `MirrorBuild` and
performs no file, network, host-clock, identity or environment operations.
This is a bundle verification interface; connecting it to rootfs assembly and
WorldServer startup remains integration work. It authenticates recipe-bound
bytes, not acquisition dates or historical npm tag state.

Hostile tests cover missing/extra/substituted files, changed reports and cutoff,
self-asserted replacement hashes, invalid digests/schema/paths/types, boolean
sizes, duplicates, ordering and named caps. Known populated and empty bundles
round-trip independently of inventory insertion order and host environment.
The publication-focused suite passed: `99 passed in 1.82s`, exit 0.
No existing tests were edited, weakened or deleted.

The existing npm non-latest-tag gap was independently reproduced again: a
synthetic 2026 tag targeting a 2020 release survives the 2020 cutoff. Its
acquisition/history or owner-policy requirement remains OPEN; the offline
publisher refuses these tags. The sandbox still maps `/` and `/home` to UID
65534 with `/proc/self/uid_map` equal to `1000 0 1`. Production VMM ownership
validation is preserved. Full gates on this continuation are recorded below.

### Publication continuation gates

- Expanded offline review suite: `409 passed in 2.15s`, exit 0.
- `cargo fmt --all`: exit 0. `git diff --check`: exit 0.
- Full `rust-gate`, run 8: exit 101 after formatting/clippy passed. The same
  four VMM fixtures reject `unsafe ancestor ownership` under the sandbox's UID
  mapping. Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
  Correcting the host/sandbox mapping is outside the branch; no ownership check
  or test was weakened to bypass it.
- Full `py-gate`, run 8, after Rust exited: exit 0. Last line:
  `2160 passed, 1 skipped, 12 warnings in 234.99s (0:03:54)`.
  The skip is the unavailable Go executable and warnings are existing recorder
  deprecations. All 33 new publication tests pass. Both full gates ran in the
  foreground from the worktree root and were awaited. Logs:
  `.phase4-rust-gate-8.log` and `.phase4-py-gate-8.log`.
- The production `DirStore` offline-mirror integration was run separately
  because the full Rust gate stops earlier: exit 0, `1 passed; 0 failed`.
  Log: `.phase4-offline-store-gate-8.log`.
- Verdict remains OPEN for npm tag history/policy and the Rust gate environment.
  No dependency, original test or git state was changed in this continuation.

## Second-worker snapshot format continuation

The requested three-dot diff and commit range are still empty. Review also
covered the existing uncommitted package filters/publisher, authenticated archive
and search readers, shared safe I/O, tests, TR-PKG/TR-VMM requirements and
architecture §11.4. `.review/` and applicable `AGENTS.md` files are absent.
Existing preparation and tests are preserved. The explicit prohibition on git
state changes takes precedence over the earlier request to commit passing items.

- [x] Choose the untouched state-task snapshot grading formats item. The latest
  commits concern boot ordering/initramfs and networking; none implement this
  handoff. No VM runs or new dependencies are required for this offline item.
- [x] Implement `hermetic_state_snapshot.prepare_snapshot_handoff(raw_recipe)`
  and `verify_snapshot_handoff(raw_manifest, expected_sha256, run_sha256,
  runtime_sha256)`. The latter returns immutable manifest bytes, runtime digest,
  reserved tests drive and network-interface inventory. All expected pins come
  from the trusted harness, independently of the received manifest.
- [x] Implement `build_state_grade_record` with the same four authentication
  arguments followed by `raw_result`. The resulting canonical
  `hermetic-state-grade/v1` record binds the snapshot, run, tests and result
  digests/sizes, always reports `grader_isolation=shared`, and records `live`
  with no fallback reason or `reboot` with `execd_unresponsive`/`no_live_state`.
  It makes no pass/fail or forgery-resistance claim for a guest result.
- [x] Add 71 offline tests for schema/type errors, arbitrary single-byte input,
  duplicate JSON keys, surrogate/overflow/depth failures, compatibility and
  authentication, missing/extra pins, exact bytes, topology, access/paused
  requirements, named caps and explicit fallback paths. The focused suite
  passed (`71 passed in 0.07s`, exit 0). No original test was changed.
- [ ] Integrate these formats with VMM snapshot/restore, execd, artifact readers,
  signed attestations and actual grading; smart-git termination and the other
  previously listed Phase 4 deliverables remain open.

The handoff schema is `hermetic-state-snapshot/v1` with exactly these fields:
`run_sha256`; `runtime` mapping `firecracker`, `cpu_model`, `cpu_template`,
`kernel`, `initramfs` to lowercase SHA-256 strings; `artifacts` mapping `state`,
`memory`, `base`, `overlay` to `{sha256,size}` records; `tests_drive` naming a
reserved non-root/non-overlay slot; `network_interfaces` equal to `[]` or
`["eth0"]`; `access_closed=true`; `paused=true`; and `clock="faked"`.
The runtime compatibility pin is SHA-256 of that runtime object's canonical JSON.
All encodings use sorted keys, compact separators and ASCII JSON. Neither paths,
hostnames, host CPU identity strings, timestamps nor environment values enter
these formats. The approved CPU-model digest describes the selected VM model.

Named caps are 16 KiB per JSON document (with the shared 24-level parser depth
and token limits), 64 MiB snapshot state, 128 GiB memory, 64 GiB per disk and
tests image, 256 GiB aggregate snapshot artifacts, 1 MiB result and 32 bytes for
the reserved tests drive ID. Artifacts must be nonempty. No artifact file is
opened, mounted or restored here; the declarations bound the reader contract.
Digests authenticate received bytes only against independent trusted pins.

The trusted producer must actually close gateway/model and network access before
pausing and consistently snapshotting memory plus disk. The restore runner must
verify artifacts without mounting an agent disk on the host, confirm the boot
reservation and complete interface inventory, apply every no-peer network
override before resuming vCPUs, and attach/mount tests read-only. Reboot fallback
must use a copy of the overlay and the pinned trusted kernel/initramfs. Only the
runner can establish these actions; accepting a manifest is no evidence that
they occurred. Integration must embed the grade-path record in the signed run
record and continue reporting state-task results separately with shared isolation.

The existing major npm tag-history defect was independently reproduced again:
`added-after-cutoff-2026` targeting a 2020 version survives the 2020 cutoff in
`cut_packument`. Fixing its preserved-tag contract requires acquisition history
or an owner-approved policy change; the offline publisher continues to refuse
these tags. The VMM ownership gate environment remains an external prerequisite:
`/proc/self/uid_map` is `1000 0 1` and `/` and `/home` have unmapped UID 65534.
No ownership check or test is relaxed.

## Artifact verification and diagnostic review

The requested three-dot diff and branch log are empty (both refs are
`9fa90704b4992706aa6e1cc688be80566fa170ad`). Review also covered the existing
uncommitted filters, publisher, archive/search readers, snapshot formats, shared
I/O, relevant tests, TR-PKG/TR-WS/TR-VMM requirements and architecture §11.4.
No applicable `AGENTS.md` or `.review/` exists. Git state is left unchanged;
the explicit prohibition on commits takes precedence over committing items.

- [x] Repair a verified diagnostic disclosure in npm's public bounded reader
  and atomic writer. Their fixed errors chained OS exceptions containing private
  paths/details, which ordinary exception-chain logging rendered. Suppress those
  causes. All five new cases were observed failing before repair, including a
  real missing private path and injected open/stat/read/write errors. Tests are
  `test_npm_io_exception_chain_omits_private_os_details` and
  `test_npm_missing_input_error_chain_omits_supplied_path`. No original test is
  changed, weakened or deleted.
- [x] Continue the offline snapshot artifact-authentication item without a VM,
  owner decision or dependency. `verify_snapshot_artifacts(raw_manifest,
  expected_sha256, run_sha256, runtime_sha256, artifacts)` first authenticates
  the canonical handoff and independent runtime/run pins. `artifacts` must map
  exactly `state`, `memory`, `base`, `overlay` to immutable bytes. Validate the
  complete inventory and every size before hashing any payload; then compare
  all SHA-256 values. Return `SnapshotArtifacts` with the authenticated handoff
  and the exact verified byte objects in stable role order. Snapshotting the
  mapping before validation prevents later changes from replacing returned bytes.
  Existing per-role and aggregate artifact caps apply; no allocation follows a
  claimed size. No files, environment, host clock or network are accessed.
- [x] Add hostile-input tests for every payload role, corrupt/truncated/extended
  or missing bodies, mutable bytearrays, extra/invalid inventories, all trusted
  pins, authentication before inventory processing, size validation before
  payload hashing, input-mapping replacement, cap boundaries and known bytes.
  The initial 41 cases failed without the interface; a further mutation test
  verifies that the returned objects remain the ones actually authenticated.
- [ ] Streaming filesystem acquisition, isolated snapshot production/restore,
  supervisor/execd integration and embedding grade-path records in signed run
  records remain open. This verifier consumes already materialized bytes; it
  does not allocate a snapshot or establish that access was closed or a VM paused.

The existing historical npm non-latest-tag defect remains OPEN: a later-created
tag pointing to an admitted release survives the filter. Correct recovery needs
acquisition history or an owner-approved policy change; the offline publisher
refuses these tags. The root UID mapping is still `1000 0 1`, with `/` and `/home`
owned by unmapped UID 65534. Repairing that environment is outside this branch;
the production VMM ownership checks and all existing fixtures are preserved.

Current full-gate results are recorded after validation below.

### Additional gateway gate finding (OPEN, major)

Rust gate run 9 stopped in the existing
`test_8_stalled_clients_are_dropped_at_the_deadline_and_service_recovers`:
both request handlers remained occupied after 8 seconds. The focused rerun
passed (`1 passed; 0 failed`, exit 0), so its scheduling-dependent failure alone
does not identify a cause. Code inspection and a separate bounded reproduction
verified an applicable startup race: `GatewayServer::run_loop` installs request
deadlines only after `Server::http` has already started accepting connections.
`ClientConnection::read` snapshots the default unlimited deadlines at the start
of a request, then uses that snapshot for its body too. A request queued before
the gateway loop starts retains no body deadline after the loop installs one.

The offline reproduction sent an incomplete 5,000-byte request to a fresh local
HTTP server, received its queued request, installed 50 ms head/body deadlines,
and read the body on a bounded worker. It remained blocked after 300 ms and
terminated only after the client was explicitly shut down. The reproduction
completed with exit 0 and its temporary source/binary were removed. Thus the
startup behavior is verified independently of the intermittent full-gate test;
it is not proven to be the cause of that particular test failure.

Affected production entry points are `crates/hermetic-gateway/src/main.rs:57`
and `crates/hermetic-gateway/src/server.rs:394`, with the cached defaults in
`crates/vendor/tiny_http/src/client.rs`. Repair needs gateway/HTTP acceptance
lifecycle work outside the Phase 4 preparation components: configure deadlines
before accepting any connection, or ensure every accepted request acquires the
required policy before reads. Per the instruction to leave work in another
component OPEN, no gateway/vendor source or original test was changed. A later
successful rerun does not repair this verified race.

### Snapshot continuation gates

- `cargo fmt --all`: exit 0. `git diff --check`: exit 0.
- Full `rust-gate`, run 9: exit 101 after formatting/clippy passed. It stopped
  at the existing stalled-body gateway test described above. Last lines:
  `test result: FAILED. 24 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.25s`
  and `error: test failed, to rerun pass \`-p hermetic-gateway --test test_rereview\``.
- Full `py-gate`, run 9, after Rust exited: exit 0. Last line:
  `2231 passed, 1 skipped, 12 warnings in 224.23s (0:03:44)`.
  This includes all 71 snapshot format tests. The unavailable-Go skip and
  recorder deprecation warnings are unchanged.
- Focused gateway recheck: exit 0,
  `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 24 filtered out; finished in 2.22s`.
  The separate bounded startup reproduction still established the race above.
- Full `rust-gate`, run 10: exit 101 after formatting/clippy and the previously
  failing gateway test passed. It reached the four known VMM ownership failures:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
  Host UID mapping repair is outside this branch; no check or original test
  was weakened. The full gate remains OPEN.

### Artifact verification continuation validation

- New diagnostic regressions before repair: `5 failed in 0.03s`, exit 1.
  An initial after-fix run exposed a new test-harness issue: the patched global
  `fstat` also affected traceback formatting (`1 failed, 19 passed in 0.17s`,
  exit 1). Restoring the patch before rendering the diagnostic corrected the new
  test. The corrected stat case was independently observed failing with the old
  exception chaining (`1 failed, 4 deselected in 0.03s`, exit 1). The repaired
  diagnostic and existing npm suite passed (`20 passed in 0.16s`, exit 0).
- Initial snapshot artifact tests without the interface: `41 failed in 0.16s`,
  exit 1. The implemented verifier plus existing handoff and new diagnostic tests
  passed (`117 passed in 0.16s`, exit 0). A subsequent additional mapping-mutation
  case brings this continuation to 42 artifact cases and five diagnostic cases;
  all are included in the full Python results below.
- `cargo fmt --all` and `git diff --check`: exit 0.
- Initial full Rust invocation: exit 101. The shared
  `.phase4-rust-gate-10.log` was concurrently written/truncated and contains
  interleaved output, including a gateway streaming assertion failure and VMM
  ownership failures. It cannot establish an unambiguous per-run result beyond
  the invocation's exit code. A distinct-log full rerun follows below.
- Initial full Python invocation, after Rust exited: exit 0. Last line:
  `2278 passed, 1 skipped, 12 warnings in 244.50s (0:04:04)`.
  Log: `.phase4-py-gate-10.log`.
- Distinct-log full Rust rerun: exit 101 after formatting, clippy and gateway
  tests passed. The four existing VMM filesystem/process fixtures refuse
  `Validation("unsafe ancestor ownership")` under the unmapped root UID.
  Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
  Log: `.phase4-reviewer-rust-gate-1.log`. The ownership checks are preserved;
  repairing the host UID mapping is outside this branch. No full Rust success
  is claimed. Final Python validation follows this Rust invocation.
- Final distinct-log full Python gate, after that Rust invocation: exit 0.
  Last line: `2278 passed, 1 skipped, 12 warnings in 214.92s (0:03:34)`.
  Log: `.phase4-reviewer-py-gate-1.log`. The skip is the unavailable Go toolchain;
  warnings are the existing recorder deprecations. Both final gates ran in the
  foreground from the worktree root and were awaited. All 47 new cases pass.
  No original test, dependency or git state was changed. Verdict remains OPEN
  for npm historical tags, gateway startup deadline integration and the host
  UID mapping. The verified in-scope I/O disclosure is fixed.

### Concurrent edits inspected during the final gate

Additional shared-worktree edits added
`hermetic_state_snapshot.verify_snapshot_artifacts` and
`python/tests/test_phase4_snapshot_artifacts.py`. Review confirmed that the
function authenticates the handoff before considering payloads, captures an
immutable ordered inventory, validates every role's type/size and aggregate cap
before hashing any payload, then verifies every digest. It returns those exact
verified immutable objects even if the caller's mapping subsequently changes.
This completes the in-memory artifact boundary; file acquisition and VM restore
remain integration work. The recorded pre-change run failed because this API
was absent; the combined post-change snapshot/error suite passed 117 cases.

The concurrent npm change fixes a verified major disclosure in filesystem
exception chains: a missing input or injected OS failure carried private paths
or credential text into formatted tracebacks despite a fixed outer error.
The new `test_npm_io_exception_chain_omits_private_os_details` covers open,
stat, read and write failures, while
`test_npm_missing_input_error_chain_omits_supplied_path` checks a real missing
path. The stat case's pre-fix log demonstrates the private detail in the direct
cause. The wrappers now raise sanitized errors with suppressed chaining. These
changes and tests were read and preserved; no original test was changed.

- Final focused snapshot/artifact/error suite: `118 passed in 0.53s`, exit 0.
- Full `py-gate`, run 10, after Rust run 10 exited: exit 0. Last line:
  `2278 passed, 1 skipped, 12 warnings in 228.63s (0:03:48)`.
  This includes all final shared-worktree regressions. The skip and warnings
  remain the unavailable Go executable and existing recorder deprecations.
- Both Rust/Python gate pairs ran in the foreground from the worktree root and
  were awaited. Full logs are `.phase4-rust-gate-9.log`,
  `.phase4-py-gate-9.log`, `.phase4-rust-gate-10.log` and
  `.phase4-py-gate-10.log`. No git state mutation, new dependency or VM run was
  performed. Verdict remains OPEN for npm historical tags, gateway startup
  deadline integration and the host UID mapping that prevents a passing Rust
  gate.

## Retained payload inventory review

The requested three-dot diff and branch log remain empty: `main`, `phase4-prep`
and `HEAD` all name `9fa90704b4992706aa6e1cc688be80566fa170ad`.
Review also covered the uncommitted preparation, its tests, shared safe I/O,
production store integration, and the package/archive/state-task requirements.
There is no `.review/` directory. No existing test or dependency was changed;
the explicit prohibition on git state changes precludes commits.

The next offline hostile-input review verified two major integrity defects:

- Archive replay building/reading and search building hashed payloads from a
  caller-owned dictionary, then fetched them again from that mutable dictionary.
  Substituting an entry after its hash check made replay emit unverified bytes
  and search index unverified text. The shared payload validator now captures
  a bounded dictionary copy and returns that inventory to every consumer.
- Mirror building and publication verification had the same check/use gap.
  Substitution after hashing a Go artifact changed the published bytes despite
  the acquisition digest; substitution after checking a served file changed the
  verified bundle returned to a consumer. Both boundaries now retain a bounded
  copy and use only the exact immutable byte objects checked by their digests.

Hashing can release the interpreter lock; these APIs therefore cannot assume
that a caller-owned mapping stays unchanged during validation. No deep copies
or additional payload allocation are needed because body types must be exact
immutable `bytes`. Existing `MAX_RECORDS`, `MAX_BLOBS` and `MAX_STORE_FILES`
caps bound the retained inventories before copying.

All five cases in `python/tests/test_phase4_inventory_identity.py` were observed
failing before repair (`.phase4-identity-before.log`, exit 1). The repaired
identity/archive/search/mirror/publication suite passed 258 tests, exit 0.
These tests deterministically substitute entries at the digest boundary and
assert the exact original output bytes, without threads, network or a VM.

Historical npm tags, gateway startup deadlines, the host UID mapping and all
unfinished Phase 4 deliverables remain open. Source inspection confirms that
`ClientConnection::read` caches deadlines before headers/body while the gateway
installs them only after `Server::http` starts acceptance. The sandbox still
reports `/proc/self/uid_map` as `1000 0 1` and `/` and `/home` as UID 65534;
VMM rejects ancestors owned by neither root nor the caller. These repairs
require another component or host configuration and are left unchanged.

### Inventory review gates

- `cargo fmt --all` and `git diff --check`: exit 0.
- Full `rust-gate`: exit 101 after formatting, clippy, gateway and earlier
  workspace tests passed. The same four VMM fixtures reject
  `Validation("unsafe ancestor ownership")`: publication/copy-budget,
  surviving-child cleanup, capped output/drop cleanup and clean process launch.
  Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
  Log: `.phase4-inventory-rust-gate-1.log`. Host UID mapping is outside this
  branch; no production check or existing test was weakened. The subsequent
  full Python gate runs from the worktree root with its temporary files inside
  the worktree. Both commands run in the foreground and are awaited.
- Full `py-gate`, after Rust exited: exit 0. Last line:
  `2283 passed, 1 skipped, 12 warnings in 198.55s (0:03:18)`.
  Log: `.phase4-inventory-py-gate-1.log`. This includes the five newly reproduced
  identity regressions. The Go fixture still skips because Go is unavailable;
  warnings are the existing assertion-recorder deprecations. Temporary fixture
  directories from this continuation were removed after execution; logs remain.
- Verdict remains OPEN for historical npm tags, gateway startup deadlines and
  the host UID mapping. No full Rust gate success, completed Phase 4 seal,
  dependency addition, VM run or git state operation is claimed.

## Go info inventory review

The requested three-dot diff and branch log are empty: `main`, `phase4-prep`
and `HEAD` still identify `9fa9070`. This review also covered the uncommitted
Phase 4 filters, publisher, archive/search readers, snapshot formats and tests,
plus their shared I/O and parser boundaries. `.review/` and `AGENTS.md` are
absent. No git state operation or commit is authorized by the final instruction.

A major resource-bound defect was reproduced in `cut_go_versions`: it validated
the caller's mutable `.info` mapping against `MAX_INPUT_BYTES`, then fetched
records from that mapping again while parsing. Substituting a larger second
record after the first parse bypassed the aggregate input budget and changed
the emitted timestamp. Removing that record instead silently changed an
admitted version to unknown. The filter now copies the bounded inventory before
validation and consumes the exact immutable byte objects covered by the budget.
Both cases of `test_go_info_inventory_is_retained_after_aggregate_validation`
failed before repair; the targeted ecosystem/mirror suite passes 149 tests.
No existing test was edited, weakened or deleted and no dependency was added.

The existing npm tag-history defect and gateway startup deadline race remain
open: fixing them needs acquisition/policy or another component, respectively.
Source inspection reconfirmed that the gateway starts acceptance before setting
deadlines. The host still maps `/` and `/home` ownership to UID 65534, outside
the VMM's accepted root/caller ownership policy. That gate prerequisite cannot
be repaired inside this worktree. All unfinished Phase 4 deliverables remain.
Validation for this review:

- `cargo fmt --all`: exit 0. `git diff --check`: exit 0.
- Full `rust-gate`, run 1: exit 101 after formatting/clippy passed. The initial
  worktree-local temporary-directory name made a bundle fixture's Unix socket
  path exceed `SUN_LEN`. No test was changed; the rerun uses the shorter `.g-tmp`.
  Last lines: `test result: FAILED. 16 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s`
  and `error: test failed, to rerun pass \`-p hermetic-bundle --test bundle\``.
  Log: `.phase4-go-inventory-rust-gate-1.log`.
- Full `rust-gate`, run 2: exit 101 after formatting/clippy, bundle, gateway and
  scanner tests passed. The same four VMM fixtures reject ancestor ownership.
  Last lines: `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
  Log: `.phase4-go-inventory-rust-gate-2.log`.
- Full `py-gate`, after Rust exited: exit 0. Last line:
  `2285 passed, 1 skipped, 12 warnings in 216.03s (0:03:36)`.
  Log: `.phase4-go-inventory-py-gate-1.log`. Both new regression cases pass.
  The Go-client fixture skips because its toolchain is unavailable; the warnings
  are the existing assertion-recorder deprecations. Both gates ran from the
  worktree root in the foreground and were awaited, using worktree-local fixture
  directories. Those temporary directories were removed after execution.
- Verdict remains OPEN for npm tag history/policy, gateway startup deadlines
  and the VMM host ownership mapping. No complete Rust gate success is claimed.

## Direct npm tree identity review

The requested `git diff main...phase4-prep` and `git log main..phase4-prep`
are empty; both refs still name `9fa9070`. Review also covered the uncommitted
Phase 4 filters, mirror builder/verifier, client configurations, replay/search
readers, snapshot formats, tests and shared descriptor-based I/O, against the
package/archive/state requirements. `.review/` is absent. Recent commits concern
boot/network/clock/VMM work; this repair concerns the direct npm input boundary.
The explicit prohibition on git state changes takes precedence over committing.

A major check/use defect was reproduced in `cut_packument`: after bounding a
caller's nested JSON tree it continued to read that mutable tree. Substituting
metadata after validation bypassed the byte cap; inserting a cycle reached
serialization and raised an uncontrolled `ValueError`. Removing a version or
replacing its publication time changed admission after validation. The validator
now optionally captures containers as it checks each node. The filter consumes
only that private retained tree; scalar values must be exact immutable JSON
types, and depth/token/string/integer/byte caps apply before captured nodes are
retained. Dictionary-size changes during iteration raise a fixed typed error.
The byte parser uses validation without copying its already private parsed tree.

All four cases in `test_npm_direct_filter_retains_validated_tree` failed before
repair and pass afterward. They inject changes at the first field-validation
call after tree validation, without threads, a network or a VM, and compare the
exact original canonical bytes and report. The focused parser/npm/ecosystem/
mirror suite passes 174 tests, exit 0. Two companion cases in
`test_npm_direct_filter_refuses_dictionary_resize_during_validation` assert
fixed typed errors when keys are added or removed during iteration.
No existing test was edited, weakened or
deleted and no dependency was added.

Source inspection reconfirmed the existing open npm tag-history defect and
gateway startup deadline race. The former needs acquisition history or a policy
decision; the latter needs the gateway/HTTP acceptance lifecycle component.
The host still maps root-owned `/` and `/home` to UID 65534 (`1000 0 1` in
`/proc/self/uid_map`), which VMM correctly refuses as unsafe ancestor ownership.
Repairing that mapping requires host configuration outside this worktree.
All unfinished Phase 4 deliverables remain open.

### Direct npm tree review gates

- `cargo fmt --all` and `git diff --check`: exit 0.
- Full `rust-gate`, run 1: exit 101 after formatting/clippy and preceding
  workspace tests passed. The same four VMM publication/process fixtures reject
  `Validation("unsafe ancestor ownership")` under this host's UID mapping.
  Last lines:
  `test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
  and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
  Log: `.phase4-npm-tree-rust-gate-1.log`. No existing test or ownership policy
  was weakened. The required Python gate follows this completed Rust run.
- Full `py-gate`, run 1, after Rust exited: exit 0. Last line:
  `2291 passed, 1 skipped, 12 warnings in 205.26s (0:03:25)`.
  Log: `.phase4-npm-tree-py-gate-1.log`. All six new regression cases pass.
  The Go-client fixture remains skipped for its unavailable toolchain; warnings
  are the existing assertion-recorder deprecations. Both gates ran from the
  worktree root in the foreground and were awaited. Fixture temporary files
  stayed inside the worktree and were removed after execution.
- Verdict remains OPEN for npm tag history/policy, gateway startup deadlines
  and the VMM host ownership mapping. No full Rust gate success, git state
  mutation, existing-test change or dependency addition is claimed.

## Final branch and preparation review

The requested three-dot diff and branch-only log are still empty: `main`,
`phase4-prep` and `HEAD` all name `9fa9070`. `.review/` and applicable `AGENTS.md`
files are absent. The review also covered the existing uncommitted preparation:
ecosystem filters, mirror publication/authentication, client configurations,
archive replay/search, snapshot handoff/artifacts, shared safe I/O and their
tests. Package, archive and state requirements were checked against TRD.md,
architecture sections 6.4/6.5/11.4 and the relevant task briefs. Recent commits
concern boot, network, clock and VMM work; the review concentrated on the offline
Phase 4 boundaries. No git state was changed.

An offline field-mutation sweep exercised 1,027 cases across replay, search,
snapshot, PyPI and Cargo inputs without an unexpected exception. Source review
found no additional verified defect requiring a repair or new regression test.
No existing code, test or dependency was changed. All unfinished deliverables
above remain open.

The previously recorded open findings were reconfirmed:

- Major: the standalone npm filter retains a non-latest tag added after the
  cutoff when it targets an admitted version. A 2020 release and cutoff with
  `added-after-cutoff-2026` reproduce this. Historical acquisition evidence or
  an owner-approved tag-policy change is required; the offline publisher already
  refuses these tags.
- Major: gateway acceptance starts in `Server::http` before `run_loop` sets
  deadlines. The HTTP reader caches both deadlines before reading the request
  line, so a connection started in that window can keep unlimited body reads.
  Repair belongs to the gateway/HTTP acceptance lifecycle component.
- Gate prerequisite: VMM correctly refuses root-owned ancestors represented
  here as unmapped UID 65534. `/proc/self/uid_map` is `1000 0 1`; both `/` and
  `/home` have UID 65534. Changing that mapping requires host configuration
  outside this worktree. No ownership policy or test was weakened.

`cargo fmt --all` and `git diff --check` passed. The full Rust gate completed
before the Python gate was started, using worktree-local fixture directories.
Rust formatting, clippy and gateway tests passed; its exit was 101 at the same
four VMM ancestor-ownership failures. Last lines:
`test result: FAILED. 5 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s`
and `error: test failed, to rerun pass \`-p hermetic-vmm --lib\``.
Log: `.phase4-final-review-rust-gate.log`.

The subsequent full Python gate exited 0. Last line:
`2291 passed, 1 skipped, 12 warnings in 202.47s (0:03:22)`.
Log: `.phase4-final-review-py-gate.log`. The Go-client fixture skips because
the local toolchain is unavailable; the warnings are the existing assertion
recorder deprecations. Both gates ran from the worktree root in the foreground
and were awaited. Temporary fixtures stayed inside the worktree and were removed
after execution. The verdict remains OPEN for the three findings above; no
complete Rust gate success is claimed.
