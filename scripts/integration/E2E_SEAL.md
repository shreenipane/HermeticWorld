# Stage-one real-task sealing

Run from the worktree root on the prepared host. Supply an existing sealcheck
binary and a **new** directory whose parent exists and is owned by the caller:

```sh
bash scripts/integration/e2e-seal.sh psf__requests-2317 \
  "$HOME/.cache/hermetic-smoke/requests-2317-stage1" \
  --sealcheck "$HOME/hermetic/cargo-target/e2e-1/release/hermetic-sealcheck"
```

Omit the directory to allocate a fresh private directory under
`${HERMETIC_SMOKE_DIR:-$HOME/.cache/hermetic-smoke}`. Physical paths are required;
symlink components are refused. Artifacts are retained for the host fix round.
The host needs Docker with the already-pulled official image, the project tools
on the fixed executable search path, and the rootfs builder's pinned e2fsprogs
1.47.2. Intake needs GitHub API access and optionally `GITHUB_TOKEN` for revision
history. No benchmark entrypoint or eval script is executed on the host.

The record is copied byte-for-byte from the existing grader fixture. Its
`.source.json` records the local source, upstream dataset URL and SHA-256; it does
not assert a new upstream retrieval. No network request is needed for this record.

The script emits one JSON line per completed step and stops on the first failure.
Subprocess contents, raw image metadata and oracle patches remain private in the
work directory. A failing command's stdout is retained as `<step>.failed-output`.
Successful scan reports are retained by step name. Exported source layers and
staging files are never included in the rootfs. The exported filesystem is
flattened, cleaned, given a freshly sealed Git store, normalised and built with
the existing rootfs builder, including its D4 guard. The direct sealcheck scan
runs all its fingerprint tiers and D0/D1/D2/D3/D3b/D4/D5a/D6/D9; D8 and D10 are
also invoked explicitly. The seal level is `repo_only`, with no claim that the
original substrate existed at the cutoff. Detector thresholds are unchanged.

The grader handoff is `oracle-inputs/`: exact gold and test patches, separate
FAIL_TO_PASS/PASS_TO_PASS JSON lists, and an input digest record. It is prepared
during intake, outside the guest tree. It is data for a future GraderVM run;
preparation is not an oracle verdict.

After the scans, `bundle-evidence.json` records the SHA-256 and byte size of
the actual rootfs, each scan report and task record, plus the declared test
services. Rootfs bytes must match the builder's D4-passing report; scans must
explicitly pass with complete coverage. In particular, `not_covered`, D8
inspection errors and incomplete D10 scans stop the run. The evidence uses
relative artifact names, excludes private oracle data and host paths, is written
atomically with mode 0600, and always records `complete: false`. This staging
handoff supplies available content evidence; it is not a world manifest or a
shippable world bundle. Repository Merkle roots require a repair to the manifest
component's canonical tree-digest tool: its existing walk is unbounded and uses
paths after inspecting their type. It cannot safely digest a mutable hostile
tree. No substitute hash scheme is invented here.

This integration cannot yet finish a world bundle. It exits 1 with an `open`
world-manifest verdict after the available scans pass, because existing
construction components do not supply the complete class-B inventory/release
metadata for D5b, package closure/baseline roots, substrate inventory/exemptions,
or installed world trust and guest run spec. These need a component contract;
empty roots and invented exemptions would certify an incomplete world. The
manifest CLI can hash supplied manifests but cannot construct that evidence.
No manifest or success verdict is published without it.

D7 is an optional deep rebuild audit; the repository has a comparison tool but
no rebuild orchestration contract. D11 applies to a later agent patch. D12 needs
the runtime probe and guest/model egress integration. D8's kernel/CPU policy and
D10's thread-provenance/payload integration remain incomplete in their owning
components (see the PHASES.md detector audit). These are open dependencies, not
passing detectors. A host run can stop earlier on a genuine gate finding; send
the JSON lines and the named private report back for that fix round.
