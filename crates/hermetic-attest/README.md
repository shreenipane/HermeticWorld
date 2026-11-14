# `hermetic-attest`

`hermetic-attest` generates, validates, signs, and verifies evaluation run records (`hermetic-run/v1`), transcript audit records (`hermetic-transcript-audit/v1`), in-toto DSSE envelopes, run statuses, and score cards.

Every evaluation run ends in a cryptographically verifiable signed statement that allows third parties to independently verify which world was used, which seal level and clock isolation applied, and how the run was graded.

---

## 1. Run Record Statement (`hermetic-run/v1`)

The run record contains only deterministic or digest values. There is no field for wall-clock time, host name, user identity, host file paths, or free text.

### Field Table

| Field | Type | Description |
|---|---|---|
| `task_id` | String | Unique benchmark task identifier (e.g. `pytest-dev__pytest-6202`). |
| `task_class` | Enum (`patch`, `artifact`, `state`) | Classification of evaluation work submitted by the agent (§1.4). |
| `seal_level` | Enum (`strict`, `repo_only`) | World sealing strength level (§1.3). |
| `agent_mode` | Enum (`H`, `G`) | Evaluation loop location: outside VM (`H`) or inside VM (`G`) (§9.1). |
| `clock` | Enum (`hidden`, `faked`, `real`) | Guest clock isolation level (§8.1). |
| `grader_isolation` | Enum (`clean`, `shared`) | Isolation of grading environment: clean VM (`clean`) or resumed VM (`shared`) (§11). |
| `deployment` | Enum (`split`, `single_host`) | Deployment infrastructure mode (§3.2). |
| `t_world` | String (RFC 3339 UTC) | World cutoff timestamp (§4). |
| `t_clock` | String (RFC 3339 UTC) | Faked or frozen guest clock timestamp (`max(t_world, base_commit)`). |
| `base_commit` | String | Git commit hash bounding the benchmark repository (§4). |
| `pkg_cutoff` | Option<String> | Optional package cutoff timestamp override (if raised per §4). |
| `version_tuple` | Object (`VersionTuple`) | Version tuple: `spec_version`, `world_version`, `sealcheck_version`, `grader_image_digest`. |
| `world_root` | Digest | Merkle root digest over the sealed world manifest. |
| `task_rootfs_digest` | Digest | SHA-256 digest of the task root filesystem image. |
| `netvm_image_digest` | Digest | SHA-256 digest of the NetVM dm-verity image. |
| `guest_kernel_digest` | Digest | SHA-256 digest of the guest kernel image. |
| `vm_config_digest` | Digest | SHA-256 digest of the VM configuration descriptor. |
| `cpu_template_digest` | Digest | SHA-256 digest of the custom CPUID template. |
| `firecracker_build_digest` | Digest | SHA-256 digest of the Firecracker binary. |
| `agent_volume_digest` | Digest | SHA-256 digest of the agent CoW disk image. |
| `sealcheck_report_digest` | Digest | SHA-256 digest of the sealcheck verification report. |
| `substrate_at_t` | Enum (`full`, `partial`, `none`) | Degree to which base substrate reflects cutoff date (§1.3). |
| `exemption_list` | Vec<String> | Sorted and deduplicated list of exempt substrate components. |
| `d5b_warning_list` | Option<Vec<String>> | Sorted D5b warning packages (permitted only in `repo_only` mode). |
| `escape_probe_result` | Enum (`passed`, `failed`) | Verdict of the pre-run escape probe. |
| `escape_probe_digest` | Digest | SHA-256 digest of the escape probe execution trace. |
| `world_server_log_head` | Digest | Head of the append-only WorldServer transaction hash chain. |
| `dedupe_index_digest` | Digest | Digest of the WorldServer deduplication index. |
| `request_count` | u64 | Total number of HTTP/network requests served by WorldServer. |
| `harness_command_log_head` | Option<Digest> | Head of command log hash chain (Mode H only). |
| `gateway_log_head` | Option<Digest> | Head of gateway traffic hash chain (Mode G only). |
| `history_rewrite_count` | Option<u64> | Count of conversation history rewrites detected (Mode G only). |
| `gateway_adapter_version` | Option<String> | Version identifier of the gateway provider adapter (Mode G only). |
| `submitted_work_digest` | Digest | SHA-256 digest of extracted candidate patch or declared artifacts. |
| `r0_result` | Enum (`passed`, `failed`, `skipped`) | Outcome of standard test execution (R0). |
| `r1_result` | Option<GradingRunResult> | Outcome of mutant test execution (R1). |
| `r2_result` | Option<GradingRunResult> | Outcome of equivalent rewritten test execution (R2). |
| `r3_result` | Option<GradingRunResult> | Outcome of fix-removal test execution (R3). |
| `r1_coverage` | Option<u32> | Share of eligible hidden tests covered by R1 mutants (per-mille: 0..=1000). |
| `run_status` | Enum (`RunStatus`) | Final run status verdict (§12.3). |
| `date_leak_observed` | bool | Whether real host date was observed in guest egress or probe: `SentinelSummary::merge` (`hermetic_sealcheck::d12_runtime`) over the gateway `date_sentinel.json`, the harness summary and the probe; an incomplete scan counts as observed. |
| `unclean_shutdown` | bool | Whether AgentVM failed to flush and freeze disk cleanly. |
| `tee_quote` | Option<TeeQuote> | Optional hardware attestation quote (AMD SEV-SNP, Intel TDX, or AWS Nitro). |

---

## 2. Transcript Audit Record (`hermetic-transcript-audit/v1`)

The transcript audit record documents the offline retrieval classifier's findings (§12.2, TR-ATT-2). It is maintained as a separate record type and separate file so that verifying a deterministic run record never depends on judge output.

### Field Table

| Field | Type | Description |
|---|---|---|
| `run_digest` | Digest | The run digest (`sha256:` + 64 lowercase hex) acting as statement subject. |
| `label` | Enum (`derived`, `retrieved`) | Classification of agent success: derived or retrieved. |
| `confidence` | u32 | Bounded integer confidence score in per-mille (0..=1000, never a float). |
| `evidence_spans` | Vec<EvidenceSpan> | Sorted spans (`log_name`, `start`, `end`) identifying evidence locations. |

Retrieval means obtaining an answer from an answer source; it is not restricted to
copying from hidden tests or gold files. These are classifier labels, not proofs
of how the answer was obtained.

Record validation applies to both parsed and directly constructed values. Text
fields are capped by `MAX_RECORD_TEXT_BYTES`, substrate lists by
`MAX_SUBSTRATE_ITEMS`, and quotes by `MAX_TEE_QUOTE_BYTES`. `world_version` must
equal `world_root`; run digests use SHA-256. Digest algorithms are limited to
SHA-256, SHA-512 and BLAKE3, with fixed lengths. Strict records omit the D5b list,
including an empty list.

Canonical serialization has `MAX_CANONICAL_BYTES` and `MAX_CANONICAL_DEPTH`
limits. DSSE applies separate payload, signature, key ID and envelope limits
when signing and verifying; base64 decoding caps decoded bytes. Each verified
statement has exactly one subject with exactly one canonical digest. Duplicate
digest keys are rejected. Score cards validate records and bound both task lists
and their metadata before copying them. Error diagnostics omit supplied text and
signer backend details.

File helpers require Linux x86_64 or aarch64 and a trusted procfs. They pin each
directory and file without following supplied symlinks, and refuse parent
traversal and special files. Reads and writes have a `MAX_FILE_BYTES` ceiling;
paths and temporary-name attempts have separate named caps. Atomic writes require
the output directory to belong to the process's effective user and have no group
or other write permission. Published files have mode 0600, and both file data and
the containing directory are synced. The helpers cannot protect against a hostile
process running as the same host user or host root.

---

## 3. What the Records Prove and Do Not Prove (§12.5)

| Proves | Does not prove |
|---|---|
| Which sealed world the run used. | That the model never saw the answer in training. |
| That Class A and B content predates cutoff (`strict`), or which Class B items did not (`repo_only`). | That no timing side channels were exploited. |
| Which substrate components were explicitly exempt. | In Mode G: which exact shell commands ran inside AgentVM. |
| That the escape probe failed to escape. | That a rooted guest could not learn the date under `faked` or `real` clock isolation. |
| Which URLs left WorldServer, and (Mode H) which harness commands were issued. | That a rooted guest could not infer physical CPU generation or cutoff boundaries. |
| Which guest clock isolation level applied. | That an adversary reading test semantic meaning at runtime was not present. |
| That grading used a clean image and passed R1 mutants and R2 equivalents (patch and artifact tasks). | Anything about code forgery in unconstrained state tasks (`shared` isolation). |
| | That the hidden test suite is comprehensive or strong. |
| | That the host environment was honest, unless accompanied by a verified hardware TEE quote. |

---

## 4. Deferred Work

The following cryptographic operations are specified for future phases:

1. **Real Offline-Key and Sigstore Keyless Signing**: Cryptographic key management (e.g. ED25519 offline keys and Sigstore Fulcio/Rekor integration) is deferred. The crate provides the `Signer` and `Verifier` trait abstractions alongside a deterministic test implementation.
2. **TEE Hardware Quote Verification**: Attestation quote verification against hardware root certificates (AMD KDS, Intel PCS, AWS Nitro PKI) is deferred. The crate defines the data model (`TeeQuote`, `TeePlatform`) and preserves quote bytes in the canonical statement.
