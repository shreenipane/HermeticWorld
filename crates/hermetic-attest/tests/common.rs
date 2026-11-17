#![allow(dead_code)]

use hermetic_attest::{
    AgentMode, ClockLevel, Deployment, Digest, GraderIsolation, GradingRunResult, HostBootRecord,
    ProbeResult, RunRecord, RunStatus, SealLevel, SignatureError, Signer, SubstrateAtT, TaskClass,
    Verifier, VersionTuple,
};
use sha2::{Digest as Sha2Digest, Sha256};

pub fn sample_run_record() -> RunRecord {
    RunRecord {
        task_id: "pytest-dev__pytest-6202".to_string(),
        task_class: TaskClass::Patch,
        seal_level: SealLevel::Strict,
        agent_mode: AgentMode::H,
        clock: ClockLevel::Hidden,
        grader_isolation: GraderIsolation::Clean,
        deployment: Deployment::SingleHost,
        t_world: "2020-01-01T00:00:00Z".to_string(),
        t_clock: "2020-01-01T00:00:00Z".to_string(),
        base_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        pkg_cutoff: None,
        version_tuple: VersionTuple {
            spec_version: "v1.1".to_string(),
            world_version: Digest::parse(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            sealcheck_version: "v1.0".to_string(),
            grader_image_digest: Digest::parse(
                "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
        },
        world_root: Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        task_rootfs_digest: Digest::parse(
            "sha256:2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        netvm_image_digest: Digest::parse(
            "sha256:3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        guest_kernel_digest: Digest::parse(
            "sha256:4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        vm_config_digest: Digest::parse(
            "sha256:5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        cpu_template_digest: Digest::parse(
            "sha256:6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        firecracker_build_digest: Digest::parse(
            "sha256:7123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        agent_volume_digest: Digest::parse(
            "sha256:8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        sealcheck_report_digest: Digest::parse(
            "sha256:9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        substrate_at_t: SubstrateAtT::Full,
        exemption_list: vec!["pkg-a".to_string(), "pkg-b".to_string()],
        d5b_warning_list: None,
        escape_probe_result: ProbeResult::Passed,
        escape_probe_digest: Digest::parse(
            "sha256:a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        world_server_log_head: Digest::parse(
            "sha256:b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        dedupe_index_digest: Digest::parse(
            "sha256:c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        request_count: 42,
        harness_command_log_head: Some(
            Digest::parse(
                "sha256:d123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
        ),
        gateway_log_head: None,
        history_rewrite_count: None,
        gateway_adapter_version: None,
        submitted_work_digest: Digest::parse(
            "sha256:e123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        r0_result: GradingRunResult::Passed,
        r1_result: Some(GradingRunResult::Passed),
        r2_result: Some(GradingRunResult::Passed),
        r3_result: Some(GradingRunResult::Passed),
        r1_coverage: Some(850),
        run_status: RunStatus::Resolved,
        date_leak_observed: false,
        unclean_shutdown: false,
        tee_quote: None,
        boot_record: Some(HostBootRecord {
            boot_path: "trusted_initramfs".to_string(),
            initrd_digest: Some(
                Digest::parse(
                    "sha256:f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
            ),
        }),
    }
}

pub fn sample_v1_0_run_record() -> RunRecord {
    let mut record = sample_run_record();
    record.version_tuple.spec_version = "v1.0".to_string();
    record.boot_record = None;
    record
}

pub struct DeterministicTestSigner {
    pub key_id: String,
    pub secret: Vec<u8>,
}

impl Signer for DeterministicTestSigner {
    fn key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        hasher.update(pae_bytes);
        Ok(hasher.finalize().to_vec())
    }
}

pub struct DeterministicTestVerifier {
    pub key_id: String,
    pub secret: Vec<u8>,
}

impl Verifier for DeterministicTestVerifier {
    fn verify(
        &self,
        key_id: Option<&str>,
        pae_bytes: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), SignatureError> {
        if let Some(kid) = key_id {
            if kid != self.key_id {
                return Err(SignatureError::VerificationFailed(format!(
                    "Key ID mismatch: expected {}, got {kid}",
                    self.key_id
                )));
            }
        }
        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        hasher.update(pae_bytes);
        let expected = hasher.finalize();
        if expected.as_slice() == sig_bytes {
            Ok(())
        } else {
            Err(SignatureError::VerificationFailed(
                "Signature bytes mismatch".into(),
            ))
        }
    }
}
