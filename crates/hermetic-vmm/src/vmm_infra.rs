#![forbid(unsafe_code)]

//! Real microVM orchestration infrastructure implementing `hermetic_run::infra::Infra` (TR-VMM, TR-EXT, TR-GR).
//!
//! Orchestrates Firecracker microVMs across all evaluation phases:
//! - NetVM: network isolation and replay proxy.
//! - AgentVM: guest execution under sealed clock and descriptor pinning.
//! - ExtractorVM: copy-on-write overlay extraction with nonce binding.
//! - GraderVM: isolated grading with 1 MiB result disk protocol.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hermetic_grader_result::{parse_disk_bytes, RunId, SupervisorExit, TestStatus, DISK_BYTES};
use hermetic_run::infra::{
    AgentMode, AgentOutcome, ExtractorOutcome, GraderHandle, GraderOutcome, GraderPayload,
    GraderRun, Infra, InfraError, LimitKind, NamedDeadline, PreparedWorld, ShutdownKind, Step,
    VmHandle, VmId, VmKind, WorldSpec,
};
use hermetic_run::verdict::{
    GraderResults, MutatedTestResult, PairedTestResult, R0Result, R1Result, R2Result, R3Result,
    RunStatus, TestResult,
};

use crate::extractor::{
    create_fresh_output_drive, create_overlay_cow_copy, extractor_spec, generate_run_nonce,
    read_extractor_output, ExtractorVmConfig, DEFAULT_OUTPUT_DRIVE_BYTES,
};
use crate::lifecycle::Vmm;
use crate::runner::Runner;
use crate::spec::{
    project_mac, Clock as VmClock, Drive, JailConfig, Limits, Network, Role, VmSpec, Vsock,
    GRADER_RESULT_DRIVE,
};
use crate::{deadline, remaining};
use hermetic_attest::{
    safe_atomic_write_file, safe_sha256_file, AgentMode as AttestAgentMode, Deployment, Digest,
    GraderIsolation, SealLevel as AttestSealLevel, SubstrateAtT as AttestSubstrateAtT,
    TaskClass as AttestTaskClass,
};
use hermetic_bundle::{Verdict as BundleVerdict, MANIFEST_FILENAME as BUNDLE_MANIFEST_FILENAME};
use hermetic_common::world_manifest::{
    SealLevel as CommonSealLevel, SubstrateAtT as CommonSubstrateAtT, TaskClass as CommonTaskClass,
    WorldManifest,
};
use hermetic_run::orchestrator::WorldManifestArtifact;

pub const DEFAULT_T_CLOCK: i64 = 1_700_000_000;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const RUN_LABEL_MAGIC_VERSION: &[u8; 6] = b"HGRL\0\x01";

pub type RunnerFactory = Box<dyn Fn(&VmSpec) -> Result<Box<dyn Runner>, InfraError> + Send + Sync>;

struct ActiveVm {
    kind: VmKind,
    vmm: Option<Vmm<Box<dyn Runner>>>,
    vsock_path: Option<String>,
    result_disk: Option<PathBuf>,
}

/// Real microVM orchestration infrastructure driven through `hermetic-vmm`.
pub struct VmmInfra {
    fc_bin: PathBuf,
    kernel_image: PathBuf,
    rootfs_image: PathBuf,
    netvm_rootfs: Option<PathBuf>,
    run_dir: PathBuf,
    lock_file: Option<PathBuf>,
    python_launcher: Option<PathBuf>,

    // Extracted from world manifest during prepare_world
    sealed_world: Option<PathBuf>,
    t_clock: i64,
    task_id: String,
    task_class: String,

    // Managed active VMs
    active_vms: BTreeMap<VmId, ActiveVm>,

    // Saved outcome of extraction
    extracted_patch_digest: Option<String>,

    // Collected grader results for verdict assembly
    r0_result: Option<R0Result>,
    r1_result: Option<R1Result>,
    r2_result: Option<R2Result>,
    r3_result: Option<R3Result>,

    // Pluggable runner builder for offline testing against process boundaries
    runner_factory: Option<RunnerFactory>,

    // Configured agent mode
    agent_mode: Option<AgentMode>,

    // Resolved AgentVM resource limits
    agent_vcpus: u8,
    agent_memory_mib: u32,
}

impl VmmInfra {
    /// Creates a new `VmmInfra` from explicit paths.
    pub fn new(
        fc_bin: PathBuf,
        kernel_image: PathBuf,
        rootfs_image: PathBuf,
        netvm_rootfs: Option<PathBuf>,
        run_dir: PathBuf,
        lock_file: Option<PathBuf>,
    ) -> Self {
        Self {
            fc_bin,
            kernel_image,
            rootfs_image,
            netvm_rootfs,
            run_dir,
            lock_file,
            python_launcher: None,
            sealed_world: None,
            t_clock: DEFAULT_T_CLOCK,
            task_id: "unknown-task".to_string(),
            task_class: "patch".to_string(),
            active_vms: BTreeMap::new(),
            extracted_patch_digest: None,
            r0_result: None,
            r1_result: None,
            r2_result: None,
            r3_result: None,
            runner_factory: None,
            agent_mode: None,
            agent_vcpus: 1,
            agent_memory_mib: 2048,
        }
    }

    /// Creates `VmmInfra` reading paths from environment variables.
    pub fn from_env_with_run_dir(run_dir: PathBuf) -> Result<Self, InfraError> {
        let fc = std::env::var_os("HERMETIC_FC_BIN").ok_or_else(|| InfraError::BackendFailure {
            step: Step::PrepareWorld,
            detail: "HERMETIC_FC_BIN must be set".to_string(),
        })?;
        let kernel =
            std::env::var_os("HERMETIC_KERNEL").ok_or_else(|| InfraError::BackendFailure {
                step: Step::PrepareWorld,
                detail: "HERMETIC_KERNEL must be set".to_string(),
            })?;
        let rootfs =
            std::env::var_os("HERMETIC_ROOTFS").ok_or_else(|| InfraError::BackendFailure {
                step: Step::PrepareWorld,
                detail: "HERMETIC_ROOTFS must be set".to_string(),
            })?;
        let netvm = std::env::var_os("HERMETIC_NETVM_ROOTFS").map(PathBuf::from);
        let lock = std::env::var_os("HERMETIC_FIRECRACKER_LOCK").map(PathBuf::from);

        Ok(Self::new(
            PathBuf::from(fc),
            PathBuf::from(kernel),
            PathBuf::from(rootfs),
            netvm,
            run_dir,
            lock,
        ))
    }

    /// Injects a custom runner factory for offline tests.
    pub fn with_runner_factory(
        mut self,
        factory: impl Fn(&VmSpec) -> Result<Box<dyn Runner>, InfraError> + Send + Sync + 'static,
    ) -> Self {
        self.runner_factory = Some(Box::new(factory));
        self
    }

    /// Sets a pre-configured python launcher path.
    pub fn with_python_launcher(mut self, launcher: PathBuf) -> Self {
        self.python_launcher = Some(launcher);
        self
    }

    /// Sets explicit clock for testing.
    pub fn with_clock(mut self, t_clock: i64) -> Self {
        self.t_clock = t_clock;
        self
    }

    /// Sets explicit agent mode.
    pub fn with_agent_mode(mut self, mode: AgentMode) -> Self {
        self.agent_mode = Some(mode);
        self
    }

    /// Sets explicit agent resources for testing.
    pub fn with_agent_resources(mut self, vcpus: u8, memory_mib: u32) -> Self {
        self.agent_vcpus = vcpus;
        self.agent_memory_mib = memory_mib;
        self
    }

    fn check_step_deadline(
        &self,
        step: Step,
        deadline_spec: &NamedDeadline,
    ) -> Result<Instant, InfraError> {
        // Step deadline is checked against standard timeout duration
        let timeout = Duration::from_millis(deadline_spec.deadline_ms.max(100));
        deadline(timeout).map_err(|_| InfraError::DeadlineExceeded {
            step,
            deadline_name: deadline_spec.name.clone(),
        })
    }

    fn build_runner(&self, spec: &VmSpec, step: Step) -> Result<Box<dyn Runner>, InfraError> {
        if let Some(ref factory) = self.runner_factory {
            return factory(spec);
        }

        #[cfg(feature = "dev-unjailed")]
        {
            let launcher_path = if let Some(ref p) = self.python_launcher {
                p.clone()
            } else {
                let p = self.run_dir.join("exec-python");
                if !p.exists() {
                    let py = std::fs::canonicalize("/usr/bin/python3").map_err(|e| {
                        InfraError::BackendFailure {
                            step,
                            detail: format!("canonicalize python: {e}"),
                        }
                    })?;
                    std::fs::copy(&py, &p).map_err(|e| InfraError::BackendFailure {
                        step,
                        detail: format!("copy python launcher: {e}"),
                    })?;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o500)).map_err(
                        |e| InfraError::BackendFailure {
                            step,
                            detail: format!("set permissions on launcher: {e}"),
                        },
                    )?;
                }
                p
            };
            let runner = crate::runner::DevUnjailed::new(
                launcher_path.to_str().unwrap_or("/usr/bin/python3"),
            )
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("DevUnjailed runner creation failed: {e}"),
            })?;
            Ok(Box::new(runner))
        }

        #[cfg(not(feature = "dev-unjailed"))]
        {
            if rustix::process::geteuid().is_root() {
                let py = self
                    .python_launcher
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "/usr/bin/python3".to_string());
                let runner = crate::runner::JailerRunner::new(&py).map_err(|e| {
                    InfraError::BackendFailure {
                        step,
                        detail: format!("JailerRunner creation failed: {e}"),
                    }
                })?;
                return Ok(Box::new(runner));
            }
            Err(InfraError::BackendFailure {
                step,
                detail: "no microVM runner available: dev-unjailed feature disabled and not root"
                    .to_string(),
            })
        }
    }

    fn create_jail_config(&self, vm_id: &str) -> JailConfig {
        let jail_dir = self.run_dir.join(format!("jail-{}", vm_id));
        let _ = fs::create_dir_all(&jail_dir);
        let _ = fs::set_permissions(&jail_dir, fs::Permissions::from_mode(0o700));
        JailConfig {
            base: jail_dir.display().to_string(),
            uid_start: 200000,
            gid_start: 200000,
            count: 16,
            firecracker: self.fc_bin.display().to_string(),
            jailer: "/bin/jailer".into(),
            netns: "isolated-0".into(),
        }
    }
}

impl Infra for VmmInfra {
    fn prepare_world(
        &mut self,
        world: &WorldSpec,
        deadline_spec: &NamedDeadline,
    ) -> Result<PreparedWorld, InfraError> {
        let step = Step::PrepareWorld;
        let _end = self.check_step_deadline(step, deadline_spec)?;

        let sealed_path = PathBuf::from(&world.cutoff_seal);
        let meta = fs::symlink_metadata(&sealed_path).map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("lstat sealed world failed: {e}"),
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(InfraError::BackendFailure {
                step,
                detail: "sealed world path must be a regular directory, not a symlink".to_string(),
            });
        }

        if let Some(ref lock) = self.lock_file {
            if !lock.exists() {
                return Err(InfraError::BackendFailure {
                    step,
                    detail: "firecracker lock file does not exist".to_string(),
                });
            }
        }

        self.sealed_world = Some(sealed_path.clone());
        self.task_id = world.world_id.clone();

        // 1. If bundle.manifest.json exists in sealed_path, verify it matches
        let bundle_manifest_path = sealed_path.join(BUNDLE_MANIFEST_FILENAME);
        if bundle_manifest_path.exists() {
            let report = hermetic_bundle::verify(&sealed_path, None).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("sealed world bundle verification failed: {e}"),
                }
            })?;
            if report.verdict != BundleVerdict::Ok || !report.manifest_root_matches {
                return Err(InfraError::BackendFailure {
                    step,
                    detail: "sealed world bundle verification failed: bundle does not match"
                        .to_string(),
                });
            }
        }

        // 2. Load and validate canonical WorldManifest from sealed_path/world_manifest.json
        let manifest_file = sealed_path.join("world_manifest.json");
        if !manifest_file.exists() {
            return Err(InfraError::BackendFailure {
                step,
                detail: "world_manifest.json does not exist in sealed world".to_string(),
            });
        }
        let m_meta =
            fs::symlink_metadata(&manifest_file).map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("lstat world_manifest.json failed: {e}"),
            })?;
        if m_meta.file_type().is_symlink() || !m_meta.file_type().is_file() {
            return Err(InfraError::BackendFailure {
                step,
                detail: "world_manifest.json must be a regular file".to_string(),
            });
        }
        if m_meta.len() > MAX_MANIFEST_BYTES as u64 {
            return Err(InfraError::BackendFailure {
                step,
                detail: "world_manifest.json exceeds size cap".to_string(),
            });
        }
        let manifest_file_fd =
            fs::File::open(&manifest_file).map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("open world_manifest.json failed: {e}"),
            })?;
        let mut bytes = Vec::new();
        manifest_file_fd
            .take((MAX_MANIFEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("read world_manifest.json failed: {e}"),
            })?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(InfraError::BackendFailure {
                step,
                detail: "world_manifest.json exceeds size cap".to_string(),
            });
        }
        let canonical = WorldManifest::from_json_str(std::str::from_utf8(&bytes).map_err(|e| {
            InfraError::BackendFailure {
                step,
                detail: format!("world_manifest.json is not valid UTF-8: {e}"),
            }
        })?)
        .map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("invalid canonical WorldManifest: {e}"),
        })?;

        // 3. Compute Merkle world_root from the verified canonical manifest
        let world_root_str = canonical
            .world_root()
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("failed to compute world root: {e}"),
            })?;
        let world_root_digest =
            Digest::parse(&world_root_str).map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("invalid world root digest: {e}"),
            })?;

        // 4. Update t_clock and task_class from canonical manifest
        if let Ok(dt) = time::OffsetDateTime::parse(
            &canonical.cutoffs.t_clock,
            &time::format_description::well_known::Rfc3339,
        ) {
            self.t_clock = dt.unix_timestamp();
        } else if let Ok(parsed) = canonical.cutoffs.t_clock.parse::<i64>() {
            self.t_clock = parsed;
        }
        self.task_class = match canonical.task_class {
            CommonTaskClass::Dated | CommonTaskClass::Undated => "patch".to_string(),
        };

        // 5. Prepare overlay image in run_dir for AgentVM if not already present
        let overlay_path = self.run_dir.join("agent_overlay.img");
        if !overlay_path.exists() {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&overlay_path)
                .map_err(|e| InfraError::BackendFailure {
                    step,
                    detail: format!("failed to create agent overlay: {e}"),
                })?;
            file.set_len(64 * 1024 * 1024)
                .map_err(|e| InfraError::BackendFailure {
                    step,
                    detail: format!("failed to set agent overlay len: {e}"),
                })?;
        }

        // 6. Prepare CPU template file in run_dir matching embedded clock-3b template
        let template_path = self.run_dir.join("cpu-template.json");
        if !template_path.exists() {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&template_path)
                .map_err(|e| InfraError::BackendFailure {
                    step,
                    detail: format!("failed to create cpu-template.json: {e}"),
                })?;
            file.write_all(crate::plan::CPU_TEMPLATE.as_bytes())
                .map_err(|e| InfraError::BackendFailure {
                    step,
                    detail: format!("failed to write cpu-template.json: {e}"),
                })?;
        }

        // 7. Prepare VM configuration descriptor in run_dir
        self.agent_vcpus = u8::try_from(canonical.run_spec.resources.vcpus).map_err(|_| {
            InfraError::BackendFailure {
                step,
                detail: format!(
                    "vcpus {} exceeds u8 max",
                    canonical.run_spec.resources.vcpus
                ),
            }
        })?;
        self.agent_memory_mib =
            u32::try_from(canonical.run_spec.resources.memory_mib).map_err(|_| {
                InfraError::BackendFailure {
                    step,
                    detail: format!(
                        "memory_mib {} exceeds u32 max",
                        canonical.run_spec.resources.memory_mib
                    ),
                }
            })?;
        let vm_config_path = self.run_dir.join("vm-config.json");
        if !vm_config_path.exists() {
            let vm_cfg = serde_json::json!({
                "cpu_template": "cpu-template.json",
                "vcpus": self.agent_vcpus,
                "mem_size_mib": self.agent_memory_mib,
                "disk_mib": canonical.run_spec.resources.disk_mib,
            });
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&vm_config_path)
                .map_err(|e| InfraError::BackendFailure {
                    step,
                    detail: format!("failed to create vm-config.json: {e}"),
                })?;
            file.write_all(serde_json::to_string_pretty(&vm_cfg).unwrap().as_bytes())
                .map_err(|e| InfraError::BackendFailure {
                    step,
                    detail: format!("failed to write vm-config.json: {e}"),
                })?;
        }

        // 8. Compute deployment digests from actual files the run uses (never read from sealed manifest):
        let task_rootfs_hex = safe_sha256_file(&self.rootfs_image, 64 * 1024 * 1024 * 1024)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("failed to compute task_rootfs digest: {e}"),
            })?;
        let task_rootfs_digest =
            Digest::parse(&format!("sha256:{task_rootfs_hex}")).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("invalid task_rootfs digest: {e}"),
                }
            })?;

        let guest_kernel_hex =
            safe_sha256_file(&self.kernel_image, 1024 * 1024 * 1024).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("failed to compute guest_kernel digest: {e}"),
                }
            })?;
        let guest_kernel_digest =
            Digest::parse(&format!("sha256:{guest_kernel_hex}")).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("invalid guest_kernel digest: {e}"),
                }
            })?;

        let netvm_image_digest = if let Some(ref netvm) = self.netvm_rootfs {
            let hex = safe_sha256_file(netvm, 64 * 1024 * 1024 * 1024).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("failed to compute netvm digest: {e}"),
                }
            })?;
            Digest::parse(&format!("sha256:{hex}")).map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("invalid netvm digest: {e}"),
            })?
        } else {
            Digest::from_sha256(&[])
        };

        let fc_build_path = if self.run_dir.join("firecracker_build.json").exists() {
            self.run_dir.join("firecracker_build.json")
        } else if let Some(ref lock) = self.lock_file {
            lock.clone()
        } else {
            self.fc_bin.clone()
        };
        let fc_build_hex = safe_sha256_file(&fc_build_path, 256 * 1024 * 1024).map_err(|e| {
            InfraError::BackendFailure {
                step,
                detail: format!("failed to compute firecracker_build digest: {e}"),
            }
        })?;
        let firecracker_build_digest =
            Digest::parse(&format!("sha256:{fc_build_hex}")).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("invalid firecracker_build digest: {e}"),
                }
            })?;

        let cpu_template_hex = safe_sha256_file(&template_path, 16 * 1024 * 1024).map_err(|e| {
            InfraError::BackendFailure {
                step,
                detail: format!("failed to compute cpu_template digest: {e}"),
            }
        })?;
        let cpu_template_digest =
            Digest::parse(&format!("sha256:{cpu_template_hex}")).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("invalid cpu_template digest: {e}"),
                }
            })?;

        let vm_config_hex = safe_sha256_file(&vm_config_path, 16 * 1024 * 1024).map_err(|e| {
            InfraError::BackendFailure {
                step,
                detail: format!("failed to compute vm_config digest: {e}"),
            }
        })?;
        let vm_config_digest = Digest::parse(&format!("sha256:{vm_config_hex}")).map_err(|e| {
            InfraError::BackendFailure {
                step,
                detail: format!("invalid vm_config digest: {e}"),
            }
        })?;

        let agent_volume_hex =
            safe_sha256_file(&overlay_path, 1024 * 1024 * 1024).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("failed to compute agent_volume digest: {e}"),
                }
            })?;
        let agent_volume_digest =
            Digest::parse(&format!("sha256:{agent_volume_hex}")).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("invalid agent_volume digest: {e}"),
                }
            })?;

        let sealcheck_report_digest =
            Digest::parse(&canonical.sealcheck_report_digest).map_err(|e| {
                InfraError::BackendFailure {
                    step,
                    detail: format!("invalid sealcheck_report digest: {e}"),
                }
            })?;

        let task_class = match canonical.task_class {
            CommonTaskClass::Dated | CommonTaskClass::Undated => AttestTaskClass::Patch,
        };
        let seal_level = match canonical.seal_level {
            CommonSealLevel::RepoOnly => AttestSealLevel::RepoOnly,
            CommonSealLevel::Strict => AttestSealLevel::Strict,
        };
        let (substrate_at_t, substrate_str) = match canonical.substrate_at_t {
            CommonSubstrateAtT::Full => (AttestSubstrateAtT::Full, "full"),
            CommonSubstrateAtT::Partial => (AttestSubstrateAtT::Partial, "partial"),
            CommonSubstrateAtT::None => (AttestSubstrateAtT::None, "none"),
        };

        let agent_mode = match self.agent_mode {
            Some(AgentMode::HarnessDriven { .. }) => AttestAgentMode::H,
            Some(AgentMode::GuestAutonomous { .. }) => AttestAgentMode::G,
            None => {
                if self.run_dir.join("gateway_head.json").exists()
                    || self.run_dir.join("gateway_history.json").exists()
                {
                    AttestAgentMode::G
                } else {
                    AttestAgentMode::H
                }
            }
        };

        // 9. Build WorldManifestArtifact for run_dir
        let run_manifest = WorldManifestArtifact {
            task_id: canonical.task_id.clone(),
            task_class,
            seal_level,
            agent_mode,
            substrate: Some(substrate_str.to_string()),
            grader_isolation: GraderIsolation::Clean,
            deployment: Deployment::SingleHost,
            t_world: canonical.cutoffs.t_world.clone(),
            t_clock: canonical.cutoffs.t_clock.clone(),
            base_commit: canonical.cutoffs.base_commit.clone().unwrap_or_default(),
            pkg_cutoff: Some(canonical.cutoffs.pkg_cutoff.clone()),
            spec_version: Some(canonical.spec_version.clone()),
            world_version: world_root_digest.clone(),
            sealcheck_version: "v1.0".to_string(),
            grader_image_digest: task_rootfs_digest.clone(),
            world_root: world_root_digest,
            task_rootfs_digest,
            netvm_image_digest,
            guest_kernel_digest,
            vm_config_digest,
            cpu_template_digest,
            firecracker_build_digest,
            agent_volume_digest,
            sealcheck_report_digest,
            substrate_at_t,
            exemption_list: canonical
                .exemptions
                .iter()
                .map(|e| e.package.clone())
                .collect(),
            d5b_warning_list: None,
            world_server_log_head: Digest::from_sha256(&[]),
            dedupe_index_digest: Digest::from_sha256(&[]),
            request_count: 0,
            harness_command_log_head: None,
            gateway_log_head: None,
            history_rewrite_count: None,
            gateway_adapter_version: None,
            tee_quote: None,
        };

        let run_manifest_json =
            serde_json::to_vec_pretty(&run_manifest).map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("failed to serialize WorldManifestArtifact: {e}"),
            })?;

        safe_atomic_write_file(
            &self.run_dir.join("world_manifest.json"),
            &run_manifest_json,
        )
        .map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("failed to write run world_manifest.json: {e}"),
        })?;

        Ok(PreparedWorld {
            world_id: world.world_id.clone(),
            image_digest: format!("sha256:{task_rootfs_hex}"),
        })
    }

    fn start_netvm(
        &mut self,
        _world: &PreparedWorld,
        deadline_spec: &NamedDeadline,
    ) -> Result<VmHandle, InfraError> {
        let step = Step::StartNetVm;
        let _end = self.check_step_deadline(step, deadline_spec)?;

        let handle = VmHandle::new("net-vm-0", VmKind::Net);
        self.active_vms.insert(
            handle.id.clone(),
            ActiveVm {
                kind: VmKind::Net,
                vmm: None,
                vsock_path: None,
                result_disk: None,
            },
        );
        Ok(handle)
    }

    fn start_agentvm(
        &mut self,
        _world: &PreparedWorld,
        _net_vm: &VmHandle,
        deadline_spec: &NamedDeadline,
    ) -> Result<VmHandle, InfraError> {
        let step = Step::StartAgentVm;
        let end = self.check_step_deadline(step, deadline_spec)?;

        let vm_id = "agent-vm-0";
        let overlay_path = self.run_dir.join("agent_overlay.img");
        let spec = VmSpec {
            id: vm_id.into(),
            role: Role::Agent,
            index: 0,
            vcpus: self.agent_vcpus,
            memory_mib: self.agent_memory_mib,
            kernel_image: self.kernel_image.display().to_string(),
            initrd: None,
            boot_args: format!(
                "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda init=/sbin/hermetic-init clocksource=tsc tsc=reliable hermetic.t={} ro",
                self.t_clock
            ),
            root_drive: Drive {
                id: "rootfs".into(),
                path: self.rootfs_image.display().to_string(),
                read_only: true,
            },
            drives: vec![Drive {
                id: "overlay".into(),
                path: overlay_path.display().to_string(),
                read_only: false,
            }],
            reserved_drives: vec![],
            vsock: Some(Vsock {
                guest_cid: 3,
                socket_path: "/vsock".into(),
            }),
            networks: if self.netvm_rootfs.is_some() {
                vec![Network {
                    tap: "agent-tap".into(),
                    guest_mac: project_mac(Role::Agent, 0),
                    peer: Role::Net,
                }]
            } else {
                vec![]
            },
            cpu_template: self.run_dir.join("cpu-template.json").display().to_string(),
            clock: VmClock::Faked,
            limits: Limits {
                pids: 128,
                file_size_bytes: 1024 * 1024 * 1024,
                open_files: 128,
            },
            jail: self.create_jail_config(vm_id),
        };

        let runner = self.build_runner(&spec, step)?;
        let validated = spec.validate().map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("agent VMM spec validation failed: {e}"),
        })?;
        let mut v = Vmm::new(validated, runner);
        let prep_timeout = remaining(end, "prepare").unwrap_or(Duration::from_secs(10));
        v.prepare(prep_timeout)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("agent VMM prepare failed: {e}"),
            })?;
        let start_timeout = remaining(end, "start").unwrap_or(Duration::from_secs(5));
        v.start(start_timeout)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("agent VMM start failed: {e}"),
            })?;
        let ready_timeout = remaining(end, "wait-ready").unwrap_or(Duration::from_secs(5));
        v.wait_ready(ready_timeout)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("agent VMM wait_ready failed: {e}"),
            })?;

        // Determine vsock address for in-process or child communication
        let vsock_path = {
            let real_path = v.jail().map(|jail| {
                crate::exec_client::vsock_socket_path(&jail.root.descriptor_path("vsock"))
            });
            if real_path
                .as_ref()
                .map(|p| std::path::Path::new(p).exists())
                .unwrap_or(false)
            {
                real_path
            } else {
                let fake_sock = self.run_dir.join("vsock.socket");
                if fake_sock.exists() {
                    Some(fake_sock.display().to_string())
                } else {
                    real_path
                }
            }
        };
        let vmm = Some(v);

        // Record boot_record.json if not present
        let boot_rec_path = self.run_dir.join("boot_record.json");
        if !boot_rec_path.exists() {
            let boot_record = serde_json::json!({
                "vm_id": vm_id,
                "boot_path": "sealed_disk",
            });
            if let Ok(bytes) = serde_json::to_vec_pretty(&boot_record) {
                let _ = fs::write(&boot_rec_path, bytes);
            }
        }

        let handle = VmHandle::new(vm_id, VmKind::Agent);
        self.active_vms.insert(
            handle.id.clone(),
            ActiveVm {
                kind: VmKind::Agent,
                vmm,
                vsock_path,
                result_disk: None,
            },
        );

        Ok(handle)
    }

    fn wait_agent_ready(
        &mut self,
        agent_vm: &VmHandle,
        deadline_spec: &NamedDeadline,
    ) -> Result<(), InfraError> {
        let step = Step::WaitAgentReady;
        let end = self.check_step_deadline(step, deadline_spec)?;

        let vm = self
            .active_vms
            .get(&agent_vm.id)
            .ok_or_else(|| InfraError::VmNotFound {
                vm_id: agent_vm.id.clone(),
            })?;
        if vm.kind != VmKind::Agent {
            return Err(InfraError::InvalidVmKind {
                expected: VmKind::Agent,
                actual: vm.kind,
            });
        }

        if let Some(ref sock) = vm.vsock_path {
            loop {
                if Instant::now() >= end {
                    return Err(InfraError::DeadlineExceeded {
                        step,
                        deadline_name: deadline_spec.name.clone(),
                    });
                }
                match crate::exec_client::check_status(sock, self.t_clock, end) {
                    Ok(_) => return Ok(()),
                    Err(crate::Error::Deadline(_)) => {
                        return Err(InfraError::DeadlineExceeded {
                            step,
                            deadline_name: deadline_spec.name.clone(),
                        });
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }

        Ok(())
    }

    fn run_agent(
        &mut self,
        agent_vm: &VmHandle,
        mode: &AgentMode,
        deadline_spec: &NamedDeadline,
    ) -> Result<AgentOutcome, InfraError> {
        let step = Step::RunAgent;
        let end = self.check_step_deadline(step, deadline_spec)?;

        let vm = self
            .active_vms
            .get(&agent_vm.id)
            .ok_or_else(|| InfraError::VmNotFound {
                vm_id: agent_vm.id.clone(),
            })?;
        if vm.kind != VmKind::Agent {
            return Err(InfraError::InvalidVmKind {
                expected: VmKind::Agent,
                actual: vm.kind,
            });
        }

        if let Some(ref sock) = vm.vsock_path {
            match mode {
                AgentMode::HarnessDriven { commands } => {
                    if commands.is_empty() {
                        return Ok(AgentOutcome::Completed { exit_code: 0 });
                    }
                    for cmd in commands {
                        if Instant::now() >= end {
                            return Err(InfraError::DeadlineExceeded {
                                step,
                                deadline_name: deadline_spec.name.clone(),
                            });
                        }
                        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), cmd.clone()];
                        let res = crate::exec_client::exec(sock, &argv, false, 30_000, end)
                            .map_err(|e| InfraError::BackendFailure {
                                step,
                                detail: format!("exec command failed: {e}"),
                            })?;
                        if res.timed_out {
                            return Ok(AgentOutcome::LimitExceeded {
                                kind: LimitKind::Quota,
                                detail: format!("command '{cmd}' timed out"),
                            });
                        }
                        if let Some(code) = res.code {
                            if code != 0 {
                                return Ok(AgentOutcome::Completed { exit_code: code });
                            }
                        }
                    }
                    Ok(AgentOutcome::Completed { exit_code: 0 })
                }
                AgentMode::GuestAutonomous { entrypoint } => {
                    let argv = vec![entrypoint.clone()];
                    let res = crate::exec_client::exec(sock, &argv, false, 300_000, end).map_err(
                        |e| InfraError::BackendFailure {
                            step,
                            detail: format!("entrypoint exec failed: {e}"),
                        },
                    )?;
                    if res.timed_out {
                        return Ok(AgentOutcome::LimitExceeded {
                            kind: LimitKind::Quota,
                            detail: "agent entrypoint timed out".to_string(),
                        });
                    }
                    Ok(AgentOutcome::Completed {
                        exit_code: res.code.unwrap_or(0),
                    })
                }
            }
        } else {
            Ok(AgentOutcome::Completed { exit_code: 0 })
        }
    }

    fn shutdown_agent(
        &mut self,
        agent_vm: &VmHandle,
        deadline_spec: &NamedDeadline,
    ) -> Result<ShutdownKind, InfraError> {
        let step = Step::ShutdownAgent;
        let end = self.check_step_deadline(step, deadline_spec)?;

        let vm = self
            .active_vms
            .get_mut(&agent_vm.id)
            .ok_or_else(|| InfraError::VmNotFound {
                vm_id: agent_vm.id.clone(),
            })?;
        if vm.kind != VmKind::Agent {
            return Err(InfraError::InvalidVmKind {
                expected: VmKind::Agent,
                actual: vm.kind,
            });
        }

        let mut clean = true;
        if let Some(ref sock) = vm.vsock_path {
            if crate::exec_client::shutdown(sock, end).is_err() {
                clean = false;
            }
        }

        if let Some(ref mut vmm) = vm.vmm {
            if vmm.stop(Duration::from_secs(5)).is_err() {
                clean = false;
            }
        }

        Ok(if clean {
            ShutdownKind::Clean
        } else {
            ShutdownKind::Unclean
        })
    }

    fn destroy_vm(
        &mut self,
        vm: &VmHandle,
        deadline_spec: &NamedDeadline,
    ) -> Result<(), InfraError> {
        let step = match vm.kind {
            VmKind::Agent => Step::DestroyAgentVm,
            VmKind::Net => Step::DestroyNetVm,
            _ => Step::DestroyNetVm,
        };
        let _end = self.check_step_deadline(step, deadline_spec)?;

        if let Some(mut active) = self.active_vms.remove(&vm.id) {
            if let Some(ref mut vmm) = active.vmm {
                let _ = vmm.destroy(Duration::from_secs(5));
            }
        }

        Ok(())
    }

    fn run_extractor(
        &mut self,
        _world: &PreparedWorld,
        deadline_spec: &NamedDeadline,
    ) -> Result<ExtractorOutcome, InfraError> {
        let step = Step::RunExtractor;
        let end = self.check_step_deadline(step, deadline_spec)?;

        let overlay_src = self.run_dir.join("agent_overlay.img");
        let overlay_cow = self.run_dir.join("extractor_overlay_cow.img");
        let output_drive = self.run_dir.join("extractor_output.img");

        // Refuse symlink or non-existent overlay
        if !overlay_src.exists() {
            return Err(InfraError::BackendFailure {
                step,
                detail: "missing agent overlay image for extraction".to_string(),
            });
        }

        // Clean up any stale destination files
        if overlay_cow.exists() {
            let _ = fs::remove_file(&overlay_cow);
        }
        if output_drive.exists() {
            let _ = fs::remove_file(&output_drive);
        }

        // 1. Create copy-on-write copy of the agent overlay
        create_overlay_cow_copy(&overlay_src, &overlay_cow).map_err(|e| {
            InfraError::BackendFailure {
                step,
                detail: format!("create_overlay_cow_copy failed: {e:?}"),
            }
        })?;

        // 2. Create fresh output drive
        create_fresh_output_drive(&output_drive, DEFAULT_OUTPUT_DRIVE_BYTES).map_err(|e| {
            InfraError::BackendFailure {
                step,
                detail: format!("create_fresh_output_drive failed: {e:?}"),
            }
        })?;

        // 3. Generate run nonce
        let nonce = generate_run_nonce().map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("generate_run_nonce failed: {e}"),
        })?;

        // 4. Generate ExtractorVM spec
        let vm_id = "extractor-vm-0";
        let task_class_str = if self.task_class == "patch" {
            "patch:".to_string()
        } else if self.task_class.starts_with("patch:")
            || self.task_class.starts_with("artifact:")
            || self.task_class == "state"
        {
            self.task_class.clone()
        } else {
            format!("patch:{}", self.task_class)
        };
        let host_class = hermetic_extract::config::parse_task_class_spec(&task_class_str)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("invalid task class: {e}"),
            })?
            .class_kind();

        let config = ExtractorVmConfig {
            vm_id: vm_id.into(),
            index: 0,
            extractor_image: self.rootfs_image.display().to_string(),
            kernel_image: self.kernel_image.display().to_string(),
            base_drive: self.rootfs_image.display().to_string(),
            overlay_cow_drive: overlay_cow.display().to_string(),
            output_drive: output_drive.display().to_string(),
            task_class: task_class_str,
            run_nonce: nonce,
            t_clock: self.t_clock as u64,
            vcpus: 1,
            memory_mib: 1024,
            cpu_template: self.run_dir.join("cpu-template.json").display().to_string(),
            jail: self.create_jail_config(vm_id),
        };

        let spec = extractor_spec(&config).map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("extractor_spec generation failed: {e}"),
        })?;

        let runner = self.build_runner(&spec, step)?;
        let validated = spec.validate().map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("extractor_spec validation failed: {e}"),
        })?;
        let mut vmm = Vmm::new(validated, runner);
        let prep_time = remaining(end, "prepare").unwrap_or(Duration::from_secs(10));
        vmm.prepare(prep_time)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("extractor VMM prepare failed: {e}"),
            })?;
        let start_time = remaining(end, "start").unwrap_or(Duration::from_secs(5));
        vmm.start(start_time)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("extractor VMM start failed: {e}"),
            })?;
        let ready_time = remaining(end, "wait-ready").unwrap_or(Duration::from_secs(5));
        vmm.wait_ready(ready_time)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("extractor VMM wait_ready failed: {e}"),
            })?;
        let exit_time = remaining(end, "wait-exit").unwrap_or(Duration::from_secs(60));
        vmm.wait_exit(exit_time)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("extractor VMM wait_exit failed: {e}"),
            })?;
        let _ = vmm.destroy(Duration::from_secs(5));

        // 5. Parse output drive using read_extractor_output
        let base_dir = self.run_dir.join("extracted_base");
        let out_dir = self.run_dir.join("extracted_work");
        let _ = fs::create_dir_all(&base_dir);
        let _ = fs::create_dir_all(&out_dir);

        let extract_cfg = hermetic_extract::config::ExtractConfig::default();

        // If the output drive does not exist or fails closed, report specific failure
        let outcome = read_extractor_output(
            &output_drive,
            &nonce,
            &base_dir,
            &out_dir,
            host_class,
            &extract_cfg,
        )
        .map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("read_extractor_output failed: {e:?}"),
        })?;

        // If submitted_work.patch was generated in out_dir, move/copy it to run_dir
        let patch_candidate = out_dir.join("submitted_work.patch");
        let run_patch = self.run_dir.join("submitted_work.patch");
        if run_patch.exists() {
            return Err(InfraError::BackendFailure {
                step,
                detail: "submitted_work.patch already exists in the run directory; refusing to keep a patch the extractor did not produce".to_string(),
            });
        }
        if patch_candidate.exists() {
            fs::copy(&patch_candidate, &run_patch).map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("copying the extracted patch into the run directory failed: {e}"),
            })?;
        }

        self.extracted_patch_digest = Some(outcome.patch_digest.clone());
        Ok(outcome)
    }

    fn start_grader(
        &mut self,
        run_name: GraderRun,
        _world: &PreparedWorld,
        _extracted: &ExtractorOutcome,
        deadline_spec: &NamedDeadline,
    ) -> Result<GraderHandle, InfraError> {
        let step = Step::RunGrader(run_name);
        let end = self.check_step_deadline(step, deadline_spec)?;

        let vm_id = format!("grader-vm-{}", run_name.as_str().to_ascii_lowercase());
        let result_disk_path = self
            .run_dir
            .join(format!("grader_result_{}.img", run_name.as_str()));

        // Format 1 MiB raw result drive with HGRL header and run label
        if result_disk_path.exists() {
            let _ = fs::remove_file(&result_disk_path);
        }
        let run_label = match run_name {
            GraderRun::R0 | GraderRun::Base => "R0",
            GraderRun::R1 => "R1",
            GraderRun::R2 => "R2",
            GraderRun::R3 => "R3",
            GraderRun::Gold => "R0",
        };
        let mut initial_image = RUN_LABEL_MAGIC_VERSION.to_vec();
        initial_image.extend_from_slice(run_label.as_bytes());
        initial_image.resize(DISK_BYTES, 0);

        fs::write(&result_disk_path, &initial_image).map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("failed to initialize grader result drive: {e}"),
        })?;
        fs::set_permissions(&result_disk_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            InfraError::BackendFailure {
                step,
                detail: format!("failed to set grader result drive permissions: {e}"),
            }
        })?;

        let spec = VmSpec {
            id: vm_id.clone(),
            role: Role::Grader,
            index: 0,
            vcpus: 1,
            memory_mib: 1024,
            kernel_image: self.kernel_image.display().to_string(),
            initrd: None,
            boot_args: format!(
                "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda init=/sbin/hermetic-grader-init clocksource=tsc tsc=reliable hermetic.t={} ro",
                self.t_clock
            ),
            root_drive: Drive {
                id: "rootfs".into(),
                path: self.rootfs_image.display().to_string(),
                read_only: true,
            },
            drives: vec![
                Drive {
                    id: GRADER_RESULT_DRIVE.into(),
                    path: result_disk_path.display().to_string(),
                    read_only: false,
                },
                Drive {
                    id: "tests".into(),
                    path: self.rootfs_image.display().to_string(),
                    read_only: true,
                },
            ],
            reserved_drives: vec![],
            vsock: None,
            networks: vec![],
            cpu_template: self.run_dir.join("cpu-template.json").display().to_string(),
            clock: VmClock::Faked,
            limits: Limits {
                pids: 128,
                file_size_bytes: 1024 * 1024 * 1024,
                open_files: 128,
            },
            jail: self.create_jail_config(&vm_id),
        };

        let runner = self.build_runner(&spec, step)?;
        let validated = spec.validate().map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("grader VMM spec validation failed: {e}"),
        })?;
        let mut v = Vmm::new(validated, runner);
        let prep_time = remaining(end, "prepare").unwrap_or(Duration::from_secs(10));
        v.prepare(prep_time)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("grader VMM prepare failed: {e}"),
            })?;
        let start_time = remaining(end, "start").unwrap_or(Duration::from_secs(5));
        v.start(start_time)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("grader VMM start failed: {e}"),
            })?;
        let ready_time = remaining(end, "wait-ready").unwrap_or(Duration::from_secs(5));
        v.wait_ready(ready_time)
            .map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("grader VMM wait_ready failed: {e}"),
            })?;
        let vmm = Some(v);

        let handle = GraderHandle {
            run: run_name,
            vm: VmHandle::new(vm_id, VmKind::Grader),
        };

        self.active_vms.insert(
            handle.vm.id.clone(),
            ActiveVm {
                kind: VmKind::Grader,
                vmm,
                vsock_path: None,
                result_disk: Some(result_disk_path),
            },
        );

        Ok(handle)
    }

    fn finish_grader(
        &mut self,
        handle: GraderHandle,
        deadline_spec: &NamedDeadline,
    ) -> Result<GraderOutcome, InfraError> {
        let step = Step::RunGrader(handle.run);
        let end = self.check_step_deadline(step, deadline_spec)?;

        let mut vm =
            self.active_vms
                .remove(&handle.vm.id)
                .ok_or_else(|| InfraError::VmNotFound {
                    vm_id: handle.vm.id.clone(),
                })?;

        if let Some(ref mut vmm) = vm.vmm {
            let wait_time = remaining(end, "wait-exit").unwrap_or(Duration::from_secs(60));
            vmm.wait_exit(wait_time)
                .map_err(|e| InfraError::BackendFailure {
                    step,
                    detail: format!("grader VMM wait_exit failed: {e}"),
                })?;
            let _ = vmm.destroy(Duration::from_secs(5));
        }

        let result_disk_path = vm.result_disk.ok_or_else(|| InfraError::BackendFailure {
            step,
            detail: "missing grader result disk path".to_string(),
        })?;

        let meta =
            fs::symlink_metadata(&result_disk_path).map_err(|e| InfraError::BackendFailure {
                step,
                detail: format!("lstat grader result drive failed: {e}"),
            })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(InfraError::BackendFailure {
                step,
                detail: "grader result drive must be a regular file, not a symlink".to_string(),
            });
        }

        let disk_bytes = fs::read(&result_disk_path).map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("read grader result drive failed: {e}"),
        })?;
        if disk_bytes.len() != DISK_BYTES {
            return Err(InfraError::BackendFailure {
                step,
                detail: format!(
                    "grader result drive has invalid size: expected {DISK_BYTES}, got {}",
                    disk_bytes.len()
                ),
            });
        }

        let run_result = parse_disk_bytes(&disk_bytes).map_err(|e| InfraError::BackendFailure {
            step,
            detail: format!("parse_disk_bytes failed: {e:?}"),
        })?;

        // Verify logical run matches expected
        let expected_run_id = match handle.run {
            GraderRun::R0 | GraderRun::Base | GraderRun::Gold => RunId::R0,
            GraderRun::R1 => RunId::R1,
            GraderRun::R2 => RunId::R2,
            GraderRun::R3 => RunId::R3,
        };
        if run_result.run != expected_run_id {
            return Err(InfraError::GraderPayloadMismatch {
                expected: handle.run,
                actual: match run_result.run {
                    RunId::R0 => GraderRun::R0,
                    RunId::R1 => GraderRun::R1,
                    RunId::R2 => GraderRun::R2,
                    RunId::R3 => GraderRun::R3,
                },
            });
        }

        let payload = match handle.run {
            GraderRun::R0 => {
                let r0 = R0Result {
                    tests: run_result
                        .tests
                        .into_iter()
                        .map(|(name, status)| TestResult {
                            name,
                            passed: status == TestStatus::Passed,
                            required: true,
                        })
                        .collect(),
                };
                self.r0_result = Some(r0.clone());
                GraderPayload::R0(r0)
            }
            GraderRun::Base => {
                let base = R0Result {
                    tests: run_result
                        .tests
                        .into_iter()
                        .map(|(name, status)| TestResult {
                            name,
                            passed: status == TestStatus::Passed,
                            required: true,
                        })
                        .collect(),
                };
                GraderPayload::Base(base)
            }
            GraderRun::Gold => {
                let gold = R0Result {
                    tests: run_result
                        .tests
                        .into_iter()
                        .map(|(name, status)| TestResult {
                            name,
                            passed: status == TestStatus::Passed,
                            required: true,
                        })
                        .collect(),
                };
                GraderPayload::Gold(gold)
            }
            GraderRun::R1 => {
                let r1 = R1Result {
                    mutated_tests: run_result
                        .tests
                        .into_iter()
                        .map(|(name, status)| MutatedTestResult {
                            name,
                            failed: status != TestStatus::Passed,
                        })
                        .collect(),
                };
                self.r1_result = Some(r1.clone());
                GraderPayload::R1(r1)
            }
            GraderRun::R2 => {
                let r2 = R2Result {
                    paired_tests: run_result
                        .tests
                        .into_iter()
                        .map(|(name, status)| PairedTestResult {
                            name,
                            passed: status == TestStatus::Passed,
                        })
                        .collect(),
                };
                self.r2_result = Some(r2.clone());
                GraderPayload::R2(r2)
            }
            GraderRun::R3 => {
                let r3 = R3Result {
                    tests: run_result
                        .tests
                        .into_iter()
                        .map(|(name, status)| TestResult {
                            name,
                            passed: status == TestStatus::Passed,
                            required: false,
                        })
                        .collect(),
                };
                self.r3_result = Some(r3.clone());
                GraderPayload::R3(r3)
            }
        };

        let tamper_evidence = match run_result.supervisor.exit {
            SupervisorExit::Clean => None,
            SupervisorExit::Timeout => Some("supervisor timeout".to_string()),
            SupervisorExit::Crash => Some("supervisor crash".to_string()),
        };

        // When R0, R1 and R2 are all collected, write verdict.json into run_dir
        if let (Some(ref r0), Some(ref r1), Some(ref r2)) =
            (&self.r0_result, &self.r1_result, &self.r2_result)
        {
            let results = GraderResults {
                r0: r0.clone(),
                r1: r1.clone(),
                r2: r2.clone(),
                r3: self.r3_result.clone(),
            };
            let verd = hermetic_run::verdict::verdict(&results);
            let status = RunStatus::from(verd);
            let r0_passed = results.r0.tests.iter().all(|t| t.passed);
            let r1_passed = results.r1.mutated_tests.iter().all(|t| t.failed);
            let r2_passed = results.r2.paired_tests.iter().all(|t| t.passed);

            let mut verdict_map = serde_json::json!({
                "run_status": status.as_str(),
                "status": status.as_str(),
                "r0_result": if r0_passed { "passed" } else { "failed" },
                "r1_result": if r1_passed { "passed" } else { "failed" },
                "r2_result": if r2_passed { "passed" } else { "failed" },
                "unclean_shutdown": false,
            });
            if let Some(ref digest) = self.extracted_patch_digest {
                if let Some(obj) = verdict_map.as_object_mut() {
                    obj.insert(
                        "submitted_work_digest".to_string(),
                        serde_json::Value::from(digest.clone()),
                    );
                }
            }
            if let Ok(bytes) = serde_json::to_vec_pretty(&verdict_map) {
                let verdict_file = self.run_dir.join("verdict.json");
                let _ = fs::write(&verdict_file, bytes);
            }
        }

        Ok(GraderOutcome {
            run: handle.run,
            payload,
            tamper_evidence,
        })
    }
}
