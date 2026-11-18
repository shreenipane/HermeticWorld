#![forbid(unsafe_code)]

//! Long-running TSC drift measurement and stability validation without kvmclock.
//!
//! Under the clock-hiding configuration, the guest has `PARAVIRT=n`, `KVM_GUEST=n`,
//! and kvmclock disabled. The guest relies entirely on the fixed 2.0 GHz virtual TSC
//! established via KVM scaling and CPUID leaf 0x15.
//!
//! This module tracks TSC tick samples across time, measures drift against nominal
//! 2.0 GHz, validates strict monotonicity, verifies pause/resume invariance (ticks do
//! not jump forward across pauses), and verifies multi-vCPU synchronization.

use serde::{Deserialize, Serialize};

pub const NOMINAL_TSC_HZ: u64 = 2_000_000_000;
pub const MAX_SAMPLES: usize = 10_000;
pub const MAX_PERMISSIBLE_DRIFT_PPM: f64 = 100.0;
pub const MAX_MULTIVCPU_SKEW_TICKS: u64 = 10_000;
pub const MAX_PAUSE_OVERHEAD_TICKS: u64 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TscSample {
    pub monotonic_nanos: u64,
    pub tsc_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TscDriftReport {
    pub sample_count: usize,
    pub total_duration_nanos: u64,
    pub total_ticks: u64,
    pub measured_hz: f64,
    pub drift_ppm: f64,
    pub monotonic: bool,
    pub passed: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub enum TscDriftError {
    Empty,
    InsufficientSamples,
    NonMonotonicTicks {
        prev: u64,
        curr: u64,
    },
    NonMonotonicTime {
        prev: u64,
        curr: u64,
    },
    ExcessiveDrift {
        drift_ppm: f64,
        max_ppm: f64,
    },
    PauseJumpDetected {
        delta_ticks: u64,
        pause_duration_nanos: u64,
    },
    MultiVcpuSkewExceeded {
        max_diff: u64,
        limit: u64,
    },
    SampleCapExceeded,
}

impl std::fmt::Display for TscDriftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("no TSC samples recorded"),
            Self::InsufficientSamples => f.write_str("insufficient TSC samples to compute drift"),
            Self::NonMonotonicTicks { prev, curr } => {
                write!(
                    f,
                    "non-monotonic TSC ticks: previous {prev} > current {curr}"
                )
            }
            Self::NonMonotonicTime { prev, curr } => {
                write!(
                    f,
                    "non-monotonic monotonic time: previous {prev} > current {curr}"
                )
            }
            Self::ExcessiveDrift { drift_ppm, max_ppm } => {
                write!(
                    f,
                    "excessive TSC drift: {drift_ppm:.2} ppm exceeds max {max_ppm:.2} ppm"
                )
            }
            Self::PauseJumpDetected {
                delta_ticks,
                pause_duration_nanos,
            } => {
                write!(f, "TSC jumped forward during pause: delta {delta_ticks} ticks over {pause_duration_nanos} ns")
            }
            Self::MultiVcpuSkewExceeded { max_diff, limit } => {
                write!(
                    f,
                    "multi-vCPU TSC skew {max_diff} ticks exceeds limit {limit}"
                )
            }
            Self::SampleCapExceeded => f.write_str("maximum TSC sample cap exceeded"),
        }
    }
}

impl std::error::Error for TscDriftError {}

#[derive(Debug, Default, Clone)]
pub struct TscDriftTracker {
    samples: Vec<TscSample>,
}

impl TscDriftTracker {
    pub fn new() -> Self {
        Self {
            samples: Vec::with_capacity(64),
        }
    }

    pub fn add_sample(
        &mut self,
        monotonic_nanos: u64,
        tsc_ticks: u64,
    ) -> Result<(), TscDriftError> {
        if self.samples.len() >= MAX_SAMPLES {
            return Err(TscDriftError::SampleCapExceeded);
        }
        if let Some(last) = self.samples.last() {
            if tsc_ticks < last.tsc_ticks {
                return Err(TscDriftError::NonMonotonicTicks {
                    prev: last.tsc_ticks,
                    curr: tsc_ticks,
                });
            }
            if monotonic_nanos < last.monotonic_nanos {
                return Err(TscDriftError::NonMonotonicTime {
                    prev: last.monotonic_nanos,
                    curr: monotonic_nanos,
                });
            }
        }
        self.samples.push(TscSample {
            monotonic_nanos,
            tsc_ticks,
        });
        Ok(())
    }

    pub fn samples(&self) -> &[TscSample] {
        &self.samples
    }

    pub fn verify_stability(&self, max_ppm: f64) -> Result<TscDriftReport, TscDriftError> {
        if self.samples.len() < 2 {
            return Err(TscDriftError::InsufficientSamples);
        }
        let first = self.samples.first().ok_or(TscDriftError::Empty)?;
        let last = self.samples.last().ok_or(TscDriftError::Empty)?;

        let duration_nanos = last.monotonic_nanos.saturating_sub(first.monotonic_nanos);
        if duration_nanos == 0 {
            return Err(TscDriftError::InsufficientSamples);
        }
        let total_ticks = last.tsc_ticks.saturating_sub(first.tsc_ticks);

        let duration_secs = duration_nanos as f64 / 1_000_000_000.0;
        let measured_hz = total_ticks as f64 / duration_secs;
        let drift_ppm =
            ((measured_hz - NOMINAL_TSC_HZ as f64) / NOMINAL_TSC_HZ as f64).abs() * 1_000_000.0;

        if drift_ppm > max_ppm {
            return Err(TscDriftError::ExcessiveDrift { drift_ppm, max_ppm });
        }

        Ok(TscDriftReport {
            sample_count: self.samples.len(),
            total_duration_nanos: duration_nanos,
            total_ticks,
            measured_hz,
            drift_ppm,
            monotonic: true,
            passed: true,
        })
    }
}

/// Verify that guest TSC does not jump forward during VM pause.
///
/// When a VM is paused for `pause_duration_nanos`, guest TSC must not advance
/// by the elapsed wall/monotonic time of the pause. Any advance must only reflect
/// immediate execution overhead (under 100,000 ticks).
pub fn verify_pause_resume_invariance(
    before_pause_tsc: u64,
    after_resume_tsc: u64,
    pause_duration_nanos: u64,
) -> Result<(), TscDriftError> {
    if after_resume_tsc < before_pause_tsc {
        return Err(TscDriftError::NonMonotonicTicks {
            prev: before_pause_tsc,
            curr: after_resume_tsc,
        });
    }
    let delta_ticks = after_resume_tsc - before_pause_tsc;
    if delta_ticks >= MAX_PAUSE_OVERHEAD_TICKS {
        return Err(TscDriftError::PauseJumpDetected {
            delta_ticks,
            pause_duration_nanos,
        });
    }
    Ok(())
}

/// Verify synchronization across multiple vCPUs at a checkpoint.
///
/// Under invariant TSC with fixed 2 GHz scaling, difference between vCPUs must
/// not exceed `MAX_MULTIVCPU_SKEW_TICKS`.
pub fn verify_multivcpu_sync(vcpu_tsc_samples: &[u64]) -> Result<(), TscDriftError> {
    if vcpu_tsc_samples.is_empty() {
        return Err(TscDriftError::Empty);
    }
    let min_val = *vcpu_tsc_samples.iter().min().unwrap();
    let max_val = *vcpu_tsc_samples.iter().max().unwrap();
    let diff = max_val - min_val;
    if diff > MAX_MULTIVCPU_SKEW_TICKS {
        return Err(TscDriftError::MultiVcpuSkewExceeded {
            max_diff: diff,
            limit: MAX_MULTIVCPU_SKEW_TICKS,
        });
    }
    Ok(())
}
