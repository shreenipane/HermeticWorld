#![forbid(unsafe_code)]
//! Nested-VM guest TSC drift measurement without kvmclock.
//!
//! Under Phase 3b clock hiding, the virtual TSC is scaled to a fixed 2.0 GHz
//! rate via hardware TSC scaling (`KVM_SET_TSC_KHZ`) and CPUID leaf 0x15.
//! kvmclock and all paravirtual clock MSRs are denied and inert.
//!
//! # Clock Hiding and Trusted Measurement Path
//! If `rdtsc` is trapped or filtered for untrusted agent workloads (e.g. via
//! CR4.TSD or VMCS RDTSC exiting) to eliminate timing covert channels,
//! the measurement helper (`/sbin/hermetic-clockprobe --read-tsc` or
//! `/sbin/hermetic-tsc-read`) is executed through `execd` (the trusted PID 1
//! supervisor inside the guest) over the vsock control channel. This constitutes
//! a trusted measurement path, isolated from agent code, enabling host-side
//! qualification of guest TSC stability without paravirtual clock assistance.

use serde::Deserialize;

/// Nominal virtual TSC frequency: 2.0 GHz (2,000,000,000 Hz).
pub const VIRTUAL_TSC_HZ: u64 = 2_000_000_000;

/// Nominal virtual TSC frequency in kHz (2,000,000 kHz).
pub const VIRTUAL_TSC_KHZ: u64 = 2_000_000;

/// Maximum permissible drift in parts per million (PPM) against the virtual TSC.
/// Standard NTP / kernel maximum frequency tolerance is 500 PPM.
pub const MAX_PERMISSIBLE_DRIFT_PPM: f64 = 500.0;

/// Integer representation of `MAX_PERMISSIBLE_DRIFT_PPM`.
pub const MAX_PERMISSIBLE_DRIFT_PPM_U64: u64 = 500;

/// Minimum duration of measurement in nanoseconds: 30 seconds (30,000,000,000 ns).
pub const MIN_MEASUREMENT_DURATION_NS: u64 = 30_000_000_000;

/// Minimum duration of measurement in seconds: 30 seconds.
pub const MIN_MEASUREMENT_DURATION_SECS: u64 = 30;

/// Minimum number of sample points required for drift qualification.
pub const MIN_DRIFT_SAMPLES: usize = 3;

/// Maximum number of samples retained by a tracker to prevent unbounded growth.
pub const MAX_SAMPLES: usize = 1024;

/// Maximum allowed length of guest helper output in bytes.
pub const MAX_HELPER_OUTPUT_BYTES: usize = 4096;

/// Nanoseconds per second constant.
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Microseconds per second (parts per million scaling constant).
pub const MICROS_PER_SEC: u64 = 1_000_000;

/// Typed errors for TSC drift tracking and helper parsing.
///
/// Output messages are deterministic and free of host timestamps, hostnames,
/// usernames, or absolute host paths.
#[derive(Debug, Clone, PartialEq)]
pub enum TscDriftError {
    EmptyOutput,
    OutputOversized(usize),
    InvalidOutput(&'static str),
    NonAsciiOutput,
    TscParseError(&'static str),
    HostTimeNonMonotonic {
        prev_host_ns: u64,
        current_host_ns: u64,
    },
    TscNonMonotonic {
        prev_tsc: u64,
        current_tsc: u64,
    },
    SampleCapExceeded(usize),
    InsufficientSamples {
        count: usize,
        min_required: usize,
    },
    InsufficientDuration {
        duration_ns: u64,
        min_required_ns: u64,
    },
    InvalidFrequency(u64),
    ArithmeticOverflow,
    ExcessiveDrift {
        drift_ppm: f64,
        max_ppm: f64,
    },
    /// The measured drift is near the limit and the host timing uncertainty of
    /// the samples is too large to decide either way; the run fails closed.
    UncertainMeasurement {
        drift_ppm: f64,
        uncertainty_ppm: f64,
        max_ppm: f64,
    },
    /// A bracketed sample's host-after timestamp precedes its host-before one.
    InvalidBracket {
        before_ns: u64,
        after_ns: u64,
    },
}

impl std::fmt::Display for TscDriftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyOutput => write!(f, "helper output is empty"),
            Self::OutputOversized(len) => write!(
                f,
                "helper output exceeds maximum size ({len} > {MAX_HELPER_OUTPUT_BYTES})"
            ),
            Self::InvalidOutput(msg) => write!(f, "invalid helper output: {msg}"),
            Self::NonAsciiOutput => write!(f, "helper output is not valid UTF-8"),
            Self::TscParseError(msg) => write!(f, "failed to parse TSC ticks: {msg}"),
            Self::HostTimeNonMonotonic {
                prev_host_ns,
                current_host_ns,
            } => {
                write!(
                    f,
                    "host elapsed time did not increase strictly ({current_host_ns} <= {prev_host_ns})"
                )
            }
            Self::TscNonMonotonic {
                prev_tsc,
                current_tsc,
            } => {
                write!(f, "guest TSC ticks decreased ({current_tsc} < {prev_tsc})")
            }
            Self::SampleCapExceeded(cap) => write!(f, "sample count reached cap ({cap})"),
            Self::InsufficientSamples {
                count,
                min_required,
            } => {
                write!(f, "insufficient samples ({count} < {min_required})")
            }
            Self::InsufficientDuration {
                duration_ns,
                min_required_ns,
            } => {
                write!(
                    f,
                    "insufficient measurement duration ({duration_ns} ns < {min_required_ns} ns)"
                )
            }
            Self::InvalidFrequency(hz) => write!(f, "invalid nominal TSC frequency ({hz} Hz)"),
            Self::ArithmeticOverflow => write!(f, "arithmetic overflow during drift calculation"),
            Self::UncertainMeasurement {
                drift_ppm,
                uncertainty_ppm,
                max_ppm,
            } => write!(
                f,
                "measured drift {drift_ppm:.2} ppm +/- {uncertainty_ppm:.2} ppm cannot be qualified against {max_ppm:.2} ppm"
            ),
            Self::InvalidBracket {
                before_ns,
                after_ns,
            } => write!(
                f,
                "sample host-after time {after_ns} ns precedes host-before time {before_ns} ns"
            ),
            Self::ExcessiveDrift { drift_ppm, max_ppm } => {
                write!(
                    f,
                    "measured drift {drift_ppm:.2} ppm exceeds tolerance {max_ppm:.2} ppm"
                )
            }
        }
    }
}

impl std::error::Error for TscDriftError {}

/// Parse guest TSC reading from helper output bytes.
///
/// Accepts strict JSON format `{"tsc": <u64>}` or raw decimal ASCII digits `<u64>`.
/// Enforces `MAX_HELPER_OUTPUT_BYTES` cap and rejects hostile input (negative,
/// floating point, overflow, extra fields, malformed UTF-8, etc.) without panics.
pub fn parse_tsc_reading(output: &[u8]) -> Result<u64, TscDriftError> {
    if output.is_empty() {
        return Err(TscDriftError::EmptyOutput);
    }
    if output.len() > MAX_HELPER_OUTPUT_BYTES {
        return Err(TscDriftError::OutputOversized(output.len()));
    }
    let text = std::str::from_utf8(output).map_err(|_| TscDriftError::NonAsciiOutput)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(TscDriftError::EmptyOutput);
    }

    if trimmed.starts_with('{') {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HelperJson {
            tsc: u64,
        }
        let parsed: HelperJson = serde_json::from_str(trimmed).map_err(|_| {
            TscDriftError::TscParseError("malformed JSON reading or invalid fields")
        })?;
        Ok(parsed.tsc)
    } else {
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(TscDriftError::InvalidOutput(
                "non-digit characters in plain reading",
            ));
        }
        trimmed
            .parse::<u64>()
            .map_err(|_| TscDriftError::TscParseError("integer overflow parsing ticks"))
    }
}

/// A single sample pair mapping host elapsed nanoseconds to guest TSC ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TscSample {
    /// Host elapsed time attributed to the guest TSC read (the midpoint of the
    /// host timestamps taken just before and just after the read).
    pub host_elapsed_ns: u64,
    pub guest_tsc: u64,
    /// Half-width of the measured host window around the read: the guest TSC
    /// was read at some host time within `host_elapsed_ns +/- uncertainty_ns`.
    pub uncertainty_ns: u64,
}

/// Tracks guest TSC advancement against host elapsed time to calculate drift.
#[derive(Debug, Clone, PartialEq)]
pub struct TscDriftTracker {
    nominal_freq_hz: u64,
    samples: Vec<TscSample>,
}

impl TscDriftTracker {
    /// Create a new tracker for a given nominal frequency in Hz.
    pub fn new(nominal_freq_hz: u64) -> Result<Self, TscDriftError> {
        if nominal_freq_hz == 0 || nominal_freq_hz > 100_000_000_000 {
            return Err(TscDriftError::InvalidFrequency(nominal_freq_hz));
        }
        Ok(Self {
            nominal_freq_hz,
            samples: Vec::new(),
        })
    }

    /// Create a tracker configured for the 2.0 GHz virtual TSC.
    pub fn for_virtual_tsc() -> Self {
        Self::new(VIRTUAL_TSC_HZ).expect("valid virtual TSC frequency")
    }

    /// The nominal frequency in Hz this tracker compares against.
    pub fn nominal_freq_hz(&self) -> u64 {
        self.nominal_freq_hz
    }

    /// Borrow the collected sample list.
    pub fn samples(&self) -> &[TscSample] {
        &self.samples
    }

    /// Number of samples collected so far.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Feed a guest TSC read bracketed by host timestamps taken immediately
    /// before the request was sent and after the reply arrived. The sample is
    /// placed at the window's midpoint and carries the measured half-width as
    /// its acquisition uncertainty, so request latency is accounted for in
    /// [`Self::validate_measurement`] instead of being read as drift.
    pub fn add_bracketed_sample(
        &mut self,
        host_before_ns: u64,
        host_after_ns: u64,
        guest_tsc: u64,
    ) -> Result<(), TscDriftError> {
        if host_after_ns < host_before_ns {
            return Err(TscDriftError::InvalidBracket {
                before_ns: host_before_ns,
                after_ns: host_after_ns,
            });
        }
        let width = host_after_ns - host_before_ns;
        let mid = host_before_ns + width / 2;
        let half = width.div_ceil(2);
        self.add_sample(mid, guest_tsc)?;
        if let Some(last) = self.samples.last_mut() {
            last.uncertainty_ns = half;
        }
        Ok(())
    }

    /// Worst-case drift contribution, in ppm, of the first and last samples'
    /// acquisition uncertainty over the measured host interval.
    pub fn uncertainty_ppm(&self) -> Result<f64, TscDriftError> {
        let elapsed = self.elapsed_host_ns()?;
        let (first, last) = match (self.samples.first(), self.samples.last()) {
            (Some(f), Some(l)) => (f, l),
            _ => {
                return Err(TscDriftError::InsufficientSamples {
                    count: self.samples.len(),
                    min_required: 2,
                })
            }
        };
        if elapsed == 0 {
            return Err(TscDriftError::ArithmeticOverflow);
        }
        let total = first.uncertainty_ns as f64 + last.uncertainty_ns as f64;
        // Relative interval error total/elapsed, kept conservative when the
        // window is a large share of the interval.
        let rel = total / (elapsed as f64 - total.min(elapsed as f64 - 1.0)).max(1.0);
        Ok(rel * 1_000_000.0)
    }

    /// Feed a sample of `(host_elapsed_ns, guest_tsc)` into the tracker.
    ///
    /// Validates strictly increasing host elapsed time and monotonically
    /// increasing guest TSC ticks. Enforces `MAX_SAMPLES` cap.
    pub fn add_sample(
        &mut self,
        host_elapsed_ns: u64,
        guest_tsc: u64,
    ) -> Result<(), TscDriftError> {
        if self.samples.len() >= MAX_SAMPLES {
            return Err(TscDriftError::SampleCapExceeded(MAX_SAMPLES));
        }
        if let Some(prev) = self.samples.last() {
            if host_elapsed_ns <= prev.host_elapsed_ns {
                return Err(TscDriftError::HostTimeNonMonotonic {
                    prev_host_ns: prev.host_elapsed_ns,
                    current_host_ns: host_elapsed_ns,
                });
            }
            if guest_tsc < prev.guest_tsc {
                return Err(TscDriftError::TscNonMonotonic {
                    prev_tsc: prev.guest_tsc,
                    current_tsc: guest_tsc,
                });
            }
        }
        self.samples.push(TscSample {
            host_elapsed_ns,
            guest_tsc,
            uncertainty_ns: 0,
        });
        Ok(())
    }

    /// Feed alias for `add_sample`.
    pub fn feed(&mut self, host_elapsed_ns: u64, guest_tsc: u64) -> Result<(), TscDriftError> {
        self.add_sample(host_elapsed_ns, guest_tsc)
    }

    /// Record sample alias for `add_sample`.
    pub fn record_sample(
        &mut self,
        host_elapsed_ns: u64,
        guest_tsc: u64,
    ) -> Result<(), TscDriftError> {
        self.add_sample(host_elapsed_ns, guest_tsc)
    }

    /// Total host elapsed time in nanoseconds between the first and latest sample.
    pub fn elapsed_host_ns(&self) -> Result<u64, TscDriftError> {
        if self.samples.len() < 2 {
            return Err(TscDriftError::InsufficientSamples {
                count: self.samples.len(),
                min_required: 2,
            });
        }
        let first = self.samples.first().unwrap();
        let last = self.samples.last().unwrap();
        Ok(last.host_elapsed_ns - first.host_elapsed_ns)
    }

    /// Total guest TSC ticks elapsed between the first and latest sample.
    pub fn elapsed_guest_tsc(&self) -> Result<u64, TscDriftError> {
        if self.samples.len() < 2 {
            return Err(TscDriftError::InsufficientSamples {
                count: self.samples.len(),
                min_required: 2,
            });
        }
        let first = self.samples.first().unwrap();
        let last = self.samples.last().unwrap();
        Ok(last.guest_tsc - first.guest_tsc)
    }

    /// Total host elapsed time in seconds.
    pub fn elapsed_host_secs(&self) -> Result<f64, TscDriftError> {
        let ns = self.elapsed_host_ns()?;
        Ok(ns as f64 / NANOS_PER_SEC as f64)
    }

    /// Compute cumulative drift in parts per million (PPM) between first and latest sample.
    ///
    /// Positive PPM means guest TSC advanced faster than nominal;
    /// negative PPM means guest TSC advanced slower than nominal.
    pub fn drift_ppm(&self) -> Result<f64, TscDriftError> {
        let delta_h_ns = self.elapsed_host_ns()?;
        let delta_t_ticks = self.elapsed_guest_tsc()?;
        if delta_h_ns == 0 {
            return Err(TscDriftError::HostTimeNonMonotonic {
                prev_host_ns: 0,
                current_host_ns: 0,
            });
        }
        let total_ticks_x_nanos = delta_h_ns as u128 * self.nominal_freq_hz as u128;
        let whole_ticks = total_ticks_x_nanos / (NANOS_PER_SEC as u128);
        let rem_ticks = total_ticks_x_nanos % (NANOS_PER_SEC as u128);
        let expected_ticks = whole_ticks as f64 + (rem_ticks as f64 / NANOS_PER_SEC as f64);
        if expected_ticks <= 0.0 {
            return Err(TscDriftError::ArithmeticOverflow);
        }
        let ppm =
            ((delta_t_ticks as f64) - expected_ticks) / expected_ticks * (MICROS_PER_SEC as f64);
        if !ppm.is_finite() {
            return Err(TscDriftError::ArithmeticOverflow);
        }
        Ok(ppm)
    }

    /// Absolute value of cumulative drift in PPM.
    pub fn abs_drift_ppm(&self) -> Result<f64, TscDriftError> {
        Ok(self.drift_ppm()?.abs())
    }

    /// Per-interval drift in PPM for each adjacent pair of samples.
    pub fn interval_drifts_ppm(&self) -> Result<Vec<f64>, TscDriftError> {
        if self.samples.len() < 2 {
            return Err(TscDriftError::InsufficientSamples {
                count: self.samples.len(),
                min_required: 2,
            });
        }
        let mut drifts = Vec::with_capacity(self.samples.len() - 1);
        for window in self.samples.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            let delta_h = curr.host_elapsed_ns - prev.host_elapsed_ns;
            let delta_t = curr.guest_tsc - prev.guest_tsc;
            let total_ticks_x_nanos = delta_h as u128 * self.nominal_freq_hz as u128;
            let whole_ticks = total_ticks_x_nanos / (NANOS_PER_SEC as u128);
            let rem_ticks = total_ticks_x_nanos % (NANOS_PER_SEC as u128);
            let expected = whole_ticks as f64 + (rem_ticks as f64 / NANOS_PER_SEC as f64);
            if expected <= 0.0 {
                return Err(TscDriftError::ArithmeticOverflow);
            }
            let ppm = ((delta_t as f64) - expected) / expected * (MICROS_PER_SEC as f64);
            drifts.push(ppm);
        }
        Ok(drifts)
    }

    /// Check whether the measurement is within an exact PPM limit without floating-point precision loss.
    fn is_within_exact_ppm(&self, max_ppm_u64: u64) -> Result<bool, TscDriftError> {
        let delta_h_ns = self.elapsed_host_ns()?;
        let delta_t_ticks = self.elapsed_guest_tsc()?;
        if delta_h_ns == 0 {
            return Err(TscDriftError::HostTimeNonMonotonic {
                prev_host_ns: 0,
                current_host_ns: 0,
            });
        }
        let expected_scaled = (delta_h_ns as u128)
            .checked_mul(self.nominal_freq_hz as u128)
            .ok_or(TscDriftError::ArithmeticOverflow)?;
        if expected_scaled == 0 {
            return Err(TscDriftError::ArithmeticOverflow);
        }
        let actual_scaled = (delta_t_ticks as u128)
            .checked_mul(NANOS_PER_SEC as u128)
            .ok_or(TscDriftError::ArithmeticOverflow)?;
        let diff_scaled = actual_scaled.abs_diff(expected_scaled);
        let lhs = diff_scaled
            .checked_mul(MICROS_PER_SEC as u128)
            .ok_or(TscDriftError::ArithmeticOverflow)?;
        let rhs = expected_scaled
            .checked_mul(max_ppm_u64 as u128)
            .ok_or(TscDriftError::ArithmeticOverflow)?;
        Ok(lhs <= rhs)
    }

    /// True if absolute drift is within `max_ppm`.
    pub fn is_within_tolerance(&self, max_ppm: f64) -> Result<bool, TscDriftError> {
        if !max_ppm.is_finite() || max_ppm < 0.0 {
            return Err(TscDriftError::ArithmeticOverflow);
        }
        if max_ppm == MAX_PERMISSIBLE_DRIFT_PPM {
            return self.is_within_exact_ppm(MAX_PERMISSIBLE_DRIFT_PPM_U64);
        }
        if max_ppm.fract() == 0.0 && max_ppm <= u64::MAX as f64 {
            return self.is_within_exact_ppm(max_ppm as u64);
        }
        Ok(self.abs_drift_ppm()? <= max_ppm)
    }

    /// Validate the full measurement against duration, sample count, and drift limits.
    pub fn validate_measurement(
        &self,
        min_duration_ns: u64,
        min_samples: usize,
        max_ppm: f64,
    ) -> Result<(), TscDriftError> {
        if !max_ppm.is_finite() || max_ppm < 0.0 {
            return Err(TscDriftError::ArithmeticOverflow);
        }
        if self.samples.len() < min_samples {
            return Err(TscDriftError::InsufficientSamples {
                count: self.samples.len(),
                min_required: min_samples,
            });
        }
        let elapsed_ns = self.elapsed_host_ns()?;
        if elapsed_ns < min_duration_ns {
            return Err(TscDriftError::InsufficientDuration {
                duration_ns: elapsed_ns,
                min_required_ns: min_duration_ns,
            });
        }
        let unc = self.uncertainty_ppm()?;
        if unc > 0.0 {
            let drift = self.abs_drift_ppm()?;
            if drift - unc > max_ppm {
                return Err(TscDriftError::ExcessiveDrift {
                    drift_ppm: drift,
                    max_ppm,
                });
            }
            if drift + unc > max_ppm {
                return Err(TscDriftError::UncertainMeasurement {
                    drift_ppm: drift,
                    uncertainty_ppm: unc,
                    max_ppm,
                });
            }
            return Ok(());
        }
        let within_tolerance = if max_ppm == MAX_PERMISSIBLE_DRIFT_PPM {
            self.is_within_exact_ppm(MAX_PERMISSIBLE_DRIFT_PPM_U64)?
        } else if max_ppm.fract() == 0.0 && max_ppm <= u64::MAX as f64 {
            self.is_within_exact_ppm(max_ppm as u64)?
        } else {
            self.abs_drift_ppm()? <= max_ppm
        };
        if !within_tolerance {
            let drift = self.abs_drift_ppm()?;
            return Err(TscDriftError::ExcessiveDrift {
                drift_ppm: drift,
                max_ppm,
            });
        }
        Ok(())
    }
}

impl Default for TscDriftTracker {
    fn default() -> Self {
        Self::for_virtual_tsc()
    }
}
