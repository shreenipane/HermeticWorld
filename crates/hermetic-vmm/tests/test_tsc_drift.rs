#![forbid(unsafe_code)]

use hermetic_vmm::tsc_drift::{
    verify_multivcpu_sync, verify_pause_resume_invariance, TscDriftError, TscDriftTracker,
    MAX_MULTIVCPU_SKEW_TICKS, MAX_PERMISSIBLE_DRIFT_PPM, MAX_SAMPLES, NOMINAL_TSC_HZ,
};

#[test]
fn test_tsc_drift_nominal_2ghz_rate_passes() {
    let mut tracker = TscDriftTracker::new();
    let num_samples = 100;
    let step_nanos = 10_000_000; // 10ms steps = 1 second total
    for i in 0..num_samples {
        let t_nanos = i * step_nanos;
        let ticks = (t_nanos as u128 * NOMINAL_TSC_HZ as u128 / 1_000_000_000) as u64;
        tracker.add_sample(t_nanos, ticks).unwrap();
    }
    let report = tracker.verify_stability(MAX_PERMISSIBLE_DRIFT_PPM).unwrap();
    assert_eq!(report.sample_count, num_samples as usize);
    assert!(report.drift_ppm < 0.001);
    assert_eq!(report.measured_hz.round() as u64, NOMINAL_TSC_HZ);
    assert!(report.monotonic);
    assert!(report.passed);
}

#[test]
fn test_tsc_drift_simulated_24_hour_run_passes() {
    let mut tracker = TscDriftTracker::new();
    // 24 hours: sample every 60 seconds = 1440 samples
    let total_seconds = 24 * 3600;
    let step_secs = 60;
    let mut s = 0;
    while s <= total_seconds {
        let t_nanos = s * 1_000_000_000;
        let ticks = (s as u128 * NOMINAL_TSC_HZ as u128) as u64;
        tracker.add_sample(t_nanos, ticks).unwrap();
        s += step_secs;
    }
    let report = tracker.verify_stability(MAX_PERMISSIBLE_DRIFT_PPM).unwrap();
    assert_eq!(
        report.sample_count,
        (total_seconds / step_secs + 1) as usize
    );
    assert!(report.drift_ppm < 0.0001);
    assert!(report.passed);
}

#[test]
fn test_tsc_drift_small_acceptable_jitter_passes() {
    let mut tracker = TscDriftTracker::new();
    let t0 = 0;
    let t1 = 1_000_000_000; // 1 second
                            // 2.0 GHz nominal = 2,000,000,000 ticks.
                            // 50 PPM drift = 100,000 ticks difference over 1 second.
    tracker.add_sample(t0, 0).unwrap();
    tracker.add_sample(t1, NOMINAL_TSC_HZ + 100_000).unwrap();

    let report = tracker.verify_stability(MAX_PERMISSIBLE_DRIFT_PPM).unwrap();
    assert!(report.drift_ppm <= 50.1 && report.drift_ppm >= 49.9);
    assert!(report.passed);
}

#[test]
fn test_tsc_drift_excessive_drift_rejected() {
    let mut tracker = TscDriftTracker::new();
    let t0 = 0;
    let t1 = 1_000_000_000; // 1 second
                            // 150 PPM drift = 300,000 ticks difference over 1 second (> 100 PPM limit).
    tracker.add_sample(t0, 0).unwrap();
    tracker.add_sample(t1, NOMINAL_TSC_HZ + 300_000).unwrap();

    let err = tracker
        .verify_stability(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap_err();
    match err {
        TscDriftError::ExcessiveDrift { drift_ppm, max_ppm } => {
            assert!(drift_ppm > 100.0);
            assert_eq!(max_ppm, MAX_PERMISSIBLE_DRIFT_PPM);
        }
        other => panic!("expected ExcessiveDrift, got {other:?}"),
    }
}

#[test]
fn test_tsc_drift_non_monotonic_ticks_rejected() {
    let mut tracker = TscDriftTracker::new();
    tracker.add_sample(1_000_000, 2_000_000).unwrap();
    let err = tracker.add_sample(2_000_000, 1_999_999).unwrap_err();
    assert_eq!(
        err,
        TscDriftError::NonMonotonicTicks {
            prev: 2_000_000,
            curr: 1_999_999
        }
    );
}

#[test]
fn test_tsc_drift_non_monotonic_time_rejected() {
    let mut tracker = TscDriftTracker::new();
    tracker.add_sample(2_000_000, 2_000_000).unwrap();
    let err = tracker.add_sample(1_000_000, 3_000_000).unwrap_err();
    assert_eq!(
        err,
        TscDriftError::NonMonotonicTime {
            prev: 2_000_000,
            curr: 1_000_000
        }
    );
}

#[test]
fn test_tsc_drift_insufficient_samples_rejected() {
    let empty = TscDriftTracker::new();
    assert_eq!(
        empty.verify_stability(100.0).unwrap_err(),
        TscDriftError::InsufficientSamples
    );

    let mut single = TscDriftTracker::new();
    single.add_sample(1_000_000, 2_000_000).unwrap();
    assert_eq!(
        single.verify_stability(100.0).unwrap_err(),
        TscDriftError::InsufficientSamples
    );
}

#[test]
fn test_tsc_drift_sample_cap_exceeded() {
    let mut tracker = TscDriftTracker::new();
    for i in 0..MAX_SAMPLES {
        tracker
            .add_sample(i as u64 * 1000, i as u64 * 2000)
            .unwrap();
    }
    let err = tracker
        .add_sample(MAX_SAMPLES as u64 * 1000, MAX_SAMPLES as u64 * 2000)
        .unwrap_err();
    assert_eq!(err, TscDriftError::SampleCapExceeded);
}

#[test]
fn test_pause_resume_invariance_clean_pause_passes() {
    let before_pause = 10_000_000_000;
    // Paused for 5 seconds (5,000,000,000 ns).
    // On resume, guest only advanced 50 ticks of internal instruction execution.
    let after_resume = before_pause + 50;
    let pause_nanos = 5_000_000_000;
    assert!(verify_pause_resume_invariance(before_pause, after_resume, pause_nanos).is_ok());
}

#[test]
fn test_pause_resume_invariance_wall_clock_leak_detected() {
    let before_pause = 10_000_000_000;
    let pause_nanos = 2_000_000_000; // 2 seconds
                                     // If wall clock leaked, TSC jumped by 2 seconds * 2 GHz = 4,000,000,000 ticks.
    let after_resume = before_pause + 4_000_000_000;
    let err = verify_pause_resume_invariance(before_pause, after_resume, pause_nanos).unwrap_err();
    match err {
        TscDriftError::PauseJumpDetected {
            delta_ticks,
            pause_duration_nanos,
        } => {
            assert_eq!(delta_ticks, 4_000_000_000);
            assert_eq!(pause_duration_nanos, 2_000_000_000);
        }
        other => panic!("expected PauseJumpDetected, got {other:?}"),
    }
}

#[test]
fn test_pause_resume_invariance_non_monotonic_rejected() {
    let before_pause = 10_000_000_000;
    let after_resume = 9_999_999_999;
    let err =
        verify_pause_resume_invariance(before_pause, after_resume, 1_000_000_000).unwrap_err();
    assert_eq!(
        err,
        TscDriftError::NonMonotonicTicks {
            prev: before_pause,
            curr: after_resume,
        }
    );
}

#[test]
fn test_pause_resume_invariance_enforces_fixed_overhead_cap() {
    use hermetic_vmm::tsc_drift::MAX_PAUSE_OVERHEAD_TICKS;
    let base = 10_000_000_000;

    // 50ms pause with 100M ticks jump: must fail despite pause < 100ms
    let err50ms = verify_pause_resume_invariance(base, base + 100_000_000, 50_000_000).unwrap_err();
    assert_eq!(
        err50ms,
        TscDriftError::PauseJumpDetected {
            delta_ticks: 100_000_000,
            pause_duration_nanos: 50_000_000,
        }
    );

    // 2s pause with 1B ticks jump (< half wall ticks = 2B): must fail despite < wall/2
    let err2s =
        verify_pause_resume_invariance(base, base + 1_000_000_000, 2_000_000_000).unwrap_err();
    assert_eq!(
        err2s,
        TscDriftError::PauseJumpDetected {
            delta_ticks: 1_000_000_000,
            pause_duration_nanos: 2_000_000_000,
        }
    );

    // Exactly MAX_PAUSE_OVERHEAD_TICKS is rejected
    assert!(
        verify_pause_resume_invariance(base, base + MAX_PAUSE_OVERHEAD_TICKS, 1_000_000_000)
            .is_err()
    );

    // Under MAX_PAUSE_OVERHEAD_TICKS is accepted
    assert!(verify_pause_resume_invariance(
        base,
        base + MAX_PAUSE_OVERHEAD_TICKS - 1,
        1_000_000_000
    )
    .is_ok());
}

#[test]
fn test_multivcpu_sync_within_skew_passes() {
    // 32 vCPUs with minor skew (up to 1,000 ticks, well below 10,000 tick limit)
    for vcpu_count in [1, 2, 4, 8, 16, 32] {
        let base_tsc = 50_000_000_000;
        let samples: Vec<u64> = (0..vcpu_count)
            .map(|i| base_tsc + (i * 200)) // max diff is 31 * 200 = 6,200 <= 10,000
            .collect();
        assert!(verify_multivcpu_sync(&samples).is_ok());
    }
}

#[test]
fn test_multivcpu_sync_excessive_skew_rejected() {
    let base_tsc = 50_000_000_000;
    let mut samples: Vec<u64> = (0..32).map(|_| base_tsc).collect();
    samples[15] = base_tsc + MAX_MULTIVCPU_SKEW_TICKS + 1; // exceed limit
    let err = verify_multivcpu_sync(&samples).unwrap_err();
    match err {
        TscDriftError::MultiVcpuSkewExceeded { max_diff, limit } => {
            assert_eq!(max_diff, MAX_MULTIVCPU_SKEW_TICKS + 1);
            assert_eq!(limit, MAX_MULTIVCPU_SKEW_TICKS);
        }
        other => panic!("expected MultiVcpuSkewExceeded, got {other:?}"),
    }
}

#[test]
fn test_tsc_drift_error_display_no_host_info() {
    let errors = [
        TscDriftError::Empty,
        TscDriftError::InsufficientSamples,
        TscDriftError::NonMonotonicTicks { prev: 10, curr: 9 },
        TscDriftError::NonMonotonicTime { prev: 10, curr: 9 },
        TscDriftError::ExcessiveDrift {
            drift_ppm: 150.0,
            max_ppm: 100.0,
        },
        TscDriftError::PauseJumpDetected {
            delta_ticks: 1000,
            pause_duration_nanos: 1000,
        },
        TscDriftError::MultiVcpuSkewExceeded {
            max_diff: 15000,
            limit: 10000,
        },
        TscDriftError::SampleCapExceeded,
    ];
    for err in &errors {
        let s = format!("{err}");
        assert!(!s.contains("/home/"));
        assert!(!s.contains("flingboot"));
    }
}
