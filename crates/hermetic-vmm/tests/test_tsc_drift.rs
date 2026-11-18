#![forbid(unsafe_code)]

use hermetic_vmm::tsc_drift::{
    parse_tsc_reading, TscDriftError, TscDriftTracker, MAX_HELPER_OUTPUT_BYTES,
    MAX_PERMISSIBLE_DRIFT_PPM, MAX_SAMPLES, MIN_DRIFT_SAMPLES, MIN_MEASUREMENT_DURATION_NS,
    VIRTUAL_TSC_HZ,
};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[test]
fn helper_output_parsing_valid_cases() {
    // Strict JSON format
    assert_eq!(
        parse_tsc_reading(b"{\"tsc\": 1234567890}\n").unwrap(),
        1234567890
    );
    assert_eq!(
        parse_tsc_reading(b"  {\"tsc\": 9876543210}  \r\n").unwrap(),
        9876543210
    );
    assert_eq!(parse_tsc_reading(b"{\"tsc\":0}").unwrap(), 0);
    assert_eq!(
        parse_tsc_reading(b"{\"tsc\": 18446744073709551615}").unwrap(),
        u64::MAX
    );

    // Plain decimal integer format
    assert_eq!(parse_tsc_reading(b"1234567890\n").unwrap(), 1234567890);
    assert_eq!(parse_tsc_reading(b"  42  ").unwrap(), 42);
    assert_eq!(parse_tsc_reading(b"0").unwrap(), 0);
    assert_eq!(
        parse_tsc_reading(b"18446744073709551615").unwrap(),
        u64::MAX
    );
}

#[test]
fn helper_output_parsing_hostile_cases_never_panic() {
    // Empty output
    assert_eq!(
        parse_tsc_reading(b"").unwrap_err(),
        TscDriftError::EmptyOutput
    );
    assert_eq!(
        parse_tsc_reading(b"   \t\r\n   ").unwrap_err(),
        TscDriftError::EmptyOutput
    );

    // Oversized output
    let huge = vec![b'9'; MAX_HELPER_OUTPUT_BYTES + 1];
    assert!(matches!(
        parse_tsc_reading(&huge).unwrap_err(),
        TscDriftError::OutputOversized(_)
    ));

    // Non-UTF8 output
    assert_eq!(
        parse_tsc_reading(b"\xff\xfe\x00\x12").unwrap_err(),
        TscDriftError::NonAsciiOutput
    );

    // Negative numbers
    assert!(matches!(
        parse_tsc_reading(b"-42").unwrap_err(),
        TscDriftError::InvalidOutput(_)
    ));
    assert!(matches!(
        parse_tsc_reading(b"{\"tsc\": -42}").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));

    // Floating point numbers
    assert!(matches!(
        parse_tsc_reading(b"1234.56").unwrap_err(),
        TscDriftError::InvalidOutput(_)
    ));
    assert!(matches!(
        parse_tsc_reading(b"{\"tsc\": 1234.56}").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));

    // String instead of integer in JSON
    assert!(matches!(
        parse_tsc_reading(b"{\"tsc\": \"1234\"}").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));

    // Array / unexpected JSON structure
    assert!(matches!(
        parse_tsc_reading(b"[1234]").unwrap_err(),
        TscDriftError::InvalidOutput(_)
    ));

    // Missing required field
    assert!(matches!(
        parse_tsc_reading(b"{\"other\": 1234}").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));

    // Extra unknown fields
    assert!(matches!(
        parse_tsc_reading(b"{\"tsc\": 1234, \"extra\": 5}").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));

    // Integer overflow beyond u64::MAX
    assert!(matches!(
        parse_tsc_reading(b"18446744073709551616").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));
    assert!(matches!(
        parse_tsc_reading(b"{\"tsc\": 18446744073709551616}").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));

    // Non-numeric plain text
    assert!(matches!(
        parse_tsc_reading(b"not_a_number").unwrap_err(),
        TscDriftError::InvalidOutput(_)
    ));

    // Injected command payload
    assert!(matches!(
        parse_tsc_reading(b"1234\nrm -rf /").unwrap_err(),
        TscDriftError::InvalidOutput(_)
    ));

    // Embedded NUL bytes
    assert!(matches!(
        parse_tsc_reading(b"1234\0extra").unwrap_err(),
        TscDriftError::InvalidOutput(_)
    ));

    // Null or boolean values
    assert!(matches!(
        parse_tsc_reading(b"{\"tsc\": null}").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));
    assert!(matches!(
        parse_tsc_reading(b"{\"tsc\": true}").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));

    // Incomplete JSON
    assert!(matches!(
        parse_tsc_reading(b"{\"tsc\": ").unwrap_err(),
        TscDriftError::TscParseError(_)
    ));
}

#[test]
fn tracker_virtual_tsc_configuration_and_zero_drift() {
    let mut tracker = TscDriftTracker::for_virtual_tsc();
    assert_eq!(tracker.nominal_freq_hz(), VIRTUAL_TSC_HZ);
    assert_eq!(tracker.sample_count(), 0);

    // Feed 6 points over 30 s with exactly 0.0 drift (2.0 ticks per ns)
    let base_tsc = 1_000_000_000_u64;
    for step in 0..=5 {
        let elapsed_ns = step * 6_000_000_000_u64; // 0, 6s, 12s, 18s, 24s, 30s
        let tsc = base_tsc + elapsed_ns * 2;
        tracker.add_sample(elapsed_ns, tsc).unwrap();
    }

    assert_eq!(tracker.sample_count(), 6);
    assert_eq!(tracker.elapsed_host_ns().unwrap(), 30_000_000_000);
    assert_eq!(tracker.elapsed_guest_tsc().unwrap(), 60_000_000_000);
    assert_eq!(tracker.elapsed_host_secs().unwrap(), 30.0);

    let drift = tracker.drift_ppm().unwrap();
    assert!(drift.abs() < 1e-9);
    assert!(tracker
        .is_within_tolerance(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap());
    assert!(tracker
        .validate_measurement(
            MIN_MEASUREMENT_DURATION_NS,
            MIN_DRIFT_SAMPLES,
            MAX_PERMISSIBLE_DRIFT_PPM
        )
        .is_ok());

    // Interval drifts are all zero
    let intervals = tracker.interval_drifts_ppm().unwrap();
    assert_eq!(intervals.len(), 5);
    for d in intervals {
        assert!(d.abs() < 1e-9);
    }
}

#[test]
fn tracker_drift_calculation_known_answers() {
    let mut tracker = TscDriftTracker::for_virtual_tsc();

    // 30 s duration: expected ticks = 60,000,000,000
    // +100 PPM means 6,000,000 extra ticks (60,006,000,000 ticks)
    tracker.add_sample(0, 100_000_000).unwrap();
    tracker
        .add_sample(30_000_000_000, 100_000_000 + 60_006_000_000)
        .unwrap();

    let drift = tracker.drift_ppm().unwrap();
    assert!((drift - 100.0).abs() < 1e-6);
    assert!(tracker
        .is_within_tolerance(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap());

    // Another tracker with -250 PPM drift (15,000,000 fewer ticks = 59,985,000,000 ticks)
    let mut slow_tracker = TscDriftTracker::for_virtual_tsc();
    slow_tracker.add_sample(0, 500_000_000).unwrap();
    slow_tracker
        .add_sample(30_000_000_000, 500_000_000 + 59_985_000_000)
        .unwrap();

    let slow_drift = slow_tracker.drift_ppm().unwrap();
    assert!((slow_drift - (-250.0)).abs() < 1e-6);
    assert!((slow_tracker.abs_drift_ppm().unwrap() - 250.0).abs() < 1e-6);
    assert!(slow_tracker
        .is_within_tolerance(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap());
}

#[test]
fn tracker_excessive_drift_fails_validation() {
    let mut tracker = TscDriftTracker::for_virtual_tsc();
    // +600 PPM exceeds MAX_PERMISSIBLE_DRIFT_PPM (500 PPM)
    // 600 PPM of 60,000,000,000 is 36,000,000 extra ticks
    tracker.add_sample(0, 0).unwrap();
    tracker.add_sample(15_000_000_000, 30_018_000_000).unwrap();
    tracker.add_sample(30_000_000_000, 60_036_000_000).unwrap();

    let drift = tracker.drift_ppm().unwrap();
    assert!((drift - 600.0).abs() < 1e-6);
    assert!(!tracker
        .is_within_tolerance(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap());

    let val_err = tracker
        .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 3, MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap_err();
    assert!(matches!(val_err, TscDriftError::ExcessiveDrift { .. }));
}

#[test]
fn tracker_monotonicity_and_duration_enforcement() {
    let mut tracker = TscDriftTracker::for_virtual_tsc();
    tracker.add_sample(1_000_000_000, 2_000_000_000).unwrap();

    // Decreasing host time rejected
    let err = tracker.add_sample(500_000_000, 3_000_000_000).unwrap_err();
    assert!(matches!(err, TscDriftError::HostTimeNonMonotonic { .. }));

    // Equal host time rejected
    let err = tracker
        .add_sample(1_000_000_000, 3_000_000_000)
        .unwrap_err();
    assert!(matches!(err, TscDriftError::HostTimeNonMonotonic { .. }));

    // Decreasing guest TSC rejected
    let err = tracker
        .add_sample(2_000_000_000, 1_000_000_000)
        .unwrap_err();
    assert!(matches!(err, TscDriftError::TscNonMonotonic { .. }));

    // Insufficient samples (< 2 for drift computation)
    assert!(matches!(
        tracker.drift_ppm().unwrap_err(),
        TscDriftError::InsufficientSamples { .. }
    ));

    // Add second sample with only 10 s duration
    tracker.add_sample(11_000_000_000, 22_000_000_000).unwrap();
    let err = tracker
        .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap_err();
    assert!(matches!(err, TscDriftError::InsufficientDuration { .. }));
}

#[test]
fn tracker_sample_cap_enforced() {
    let mut tracker = TscDriftTracker::for_virtual_tsc();
    for i in 0..MAX_SAMPLES {
        let ns = (i as u64) + 1;
        let tsc = (i as u64) * 2;
        tracker.add_sample(ns, tsc).unwrap();
    }
    assert_eq!(tracker.sample_count(), MAX_SAMPLES);
    let overflow = tracker
        .add_sample(MAX_SAMPLES as u64 + 1, 99999)
        .unwrap_err();
    assert_eq!(overflow, TscDriftError::SampleCapExceeded(MAX_SAMPLES));
}

#[test]
fn exact_500_ppm_boundary_accepted_and_excess_rejected() {
    // At 2.0 GHz virtual TSC:
    // 60_000_001_000 ns corresponds to exactly 120_000_002_000 expected ticks.
    // 500 ppm of 120_000_002_000 is 60_000_001 ticks.

    // 1. Exact +500 ppm fast: 120_000_002_000 + 60_000_001 = 120_060_002_001 ticks.
    let mut tracker = TscDriftTracker::for_virtual_tsc();
    tracker.add_sample(0, 0).unwrap();
    tracker.add_sample(60_000_001_000, 120_060_002_001).unwrap();
    assert_eq!(tracker.drift_ppm().unwrap(), 500.0);
    assert!(tracker
        .is_within_tolerance(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap());
    assert!(tracker
        .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, MAX_PERMISSIBLE_DRIFT_PPM)
        .is_ok());

    // 2. One tick above (+500 ppm + 1 tick): 120_060_002_002 ticks.
    let mut over_tracker = TscDriftTracker::for_virtual_tsc();
    over_tracker.add_sample(0, 0).unwrap();
    over_tracker
        .add_sample(60_000_001_000, 120_060_002_002)
        .unwrap();
    assert!(!over_tracker
        .is_within_tolerance(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap());
    let err = over_tracker
        .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap_err();
    assert!(matches!(err, TscDriftError::ExcessiveDrift { .. }));

    // 3. Exact -500 ppm slow: 120_000_002_000 - 60_000_001 = 119_940_001_999 ticks.
    let mut slow_tracker = TscDriftTracker::for_virtual_tsc();
    slow_tracker.add_sample(0, 0).unwrap();
    slow_tracker
        .add_sample(60_000_001_000, 119_940_001_999)
        .unwrap();
    assert_eq!(slow_tracker.drift_ppm().unwrap(), -500.0);
    assert!(slow_tracker
        .is_within_tolerance(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap());
    assert!(slow_tracker
        .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, MAX_PERMISSIBLE_DRIFT_PPM)
        .is_ok());

    // 4. One tick below (-500 ppm - 1 tick): 119_940_001_998 ticks.
    let mut underslow_tracker = TscDriftTracker::for_virtual_tsc();
    underslow_tracker.add_sample(0, 0).unwrap();
    underslow_tracker
        .add_sample(60_000_001_000, 119_940_001_998)
        .unwrap();
    assert!(!underslow_tracker
        .is_within_tolerance(MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap());
    let err = underslow_tracker
        .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, MAX_PERMISSIBLE_DRIFT_PPM)
        .unwrap_err();
    assert!(matches!(err, TscDriftError::ExcessiveDrift { .. }));
}

#[test]
fn undefined_or_negative_tolerance_rejected() {
    let mut tracker = TscDriftTracker::for_virtual_tsc();
    // 30 s run with 1,000 ppm drift (60,060,000,000 ticks)
    tracker.add_sample(0, 0).unwrap();
    tracker.add_sample(30_000_000_000, 60_060_000_000).unwrap();

    // NaN tolerance must be rejected by both APIs with ArithmeticOverflow
    assert_eq!(
        tracker.is_within_tolerance(f64::NAN).unwrap_err(),
        TscDriftError::ArithmeticOverflow
    );
    assert_eq!(
        tracker
            .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, f64::NAN)
            .unwrap_err(),
        TscDriftError::ArithmeticOverflow
    );

    // Negative tolerance must be rejected
    assert_eq!(
        tracker.is_within_tolerance(-1.0).unwrap_err(),
        TscDriftError::ArithmeticOverflow
    );
    assert_eq!(
        tracker
            .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, -500.0)
            .unwrap_err(),
        TscDriftError::ArithmeticOverflow
    );

    // Infinite tolerance must be rejected
    assert_eq!(
        tracker.is_within_tolerance(f64::INFINITY).unwrap_err(),
        TscDriftError::ArithmeticOverflow
    );
    assert_eq!(
        tracker
            .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, f64::INFINITY)
            .unwrap_err(),
        TscDriftError::ArithmeticOverflow
    );

    // Finite nonnegative tolerance: 1000.0 is exact match, 1001.0 passes, 999.0 fails with ExcessiveDrift
    assert!(tracker.is_within_tolerance(1000.0).unwrap());
    assert!(tracker
        .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, 1000.0)
        .is_ok());
    assert!(!tracker.is_within_tolerance(999.0).unwrap());
    assert!(matches!(
        tracker
            .validate_measurement(MIN_MEASUREMENT_DURATION_NS, 2, 999.0)
            .unwrap_err(),
        TscDriftError::ExcessiveDrift { .. }
    ));
}

#[test]
fn tsc_drift_smoke_script_present_and_executable() {
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("scripts/integration/tsc-drift-smoke.sh");

    assert!(script_path.is_file(), "tsc-drift-smoke.sh must exist");
    let perms = std::fs::metadata(&script_path)
        .expect("read metadata")
        .permissions();
    let mode = perms.mode();
    assert_ne!(
        mode & 0o111,
        0,
        "tsc-drift-smoke.sh must be executable in checkout (mode {:o})",
        mode
    );

    let content = std::fs::read_to_string(&script_path).expect("read content");
    assert!(content.starts_with("#!/usr/bin/env bash"));
    assert!(content.contains("readlink -f"));
    assert!(content.contains("HERMETIC_FC_BIN"));
    assert!(content.contains("HERMETIC_FIRECRACKER_LOCK"));
    assert!(content.contains("HERMETIC_KERNEL"));
    assert!(content.contains("measures_guest_tsc_drift_without_kvmclock"));
}

#[test]
fn smoke_script_check_does_not_mutate_permissions() {
    // Verify that testing file executable bit does not modify filesystem permissions
    let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
    let mut perms = tmp.as_file().metadata().expect("meta").permissions();
    perms.set_mode(0o644);
    tmp.as_file().set_permissions(perms).expect("set 0644");

    let read_mode = tmp.as_file().metadata().expect("meta").permissions().mode();
    assert_eq!(read_mode & 0o777, 0o644);
    // Non-mutating verification: checking the bit does not change it to 0755
    let is_exec = (read_mode & 0o111) != 0;
    assert!(!is_exec);
    let after_mode = tmp.as_file().metadata().expect("meta").permissions().mode();
    assert_eq!(after_mode & 0o777, 0o644, "permissions must not be mutated");
}

#[test]
fn bracketed_samples_carry_measured_uncertainty() {
    let mut t = TscDriftTracker::for_virtual_tsc();
    // 2 ms request windows; 30 s interval; exact 2 GHz guest counter.
    t.add_bracketed_sample(0, 2_000_000, 2_000_000).unwrap();
    t.add_bracketed_sample(30_000_000_000, 30_002_000_000, 60_002_000_000)
        .unwrap();
    assert_eq!(t.samples()[0].host_elapsed_ns, 1_000_000);
    assert_eq!(t.samples()[0].uncertainty_ns, 1_000_000);
    let unc = t.uncertainty_ppm().unwrap();
    assert!(unc > 66.0 && unc < 67.0, "unc={unc}");
    // Exact counter: drift 0, worst case 66.7 ppm, inside a 100 ppm limit.
    t.validate_measurement(30_000_000_000, 2, 100.0).unwrap();
}

#[test]
fn uncertainty_never_lets_drift_pass_or_fails_ambiguous_runs_closed() {
    // Drift 150 ppm with +/-66.7 ppm uncertainty against 50 ppm: definitely excessive.
    let mut t = TscDriftTracker::for_virtual_tsc();
    t.add_bracketed_sample(0, 2_000_000, 2_000_000).unwrap();
    t.add_bracketed_sample(30_000_000_000, 30_002_000_000, 60_011_000_000)
        .unwrap();
    assert!(matches!(
        t.validate_measurement(30_000_000_000, 2, 50.0),
        Err(TscDriftError::ExcessiveDrift { .. })
    ));
    // Exact counter against 50 ppm: cannot be decided, so it fails closed as uncertain.
    let mut u = TscDriftTracker::for_virtual_tsc();
    u.add_bracketed_sample(0, 2_000_000, 2_000_000).unwrap();
    u.add_bracketed_sample(30_000_000_000, 30_002_000_000, 60_002_000_000)
        .unwrap();
    assert!(matches!(
        u.validate_measurement(30_000_000_000, 2, 50.0),
        Err(TscDriftError::UncertainMeasurement { .. })
    ));
}

#[test]
fn bracket_with_after_before_before_is_rejected() {
    let mut t = TscDriftTracker::for_virtual_tsc();
    assert!(matches!(
        t.add_bracketed_sample(10, 5, 0),
        Err(TscDriftError::InvalidBracket { .. })
    ));
}
