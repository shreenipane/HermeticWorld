use hermetic_common::world_manifest::{
    DispositionKind, ManifestCutoffs, PackagesRecord, Resources, RunSpec, SealLevel, SubstrateAtT,
    TaskClass, WorldManifest,
};
use hermetic_common::{
    redact_statement, should_exclude_d0, validate_and_merge_spans, DispositionError, RedactedSpan,
    TaskDispositionRecord, MAX_REDACTION_FRACTION, MIN_REMAINING_CHARS,
};
use std::collections::BTreeMap;

fn sample_manifest() -> WorldManifest {
    WorldManifest {
        spec_version: "hermetic-world/v1".to_string(),
        task_id: "test__task-001".to_string(),
        task_class: TaskClass::Dated,
        seal_level: SealLevel::Strict,
        cutoffs: ManifestCutoffs {
            t_world: "2024-01-15T00:00:00Z".to_string(),
            t_clock: "2024-01-15T00:00:00Z".to_string(),
            base_commit: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
            pkg_cutoff: "2024-01-15T00:00:00Z".to_string(),
        },
        repo_tree_digest: "blake3:0000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        rootfs_digest: "blake3:0000000000000000000000000000000000000000000000000000000000000002"
            .to_string(),
        packages: PackagesRecord {
            closure_root: "blake3:0000000000000000000000000000000000000000000000000000000000000003"
                .to_string(),
            baseline_month: "2024-01".to_string(),
            baseline_root:
                "blake3:0000000000000000000000000000000000000000000000000000000000000004"
                    .to_string(),
        },
        web: None,
        substrate: Vec::new(),
        substrate_at_t: SubstrateAtT::Full,
        exemptions: Vec::new(),
        dns_table: Vec::new(),
        world_ca_cert_sha256:
            "blake3:0000000000000000000000000000000000000000000000000000000000000007".to_string(),
        trust_store_paths: Vec::new(),
        run_spec: RunSpec {
            env: BTreeMap::new(),
            workdir: "/testbed".to_string(),
            user: "root".to_string(),
            entrypoint: vec!["/bin/bash".to_string()],
            resources: Resources {
                vcpus: 4,
                memory_mib: 8192,
                disk_mib: 20480,
                wall_time_s: 1800,
            },
        },
        sealcheck_report_digest:
            "blake3:0000000000000000000000000000000000000000000000000000000000000008".to_string(),
        dispositions: Vec::new(),
    }
}

#[test]
fn test_threshold_constants() {
    assert_eq!(MAX_REDACTION_FRACTION, 0.50);
    assert_eq!(MIN_REMAINING_CHARS, 20);
}

#[test]
fn test_redact_statement_removes_leak_without_logging_text() {
    let stmt = "Bug report header.\nLeak snippet: SECRET_CODE_123\nMore information.";
    let leak = "SECRET_CODE_123";
    let start = stmt.find(leak).expect("find leak");
    let end = start + leak.len();

    let (redacted, spans) = redact_statement(stmt, vec![(start, end)]).expect("redact statement");
    assert!(!redacted.contains(leak));
    assert!(redacted.contains("[REDACTED]"));

    assert_eq!(spans.len(), 1);
    let span = &spans[0];
    assert_eq!(span.start, start);
    assert_eq!(span.end, end);
    assert!(span.hash.starts_with("sha256:"));
    assert_eq!(span.sha256.len(), 64);

    let json_str = serde_json::to_string(&span).expect("serialize");
    assert!(!json_str.contains(leak));
}

#[test]
fn test_non_char_boundary_returns_error_never_panics() {
    // "é" in UTF-8 is 2 bytes: 0xC3 0xA9
    let stmt = "é";
    assert_eq!(stmt.len(), 2);

    let res = redact_statement(stmt, vec![(1, 2)]);
    assert_eq!(res, Err(DispositionError::InvalidCharBoundary(1)));

    let out_of_bounds = redact_statement(stmt, vec![(0, 5)]);
    assert_eq!(out_of_bounds, Err(DispositionError::OutOfBounds(0, 5, 2)));
}

#[test]
fn test_utf8_japanese_offsets_and_sha256_convention() {
    // "日本" in UTF-8: '日' is 3 bytes (0..3), '本' is 3 bytes (3..6).
    let stmt = "日本 issue description text here for testing.";
    assert_eq!("日本".len(), 6);

    let (redacted, spans) = redact_statement(stmt, vec![(0, 6)]).expect("redact 日本");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start, 0);
    assert_eq!(spans[0].end, 6);

    // sha256("日本") in hex
    let expected_sha256 = "cf2abf0c5be326cb922a70f8163f91079c4d9aa8655c60ead89ad545c9de2e92";
    assert_eq!(spans[0].sha256, expected_sha256);
    assert_eq!(spans[0].hash, format!("sha256:{expected_sha256}"));
    assert!(redacted.starts_with("[REDACTED]"));
}

#[test]
fn test_unsorted_nested_overlapping_and_duplicate_spans() {
    let stmt = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Unsorted: [(20, 30), (0, 5)]
    let merged_unsorted =
        validate_and_merge_spans(stmt, vec![(20, 30), (0, 5)]).expect("merge unsorted");
    assert_eq!(merged_unsorted, vec![(0, 5), (20, 30)]);

    // Nested: [(0, 30), (5, 10)]
    let merged_nested =
        validate_and_merge_spans(stmt, vec![(0, 30), (5, 10)]).expect("merge nested");
    assert_eq!(merged_nested, vec![(0, 30)]);

    // Overlapping: [(0, 15), (10, 25)]
    let merged_overlap =
        validate_and_merge_spans(stmt, vec![(0, 15), (10, 25)]).expect("merge overlap");
    assert_eq!(merged_overlap, vec![(0, 25)]);

    // Duplicates: [(5, 10), (5, 10)]
    let merged_dup =
        validate_and_merge_spans(stmt, vec![(5, 10), (5, 10)]).expect("merge duplicate");
    assert_eq!(merged_dup, vec![(5, 10)]);

    // Redaction with unsorted + nested spans applied correctly
    let (redacted, spans) =
        redact_statement(stmt, vec![(20, 30), (0, 5), (25, 35)]).expect("redact");
    assert_eq!(spans.len(), 2);
    assert_eq!(
        spans[0],
        RedactedSpan {
            start: 0,
            end: 5,
            sha256: hermetic_common::sha256_hex(b"01234"),
            hash: format!("sha256:{}", hermetic_common::sha256_hex(b"01234")),
        }
    );
    assert_eq!(spans[1].start, 20);
    assert_eq!(spans[1].end, 35);
    assert!(redacted.starts_with("[REDACTED]56789"));
}

#[test]
fn test_exact_threshold_boundaries_rust() {
    // Test 1: EXACT 50% fraction boundary
    // Statement length: 100 bytes.
    // Redacting 50 bytes -> fraction = 50 / 100 = 0.50 (<= 0.50 -> eligible, not excluded)
    // Redacting 51 bytes -> fraction = 51 / 100 = 0.51 (> 0.50 -> excluded!)
    let stmt_100 = "a".repeat(100);

    // Exactly 50% redacted: remaining non-ws chars = 50 (>= 20) -> should NOT exclude
    let spans_50 = vec![(0, 50)];
    assert!(
        !should_exclude_d0(&stmt_100, &spans_50),
        "Exact 50% must not be excluded"
    );

    // 51% redacted: remaining non-ws chars = 49 (>= 20), but fraction > 0.50 -> MUST exclude
    let spans_51 = vec![(0, 51)];
    assert!(
        should_exclude_d0(&stmt_100, &spans_51),
        "51% must be excluded"
    );

    // 49% redacted -> should NOT exclude
    let spans_49 = vec![(0, 49)];
    assert!(
        !should_exclude_d0(&stmt_100, &spans_49),
        "49% must not be excluded"
    );

    // Test 2: EXACT 20 remaining non-whitespace chars boundary
    // Let statement have 60 chars.
    // Redact 40 chars -> remaining non-ws = 20 chars (fraction = 40/60 = 0.667 which would exclude on fraction).
    // So let statement have 100 chars:
    // Redact 80 chars would exceed 50%.
    // To isolate MIN_REMAINING_CHARS:
    // Statement with lots of whitespace:
    // e.g. 10 chars of leak, 20 chars of letters, 70 spaces = 100 chars total.
    // Redacting 10 chars: fraction = 10% (<= 50%).
    // Remaining non-whitespace letters: exactly 20 -> should NOT exclude!
    let stmt_with_20_letters = format!("LEAK123456{}   {}", "X".repeat(20), " ".repeat(50));
    let leak_span = vec![(0, 10)];
    assert!(
        !should_exclude_d0(&stmt_with_20_letters, &leak_span),
        "Exactly 20 remaining non-whitespace chars must not be excluded"
    );

    // If remaining non-whitespace letters is 19 -> MUST exclude!
    let stmt_with_19_letters = format!("LEAK123456{}   {}", "X".repeat(19), " ".repeat(50));
    assert!(
        should_exclude_d0(&stmt_with_19_letters, &leak_span),
        "Fewer than 20 remaining non-whitespace chars (19) must be excluded"
    );

    // If remaining non-whitespace letters is 21 -> should NOT exclude!
    let stmt_with_21_letters = format!("LEAK123456{}   {}", "X".repeat(21), " ".repeat(50));
    assert!(
        !should_exclude_d0(&stmt_with_21_letters, &leak_span),
        "21 remaining non-whitespace chars must not be excluded"
    );
}

#[test]
fn test_manifest_repaired_produces_new_world_version() {
    let mut manifest = sample_manifest();
    let initial_root = manifest.world_root().expect("initial root");

    // Add repaired disposition
    manifest.add_disposition(
        DispositionKind::Repaired,
        "D0",
        "problem_statement_redacted: 1 span",
    );

    let repaired_root = manifest.world_root().expect("repaired root");
    assert_ne!(
        initial_root, repaired_root,
        "Repaired disposition must yield new world version"
    );
}

#[test]
fn test_task_disposition_record_json_schema() {
    let record = TaskDispositionRecord {
        task_id: "test__task-001".to_string(),
        disposition: "clean".to_string(),
        detectors: vec![],
        reason: "gate passed".to_string(),
        world_version: Some("blake3:abcdef".to_string()),
    };

    let json_val = serde_json::to_value(&record).expect("serde_json::to_value");
    assert_eq!(json_val["task_id"], "test__task-001");
    assert_eq!(json_val["disposition"], "clean");
    assert_eq!(json_val["detectors"], serde_json::json!([]));
    assert_eq!(json_val["reason"], "gate passed");
    assert_eq!(json_val["world_version"], "blake3:abcdef");
}

#[test]
fn test_should_exclude_rejects_untrusted_spans_without_panicking() {
    use hermetic_common::disposition::checked_should_exclude_d0;
    for spans in [
        vec![(1, 1)],
        vec![(1, 2)],
        vec![(2, 1)],
        vec![(0, usize::MAX)],
    ] {
        assert!(checked_should_exclude_d0("é", &spans).is_err());
        assert!(should_exclude_d0("é", &spans));
    }
    let statement = "a".repeat(100);
    let overlapping = [(20, 40), (0, 30), (10, 20)];
    assert_eq!(
        checked_should_exclude_d0(&statement, &overlapping),
        Ok(false)
    );
    assert!(!should_exclude_d0(&statement, &overlapping));
    assert!(should_exclude_d0("a", &vec![(0, 0); 4097]));
    assert!(should_exclude_d0(&"a".repeat(1024 * 1024 + 1), &[]));
}

#[test]
fn test_clean_disposition_rejected_in_manifest() {
    let mut manifest = serde_json::to_value(sample_manifest()).expect("serialize manifest");
    manifest["dispositions"] = serde_json::json!([{
        "kind": "clean", "detector": "none", "detail": "gate passed"
    }]);
    assert!(WorldManifest::from_json_str(&manifest.to_string()).is_err());
}

#[test]
fn test_empty_spans_rejected_before_merging() {
    for spans in [vec![(0, 0)], vec![(0, 1), (1, 1)]] {
        assert!(validate_and_merge_spans("xxxxxxxxxx", spans.clone()).is_err());
        assert!(redact_statement("xxxxxxxxxx", spans).is_err());
    }
}

#[test]
fn test_surviving_characters_shared_with_python() {
    for (survivors, excluded) in [
        ("[REDACTED]abcdefghij".to_string(), false),
        (
            format!("{}\u{001c}\u{001d}\u{001e}\u{001f}", "a".repeat(19)),
            false,
        ),
        (
            format!("{}\u{0085}\u{00a0}\u{2028}\u{2029}", "a".repeat(19)),
            true,
        ),
        ("a".repeat(20), false),
    ] {
        assert_eq!(
            should_exclude_d0(&format!("LEAK {survivors}"), &[(0, 4)]),
            excluded
        );
    }
    for spans in [vec![(0, 1), (1, 2)], vec![(0, 2), (1, 2)]] {
        assert!(redact_statement("é", spans).is_err());
    }
}
