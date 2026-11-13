mod common;

use common::{sample_run_record, DeterministicTestSigner, DeterministicTestVerifier};
use hermetic_attest::base64::{base64_decode, base64_encode};
use hermetic_attest::canonical::{MAX_CANONICAL_BYTES, MAX_CANONICAL_DEPTH};
use hermetic_attest::dsse::{MAX_KEY_ID_BYTES, MAX_SIGNATURE_BYTES};
use hermetic_attest::fs::MAX_FILE_BYTES;
use hermetic_attest::run::{MAX_RECORD_TEXT_BYTES, MAX_SUBSTRATE_ITEMS, MAX_TEE_QUOTE_BYTES};
use hermetic_attest::score_card::{MAX_SCORE_CARD_DETAIL_BYTES, MAX_SCORE_CARD_TASKS};
use hermetic_attest::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn signer() -> DeterministicTestSigner {
    DeterministicTestSigner {
        key_id: "key".into(),
        secret: b"test key".to_vec(),
    }
}

fn verifier() -> DeterministicTestVerifier {
    DeterministicTestVerifier {
        key_id: "key".into(),
        secret: b"test key".to_vec(),
    }
}

fn audit() -> TranscriptAuditRecord {
    TranscriptAuditRecord {
        run_digest: compute_run_digest(&sample_run_record()).unwrap(),
        label: AuditLabel::Retrieved,
        confidence: 500,
        evidence_spans: vec![EvidenceSpan {
            log_name: "gateway".into(),
            start: 0,
            end: 1,
        }],
    }
}

#[test]
fn filesystem_refuses_symlinked_ancestors_for_reads_and_writes() {
    let dir = tempfile::tempdir().unwrap();
    let actual = dir.path().join("actual");
    std::fs::create_dir_all(actual.join("nested")).unwrap();
    std::fs::write(actual.join("nested/record"), b"secret").unwrap();
    symlink(&actual, dir.path().join("link")).unwrap();
    let path = dir.path().join("link/nested/record");
    assert!(safe_read_file(&path, 100).is_err());
    assert!(safe_atomic_write_file(&path, b"replacement").is_err());
    assert_eq!(
        std::fs::read(actual.join("nested/record")).unwrap(),
        b"secret"
    );
}

#[test]
fn filesystem_maximum_cap_never_overflows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    std::fs::write(&path, b"record").unwrap();
    assert_eq!(safe_read_file(&path, usize::MAX).unwrap(), b"record");
}

#[test]
fn filesystem_rejects_oversized_writes_before_creating_files() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        safe_atomic_write_file(&dir.path().join("record"), &vec![0; MAX_FILE_BYTES + 1]).is_err()
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn filesystem_requires_a_protected_output_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(safe_atomic_write_file(&dir.path().join("record"), b"record").is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn filesystem_refuses_special_files_and_symlink_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("socket");
    let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    assert!(safe_read_file(&socket_path, 100).is_err());
    assert!(safe_atomic_write_file(&socket_path, b"record").is_err());
    let target = dir.path().join("target");
    std::fs::write(&target, b"target").unwrap();
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(safe_atomic_write_file(&link, b"record").is_err());
    assert!(std::fs::symlink_metadata(link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read(target).unwrap(), b"target");
}

#[test]
fn filesystem_errors_hide_paths_and_publication_keeps_mode_0600() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = dir.path().join("target");
    safe_atomic_write_file(&target, b"old").unwrap();
    safe_atomic_write_file(&target, b"new").unwrap();
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(safe_read_file(&target, 3).unwrap(), b"new");
    let link = dir.path().join("PRIVATE_HOST_PATH");
    symlink(&target, &link).unwrap();
    let error = safe_read_file(&link, 100).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("PRIVATE_HOST_PATH"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn strict_records_reject_even_empty_d5b_lists() {
    let mut record = sample_run_record();
    record.d5b_warning_list = Some(vec![]);
    assert!(record.validate().is_err());
    assert!(RunRecord::from_json_str(&serde_json::to_string(&record).unwrap()).is_err());
    assert!(Statement::new_run_statement(record).is_err());
}

#[test]
fn world_version_must_name_actual_world_root() {
    let mut record = sample_run_record();
    record.world_root = Digest::from_sha256(b"different world");
    assert!(record.validate().is_err());
    assert!(RunRecord::from_json_str(&serde_json::to_string(&record).unwrap()).is_err());
    assert!(Statement::new_run_statement(record.clone()).is_err());
    assert!(generate_score_card("Bench", "v1", &[record], &[], &[]).is_err());
}

#[test]
fn base_commit_requires_a_full_lowercase_object_id() {
    for commit in ["a".to_string(), "A".repeat(40), "f".repeat(41)] {
        let mut record = sample_run_record();
        record.base_commit = commit;
        assert!(record.validate().is_err());
    }
    let mut record = sample_run_record();
    record.base_commit = "a".repeat(64);
    record.validate().unwrap();
}

#[test]
fn timestamps_require_rfc3339_widths_digits_and_known_utc() {
    for timestamp in [
        "2020-1-01T00:00:00Z",
        "2020-01-1T00:00:00Z",
        "+2020-01-01T00:00:00Z",
        "2020-01-01T0:00:00Z",
        "2020-01-01T00:+0:00Z",
        "2020-01-01T00:00:00-00:00",
    ] {
        let mut record = sample_run_record();
        record.t_world = timestamp.into();
        record.t_clock = timestamp.into();
        assert!(record.validate().is_err(), "accepted {timestamp}");
    }
    let mut record = sample_run_record();
    record.t_clock = "2020-01-01T00:00:00.123456789+00:00".into();
    record.validate().unwrap();
}

#[test]
fn typed_records_bound_all_variable_fields() {
    let mut records = Vec::new();
    let mut record = sample_run_record();
    record.version_tuple.spec_version.clear();
    records.push(record);
    let mut record = sample_run_record();
    record.version_tuple.sealcheck_version = "v".repeat(MAX_RECORD_TEXT_BYTES + 1);
    records.push(record);
    let mut record = sample_run_record();
    record.exemption_list = vec!["p".repeat(MAX_RECORD_TEXT_BYTES + 1)];
    records.push(record);
    let mut record = sample_run_record();
    record.exemption_list = (0..=MAX_SUBSTRATE_ITEMS)
        .map(|i| format!("pkg-{i:08}"))
        .collect();
    records.push(record);
    let mut record = sample_run_record();
    record.tee_quote = Some(TeeQuote {
        platform: TeePlatform::Tdx,
        quote: "x".repeat(MAX_TEE_QUOTE_BYTES + 1),
    });
    records.push(record);
    let mut record = sample_run_record();
    record.agent_mode = AgentMode::G;
    record.harness_command_log_head = None;
    record.gateway_log_head = Some(Digest::from_sha256(b"log"));
    record.history_rewrite_count = Some(0);
    record.gateway_adapter_version = Some(String::new());
    records.push(record);
    for record in records {
        assert!(record.validate().is_err());
        assert!(RunRecord::from_json_str(&serde_json::to_string(&record).unwrap()).is_err());
        assert!(Statement::new_run_statement(record).is_err());
    }
}

#[test]
fn digest_algorithms_are_known_and_have_fixed_lengths() {
    assert!(Digest::parse(&format!("unknown:{}", "f".repeat(64))).is_err());
    assert!(Digest::parse(&format!("unknown:{}", "f".repeat(4096))).is_err());
    assert!(Digest::parse(&format!("sha512:{}", "f".repeat(128))).is_ok());
    assert!(Digest::parse(&format!("blake3:{}", "f".repeat(64))).is_ok());
}

#[test]
fn audits_require_sha256_run_digests_and_bounded_log_names() {
    let mut record = audit();
    record.run_digest = Digest::from_blake3_hex(&"a".repeat(64)).unwrap();
    assert!(record.validate().is_err());
    assert!(Statement::new_audit_statement(record).is_err());
    for name in ["x".repeat(MAX_RECORD_TEXT_BYTES + 1), "log\nsecret".into()] {
        let mut record = audit();
        record.evidence_spans[0].log_name = name;
        assert!(record.validate().is_err());
        assert!(
            TranscriptAuditRecord::from_json_str(&serde_json::to_string(&record).unwrap()).is_err()
        );
    }
}

#[test]
fn parser_and_signer_diagnostics_never_echo_supplied_text() {
    let marker = "PRIVATE_TOKEN_12345";
    let mut value = serde_json::to_value(sample_run_record()).unwrap();
    value["task_class"] = marker.into();
    let error = RunRecord::from_json_str(&value.to_string()).unwrap_err();
    assert!(!format!("{error} {error:?}").contains(marker));
    let mut value = serde_json::to_value(audit()).unwrap();
    value[marker] = true.into();
    let error = TranscriptAuditRecord::from_json_str(&value.to_string()).unwrap_err();
    assert!(!format!("{error} {error:?}").contains(marker));
    let error =
        verify_run_envelope(&format!(r#"{{"{marker}":true}}"#), None, &verifier()).unwrap_err();
    assert!(!format!("{error} {error:?}").contains(marker));
    let error = SignatureError::SigningFailed(marker.into());
    assert!(!format!("{error} {error:?}").contains(marker));
    let mut record = sample_run_record();
    record.t_world = marker.into();
    let error = record.validate().unwrap_err();
    assert!(!format!("{error} {error:?}").contains(marker));
}

#[test]
fn canonical_encoding_bounds_depth_and_total_bytes_before_cloning() {
    let mut value = serde_json::Value::Null;
    for _ in 0..=MAX_CANONICAL_DEPTH {
        value = serde_json::Value::Array(vec![value]);
    }
    assert!(canonicalize_value(&value).is_err());
    assert!(to_canonical_json_bytes(&value).is_err());
    let text = serde_json::to_string(&value).unwrap();
    assert!(canonical_json_from_str(&text, usize::MAX).is_err());
    let value = "x".repeat(MAX_CANONICAL_BYTES + 1);
    assert!(to_canonical_json_bytes(&value).is_err());
}

#[test]
fn score_cards_revalidate_records_and_bound_supplementary_inputs() {
    let mut record = sample_run_record();
    record.harness_command_log_head = None;
    assert!(generate_score_card("Bench", "v1", &[record], &[], &[]).is_err());
    let records = [sample_run_record()];
    let task = ExcludedTask {
        task_id: "task".into(),
        detector: "D0".into(),
        reason: None,
    };
    assert!(generate_score_card(
        "Bench",
        "v1",
        &records,
        &vec![task.clone(); MAX_SCORE_CARD_TASKS + 1],
        &[]
    )
    .is_err());
    let task = ExcludedTask {
        reason: Some("x".repeat(MAX_SCORE_CARD_DETAIL_BYTES + 1)),
        ..task
    };
    assert!(generate_score_card("Bench", "v1", &records, &[task], &[]).is_err());
    assert!(generate_score_card(
        &"x".repeat(MAX_RECORD_TEXT_BYTES + 1),
        "v1",
        &records,
        &[],
        &[]
    )
    .is_err());
}

#[test]
fn base64_caps_measure_decoded_bytes_at_exact_boundary() {
    assert_eq!(base64_decode("Zg==", 1).unwrap(), b"f");
    assert_eq!(base64_decode("Zm8=", 2).unwrap(), b"fo");
    assert!(base64_decode("Zm8=", 1).is_err());
    assert!(base64_decode("Zg==", 0).is_err());
    assert_eq!(base64_decode("Zm9v", usize::MAX).unwrap(), b"foo");
}

#[test]
fn dsse_signing_enforces_payload_key_and_signature_caps() {
    let statement = Statement {
        statement_type: IN_TOTO_STATEMENT_V1_TYPE.into(),
        subject: vec![],
        predicate_type: PREDICATE_TYPE_RUN_V1.into(),
        predicate: "x".repeat(MAX_PAYLOAD_BYTES + 1),
    };
    assert!(DsseEnvelope::sign_statement(&statement, &signer()).is_err());
    let statement = Statement::new_run_statement(sample_run_record()).unwrap();
    let signer = DeterministicTestSigner {
        key_id: "k".repeat(MAX_KEY_ID_BYTES + 1),
        secret: vec![],
    };
    assert!(DsseEnvelope::sign_statement(&statement, &signer).is_err());
    struct OversizedSigner;
    impl Signer for OversizedSigner {
        fn key_id(&self) -> Option<String> {
            None
        }
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignatureError> {
            Ok(vec![0; MAX_SIGNATURE_BYTES + 1])
        }
    }
    assert!(DsseEnvelope::sign_statement(&statement, &OversizedSigner).is_err());
}

#[test]
fn dsse_rejects_additional_or_noncanonical_subject_digests() {
    let base = Statement::new_run_statement(sample_run_record()).unwrap();
    let mut statements = vec![];
    let mut statement = base.clone();
    statement.subject.push(StatementSubject::from_digest(
        "other",
        &Digest::from_sha256(b"wrong"),
    ));
    statements.push(statement);
    let mut statement = base.clone();
    statement.subject[0]
        .digest
        .insert("blake3".into(), "a".repeat(64));
    statements.push(statement);
    let mut statement = base;
    for digest in statement.subject[0].digest.values_mut() {
        *digest = digest.to_uppercase();
    }
    statements.push(statement);
    for statement in statements {
        let envelope = DsseEnvelope::sign_statement(&statement, &signer()).unwrap();
        assert!(verify_run_envelope(
            &serde_json::to_string(&envelope).unwrap(),
            None,
            &verifier()
        )
        .is_err());
    }
    let mut statement = Statement::new_audit_statement(audit()).unwrap();
    let digest = statement.predicate.run_digest.clone();
    statement.subject.push(StatementSubject::from_digest(
        "other",
        &Digest::from_sha256(b"wrong"),
    ));
    let envelope = DsseEnvelope::sign_statement(&statement, &signer()).unwrap();
    assert!(verify_audit_envelope(
        &serde_json::to_string(&envelope).unwrap(),
        &digest,
        &verifier()
    )
    .is_err());
}

#[test]
fn dsse_validates_all_signature_inputs_before_verification() {
    struct MustNotVerify;
    impl Verifier for MustNotVerify {
        fn verify(&self, _: Option<&str>, _: &[u8], _: &[u8]) -> Result<(), SignatureError> {
            panic!("verifier called before validating all signature inputs");
        }
    }
    let envelope = DsseEnvelope {
        payload: base64_encode(b"{}"),
        payload_type: DSSE_PAYLOAD_TYPE_IN_TOTO.into(),
        signatures: vec![
            DsseSignature {
                keyid: None,
                sig: "AAAA".into(),
            },
            DsseSignature {
                keyid: None,
                sig: "????".into(),
            },
        ],
    };
    assert!(envelope.verify_and_decode(&MustNotVerify).is_err());
}

#[test]
fn dsse_rejects_duplicate_subject_digest_keys() {
    let statement = Statement::new_run_statement(sample_run_record()).unwrap();
    let digest = compute_run_digest(&statement.predicate).unwrap();
    let json = serde_json::to_string(&statement).unwrap();
    let needle = format!(r#""digest":{{"sha256":"{}"}}"#, digest.hex());
    let duplicate = format!(
        r#""digest":{{"sha256":"{}","sha256":"{}"}}"#,
        "0".repeat(64),
        digest.hex()
    );
    assert_eq!(json.matches(&needle).count(), 1);
    let payload = json.replace(&needle, &duplicate).into_bytes();
    let signature = signer()
        .sign(&dsse_pae(DSSE_PAYLOAD_TYPE_IN_TOTO, &payload))
        .unwrap();
    let envelope = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE_IN_TOTO.into(),
        payload: base64_encode(&payload),
        signatures: vec![DsseSignature {
            keyid: Some("key".into()),
            sig: base64_encode(&signature),
        }],
    };
    assert!(verify_run_envelope(
        &serde_json::to_string(&envelope).unwrap(),
        None,
        &verifier()
    )
    .is_err());
}

#[test]
fn dsse_exact_payload_limit_round_trips() {
    let mut statement = Statement {
        statement_type: IN_TOTO_STATEMENT_V1_TYPE.into(),
        subject: vec![],
        predicate_type: PREDICATE_TYPE_RUN_V1.into(),
        predicate: String::new(),
    };
    let overhead = to_canonical_json_bytes(&statement).unwrap().len();
    statement.predicate = "x".repeat(MAX_PAYLOAD_BYTES - overhead);
    let envelope = DsseEnvelope::sign_statement(&statement, &signer()).unwrap();
    let bytes = envelope.verify_and_decode(&verifier()).unwrap();
    assert_eq!(bytes.len(), MAX_PAYLOAD_BYTES);
    assert_eq!(bytes, to_canonical_json_bytes(&statement).unwrap());
}
