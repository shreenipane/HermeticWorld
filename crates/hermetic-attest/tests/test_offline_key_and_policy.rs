mod common;
use common::sample_run_record;
use hermetic_attest::base64::{base64_decode, base64_encode};
use hermetic_attest::{
    check_against_classification, compute_run_digest, dsse_pae, ed25519_key_id,
    verify_audit_attestation, verify_run_attestation, AuditLabel, ClockLevel, Digest, DsseEnvelope,
    DsseError, Ed25519Signer, Ed25519Verifier, KeyError, ReplayGuard, RunBinding,
    RunClassification, RunRecord, RunStatus, Signer, Statement, TranscriptAuditRecord, Verifier,
    VerifyError, DSSE_PAYLOAD_TYPE_IN_TOTO,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde_json::Value;

/// Throwaway test key, generated in memory for this test only.
fn test_pkcs8() -> Vec<u8> {
    Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .unwrap()
        .as_ref()
        .to_vec()
}

fn keys() -> (Ed25519Signer, Ed25519Verifier) {
    let signer = Ed25519Signer::from_pkcs8(&test_pkcs8()).unwrap();
    let pk = signer.public_key();
    (signer, Ed25519Verifier::new(&[&pk]).unwrap())
}

fn signed_run(record: RunRecord, signer: &Ed25519Signer) -> String {
    let st = Statement::new_run_statement(record).unwrap();
    serde_json::to_string(&DsseEnvelope::sign_statement(&st, signer).unwrap()).unwrap()
}

/// Re-sign an arbitrary payload value (used to test missing fields and wrong types
/// behind a valid signature).
fn sign_raw_payload(payload: &Value, signer: &Ed25519Signer) -> String {
    let bytes = serde_json::to_vec(payload).unwrap();
    let sig = signer
        .sign(&dsse_pae(DSSE_PAYLOAD_TYPE_IN_TOTO, &bytes))
        .unwrap();
    serde_json::json!({
        "payload": base64_encode(&bytes),
        "payloadType": DSSE_PAYLOAD_TYPE_IN_TOTO,
        "signatures": [{"keyid": signer.key_id().unwrap(), "sig": base64_encode(&sig)}],
    })
    .to_string()
}

fn payload_of(envelope: &str) -> Value {
    let v: Value = serde_json::from_str(envelope).unwrap();
    serde_json::from_slice(&base64_decode(v["payload"].as_str().unwrap(), 1 << 20).unwrap())
        .unwrap()
}

fn verify(env: &str, verifier: &Ed25519Verifier) -> Result<Digest, VerifyError> {
    verify_run_attestation(
        env,
        verifier,
        &RunBinding::default(),
        &mut ReplayGuard::new(),
    )
    .map(|(_, d)| d)
}

#[test]
fn ed25519_round_trip_and_key_id() {
    let (signer, verifier) = keys();
    let env = signed_run(sample_run_record(), &signer);
    let digest = verify(&env, &verifier).unwrap();
    assert_eq!(digest, compute_run_digest(&sample_run_record()).unwrap());
    let kid = signer.key_id().unwrap();
    assert_eq!(kid, ed25519_key_id(&signer.public_key()));
    assert!(kid.starts_with("sha256:") && kid.len() == 71);
}

#[test]
fn ed25519_rejects_tampered_payload_and_signature() {
    let (signer, verifier) = keys();
    let env = signed_run(sample_run_record(), &signer);
    let mut v: Value = serde_json::from_str(&env).unwrap();

    // Payload changed after signing (request_count bumped).
    let mut payload = payload_of(&env);
    payload["predicate"]["request_count"] = Value::from(999_u64);
    let mut t = v.clone();
    t["payload"] = Value::from(base64_encode(&serde_json::to_vec(&payload).unwrap()));
    assert!(matches!(
        verify(&t.to_string(), &verifier),
        Err(VerifyError::Envelope(DsseError::SignatureVerification(_)))
    ));

    // One bit of the signature flipped.
    let mut sig = base64_decode(v["signatures"][0]["sig"].as_str().unwrap(), 1024).unwrap();
    sig[0] ^= 1;
    v["signatures"][0]["sig"] = Value::from(base64_encode(&sig));
    assert!(verify(&v.to_string(), &verifier).is_err());

    // Truncated signature.
    v["signatures"][0]["sig"] = Value::from(base64_encode(&sig[..63]));
    assert!(verify(&v.to_string(), &verifier).is_err());
}

#[test]
fn ed25519_rejects_wrong_missing_and_unknown_key_ids() {
    let (signer, _) = keys();
    let (_, other_verifier) = keys();
    let env = signed_run(sample_run_record(), &signer);
    assert!(verify(&env, &other_verifier).is_err());

    let pk = signer.public_key();
    let verifier = Ed25519Verifier::new(&[&pk]).unwrap();
    let mut v: Value = serde_json::from_str(&env).unwrap();
    v["signatures"][0].as_object_mut().unwrap().remove("keyid");
    assert!(verify(&v.to_string(), &verifier).is_err());
    v["signatures"][0]["keyid"] = Value::from(format!("sha256:{}", "0".repeat(64)));
    assert!(verify(&v.to_string(), &verifier).is_err());

    // A second, valid-looking but unsigned signature entry fails the whole envelope.
    let mut v: Value = serde_json::from_str(&env).unwrap();
    let extra = v["signatures"][0].clone();
    let mut extra2 = extra.clone();
    extra2["sig"] = Value::from(base64_encode(&[0u8; 64]));
    v["signatures"] = Value::from(vec![extra, extra2]);
    assert!(verify(&v.to_string(), &verifier).is_err());
}

#[test]
fn verifier_construction_rejects_bad_key_sets() {
    assert!(matches!(
        Ed25519Verifier::new(&[]),
        Err(KeyError::NoTrustedKeys)
    ));
    assert!(matches!(
        Ed25519Verifier::new(&[&[0u8; 31]]),
        Err(KeyError::InvalidPublicKey)
    ));
    let pk = [7u8; 32];
    assert!(matches!(
        Ed25519Verifier::new(&[&pk, &pk]),
        Err(KeyError::DuplicateTrustedKey)
    ));
    let many: Vec<&[u8]> = vec![&pk; 65];
    assert!(matches!(
        Ed25519Verifier::new(&many),
        Err(KeyError::TooManyTrustedKeys { .. })
    ));
}

#[test]
fn signer_loads_key_by_path_and_fd_and_refuses_hostile_files() {
    let dir = tempfile::tempdir().unwrap();
    let der = test_pkcs8();
    let key = dir.path().join("key.p8");
    std::fs::write(&key, &der).unwrap();
    let by_path = Ed25519Signer::from_pkcs8_path(&key).unwrap();
    let by_fd = Ed25519Signer::from_pkcs8_reader(std::fs::File::open(&key).unwrap()).unwrap();
    assert_eq!(by_path.public_key(), by_fd.public_key());

    // Public key file by path.
    let pubf = dir.path().join("key.pub");
    std::fs::write(&pubf, by_path.public_key()).unwrap();
    let verifier = Ed25519Verifier::from_public_key_path(&pubf).unwrap();
    verify(&signed_run(sample_run_record(), &by_path), &verifier).unwrap();

    // Symlinked key is refused.
    let link = dir.path().join("link.p8");
    std::os::unix::fs::symlink(&key, &link).unwrap();
    assert!(matches!(
        Ed25519Signer::from_pkcs8_path(&link),
        Err(KeyError::Read(_))
    ));
    // Garbage, empty and oversized keys are refused.
    assert!(matches!(
        Ed25519Signer::from_pkcs8(b"not a key"),
        Err(KeyError::InvalidPrivateKey)
    ));
    assert!(Ed25519Signer::from_pkcs8(&[]).is_err());
    assert!(matches!(
        Ed25519Signer::from_pkcs8_reader(&vec![0u8; 4096][..]),
        Err(KeyError::TooLarge { .. })
    ));
    let big = dir.path().join("big.p8");
    std::fs::write(&big, vec![0u8; 4096]).unwrap();
    assert!(Ed25519Signer::from_pkcs8_path(&big).is_err());
    // A directory is not a key.
    assert!(Ed25519Signer::from_pkcs8_path(dir.path()).is_err());
}

#[test]
fn signed_payload_with_missing_field_or_wrong_type_is_rejected() {
    let (signer, verifier) = keys();
    let env = signed_run(sample_run_record(), &signer);
    let base = payload_of(&env);

    for field in ["world_root", "run_status", "clock", "date_leak_observed"] {
        let mut p = base.clone();
        p["predicate"].as_object_mut().unwrap().remove(field);
        assert!(
            verify(&sign_raw_payload(&p, &signer), &verifier).is_err(),
            "missing {field}"
        );
    }
    for (field, bad) in [
        ("request_count", Value::from("12")),
        ("date_leak_observed", Value::from(0)),
        ("clock", Value::from("HIDDEN")),
        ("world_root", Value::from("sha256:XYZ")),
    ] {
        let mut p = base.clone();
        p["predicate"][field] = bad;
        assert!(
            verify(&sign_raw_payload(&p, &signer), &verifier).is_err(),
            "wrong type {field}"
        );
    }
    let mut p = base.clone();
    p["predicate"]["extra"] = Value::from(1);
    assert!(verify(&sign_raw_payload(&p, &signer), &verifier).is_err());
    // Re-signed but subject still names the old digest: mismatch.
    let mut p = base.clone();
    p["predicate"]["request_count"] = Value::from(5);
    assert!(matches!(
        verify(&sign_raw_payload(&p, &signer), &verifier),
        Err(VerifyError::Envelope(
            DsseError::SubjectDigestMismatch { .. }
        ))
    ));
    // Unchanged payload re-signed raw still verifies (control).
    verify(&sign_raw_payload(&base, &signer), &verifier).unwrap();
}

#[test]
fn replay_of_a_verified_record_is_rejected() {
    let (signer, verifier) = keys();
    let env = signed_run(sample_run_record(), &signer);
    let mut guard = ReplayGuard::new();
    let b = RunBinding::default();
    verify_run_attestation(&env, &verifier, &b, &mut guard).unwrap();
    assert_eq!(
        verify_run_attestation(&env, &verifier, &b, &mut guard).unwrap_err(),
        VerifyError::Replay
    );
    // Same record re-wrapped in a fresh envelope is still a replay.
    let env2 = signed_run(sample_run_record(), &signer);
    assert_eq!(
        verify_run_attestation(&env2, &verifier, &b, &mut guard).unwrap_err(),
        VerifyError::Replay
    );
    assert_eq!(guard.len(), 1);
    // A different record is admitted.
    let mut r = sample_run_record();
    r.request_count += 1;
    verify_run_attestation(&signed_run(r, &signer), &verifier, &b, &mut guard).unwrap();
}

#[test]
fn mismatched_world_root_bundle_and_other_bindings_are_rejected() {
    let (signer, verifier) = keys();
    let rec = sample_run_record();
    let env = signed_run(rec.clone(), &signer);
    let other = Digest::from_sha256(b"other world");
    let good = RunBinding {
        task_id: Some(rec.task_id.clone()),
        world_root: Some(rec.world_root.clone()),
        world_bundle: Some(rec.version_tuple.world_version.clone()),
        sealcheck_report_digest: Some(rec.sealcheck_report_digest.clone()),
        grader_image_digest: Some(rec.version_tuple.grader_image_digest.clone()),
    };
    verify_run_attestation(&env, &verifier, &good, &mut ReplayGuard::new()).unwrap();

    let cases: Vec<(RunBinding, &str)> = vec![
        (
            RunBinding {
                world_root: Some(other.clone()),
                ..good.clone()
            },
            "world_root",
        ),
        (
            RunBinding {
                world_bundle: Some(other.clone()),
                ..good.clone()
            },
            "world_version",
        ),
        (
            RunBinding {
                sealcheck_report_digest: Some(other.clone()),
                ..good.clone()
            },
            "sealcheck_report_digest",
        ),
        (
            RunBinding {
                grader_image_digest: Some(other.clone()),
                ..good.clone()
            },
            "grader_image_digest",
        ),
        (
            RunBinding {
                task_id: Some("other__task-1".into()),
                ..good.clone()
            },
            "task_id",
        ),
    ];
    for (binding, name) in cases {
        let mut guard = ReplayGuard::new();
        assert_eq!(
            verify_run_attestation(&env, &verifier, &binding, &mut guard).unwrap_err(),
            VerifyError::BindingMismatch(name)
        );
        // A rejected record is not remembered.
        assert!(guard.is_empty());
    }
}

#[test]
fn audit_requires_a_verified_run_and_matching_digest() {
    let (signer, verifier) = keys();
    let env = signed_run(sample_run_record(), &signer);
    let mut guard = ReplayGuard::new();
    let (_, run_digest) =
        verify_run_attestation(&env, &verifier, &RunBinding::default(), &mut guard).unwrap();
    let audit = TranscriptAuditRecord {
        run_digest: run_digest.clone(),
        label: AuditLabel::Derived,
        confidence: 900,
        evidence_spans: vec![],
    };
    let aenv = serde_json::to_string(
        &DsseEnvelope::sign_statement(&Statement::new_audit_statement(audit).unwrap(), &signer)
            .unwrap(),
    )
    .unwrap();
    verify_audit_attestation(&aenv, &verifier, &run_digest, &guard).unwrap();
    // Unverified run.
    assert_eq!(
        verify_audit_attestation(&aenv, &verifier, &run_digest, &ReplayGuard::new()).unwrap_err(),
        VerifyError::AuditRunNotVerified
    );
    // Audit replayed against another verified run.
    let mut r = sample_run_record();
    r.request_count += 1;
    let (_, other) = verify_run_attestation(
        &signed_run(r, &signer),
        &verifier,
        &RunBinding::default(),
        &mut guard,
    )
    .unwrap();
    assert!(verify_audit_attestation(&aenv, &verifier, &other, &guard).is_err());
    // Run envelope offered as an audit envelope.
    assert!(verify_audit_attestation(&env, &verifier, &run_digest, &guard).is_err());
}

fn classification(clock: &str, status: &str, flags: &[&str]) -> String {
    let reasons: Vec<&str> = if clock == "hidden" {
        vec![]
    } else {
        vec!["probe_incomplete"]
    };
    serde_json::json!({
        "schema": "hermetic-run-classification/v1",
        "run_digest": format!("sha256:{}", "a".repeat(64)),
        "clock": clock,
        "clock_reasons": reasons,
        "label": "derived",
        "confidence": 900,
        "status": status,
        "flags": flags,
    })
    .to_string()
}

#[test]
fn record_must_match_classifier_clock_date_leak_and_status() {
    let rec = sample_run_record(); // hidden, no leak, resolved
    let ok = RunClassification::from_json_str(&classification("hidden", "resolved", &[])).unwrap();
    check_against_classification(&rec, &ok).unwrap();

    let c = RunClassification::from_json_str(&classification("faked", "resolved", &[])).unwrap();
    assert_eq!(
        check_against_classification(&rec, &c).unwrap_err(),
        VerifyError::ClassificationMismatch("clock")
    );
    let c = RunClassification::from_json_str(&classification("hidden", "review", &[])).unwrap();
    assert_eq!(
        check_against_classification(&rec, &c).unwrap_err(),
        VerifyError::ClassificationMismatch("run_status")
    );
    for flag in ["date_leak_observed", "date_sentinel_not_run"] {
        let c =
            RunClassification::from_json_str(&classification("faked", "review", &[flag])).unwrap();
        assert!(c.date_leak_observed());
        let mut r = sample_run_record();
        r.clock = ClockLevel::Faked;
        r.run_status = RunStatus::Review;
        assert_eq!(
            check_against_classification(&r, &c).unwrap_err(),
            VerifyError::ClassificationMismatch("date_leak_observed")
        );
        r.date_leak_observed = true;
        check_against_classification(&r, &c).unwrap();
    }
}

#[test]
fn hostile_classification_documents_are_rejected() {
    let good: Value = serde_json::from_str(&classification("hidden", "resolved", &[])).unwrap();
    let mut cases: Vec<Value> = Vec::new();
    let mut set = |k: &str, v: Value| {
        let mut c = good.clone();
        c[k] = v;
        cases.push(c);
    };
    set("schema", Value::from("hermetic-run-classification/v2"));
    set("clock", Value::from("frozen"));
    set("clock", Value::from(1));
    set("status", Value::from("passed"));
    set("confidence", Value::from(1001));
    set("confidence", Value::from(0.5));
    set("confidence", Value::Null); // label without confidence
    set("run_digest", Value::from("sha256:ABC"));
    set("flags", serde_json::json!(["z", "a"]));
    set("flags", serde_json::json!(["a", "a"]));
    set("flags", serde_json::json!(["Bad Flag"]));
    set("flags", Value::from("date_leak_observed"));
    set("clock_reasons", serde_json::json!(["x"])); // hidden with reasons
    set("extra", Value::from(1));
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("flags");
    cases.push(missing);
    for c in cases {
        assert!(
            RunClassification::from_json_str(&c.to_string()).is_err(),
            "accepted {c}"
        );
    }
    let huge = format!("{{\"schema\":\"{}\"}}", "x".repeat(70 * 1024));
    assert!(RunClassification::from_json_str(&huge).is_err());
    assert!(RunClassification::from_json_str("[]").is_err());
    let flags: Vec<String> = (0..65).map(|i| format!("f{i:03}")).collect();
    let mut c = good.clone();
    c["flags"] = serde_json::json!(flags);
    assert!(RunClassification::from_json_str(&c.to_string()).is_err());
}

#[test]
fn hidden_clock_with_date_leak_is_an_invalid_record() {
    let mut r = sample_run_record();
    r.date_leak_observed = true;
    assert!(r.validate().is_err());
    r.clock = ClockLevel::Faked;
    r.validate().unwrap();
}

#[test]
fn verifier_trait_object_is_usable() {
    let (_, verifier) = keys();
    let v: &dyn Verifier = &verifier;
    assert!(v.verify(None, b"x", &[0u8; 64]).is_err());
}
