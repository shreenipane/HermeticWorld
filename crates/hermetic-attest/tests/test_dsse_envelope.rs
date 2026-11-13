mod common;
use common::{sample_run_record, DeterministicTestSigner, DeterministicTestVerifier};
use hermetic_attest::{
    compute_run_digest, dsse_pae, verify_audit_envelope, verify_run_envelope, AuditLabel, Digest,
    DsseEnvelope, DsseError, DsseSignature, EvidenceSpan, Statement, StatementSubject,
    TranscriptAuditRecord, DSSE_PAYLOAD_TYPE_IN_TOTO, IN_TOTO_STATEMENT_V1_TYPE,
    MAX_ENVELOPE_JSON_BYTES, MAX_SIGNATURES, PREDICATE_TYPE_AUDIT_V1, PREDICATE_TYPE_RUN_V1,
};

#[test]
fn test_dsse_pae_spec_known_answers() {
    // Official DSSE spec vector 1:
    let pae1 = dsse_pae("http://example.com/HelloWorld", b"hello world");
    assert_eq!(
        pae1,
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    );

    // Official DSSE spec vector 2 (empty body):
    let pae2 = dsse_pae("application/vnd.in-toto+json", b"");
    assert_eq!(pae2, b"DSSEv1 28 application/vnd.in-toto+json 0 ");
}

#[test]
fn test_sign_and_verify_run_envelope() {
    let record = sample_run_record();
    let statement = Statement::new_run_statement(record.clone()).expect("new statement");
    assert_eq!(statement.statement_type, IN_TOTO_STATEMENT_V1_TYPE);
    assert_eq!(statement.predicate_type, PREDICATE_TYPE_RUN_V1);

    let signer = DeterministicTestSigner {
        key_id: "test-key-1".to_string(),
        secret: b"test-secret-bytes-1234".to_vec(),
    };
    let verifier = DeterministicTestVerifier {
        key_id: "test-key-1".to_string(),
        secret: b"test-secret-bytes-1234".to_vec(),
    };

    let envelope = DsseEnvelope::sign_statement(&statement, &signer).expect("sign");
    assert_eq!(envelope.payload_type, DSSE_PAYLOAD_TYPE_IN_TOTO);
    assert_eq!(envelope.signatures.len(), 1);
    assert_eq!(envelope.signatures[0].keyid.as_deref(), Some("test-key-1"));

    let envelope_json = serde_json::to_string(&envelope).expect("serialize envelope");
    let verified_statement = verify_run_envelope(&envelope_json, None, &verifier).expect("verify");
    assert_eq!(verified_statement.predicate, record);

    // Verify with expected digest
    let run_digest = compute_run_digest(&record).expect("run digest");
    let verified_with_digest = verify_run_envelope(&envelope_json, Some(&run_digest), &verifier)
        .expect("verify with digest");
    assert_eq!(verified_with_digest.predicate, record);
}

#[test]
fn test_verify_run_envelope_refuses_digest_mismatch() {
    let record = sample_run_record();
    let statement = Statement::new_run_statement(record).expect("statement");

    let signer = DeterministicTestSigner {
        key_id: "test-key".to_string(),
        secret: b"secret".to_vec(),
    };
    let verifier = DeterministicTestVerifier {
        key_id: "test-key".to_string(),
        secret: b"secret".to_vec(),
    };

    let envelope = DsseEnvelope::sign_statement(&statement, &signer).expect("sign");
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let bogus_digest =
        Digest::parse("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();
    let err = verify_run_envelope(&envelope_json, Some(&bogus_digest), &verifier);
    assert!(matches!(err, Err(DsseError::SubjectDigestMismatch { .. })));
}

#[test]
fn test_verify_run_envelope_refuses_tampered_subject_in_statement() {
    let record = sample_run_record();
    let mut statement = Statement::new_run_statement(record).expect("statement");

    // Tamper with subject in statement prior to signing
    let bogus_digest =
        Digest::parse("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();
    statement.subject = vec![StatementSubject::from_digest("tampered", &bogus_digest)];

    let signer = DeterministicTestSigner {
        key_id: "test-key".to_string(),
        secret: b"secret".to_vec(),
    };
    let verifier = DeterministicTestVerifier {
        key_id: "test-key".to_string(),
        secret: b"secret".to_vec(),
    };

    let envelope = DsseEnvelope::sign_statement(&statement, &signer).expect("sign");
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    // Recomputed digest from predicate must mismatch the statement's subject
    let err = verify_run_envelope(&envelope_json, None, &verifier);
    assert!(matches!(err, Err(DsseError::SubjectDigestMismatch { .. })));
}

#[test]
fn test_sign_and_verify_audit_envelope() {
    let run_digest =
        Digest::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    let audit_record = TranscriptAuditRecord {
        run_digest: run_digest.clone(),
        label: AuditLabel::Derived,
        confidence: 900,
        evidence_spans: vec![EvidenceSpan {
            log_name: "gateway".to_string(),
            start: 1,
            end: 5,
        }],
    };
    let statement = Statement::new_audit_statement(audit_record.clone()).expect("new audit stmt");
    assert_eq!(statement.predicate_type, PREDICATE_TYPE_AUDIT_V1);

    let signer = DeterministicTestSigner {
        key_id: "audit-key".to_string(),
        secret: b"audit-secret".to_vec(),
    };
    let verifier = DeterministicTestVerifier {
        key_id: "audit-key".to_string(),
        secret: b"audit-secret".to_vec(),
    };

    let envelope = DsseEnvelope::sign_statement(&statement, &signer).expect("sign");
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let verified = verify_audit_envelope(&envelope_json, &run_digest, &verifier).expect("verify");
    assert_eq!(verified.predicate, audit_record);

    // Mismatched expected run digest refused
    let wrong_digest =
        Digest::parse("sha256:9999999999abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    let err = verify_audit_envelope(&envelope_json, &wrong_digest, &verifier);
    assert!(matches!(err, Err(DsseError::SubjectDigestMismatch { .. })));
}

#[test]
fn test_refuse_unknown_payload_type() {
    let mut envelope = DsseEnvelope {
        payload: "e30=".to_string(),
        payload_type: "application/json".to_string(),
        signatures: vec![DsseSignature {
            keyid: None,
            sig: "AAAA".to_string(),
        }],
    };

    let verifier = DeterministicTestVerifier {
        key_id: "key".to_string(),
        secret: b"s".to_vec(),
    };

    let err = envelope.verify_and_decode(&verifier);
    assert_eq!(
        err,
        Err(DsseError::UnknownPayloadType("application/json".into()))
    );

    envelope.payload_type = "text/plain".to_string();
    assert_eq!(
        envelope.verify_and_decode(&verifier),
        Err(DsseError::UnknownPayloadType("text/plain".into()))
    );
}

#[test]
fn test_refuse_signature_count_limits() {
    let verifier = DeterministicTestVerifier {
        key_id: "key".to_string(),
        secret: b"s".to_vec(),
    };

    // No signatures
    let empty_sig_envelope = DsseEnvelope {
        payload: "e30=".to_string(),
        payload_type: DSSE_PAYLOAD_TYPE_IN_TOTO.to_string(),
        signatures: vec![],
    };
    assert_eq!(
        empty_sig_envelope.verify_and_decode(&verifier),
        Err(DsseError::NoSignatures)
    );

    // Exceeding MAX_SIGNATURES
    let excessive_sig_envelope = DsseEnvelope {
        payload: "e30=".to_string(),
        payload_type: DSSE_PAYLOAD_TYPE_IN_TOTO.to_string(),
        signatures: (0..=MAX_SIGNATURES)
            .map(|_| DsseSignature {
                keyid: None,
                sig: "AAAA".to_string(),
            })
            .collect(),
    };
    assert_eq!(
        excessive_sig_envelope.verify_and_decode(&verifier),
        Err(DsseError::TooManySignatures {
            count: MAX_SIGNATURES + 1,
            limit: MAX_SIGNATURES,
        })
    );
}

#[test]
fn test_size_cap_envelope() {
    let verifier = DeterministicTestVerifier {
        key_id: "key".to_string(),
        secret: b"s".to_vec(),
    };
    let huge = " ".repeat(MAX_ENVELOPE_JSON_BYTES + 10);
    assert!(matches!(
        verify_run_envelope(&huge, None, &verifier),
        Err(DsseError::SizeCapExceeded { .. })
    ));
}
