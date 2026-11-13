use hermetic_attest::{
    AuditLabel, AuditValidationError, Digest, EvidenceSpan, TranscriptAuditRecord,
    MAX_AUDIT_RECORD_SIZE, MAX_EVIDENCE_SPANS,
};

fn sample_audit_record() -> TranscriptAuditRecord {
    TranscriptAuditRecord {
        run_digest: Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        label: AuditLabel::Derived,
        confidence: 950,
        evidence_spans: vec![
            EvidenceSpan {
                log_name: "agent_patch".to_string(),
                start: 10,
                end: 25,
            },
            EvidenceSpan {
                log_name: "world_server".to_string(),
                start: 100,
                end: 200,
            },
        ],
    }
}

#[test]
fn test_valid_audit_record() {
    let audit = sample_audit_record();
    assert!(audit.validate().is_ok());

    let json_str = serde_json::to_string(&audit).expect("serialize");
    let parsed = TranscriptAuditRecord::from_json_str(&json_str).expect("deserialize");
    assert_eq!(parsed, audit);
}

#[test]
fn test_audit_label_variants() {
    let mut audit = sample_audit_record();
    audit.label = AuditLabel::Retrieved;
    assert!(audit.validate().is_ok());

    let json_str = serde_json::to_string(&audit).expect("serialize");
    assert!(json_str.contains(r#""label":"retrieved""#));
}

#[test]
fn test_confidence_out_of_bounds() {
    let mut audit = sample_audit_record();
    audit.confidence = 1001;
    assert_eq!(
        audit.validate(),
        Err(AuditValidationError::ConfidenceOutOfBounds(1001))
    );

    audit.confidence = 1000;
    assert!(audit.validate().is_ok());

    audit.confidence = 0;
    assert!(audit.validate().is_ok());
}

#[test]
fn test_evidence_span_validation() {
    let mut audit = sample_audit_record();

    // Empty log name
    audit.evidence_spans = vec![EvidenceSpan {
        log_name: "".to_string(),
        start: 0,
        end: 10,
    }];
    assert_eq!(
        audit.validate(),
        Err(AuditValidationError::EmptyLogName { index: 0 })
    );

    // Invalid range (start > end)
    audit.evidence_spans = vec![EvidenceSpan {
        log_name: "test".to_string(),
        start: 20,
        end: 10,
    }];
    assert_eq!(
        audit.validate(),
        Err(AuditValidationError::InvalidEvidenceSpanRange {
            index: 0,
            start: 20,
            end: 10,
        })
    );

    // Unsorted spans
    audit.evidence_spans = vec![
        EvidenceSpan {
            log_name: "z_log".to_string(),
            start: 10,
            end: 20,
        },
        EvidenceSpan {
            log_name: "a_log".to_string(),
            start: 10,
            end: 20,
        },
    ];
    assert_eq!(
        audit.validate(),
        Err(AuditValidationError::UnsortedEvidenceSpans)
    );
}

#[test]
fn test_too_many_evidence_spans() {
    let mut audit = sample_audit_record();
    audit.evidence_spans = (0..=MAX_EVIDENCE_SPANS)
        .map(|i| EvidenceSpan {
            log_name: format!("log_{i:04}"),
            start: i as u64,
            end: i as u64 + 1,
        })
        .collect();
    assert!(matches!(
        audit.validate(),
        Err(AuditValidationError::TooManyEvidenceSpans { .. })
    ));
}

#[test]
fn test_size_cap_audit_record() {
    let huge_str = " ".repeat(MAX_AUDIT_RECORD_SIZE + 10);
    assert!(matches!(
        TranscriptAuditRecord::from_json_str(&huge_str),
        Err(AuditValidationError::SizeCapExceeded { .. })
    ));
}
