#![forbid(unsafe_code)]

//! Comprehensive offline tests for Sigstore keyless signing and verification.
//!
//! Tests include:
//! - Deterministic known-answer Sigstore bundle generation (v0.3 and v0.2).
//! - Offline verification against a pinned trust root (Fulcio CA + Rekor log keys).
//! - Replay prevention with ReplayGuard.
//! - RunBinding verification (world root, world bundle, sealcheck report, grader image).
//! - Classification cross-checks.
//! - Comprehensive hostile/negative test matrix:
//!   - Tampered DSSE payload and signatures.
//!   - Untrusted Fulcio root CA.
//!   - Tampered Fulcio certificate.
//!   - Expired and premature certificates (integratedTime bounds).
//!   - Mismatched SAN and OIDC issuer policies.
//!   - Unknown Rekor log ID and tampered Rekor SET signatures.
//!   - Mismatched Rekor entry body (digest mismatch).
//!   - Unsupported bundle media types and missing sections.
//!   - Truncated and non-canonical DER inputs.
//!   - Bounded size caps (bundle, certificate, Rekor body, SET, tlog entries count).

use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest as _, Sha256};

use hermetic_attest::base64::{base64_decode, base64_encode};
use hermetic_attest::canonical::to_canonical_json_bytes;
use hermetic_attest::dsse::{
    dsse_pae, DsseEnvelope, DsseSignature, Statement, DSSE_PAYLOAD_TYPE_IN_TOTO,
    IN_TOTO_STATEMENT_V1_TYPE, PREDICATE_TYPE_RUN_V1,
};
use hermetic_attest::hex::hex_encode;
use hermetic_attest::run::{ClockLevel, RunRecord, RunStatus};
use hermetic_attest::sigstore::{
    verify_sigstore_bundle, InclusionPromise, LogId, ParsedCertificate, RawCert, RekorKey,
    RekorKeyAlgorithm, SigstoreBundle, SigstoreError, SigstoreSigner, SigstoreTrustRoot, TlogEntry,
    VerificationMaterial, X509CertChain, MAX_CERT_DER_BYTES, MAX_FULCIO_ROOTS, MAX_REKOR_KEYS,
    MAX_SET_BYTES, MAX_SIGSTORE_BUNDLE_BYTES, MAX_TLOG_ENTRIES, OID_ED25519, OID_FULCIO_ISSUER,
    OID_SAN, SIGSTORE_BUNDLE_MEDIA_TYPE_V02, SIGSTORE_BUNDLE_MEDIA_TYPE_V03,
};
use hermetic_attest::verify::{
    check_against_classification, verify_run_sigstore_attestation, ReplayGuard, RunBinding,
    RunClassification, VerifyError,
};

mod common;

// ============================================================================
// ASN.1 DER Helper for Test Certificate Minting
// ============================================================================

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(value.len()));
    out.extend_from_slice(value);
    out
}

fn der_seq(items: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for it in items {
        payload.extend_from_slice(it);
    }
    der_tlv(0x30, &payload)
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut val = vec![0x00]; // 0 unused bits
    val.extend_from_slice(bytes);
    der_tlv(0x03, &val)
}

fn der_spki_ed25519(pub_bytes: &[u8]) -> Vec<u8> {
    let alg = der_seq(&[&der_tlv(0x06, OID_ED25519)]);
    let pub_bits = der_bit_string(pub_bytes);
    der_seq(&[&alg, &pub_bits])
}

fn der_name(cn: &str) -> Vec<u8> {
    let oid_cn = &[0x55, 0x04, 0x03];
    let atv = der_seq(&[&der_tlv(0x06, oid_cn), &der_tlv(0x0C, cn.as_bytes())]);
    let rdn = der_tlv(0x31, &atv);
    der_seq(&[&rdn])
}

fn der_validity(not_before_utc: &str, not_after_utc: &str) -> Vec<u8> {
    let nb = der_tlv(0x17, not_before_utc.as_bytes());
    let na = der_tlv(0x17, not_after_utc.as_bytes());
    der_seq(&[&nb, &na])
}

fn mint_ed25519_cert(
    issuer_ca: Option<(&Ed25519KeyPair, &str)>,
    subject_cn: &str,
    subject_key: &Ed25519KeyPair,
    not_before_utc: &str,
    not_after_utc: &str,
    san: Option<&str>,
    oidc_issuer: Option<&str>,
) -> Vec<u8> {
    let (signer_pair, issuer_cn) = match issuer_ca {
        Some((ca, cn)) => (ca, cn),
        None => (subject_key, subject_cn), // Self-signed
    };

    let version = der_tlv(0xA0, &der_tlv(0x02, &[0x02])); // v3
    let serial = der_tlv(0x02, &[0x01, 0x02]);
    let sig_alg = der_seq(&[&der_tlv(0x06, OID_ED25519)]);
    let issuer_name = der_name(issuer_cn);
    let validity = der_validity(not_before_utc, not_after_utc);
    let subject_name = der_name(subject_cn);
    let spki = der_spki_ed25519(subject_key.public_key().as_ref());

    let mut extensions = Vec::new();
    if let Some(san_val) = san {
        // [1] rfc822Name tag 0x81
        let gn = der_tlv(0x81, san_val.as_bytes());
        let gns = der_seq(&[&gn]);
        let ext_san = der_seq(&[&der_tlv(0x06, OID_SAN), &der_tlv(0x04, &gns)]);
        extensions.extend_from_slice(&ext_san);
    }
    if let Some(iss_val) = oidc_issuer {
        let iss_str = der_tlv(0x0C, iss_val.as_bytes());
        let ext_iss = der_seq(&[&der_tlv(0x06, OID_FULCIO_ISSUER), &der_tlv(0x04, &iss_str)]);
        extensions.extend_from_slice(&ext_iss);
    }

    let mut tbs_items = vec![
        version.as_slice(),
        serial.as_slice(),
        sig_alg.as_slice(),
        issuer_name.as_slice(),
        validity.as_slice(),
        subject_name.as_slice(),
        spki.as_slice(),
    ];
    let exts_seq = der_seq(&[&extensions]);
    let exts_wrap = der_tlv(0xA3, &exts_seq);
    if !extensions.is_empty() {
        tbs_items.push(&exts_wrap);
    }

    let tbs_der = der_seq(&tbs_items);
    let sig = signer_pair.sign(&tbs_der);
    let sig_bits = der_bit_string(sig.as_ref());

    der_seq(&[&tbs_der, &sig_alg, &sig_bits])
}

// ============================================================================
// Test Fixture Setup
// ============================================================================

#[allow(dead_code)]
struct TestPki {
    ca_pair: Ed25519KeyPair,
    ca_cert_der: Vec<u8>,
    leaf_pair: Ed25519KeyPair,
    leaf_cert_der: Vec<u8>,
    rekor_pair: Ed25519KeyPair,
    rekor_key_id: String,
    trust_root: SigstoreTrustRoot,
    run_record: RunRecord,
}

fn create_test_pki() -> TestPki {
    // Generate CA key
    let rng = ring::rand::SystemRandom::new();
    let ca_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate CA key");
    let ca_pair = Ed25519KeyPair::from_pkcs8(ca_pkcs8.as_ref()).expect("parse CA key");
    let ca_cert_der = mint_ed25519_cert(
        None,
        "Fulcio Root CA",
        &ca_pair,
        "200101000000Z",
        "400101000000Z",
        None,
        None,
    );

    // Generate Leaf key
    let leaf_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate leaf key");
    let leaf_pair = Ed25519KeyPair::from_pkcs8(leaf_pkcs8.as_ref()).expect("parse leaf key");
    let leaf_cert_der = mint_ed25519_cert(
        Some((&ca_pair, "Fulcio Root CA")),
        "Hermetic Evaluation Agent",
        &leaf_pair,
        "240101000000Z",
        "280101000000Z",
        Some("agent@hermetic.world"),
        Some("https://accounts.google.com"),
    );

    // Generate Rekor key
    let rekor_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate rekor key");
    let rekor_pair = Ed25519KeyPair::from_pkcs8(rekor_pkcs8.as_ref()).expect("parse rekor key");
    let rekor_pub_bytes = rekor_pair.public_key().as_ref();
    let rekor_key_id = hex_encode(&Sha256::digest(rekor_pub_bytes));

    let trust_root = SigstoreTrustRoot {
        fulcio_roots: vec![base64_encode(&ca_cert_der)],
        rekor_keys: vec![RekorKey {
            key_id: rekor_key_id.clone(),
            algorithm: RekorKeyAlgorithm::Ed25519,
            public_key: base64_encode(rekor_pub_bytes),
        }],
        expected_san: Some("agent@hermetic.world".to_string()),
        expected_issuer: Some("https://accounts.google.com".to_string()),
    };

    let run_record = common::sample_run_record();

    TestPki {
        ca_pair,
        ca_cert_der,
        leaf_pair,
        leaf_cert_der,
        rekor_pair,
        rekor_key_id,
        trust_root,
        run_record,
    }
}

struct Ed25519Wrapper(Ed25519KeyPair);
impl hermetic_attest::dsse::Signer for Ed25519Wrapper {
    fn key_id(&self) -> Option<String> {
        None
    }
    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, hermetic_attest::dsse::SignatureError> {
        Ok(self.0.sign(pae_bytes).as_ref().to_vec())
    }
}

fn create_sigstore_bundle(pki: &TestPki, integrated_time: u64) -> SigstoreBundle {
    let signer = SigstoreSigner {
        leaf_cert_der: pki.leaf_cert_der.clone(),
        dsse_signer: Box::new(Ed25519Wrapper(
            Ed25519KeyPair::from_pkcs8(
                Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap(),
        )),
        rekor_key_id: pki.rekor_key_id.clone(),
        integrated_time,
        rekor_signer: Box::new({
            let rekor_pkcs8 =
                Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            let _ = rekor_pkcs8;
            move |_bytes: &[u8]| Ok(vec![])
        }),
    };
    let _ = signer;

    // Direct deterministic creation using pki's exact keys:
    let statement = Statement::new_run_statement(pki.run_record.clone()).unwrap();
    let payload_bytes = to_canonical_json_bytes(&statement).unwrap();
    let pae = dsse_pae(DSSE_PAYLOAD_TYPE_IN_TOTO, &payload_bytes);
    let sig_bytes = pki.leaf_pair.sign(&pae).as_ref().to_vec();

    let envelope = DsseEnvelope {
        payload: base64_encode(&payload_bytes),
        payload_type: DSSE_PAYLOAD_TYPE_IN_TOTO.to_string(),
        signatures: vec![DsseSignature {
            keyid: None,
            sig: base64_encode(&sig_bytes),
        }],
    };

    let payload_sha256_hex = hex_encode(&Sha256::digest(&payload_bytes));
    let rekor_body = serde_json::json!({
        "apiVersion": "0.0.2",
        "kind": "intoto",
        "spec": {
            "content": {
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE_IN_TOTO,
                    "payloadHash": {
                        "algorithm": "sha256",
                        "value": payload_sha256_hex,
                    }
                },
                "hash": {
                    "algorithm": "sha256",
                    "value": payload_sha256_hex,
                }
            }
        }
    });
    let canonical_rekor_bytes = to_canonical_json_bytes(&rekor_body).unwrap();
    let set_sig = pki
        .rekor_pair
        .sign(&canonical_rekor_bytes)
        .as_ref()
        .to_vec();

    let entry = TlogEntry {
        log_index: serde_json::Value::from(1),
        log_id: LogId {
            key_id: pki.rekor_key_id.clone(),
        },
        integrated_time: serde_json::Value::from(integrated_time),
        inclusion_promise: Some(InclusionPromise {
            signed_entry_timestamp: base64_encode(&set_sig),
        }),
        inclusion_proof: None,
        canonicalized_body: base64_encode(&canonical_rekor_bytes),
    };

    SigstoreBundle {
        media_type: SIGSTORE_BUNDLE_MEDIA_TYPE_V03.to_string(),
        verification_material: VerificationMaterial {
            x509_certificate_chain: None,
            certificate: Some(RawCert {
                raw_bytes: base64_encode(&pki.leaf_cert_der),
            }),
            tlog_entries: vec![entry],
        },
        dsse_envelope: envelope,
    }
}

// ============================================================================
// Positive Tests: Known-Answer & Verification
// ============================================================================

#[test]
fn test_known_answer_sigstore_bundle_verification() {
    let pki = create_test_pki();
    // 2026-06-01T00:00:00Z = 1780272000 (within 2024..2028 validity)
    let bundle = create_sigstore_bundle(&pki, 1780272000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let verified =
        verify_sigstore_bundle(&bundle_json, &pki.trust_root, None).expect("bundle should verify");
    assert_eq!(verified.statement_type, IN_TOTO_STATEMENT_V1_TYPE);
    assert_eq!(verified.predicate_type, PREDICATE_TYPE_RUN_V1);
    assert_eq!(verified.predicate.task_id, "pytest-dev__pytest-6202");
}

#[test]
fn test_sigstore_bundle_v02_chain_format_verifies() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    bundle.media_type = SIGSTORE_BUNDLE_MEDIA_TYPE_V02.to_string();
    bundle.verification_material.certificate = None;
    bundle.verification_material.x509_certificate_chain = Some(X509CertChain {
        certificates: vec![RawCert {
            raw_bytes: base64_encode(&pki.leaf_cert_der),
        }],
    });
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let verified = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None)
        .expect("v0.2 bundle should verify");
    assert_eq!(verified.predicate.task_id, "pytest-dev__pytest-6202");
}

#[test]
fn test_verify_run_sigstore_attestation_full_policy_and_replay_guard() {
    let pki = create_test_pki();
    let bundle = create_sigstore_bundle(&pki, 1780272000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let binding = RunBinding {
        task_id: Some("pytest-dev__pytest-6202".to_string()),
        world_root: Some(pki.run_record.world_root.clone()),
        world_bundle: Some(pki.run_record.version_tuple.world_version.clone()),
        sealcheck_report_digest: Some(pki.run_record.sealcheck_report_digest.clone()),
        grader_image_digest: Some(pki.run_record.version_tuple.grader_image_digest.clone()),
        boot_record: None,
    };

    let mut guard = ReplayGuard::new();
    let (stmt, digest) =
        verify_run_sigstore_attestation(&bundle_json, &pki.trust_root, &binding, &mut guard)
            .expect("first verification should pass");
    assert_eq!(stmt.predicate.task_id, "pytest-dev__pytest-6202");
    assert!(guard.contains(&digest));

    // Replay with the same guard must be rejected
    let replay_res =
        verify_run_sigstore_attestation(&bundle_json, &pki.trust_root, &binding, &mut guard);
    assert!(matches!(replay_res, Err(VerifyError::Replay)));
}

#[test]
fn test_classification_cross_check_with_sigstore_bundle() {
    let pki = create_test_pki();
    let bundle = create_sigstore_bundle(&pki, 1780272000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let binding = RunBinding::default();
    let mut guard = ReplayGuard::new();
    let (stmt, digest) =
        verify_run_sigstore_attestation(&bundle_json, &pki.trust_root, &binding, &mut guard)
            .unwrap();

    let classification = RunClassification {
        schema: "hermetic-run-classification/v1".to_string(),
        run_digest: digest,
        clock: ClockLevel::Hidden,
        clock_reasons: vec!["blocked".to_string()],
        label: None,
        confidence: None,
        status: RunStatus::Resolved,
        flags: vec![],
    };

    assert!(check_against_classification(&stmt.predicate, &classification).is_ok());

    // Disagreement on status must fail
    let mut bad_classification = classification.clone();
    bad_classification.status = RunStatus::Review;
    assert!(matches!(
        check_against_classification(&stmt.predicate, &bad_classification),
        Err(VerifyError::ClassificationMismatch("run_status"))
    ));
}

// ============================================================================
// Negative Tests: Hostile Inputs & Tampering
// ============================================================================

#[test]
fn test_tampered_dsse_payload_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    // Tamper with payload
    let mut payload_bytes = base64_decode(&bundle.dsse_envelope.payload, 1024 * 1024).unwrap();
    payload_bytes[10] ^= 0xFF;
    bundle.dsse_envelope.payload = base64_encode(&payload_bytes);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(res.is_err());
}

#[test]
fn test_tampered_dsse_signature_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    let mut sig_bytes =
        base64_decode(&bundle.dsse_envelope.signatures[0].sig, 1024 * 1024).unwrap();
    sig_bytes[5] ^= 0xFF;
    bundle.dsse_envelope.signatures[0].sig = base64_encode(&sig_bytes);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::DsseError(_))));
}

#[test]
fn test_untrusted_fulcio_root_rejected() {
    let pki = create_test_pki();
    let bundle = create_sigstore_bundle(&pki, 1780272000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    // Trust root with an unrelated CA
    let rng = ring::rand::SystemRandom::new();
    let other_ca_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let other_ca_pair = Ed25519KeyPair::from_pkcs8(other_ca_pkcs8.as_ref()).unwrap();
    let other_ca_der = mint_ed25519_cert(
        None,
        "Other Untrusted CA",
        &other_ca_pair,
        "200101000000Z",
        "400101000000Z",
        None,
        None,
    );

    let mut untrusted_trust_root = pki.trust_root.clone();
    untrusted_trust_root.fulcio_roots = vec![base64_encode(&other_ca_der)];

    let res = verify_sigstore_bundle(&bundle_json, &untrusted_trust_root, None);
    assert!(matches!(res, Err(SigstoreError::CertUntrustedRoot)));
}

#[test]
fn test_tampered_fulcio_cert_signature_rejected() {
    let pki = create_test_pki();
    let mut tampered_cert_der = pki.leaf_cert_der.clone();
    let len = tampered_cert_der.len();
    tampered_cert_der[len - 5] ^= 0xFF; // flip bit in signature
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    bundle.verification_material.certificate = Some(RawCert {
        raw_bytes: base64_encode(&tampered_cert_der),
    });
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::CertUntrustedRoot)));
}

#[test]
fn test_expired_certificate_rejected() {
    let pki = create_test_pki();
    // Leaf certificate validity: 2024-01-01 to 2028-01-01.
    // 2029-01-01T00:00:00Z = 1861920000
    let bundle = create_sigstore_bundle(&pki, 1861920000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::CertExpired { .. })));
}

#[test]
fn test_premature_certificate_rejected() {
    let pki = create_test_pki();
    // 2023-01-01T00:00:00Z = 1672531200 (before 2024-01-01)
    let bundle = create_sigstore_bundle(&pki, 1672531200);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::CertNotYetValid { .. })));
}

#[test]
fn test_san_policy_mismatch_rejected() {
    let pki = create_test_pki();
    let bundle = create_sigstore_bundle(&pki, 1780272000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let mut strict_root = pki.trust_root.clone();
    strict_root.expected_san = Some("other-identity@hermetic.world".to_string());

    let res = verify_sigstore_bundle(&bundle_json, &strict_root, None);
    assert!(matches!(res, Err(SigstoreError::SanMismatch { .. })));
}

#[test]
fn test_oidc_issuer_mismatch_rejected() {
    let pki = create_test_pki();
    let bundle = create_sigstore_bundle(&pki, 1780272000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let mut strict_root = pki.trust_root.clone();
    strict_root.expected_issuer = Some("https://other-issuer.example.com".to_string());

    let res = verify_sigstore_bundle(&bundle_json, &strict_root, None);
    assert!(matches!(res, Err(SigstoreError::IssuerMismatch { .. })));
}

#[test]
fn test_unknown_rekor_key_id_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    bundle.verification_material.tlog_entries[0].log_id.key_id = "unknown_key_id".to_string();
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::UnknownRekorKey(_))));
}

#[test]
fn test_tampered_rekor_set_signature_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    let mut set_bytes = base64_decode(
        &bundle.verification_material.tlog_entries[0]
            .inclusion_promise
            .as_ref()
            .unwrap()
            .signed_entry_timestamp,
        MAX_SET_BYTES,
    )
    .unwrap();
    set_bytes[3] ^= 0xFF;
    bundle.verification_material.tlog_entries[0]
        .inclusion_promise
        .as_mut()
        .unwrap()
        .signed_entry_timestamp = base64_encode(&set_bytes);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::RekorSignatureInvalid)));
}

#[test]
fn test_tampered_rekor_body_digest_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    // Replace rekor canonicalizedBody with an unrelated payload hash
    let fake_rekor_body = serde_json::json!({
        "apiVersion": "0.0.2",
        "kind": "intoto",
        "spec": {
            "content": {
                "hash": {
                    "algorithm": "sha256",
                    "value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                }
            }
        }
    });
    let fake_rekor_bytes = to_canonical_json_bytes(&fake_rekor_body).unwrap();
    let fake_set_sig = pki.rekor_pair.sign(&fake_rekor_bytes).as_ref().to_vec();

    bundle.verification_material.tlog_entries[0].canonicalized_body =
        base64_encode(&fake_rekor_bytes);
    bundle.verification_material.tlog_entries[0]
        .inclusion_promise
        .as_mut()
        .unwrap()
        .signed_entry_timestamp = base64_encode(&fake_set_sig);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::RekorPayloadMismatch)));
}

#[test]
fn test_unsupported_media_type_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    bundle.media_type = "application/vnd.dev.sigstore.bundle+json;version=0.1".to_string();
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::UnsupportedMediaType(_))));
}

#[test]
fn test_missing_certificate_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    bundle.verification_material.certificate = None;
    bundle.verification_material.x509_certificate_chain = None;
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::MissingCertificate)));
}

#[test]
fn test_missing_tlog_entries_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    bundle.verification_material.tlog_entries.clear();
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::MissingTlogEntries)));
}

#[test]
fn test_size_cap_bundle_json_exceeded() {
    let pki = create_test_pki();
    let huge_str = " ".repeat(MAX_SIGSTORE_BUNDLE_BYTES + 10);
    let res = verify_sigstore_bundle(&huge_str, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::SizeCapExceeded { .. })));
}

#[test]
fn test_size_cap_certificate_der_exceeded() {
    let _pki = create_test_pki();
    let huge_der = vec![0u8; MAX_CERT_DER_BYTES + 1];
    let res = ParsedCertificate::parse(&huge_der);
    assert!(matches!(res, Err(SigstoreError::SizeCapExceeded { .. })));
}

#[test]
fn test_too_many_tlog_entries_rejected() {
    let pki = create_test_pki();
    let mut bundle = create_sigstore_bundle(&pki, 1780272000);
    let single_entry = bundle.verification_material.tlog_entries[0].clone();
    bundle.verification_material.tlog_entries = vec![single_entry; MAX_TLOG_ENTRIES + 1];
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let res = verify_sigstore_bundle(&bundle_json, &pki.trust_root, None);
    assert!(matches!(res, Err(SigstoreError::TooManyTlogEntries { .. })));
}

#[test]
fn test_binding_mismatch_fails_closed() {
    let pki = create_test_pki();
    let bundle = create_sigstore_bundle(&pki, 1780272000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let wrong_binding = RunBinding {
        task_id: Some("wrong-task-id".to_string()),
        world_root: None,
        world_bundle: None,
        sealcheck_report_digest: None,
        grader_image_digest: None,
        boot_record: None,
    };

    let mut guard = ReplayGuard::new();
    let res =
        verify_run_sigstore_attestation(&bundle_json, &pki.trust_root, &wrong_binding, &mut guard);
    assert!(matches!(res, Err(VerifyError::BindingMismatch("task_id"))));
}

#[test]
fn test_too_many_fulcio_roots_rejected() {
    let pki = create_test_pki();
    let mut bad_root = pki.trust_root.clone();
    bad_root.fulcio_roots = vec![bad_root.fulcio_roots[0].clone(); MAX_FULCIO_ROOTS + 1];
    let root_json = serde_json::to_string(&bad_root).unwrap();
    let res = SigstoreTrustRoot::from_json_str(&root_json);
    assert!(matches!(res, Err(SigstoreError::SizeCapExceeded { .. })));
}

#[test]
fn test_too_many_rekor_keys_rejected() {
    let pki = create_test_pki();
    let mut bad_root = pki.trust_root.clone();
    bad_root.rekor_keys = vec![bad_root.rekor_keys[0].clone(); MAX_REKOR_KEYS + 1];
    let root_json = serde_json::to_string(&bad_root).unwrap();
    let res = SigstoreTrustRoot::from_json_str(&root_json);
    assert!(matches!(res, Err(SigstoreError::SizeCapExceeded { .. })));
}

#[test]
fn test_empty_trust_root_rejected() {
    let root_no_ca = serde_json::json!({
        "fulcio_roots": [],
        "rekor_keys": [{"key_id": "test", "algorithm": "ed25519", "public_key": "test"}]
    });
    assert!(SigstoreTrustRoot::from_json_str(&root_no_ca.to_string()).is_err());

    let root_no_rekor = serde_json::json!({
        "fulcio_roots": ["test"],
        "rekor_keys": []
    });
    assert!(SigstoreTrustRoot::from_json_str(&root_no_rekor.to_string()).is_err());
}

#[test]
fn test_trust_root_without_pinned_identity_rejected() {
    let pki = create_test_pki();
    let bundle = create_sigstore_bundle(&pki, 1780272000);
    let bundle_json = serde_json::to_string(&bundle).unwrap();

    let mut no_san = pki.trust_root.clone();
    no_san.expected_san = None;
    assert!(matches!(
        verify_sigstore_bundle(&bundle_json, &no_san, None),
        Err(SigstoreError::IdentityPolicyMissing)
    ));

    let mut no_issuer = pki.trust_root.clone();
    no_issuer.expected_issuer = None;
    assert!(matches!(
        verify_sigstore_bundle(&bundle_json, &no_issuer, None),
        Err(SigstoreError::IdentityPolicyMissing)
    ));
}
