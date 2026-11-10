use hermetic_common::hash::{sha256_hex, ChainError, HashChain};
use sha2::{Digest, Sha256};

#[test]
fn test_sha256_hex() {
    let empty = sha256_hex(b"");
    assert_eq!(
        empty,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let hello = sha256_hex(b"hello world");
    assert_eq!(
        hello,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn test_hash_chain_vectors_and_tamper() {
    let mut chain = HashChain::new();
    assert_eq!(
        chain.head_hex(),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

    let records: [&[u8]; 3] = [b"first record", b"second record", b"third record"];

    // Compute expected heads manually with Sha256
    let mut current_head = [0u8; 32];
    let mut expected_heads = Vec::new();
    for r in records {
        let rec_hash = Sha256::digest(r);
        let mut h = Sha256::new();
        h.update(current_head);
        h.update(rec_hash);
        current_head = h.finalize().into();
        expected_heads.push(hex::encode(current_head));
    }

    // Verify append matches step-by-step
    for (i, r) in records.iter().enumerate() {
        let head = chain.append(r);
        assert_eq!(head, expected_heads[i]);
    }

    // Verification succeeds on correct records
    let verified = chain.verify(records).expect("verification should succeed");
    assert_eq!(verified, expected_heads[2]);

    // Standalone verify_records also succeeds
    let verified_records =
        HashChain::verify_records(records, &expected_heads[2]).expect("standalone verify succeeds");
    assert_eq!(verified_records, expected_heads[2]);

    // Tampered record fails verify
    let tampered_records: [&[u8]; 3] = [b"first record", b"tampered record", b"third record"];
    let err = chain.verify(tampered_records).unwrap_err();
    match err {
        ChainError::HeadMismatch { expected, actual } => {
            assert_eq!(expected, expected_heads[2]);
            assert_ne!(actual, expected);
        }
    }

    // Tampered verify_records fails
    assert!(HashChain::verify_records(tampered_records, &expected_heads[2]).is_err());
}
