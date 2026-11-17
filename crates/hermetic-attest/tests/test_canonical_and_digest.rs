mod common;
use common::{sample_run_record, sample_v1_0_run_record};
use hermetic_attest::{
    compute_run_digest, to_canonical_json_bytes, Digest, HostBootRecord, RunRecord,
};

#[test]
fn test_known_answer_run_digest() {
    let record = sample_run_record();
    let digest = compute_run_digest(&record).expect("compute digest");

    // The canonical JSON has deterministic sorted keys and compact formatting:
    let canonical_bytes = to_canonical_json_bytes(&record).expect("canonical bytes");
    let sha256_expected = Digest::from_sha256(&canonical_bytes);
    assert_eq!(digest, sha256_expected);

    // Hardcoded known-answer digest check to prevent silent format drift
    assert_eq!(
        digest.as_str(),
        "sha256:276890036858a059aa3a9fa90866df7d47345bca5011e77a340227aeb917b9a2"
    );
}

#[test]
fn test_known_answer_v1_0_run_digest() {
    let record = sample_v1_0_run_record();
    let digest = compute_run_digest(&record).expect("compute digest");

    let canonical_bytes = to_canonical_json_bytes(&record).expect("canonical bytes");
    let sha256_expected = Digest::from_sha256(&canonical_bytes);
    assert_eq!(digest, sha256_expected);

    // Old v1.0 records without boot_record keep their exact known-answer digest
    assert_eq!(
        digest.as_str(),
        "sha256:8f6dbdb819c5ddf82272a6245e128700869f671e2546eb82fbfc8acf6657f998"
    );
}

#[test]
fn test_field_order_and_whitespace_independence() {
    let record = sample_run_record();
    let original_digest = compute_run_digest(&record).expect("original digest");

    // Re-serialize with indentation and arbitrary whitespace
    let pretty_json = serde_json::to_string_pretty(&record).expect("pretty");
    let parsed_from_pretty: RunRecord = serde_json::from_str(&pretty_json).expect("parse pretty");
    let pretty_digest = compute_run_digest(&parsed_from_pretty).expect("pretty digest");
    assert_eq!(original_digest, pretty_digest);

    // Parse untyped value, reorder keys, serialize back
    let mut untyped: serde_json::Value = serde_json::from_str(&pretty_json).expect("untyped");
    if let serde_json::Value::Object(ref mut map) = untyped {
        // Reverse order of keys in JSON text
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.reverse();
        let mut reversed_obj = serde_json::Map::new();
        for k in keys {
            let v = map.get(&k).unwrap().clone();
            reversed_obj.insert(k, v);
        }
        untyped = serde_json::Value::Object(reversed_obj);
    }

    let reversed_json = serde_json::to_string(&untyped).expect("reversed json");
    let parsed_from_reversed: RunRecord =
        serde_json::from_str(&reversed_json).expect("parse reversed");
    let reversed_digest = compute_run_digest(&parsed_from_reversed).expect("reversed digest");
    assert_eq!(original_digest, reversed_digest);
}

#[test]
fn test_single_field_changes_alter_digest() {
    let base = sample_run_record();
    let base_digest = compute_run_digest(&base).expect("base digest");

    // 1. task_id changed
    let mut mut_record = base.clone();
    mut_record.task_id = "pytest-dev__pytest-6203".to_string();
    assert_ne!(base_digest, compute_run_digest(&mut_record).unwrap());

    // 2. request_count changed
    let mut mut_record = base.clone();
    mut_record.request_count = 43;
    assert_ne!(base_digest, compute_run_digest(&mut_record).unwrap());

    // 3. r1_coverage changed
    let mut mut_record = base.clone();
    mut_record.r1_coverage = Some(851);
    assert_ne!(base_digest, compute_run_digest(&mut_record).unwrap());

    // 4. date_leak_observed changed
    let mut mut_record = base.clone();
    mut_record.date_leak_observed = true;
    assert_ne!(base_digest, compute_run_digest(&mut_record).unwrap());

    // 5. t_world changed
    let mut mut_record = base.clone();
    mut_record.t_world = "2019-12-31T23:59:59Z".to_string();
    assert_ne!(base_digest, compute_run_digest(&mut_record).unwrap());

    // 6. world_root changed
    let mut mut_record = base.clone();
    mut_record.world_root =
        Digest::parse("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();
    assert_ne!(base_digest, compute_run_digest(&mut_record).unwrap());

    // 7. exemption_list changed
    let mut mut_record = base.clone();
    mut_record.exemption_list = vec!["pkg-a".to_string(), "pkg-c".to_string()];
    assert_ne!(base_digest, compute_run_digest(&mut_record).unwrap());

    // 8. boot_record changed
    let mut mut_record = base.clone();
    mut_record.boot_record = Some(HostBootRecord::sealed_disk());
    assert_ne!(base_digest, compute_run_digest(&mut_record).unwrap());
}
