use hermetic_sealcheck::{
    scan_tree, winnow_tokens, FingerprintSet, ScanOptions, Severity, Visibility,
};
use std::collections::HashSet;
use std::fs;
use tempfile::tempdir;

struct SimpleRng(u64);

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.0 >> 33) as u32
    }

    fn gen_range(&mut self, low: usize, high: usize) -> usize {
        let span = high - low;
        low + (self.next_u32() as usize % span)
    }
}

#[test]
fn test_winnow_guarantee_property() {
    let mut rng = SimpleRng::new(0x1234_5678_9abc_def0);

    let token_pool = [
        "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
        "lambda", "mu", "nu", "xi", "omicron", "pi", "rho", "sigma", "tau", "upsilon", "phi",
        "chi", "psi", "omega", "10", "20", "30", "42", "100", "+", "-", "*", "/", "=", "(", ")",
        ":", ",", ".", "def", "return", "if", "else", "while",
    ];

    // Shared run of exactly 15 tokens: w + k - 1 = 8 + 8 - 1 = 15
    let shared_run: Vec<String> = (0..15).map(|i| format!("shared_tok_{}", i)).collect();

    for iter in 0..50 {
        let len_before_a = rng.gen_range(5, 50);
        let len_after_a = rng.gen_range(5, 50);
        let mut seq_a = Vec::new();
        for _ in 0..len_before_a {
            let idx = rng.gen_range(0, token_pool.len());
            seq_a.push(token_pool[idx].to_string());
        }
        seq_a.extend(shared_run.clone());
        for _ in 0..len_after_a {
            let idx = rng.gen_range(0, token_pool.len());
            seq_a.push(token_pool[idx].to_string());
        }

        let len_before_b = rng.gen_range(5, 50);
        let len_after_b = rng.gen_range(5, 50);
        let mut seq_b = Vec::new();
        for _ in 0..len_before_b {
            let idx = rng.gen_range(0, token_pool.len());
            seq_b.push(token_pool[idx].to_string());
        }
        seq_b.extend(shared_run.clone());
        for _ in 0..len_after_b {
            let idx = rng.gen_range(0, token_pool.len());
            seq_b.push(token_pool[idx].to_string());
        }

        let fps_a = winnow_tokens(&seq_a);
        let fps_b = winnow_tokens(&seq_b);

        let set_a: HashSet<u64> = fps_a.into_iter().map(|f| f.hash).collect();
        let set_b: HashSet<u64> = fps_b.into_iter().map(|f| f.hash).collect();

        let common: HashSet<_> = set_a.intersection(&set_b).collect();
        assert!(
            !common.is_empty(),
            "Iteration {}: 15 shared tokens must yield at least one common winnow fingerprint",
            iter
        );
    }
}

#[test]
fn test_winnow_baseline_subtraction_gives_zero_gates() {
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();

    let base_code = r#"def calculate_sum(items):
    total = 0
    for item in items:
        total += item
    return total
"#;
    fs::write(base_tree.join("math.py"), base_code).expect("write base");

    let gold_patch = r#"diff --git a/math.py b/math.py
--- a/math.py
+++ b/math.py
@@ -1,5 +1,9 @@
 def calculate_sum(items):
+    # Extra validation routine added in fix
+    if not items:
+        return 0
     total = 0
     for item in items:
         total += item
     return total
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let findings = scan_tree(base_tree, &fp, &opts);
    let winnow_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D2" && f.channel == "winnow" && f.severity == Severity::Gate)
        .collect();

    assert!(
        winnow_gates.is_empty(),
        "Scanning base tree must produce 0 tier 3 winnow gates, got: {:?}",
        winnow_gates
    );
}

#[test]
fn test_winnow_planted_reformatted_copy_gives_tier3_gate() {
    let base_dir = tempdir().expect("tempdir");
    let base_tree = base_dir.path();

    let base_code = r#"def existing_helper():
    return 42
"#;
    fs::write(base_tree.join("core.py"), base_code).expect("write base");

    let gold_patch = r#"diff --git a/core.py b/core.py
--- a/core.py
+++ b/core.py
@@ -1,2 +1,10 @@
 def existing_helper():
     return 42
+
+def execute_complex_processing_pipeline(alpha, beta, gamma):
+    step_one_result = alpha * 100 + beta * 20
+    step_two_result = step_one_result - gamma + 42
+    if step_two_result > 0:
+        return step_two_result
+    return 0
"#;

    let fp = FingerprintSet::from_task(gold_patch, "", base_tree).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    // Plant a reformatted copy: different whitespace, split lines, removed comments
    let target_dir = tempdir().expect("tempdir");
    let reformatted = r#"def execute_complex_processing_pipeline(
    alpha,
    beta,
    gamma
):
    step_one_result=alpha*100+beta*20
    step_two_result=step_one_result-gamma+42
    if step_two_result>0:
        return step_two_result
    return 0
"#;
    fs::write(target_dir.path().join("reformatted.py"), reformatted).expect("write reformatted");

    let findings = scan_tree(target_dir.path(), &fp, &opts);
    let winnow_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D2" && f.channel == "winnow" && f.severity == Severity::Gate)
        .collect();

    assert!(
        !winnow_gates.is_empty(),
        "Reformatted copy must produce a tier 3 winnow gate finding"
    );
}

#[test]
fn test_h10_triple_quoted_string_backslash_newline_line_counting() {
    let text = "'''first line\\\nsecond line\n'''\nx = 1\n";
    let tokens = hermetic_sealcheck::tokenize(text);
    // Line 0: '''first line\ (escaped newline)
    // Line 1: second line
    // Line 2: ''' (closing quote)
    // Line 3: x = 1
    let x_token = tokens.iter().find(|t| t.text == "x").expect("find x token");
    assert_eq!(
        x_token.line, 3,
        "token 'x' after triple-quoted string with backslash-newline must have line 3, got {}",
        x_token.line
    );
}

#[test]
fn test_h11_baseline_subtraction_unselected_base_kgram() {
    use hermetic_sealcheck::winnow_hashes;
    use std::collections::HashSet;

    // 1. Build a deterministic base k-gram hash sequence:
    // Seven of hash 100, then one of hash 10.
    let base_kgram_hashes = vec![100u64, 100, 100, 100, 100, 100, 100, 10];
    let base_winnow_selected = winnow_hashes(&base_kgram_hashes);
    // Base winnowing selected ONLY hash 10, because 10 is the minimum of window [100..10]
    assert_eq!(base_winnow_selected.len(), 1);
    assert_eq!(base_winnow_selected[0].hash, 10);
    let base_selected_set: HashSet<u64> = base_winnow_selected.iter().map(|f| f.hash).collect();
    assert!(!base_selected_set.contains(&100));

    // 2. Build a post-fix slice whose selected k-gram exists at base (hash 100)
    // but was not selected by base's winnowing:
    // Hash 100, followed by seven of hash 200.
    let postfix_kgram_hashes = vec![100u64, 200, 200, 200, 200, 200, 200, 200];
    let postfix_selected = winnow_hashes(&postfix_kgram_hashes);
    // Post-fix winnowing selects hash 100 at pos 0!
    assert_eq!(postfix_selected.len(), 1);
    assert_eq!(postfix_selected[0].hash, 100);

    // Old T1.2 behavior:
    // Base subtraction only subtracted hashes selected by base's own winnowing:
    let old_surviving: Vec<_> = postfix_selected
        .iter()
        .filter(|f| !base_selected_set.contains(&f.hash))
        .collect();
    assert_eq!(
        old_surviving.len(),
        1,
        "under old T1.2 behavior, unselected base k-gram survived"
    );

    // New H11 behavior:
    // Base subtraction collects all k-gram hashes occurring in the base:
    let base_all_kgrams_set: HashSet<u64> = base_kgram_hashes.into_iter().collect();
    assert!(base_all_kgrams_set.contains(&100));

    // Subtracting against all base k-grams:
    let new_surviving: Vec<_> = postfix_selected
        .iter()
        .filter(|f| !base_all_kgrams_set.contains(&f.hash))
        .collect();
    assert!(
        new_surviving.is_empty(),
        "under H11, selected k-gram in post-fix that exists in base must be subtracted"
    );
}
