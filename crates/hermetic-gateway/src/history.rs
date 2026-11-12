#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

/// Compute SHA-256 hash of a byte slice and return raw 32 bytes.
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 hash and return lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_bytes(data))
}

/// Default most conversation tips remembered. When full, the oldest tip is forgotten; a later
/// request extending a forgotten conversation is then counted as a history rewrite. This bounds
/// the history state even when no request quota is configured.
pub const MAX_HISTORY_TIPS: usize = 4096;

pub struct HistoryLog {
    inner: Mutex<HistoryState>,
    capacity: usize,
}

struct HistoryState {
    seen_tips: HashSet<String>,
    /// Insertion order of `seen_tips` (may hold stale entries already removed from the set).
    order: VecDeque<String>,
    rewrites_count: u64,
}

impl HistoryState {
    fn insert(&mut self, tip: String, capacity: usize) {
        if self.seen_tips.insert(tip.clone()) {
            self.order.push_back(tip);
        }
        while self.seen_tips.len() > capacity {
            match self.order.pop_front() {
                Some(old) => {
                    self.seen_tips.remove(&old);
                }
                None => break,
            }
        }
        // Drop stale order entries so `order` stays bounded too.
        if self.order.len() > capacity.saturating_mul(2).max(16) {
            let seen = &self.seen_tips;
            self.order.retain(|t| seen.contains(t));
        }
    }
}

impl Default for HistoryLog {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoryLog {
    pub fn new() -> Self {
        Self::with_capacity(MAX_HISTORY_TIPS)
    }

    /// History that remembers at most `capacity` conversation tips (at least 1).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HistoryState {
                seen_tips: HashSet::new(),
                order: VecDeque::new(),
                rewrites_count: 0,
            }),
            capacity: capacity.max(1),
        }
    }

    /// Number of conversation tips currently remembered.
    pub fn tip_count(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.seen_tips.len(),
            Err(p) => p.into_inner().seen_tips.len(),
        }
    }

    /// Hash the conversation prefix step by step:
    /// H_0 = sha256(canonical_system)
    /// H_{i+1} = sha256(H_i || sha256(canonical_message[i]))
    ///
    /// Returns vector of hex hashes: [H_0, H_1, ..., H_k] where k = messages.len().
    pub fn compute_chain_hashes(
        system_canonical_json: &[u8],
        messages_canonical_json: &[Vec<u8>],
    ) -> Vec<String> {
        let mut hashes = Vec::with_capacity(messages_canonical_json.len() + 1);

        // H_0 from system prompt
        let mut current_h = sha256_bytes(system_canonical_json);
        hashes.push(hex::encode(current_h));

        for msg_bytes in messages_canonical_json {
            let msg_digest = sha256_bytes(msg_bytes);
            let mut chain_hasher = Sha256::new();
            chain_hasher.update(current_h);
            chain_hasher.update(msg_digest);
            current_h = chain_hasher.finalize().into();
            hashes.push(hex::encode(current_h));
        }

        hashes
    }

    /// Record a conversation request and determine if it represents a history rewrite.
    ///
    /// Per TR-GW-8:
    /// A request whose message list neither extends a conversation already seen nor
    /// starts a new one (first message only) is recorded as a history_rewrite;
    /// rewrites are counted, never rejected.
    pub fn check_and_record(
        &self,
        system_canonical_json: &[u8],
        messages_canonical_json: &[Vec<u8>],
    ) -> (bool, u64) {
        let hashes = Self::compute_chain_hashes(system_canonical_json, messages_canonical_json);
        let msg_count = messages_canonical_json.len();

        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let full_tip = hashes.last().cloned().unwrap_or_default();

        if msg_count <= 1 {
            // Starts a new conversation (first message only, or empty)
            state.insert(full_tip, self.capacity);
            (false, state.rewrites_count)
        } else {
            // Check if any proper prefix H_1 .. H_{msg_count - 1} matches an active tip
            let mut matched_tip: Option<String> = None;
            for prefix_hash in &hashes[1..msg_count] {
                if state.seen_tips.contains(prefix_hash) {
                    matched_tip = Some(prefix_hash.clone());
                    break;
                }
            }

            if let Some(old_tip) = matched_tip {
                // Extends a conversation already seen
                state.seen_tips.remove(&old_tip);
                state.insert(full_tip, self.capacity);
                (false, state.rewrites_count)
            } else {
                // History rewrite detected
                state.rewrites_count += 1;
                state.insert(full_tip, self.capacity);
                (true, state.rewrites_count)
            }
        }
    }

    pub fn rewrites_total(&self) -> u64 {
        let state = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.rewrites_count
    }
}
