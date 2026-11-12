#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How long `check_and_acquire` waits for a concurrency slot held by *active* requests before
/// declaring a breach. A client that cancels a request (closes its connection) and at once
/// sends the next one can reach the quota check a moment before the gateway has noticed the
/// disconnect; this grace keeps that race from being a (terminal) concurrency breach.
pub const CONCURRENCY_RELEASE_GRACE: Duration = Duration::from_secs(2);

/// Default longest wait for a slot held by a *draining* request (one whose client has closed
/// its side but whose upstream work has not finished yet). A slot is released only when the
/// upstream work really ends, so upstream concurrency never exceeds the limit; a request that
/// has to wait for a draining slot longer than this gets `QuotaBreach::Busy` (not terminal).
pub const DEFAULT_DRAIN_WAIT: Duration = Duration::from_secs(130);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QuotasConfig {
    #[serde(default)]
    pub max_requests: Option<u64>,
    #[serde(default)]
    pub max_input_tokens: Option<u64>,
    #[serde(default)]
    pub max_output_tokens: Option<u64>,
    #[serde(default)]
    pub max_concurrent_requests: Option<u64>,
    #[serde(default)]
    pub max_wall_time_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotaSnapshot {
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub concurrent_requests: u64,
    pub limit_exceeded: bool,
    pub limit_exceeded_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuotaBreach {
    #[error("Limit exceeded: {0}")]
    Terminal(String),
    #[error("Request quota exceeded: limit is {limit}")]
    RequestsExceeded { limit: u64 },
    #[error("Concurrent request quota exceeded: limit is {limit}")]
    ConcurrencyExceeded { limit: u64 },
    #[error("Wall time quota exceeded: {elapsed_secs}s elapsed, limit is {limit}s")]
    WallTimeExceeded { elapsed_secs: u64, limit: u64 },
    #[error("Input token quota exceeded: total {total}, limit is {limit}")]
    InputTokensExceeded { total: u64, limit: u64 },
    #[error("Output token quota exceeded: total {total}, limit is {limit}")]
    OutputTokensExceeded { total: u64, limit: u64 },
    /// Not a breach: every slot is held by a request still draining after its client left.
    /// Not terminal; the client may retry.
    #[error("All concurrency slots are held by requests still finishing upstream")]
    Busy,
}

impl QuotaBreach {
    pub fn reason(&self) -> String {
        self.to_string()
    }
}

struct QuotaState {
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    concurrent_requests: u64,
    /// Slots (counted in `concurrent_requests`) whose client has closed its side while the
    /// upstream work goes on.
    draining_requests: u64,
    limit_exceeded: bool,
    limit_exceeded_reason: Option<String>,
}

impl QuotaState {
    fn mark(&mut self, breach: QuotaBreach) -> QuotaBreach {
        self.limit_exceeded = true;
        self.limit_exceeded_reason = Some(breach.reason());
        breach
    }

    fn terminal(&self) -> QuotaBreach {
        QuotaBreach::Terminal(
            self.limit_exceeded_reason
                .clone()
                .unwrap_or_else(|| "limit_exceeded".to_string()),
        )
    }
}

pub struct QuotaTracker {
    config: QuotasConfig,
    state: Mutex<QuotaState>,
    /// Notified whenever a concurrency slot is released or starts draining.
    slot_released: Condvar,
    drain_wait: Duration,
}

impl QuotaTracker {
    pub fn new(config: QuotasConfig) -> Self {
        Self::with_drain_wait(config, DEFAULT_DRAIN_WAIT)
    }

    /// Like `new`, waiting at most `drain_wait` for a slot held by a draining request.
    pub fn with_drain_wait(config: QuotasConfig, drain_wait: Duration) -> Self {
        Self {
            config,
            state: Mutex::new(QuotaState {
                requests: 0,
                input_tokens: 0,
                output_tokens: 0,
                concurrent_requests: 0,
                draining_requests: 0,
                limit_exceeded: false,
                limit_exceeded_reason: None,
            }),
            slot_released: Condvar::new(),
            drain_wait,
        }
    }

    pub fn config(&self) -> &QuotasConfig {
        &self.config
    }

    fn lock(&self) -> MutexGuard<'_, QuotaState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// True once the gateway is in the terminal limit_exceeded state.
    pub fn is_limit_exceeded(&self) -> bool {
        self.lock().limit_exceeded
    }

    /// Check quotas before processing a request. If allowed, increments requests and concurrent
    /// count. If any quota is breached, marks the gateway into the terminal limit_exceeded state.
    ///
    /// When the concurrency limit is full:
    /// - slots held by active requests: wait up to `CONCURRENCY_RELEASE_GRACE` for one to be
    ///   released or to start draining, then declare a (terminal) concurrency breach;
    /// - otherwise (at least one occupant is draining): wait up to the drain wait for a release,
    ///   then return `QuotaBreach::Busy` (not terminal, nothing recorded).
    pub fn check_and_acquire(&self, elapsed_secs: u64) -> Result<(), QuotaBreach> {
        let start = Instant::now();
        let grace_deadline = start + CONCURRENCY_RELEASE_GRACE;
        let drain_deadline = start + self.drain_wait;
        let mut state = self.lock();
        loop {
            if state.limit_exceeded {
                return Err(state.terminal());
            }
            if let Some(limit) = self.config.max_wall_time_seconds {
                if elapsed_secs >= limit {
                    return Err(state.mark(QuotaBreach::WallTimeExceeded {
                        elapsed_secs,
                        limit,
                    }));
                }
            }
            if let Some(limit) = self.config.max_requests {
                if state.requests + 1 > limit {
                    return Err(state.mark(QuotaBreach::RequestsExceeded { limit }));
                }
            }
            let now = Instant::now();
            let wait_until = match self.config.max_concurrent_requests {
                Some(limit) if state.concurrent_requests + 1 > limit => {
                    let active = state
                        .concurrent_requests
                        .saturating_sub(state.draining_requests);
                    if active + 1 > limit {
                        if now >= grace_deadline {
                            return Err(state.mark(QuotaBreach::ConcurrencyExceeded { limit }));
                        }
                        grace_deadline
                    } else {
                        if now >= drain_deadline {
                            return Err(QuotaBreach::Busy);
                        }
                        drain_deadline
                    }
                }
                _ => {
                    state.requests += 1;
                    state.concurrent_requests += 1;
                    return Ok(());
                }
            };
            let wait = wait_until.saturating_duration_since(now);
            state = match self.slot_released.wait_timeout(state, wait) {
                Ok((g, _)) => g,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// Marks one held slot as draining: its client has closed its side, its upstream work goes
    /// on. The slot stays held until `record_usage_and_release(.., true)`.
    pub fn mark_draining(&self) {
        let mut state = self.lock();
        state.draining_requests = state.draining_requests.saturating_add(1);
        drop(state);
        self.slot_released.notify_all();
    }

    /// Decrement concurrency count without recording token usage (e.g. for rejected requests).
    pub fn release_concurrent(&self) {
        let mut state = self.lock();
        state.concurrent_requests = state.concurrent_requests.saturating_sub(1);
        drop(state);
        self.slot_released.notify_all();
    }

    /// Record token usage from upstream response and release concurrency.
    /// If token caps are breached, marks the gateway into terminal limit_exceeded state.
    pub fn record_usage_and_release(
        &self,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<(), QuotaBreach> {
        self.finish(input_tokens, output_tokens, false)
    }

    /// Records a finished request's usage and releases its slot (`was_draining`: the slot had
    /// been marked draining). Returns the breach if the usage crosses a token cap.
    pub fn finish(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        was_draining: bool,
    ) -> Result<(), QuotaBreach> {
        let mut state = self.lock();
        state.concurrent_requests = state.concurrent_requests.saturating_sub(1);
        if was_draining {
            state.draining_requests = state.draining_requests.saturating_sub(1);
        }
        state.input_tokens = state.input_tokens.saturating_add(input_tokens);
        state.output_tokens = state.output_tokens.saturating_add(output_tokens);
        let result = self.check_tokens_locked(&mut state, 0, 0);
        drop(state);
        self.slot_released.notify_all();
        result
    }

    fn check_tokens_locked(
        &self,
        state: &mut QuotaState,
        pending_in: u64,
        pending_out: u64,
    ) -> Result<(), QuotaBreach> {
        if state.limit_exceeded {
            return Err(state.terminal());
        }
        let total_in = state.input_tokens.saturating_add(pending_in);
        let total_out = state.output_tokens.saturating_add(pending_out);
        if let Some(limit) = self.config.max_input_tokens {
            if total_in > limit {
                return Err(state.mark(QuotaBreach::InputTokensExceeded {
                    total: total_in,
                    limit,
                }));
            }
        }
        if let Some(limit) = self.config.max_output_tokens {
            if total_out > limit {
                return Err(state.mark(QuotaBreach::OutputTokensExceeded {
                    total: total_out,
                    limit,
                }));
            }
        }
        Ok(())
    }

    /// Checks a running request: its usage so far (not yet recorded) plus the recorded totals
    /// against the token caps, and `elapsed_secs` against the wall-time limit. A breach marks
    /// the terminal limit_exceeded state and is returned so the request can be stopped.
    pub fn check_live(
        &self,
        pending_in: u64,
        pending_out: u64,
        elapsed_secs: u64,
    ) -> Result<(), QuotaBreach> {
        let mut state = self.lock();
        self.check_tokens_locked(&mut state, pending_in, pending_out)?;
        if let Some(limit) = self.config.max_wall_time_seconds {
            if elapsed_secs >= limit {
                return Err(state.mark(QuotaBreach::WallTimeExceeded {
                    elapsed_secs,
                    limit,
                }));
            }
        }
        Ok(())
    }

    /// Manually trigger limit_exceeded
    pub fn trigger_limit_exceeded(&self, reason: String) {
        let mut state = self.lock();
        state.limit_exceeded = true;
        state.limit_exceeded_reason = Some(reason);
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        let state = self.lock();
        QuotaSnapshot {
            requests: state.requests,
            input_tokens: state.input_tokens,
            output_tokens: state.output_tokens,
            concurrent_requests: state.concurrent_requests,
            limit_exceeded: state.limit_exceeded,
            limit_exceeded_reason: state.limit_exceeded_reason.clone(),
        }
    }
}
