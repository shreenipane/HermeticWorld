#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

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
    limit_exceeded: bool,
    limit_exceeded_reason: Option<String>,
}

pub struct QuotaTracker {
    config: QuotasConfig,
    state: Mutex<QuotaState>,
}

impl QuotaTracker {
    pub fn new(config: QuotasConfig) -> Self {
        Self {
            config,
            state: Mutex::new(QuotaState {
                requests: 0,
                input_tokens: 0,
                output_tokens: 0,
                concurrent_requests: 0,
                limit_exceeded: false,
                limit_exceeded_reason: None,
            }),
        }
    }

    /// Check quotas before processing a request. If allowed, increments requests and concurrent count.
    /// If any quota is breached, marks the gateway into the terminal limit_exceeded state.
    pub fn check_and_acquire(&self, elapsed_secs: u64) -> Result<(), QuotaBreach> {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if state.limit_exceeded {
            let reason = state
                .limit_exceeded_reason
                .clone()
                .unwrap_or_else(|| "limit_exceeded".to_string());
            return Err(QuotaBreach::Terminal(reason));
        }

        // Check wall time
        if let Some(limit) = self.config.max_wall_time_seconds {
            if elapsed_secs >= limit {
                let breach = QuotaBreach::WallTimeExceeded {
                    elapsed_secs,
                    limit,
                };
                state.limit_exceeded = true;
                state.limit_exceeded_reason = Some(breach.reason());
                return Err(breach);
            }
        }

        // Check requests
        if let Some(limit) = self.config.max_requests {
            if state.requests + 1 > limit {
                let breach = QuotaBreach::RequestsExceeded { limit };
                state.limit_exceeded = true;
                state.limit_exceeded_reason = Some(breach.reason());
                return Err(breach);
            }
        }

        // Check concurrency
        if let Some(limit) = self.config.max_concurrent_requests {
            if state.concurrent_requests + 1 > limit {
                let breach = QuotaBreach::ConcurrencyExceeded { limit };
                state.limit_exceeded = true;
                state.limit_exceeded_reason = Some(breach.reason());
                return Err(breach);
            }
        }

        state.requests += 1;
        state.concurrent_requests += 1;
        Ok(())
    }

    /// Decrement concurrency count without recording token usage (e.g. for rejected requests).
    pub fn release_concurrent(&self) {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.concurrent_requests = state.concurrent_requests.saturating_sub(1);
    }

    /// Record token usage from upstream response and release concurrency.
    /// If token caps are breached, marks the gateway into terminal limit_exceeded state.
    pub fn record_usage_and_release(
        &self,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<(), QuotaBreach> {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        state.concurrent_requests = state.concurrent_requests.saturating_sub(1);
        state.input_tokens = state.input_tokens.saturating_add(input_tokens);
        state.output_tokens = state.output_tokens.saturating_add(output_tokens);

        if state.limit_exceeded {
            let reason = state
                .limit_exceeded_reason
                .clone()
                .unwrap_or_else(|| "limit_exceeded".to_string());
            return Err(QuotaBreach::Terminal(reason));
        }

        if let Some(limit) = self.config.max_input_tokens {
            if state.input_tokens > limit {
                let breach = QuotaBreach::InputTokensExceeded {
                    total: state.input_tokens,
                    limit,
                };
                state.limit_exceeded = true;
                state.limit_exceeded_reason = Some(breach.reason());
                return Err(breach);
            }
        }

        if let Some(limit) = self.config.max_output_tokens {
            if state.output_tokens > limit {
                let breach = QuotaBreach::OutputTokensExceeded {
                    total: state.output_tokens,
                    limit,
                };
                state.limit_exceeded = true;
                state.limit_exceeded_reason = Some(breach.reason());
                return Err(breach);
            }
        }

        Ok(())
    }

    /// Manually trigger limit_exceeded
    pub fn trigger_limit_exceeded(&self, reason: String) {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.limit_exceeded = true;
        state.limit_exceeded_reason = Some(reason);
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        let state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
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
