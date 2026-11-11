#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

pub const MIN_RATE_RPS: f64 = 0.001;
pub const MAX_RATE_RPS: f64 = 1_000_000.0;
pub const MAX_BURST: f64 = 1_000_000.0;
pub const MAX_RUN_REQUESTS: u64 = 4096;
pub const MAX_RUN_BYTES: u64 = 1024 * 1024 * 1024;

pub fn validate_rate(rate: Option<f64>, burst: Option<f64>) -> bool {
    rate.is_none_or(|r| r.is_finite() && (MIN_RATE_RPS..=MAX_RATE_RPS).contains(&r))
        && burst.is_none_or(|b| b.is_finite() && (1.0..=MAX_BURST).contains(&b))
}

/// Indicates which limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitExceeded {
    Requests(u64),
    Bytes(u64),
}

/// Token bucket rate-limiter and per-run total volume caps.
pub struct Limits {
    rate_rps: Option<f64>,
    burst: f64,
    tokens: f64,
    last_update: Instant,
    max_requests: Option<u64>,
    max_bytes: Option<u64>,
    total_requests: u64,
    total_bytes: u64,
}

impl Limits {
    pub fn new(
        rate_rps: Option<f64>,
        burst: Option<f64>,
        max_requests: Option<u64>,
        max_bytes: Option<u64>,
    ) -> Self {
        let b = burst.unwrap_or_else(|| rate_rps.unwrap_or(100.0).max(1.0));
        Self {
            rate_rps,
            burst: b,
            tokens: b,
            last_update: Instant::now(),
            max_requests: Some(
                max_requests
                    .unwrap_or(MAX_RUN_REQUESTS)
                    .min(MAX_RUN_REQUESTS),
            ),
            max_bytes: Some(max_bytes.unwrap_or(MAX_RUN_BYTES).min(MAX_RUN_BYTES)),
            total_requests: 0,
            total_bytes: 0,
        }
    }

    /// Delay until 1 token is available from the token bucket. Never refuses.
    pub fn acquire_token(&mut self) -> Result<(), LimitExceeded> {
        if !validate_rate(self.rate_rps, Some(self.burst)) {
            return Err(LimitExceeded::Requests(self.total_requests));
        }
        if let Some(rate) = self.rate_rps {
            if rate <= 0.0 {
                return Err(LimitExceeded::Requests(self.total_requests));
            }
            let now = Instant::now();
            let elapsed = (now - self.last_update).as_secs_f64();
            self.tokens = (self.tokens + elapsed * rate).min(self.burst);
            self.last_update = now;

            if self.tokens < 1.0 {
                let needed = 1.0 - self.tokens;
                let wait_secs = needed / rate;
                let wait = Duration::try_from_secs_f64(wait_secs)
                    .map_err(|_| LimitExceeded::Requests(self.total_requests))?;
                std::thread::sleep(wait);
                self.last_update = Instant::now();
                self.tokens = 0.0;
            } else {
                self.tokens -= 1.0;
            }
        }
        Ok(())
    }

    pub fn restore(&mut self, requests: u64, bytes: u64) {
        self.total_requests = requests;
        self.total_bytes = bytes;
        self.tokens = 0.0;
    }

    /// Check if processing this request would exceed max_requests.
    pub fn check_request_cap(&self) -> Result<(), LimitExceeded> {
        if let Some(max) = self.max_requests {
            if self.total_requests.saturating_add(1) > max {
                return Err(LimitExceeded::Requests(
                    self.total_requests.saturating_add(1),
                ));
            }
        }
        Ok(())
    }

    /// Record a successfully accepted request.
    pub fn record_request(&mut self) {
        self.total_requests = self.total_requests.saturating_add(1);
    }

    /// Check if transmitting `new_bytes` would exceed max_bytes.
    pub fn check_bytes_cap(&self, new_bytes: u64) -> Result<(), LimitExceeded> {
        if let Some(max) = self.max_bytes {
            if self.total_bytes.saturating_add(new_bytes) > max {
                return Err(LimitExceeded::Bytes(
                    self.total_bytes.saturating_add(new_bytes),
                ));
            }
        }
        Ok(())
    }

    /// Record transmitted response bytes.
    pub fn record_bytes(&mut self, new_bytes: u64) {
        self.total_bytes = self.total_bytes.saturating_add(new_bytes);
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}
