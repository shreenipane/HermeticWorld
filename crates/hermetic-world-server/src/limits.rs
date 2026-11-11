#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

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
            max_requests,
            max_bytes,
            total_requests: 0,
            total_bytes: 0,
        }
    }

    /// Delay until 1 token is available from the token bucket. Never refuses.
    pub fn acquire_token(&mut self) {
        if let Some(rate) = self.rate_rps {
            if rate <= 0.0 {
                return;
            }
            let now = Instant::now();
            let elapsed = (now - self.last_update).as_secs_f64();
            self.tokens = (self.tokens + elapsed * rate).min(self.burst);
            self.last_update = now;

            if self.tokens < 1.0 {
                let needed = 1.0 - self.tokens;
                let wait_secs = needed / rate;
                std::thread::sleep(Duration::from_secs_f64(wait_secs));
                self.last_update = Instant::now();
                self.tokens = 0.0;
            } else {
                self.tokens -= 1.0;
            }
        }
    }

    /// Check if processing this request would exceed max_requests.
    pub fn check_request_cap(&self) -> Result<(), LimitExceeded> {
        if let Some(max) = self.max_requests {
            if self.total_requests + 1 > max {
                return Err(LimitExceeded::Requests(self.total_requests + 1));
            }
        }
        Ok(())
    }

    /// Record a successfully accepted request.
    pub fn record_request(&mut self) {
        self.total_requests += 1;
    }

    /// Check if transmitting `new_bytes` would exceed max_bytes.
    pub fn check_bytes_cap(&self, new_bytes: u64) -> Result<(), LimitExceeded> {
        if let Some(max) = self.max_bytes {
            if self.total_bytes + new_bytes > max {
                return Err(LimitExceeded::Bytes(self.total_bytes + new_bytes));
            }
        }
        Ok(())
    }

    /// Record transmitted response bytes.
    pub fn record_bytes(&mut self, new_bytes: u64) {
        self.total_bytes += new_bytes;
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}
