use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use hermetic_gateway::config::GatewayConfig;
use hermetic_gateway::quota::QuotasConfig;
use hermetic_gateway::server::GatewayServer;

#[allow(dead_code)]
pub struct TestEnv {
    pub temp_dir: TempDir,
    pub gateway_url: String,
    pub mock_addr: SocketAddr,
    pub mock_server: Arc<tiny_http::Server>,
    pub gateway_server: Arc<GatewayServer>,
    pub api_key: String,
    pub t_clock: OffsetDateTime,
    gateway_thread: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

#[allow(dead_code)]
impl TestEnv {
    pub fn new(
        pinned_models: Vec<String>,
        allowed_betas: Vec<String>,
        quotas: QuotasConfig,
    ) -> Self {
        let t_clock =
            OffsetDateTime::parse("2026-11-11T12:00:00Z", &Rfc3339).expect("Valid RFC3339 t-clock");
        Self::new_with_options(pinned_models, allowed_betas, quotas, t_clock, None)
    }

    pub fn new_with_options(
        pinned_models: Vec<String>,
        allowed_betas: Vec<String>,
        quotas: QuotasConfig,
        t_clock: OffsetDateTime,
        upstream_read_timeout_s: Option<u64>,
    ) -> Self {
        let mock_server =
            Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("Failed to bind mock upstream"));
        let mock_addr = mock_server.server_addr().to_ip().expect("mock ip");
        Self::new_with_upstream_url(
            format!("http://{mock_addr}"),
            mock_server,
            pinned_models,
            allowed_betas,
            quotas,
            t_clock,
            upstream_read_timeout_s,
        )
    }

    pub fn new_with_upstream_url(
        upstream_url: String,
        mock_server: Arc<tiny_http::Server>,
        pinned_models: Vec<String>,
        allowed_betas: Vec<String>,
        quotas: QuotasConfig,
        t_clock: OffsetDateTime,
        upstream_read_timeout_s: Option<u64>,
    ) -> Self {
        Self::build(
            upstream_url,
            mock_server,
            pinned_models,
            allowed_betas,
            quotas,
            t_clock,
            upstream_read_timeout_s,
            None,
        )
    }

    /// Default options, but with the gateway's in-flight and body-budget caps overridden.
    pub fn new_with_request_limits(
        quotas: QuotasConfig,
        t_clock: OffsetDateTime,
        max_in_flight: usize,
        max_buffered_body_bytes: usize,
    ) -> Self {
        Self::new_with_setup(quotas, t_clock, None, move |g| {
            g.with_request_limits(max_in_flight, max_buffered_body_bytes)
        })
    }

    /// Default options; `setup` adjusts the gateway before it serves (caps, deadlines, ...).
    pub fn new_with_setup(
        quotas: QuotasConfig,
        t_clock: OffsetDateTime,
        upstream_read_timeout_s: Option<u64>,
        setup: impl FnOnce(GatewayServer) -> GatewayServer + 'static,
    ) -> Self {
        let mock_server =
            Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("Failed to bind mock upstream"));
        let mock_addr = mock_server.server_addr().to_ip().expect("mock ip");
        Self::build(
            format!("http://{mock_addr}"),
            mock_server,
            vec!["claude-3-5-sonnet-20241022".to_string()],
            vec![],
            quotas,
            t_clock,
            upstream_read_timeout_s,
            Some(Box::new(setup)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        upstream_url: String,
        mock_server: Arc<tiny_http::Server>,
        pinned_models: Vec<String>,
        allowed_betas: Vec<String>,
        quotas: QuotasConfig,
        t_clock: OffsetDateTime,
        upstream_read_timeout_s: Option<u64>,
        setup: Option<Box<dyn FnOnce(GatewayServer) -> GatewayServer>>,
    ) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create tempdir");
        let key_path = temp_dir.path().join("upstream_api_key.txt");
        let api_key = "test-secret-gateway-key-xyz".to_string();
        std::fs::write(&key_path, &api_key).expect("Failed to write api key");

        let log_dir = temp_dir.path().join("logs");

        let mock_addr = mock_server.server_addr().to_ip().expect("mock ip");

        let mut config = GatewayConfig::from_raw(
            upstream_url,
            "2023-06-01".to_string(),
            allowed_betas,
            pinned_models,
            quotas,
            log_dir,
            key_path,
            api_key.clone(),
        );

        if let Some(timeout_s) = upstream_read_timeout_s {
            config = config.with_upstream_read_timeout_s(timeout_s);
        }

        let mut gateway_inner =
            GatewayServer::new(config, t_clock).expect("Failed to create GatewayServer");
        if let Some(setup) = setup {
            gateway_inner = setup(gateway_inner);
        }
        let gateway = Arc::new(gateway_inner);

        // Gateway HTTP front end
        // Deadlines are installed before the first accept, as in the gateway binary;
        // installing them later in run_loop left early connections unbounded.
        let gateway_http =
            tiny_http::Server::http_with_deadlines("127.0.0.1:0", gateway.client_deadlines())
                .expect("Failed to bind gateway HTTP");
        let gw_addr = gateway_http.server_addr().to_ip().expect("gw ip");
        let gateway_url = format!("http://{gw_addr}");

        let running = Arc::new(AtomicBool::new(true));
        let gw_clone = gateway.clone();

        // The real accept loop (with its handler-thread cap); `stop()` ends it.
        let gateway_thread = thread::spawn(move || {
            gw_clone.run_loop(gateway_http);
        });

        Self {
            temp_dir,
            gateway_url,
            mock_addr,
            mock_server,
            gateway_server: gateway,
            api_key,
            t_clock,
            gateway_thread: Some(gateway_thread),
            running,
        }
    }

    /// Read host logs from gateway.jsonl
    pub fn read_host_logs(&self) -> Vec<serde_json::Value> {
        let log_file = self.temp_dir.path().join("logs").join("gateway.jsonl");
        if !log_file.exists() {
            return Vec::new();
        }
        let content = std::fs::read_to_string(&log_file).unwrap_or_default();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .collect()
    }
}

/// Longest a test waits for any single event (upstream request, thread join, response).
#[allow(dead_code)]
pub const TEST_WAIT: Duration = Duration::from_secs(30);

/// HTTP client for tests: every connect, read and write is bounded.
#[allow(dead_code)]
pub fn test_client() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(TEST_WAIT)
        .timeout_write(TEST_WAIT)
        .build()
}

/// Waits for the gateway's upstream request at the mock server, failing after `TEST_WAIT`.
#[allow(dead_code)]
pub fn recv_upstream(mock: &tiny_http::Server) -> tiny_http::Request {
    match mock.recv_timeout(TEST_WAIT) {
        Ok(Some(req)) => req,
        Ok(None) => panic!("mock upstream received no request within {TEST_WAIT:?}"),
        Err(e) => panic!("mock upstream recv failed: {e}"),
    }
}

/// Allowed lag between `T_clock` and a guest timestamp observed in a test: guest time is
/// `T_clock` plus the real time elapsed since the gateway started, so exact equality is flaky.
#[allow(dead_code)]
pub const GUEST_CLOCK_SLACK_SECS: i64 = 60;

/// True if `text` holds `"created_at":<n>` with `n` in `[guest_unix, guest_unix + slack]`.
#[allow(dead_code)]
pub fn contains_guest_unix_created_at(text: &str, guest_unix: i64) -> bool {
    let key = "\"created_at\":";
    text.match_indices(key).any(|(i, _)| {
        let digits: String = text[i + key.len()..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits
            .parse::<i64>()
            .map(|n| n >= guest_unix && n <= guest_unix + GUEST_CLOCK_SLACK_SECS)
            .unwrap_or(false)
    })
}

/// Joins a thread, failing the test if it has not finished within `TEST_WAIT`.
#[allow(dead_code)]
pub fn join_within<T>(handle: JoinHandle<T>) -> T {
    let deadline = std::time::Instant::now() + TEST_WAIT;
    while !handle.is_finished() {
        if std::time::Instant::now() >= deadline {
            panic!("thread did not finish within {TEST_WAIT:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    match handle.join() {
        Ok(v) => v,
        Err(_) => panic!("joined thread panicked"),
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.gateway_server.stop();
        if let Some(handle) = self.gateway_thread.take() {
            // run_loop polls its stop flag every 200 ms; bound the wait anyway.
            let deadline = std::time::Instant::now() + TEST_WAIT;
            while !handle.is_finished() && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
    }
}
