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
        let temp_dir = TempDir::new().expect("Failed to create tempdir");
        let key_path = temp_dir.path().join("upstream_api_key.txt");
        let api_key = "test-secret-gateway-key-xyz".to_string();
        std::fs::write(&key_path, &api_key).expect("Failed to write api key");

        let log_dir = temp_dir.path().join("logs");

        // Mock upstream server
        let mock_server =
            Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("Failed to bind mock upstream"));
        let mock_addr = mock_server.server_addr().to_ip().expect("mock ip");

        let mut config = GatewayConfig::from_raw(
            format!("http://{mock_addr}"),
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

        let gateway =
            Arc::new(GatewayServer::new(config, t_clock).expect("Failed to create GatewayServer"));

        // Gateway HTTP front end
        let gateway_http =
            tiny_http::Server::http("127.0.0.1:0").expect("Failed to bind gateway HTTP");
        let gw_addr = gateway_http.server_addr().to_ip().expect("gw ip");
        let gateway_url = format!("http://{gw_addr}");

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let gw_clone = gateway.clone();

        let gateway_thread = thread::spawn(move || {
            while running_clone.load(Ordering::SeqCst) {
                match gateway_http.recv_timeout(Duration::from_millis(50)) {
                    Ok(Some(req)) => {
                        let gw = gw_clone.clone();
                        thread::spawn(move || {
                            gw.handle_agent_request(req);
                        });
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
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

impl Drop for TestEnv {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.gateway_server.stop();
        if let Some(handle) = self.gateway_thread.take() {
            let _ = handle.join();
        }
    }
}
