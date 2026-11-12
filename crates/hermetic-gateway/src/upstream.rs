#![forbid(unsafe_code)]

use crate::config::GatewayConfig;
use crate::error::GatewayError;
use std::error::Error;
use std::io::Read;
use std::sync::Arc;

pub enum UpstreamResponse {
    Body {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    Stream {
        status: u16,
        headers: Vec<(String, String)>,
        reader: Box<dyn Read + Send + Sync + 'static>,
    },
}

pub struct UpstreamClient {
    agent: ureq::Agent,
    config: Arc<GatewayConfig>,
}

impl UpstreamClient {
    pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024; // 32 MiB limit
    /// A non-2xx body is only inspected for its error type and is never forwarded, so far
    /// less of it is read (bounds memory per in-flight request).
    pub const MAX_ERROR_BODY_BYTES: usize = 1024 * 1024;

    pub fn new(config: Arc<GatewayConfig>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(std::time::Duration::from_secs(30))
            .timeout_read(std::time::Duration::from_secs(
                config.upstream_read_timeout_s,
            ))
            .build();
        Self { agent, config }
    }

    /// Forward a rebuilt request to upstream.
    pub fn send_request(
        &self,
        endpoint: &str,
        rebuilt_json: &str,
        beta_header: Option<&str>,
        is_streaming: bool,
        overall_timeout: Option<std::time::Duration>,
    ) -> Result<UpstreamResponse, GatewayError> {
        let url = format!(
            "{}{}",
            self.config.upstream_base_url.trim_end_matches('/'),
            endpoint
        );

        let mut req = self
            .agent
            .post(&url)
            .set("x-api-key", self.config.api_key())
            .set("anthropic-version", &self.config.anthropic_version)
            .set("content-type", "application/json");

        if let Some(betas) = beta_header {
            if !betas.trim().is_empty() {
                req = req.set("anthropic-beta", betas);
            }
        }

        // Overall deadline (connect, send and the whole response body), e.g. the time left
        // under the wall-time quota.
        if let Some(t) = overall_timeout {
            req = req.timeout(t);
        }

        let call_res = req.send_string(rebuilt_json);

        match call_res {
            Ok(resp) => {
                let status = resp.status();
                let mut headers = Vec::new();
                for h_name in resp.headers_names() {
                    if let Some(val) = resp.header(&h_name) {
                        headers.push((h_name, val.to_string()));
                    }
                }

                // Only a 2xx response may be streamed; anything else (with redirects off, a
                // 3xx arrives here) is read as a body and replaced by a standard error.
                if is_streaming && (200..300).contains(&status) {
                    Ok(UpstreamResponse::Stream {
                        status,
                        headers,
                        reader: resp.into_reader(),
                    })
                } else {
                    let cap = if (200..300).contains(&status) {
                        Self::MAX_RESPONSE_BYTES
                    } else {
                        Self::MAX_ERROR_BODY_BYTES
                    };
                    // Read at most cap + 1 bytes: more than the cap is refused, never cut.
                    let mut reader = resp.into_reader().take(cap as u64 + 1);
                    let mut raw = Vec::new();
                    if let Err(e) = reader.read_to_end(&mut raw) {
                        return Err(GatewayError::UpstreamTimeout(format!(
                            "Upstream read timed out: {e}"
                        )));
                    }
                    if raw.len() > cap {
                        if (200..300).contains(&status) {
                            return Err(GatewayError::UpstreamError(format!(
                                "Upstream response body exceeds the {cap}-byte limit"
                            )));
                        }
                        raw.truncate(cap);
                    }
                    let body = if (200..300).contains(&status) {
                        String::from_utf8(raw).map_err(|_| {
                            GatewayError::UpstreamError(
                                "Upstream response body is not UTF-8".to_string(),
                            )
                        })?
                    } else {
                        String::from_utf8_lossy(&raw).into_owned()
                    };
                    Ok(UpstreamResponse::Body {
                        status,
                        headers,
                        body,
                    })
                }
            }
            Err(ureq::Error::Status(status, resp)) => {
                let mut headers = Vec::new();
                for h_name in resp.headers_names() {
                    if let Some(val) = resp.header(&h_name) {
                        headers.push((h_name, val.to_string()));
                    }
                }
                let mut reader = resp.into_reader().take(Self::MAX_ERROR_BODY_BYTES as u64);
                let mut body = String::new();
                let _ = reader.read_to_string(&mut body);
                Ok(UpstreamResponse::Body {
                    status,
                    headers,
                    body,
                })
            }
            Err(ureq::Error::Transport(e)) => {
                let err_str = e.to_string();
                if e.kind() == ureq::ErrorKind::Io {
                    if let Some(io_err) =
                        e.source().and_then(|s| s.downcast_ref::<std::io::Error>())
                    {
                        if io_err.kind() == std::io::ErrorKind::TimedOut {
                            return Err(GatewayError::UpstreamTimeout(format!(
                                "Upstream transport timed out: {err_str}"
                            )));
                        }
                    }
                }
                if err_str.to_lowercase().contains("timed out")
                    || err_str.to_lowercase().contains("timeout")
                {
                    return Err(GatewayError::UpstreamTimeout(format!(
                        "Upstream transport timed out: {err_str}"
                    )));
                }
                Err(GatewayError::UpstreamError(format!(
                    "Upstream transport error: {err_str}"
                )))
            }
        }
    }
}
