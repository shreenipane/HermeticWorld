#![forbid(unsafe_code)]

use crate::config::GatewayConfig;
use crate::error::GatewayError;
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

    pub fn new(config: Arc<GatewayConfig>) -> Self {
        let agent = ureq::AgentBuilder::new().redirects(0).build();
        Self { agent, config }
    }

    /// Forward a rebuilt request to upstream.
    pub fn send_request(
        &self,
        endpoint: &str,
        rebuilt_json: &str,
        beta_header: Option<&str>,
        is_streaming: bool,
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

                if is_streaming {
                    Ok(UpstreamResponse::Stream {
                        status,
                        headers,
                        reader: resp.into_reader(),
                    })
                } else {
                    let mut reader = resp.into_reader().take(Self::MAX_RESPONSE_BYTES as u64);
                    let mut body = String::new();
                    reader.read_to_string(&mut body)?;
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
                let mut reader = resp.into_reader().take(Self::MAX_RESPONSE_BYTES as u64);
                let mut body = String::new();
                let _ = reader.read_to_string(&mut body);
                Ok(UpstreamResponse::Body {
                    status,
                    headers,
                    body,
                })
            }
            Err(ureq::Error::Transport(e)) => Err(GatewayError::UpstreamError(format!(
                "Upstream transport error: {e}"
            ))),
        }
    }
}
