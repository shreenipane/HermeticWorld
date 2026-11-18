#![forbid(unsafe_code)]

//! Gateway abuse probes and real model-call date scanning (TR-SEC-6, §9.6, §9.2).
//!
//! Evaluates the model gateway's default-deny policies:
//! 1. `gateway.remote_source`: rejects server-fetched URLs and file IDs.
//! 2. `gateway.provider_tools`: rejects provider-hosted search, fetch, bash tools.
//! 3. `gateway.other_endpoint`: rejects endpoints other than allowed messages endpoint.
//! 4. `gateway.other_model`: rejects unpinned models.
//! 5. `gateway.unlisted_beta`: rejects unlisted beta headers.
//! 6. `gateway.quota`: enforces body size and rate/request quotas (413/429).
//! 7. `gateway.model_call_date`: verifies real model call responses are sanitized
//!    and contain no real dates, host names, or host paths (D12).

use std::time::Duration;

use hermetic_sealcheck::d12::D12Options;
use hermetic_sealcheck::d12_runtime::{DateSentinel, SentinelSummary};

use crate::classify::{EscapeRecord, EscapeResult};
use crate::config::GatewayConfig;
use crate::http::{self, HttpError, HttpResponse};

pub const DEFAULT_GATEWAY_TIMEOUT: Duration = Duration::from_millis(5000);

pub fn classify_remote_source(status: Result<u16, &HttpError>) -> (EscapeResult, &'static str) {
    match status {
        Ok(code) if (400..=499).contains(&code) => {
            (EscapeResult::Blocked, "remote source rejected by gateway")
        }
        Ok(code) if (200..=299).contains(&code) => {
            (EscapeResult::Leak, "remote source accepted by gateway")
        }
        Ok(_) => (EscapeResult::Error, "unexpected gateway response status"),
        Err(HttpError::Timeout) => (EscapeResult::Blocked, "gateway connection timed out"),
        Err(HttpError::Io(_)) => (EscapeResult::Blocked, "gateway connection refused"),
        Err(_) => (EscapeResult::Error, "protocol error connecting to gateway"),
    }
}

pub fn classify_provider_tools(status: Result<u16, &HttpError>) -> (EscapeResult, &'static str) {
    match status {
        Ok(code) if (400..=499).contains(&code) => {
            (EscapeResult::Blocked, "provider tools rejected by gateway")
        }
        Ok(code) if (200..=299).contains(&code) => {
            (EscapeResult::Leak, "provider tools accepted by gateway")
        }
        Ok(_) => (EscapeResult::Error, "unexpected gateway response status"),
        Err(HttpError::Timeout) => (EscapeResult::Blocked, "gateway connection timed out"),
        Err(HttpError::Io(_)) => (EscapeResult::Blocked, "gateway connection refused"),
        Err(_) => (EscapeResult::Error, "protocol error connecting to gateway"),
    }
}

pub fn classify_other_endpoint(status: Result<u16, &HttpError>) -> (EscapeResult, &'static str) {
    match status {
        Ok(code) if (400..=499).contains(&code) => (
            EscapeResult::Blocked,
            "unlisted endpoint rejected by gateway",
        ),
        Ok(code) if (200..=299).contains(&code) => {
            (EscapeResult::Leak, "unlisted endpoint reachable")
        }
        Ok(_) => (EscapeResult::Error, "unexpected gateway response status"),
        Err(HttpError::Timeout) => (EscapeResult::Blocked, "gateway connection timed out"),
        Err(HttpError::Io(_)) => (EscapeResult::Blocked, "gateway connection refused"),
        Err(_) => (EscapeResult::Error, "protocol error connecting to gateway"),
    }
}

pub fn classify_other_model(status: Result<u16, &HttpError>) -> (EscapeResult, &'static str) {
    match status {
        Ok(code) if (400..=499).contains(&code) => {
            (EscapeResult::Blocked, "unpinned model rejected by gateway")
        }
        Ok(code) if (200..=299).contains(&code) => {
            (EscapeResult::Leak, "unpinned model accepted by gateway")
        }
        Ok(_) => (EscapeResult::Error, "unexpected gateway response status"),
        Err(HttpError::Timeout) => (EscapeResult::Blocked, "gateway connection timed out"),
        Err(HttpError::Io(_)) => (EscapeResult::Blocked, "gateway connection refused"),
        Err(_) => (EscapeResult::Error, "protocol error connecting to gateway"),
    }
}

pub fn classify_unlisted_beta(status: Result<u16, &HttpError>) -> (EscapeResult, &'static str) {
    match status {
        Ok(code) if (400..=499).contains(&code) => {
            (EscapeResult::Blocked, "unlisted beta rejected by gateway")
        }
        Ok(code) if (200..=299).contains(&code) => {
            (EscapeResult::Leak, "unlisted beta accepted by gateway")
        }
        Ok(_) => (EscapeResult::Error, "unexpected gateway response status"),
        Err(HttpError::Timeout) => (EscapeResult::Blocked, "gateway connection timed out"),
        Err(HttpError::Io(_)) => (EscapeResult::Blocked, "gateway connection refused"),
        Err(_) => (EscapeResult::Error, "protocol error connecting to gateway"),
    }
}

pub fn classify_quota(status: Result<u16, &HttpError>) -> (EscapeResult, &'static str) {
    match status {
        Ok(413) | Ok(429) => (EscapeResult::Blocked, "quota limits enforced by gateway"),
        Ok(code) if (400..=499).contains(&code) => {
            (EscapeResult::Blocked, "quota limits enforced by gateway")
        }
        Ok(code) if (200..=299).contains(&code) => {
            (EscapeResult::Leak, "quota limits not enforced")
        }
        Ok(_) => (EscapeResult::Error, "unexpected gateway response status"),
        Err(HttpError::ResponseTooLarge) => (
            EscapeResult::Error,
            "oversized response received from gateway",
        ),
        Err(HttpError::Timeout) => (EscapeResult::Blocked, "gateway connection timed out"),
        Err(HttpError::Io(_)) => (EscapeResult::Blocked, "gateway connection refused"),
        Err(_) => (EscapeResult::Error, "protocol error connecting to gateway"),
    }
}

pub fn classify_model_call_date(
    resp: Result<&HttpResponse, &HttpError>,
    opts: Option<&D12Options>,
) -> (EscapeResult, &'static str, Option<SentinelSummary>) {
    let resp = match resp {
        Ok(r) => r,
        Err(HttpError::Timeout) => {
            return (EscapeResult::Blocked, "gateway connection timed out", None);
        }
        Err(HttpError::Io(_)) => {
            return (EscapeResult::Blocked, "gateway connection refused", None);
        }
        Err(_) => {
            return (
                EscapeResult::Error,
                "protocol error connecting to gateway",
                None,
            );
        }
    };

    let Some(options) = opts else {
        // Without sentinel options, the response is not verified clean of dates.
        return (
            EscapeResult::Unavailable,
            "gateway responded without date options",
            None,
        );
    };

    let sentinel = match DateSentinel::new(options.clone()) {
        Ok(s) => s,
        Err(_) => return (EscapeResult::Error, "invalid date sentinel options", None),
    };

    // Scan headers: Date, server timestamps, x-amz-date, etc.
    for (k, v) in &resp.headers {
        let header_line = format!("{k}: {v}");
        sentinel.scan_text("gateway_header", &header_line);
    }

    // Scan response body
    if let Ok(body_str) = resp.body_str() {
        sentinel.scan_text("gateway_body", body_str);
    } else {
        sentinel.mark_incomplete("gateway_body", "non_utf8_body");
    }

    let summary = sentinel.summary();
    if summary.date_leak_observed {
        (
            EscapeResult::Leak,
            "real date leaked in model call response",
            Some(summary),
        )
    } else if (200..=299).contains(&resp.status) {
        (
            EscapeResult::Blocked,
            "model call response verified clean of real dates",
            Some(summary),
        )
    } else {
        (
            EscapeResult::Error,
            "model call response status was not successful",
            Some(summary),
        )
    }
}

/// Executes all 7 gateway probes against a configured gateway.
pub fn run_gateway_probes(
    cfg: Option<&GatewayConfig>,
    timeout: Duration,
) -> (Vec<EscapeRecord>, Option<SentinelSummary>) {
    let Some(g) = cfg else {
        let mut recs = Vec::new();
        for name in crate::probes::GATEWAY_PROBES {
            recs.push(EscapeRecord::new(
                *name,
                EscapeResult::Unavailable,
                "gateway probe not configured",
            ));
        }
        return (recs, None);
    };

    let mut records = Vec::new();
    let base = g.base_url.trim_end_matches('/');

    let common_headers = [
        ("content-type", "application/json"),
        ("anthropic-version", g.api_version.as_str()),
    ];

    // 1. gateway.remote_source
    let remote_source_body = serde_json::json!({
        "model": g.pinned_model,
        "max_tokens": 10,
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image",
                "source": {
                    "type": "url",
                    "url": "http://127.0.0.1/evil.png"
                }
            }]
        }]
    })
    .to_string();
    let res = http::request(
        &format!("{base}/v1/messages"),
        "POST",
        &common_headers,
        remote_source_body.as_bytes(),
        timeout,
    );
    let (r, d) = classify_remote_source(res.as_ref().map(|resp| resp.status));
    records.push(EscapeRecord::new("gateway.remote_source", r, d));

    // 2. gateway.provider_tools
    let provider_tools_body = serde_json::json!({
        "model": g.pinned_model,
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "ping"}],
        "tools": [{
            "type": "web_search_20250101",
            "name": "web_search"
        }]
    })
    .to_string();
    let res = http::request(
        &format!("{base}/v1/messages"),
        "POST",
        &common_headers,
        provider_tools_body.as_bytes(),
        timeout,
    );
    let (r, d) = classify_provider_tools(res.as_ref().map(|resp| resp.status));
    records.push(EscapeRecord::new("gateway.provider_tools", r, d));

    // 3. gateway.other_endpoint
    let other_endpoint_body = serde_json::json!({
        "model": g.pinned_model,
        "prompt": "ping"
    })
    .to_string();
    let res = http::request(
        &format!("{base}/v1/complete"),
        "POST",
        &common_headers,
        other_endpoint_body.as_bytes(),
        timeout,
    );
    let (r, d) = classify_other_endpoint(res.as_ref().map(|resp| resp.status));
    records.push(EscapeRecord::new("gateway.other_endpoint", r, d));

    // 4. gateway.other_model
    let other_model_body = serde_json::json!({
        "model": "unpinned-prohibited-model",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "ping"}]
    })
    .to_string();
    let res = http::request(
        &format!("{base}/v1/messages"),
        "POST",
        &common_headers,
        other_model_body.as_bytes(),
        timeout,
    );
    let (r, d) = classify_other_model(res.as_ref().map(|resp| resp.status));
    records.push(EscapeRecord::new("gateway.other_model", r, d));

    // 5. gateway.unlisted_beta
    let mut beta_headers = common_headers.to_vec();
    beta_headers.push(("anthropic-beta", "unlisted-prohibited-beta-2026"));
    let normal_body = serde_json::json!({
        "model": g.pinned_model,
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "ping"}]
    })
    .to_string();
    let res = http::request(
        &format!("{base}/v1/messages"),
        "POST",
        &beta_headers,
        normal_body.as_bytes(),
        timeout,
    );
    let (r, d) = classify_unlisted_beta(res.as_ref().map(|resp| resp.status));
    records.push(EscapeRecord::new("gateway.unlisted_beta", r, d));

    // 6. gateway.quota
    let large_body = serde_json::json!({
        "model": g.pinned_model,
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "a".repeat(11 * 1024 * 1024)}]
    })
    .to_string();
    let res = http::request(
        &format!("{base}/v1/messages"),
        "POST",
        &common_headers,
        large_body.as_bytes(),
        timeout,
    );
    let (r, d) = classify_quota(res.as_ref().map(|resp| resp.status));
    records.push(EscapeRecord::new("gateway.quota", r, d));

    // 7. gateway.model_call_date
    let mut model_call_headers = common_headers.to_vec();
    if let Some(ref beta) = g.allowed_beta {
        model_call_headers.push(("anthropic-beta", beta.as_str()));
    }
    let d12_opts = g.sentinel.as_ref().and_then(|s| {
        s.parse_date().ok().map(|d| D12Options {
            real_date: d,
            tolerance_days: s.tolerance_days,
            host_names: s.host_names.clone(),
            host_paths: s.host_paths.clone(),
        })
    });
    let res = http::request(
        &format!("{base}/v1/messages"),
        "POST",
        &model_call_headers,
        normal_body.as_bytes(),
        timeout,
    );
    let (r, d, summary) = classify_model_call_date(res.as_ref(), d12_opts.as_ref());
    records.push(EscapeRecord::new("gateway.model_call_date", r, d));

    (records, summary)
}
