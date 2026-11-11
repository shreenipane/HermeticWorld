#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub const INVALID_REQUEST_ERROR: &str = "invalid_request_error";
pub const AUTHENTICATION_ERROR: &str = "authentication_error";
pub const PERMISSION_ERROR: &str = "permission_error";
pub const NOT_FOUND_ERROR: &str = "not_found_error";
pub const REQUEST_TOO_LARGE: &str = "request_too_large";
pub const RATE_LIMIT_ERROR: &str = "rate_limit_error";
pub const API_ERROR: &str = "api_error";
pub const OVERLOADED_ERROR: &str = "overloaded_error";

pub const RECOGNISED_ERROR_TYPES: &[&str] = &[
    INVALID_REQUEST_ERROR,
    AUTHENTICATION_ERROR,
    PERMISSION_ERROR,
    NOT_FOUND_ERROR,
    REQUEST_TOO_LARGE,
    RATE_LIMIT_ERROR,
    API_ERROR,
    OVERLOADED_ERROR,
];

pub fn standard_message_for_type(error_type: &str) -> &'static str {
    match error_type {
        INVALID_REQUEST_ERROR => "Invalid request",
        AUTHENTICATION_ERROR => "Authentication error",
        PERMISSION_ERROR => "Permission error",
        NOT_FOUND_ERROR => "Not found",
        REQUEST_TOO_LARGE => "Request too large",
        RATE_LIMIT_ERROR => "Rate limit exceeded",
        OVERLOADED_ERROR => "Overloaded",
        _ => "Upstream API error",
    }
}

pub fn is_recognised_error_type(error_type: &str) -> bool {
    RECOGNISED_ERROR_TYPES.contains(&error_type)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnthropicErrorDetail {
    pub r#type: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnthropicErrorResponse {
    pub r#type: String,
    pub error: AnthropicErrorDetail,
}

impl AnthropicErrorResponse {
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            r#type: "error".to_string(),
            error: AnthropicErrorDetail {
                r#type: error_type.into(),
                message: message.into(),
            },
        }
    }

    pub fn standard(error_type: &str) -> Self {
        let recognised = if is_recognised_error_type(error_type) {
            error_type
        } else {
            API_ERROR
        };
        Self::new(recognised, standard_message_for_type(recognised))
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"type":"error","error":{"type":"api_error","message":"Internal error"}}"#
                .to_string()
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Request too large: {0}")]
    RequestTooLarge(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Upstream error: {0}")]
    UpstreamError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl GatewayError {
    pub fn status_code(&self) -> u16 {
        match self {
            GatewayError::InvalidRequest(_) => 400,
            GatewayError::NotFound(_) => 404,
            GatewayError::RequestTooLarge(_) => 413,
            GatewayError::RateLimitExceeded(_) => 429,
            GatewayError::UpstreamError(_) => 502,
            GatewayError::Io(_) => 500,
            GatewayError::Json(_) => 400,
        }
    }

    pub fn error_type(&self) -> &'static str {
        match self {
            GatewayError::InvalidRequest(_) => INVALID_REQUEST_ERROR,
            GatewayError::NotFound(_) => NOT_FOUND_ERROR,
            GatewayError::RequestTooLarge(_) => REQUEST_TOO_LARGE,
            GatewayError::RateLimitExceeded(_) => RATE_LIMIT_ERROR,
            GatewayError::UpstreamError(_) => API_ERROR,
            GatewayError::Io(_) => API_ERROR,
            GatewayError::Json(_) => INVALID_REQUEST_ERROR,
        }
    }

    pub fn to_anthropic_response(&self) -> AnthropicErrorResponse {
        match self {
            GatewayError::InvalidRequest(msg) => {
                AnthropicErrorResponse::new(INVALID_REQUEST_ERROR, msg.clone())
            }
            GatewayError::NotFound(msg) => {
                AnthropicErrorResponse::new(NOT_FOUND_ERROR, msg.clone())
            }
            GatewayError::RequestTooLarge(msg) => {
                AnthropicErrorResponse::new(REQUEST_TOO_LARGE, msg.clone())
            }
            GatewayError::RateLimitExceeded(msg) => {
                AnthropicErrorResponse::new(RATE_LIMIT_ERROR, msg.clone())
            }
            GatewayError::UpstreamError(msg) => AnthropicErrorResponse::new(API_ERROR, msg.clone()),
            GatewayError::Io(e) => AnthropicErrorResponse::new(API_ERROR, e.to_string()),
            GatewayError::Json(e) => {
                AnthropicErrorResponse::new(INVALID_REQUEST_ERROR, e.to_string())
            }
        }
    }
}
