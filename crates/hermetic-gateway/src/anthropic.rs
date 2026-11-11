#![forbid(unsafe_code)]

use crate::error::GatewayError;
use crate::nonce::RunNonce;
use serde::{Deserialize, Serialize};

pub const ANTHROPIC_ADAPTER_VERSION: &str = "2026-11-1";
pub const MAX_JSON_DEPTH: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CacheControl {
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TextBlock {
    pub r#type: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SystemPrompt {
    String(String),
    Blocks(Vec<TextBlock>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImageSource {
    pub r#type: String,
    pub media_type: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentSource {
    pub r#type: String,
    pub media_type: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ToolResultContentBlock {
    Text(TextBlock),
    Image {
        r#type: String,
        source: ImageSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ToolResultContent {
    Text(String),
    Blocks(Vec<ToolResultContentBlock>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "image")]
    Image {
        source: ImageSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "document")]
    Document {
        source: DocumentSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        content: Option<ToolResultContent>,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "thinking")]
    Thinking {
        thinking: String,
        signature: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "redacted_thinking")]
    RedactedThinking {
        data: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub role: String,
    pub content: MessageContent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientTool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ToolChoice {
    #[serde(rename = "auto")]
    Auto {
        #[serde(skip_serializing_if = "Option::is_none")]
        disable_parallel_tool_use: Option<bool>,
    },
    #[serde(rename = "any")]
    Any {
        #[serde(skip_serializing_if = "Option::is_none")]
        disable_parallel_tool_use: Option<bool>,
    },
    #[serde(rename = "tool")]
    Tool {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        disable_parallel_tool_use: Option<bool>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ThinkingConfig {
    #[serde(rename = "enabled")]
    Enabled { budget_tokens: u32 },
    #[serde(rename = "disabled")]
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnthropicRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ClientTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<ThinkingConfig>,
}

impl AnthropicRequest {
    /// Injects the 128-bit run nonce into the system prompt.
    /// Prepend "[run-nonce <hex>]\n" as the first text of the system prompt.
    /// If system is absent, creates one.
    /// If system is an array, inserts a new first text block.
    pub fn inject_nonce(&mut self, nonce: &RunNonce) {
        let prefix = nonce.system_prefix();
        match &mut self.system {
            None => {
                self.system = Some(SystemPrompt::String(prefix));
            }
            Some(SystemPrompt::String(s)) => {
                *s = format!("{}{}", prefix, s);
            }
            Some(SystemPrompt::Blocks(blocks)) => {
                blocks.insert(
                    0,
                    TextBlock {
                        r#type: "text".to_string(),
                        text: prefix,
                        cache_control: None,
                    },
                );
            }
        }
    }

    /// Rebuilds the upstream JSON representation from the typed struct.
    pub fn rebuild_json(&self) -> Result<String, GatewayError> {
        serde_json::to_string(self).map_err(GatewayError::Json)
    }
}

/// Calculate the maximum nesting depth of JSON string.
pub fn check_json_nesting_depth(json_str: &str, max_depth: usize) -> Result<(), GatewayError> {
    let mut current_depth = 0usize;
    let mut in_string = false;
    let mut escape = false;

    for b in json_str.bytes() {
        if escape {
            escape = false;
            continue;
        }
        if b == b'\\' && in_string {
            escape = true;
            continue;
        }
        if b == b'"' {
            in_string = !in_string;
            continue;
        }
        if !in_string {
            if b == b'{' || b == b'[' {
                current_depth += 1;
                if current_depth > max_depth {
                    return Err(GatewayError::InvalidRequest(format!(
                        "JSON nesting depth exceeds maximum allowed limit of {max_depth}"
                    )));
                }
            } else if b == b'}' || b == b']' {
                current_depth = current_depth.saturating_sub(1);
            }
        }
    }
    Ok(())
}

/// Pre-validate raw JSON structure to provide explicit, clean errors naming the specific reason
/// before serde parsing, including server tools, URLs, forbidden fields, etc.
pub fn pre_validate_raw_json(val: &serde_json::Value) -> Result<(), GatewayError> {
    let obj = val.as_object().ok_or_else(|| {
        GatewayError::InvalidRequest("Request body must be a JSON object".to_string())
    })?;

    // Check forbidden top-level fields
    for key in obj.keys() {
        if key == "mcp_servers" {
            return Err(GatewayError::InvalidRequest(
                "Field 'mcp_servers' is forbidden".to_string(),
            ));
        }
        if key == "container" {
            return Err(GatewayError::InvalidRequest(
                "Field 'container' is forbidden".to_string(),
            ));
        }
        if key == "previous_response_id" || key.starts_with("previous_response") {
            return Err(GatewayError::InvalidRequest(format!(
                "Stored-state field '{key}' is forbidden"
            )));
        }
        if key == "batch_id" || key == "background" || key == "background_task" {
            return Err(GatewayError::InvalidRequest(format!(
                "Batch or background mode field '{key}' is forbidden"
            )));
        }
    }

    // Inspect tools for server/provider-hosted tools (tools with a 'type' field)
    if let Some(tools_val) = obj.get("tools") {
        if let Some(tools_arr) = tools_val.as_array() {
            for tool in tools_arr {
                if let Some(tool_obj) = tool.as_object() {
                    if let Some(tool_type) = tool_obj.get("type") {
                        return Err(GatewayError::InvalidRequest(format!(
                            "Provider-hosted or server tools with a 'type' field (got {}) are forbidden",
                            tool_type
                        )));
                    }
                }
            }
        }
    }

    // Recursively check image and document sources for url or file_id
    check_sources_recursive(val)?;

    Ok(())
}

fn check_sources_recursive(val: &serde_json::Value) -> Result<(), GatewayError> {
    match val {
        serde_json::Value::Object(map) => {
            if let Some(block_type) = map.get("type").and_then(|t| t.as_str()) {
                if block_type == "image" || block_type == "document" {
                    if let Some(source) = map.get("source").and_then(|s| s.as_object()) {
                        let source_type = source.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        if source_type == "url" {
                            return Err(GatewayError::InvalidRequest(format!(
                                "URL {block_type} sources are forbidden; only base64 is permitted"
                            )));
                        }
                        if source_type == "file_id" || source_type == "file" {
                            return Err(GatewayError::InvalidRequest(format!(
                                "File-ID {block_type} sources are forbidden; only base64 is permitted"
                            )));
                        }
                        if source_type != "base64" {
                            return Err(GatewayError::InvalidRequest(format!(
                                "Invalid {block_type} source type '{source_type}': only base64 is permitted"
                            )));
                        }
                    }
                }
            }
            for v in map.values() {
                check_sources_recursive(v)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                check_sources_recursive(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parses and validates an Anthropic request from JSON bytes.
pub fn parse_and_validate_request(
    json_str: &str,
    pinned_models: &[String],
) -> Result<AnthropicRequest, GatewayError> {
    // 1. Check nesting depth
    check_json_nesting_depth(json_str, MAX_JSON_DEPTH)?;

    // 2. Parse into generic serde_json::Value for explicit forbidden checks
    let raw_val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| GatewayError::InvalidRequest(format!("Malformed JSON: {e}")))?;

    // 3. Pre-validate forbidden fields, server tools, url sources
    pre_validate_raw_json(&raw_val)?;

    // 4. Parse into typed struct with deny_unknown_fields at all levels
    let req: AnthropicRequest = serde_json::from_str(json_str)
        .map_err(|e| GatewayError::InvalidRequest(format!("Invalid request structure: {e}")))?;

    // 5. Verify model is in pinned_models
    if !pinned_models.iter().any(|m| m == &req.model) {
        return Err(GatewayError::InvalidRequest(format!(
            "Model '{}' is not in the pinned models list",
            req.model
        )));
    }

    Ok(req)
}
