#![forbid(unsafe_code)]

//! Rebuild Chat Completions requests and responses from the Messages policy surface.

use crate::anthropic::{
    AnthropicRequest, ContentBlock, MessageContent, Role, SystemPrompt, ToolChoice,
    ToolResultContent, ToolResultContentBlock,
};
use crate::error::GatewayError;
use crate::quota::QuotaTracker;
use crate::response::StreamSlotGuard;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Cursor, Read};
use std::sync::Arc;

pub const ADAPTER_VERSION: &str = "chat-completions-1";
pub const MAX_TOOL_CALLS: usize = 128;
pub const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;
pub const MAX_SSE_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_SSE_EVENTS: usize = 65536;

fn invalid() -> GatewayError {
    GatewayError::UpstreamError("Invalid Chat Completions response".into())
}
fn unsupported() -> GatewayError {
    GatewayError::InvalidRequest("Unsupported Chat Completions request feature".into())
}

pub fn validate_base_url(url: &str) -> Result<(), String> {
    if url.trim_end_matches('/') == "https://generativelanguage.googleapis.com/v1beta/openai" {
        return Ok(());
    }
    // Offline tests may use an explicitly loopback HTTP upstream. No credentials, redirects,
    // arbitrary URL suffix, environment proxy or remote cleartext destination is admitted.
    let authority = url
        .strip_prefix("http://127.0.0.1:")
        .and_then(|tail| tail.strip_suffix("/v1beta/openai").or(Some(tail)));
    if authority.is_some_and(|port| {
        !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|p| p != 0)
    }) {
        return Ok(());
    }
    Err("Invalid Chat Completions upstream URL".into())
}

fn text_parts(content: &ToolResultContent) -> Value {
    match content {
        ToolResultContent::Text(s) => json!(s),
        ToolResultContent::Blocks(blocks) => json!(blocks
            .iter()
            .map(|block| match block {
                ToolResultContentBlock::Text(t) => json!({"type":"text","text":t.text}),
                ToolResultContentBlock::Image(i) => json!({"type":"image_url","image_url":{
                "url":format!("data:{};base64,{}", i.source.media_type, i.source.data)}}),
            })
            .collect::<Vec<_>>()),
    }
}

pub fn request(body: &str, endpoint: &str) -> Result<(String, String), GatewayError> {
    if endpoint != "/v1/messages" {
        // There is no exact count_tokens endpoint on this upstream. Never estimate a quota.
        return Err(unsupported());
    }
    let req: AnthropicRequest = serde_json::from_str(body).map_err(|_| unsupported())?;
    if req.top_k.is_some() || req.thinking.is_some() || req.metadata.is_some() {
        return Err(unsupported());
    }
    let mut messages = Vec::new();
    if let Some(system) = req.system {
        let text = match system {
            SystemPrompt::String(s) => s,
            SystemPrompt::Blocks(blocks) => blocks
                .into_iter()
                .map(|b| b.text)
                .collect::<Vec<_>>()
                .join("\n"),
        };
        messages.push(json!({"role":"system","content":text}));
    }
    for message in req.messages {
        let role = match message.role {
            Role::User => "user",
            Role::Assistant => "assistant",
        };
        match message.content {
            MessageContent::Text(text) => messages.push(json!({"role":role,"content":text})),
            MessageContent::Blocks(blocks) => {
                let mut content = Vec::new();
                let mut calls = Vec::new();
                let mut results = Vec::new();
                for block in blocks {
                    match block {
                        ContentBlock::Text { text, .. } => content.push(json!({"type":"text","text":text})),
                        ContentBlock::Image { source, .. } if role == "user" => content.push(json!({
                            "type":"image_url","image_url":{"url":format!("data:{};base64,{}",source.media_type,source.data)}})),
                        ContentBlock::ToolUse { id, name, input, .. } if role == "assistant" => {
                            calls.push(json!({"id":id,"type":"function","function":{
                                "name":name,"arguments":serde_json::to_string(&input).map_err(|_| unsupported())?}}));
                        }
                        ContentBlock::ToolResult { tool_use_id, content, is_error, .. } if role == "user" => {
                            let output = content.as_ref().map(text_parts).unwrap_or(json!(""));
                            // Preserve error semantics in the tool content, not provider control fields.
                            let output = if is_error == Some(true) { json!(format!("Tool failed: {output}")) } else { output };
                            results.push(json!({"role":"tool","tool_call_id":tool_use_id,"content":output}));
                        }
                        _ => return Err(unsupported()),
                    }
                }
                if calls.len() > MAX_TOOL_CALLS || results.len() > MAX_TOOL_CALLS {
                    return Err(unsupported());
                }
                // Tool results belong immediately after the preceding assistant tool_calls.
                messages.extend(results);
                if !content.is_empty() || !calls.is_empty() {
                    let mut m = json!({"role":role,"content":content});
                    if !calls.is_empty() {
                        m["tool_calls"] = json!(calls);
                    }
                    messages.push(m);
                }
            }
        }
    }
    let mut output = json!({"model":req.model,"messages":messages,"max_tokens":req.max_tokens,
        "stream":req.stream.unwrap_or(false),"n":1});
    if let Some(value) = req.temperature {
        output["temperature"] = json!(value);
    }
    if let Some(value) = req.top_p {
        output["top_p"] = json!(value);
    }
    if let Some(value) = req.stop_sequences {
        output["stop"] = json!(value);
    }
    if let Some(tools) = req.tools {
        output["tools"] = json!(tools.into_iter().map(|t| json!({"type":"function","function":{
            "name":t.name,"description":t.description.unwrap_or_default(),"parameters":t.input_schema}})).collect::<Vec<_>>());
    }
    if let Some(choice) = req.tool_choice {
        let (value, parallel) = match choice {
            ToolChoice::Auto {
                disable_parallel_tool_use,
            } => (json!("auto"), disable_parallel_tool_use),
            ToolChoice::Any {
                disable_parallel_tool_use,
            } => (json!("required"), disable_parallel_tool_use),
            ToolChoice::Tool {
                name,
                disable_parallel_tool_use,
            } => (
                json!({"type":"function","function":{"name":name}}),
                disable_parallel_tool_use,
            ),
        };
        output["tool_choice"] = value;
        if let Some(disable) = parallel {
            output["parallel_tool_calls"] = json!(!disable);
        }
    }
    if req.stream == Some(true) {
        output["stream_options"] = json!({"include_usage":true});
    }
    Ok((
        "/chat/completions".into(),
        serde_json::to_string(&output).map_err(|_| unsupported())?,
    ))
}

#[derive(Clone, Copy, Deserialize)]
struct Usage {
    prompt_tokens: u64,
    completion_tokens: u64,
}
impl Usage {
    fn value(self) -> Value {
        json!({"input_tokens":self.prompt_tokens,"output_tokens":self.completion_tokens})
    }
}

pub fn reported_usage(body: &str) -> Result<(u64, u64), GatewayError> {
    #[derive(Deserialize)]
    struct Report {
        usage: Usage,
    }
    let report: Report = serde_json::from_str(body).map_err(|_| invalid())?;
    Ok((report.usage.prompt_tokens, report.usage.completion_tokens))
}
#[derive(Deserialize)]
struct Function {
    name: String,
    arguments: String,
}
#[derive(Deserialize)]
struct Call {
    r#type: String,
    function: Function,
}
#[derive(Deserialize)]
struct Message {
    role: String,
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<Call>,
}
#[derive(Deserialize)]
struct Choice {
    index: u32,
    message: Message,
    finish_reason: String,
}
#[derive(Deserialize)]
struct Completion {
    choices: Vec<Choice>,
    usage: Usage,
}

fn reason(value: &str) -> Result<&'static str, GatewayError> {
    match value {
        "stop" => Ok("end_turn"),
        "length" => Ok("max_tokens"),
        "tool_calls" => Ok("tool_use"),
        _ => Err(invalid()),
    }
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn response(body: &str, model: &str) -> Result<String, GatewayError> {
    let completion: Completion = serde_json::from_str(body).map_err(|_| invalid())?;
    if completion.choices.len() != 1 {
        return Err(invalid());
    }
    let choice = completion.choices.into_iter().next().ok_or_else(invalid)?;
    if choice.index != 0
        || choice.message.role != "assistant"
        || choice.message.tool_calls.len() > MAX_TOOL_CALLS
    {
        return Err(invalid());
    }
    let mut content = Vec::new();
    if let Some(text) = choice.message.content {
        content.push(json!({"type":"text","text":text}));
    }
    for (index, call) in choice.message.tool_calls.into_iter().enumerate() {
        if call.r#type != "function" || !valid_name(&call.function.name) {
            return Err(invalid());
        }
        let input: Value = serde_json::from_str(&call.function.arguments).map_err(|_| invalid())?;
        if !input.is_object() {
            return Err(invalid());
        }
        content.push(json!({"type":"tool_use","id":format!("toolu_{index}"),"name":call.function.name,"input":input}));
    }
    serde_json::to_string(&json!({"id":"msg_gateway","type":"message","role":"assistant",
        "model":model,"content":content,"stop_reason":reason(&choice.finish_reason)?,"stop_sequence":null,
        "usage":completion.usage.value()})).map_err(|_| invalid())
}

fn event(value: Value, out: &mut Vec<u8>) -> io::Result<()> {
    let name = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(bad_stream)?;
    out.extend_from_slice(format!("event: {name}\ndata: {value}\n\n").as_bytes());
    Ok(())
}
fn bad_stream() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid upstream stream")
}

#[derive(Deserialize)]
struct FunctionDelta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}
#[derive(Deserialize)]
struct CallDelta {
    index: usize,
    #[serde(default)]
    function: Option<FunctionDelta>,
}
#[derive(Deserialize, Default)]
struct Delta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<CallDelta>,
}
#[derive(Deserialize)]
struct StreamChoice {
    index: u32,
    delta: Delta,
    finish_reason: Option<String>,
}
#[derive(Deserialize)]
struct Chunk {
    choices: Vec<StreamChoice>,
    #[serde(default)]
    usage: Option<Usage>,
}

/// Incremental SSE translator. Unknown provider fields are never forwarded. Event bytes,
/// total bytes, event count and tool count are independently bounded before accumulation.
pub struct SseReader {
    input: BufReader<Box<dyn Read + Send + Sync>>,
    output: Cursor<Vec<u8>>,
    model: String,
    total: u64,
    events: usize,
    started: bool,
    done: bool,
    text_index: Option<usize>,
    tools: BTreeMap<usize, (usize, String)>,
    next_index: usize,
    finish: Option<String>,
    usage: Option<Usage>,
    accounting: Option<(Arc<StreamSlotGuard>, Arc<QuotaTracker>)>,
}
impl SseReader {
    pub fn new(input: Box<dyn Read + Send + Sync>, model: String) -> Self {
        Self {
            input: BufReader::new(input),
            output: Cursor::new(Vec::new()),
            model,
            total: 0,
            events: 0,
            started: false,
            done: false,
            text_index: None,
            tools: BTreeMap::new(),
            next_index: 0,
            finish: None,
            usage: None,
            accounting: None,
        }
    }
    pub fn with_accounting(mut self, slot: Arc<StreamSlotGuard>, quota: Arc<QuotaTracker>) -> Self {
        self.accounting = Some((slot, quota));
        self
    }
    fn next(&mut self) -> io::Result<Vec<u8>> {
        let mut raw = Vec::new();
        loop {
            let mut line = Vec::new();
            let remaining = MAX_SSE_EVENT_BYTES.saturating_sub(raw.len());
            let n = self
                .input
                .by_ref()
                .take(remaining as u64 + 1)
                .read_until(b'\n', &mut line)?;
            self.total = self.total.saturating_add(n as u64);
            if self.total > MAX_SSE_TOTAL_BYTES || n == 0 || n > remaining {
                return Err(bad_stream());
            }
            raw.extend_from_slice(&line);
            if line == b"\n" || line == b"\r\n" {
                break;
            }
        }
        self.events = self.events.saturating_add(1);
        if self.events > MAX_SSE_EVENTS {
            return Err(bad_stream());
        }
        let raw = std::str::from_utf8(&raw).map_err(|_| bad_stream())?;
        let mut data = String::new();
        for line in raw.lines() {
            if let Some(value) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value.strip_prefix(' ').unwrap_or(value));
            } else if !line.is_empty() && !line.starts_with(':') && !line.starts_with("event:") {
                return Err(bad_stream());
            }
        }
        let mut out = Vec::new();
        if data.is_empty() {
            return Ok(out);
        }
        if data == "[DONE]" {
            let finish = self.finish.as_deref().ok_or_else(bad_stream)?;
            let usage = self.usage.ok_or_else(bad_stream)?;
            if let Some(index) = self.text_index {
                event(json!({"type":"content_block_stop","index":index}), &mut out)?;
            }
            for (index, _) in self.tools.values() {
                event(json!({"type":"content_block_stop","index":index}), &mut out)?;
            }
            event(
                json!({"type":"message_delta","delta":{"stop_reason":finish,"stop_sequence":null},"usage":usage.value()}),
                &mut out,
            )?;
            event(json!({"type":"message_stop"}), &mut out)?;
            self.done = true;
            return Ok(out);
        }
        let chunk: Chunk = serde_json::from_str(&data).map_err(|_| bad_stream())?;
        if !self.started {
            event(
                json!({"type":"message_start","message":{"id":"msg_gateway","type":"message","role":"assistant",
                "model":self.model,"content":[],"usage":{"input_tokens":0,"output_tokens":0},"stop_reason":null,"stop_sequence":null}}),
                &mut out,
            )?;
            self.started = true;
        }
        if let Some(usage) = chunk.usage {
            let previous = self.usage.unwrap_or(Usage {
                prompt_tokens: 0,
                completion_tokens: 0,
            });
            let usage = Usage {
                prompt_tokens: previous.prompt_tokens.max(usage.prompt_tokens),
                completion_tokens: previous.completion_tokens.max(usage.completion_tokens),
            };
            self.usage = Some(usage);
            if let Some((slot, _)) = &self.accounting {
                // Account on receipt, before a client can abandon buffered Anthropic events.
                slot.set_usage(usage.prompt_tokens, usage.completion_tokens);
                slot.check_live(0).map_err(|_| bad_stream())?;
            }
        }
        if chunk.choices.len() > 1 {
            return Err(bad_stream());
        }
        for choice in chunk.choices {
            if choice.index != 0 || self.finish.is_some() {
                return Err(bad_stream());
            }
            if let Some(text) = choice.delta.content {
                let index = if let Some(index) = self.text_index {
                    index
                } else {
                    let index = self.next_index;
                    self.next_index = self.next_index.saturating_add(1);
                    self.text_index = Some(index);
                    event(
                        json!({"type":"content_block_start","index":index,"content_block":{"type":"text","text":""}}),
                        &mut out,
                    )?;
                    index
                };
                event(
                    json!({"type":"content_block_delta","index":index,"delta":{"type":"text_delta","text":text}}),
                    &mut out,
                )?;
            }
            if choice.delta.tool_calls.len() > MAX_TOOL_CALLS {
                return Err(bad_stream());
            }
            for call in choice.delta.tool_calls {
                if call.index >= MAX_TOOL_CALLS {
                    return Err(bad_stream());
                }
                let f = call.function.ok_or_else(bad_stream)?;
                let index = if let Some((index, _)) = self.tools.get(&call.index) {
                    if f.name.as_ref().is_some_and(|n| !n.is_empty()) {
                        return Err(bad_stream());
                    }
                    *index
                } else {
                    let name = f.name.ok_or_else(bad_stream)?;
                    if !valid_name(&name) || self.tools.len() >= MAX_TOOL_CALLS {
                        return Err(bad_stream());
                    }
                    let index = self.next_index;
                    self.next_index = self.next_index.saturating_add(1);
                    event(
                        json!({"type":"content_block_start","index":index,"content_block":{"type":"tool_use","id":format!("toolu_{}",call.index),"name":name,"input":{}}}),
                        &mut out,
                    )?;
                    self.tools.insert(call.index, (index, String::new()));
                    index
                };
                if let Some(arguments) = f.arguments {
                    // Retain only the capped argument string to validate completed JSON.
                    let (_, saved) = self.tools.get_mut(&call.index).ok_or_else(bad_stream)?;
                    if saved.len().saturating_add(arguments.len()) > MAX_SSE_EVENT_BYTES {
                        return Err(bad_stream());
                    }
                    saved.push_str(&arguments);
                    event(
                        json!({"type":"content_block_delta","index":index,"delta":{"type":"input_json_delta","partial_json":arguments}}),
                        &mut out,
                    )?;
                }
            }
            if let Some(finish) = choice.finish_reason {
                for (_, args) in self.tools.values() {
                    let value: Value = serde_json::from_str(args).map_err(|_| bad_stream())?;
                    if !value.is_object() {
                        return Err(bad_stream());
                    }
                }
                self.finish = Some(reason(&finish).map_err(|_| bad_stream())?.into());
            }
        }
        Ok(out)
    }
}
impl Drop for SseReader {
    fn drop(&mut self) {
        if !self.done || self.usage.is_none() {
            if let Some((_, quota)) = &self.accounting {
                // Chat usage arrives late. A cancelled or malformed stream cannot become
                // a repeatable source of unmetered output; stop this run instead.
                if !quota.is_limit_exceeded() {
                    quota.trigger_limit_exceeded("Unverifiable upstream streaming usage".into());
                }
            }
        }
    }
}
impl Read for SseReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.output.read(buf)?;
            if n != 0 || self.done {
                return Ok(n);
            }
            self.output = Cursor::new(self.next()?);
        }
    }
}
