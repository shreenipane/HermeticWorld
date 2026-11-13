# Policy gateway and Chat Completions upstream

The default upstream protocol remains Anthropic Messages. Set
`upstream_protocol` to `openai_chat` and `upstream_base_url` to
`https://generativelanguage.googleapis.com/v1beta/openai` for the
[documented compatibility endpoint](https://aistudio.google.com/docs/openai).
The gateway appends `/chat/completions` and supplies a Bearer credential read
once from `api_key_file`. The key must be a regular file with mode 0600;
symlinks in any input path component, FIFOs and devices are refused. Do not put
the key in this repository. Tests create fake keys and loopback upstreams only.

```json
{
  "upstream_protocol": "openai_chat",
  "upstream_base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
  "anthropic_version": "2023-06-01",
  "pinned_models": ["PINNED"],
  "api_key_file": "/private/provider-key",
  "log_dir": "/private/gateway-logs",
  "upstream_read_timeout_s": 120
}
```

Requests still pass the existing typed Messages allowlist, model pinning,
nonce injection, history consistency and quota checks. The upstream adapter
rebuilds text, inline images, function tools, tool choices and tool results.
It does not forward arbitrary guest or provider fields. There is no exact
count_tokens equivalent; that endpoint fails closed on this upstream. Thinking,
top_k, metadata and documents are rejected where no supported translation is
defined. The Anthropic upstream retains its existing surface.

Responses rebuild only assistant text, function calls, finish reason and
required token usage. Provider IDs, model names, clocks and metadata are
discarded. Tool argument JSON is preserved. Incremental SSE uses bounded
events, total bytes, event count and tool counts; incomplete streams and missing
usage fail closed. The existing response filter then applies guest Date,
standard errors, stream error handling, quota accounting and secret-redacted
host logging. The active adapter version is recorded as `chat-completions-1`.
Redirects remain disabled. Tests may use a numeric loopback HTTP endpoint;
remote cleartext and arbitrary production hosts are refused.

Usage is charged before validating generated content. Cancelling a stream before
its terminal usage is verified ends the run, so repeated cancellations cannot
obtain unmetered output. Reported usage is recorded before buffered translated
events can be abandoned by the client.
