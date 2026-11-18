#![forbid(unsafe_code)]

pub mod agent_config;
pub mod anthropic;
pub mod config;
pub mod error;
pub mod fsutil;
pub mod history;
pub mod log;
pub mod nonce;
pub mod openai;
pub mod quota;
pub mod response;
pub mod sandbox;
pub mod server;
pub mod upstream;

pub use agent_config::{AgentConfig, AgentConfigError, SettingsPayload};
pub use anthropic::{AnthropicRequest, ANTHROPIC_ADAPTER_VERSION};
pub use config::GatewayConfig;
pub use error::{AnthropicErrorResponse, DateFormatError, GatewayError};
pub use history::HistoryLog;
pub use log::{HostLogEntry, HostLogger};
pub use nonce::RunNonce;
pub use quota::{QuotaBreach, QuotaSnapshot, QuotaTracker, QuotasConfig};
pub use response::{
    format_imf_fixdate, GuestClock, SanitizingSseReader, StreamSlotGuard, StreamUsage,
};
pub use sandbox::{
    apply_landlock, apply_resource_limits, apply_sandbox, apply_seccomp, SandboxError,
    SandboxLandlockStatus,
};
pub use server::{GatewayHistorySummary, GatewayServer, GATEWAY_HISTORY_FILE};
pub use upstream::UpstreamClient;
