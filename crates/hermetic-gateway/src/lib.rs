#![forbid(unsafe_code)]

pub mod anthropic;
pub mod config;
pub mod error;
pub mod history;
pub mod log;
pub mod nonce;
pub mod quota;
pub mod response;
pub mod server;
pub mod upstream;

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
pub use server::GatewayServer;
pub use upstream::UpstreamClient;
