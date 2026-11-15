use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Maximum number of argument tokens accepted after `argv[0]`.
pub const MAX_ARGS: usize = 64;

/// Maximum byte length of any single argument token.
pub const MAX_ARG_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubcommandKind {
    Seal,
    VerifyBundle,
    Probe,
    Run,
    Verify,
    Help,
}

impl SubcommandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seal => "seal",
            Self::VerifyBundle => "verify-bundle",
            Self::Probe => "probe",
            Self::Run => "run",
            Self::Verify => "verify",
            Self::Help => "help",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "seal" => Some(Self::Seal),
            "verify-bundle" => Some(Self::VerifyBundle),
            "probe" => Some(Self::Probe),
            "run" => Some(Self::Run),
            "verify" => Some(Self::Verify),
            "help" => Some(Self::Help),
            _ => None,
        }
    }
}

impl fmt::Display for SubcommandKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealLevel {
    Strict,
    RepoOnly,
}

impl SealLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::RepoOnly => "repo_only",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "strict" => Some(Self::Strict),
            "repo_only" => Some(Self::RepoOnly),
            _ => None,
        }
    }
}

impl fmt::Display for SealLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMode {
    H,
    G,
}

impl AgentMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H => "H",
            Self::G => "G",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "H" => Some(Self::H),
            "G" => Some(Self::G),
            _ => None,
        }
    }
}

impl fmt::Display for AgentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockMode {
    Faked,
    Hidden,
}

impl ClockMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Faked => "faked",
            Self::Hidden => "hidden",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "faked" => Some(Self::Faked),
            "hidden" => Some(Self::Hidden),
            _ => None,
        }
    }
}

impl fmt::Display for ClockMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSealArgs {
    pub src: String,
    pub out: String,
    pub t_clock: String,
    pub world_id: String,
    pub seal_level: SealLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawVerifyBundleArgs {
    pub dir: String,
    pub root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProbeArgs {
    pub world: String,
    pub json: bool,
    pub clockprobe_output: Option<String>,
    pub kernel_canary_serial: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRunArgs {
    pub world: String,
    pub task: String,
    pub agent_mode: AgentMode,
    pub clock: ClockMode,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawVerifyArgs {
    pub record: String,
    pub key: String,
    pub bundle: Option<String>,
    pub classification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawCommand {
    Version,
    Help(Option<SubcommandKind>),
    Seal(RawSealArgs),
    VerifyBundle(RawVerifyBundleArgs),
    Probe(RawProbeArgs),
    Run(RawRunArgs),
    Verify(RawVerifyArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealRequest {
    pub src: PathBuf,
    pub out: PathBuf,
    pub t_clock: String,
    pub world_id: String,
    pub seal_level: SealLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyBundleRequest {
    pub dir: PathBuf,
    pub root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub world: PathBuf,
    pub json: bool,
    /// Captured `hermetic-clockprobe` JSON-lines output to classify (never run on the host).
    #[serde(default)]
    pub clockprobe_output: Option<PathBuf>,
    /// Captured disposable-kernel canary serial transcript to classify.
    #[serde(default)]
    pub kernel_canary_serial: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRequest {
    pub world: PathBuf,
    pub task: String,
    pub agent_mode: AgentMode,
    pub clock: ClockMode,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub record: PathBuf,
    pub key: PathBuf,
    pub bundle: Option<PathBuf>,
    pub classification: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedCommand {
    Version,
    Help(Option<SubcommandKind>),
    Seal(SealRequest),
    VerifyBundle(VerifyBundleRequest),
    Probe(ProbeRequest),
    Run(RunRequest),
    Verify(VerifyRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    NonUtf8Argument {
        position: usize,
    },
    TooManyArguments {
        limit: usize,
    },
    ArgumentTooLong {
        position: usize,
        limit: usize,
    },
    MissingSubcommand,
    UnknownSubcommand {
        name: String,
    },
    ShortFlagNotSupported {
        flag: String,
    },
    UnknownFlag {
        flag: String,
    },
    MissingFlagValue {
        flag: String,
    },
    UnexpectedFlagValue {
        flag: String,
    },
    RepeatedFlag {
        flag: String,
    },
    MissingRequiredFlag {
        flag: &'static str,
    },
    MissingPositional {
        name: &'static str,
    },
    StrayPositional {
        value: String,
    },
    InvalidFlagChoice {
        flag: &'static str,
        value: String,
        expected: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub subcommand: Option<SubcommandKind>,
    pub kind: ParseErrorKind,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ParseErrorKind::NonUtf8Argument { position } => {
                write!(f, "argument at position {position} is not valid UTF-8")
            }
            ParseErrorKind::TooManyArguments { limit } => {
                write!(f, "too many arguments (at most {limit})")
            }
            ParseErrorKind::ArgumentTooLong { position, limit } => {
                write!(f, "argument at position {position} exceeds {limit} bytes")
            }
            ParseErrorKind::MissingSubcommand => f.write_str("missing subcommand"),
            ParseErrorKind::UnknownSubcommand { name } => {
                write!(f, "unknown subcommand '{name}'")
            }
            ParseErrorKind::ShortFlagNotSupported { flag } => {
                write!(f, "short flags are not supported: '{flag}'")
            }
            ParseErrorKind::UnknownFlag { flag } => write!(f, "unknown flag '{flag}'"),
            ParseErrorKind::MissingFlagValue { flag } => {
                write!(f, "flag '{flag}' requires a value")
            }
            ParseErrorKind::UnexpectedFlagValue { flag } => {
                write!(f, "flag '{flag}' does not accept a value")
            }
            ParseErrorKind::RepeatedFlag { flag } => {
                write!(f, "flag '{flag}' cannot be specified more than once")
            }
            ParseErrorKind::MissingRequiredFlag { flag } => {
                write!(f, "missing required flag '{flag}'")
            }
            ParseErrorKind::MissingPositional { name } => {
                write!(f, "missing required positional argument <{name}>")
            }
            ParseErrorKind::StrayPositional { value } => {
                write!(f, "unexpected positional argument '{value}'")
            }
            ParseErrorKind::InvalidFlagChoice {
                flag,
                value,
                expected,
            } => {
                write!(
                    f,
                    "invalid value '{value}' for '{flag}' (expected {expected})"
                )
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    EmptyPath { field: &'static str },
    PathContainsNul { field: &'static str },
    InvalidTimestamp { value: String, reason: &'static str },
    InvalidWorldId { value: String },
    InvalidTaskId { value: String },
    InvalidSha256Root { value: String },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath { field } => write!(f, "{field} must not be empty"),
            Self::PathContainsNul { field } => write!(f, "{field} must not contain NUL bytes"),
            Self::InvalidTimestamp { value, reason } => {
                write!(
                    f,
                    "invalid RFC 3339 UTC timestamp '{value}' for --t-clock: {reason}"
                )
            }
            Self::InvalidWorldId { value } => {
                write!(
                    f,
                    "invalid world id '{value}' for --world-id (must match [a-z0-9-]{{1,64}})"
                )
            }
            Self::InvalidTaskId { value } => {
                write!(
                    f,
                    "invalid task id '{value}' for --task (must match [A-Za-z0-9._-]{{1,128}})"
                )
            }
            Self::InvalidSha256Root { value } => {
                write!(
                    f,
                    "invalid sha256 root '{value}' for --root (must be 'sha256:' followed by 64 lowercase hex characters)"
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

enum FlagSpec {
    Value,
    Bool,
}

struct ParsedTokens {
    flags: Vec<(String, Option<String>)>,
    positionals: Vec<String>,
}

fn scan_tokens(
    subcommand: SubcommandKind,
    tokens: &[String],
    specs: &[(&'static str, FlagSpec)],
) -> Result<ParsedTokens, ParseError> {
    let mut flags: Vec<(String, Option<String>)> = Vec::new();
    let mut positionals: Vec<String> = Vec::new();
    let mut after_double_dash = false;
    let mut i = 0;

    while let Some(token) = tokens.get(i) {
        if after_double_dash {
            positionals.push(token.clone());
            i = i.saturating_add(1);
            continue;
        }

        if token == "--" {
            after_double_dash = true;
            i = i.saturating_add(1);
            continue;
        }

        if let Some(rest) = token.strip_prefix("--") {
            if rest.is_empty() {
                after_double_dash = true;
                i = i.saturating_add(1);
                continue;
            }
            let (flag_name, inline_value) = match token.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (token.as_str(), None),
            };

            let spec = specs
                .iter()
                .find(|(name, _)| *name == flag_name)
                .map(|(_, kind)| kind)
                .ok_or_else(|| ParseError {
                    subcommand: Some(subcommand),
                    kind: ParseErrorKind::UnknownFlag {
                        flag: flag_name.to_string(),
                    },
                })?;

            if flags.iter().any(|(seen, _)| seen == flag_name) {
                return Err(ParseError {
                    subcommand: Some(subcommand),
                    kind: ParseErrorKind::RepeatedFlag {
                        flag: flag_name.to_string(),
                    },
                });
            }

            match spec {
                FlagSpec::Bool => {
                    if inline_value.is_some() {
                        return Err(ParseError {
                            subcommand: Some(subcommand),
                            kind: ParseErrorKind::UnexpectedFlagValue {
                                flag: flag_name.to_string(),
                            },
                        });
                    }
                    flags.push((flag_name.to_string(), None));
                    i = i.saturating_add(1);
                }
                FlagSpec::Value => {
                    if let Some(val) = inline_value {
                        flags.push((flag_name.to_string(), Some(val.to_string())));
                        i = i.saturating_add(1);
                    } else {
                        let next = tokens.get(i.saturating_add(1)).ok_or_else(|| ParseError {
                            subcommand: Some(subcommand),
                            kind: ParseErrorKind::MissingFlagValue {
                                flag: flag_name.to_string(),
                            },
                        })?;
                        if next == "--" || next.starts_with("--") {
                            return Err(ParseError {
                                subcommand: Some(subcommand),
                                kind: ParseErrorKind::MissingFlagValue {
                                    flag: flag_name.to_string(),
                                },
                            });
                        }
                        flags.push((flag_name.to_string(), Some(next.clone())));
                        i = i.saturating_add(2);
                    }
                }
            }
            continue;
        }

        if token.starts_with('-') {
            return Err(ParseError {
                subcommand: Some(subcommand),
                kind: ParseErrorKind::ShortFlagNotSupported {
                    flag: token.clone(),
                },
            });
        }

        positionals.push(token.clone());
        i = i.saturating_add(1);
    }

    Ok(ParsedTokens { flags, positionals })
}

fn take_value_flag(parsed: &ParsedTokens, name: &str) -> Option<String> {
    parsed
        .flags
        .iter()
        .find(|(k, _)| k == name)
        .and_then(|(_, v)| v.clone())
}

fn has_bool_flag(parsed: &ParsedTokens, name: &str) -> bool {
    parsed.flags.iter().any(|(k, _)| k == name)
}

fn require_value_flag(
    subcommand: SubcommandKind,
    parsed: &ParsedTokens,
    name: &'static str,
) -> Result<String, ParseError> {
    take_value_flag(parsed, name).ok_or(ParseError {
        subcommand: Some(subcommand),
        kind: ParseErrorKind::MissingRequiredFlag { flag: name },
    })
}

fn reject_any_positionals(
    subcommand: SubcommandKind,
    parsed: &ParsedTokens,
) -> Result<(), ParseError> {
    if let Some(first) = parsed.positionals.first() {
        return Err(ParseError {
            subcommand: Some(subcommand),
            kind: ParseErrorKind::StrayPositional {
                value: first.clone(),
            },
        });
    }
    Ok(())
}

/// Parses CLI arguments (excluding `argv[0]`).
/// Every `OsString` is strictly converted to UTF-8 without lossy conversion.
pub fn parse_args<I>(args: I) -> Result<RawCommand, ParseError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut tokens = Vec::new();
    for (idx, os_arg) in args.into_iter().enumerate() {
        if idx >= MAX_ARGS {
            return Err(ParseError {
                subcommand: None,
                kind: ParseErrorKind::TooManyArguments { limit: MAX_ARGS },
            });
        }
        let position = idx.saturating_add(1);
        if os_arg.len() > MAX_ARG_BYTES {
            return Err(ParseError {
                subcommand: None,
                kind: ParseErrorKind::ArgumentTooLong {
                    position,
                    limit: MAX_ARG_BYTES,
                },
            });
        }
        let utf8 = os_arg.into_string().map_err(|_| ParseError {
            subcommand: None,
            kind: ParseErrorKind::NonUtf8Argument { position },
        })?;
        tokens.push(utf8);
    }

    let first = tokens.first().ok_or(ParseError {
        subcommand: None,
        kind: ParseErrorKind::MissingSubcommand,
    })?;

    if first == "--version" {
        if let Some(extra) = tokens.get(1) {
            return Err(ParseError {
                subcommand: None,
                kind: ParseErrorKind::StrayPositional {
                    value: extra.clone(),
                },
            });
        }
        return Ok(RawCommand::Version);
    }

    if first.starts_with("--") {
        return Err(ParseError {
            subcommand: None,
            kind: ParseErrorKind::UnknownFlag {
                flag: first.clone(),
            },
        });
    }

    if first.starts_with('-') {
        return Err(ParseError {
            subcommand: None,
            kind: ParseErrorKind::ShortFlagNotSupported {
                flag: first.clone(),
            },
        });
    }

    let subcommand = SubcommandKind::from_name(first).ok_or_else(|| ParseError {
        subcommand: None,
        kind: ParseErrorKind::UnknownSubcommand {
            name: first.clone(),
        },
    })?;

    let rest = tokens.get(1..).unwrap_or(&[]);

    match subcommand {
        SubcommandKind::Help => {
            let Some(target_raw) = rest.first() else {
                return Ok(RawCommand::Help(None));
            };
            if target_raw.starts_with("--") {
                return Err(ParseError {
                    subcommand: Some(SubcommandKind::Help),
                    kind: ParseErrorKind::UnknownFlag {
                        flag: target_raw.clone(),
                    },
                });
            }
            if target_raw.starts_with('-') {
                return Err(ParseError {
                    subcommand: Some(SubcommandKind::Help),
                    kind: ParseErrorKind::ShortFlagNotSupported {
                        flag: target_raw.clone(),
                    },
                });
            }
            let target = SubcommandKind::from_name(target_raw).ok_or_else(|| ParseError {
                subcommand: Some(SubcommandKind::Help),
                kind: ParseErrorKind::UnknownSubcommand {
                    name: target_raw.clone(),
                },
            })?;
            if let Some(extra) = rest.get(1) {
                return Err(ParseError {
                    subcommand: Some(SubcommandKind::Help),
                    kind: ParseErrorKind::StrayPositional {
                        value: extra.clone(),
                    },
                });
            }
            Ok(RawCommand::Help(Some(target)))
        }
        SubcommandKind::Seal => {
            let parsed = scan_tokens(
                SubcommandKind::Seal,
                rest,
                &[
                    ("--src", FlagSpec::Value),
                    ("--out", FlagSpec::Value),
                    ("--t-clock", FlagSpec::Value),
                    ("--world-id", FlagSpec::Value),
                    ("--seal-level", FlagSpec::Value),
                ],
            )?;
            reject_any_positionals(SubcommandKind::Seal, &parsed)?;
            let src = require_value_flag(SubcommandKind::Seal, &parsed, "--src")?;
            let out = require_value_flag(SubcommandKind::Seal, &parsed, "--out")?;
            let t_clock = require_value_flag(SubcommandKind::Seal, &parsed, "--t-clock")?;
            let world_id = require_value_flag(SubcommandKind::Seal, &parsed, "--world-id")?;
            let seal_level = match take_value_flag(&parsed, "--seal-level") {
                Some(raw) => SealLevel::parse(&raw).ok_or(ParseError {
                    subcommand: Some(SubcommandKind::Seal),
                    kind: ParseErrorKind::InvalidFlagChoice {
                        flag: "--seal-level",
                        value: raw,
                        expected: "strict|repo_only",
                    },
                })?,
                None => SealLevel::Strict,
            };
            Ok(RawCommand::Seal(RawSealArgs {
                src,
                out,
                t_clock,
                world_id,
                seal_level,
            }))
        }
        SubcommandKind::VerifyBundle => {
            let parsed = scan_tokens(
                SubcommandKind::VerifyBundle,
                rest,
                &[("--root", FlagSpec::Value)],
            )?;
            let dir = parsed.positionals.first().cloned().ok_or(ParseError {
                subcommand: Some(SubcommandKind::VerifyBundle),
                kind: ParseErrorKind::MissingPositional { name: "DIR" },
            })?;
            if let Some(extra) = parsed.positionals.get(1) {
                return Err(ParseError {
                    subcommand: Some(SubcommandKind::VerifyBundle),
                    kind: ParseErrorKind::StrayPositional {
                        value: extra.clone(),
                    },
                });
            }
            let root = take_value_flag(&parsed, "--root");
            Ok(RawCommand::VerifyBundle(RawVerifyBundleArgs { dir, root }))
        }
        SubcommandKind::Probe => {
            let parsed = scan_tokens(
                SubcommandKind::Probe,
                rest,
                &[
                    ("--world", FlagSpec::Value),
                    ("--json", FlagSpec::Bool),
                    ("--clockprobe-output", FlagSpec::Value),
                    ("--kernel-canary-serial", FlagSpec::Value),
                ],
            )?;
            reject_any_positionals(SubcommandKind::Probe, &parsed)?;
            let world = require_value_flag(SubcommandKind::Probe, &parsed, "--world")?;
            let json = has_bool_flag(&parsed, "--json");
            let clockprobe_output = take_value_flag(&parsed, "--clockprobe-output");
            let kernel_canary_serial = take_value_flag(&parsed, "--kernel-canary-serial");
            Ok(RawCommand::Probe(RawProbeArgs {
                world,
                json,
                clockprobe_output,
                kernel_canary_serial,
            }))
        }
        SubcommandKind::Run => {
            let parsed = scan_tokens(
                SubcommandKind::Run,
                rest,
                &[
                    ("--world", FlagSpec::Value),
                    ("--task", FlagSpec::Value),
                    ("--agent-mode", FlagSpec::Value),
                    ("--clock", FlagSpec::Value),
                    ("--json", FlagSpec::Bool),
                ],
            )?;
            reject_any_positionals(SubcommandKind::Run, &parsed)?;
            let world = require_value_flag(SubcommandKind::Run, &parsed, "--world")?;
            let task = require_value_flag(SubcommandKind::Run, &parsed, "--task")?;
            let agent_mode_raw = require_value_flag(SubcommandKind::Run, &parsed, "--agent-mode")?;
            let agent_mode = AgentMode::parse(&agent_mode_raw).ok_or(ParseError {
                subcommand: Some(SubcommandKind::Run),
                kind: ParseErrorKind::InvalidFlagChoice {
                    flag: "--agent-mode",
                    value: agent_mode_raw,
                    expected: "H|G",
                },
            })?;
            let clock = match take_value_flag(&parsed, "--clock") {
                Some(raw) => ClockMode::parse(&raw).ok_or(ParseError {
                    subcommand: Some(SubcommandKind::Run),
                    kind: ParseErrorKind::InvalidFlagChoice {
                        flag: "--clock",
                        value: raw,
                        expected: "faked|hidden",
                    },
                })?,
                None => ClockMode::Faked,
            };
            let json = has_bool_flag(&parsed, "--json");
            Ok(RawCommand::Run(RawRunArgs {
                world,
                task,
                agent_mode,
                clock,
                json,
            }))
        }
        SubcommandKind::Verify => {
            let parsed = scan_tokens(
                SubcommandKind::Verify,
                rest,
                &[
                    ("--record", FlagSpec::Value),
                    ("--key", FlagSpec::Value),
                    ("--bundle", FlagSpec::Value),
                    ("--classification", FlagSpec::Value),
                ],
            )?;
            reject_any_positionals(SubcommandKind::Verify, &parsed)?;
            let record = require_value_flag(SubcommandKind::Verify, &parsed, "--record")?;
            let key = require_value_flag(SubcommandKind::Verify, &parsed, "--key")?;
            let bundle = take_value_flag(&parsed, "--bundle");
            let classification = take_value_flag(&parsed, "--classification");
            Ok(RawCommand::Verify(RawVerifyArgs {
                record,
                key,
                bundle,
                classification,
            }))
        }
    }
}

pub fn validate_command(raw: RawCommand) -> Result<ValidatedCommand, ValidationError> {
    match raw {
        RawCommand::Version => Ok(ValidatedCommand::Version),
        RawCommand::Help(sub) => Ok(ValidatedCommand::Help(sub)),
        RawCommand::Seal(args) => {
            let src = validate_path("--src", &args.src)?;
            let out = validate_path("--out", &args.out)?;
            validate_rfc3339_utc(&args.t_clock)?;
            validate_world_id(&args.world_id)?;
            Ok(ValidatedCommand::Seal(SealRequest {
                src,
                out,
                t_clock: args.t_clock,
                world_id: args.world_id,
                seal_level: args.seal_level,
            }))
        }
        RawCommand::VerifyBundle(args) => {
            let dir = validate_path("DIR", &args.dir)?;
            if let Some(ref root) = args.root {
                validate_sha256_root(root)?;
            }
            Ok(ValidatedCommand::VerifyBundle(VerifyBundleRequest {
                dir,
                root: args.root,
            }))
        }
        RawCommand::Probe(args) => {
            let world = validate_path("--world", &args.world)?;
            let clockprobe_output = args
                .clockprobe_output
                .as_deref()
                .map(|v| validate_path("--clockprobe-output", v))
                .transpose()?;
            let kernel_canary_serial = args
                .kernel_canary_serial
                .as_deref()
                .map(|v| validate_path("--kernel-canary-serial", v))
                .transpose()?;
            Ok(ValidatedCommand::Probe(ProbeRequest {
                world,
                json: args.json,
                clockprobe_output,
                kernel_canary_serial,
            }))
        }
        RawCommand::Run(args) => {
            let world = validate_path("--world", &args.world)?;
            validate_task_id(&args.task)?;
            Ok(ValidatedCommand::Run(RunRequest {
                world,
                task: args.task,
                agent_mode: args.agent_mode,
                clock: args.clock,
                json: args.json,
            }))
        }
        RawCommand::Verify(args) => {
            let record = validate_path("--record", &args.record)?;
            let key = validate_path("--key", &args.key)?;
            let bundle = match args.bundle {
                Some(ref b) => Some(validate_path("--bundle", b)?),
                None => None,
            };
            let classification = args
                .classification
                .as_deref()
                .map(|v| validate_path("--classification", v))
                .transpose()?;
            Ok(ValidatedCommand::Verify(VerifyRequest {
                record,
                key,
                bundle,
                classification,
            }))
        }
    }
}

pub fn validate_path(field: &'static str, value: &str) -> Result<PathBuf, ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyPath { field });
    }
    if value.contains('\0') {
        return Err(ValidationError::PathContainsNul { field });
    }
    Ok(PathBuf::from(value))
}

pub fn validate_world_id(value: &str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(ValidationError::InvalidWorldId {
            value: value.to_string(),
        });
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(ValidationError::InvalidWorldId {
            value: value.to_string(),
        });
    }
    Ok(())
}

pub fn validate_task_id(value: &str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(ValidationError::InvalidTaskId {
            value: value.to_string(),
        });
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'_' || *b == b'-')
    {
        return Err(ValidationError::InvalidTaskId {
            value: value.to_string(),
        });
    }
    Ok(())
}

pub fn validate_sha256_root(value: &str) -> Result<(), ValidationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ValidationError::InvalidSha256Root {
            value: value.to_string(),
        });
    };
    let bytes = hex.as_bytes();
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(ValidationError::InvalidSha256Root {
            value: value.to_string(),
        });
    }
    Ok(())
}

pub fn validate_rfc3339_utc(value: &str) -> Result<(), ValidationError> {
    let err = |reason: &'static str| ValidationError::InvalidTimestamp {
        value: value.to_string(),
        reason,
    };

    let bytes = value.as_bytes();
    let fmt_err = "expected format YYYY-MM-DDTHH:MM:SS[.frac]Z";
    // Minimum length: YYYY-MM-DDTHH:MM:SSZ = 20 bytes
    if bytes.len() < 20 {
        return Err(err(fmt_err));
    }
    let Some((&last, body)) = bytes.split_last() else {
        return Err(err(fmt_err));
    };
    if last != b'Z' {
        return Err(err("timestamp must end with uppercase 'Z'"));
    }
    let at = |idx: usize| bytes.get(idx).copied();
    if at(4) != Some(b'-')
        || at(7) != Some(b'-')
        || at(10) != Some(b'T')
        || at(13) != Some(b':')
        || at(16) != Some(b':')
    {
        return Err(err(fmt_err));
    }

    let field = |range: std::ops::Range<usize>| bytes.get(range).and_then(parse_digits);
    let year = field(0..4).ok_or_else(|| err("invalid year"))?;
    let month = field(5..7).ok_or_else(|| err("invalid month"))?;
    let day = field(8..10).ok_or_else(|| err("invalid day"))?;
    let hour = field(11..13).ok_or_else(|| err("invalid hour"))?;
    let minute = field(14..16).ok_or_else(|| err("invalid minute"))?;
    let second = field(17..19).ok_or_else(|| err("invalid second"))?;

    if !(1..=12).contains(&month) {
        return Err(err("month out of range 01..=12"));
    }
    let max_day = days_in_month(year, month);
    if day < 1 || day > max_day {
        return Err(err("day out of range for month"));
    }
    if hour > 23 {
        return Err(err("hour out of range 00..=23"));
    }
    if minute > 59 {
        return Err(err("minute out of range 00..=59"));
    }
    if second > 60 {
        return Err(err("second out of range 00..=60"));
    }

    let tail = body.get(19..).unwrap_or(&[]);
    if let Some((&first, digits)) = tail.split_first() {
        if first != b'.' || digits.is_empty() || !digits.iter().all(|b| b.is_ascii_digit()) {
            return Err(err("invalid fractional seconds"));
        }
    }

    Ok(())
}

fn parse_digits(slice: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    for &b in slice {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(acc)
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}
