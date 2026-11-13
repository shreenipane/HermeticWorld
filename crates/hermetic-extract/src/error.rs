#![forbid(unsafe_code)]

use std::fmt;

/// Top-level error for hermetic-extract operations.
#[derive(Debug)]
pub enum ExtractError {
    Format(FormatError),
    PathValidation(PathError),
    Quota(QuotaError),
    TaskClass(TaskClassError),
    FsSecurity(FsSecurityError),
    Config(String),
    Io(std::io::Error),
}

impl ExtractError {
    /// Returns true if this error is caused by hostile or invalid agent input
    /// (which should cause the validator binary to exit with status 2), or false
    /// if it is a host/configuration/operational failure (exit status 1).
    pub fn is_rejection(&self) -> bool {
        match self {
            Self::Format(_)
            | Self::PathValidation(_)
            | Self::Quota(_)
            | Self::TaskClass(_)
            | Self::FsSecurity(_) => true,
            Self::Config(_) | Self::Io(_) => false,
        }
    }
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(e) => write!(f, "format error: {e}"),
            Self::PathValidation(e) => write!(f, "path validation error: {e}"),
            Self::Quota(e) => write!(f, "quota exceeded: {e}"),
            Self::TaskClass(e) => write!(f, "task class error: {e}"),
            Self::FsSecurity(e) => write!(f, "filesystem security error: {e}"),
            Self::Config(e) => write!(f, "config error: {e}"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(e) => Some(e),
            Self::PathValidation(e) => Some(e),
            Self::Quota(e) => Some(e),
            Self::TaskClass(e) => Some(e),
            Self::FsSecurity(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Config(_) => None,
        }
    }
}

impl From<FormatError> for ExtractError {
    fn from(e: FormatError) -> Self {
        Self::Format(e)
    }
}

impl From<PathError> for ExtractError {
    fn from(e: PathError) -> Self {
        Self::PathValidation(e)
    }
}

impl From<QuotaError> for ExtractError {
    fn from(e: QuotaError) -> Self {
        Self::Quota(e)
    }
}

impl From<TaskClassError> for ExtractError {
    fn from(e: TaskClassError) -> Self {
        Self::TaskClass(e)
    }
}

impl From<FsSecurityError> for ExtractError {
    fn from(e: FsSecurityError) -> Self {
        Self::FsSecurity(e)
    }
}

impl From<std::io::Error> for ExtractError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FormatError {
    BadMagic([u8; 4]),
    UnsupportedVersion(u32),
    UnknownRecordType(u8),
    UnsupportedRecordType {
        record_type: u8,
        name: &'static str,
    },
    Truncated(&'static str),
    TrailingGarbage,
    OversizedField {
        field: &'static str,
        size: usize,
        cap: usize,
    },
    SizeMismatch {
        declared: u64,
        actual: u64,
    },
    HashMismatch {
        path: String,
        declared: String,
        actual: String,
    },
    CountMismatch {
        declared: u64,
        actual: u64,
    },
    TotalBytesMismatch {
        declared: u64,
        actual: u64,
    },
    InvalidReservedBytes([u8; 2]),
    InvalidUtf8Path,
    InvalidPayloadForType(&'static str),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic(m) => write!(f, "invalid stream magic: {m:?}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported stream version: {v}"),
            Self::UnknownRecordType(t) => write!(f, "unknown record type: {t}"),
            Self::UnsupportedRecordType { record_type, name } => {
                write!(f, "unsupported hostile record type {record_type} ({name})")
            }
            Self::Truncated(msg) => write!(f, "truncated stream: {msg}"),
            Self::TrailingGarbage => write!(f, "unexpected trailing bytes after end-of-stream"),
            Self::OversizedField { field, size, cap } => {
                write!(f, "field '{field}' size {size} exceeds cap {cap}")
            }
            Self::SizeMismatch { declared, actual } => {
                write!(f, "size mismatch: declared {declared}, got {actual}")
            }
            Self::HashMismatch {
                path,
                declared,
                actual,
            } => {
                write!(
                    f,
                    "hash mismatch for '{path}': declared {declared}, got {actual}"
                )
            }
            Self::CountMismatch { declared, actual } => {
                write!(
                    f,
                    "record count mismatch: declared {declared}, counted {actual}"
                )
            }
            Self::TotalBytesMismatch { declared, actual } => {
                write!(
                    f,
                    "total bytes mismatch: declared {declared}, counted {actual}"
                )
            }
            Self::InvalidReservedBytes(b) => write!(f, "reserved bytes must be zero, got {b:?}"),
            Self::InvalidUtf8Path => write!(f, "record path is not valid UTF-8"),
            Self::InvalidPayloadForType(t) => write!(f, "record type {t} must not carry payload"),
        }
    }
}

impl std::error::Error for FormatError {}

#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    Empty,
    Absolute(String),
    DrivePrefix(String),
    Backslash(String),
    NulByte(String),
    EmptyComponent(String),
    DotOrDotDot(String),
    DepthExceeded {
        path: String,
        depth: usize,
        cap: usize,
    },
    LengthExceeded {
        path: String,
        len: usize,
        cap: usize,
    },
    TraversesRegularFile {
        path: String,
        file_component: String,
    },
    FileReplacesDirectoryWithChildren {
        path: String,
    },
    DuplicatePath(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "path is empty"),
            Self::Absolute(p) => write!(f, "path '{p}' is absolute"),
            Self::DrivePrefix(p) => write!(f, "path '{p}' contains drive prefix"),
            Self::Backslash(p) => write!(f, "path '{p}' contains backslash"),
            Self::NulByte(p) => write!(f, "path '{p}' contains NUL byte"),
            Self::EmptyComponent(p) => write!(f, "path '{p}' contains empty component"),
            Self::DotOrDotDot(p) => write!(f, "path '{p}' contains '.' or '..' component"),
            Self::DepthExceeded { path, depth, cap } => {
                write!(f, "path '{path}' depth {depth} exceeds cap {cap}")
            }
            Self::LengthExceeded { path, len, cap } => {
                write!(f, "path '{path}' length {len} exceeds cap {cap}")
            }
            Self::TraversesRegularFile {
                path,
                file_component,
            } => {
                write!(
                    f,
                    "path '{path}' passes through declared regular file '{file_component}'"
                )
            }
            Self::FileReplacesDirectoryWithChildren { path } => {
                write!(f, "path '{path}' was declared as a directory with children; cannot declare as regular file")
            }
            Self::DuplicatePath(p) => write!(f, "duplicate record for path '{p}'"),
        }
    }
}

impl std::error::Error for PathError {}

#[derive(Debug, PartialEq, Eq)]
pub enum QuotaError {
    ResourceLimit(&'static str),
    FileBytesExceeded { path: String, size: u64, cap: u64 },
    TotalBytesExceeded { total: u64, cap: u64 },
    FileCountExceeded { count: u64, cap: u64 },
    DirCountExceeded { count: u64, cap: u64 },
}

impl fmt::Display for QuotaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceLimit(name) => write!(f, "resource limit exceeded: {name}"),
            Self::FileBytesExceeded { path, size, cap } => {
                write!(f, "file '{path}' size {size} exceeds quota {cap}")
            }
            Self::TotalBytesExceeded { total, cap } => {
                write!(f, "total bytes {total} exceeds quota {cap}")
            }
            Self::FileCountExceeded { count, cap } => {
                write!(f, "file count {count} exceeds quota {cap}")
            }
            Self::DirCountExceeded { count, cap } => {
                write!(f, "directory count {count} exceeds quota {cap}")
            }
        }
    }
}

impl std::error::Error for QuotaError {}

#[derive(Debug, PartialEq, Eq)]
pub enum TaskClassError {
    OutsideRepoDir { path: String, repo_dir: String },
    UndeclaredArtifactPath { path: String },
    StateTaskNonEmptyStream { path: String },
}

impl fmt::Display for TaskClassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutsideRepoDir { path, repo_dir } => {
                write!(
                    f,
                    "path '{path}' is outside declared repository directory '{repo_dir}'"
                )
            }
            Self::UndeclaredArtifactPath { path } => {
                write!(f, "path '{path}' is not among declared artifact paths")
            }
            Self::StateTaskNonEmptyStream { path } => {
                write!(
                    f,
                    "state task class requires empty stream; received entry for '{path}'"
                )
            }
        }
    }
}

impl std::error::Error for TaskClassError {}

#[derive(Debug, PartialEq, Eq)]
pub enum FsSecurityError {
    SymlinkRejected(String),
    SpecialFileRejected(String),
    OutputDirNotEmpty(String),
    OutputDirNotOwned(String),
    OutputDirIsSymlink(String),
    TamperingDetected(String),
}

impl fmt::Display for FsSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SymlinkRejected(p) => write!(f, "symlink rejected: '{p}'"),
            Self::SpecialFileRejected(p) => {
                write!(f, "special file (FIFO/device/socket) rejected: '{p}'")
            }
            Self::OutputDirNotEmpty(p) => write!(f, "output directory '{p}' must be empty"),
            Self::OutputDirNotOwned(p) => write!(
                f,
                "output directory '{p}' is not owned by current process uid"
            ),
            Self::OutputDirIsSymlink(p) => write!(f, "output directory '{p}' is a symlink"),
            Self::TamperingDetected(m) => write!(f, "filesystem tampering detected: {m}"),
        }
    }
}

impl std::error::Error for FsSecurityError {}
