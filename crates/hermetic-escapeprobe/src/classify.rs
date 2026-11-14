//! Pure classification of escape attempts. No I/O here: every function maps an
//! observed outcome to a result and a fixed, safe detail string. Nothing taken
//! from the host or the network is ever echoed into a record.
#![forbid(unsafe_code)]

/// Result of one probe. `Ok` is used only by positive checks (something that
/// must work inside the sealed world); every escape attempt is `Blocked`,
/// `Leak`, `Unavailable` or `Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeResult {
    Blocked,
    Leak,
    Unavailable,
    Error,
    Ok,
}

impl EscapeResult {
    pub fn as_str(self) -> &'static str {
        match self {
            EscapeResult::Blocked => "blocked",
            EscapeResult::Leak => "leak",
            EscapeResult::Unavailable => "unavailable",
            EscapeResult::Error => "error",
            EscapeResult::Ok => "ok",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "blocked" => EscapeResult::Blocked,
            "leak" => EscapeResult::Leak,
            "unavailable" => EscapeResult::Unavailable,
            "error" => EscapeResult::Error,
            "ok" => EscapeResult::Ok,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscapeRecord {
    pub probe: String,
    pub result: EscapeResult,
    pub detail: &'static str,
}

impl EscapeRecord {
    pub fn new(probe: impl Into<String>, result: EscapeResult, detail: &'static str) -> Self {
        Self {
            probe: probe.into(),
            result,
            detail,
        }
    }

    /// One JSON object per line, same shape as the clock probe minus `value`.
    /// Probe names and details are produced by this crate only and are
    /// restricted to a safe charset; anything else is replaced.
    pub fn to_json_line(&self) -> String {
        let probe = if is_safe_token(&self.probe) {
            self.probe.as_str()
        } else {
            "invalid_probe_name"
        };
        let detail = if is_safe_token(self.detail) {
            self.detail
        } else {
            "invalid detail"
        };
        format!(
            "{{\"probe\":\"{probe}\",\"result\":\"{}\",\"detail\":\"{detail}\"}}",
            self.result.as_str()
        )
    }
}

pub const MAX_TOKEN_BYTES: usize = 128;

/// Charset allowed in probe names and details: needs no JSON escaping.
pub fn is_safe_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TOKEN_BYTES
        && s.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'_' | b'.' | b':' | b'-' | b' ' | b'/' | b'=' | b',')
        })
}

/// Exit code: 2 on any leak, 1 on any error, else 0.
pub fn exit_code(records: &[EscapeRecord]) -> i32 {
    if records.iter().any(|r| r.result == EscapeResult::Leak) {
        2
    } else if records.iter().any(|r| r.result == EscapeResult::Error) {
        1
    } else {
        0
    }
}

/// Outcome of a connect/send attempt as seen by the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// The connection was established, or a reply datagram arrived.
    Reached,
    /// No answer before the deadline.
    Timeout,
    /// The kernel returned this errno.
    Errno(i32),
}

/// Errnos that mean "the packet did not get out" for IP and vsock attempts.
pub fn is_blocking_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::ENETUNREACH
            | libc::EHOSTUNREACH
            | libc::ENETDOWN
            | libc::ECONNREFUSED
            | libc::ECONNRESET
            | libc::ETIMEDOUT
            | libc::EACCES
            | libc::EPERM
            | libc::EAFNOSUPPORT
            | libc::EPROTONOSUPPORT
            | libc::ESOCKTNOSUPPORT
            | libc::EADDRNOTAVAIL
            | libc::ENODEV
            | libc::ENOPROTOOPT
    )
}

/// Network or vsock egress attempt: reaching anything is a leak.
pub fn classify_attempt(attempt: Attempt) -> (EscapeResult, &'static str) {
    match attempt {
        Attempt::Reached => (EscapeResult::Leak, "peer reached"),
        Attempt::Timeout => (EscapeResult::Blocked, "no answer before deadline"),
        Attempt::Errno(e) if e == libc::EAFNOSUPPORT || e == libc::ESOCKTNOSUPPORT => {
            (EscapeResult::Blocked, "address family not supported")
        }
        Attempt::Errno(e) if is_blocking_errno(e) => (EscapeResult::Blocked, "kernel refused"),
        Attempt::Errno(_) => (EscapeResult::Error, "unexpected errno"),
    }
}

/// Opening a host-facing device node. Success is a leak; absence or refusal is
/// blocked. (Absence alone is weak; lockdown checks in the clock probe cover
/// node recreation.)
pub fn classify_device_open(result: Result<(), i32>) -> (EscapeResult, &'static str) {
    match result {
        Ok(()) => (EscapeResult::Leak, "device opened"),
        Err(libc::ENOENT | libc::ENXIO | libc::ENODEV | libc::EACCES | libc::EPERM) => {
            (EscapeResult::Blocked, "device not available")
        }
        Err(libc::ELOOP) => (EscapeResult::Error, "device path is a symlink"),
        Err(_) => (EscapeResult::Error, "unexpected errno"),
    }
}

/// `init_module` with an empty image. Module loading must be compiled out
/// (`ENOSYS`) or refused (`EPERM`). Any other answer means the kernel parsed
/// the request, so a crafted module could read the kvmclock MSRs.
pub fn classify_module_load(result: Result<(), i32>) -> (EscapeResult, &'static str) {
    match result {
        Err(libc::ENOSYS) => (EscapeResult::Blocked, "module loading not built"),
        Err(libc::EPERM) => (EscapeResult::Blocked, "module loading refused"),
        Err(libc::ENOEXEC | libc::EINVAL | libc::EFAULT | libc::ENOMEM | libc::EBADMSG) => {
            (EscapeResult::Leak, "module loader reachable")
        }
        Ok(()) => (EscapeResult::Leak, "module loaded"),
        Err(_) => (EscapeResult::Error, "unexpected errno"),
    }
}

/// Positive check: `getrandom(GRND_NONBLOCK)` must fill the buffer at once.
pub fn classify_getrandom(
    result: Result<usize, i32>,
    wanted: usize,
) -> (EscapeResult, &'static str) {
    match result {
        Ok(n) if n == wanted && wanted > 0 => (EscapeResult::Ok, "entropy ready"),
        Ok(_) => (EscapeResult::Error, "short read"),
        Err(libc::EAGAIN) => (EscapeResult::Error, "entropy pool not ready"),
        Err(libc::ENOSYS) => (EscapeResult::Error, "getrandom not available"),
        Err(_) => (EscapeResult::Error, "unexpected errno"),
    }
}

pub const MAX_MOUNTINFO_BYTES: usize = 256 * 1024;
pub const MAX_MOUNT_LINES: usize = 4096;

/// Filesystem types that would share host files into the guest.
pub const HOST_SHARE_FSTYPES: &[&str] = &[
    "9p",
    "virtiofs",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "fuse.sshfs",
    "vboxsf",
];

/// Host filesystem access: a mount of a host-sharing filesystem is a leak.
/// Malformed or oversized input fails closed as an error.
pub fn classify_mountinfo(text: &[u8]) -> (EscapeResult, &'static str) {
    if text.len() > MAX_MOUNTINFO_BYTES {
        return (EscapeResult::Error, "mount table too large");
    }
    let Ok(text) = std::str::from_utf8(text) else {
        return (EscapeResult::Error, "mount table not utf-8");
    };
    let mut lines = 0usize;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        lines += 1;
        if lines > MAX_MOUNT_LINES {
            return (EscapeResult::Error, "mount table too long");
        }
        // Fields: id parent major:minor root mountpoint options [optional...] - fstype source superopts
        let mut parts = line.split(" - ");
        let (Some(head), Some(tail), None) = (parts.next(), parts.next(), parts.next()) else {
            return (EscapeResult::Error, "malformed mount line");
        };
        if head.split(' ').count() < 6 {
            return (EscapeResult::Error, "malformed mount line");
        }
        let Some(fstype) = tail.split(' ').next().filter(|s| !s.is_empty()) else {
            return (EscapeResult::Error, "malformed mount line");
        };
        if HOST_SHARE_FSTYPES.contains(&fstype) {
            return (EscapeResult::Leak, "host share filesystem mounted");
        }
    }
    if lines == 0 {
        return (EscapeResult::Error, "mount table empty");
    }
    (EscapeResult::Blocked, "no host share mounts")
}
