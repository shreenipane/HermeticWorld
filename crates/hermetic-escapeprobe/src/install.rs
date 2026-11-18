#![forbid(unsafe_code)]

//! Positive install checks through NetVM (TR-SEC-6, §9.6): pip, git, curl.
//!
//! Confirms that normal package installation and resource downloads function
//! as expected through NetVM while the world is sealed.

use std::process::{Command, Stdio};
use std::time::Duration;

use crate::classify::{EscapeRecord, EscapeResult};
use crate::config::InstallConfig;
use crate::http;

pub const DEFAULT_INSTALL_TIMEOUT: Duration = Duration::from_millis(10000);

pub fn classify_pip_install(outcome: Result<bool, &'static str>) -> (EscapeResult, &'static str) {
    match outcome {
        Ok(true) => (EscapeResult::Ok, "pip install succeeded"),
        Ok(false) => (EscapeResult::Error, "pip install command failed"),
        Err("unavailable") => (EscapeResult::Unavailable, "install check not configured"),
        Err(e) => (EscapeResult::Error, e),
    }
}

pub fn classify_git_clone(outcome: Result<bool, &'static str>) -> (EscapeResult, &'static str) {
    match outcome {
        Ok(true) => (EscapeResult::Ok, "git clone succeeded"),
        Ok(false) => (EscapeResult::Error, "git clone command failed"),
        Err("unavailable") => (EscapeResult::Unavailable, "install check not configured"),
        Err(e) => (EscapeResult::Error, e),
    }
}

pub fn classify_curl_get(outcome: Result<bool, &'static str>) -> (EscapeResult, &'static str) {
    match outcome {
        Ok(true) => (EscapeResult::Ok, "curl get succeeded"),
        Ok(false) => (EscapeResult::Error, "curl get command failed"),
        Err("unavailable") => (EscapeResult::Unavailable, "install check not configured"),
        Err(e) => (EscapeResult::Error, e),
    }
}

pub const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(20);
pub const MAX_COMMAND_POLL_ITERATIONS: usize = 10_000;

fn run_child_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<bool, &'static str> {
    let start = std::time::Instant::now();
    for _ in 0..MAX_COMMAND_POLL_ITERATIONS {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("command timed out");
                }
                std::thread::sleep(COMMAND_POLL_INTERVAL.min(timeout));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("command execution failed");
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("command timed out")
}

fn run_command(argv: &[String], timeout: Duration) -> Result<bool, &'static str> {
    if argv.is_empty() {
        return Err("empty command");
    }
    let child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "command execution failed")?;
    run_child_with_timeout(child, timeout)
}

/// Executes pip install check.
pub fn check_pip_install(
    cmd: Option<&[String]>,
    target: Option<&str>,
    timeout: Duration,
) -> Result<bool, &'static str> {
    if let Some(c) = cmd {
        return run_command(c, timeout);
    }
    let Some(target) = target else {
        return Err("unavailable");
    };

    if target.starts_with("http://") {
        match http::request(target, "GET", &[], &[], timeout) {
            Ok(resp) if (200..=299).contains(&resp.status) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Ok(false),
        }
    } else {
        let pip_spawn = Command::new("python3")
            .args(["-m", "pip", "install", "--dry-run", "--no-deps", target])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match pip_spawn {
            Ok(child) => run_child_with_timeout(child, timeout),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err("pip binary not found and target is not http")
            }
            Err(_) => Err("pip execution error"),
        }
    }
}

/// Executes git clone check.
pub fn check_git_clone(
    cmd: Option<&[String]>,
    target: Option<&str>,
    timeout: Duration,
) -> Result<bool, &'static str> {
    if let Some(c) = cmd {
        return run_command(c, timeout);
    }
    let Some(target) = target else {
        return Err("unavailable");
    };

    if target.starts_with("http://") {
        match http::request(target, "GET", &[], &[], timeout) {
            Ok(resp) if (200..=299).contains(&resp.status) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Ok(false),
        }
    } else {
        let git_spawn = Command::new("git")
            .args(["ls-remote", target, "HEAD"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match git_spawn {
            Ok(child) => run_child_with_timeout(child, timeout),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err("git binary not found and target is not http")
            }
            Err(_) => Err("git execution error"),
        }
    }
}

/// Executes curl get check.
pub fn check_curl_get(
    cmd: Option<&[String]>,
    target: Option<&str>,
    timeout: Duration,
) -> Result<bool, &'static str> {
    if let Some(c) = cmd {
        return run_command(c, timeout);
    }
    let Some(target) = target else {
        return Err("unavailable");
    };

    if target.starts_with("http://") {
        // Try system curl if present
        let curl_spawn = Command::new("curl")
            .args([
                "-s",
                "-S",
                "-f",
                "-o",
                "/dev/null",
                "--connect-timeout",
                "5",
                "--max-time",
                "10",
                target,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        if let Ok(child) = curl_spawn {
            if let Ok(success) = run_child_with_timeout(child, timeout) {
                return Ok(success);
            }
        }

        // Fallback to internal HTTP client
        match http::request(target, "GET", &[], &[], timeout) {
            Ok(resp) if (200..=299).contains(&resp.status) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Ok(false),
        }
    } else {
        Err("target is not http")
    }
}

/// Runs all 3 install positive checks.
pub fn run_install_probes(cfg: Option<&InstallConfig>) -> Vec<EscapeRecord> {
    let mut out = Vec::new();

    let pip_cmd = cfg.and_then(|c| c.pip_command.as_deref());
    let pip_target = cfg.and_then(|c| c.pip_target.as_deref());
    let (r, d) = classify_pip_install(check_pip_install(
        pip_cmd,
        pip_target,
        DEFAULT_INSTALL_TIMEOUT,
    ));
    out.push(EscapeRecord::new("positive.pip_install", r, d));

    let git_cmd = cfg.and_then(|c| c.git_command.as_deref());
    let git_target = cfg.and_then(|c| c.git_target.as_deref());
    let (r, d) = classify_git_clone(check_git_clone(
        git_cmd,
        git_target,
        DEFAULT_INSTALL_TIMEOUT,
    ));
    out.push(EscapeRecord::new("positive.git_clone", r, d));

    let curl_cmd = cfg.and_then(|c| c.curl_command.as_deref());
    let curl_url = cfg.and_then(|c| c.curl_url.as_deref());
    let (r, d) = classify_curl_get(check_curl_get(curl_cmd, curl_url, DEFAULT_INSTALL_TIMEOUT));
    out.push(EscapeRecord::new("positive.curl_get", r, d));

    out
}
