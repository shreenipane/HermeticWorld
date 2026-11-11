#![forbid(unsafe_code)]

use hermetic_common::{Method, RequestFrame, ResponseFrame, ResponseHeader, WireError};
use std::io::ErrorKind;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Instant;
use time::OffsetDateTime;

use crate::limits::Limits;
use crate::log::{LogEventParams, LogManager};
use crate::sandbox::apply_sandbox;
use crate::store::{DirStore, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerExit {
    Normal,
    Tampered = 3,
    LimitExceeded = 4,
}

pub struct ServerConfig {
    pub store_dir: PathBuf,
    pub socket_path: PathBuf,
    pub log_dir: PathBuf,
    pub t_clock: OffsetDateTime,
    pub rate_rps: Option<f64>,
    pub burst: Option<f64>,
    pub max_requests: Option<u64>,
    pub max_bytes: Option<u64>,
    pub allow_no_landlock: bool,
    pub no_sandbox: bool, // For in-process unit testing without restricting cargo test runner
}

/// Format an OffsetDateTime in IMF-fixdate format (RFC 7231 / RFC 9110), e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
pub fn format_imf_fixdate(dt: OffsetDateTime) -> String {
    let utc = dt.to_offset(time::UtcOffset::UTC);
    let weekday = match utc.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    let month = match utc.month() {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        weekday,
        utc.day(),
        month,
        utc.year(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// Strip forbidden headers: memento-*, x-archive-*, server containing pywb.
pub fn filter_headers(
    extra_headers: Vec<(String, String)>,
    content_type: Option<&str>,
    content_length: usize,
    date_str: &str,
    content_range: Option<&str>,
) -> Vec<ResponseHeader> {
    let mut out = Vec::new();

    // Standard headers
    out.push(ResponseHeader {
        name: "date".into(),
        value: date_str.into(),
    });
    out.push(ResponseHeader {
        name: "content-length".into(),
        value: content_length.to_string(),
    });
    out.push(ResponseHeader {
        name: "accept-ranges".into(),
        value: "bytes".into(),
    });

    if let Some(ct) = content_type {
        out.push(ResponseHeader {
            name: "content-type".into(),
            value: ct.into(),
        });
    }

    if let Some(cr) = content_range {
        out.push(ResponseHeader {
            name: "content-range".into(),
            value: cr.into(),
        });
    }

    // Extra headers with security stripping
    for (name, val) in extra_headers {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("memento-") || lower.starts_with("x-archive-") {
            continue;
        }
        if lower == "server" && val.to_ascii_lowercase().contains("pywb") {
            continue;
        }
        // Don't overwrite the ones we already set
        if lower == "date"
            || lower == "content-length"
            || lower == "content-type"
            || lower == "content-range"
            || lower == "accept-ranges"
        {
            continue;
        }
        out.push(ResponseHeader {
            name: lower,
            value: val,
        });
    }

    out
}

pub struct WorldServer {
    config: ServerConfig,
    store: DirStore,
    limits: Limits,
    log: LogManager,
    start_time: Instant,
}

impl WorldServer {
    pub fn new(config: ServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Step 1: Open store directory and create log files
        let store = DirStore::new(&config.store_dir);
        let log = LogManager::new(&config.log_dir)?;
        let limits = Limits::new(
            config.rate_rps,
            config.burst,
            config.max_requests,
            config.max_bytes,
        );

        Ok(Self {
            config,
            store,
            limits,
            log,
            start_time: Instant::now(),
        })
    }

    /// Run the server loop.
    pub fn run(mut self) -> Result<(), ServerExit> {
        // Step 2: Bind Unix socket
        if self.config.socket_path.exists() {
            let _ = std::fs::remove_file(&self.config.socket_path);
        }
        let listener = UnixListener::bind(&self.config.socket_path).map_err(|e| {
            eprintln!("Failed to bind socket: {e}");
            ServerExit::Normal
        })?;

        // Step 3: Apply Landlock and Seccomp (TR-WS-1)
        if !self.config.no_sandbox {
            if let Err(e) = apply_sandbox(
                &self.config.store_dir,
                &self.config.log_dir,
                self.config.allow_no_landlock,
            ) {
                eprintln!("Failed to apply sandbox: {e}");
                return Err(ServerExit::Normal);
            }
        }

        // Step 4: Accept connections
        for stream_res in listener.incoming() {
            let mut stream = match stream_res {
                Ok(s) => s,
                Err(_) => continue,
            };

            let exit = self.handle_connection(&mut stream);
            if exit != ServerExit::Normal {
                let _ = self.log.finish();
                return Err(exit);
            }
        }

        let _ = self.log.finish();
        Ok(())
    }

    /// Handle requests on a single connection sequentially until EOF or fatal error.
    fn handle_connection(&mut self, stream: &mut UnixStream) -> ServerExit {
        loop {
            let frame = match RequestFrame::read_from(stream) {
                Ok(f) => f,
                Err(WireError::Io(e))
                    if e.kind() == ErrorKind::UnexpectedEof
                        || e.kind() == ErrorKind::ConnectionReset
                        || e.kind() == ErrorKind::BrokenPipe =>
                {
                    // Clean EOF from client
                    return ServerExit::Normal;
                }
                Err(WireError::Malformed(reason)) => {
                    // Malformed frame: log tampered, exit code 3
                    let elapsed_ms = self.start_time.elapsed().as_millis() as u64;
                    eprintln!("Malformed frame received: {reason}");
                    let _ = self.log.log_event(&LogEventParams {
                        elapsed_ms,
                        request_id: 0,
                        method: "",
                        authority: "",
                        path_and_query: "",
                        range: None,
                        status: "tampered",
                        bytes: 0,
                    });
                    let _ = self.log.finish();
                    return ServerExit::Tampered;
                }
                Err(e) => {
                    eprintln!("I/O error reading frame: {e}");
                    return ServerExit::Normal;
                }
            };

            // 1. Check request cap
            if self.limits.check_request_cap().is_err() {
                let elapsed_ms = self.start_time.elapsed().as_millis() as u64;
                let _ = self.log.log_event(&LogEventParams {
                    elapsed_ms,
                    request_id: frame.request_id,
                    method: match frame.method {
                        Method::Get => "GET",
                        Method::Head => "HEAD",
                    },
                    authority: &frame.authority,
                    path_and_query: &frame.path_and_query,
                    range: frame.range,
                    status: "limit_exceeded",
                    bytes: 0,
                });
                let _ = self.log.finish();
                return ServerExit::LimitExceeded;
            }

            // 2. Token bucket delay
            self.limits.acquire_token();

            // 3. Process request
            let elapsed = self.start_time.elapsed();
            let elapsed_ms = elapsed.as_millis() as u64;
            let current_clock = self.config.t_clock + elapsed;
            let date_str = format_imf_fixdate(current_clock);

            let method_str = match frame.method {
                Method::Get => "GET",
                Method::Head => "HEAD",
            };

            let stored = self.store.get(&frame.authority, &frame.path_and_query);

            let (status, headers, body) = match stored {
                Some(obj) => {
                    let total_len = obj.body.len();
                    match frame.range {
                        Some((r_start, r_end)) => {
                            if total_len == 0 || r_start >= total_len as u64 || r_start > r_end {
                                // Unsatisfiable range -> 416
                                let cr = format!("bytes */{total_len}");
                                let hdrs = filter_headers(
                                    obj.extra_headers,
                                    obj.content_type.as_deref(),
                                    0,
                                    &date_str,
                                    Some(&cr),
                                );
                                (416u16, hdrs, Vec::new())
                            } else {
                                // Satisfiable range -> 206
                                let clamped_end = (r_end as usize).min(total_len - 1);
                                let sliced = obj.body[r_start as usize..=clamped_end].to_vec();
                                let cr = format!("bytes {r_start}-{clamped_end}/{total_len}");
                                let length = sliced.len();
                                let hdrs = filter_headers(
                                    obj.extra_headers,
                                    obj.content_type.as_deref(),
                                    length,
                                    &date_str,
                                    Some(&cr),
                                );
                                let resp_body = if frame.method == Method::Head {
                                    Vec::new()
                                } else {
                                    sliced
                                };
                                (206u16, hdrs, resp_body)
                            }
                        }
                        None => {
                            // Full object -> 200
                            let length = total_len;
                            let hdrs = filter_headers(
                                obj.extra_headers,
                                obj.content_type.as_deref(),
                                length,
                                &date_str,
                                None,
                            );
                            let resp_body = if frame.method == Method::Head {
                                Vec::new()
                            } else {
                                obj.body
                            };
                            (200u16, hdrs, resp_body)
                        }
                    }
                }
                None => {
                    // Miss -> 404
                    let (st, ct, b) = self.store.get_404(&frame.authority);
                    let length = b.len();
                    let hdrs = filter_headers(Vec::new(), ct.as_deref(), length, &date_str, None);
                    let resp_body = if frame.method == Method::Head {
                        Vec::new()
                    } else {
                        b
                    };
                    (st, hdrs, resp_body)
                }
            };

            let response_bytes = body.len() as u64;

            // 4. Check byte cap
            if self.limits.check_bytes_cap(response_bytes).is_err() {
                let _ = self.log.log_event(&LogEventParams {
                    elapsed_ms,
                    request_id: frame.request_id,
                    method: method_str,
                    authority: &frame.authority,
                    path_and_query: &frame.path_and_query,
                    range: frame.range,
                    status: "limit_exceeded",
                    bytes: 0,
                });
                let _ = self.log.finish();
                return ServerExit::LimitExceeded;
            }

            // 5. Send response frame
            let response = ResponseFrame {
                request_id: frame.request_id,
                status,
                headers,
                body,
            };

            let max_body = self.config.max_bytes.unwrap_or(u64::MAX);
            if let Err(e) = response.write_to(stream, max_body) {
                eprintln!("Error writing response frame: {e}");
                return ServerExit::Normal;
            }

            // 6. Record usage and log event
            self.limits.record_request();
            self.limits.record_bytes(response_bytes);

            let status_str = status.to_string();
            let _ = self.log.log_event(&LogEventParams {
                elapsed_ms,
                request_id: frame.request_id,
                method: method_str,
                authority: &frame.authority,
                path_and_query: &frame.path_and_query,
                range: frame.range,
                status: &status_str,
                bytes: response_bytes,
            });
        }
    }
}
