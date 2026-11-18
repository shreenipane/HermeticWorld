//! One connection per fixed-shape request. Nonblocking connect, writes and reads
//! share one monotonic deadline, including slow-drip responses.
use crate::{remaining, ApiRequest, Error, Result};
use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub const MAX_HEADER_BYTES: usize = 8192;
pub const MAX_RESPONSE_BYTES: usize = 65536;
pub const MAX_REQUEST_BYTES: usize = 16384;
pub const IO_RETRY: Duration = Duration::from_millis(2);
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}
fn retry(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}
fn wait(end: Instant) -> Result<()> {
    let left = remaining(end, "api")?;
    std::thread::sleep(left.min(IO_RETRY));
    Ok(())
}
pub fn connect(path: &str, end: Instant) -> Result<UnixStream> {
    remaining(end, "api-connect")?;
    let fd = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    let address = SocketAddrUnix::new(path)?;
    match net::connect(&fd, &address) {
        Ok(()) => (),
        Err(e) if e == rustix::io::Errno::INPROGRESS || e == rustix::io::Errno::AGAIN => {
            let mut poll = [rustix::event::PollFd::new(
                &fd,
                rustix::event::PollFlags::OUT,
            )];
            loop {
                let d = remaining(end, "api-connect")?;
                let timeout = rustix::event::Timespec {
                    tv_sec: d.as_secs().try_into().map_err(|_| Error::Io)?,
                    tv_nsec: i64::from(d.subsec_nanos()),
                };
                match rustix::event::poll(&mut poll, Some(&timeout)) {
                    Ok(0) => return Err(Error::Deadline("api-connect")),
                    Ok(_) => break,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            net::sockopt::socket_error(&fd)?.map_err(Error::from)?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(UnixStream::from(fd))
}
pub fn write_deadline(stream: &mut UnixStream, mut bytes: &[u8], end: Instant) -> Result<()> {
    stream.set_nonblocking(true)?;
    while !bytes.is_empty() {
        remaining(end, "api-write")?;
        match rustix::io::write(&*stream, bytes).map_err(std::io::Error::from) {
            Ok(0) => return Err(Error::Protocol),
            Ok(n) => bytes = bytes.get(n..).ok_or(Error::Protocol)?,
            Err(e) if retry(&e) => wait(end)?,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
pub fn read_exact_deadline(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    end: Instant,
) -> Result<()> {
    stream.set_nonblocking(true)?;
    while !bytes.is_empty() {
        remaining(end, "api-read")?;
        match rustix::io::read(&*stream, &mut *bytes).map_err(std::io::Error::from) {
            Ok(0) => return Err(Error::Protocol),
            Ok(n) => bytes = bytes.get_mut(n..).ok_or(Error::Protocol)?,
            Err(e) if retry(&e) => wait(end)?,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
struct CappedWriter(Vec<u8>);
impl Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > MAX_REQUEST_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("request cap"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn fields(body: &serde_json::Value, names: &[&str]) -> bool {
    body.as_object().is_some_and(|map| {
        map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))
    })
}
fn valid_body(req: &ApiRequest) -> bool {
    use crate::spec::{absolute_path, MAX_MEMORY_MIB, MAX_VCPUS};
    let b = &req.body;
    let path = |key: &str| {
        b.get(key)
            .and_then(|v| v.as_str())
            .is_some_and(absolute_path)
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("PUT", "/entropy") => fields(b, &[]),
        ("PUT", "/cpu-config") => b.is_object() && *b == crate::plan::cpu_template(),
        ("PUT", "/machine-config") => {
            fields(b, &["vcpu_count", "mem_size_mib", "smt"])
                && b.get("smt").and_then(|v| v.as_bool()) == Some(false)
                && b.get("vcpu_count")
                    .and_then(|v| v.as_u64())
                    .is_some_and(|v| (1..=u64::from(MAX_VCPUS)).contains(&v))
                && b.get("mem_size_mib")
                    .and_then(|v| v.as_u64())
                    .is_some_and(|v| (64..=u64::from(MAX_MEMORY_MIB)).contains(&v))
        }
        ("PUT", "/boot-source") => {
            (fields(b, &["kernel_image_path", "boot_args"])
                || (fields(b, &["kernel_image_path", "boot_args", "initrd_path"])
                    && path("initrd_path")))
                && path("kernel_image_path")
                && b.get("boot_args")
                    .and_then(|v| v.as_str())
                    .is_some_and(crate::plan::valid_calibrated_boot_args)
        }
        ("PUT", "/vsock") => {
            fields(b, &["guest_cid", "uds_path"])
                && path("uds_path")
                && b.get("guest_cid")
                    .and_then(|v| v.as_u64())
                    .is_some_and(|v| (3..=u64::from(u32::MAX)).contains(&v))
        }
        ("PUT", "/actions") => {
            fields(b, &["action_type"])
                && matches!(
                    b.get("action_type").and_then(|v| v.as_str()),
                    Some("InstanceStart" | "SendCtrlAltDel")
                )
        }
        ("PATCH", "/vm") => {
            fields(b, &["state"])
                && matches!(
                    b.get("state").and_then(|v| v.as_str()),
                    Some("Paused" | "Resumed")
                )
        }
        (method, p) if p.starts_with("/drives/") => {
            let names: &[&str] = if method == "PUT" {
                &["drive_id", "path_on_host", "is_root_device", "is_read_only"]
            } else {
                &["drive_id", "path_on_host"]
            };
            fields(b, names)
                && path("path_on_host")
                && b.get("drive_id").and_then(|v| v.as_str()) == p.strip_prefix("/drives/")
                && (method != "PUT"
                    || (b.get("is_root_device").is_some_and(|v| v.is_boolean())
                        && b.get("is_read_only").is_some_and(|v| v.is_boolean())))
        }
        ("PUT", p) if p.starts_with("/network-interfaces/") => {
            fields(b, &["iface_id", "host_dev_name", "guest_mac"])
                && b.get("iface_id").and_then(|v| v.as_str())
                    == p.strip_prefix("/network-interfaces/")
                && b.get("host_dev_name")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| crate::spec::identifier(v, 15))
                && b.get("guest_mac")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| {
                        v.len() == 17
                            && v.split(':').count() == 6
                            && v.split(':').all(|part| {
                                part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                    })
        }
        _ => false,
    }
}
fn request_bytes(req: &ApiRequest) -> Result<Vec<u8>> {
    let path_ok = match req.method.as_str() {
        "GET" => req.path == "/" && req.body == serde_json::json!({}),
        "PUT" => {
            matches!(
                req.path.as_str(),
                "/machine-config"
                    | "/cpu-config"
                    | "/boot-source"
                    | "/vsock"
                    | "/entropy"
                    | "/actions"
            ) || req
                .path
                .strip_prefix("/drives/")
                .is_some_and(crate::spec::drive_id)
                || req
                    .path
                    .strip_prefix("/network-interfaces/")
                    .is_some_and(|s| crate::spec::identifier(s, 32))
        }
        "PATCH" => {
            req.path == "/vm"
                || req
                    .path
                    .strip_prefix("/drives/")
                    .is_some_and(crate::spec::drive_id)
        }
        _ => false,
    };
    if !path_ok {
        return Err(Error::Validation("API request shape"));
    }
    let body = if req.method == "GET" {
        Vec::new()
    } else {
        let mut writer = CappedWriter(Vec::new());
        serde_json::to_writer(&mut writer, &req.body)
            .map_err(|_| Error::Validation("API request size cap"))?;
        writer.0
    };
    if body.len() > MAX_REQUEST_BYTES {
        return Err(Error::Validation("API request size cap"));
    }
    if !valid_body(req) {
        return Err(Error::Validation("API request body shape"));
    }
    let mut data = format!(
        concat!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n",
            "Content-Length: {}\r\nConnection: close\r\n\r\n"
        ),
        req.method,
        req.path,
        body.len(),
    )
    .into_bytes();
    data.extend(body);
    Ok(data)
}
pub fn call(path: &str, req: &ApiRequest, end: Instant) -> Result<Response> {
    // Validate before even opening a socket.
    let bytes = request_bytes(req)?;
    let stream = connect(path, end)?;
    exchange(stream, &bytes, end)
}
/// Connected-stream entry point for a socketpair fake server and embedders
/// that already hold a trusted Firecracker API connection.
pub fn call_stream(stream: UnixStream, req: &ApiRequest, end: Instant) -> Result<Response> {
    let bytes = request_bytes(req)?;
    exchange(stream, &bytes, end)
}
fn exchange(mut stream: UnixStream, bytes: &[u8], end: Instant) -> Result<Response> {
    write_deadline(&mut stream, bytes, end)?;
    let response = read_response(&mut stream, end)?;
    if !(200..300).contains(&response.status) {
        return Err(Error::Api(response.status));
    }
    Ok(response)
}
pub fn read_response(stream: &mut UnixStream, end: Instant) -> Result<Response> {
    let mut header = Vec::new();
    loop {
        if header.len() >= MAX_HEADER_BYTES {
            return Err(Error::Protocol);
        }
        let mut b = [0];
        read_exact_deadline(stream, &mut b, end)?;
        header.push(b[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&header).map_err(|_| Error::Protocol)?;
    if !text
        .bytes()
        .all(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\r' | b'\n' | b'\t'))
    {
        return Err(Error::Protocol);
    }
    let mut lines = text.split("\r\n");
    let mut status_line = lines.next().ok_or(Error::Protocol)?.splitn(3, ' ');
    if status_line.next() != Some("HTTP/1.1") {
        return Err(Error::Protocol);
    }
    let code = status_line.next().ok_or(Error::Protocol)?;
    let reason = status_line.next().ok_or(Error::Protocol)?;
    if code.len() != 3
        || !code.bytes().all(|b| b.is_ascii_digit())
        || !reason.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
    {
        return Err(Error::Protocol);
    }
    let status = code.parse::<u16>().map_err(|_| Error::Protocol)?;
    if !(200..600).contains(&status) {
        return Err(Error::Protocol);
    }
    let mut length = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(Error::Protocol)?;
        if !value
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t')
        {
            return Err(Error::Protocol);
        }
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(Error::Protocol);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Error::Protocol);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim_matches([' ', '\t']);
            if length.is_some()
                || value.is_empty()
                || value.len() > 10
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(Error::Protocol);
            }
            let n = value.parse::<usize>().map_err(|_| Error::Protocol)?;
            if n > MAX_RESPONSE_BYTES {
                return Err(Error::Protocol);
            }
            length = Some(n);
        }
    }
    let length = match length {
        Some(n) => n,
        None if status == 204 => 0,
        None => return Err(Error::Protocol),
    };
    if status == 204 && length != 0 {
        return Err(Error::Protocol);
    }
    let mut body = vec![0; length];
    read_exact_deadline(stream, &mut body, end)?;
    Ok(Response { status, body })
}
