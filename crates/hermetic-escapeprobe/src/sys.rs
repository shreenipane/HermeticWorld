//! Thin system-call layer. Every function returns only an outcome and an errno;
//! no received bytes leave this module except bounded DNS replies, which are
//! classified by header and never printed.

use std::fs::OpenOptions;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

use crate::classify::Attempt;

fn errno_of(e: &io::Error) -> Attempt {
    match e.raw_os_error() {
        Some(code) => Attempt::Errno(code),
        None if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock => {
            Attempt::Timeout
        }
        None => Attempt::Errno(libc::EIO),
    }
}

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

pub fn tcp_connect(addr: SocketAddr, timeout: Duration) -> Attempt {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Attempt::Reached,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Attempt::Timeout,
        Err(e) => errno_of(&e),
    }
}

/// Send one datagram on a connected UDP socket and wait for one reply.
/// Ok(Some(reply)) is at most `max` bytes; Ok(None) is a timeout.
pub fn udp_exchange(
    dst: SocketAddr,
    payload: &[u8],
    timeout: Duration,
    max: usize,
) -> Result<Option<Vec<u8>>, i32> {
    let bind: SocketAddr = if dst.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let map = |e: io::Error| e.raw_os_error().unwrap_or(libc::EIO);
    let sock = UdpSocket::bind(bind).map_err(map)?;
    sock.connect(dst).map_err(map)?;
    sock.set_read_timeout(Some(timeout)).map_err(map)?;
    sock.send(payload).map_err(map)?;
    let mut buf = vec![0u8; max + 1];
    match sock.recv(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            Ok(Some(buf))
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(map(e)),
    }
}

fn socket(domain: i32, ty: i32, proto: i32) -> Result<OwnedFd, i32> {
    // SAFETY: socket takes scalar arguments and returns a new descriptor or -1.
    let raw = unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, proto) };
    if raw < 0 {
        return Err(last_errno());
    }
    // SAFETY: raw is a fresh descriptor owned exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn poll_one(fd: &OwnedFd, events: i16, deadline: Instant) -> Result<bool, i32> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let ms = (deadline - now).as_millis().clamp(1, 60_000) as i32;
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: pfd is a valid pollfd array of length 1.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let e = last_errno();
            if e == libc::EINTR {
                continue;
            }
            return Err(e);
        }
        if rc > 0 {
            return Ok(true);
        }
    }
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMP echo to `dst`: datagram ping socket first, raw socket as fallback.
/// Only an echo reply counts as reached; other traffic is ignored.
pub fn icmp_echo(dst: Ipv4Addr, timeout: Duration) -> Attempt {
    let (fd, raw) = match socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) {
        Ok(fd) => (fd, false),
        Err(_) => match socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) {
            Ok(fd) => (fd, true),
            Err(e) => return Attempt::Errno(e),
        },
    };
    let mut pkt = [0u8; 16];
    pkt[0] = 8; // echo request
    pkt[4..6].copy_from_slice(&0x4857u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&1u16.to_be_bytes());
    let sum = icmp_checksum(&pkt);
    pkt[2..4].copy_from_slice(&sum.to_be_bytes());
    // SAFETY: zeroed sockaddr_in is valid; fields set below.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as _;
    sa.sin_addr.s_addr = u32::from(dst).to_be();
    // SAFETY: pkt and sa are valid for the given lengths.
    let rc = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            pkt.as_ptr().cast(),
            pkt.len(),
            0,
            (&sa as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&sa) as _,
        )
    };
    if rc < 0 {
        return Attempt::Errno(last_errno());
    }
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        match poll_one(&fd, libc::POLLIN, deadline) {
            Ok(false) => return Attempt::Timeout,
            Err(e) => return Attempt::Errno(e),
            Ok(true) => {}
        }
        // SAFETY: buf is valid for writes of its length.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let e = last_errno();
            if e == libc::EAGAIN || e == libc::EINTR {
                continue;
            }
            return Attempt::Errno(e);
        }
        if is_echo_reply(&buf[..n as usize], raw) {
            return Attempt::Reached;
        }
    }
}

/// True if `packet` is an ICMP echo reply (raw sockets include the IP header).
pub fn is_echo_reply(packet: &[u8], raw: bool) -> bool {
    let icmp = if raw {
        let Some(&first) = packet.first() else {
            return false;
        };
        let ihl = usize::from(first & 0x0f) * 4;
        if first >> 4 != 4 || ihl < 20 {
            return false;
        }
        match packet.get(ihl..) {
            Some(rest) => rest,
            None => return false,
        }
    } else {
        packet
    };
    icmp.len() >= 8 && icmp[0] == 0
}

/// Guest-initiated AF_VSOCK stream connect.
pub fn vsock_connect(cid: u32, port: u32, timeout: Duration) -> Attempt {
    let fd = match socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) {
        Ok(fd) => fd,
        Err(e) => return Attempt::Errno(e),
    };
    // SAFETY: zeroed sockaddr_vm is a valid initial representation.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_cid = cid;
    addr.svm_port = port;
    // SAFETY: addr is initialized and its exact size is supplied.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of_val(&addr) as _,
        )
    };
    if rc == 0 {
        return Attempt::Reached;
    }
    let e = last_errno();
    if e != libc::EINPROGRESS {
        return Attempt::Errno(e);
    }
    match poll_one(&fd, libc::POLLOUT, Instant::now() + timeout) {
        Ok(false) => return Attempt::Timeout,
        Err(e) => return Attempt::Errno(e),
        Ok(true) => {}
    }
    let mut err: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: err and len are valid out-pointers of the right size.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut err as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Attempt::Errno(last_errno());
    }
    if err == 0 {
        Attempt::Reached
    } else {
        Attempt::Errno(err)
    }
}

/// Open a device node read-only without following symlinks and without
/// becoming its controlling terminal. The descriptor is closed at once.
pub fn open_device(path: &str) -> Result<(), i32> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map(|_| ())
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

/// Read a regular file (procfs files report size 0) without following
/// symlinks, at most `max + 1` bytes so the caller can detect oversize.
pub fn read_bounded(path: &str, max: usize) -> Result<Vec<u8>, i32> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    let meta = file
        .metadata()
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    if !meta.is_file() {
        return Err(libc::EINVAL);
    }
    let mut out = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    Ok(out)
}

/// `init_module` with an empty image and empty parameters.
pub fn init_module_empty() -> Result<(), i32> {
    let image = [0u8; 1];
    let params = [0u8; 1];
    // SAFETY: image is valid for 0 bytes, params is a NUL-terminated string.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_init_module,
            image.as_ptr(),
            0usize,
            params.as_ptr(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_errno())
    }
}

pub fn getrandom_nonblock(buf: &mut [u8]) -> Result<usize, i32> {
    // SAFETY: buf is valid for writes of its length.
    let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), libc::GRND_NONBLOCK) };
    if n < 0 {
        Err(last_errno())
    } else {
        Ok(n as usize)
    }
}
