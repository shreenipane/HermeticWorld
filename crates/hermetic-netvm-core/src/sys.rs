#![allow(unsafe_code)]
//! Small Linux ABI boundary. Policy, parsing and file traversal remain safe Rust.
use std::{
    ffi::{c_int, c_short, c_void},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::Instant,
};

// Linux UAPI: socket.h, un.h, vm_sockets.h, poll.h. No external crate required.
const SOCK_STREAM: c_int = 1;
const SOCK_CLOEXEC: c_int = 0x80000;
const SOCK_NONBLOCK: c_int = 0x800;
#[repr(C)]
struct UnixAddress {
    family: u16,
    path: [u8; 108],
}
#[repr(C)]
struct VsockAddress {
    family: u16,
    reserved: u16,
    port: u32,
    cid: u32,
    zero: [u8; 4],
}
#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}
unsafe extern "C" {
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn connect(fd: c_int, address: *const c_void, length: u32) -> c_int;
    fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, length: u32)
        -> c_int;
    fn getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        length: *mut u32,
    ) -> c_int;
}

pub(crate) fn ready(stream: &UnixStream, write: bool, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(io::ErrorKind::TimedOut)?;
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(c_int::MAX as u128) as c_int;
        let mut fd = PollFd {
            fd: stream.as_raw_fd(),
            events: if write { 4 } else { 1 },
            revents: 0,
        };
        // SAFETY: one live descriptor and initialized writable pollfd; bounded timeout.
        let result = unsafe { poll(&mut fd, 1, millis) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
fn connected(
    domain: c_int,
    address: *const c_void,
    length: u32,
    deadline: Instant,
) -> io::Result<UnixStream> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    // SAFETY: scalar Linux socket parameters. A successful descriptor is owned once.
    let raw = unsafe { socket(domain, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new descriptor. UnixStream's I/O and socket options
    // are family-independent; no Unix address methods are used for AF_VSOCK.
    let stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(raw) });
    // SAFETY: each private caller supplies a live repr(C) address and its exact size.
    let result = unsafe { connect(stream.as_raw_fd(), address, length) };
    if result < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(115) && e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
        ready(&stream, true, deadline)?;
        let mut error: c_int = 0;
        let mut size = std::mem::size_of_val(&error) as u32;
        // SAFETY: SO_ERROR writes a single integer; both pointers remain live.
        if unsafe {
            getsockopt(
                stream.as_raw_fd(),
                1,
                4,
                (&mut error as *mut c_int).cast(),
                &mut size,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
    }
    Ok(stream)
}
pub(crate) fn unix(path: &[u8], deadline: Instant) -> io::Result<UnixStream> {
    if path.is_empty() || path.contains(&0) || path.len() >= 108 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut addr = UnixAddress {
        family: 1,
        path: [0; 108],
    };
    for (dst, src) in addr.path.iter_mut().zip(path) {
        *dst = *src;
    }
    connected(
        1,
        (&addr as *const UnixAddress).cast(),
        std::mem::size_of_val(&addr) as u32,
        deadline,
    )
}
pub(crate) fn vsock(port: u32, deadline: Instant) -> io::Result<UnixStream> {
    let addr = VsockAddress {
        family: 40,
        reserved: 0,
        port,
        cid: 2,
        zero: [0; 4],
    };
    connected(
        40,
        (&addr as *const VsockAddress).cast(),
        std::mem::size_of_val(&addr) as u32,
        deadline,
    )
}

/// Install the bounded legacy IPv4 table in this VM's network namespace.
/// The byte offsets are the x86-64 Linux UAPI (the only supported guest target).
pub(crate) fn install_filter(table: &crate::firewall::Table) -> io::Result<()> {
    use crate::firewall::{MAX_OLD_RULES, REPLACE_HEADER_BYTES};
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(io::ErrorKind::Unsupported.into());
    }
    // SAFETY: scalar Linux parameters; the new raw IPv4 descriptor is owned once.
    let raw = unsafe { socket(2, 3 | SOCK_CLOEXEC, 255) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket created a fresh, live descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut info = [0u8; 84];
    info[..6].copy_from_slice(b"filter");
    let mut size = info.len() as u32;
    // SAFETY: IPT_SO_GET_INFO writes at most the initialized buffer's length.
    if unsafe { getsockopt(fd.as_raw_fd(), 0, 64, info.as_mut_ptr().cast(), &mut size) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = u32::from_ne_bytes(
        info[76..80]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?,
    );
    let hooks = u32::from_ne_bytes(
        info[32..36]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?,
    );
    if size != info.len() as u32 || hooks != 14 || count == 0 || count as usize > MAX_OLD_RULES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // The kernel copies old counters out through this pointer. Their number is
    // capped before allocating, and their contents are never exposed.
    let mut counters = vec![[0u64; 2]; count as usize];
    let mut replacement = vec![0u8; REPLACE_HEADER_BYTES];
    replacement[..6].copy_from_slice(b"filter");
    replacement[32..36].copy_from_slice(&hooks.to_ne_bytes());
    replacement[36..40].copy_from_slice(&table.count.to_ne_bytes());
    replacement[40..44].copy_from_slice(&(table.entries.len() as u32).to_ne_bytes());
    for (index, value) in table.hooks.iter().enumerate() {
        let offset = 44 + index * 4;
        replacement[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    for (index, value) in table.underflows.iter().enumerate() {
        let offset = 64 + index * 4;
        replacement[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    replacement[84..88].copy_from_slice(&count.to_ne_bytes());
    replacement[88..96].copy_from_slice(&(counters.as_mut_ptr() as u64).to_ne_bytes());
    replacement.extend_from_slice(&table.entries);
    // SAFETY: the fixed UAPI buffer and capped counter array remain live until
    // setsockopt returns; the kernel validates all rules before replacing the table.
    if unsafe {
        setsockopt(
            fd.as_raw_fd(),
            0,
            64,
            replacement.as_ptr().cast(),
            replacement.len() as u32,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
