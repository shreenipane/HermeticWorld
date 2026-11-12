#![allow(unsafe_code)]
//! Thin wrappers for interfaces not exposed as safe rustix operations.
use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

fn checked(ret: libc::c_int) -> io::Result<()> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Duplicate a raw descriptor inherited across helper exec and mark the original
/// close-on-exec too. rustix requires an already owned/borrowed descriptor; this
/// boundary instead accepts a numeric descriptor from the bounded helper payload.
pub fn inherited(raw: i32) -> io::Result<std::fs::File> {
    if raw < 3 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: fcntl validates the scalar descriptor; no pointers are passed.
    let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    checked(duplicate)?;
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh descriptor, owned exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(duplicate) };
    // SAFETY: scalar descriptor/flag arguments; original ownership is unchanged.
    checked(unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    Ok(fd.into())
}

/// Bind AF_VSOCK and accept only the host CID (2) on accepted connections.
pub fn vsock(port: u32) -> io::Result<OwnedFd> {
    // SAFETY: socket takes scalar values and returns an owned descriptor.
    let raw = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    checked(raw)?;
    // SAFETY: raw is a fresh, valid descriptor, transferred exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: all-zero sockaddr_vm is a valid initial representation.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    addr.svm_port = port;
    // SAFETY: addr is initialized and its exact size is supplied.
    checked(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of_val(&addr) as _,
        )
    })?;
    Ok(fd)
}

/// AF_VSOCK peer address validation and accept with CLOEXEC.
pub fn accept(fd: &OwnedFd) -> io::Result<Option<OwnedFd>> {
    // SAFETY: initialized storage is large enough for sockaddr_vm.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    // SAFETY: the address and length pointers are writable for their sizes.
    let raw = unsafe {
        libc::accept4(
            fd.as_raw_fd(),
            (&mut addr as *mut libc::sockaddr_vm).cast(),
            &mut len,
            libc::SOCK_CLOEXEC,
        )
    };
    if raw < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
            Ok(None)
        } else {
            Err(e)
        };
    }
    // SAFETY: accept4 returned a fresh descriptor.
    let accepted = unsafe { OwnedFd::from_raw_fd(raw) };
    if len as usize != std::mem::size_of_val(&addr)
        || addr.svm_family as i32 != libc::AF_VSOCK
        || addr.svm_cid != libc::VMADDR_CID_HOST
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(Some(accepted))
}

/// Freeze through a retained descriptor, never a path lookup.
pub fn freeze(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: FIFREEZE takes an integer argument, not a pointer; fd is live.
    checked(unsafe { libc::ioctl(fd.as_raw_fd(), 0xc0045877 as libc::c_ulong, 0) })
}

/// Block PID 1 signals and return a nonblocking signalfd. rustix's signal
/// mask interfaces live in its unsafe runtime API.
pub fn signals() -> io::Result<OwnedFd> {
    // SAFETY: libc initializes the entire sigset before it is used.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: mask is writable and all signal numbers are valid constants.
    unsafe {
        checked(libc::sigemptyset(&mut mask))?;
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD] {
            checked(libc::sigaddset(&mut mask, sig))?;
        }
        checked(libc::sigprocmask(
            libc::SIG_BLOCK,
            &mask,
            std::ptr::null_mut(),
        ))?;
        let raw = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        checked(raw)?;
        Ok(OwnedFd::from_raw_fd(raw))
    }
}

/// Restore the child's empty signal mask before executing guest code.
pub fn clear_signal_mask() -> io::Result<()> {
    // SAFETY: initialized sigset passed by reference, no old mask requested.
    unsafe {
        let mut mask = std::mem::zeroed();
        checked(libc::sigemptyset(&mut mask))?;
        checked(libc::sigprocmask(
            libc::SIG_SETMASK,
            &mask,
            std::ptr::null_mut(),
        ))
    }
}

/// Clear supplementary groups. rustix doesn't provide a safe process-wide setter.
pub fn clear_groups() -> io::Result<()> {
    // SAFETY: a zero group count permits a null list pointer.
    checked(unsafe { libc::setgroups(0, std::ptr::null()) })
}
/// Set all group ids in the single-threaded child helper.
pub fn set_gid(gid: u32) -> io::Result<()> {
    // SAFETY: scalar ids, no memory access.
    checked(unsafe { libc::setresgid(gid, gid, gid) })
}
/// Set all user ids after supplementary groups and gid have been dropped.
pub fn set_uid(uid: u32) -> io::Result<()> {
    // SAFETY: scalar ids, no memory access.
    checked(unsafe { libc::setresuid(uid, uid, uid) })
}

/// Execute an already validated and pinned regular file. This also supports
/// scripts; the descriptor is deliberately inherited for the interpreter.
pub fn exec(fd: &std::fs::File, argv: &[CString], env: &[CString]) -> io::Result<()> {
    let mut args: Vec<_> = argv.iter().map(|s| s.as_ptr()).collect();
    let mut vars: Vec<_> = env.iter().map(|s| s.as_ptr()).collect();
    args.push(std::ptr::null());
    vars.push(std::ptr::null());
    // SAFETY: both arrays are null-terminated and all CString storage stays
    // alive for the syscall. fd is held throughout. Success never returns.
    checked(unsafe { libc::fexecve(fd.as_raw_fd(), args.as_ptr(), vars.as_ptr()) })
}

/// Signal every process except PID 1 and the caller, as defined by kill(-1).
pub fn kill_all(signal: i32) -> io::Result<()> {
    // SAFETY: kill takes only scalar values.
    let ret = unsafe { libc::kill(-1, signal) };
    if ret < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    checked(ret)
}
