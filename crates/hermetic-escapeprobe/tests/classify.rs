use hermetic_escapeprobe::classify::*;
use hermetic_escapeprobe::probes::*;
use hermetic_escapeprobe::sys::is_echo_reply;

#[test]
fn attempt_reached_is_leak_timeout_and_refusals_blocked_other_error() {
    assert_eq!(classify_attempt(Attempt::Reached).0, EscapeResult::Leak);
    assert_eq!(classify_attempt(Attempt::Timeout).0, EscapeResult::Blocked);
    for e in [
        libc::ENETUNREACH,
        libc::EHOSTUNREACH,
        libc::ENETDOWN,
        libc::ECONNREFUSED,
        libc::ECONNRESET,
        libc::ETIMEDOUT,
        libc::EACCES,
        libc::EPERM,
        libc::EAFNOSUPPORT,
        libc::EPROTONOSUPPORT,
        libc::ESOCKTNOSUPPORT,
        libc::EADDRNOTAVAIL,
        libc::ENODEV,
        libc::ENOPROTOOPT,
    ] {
        assert_eq!(
            classify_attempt(Attempt::Errno(e)).0,
            EscapeResult::Blocked,
            "{e}"
        );
    }
    for e in [
        libc::EIO,
        libc::EINVAL,
        libc::EMFILE,
        libc::EBADF,
        0,
        -1,
        i32::MAX,
    ] {
        assert_eq!(
            classify_attempt(Attempt::Errno(e)).0,
            EscapeResult::Error,
            "{e}"
        );
    }
}

#[test]
fn device_open_success_leaks_absence_blocks_symlink_errors() {
    assert_eq!(classify_device_open(Ok(())).0, EscapeResult::Leak);
    for e in [
        libc::ENOENT,
        libc::ENXIO,
        libc::ENODEV,
        libc::EACCES,
        libc::EPERM,
    ] {
        assert_eq!(classify_device_open(Err(e)).0, EscapeResult::Blocked);
    }
    assert_eq!(
        classify_device_open(Err(libc::ELOOP)).0,
        EscapeResult::Error
    );
    assert_eq!(classify_device_open(Err(libc::EIO)).0, EscapeResult::Error);
}

#[test]
fn module_load_only_enosys_or_eperm_is_blocked() {
    assert_eq!(
        classify_module_load(Err(libc::ENOSYS)).0,
        EscapeResult::Blocked
    );
    assert_eq!(
        classify_module_load(Err(libc::EPERM)).0,
        EscapeResult::Blocked
    );
    for e in [
        libc::ENOEXEC,
        libc::EINVAL,
        libc::EFAULT,
        libc::ENOMEM,
        libc::EBADMSG,
    ] {
        assert_eq!(classify_module_load(Err(e)).0, EscapeResult::Leak);
    }
    assert_eq!(classify_module_load(Ok(())).0, EscapeResult::Leak);
    assert_eq!(classify_module_load(Err(libc::EIO)).0, EscapeResult::Error);
}

#[test]
fn getrandom_positive_check() {
    assert_eq!(classify_getrandom(Ok(32), 32).0, EscapeResult::Ok);
    assert_eq!(classify_getrandom(Ok(31), 32).0, EscapeResult::Error);
    assert_eq!(classify_getrandom(Ok(0), 0).0, EscapeResult::Error);
    assert_eq!(
        classify_getrandom(Err(libc::EAGAIN), 32).0,
        EscapeResult::Error
    );
    assert_eq!(
        classify_getrandom(Err(libc::ENOSYS), 32).0,
        EscapeResult::Error
    );
    assert_eq!(
        classify_getrandom(Err(libc::EFAULT), 32).0,
        EscapeResult::Error
    );
}

const ROOT: &str = "22 1 254:0 / / ro,relatime shared:1 - ext4 /dev/vda ro\n";

#[test]
fn mountinfo_host_shares_leak_clean_blocks_hostile_errors() {
    assert_eq!(classify_mountinfo(ROOT.as_bytes()).0, EscapeResult::Blocked);
    for fs in HOST_SHARE_FSTYPES {
        let t = format!("{ROOT}30 22 0:40 / /mnt rw - {fs} hostshare rw\n");
        assert_eq!(
            classify_mountinfo(t.as_bytes()).0,
            EscapeResult::Leak,
            "{fs}"
        );
    }
    // A mount point literally named "9p" is not a 9p mount.
    let t = format!("{ROOT}31 22 0:41 / /9p rw - tmpfs 9p rw\n");
    assert_eq!(classify_mountinfo(t.as_bytes()).0, EscapeResult::Blocked);
    assert_eq!(classify_mountinfo(b"").0, EscapeResult::Error);
    assert_eq!(classify_mountinfo(b"\xff\xfe").0, EscapeResult::Error);
    assert_eq!(classify_mountinfo(b"garbage line\n").0, EscapeResult::Error);
    assert_eq!(
        classify_mountinfo(b"1 2 3 4 5 6 - \n").0,
        EscapeResult::Error
    );
    assert_eq!(
        classify_mountinfo(b"1 2 - ext4 a b\n").0,
        EscapeResult::Error
    );
    assert_eq!(
        classify_mountinfo(b"1 2 3 4 5 6 - a - b\n").0,
        EscapeResult::Error
    );
    let big = vec![b'a'; MAX_MOUNTINFO_BYTES + 1];
    assert_eq!(classify_mountinfo(&big).0, EscapeResult::Error);
    let many = ROOT.repeat(MAX_MOUNT_LINES + 1);
    assert_eq!(classify_mountinfo(many.as_bytes()).0, EscapeResult::Error);
}

#[test]
fn json_line_shape_and_unsafe_names_never_echoed() {
    let r = EscapeRecord::new("ip.tcp.x", EscapeResult::Blocked, "kernel refused");
    assert_eq!(
        r.to_json_line(),
        r#"{"probe":"ip.tcp.x","result":"blocked","detail":"kernel refused"}"#
    );
    let bad = EscapeRecord::new("a\"b\nhost", EscapeResult::Leak, "x");
    let line = bad.to_json_line();
    assert!(line.contains("invalid_probe_name") && !line.contains("host"));
    let bad = EscapeRecord::new("ok", EscapeResult::Ok, "Upper\"");
    assert!(bad.to_json_line().contains("invalid detail"));
    assert!(!is_safe_token(&"a".repeat(MAX_TOKEN_BYTES + 1)));
    assert!(!is_safe_token(""));
}

#[test]
fn exit_code_leak_beats_error_beats_ok() {
    let b = EscapeRecord::new("a", EscapeResult::Blocked, "x");
    let e = EscapeRecord::new("b", EscapeResult::Error, "x");
    let l = EscapeRecord::new("c", EscapeResult::Leak, "x");
    let u = EscapeRecord::new("d", EscapeResult::Unavailable, "x");
    let o = EscapeRecord::new("e", EscapeResult::Ok, "x");
    assert_eq!(exit_code(&[b.clone(), u, o]), 0);
    assert_eq!(exit_code(&[b.clone(), e.clone()]), 1);
    assert_eq!(exit_code(&[e, l, b]), 2);
}

#[test]
fn vsock_scan_any_reach_leaks_unexpected_errors_empty_errors() {
    let refused = vec![Attempt::Errno(libc::ECONNRESET); 10];
    assert_eq!(classify_scan(&refused).0, EscapeResult::Blocked);
    let mut leak = refused.clone();
    leak.push(Attempt::Reached);
    assert_eq!(classify_scan(&leak).0, EscapeResult::Leak);
    let mut err = refused.clone();
    err.push(Attempt::Errno(libc::EIO));
    assert_eq!(classify_scan(&err).0, EscapeResult::Error);
    err.push(Attempt::Reached);
    assert_eq!(classify_scan(&err).0, EscapeResult::Leak);
    assert_eq!(classify_scan(&[]).0, EscapeResult::Error);
    assert_eq!(classify_scan(&[Attempt::Timeout]).0, EscapeResult::Blocked);
}

#[test]
fn datagram_reply_leaks_silence_blocks() {
    assert_eq!(classify_datagram(Ok(Some(vec![1]))).0, EscapeResult::Leak);
    assert_eq!(classify_datagram(Ok(Some(vec![]))).0, EscapeResult::Leak);
    assert_eq!(classify_datagram(Ok(None)).0, EscapeResult::Blocked);
    assert_eq!(
        classify_datagram(Err(libc::ENETUNREACH)).0,
        EscapeResult::Blocked
    );
    assert_eq!(classify_datagram(Err(libc::EIO)).0, EscapeResult::Error);
    let q = quic_initial();
    assert_eq!(q.len(), 1200);
    assert_eq!(q[0] & 0xc0, 0xc0);
}

#[test]
fn resolv_conf_parsing_is_bounded_and_fail_closed() {
    let t = b"# c\nsearch x\nnameserver 10.0.0.1\nnameserver ::1\nnameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\nnameserver 10.0.0.4\n";
    let v = parse_resolv_conf(t).unwrap();
    assert_eq!(v.len(), MAX_RESOLVERS);
    assert_eq!(v[0].to_string(), "10.0.0.1");
    assert_eq!(v[1].to_string(), "10.0.0.2");
    assert!(parse_resolv_conf(b"").unwrap().is_empty());
    assert!(parse_resolv_conf(b"nameserver\n").is_none());
    assert!(parse_resolv_conf(b"nameserver evil.example\n").is_none());
    assert!(parse_resolv_conf(b"\xff").is_none());
    assert!(parse_resolv_conf(&vec![b' '; MAX_RESOLV_BYTES + 1]).is_none());
}

#[test]
fn echo_reply_detection_dgram_and_raw() {
    assert!(is_echo_reply(&[0, 0, 0, 0, 0, 0, 0, 1], false));
    assert!(!is_echo_reply(&[8, 0, 0, 0, 0, 0, 0, 1], false));
    assert!(!is_echo_reply(&[0, 0, 0], false));
    let mut raw = vec![0x45u8];
    raw.extend_from_slice(&[0; 19]);
    raw.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(is_echo_reply(&raw, true));
    raw[20] = 3; // destination unreachable
    assert!(!is_echo_reply(&raw, true));
    assert!(!is_echo_reply(&[0x4f], true));
    assert!(!is_echo_reply(&[0x41, 0, 0], true));
    assert!(!is_echo_reply(&[0x65; 28], true));
    assert!(!is_echo_reply(&[], true));
}

#[test]
fn expected_names_unique_safe_and_cover_spec_list() {
    let names = expected_probe_names();
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
    assert!(names.iter().all(|n| is_safe_token(n)));
    for prefix in [
        "dns.resolver0.",
        "dns.resolver0.com_ns",
        "dns.public.",
        "ip.tcp.",
        "icmp.echo.",
        "ipv6.tcp.",
        "ipv6.udp.",
        "quic.udp443.",
        "vsock.cid2.scan",
        "device.msr",
        "hostfs.mounts",
        "kernel.module_load",
        "gateway.model_call_date",
        "gateway.quota",
        "positive.getrandom_nonblock",
        "positive.pip_install",
        "positive.git_clone",
        "positive.curl_get",
    ] {
        assert!(names.iter().any(|n| n.starts_with(prefix)), "{prefix}");
    }
}

#[test]
fn vsock_scan_preserves_ports_excludes_control_and_fits_exec_budget() {
    let ports: Vec<_> = vsock_ports().collect();
    assert!(!ports.contains(&5000));
    assert_eq!(&ports[..1024], &(1..=1024).collect::<Vec<_>>());
    assert_eq!(ports.len(), 1024 + VSOCK_EXTRA_PORTS.len() - 1);
    let network_attempts = MAX_RESOLVERS * (REAL_NAMES.len() + DELEGATION.len())
        + PUBLIC_RESOLVERS.len()
        + RAW_TCP.len()
        + ICMP.len()
        + IPV6_TCP.len()
        + 1
        + QUIC.len();
    let worst = CONNECT_TIMEOUT * network_attempts as u32
        + VSOCK_TIMEOUT * (ports.len() * VSOCK_CIDS.len()) as u32;
    assert!(worst < MAX_PROBE_RUNTIME);
    assert!(MAX_PROBE_RUNTIME < std::time::Duration::from_secs(200));
    let start = std::time::Instant::now();
    for cid in VSOCK_CIDS {
        let mut seen = Vec::new();
        let result = scan_vsock(
            *cid,
            start + MAX_PROBE_RUNTIME,
            || start,
            |c, p, t| {
                assert_eq!(c, *cid);
                assert_eq!(t, VSOCK_TIMEOUT);
                seen.push(p);
                Attempt::Timeout
            },
        );
        assert_eq!(seen, ports);
        assert_eq!(result.0, EscapeResult::Blocked);
    }
}

#[test]
fn vsock_runtime_exhaustion_is_error_and_never_extends_deadline() {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let end = start + Duration::from_millis(1);
    let now = std::cell::Cell::new(start);
    let mut calls = 0;
    let result = scan_vsock(
        2,
        end,
        || now.get(),
        |_, _, timeout| {
            assert_eq!(timeout, Duration::from_millis(1));
            now.set(end);
            calls += 1;
            Attempt::Timeout
        },
    );
    assert_eq!(calls, 1);
    assert_eq!(result.0, EscapeResult::Error);
    assert_eq!(
        scan_vsock(2, end, || end, |_, _, _| panic!("expired scan connected")).0,
        EscapeResult::Error
    );
}
