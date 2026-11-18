#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use hermetic_escapeprobe::classify::EscapeResult;
use hermetic_escapeprobe::config::InstallConfig;
use hermetic_escapeprobe::install::*;

#[test]
fn test_classify_install_probes() {
    // pip_install
    assert_eq!(classify_pip_install(Ok(true)).0, EscapeResult::Ok);
    assert_eq!(classify_pip_install(Ok(false)).0, EscapeResult::Error);
    assert_eq!(
        classify_pip_install(Err("unavailable")).0,
        EscapeResult::Unavailable
    );

    // git_clone
    assert_eq!(classify_git_clone(Ok(true)).0, EscapeResult::Ok);
    assert_eq!(classify_git_clone(Ok(false)).0, EscapeResult::Error);
    assert_eq!(
        classify_git_clone(Err("unavailable")).0,
        EscapeResult::Unavailable
    );

    // curl_get
    assert_eq!(classify_curl_get(Ok(true)).0, EscapeResult::Ok);
    assert_eq!(classify_curl_get(Ok(false)).0, EscapeResult::Error);
    assert_eq!(
        classify_curl_get(Err("unavailable")).0,
        EscapeResult::Unavailable
    );
}

#[test]
fn test_unconfigured_install_probes_return_unavailable() {
    let recs = run_install_probes(None);
    assert_eq!(recs.len(), 3);
    for r in &recs {
        assert_eq!(r.result, EscapeResult::Unavailable);
        assert!(r.probe.starts_with("positive."));
    }
}

#[test]
fn test_mock_http_install_positive_checks_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
            stream.write_all(resp).unwrap();
        }
    });

    let config = InstallConfig {
        pip_target: Some(format!("http://127.0.0.1:{port}/pkg.whl")),
        pip_command: None,
        git_target: Some(format!("http://127.0.0.1:{port}/repo.git")),
        git_command: None,
        curl_url: Some(format!("http://127.0.0.1:{port}/hello.txt")),
        curl_command: None,
    };

    let recs = run_install_probes(Some(&config));
    server_thread.join().unwrap();

    assert_eq!(recs.len(), 3);
    for r in &recs {
        assert_eq!(
            r.result,
            EscapeResult::Ok,
            "probe {} failed: {}",
            r.probe,
            r.detail
        );
    }
}

#[test]
fn test_mock_http_install_positive_checks_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(resp).unwrap();
        }
    });

    let config = InstallConfig {
        pip_target: Some(format!("http://127.0.0.1:{port}/pkg.whl")),
        pip_command: None,
        git_target: Some(format!("http://127.0.0.1:{port}/repo.git")),
        git_command: None,
        curl_url: Some(format!("http://127.0.0.1:{port}/hello.txt")),
        curl_command: None,
    };

    let recs = run_install_probes(Some(&config));
    server_thread.join().unwrap();

    assert_eq!(recs.len(), 3);
    for r in &recs {
        assert_eq!(r.result, EscapeResult::Error);
    }
}

#[test]
fn test_command_install_positive_checks() {
    let config = InstallConfig {
        pip_target: None,
        pip_command: Some(vec!["echo".to_string(), "pip-ok".to_string()]),
        git_target: None,
        git_command: Some(vec!["echo".to_string(), "git-ok".to_string()]),
        curl_url: None,
        curl_command: Some(vec!["echo".to_string(), "curl-ok".to_string()]),
    };

    let recs = run_install_probes(Some(&config));
    assert_eq!(recs.len(), 3);
    for r in &recs {
        assert_eq!(r.result, EscapeResult::Ok);
    }
}

#[test]
fn test_regression_command_install_timeout_terminates_and_reaps() {
    let start = std::time::Instant::now();
    let res = check_pip_install(
        Some(&["sleep".to_string(), "10".to_string()]),
        None,
        std::time::Duration::from_millis(100),
    );
    let elapsed = start.elapsed();
    assert_eq!(res, Err("command timed out"));
    assert!(elapsed < std::time::Duration::from_secs(2));
}
