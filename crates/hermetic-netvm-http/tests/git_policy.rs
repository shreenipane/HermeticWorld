#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use hermetic_netvm_http::{decide, parse_request_head, Decision, HttpError, Scheme};

fn allowed_hosts() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert("git.example.com".to_owned());
    s.insert("github.com".to_owned());
    s
}

#[test]
fn test_post_allowed_only_for_git_upload_pack() {
    let hosts = allowed_hosts();

    // 1. Valid POST to /repo.git/git-upload-pack
    let valid_post = b"POST /repo.git/git-upload-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Type: application/x-git-upload-pack-request\r\n\
Content-Length: 42\r\n\
Git-Protocol: version=2\r\n\
User-Agent: git/2.43.0\r\n\r\n";
    let head = parse_request_head(valid_post).unwrap();
    match decide(&head, &hosts, Scheme::Https) {
        Decision::Forward(req) => {
            assert_eq!(req.method, "POST");
            assert_eq!(req.host, "git.example.com");
            assert_eq!(req.path, "/repo.git/git-upload-pack");
            assert_eq!(
                req.headers,
                vec![
                    hermetic_netvm_http::policy::ForwardHeader {
                        name: "content-length".into(),
                        value: "42".into(),
                    },
                    hermetic_netvm_http::policy::ForwardHeader {
                        name: "content-type".into(),
                        value: "application/x-git-upload-pack-request".into(),
                    },
                    hermetic_netvm_http::policy::ForwardHeader {
                        name: "git-protocol".into(),
                        value: "version=2".into(),
                    },
                    hermetic_netvm_http::policy::ForwardHeader {
                        name: "user-agent".into(),
                        value: "hermetic-world/1".into(),
                    },
                ]
            );
        }
        other => panic!("expected Forward, got {other:?}"),
    }

    // 2. Valid POST to bare /git-upload-pack
    let bare_post = b"POST /git-upload-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Type: application/x-git-upload-pack-request\r\n\
Content-Length: 0\r\n\r\n";
    let head = parse_request_head(bare_post).unwrap();
    assert!(matches!(
        decide(&head, &hosts, Scheme::Https),
        Decision::Forward(_)
    ));

    // 3. POST to /git-receive-pack (push) -> 405 Method Not Allowed
    let receive_pack = b"POST /repo.git/git-receive-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Type: application/x-git-receive-pack-request\r\n\
Content-Length: 10\r\n\r\n";
    let head = parse_request_head(receive_pack).unwrap();
    assert_eq!(
        decide(&head, &hosts, Scheme::Https),
        Decision::MethodNotAllowed
    );

    // 4. POST to random endpoints -> 405 Method Not Allowed
    for bad_path in [
        "/",
        "/index.html",
        "/api/v1",
        "/repo.git",
        "/upload-pack",
        "/git-upload-pack/evil",
    ] {
        let req = format!(
            "POST {bad_path} HTTP/1.1\r\nHost: git.example.com\r\nContent-Length: 0\r\n\r\n"
        );
        let head = parse_request_head(req.as_bytes()).unwrap();
        assert_eq!(
            decide(&head, &hosts, Scheme::Https),
            Decision::MethodNotAllowed,
            "path {bad_path} should be MethodNotAllowed"
        );
    }

    // 5. Other HTTP methods to git-upload-pack -> 405 Method Not Allowed
    for method in ["PUT", "DELETE", "PATCH", "OPTIONS"] {
        let req = format!(
            "{method} /repo.git/git-upload-pack HTTP/1.1\r\nHost: git.example.com\r\nContent-Length: 0\r\n\r\n"
        );
        let head = parse_request_head(req.as_bytes()).unwrap();
        assert_eq!(
            decide(&head, &hosts, Scheme::Https),
            Decision::MethodNotAllowed,
            "method {method} should be MethodNotAllowed"
        );
    }
}

#[test]
fn test_post_git_upload_pack_content_type_validation() {
    let hosts = allowed_hosts();

    // Invalid content type rejected
    let bad_ct = b"POST /repo.git/git-upload-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Type: application/json\r\n\
Content-Length: 10\r\n\r\n";
    let head = parse_request_head(bad_ct).unwrap();
    assert_eq!(
        decide(&head, &hosts, Scheme::Https),
        Decision::Reject("invalid_content_type".to_owned())
    );

    // Another hostile content type rejected
    let bad_ct2 = b"POST /repo.git/git-upload-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Type: text/plain\r\n\
Content-Length: 10\r\n\r\n";
    let head = parse_request_head(bad_ct2).unwrap();
    assert_eq!(
        decide(&head, &hosts, Scheme::Https),
        Decision::Reject("invalid_content_type".to_owned())
    );
}

#[test]
fn test_post_git_host_and_scheme_checks() {
    let hosts = allowed_hosts();

    // Disallowed host rejected
    let bad_host = b"POST /repo.git/git-upload-pack HTTP/1.1\r\n\
Host: evil.com\r\n\
Content-Type: application/x-git-upload-pack-request\r\n\
Content-Length: 10\r\n\r\n";
    let head = parse_request_head(bad_host).unwrap();
    assert_eq!(
        decide(&head, &hosts, Scheme::Https),
        Decision::Reject("host_not_allowed".to_owned())
    );

    // Disallowed port rejected
    let bad_port = b"POST /repo.git/git-upload-pack HTTP/1.1\r\n\
Host: git.example.com:8080\r\n\
Content-Type: application/x-git-upload-pack-request\r\n\
Content-Length: 10\r\n\r\n";
    let head = parse_request_head(bad_port).unwrap();
    assert_eq!(
        decide(&head, &hosts, Scheme::Https),
        Decision::Reject("disallowed_port".to_owned())
    );

    // Scheme mismatch rejected
    let bad_scheme = b"POST http://git.example.com/repo.git/git-upload-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Type: application/x-git-upload-pack-request\r\n\
Content-Length: 10\r\n\r\n";
    let head = parse_request_head(bad_scheme).unwrap();
    assert_eq!(
        decide(&head, &hosts, Scheme::Https),
        Decision::Reject("scheme_mismatch".to_owned())
    );
}

#[test]
fn test_post_content_length_bounds() {
    // Missing Content-Length on POST fails
    let no_cl = b"POST /repo.git/git-upload-pack HTTP/1.1\r\nHost: git.example.com\r\n\r\n";
    assert_eq!(
        parse_request_head(no_cl),
        Err(HttpError::InvalidContentLength)
    );

    // Oversized Content-Length (> 16 MiB) fails
    let huge_cl = b"POST /repo.git/git-upload-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Length: 16777217\r\n\r\n";
    assert_eq!(
        parse_request_head(huge_cl),
        Err(HttpError::HeaderValueTooLarge)
    );

    // GET with non-zero Content-Length still fails
    let get_nonzero =
        b"GET /repo.git/info/refs HTTP/1.1\r\nHost: git.example.com\r\nContent-Length: 5\r\n\r\n";
    assert_eq!(
        parse_request_head(get_nonzero),
        Err(HttpError::NonZeroContentLength)
    );
}

#[test]
fn test_post_duplicate_headers_rejected() {
    let hosts = allowed_hosts();

    let dup_ct = b"POST /repo.git/git-upload-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Length: 10\r\n\
Content-Type: application/x-git-upload-pack-request\r\n\
Content-Type: application/x-git-upload-pack-request\r\n\r\n";
    let head = parse_request_head(dup_ct).unwrap();
    assert_eq!(
        decide(&head, &hosts, Scheme::Https),
        Decision::Reject("duplicate_forward_header".to_owned())
    );

    let dup_proto = b"POST /repo.git/git-upload-pack HTTP/1.1\r\n\
Host: git.example.com\r\n\
Content-Length: 10\r\n\
Git-Protocol: version=2\r\n\
Git-Protocol: version=2\r\n\r\n";
    let head = parse_request_head(dup_proto).unwrap();
    assert_eq!(
        decide(&head, &hosts, Scheme::Https),
        Decision::Reject("duplicate_forward_header".to_owned())
    );
}
