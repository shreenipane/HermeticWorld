use std::collections::BTreeSet;

use hermetic_netvm_http::{
    decide, encode_forward, parse_request_head, Decision, HttpError, Scheme,
};

fn allowed() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert("example.com".to_owned());
    s.insert("registry.hermetic.test".to_owned());
    s
}

#[test]
fn test_every_error_kind() {
    // EmptyRequest
    assert_eq!(parse_request_head(b""), Err(HttpError::EmptyRequest));

    // IncompleteHead
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
        Err(HttpError::IncompleteHead)
    );

    // HeadTooLarge
    let huge = vec![b'A'; 16 * 1024 + 1];
    assert_eq!(parse_request_head(&huge), Err(HttpError::HeadTooLarge));

    // BareLineFeed
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\nHost: example.com\r\n\r\n"),
        Err(HttpError::BareLineFeed)
    );

    // BareCarriageReturn
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\rHost: example.com\r\n\r\n"),
        Err(HttpError::BareCarriageReturn)
    );

    // NonAsciiOrNul
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Test: \x80\r\n\r\n"),
        Err(HttpError::NonAsciiOrNul)
    );
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Test: a\0b\r\n\r\n"),
        Err(HttpError::NonAsciiOrNul)
    );

    // InvalidRequestLine
    assert_eq!(
        parse_request_head(b"GET /\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::InvalidRequestLine)
    );
    assert_eq!(
        parse_request_head(b"GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::InvalidRequestLine)
    );

    // InvalidMethod
    assert_eq!(
        parse_request_head(b"G@T / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::InvalidMethod)
    );

    // Http10Unsupported
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::Http10Unsupported)
    );

    // Http2PrefaceUnsupported
    assert_eq!(
        parse_request_head(b"PRI * HTTP/2.0\r\n\r\n"),
        Err(HttpError::Http2PrefaceUnsupported)
    );

    // UnsupportedHttpVersion
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.2\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::UnsupportedHttpVersion)
    );

    // TargetTooLarge
    let long_target = format!(
        "GET /{} HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "a".repeat(8 * 1024)
    );
    assert_eq!(
        parse_request_head(long_target.as_bytes()),
        Err(HttpError::TargetTooLarge)
    );

    // UnsupportedTargetForm (asterisk-form and authority-form)
    assert_eq!(
        parse_request_head(b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::UnsupportedTargetForm)
    );
    assert_eq!(
        parse_request_head(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
        Err(HttpError::UnsupportedTargetForm)
    );

    // InvalidTargetEncoding
    assert_eq!(
        parse_request_head(b"GET /%ZZ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::InvalidTargetEncoding)
    );

    // ForbiddenPathCharacter
    assert_eq!(
        parse_request_head(b"GET /a%2Fb HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::ForbiddenPathCharacter)
    );
    assert_eq!(
        parse_request_head(b"GET /a\\b HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::ForbiddenPathCharacter)
    );
    assert_eq!(
        parse_request_head(b"GET /a%00b HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::ForbiddenPathCharacter)
    );

    // DotSegmentInPath
    assert_eq!(
        parse_request_head(b"GET /a/../b HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::DotSegmentInPath)
    );
    assert_eq!(
        parse_request_head(b"GET /a/%2e%2e/b HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::DotSegmentInPath)
    );

    // TooManyHeaders
    let mut many = String::from("GET / HTTP/1.1\r\nHost: example.com\r\n");
    for i in 0..100 {
        many.push_str(&format!("X-H{}: v\r\n", i));
    }
    many.push_str("\r\n");
    assert_eq!(
        parse_request_head(many.as_bytes()),
        Err(HttpError::TooManyHeaders)
    );

    // ObsFoldForbidden
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\n folded\r\n\r\n"),
        Err(HttpError::ObsFoldForbidden)
    );

    // InvalidHeaderLine
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nNoColonHere\r\n\r\n"),
        Err(HttpError::InvalidHeaderLine)
    );

    // InvalidHeaderName (including space before colon)
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n"),
        Err(HttpError::InvalidHeaderName)
    );

    // HeaderNameTooLarge
    let long_name = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\n{}: v\r\n\r\n",
        "x".repeat(65)
    );
    assert_eq!(
        parse_request_head(long_name.as_bytes()),
        Err(HttpError::HeaderNameTooLarge)
    );

    // InvalidHeaderValue
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Ctrl: \x07\r\n\r\n"),
        Err(HttpError::InvalidHeaderValue)
    );

    // HeaderValueTooLarge
    let long_val = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: {}\r\n\r\n",
        "v".repeat(8 * 1024 + 1)
    );
    assert_eq!(
        parse_request_head(long_val.as_bytes()),
        Err(HttpError::HeaderValueTooLarge)
    );

    // TransferEncodingForbidden
    assert_eq!(
        parse_request_head(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        Err(HttpError::TransferEncodingForbidden)
    );

    // DuplicateContentLength
    assert_eq!(
        parse_request_head(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
        ),
        Err(HttpError::DuplicateContentLength)
    );

    // InvalidContentLength
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: +0\r\n\r\n"),
        Err(HttpError::InvalidContentLength)
    );

    // NonZeroContentLength
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n"),
        Err(HttpError::NonZeroContentLength)
    );

    // DuplicateHost
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::DuplicateHost)
    );

    // MissingHost
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"),
        Err(HttpError::MissingHost)
    );

    // InvalidHostHeader
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: user@example.com\r\n\r\n"),
        Err(HttpError::InvalidHostHeader)
    );

    // HostAuthorityMismatch
    assert_eq!(
        parse_request_head(b"GET http://evil.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Err(HttpError::HostAuthorityMismatch)
    );

    // ExpectHeaderForbidden
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\n\r\n"),
        Err(HttpError::ExpectHeaderForbidden)
    );

    // UpgradeForbidden
    assert_eq!(
        parse_request_head(b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n"),
        Err(HttpError::UpgradeForbidden)
    );
    assert_eq!(
        parse_request_head(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, Upgrade\r\n\r\n"
        ),
        Err(HttpError::UpgradeForbidden)
    );
}

#[test]
fn test_smuggling_vectors() {
    // CL.TE
    let cl_te = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(
        parse_request_head(cl_te),
        Err(HttpError::TransferEncodingForbidden)
    );

    // TE.CL
    let te_cl = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n";
    assert_eq!(
        parse_request_head(te_cl),
        Err(HttpError::TransferEncodingForbidden)
    );

    // Duplicate CL with equal values
    let dup_cl =
        b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        parse_request_head(dup_cl),
        Err(HttpError::DuplicateContentLength)
    );

    // Transfer-Encoding with odd spacing and mixed case
    let odd_te = b"GET / HTTP/1.1\r\nHost: example.com\r\ntRaNsFeR-eNcOdInG:\t  cHuNkEd  \r\n\r\n";
    assert_eq!(
        parse_request_head(odd_te),
        Err(HttpError::TransferEncodingForbidden)
    );

    // Header name with trailing space before colon
    let space_colon = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length : 0\r\n\r\n";
    assert_eq!(
        parse_request_head(space_colon),
        Err(HttpError::InvalidHeaderName)
    );
}

#[test]
fn test_path_normalisation_and_query_preservation() {
    // %7E -> ~ (unreserved), %2D -> - (unreserved), %20 -> %20 (reserved/non-unreserved kept uppercase)
    // Query string kept byte-for-byte including %2f and %7e.
    let raw =
        b"GET /pkg/%7euser/my%2Dcrate/%20v1?q=%2f%7e&a=1+2 HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
    let head = parse_request_head(raw).expect("valid request");
    assert_eq!(head.target.path, "/pkg/~user/my-crate/%20v1");
    assert_eq!(head.target.query.as_deref(), Some("q=%2f%7e&a=1+2"));

    // Absolute-form matching Host
    let abs = b"HEAD http://EXAMPLE.COM:80/a/b HTTP/1.1\r\nHost: example.com:80\r\n\r\n";
    let head_abs = parse_request_head(abs).expect("valid absolute-form");
    assert_eq!(head_abs.target.path, "/a/b");
    assert_eq!(
        head_abs.target.authority_host.as_deref(),
        Some("example.com")
    );
    assert_eq!(head_abs.target.authority_port, Some(80));
}

#[test]
fn test_policy_and_canonical_json_known_answer() {
    let raw = concat!(
        "GET /crates/serde/1.0.0/download?token=AbC%2f123 HTTP/1.1\r\n",
        "Host: REGISTRY.HERMETIC.TEST:443\r\n",
        "X-Secret-Token: super-secret-value\r\n",
        "User-Agent: curl/8.5.0\r\n",
        "Accept-Encoding: br, gzip;q=1.0, deflate, identity;q=0.5\r\n",
        "Range: bytes=0-1023\r\n",
        "Accept: application/octet-stream\r\n",
        "If-None-Match: \"etag-1\"\r\n",
        "If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
        "Cookie: session=xyz\r\n",
        "\r\n"
    );
    let head = parse_request_head(raw.as_bytes()).expect("valid head");
    let decision = decide(&head, &allowed(), Scheme::Https);

    let fwd = match decision {
        Decision::Forward(f) => f,
        other => panic!("expected Forward, got {:?}", other),
    };

    let json_bytes = encode_forward(&fwd);
    let json_str = std::str::from_utf8(&json_bytes).expect("valid utf8");

    let expected = concat!(
        r#"{"dropped_headers":["cookie","host","x-secret-token"],"#,
        r#""headers":["#,
        r#"{"name":"accept","value":"application/octet-stream"},"#,
        r#"{"name":"accept-encoding","value":"gzip, identity"},"#,
        r#"{"name":"range","value":"bytes=0-1023"},"#,
        r#"{"name":"if-none-match","value":"\"etag-1\""}, "#,
        r#"{"name":"if-modified-since","value":"Wed, 21 Oct 2015 07:28:00 GMT"},"#,
        r#"{"name":"user-agent","value":"hermetic-world/1"}"#,
        r#"],"#,
        r#""host":"registry.hermetic.test","#,
        r#""method":"GET","#,
        r#""path":"/crates/serde/1.0.0/download","#,
        r#""query":"token=AbC%2f123"}"#
    )
    .replace("}, {", "},{");

    assert_eq!(json_str, expected);

    // Port mismatch for scheme must be rejected
    let wrong_port = decide(&head, &allowed(), Scheme::Http);
    assert_eq!(wrong_port, Decision::Reject("disallowed_port".to_owned()));

    // Non-GET/HEAD valid method returns MethodNotAllowed (405)
    let post_raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    let post_head = parse_request_head(post_raw).expect("valid POST head");
    assert_eq!(
        decide(&post_head, &allowed(), Scheme::Https),
        Decision::MethodNotAllowed
    );
}

#[test]
fn test_fuzz_xorshift_and_truncation_no_panic() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next_u64 = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let hosts = allowed();
    let mut buf = Vec::with_capacity(512);
    for _ in 0..100_000 {
        let len = (next_u64() % 512) as usize;
        buf.clear();
        while buf.len() < len {
            let chunk = next_u64().to_le_bytes();
            let take = (len - buf.len()).min(8);
            buf.extend_from_slice(&chunk[..take]);
        }
        if let Ok(head) = parse_request_head(&buf) {
            let dec = decide(&head, &hosts, Scheme::Https);
            if let Decision::Forward(fwd) = dec {
                let _ = encode_forward(&fwd);
            }
        }
    }

    // Truncation of a valid head at every byte offset never panics
    let valid =
        b"GET /foo/bar?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nUser-Agent: x\r\n\r\n";
    for cut in 0..valid.len() {
        let res = parse_request_head(&valid[..cut]);
        assert!(res.is_err());
    }
    assert!(parse_request_head(valid).is_ok());
}
