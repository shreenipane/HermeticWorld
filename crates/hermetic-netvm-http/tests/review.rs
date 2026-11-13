use hermetic_netvm_http::{decide, parse_request_head, Decision, Scheme};
use std::collections::BTreeSet;

fn decision(target: &str, headers: &str, scheme: Scheme) -> Decision {
    let raw = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n");
    let head = parse_request_head(raw.as_bytes()).expect("valid framing");
    decide(&head, &BTreeSet::from(["example.com".to_owned()]), scheme)
}

#[test]
fn review_absolute_scheme_cannot_change_transport() {
    assert!(matches!(
        decision("http://example.com/a", "", Scheme::Https),
        Decision::Reject(_)
    ));
    assert!(matches!(
        decision("https://example.com/a", "", Scheme::Http),
        Decision::Reject(_)
    ));
    assert!(matches!(
        decision("https://example.com/a", "", Scheme::Https),
        Decision::Forward(_)
    ));
}

#[test]
fn review_ipv6_literals_must_parse() {
    for host in ["[deadbeef]", "[.:]", "[1:2:3]", "[1:::2]"] {
        let raw = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert!(parse_request_head(raw.as_bytes()).is_err(), "{host}");
    }
    assert!(parse_request_head(b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n").is_ok());
}

#[test]
fn review_connection_nominations_and_duplicates_refused() {
    for headers in [
        "Connection: range\r\nRange: bytes=0-1\r\n",
        "Connection: host\r\n",
        "Connection: ,close\r\n",
        "Connection: bad token\r\n",
        "Accept: a\r\nAccept: b\r\n",
        "Range: bytes=0-1\r\nRange: bytes=1-2\r\n",
        "If-None-Match: a\r\nIf-None-Match: b\r\n",
        "Accept-Encoding: gzip\r\nAccept-Encoding: identity\r\n",
    ] {
        let raw = format!("GET / HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n");
        if let Ok(head) = parse_request_head(raw.as_bytes()) {
            assert!(
                matches!(
                    decide(
                        &head,
                        &BTreeSet::from(["example.com".to_owned()]),
                        Scheme::Http
                    ),
                    Decision::Reject(_)
                ),
                "{headers}"
            );
        }
    }
}

#[test]
fn review_encoding_zero_quality_and_limits() {
    let Decision::Forward(fwd) =
        decision("/", "Accept-Encoding: gzip;q=0, identity\r\n", Scheme::Http)
    else {
        panic!("forward");
    };
    assert!(fwd
        .headers
        .iter()
        .any(|h| h.name == "accept-encoding" && h.value.contains("gzip;q=0")));
    for value in [
        "gzip;q=bogus",
        "gzip;q=1.001",
        "gzip;q=0, identity;q=0",
        "gzip, gzip;q=0",
    ] {
        assert!(
            matches!(
                decision("/", &format!("Accept-Encoding: {value}\r\n"), Scheme::Http),
                Decision::Reject(_)
            ),
            "{value}"
        );
    }
    let value = vec!["br"; 33].join(",");
    assert!(matches!(
        decision("/", &format!("Accept-Encoding: {value}\r\n"), Scheme::Http),
        Decision::Reject(_)
    ));
}

#[test]
fn review_encoding_wildcard_can_supply_gzip() {
    let Decision::Forward(fwd) = decision(
        "/",
        "Accept-Encoding: identity;q=0, *;q=1\r\n",
        Scheme::Http,
    ) else {
        panic!("wildcard permits gzip");
    };
    assert!(fwd
        .headers
        .iter()
        .any(|h| h.name == "accept-encoding" && h.value == "identity;q=0, gzip"));
}

#[test]
fn review_repeated_path_separators_are_refused() {
    for target in ["//evil.example/a", "/a//b", "http://example.com//a"] {
        let raw = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert!(parse_request_head(raw.as_bytes()).is_err(), "{target}");
    }
}

#[test]
fn review_encoding_token_cap_uses_distinct_tokens() {
    let cap = hermetic_netvm_http::policy::MAX_ACCEPT_ENCODING_TOKENS;
    let mut tokens: Vec<String> = (0..cap).map(|i| format!("coding{i}")).collect();
    assert!(matches!(
        decision(
            "/",
            &format!("Accept-Encoding: {}\r\n", tokens.join(",")),
            Scheme::Http
        ),
        Decision::Forward(_)
    ));
    tokens.push("one-more".into());
    assert_eq!(
        decision(
            "/",
            &format!("Accept-Encoding: {}\r\n", tokens.join(",")),
            Scheme::Http
        ),
        Decision::Reject("too_many_accept_encoding_tokens".into())
    );
}
