use hermetic_escapeprobe::classify::{EscapeRecord, EscapeResult};
use hermetic_escapeprobe::probes::expected_probe_names;
use hermetic_escapeprobe::report::*;

fn render(f: impl Fn(&str) -> EscapeResult) -> String {
    expected_probe_names()
        .iter()
        .map(|n| EscapeRecord::new(n.clone(), f(n), "fixed detail").to_json_line() + "\n")
        .collect()
}
fn good(n: &str) -> EscapeResult {
    if n.starts_with("positive.") {
        EscapeResult::Ok
    } else {
        EscapeResult::Blocked
    }
}

#[test]
fn all_blocked_and_positive_ok_is_sealed() {
    let e = expected_probe_names();
    assert_eq!(aggregate(render(good).as_bytes(), &e), Verdict::Sealed);
}

#[test]
fn any_leak_is_escaped_even_alongside_errors() {
    let e = expected_probe_names();
    let r = render(|n| match n {
        "ip.tcp.google_443" => EscapeResult::Leak,
        "hostfs.mounts" => EscapeResult::Error,
        _ => good(n),
    });
    assert_eq!(
        aggregate(r.as_bytes(), &e),
        Verdict::Escaped {
            leaks: vec!["ip.tcp.google_443".into()]
        }
    );
}

#[test]
fn unavailable_is_incomplete_not_sealed() {
    let e = expected_probe_names();
    let r = render(|n| {
        if n == "gateway.quota" {
            EscapeResult::Unavailable
        } else {
            good(n)
        }
    });
    assert_eq!(
        aggregate(r.as_bytes(), &e),
        Verdict::Incomplete {
            unavailable: vec!["gateway.quota".into()]
        }
    );
}

#[test]
fn errors_and_wrong_result_kinds_are_invalid() {
    let e = expected_probe_names();
    for (name, res) in [
        ("hostfs.mounts", EscapeResult::Error),
        ("positive.getrandom_nonblock", EscapeResult::Blocked),
        ("positive.getrandom_nonblock", EscapeResult::Error),
        ("positive.getrandom_nonblock", EscapeResult::Leak),
        ("ip.tcp.google_443", EscapeResult::Ok),
    ] {
        let r = render(|n| if n == name { res } else { good(n) });
        assert!(
            matches!(aggregate(r.as_bytes(), &e), Verdict::Invalid { .. }),
            "{name} {res:?}"
        );
    }
}

#[test]
fn hostile_reports_fail_closed() {
    let e = expected_probe_names();
    let ok = render(good);
    let lines: Vec<&str> = ok.lines().collect();
    let invalid = |s: &str| matches!(aggregate(s.as_bytes(), &e), Verdict::Invalid { .. });
    assert!(invalid(""));
    assert!(invalid(&lines[1..].join("\n")), "missing");
    assert!(invalid(&format!("{ok}{}\n", lines[0])), "duplicate");
    assert!(invalid(&format!(
        "{ok}{{\"probe\":\"extra.probe\",\"result\":\"blocked\",\"detail\":\"x\"}}\n"
    )));
    assert!(invalid(&format!("{ok}not json\n")));
    assert!(invalid(&ok.replacen("\"blocked\"", "\"BLOCKED\"", 1)));
    assert!(invalid(&ok.replacen(
        "\"detail\":\"fixed detail\"",
        "\"detail\":\"Host /home\\\"x\"",
        1
    )));
    assert!(invalid(&ok.replacen("{\"probe\"", " {\"probe\"", 1)));
    assert!(invalid(&ok.replacen("\"}", "\",\"value\":\"x\"}", 1)));
    assert!(invalid(&format!("{ok}\u{0}")));
    let mut bin = ok.clone().into_bytes();
    bin.push(0xff);
    assert!(matches!(aggregate(&bin, &e), Verdict::Invalid { .. }));
    let big = "\n".repeat(MAX_REPORT_BYTES + 1);
    assert!(invalid(&big));
    let long = format!(
        "{{\"probe\":\"{}\",\"result\":\"blocked\",\"detail\":\"x\"}}",
        "a".repeat(600)
    );
    assert!(invalid(&long));
}

#[test]
fn parse_line_exact_shape() {
    assert_eq!(
        parse_line(r#"{"probe":"a.b","result":"leak","detail":"peer reached"}"#),
        Some(("a.b", EscapeResult::Leak, "peer reached"))
    );
    assert!(parse_line(r#"{"probe":"a","result":"maybe","detail":"x"}"#).is_none());
    assert!(parse_line(r#"{"result":"leak","probe":"a","detail":"x"}"#).is_none());
    assert!(parse_line(r#"{"probe":"a","result":"leak","detail":"x"} "#).is_none());
}

#[test]
fn verdict_names() {
    assert_eq!(Verdict::Sealed.as_str(), "sealed");
    assert_eq!(Verdict::Invalid { reason: "x" }.as_str(), "invalid");
    assert_eq!(Verdict::Escaped { leaks: vec![] }.as_str(), "escaped");
    assert_eq!(
        Verdict::Incomplete {
            unavailable: vec![]
        }
        .as_str(),
        "incomplete"
    );
}
