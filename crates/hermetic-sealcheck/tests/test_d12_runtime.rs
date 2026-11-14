use std::sync::Arc;

use hermetic_sealcheck::d12::D12Options;
use hermetic_sealcheck::d12_runtime::{
    decode_escapes, DateSentinel, SentinelSummary, SseScanner, MAX_SSE_LINE_BYTES,
};
use time::{Date, Month};

fn opts() -> D12Options {
    D12Options {
        real_date: Date::from_calendar_date(2026, Month::November, 14).unwrap(),
        tolerance_days: 1,
        host_names: vec!["buildhost-7".into()],
        host_paths: vec!["/srv/hostonly/secret".into()],
    }
}

fn sentinel() -> DateSentinel {
    DateSentinel::new(opts()).unwrap()
}

#[test]
fn rt_clean_text_records_nothing() {
    let s = sentinel();
    s.scan_text("request", "world date is 2023-03-01, nothing else");
    let sum = s.summary();
    assert!(!sum.date_leak_observed);
    assert!(sum.hits.is_empty());
    assert!(!sum.scan_incomplete);
}

#[test]
fn rt_real_date_host_name_and_path_counted_without_echo() {
    let s = sentinel();
    s.scan_text(
        "request",
        "today 2026-11-14 on buildhost-7 at /srv/hostonly/secret/x",
    );
    let sum = s.summary();
    assert!(sum.date_leak_observed);
    assert_eq!(sum.hits.get("request:real_date"), Some(&1));
    assert_eq!(sum.hits.get("request:host_name"), Some(&1));
    assert_eq!(sum.hits.get("request:host_path"), Some(&1));
    let json = serde_json::to_string(&sum).unwrap();
    assert!(
        !json.contains("buildhost"),
        "summary must not echo host data"
    );
    assert!(!json.contains("hostonly"));
    assert!(!json.contains("2026-11-14"));
    assert!(!format!("{s:?}").contains("buildhost"));
}

#[test]
fn rt_encoded_dates_are_decoded() {
    for text in [
        "d=2026\\u002d11\\u002d14",
        "d=2026%2D11%2D14",
        "d=11\\/14\\/2026",
        "d=2026&#45;11&#x2d;14",
        "d=\u{FF12}\u{FF10}\u{FF12}\u{FF16}-\u{FF11}\u{FF11}-\u{FF11}\u{FF14}",
    ] {
        let s = sentinel();
        s.scan_text("request", text);
        assert!(s.date_leak_observed(), "missed encoded date in {text:?}");
    }
    assert_eq!(decode_escapes("plain"), None);
}

#[test]
fn rt_json_string_values_scanned() {
    let s = sentinel();
    s.scan_json("response", r#"{"content":[{"text":"Nov 14, 2026"}]}"#);
    assert!(s.date_leak_observed());
}

#[test]
fn rt_utf16_bytes_scanned() {
    let s = sentinel();
    let utf16: Vec<u8> = "on 2026-11-14 ok"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    s.scan_bytes("observation", &utf16);
    assert!(s.date_leak_observed());
}

#[test]
fn rt_text_stream_date_split_across_chunks() {
    let s = sentinel();
    {
        let mut st = s.stream("observation");
        st.feed("log line 2026-1");
        st.feed("1-14 end");
    }
    let sum = s.summary();
    assert_eq!(sum.hits.get("observation:real_date"), Some(&1));
}

#[test]
fn rt_text_stream_does_not_double_count_tail() {
    let s = sentinel();
    {
        let mut st = s.stream("observation");
        st.feed("2026-11-14");
        st.feed(" more");
        st.feed(" and more");
    }
    assert_eq!(s.summary().hits.get("observation:real_date"), Some(&1));
}

fn sse_event(text: &str) -> String {
    format!(
        "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{text}\"}}}}\n\n"
    )
}

#[test]
fn rt_sse_date_split_across_deltas_and_byte_chunks() {
    let s = Arc::new(sentinel());
    let stream = format!(
        "{}{}{}",
        sse_event("The date is 2026-"),
        sse_event("11-"),
        sse_event("14.")
    );
    {
        let mut sc = SseScanner::new(s.clone(), "stream");
        // Feed three bytes at a time so lines and JSON are split too.
        for c in stream.as_bytes().chunks(3) {
            sc.feed(c);
        }
    }
    assert!(s.date_leak_observed());
    assert!(s.summary().hits.contains_key("stream:real_date"));
}

#[test]
fn rt_sse_json_escaped_date_detected() {
    let s = Arc::new(sentinel());
    {
        let mut sc = SseScanner::new(s.clone(), "stream");
        sc.feed(sse_event("2026\\u002d11\\u002d14").as_bytes());
    }
    assert!(s.date_leak_observed());
}

#[test]
fn rt_sse_split_utf8_multibyte_is_not_lost() {
    let s = Arc::new(sentinel());
    let stream = sse_event("\u{FF12}0\u{FF12}6-11-14");
    {
        let mut sc = SseScanner::new(s.clone(), "stream");
        for c in stream.as_bytes().chunks(1) {
            sc.feed(c);
        }
    }
    assert!(s.date_leak_observed());
}

#[test]
fn rt_sse_clean_stream_not_flagged() {
    let s = Arc::new(sentinel());
    {
        let mut sc = SseScanner::new(s.clone(), "stream");
        sc.feed(sse_event("hello 2023-01-05").as_bytes());
    }
    assert!(!s.date_leak_observed());
}

#[test]
fn rt_sse_line_cap_fails_closed() {
    let s = Arc::new(sentinel());
    {
        let mut sc = SseScanner::new(s.clone(), "stream");
        let long = vec![b'a'; MAX_SSE_LINE_BYTES + 10];
        sc.feed(b"data: ");
        sc.feed(&long);
        sc.feed(b"\n");
    }
    let sum = s.summary();
    assert!(sum.scan_incomplete);
    assert!(sum.date_leak_observed);
    assert_eq!(sum.incomplete.get("stream:sse_line_cap"), Some(&1));
}

#[test]
fn rt_run_byte_cap_fails_closed() {
    let s = DateSentinel::with_max_bytes(opts(), 16).unwrap();
    s.scan_text("request", "short");
    assert!(!s.date_leak_observed());
    s.scan_text("request", "this text pushes over the cap");
    let sum = s.summary();
    assert!(sum.scan_incomplete && sum.date_leak_observed);
    assert!(sum.incomplete.contains_key("request:run_byte_cap"));
}

#[test]
fn rt_option_caps_refused() {
    let mut o = opts();
    o.host_names = vec!["x".into(); 10_001];
    assert!(DateSentinel::new(o).is_err());
}

#[test]
fn rt_merge_aggregates_fail_closed() {
    let clean = SentinelSummary::default();
    let incomplete = SentinelSummary {
        scan_incomplete: true,
        ..Default::default()
    };
    assert!(!SentinelSummary::merge(&[clean.clone(), clean.clone()]).date_leak_observed);
    assert!(SentinelSummary::merge(&[clean.clone(), incomplete]).date_leak_observed);
    let s = sentinel();
    s.scan_text("observation", "2026-11-13");
    let m = SentinelSummary::merge(&[clean, s.summary()]);
    assert!(m.date_leak_observed);
    assert_eq!(m.hits.get("observation:real_date"), Some(&1));
}
