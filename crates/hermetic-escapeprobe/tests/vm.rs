//! Runs the full probe inside a rooted throwaway AgentVM. Ignored by default:
//! on a developer host the probes would touch the real network. Run with
//! `HERMETIC_ESCAPE_PROBE_IN_GUEST=1 cargo test -p hermetic-escapeprobe --test vm -- --ignored`.
use hermetic_escapeprobe::classify::EscapeResult;
use hermetic_escapeprobe::probes::{expected_probe_names, run_all, GATEWAY_PROBES, INSTALL_PROBES};
use hermetic_escapeprobe::report::{aggregate, Verdict};

#[test]
#[ignore = "dev-unjailed: run only inside an AgentVM guest"]
fn escape_probe_in_guest_finds_no_way_out() {
    assert_eq!(
        std::env::var("HERMETIC_ESCAPE_PROBE_IN_GUEST").as_deref(),
        Ok("1"),
        "refusing to probe outside a guest"
    );
    let records = run_all();
    let report: String = records.iter().map(|r| r.to_json_line() + "\n").collect();
    print!("{report}");
    let v = aggregate(report.as_bytes(), &expected_probe_names());
    assert!(!matches!(v, Verdict::Escaped { .. }), "{v:?}");
    assert!(!matches!(v, Verdict::Invalid { .. }), "{v:?}");
    if let Verdict::Incomplete { unavailable } = &v {
        for n in unavailable {
            let allowed = GATEWAY_PROBES.contains(&n.as_str())
                || INSTALL_PROBES.contains(&n.as_str())
                || n.starts_with("dns.resolver1.")
                || n.starts_with("dns.resolver2.");
            assert!(allowed, "unexpected unavailable: {n}");
        }
    }
    assert!(records
        .iter()
        .any(|r| r.probe == "positive.getrandom_nonblock" && r.result == EscapeResult::Ok));
}
