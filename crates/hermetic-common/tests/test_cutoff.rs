use hermetic_common::cutoff::{
    compute_cutoffs, ensure_utc, parse_utc_datetime, CutoffError, DiscardReason, FixCommit,
};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

fn dt(iso: &str) -> OffsetDateTime {
    parse_utc_datetime(iso).expect("valid iso datetime")
}

#[test]
fn test_earliest_candidate_wins() {
    let t1 = dt("2024-01-01T00:00:00Z");
    let t2 = dt("2024-01-05T00:00:00Z");
    let t3 = dt("2024-01-10T00:00:00Z");
    let t_base = dt("2024-01-15T00:00:00Z");
    let t_repo_first = dt("2023-01-01T00:00:00Z");

    let cutoffs = compute_cutoffs(
        Some(t1),
        Some(t2),
        &[FixCommit {
            sha: "abc".into(),
            author_date: t3,
            committer_date: t3,
        }],
        t_base,
        t_repo_first,
    )
    .expect("compute cutoffs succeeded");

    assert_eq!(cutoffs.t_world, t1);
    assert_eq!(cutoffs.t_clock, t_base);
    assert!(cutoffs.discarded.is_empty());
}

#[test]
fn test_t_clock_uses_base_when_later() {
    let t_world_candidate = dt("2024-01-01T00:00:00Z");
    let t_base = dt("2024-02-01T00:00:00Z");
    let t_first = dt("2023-01-01T00:00:00Z");

    let cutoffs = compute_cutoffs(Some(t_world_candidate), None, &[], t_base, t_first)
        .expect("compute cutoffs succeeded");

    assert_eq!(cutoffs.t_world, t_world_candidate);
    assert_eq!(cutoffs.t_clock, t_base);

    // When t_world is later than base_commit_time
    let t_base_early = dt("2023-12-01T00:00:00Z");
    let cutoffs2 = compute_cutoffs(Some(t_world_candidate), None, &[], t_base_early, t_first)
        .expect("compute cutoffs succeeded");

    assert_eq!(cutoffs2.t_world, t_world_candidate);
    assert_eq!(cutoffs2.t_clock, t_world_candidate);
}

#[test]
fn test_discard_reason_before_first_commit() {
    let t_first = dt("2023-01-01T00:00:00Z");
    let t_implausible = dt("2022-06-01T00:00:00Z");
    let t_valid = dt("2024-01-01T00:00:00Z");

    let cutoffs = compute_cutoffs(
        Some(t_valid),
        None,
        &[FixCommit {
            sha: "c1".into(),
            author_date: t_implausible,
            committer_date: t_valid,
        }],
        t_valid,
        t_first,
    )
    .expect("compute cutoffs succeeded");

    assert_eq!(cutoffs.t_world, t_valid);
    assert_eq!(cutoffs.discarded.len(), 1);
    assert_eq!(cutoffs.discarded[0].commit, "c1");
    assert_eq!(cutoffs.discarded[0].author_date, t_implausible);
    assert_eq!(
        cutoffs.discarded[0].reason,
        DiscardReason::BeforeFirstCommit
    );
}

#[test]
fn test_discard_reason_outlier_gt_90d() {
    let t_first = dt("2020-01-01T00:00:00Z");
    let t_other = dt("2024-05-01T00:00:00Z");
    let t_outlier = t_other - Duration::days(91);

    let cutoffs = compute_cutoffs(
        Some(t_other),
        None,
        &[FixCommit {
            sha: "c1".into(),
            author_date: t_outlier,
            committer_date: t_other,
        }],
        t_other,
        t_first,
    )
    .expect("compute cutoffs succeeded");

    assert_eq!(cutoffs.t_world, t_other);
    assert_eq!(cutoffs.discarded.len(), 1);
    assert_eq!(cutoffs.discarded[0].commit, "c1");
    assert_eq!(cutoffs.discarded[0].author_date, t_outlier);
    assert_eq!(cutoffs.discarded[0].reason, DiscardReason::OutlierGt90d);
}

#[test]
fn test_author_date_not_discarded_within_90_days() {
    let t_first = dt("2020-01-01T00:00:00Z");
    let t_committer = dt("2024-05-01T00:00:00Z");
    let t_author = t_committer - Duration::days(89);

    let cutoffs = compute_cutoffs(
        None,
        None,
        &[FixCommit {
            sha: "c1".into(),
            author_date: t_author,
            committer_date: t_committer,
        }],
        t_committer,
        t_first,
    )
    .expect("compute cutoffs succeeded");

    assert_eq!(cutoffs.t_world, t_author);
    assert!(cutoffs.discarded.is_empty());
}

#[test]
fn test_no_candidates_raises_error() {
    let aware = dt("2024-01-01T00:00:00Z");
    let err = compute_cutoffs(None, None, &[], aware, aware).unwrap_err();
    assert_eq!(err, CutoffError::NoCandidates);
}

#[test]
fn test_only_author_dates_ever_discarded() {
    let t_first = dt("2024-01-01T00:00:00Z");
    let t_old = dt("2020-01-01T00:00:00Z");
    let t_base = dt("2024-06-01T00:00:00Z");

    let cutoffs = compute_cutoffs(
        None,
        None,
        &[FixCommit {
            sha: "c1".into(),
            author_date: dt("2024-05-01T00:00:00Z"),
            committer_date: t_old,
        }],
        t_base,
        t_first,
    )
    .expect("compute cutoffs succeeded");

    // Even though committer date is older than repo_first_commit, it is NOT discarded
    assert_eq!(cutoffs.t_world, t_old);
    assert!(cutoffs.discarded.is_empty());
}

#[test]
fn test_non_utc_datetimes_normalized() {
    let offset_plus5 = UtcOffset::from_hms(5, 0, 0).expect("valid offset");
    let dt_plus5 = OffsetDateTime::parse("2024-01-01T10:00:00+05:00", &Rfc3339)
        .expect("parse with offset")
        .to_offset(offset_plus5);

    let t_first = dt("2020-01-01T00:00:00Z");
    let t_base = dt("2024-01-01T12:00:00Z");

    let cutoffs = compute_cutoffs(Some(dt_plus5), None, &[], t_base, t_first)
        .expect("compute cutoffs succeeded");

    assert_eq!(cutoffs.t_world.offset(), UtcOffset::UTC);
    assert_eq!(cutoffs.t_world, dt("2024-01-01T05:00:00Z"));
}

#[test]
fn test_ensure_utc_validation() {
    let offset_plus2 = UtcOffset::from_hms(2, 0, 0).expect("valid offset");
    let aware = OffsetDateTime::parse("2024-01-01T14:00:00+02:00", &Rfc3339)
        .expect("parse with offset")
        .to_offset(offset_plus2);

    let normalized = ensure_utc(aware);
    assert_eq!(normalized.offset(), UtcOffset::UTC);
    assert_eq!(normalized, dt("2024-01-01T12:00:00Z"));

    // Invalid ISO strings fail parse_utc_datetime
    assert!(parse_utc_datetime("not-a-datetime").is_err());
    assert!(parse_utc_datetime("2024-01-01 00:00:00").is_err());
}
