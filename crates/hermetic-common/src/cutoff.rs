use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscardReason {
    BeforeFirstCommit,
    OutlierGt90d,
}

pub mod rfc3339_utc {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = date.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&s, &Rfc3339).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscardedDate {
    pub commit: String,
    #[serde(with = "rfc3339_utc")]
    pub author_date: OffsetDateTime,
    pub reason: DiscardReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixCommit {
    pub sha: String,
    #[serde(with = "rfc3339_utc")]
    pub author_date: OffsetDateTime,
    #[serde(with = "rfc3339_utc")]
    pub committer_date: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cutoffs {
    #[serde(with = "rfc3339_utc")]
    pub t_world: OffsetDateTime,
    #[serde(with = "rfc3339_utc")]
    pub t_clock: OffsetDateTime,
    pub discarded: Vec<DiscardedDate>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CutoffError {
    #[error("No candidates survive for t_world")]
    NoCandidates,
    #[error("{name} must be timezone-aware: {message}")]
    NonUtc { name: String, message: String },
}

/// Ensure datetime is converted to UTC.
pub fn ensure_utc(dt: OffsetDateTime) -> OffsetDateTime {
    dt.to_offset(UtcOffset::UTC)
}

/// Parse an RFC 3339 string and ensure it is in UTC.
pub fn parse_utc_datetime(s: &str) -> Result<OffsetDateTime, CutoffError> {
    let dt = OffsetDateTime::parse(s, &Rfc3339).map_err(|e| CutoffError::NonUtc {
        name: s.to_string(),
        message: e.to_string(),
    })?;
    Ok(ensure_utc(dt))
}

/// Compute cutoffs following Hermetic World cutoff rules.
///
/// Matches reference behavior in `python/hermetic_slice/cutoffs.py`.
pub fn compute_cutoffs(
    issue_created: Option<OffsetDateTime>,
    pr_opened: Option<OffsetDateTime>,
    fix_commits: &[FixCommit],
    base_commit_time: OffsetDateTime,
    repo_first_commit_time: OffsetDateTime,
) -> Result<Cutoffs, CutoffError> {
    let base_utc = ensure_utc(base_commit_time);
    let repo_first_utc = ensure_utc(repo_first_commit_time);

    let mut permanent_candidates: Vec<OffsetDateTime> = Vec::new();
    if let Some(ic) = issue_created {
        permanent_candidates.push(ensure_utc(ic));
    }
    if let Some(po) = pr_opened {
        permanent_candidates.push(ensure_utc(po));
    }

    for fc in fix_commits {
        permanent_candidates.push(ensure_utc(fc.committer_date));
    }

    let mut discarded: Vec<DiscardedDate> = Vec::new();
    let mut author_candidates: Vec<(String, OffsetDateTime)> = Vec::new();

    for fc in fix_commits {
        let author_utc = ensure_utc(fc.author_date);
        if author_utc < repo_first_utc {
            discarded.push(DiscardedDate {
                commit: fc.sha.clone(),
                author_date: author_utc,
                reason: DiscardReason::BeforeFirstCommit,
            });
        } else {
            author_candidates.push((fc.sha.clone(), author_utc));
        }
    }

    let mut surviving_author_dates: Vec<OffsetDateTime> = Vec::new();
    for (idx, (sha, author_utc)) in author_candidates.iter().enumerate() {
        let mut other_candidates = permanent_candidates.clone();
        for (i, (_, other_utc)) in author_candidates.iter().enumerate() {
            if i != idx {
                other_candidates.push(*other_utc);
            }
        }

        let is_outlier = if let Some(min_other) = other_candidates.iter().min() {
            *min_other - *author_utc > Duration::days(90)
        } else {
            false
        };

        if is_outlier {
            discarded.push(DiscardedDate {
                commit: sha.clone(),
                author_date: *author_utc,
                reason: DiscardReason::OutlierGt90d,
            });
        } else {
            surviving_author_dates.push(*author_utc);
        }
    }

    let mut surviving = permanent_candidates;
    surviving.extend(surviving_author_dates);

    if surviving.is_empty() {
        return Err(CutoffError::NoCandidates);
    }

    let t_world = *surviving.iter().min().ok_or(CutoffError::NoCandidates)?;
    let t_clock = t_world.max(base_utc);

    Ok(Cutoffs {
        t_world,
        t_clock,
        discarded,
    })
}
