use std::path::Path;
use time::OffsetDateTime;

use crate::benchmark::{check_d9_content, BenchmarkSignatures};
use crate::fingerprint::FingerprintSet;
use crate::scan::{match_unit, Finding, ScanOptions, Severity, Visibility};

#[derive(Debug, thiserror::Error)]
pub enum D6Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn parse_oci_date(s: &str) -> Result<OffsetDateTime, String> {
    let trimmed = s.trim();

    // 1. Try RFC 3339 directly
    if let Ok(dt) = OffsetDateTime::parse(trimmed, &time::format_description::well_known::Rfc3339) {
        return Ok(dt);
    }

    // 2. Docker format: "2026-08-15 06:04:51 +0000 UTC" or "2026-08-15 06:04:51.123456789 +0000 UTC"
    let mut cleaned = trimmed.to_string();
    if cleaned.ends_with(" UTC") {
        cleaned.truncate(cleaned.len() - 4);
    }

    // Replace date-time separator ' ' with 'T' if present
    if let Some(space_idx) = cleaned.find(' ') {
        if space_idx == 10 {
            cleaned.replace_range(space_idx..space_idx + 1, "T");
        }
    }

    // Check timezone offset: " +0000" or "+0000" -> "+00:00"
    if let Some(plus_idx) = cleaned.rfind('+').or_else(|| cleaned.rfind('-')) {
        let offset_str = &cleaned[plus_idx..];
        if offset_str.len() == 5 && !offset_str.contains(':') {
            let sign = &offset_str[0..1];
            let hours = &offset_str[1..3];
            let mins = &offset_str[3..5];
            let formatted_offset = format!("{}{}:{}", sign, hours, mins);
            cleaned.replace_range(plus_idx.., &formatted_offset);
        }
        cleaned = cleaned.replace(" +", "+").replace(" -", "-");
    }

    if let Ok(dt) = OffsetDateTime::parse(&cleaned, &time::format_description::well_known::Rfc3339)
    {
        return Ok(dt);
    }

    Err(format!("cannot parse date '{}'", s))
}

pub fn scan_oci(
    inspect_path: Option<&Path>,
    history_path: Option<&Path>,
    t_clock: Option<OffsetDateTime>,
    fp: &FingerprintSet,
    signatures: &BenchmarkSignatures,
    opts: &ScanOptions,
) -> Result<Vec<Finding>, D6Error> {
    let mut findings = Vec::new();

    // 1. Scan docker inspect file
    if let Some(insp) = inspect_path {
        let content = std::fs::read_to_string(insp)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;
        let insp_str = insp.display().to_string();

        let images = match value {
            serde_json::Value::Array(arr) => arr,
            single @ serde_json::Value::Object(_) => vec![single],
            _ => Vec::new(),
        };

        for img in images {
            // Check Created
            if let Some(created_val) = img.get("Created").and_then(|v| v.as_str()) {
                match parse_oci_date(created_val) {
                    Ok(created_dt) => {
                        if let Some(tc) = t_clock {
                            if created_dt > tc {
                                findings.push(Finding {
                                    detector: "D6".into(),
                                    channel: "oci_created".into(),
                                    path: insp_str.clone(),
                                    visibility: Visibility::ImageOnly,
                                    severity: Severity::Gate,
                                    confidence: 1.0,
                                    hunk: None,
                                    evidence: vec![format!(
                                        "image Created date {} is after T_clock {}",
                                        created_val, tc
                                    )],
                                });
                            }
                        }
                    }
                    Err(_) => {
                        findings.push(Finding {
                            detector: "D6".into(),
                            channel: "oci_bad_date".into(),
                            path: insp_str.clone(),
                            visibility: Visibility::ImageOnly,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!("unparseable Created date '{}'", created_val)],
                        });
                    }
                }
            }

            // Check Env in Config and ContainerConfig
            let env_configs = [
                img.get("Config").and_then(|c| c.get("Env")),
                img.get("ContainerConfig").and_then(|c| c.get("Env")),
            ];

            let mut checked_envs = std::collections::HashSet::new();
            for env_opt in env_configs.into_iter().flatten() {
                if let Some(env_arr) = env_opt.as_array() {
                    for env_item in env_arr {
                        if let Some(env_str) = env_item.as_str() {
                            if checked_envs.insert(env_str.to_string()) {
                                let mut d6_opts = opts.clone();
                                d6_opts.visibility = Visibility::AgentVisible;

                                let d9_match = !check_d9_content(
                                    &insp_str,
                                    env_str,
                                    signatures,
                                    Visibility::AgentVisible,
                                )
                                .is_empty();

                                let fp_match =
                                    !match_unit(env_str, fp, &d6_opts, "D6", "oci_env", &insp_str)
                                        .is_empty();

                                if d9_match || fp_match {
                                    findings.push(Finding {
                                        detector: "D6".into(),
                                        channel: "oci_env".into(),
                                        path: insp_str.clone(),
                                        visibility: Visibility::AgentVisible,
                                        severity: Severity::Gate,
                                        confidence: 1.0,
                                        hunk: None,
                                        evidence: vec![format!(
                                            "Env value '{}' matches leak signature",
                                            env_str
                                        )],
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Check Labels in Config and ContainerConfig
            let label_configs = [
                img.get("Config").and_then(|c| c.get("Labels")),
                img.get("ContainerConfig").and_then(|c| c.get("Labels")),
            ];

            let mut checked_labels = std::collections::HashSet::new();
            for label_opt in label_configs.into_iter().flatten() {
                if let Some(label_map) = label_opt.as_object() {
                    for (k, v) in label_map {
                        let text_to_check = if let Some(v_str) = v.as_str() {
                            format!("{}: {}", k, v_str)
                        } else {
                            k.clone()
                        };

                        if checked_labels.insert(text_to_check.clone()) {
                            let mut d6_opts = opts.clone();
                            d6_opts.visibility = Visibility::ImageOnly;

                            let d9_match = !check_d9_content(
                                &insp_str,
                                &text_to_check,
                                signatures,
                                Visibility::ImageOnly,
                            )
                            .is_empty();

                            let fp_match = !match_unit(
                                &text_to_check,
                                fp,
                                &d6_opts,
                                "D6",
                                "oci_text",
                                &insp_str,
                            )
                            .is_empty();

                            if d9_match || fp_match {
                                findings.push(Finding {
                                    detector: "D6".into(),
                                    channel: "oci_text".into(),
                                    path: insp_str.clone(),
                                    visibility: Visibility::ImageOnly,
                                    severity: Severity::Gate,
                                    confidence: 1.0,
                                    hunk: None,
                                    evidence: vec![format!(
                                        "Label '{}' matches leak signature",
                                        text_to_check
                                    )],
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Scan docker history file (JSON Lines)
    if let Some(hist) = history_path {
        let content = std::fs::read_to_string(hist)?;
        let hist_str = hist.display().to_string();

        let mut history_after_count = 0usize;
        let mut latest_history_date: Option<OffsetDateTime> = None;
        let mut latest_history_str = String::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let entry: serde_json::Value = serde_json::from_str(trimmed)?;

            // Check CreatedAt
            if let Some(created_at_val) = entry.get("CreatedAt").and_then(|v| v.as_str()) {
                match parse_oci_date(created_at_val) {
                    Ok(entry_dt) => {
                        if let Some(tc) = t_clock {
                            if entry_dt > tc {
                                history_after_count += 1;
                                if latest_history_date.is_none_or(|lat| entry_dt > lat) {
                                    latest_history_date = Some(entry_dt);
                                    latest_history_str = created_at_val.to_string();
                                }
                            }
                        }
                    }
                    Err(_) => {
                        findings.push(Finding {
                            detector: "D6".into(),
                            channel: "oci_bad_date".into(),
                            path: hist_str.clone(),
                            visibility: Visibility::ImageOnly,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!(
                                "unparseable CreatedAt date '{}'",
                                created_at_val
                            )],
                        });
                    }
                }
            }

            // Check CreatedBy
            if let Some(created_by_val) = entry.get("CreatedBy").and_then(|v| v.as_str()) {
                let mut d6_opts = opts.clone();
                d6_opts.visibility = Visibility::ImageOnly;

                let d9_match =
                    !check_d9_content(&hist_str, created_by_val, signatures, Visibility::ImageOnly)
                        .is_empty();

                let fp_match =
                    !match_unit(created_by_val, fp, &d6_opts, "D6", "oci_text", &hist_str)
                        .is_empty();

                if d9_match || fp_match {
                    findings.push(Finding {
                        detector: "D6".into(),
                        channel: "oci_text".into(),
                        path: hist_str.clone(),
                        visibility: Visibility::ImageOnly,
                        severity: Severity::Gate,
                        confidence: 1.0,
                        hunk: None,
                        evidence: vec![format!(
                            "CreatedBy '{}' matches leak signature",
                            created_by_val
                        )],
                    });
                }
            }
        }

        if history_after_count > 0 {
            findings.push(Finding {
                detector: "D6".into(),
                channel: "oci_history_date".into(),
                path: hist_str,
                visibility: Visibility::ImageOnly,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!(
                    "{} history entries created after T_clock, latest is {}",
                    history_after_count, latest_history_str
                )],
            });
        }
    }

    Ok(findings)
}
