use serde::{Deserialize, Serialize};

use crate::scan::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SarifRunProperties {
    pub mode: String,
    pub not_covered: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRunProperties>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// Convert findings to a valid SARIF 2.1.0 log.
pub fn generate_sarif(findings: &[Finding]) -> SarifLog {
    let mut results = Vec::new();

    for f in findings {
        if f.severity == Severity::Info {
            continue;
        }

        let level = match f.severity {
            Severity::Gate => "error",
            Severity::Review => "warning",
            Severity::Info => "note",
        };

        let msg_text = if !f.evidence.is_empty() {
            format!(
                "Leak detected via {} (confidence {:.2}): {}",
                f.channel,
                f.confidence,
                f.evidence.join("; ")
            )
        } else {
            format!(
                "Leak detected via {} (confidence {:.2})",
                f.channel, f.confidence
            )
        };

        results.push(SarifResult {
            rule_id: f.detector.clone(),
            level: level.to_string(),
            message: SarifMessage { text: msg_text },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.path.clone(),
                    },
                },
            }],
        });
    }

    let rules = vec![
        SarifRule {
            id: "D0".to_string(),
            short_description: SarifMessage {
                text: "Problem-statement leak".to_string(),
            },
        },
        SarifRule {
            id: "D1".to_string(),
            short_description: SarifMessage {
                text: "Git state leak".to_string(),
            },
        },
        SarifRule {
            id: "D2".to_string(),
            short_description: SarifMessage {
                text: "Files and archives leak".to_string(),
            },
        },
        SarifRule {
            id: "D3".to_string(),
            short_description: SarifMessage {
                text: "Stale bytecode".to_string(),
            },
        },
        SarifRule {
            id: "D3b".to_string(),
            short_description: SarifMessage {
                text: "Compiled and derived artifacts".to_string(),
            },
        },
        SarifRule {
            id: "D5a".to_string(),
            short_description: SarifMessage {
                text: "Target project at a post-fix version".to_string(),
            },
        },
        SarifRule {
            id: "D6".to_string(),
            short_description: SarifMessage {
                text: "OCI and VM metadata leak".to_string(),
            },
        },
        SarifRule {
            id: "D9".to_string(),
            short_description: SarifMessage {
                text: "Benchmark presence".to_string(),
            },
        },
    ];

    SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "hermetic-sealcheck".to_string(),
                    rules,
                },
            },
            results,
            properties: None,
        }],
    }
}

/// Convert findings to a valid SARIF 2.1.0 log with optional run properties (e.g. query mode).
pub fn generate_sarif_with_properties(
    findings: &[Finding],
    properties: Option<SarifRunProperties>,
) -> SarifLog {
    let mut log = generate_sarif(findings);
    if let Some(run) = log.runs.first_mut() {
        run.properties = properties;
    }
    log
}
