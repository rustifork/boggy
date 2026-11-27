//! SARIF 2.1.0 renderer so boggy findings can be uploaded to CI code-scanning dashboards.

use crate::json::Json;
use crate::types::{Finding, ScanReport, Severity};
use std::collections::BTreeMap;

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

pub fn render(report: &ScanReport) -> String {
    let mut rules: BTreeMap<String, Finding> = BTreeMap::new();
    let mut results = Vec::new();

    for host in &report.hosts {
        for finding in &host.findings {
            rules
                .entry(finding.id.clone())
                .or_insert_with(|| finding.clone());
            let uri = format!("scan://{}", host.ip);
            let mut properties = Vec::new();
            if let Some(cve) = &finding.cve {
                properties.push(("cve", Json::str(cve)));
            }
            if let Some(cvss) = finding.cvss {
                properties.push(("cvss", Json::num(cvss as f64)));
            }
            if let Some(confidence) = &finding.confidence {
                properties.push(("confidence", Json::str(confidence)));
            }
            let mut result = vec![
                ("ruleId", Json::str(&finding.id)),
                ("level", Json::str(level(finding.rank()))),
                (
                    "message",
                    Json::obj(vec![("text", Json::str(&finding.detail))]),
                ),
                (
                    "locations",
                    Json::arr(vec![Json::obj(vec![(
                        "physicalLocation",
                        Json::obj(vec![
                            (
                                "artifactLocation",
                                Json::obj(vec![("uri", Json::str(&uri))]),
                            ),
                            ("region", Json::obj(vec![("startLine", Json::num(1.0))])),
                        ]),
                    )])]),
                ),
            ];
            if !properties.is_empty() {
                result.push(("properties", Json::obj(properties)));
            }
            results.push(Json::obj(result));
        }
    }

    let rule_values: Vec<Json> = rules
        .values()
        .map(|f| {
            let mut rule = vec![
                ("id", Json::str(&f.id)),
                (
                    "shortDescription",
                    Json::obj(vec![("text", Json::str(&f.title))]),
                ),
                (
                    "defaultConfiguration",
                    Json::obj(vec![("level", Json::str(level(f.rank())))]),
                ),
            ];
            if let Some(reference) = &f.reference {
                rule.push(("helpUri", Json::str(reference)));
            }
            Json::obj(rule)
        })
        .collect();

    Json::obj(vec![
        ("version", Json::str("2.1.0")),
        (
            "$schema",
            Json::str("https://json.schemastore.org/sarif-2.1.0.json"),
        ),
        (
            "runs",
            Json::arr(vec![Json::obj(vec![
                (
                    "tool",
                    Json::obj(vec![(
                        "driver",
                        Json::obj(vec![
                            ("name", Json::str("boggy")),
                            ("version", Json::str(env!("CARGO_PKG_VERSION"))),
                            (
                                "informationUri",
                                Json::str("https://github.com/rustifork/boggy"),
                            ),
                            ("rules", Json::arr(rule_values)),
                        ]),
                    )]),
                ),
                ("results", Json::arr(results)),
            ])]),
        ),
    ])
    .pretty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_is_valid_sarif() {
        let report = ScanReport {
            target: "test".into(),
            hosts: Vec::new(),
            started: "0".into(),
            finished: "0".into(),
            summary: Default::default(),
        };
        let text = render(&report);
        let parsed = crate::json::parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.get("version").unwrap().as_str(), Some("2.1.0"));
        assert!(parsed.get("runs").unwrap().as_arr().unwrap().len() == 1);
    }
}
