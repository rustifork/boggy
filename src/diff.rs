//! Compare a scan with a stored JSON baseline to spot new and resolved exposure.

use crate::json::Json;
use crate::types::ScanReport;
use std::collections::BTreeSet;

fn keys(root: &Json) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut hosts = BTreeSet::new();
    let mut findings = BTreeSet::new();
    if let Some(rows) = root.get("hosts").and_then(Json::as_arr) {
        for host in rows {
            let ip = host.get("ip").map(Json::string).unwrap_or_default();
            if !ip.is_empty() {
                hosts.insert(ip.clone());
            }
            if let Some(items) = host.get("findings").and_then(Json::as_arr) {
                for item in items {
                    let id = item.get("id").map(Json::string).unwrap_or_default();
                    let detail = item.get("detail").map(Json::string).unwrap_or_default();
                    findings.insert(format!("{}|{}|{}", ip, id, detail));
                }
            }
        }
    }
    (hosts, findings)
}

fn array(set: &BTreeSet<String>) -> Json {
    Json::arr(set.iter().take(50).map(|s| Json::str(s)).collect())
}

pub fn compare(current: &ScanReport, baseline_path: &str) -> Result<Json, String> {
    let data = std::fs::read_to_string(baseline_path)
        .map_err(|e| format!("read baseline {}: {}", baseline_path, e))?;
    let root = crate::json::parse(data.as_bytes())
        .map_err(|e| format!("invalid baseline {}: {}", baseline_path, e))?;
    let (base_hosts, base_findings) = keys(&root);

    let mut hosts = BTreeSet::new();
    let mut findings = BTreeSet::new();
    for host in &current.hosts {
        let ip = host.ip.to_string();
        hosts.insert(ip.clone());
        for finding in &host.findings {
            findings.insert(format!("{}|{}|{}", ip, finding.id, finding.detail));
        }
    }

    let new_hosts: BTreeSet<String> = hosts.difference(&base_hosts).cloned().collect();
    let lost_hosts: BTreeSet<String> = base_hosts.difference(&hosts).cloned().collect();
    let new_findings: BTreeSet<String> = findings.difference(&base_findings).cloned().collect();
    let resolved: BTreeSet<String> = base_findings.difference(&findings).cloned().collect();

    Ok(Json::obj(vec![
        ("baseline", Json::str(baseline_path)),
        ("new_hosts", Json::num(new_hosts.len() as f64)),
        ("missing_hosts", Json::num(lost_hosts.len() as f64)),
        ("new_findings", Json::num(new_findings.len() as f64)),
        ("resolved_findings", Json::num(resolved.len() as f64)),
        ("new_host_list", array(&new_hosts)),
        ("missing_host_list", array(&lost_hosts)),
        ("new_finding_list", array(&new_findings)),
        ("resolved_finding_list", array(&resolved)),
    ]))
}

pub fn render_text(diff: &Json) -> String {
    let n = |key: &str| diff.get(key).and_then(Json::as_u64).unwrap_or(0);
    let mut out = String::from("baseline comparison:\n");
    out.push_str(&format!(
        "  new hosts: {} | missing hosts: {} | new findings: {} | resolved findings: {}\n",
        n("new_hosts"),
        n("missing_hosts"),
        n("new_findings"),
        n("resolved_findings")
    ));
    for (label, key) in [
        ("new findings", "new_finding_list"),
        ("resolved findings", "resolved_finding_list"),
    ] {
        if let Some(items) = diff.get(key).and_then(Json::as_arr) {
            for item in items.iter().take(10) {
                out.push_str(&format!("  {}: {}\n", label, item.string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_changes() {
        let baseline = r#"{"hosts":[{"ip":"192.168.1.2","findings":[{"id":"OLD","detail":"x"}]}]}"#;
        let path = std::env::temp_dir().join(format!("boggy-diff-{}.json", std::process::id()));
        std::fs::write(&path, baseline).unwrap();
        let report = ScanReport {
            target: "test".into(),
            hosts: Vec::new(),
            started: "0".into(),
            finished: "0".into(),
            summary: Default::default(),
            diff: None,
        };
        let diff = compare(&report, path.to_str().unwrap()).unwrap();
        assert_eq!(diff.get("missing_hosts").unwrap().as_u64(), Some(1));
        assert_eq!(diff.get("resolved_findings").unwrap().as_u64(), Some(1));
        let _ = std::fs::remove_file(path);
    }
}
