use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub ports: Vec<PortResult>,
    pub protocols: Vec<String>,
    pub device_type: Option<String>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub cve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl Finding {
    pub fn new(id: &str, severity: &str, title: &str, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            detail: detail.into(),
            cve: None,
            cvss: None,
            confidence: None,
            reference: None,
        }
    }

    pub fn rank(&self) -> Severity {
        Severity::parse(&self.severity)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub hosts: Vec<HostResult>,
    pub started: String,
    pub finished: String,
    #[serde(default, skip_serializing_if = "Summary::is_empty")]
    pub summary: Summary,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    pub hosts: usize,
    pub open_ports: usize,
    pub findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl Summary {
    fn is_empty(&self) -> bool {
        self.hosts == 0 && self.open_ports == 0 && self.findings == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert_eq!(Severity::parse("MODERATE"), Severity::Medium);
        assert_eq!(Severity::parse("nonsense"), Severity::Info);
    }
}
