use crate::json::Json;
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

#[derive(Clone, Debug)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub tls: bool,
    pub server: Option<String>,
    pub title: Option<String>,
}

impl PortResult {
    pub fn to_json(&self) -> Json {
        let mut fields = vec![
            ("port", Json::num(self.port as f64)),
            ("open", Json::Bool(self.open)),
            ("service", Json::opt_str(self.service.as_deref())),
            ("banner", Json::opt_str(self.banner.as_deref())),
            ("tls", Json::Bool(self.tls)),
        ];
        if self.server.is_some() {
            fields.push(("server", Json::opt_str(self.server.as_deref())));
        }
        if self.title.is_some() {
            fields.push(("title", Json::opt_str(self.title.as_deref())));
        }
        Json::obj(fields)
    }
}

#[derive(Clone, Debug)]
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

impl HostResult {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("ip", Json::str(self.ip.to_string())),
            ("hostname", Json::opt_str(self.hostname.as_deref())),
            ("mac", Json::opt_str(self.mac.as_deref())),
            ("vendor", Json::opt_str(self.vendor.as_deref())),
            ("model", Json::opt_str(self.model.as_deref())),
            (
                "ports",
                Json::arr(self.ports.iter().map(|p| p.to_json()).collect()),
            ),
            (
                "protocols",
                Json::arr(self.protocols.iter().map(|s| Json::str(s)).collect()),
            ),
            ("device_type", Json::opt_str(self.device_type.as_deref())),
            (
                "findings",
                Json::arr(self.findings.iter().map(|f| f.to_json()).collect()),
            ),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub cve: Option<String>,
    pub cvss: Option<f32>,
    pub confidence: Option<String>,
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

    pub fn to_json(&self) -> Json {
        let mut fields = vec![
            ("id", Json::str(&self.id)),
            ("severity", Json::str(&self.severity)),
            ("title", Json::str(&self.title)),
            ("detail", Json::str(&self.detail)),
            ("cve", Json::opt_str(self.cve.as_deref())),
        ];
        if let Some(cvss) = self.cvss {
            fields.push(("cvss", Json::num(cvss as f64)));
        }
        if let Some(confidence) = &self.confidence {
            fields.push(("confidence", Json::str(confidence)));
        }
        if let Some(reference) = &self.reference {
            fields.push(("reference", Json::str(reference)));
        }
        Json::obj(fields)
    }
}

#[derive(Clone, Debug)]
pub struct ScanReport {
    pub target: String,
    pub hosts: Vec<HostResult>,
    pub started: String,
    pub finished: String,
    pub summary: Summary,
}

impl ScanReport {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("target", Json::str(&self.target)),
            (
                "hosts",
                Json::arr(self.hosts.iter().map(|h| h.to_json()).collect()),
            ),
            ("started", Json::str(&self.started)),
            ("finished", Json::str(&self.finished)),
            ("summary", self.summary.to_json()),
        ])
    }
}

#[derive(Clone, Debug, Default)]
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
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("hosts", Json::num(self.hosts as f64)),
            ("open_ports", Json::num(self.open_ports as f64)),
            ("findings", Json::num(self.findings as f64)),
            ("critical", Json::num(self.critical as f64)),
            ("high", Json::num(self.high as f64)),
            ("medium", Json::num(self.medium as f64)),
            ("low", Json::num(self.low as f64)),
            ("info", Json::num(self.info as f64)),
        ])
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
