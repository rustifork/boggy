use crate::types::{Finding, HostResult, PortResult};
use serde::Deserialize;

#[derive(Deserialize)]
struct CveEntry {
    id: String,
    cve: Option<String>,
    severity: String,
    title: String,
    detail: String,
    ports: Option<Vec<u16>>,
    keywords: Option<Vec<String>>,
}

static CVE_DB: &str = include_str!("../../db/cves.json");

fn load() -> Vec<CveEntry> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(format!("{}/.boggy/cves.json", home));
    }
    candidates.push("db/cves.json".to_string());
    candidates.push("/etc/boggy/cves.json".to_string());
    for path in &candidates {
        if let Ok(data) = std::fs::read_to_string(path) {
            if let Ok(v) = serde_json::from_str::<Vec<CveEntry>>(&data) {
                return v;
            }
        }
    }
    serde_json::from_str(CVE_DB).unwrap_or_default()
}

pub fn match_host(host: &HostResult, ports: &[PortResult]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let db = load();
    let banners: String = ports.iter().filter_map(|p| p.banner.clone()).collect::<Vec<_>>().join(" ").to_lowercase();
    let open_ports: Vec<u16> = ports.iter().filter(|p| p.open).map(|p| p.port).collect();
    for e in db {
        let has_kw = e.keywords.as_ref().map(|k| !k.is_empty()).unwrap_or(false);
        let kw_hit = e.keywords.as_ref().map(|k| k.iter().any(|kk| banners.contains(&kk.to_lowercase()))).unwrap_or(false);
        let port_hit = e.ports.as_ref().map(|ps| ps.iter().any(|p| open_ports.contains(p))).unwrap_or(false);
        let hit = if has_kw {
            kw_hit && (e.ports.is_none() || port_hit)
        } else {
            port_hit
        };
        if e.ports.is_none() && e.keywords.is_none() { continue; }
        if hit {
            findings.push(Finding {
                id: e.id.clone(),
                severity: e.severity.clone(),
                title: e.title.clone(),
                detail: e.detail.clone(),
                cve: e.cve.clone(),
            });
        }
    }
    // weak services
    for p in ports {
        if !p.open { continue; }
        let f = match p.port {
            23 | 2323 => Some(("TELNET", "high", "Telnet cleartext management interface")),
            6379 => Some(("REDIS", "critical", "Redis exposed without authentication likely")),
            9200 | 9300 => Some(("ELASTICSEARCH", "high", "Elasticsearch HTTP API exposed")),
            27017 => Some(("MONGODB", "high", "MongoDB exposed")),
            5984 => Some(("COUCHDB", "high", "CouchDB exposed")),
            11211 => Some(("MEMCACHED", "medium", "Memcached exposed")),
            2375 => Some(("DOCKER", "critical", "Docker daemon unauthenticated")),
            2376 => Some(("DOCKER_TLS", "medium", "Docker TLS endpoint exposed")),
            445 => Some(("SMB", "medium", "SMB service exposed")),
            5900 => Some(("VNC", "high", "VNC remote desktop exposed")),
            3389 => Some(("RDP", "medium", "RDP exposed")),
            _ => None,
        };
        if let Some((id, sev, title)) = f {
            findings.push(Finding {
                id: id.to_string(),
                severity: sev.to_string(),
                title: title.to_string(),
                detail: format!("port {}", p.port),
                cve: None,
            });
        }
    }
    let _ = host;
    findings
}