//! CVE and weak-configuration matching. The database is data-driven: entries can
//! require a banner keyword, an open port, a device class, or an affected version.

use crate::iot::fingerprints::{version_lt, versions};
use crate::json::Json;
use crate::types::{Finding, HostResult, PortResult, Severity};

#[derive(Clone, Debug)]
struct Affected {
    product: String,
    below: String,
}

#[derive(Clone, Debug)]
struct CveEntry {
    id: String,
    cve: Option<String>,
    severity: String,
    title: String,
    detail: String,
    cvss: Option<f32>,
    vendor: Option<String>,
    product: Option<String>,
    ports: Option<Vec<u16>>,
    keywords: Option<Vec<String>>,
    all_keywords: Option<Vec<String>>,
    exclude_keywords: Option<Vec<String>>,
    device_types: Option<Vec<String>>,
    affected: Option<Vec<Affected>>,
    reference: Option<String>,
}

static CVE_DB: &str = include_str!("../../db/cves.json");

fn strings(value: Option<&Json>) -> Option<Vec<String>> {
    value.and_then(Json::as_arr).map(|items| {
        items
            .iter()
            .map(|v| v.string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

fn ports(value: Option<&Json>) -> Option<Vec<u16>> {
    value.and_then(Json::as_arr).map(|items| {
        items
            .iter()
            .filter_map(|v| v.as_u64())
            .filter(|n| *n <= u16::MAX as u64)
            .map(|n| n as u16)
            .collect()
    })
}

fn entry(value: &Json) -> Option<CveEntry> {
    let id = value.get("id")?.as_str()?.to_string();
    let severity = value.get("severity")?.as_str()?.to_string();
    let title = value.get("title")?.as_str()?.to_string();
    let detail = value.get("detail")?.as_str()?.to_string();
    let affected = value.get("affected").and_then(Json::as_arr).map(|items| {
        items
            .iter()
            .filter_map(|a| {
                Some(Affected {
                    product: a.get("product")?.as_str()?.to_string(),
                    below: a.get("below")?.as_str()?.to_string(),
                })
            })
            .collect()
    });
    Some(CveEntry {
        id,
        cve: value.get("cve").and_then(Json::as_str).map(str::to_string),
        severity,
        title,
        detail,
        cvss: value.get("cvss").and_then(Json::as_f64).map(|v| v as f32),
        vendor: value
            .get("vendor")
            .and_then(Json::as_str)
            .map(str::to_string),
        product: value
            .get("product")
            .and_then(Json::as_str)
            .map(str::to_string),
        ports: ports(value.get("ports")),
        keywords: strings(value.get("keywords")),
        all_keywords: strings(value.get("all_keywords")),
        exclude_keywords: strings(value.get("exclude_keywords")),
        device_types: strings(value.get("device_types")),
        affected,
        reference: value
            .get("reference")
            .and_then(Json::as_str)
            .map(str::to_string),
    })
}

fn decode(data: &str) -> Option<Vec<CveEntry>> {
    let root = crate::json::parse(data.as_bytes()).ok()?;
    let rows = root.as_arr()?;
    Some(rows.iter().filter_map(entry).collect())
}

fn load(explicit: Option<&str>) -> Vec<CveEntry> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(p) = explicit {
        candidates.push(p.to_string());
    }
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(format!("{}/.boggy/cves.json", home));
    }
    candidates.push("db/cves.json".to_string());
    candidates.push("/etc/boggy/cves.json".to_string());
    for path in &candidates {
        if let Ok(data) = std::fs::read_to_string(path) {
            if crate::update::validate_cves(data.as_bytes()).is_ok() {
                if let Some(db) = decode(&data) {
                    if !db.is_empty() {
                        return db;
                    }
                }
            }
        }
    }
    decode(CVE_DB).unwrap_or_default()
}

fn fingerprint_text(host: &HostResult, ports: &[PortResult]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for p in ports {
        for value in [
            p.banner.clone(),
            p.server.clone(),
            p.title.clone(),
            p.service.clone(),
        ] {
            if let Some(v) = value {
                parts.push(v);
            }
        }
    }
    for value in [
        host.hostname.clone(),
        host.vendor.clone(),
        host.model.clone(),
        host.device_type.clone(),
    ] {
        if let Some(v) = value {
            parts.push(v);
        }
    }
    parts.extend(host.protocols.clone());
    parts.join(" ").to_ascii_lowercase()
}

fn contains_any(text: &str, words: &[String]) -> bool {
    words.iter().any(|w| {
        let w = w.trim().to_ascii_lowercase();
        !w.is_empty() && text.contains(&w)
    })
}

pub fn match_host(
    host: &HostResult,
    ports: &[PortResult],
    limit: usize,
    min_severity: Severity,
    explicit_db: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let db = load(explicit_db);
    let text = fingerprint_text(host, ports);
    let open_ports: Vec<u16> = ports.iter().filter(|p| p.open).map(|p| p.port).collect();
    let hints = versions(&text);
    let host_vendor = host.vendor.as_deref().unwrap_or("").to_ascii_lowercase();

    for e in db {
        let severity = Severity::parse(&e.severity);
        if severity < min_severity {
            continue;
        }
        if let Some(words) = &e.exclude_keywords {
            if contains_any(&text, words) {
                continue;
            }
        }

        let mut confidence = "medium";
        let mut matched = false;

        if let Some(affected) = &e.affected {
            for a in affected {
                let product = a.product.to_ascii_lowercase();
                if hints
                    .iter()
                    .any(|(p, v)| *p == product && version_lt(v, &a.below))
                {
                    matched = true;
                    confidence = "high";
                    break;
                }
            }
        } else {
            let mut kw_hit = e
                .keywords
                .as_ref()
                .map(|k| contains_any(&text, k))
                .unwrap_or(false);
            if !kw_hit {
                if let Some(product) = &e.product {
                    kw_hit = text.contains(&product.to_ascii_lowercase());
                }
            }
            let all_hit = e
                .all_keywords
                .as_ref()
                .map(|k| !k.is_empty() && k.iter().all(|w| text.contains(&w.to_ascii_lowercase())))
                .unwrap_or(true);
            let port_hit = e
                .ports
                .as_ref()
                .map(|ps| ps.iter().any(|p| open_ports.contains(p)))
                .unwrap_or(false);
            let type_hit = e
                .device_types
                .as_ref()
                .map(|types| {
                    types.iter().any(|t| {
                        text.contains(&t.to_ascii_lowercase())
                            || host
                                .device_type
                                .as_deref()
                                .map(|d| d.to_ascii_lowercase().contains(&t.to_ascii_lowercase()))
                                .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            let has_signal = e.keywords.is_some() || e.ports.is_some() || e.device_types.is_some();
            if has_signal && all_hit {
                if e.ports.is_none() && e.keywords.is_none() {
                    // Device-class-only entries must be gated by the class.
                    matched = type_hit;
                } else {
                    matched = (e.keywords.is_none() || kw_hit) && (e.ports.is_none() || port_hit);
                }
                if matched {
                    let vendor_match = e
                        .vendor
                        .as_ref()
                        .map(|v| {
                            let v = v.to_ascii_lowercase();
                            !host_vendor.is_empty()
                                && (text.contains(&v) || host_vendor.contains(&v))
                        })
                        .unwrap_or(false);
                    confidence = if kw_hit && port_hit && (vendor_match || type_hit) {
                        "high"
                    } else {
                        "medium"
                    };
                }
            }
        }

        if matched {
            let mut finding = Finding::new(&e.id, &e.severity, &e.title, e.detail.clone());
            finding.cve = e.cve.clone();
            finding.cvss = e.cvss;
            finding.confidence = Some(confidence.into());
            finding.reference = e.reference.clone();
            findings.push(finding);
        }
    }

    findings.sort_by(|a, b| {
        b.cvss
            .unwrap_or(0.0)
            .partial_cmp(&a.cvss.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.rank().cmp(&a.rank()))
            .then_with(|| a.id.cmp(&b.id))
    });
    if limit > 0 && findings.len() > limit {
        findings.truncate(limit);
    }
    findings
}

/// Findings derived from an exposed port alone, independent of any CVE database.
pub fn weak_services(ports: &[PortResult], min_severity: Severity) -> Vec<Finding> {
    let mut out = Vec::new();
    let table: &[(u16, &str, &str, &str)] = &[
        (
            21,
            "FTP_PLAINTEXT",
            "low",
            "FTP control channel exposed (cleartext)",
        ),
        (
            23,
            "TELNET_PLAINTEXT",
            "high",
            "Telnet exposed (cleartext management)",
        ),
        (
            2323,
            "TELNET_PLAINTEXT",
            "high",
            "Telnet exposed (cleartext management)",
        ),
        (161, "SNMP_EXPOSED", "medium", "SNMP agent exposed"),
        (502, "MODBUS_EXPOSED", "high", "Modbus/TCP exposed"),
        (1883, "MQTT_EXPOSED", "high", "MQTT broker exposed"),
        (1900, "UPNP_EXPOSED", "medium", "UPnP SSDP exposed"),
        (2375, "DOCKER_EXPOSED", "critical", "Docker API exposed"),
        (2376, "DOCKER_TLS", "medium", "Docker TLS endpoint exposed"),
        (
            2404,
            "IEC104_EXPOSED",
            "high",
            "IEC 60870-5-104 control channel exposed",
        ),
        (445, "SMB_EXPOSED", "medium", "SMB service exposed"),
        (44818, "ETHERNET_IP_EXPOSED", "high", "EtherNet/IP exposed"),
        (47808, "BACNET_EXPOSED", "high", "BACnet exposed"),
        (554, "RTSP_EXPOSED", "medium", "RTSP exposed"),
        (5683, "COAP_EXPOSED", "medium", "CoAP endpoint exposed"),
        (5900, "VNC_EXPOSED", "high", "VNC remote desktop exposed"),
        (5984, "COUCHDB_EXPOSED", "high", "CouchDB exposed"),
        (6379, "REDIS_EXPOSED", "critical", "Redis exposed"),
        (7547, "TR069_EXPOSED", "medium", "TR-069/CWMP exposed"),
        (8554, "RTSP_EXPOSED", "medium", "RTSP exposed"),
        (9200, "ELASTIC_EXPOSED", "high", "Elasticsearch API exposed"),
        (
            9300,
            "ELASTIC_EXPOSED",
            "high",
            "Elasticsearch transport exposed",
        ),
        (11211, "MEMCACHED_EXPOSED", "high", "Memcached exposed"),
        (27017, "MONGODB_EXPOSED", "critical", "MongoDB exposed"),
        (3389, "RDP_EXPOSED", "medium", "RDP exposed"),
        (
            5555,
            "ADB_EXPOSED",
            "critical",
            "Android Debug Bridge exposed",
        ),
        (
            49152,
            "UPNP_EXPOSED",
            "medium",
            "UPnP SOAP endpoint exposed",
        ),
        (
            52869,
            "UPNP_EXPOSED",
            "medium",
            "UPnP SOAP endpoint exposed",
        ),
    ];
    let mut seen = std::collections::HashSet::new();
    for p in ports {
        if !p.open {
            continue;
        }
        for (port, id, sev, title) in table {
            if *port == p.port && Severity::parse(sev) >= min_severity && seen.insert((*id, p.port))
            {
                out.push(Finding::new(id, sev, title, format!("port {}", p.port)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(vendor: &str, device: &str) -> HostResult {
        HostResult {
            ip: "192.168.1.10".parse().unwrap(),
            hostname: None,
            mac: None,
            vendor: Some(vendor.into()),
            model: None,
            ports: vec![],
            protocols: vec![],
            device_type: Some(device.into()),
            findings: vec![],
        }
    }

    fn port(port: u16, banner: &str) -> PortResult {
        PortResult {
            port,
            open: true,
            service: None,
            banner: Some(banner.into()),
            tls: false,
            server: None,
            title: None,
        }
    }

    #[test]
    fn embedded_db_is_valid() {
        let db = decode(CVE_DB).unwrap();
        assert!(!db.is_empty());
        for e in &db {
            assert!(!e.id.is_empty());
            assert!(!e.title.is_empty());
        }
    }

    #[test]
    fn keyword_and_port_match() {
        let h = host("Hikvision", "ip camera");
        let ports = vec![port(80, "Hikvision-Webs 4.0")];
        let findings = match_host(&h, &ports, 0, Severity::Info, None);
        assert!(findings.iter().any(|f| f.id == "CVE-2021-36260"));
    }

    #[test]
    fn version_constraint() {
        let h = host("Apache", "web server");
        let old = vec![port(80, "Apache/2.4.49 (Ubuntu)")];
        let new = vec![port(80, "Apache/2.4.51 (Ubuntu)")];
        let a = match_host(&h, &old, 0, Severity::Info, None);
        let b = match_host(&h, &new, 0, Severity::Info, None);
        assert!(a.iter().any(|f| f.id == "CVE-2021-41773"));
        assert!(!b.iter().any(|f| f.id == "CVE-2021-41773"));
    }

    #[test]
    fn weak_service_severity_filter() {
        let ports = vec![port(23, "BusyBox")];
        assert!(weak_services(&ports, Severity::High).len() == 1);
        assert!(weak_services(&ports, Severity::Critical).is_empty());
    }
}
