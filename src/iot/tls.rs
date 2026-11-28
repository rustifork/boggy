//! Optional TLS certificate fingerprinting via the system `openssl` client.
//! No TLS library is linked into boggy; this is an opt-in, bounded probe.

use crate::types::Finding;
use std::net::IpAddr;
use std::process::{Command, Stdio};

#[derive(Clone, Debug, Default)]
pub struct TlsInfo {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub verify: Option<String>,
    pub protocol: Option<String>,
}

fn host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => format!("[{}]", v),
    }
}

fn value(line: &str, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(pos) = line.find(name) {
            let rest = &line[pos + name.len()..];
            let value = rest.trim().trim_start_matches(':').trim();
            if !value.is_empty() {
                return Some(value.chars().take(180).collect());
            }
        }
    }
    None
}

pub fn probe(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<TlsInfo> {
    let secs = (timeout_ms.clamp(200, 5000) / 1000).max(1);
    let target = format!("{}:{}", host(ip), port);
    let mut cmd = Command::new("timeout");
    cmd.arg(secs.to_string())
        .arg("openssl")
        .args(["s_client", "-connect", &target, "-servername"])
        .arg(ip.to_string())
        .args(["-brief"])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut info = TlsInfo::default();
    for line in text.lines() {
        if info.subject.is_none() {
            info.subject = value(
                line,
                &["subject=", "Peer certificate:", "Peer certificate: "],
            );
        }
        if info.issuer.is_none() {
            info.issuer = value(line, &["issuer=", "Issuer:"]);
        }
        if info.verify.is_none() {
            info.verify = value(line, &["Verify return code:", "Verification:"]);
        }
        if info.protocol.is_none() {
            info.protocol = value(line, &["Protocol version:", "New, "]);
        }
    }
    if info.subject.is_none() && info.issuer.is_none() {
        return None;
    }
    Some(info)
}

pub fn findings(ip: IpAddr, port: u16, info: &TlsInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    if let (Some(subject), Some(issuer)) = (&info.subject, &info.issuer) {
        out.push(Finding::new(
            "TLS_CERT",
            "info",
            "TLS certificate disclosed",
            format!("{}:{} subject={} issuer={}", ip, port, subject, issuer),
        ));
    }
    if let Some(verify) = &info.verify {
        if !verify.starts_with("0") && !verify.eq_ignore_ascii_case("OK") {
            let mut f = Finding::new(
                "TLS_UNTRUSTED",
                "medium",
                "TLS certificate failed verification",
                format!("{}:{} - {}", ip, port, verify),
            );
            f.confidence = Some("high".into());
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_brief_output() {
        let text = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nPeer certificate: CN=camera.local\nIssuer: CN=camera.local\nVerification: OK\n";
        let mut info = TlsInfo::default();
        for line in text.lines() {
            if info.subject.is_none() {
                info.subject = value(line, &["subject=", "Peer certificate:"]);
            }
            if info.issuer.is_none() {
                info.issuer = value(line, &["issuer=", "Issuer:"]);
            }
            if info.verify.is_none() {
                info.verify = value(line, &["Verify return code:", "Verification:"]);
            }
            if info.protocol.is_none() {
                info.protocol = value(line, &["Protocol version:"]);
            }
        }
        assert_eq!(info.subject.as_deref(), Some("CN=camera.local"));
        assert_eq!(info.verify.as_deref(), Some("OK"));
        assert_eq!(info.protocol.as_deref(), Some("TLSv1.3"));
    }
}
