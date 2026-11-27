//! Small, targeted probes for the protocols that dominate IoT networks.
//! Each probe is a handful of packets, never a full protocol implementation.

use crate::net::http::{self, HttpRequest, HttpResponse};
use crate::types::Finding;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

fn tcp(ip: Ipv4Addr, port: u16, to: Duration) -> Option<TcpStream> {
    let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
    let s = TcpStream::connect_timeout(&addr, to).ok()?;
    let _ = s.set_read_timeout(Some(to));
    let _ = s.set_write_timeout(Some(to));
    Some(s)
}

fn f(id: &str, sev: &str, title: &str, detail: impl Into<String>) -> Finding {
    Finding::new(id, sev, title, detail)
}

// --- SNMPv1/v2c community strings ------------------------------------------------

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let len = (content.len() as u16).to_be_bytes();
        out.push(0x82);
        out.extend_from_slice(&len);
    }
    out.extend_from_slice(content);
    out
}

fn ber_int(mut value: u32) -> Vec<u8> {
    let mut bytes = vec![(value & 0xff) as u8];
    value >>= 8;
    while value > 0 {
        bytes.insert(0, (value & 0xff) as u8);
        value >>= 8;
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

fn ber_oid(parts: &[u32]) -> Vec<u8> {
    let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
    for &p in &parts[2..] {
        let mut v = p;
        let mut group = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            group.insert(0, ((v & 0x7f) | 0x80) as u8);
            v >>= 7;
        }
        body.extend_from_slice(&group);
    }
    tlv(0x06, &body)
}

fn get_request(community: &str, version: u8) -> Vec<u8> {
    let oid = ber_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    let mut var = oid;
    var.extend_from_slice(&[0x05, 0x00]);
    let var = tlv(0x30, &var);
    let mut pdu = ber_int(0x1234);
    pdu.extend_from_slice(&ber_int(0));
    pdu.extend_from_slice(&ber_int(0));
    pdu.extend_from_slice(&tlv(0x30, &var));
    let mut body = ber_int(version as u32);
    body.extend_from_slice(&tlv(0x04, community.as_bytes()));
    body.extend_from_slice(&tlv(0xa0, &pdu));
    tlv(0x30, &body)
}

struct Ber<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Ber<'a> {
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        if self.pos + 2 > self.buf.len() {
            return None;
        }
        let tag = self.buf[self.pos];
        let mut len = self.buf[self.pos + 1] as usize;
        let mut head = 2;
        if len & 0x80 != 0 {
            let n = len & 0x7f;
            if n == 0 || n > 2 || self.pos + 2 + n > self.buf.len() {
                return None;
            }
            len = 0;
            for i in 0..n {
                len = (len << 8) | self.buf[self.pos + 2 + i] as usize;
            }
            head += n;
        }
        if self.pos + head + len > self.buf.len() {
            return None;
        }
        let content = &self.buf[self.pos + head..self.pos + head + len];
        self.pos += head + len;
        Some((tag, content))
    }
}

fn snmp_sysdescr(data: &[u8]) -> Option<String> {
    let mut top = Ber { buf: data, pos: 0 };
    let (tag, body) = top.next()?;
    if tag != 0x30 {
        return None;
    }
    let mut reader = Ber { buf: body, pos: 0 };
    reader.next()?; // version
    reader.next()?; // community
    let (pdu_tag, pdu) = reader.next()?;
    if pdu_tag != 0xa2 {
        return None;
    }
    let mut pdu_reader = Ber { buf: pdu, pos: 0 };
    pdu_reader.next()?;
    pdu_reader.next()?;
    pdu_reader.next()?;
    let (_, vars) = pdu_reader.next()?;
    let mut vars_reader = Ber { buf: vars, pos: 0 };
    loop {
        let (t, content) = vars_reader.next()?;
        if t != 0x30 {
            return None;
        }
        let mut var = Ber {
            buf: content,
            pos: 0,
        };
        var.next()?; // oid
        if let Some((0x04, value)) = var.next() {
            let s = String::from_utf8_lossy(value).trim().to_string();
            if !s.is_empty() {
                return Some(s.chars().take(160).collect());
            }
        }
    }
}

pub fn snmp_probe(ip: Ipv4Addr, community: &str, timeout_ms: u64) -> Option<Finding> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let to = Duration::from_millis(timeout_ms.clamp(80, 250));
    let _ = sock.set_read_timeout(Some(to));
    let mut buf = [0u8; 2048];
    for version in [1u8, 0u8] {
        let packet = get_request(community, version);
        if sock.send_to(&packet, (ip, 161u16)).is_err() {
            return None;
        }
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            if let Some(descr) = snmp_sysdescr(&buf[..n]) {
                let mut out = f(
                    "SNMP_DEFAULT_COMMUNITY",
                    "high",
                    "SNMP agent accepts a default community string",
                    format!("community '{}' on {}:161 - {}", community, ip, descr),
                );
                out.confidence = Some("high".into());
                return Some(out);
            }
        }
    }
    None
}

// --- Cleartext / unauthenticated management services -----------------------------

pub fn redis_probe(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let mut s = tcp(ip, port, Duration::from_millis(timeout_ms.max(100)))?;
    s.write_all(b"PING\r\n").ok()?;
    let mut buf = [0u8; 512];
    let n = s.read(&mut buf).ok()?;
    let reply = String::from_utf8_lossy(&buf[..n]);
    if !reply.starts_with("+PONG") {
        return None;
    }
    let mut detail = format!("{}:{} answers PING without authentication", ip, port);
    let _ = s.write_all(b"INFO server\r\n");
    let mut info = [0u8; 1024];
    if let Ok(n) = s.read(&mut info) {
        let text = String::from_utf8_lossy(&info[..n]);
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("redis_version:") {
                detail.push_str(&format!(" (Redis {})", v.trim()));
                break;
            }
        }
    }
    Some(f(
        "REDIS_NO_AUTH",
        "critical",
        "Redis exposed without authentication",
        detail,
    ))
}

pub fn memcached_probe(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let mut s = tcp(ip, port, Duration::from_millis(timeout_ms.max(100)))?;
    s.write_all(b"stats\r\n").ok()?;
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    if text.contains("STAT ") && (text.contains("version") || text.contains("uptime")) {
        Some(f(
            "MEMCACHED_OPEN",
            "high",
            "Memcached stats exposed without authentication",
            format!("{}:{}", ip, port),
        ))
    } else {
        None
    }
}

pub fn adb_probe(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let mut s = tcp(ip, port, Duration::from_millis(timeout_ms.max(100)))?;
    s.write_all(b"000chost:version").ok()?;
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf).ok()?;
    if n >= 4 && &buf[..4] == b"OKAY" {
        Some(f(
            "ADB_OPEN",
            "critical",
            "Android Debug Bridge exposed without authentication",
            format!("{}:{}", ip, port),
        ))
    } else {
        None
    }
}

pub fn mqtt_anonymous(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let to = Duration::from_millis(timeout_ms.max(100));
    let mut stream = tcp(ip, port, to)?;
    let mut vh = Vec::new();
    vh.extend_from_slice(&[0x00, 0x04]);
    vh.extend_from_slice(b"MQTT");
    vh.push(0x04);
    vh.push(0x00);
    vh.extend_from_slice(&[0x00, 0x3c]);
    let cid = b"boggy";
    vh.extend_from_slice(&[0x00, cid.len() as u8]);
    vh.extend_from_slice(cid);
    let mut pkt = vec![0x10];
    let mut len = vh.len();
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        pkt.push(byte);
        if len == 0 {
            break;
        }
    }
    pkt.extend_from_slice(&vh);
    stream.write_all(&pkt).ok()?;
    let mut buf = [0u8; 8];
    let n = stream.read(&mut buf).ok()?;
    if n >= 4 && buf[0] == 0x20 && buf[1] == 0x02 && buf[3] == 0x00 {
        Some(f(
            "MQTT_ANON",
            "high",
            "MQTT broker allows anonymous access",
            format!("{}:{}", ip, port),
        ))
    } else {
        None
    }
}

pub fn coap_probe(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms.max(150))));
    let req = [
        0x40, 0x01, 0x12, 0x34, 0xbb, b'.', b'w', b'e', b'l', b'l', b'-', b'k', b'n', b'o', b'w',
        b'n', 0x04, b'c', b'o', b'r', b'e',
    ];
    let _ = sock.send_to(&req, (ip, port));
    let mut buf = [0u8; 512];
    if let Ok((n, _)) = sock.recv_from(&mut buf) {
        // CoAP header: ver(2) type(2) TKL(4), code, mid. A valid response has
        // version 1 and a non-zero code; random UDP noise must not match.
        if n > 4 && buf[0] >> 6 == 1 && buf[1] != 0 {
            return Some(f(
                "COAP_OPEN",
                "medium",
                "CoAP endpoint responds without auth",
                format!("{}:{}", ip, port),
            ));
        }
    }
    None
}

pub fn rtsp_request(
    ip: Ipv4Addr,
    port: u16,
    method: &str,
    path: &str,
    auth: Option<&str>,
    timeout_ms: u64,
) -> Option<HttpResponse> {
    let mut headers = vec![
        ("CSeq".to_string(), "1".to_string()),
        (
            "User-Agent".to_string(),
            format!("boggy/{}", env!("CARGO_PKG_VERSION")),
        ),
    ];
    if let Some(value) = auth {
        headers.push(("Authorization".to_string(), value.to_string()));
    }
    http::raw_request(
        ip,
        port,
        &format!("{} {} RTSP/1.0", method, path),
        &headers,
        &[],
        timeout_ms,
    )
}

pub fn rtsp_probe(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let path = format!("rtsp://{}:{}/", ip, port);
    let resp = rtsp_request(ip, port, "OPTIONS", &path, None, timeout_ms)?;
    if resp.status == 200 || resp.body_text().contains("200 OK") {
        Some(f(
            "RTSP_OPEN",
            "medium",
            "RTSP stream accessible without authentication",
            format!("{}:{}", ip, port),
        ))
    } else {
        None
    }
}

pub fn modbus_probe(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let mut s = tcp(ip, port, Duration::from_millis(timeout_ms.max(100)))?;
    let pdu: &[u8] = &[0x2b, 0x0e, 0x01, 0x00];
    let mut packet = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x06, 0x01];
    packet.extend_from_slice(pdu);
    s.write_all(&packet).ok()?;
    let mut buf = [0u8; 512];
    let n = s.read(&mut buf).ok()?;
    if n < 12 || buf[7] != 0x2b || buf[8] != 0x0e {
        return None;
    }
    let mut info = Vec::new();
    for &b in &buf[12..n] {
        if (0x20..0x7f).contains(&b) {
            info.push(b as char);
        }
    }
    let mut out = f(
        "MODBUS_OPEN",
        "high",
        "Modbus device identification readable",
        format!("{}:{} {}", ip, port, info.iter().collect::<String>()),
    );
    out.confidence = Some("high".into());
    Some(out)
}

pub fn http_unauth_api(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    let to = timeout_ms.max(100);
    if port == 2375 {
        if let Some(resp) = http::request(ip, port, &HttpRequest::get("/version"), to) {
            let body = resp.body_text();
            if body.contains("ApiVersion") || body.contains("\"Version\"") {
                out.push(f(
                    "DOCKER_UNAUTH",
                    "critical",
                    "Docker daemon unauthenticated",
                    format!(
                        "{}:{} - {}",
                        ip,
                        port,
                        body.chars().take(80).collect::<String>()
                    ),
                ));
            }
        }
    }
    if port == 9200 || port == 9300 {
        if let Some(resp) = http::request(ip, port, &HttpRequest::get("/"), to) {
            let body = resp.body_text();
            if body.contains("cluster_name") || body.contains("\"tagline\"") {
                out.push(f(
                    "ELASTICSEARCH_OPEN",
                    "high",
                    "Elasticsearch API exposed without authentication",
                    format!("{}:{}", ip, port),
                ));
            }
        }
    }
    if port == 7547 {
        if let Some(resp) = http::request(ip, port, &HttpRequest::get("/"), to) {
            let body = resp.body_text().to_ascii_lowercase();
            if body.contains("cwmp") || body.contains("tr-069") || body.contains("cpe") {
                out.push(f(
                    "TR069_EXPOSED",
                    "medium",
                    "TR-069/CWMP management interface exposed",
                    format!("{}:{}", ip, port),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_packet_layout() {
        let p = get_request("public", 1);
        assert_eq!(p[0], 0x30);
        assert_eq!(p[1] & 0x80, 0);
        assert!(p.windows(6).any(|w| w == b"public"));
    }

    #[test]
    fn snmp_response_parser() {
        // minimal get-response with one OCTET STRING varbind
        let mut var = ber_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        var.extend_from_slice(&tlv(0x04, b"Linux router 5.4"));
        let mut vars = tlv(0x30, &var);
        let mut pdu = ber_int(0x1234);
        pdu.extend_from_slice(&ber_int(0));
        pdu.extend_from_slice(&ber_int(0));
        pdu.extend_from_slice(&tlv(0x30, &vars));
        vars = tlv(0xa2, &pdu);
        let mut body = ber_int(1);
        body.extend_from_slice(&tlv(0x04, b"public"));
        body.extend_from_slice(&vars);
        let packet = tlv(0x30, &body);
        assert_eq!(snmp_sysdescr(&packet).as_deref(), Some("Linux router 5.4"));
    }

    #[test]
    fn oid_encoding() {
        assert_eq!(ber_oid(&[1, 3, 6, 1]), tlv(0x06, &[0x2b, 0x06, 0x01]));
    }
}
