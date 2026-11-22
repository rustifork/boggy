use crate::types::Finding;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

fn b64(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let a = bytes[i] as usize;
        let b = if i+1 < bytes.len() { bytes[i+1] as usize } else { 0 };
        let c = if i+2 < bytes.len() { bytes[i+2] as usize } else { 0 };
        out.push(T[a >> 2] as char);
        out.push(T[((a & 3) << 4) | (b >> 4)] as char);
        if i + 1 < bytes.len() { out.push(T[((b & 15) << 2) | (c >> 6)] as char); } else { out.push('='); }
        if i + 2 < bytes.len() { out.push(T[c & 63] as char); } else { out.push('='); }
        i += 3;
    }
    out
}

pub fn http_default_creds(ip: std::net::Ipv4Addr, port: u16, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let to = Duration::from_millis(timeout_ms);
    let addr = (ip, port);
    // first unauth
    let unauth = http_get(ip, port, None, to);
    let needs_auth = unauth.as_ref().map(|r| r.starts_with("HTTP/1.1 401") || r.starts_with("HTTP/1.0 401")).unwrap_or(false);
    if !needs_auth { return findings; }
    let pairs = [
        ("admin","admin"), ("admin",""), ("admin","1234"), ("admin","password"),
        ("root","root"), ("root",""), ("root","admin"), ("user","user"),
        ("admin","12345"), ("guest","guest"), ("admin","admin123"),
        ("admin","123456"), ("ubnt","ubnt"), ("pi","raspberry"),
        ("admin","0000"), ("service","service"), ("support","support"),
    ];
    for (u, p) in pairs.iter() {
        let cred = format!("{}:{}", u, p);
        if let Some(resp) = http_get(ip, port, Some(&cred), to) {
            if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
                findings.push(Finding {
                    id: "DEFAULT_CREDS_HTTP".into(),
                    severity: "critical".into(),
                    title: "Default HTTP credentials accepted".into(),
                    detail: format!("{}:{} on {}:{}", u, p, ip, port),
                    cve: None,
                });
                break;
            }
        }
    }
    let _ = addr;
    findings
}

fn http_get(ip: std::net::Ipv4Addr, port: u16, cred: Option<&str>, to: Duration) -> Option<String> {
    let mut stream = TcpStream::connect((ip, port)).ok()?;
    let _ = stream.set_read_timeout(Some(to));
    let _ = stream.set_write_timeout(Some(to));
    let auth = match cred {
        Some(c) => format!("Authorization: Basic {}\r\n", b64(c)),
        None => String::new(),
    };
    let req = format!("GET / HTTP/1.0\r\nHost: {}\r\n{}\r\n", ip, auth);
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = [0u8; 2048];
    let mut total = Vec::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => { total.extend_from_slice(&buf[..n]); if total.len() > 4096 { break; } }
            Err(_) => break,
        }
    }
    Some(String::from_utf8_lossy(&total).to_string())
}

pub fn mqtt_anonymous(ip: std::net::Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let to = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect((ip, port)).ok()?;
    let _ = stream.set_read_timeout(Some(to));
    let _ = stream.set_write_timeout(Some(to));
    // CONNECT packet: protocol name MQTT (level 4), connect flags 0 (no auth), keepalive 60
    let mut pkt = Vec::new();
    // variable header
    let mut vh = Vec::new();
    vh.extend_from_slice(&[0x00, 0x04]); // length
    vh.extend_from_slice(b"MQTT");
    vh.push(0x04); // level 4
    vh.push(0x00); // flags (no auth, no will)
    vh.extend_from_slice(&[0x00, 0x3c]); // keepalive 60
    // payload client id
    let cid = b"boggy";
    vh.extend_from_slice(&[0x00, cid.len() as u8]);
    vh.extend_from_slice(cid);
    // fixed header
    pkt.push(0x10);
    // remaining length
    encode_remaining(&mut pkt, vh.len());
    pkt.extend_from_slice(&vh);
    stream.write_all(&pkt).ok()?;
    let mut buf = [0u8; 4];
    let n = stream.read(&mut buf).ok()?;
    if n >= 2 && buf[0] == 0x20 && buf[3] == 0x00 {
        return Some(Finding {
            id: "MQTT_ANON".into(),
            severity: "high".into(),
            title: "MQTT broker allows anonymous access".into(),
            detail: format!("{}:{}", ip, port),
            cve: None,
        });
    }
    None
}

fn encode_remaining(buf: &mut Vec<u8>, mut len: usize) {
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 { byte |= 0x80; }
        buf.push(byte);
        if len == 0 { break; }
    }
}

pub fn coap_probe(ip: std::net::Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    // CoAP GET /.well-known/core, CON, msgid 0x1234, token empty
    let req = [0x40, 0x01, 0x12, 0x34, 0xbb, b'.', b'w', b'e', b'l', b'l', b'-', b'k', b'n', b'o', b'w', b'n', 0x04, 0x63, 0x6f, 0x72, 0x65];
    let _ = sock.send_to(&req, (ip, port));
    let mut buf = [0u8; 512];
    if let Ok((n, _)) = sock.recv_from(&mut buf) {
        if n > 0 {
            return Some(Finding {
                id: "COAP_OPEN".into(),
                severity: "medium".into(),
                title: "CoAP endpoint responds without auth".into(),
                detail: format!("{}:{}", ip, port),
                cve: None,
            });
        }
    }
    None
}

pub fn telnet_finding(port: u16) -> Option<Finding> {
    if port == 23 || port == 2323 {
        Some(Finding {
            id: "TELNET_EXPOSED".into(),
            severity: "high".into(),
            title: "Telnet service exposed (cleartext)".into(),
            detail: format!("port {}", port),
            cve: None,
        })
    } else { None }
}

pub fn rtsp_finding(ip: std::net::Ipv4Addr, port: u16, timeout_ms: u64) -> Option<Finding> {
    let to = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect((ip, port)).ok()?;
    let _ = stream.set_read_timeout(Some(to));
    let req = format!("OPTIONS rtsp://{}:{}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip, port);
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).ok()?;
    if n > 0 {
        let s = String::from_utf8_lossy(&buf[..n]);
        if s.contains("200 OK") {
            return Some(Finding {
                id: "RTSP_OPEN".into(),
                severity: "medium".into(),
                title: "RTSP stream may be accessible".into(),
                detail: format!("{}:{}", ip, port),
                cve: None,
            });
        }
    }
    None
}