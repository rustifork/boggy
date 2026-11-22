use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct MdnsEntry {
    pub ip: Ipv4Addr,
    pub name: Option<String>,
    pub service: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SsdpEntry {
    pub ip: Ipv4Addr,
    pub location: Option<String>,
    pub server: Option<String>,
    pub st: Option<String>,
}

pub fn tcp_alive(ip: Ipv4Addr, timeout_ms: u64) -> bool {
    let to = Duration::from_millis(timeout_ms.min(500));
    for port in [80u16, 443, 22, 23, 445, 554, 8080] {
        let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
        if TcpStream::connect_timeout(&addr, to).is_ok() {
            return true;
        }
    }
    false
}

pub fn mdns_scan(timeout_ms: u64) -> Vec<MdnsEntry> {
    let mut out = Vec::new();
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    // send query for _services._dns-sd._udp.local
    let query: &[u8] = &[
        0x00,0x00, // id
        0x00,0x00, // flags
        0x00,0x01, // qdcount
        0x00,0x00,0x00,0x00,0x00,0x00,
        // _services._dns-sd._udp.local
        9, b'_',b's',b'e',b'r',b'v',b'i',b'c',b'e',b's',
        7, b'_',b'd',b'n',b's',b'-',b's',b'd',
        4, b'_',b'u',b'd',b'p',
        5, b'l',b'o',b'c',b'a',b'l',
        0,
        0x00,0x0c, // type PTR
        0x00,0x01, // class IN
    ];
    let _ = sock.send_to(query, "224.0.0.251:5353");
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                let ip = match src.ip() {
                    std::net::IpAddr::V4(v) => v,
                    _ => continue,
                };
                // naive parse: extract readable names
                let text = String::from_utf8_lossy(&buf[..n]);
                let mut name = None;
                // find printable runs
                for token in text.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_') {
                    if token.contains(".local") || token.contains("_") {
                        if token.len() > 4 { name = Some(token.to_string()); break; }
                    }
                }
                out.push(MdnsEntry { ip, name, service: None });
            }
            Err(_) => break,
        }
    }
    // dedup by ip
    let mut map: BTreeMap<Ipv4Addr, MdnsEntry> = BTreeMap::new();
    for e in out.drain(..) {
        map.entry(e.ip).or_insert(e);
    }
    map.into_values().collect()
}

pub fn ssdp_scan(timeout_ms: u64) -> Vec<SsdpEntry> {
    let mut out = Vec::new();
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    let _ = sock.send_to(msg.as_bytes(), "239.255.255.250:1900");
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                let ip = match src.ip() {
                    std::net::IpAddr::V4(v) => v,
                    _ => continue,
                };
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                let mut location = None;
                let mut server = None;
                let mut st = None;
                for line in text.lines() {
                    let l = line.trim();
                    if let Some(v) = l.strip_prefix("LOCATION:") { location = Some(v.trim().to_string()); }
                    else if let Some(v) = l.strip_prefix("SERVER:") { server = Some(v.trim().to_string()); }
                    else if let Some(v) = l.strip_prefix("ST:") { st = Some(v.trim().to_string()); }
                }
                out.push(SsdpEntry { ip, location, server, st });
            }
            Err(_) => break,
        }
    }
    out
}

pub fn arp_table() -> std::collections::BTreeMap<Ipv4Addr, String> {
    let mut map = std::collections::BTreeMap::new();
    if let Ok(s) = std::fs::read_to_string("/proc/net/arp") {
        for line in s.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    map.insert(ip, parts[3].to_string());
                }
            }
        }
    }
    map
}