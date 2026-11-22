use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct MdnsEntry {
    pub ip: Ipv4Addr,
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SsdpEntry {
    pub ip: Ipv4Addr,
    pub location: Option<String>,
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

fn read_dns_name(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_off = off;
    let mut guard = 0;
    loop {
        if guard > 64 { return None; }
        guard += 1;
        if off >= buf.len() { return None; }
        let len = buf[off] as usize;
        if len == 0 {
            off += 1;
            if !jumped { next_off = off; }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if off + 1 >= buf.len() { return None; }
            let ptr = ((len & 0x3F) << 8) | (buf[off+1] as usize);
            if !jumped { next_off = off + 2; }
            off = ptr;
            jumped = true;
            continue;
        }
        off += 1;
        if off + len > buf.len() { return None; }
        if let Ok(s) = std::str::from_utf8(&buf[off..off+len]) {
            labels.push(s.to_string());
        } else {
            return None;
        }
        off += len;
    }
    let name = labels.join(".");
    if name.is_empty() { None } else { Some((name, next_off)) }
}

pub fn mdns_scan(timeout_ms: u64) -> Vec<MdnsEntry> {
    let mut out = Vec::new();
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let query: &[u8] = &[
        0x00,0x00,
        0x00,0x00,
        0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,
        9, b'_',b's',b'e',b'r',b'v',b'i',b'c',b'e',b's',
        7, b'_',b'd',b'n',b's',b'-',b's',b'd',
        4, b'_',b'u',b'd',b'p',
        5, b'l',b'o',b'c',b'a',b'l',
        0,
        0x00,0x0c,
        0x00,0x01,
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
                let packet = &buf[..n];
                let mut name = None;
                // parse header
                if packet.len() >= 12 {
                    let qd = u16::from_be_bytes([packet[4], packet[5]]) as usize;
                    let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
                    let ns = u16::from_be_bytes([packet[8], packet[9]]) as usize;
                    let ar = u16::from_be_bytes([packet[10], packet[11]]) as usize;
                    let mut off = 12usize;
                    // skip questions
                    for _ in 0..qd {
                        if let Some((_, no)) = read_dns_name(packet, off) {
                            off = no;
                            off += 4; // qtype + qclass
                        } else { break; }
                    }
                    // answers
                    let total = an + ns + ar;
                    for _ in 0..total {
                        if off >= packet.len() { break; }
                        let (owner, no) = match read_dns_name(packet, off) {
                            Some(x) => x,
                            None => break,
                        };
                        off = no;
                        if off + 10 > packet.len() { break; }
                        let rtype = u16::from_be_bytes([packet[off], packet[off+1]]);
                        // class
                        // ttl
                        let rdlen = u16::from_be_bytes([packet[off+8], packet[off+9]]) as usize;
                        let rdata_off = off + 10;
                        if rtype == 1 && rdlen == 4 && rdata_off + 4 <= packet.len() {
                            // A record: owner name is hostname
                            if owner.ends_with(".local") || owner.contains('.') {
                                if name.is_none() { name = Some(owner.clone()); }
                            }
                        }
                        if rtype == 12 && rdata_off < packet.len() {
                            // PTR: rdata is a name; use as service name if no hostname
                            if let Some((ptrname, _)) = read_dns_name(packet, rdata_off) {
                                if name.is_none() && (ptrname.contains(".local") || ptrname.contains("_")) {
                                    name = Some(ptrname);
                                }
                            }
                        }
                        off = rdata_off + rdlen;
                    }
                }
                // fallback
                if name.is_none() {
                    let text = String::from_utf8_lossy(packet);
                    for token in text.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_') {
                        if token.contains(".local") && token.len() > 4 {
                            name = Some(token.to_string());
                            break;
                        }
                    }
                }
                out.push(MdnsEntry { ip, name });
            }
            Err(_) => break,
        }
    }
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
                for line in text.lines() {
                    let l = line.trim();
                    if let Some(v) = l.strip_prefix("LOCATION:") { location = Some(v.trim().to_string()); }
                }
                out.push(SsdpEntry { ip, location });
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