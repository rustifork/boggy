use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct MdnsEntry {
    pub ip: Ipv4Addr,
    pub name: Option<String>,
    pub txt: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SsdpEntry {
    pub ip: Ipv4Addr,
    pub location: Option<String>,
    pub server: Option<String>,
    pub search_target: Option<String>,
}

/// Liveness probing over an explicit port set, so devices that only expose a
/// custom port are not dropped before the real scan starts.
pub fn tcp_alive_ports(ip: Ipv4Addr, timeout_ms: u64, ports: &[u16]) -> bool {
    let to = Duration::from_millis(timeout_ms.clamp(30, 150));
    for &port in ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        if TcpStream::connect_timeout(&addr, to).is_ok() {
            return true;
        }
    }
    false
}

/// Populate the kernel ARP cache with unprivileged UDP sends, then read /proc/net/arp.
/// Devices that answer no TCP probe still show up with a MAC address.
pub fn arp_sweep(hosts: &[Ipv4Addr]) {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    for ip in hosts {
        let _ = sock.send_to(&[0u8; 4], (*ip, 9));
    }
    std::thread::sleep(Duration::from_millis(180));
}

fn ptr_query(service: &[u8]) -> Vec<u8> {
    // header: ID=0, flags=0, QD=1
    let mut q = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in service.split(|b| *b == b'.') {
        if label.is_empty() {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label);
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]);
    q
}

fn read_dns_name(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_off = off;
    let mut guard = 0;
    loop {
        if guard > 64 {
            return None;
        }
        guard += 1;
        if off >= buf.len() {
            return None;
        }
        let len = buf[off] as usize;
        if len == 0 {
            off += 1;
            if !jumped {
                next_off = off;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if off + 1 >= buf.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | buf[off + 1] as usize;
            if !jumped {
                next_off = off + 2;
            }
            off = ptr;
            jumped = true;
            continue;
        }
        off += 1;
        if off + len > buf.len() {
            return None;
        }
        match std::str::from_utf8(&buf[off..off + len]) {
            Ok(s) => labels.push(s.to_string()),
            Err(_) => return None,
        }
        off += len;
    }
    let name = labels.join(".");
    if name.is_empty() {
        None
    } else {
        Some((name, next_off))
    }
}

pub fn mdns_scan(timeout_ms: u64) -> Vec<MdnsEntry> {
    let mut out = Vec::new();
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    let queries: &[&[u8]] = &[
        b"_services._dns-sd._udp.local",
        b"_http._tcp.local",
        b"_hap._tcp.local",
        b"_ipp._tcp.local",
        b"_mqtt._tcp.local",
        b"_googlecast._tcp.local",
    ];
    for q in queries {
        let packet = ptr_query(q);
        let _ = sock.send_to(&packet, "224.0.0.251:5353");
    }

    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(300));
    while Instant::now() < deadline {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => break,
        };
        let ip = match src.ip() {
            IpAddr::V4(v) => v,
            _ => continue,
        };
        let packet = &buf[..n];
        let mut name = None;
        let mut txt: Vec<String> = Vec::new();
        if packet.len() >= 12 {
            let qd = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
            let ns = u16::from_be_bytes([packet[8], packet[9]]) as usize;
            let ar = u16::from_be_bytes([packet[10], packet[11]]) as usize;
            let mut off = 12usize;
            for _ in 0..qd {
                match read_dns_name(packet, off) {
                    Some((_, no)) => off = no + 4,
                    None => break,
                }
            }
            for _ in 0..(an + ns + ar) {
                if off >= packet.len() {
                    break;
                }
                let (owner, no) = match read_dns_name(packet, off) {
                    Some(x) => x,
                    None => break,
                };
                off = no;
                if off + 10 > packet.len() {
                    break;
                }
                let rtype = u16::from_be_bytes([packet[off], packet[off + 1]]);
                let rdlen = u16::from_be_bytes([packet[off + 8], packet[off + 9]]) as usize;
                let rdata_off = off + 10;
                if rtype == 1 && rdlen == 4 && rdata_off + 4 <= packet.len() {
                    if owner.ends_with(".local") || owner.contains('.') {
                        if name.is_none() {
                            name = Some(owner.clone());
                        }
                    }
                }
                if rtype == 16 && rdata_off + rdlen <= packet.len() {
                    let mut p = rdata_off;
                    let end = rdata_off + rdlen;
                    while p < end {
                        let len = packet[p] as usize;
                        p += 1;
                        if p + len > end {
                            break;
                        }
                        if let Ok(value) = std::str::from_utf8(&packet[p..p + len]) {
                            if !value.is_empty() {
                                txt.push(value.to_string());
                            }
                        }
                        p += len;
                    }
                }
                if rtype == 12 && rdata_off < packet.len() {
                    if let Some((ptrname, _)) = read_dns_name(packet, rdata_off) {
                        if name.is_none() && (ptrname.contains(".local") || ptrname.contains('_')) {
                            name = Some(ptrname);
                        }
                    }
                }
                off = rdata_off + rdlen;
                if off > packet.len() {
                    break;
                }
            }
        }
        if name.is_none() {
            let text = String::from_utf8_lossy(packet);
            for token in
                text.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_')
            {
                if token.contains(".local") && token.len() > 4 {
                    name = Some(token.to_string());
                    break;
                }
            }
        }
        out.push(MdnsEntry { ip, name, txt });
    }
    let mut map: BTreeMap<Ipv4Addr, MdnsEntry> = BTreeMap::new();
    for e in out {
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
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    for st in [
        "ssdp:all",
        "upnp:rootdevice",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    ] {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {}\r\n\r\n",
            st
        );
        let _ = sock.send_to(msg.as_bytes(), "239.255.255.250:1900");
    }

    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(300));
    while Instant::now() < deadline {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => break,
        };
        let ip = match src.ip() {
            IpAddr::V4(v) => v,
            _ => continue,
        };
        let text = String::from_utf8_lossy(&buf[..n]);
        let mut entry = SsdpEntry {
            ip,
            location: None,
            server: None,
            search_target: None,
        };
        for line in text.lines() {
            let l = line.trim();
            let (key, value) = match l.split_once(':') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
                None => continue,
            };
            match key.as_str() {
                "location" => entry.location = Some(value),
                "server" => entry.server = Some(value),
                "st" => entry.search_target = Some(value),
                _ => {}
            }
        }
        out.push(entry);
    }
    out
}

pub fn arp_table() -> BTreeMap<Ipv4Addr, String> {
    let mut map = BTreeMap::new();
    if let Ok(s) = std::fs::read_to_string("/proc/net/arp") {
        for line in s.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    let mac = parts[3];
                    if mac != "00:00:00:00:00:00" && mac.contains(':') {
                        map.insert(ip, mac.to_string());
                    }
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::ptr_query;

    #[test]
    fn dns_query_layout() {
        let q = ptr_query(b"_hap._tcp.local");
        assert_eq!(q.len(), 12 + 5 + 5 + 6 + 1 + 4);
        assert_eq!(&q[0..4], &[0, 0, 0, 0]);
        assert_eq!(q[q.len() - 4..], [0x00, 0x0c, 0x00, 0x01]);
    }
}
