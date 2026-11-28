use crate::net::http;
use crate::types::PortResult;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// IoT-oriented top ports. Enough to find a device without waking every socket.
pub const FAST_PORTS: &[u16] = &[
    22, 23, 53, 80, 443, 554, 1883, 1900, 5000, 7547, 8000, 8080, 8443, 8888, 9100, 37777, 49152,
];

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 82, 83, 88, 102, 110, 111, 139, 143, 161, 162, 443, 445, 502, 515,
    548, 554, 587, 631, 873, 902, 993, 995, 1080, 1433, 1723, 1883, 1900, 2049, 2181, 2323, 2375,
    2376, 2404, 3306, 3389, 4000, 4840, 5000, 5001, 5060, 5353, 5357, 5432, 5555, 5672, 5683, 5684,
    5900, 5984, 6000, 6379, 7001, 7547, 8000, 8008, 8009, 8080, 8081, 8082, 8083, 8086, 8090, 8123,
    8181, 8443, 8554, 8883, 8888, 9000, 9042, 9090, 9100, 9200, 9300, 9600, 9999, 10000, 10250,
    11211, 20000, 27017, 34567, 37215, 37777, 44818, 47808, 49152, 50000, 52869,
];

pub const DEEP_PORTS: &[u16] = &[
    7, 9, 13, 19, 21, 22, 23, 25, 37, 53, 67, 68, 69, 79, 80, 81, 82, 83, 88, 102, 110, 111, 113,
    123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 427, 443, 445, 464, 500, 502, 512, 513, 514,
    515, 548, 554, 587, 623, 631, 636, 873, 902, 989, 990, 993, 995, 1025, 1080, 1194, 1433, 1434,
    1521, 1701, 1723, 1883, 1900, 2049, 2082, 2083, 2181, 2222, 2323, 2375, 2376, 2404, 2483, 2484,
    3000, 3260, 3306, 3389, 3478, 3479, 4000, 4369, 4443, 4505, 4506, 4840, 5000, 5001, 5060, 5061,
    5353, 5357, 5432, 5555, 5601, 5672, 5683, 5684, 5900, 5984, 6000, 6379, 6443, 7001, 7002, 7443,
    7547, 8000, 8008, 8009, 8080, 8081, 8082, 8083, 8086, 8090, 8123, 8181, 8243, 8333, 8443, 8554,
    8883, 8888, 9000, 9042, 9090, 9100, 9200, 9300, 9418, 9600, 9999, 10000, 10250, 11211, 15672,
    20000, 25565, 27017, 32764, 34567, 37215, 37777, 44818, 47808, 49152, 50000, 50070, 52869,
    55443, 62078,
];

pub fn ports_for(fast: bool, deep: bool) -> &'static [u16] {
    if fast {
        FAST_PORTS
    } else if deep {
        DEEP_PORTS
    } else {
        COMMON_PORTS
    }
}

/// Parse `22,80,443,8000-8010`. Caps the expansion so a typo cannot fork a /59 scan.
pub fn parse_ports(s: &str) -> Option<Vec<u16>> {
    let mut set = BTreeSet::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().ok()?;
            let b: u16 = b.trim().parse().ok()?;
            if a > b || (b as u32 - a as u32) > 4096 {
                return None;
            }
            for p in a..=b {
                set.insert(p);
            }
        } else {
            set.insert(part.parse().ok()?);
        }
        if set.len() > 16384 {
            return None;
        }
    }
    if set.is_empty() {
        None
    } else {
        Some(set.into_iter().collect())
    }
}

/// Connect probes are capped independently of banner reads: a filtered port
/// fails fast, while a chatty device still gets the full read timeout.
fn connect_ms(timeout_ms: u64) -> u64 {
    timeout_ms.clamp(50, 400)
}

pub fn scan_port(ip: IpAddr, port: u16, timeout_ms: u64) -> PortResult {
    let mut res = PortResult {
        port,
        open: false,
        service: guess_service(port),
        banner: None,
        tls: is_tls(port),
        server: None,
        title: None,
    };
    let addr = SocketAddr::new(ip, port);
    let connect = Duration::from_millis(connect_ms(timeout_ms));
    let read = Duration::from_millis(timeout_ms.max(50));
    // One connection does both the liveness check and the banner grab.
    let mut stream = match TcpStream::connect_timeout(&addr, connect) {
        Ok(s) => s,
        Err(_) => return res,
    };
    res.open = true;
    let _ = stream.set_read_timeout(Some(read));
    let _ = stream.set_write_timeout(Some(read));

    if is_http(port) {
        if let Some((banner, server, title)) = http_probe(&mut stream, ip, port) {
            res.banner = Some(banner);
            res.server = server;
            res.title = title;
        }
        return res;
    }
    if is_tls(port) {
        return res;
    }

    let mut buf = [0u8; 512];
    if matches!(port, 21 | 22 | 25 | 23 | 2323 | 110 | 143 | 587 | 994) {
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                if !s.is_empty() {
                    res.banner = Some(s.chars().take(400).collect());
                }
            }
        }
    } else if port == 554 || port == 8554 {
        let req = format!(
            "OPTIONS rtsp://{}:{}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            ip, port
        );
        let _ = stream.write_all(req.as_bytes());
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                res.banner = Some(
                    String::from_utf8_lossy(&buf[..n])
                        .trim()
                        .chars()
                        .take(400)
                        .collect(),
                );
            }
        }
    } else if let Some((banner, server, title)) = http_probe(&mut stream, ip, port) {
        // Custom IoT ports often speak HTTP but are absent from the built-in list.
        res.service = Some("http".into());
        res.banner = Some(banner);
        res.server = server;
        res.title = title;
    }
    res
}

fn http_probe(
    stream: &mut TcpStream,
    ip: IpAddr,
    port: u16,
) -> Option<(String, Option<String>, Option<String>)> {
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {}:{}\r\nUser-Agent: boggy/{}\r\nConnection: close\r\n\r\n",
        ip,
        port,
        env!("CARGO_PKG_VERSION")
    );
    stream.write_all(req.as_bytes()).ok()?;
    let resp = http::read_response(stream, 24 * 1024)?;
    let server = resp.header("server").map(|s| s.to_string());
    let powered = resp.header("x-powered-by").map(|s| s.to_string());
    let auth = resp.header("www-authenticate").map(|s| s.to_string());
    let body = resp.body_text();
    let title = http::title(&body);
    let mut banner = format!("HTTP/1.1 {}", resp.status);
    for value in [server.clone(), powered, auth] {
        if let Some(v) = value {
            banner.push_str(" | ");
            banner.push_str(&v);
        }
    }
    if let Some(t) = &title {
        banner.push_str(" | ");
        banner.push_str(t);
    }
    Some((banner.chars().take(400).collect(), server, title))
}

fn is_http(port: u16) -> bool {
    matches!(
        port,
        80 | 81
            | 82
            | 83
            | 88
            | 3000
            | 5000
            | 5001
            | 8000
            | 8008
            | 8009
            | 8080
            | 8081
            | 8082
            | 8083
            | 8086
            | 8090
            | 8123
            | 8181
            | 8888
            | 9000
            | 9080
            | 9443
            | 10000
            | 15672
    )
}

fn is_tls(port: u16) -> bool {
    matches!(
        port,
        443 | 636
            | 873
            | 993
            | 995
            | 1443
            | 2376
            | 2484
            | 3443
            | 4443
            | 5061
            | 5443
            | 6443
            | 7443
            | 8243
            | 8443
            | 8883
            | 9443
    )
}

fn guess_service(port: u16) -> Option<String> {
    let name = match port {
        7 => "echo",
        9 => "discard",
        21 => "ftp",
        22 => "ssh",
        23 | 2323 => "telnet",
        25 | 587 => "smtp",
        53 => "dns",
        69 => "tftp",
        80 | 81 | 82 | 83 | 88 => "http",
        102 => "iso-tsap",
        110 => "pop3",
        111 => "rpcbind",
        139 => "netbios",
        143 => "imap",
        161 | 162 => "snmp",
        443 => "https",
        445 => "smb",
        502 => "modbus",
        515 => "lpd",
        548 => "afp",
        554 | 8554 => "rtsp",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        902 => "vmware",
        1080 => "socks",
        1433 => "mssql",
        1723 => "pptp",
        1883 => "mqtt",
        1900 => "ssdp/upnp",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 | 2376 => "docker",
        2404 => "iec-104",
        3306 => "mysql",
        3389 => "rdp",
        4000 => "stun",
        4443 | 8443 => "https",
        44818 => "ethernet-ip",
        47808 => "bacnet",
        4840 => "opc-ua",
        5000 | 5001 => "upnp/http",
        5060 | 5061 => "sip",
        5353 => "mdns",
        5357 => "wsd",
        5432 => "postgres",
        5555 => "adb",
        5601 => "kibana",
        5672 => "amqp",
        5683 => "coap",
        5684 => "coaps",
        5900 => "vnc",
        5984 => "couchdb",
        6000 => "x11",
        6379 => "redis",
        7001 | 7002 => "weblogic",
        7547 => "tr069/cwmp",
        8000 | 8008 | 8009 | 8080 | 8081 | 8082 | 8083 | 8086 | 8090 | 8123 | 8181 | 8888
        | 9000 | 9080 => "http",
        9042 => "cassandra",
        9090 => "prometheus",
        9100 => "jetdirect",
        9200 | 9300 => "elasticsearch",
        9600 => "opc-ua",
        9999 => "ajp",
        10000 => "webmin",
        10250 => "kubelet",
        11211 => "memcached",
        15672 => "rabbitmq",
        20000 => "dicom",
        27017 => "mongo",
        32764 => "backdoor",
        34567 | 37777 => "dvr",
        37215 => "huawei",
        49152 | 52869 => "upnp/soap",
        50000 => "synology",
        62078 => "iphone",
        _ => "",
    };
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_timeout_is_capped() {
        assert_eq!(connect_ms(800), 400);
        assert_eq!(connect_ms(120), 120);
        assert_eq!(connect_ms(0), 50);
    }

    #[test]
    fn port_lists() {
        assert!(FAST_PORTS.len() < COMMON_PORTS.len());
        assert!(COMMON_PORTS.len() < DEEP_PORTS.len());
    }

    #[test]
    fn parse_port_spec() {
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(
            parse_ports("8000-8002,80").unwrap(),
            vec![80, 8000, 8001, 8002]
        );
        assert!(parse_ports("70000").is_none());
        assert!(parse_ports("100-1").is_none());
    }
}
