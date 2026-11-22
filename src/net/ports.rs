use crate::types::PortResult;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub const FAST_PORTS: &[u16] = &[
    22, 23, 80, 443, 554, 1883, 5683, 8000, 8080, 8443, 8888, 9000,
];

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 587, 993, 995,
    1883, 1900, 2323, 3306, 3389, 5000, 5353, 5357, 5683, 6000, 7547,
    8000, 8008, 8080, 8081, 8443, 8888, 9000, 9100, 10000,
];

pub const DEEP_PORTS: &[u16] = &[
    21,22,23,25,53,67,68,69,80,110,123,135,137,138,139,143,161,162,389,
    443,445,502,515,548,554,587,631,993,995,1025,1433,1723,1883,1900,
    2049,2323,2375,2376,3306,3389,4369,5000,5001,5353,5357,5432,5672,
    5683,5684,5900,5984,6000,6379,7547,8000,8008,8009,8080,8081,8086,
    8123,8181,8443,8883,8888,9000,9042,9090,9100,9200,9300,10000,10250,
    27017,50000,
];

pub fn ports_for(fast: bool, deep: bool) -> &'static [u16] {
    if fast { FAST_PORTS }
    else if deep { DEEP_PORTS }
    else { COMMON_PORTS }
}

pub fn scan_port(ip: std::net::Ipv4Addr, port: u16, timeout_ms: u64) -> PortResult {
    let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
    let to = Duration::from_millis(timeout_ms);
    let mut res = PortResult {
        port,
        open: false,
        service: guess_service(port),
        banner: None,
        tls: port == 443 || port == 8443,
    };
    match TcpStream::connect_timeout(&addr, to) {
        Ok(mut stream) => {
            res.open = true;
            let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
            // banner grab: send nothing for some, HTTP probe for web
            let probe = if port == 80 || port == 8000 || port == 8080 || port == 8008 || port == 8081 {
                Some("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n".as_bytes())
            } else if port == 23 || port == 2323 {
                None
            } else {
                None
            };
            if let Some(p) = probe {
                use std::io::Write;
                let _ = stream.write_all(p);
            }
            use std::io::Read;
            let mut buf = [0u8; 512];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let s = String::from_utf8_lossy(&buf[..n]).to_string();
                    let trimmed = s.trim().to_string();
                    if !trimmed.is_empty() {
                        res.banner = Some(trimmed.chars().take(400).collect());
                    }
                }
            }
        }
        Err(_) => {}
    }
    res
}

fn guess_service(port: u16) -> Option<String> {
    let name = match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns",
        80 => "http", 110 => "pop3", 139 => "netbios", 143 => "imap",
        443 => "https", 445 => "smb", 502 => "modbus", 554 => "rtsp",
        631 => "ipp", 1883 => "mqtt", 1900 => "ssdp/upnp", 2323 => "telnet",
        3306 => "mysql", 3389 => "rdp", 5000 => "upnp/http", 5353 => "mdns",
        5357 => "wsd", 5683 => "coap", 5900 => "vnc", 6379 => "redis",
        7547 => "tr069/cwmp", 8000 => "http", 8080 => "http", 8081 => "http",
        8443 => "https", 8883 => "mqtts", 8888 => "http", 9000 => "http",
        9100 => "jetdirect", 10000 => "webmin", 27017 => "mongo", _ => "",
    };
    if name.is_empty() { None } else { Some(name.to_string()) }
}