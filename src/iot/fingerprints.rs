use crate::types::PortResult;

#[derive(Clone, Copy, Debug)]
pub struct Fingerprint {
    pub device_type: &'static str,
    pub vendor: &'static str,
}

/// (banner needle, device type, vendor). Order matters: specific before generic.
static SIGNATURES: &[(&str, &str, &str)] = &[
    // cameras / video
    ("hikvision", "ip camera", "Hikvision"),
    ("dahua", "ip camera", "Dahua"),
    ("uniview", "ip camera", "Uniview"),
    ("hanwha", "ip camera", "Hanwha"),
    ("vivotek", "ip camera", "Vivotek"),
    ("geovision", "ip camera", "GeoVision"),
    ("reolink", "ip camera", "Reolink"),
    ("amcrest", "ip camera", "Amcrest"),
    ("foscam", "ip camera", "Foscam"),
    ("mobotix", "ip camera", "Mobotix"),
    ("bosch security", "ip camera", "Bosch"),
    ("axis", "ip camera", "Axis"),
    ("onvif", "ip camera", ""),
    ("dvr", "dvr/nvr", ""),
    ("nvr", "dvr/nvr", ""),
    ("uc-httpd", "camera/router", ""),
    // routers / network
    ("mikrotik", "router", "MikroTik"),
    ("routeros", "router", "MikroTik"),
    ("tp-link", "router/switch", "TP-Link"),
    ("tplink", "router/switch", "TP-Link"),
    ("netgear", "router", "NETGEAR"),
    ("d-link", "router", "D-Link"),
    ("dlink", "router", "D-Link"),
    ("linksys", "router", "Linksys"),
    ("asus", "router", "ASUS"),
    ("zyxel", "router/firewall", "Zyxel"),
    ("tenda", "router", "Tenda"),
    ("totolink", "router", "TOTOlink"),
    ("draytek", "router", "DrayTek"),
    ("arcadyan", "cpe router", "Arcadyan"),
    ("gpon", "ont/gpon", ""),
    ("dasan", "ont/gpon", "Dasan"),
    ("huawei", "router/cpe", "Huawei"),
    ("zte", "router/cpe", "ZTE"),
    ("technicolor", "cpe router", "Technicolor"),
    ("sagemcom", "cpe router", "Sagemcom"),
    ("arris", "cpe router", "ARRIS"),
    ("actiontec", "cpe router", "Actiontec"),
    ("trendnet", "router/switch", "TRENDnet"),
    ("edimax", "router/switch", "Edimax"),
    ("ubiquiti", "network appliance", "Ubiquiti"),
    ("unifi", "network appliance", "Ubiquiti"),
    ("fortinet", "firewall", "Fortinet"),
    ("fortios", "firewall", "Fortinet"),
    ("sonicwall", "firewall", "SonicWall"),
    ("watchguard", "firewall", "WatchGuard"),
    ("sophos", "firewall", "Sophos"),
    ("cisco", "network appliance", "Cisco"),
    ("juniper", "network appliance", "Juniper"),
    ("palo alto", "firewall", "Palo Alto"),
    ("check point", "firewall", "Check Point"),
    ("mikrotik router", "router", "MikroTik"),
    ("dnsmasq", "router/dns", ""),
    ("tr069", "cpe/router", ""),
    ("cwmp", "cpe/router", ""),
    // NAS / storage
    ("synology", "nas", "Synology"),
    ("qnap", "nas", "QNAP"),
    ("asustor", "nas", "Asustor"),
    ("readynas", "nas", "NETGEAR"),
    ("terramaster", "nas", "TerraMaster"),
    ("truenas", "nas", "TrueNAS"),
    ("freenas", "nas", "FreeNAS"),
    ("western digital", "nas", "Western Digital"),
    ("netatalk", "nas", ""),
    // smart home / embedded
    ("shelly", "smart relay", "Shelly"),
    ("tuya", "smart home device", "Tuya"),
    ("tasmota", "iot device", "Tasmota"),
    ("espressif", "esp embedded", "Espressif"),
    ("esp32", "esp embedded", "Espressif"),
    ("esp8266", "esp embedded", "Espressif"),
    ("sonoff", "smart relay", "Sonoff"),
    ("xiaomi", "smart home hub", "Xiaomi"),
    ("aqara", "smart home device", "Aqara"),
    ("philips hue", "smart lighting", "Philips"),
    ("home assistant", "smart home hub", ""),
    ("fibaro", "smart home hub", "Fibaro"),
    ("googlecast", "media device", "Google"),
    ("chromecast", "media device", "Google"),
    ("roku", "media device", "Roku"),
    ("sonos", "media device", "Sonos"),
    ("plex", "media server", "Plex"),
    ("kodi", "media center", "Kodi"),
    // printers
    ("jetdirect", "printer", "HP"),
    ("hp laserjet", "printer", "HP"),
    ("canon", "printer", "Canon"),
    ("epson", "printer", "Epson"),
    ("brother", "printer", "Brother"),
    ("xerox", "printer", "Xerox"),
    ("kyocera", "printer", "Kyocera"),
    ("ricoh", "printer", "Ricoh"),
    ("lexmark", "printer", "Lexmark"),
    ("cups", "print server", ""),
    // industrial / OT
    ("siemens", "industrial controller", "Siemens"),
    ("schneider electric", "industrial controller", "Schneider"),
    ("rockwell", "industrial controller", "Rockwell"),
    ("allen-bradley", "industrial controller", "Rockwell"),
    ("moxa", "industrial device", "Moxa"),
    ("advantech", "industrial device", "Advantech"),
    ("wago", "industrial device", "WAGO"),
    ("beckhoff", "industrial controller", "Beckhoff"),
    ("codesys", "industrial controller", "CODESYS"),
    ("openplc", "industrial controller", "OpenPLC"),
    ("modbus", "industrial controller", ""),
    ("bacnet", "building controller", ""),
    // embedded web servers / shells
    ("boa/", "embedded web", ""),
    ("goahead", "embedded web", ""),
    ("thttpd", "embedded web", ""),
    ("mini_httpd", "embedded web", ""),
    ("lighttpd", "web server", ""),
    ("apache", "web server", "Apache"),
    ("nginx", "web server", ""),
    ("busybox", "embedded linux", ""),
    ("dropbear", "embedded linux", ""),
    ("openssh", "ssh host", ""),
    ("vsftpd", "ftp server", ""),
    ("proftpd", "ftp server", ""),
    ("pure-ftpd", "ftp server", ""),
    ("samba", "file server", ""),
    ("vmware", "hypervisor", "VMware"),
    ("esxi", "hypervisor", "VMware"),
    ("docker", "container host", ""),
    ("kubernetes", "kubernetes", ""),
    ("gitlab", "git server", "GitLab"),
    ("jenkins", "ci server", "Jenkins"),
    ("grafana", "monitoring", "Grafana"),
    ("redis", "database", ""),
    ("mongodb", "database", ""),
    ("elasticsearch", "database", ""),
    ("mysql", "database", ""),
    ("mariadb", "database", ""),
    ("postgres", "database", ""),
    (" asterisk", "voip", "Asterisk"),
    ("grandstream", "voip", "Grandstream"),
    ("yealink", "voip", "Yealink"),
    ("polycom", "voip", "Polycom"),
    ("mitel", "voip", "Mitel"),
];

static PORT_TYPES: &[(u16, &str)] = &[
    (1883, "mqtt broker"),
    (8883, "mqtt broker"),
    (5683, "coap device"),
    (5684, "coap device"),
    (502, "modbus device"),
    (44818, "industrial controller"),
    (47808, "bacnet device"),
    (2404, "industrial controller"),
    (9600, "opc-ua server"),
    (9100, "printer"),
    (631, "printer"),
    (7547, "cpe/router"),
    (554, "ip camera (rtsp)"),
    (8554, "ip camera (rtsp)"),
    (2375, "docker host"),
    (9200, "elasticsearch"),
    (27017, "mongodb"),
    (6379, "redis"),
    (1900, "upnp device"),
    (49152, "upnp device"),
];

pub fn fingerprint(
    port: u16,
    banner: Option<&str>,
    service: Option<&str>,
    title: Option<&str>,
    server: Option<&str>,
) -> Option<Fingerprint> {
    let text = format!(
        "{} {} {} {}",
        banner.unwrap_or(""),
        service.unwrap_or(""),
        title.unwrap_or(""),
        server.unwrap_or("")
    )
    .to_ascii_lowercase();
    for (needle, device_type, vendor) in SIGNATURES {
        if text.contains(needle) {
            return Some(Fingerprint {
                device_type,
                vendor,
            });
        }
    }
    for (p, device_type) in PORT_TYPES {
        if *p == port {
            return Some(Fingerprint {
                device_type,
                vendor: "",
            });
        }
    }
    None
}

pub fn vendor_of(text: &str) -> Option<&'static str> {
    let text = text.to_ascii_lowercase();
    for (needle, _, vendor) in SIGNATURES {
        if !vendor.is_empty() && text.contains(needle) {
            return Some(vendor);
        }
    }
    None
}

pub fn device_types(text: &str) -> Vec<&'static str> {
    let text = text.to_ascii_lowercase();
    let mut out = Vec::new();
    for (needle, device_type, _) in SIGNATURES {
        if text.contains(needle) && !out.contains(device_type) {
            out.push(device_type);
        }
    }
    out
}

static VERSIONED_PRODUCTS: &[&str] = &[
    "apache",
    "nginx",
    "lighttpd",
    "boa",
    "goahead",
    "thttpd",
    "mini_httpd",
    "uc-httpd",
    "openssh",
    "dropbear",
    "samba",
    "vsftpd",
    "proftpd",
    "pure-ftpd",
    "php",
    "tomcat",
    "jetty",
    "redis",
    "mongodb",
    "elasticsearch",
    "mysql",
    "mariadb",
    "postgresql",
    "rabbitmq",
    "docker",
    "busybox",
    "dnsmasq",
    "hikvision",
    "dahua",
    "synology",
    "qnap",
    "mikrotik",
    "routeros",
    "axis",
    "wire",
    "openssl",
    "zlib",
    "curl",
];

/// Pull `(product, version)` pairs out of banners: `Apache/2.4.49`, `OpenSSH_8.2p1`, ...
pub fn versions(text: &str) -> Vec<(String, String)> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    for product in VERSIONED_PRODUCTS {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(product) {
            let at = from + rel;
            let mut i = at + product.len();
            let bytes = lower.as_bytes();
            if i >= bytes.len() {
                break;
            }
            if matches!(bytes[i], b'/' | b'_' | b' ' | b'-' | b'=') {
                i += 1;
            } else {
                from = at + 1;
                continue;
            }
            let vs = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') && i - vs < 24
            {
                i += 1;
            }
            let version = &lower[vs..i];
            if version.chars().filter(|c| c.is_ascii_digit()).count() >= 1
                && !out.iter().any(|(p, v)| p == product && v == version)
            {
                out.push((product.to_string(), version.to_string()));
            }
            from = at + 1;
        }
    }
    out
}

/// Compare dotted numeric versions; a shorter prefix is older (`2.4` < `2.4.1`).
pub fn version_lt(a: &str, b: &str) -> bool {
    let pa: Vec<u32> = a
        .split('.')
        .map(|s| {
            s.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .unwrap_or(0)
        })
        .collect();
    let pb: Vec<u32> = b
        .split('.')
        .map(|s| {
            s.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .unwrap_or(0)
        })
        .collect();
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).copied().unwrap_or(0);
        let y = pb.get(i).copied().unwrap_or(0);
        if x != y {
            return x < y;
        }
    }
    pa.len() < pb.len()
}

pub fn classify_ports(ports: &[PortResult]) -> Vec<String> {
    let mut protos = Vec::new();
    for p in ports {
        if !p.open {
            continue;
        }
        if let Some(s) = &p.service {
            if !protos.contains(s) {
                protos.push(s.clone());
            }
        }
    }
    protos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_vendor_and_type() {
        let f = fingerprint(
            80,
            Some("HTTP/1.1 200 OK | Hikvision-Webs"),
            Some("http"),
            None,
            Some("Hikvision-Webs"),
        )
        .unwrap();
        assert_eq!(f.vendor, "Hikvision");
        assert_eq!(f.device_type, "ip camera");
    }

    #[test]
    fn version_comparison() {
        assert!(version_lt("2.4.49", "2.4.51"));
        assert!(!version_lt("2.4.51", "2.4.49"));
        assert!(version_lt("8.2", "8.2.1"));
    }

    #[test]
    fn version_extraction() {
        let v = versions("Apache/2.4.49 (Ubuntu) OpenSSH_8.2p1 Samba 4.11.6");
        assert!(v.contains(&("apache".into(), "2.4.49".into())));
        assert!(v.contains(&("openssh".into(), "8.2".into())));
        assert!(v.contains(&("samba".into(), "4.11.6".into())));
    }
}
