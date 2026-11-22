use crate::types::PortResult;

#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub device_type: &'static str,
}

pub fn fingerprint(port: u16, banner: Option<&str>, service: Option<&str>) -> Option<Fingerprint> {
    let b = banner.unwrap_or("").to_lowercase();
    let s = service.unwrap_or("").to_lowercase();

    if b.contains("dropbear") { return Some(Fingerprint { device_type: "embedded linux" }); }
    if b.contains("openssh") { return Some(Fingerprint { device_type: "ssh host" }); }
    if b.contains("apache") || b.contains("nginx") || b.contains("lighttpd") { return Some(Fingerprint { device_type: "web server" }); }
    if b.contains("boa") { return Some(Fingerprint { device_type: "embedded web" }); }
    if b.contains("goahead") { return Some(Fingerprint { device_type: "embedded web" }); }
    if b.contains("thttpd") { return Some(Fingerprint { device_type: "embedded web" }); }
    if b.contains("mini_httpd") { return Some(Fingerprint { device_type: "embedded web" }); }
    if b.contains("uc-httpd") { return Some(Fingerprint { device_type: "camera/router" }); }
    if b.contains("hikvision") { return Some(Fingerprint { device_type: "ip camera" }); }
    if b.contains("dahua") { return Some(Fingerprint { device_type: "ip camera" }); }
    if b.contains("axis") { return Some(Fingerprint { device_type: "ip camera" }); }
    if b.contains("busybox") { return Some(Fingerprint { device_type: "embedded linux" }); }
    if b.contains("dnsmasq") { return Some(Fingerprint { device_type: "router/dns" }); }
    if b.contains("mqtt") || s == "mqtt" { return Some(Fingerprint { device_type: "mqtt broker" }); }
    if b.contains("tp-link") || b.contains("tplink") { return Some(Fingerprint { device_type: "router/switch" }); }
    if b.contains("xiaomi") { return Some(Fingerprint { device_type: "smart home hub" }); }
    if b.contains("tuya") { return Some(Fingerprint { device_type: "smart home device" }); }
    if b.contains("shelly") { return Some(Fingerprint { device_type: "smart relay" }); }
    if b.contains("espressif") || b.contains("esp32") || b.contains("esp8266") { return Some(Fingerprint { device_type: "esp embedded" }); }
    if b.contains("mikrotik") { return Some(Fingerprint { device_type: "router" }); }
    if b.contains("ubiquiti") || b.contains("unifi") { return Some(Fingerprint { device_type: "network appliance" }); }
    if b.contains("synology") { return Some(Fingerprint { device_type: "nas" }); }
    if b.contains("qnap") { return Some(Fingerprint { device_type: "nas" }); }
    if port == 554 { return Some(Fingerprint { device_type: "ip camera (rtsp)" }); }
    if port == 7547 { return Some(Fingerprint { device_type: "cpe/router (tr069)" }); }
    if port == 5683 { return Some(Fingerprint { device_type: "coap device" }); }
    if port == 1883 { return Some(Fingerprint { device_type: "mqtt broker" }); }
    if port == 5357 { return Some(Fingerprint { device_type: "windows device" }); }
    None
}

pub fn classify_ports(ports: &[PortResult]) -> Vec<String> {
    let mut protos = Vec::new();
    for p in ports {
        if !p.open { continue; }
        if let Some(s) = &p.service {
            if !protos.contains(s) { protos.push(s.clone()); }
        }
    }
    protos
}