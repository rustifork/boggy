use crate::types::PortResult;

#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub device_type: &'static str,
    pub vendor: Option<&'static str>,
}

pub fn fingerprint(port: u16, banner: Option<&str>, service: Option<&str>) -> Option<Fingerprint> {
    let b = banner.unwrap_or("").to_lowercase();
    let s = service.unwrap_or("").to_lowercase();

    if b.contains("dropbear") { return Some(Fingerprint { device_type: "embedded linux", vendor: Some("Dropbear") }); }
    if b.contains("openssh") { return Some(Fingerprint { device_type: "ssh host", vendor: None }); }
    if b.contains("apache") || b.contains("nginx") || b.contains("lighttpd") { return Some(Fingerprint { device_type: "web server", vendor: None }); }
    if b.contains("boa") { return Some(Fingerprint { device_type: "embedded web", vendor: Some("Boa") }); }
    if b.contains("goahead") { return Some(Fingerprint { device_type: "embedded web", vendor: Some("GoAhead") }); }
    if b.contains("thttpd") { return Some(Fingerprint { device_type: "embedded web", vendor: Some("thttpd") }); }
    if b.contains("mini_httpd") { return Some(Fingerprint { device_type: "embedded web", vendor: Some("mini_httpd") }); }
    if b.contains("uc-httpd") { return Some(Fingerprint { device_type: "camera/router", vendor: Some("uc-httpd") }); }
    if b.contains("hikvision") { return Some(Fingerprint { device_type: "ip camera", vendor: Some("Hikvision") }); }
    if b.contains("dahua") { return Some(Fingerprint { device_type: "ip camera", vendor: Some("Dahua") }); }
    if b.contains("axis") { return Some(Fingerprint { device_type: "ip camera", vendor: Some("Axis") }); }
    if b.contains("busybox") { return Some(Fingerprint { device_type: "embedded linux", vendor: Some("BusyBox") }); }
    if b.contains("dnsmasq") { return Some(Fingerprint { device_type: "router/dns", vendor: Some("dnsmasq") }); }
    if b.contains("mqtt") || s == "mqtt" { return Some(Fingerprint { device_type: "mqtt broker", vendor: None }); }
    if port == 554 { return Some(Fingerprint { device_type: "ip camera (rtsp)", vendor: None }); }
    if port == 7547 { return Some(Fingerprint { device_type: "cpe/router (tr069)", vendor: None }); }
    if port == 5683 { return Some(Fingerprint { device_type: "coap device", vendor: None }); }
    if port == 1883 { return Some(Fingerprint { device_type: "mqtt broker", vendor: None }); }
    if port == 5357 { return Some(Fingerprint { device_type: "windows device", vendor: Some("Microsoft") }); }
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