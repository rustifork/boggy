use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct UpnpDevice {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub serial: Option<String>,
    pub udn: Option<String>,
    pub device_type: Option<String>,
    pub firmware: Option<String>,
    pub control_url: Option<String>,
}

pub fn fetch_device(location: &str, timeout_ms: u64) -> Option<UpnpDevice> {
    // parse host/path
    let url = location.trim();
    let without = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let (hostpart, path) = if let Some(i) = without.find('/') {
        (&without[..i], &without[i..])
    } else {
        (without, "/")
    };
    let host = hostpart.split(':').next()?;
    let port: u16 = if let Some(p) = hostpart.split(':').nth(1) {
        p.parse().ok()?
    } else {
        80
    };
    let mut stream = TcpStream::connect((host, port)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, hostpart
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    // strip headers
    let body = if let Some(i) = text.find("\r\n\r\n") {
        &text[i + 4..]
    } else {
        &text
    };
    let mut dev = UpnpDevice::default();
    dev.friendly_name = tag(body, "friendlyName");
    dev.manufacturer = tag(body, "manufacturer");
    dev.model_name = tag(body, "modelName");
    dev.model_number = tag(body, "modelNumber");
    dev.serial = tag(body, "serialNumber");
    dev.udn = tag(body, "UDN");
    dev.device_type = tag(body, "deviceType");
    dev.firmware = tag(body, "firmwareVersion").or_else(|| tag(body, "softwareVersion"));
    dev.control_url = tag(body, "controlURL");
    Some(dev)
}

pub fn tag(s: &str, name: &str) -> Option<String> {
    // find an opening tag whose local name == name (possibly namespaced, possibly with attrs)
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            // parse tag name
            let mut j = i + 1;
            // skip /
            let closing = j < bytes.len() && bytes[j] == b'/';
            if closing {
                j += 1;
            }
            // skip namespace prefix? we want local name; collect until space or >
            let start_name = j;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric()
                    || bytes[j] == b':'
                    || bytes[j] == b'-'
                    || bytes[j] == b'_')
            {
                j += 1;
            }
            let full = &s[start_name..j];
            let local = full.rsplit(':').next().unwrap_or(full);
            if local == name && !closing {
                // find end of opening tag
                if let Some(gt) = s[j..].find('>') {
                    let content_start = j + gt + 1;
                    // find closing tag </...name>
                    let mut search = content_start;
                    let mut found = None;
                    while let Some(rel) = s[search..].find("</") {
                        let pos = search + rel;
                        // parse closing tag name
                        let mut k = pos + 2;
                        let cs = k;
                        while k < bytes.len()
                            && (bytes[k].is_ascii_alphanumeric()
                                || bytes[k] == b':'
                                || bytes[k] == b'-'
                                || bytes[k] == b'_')
                        {
                            k += 1;
                        }
                        let cfull = &s[cs..k];
                        let clocal = cfull.rsplit(':').next().unwrap_or(cfull);
                        if clocal == name {
                            found = Some((content_start, pos));
                            break;
                        }
                        search = pos + 2;
                    }
                    if let Some((cs, ce)) = found {
                        let v = s[cs..ce].trim().to_string();
                        if !v.is_empty() {
                            return Some(v);
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

#[derive(Clone, Debug)]
pub struct PortMapping {
    pub external: u16,
    pub protocol: String,
    pub internal: String,
}

fn split_url(url: &str) -> Option<(String, u16, String)> {
    let without = url
        .trim()
        .strip_prefix("http://")
        .or_else(|| url.trim().strip_prefix("https://"))?;
    let (hostpart, path) = match without.find('/') {
        Some(i) => (&without[..i], &without[i..]),
        None => (without, "/"),
    };
    let host = hostpart.split(':').next()?;
    let port = hostpart
        .split(':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(80);
    Some((host.to_string(), port, path.to_string()))
}

const WAN_SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

fn soap(host: &str, port: u16, path: &str, action: &str, body: &str, to: u64) -> Option<String> {
    let mut stream = TcpStream::connect((host, port)).ok()?;
    let to = Duration::from_millis(to.clamp(100, 400));
    let _ = stream.set_read_timeout(Some(to));
    let _ = stream.set_write_timeout(Some(to));
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPACTION: \"{}#{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        host,
        port,
        WAN_SERVICE,
        action,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut data = Vec::new();
    let mut tmp = [0u8; 4096];
    while data.len() < 32 * 1024 {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&data);
    let body = if let Some(i) = text.find("\r\n\r\n") {
        &text[i + 4..]
    } else {
        &text
    };
    Some(body.to_string())
}

fn envelope(action: &str, args: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service}\">{args}</u:{action}></s:Body></s:Envelope>",
        action = action,
        service = WAN_SERVICE,
        args = args
    )
}

/// Query a WANIPConnection service for its public IP and active port mappings.
pub fn igd_info(
    location: &str,
    control_url: &str,
    timeout_ms: u64,
) -> Option<(Option<String>, Vec<PortMapping>)> {
    let (base_host, base_port, _) = split_url(location)?;
    let (host, port, path) = if control_url.starts_with("http") {
        split_url(control_url)?
    } else {
        (base_host, base_port, control_url.to_string())
    };

    let reply = soap(
        &host,
        port,
        &path,
        "GetExternalIPAddress",
        &envelope("GetExternalIPAddress", ""),
        timeout_ms,
    )?;
    if reply.contains("SOAP-ENV:Fault") || reply.contains("s:Fault") {
        return None;
    }
    let external = tag(&reply, "NewExternalIPAddress");

    let mut mappings = Vec::new();
    for index in 0..8u32 {
        let args = format!("<NewPortMappingIndex>{}</NewPortMappingIndex>", index);
        let reply = match soap(
            &host,
            port,
            &path,
            "GetGenericPortMappingEntry",
            &envelope("GetGenericPortMappingEntry", &args),
            timeout_ms,
        ) {
            Some(r) => r,
            None => break,
        };
        if reply.contains(":Fault") {
            break;
        }
        let port_value = match tag(&reply, "NewExternalPort").and_then(|v| v.parse::<u16>().ok()) {
            Some(p) => p,
            None => break,
        };
        mappings.push(PortMapping {
            external: port_value,
            protocol: tag(&reply, "NewProtocol").unwrap_or_default(),
            internal: tag(&reply, "NewInternalClient").unwrap_or_default(),
        });
    }
    Some((external, mappings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_soap_action_values() {
        let xml = "<s:Envelope><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress><NewExternalPort>8080</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalClient>192.168.1.20</NewInternalClient></s:Envelope>";
        assert_eq!(
            tag(xml, "NewExternalIPAddress").as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(tag(xml, "NewExternalPort").as_deref(), Some("8080"));
        assert_eq!(tag(xml, "NewProtocol").as_deref(), Some("TCP"));
    }

    #[test]
    fn splits_location() {
        assert_eq!(
            split_url("http://192.168.1.1:80/desc.xml").unwrap(),
            ("192.168.1.1".into(), 80, "/desc.xml".into())
        );
    }
}
