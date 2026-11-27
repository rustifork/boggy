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
    Some(dev)
}

fn tag(s: &str, name: &str) -> Option<String> {
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
