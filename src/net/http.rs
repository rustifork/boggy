//! Tiny HTTP/1.0 client and the pieces needed to answer authentication challenges.
//! Kept dependency-free so the release binary stays small.

use crate::net::md5;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

const MAX_RESPONSE: usize = 24 * 1024;

#[derive(Clone, Debug)]
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl<'a> HttpRequest<'a> {
    pub fn get(path: &'a str) -> Self {
        Self {
            method: "GET",
            path,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn ok(&self) -> bool {
        (200..400).contains(&self.status)
    }
}

pub fn request(
    ip: Ipv4Addr,
    port: u16,
    req: &HttpRequest<'_>,
    timeout_ms: u64,
) -> Option<HttpResponse> {
    let line = format!("{} {} HTTP/1.0", req.method, req.path);
    let mut headers = Vec::with_capacity(req.headers.len() + 1);
    headers.push(("Host".to_string(), format!("{}:{}", ip, port)));
    headers.push((
        "User-Agent".to_string(),
        format!("boggy/{}", env!("CARGO_PKG_VERSION")),
    ));
    headers.extend(req.headers.iter().cloned());
    raw_request(ip, port, &line, &headers, &req.body, timeout_ms)
}

/// Send a request with a caller-supplied request line (used for RTSP/1.0).
/// Reject CR/LF and NUL so a value taken from a scanned page cannot inject
/// extra request lines or headers into the client.
fn safe_field(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

pub fn raw_request(
    ip: Ipv4Addr,
    port: u16,
    request_line: &str,
    headers: &[(String, String)],
    body: &[u8],
    timeout_ms: u64,
) -> Option<HttpResponse> {
    if !safe_field(request_line, 2048)
        || headers
            .iter()
            .any(|(k, v)| !safe_field(k, 128) || !safe_field(v, 4096))
    {
        return None;
    }
    let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
    let to = Duration::from_millis(timeout_ms.max(50));
    let mut stream = TcpStream::connect_timeout(&addr, to).ok()?;
    let _ = stream.set_read_timeout(Some(to));
    let _ = stream.set_write_timeout(Some(to));

    let mut raw = format!("{}\r\n", request_line);
    for (k, v) in headers {
        raw.push_str(k);
        raw.push_str(": ");
        raw.push_str(v);
        raw.push_str("\r\n");
    }
    raw.push_str("Connection: close\r\n");
    if !body.is_empty() {
        raw.push_str(&format!("Content-Length: {}\r\n", body.len()));
        raw.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
    }
    raw.push_str("\r\n");
    let mut buf = raw.into_bytes();
    buf.extend_from_slice(body);
    stream.write_all(&buf).ok()?;

    read_response(&mut stream, MAX_RESPONSE)
}

/// Read a response from an already connected socket. Lets the port scanner reuse
/// its liveness connection instead of opening a second one for every banner.
pub fn read_response(stream: &mut TcpStream, limit: usize) -> Option<HttpResponse> {
    let mut data = Vec::new();
    let mut tmp = [0u8; 4096];
    while data.len() < limit {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    parse_response(&data)
}

pub fn parse_response(data: &[u8]) -> Option<HttpResponse> {
    let sep = find(data, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&data[..sep]);
    let mut lines = head.lines();
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let _proto = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let raw_body = &data[sep + 4..];
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        dechunk(raw_body)
    } else {
        raw_body.to_vec()
    };
    Some(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Decode an HTTP/1.1 chunked body, bounded by the response limit.
fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let line_end = match data[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(i) => pos + i,
            None => break,
        };
        let size_text = String::from_utf8_lossy(&data[pos..line_end]);
        let size = match usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
        {
            Ok(n) => n,
            Err(_) => break,
        };
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size > data.len() || out.len() + size > MAX_RESPONSE {
            break;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2; // trailing CRLF after the chunk
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn b64(input: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < bytes.len() {
        let a = bytes[i] as usize;
        let b = if i + 1 < bytes.len() {
            bytes[i + 1] as usize
        } else {
            0
        };
        let c = if i + 2 < bytes.len() {
            bytes[i + 2] as usize
        } else {
            0
        };
        out.push(T[a >> 2] as char);
        out.push(T[((a & 3) << 4) | (b >> 4)] as char);
        out.push(if i + 1 < bytes.len() {
            T[((b & 15) << 2) | (c >> 6)] as char
        } else {
            '='
        });
        out.push(if i + 2 < bytes.len() {
            T[c & 63] as char
        } else {
            '='
        });
        i += 3;
    }
    out
}

#[derive(Clone, Debug, Default)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub qop: Option<String>,
    pub opaque: Option<String>,
    pub algorithm: String,
}

/// Parse a `WWW-Authenticate: Digest ...` value. Returns None for Basic or malformed input.
pub fn parse_digest(header: &str) -> Option<DigestChallenge> {
    if !header.to_ascii_lowercase().starts_with("digest") {
        return None;
    }
    let mut out = DigestChallenge {
        realm: String::new(),
        nonce: String::new(),
        qop: None,
        opaque: None,
        algorithm: "MD5".to_string(),
    };
    for (k, v) in parse_params(&header[6..]) {
        let k = k.to_ascii_lowercase();
        match k.as_str() {
            "realm" => out.realm = v,
            "nonce" => out.nonce = v,
            "qop" => out.qop = v.split(',').next().map(|s| s.trim().to_string()),
            "opaque" => out.opaque = Some(v),
            "algorithm" => out.algorithm = v,
            _ => {}
        }
    }
    if out.realm.is_empty() || out.nonce.is_empty() {
        return None;
    }
    Some(out)
}

fn parse_params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',' || bytes[i] == b'\t') {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            i += 1;
            continue;
        }
        let key = s[start..i].trim().to_string();
        i += 1;
        let value: String;
        if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let vs = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            value = s[vs..i.min(s.len())].to_string();
            if i < bytes.len() {
                i += 1;
            }
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            i += 1;
        } else {
            let vs = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            value = s[vs..i].trim().to_string();
            i += 1;
        }
        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

pub fn digest_header(
    user: &str,
    pass: &str,
    method: &str,
    uri: &str,
    challenge: &DigestChallenge,
) -> String {
    let nc = "00000001";
    let cnonce = "0b0g9y";
    let base = md5::hex(format!("{}:{}:{}", user, challenge.realm, pass).as_bytes());
    let ha1 = if challenge.algorithm.eq_ignore_ascii_case("MD5-sess") {
        md5::hex(format!("{}:{}:{}", base, challenge.nonce, cnonce).as_bytes())
    } else {
        base
    };
    let ha2 = md5::hex(format!("{}:{}", method, uri).as_bytes());
    let use_qop = challenge
        .qop
        .as_deref()
        .map(|q| q.split(',').any(|x| x.trim() == "auth"))
        .unwrap_or(false);
    let qop = if use_qop { "auth" } else { "" };
    let response = if use_qop {
        md5::hex(
            format!(
                "{}:{}:{}:{}:{}:{}",
                ha1, challenge.nonce, nc, cnonce, qop, ha2
            )
            .as_bytes(),
        )
    } else {
        md5::hex(format!("{}:{}:{}", ha1, challenge.nonce, ha2).as_bytes())
    };
    let mut h = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        user, challenge.realm, challenge.nonce, uri, response
    );
    if use_qop {
        h.push_str(&format!(", qop=auth, nc={}, cnonce=\"{}\"", nc, cnonce));
    }
    if let Some(opaque) = &challenge.opaque {
        h.push_str(&format!(", opaque=\"{}\"", opaque));
    }
    if challenge.algorithm.eq_ignore_ascii_case("MD5-sess") {
        h.push_str(", algorithm=MD5-sess");
    }
    h
}

pub fn title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let gt = lower[start..].find('>')? + start + 1;
    let end = lower[gt..].find("</title")? + gt;
    let value = body[gt..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.chars().take(160).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors() {
        assert_eq!(b64("admin:admin"), "YWRtaW46YWRtaW4=");
        assert_eq!(b64("a"), "YQ==");
    }

    #[test]
    fn digest_challenge_and_header() {
        let challenge = parse_digest(
            "Digest realm=\"IP Camera\", nonce=\"abc123\", qop=\"auth,auth-int\", opaque=\"xy\"",
        )
        .unwrap();
        assert_eq!(challenge.realm, "IP Camera");
        let header = digest_header("admin", "12345", "GET", "/", &challenge);
        assert!(header.contains("qop=auth"));
        assert!(header.contains("response=\""));
    }

    #[test]
    fn rejects_header_injection() {
        let req = crate::net::http::HttpRequest {
            method: "GET",
            path: "/ HTTP/1.1\r\nX-Injected: yes",
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(request("127.0.0.1".parse().unwrap(), 1, &req, 10).is_none());
    }

    #[test]
    fn decodes_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body_text(), "hello world");
    }

    #[test]
    fn parse_status() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nServer: Boa/0.94\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\r\nbody";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 401);
        assert_eq!(r.header("server"), Some("Boa/0.94"));
        assert_eq!(r.body_text(), "body");
    }
}
