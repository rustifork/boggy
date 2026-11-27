//! Default / weak credential checks. The pair database lives in `db/creds.json`,
//! so new devices can be added without recompiling.

use crate::iot::protocols;
use crate::json::Json;
use crate::net::http::{self, HttpRequest, HttpResponse};
use crate::types::Finding;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
struct CredSet {
    http: Vec<(String, String)>,
    telnet: Vec<(String, String)>,
    ftp: Vec<(String, String)>,
    rtsp: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default)]
struct CredDb {
    generic: CredSet,
    vendors: BTreeMap<String, CredSet>,
    snmp: Vec<String>,
}

static CREDS_DB: &str = include_str!("../../db/creds.json");

fn pairs(value: Option<&Json>) -> Vec<(String, String)> {
    value
        .and_then(Json::as_arr)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    let items = row.as_arr()?;
                    if items.len() != 2 {
                        return None;
                    }
                    Some((items[0].string(), items[1].string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn cred_set(value: Option<&Json>) -> CredSet {
    let empty = Json::Null;
    let value = value.unwrap_or(&empty);
    CredSet {
        http: pairs(value.get("http")),
        telnet: pairs(value.get("telnet")),
        ftp: pairs(value.get("ftp")),
        rtsp: pairs(value.get("rtsp")),
    }
}

fn decode(data: &str) -> Option<CredDb> {
    let root = crate::json::parse(data.as_bytes()).ok()?;
    let generic = cred_set(root.get("generic"));
    let mut vendors = BTreeMap::new();
    if let Some(rows) = root.get("vendors").and_then(Json::as_obj) {
        for (name, value) in rows {
            vendors.insert(name.clone(), cred_set(Some(value)));
        }
    }
    let snmp = root
        .get("snmp")
        .and_then(Json::as_arr)
        .map(|rows| rows.iter().map(|v| v.string()).collect())
        .unwrap_or_default();
    Some(CredDb {
        generic,
        vendors,
        snmp,
    })
}

fn load(explicit: Option<&str>) -> CredDb {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(p) = explicit {
        candidates.push(p.to_string());
    }
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(format!("{}/.boggy/creds.json", home));
    }
    candidates.push("db/creds.json".to_string());
    candidates.push("/etc/boggy/creds.json".to_string());
    for path in &candidates {
        if let Ok(data) = std::fs::read_to_string(path) {
            if crate::update::validate_creds(data.as_bytes()).is_ok() {
                if let Some(db) = decode(&data) {
                    if !db.generic.http.is_empty() {
                        return db;
                    }
                }
            }
        }
    }
    decode(CREDS_DB).unwrap_or_default()
}

fn vendor_set<'a>(db: &'a CredDb, vendor: &str) -> Option<&'a CredSet> {
    let v = vendor.to_ascii_lowercase();
    if v.is_empty() {
        return None;
    }
    db.vendors.iter().find_map(|(key, set)| {
        let k = key.to_ascii_lowercase();
        if k == v || k.contains(&v) || v.contains(&k) {
            Some(set)
        } else {
            None
        }
    })
}

fn select(db: &CredDb, protocol: &str, vendor: &str, limit: usize) -> Vec<(String, String)> {
    let generic = match protocol {
        "http" => &db.generic.http,
        "telnet" => &db.generic.telnet,
        "ftp" => &db.generic.ftp,
        "rtsp" => &db.generic.rtsp,
        _ => return Vec::new(),
    };
    // Vendor-specific defaults go first: they are both rarer and far more likely
    // to work than the generic list.
    let mut out = Vec::new();
    if let Some(set) = vendor_set(db, vendor) {
        let vendor_pairs = match protocol {
            "http" => &set.http,
            "telnet" => &set.telnet,
            "ftp" => &set.ftp,
            "rtsp" => &set.rtsp,
            _ => &set.http,
        };
        for pair in vendor_pairs {
            if !out.contains(pair) {
                out.push(pair.clone());
            }
        }
    }
    for pair in generic {
        if !out.contains(pair) {
            out.push(pair.clone());
        }
    }
    if limit > 0 && out.len() > limit {
        out.truncate(limit);
    }
    out
}

pub fn snmp_communities(explicit: Option<&str>) -> Vec<String> {
    let db = load(explicit);
    if db.snmp.is_empty() {
        vec![
            "public".into(),
            "private".into(),
            "manager".into(),
            "monitor".into(),
        ]
    } else {
        db.snmp
    }
}

fn found(
    id: &str,
    title: &str,
    user: &str,
    pass: &str,
    ip: Ipv4Addr,
    port: u16,
    method: &str,
) -> Finding {
    let mut f = Finding::new(
        id,
        "critical",
        title,
        format!("{}:{} on {}:{} via {}", user, pass, ip, port, method),
    );
    f.confidence = Some("high".into());
    f
}

/// HTTP Basic, Digest and simple form logins.
pub fn http_default_creds(
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    vendor: &str,
    limit: usize,
    explicit_db: Option<&str>,
) -> Vec<Finding> {
    let db = load(explicit_db);
    let pairs = select(&db, "http", vendor, limit);
    if pairs.is_empty() {
        return Vec::new();
    }
    let to = timeout_ms.max(100);
    let initial = match http::request(ip, port, &HttpRequest::get("/"), to) {
        Some(r) => r,
        None => return Vec::new(),
    };
    let challenge = initial
        .header("www-authenticate")
        .map(|s| s.to_string())
        .unwrap_or_default();

    if initial.status == 401 || challenge.to_ascii_lowercase().starts_with("digest") {
        if let Some(digest) = http::parse_digest(&challenge) {
            for (user, pass) in &pairs {
                let mut req = HttpRequest::get("/");
                req.headers.push((
                    "Authorization".into(),
                    http::digest_header(user, pass, "GET", "/", &digest),
                ));
                if let Some(resp) = http::request(ip, port, &req, to) {
                    if authenticated(&resp) {
                        return vec![found(
                            "DEFAULT_CREDS_HTTP",
                            "Default HTTP credentials accepted (Digest)",
                            user,
                            pass,
                            ip,
                            port,
                            "digest",
                        )];
                    }
                }
            }
        }
        // Basic is tried even when the challenge is unknown: many embedded stacks
        // omit WWW-Authenticate details but still accept Basic.
        for (user, pass) in &pairs {
            let mut req = HttpRequest::get("/");
            req.headers.push((
                "Authorization".into(),
                format!("Basic {}", http::b64(&format!("{}:{}", user, pass))),
            ));
            if let Some(resp) = http::request(ip, port, &req, to) {
                if authenticated(&resp) {
                    return vec![found(
                        "DEFAULT_CREDS_HTTP",
                        "Default HTTP credentials accepted (Basic)",
                        user,
                        pass,
                        ip,
                        port,
                        "basic",
                    )];
                }
            }
        }
        return Vec::new();
    }

    if initial.status == 200 {
        if let Some((action, user_field, pass_field)) = parse_form(&initial.body_text()) {
            // Bound form attempts more tightly: each one is a POST.
            for (user, pass) in pairs.iter().take(limit.min(12)) {
                let body = form_body(&user_field, user, &pass_field, pass);
                let req = HttpRequest {
                    method: "POST",
                    path: &action,
                    headers: vec![("Referer".into(), format!("http://{}:{}/", ip, port))],
                    body: body.into_bytes(),
                };
                if let Some(resp) = http::request(ip, port, &req, to) {
                    if form_login_succeeded(&resp, &pass_field) {
                        return vec![found(
                            "DEFAULT_CREDS_HTTP_FORM",
                            "Default credentials accepted by web login form",
                            user,
                            pass,
                            ip,
                            port,
                            "form",
                        )];
                    }
                }
            }
        }
    }
    Vec::new()
}

fn authenticated(resp: &HttpResponse) -> bool {
    if resp.status == 401 || resp.status == 403 {
        return false;
    }
    if let Some(location) = resp.header("location") {
        let target = location.to_ascii_lowercase();
        if target.contains("login") || target.contains("signin") {
            return false;
        }
    }
    resp.ok()
}

fn form_login_succeeded(resp: &HttpResponse, pass_field: &str) -> bool {
    if !resp.ok() {
        return false;
    }
    let body = resp.body_text().to_ascii_lowercase();
    if body.contains("incorrect")
        || body.contains("invalid")
        || body.contains("failed")
        || body.contains("wrong password")
    {
        return false;
    }
    let still_login = body.contains(&format!("name=\"{}\"", pass_field.to_ascii_lowercase()))
        || body.contains(&format!("name='{}'", pass_field.to_ascii_lowercase()));
    let success_marker = [
        "logout",
        "dashboard",
        "status",
        "welcome",
        "main menu",
        "device information",
    ]
    .iter()
    .any(|s| body.contains(s));
    // A failed login often sets a session cookie too; require a real success
    // marker and the absence of the password field.
    !still_login && success_marker
}

fn parse_form(body: &str) -> Option<(String, String, String)> {
    let lower = body.to_ascii_lowercase();
    let form_start = lower.find("<form")?;
    let form_end = lower[form_start..].find('>')? + form_start;
    let form_tag = &body[form_start..form_end];
    let lower_tag = form_tag.to_ascii_lowercase();
    let action = if lower_tag.contains("action=") {
        attr(form_tag, "action").unwrap_or_else(|| "/".to_string())
    } else {
        "/".to_string()
    };
    let action = if action.starts_with('/') {
        action
    } else {
        format!("/{}", action.trim_start_matches("./"))
    };
    let mut user_field = None;
    let mut pass_field = None;
    let form_close = lower[form_end..]
        .find("</form")
        .map(|i| form_end + i)
        .unwrap_or(lower.len());
    let mut pos = form_end;
    while pos < form_close {
        let rel = match lower[pos..form_close].find("<input") {
            Some(r) => r,
            None => break,
        };
        let start = pos + rel;
        let end = match lower[start..].find('>') {
            Some(e) => start + e + 1,
            None => break,
        };
        let tag = &lower[start..end];
        let name = attr(tag, "name").unwrap_or_default();
        let typ = attr(tag, "type").unwrap_or_else(|| "text".into());
        if typ == "password" && pass_field.is_none() {
            pass_field = Some(name.clone());
        }
        let u = name.to_ascii_lowercase();
        if user_field.is_none()
            && typ != "password"
            && ["user", "username", "login", "usr", "account", "name", "uid"]
                .iter()
                .any(|k| u.contains(k))
        {
            user_field = Some(name.clone());
        }
        pos = end;
    }
    let user_field = user_field?;
    let pass_field = pass_field?;
    Some((action, user_field, pass_field))
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let key = format!("{}=", name);
    let mut from = 0;
    let found = loop {
        let rel = tag[from..].find(&key)?;
        let at = from + rel;
        if at == 0 || tag.as_bytes()[at - 1].is_ascii_whitespace() {
            break at;
        }
        from = at + 1;
    };
    let rest = &tag[found + key.len()..];
    let quote = rest.as_bytes().first().copied()?;
    if quote != b'"' && quote != b'\'' {
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    let end = rest[1..].find(quote as char)? + 1;
    Some(rest[1..end].to_string())
}

fn form_body(user_field: &str, user: &str, pass_field: &str, pass: &str) -> String {
    format!(
        "{}={}&{}={}",
        urlenc(user_field),
        urlenc(user),
        urlenc(pass_field),
        urlenc(pass)
    )
}

fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn read_available(stream: &mut TcpStream, buf: &mut [u8], timeout_ms: u64) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms.max(50))));
    match stream.read(buf) {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).to_string(),
        Err(_) => String::new(),
    }
}

/// One credential attempt on its own connection: a failed login frequently makes
/// embedded Telnet servers close the socket, so reusing it causes false negatives.
fn telnet_attempt(ip: Ipv4Addr, port: u16, to: u64, user: &str, pass: &str) -> bool {
    let mut stream = match TcpStream::connect_timeout(
        &std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port),
        Duration::from_millis(to),
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_write_timeout(Some(Duration::from_millis(to)));
    let mut buf = [0u8; 2048];
    let greeting = read_available(&mut stream, &mut buf, to).to_ascii_lowercase();
    if greeting.is_empty() {
        return false;
    }
    let mut response = String::new();
    if greeting.contains("login:") || greeting.contains("username:") {
        if stream
            .write_all(format!("{}\r\n", user).as_bytes())
            .is_err()
        {
            return false;
        }
        response = read_available(&mut stream, &mut buf, to).to_ascii_lowercase();
        if !response.contains("password") {
            return false;
        }
    }
    if stream
        .write_all(format!("{}\r\n", pass).as_bytes())
        .is_err()
    {
        return false;
    }
    let answer = read_available(&mut stream, &mut buf, to).to_ascii_lowercase();
    response.push_str(&answer);
    if [
        "incorrect",
        "invalid",
        "failed",
        "denied",
        "try again",
        "authentication failed",
    ]
    .iter()
    .any(|s| response.contains(s))
    {
        return false;
    }
    let shell_prompt = ['#', '$', '>']
        .iter()
        .any(|c| answer.trim_end().ends_with(*c));
    shell_prompt || answer.contains("welcome") || answer.contains("busybox")
}

pub fn telnet_default_creds(
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    vendor: &str,
    limit: usize,
    explicit_db: Option<&str>,
) -> Vec<Finding> {
    let db = load(explicit_db);
    let pairs = select(&db, "telnet", vendor, limit);
    let to = timeout_ms.max(150).min(900);
    for (user, pass) in &pairs {
        if telnet_attempt(ip, port, to, user, pass) {
            return vec![found(
                "DEFAULT_CREDS_TELNET",
                "Default Telnet credentials accepted",
                user,
                pass,
                ip,
                port,
                "telnet",
            )];
        }
    }
    Vec::new()
}

fn ftp_attempt(ip: Ipv4Addr, port: u16, to: u64, user: &str, pass: &str) -> Option<&'static str> {
    let mut stream = match TcpStream::connect_timeout(
        &std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port),
        Duration::from_millis(to),
    ) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(to)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(to)));
    let mut buf = [0u8; 1024];
    let greeting = read_available(&mut stream, &mut buf, to);
    if !greeting.starts_with('2') {
        return None;
    }
    if stream
        .write_all(format!("USER {}\r\n", user).as_bytes())
        .is_err()
    {
        return None;
    }
    let user_reply = read_available(&mut stream, &mut buf, to);
    if !(user_reply.starts_with("331") || user_reply.starts_with("230")) {
        return None;
    }
    if stream
        .write_all(format!("PASS {}\r\n", pass).as_bytes())
        .is_err()
    {
        return None;
    }
    let pass_reply = read_available(&mut stream, &mut buf, to);
    if pass_reply.starts_with("230") {
        Some(if user.eq_ignore_ascii_case("anonymous") {
            "FTP_ANONYMOUS"
        } else {
            "DEFAULT_CREDS_FTP"
        })
    } else {
        None
    }
}

pub fn ftp_default_creds(
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    vendor: &str,
    limit: usize,
    explicit_db: Option<&str>,
) -> Vec<Finding> {
    let db = load(explicit_db);
    let pairs = select(&db, "ftp", vendor, limit);
    let to = timeout_ms.max(150).min(1200);
    for (user, pass) in &pairs {
        if let Some(id) = ftp_attempt(ip, port, to, user, pass) {
            let sev = if id == "FTP_ANONYMOUS" {
                "high"
            } else {
                "critical"
            };
            let mut f = found(id, "FTP login accepted", user, pass, ip, port, "ftp");
            f.severity = sev.into();
            return vec![f];
        }
    }
    Vec::new()
}

pub fn rtsp_default_creds(
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    vendor: &str,
    limit: usize,
    explicit_db: Option<&str>,
) -> Vec<Finding> {
    let db = load(explicit_db);
    let pairs = select(&db, "rtsp", vendor, limit);
    if pairs.is_empty() {
        return Vec::new();
    }
    let to = timeout_ms.max(100);
    let path = format!("rtsp://{}:{}/", ip, port);
    let initial = match protocols::rtsp_request(ip, port, "OPTIONS", &path, None, to) {
        Some(r) => r,
        None => return Vec::new(),
    };
    if initial.status != 401 {
        return Vec::new();
    }
    let challenge = initial.header("www-authenticate").unwrap_or("Basic");
    let digest = http::parse_digest(challenge);
    for (user, pass) in &pairs {
        let auth = match &digest {
            Some(d) => http::digest_header(user, pass, "OPTIONS", &path, d),
            None => format!("Basic {}", http::b64(&format!("{}:{}", user, pass))),
        };
        if let Some(resp) = protocols::rtsp_request(ip, port, "OPTIONS", &path, Some(&auth), to) {
            if resp.status == 200 {
                return vec![found(
                    "DEFAULT_CREDS_RTSP",
                    "Default RTSP credentials accepted",
                    user,
                    pass,
                    ip,
                    port,
                    if digest.is_some() { "digest" } else { "basic" },
                )];
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_loads_and_selects() {
        let db = decode(CREDS_DB).unwrap();
        assert!(!db.generic.http.is_empty());
        assert!(vendor_set(&db, "hikvision").is_some());
        let pairs = select(&db, "http", "Hikvision", 10);
        assert!(pairs.len() <= 10);
        assert!(pairs.iter().any(|(u, p)| u == "admin" && p == "12345"));
    }

    #[test]
    fn telnet_reconnects_after_failure() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        let server = thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let mut buf = [0u8; 256];
                let _ = stream.write_all(b"login: ");
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"Password: ");
                let _ = stream.read(&mut buf);
                let reply = if attempt == 0 {
                    b"Login incorrect\r\n".as_slice()
                } else {
                    b"Welcome to BusyBox v1.2\r\n".as_slice()
                };
                let _ = stream.write_all(reply);
            }
        });
        let findings = telnet_default_creds(
            "127.0.0.1".parse().unwrap(),
            port,
            600,
            "NoSuchVendor",
            3,
            None,
        );
        server.join().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn form_fields() {
        let html = r#"<form method="post" action="/login.cgi"><input name="username" type="text"><input type="password" name="pwd"></form>"#;
        let (action, user, pass) = parse_form(html).unwrap();
        assert_eq!(action, "/login.cgi");
        assert_eq!(user, "username");
        assert_eq!(pass, "pwd");
    }
}
