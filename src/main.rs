mod cli;
mod iot;
mod net;
mod types;

use crate::cli::{Cli, Command, ScanOpts};
use crate::iot::cve;
use crate::iot::default_creds as dc;
use crate::iot::fingerprints;
use crate::iot::upnp;
use crate::net::discover;
use crate::net::ports;
use crate::net::subnet::Subnet;
use crate::types::{Finding, HostResult, PortResult, ScanReport};
use clap::Parser;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

// Simple counting semaphore for rate limiting concurrent connections.
pub struct Semaphore {
    cur: Mutex<usize>,
    max: usize,
    cond: std::sync::Condvar,
}
impl Semaphore {
    pub fn new(max: usize) -> Self {
        Self { cur: Mutex::new(0), max: max.max(1), cond: std::sync::Condvar::new() }
    }
    pub fn acquire(&self) {
        let mut g = self.cur.lock().unwrap();
        while *g >= self.max {
            g = self.cond.wait(g).unwrap();
        }
        *g += 1;
    }
    pub fn release(&self) {
        let mut g = self.cur.lock().unwrap();
        if *g > 0 { *g -= 1; }
        self.cond.notify_one();
    }
}

fn now_str() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{}", secs)
}

fn fetch_url(url: &str) -> Result<String, String> {
    if url.starts_with("https://") {
        #[cfg(feature = "https")]
        {
            match ureq::get(url).call() {
                Ok(resp) => {
                    let mut s = String::new();
                    use std::io::Read;
                    resp.into_reader().read_to_string(&mut s).map_err(|e| e.to_string())?;
                    return Ok(s);
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        #[cfg(not(feature = "https"))]
        {
            use std::process::Command;
            let out = Command::new("curl").args(["-fsSL", url]).output();
            if let Ok(o) = out {
                if o.status.success() {
                    return Ok(String::from_utf8_lossy(&o.stdout).to_string());
                }
            }
            let out = Command::new("wget").args(["-qO-", url]).output();
            if let Ok(o) = out {
                if o.status.success() {
                    return Ok(String::from_utf8_lossy(&o.stdout).to_string());
                }
            }
            return Err("https fetch requires curl or wget (build with --features https)".into());
        }
    }
    // http
    let without = url.strip_prefix("http://").ok_or("bad url")?;
    let (hostpart, path) = if let Some(i) = without.find('/') {
        (&without[..i], &without[i..])
    } else {
        (without, "/")
    };
    let host = hostpart.split(':').next().unwrap_or(hostpart);
    let port: u16 = if let Some(p) = hostpart.split(':').nth(1) { p.parse().unwrap_or(80) } else { 80 };
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut stream = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let req = format!("GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", path, hostpart);
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    if let Some(i) = text.find("\r\n\r\n") { Ok(text[i+4..].to_string()) } else { Ok(text) }
}

fn update_db(opts_out: Option<String>, url: &str) {
    match fetch_url(url) {
        Ok(body) => {
            // validate JSON
            if serde_json::from_str::<serde_json::Value>(&body).is_err() {
                eprintln!("downloaded data is not valid JSON");
                std::process::exit(1);
            }
            let dest = if let Some(p) = opts_out {
                p
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                format!("{}/.boggy/cves.json", home)
            };
            if let Some(parent) = std::path::Path::new(&dest).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(&dest, body) {
                Ok(_) => println!("CVE database updated: {}", dest),
                Err(e) => { eprintln!("write failed: {}", e); std::process::exit(1); }
            }
        }
        Err(e) => { eprintln!("download failed: {}", e); std::process::exit(1); }
    }
}

fn scan_host(
    ip: std::net::Ipv4Addr,
    opts: &ScanOpts,
    mdns: &BTreeMap<std::net::Ipv4Addr, discover::MdnsEntry>,
    ssdp: &BTreeMap<std::net::Ipv4Addr, discover::SsdpEntry>,
    arp: &BTreeMap<std::net::Ipv4Addr, String>,
    sem: &Arc<Semaphore>,
    passive: bool,
) -> Option<HostResult> {
    let discovered = mdns.contains_key(&ip) || ssdp.contains_key(&ip) || arp.contains_key(&ip);
    if passive && !discovered {
        return None;
    }
    if !discovered && !passive {
        if !discover::tcp_alive(ip, opts.timeout) { return None; }
    }

    let mut port_results: Vec<PortResult> = Vec::new();

    if !passive {
        let port_list = ports::ports_for(opts.fast, opts.deep);
        for &p in port_list {
            sem.acquire();
            let r = ports::scan_port(ip, p, opts.timeout);
            sem.release();
            if r.open { port_results.push(r); }
        }
    }

    let hostname = mdns.get(&ip).and_then(|e| e.name.clone());
    let mac = arp.get(&ip).cloned();
    let vendor = None;
    let protocols = fingerprints::classify_ports(&port_results);

    let mut device_type = None;
    for pr in &port_results {
        if let Some(fp) = fingerprints::fingerprint(pr.port, pr.banner.as_deref(), pr.service.as_deref()) {
            device_type = Some(fp.device_type.to_string());
            break;
        }
    }

    let mut findings: Vec<Finding> = Vec::new();

    if !passive {
        if let Some(entry) = ssdp.get(&ip) {
            if let Some(loc) = &entry.location {
                if let Some(dev) = upnp::fetch_device(loc, opts.timeout) {
                    if device_type.is_none() {
                        device_type = dev.device_type.clone().or(dev.friendly_name.clone());
                    }
                    if let Some(fw) = &dev.firmware {
                        findings.push(Finding {
                            id: "UPNP_FIRMWARE".into(),
                            severity: "info".into(),
                            title: "UPnP firmware version disclosed".into(),
                            detail: fw.clone(),
                            cve: None,
                        });
                    }
                }
            }
        }

        for pr in &port_results {
            if let Some(f) = dc::telnet_finding(pr.port) {
                findings.push(f);
            }
            if pr.service.as_deref() == Some("http") || pr.service.as_deref() == Some("https") {
                let http_findings = dc::http_default_creds(ip, pr.port, opts.timeout);
                findings.extend(http_findings);
            }
            if pr.port == 1883 || pr.port == 8883 {
                if let Some(f) = dc::mqtt_anonymous(ip, pr.port, opts.timeout) {
                    findings.push(f);
                }
            }
            if pr.port == 554 {
                if let Some(f) = dc::rtsp_finding(ip, pr.port, opts.timeout) {
                    findings.push(f);
                }
            }
            if pr.port == 5683 {
                if let Some(f) = dc::coap_probe(ip, pr.port, opts.timeout) {
                    findings.push(f);
                }
            }
        }

        let host_stub = HostResult {
            ip,
            hostname: hostname.clone(),
            mac: mac.clone(),
            vendor: vendor.clone(),
            ports: port_results.clone(),
            protocols: protocols.clone(),
            device_type: device_type.clone(),
            findings: vec![],
        };
        let cve_findings = cve::match_host(&host_stub, &port_results);
        findings.extend(cve_findings);
    }

    // dedup findings by id
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));

    let host = HostResult {
        ip,
        hostname,
        mac,
        vendor,
        ports: port_results,
        protocols,
        device_type,
        findings,
    };
    Some(host)
}

fn render_text(r: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("boggy scan report - target {}\n", r.target));
    out.push_str(&format!("hosts found: {}\n\n", r.hosts.len()));
    for h in &r.hosts {
        out.push_str(&format!("== {} ==\n", h.ip));
        if let Some(hn) = &h.hostname { out.push_str(&format!("  hostname: {}\n", hn)); }
        if let Some(m) = &h.mac { out.push_str(&format!("  mac: {}\n", m)); }
        if let Some(d) = &h.device_type { out.push_str(&format!("  type: {}\n", d)); }
        if !h.protocols.is_empty() { out.push_str(&format!("  protocols: {}\n", h.protocols.join(", "))); }
        if !h.ports.is_empty() {
            out.push_str("  open ports:\n");
            for p in &h.ports {
                out.push_str(&format!("    {}/{} {}\n", p.port, p.service.clone().unwrap_or_default(), p.banner.clone().unwrap_or_default()));
            }
        }
        if !h.findings.is_empty() {
            out.push_str("  findings:\n");
            for f in &h.findings {
                out.push_str(&format!("    [{}] {} - {}\n", f.severity, f.title, f.detail));
                if let Some(c) = &f.cve { out.push_str(&format!("        {}\n", c)); }
            }
        }
        out.push('\n');
    }
    out
}

fn main() {
    let cli = Cli::parse();

    if let Some(Command::UpdateDb { out, url }) = &cli.command {
        update_db(out.clone(), url);
        return;
    }

    let opts = &cli.scan;

    // resolve subnets
    let mut subnets: Vec<Subnet> = Vec::new();
    if let Some(t) = &opts.target {
        if let Some(s) = Subnet::parse(t) { subnets.push(s); }
        else { eprintln!("invalid target: {}", t); std::process::exit(1); }
    }
    if opts.auto || subnets.is_empty() {
        if let Some(s) = Subnet::auto() { subnets.push(s); }
        else { eprintln!("could not auto-detect subnet"); if subnets.is_empty() { std::process::exit(1); } }
    }

    // discovery
    let mdns_entries = discover::mdns_scan(opts.timeout.max(1500));
    let ssdp_entries = discover::ssdp_scan(opts.timeout.max(1500));
    let arp = discover::arp_table();

    let mut mdns_map: BTreeMap<std::net::Ipv4Addr, discover::MdnsEntry> = BTreeMap::new();
    for e in mdns_entries { mdns_map.entry(e.ip).or_insert(e); }
    let mut ssdp_map: BTreeMap<std::net::Ipv4Addr, discover::SsdpEntry> = BTreeMap::new();
    for e in ssdp_entries {
        ssdp_map.entry(e.ip).or_insert(e);
    }

    let mut all_hosts: Vec<std::net::Ipv4Addr> = Vec::new();
    for s in &subnets {
        all_hosts.extend(s.hosts());
    }
    all_hosts.sort();
    all_hosts.dedup();

    for ip in mdns_map.keys().chain(ssdp_map.keys()).chain(arp.keys()) {
        if all_hosts.contains(ip) { continue; }
        if subnets.iter().any(|s| s.contains(*ip)) {
            all_hosts.push(*ip);
        }
    }

    let started = now_str();

    let mdns_arc = Arc::new(mdns_map);
    let ssdp_arc = Arc::new(ssdp_map);
    let arp_arc = Arc::new(arp);

    let rate = if opts.rate_limit == 0 {
        (opts.threads * 2).max(8)
    } else {
        opts.rate_limit
    };
    let sem = Arc::new(Semaphore::new(rate));

    let (tx, rx) = mpsc::channel::<std::net::Ipv4Addr>();
    let rx = Arc::new(Mutex::new(rx));
    let (res_tx, res_rx) = mpsc::channel::<HostResult>();

    let workers = if opts.threads == 64 {
        (all_hosts.len() / 4).clamp(8, 128)
    } else {
        opts.threads.max(1)
    };
    let mut handles = Vec::new();
    for _ in 0..workers {
        let rx = rx.clone();
        let res_tx = res_tx.clone();
        let opts = opts.clone();
        let mdns = mdns_arc.clone();
        let ssdp = ssdp_arc.clone();
        let arp = arp_arc.clone();
        let sem = sem.clone();
        let passive = opts.passive;
        handles.push(thread::spawn(move || {
            loop {
                let ip = {
                    let guard = rx.lock().unwrap();
                    guard.recv()
                };
                match ip {
                    Ok(ip) => {
                        if let Some(h) = scan_host(ip, &opts, &*mdns, &*ssdp, &*arp, &sem, passive) {
                            let _ = res_tx.send(h);
                        }
                    }
                    Err(_) => break,
                }
            }
        }));
    }
    drop(res_tx);

    for ip in all_hosts {
        let _ = tx.send(ip);
    }
    drop(tx);

    let mut hosts: Vec<HostResult> = Vec::new();
    while let Ok(h) = res_rx.recv() {
        hosts.push(h);
    }
    for h in handles { let _ = h.join(); }

    hosts.sort_by_key(|h| h.ip);

    let finished = now_str();
    let target_str = opts.target.clone().unwrap_or_else(|| "auto".into());
    let report = ScanReport {
        target: target_str,
        hosts,
        started,
        finished,
    };

    let text = if opts.output == "json" {
        serde_json::to_string_pretty(&report).unwrap_or_default()
    } else {
        render_text(&report)
    };

    if let Some(path) = &opts.out {
        let _ = std::fs::write(path, text);
        eprintln!("report written to {}", path);
    } else {
        println!("{}", text);
    }
}