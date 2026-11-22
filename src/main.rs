mod cli;
mod iot;
mod net;
mod types;

use crate::cli::Cli;
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

fn now_str() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{}", secs)
}

fn scan_host(
    ip: std::net::Ipv4Addr,
    cli: &Cli,
    mdns: &BTreeMap<std::net::Ipv4Addr, discover::MdnsEntry>,
    ssdp: &BTreeMap<std::net::Ipv4Addr, discover::SsdpEntry>,
    arp: &BTreeMap<std::net::Ipv4Addr, String>,
) -> Option<HostResult> {
    // alive check
    let discovered = mdns.contains_key(&ip) || ssdp.contains_key(&ip) || arp.contains_key(&ip);
    if !discovered {
        if !discover::tcp_alive(ip, cli.timeout) { return None; }
    }

    let port_list = ports::ports_for(cli.fast, cli.deep);
    let mut port_results: Vec<PortResult> = Vec::new();
    for &p in port_list {
        let r = ports::scan_port(ip, p, cli.timeout);
        if r.open { port_results.push(r); }
        else { /* keep closed? skip to save */ }
    }
    // We only keep open ports in results; but CVE matching uses open. Fine.
    // Actually keep full? Report smaller if only open. We'll keep open only.
    // But classify ports needs open. OK.

    // hostname from mdns
    let hostname = mdns.get(&ip).and_then(|e| e.name.clone());
    let mac = arp.get(&ip).cloned();
    // vendor not resolved (OUI db omitted for size)
    let vendor = None;

    // protocols
    let protocols = fingerprints::classify_ports(&port_results);

    // device type from fingerprints + upnp
    let mut device_type = None;
    for pr in &port_results {
        if let Some(fp) = fingerprints::fingerprint(pr.port, pr.banner.as_deref(), pr.service.as_deref()) {
            device_type = Some(fp.device_type.to_string());
            break;
        }
    }

    let mut findings: Vec<Finding> = Vec::new();

    // upnp fetch
    if let Some(entry) = ssdp.get(&ip) {
        if let Some(loc) = &entry.location {
            if let Some(dev) = upnp::fetch_device(loc, cli.timeout) {
                if device_type.is_none() {
                    device_type = dev.device_type.clone().or(dev.friendly_name.clone());
                }
                // firmware finding if version present? store as finding maybe
                if let Some(fw) = &dev.firmware {
                    findings.push(Finding {
                        id: "UPNP_FIRMWARE".into(),
                        severity: "info".into(),
                        title: "UPnP firmware version disclosed".into(),
                        detail: fw.clone(),
                        cve: None,
                    });
                }
                // default creds HTTP on upnp ports? handled below
            }
        }
    }

    // default creds / service probes (deep or always for relevant ports)
    let do_creds = cli.deep || true;
    for pr in &port_results {
        // telnet
        if let Some(f) = dc::telnet_finding(pr.port) {
            findings.push(f);
        }
        // http default creds
        if pr.service.as_deref() == Some("http") || pr.service.as_deref() == Some("https") {
            let http_findings = dc::http_default_creds(ip, pr.port, cli.timeout);
            findings.extend(http_findings);
        }
        if pr.port == 1883 || pr.port == 8883 {
            if let Some(f) = dc::mqtt_anonymous(ip, pr.port, cli.timeout) {
                findings.push(f);
            }
        }
        if pr.port == 554 {
            if let Some(f) = dc::rtsp_finding(ip, pr.port, cli.timeout) {
                findings.push(f);
            }
        }
        if pr.port == 5683 {
            if let Some(f) = dc::coap_probe(ip, pr.port, cli.timeout) {
                findings.push(f);
            }
        }
        if do_creds {
            // mqtt/coap already above
        }
    }

    // CVE + weak service matching
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



fn main() {
    let cli = Cli::parse();

    // resolve subnets
    let mut subnets: Vec<Subnet> = Vec::new();
    if let Some(t) = &cli.target {
        if let Some(s) = Subnet::parse(t) { subnets.push(s); }
        else { eprintln!("invalid target: {}", t); std::process::exit(1); }
    }
    if cli.auto || subnets.is_empty() {
        if let Some(s) = Subnet::auto() { subnets.push(s); }
        else { eprintln!("could not auto-detect subnet"); if subnets.is_empty() { std::process::exit(1); } }
    }

    // discovery
    let mdns_entries = discover::mdns_scan(cli.timeout.max(1500));
    let ssdp_entries = discover::ssdp_scan(cli.timeout.max(1500));
    let arp = discover::arp_table();

    let mut mdns_map: BTreeMap<std::net::Ipv4Addr, discover::MdnsEntry> = BTreeMap::new();
    for e in mdns_entries { mdns_map.entry(e.ip).or_insert(e); }
    let mut ssdp_map: BTreeMap<std::net::Ipv4Addr, discover::SsdpEntry> = BTreeMap::new();
    for e in ssdp_entries {
        // resolve ip from location if ip is multicast? src ip usually device
        ssdp_map.entry(e.ip).or_insert(e);
    }

    // collect hosts
    let mut all_hosts: Vec<std::net::Ipv4Addr> = Vec::new();
    for s in &subnets {
        all_hosts.extend(s.hosts());
    }
    // dedup
    all_hosts.sort();
    all_hosts.dedup();

    // include discovered hosts only if within target subnets
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

    let (tx, rx) = mpsc::channel::<std::net::Ipv4Addr>();
    let rx = Arc::new(Mutex::new(rx));
    let (res_tx, res_rx) = mpsc::channel::<HostResult>();

    let workers = if cli.threads == 64 {
        (all_hosts.len() / 4).clamp(8, 128)
    } else {
        cli.threads.max(1)
    };
    let mut handles = Vec::new();
    for _ in 0..workers {
        let rx = rx.clone();
        let res_tx = res_tx.clone();
        let cli = cli.clone();
        let mdns = mdns_arc.clone();
        let ssdp = ssdp_arc.clone();
        let arp = arp_arc.clone();
        handles.push(thread::spawn(move || {
            loop {
                let ip = {
                    let guard = rx.lock().unwrap();
                    guard.recv()
                };
                match ip {
                    Ok(ip) => {
                        if let Some(h) = scan_host(ip, &cli, &*mdns, &*ssdp, &*arp) {
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
    let target_str = cli.target.clone().unwrap_or_else(|| "auto".into());
    let report = ScanReport {
        target: target_str,
        hosts,
        started,
        finished,
    };

    // output
    let text = if cli.output == "json" {
        serde_json::to_string_pretty(&report).unwrap_or_default()
    } else {
        render_text(&report)
    };

    if let Some(path) = &cli.out {
        let _ = std::fs::write(path, text);
        eprintln!("report written to {}", path);
    } else {
        println!("{}", text);
    }
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

