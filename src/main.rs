mod cli;
mod config;
mod diff;
mod iot;
mod json;
mod net;
mod sarif;
mod selftest;
mod source;
mod types;
mod update;

use crate::cli::{Command, ScanOpts};
use crate::iot::creds as dc;
use crate::iot::{cve, fingerprints, protocols, upnp};
use crate::net::discover;
use crate::net::ports;
use crate::net::subnet::Subnet;
use crate::types::{Finding, HostResult, PortResult, ScanReport, Severity, Summary};
use crate::update as upd;
use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// Counting semaphore: a hard ceiling on simultaneous sockets, independent of worker count.
pub struct Semaphore {
    cur: Mutex<usize>,
    max: usize,
    cond: Condvar,
}

pub struct SemaphoreGuard<'a>(&'a Semaphore);

impl Drop for SemaphoreGuard<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl Semaphore {
    /// RAII acquisition: the slot is returned even if a probe unwinds.
    pub fn guard(&self) -> SemaphoreGuard<'_> {
        self.acquire();
        SemaphoreGuard(self)
    }

    pub fn new(max: usize) -> Self {
        Self {
            cur: Mutex::new(0),
            max: max.max(1),
            cond: Condvar::new(),
        }
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
        if *g > 0 {
            *g -= 1;
        }
        self.cond.notify_one();
    }
}

fn now_str() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs.to_string()
}

#[allow(clippy::too_many_arguments)]
fn scan_host(
    ip: std::net::Ipv4Addr,
    opts: &ScanOpts,
    custom_ports: Option<&[u16]>,
    mdns: &BTreeMap<std::net::Ipv4Addr, discover::MdnsEntry>,
    ssdp: &BTreeMap<std::net::Ipv4Addr, discover::SsdpEntry>,
    arp: &BTreeMap<std::net::Ipv4Addr, String>,
    sem: &Arc<Semaphore>,
    passive: bool,
    cred_limit: usize,
    cve_db: &[cve::CveEntry],
    cred_db: &dc::CredDb,
) -> Option<HostResult> {
    let discovered = mdns.contains_key(&ip) || ssdp.contains_key(&ip) || arp.contains_key(&ip);
    if passive && !discovered {
        return None;
    }
    if !discovered && !passive {
        let mut probes: Vec<u16> = vec![80, 443, 22, 554];
        if let Some(custom) = custom_ports {
            probes.extend(custom.iter().take(4));
        }
        probes.sort_unstable();
        probes.dedup();
        if !discover::tcp_alive_ports(ip, opts.timeout, &probes) {
            return None;
        }
    }

    let mut port_results: Vec<PortResult> = Vec::new();
    if !passive {
        let list: &[u16] = custom_ports.unwrap_or_else(|| ports::ports_for(opts.fast, opts.deep));
        if list.len() >= 24 {
            // A single quiet host used to serialise ~100 connect timeouts. Split
            // the port list; the semaphore remains the global concurrency cap.
            let collected = Mutex::new(Vec::new());
            let sem_ref = sem.as_ref();
            let timeout = opts.timeout;
            let per_thread = (list.len() + 3) / 4;
            std::thread::scope(|scope| {
                for chunk in list.chunks(per_thread) {
                    let collected = &collected;
                    scope.spawn(move || {
                        for &port in chunk {
                            let _slot = sem_ref.guard();
                            let result = ports::scan_port(ip, port, timeout);
                            if result.open {
                                collected.lock().unwrap().push(result);
                            }
                        }
                    });
                }
            });
            port_results = collected.into_inner().unwrap_or_default();
        } else {
            for &p in list {
                let _slot = sem.guard();
                let r = ports::scan_port(ip, p, opts.timeout);
                if r.open {
                    port_results.push(r);
                }
            }
        }
        port_results.sort_by_key(|p| p.port);
    }

    let hostname = mdns.get(&ip).and_then(|e| e.name.clone());
    let mac = arp.get(&ip).cloned();
    let protocols = fingerprints::classify_ports(&port_results);

    let mut banner_text = port_results
        .iter()
        .flat_map(|p| {
            [
                p.banner.clone(),
                p.server.clone(),
                p.title.clone(),
                p.service.clone(),
            ]
        })
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(h) = &hostname {
        banner_text.push(' ');
        banner_text.push_str(h);
    }
    if let Some(entry) = mdns.get(&ip) {
        for value in &entry.txt {
            banner_text.push(' ');
            banner_text.push_str(value);
        }
    }

    let mut device_type = None;
    let mut vendor = None;
    let mut model = None;
    for pr in &port_results {
        if let Some(fp) = fingerprints::fingerprint(
            pr.port,
            pr.banner.as_deref(),
            pr.service.as_deref(),
            pr.title.as_deref(),
            pr.server.as_deref(),
        ) {
            device_type = Some(fp.device_type.to_string());
            if !fp.vendor.is_empty() {
                vendor = Some(fp.vendor.to_string());
            }
            break;
        }
    }
    if vendor.is_none() {
        vendor = fingerprints::vendor_of(&banner_text).map(|v| v.to_string());
    }
    if device_type.is_none() {
        device_type = fingerprints::device_types(&banner_text)
            .first()
            .map(|d| d.to_string());
    }

    let mut findings: Vec<Finding> = Vec::new();

    if !passive {
        if let Some(entry) = ssdp.get(&ip) {
            if entry
                .search_target
                .as_deref()
                .map(|s| s.to_ascii_lowercase().contains("internetgatewaydevice"))
                .unwrap_or(false)
            {
                let mut f = Finding::new(
                    "UPNP_IGD_EXPOSED",
                    "high",
                    "UPnP Internet Gateway Device exposed to LAN",
                    format!("SSDP on {} advertises WAN port mapping capability", ip),
                );
                f.confidence = Some("high".into());
                findings.push(f);
            }
            if let Some(loc) = &entry.location {
                sem.acquire();
                let dev = upnp::fetch_device(loc, opts.timeout);
                sem.release();
                if let Some(dev) = dev {
                    if device_type.is_none() {
                        device_type = dev.device_type.clone().or(dev.friendly_name.clone());
                    }
                    if vendor.is_none() {
                        vendor = dev.manufacturer.clone();
                    }
                    if model.is_none() {
                        model = dev.model_name.clone().or_else(|| dev.model_number.clone());
                    }
                    if let Some(fw) = &dev.firmware {
                        findings.push(Finding::new(
                            "UPNP_FIRMWARE",
                            "info",
                            "UPnP firmware version disclosed",
                            fw.clone(),
                        ));
                    }
                    if let Some(control) = &dev.control_url {
                        sem.acquire();
                        let igd = upnp::igd_info(loc, control, opts.timeout);
                        sem.release();
                        if let Some((external, mappings)) = igd {
                            if let Some(ip) = external {
                                findings.push(Finding::new(
                                    "UPNP_WAN_IP",
                                    "info",
                                    "UPnP IGD disclosed the WAN IP address",
                                    ip,
                                ));
                            }
                            if !mappings.is_empty() {
                                let sample = mappings
                                    .iter()
                                    .take(3)
                                    .map(|m| {
                                        format!("{}/{}->{}", m.external, m.protocol, m.internal)
                                    })
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                let mut f = Finding::new(
                                    "UPNP_PORT_MAPPINGS",
                                    "high",
                                    "UPnP IGD exposes active WAN port mappings",
                                    format!("{} mapping(s): {}", mappings.len(), sample),
                                );
                                f.confidence = Some("high".into());
                                findings.push(f);
                            }
                        }
                    }
                }
            }
        }

        for pr in &port_results {
            let service = pr.service.as_deref().unwrap_or("");
            let vendor_name = vendor.as_deref().unwrap_or("");

            if (service == "http" || service == "https") && !opts.no_creds && !pr.tls {
                sem.acquire();
                let found = dc::http_default_creds(
                    ip,
                    pr.port,
                    opts.timeout,
                    vendor_name,
                    cred_limit,
                    cred_db,
                );
                sem.release();
                findings.extend(found);
                sem.acquire();
                findings.extend(protocols::http_unauth_api(ip, pr.port, opts.timeout));
                sem.release();
            }
            if pr.port == 21 && !opts.no_creds {
                sem.acquire();
                findings.extend(dc::ftp_default_creds(
                    ip,
                    pr.port,
                    opts.timeout,
                    vendor_name,
                    cred_limit,
                    cred_db,
                ));
                sem.release();
            }
            if (pr.port == 23 || pr.port == 2323) && !opts.no_creds {
                sem.acquire();
                findings.extend(dc::telnet_default_creds(
                    ip,
                    pr.port,
                    opts.timeout,
                    vendor_name,
                    cred_limit,
                    cred_db,
                ));
                sem.release();
            }
            if (pr.port == 554 || pr.port == 8554) && !opts.no_creds {
                sem.acquire();
                findings.extend(dc::rtsp_default_creds(
                    ip,
                    pr.port,
                    opts.timeout,
                    vendor_name,
                    cred_limit,
                    cred_db,
                ));
                findings.extend(protocols::rtsp_probe(ip, pr.port, opts.timeout));
                sem.release();
            }
            if pr.port == 1883 || pr.port == 8883 {
                sem.acquire();
                findings.extend(protocols::mqtt_anonymous(ip, pr.port, opts.timeout));
                sem.release();
            }
            if pr.port == 5683 {
                sem.acquire();
                findings.extend(protocols::coap_probe(ip, pr.port, opts.timeout));
                sem.release();
            }
            if pr.port == 6379 {
                sem.acquire();
                findings.extend(protocols::redis_probe(ip, pr.port, opts.timeout));
                sem.release();
            }
            if pr.port == 11211 {
                sem.acquire();
                findings.extend(protocols::memcached_probe(ip, pr.port, opts.timeout));
                sem.release();
            }
            if pr.port == 502 {
                sem.acquire();
                findings.extend(protocols::modbus_probe(ip, pr.port, opts.timeout));
                sem.release();
            }
            if pr.port == 5555 {
                sem.acquire();
                findings.extend(protocols::adb_probe(ip, pr.port, opts.timeout));
                sem.release();
            }
        }

        // UDP services do not appear in the TCP port list.
        sem.acquire();
        if !opts.no_creds {
            if let Some(community) = dc::snmp_communities(cred_db).into_iter().next() {
                if let Some(f) = protocols::snmp_probe(ip, &community, opts.timeout) {
                    findings.push(f);
                }
            }
        }
        if let Some(f) = protocols::coap_probe(ip, 5683, opts.timeout) {
            findings.push(f);
        }
        if opts.deep {
            for probe in [
                protocols::ntp_probe as fn(Ipv4Addr, u64) -> Option<Finding>,
                protocols::bacnet_probe,
                protocols::ethernet_ip_probe,
            ] {
                if let Some(f) = probe(ip, opts.timeout) {
                    findings.push(f);
                }
            }
        }
        sem.release();

        let stub = HostResult {
            ip,
            hostname: hostname.clone(),
            mac: mac.clone(),
            vendor: vendor.clone(),
            model: model.clone(),
            ports: port_results.clone(),
            protocols: protocols.clone(),
            device_type: device_type.clone(),
            findings: vec![],
        };
        if !opts.no_cve {
            findings.extend(cve::match_host(
                &stub,
                &port_results,
                cve_db,
                opts.max_cve,
                Severity::parse(&opts.min_severity),
            ));
        }
        findings.extend(cve::weak_services(
            &port_results,
            Severity::parse(&opts.min_severity),
        ));
    }

    // Dedup by id, keep the most severe version of each finding.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    findings.sort_by(|a, b| {
        b.rank()
            .cmp(&a.rank())
            .then_with(|| {
                b.cvss
                    .unwrap_or(0.0)
                    .partial_cmp(&a.cvss.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    findings.retain(|f| seen.insert((f.id.clone(), f.detail.clone())));
    let min = Severity::parse(&opts.min_severity);
    findings.retain(|f| f.rank() >= min);
    // The CVE cap applies to CVE-shaped ids only; weak-config findings stay visible.
    if opts.max_cve > 0 {
        let mut cve_count = 0;
        findings.retain(|f| {
            if f.cve.is_some() || f.id.starts_with("CVE-") {
                cve_count += 1;
                cve_count <= opts.max_cve
            } else {
                true
            }
        });
    }

    Some(HostResult {
        ip,
        hostname,
        mac,
        vendor,
        model,
        ports: port_results,
        protocols,
        device_type,
        findings,
    })
}

/// Device banners can contain control characters that would corrupt a text report.
fn clean(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn render_text(r: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("boggy scan report - target {}\n", r.target));
    out.push_str(&format!("hosts found: {}\n", r.hosts.len()));
    let open: usize = r.hosts.iter().map(|h| h.ports.len()).sum();
    let findings: Vec<&Finding> = r.hosts.iter().flat_map(|h| h.findings.iter()).collect();
    out.push_str(&format!(
        "open ports: {} | findings: {} (critical {}, high {}, medium {}, low {}, info {})\n\n",
        open,
        findings.len(),
        findings
            .iter()
            .filter(|f| f.rank() == Severity::Critical)
            .count(),
        findings
            .iter()
            .filter(|f| f.rank() == Severity::High)
            .count(),
        findings
            .iter()
            .filter(|f| f.rank() == Severity::Medium)
            .count(),
        findings
            .iter()
            .filter(|f| f.rank() == Severity::Low)
            .count(),
        findings
            .iter()
            .filter(|f| f.rank() == Severity::Info)
            .count(),
    ));
    for h in &r.hosts {
        out.push_str(&format!("== {} ==\n", h.ip));
        if let Some(hn) = &h.hostname {
            out.push_str(&format!("  hostname: {}\n", clean(hn)));
        }
        if let Some(m) = &h.mac {
            out.push_str(&format!("  mac: {}\n", m));
        }
        if let Some(v) = &h.vendor {
            out.push_str(&format!("  vendor: {}\n", clean(v)));
        }
        if let Some(m) = &h.model {
            out.push_str(&format!("  model: {}\n", clean(m)));
        }
        if let Some(d) = &h.device_type {
            out.push_str(&format!("  type: {}\n", clean(d)));
        }
        if !h.protocols.is_empty() {
            out.push_str(&format!("  protocols: {}\n", h.protocols.join(", ")));
        }
        if !h.ports.is_empty() {
            out.push_str("  open ports:\n");
            for p in &h.ports {
                out.push_str(&format!(
                    "    {}/{} {}\n",
                    p.port,
                    p.service.clone().unwrap_or_default(),
                    clean(p.banner.as_deref().unwrap_or(""))
                ));
            }
        }
        if !h.findings.is_empty() {
            out.push_str("  findings:\n");
            for f in &h.findings {
                out.push_str(&format!(
                    "    [{}] {} - {}",
                    f.rank().as_str(),
                    clean(&f.title),
                    clean(&f.detail)
                ));
                if let Some(cvss) = f.cvss {
                    out.push_str(&format!(" [CVSS {}]", cvss));
                }
                if let Some(c) = &f.confidence {
                    out.push_str(&format!(" [{}]", c));
                }
                out.push('\n');
                if let Some(c) = &f.cve {
                    out.push_str(&format!("        {}\n", c));
                }
            }
        }
        out.push('\n');
    }
    if let Some(diff) = &r.diff {
        out.push_str(&crate::diff::render_text(diff));
    }
    out
}

fn build_report_text(report: &ScanReport, output: &str) -> String {
    match output {
        "json" => report.to_json().pretty(),
        "jsonl" => report
            .hosts
            .iter()
            .map(|h| h.to_json().compact())
            .collect::<Vec<_>>()
            .join("\n"),
        "sarif" => sarif::render(report),
        _ => render_text(report),
    }
}

fn release_summary() -> Result<String, String> {
    let check = upd::check_latest()?;
    let mut out = format!(
        "boggy {}{} (latest release {})",
        check.version,
        if check.newer { " is outdated" } else { "" },
        check.tag
    );
    if !check.assets.is_empty() {
        out.push_str(&format!("\nassets: {}", check.assets.join(", ")));
    }
    Ok(out)
}

fn main() {
    let cli = match cli::parse(std::env::args().skip(1)) {
        Ok(cli) => cli,
        Err(cli::ParseError::Help(text)) => {
            println!("{}", text);
            return;
        }
        Err(cli::ParseError::Version) => {
            println!("boggy {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Err(cli::ParseError::Message(message)) => {
            eprintln!("boggy: {}", message);
            std::process::exit(1);
        }
    };

    match &cli.command {
        Some(Command::UpdateDb { db }) => {
            match upd::update_databases(&db.to_opts()) {
                Ok(summary) => println!("{}", summary),
                Err(e) => {
                    eprintln!("update failed: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(Command::Update {
            src,
            self_update,
            check_only,
        }) => {
            if *check_only {
                match release_summary() {
                    Ok(text) => println!("{}", text),
                    Err(e) => {
                        eprintln!("release check failed: {}", e);
                        std::process::exit(1);
                    }
                }
                return;
            }
            if *self_update {
                match upd::self_update(false) {
                    Ok(message) => println!("{}", message),
                    Err(e) => {
                        eprintln!("self-update failed: {}", e);
                        std::process::exit(1);
                    }
                }
                return;
            }
            match source::update(src) {
                Ok(message) => println!("{}", message),
                Err(e) => {
                    eprintln!("source update failed: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(Command::SelfUpdate { allow_http }) => {
            match upd::self_update(*allow_http) {
                Ok(message) => println!("{}", message),
                Err(e) => {
                    eprintln!("self-update failed: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(Command::UpdateCheck) => {
            match release_summary() {
                Ok(text) => println!("{}", text),
                Err(e) => {
                    eprintln!("release check failed: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(Command::DbInfo) => {
            match upd::db_info() {
                Ok(info) => println!("{}", info),
                Err(e) => {
                    eprintln!("db-info failed: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(Command::Config { show_path }) => {
            if *show_path {
                println!("{}", config::path().display());
            } else {
                println!("{}", config::show());
            }
            return;
        }
        Some(Command::SelfTest) => {
            match selftest::run() {
                Ok(report) => println!("{}", report),
                Err(report) => {
                    eprint!("{}", report);
                    std::process::exit(1);
                }
            }
            return;
        }
        None => {}
    }

    let opts = &cli.scan;

    let mut subnets: Vec<Subnet> = Vec::new();
    for t in &opts.target {
        match Subnet::parse(t) {
            Some(s) => subnets.push(s),
            None => {
                eprintln!("invalid target: {}", t);
                std::process::exit(1);
            }
        }
    }
    if opts.auto || subnets.is_empty() {
        match Subnet::auto() {
            Some(s) => subnets.push(s),
            None if subnets.is_empty() => {
                eprintln!("could not auto-detect subnet; use --target CIDR");
                std::process::exit(1);
            }
            None => {}
        }
    }
    let excluded: Vec<Subnet> = opts
        .exclude
        .iter()
        .filter_map(|s| Subnet::parse(s))
        .collect();

    let custom_ports = match &opts.ports {
        Some(spec) => match ports::parse_ports(spec) {
            Some(p) => Some(p),
            None => {
                eprintln!("invalid --ports specification: {}", spec);
                std::process::exit(1);
            }
        },
        None => None,
    };

    let discovery_ms = opts.discovery_ms.max(100);
    // mDNS and SSDP both wait for multicast replies; run them concurrently.
    let mdns_handle = thread::spawn(move || discover::mdns_scan(discovery_ms));
    let ssdp_entries = discover::ssdp_scan(discovery_ms);
    let mdns_entries = mdns_handle.join().unwrap_or_default();

    if opts.max_hosts > 0 {
        let projected: usize = subnets.iter().map(Subnet::host_count).sum();
        if projected > opts.max_hosts {
            eprintln!(
                "target expands to {} hosts (limit {}); narrow --target or raise --max-hosts",
                projected, opts.max_hosts
            );
            std::process::exit(1);
        }
    }

    let mut all_hosts: Vec<std::net::Ipv4Addr> = Vec::new();
    for s in &subnets {
        all_hosts.extend(s.hosts());
    }
    all_hosts.retain(|ip| !excluded.iter().any(|s| s.contains(*ip)));
    all_hosts.sort();
    all_hosts.dedup();

    if !opts.passive {
        discover::arp_sweep(&all_hosts);
    }
    let mut arp = discover::arp_table();

    let mut mdns_map: BTreeMap<std::net::Ipv4Addr, discover::MdnsEntry> = BTreeMap::new();
    for e in mdns_entries {
        mdns_map.entry(e.ip).or_insert(e);
    }
    let mut ssdp_map: BTreeMap<std::net::Ipv4Addr, discover::SsdpEntry> = BTreeMap::new();
    for e in ssdp_entries {
        ssdp_map.entry(e.ip).or_insert(e);
    }
    for ip in mdns_map.keys().chain(ssdp_map.keys()).chain(arp.keys()) {
        if all_hosts.contains(ip) {
            continue;
        }
        if subnets.iter().any(|s| s.contains(*ip)) && !excluded.iter().any(|s| s.contains(*ip)) {
            all_hosts.push(*ip);
        }
    }
    arp.retain(|ip, _| all_hosts.contains(ip));
    all_hosts.sort();
    all_hosts.dedup();

    if opts.max_hosts > 0 && all_hosts.len() > opts.max_hosts {
        eprintln!(
            "target expands to {} hosts (limit {}); narrow --target or raise --max-hosts",
            all_hosts.len(),
            opts.max_hosts
        );
        std::process::exit(1);
    }

    if opts.verbose {
        eprintln!(
            "boggy: {} hosts in scope, {} discovered (mDNS/SSDP/ARP)",
            all_hosts.len(),
            mdns_map.len() + ssdp_map.len() + arp.len()
        );
    }

    let started = now_str();
    let mdns_arc = Arc::new(mdns_map);
    let ssdp_arc = Arc::new(ssdp_map);
    let arp_arc = Arc::new(arp);

    let rate = if opts.rate_limit == 0 {
        opts.threads.saturating_mul(2).max(8)
    } else {
        opts.rate_limit
    };
    let sem = Arc::new(Semaphore::new(rate));
    // Parsing the 500 KB CVE database once per host was the dominant CPU cost.
    let cve_db = Arc::new(cve::load(opts.cve_file.as_deref()));
    let cred_db = Arc::new(dc::load(opts.creds_file.as_deref()));
    let cred_limit = if opts.fast {
        opts.cred_limit.min(8)
    } else {
        opts.cred_limit
    };

    let (tx, rx) = mpsc::channel::<std::net::Ipv4Addr>();
    let rx = Arc::new(Mutex::new(rx));
    let (res_tx, res_rx) = mpsc::channel::<HostResult>();

    let workers = if opts.threads == 64 {
        all_hosts.len().clamp(1, 64)
    } else {
        opts.threads.max(1)
    };
    let mut handles = Vec::new();
    for _ in 0..workers {
        let rx = rx.clone();
        let res_tx = res_tx.clone();
        let opts = opts.clone();
        let ports_arc = custom_ports.clone();
        let mdns = mdns_arc.clone();
        let ssdp = ssdp_arc.clone();
        let arp = arp_arc.clone();
        let sem = sem.clone();
        let cve_db = cve_db.clone();
        let cred_db = cred_db.clone();
        let verbose = opts.verbose;
        handles.push(thread::spawn(move || loop {
            let ip = {
                let guard = rx.lock().unwrap();
                guard.recv()
            };
            match ip {
                Ok(ip) => {
                    if let Some(h) = scan_host(
                        ip,
                        &opts,
                        ports_arc.as_deref(),
                        &mdns,
                        &ssdp,
                        &arp,
                        &sem,
                        opts.passive,
                        cred_limit,
                        &cve_db,
                        &cred_db,
                    ) {
                        if verbose {
                            eprintln!(
                                "boggy: {} - {} ports, {} findings",
                                ip,
                                h.ports.len(),
                                h.findings.len()
                            );
                        }
                        let _ = res_tx.send(h);
                    }
                }
                Err(_) => break,
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
    for h in handles {
        let _ = h.join();
    }
    hosts.sort_by_key(|h| h.ip);

    let finished = now_str();
    let target_str = if opts.target.is_empty() {
        "auto".into()
    } else {
        opts.target.join(",")
    };
    let mut summary = Summary {
        hosts: hosts.len(),
        open_ports: hosts.iter().map(|h| h.ports.len()).sum(),
        ..Summary::default()
    };
    for h in &hosts {
        for f in &h.findings {
            summary.findings += 1;
            match f.rank() {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
    }

    let mut report = ScanReport {
        target: target_str,
        hosts,
        started,
        finished,
        summary,
        diff: None,
    };
    if let Some(baseline) = &opts.compare {
        match diff::compare(&report, baseline) {
            Ok(result) => report.diff = Some(result),
            Err(e) => {
                eprintln!("baseline comparison failed: {}", e);
                std::process::exit(1);
            }
        }
    }
    let text = build_report_text(&report, &opts.output);
    if let Some(path) = &opts.out {
        match upd::atomic_write(std::path::Path::new(path), text.as_bytes(), false) {
            Ok(()) => eprintln!("report written to {}", path),
            Err(e) => {
                eprintln!("write failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("{}", text);
    }

    if let Some(fail_on) = &opts.fail_on {
        let threshold = Severity::parse(fail_on);
        if report
            .hosts
            .iter()
            .any(|h| h.findings.iter().any(|f| f.rank() >= threshold))
        {
            std::process::exit(2);
        }
    }
}
