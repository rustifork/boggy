use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub tls: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub ports: Vec<PortResult>,
    pub protocols: Vec<String>,
    pub device_type: Option<String>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub cve: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub hosts: Vec<HostResult>,
    pub started: String,
    pub finished: String,
}