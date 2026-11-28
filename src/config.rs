//! Optional defaults loaded from ~/.boggy/config.json. CLI flags always win.

use crate::cli::ScanOpts;
use crate::json::Json;
use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub target: Vec<String>,
    pub exclude: Vec<String>,
    pub threads: Option<usize>,
    pub rate_limit: Option<usize>,
    pub timeout: Option<u64>,
    pub discovery_ms: Option<u64>,
    pub fast: Option<bool>,
    pub deep: Option<bool>,
    pub passive: Option<bool>,
    pub output: Option<String>,
    pub min_severity: Option<String>,
    pub fail_on: Option<String>,
    pub cred_limit: Option<usize>,
    pub max_cve: Option<usize>,
    pub max_hosts: Option<usize>,
    pub no_creds: Option<bool>,
    pub no_cve: Option<bool>,
}

pub fn path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".boggy/config.json")
}

fn strings(root: &Json, key: &str) -> Vec<String> {
    root.get(key)
        .and_then(Json::as_arr)
        .map(|items| {
            items
                .iter()
                .map(|v| v.string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn num(root: &Json, key: &str) -> Option<usize> {
    root.get(key).and_then(Json::as_u64).map(|v| v as usize)
}

fn boolean(root: &Json, key: &str) -> Option<bool> {
    root.get(key).and_then(|v| match v {
        Json::Bool(b) => Some(*b),
        _ => None,
    })
}

fn text(root: &Json, key: &str) -> Option<String> {
    root.get(key)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map(str::to_string)
}

pub fn load() -> Config {
    let data = match std::fs::read_to_string(path()) {
        Ok(d) => d,
        Err(_) => return Config::default(),
    };
    let root = match crate::json::parse(data.as_bytes()) {
        Ok(v) => v,
        Err(_) => return Config::default(),
    };
    Config {
        target: strings(&root, "target"),
        exclude: strings(&root, "exclude"),
        threads: num(&root, "threads"),
        rate_limit: num(&root, "rate_limit"),
        timeout: num(&root, "timeout").map(|v| v as u64),
        discovery_ms: num(&root, "discovery_ms").map(|v| v as u64),
        fast: boolean(&root, "fast"),
        deep: boolean(&root, "deep"),
        passive: boolean(&root, "passive"),
        output: text(&root, "output"),
        min_severity: text(&root, "min_severity"),
        fail_on: text(&root, "fail_on"),
        cred_limit: num(&root, "cred_limit"),
        max_cve: num(&root, "max_cve"),
        max_hosts: num(&root, "max_hosts"),
        no_creds: boolean(&root, "no_creds"),
        no_cve: boolean(&root, "no_cve"),
    }
}

pub fn apply(config: &Config, scan: &mut ScanOpts) {
    if !config.target.is_empty() {
        scan.target = config.target.clone();
    }
    if !config.exclude.is_empty() {
        scan.exclude = config.exclude.clone();
    }
    if let Some(v) = config.threads {
        scan.threads = v;
    }
    if let Some(v) = config.rate_limit {
        scan.rate_limit = v;
    }
    if let Some(v) = config.timeout {
        scan.timeout = v;
    }
    if let Some(v) = config.discovery_ms {
        scan.discovery_ms = v;
    }
    if let Some(v) = config.fast {
        scan.fast = v;
    }
    if let Some(v) = config.deep {
        scan.deep = v;
    }
    if let Some(v) = config.passive {
        scan.passive = v;
    }
    if let Some(v) = &config.output {
        scan.output = v.clone();
    }
    if let Some(v) = &config.min_severity {
        scan.min_severity = v.clone();
    }
    if let Some(v) = &config.fail_on {
        scan.fail_on = Some(v.clone());
    }
    if let Some(v) = config.cred_limit {
        scan.cred_limit = v;
    }
    if let Some(v) = config.max_cve {
        scan.max_cve = v;
    }
    if let Some(v) = config.max_hosts {
        scan.max_hosts = v;
    }
    if let Some(v) = config.no_creds {
        scan.no_creds = v;
    }
    if let Some(v) = config.no_cve {
        scan.no_cve = v;
    }
}

pub fn show() -> String {
    match std::fs::read_to_string(path()) {
        Ok(data) => match crate::json::parse(data.as_bytes()) {
            Ok(value) => value.pretty(),
            Err(e) => format!("invalid config: {}", e),
        },
        Err(_) => "{}".into(),
    }
}

const NUMERIC: &[&str] = &[
    "threads",
    "rate_limit",
    "timeout",
    "discovery_ms",
    "cred_limit",
    "max_cve",
    "max_hosts",
];
const BOOLEAN: &[&str] = &["fast", "deep", "passive", "no_creds", "no_cve"];
const STRINGS: &[&str] = &["output", "min_severity", "fail_on"];
const LISTS: &[&str] = &["target", "exclude"];

pub fn set(key: &str, value: &str) -> Result<String, String> {
    let root = match std::fs::read_to_string(path()) {
        Ok(data) => crate::json::parse(data.as_bytes()).unwrap_or(Json::Obj(Vec::new())),
        Err(_) => Json::Obj(Vec::new()),
    };
    let mut fields = match root {
        Json::Obj(fields) => fields,
        _ => Vec::new(),
    };
    let new_value = if NUMERIC.contains(&key) {
        let n: u64 = value
            .parse()
            .map_err(|_| format!("{} needs a number", key))?;
        Json::num(n as f64)
    } else if BOOLEAN.contains(&key) {
        match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Json::Bool(true),
            "false" | "0" | "no" => Json::Bool(false),
            _ => return Err(format!("{} needs true or false", key)),
        }
    } else if LISTS.contains(&key) {
        let mut items = match fields
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_arr())
        {
            Some(items) => items.to_vec(),
            None => Vec::new(),
        };
        items.push(Json::str(value));
        Json::arr(items)
    } else if STRINGS.contains(&key) {
        Json::str(value)
    } else {
        return Err(format!(
            "unknown key {} (allowed: {})",
            key,
            [NUMERIC, BOOLEAN, STRINGS, LISTS].concat().join(", ")
        ));
    };
    if let Some((_, field)) = fields.iter_mut().find(|(k, _)| k == key) {
        *field = new_value;
    } else {
        fields.push((key.to_string(), new_value));
    }
    let target = path();
    let data = Json::Obj(fields).pretty();
    crate::update::atomic_write(&target, data.as_bytes(), false)?;
    Ok(format!("{}: {} = {}", target.display(), key, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_or_bad_values() {
        assert!(set("bogus", "1").is_err());
        assert!(set("threads", "many").is_err());
        assert!(set("fast", "maybe").is_err());
    }

    #[test]
    fn applies_only_present_fields() {
        let mut scan = ScanOpts::default();
        let config = Config {
            threads: Some(8),
            min_severity: Some("high".into()),
            ..Config::default()
        };
        apply(&config, &mut scan);
        assert_eq!(scan.threads, 8);
        assert_eq!(scan.min_severity, "high");
        assert_eq!(scan.output, "text");
    }
}
