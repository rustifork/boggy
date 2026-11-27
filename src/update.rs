//! Secure database / binary updates: pinned digests, no redirects, bounded downloads,
//! strict schema validation and atomic replacement.

use crate::net::sha256;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const CVE_URL: &str = "https://raw.githubusercontent.com/rustifork/boggy/main/db/cves.json";
pub const CREDS_URL: &str = "https://raw.githubusercontent.com/rustifork/boggy/main/db/creds.json";
pub const MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/rustifork/boggy/main/db/manifest.json";
pub const RELEASES_URL: &str = "https://api.github.com/repos/rustifork/boggy/releases/latest";

const MAX_DB_BYTES: usize = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_RELEASE_BYTES: usize = 2 * 1024 * 1024;
const MAX_BINARY_BYTES: usize = 48 * 1024 * 1024;
const MAX_ENTRIES: usize = 5000;

#[derive(Clone, Debug)]
pub struct UpdateOpts {
    pub cves_url: String,
    pub creds_url: String,
    pub manifest_url: String,
    pub cves_out: Option<String>,
    pub creds_out: Option<String>,
    pub verify: bool,
    pub allow_http: bool,
    pub cves_only: bool,
    pub creds_only: bool,
    pub cves_sha256: Option<String>,
    pub creds_sha256: Option<String>,
}

impl Default for UpdateOpts {
    fn default() -> Self {
        Self {
            cves_url: CVE_URL.into(),
            creds_url: CREDS_URL.into(),
            manifest_url: MANIFEST_URL.into(),
            cves_out: None,
            creds_out: None,
            verify: true,
            allow_http: false,
            cves_only: false,
            creds_only: false,
            cves_sha256: None,
            creds_sha256: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestFile {
    file: String,
    sha256: String,
    entries: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct Manifest {
    version: u32,
    cves: ManifestFile,
    creds: ManifestFile,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    size: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

/// Validate the scheme before any network or filesystem access.
fn checked_url(url: &str, allow_http: bool) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with("http://") {
        return if allow_http {
            Ok(())
        } else {
            Err(format!("plain HTTP refused for {} (use --allow-http)", url))
        };
    }
    if url.starts_with("file://") {
        return Ok(());
    }
    Err(format!("unsupported URL scheme: {}", url))
}

pub fn fetch_bytes(url: &str, max_bytes: usize, allow_http: bool) -> Result<Vec<u8>, String> {
    checked_url(url, allow_http)?;
    if let Some(path) = url.strip_prefix("file://") {
        let bytes = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
        if bytes.len() > max_bytes {
            return Err(format!("{} is larger than {} bytes", path, max_bytes));
        }
        return Ok(bytes);
    }

    #[cfg(feature = "https")]
    {
        let agent = ureq::builder()
            .timeout(Duration::from_secs(30))
            .timeout_connect(Duration::from_secs(8))
            .redirects(0) // never follow a redirect to another host / scheme
            .user_agent("boggy-update/0.3")
            .build();
        let resp = agent
            .get(url)
            .call()
            .map_err(|e| format!("GET {}: {}", url, e))?;
        if !(200..300).contains(&resp.status()) {
            return Err(format!("GET {} returned HTTP {}", url, resp.status()));
        }
        let mut limited = resp.into_reader().take(max_bytes as u64 + 1);
        let mut out = Vec::new();
        limited
            .read_to_end(&mut out)
            .map_err(|e| format!("read {}: {}", url, e))?;
        if out.len() > max_bytes {
            return Err(format!("{} exceeds the {} byte limit", url, max_bytes));
        }
        Ok(out)
    }
    #[cfg(not(feature = "https"))]
    {
        let mut args = vec!["-fsSL".to_string(), "--max-redirs".into(), "0".into()];
        if !allow_http {
            args.push("--proto".into());
            args.push("=https".into());
        }
        args.push(url.to_string());
        let out = std::process::Command::new("curl")
            .args(&args)
            .output()
            .map_err(|e| format!("curl: {}", e))?;
        if !out.status.success() {
            return Err(format!(
                "GET {} failed (curl exit {:?})",
                url,
                out.status.code()
            ));
        }
        if out.stdout.len() > max_bytes {
            return Err(format!("{} exceeds the {} byte limit", url, max_bytes));
        }
        Ok(out.stdout)
    }
}

const ASSET_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "api.github.com",
    "raw.githubusercontent.com",
];

fn redirect_target(location: &str, current: &str, allow_http: bool) -> Result<String, String> {
    let url = if location.starts_with('/') {
        let scheme_end = current.find("://").ok_or("malformed current URL")? + 3;
        let host_end = current[scheme_end..]
            .find('/')
            .map(|i| scheme_end + i)
            .unwrap_or(current.len());
        format!("{}{}", &current[..host_end], location)
    } else {
        location.to_string()
    };
    checked_url(&url, allow_http)?;
    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .and_then(|h| h.split(':').next())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !ASSET_HOSTS.contains(&host.as_str()) {
        return Err(format!("refusing redirect to untrusted host {}", host));
    }
    Ok(url)
}

/// Release assets live on GitHub's object storage behind a redirect. Follow only
/// HTTPS redirects to GitHub-owned hosts, never forward credentials.
pub fn fetch_asset(url: &str, max_bytes: usize, allow_http: bool) -> Result<Vec<u8>, String> {
    let mut current = url.to_string();
    for _ in 0..4 {
        match fetch_asset_hop(&current, max_bytes, allow_http)? {
            Fetched::Bytes(bytes) => return Ok(bytes),
            Fetched::Redirect(next) => current = next,
        }
    }
    Err("too many asset redirects".into())
}

enum Fetched {
    Bytes(Vec<u8>),
    Redirect(String),
}

#[cfg(feature = "https")]
fn fetch_asset_hop(url: &str, max_bytes: usize, allow_http: bool) -> Result<Fetched, String> {
    let agent = ureq::builder()
        .timeout(Duration::from_secs(60))
        .redirects(0)
        .user_agent("boggy-update/0.3")
        .build();
    let resp = agent.get(url).call().map_err(|e| e.to_string())?;
    if (300..400).contains(&resp.status()) {
        let location = resp
            .header("Location")
            .ok_or_else(|| format!("redirect from {} has no Location", url))?;
        return Ok(Fetched::Redirect(redirect_target(
            location, url, allow_http,
        )?));
    }
    if !(200..300).contains(&resp.status()) {
        return Err(format!("GET {} returned HTTP {}", url, resp.status()));
    }
    let mut out = Vec::new();
    resp.into_reader()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > max_bytes {
        return Err(format!("{} exceeds the {} byte limit", url, max_bytes));
    }
    Ok(Fetched::Bytes(out))
}

#[cfg(not(feature = "https"))]
fn fetch_asset_hop(url: &str, max_bytes: usize, allow_http: bool) -> Result<Vec<u8>, Fetched> {
    fetch_bytes(url, max_bytes, allow_http).map(Fetched::Bytes)
}

fn safe_file_name(name: &str) -> Result<&str, String> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.starts_with('.')
    {
        return Err(format!("unsafe file name in manifest: {}", name));
    }
    Ok(name)
}

fn valid_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid sha256: {}", hash));
    }
    Ok(())
}

/// Replace a file without ever truncating the original: create-new temp file,
/// fsync, then atomic rename over the destination. Symlinks are never followed.
pub fn atomic_write(path: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    let parent = path.parent().ok_or("destination has no parent directory")?;
    fs::create_dir_all(parent).map_err(|e| format!("create {}: {}", parent.display(), e))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("destination has no file name")?;
    let tmp: PathBuf = parent.join(format!(".{}.tmp.{}", name, std::process::id()));

    let cleanup = |e: String| -> String {
        let _ = fs::remove_file(&tmp);
        e
    };
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| cleanup(format!("create {}: {}", tmp.display(), e)))?;
    f.write_all(bytes)
        .map_err(|e| cleanup(format!("write {}: {}", tmp.display(), e)))?;
    f.sync_all()
        .map_err(|e| cleanup(format!("sync {}: {}", tmp.display(), e)))?;
    drop(f);

    set_permissions(&tmp, executable)
        .map_err(|e| cleanup(format!("chmod {}: {}", tmp.display(), e)))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("replace {}: {}", path.display(), e)
    })
}

#[cfg(unix)]
fn set_permissions(path: &Path, executable: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn set_permissions(_path: &Path, _executable: bool) -> Result<(), String> {
    Ok(())
}

fn as_array(value: &Value) -> Result<&Vec<Value>, String> {
    value
        .as_array()
        .ok_or_else(|| "expected a JSON array".into())
}

fn as_object(value: &Value) -> Result<&serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| "expected a JSON object".into())
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 2048)
        .ok_or_else(|| format!("invalid {} field", field))
}

/// Structural validation, independent of serde's field skipping.
pub fn validate_cves(bytes: &[u8]) -> Result<usize, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let rows = as_array(&value)?;
    if rows.len() < 100 || rows.len() > MAX_ENTRIES {
        return Err(format!("unexpected CVE entry count: {}", rows.len()));
    }
    let allowed = ["critical", "high", "medium", "low", "info"];
    let mut ids = HashSet::new();
    for row in rows {
        let obj = as_object(row)?;
        let id = text(&obj["id"], "id")?;
        if !ids.insert(id) {
            return Err(format!("duplicate CVE id: {}", id));
        }
        let severity = text(&obj["severity"], "severity")?.to_ascii_lowercase();
        if !allowed.contains(&severity.as_str()) {
            return Err(format!("invalid severity: {}", severity));
        }
        text(&obj["title"], "title")?;
        text(&obj["detail"], "detail")?;
        if let Some(ports) = obj.get("ports") {
            for port in as_array(ports)? {
                let n = port.as_u64().ok_or("invalid port")?;
                if n > u16::MAX as u64 {
                    return Err("port out of range".into());
                }
            }
        }
        for field in ["keywords", "all_keywords", "exclude_keywords"] {
            if let Some(words) = obj.get(field) {
                for word in as_array(words)? {
                    if word.as_str().map(|s| s.len() > 64).unwrap_or(true) {
                        return Err(format!("invalid {} entry", field));
                    }
                }
            }
        }
        if let Some(cvss) = obj.get("cvss") {
            let score = cvss.as_f64().ok_or("invalid cvss")?;
            if !(0.0..=10.0).contains(&score) {
                return Err("cvss out of range".into());
            }
        }
        if let Some(affected) = obj.get("affected") {
            for a in as_array(affected)? {
                let a = as_object(a)?;
                text(&a["product"], "affected.product")?;
                text(&a["below"], "affected.below")?;
            }
        }
        let gated = obj.get("ports").is_some()
            || obj.get("keywords").is_some()
            || obj.get("device_types").is_some();
        if !gated {
            return Err(format!("{} has no matching gate", id));
        }
    }
    Ok(rows.len())
}

fn validate_pairs(value: &Value, field: &str) -> Result<usize, String> {
    let rows = as_array(value)?;
    if rows.len() > 2000 {
        return Err(format!("too many pairs in {}", field));
    }
    for row in rows {
        let pair = as_array(row)?;
        if pair.len() != 2 {
            return Err(format!("invalid pair in {}", field));
        }
        for item in pair {
            if item.as_str().map(|s| s.len() > 128).unwrap_or(true) {
                return Err(format!("invalid credential in {}", field));
            }
        }
    }
    Ok(rows.len())
}

pub fn validate_creds(bytes: &[u8]) -> Result<usize, String> {
    let root: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let obj = as_object(&root)?;
    let generic = as_object(obj.get("generic").ok_or("missing generic credentials")?)?;
    let mut count = 0;
    for protocol in ["http", "telnet", "ftp", "rtsp"] {
        count += validate_pairs(
            generic
                .get(protocol)
                .ok_or_else(|| format!("missing {}", protocol))?,
            protocol,
        )?;
    }
    if let Some(vendors) = obj.get("vendors") {
        let vendors = as_object(vendors)?;
        if vendors.len() > 500 {
            return Err("too many vendor blocks".into());
        }
        for (name, set) in vendors {
            if name.len() > 64 {
                return Err("vendor name too long".into());
            }
            let set = as_object(set)?;
            for protocol in ["http", "telnet", "ftp", "rtsp"] {
                if let Some(pairs) = set.get(protocol) {
                    count += validate_pairs(pairs, protocol)?;
                }
            }
        }
    }
    if let Some(communities) = obj.get("snmp") {
        let communities = as_array(communities)?;
        if communities.len() > 500 {
            return Err("too many SNMP communities".into());
        }
        for c in communities {
            if c.as_str().map(|s| s.len() > 128).unwrap_or(true) {
                return Err("invalid SNMP community".into());
            }
        }
        count += communities.len();
    }
    if count < 50 {
        return Err("credential database is too small".into());
    }
    Ok(count)
}

struct Download {
    bytes: Vec<u8>,
    sha256: String,
    entries: usize,
}

fn prepare(
    url: &str,
    opts: &UpdateOpts,
    expected: Option<&str>,
    manifest_entries: Option<usize>,
    validator: fn(&[u8]) -> Result<usize, String>,
) -> Result<Download, String> {
    let bytes = fetch_bytes(url, MAX_DB_BYTES, opts.allow_http)?;
    if let Some(expected) = expected {
        valid_hash(expected)?;
        if !sha256::matches_hex(&bytes, expected) {
            return Err(format!(
                "checksum mismatch for {}: expected {}, got {}",
                url,
                expected,
                sha256::hex(&bytes)
            ));
        }
    }
    let entries = validator(&bytes)?;
    if let Some(manifest_entries) = manifest_entries {
        if manifest_entries != entries {
            return Err(format!(
                "entry count mismatch for {}: manifest says {}, database has {}",
                url, manifest_entries, entries
            ));
        }
    }
    Ok(Download {
        sha256: sha256::hex(&bytes),
        bytes,
        entries,
    })
}

fn home_path(name: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{}/.boggy/{}", home, name)
}

pub fn update_databases(opts: &UpdateOpts) -> Result<String, String> {
    if opts.cves_only && opts.creds_only {
        return Err("--cves-only and --creds-only are mutually exclusive".into());
    }
    checked_url(&opts.cves_url, opts.allow_http)?;
    checked_url(&opts.creds_url, opts.allow_http)?;
    checked_url(&opts.manifest_url, opts.allow_http)?;
    let mut expected_cves = opts.cves_sha256.clone();
    let mut expected_creds = opts.creds_sha256.clone();
    let mut manifest_cves_entries = None;
    let mut manifest_creds_entries = None;

    if opts.verify {
        let raw = fetch_bytes(&opts.manifest_url, MAX_MANIFEST_BYTES, opts.allow_http)?;
        let manifest: Manifest =
            serde_json::from_slice(&raw).map_err(|e| format!("invalid manifest: {}", e))?;
        if manifest.version != 1 {
            return Err(format!("unsupported manifest version {}", manifest.version));
        }
        safe_file_name(&manifest.cves.file)?;
        safe_file_name(&manifest.creds.file)?;
        valid_hash(&manifest.cves.sha256)?;
        valid_hash(&manifest.creds.sha256)?;
        expected_cves = expected_cves.or(Some(manifest.cves.sha256.clone()));
        expected_creds = expected_creds.or(Some(manifest.creds.sha256.clone()));
        manifest_cves_entries = Some(manifest.cves.entries);
        manifest_creds_entries = Some(manifest.creds.entries);
    }

    // Fetch and validate everything before touching either destination.
    let cves = if opts.creds_only {
        None
    } else {
        Some(prepare(
            &opts.cves_url,
            opts,
            expected_cves.as_deref(),
            manifest_cves_entries,
            validate_cves,
        )?)
    };
    let creds = if opts.cves_only {
        None
    } else {
        Some(prepare(
            &opts.creds_url,
            opts,
            expected_creds.as_deref(),
            manifest_creds_entries,
            validate_creds,
        )?)
    };

    let mut lines = Vec::new();
    if let Some(cves) = cves {
        let dest = PathBuf::from(
            opts.cves_out
                .clone()
                .unwrap_or_else(|| home_path("cves.json")),
        );
        atomic_write(&dest, &cves.bytes, false)?;
        lines.push(format!(
            "CVE database: {} entries, sha256 {} -> {}",
            cves.entries,
            cves.sha256,
            dest.display()
        ));
    }
    if let Some(creds) = creds {
        let dest = PathBuf::from(
            opts.creds_out
                .clone()
                .unwrap_or_else(|| home_path("creds.json")),
        );
        atomic_write(&dest, &creds.bytes, false)?;
        lines.push(format!(
            "Credential database: {} pairs, sha256 {} -> {}",
            creds.entries,
            creds.sha256,
            dest.display()
        ));
    }
    Ok(lines.join("\n"))
}

#[derive(Clone, Debug)]
pub struct UpdateCheck {
    pub version: String,
    pub tag: String,
    pub assets: Vec<String>,
    pub newer: bool,
}

fn version_parts(s: &str) -> Vec<u64> {
    s.trim_start_matches('v')
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse().unwrap_or(0))
        .collect()
}

fn is_newer(latest: &str, current: &str) -> bool {
    let a = version_parts(latest);
    let b = version_parts(current);
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

pub fn check_latest() -> Result<UpdateCheck, String> {
    let raw = fetch_bytes(RELEASES_URL, MAX_RELEASE_BYTES, false)?;
    let release: Release =
        serde_json::from_slice(&raw).map_err(|e| format!("invalid release response: {}", e))?;
    let assets = release.assets.iter().map(|a| a.name.clone()).collect();
    let newer = is_newer(&release.tag_name, env!("CARGO_PKG_VERSION"));
    Ok(UpdateCheck {
        version: env!("CARGO_PKG_VERSION").into(),
        tag: release.tag_name,
        newer,
        assets,
    })
}

fn asset_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "boggy-x86_64-unknown-linux-gnu",
        "aarch64" => "boggy-aarch64-unknown-linux-gnu",
        "arm" => "boggy-armv7-unknown-linux-gnueabihf",
        _other => "",
    }
}

fn digest_hex(digest: &str) -> Option<String> {
    let value = digest.strip_prefix("sha256:").unwrap_or(digest);
    if valid_hash(value).is_ok() {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn checksums_asset(release: &Release, name: &str, allow_http: bool) -> Result<String, String> {
    let sums = release
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS" || a.name == "checksums.txt")
        .ok_or_else(|| format!("release has no SHA256SUMS asset for {}", name))?;
    let bytes = fetch_asset(&sums.browser_download_url, 64 * 1024, allow_http)?;
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let hash = parts.next().unwrap_or("");
        let file = parts.next().unwrap_or("").trim_start_matches('*');
        if file == name {
            return digest_hex(hash).ok_or_else(|| format!("invalid checksum line for {}", name));
        }
    }
    Err(format!("no checksum line for {} in SHA256SUMS", name))
}

pub fn self_update(allow_http: bool) -> Result<String, String> {
    let name = asset_name();
    if name.is_empty() {
        return Err(format!(
            "self-update has no release asset for architecture {}",
            std::env::consts::ARCH
        ));
    }
    let raw = fetch_bytes(RELEASES_URL, MAX_RELEASE_BYTES, allow_http)?;
    let release: Release =
        serde_json::from_slice(&raw).map_err(|e| format!("invalid release response: {}", e))?;
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| format!("release {} has no asset {}", release.tag_name, name))?;
    if asset.size > MAX_BINARY_BYTES {
        return Err(format!("asset {} is too large: {} bytes", name, asset.size));
    }
    let bytes = fetch_asset(&asset.browser_download_url, MAX_BINARY_BYTES, allow_http)?;
    if !bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Err("downloaded asset is not an ELF binary".into());
    }
    let expected = match digest_hex(&asset.digest) {
        Some(hash) => hash,
        None => checksums_asset(&release, name, allow_http)?,
    };
    if !sha256::matches_hex(&bytes, &expected) {
        return Err(format!(
            "binary checksum mismatch: expected {}, got {}",
            expected,
            sha256::hex(&bytes)
        ));
    }
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {}", e))?;
    atomic_write(&exe, &bytes, true)?;
    Ok(format!(
        "boggy updated to {} ({})",
        release.tag_name,
        exe.display()
    ))
}

pub fn db_info() -> Result<String, String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let mut lines = Vec::new();
    for (name, embedded) in [
        ("cves.json", include_str!("../db/cves.json")),
        ("creds.json", include_str!("../db/creds.json")),
        ("manifest.json", include_str!("../db/manifest.json")),
    ] {
        let bytes = embedded.as_bytes();
        let local = format!("{}/.boggy/{}", home, name);
        let active = if Path::new(&local).exists() {
            format!("local override {}", local)
        } else {
            "embedded".to_string()
        };
        lines.push(format!(
            "{}: sha256 {} ({} bytes), {}",
            name,
            sha256::hex(bytes),
            bytes.len(),
            active
        ));
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_scheme_policy() {
        assert!(checked_url("https://example.org/a", false).is_ok());
        assert!(checked_url("http://example.org/a", false).is_err());
        assert!(checked_url("http://example.org/a", true).is_ok());
        assert!(checked_url("ftp://example.org/a", true).is_err());
    }

    #[test]
    fn embedded_databases_validate() {
        assert!(validate_cves(include_bytes!("../db/cves.json").as_slice()).is_ok());
        assert!(validate_creds(include_bytes!("../db/creds.json").as_slice()).is_ok());
    }

    #[test]
    fn manifest_is_consistent() {
        let manifest: Manifest = serde_json::from_str(include_str!("../db/manifest.json")).unwrap();
        assert!(sha256::matches_hex(
            include_bytes!("../db/cves.json"),
            &manifest.cves.sha256
        ));
        assert!(sha256::matches_hex(
            include_bytes!("../db/creds.json"),
            &manifest.creds.sha256
        ));
        assert_eq!(
            manifest.cves.entries,
            validate_cves(include_bytes!("../db/cves.json")).unwrap()
        );
    }

    #[test]
    fn manifest_rejects_unsafe_names() {
        assert!(safe_file_name("cves.json").is_ok());
        assert!(safe_file_name("../etc/passwd").is_err());
        assert!(safe_file_name("a/b.json").is_err());
    }

    #[test]
    fn version_comparison() {
        assert!(is_newer("v0.3.0", "0.2.1"));
        assert!(!is_newer("0.2.0", "0.2.1"));
    }

    #[test]
    fn bad_database_is_rejected() {
        let bad = br#"[{"id":"CVE-1","severity":"nope","title":"x","detail":"y","ports":[80]}]"#;
        assert!(validate_cves(bad).is_err());
    }
}
