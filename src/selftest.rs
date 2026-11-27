//! `boggy selftest`: integrity and parser checks that run anywhere the binary runs.
//! Useful on a Raspberry Pi where cargo and the test suite are not available.

use crate::json::Json;
use crate::net::{md5, ports, sha256};
use crate::types::Summary;

struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok,
        detail: detail.into(),
    }
}

pub fn run() -> Result<String, String> {
    let mut checks = Vec::new();

    checks.push(check(
        "sha256 vectors",
        sha256::hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            && sha256::matches_hex(
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        "empty string and 'abc'",
    ));
    checks.push(check(
        "md5 vectors",
        md5::hex(b"abc") == "900150983cd24fb0d6963f7d28e17f72",
        "HTTP Digest primitive",
    ));

    let valid_json = crate::json::parse(br#"{"a":[1,2,null,true],"b":"x"}"#);
    let bad_json = crate::json::parse(b"{\"a\":}");
    checks.push(check(
        "json parser",
        valid_json
            .as_ref()
            .map(|v| v.get("a").and_then(Json::as_arr).map(|a| a.len()) == Some(4))
            .unwrap_or(false)
            && bad_json.is_err(),
        "valid input accepted, malformed input rejected",
    ));
    let deep = format!("{}]", "[".repeat(100));
    checks.push(check(
        "json depth guard",
        crate::json::parse(deep.as_bytes()).is_err(),
        "100 nested arrays refused",
    ));

    let cves = crate::update::validate_cves(include_bytes!("../db/cves.json"));
    checks.push(check(
        "embedded CVE database",
        cves.is_ok(),
        format!("{} entries", cves.unwrap_or(0)),
    ));
    let creds = crate::update::validate_creds(include_bytes!("../db/creds.json"));
    checks.push(check(
        "embedded credential database",
        creds.is_ok(),
        format!("{} pairs", creds.unwrap_or(0)),
    ));

    let manifest = crate::update::parse_manifest(include_bytes!("../db/manifest.json"));
    let hashes_ok = manifest.as_ref().map(|m| {
        sha256::matches_hex(include_bytes!("../db/cves.json"), &m.cves.sha256)
            && sha256::matches_hex(include_bytes!("../db/creds.json"), &m.creds.sha256)
    });
    checks.push(check(
        "manifest digests",
        hashes_ok.unwrap_or(false),
        "embedded databases match the manifest",
    ));

    let parsed = crate::cli::parse(
        ["--target", "10.0.0.0/24", "--fast", "-j", "4"]
            .iter()
            .map(|s| s.to_string()),
    );
    let cli_ok = parsed
        .as_ref()
        .map(|cli| cli.scan.fast && cli.scan.threads == 4 && cli.scan.target.len() == 1)
        .unwrap_or(false);
    checks.push(check("cli parser", cli_ok, "scan flags and value forms"));

    let subnet_ok = crate::net::subnet::Subnet::parse("10.0.0.0/30")
        .map(|s| s.hosts().len() == 2)
        .unwrap_or(false);
    checks.push(check("subnet math", subnet_ok, "/30 yields two hosts"));

    let port_ok = ports::parse_ports("22,80,8000-8002")
        .map(|p| p == vec![22, 80, 8000, 8001, 8002])
        .unwrap_or(false);
    checks.push(check("port ranges", port_ok, "22,80,8000-8002"));

    let version_ok = crate::iot::fingerprints::version_lt("2.4.49", "2.4.51")
        && !crate::iot::fingerprints::version_lt("2.4.51", "2.4.49");
    checks.push(check(
        "version ordering",
        version_ok,
        "Apache style versions",
    ));

    let digest_ok =
        crate::net::http::parse_digest("Digest realm=\"camera\", nonce=\"abc\", qop=\"auth\"")
            .is_some();
    checks.push(check(
        "digest challenge",
        digest_ok,
        "WWW-Authenticate parsing",
    ));

    let report = crate::types::ScanReport {
        target: "selftest".into(),
        hosts: Vec::new(),
        started: "0".into(),
        finished: "0".into(),
        summary: Summary::default(),
    };
    let report_json = report.to_json().compact();
    let roundtrip = crate::json::parse(report_json.as_bytes())
        .map(|v| v.get("summary").and_then(Json::as_obj).map(|o| o.len()) == Some(8))
        .unwrap_or(false);
    checks.push(check(
        "report serialization",
        roundtrip,
        "JSON roundtrip of an empty report",
    ));

    let mut out = String::new();
    out.push_str("boggy selftest\n");
    let mut failures = 0;
    for c in &checks {
        out.push_str(&format!(
            "  [{}] {} - {}\n",
            if c.ok { "PASS" } else { "FAIL" },
            c.name,
            c.detail
        ));
        if !c.ok {
            failures += 1;
        }
    }
    out.push_str(&format!(
        "{} checks, {} passed, {} failed\n",
        checks.len(),
        checks.len() - failures,
        failures
    ));
    if failures == 0 {
        Ok(out)
    } else {
        Err(out)
    }
}
