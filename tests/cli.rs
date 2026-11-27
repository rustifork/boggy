//! End-to-end checks against the built binary. No network beyond localhost is used.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_boggy"))
}

fn tmp(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("boggy-it-{}-{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn file_url(path: &Path) -> String {
    format!("file://{}", path.display())
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("failed to spawn boggy")
}

fn ok(output: &Output) -> String {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn help_version_and_commands() {
    let out = run(bin().arg("--help"));
    let text = ok(&out);
    for command in ["update-db", "update", "update-check", "db-info", "selftest"] {
        assert!(text.contains(command), "missing {} in help", command);
    }
    let version = ok(&run(bin().arg("--version")));
    assert!(version.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn selftest_passes() {
    let text = ok(&run(bin().arg("selftest")));
    assert!(text.contains("0 failed"), "{}", text);
    assert!(text.contains("[PASS] manifest digests"), "{}", text);
}

#[test]
fn db_info_lists_three_databases() {
    let text = ok(&run(bin().arg("db-info")));
    for name in ["cves.json", "creds.json", "manifest.json"] {
        assert!(text.contains(name), "{}", text);
    }
    assert_eq!(text.lines().count(), 3);
}

#[test]
fn db_info_flags_divergent_override() {
    let home = tmp("home");
    let override_dir = home.join(".boggy");
    fs::create_dir_all(&override_dir).unwrap();
    fs::write(override_dir.join("cves.json"), b"[]").unwrap();
    let out = run(bin().arg("db-info").env("HOME", &home));
    let text = ok(&out);
    assert!(text.contains("cves.json:"), "{}", text);
    assert!(text.contains("DIFFERS"), "{}", text);
}

#[test]
fn dry_run_does_not_write() {
    let dir = tmp("dry-run");
    let dest = dir.join("cves.json");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = run(bin().args([
        "update-db",
        "--cves-only",
        "--dry-run",
        "--url",
        &file_url(&root.join("db/cves.json")),
        "--manifest-url",
        &file_url(&root.join("db/manifest.json")),
        "--out",
        dest.to_str().unwrap(),
    ]));
    let text = ok(&out);
    assert!(text.contains("dry-run"), "{}", text);
    assert!(text.contains("677 entries"), "{}", text);
    assert!(!dest.exists(), "dry-run created a file");
}

#[test]
fn bad_checksum_aborts_without_writing() {
    let dir = tmp("bad-checksum");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tampered = dir.join("tampered.json");
    let original = fs::read_to_string(root.join("db/cves.json")).unwrap();
    fs::write(&tampered, original.replacen("CVE-", "XXX-", 1)).unwrap();
    let dest = dir.join("out.json");
    let out = run(bin().args([
        "update-db",
        "--cves-only",
        "--url",
        &file_url(&tampered),
        "--manifest-url",
        &file_url(&root.join("db/manifest.json")),
        "--out",
        dest.to_str().unwrap(),
    ]));
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("checksum mismatch"), "{}", stderr);
    assert!(!dest.exists(), "a bad update wrote a file");
}

#[test]
fn json_report_is_well_shaped() {
    let out = run(bin().args([
        "--target",
        "127.0.0.1/32",
        "--ports",
        "1",
        "--timeout",
        "100",
        "--no-creds",
        "--no-cve",
        "--output",
        "json",
    ]));
    let text = ok(&out);
    for key in [
        "\"target\"",
        "\"hosts\"",
        "\"summary\"",
        "\"critical\"",
        "\"open_ports\"",
    ] {
        assert!(text.contains(key), "missing {} in report", key);
    }
    assert!(text.trim_start().starts_with('{'));

    let lines = ok(&run(bin().args([
        "--target",
        "127.0.0.1/32",
        "--ports",
        "1",
        "--timeout",
        "100",
        "--no-creds",
        "--no-cve",
        "--output",
        "jsonl",
    ])));
    for line in lines.lines() {
        assert!(line.starts_with('{') && line.ends_with('}'));
    }
}

#[test]
fn invalid_inputs_fail_closed() {
    let unknown = run(bin().arg("--definitely-unknown"));
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown option"));

    let ports = run(bin().args(["--ports", "not-a-port"]));
    assert!(!ports.status.success());

    let huge = run(bin().args(["--target", "10.0.0.0/8", "--max-hosts", "10", "--passive"]));
    assert!(!huge.status.success());
    assert!(String::from_utf8_lossy(&huge.stderr).contains("limit 10"));
}

#[test]
fn invalid_values_fail_in_binary() {
    for flag in ["--min-severity", "--fail-on", "--output"] {
        let out = run(bin().args([flag, "not-a-value"]));
        assert!(!out.status.success(), "{} was accepted", flag);
    }
    let extra = run(bin().args(["selftest", "unexpected"]));
    assert!(!extra.status.success());
    assert!(String::from_utf8_lossy(&extra.stderr).contains("unexpected argument"));
}

#[test]
fn fail_on_without_findings_is_zero() {
    let out = run(bin().args([
        "--target",
        "127.0.0.1/32",
        "--ports",
        "1",
        "--timeout",
        "100",
        "--no-creds",
        "--no-cve",
        "--min-severity",
        "high",
        "--fail-on",
        "critical",
    ]));
    assert!(out.status.success());
}
