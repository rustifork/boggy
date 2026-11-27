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
        "--discovery-ms",
        "100",
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
        "--discovery-ms",
        "100",
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
fn parallel_ports_and_keepalive_servers() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};

    let mut ports = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..2 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        ports.push(listener.local_addr().unwrap().port());
        handles.push(thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nServer: TestCam\r\n\r\nhello");
                thread::sleep(Duration::from_millis(900));
            }
        }));
    }

    let started = Instant::now();
    let spec = format!("{},{}", ports[0], ports[1]);
    let out = run(bin().args([
        "--discovery-ms",
        "100",
        "--target",
        "127.0.0.1/32",
        "--ports",
        &spec,
        "--timeout",
        "2000",
        "--no-creds",
        "--no-cve",
        "--output",
        "json",
    ]));
    let elapsed = started.elapsed();
    let text = ok(&out);
    for port in &ports {
        assert!(
            text.contains(&format!("\"port\": {}", port)),
            "missing port {} in {}",
            port,
            text
        );
    }
    assert!(
        elapsed < Duration::from_millis(1200),
        "keep-alive servers stalled the scan: {:?}",
        elapsed
    );
    for handle in handles {
        let _ = handle.join();
    }
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
        "--discovery-ms",
        "100",
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
