//! Offline end-to-end test of `boggy update` against a local git repository.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn git(args: &[&str], cwd: &Path) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git is required for this test")
}

fn ok(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{} failed: {}",
        what,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn repo_url(path: &Path) -> String {
    format!("file://{}", path.display())
}

fn workdir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("boggy-src-{}-{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn boggy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boggy"))
        .args(args)
        .output()
        .expect("failed to spawn boggy")
}

#[test]
fn source_update_clone_and_fetch() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let base = workdir("flow");
    let seed = base.join("seed");
    let remote = base.join("remote.git");
    let work = base.join("work");
    fs::create_dir_all(&seed).unwrap();

    ok(&git(&["init", "-b", "main"], &seed), "git init");
    ok(
        &git(&["config", "user.email", "test@boggy.local"], &seed),
        "git config email",
    );
    ok(
        &git(&["config", "user.name", "boggy test"], &seed),
        "git config name",
    );
    fs::write(seed.join("Cargo.toml"), "[package]\nname = \"boggy\"\n").unwrap();
    ok(&git(&["add", "."], &seed), "git add");
    ok(&git(&["commit", "-m", "first"], &seed), "git commit");
    ok(
        &Command::new("git")
            .args(["clone", "--bare"])
            .arg(&seed)
            .arg(&remote)
            .output()
            .expect("git clone"),
        "git clone --bare",
    );
    ok(
        &git(&["remote", "add", "origin", &repo_url(&remote)], &seed),
        "git remote add",
    );

    let r = repo_url(&remote);
    let w = work.to_string_lossy();
    let dry = boggy(&[
        "update",
        "--repo",
        &r,
        "--dir",
        &w,
        "--branch",
        "main",
        "--allow-local",
        "--dry-run",
    ]);
    ok(&dry, "boggy update dry-run");
    assert!(String::from_utf8_lossy(&dry.stdout).contains("dry-run"));
    assert!(!work.exists(), "dry-run created the work directory");

    let first = boggy(&[
        "update",
        "--repo",
        &r,
        "--dir",
        &w,
        "--branch",
        "main",
        "--allow-local",
    ]);
    ok(&first, "boggy update clone");
    assert!(work.join(".git").exists());
    assert!(work.join("Cargo.toml").exists());

    // Second commit on the remote must be fetched by a plain `boggy update`.
    fs::write(seed.join("Cargo.toml"), "[package]\nname = \"boggy-v2\"\n").unwrap();
    ok(&git(&["add", "."], &seed), "git add v2");
    ok(&git(&["commit", "-m", "second"], &seed), "git commit v2");
    ok(&git(&["push", "origin", "main"], &seed), "git push");

    let second = boggy(&[
        "update",
        "--repo",
        &r,
        "--dir",
        &w,
        "--branch",
        "main",
        "--allow-local",
    ]);
    ok(&second, "boggy update fetch");
    assert!(fs::read_to_string(work.join("Cargo.toml"))
        .unwrap()
        .contains("boggy-v2"));

    // Dirty trees are refused unless --force is explicit.
    fs::write(work.join("Cargo.toml"), "local edit\n").unwrap();
    let dirty = boggy(&[
        "update",
        "--repo",
        &r,
        "--dir",
        &w,
        "--branch",
        "main",
        "--allow-local",
    ]);
    assert!(!dirty.status.success());
    assert!(String::from_utf8_lossy(&dirty.stderr).contains("--force"));

    let forced = boggy(&[
        "update",
        "--repo",
        &r,
        "--dir",
        &w,
        "--branch",
        "main",
        "--allow-local",
        "--force",
    ]);
    ok(&forced, "boggy update --force");
    assert!(fs::read_to_string(work.join("Cargo.toml"))
        .unwrap()
        .contains("boggy-v2"));
}
