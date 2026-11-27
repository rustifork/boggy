//! Source-code updates from GitHub using git, with no shell invocation.

use crate::update::atomic_write;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const REPO_URL: &str = "https://github.com/rustifork/boggy.git";
pub const DEFAULT_BRANCH: &str = "main";

#[derive(Clone, Debug)]
pub struct SourceOpts {
    pub dir: Option<String>,
    pub repo: String,
    pub branch: String,
    pub force: bool,
    pub build: bool,
    pub install: bool,
    pub install_path: Option<String>,
    pub dry_run: bool,
    pub allow_local: bool,
}

impl Default for SourceOpts {
    fn default() -> Self {
        Self {
            dir: None,
            repo: REPO_URL.into(),
            branch: DEFAULT_BRANCH.into(),
            force: false,
            build: false,
            install: false,
            install_path: None,
            dry_run: false,
            allow_local: false,
        }
    }
}

fn run(name: &str, args: &[String], cwd: Option<&Path>) -> Result<String, String> {
    let mut cmd = Command::new(name);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let output = cmd
        .output()
        .map_err(|e| format!("{} is unavailable: {}", name, e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "{} {} failed: {}",
            name,
            args.join(" "),
            if stderr.is_empty() {
                format!("exit {:?}", output.status.code())
            } else {
                stderr
            }
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Reject anything that could be interpreted as a git option or path traversal.
pub fn validate_branch(branch: &str) -> Result<(), String> {
    if branch.is_empty() || branch.len() > 128 {
        return Err("branch name is empty or too long".into());
    }
    if branch.starts_with('-')
        || branch.ends_with('/')
        || branch.contains("..")
        || branch.contains("//")
    {
        return Err(format!("unsafe branch name: {}", branch));
    }
    if !branch
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(format!("unsafe branch name: {}", branch));
    }
    Ok(())
}

pub fn validate_repo(repo: &str, allow_local: bool) -> Result<(), String> {
    if repo.starts_with("https://github.com/") && !repo.contains(' ') {
        return Ok(());
    }
    if allow_local && repo.starts_with("file://") && !repo.contains(' ') {
        return Ok(());
    }
    Err(format!(
        "repository must be an HTTPS GitHub URL{}",
        if allow_local {
            " or file:// with --allow-local"
        } else {
            ""
        }
    ))
}

fn default_dir() -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    if cwd.join(".git").exists() {
        return Ok(cwd);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Ok(PathBuf::from(home).join(".boggy/src/boggy"))
}

fn git(args: &[&str], cwd: Option<&Path>) -> Result<String, String> {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run("git", &owned, cwd)
}

fn build(dir: &Path) -> Result<String, String> {
    let manifest = dir.join("Cargo.toml");
    let args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--manifest-path".to_string(),
        manifest.to_string_lossy().into_owned(),
    ];
    run("cargo", &args, None)?;
    Ok(dir.join("target/release/boggy").display().to_string())
}

fn install(binary: &str, dest: &str) -> Result<String, String> {
    let bytes = std::fs::read(binary).map_err(|e| format!("read {}: {}", binary, e))?;
    crate::update::verify_elf(&bytes)?;
    atomic_write(Path::new(dest), &bytes, true)?;
    Ok(dest.to_string())
}

pub fn update(opts: &SourceOpts) -> Result<String, String> {
    if run("git", &["--version".to_string()], None).is_err() {
        return Err("git is required for `boggy update`".into());
    }
    validate_branch(&opts.branch)?;
    validate_repo(&opts.repo, opts.allow_local)?;

    let dir = match &opts.dir {
        Some(path) => PathBuf::from(path),
        None => default_dir()?,
    };
    let mut lines = vec![format!(
        "source update: {} (branch {}, dir {})",
        opts.repo,
        opts.branch,
        dir.display()
    )];
    let mut binary = None;

    if dir.join(".git").exists() {
        let status = git(&["status", "--porcelain"], Some(&dir))?;
        if !status.is_empty() && !opts.force {
            return Err(format!(
                "working tree in {} has local changes; commit them or pass --force",
                dir.display()
            ));
        }
        let old = git(&["rev-parse", "HEAD"], Some(&dir))?;
        git(&["fetch", "--prune", "origin", &opts.branch], Some(&dir))?;
        let new = git(
            &[
                "rev-parse",
                "--verify",
                &format!("refs/remotes/origin/{}", opts.branch),
            ],
            Some(&dir),
        )?;
        if old == new {
            lines.push(format!("already at {}", &new[..new.len().min(12)]));
            if opts.force && !status.is_empty() && !opts.dry_run {
                git(&["checkout", "-f", "-B", &opts.branch, &new], Some(&dir))?;
                lines.push("local changes discarded".into());
            }
        } else {
            lines.push(format!(
                "{} -> {}",
                &old[..old.len().min(12)],
                &new[..new.len().min(12)]
            ));
            if !opts.dry_run {
                git(&["checkout", "-B", &opts.branch, &new], Some(&dir))?;
            }
        }
    } else {
        if dir.exists() {
            let empty = std::fs::read_dir(&dir)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
            if !empty && !opts.force {
                return Err(format!(
                    "{} exists and is not empty; pass --force or choose another --dir",
                    dir.display()
                ));
            }
        }
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("boggy-source");
        let tmp = dir.with_file_name(format!(".{}.boggy-clone-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        git(
            &[
                "clone",
                "--depth",
                "1",
                "--branch",
                &opts.branch,
                &opts.repo,
                &tmp.to_string_lossy(),
            ],
            None,
        )?;
        let new = git(&["rev-parse", "HEAD"], Some(&tmp))?;
        if opts.dry_run {
            let _ = std::fs::remove_dir_all(&tmp);
        } else {
            if dir.exists() {
                std::fs::remove_dir_all(&dir)
                    .map_err(|e| format!("remove {}: {}", dir.display(), e))?;
            }
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create {}: {}", parent.display(), e))?;
            }
            std::fs::rename(&tmp, &dir)
                .map_err(|e| format!("rename {} -> {}: {}", tmp.display(), dir.display(), e))?;
        }
        lines.push(format!("cloned at {}", &new[..new.len().min(12)]));
    }

    if opts.dry_run {
        lines.push("dry-run: no files changed".into());
        return Ok(lines.join("\n"));
    }

    if opts.build || opts.install {
        binary = Some(build(&dir)?);
        lines.push(format!("built {}", binary.as_deref().unwrap_or("")));
    }
    if opts.install {
        let dest = opts.install_path.clone().unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            format!("{}/.local/bin/boggy", home)
        });
        let installed = install(binary.as_deref().ok_or("no binary to install")?, &dest)?;
        lines.push(format!("installed {}", installed));
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_validation() {
        assert!(validate_branch("main").is_ok());
        assert!(validate_branch("feature/v0.6").is_ok());
        assert!(validate_branch("--upload-pack=x").is_err());
        assert!(validate_branch("a..b").is_err());
        assert!(validate_branch("bad name").is_err());
    }

    #[test]
    fn repo_validation() {
        assert!(validate_repo(REPO_URL, false).is_ok());
        assert!(validate_repo("http://github.com/x.git", false).is_err());
        assert!(validate_repo("file:///tmp/repo", false).is_err());
        assert!(validate_repo("file:///tmp/repo", true).is_ok());
    }
}
