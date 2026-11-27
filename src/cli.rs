//! Hand-written argument parser: no clap, no external crates.

use crate::update::{UpdateOpts, CREDS_URL, CVE_URL, MANIFEST_URL};

#[derive(Debug, Clone, Default)]
pub struct Cli {
    pub command: Option<Command>,
    pub scan: ScanOpts,
}

#[derive(Debug, Clone)]
pub enum Command {
    UpdateDb {
        db: DbUpdateArgs,
    },
    Update {
        db: DbUpdateArgs,
        self_update: bool,
        check_only: bool,
        no_db: bool,
    },
    UpdateCheck,
    DbInfo,
    SelfTest,
}

#[derive(Debug, Clone)]
pub struct DbUpdateArgs {
    pub out: Option<String>,
    pub url: String,
    pub creds_url: String,
    pub creds_out: Option<String>,
    pub manifest_url: String,
    pub cves_only: bool,
    pub creds_only: bool,
    pub no_verify: bool,
    pub allow_http: bool,
    pub cves_sha256: Option<String>,
    pub creds_sha256: Option<String>,
    pub dry_run: bool,
}

impl Default for DbUpdateArgs {
    fn default() -> Self {
        Self {
            out: None,
            url: CVE_URL.into(),
            creds_url: CREDS_URL.into(),
            creds_out: None,
            manifest_url: MANIFEST_URL.into(),
            cves_only: false,
            creds_only: false,
            no_verify: false,
            allow_http: false,
            cves_sha256: None,
            creds_sha256: None,
            dry_run: false,
        }
    }
}

impl DbUpdateArgs {
    pub fn to_opts(&self) -> UpdateOpts {
        UpdateOpts {
            cves_url: self.url.clone(),
            creds_url: self.creds_url.clone(),
            manifest_url: self.manifest_url.clone(),
            cves_out: self.out.clone(),
            creds_out: self.creds_out.clone(),
            verify: !self.no_verify,
            allow_http: self.allow_http,
            cves_only: self.cves_only,
            creds_only: self.creds_only,
            cves_sha256: self.cves_sha256.clone(),
            creds_sha256: self.creds_sha256.clone(),
            dry_run: self.dry_run,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanOpts {
    pub target: Vec<String>,
    pub auto: bool,
    pub exclude: Vec<String>,
    pub deep: bool,
    pub passive: bool,
    pub output: String,
    pub out: Option<String>,
    pub threads: usize,
    pub rate_limit: usize,
    pub timeout: u64,
    pub fast: bool,
    pub ports: Option<String>,
    pub no_creds: bool,
    pub no_cve: bool,
    pub cred_limit: usize,
    pub max_cve: usize,
    pub min_severity: String,
    pub fail_on: Option<String>,
    pub verbose: bool,
    pub cve_file: Option<String>,
    pub creds_file: Option<String>,
    pub max_hosts: usize,
}

impl Default for ScanOpts {
    fn default() -> Self {
        Self {
            target: Vec::new(),
            auto: false,
            exclude: Vec::new(),
            deep: false,
            passive: false,
            output: "text".into(),
            out: None,
            threads: 64,
            rate_limit: 0,
            timeout: 800,
            fast: false,
            ports: None,
            no_creds: false,
            no_cve: false,
            cred_limit: 24,
            max_cve: 15,
            min_severity: "info".into(),
            fail_on: None,
            verbose: false,
            cve_file: None,
            creds_file: None,
            max_hosts: 65536,
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    Help(String),
    Version,
    Message(String),
}

const GENERAL_HELP: &str = "\
Lightweight agentless IoT network scanner

Usage: boggy [OPTIONS] [COMMAND]

Commands:
  update-db     Download and verify the latest CVE and credential databases
  update        Check for a release and refresh databases (or self-update)
  update-check  Print the latest release version without changing anything
  db-info       Show hashes and active locations of the shipped databases
  selftest      Run integrity and parser checks without cargo
  help          Print this message

Options:
  -t, --target <CIDR>       Target network (repeatable)
      --auto                Auto-detect local /24
      --exclude <CIDR>      Skip a network (repeatable)
      --deep                Extended ports and probes
      --fast                Top ports only
      --passive             Discovery only, no active probes
      --ports <SPEC>        22,80,443,8000-8100
  -o, --output <FORMAT>     text | json | jsonl (default: text)
      --out <FILE>          Write report to file
  -j, --threads <N>         Concurrent workers (default: 64)
      --rate-limit <N>      Max simultaneous sockets (0 = auto)
      --timeout <MS>        Per-probe timeout (default: 800)
      --no-creds            Disable credential probes
      --no-cve              Disable CVE matching
      --cred-limit <N>      Credential attempts per service (default: 24)
      --max-cve <N>         CVE findings per host (default: 15)
      --min-severity <S>    info|low|medium|high|critical
      --fail-on <S>         Exit 2 when a finding reaches this severity
      --max-hosts <N>       Refuse larger target expansions (default: 65536)
      --cve-file <FILE>     Override CVE database
      --creds-file <FILE>   Override credential database
  -v, --verbose             Progress on stderr
  -h, --help                Show help
  -V, --version             Show version
";

const UPDATE_HELP: &str = "\
Download and verify the latest databases

Usage: boggy update-db [OPTIONS]

Options:
      --out <FILE>            CVE database destination
      --url <URL>             CVE database source
      --creds-url <URL>       Credential database source
      --creds-out <FILE>      Credential database destination
      --manifest-url <URL>    SHA-256 manifest source
      --cves-only             Only the CVE database
      --creds-only            Only the credential database
      --no-verify             Skip SHA-256 verification
      --allow-http            Permit plain HTTP
      --cves-sha256 <HEX>     Override expected CVE hash
      --creds-sha256 <HEX>    Override expected credential hash
      --dry-run              Validate without writing
  -h, --help                  Show help
";

const UPGRADE_HELP: &str = "\
Check for a release, refresh databases or self-update

Usage: boggy update [OPTIONS]

Options:
  [all update-db options]
      --self          Replace the running binary with the verified release asset
      --check-only    Only print the latest release information
      --no-db         Skip the database refresh
  -h, --help          Show help
";

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Cli, ParseError> {
    let mut expanded: Vec<String> = Vec::new();
    for arg in args {
        if let Some((key, value)) = arg.split_once('=') {
            if key.starts_with("--") {
                expanded.push(key.to_string());
                expanded.push(value.to_string());
                continue;
            }
        }
        expanded.push(arg);
    }

    let mut cli = Cli::default();
    let mut i = 0;
    while i < expanded.len() {
        let arg = expanded[i].as_str();
        match arg {
            "-h" | "--help" => return Err(ParseError::Help(GENERAL_HELP.into())),
            "-V" | "--version" => return Err(ParseError::Version),
            "help" => return Err(ParseError::Help(GENERAL_HELP.into())),
            "update-db" => {
                cli.command = Some(Command::UpdateDb {
                    db: parse_db_args(&expanded, &mut i)?,
                });
                break;
            }
            "update" => {
                let db = parse_db_args(&expanded, &mut i)?;
                let mut self_update = false;
                let mut check_only = false;
                let mut no_db = false;
                while i < expanded.len() {
                    match expanded[i].as_str() {
                        "--self" => self_update = true,
                        "--check-only" => check_only = true,
                        "--no-db" => no_db = true,
                        "-h" | "--help" => return Err(ParseError::Help(UPGRADE_HELP.into())),
                        other => {
                            return Err(ParseError::Message(format!(
                                "unknown update option: {}",
                                other
                            )))
                        }
                    }
                    i += 1;
                }
                cli.command = Some(Command::Update {
                    db,
                    self_update,
                    check_only,
                    no_db,
                });
                break;
            }
            "update-check" => {
                cli.command = Some(Command::UpdateCheck);
                break;
            }
            "db-info" => {
                cli.command = Some(Command::DbInfo);
                break;
            }
            "selftest" => {
                cli.command = Some(Command::SelfTest);
                break;
            }
            "-t" | "--target" => {
                cli.scan.target.push(value(&expanded, &mut i, arg)?);
            }
            "--exclude" => cli.scan.exclude.push(value(&expanded, &mut i, arg)?),
            "--auto" => cli.scan.auto = true,
            "--deep" => cli.scan.deep = true,
            "--fast" => cli.scan.fast = true,
            "--passive" => cli.scan.passive = true,
            "--no-creds" => cli.scan.no_creds = true,
            "--no-cve" => cli.scan.no_cve = true,
            "-v" | "--verbose" => cli.scan.verbose = true,
            "-o" | "--output" => cli.scan.output = value(&expanded, &mut i, arg)?,
            "--out" => cli.scan.out = Some(value(&expanded, &mut i, arg)?),
            "-j" | "--threads" => {
                cli.scan.threads = value(&expanded, &mut i, arg)?
                    .parse()
                    .map_err(|_| ParseError::Message(format!("invalid number for {}", arg)))?;
            }
            "--rate-limit" => {
                cli.scan.rate_limit = value(&expanded, &mut i, arg)?
                    .parse()
                    .map_err(|_| ParseError::Message(format!("invalid number for {}", arg)))?;
            }
            "--timeout" => {
                cli.scan.timeout = value(&expanded, &mut i, arg)?
                    .parse()
                    .map_err(|_| ParseError::Message(format!("invalid number for {}", arg)))?;
            }
            "--cred-limit" => {
                cli.scan.cred_limit = value(&expanded, &mut i, arg)?
                    .parse()
                    .map_err(|_| ParseError::Message(format!("invalid number for {}", arg)))?;
            }
            "--max-cve" => {
                cli.scan.max_cve = value(&expanded, &mut i, arg)?
                    .parse()
                    .map_err(|_| ParseError::Message(format!("invalid number for {}", arg)))?;
            }
            "--max-hosts" => {
                cli.scan.max_hosts = value(&expanded, &mut i, arg)?
                    .parse()
                    .map_err(|_| ParseError::Message(format!("invalid number for {}", arg)))?;
            }
            "--min-severity" => cli.scan.min_severity = value(&expanded, &mut i, arg)?,
            "--fail-on" => cli.scan.fail_on = Some(value(&expanded, &mut i, arg)?),
            "--ports" => cli.scan.ports = Some(value(&expanded, &mut i, arg)?),
            "--cve-file" => cli.scan.cve_file = Some(value(&expanded, &mut i, arg)?),
            "--creds-file" => cli.scan.creds_file = Some(value(&expanded, &mut i, arg)?),
            other => {
                return Err(ParseError::Message(format!(
                    "unknown option: {} (try --help)",
                    other
                )))
            }
        }
        i += 1;
    }
    Ok(cli)
}

fn value(args: &[String], i: &mut usize, name: &str) -> Result<String, ParseError> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| ParseError::Message(format!("{} requires a value", name)))
}

fn parse_db_args(args: &[String], i: &mut usize) -> Result<DbUpdateArgs, ParseError> {
    let mut db = DbUpdateArgs::default();
    let mut j = *i + 1; // skip the subcommand token
    while j < args.len() {
        let arg = args[j].as_str();
        match arg {
            "--out" => db.out = Some(take(args, &mut j, arg)?),
            "--url" => db.url = take(args, &mut j, arg)?,
            "--creds-url" => db.creds_url = take(args, &mut j, arg)?,
            "--creds-out" => db.creds_out = Some(take(args, &mut j, arg)?),
            "--manifest-url" => db.manifest_url = take(args, &mut j, arg)?,
            "--cves-sha256" => db.cves_sha256 = Some(take(args, &mut j, arg)?),
            "--creds-sha256" => db.creds_sha256 = Some(take(args, &mut j, arg)?),
            "--cves-only" => db.cves_only = true,
            "--creds-only" => db.creds_only = true,
            "--no-verify" => db.no_verify = true,
            "--allow-http" => db.allow_http = true,
            "--dry-run" => db.dry_run = true,
            "-h" | "--help" => {
                *i = j;
                return Err(ParseError::Help(UPDATE_HELP.into()));
            }
            _ => break,
        }
        j += 1;
    }
    *i = j;
    Ok(db)
}

fn take(args: &[String], i: &mut usize, name: &str) -> Result<String, ParseError> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| ParseError::Message(format!("{} requires a value", name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults() {
        let cli = parse(args(&[])).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.scan.threads, 64);
        assert_eq!(cli.scan.max_hosts, 65536);
    }

    #[test]
    fn scan_flags() {
        let cli = parse(args(&[
            "--target",
            "10.0.0.0/24",
            "--target",
            "10.0.1.0/24",
            "--fast",
            "-j",
            "4",
            "--min-severity",
            "high",
            "--fail-on",
            "critical",
            "--ports",
            "22,80,443",
        ]))
        .unwrap();
        assert_eq!(cli.scan.target.len(), 2);
        assert!(cli.scan.fast);
        assert_eq!(cli.scan.threads, 4);
        assert_eq!(cli.scan.fail_on.as_deref(), Some("critical"));
        assert_eq!(cli.scan.ports.as_deref(), Some("22,80,443"));
    }

    #[test]
    fn update_db_flags() {
        let cli = parse(args(&[
            "update-db",
            "--cves-only",
            "--url=file:///tmp/c.json",
            "--creds-sha256",
            "abc",
            "--no-verify",
        ]))
        .unwrap();
        match cli.command.unwrap() {
            Command::UpdateDb { db } => {
                assert!(db.cves_only);
                assert!(db.no_verify);
                assert_eq!(db.url, "file:///tmp/c.json");
                assert_eq!(db.creds_sha256.as_deref(), Some("abc"));
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn self_update_flags() {
        let cli = parse(args(&["update", "--self", "--no-db"])).unwrap();
        match cli.command.unwrap() {
            Command::Update {
                self_update, no_db, ..
            } => assert!(self_update && no_db),
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn selftest_and_dry_run() {
        let cli = parse(args(&["selftest"])).unwrap();
        assert!(matches!(cli.command, Some(Command::SelfTest)));
        let cli = parse(args(&["update-db", "--dry-run"])).unwrap();
        match cli.command.unwrap() {
            Command::UpdateDb { db } => assert!(db.dry_run),
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn errors_and_help() {
        assert!(parse(args(&["--bogus"])).is_err());
        assert!(matches!(parse(args(&["--help"])), Err(ParseError::Help(_))));
        assert!(matches!(parse(args(&["-V"])), Err(ParseError::Version)));
        assert!(parse(args(&["--timeout"])).is_err());
    }
}
