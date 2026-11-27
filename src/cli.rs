use crate::update::{UpdateOpts, CREDS_URL, CVE_URL, MANIFEST_URL};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "boggy",
    version,
    about = "Lightweight agentless IoT network scanner"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub scan: ScanOpts,
}

#[derive(Args, Debug, Clone)]
pub struct DbUpdateArgs {
    /// CVE database destination (default: ~/.boggy/cves.json)
    #[arg(long)]
    pub out: Option<String>,

    /// CVE database source URL
    #[arg(long, default_value = CVE_URL)]
    pub url: String,

    /// Credential database source URL
    #[arg(long, default_value = CREDS_URL)]
    pub creds_url: String,

    /// Credential database destination (default: ~/.boggy/creds.json)
    #[arg(long)]
    pub creds_out: Option<String>,

    /// Signed manifest URL used for sha256 verification
    #[arg(long, default_value = MANIFEST_URL)]
    pub manifest_url: String,

    /// Update only the CVE database
    #[arg(long, default_value_t = false)]
    pub cves_only: bool,

    /// Update only the credential database
    #[arg(long, default_value_t = false)]
    pub creds_only: bool,

    /// Skip sha256 manifest verification (not recommended)
    #[arg(long, default_value_t = false)]
    pub no_verify: bool,

    /// Allow plain HTTP downloads
    #[arg(long, default_value_t = false)]
    pub allow_http: bool,

    /// Override the expected CVE sha256
    #[arg(long)]
    pub cves_sha256: Option<String>,

    /// Override the expected credential sha256
    #[arg(long)]
    pub creds_sha256: Option<String>,
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
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Download and verify the latest CVE and credential databases
    UpdateDb {
        #[command(flatten)]
        db: DbUpdateArgs,
    },
    /// Check for a release and refresh databases (or self-update)
    Update {
        #[command(flatten)]
        db: DbUpdateArgs,
        /// Replace the running binary with the verified release asset
        #[arg(long = "self", default_value_t = false)]
        self_update: bool,
        /// Only print the latest release information
        #[arg(long, default_value_t = false)]
        check_only: bool,
        /// Skip the database refresh
        #[arg(long, default_value_t = false)]
        no_db: bool,
    },
    /// Print the latest release version without changing anything
    UpdateCheck,
    /// Show hashes and active locations of the shipped databases
    DbInfo,
}

#[derive(Parser, Debug, Clone)]
pub struct ScanOpts {
    /// Target CIDR, e.g. 192.168.1.0/24 (repeatable)
    #[arg(short, long)]
    pub target: Vec<String>,

    /// Auto-detect local subnet
    #[arg(long, default_value_t = false)]
    pub auto: bool,

    /// CIDR to exclude (repeatable)
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Deep scan: more ports, stronger probes
    #[arg(long, default_value_t = false)]
    pub deep: bool,

    /// Passive mode: discovery only, no active probes
    #[arg(long, default_value_t = false)]
    pub passive: bool,

    /// Output format: text, json or jsonl
    #[arg(short, long, default_value = "text")]
    pub output: String,

    /// Output file (stdout if omitted)
    #[arg(long)]
    pub out: Option<String>,

    /// Concurrent workers
    #[arg(short = 'j', long, default_value_t = 64)]
    pub threads: usize,

    /// Max concurrent connections (rate limit). 0 = auto
    #[arg(long, default_value_t = 0)]
    pub rate_limit: usize,

    /// Per-probe timeout in ms
    #[arg(long, default_value_t = 800)]
    pub timeout: u64,

    /// Top ports only (fast)
    #[arg(long, default_value_t = false)]
    pub fast: bool,

    /// Comma-separated ports/ranges, e.g. 22,80,443,8000-9000
    #[arg(long)]
    pub ports: Option<String>,

    /// Disable credential probing
    #[arg(long, default_value_t = false)]
    pub no_creds: bool,

    /// Disable CVE matching
    #[arg(long, default_value_t = false)]
    pub no_cve: bool,

    /// Max credential attempts per service (0 = no limit)
    #[arg(long, default_value_t = 24)]
    pub cred_limit: usize,

    /// Max CVE findings reported per host (0 = no limit)
    #[arg(long, default_value_t = 15)]
    pub max_cve: usize,

    /// Hide findings below this severity: info|low|medium|high|critical
    #[arg(long, default_value = "info")]
    pub min_severity: String,

    /// Exit with code 2 when a finding at or above this severity exists
    #[arg(long)]
    pub fail_on: Option<String>,

    /// Print progress to stderr
    #[arg(long, short, default_value_t = false)]
    pub verbose: bool,

    /// Use a custom CVE database file
    #[arg(long)]
    pub cve_file: Option<String>,

    /// Use a custom credential database file
    #[arg(long)]
    pub creds_file: Option<String>,

    /// Refuse targets with more addresses than this (0 = unlimited)
    #[arg(long, default_value_t = 65536)]
    pub max_hosts: usize,
}
