use clap::{Parser, Subcommand};

const CVE_URL: &str = "https://raw.githubusercontent.com/rustifork/boggy/main/db/cves.json";
const CREDS_URL: &str = "https://raw.githubusercontent.com/rustifork/boggy/main/db/creds.json";

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

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Download the latest CVE and credential databases
    UpdateDb {
        /// CVE database destination (default: ~/.boggy/cves.json)
        #[arg(long)]
        out: Option<String>,
        /// CVE database source URL
        #[arg(long, default_value = CVE_URL)]
        url: String,
        /// Credential database source URL
        #[arg(long, default_value = CREDS_URL)]
        creds_url: String,
        /// Credential database destination (default: ~/.boggy/creds.json)
        #[arg(long)]
        creds_out: Option<String>,
        /// Skip the credential database download
        #[arg(long, default_value_t = false)]
        cves_only: bool,
    },
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
}
