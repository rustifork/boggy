use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "boggy", version, about = "Lightweight agentless IoT network scanner")]
pub struct Cli {
    /// Target CIDR, e.g. 192.168.1.0/24
    #[arg(short, long)]
    pub target: Option<String>,

    /// Auto-detect local subnet
    #[arg(long, default_value_t = false)]
    pub auto: bool,

    /// Deep scan: more ports, CVE + default creds
    #[arg(long, default_value_t = false)]
    pub deep: bool,

    /// Output format: text or json
    #[arg(short, long, default_value = "text")]
    pub output: String,

    /// Output file (stdout if omitted)
    #[arg(long)]
    pub out: Option<String>,

    /// Concurrent workers
    #[arg(short = 'j', long, default_value_t = 64)]
    pub threads: usize,

    /// Per-probe timeout in ms
    #[arg(long, default_value_t = 800)]
    pub timeout: u64,

    /// Top ports only (fast)
    #[arg(long, default_value_t = false)]
    pub fast: bool,
}