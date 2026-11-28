# Usage

## Basic

```sh
boggy --auto
boggy --target 192.168.1.0/24
boggy --target 192.168.1.0/24 --exclude 192.168.1.50/32
```

## Scan profiles

```sh
boggy --target 192.168.1.0/24 --fast              # 17 top IoT ports
boggy --target 192.168.1.0/24                     # 100 common ports
boggy --target 192.168.1.0/24 --deep              # 170+ ports, all probes
boggy --target 192.168.1.0/24 --ports 22,80,443,8000-8100
boggy --target 192.168.1.0/24 --passive           # mDNS/SSDP/ARP only
```

## Reporting

```sh
boggy --target 192.168.1.0/24 --output json --out report.json
boggy --target 192.168.1.0/24 --output jsonl
boggy --target 192.168.1.0/24 --output html --out report.html
boggy --target 192.168.1.0/24 --min-severity high --fail-on critical -v
boggy --target 192.168.1.0/24 --max-cve 5 --no-creds
```

`--fail-on` exits with code 2 when a finding at or above the chosen severity exists,
which makes it usable as a CI gate.

## Options

- `--target CIDR` target network (repeatable)
- `--auto` auto-detect local /24
- `--exclude CIDR` skip addresses (repeatable)
- `--fast` / `--deep` / `--ports SPEC` port selection; `--deep` also enables NTP, BACnet and EtherNet/IP probes
- `--passive` no active probes
- `--no-creds` / `--no-cve` disable entire probe families
- `--cred-limit N` max credential attempts per service (0 = unlimited)
- `--max-cve N` max CVE findings per host (0 = unlimited)
- `--min-severity` hide findings below `info|low|medium|high|critical`
- `--fail-on` exit 2 when a finding reaches this severity
- `-j, --threads N` workers (default 64)
- `--rate-limit N` max simultaneous sockets (0 = auto)
- `--timeout MS` per-probe timeout (default 800)
- `--discovery-ms MS` mDNS/SSDP listen window (default 1500)
- `--cve-file` / `--creds-file` override databases
- `-o, --output text|json|jsonl|sarif|html`
- `--compare FILE` diff against a baseline report
- `boggy config` / `--path` inspect optional defaults
- `--out FILE` write report to file
- `-v` progress on stderr

## Updates

Three separate paths:

```sh
# Source code (git)
boggy update                                   # fetch + apply tracked branch
boggy update --dry-run                         # print target commit, change nothing
boggy update --build --install                 # compile and install to ~/.local/bin
boggy update --dir ~/src/boggy --branch main
boggy update --force                           # discard local changes if needed

# Databases (HTTPS, SHA-256 pinned)
boggy update-db
boggy update-db --cves-only
boggy update-db --creds-only
boggy update-db --dry-run
boggy update-db --url https://mirror/cves.json --cves-sha256 <hex>

# Binary and inspection
boggy self-update
boggy update-check
boggy db-info
boggy selftest
```

`boggy update` uses git with an argument array: branch and repository URLs are validated,
a dirty working tree is refused unless `--force`, and outside a checkout the source is
cloned into `~/.boggy/src/boggy` or `--dir`. Database downloads are SHA-256 pinned against
`db/manifest.json`, size-bounded, never follow redirects and reject plain HTTP unless
`--allow-http` is given. Writes are atomic: databases are mode 0600, binaries 0755. A
checksum or schema mismatch aborts the whole update before any file is replaced.

The refresh tool `tools/refresh_cves.py` can extend the embedded CVE database from NVD:

```sh
python3 tools/refresh_cves.py --cache .cache/nvd
```

It needs only the Python standard library and respects NVD's public rate limit.

## Raspberry Pi

Cross-compile:

```sh
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/boggy pi@host:/usr/local/bin/
```

No root privileges are required (TCP connect, UDP probes, multicast discovery).
`git` is needed for `boggy update`; `curl` (or `wget`) for `update-db` / `self-update`
HTTPS downloads. The scanner itself needs no runtime dependency beyond the binary and its
JSON database files. `boggy selftest` runs integrity and parser checks inside the binary,
useful on a Pi without cargo. `--dry-run` validates an update and prints what would be
written, without touching files.
