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
boggy --target 192.168.1.0/24 --min-severity high --fail-on critical -v
boggy --target 192.168.1.0/24 --max-cve 5 --no-creds
```

`--fail-on` exits with code 2 when a finding at or above the chosen severity exists,
which makes it usable as a CI gate.

## Options

- `--target CIDR` target network (repeatable)
- `--auto` auto-detect local /24
- `--exclude CIDR` skip addresses (repeatable)
- `--fast` / `--deep` / `--ports SPEC` port selection
- `--passive` no active probes
- `--no-creds` / `--no-cve` disable entire probe families
- `--cred-limit N` max credential attempts per service (0 = unlimited)
- `--max-cve N` max CVE findings per host (0 = unlimited)
- `--min-severity` hide findings below `info|low|medium|high|critical`
- `--fail-on` exit 2 when a finding reaches this severity
- `-j, --threads N` workers (default 64)
- `--rate-limit N` max simultaneous sockets (0 = auto)
- `--timeout MS` per-probe timeout (default 800)
- `--cve-file` / `--creds-file` override databases
- `-o, --output text|json|jsonl`
- `--out FILE` write report to file
- `-v` progress on stderr

## Updates

```sh
boggy update-db                          # both databases into ~/.boggy/, verified
boggy update-db --cves-only
boggy update-db --creds-only
boggy update-db --url https://mirror/cves.json --cves-sha256 <hex>
boggy update                             # release check + database refresh
boggy update --check-only
boggy update --self                      # verified self-update of the binary
boggy update-check
boggy db-info
```

Downloads are SHA-256 pinned against `db/manifest.json`, limited in size, never follow
redirects and reject plain HTTP unless `--allow-http` is given. Writes are atomic:
databases are mode 0600, the self-updated binary 0755. A checksum or schema mismatch
aborts the whole update before any file is replaced.

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
`curl` (or `wget`) must be installed for `update-db` / `update` HTTPS downloads; the
scanner itself needs no runtime dependency beyond the binary and its JSON database files.
