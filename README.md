# boggy

[![CI](https://github.com/rustifork/boggy/actions/workflows/ci.yml/badge.svg)](https://github.com/rustifork/boggy/actions/workflows/ci.yml)

Lightweight, agentless IoT network vulnerability scanner for Raspberry Pi and other small Linux devices. One ~1.2 MB binary, **zero external Rust crates**, no root privileges.

> Boggy is neither affiliated with, nor used by, nor made by the Iranian APT group Boggy Serpens.

## Why boggy

- **Small**: ~1.23 MB release binary, embedded databases, `std`-only build that works offline.
- **Quiet**: bounded worker pool and a socket semaphore; fragile IoT devices are not flooded.
- **Data-driven**: 677 IoT/OT CVEs and 278 default credential pairs live in JSON, not in code.
- **Verifiable updates**: SHA-256 pinned databases and release binaries, atomic writes.

## Quick start

```sh
# Build (no crates are downloaded)
cargo build --release

# Scan the local subnet
./target/release/boggy --auto

# Or a specific network, with a JSON report
./target/release/boggy --target 192.168.1.0/24 --output json --out report.json
```

Prebuilt x86_64 binaries are on the [releases page](https://github.com/rustifork/boggy/releases). After installing one, `boggy update --self` verifies and replaces it.

## Features

| Area | What it does |
| --- | --- |
| Discovery | ARP sweep, mDNS (6 service types), SSDP/UPnP (3 search targets), TCP liveness |
| Ports | Fast / common / deep sets, custom ranges, banner grabbing |
| Fingerprinting | 150+ vendor/device signatures; `Server`, `WWW-Authenticate`, page title, version extraction |
| Credentials | HTTP Basic, Digest, login forms, Telnet, FTP, RTSP; vendor-aware pairs |
| Protocol probes | MQTT, CoAP, SNMP, Redis, Memcached, Modbus, Docker, Elasticsearch, ADB, TR-069 |
| UPnP | Manufacturer, model, firmware, IGD exposure |
| Vulnerabilities | 677 CVEs with port, keyword, device-class and version gates; CVSS ranking |
| Reporting | Text, JSON, JSONL; severity summary and CI exit codes |

## Scanning

```sh
boggy --auto
boggy --target 192.168.1.0/24 --exclude 192.168.1.50/32
boggy --target 192.168.1.0/24 --fast
boggy --target 192.168.1.0/24 --deep
boggy --target 192.168.1.0/24 --ports 22,80,443,8000-8100
boggy --target 192.168.1.0/24 --passive
boggy --target 192.168.1.0/24 --rate-limit 32 --timeout 500 -j 8
boggy --target 192.168.1.0/24 --min-severity high --fail-on critical -v
```

`--fast` scans 17 top IoT ports, the default scans ~100, `--deep` scans ~170. `--passive` only reports devices discovered through mDNS/SSDP/ARP. `--cred-limit` (default 24) bounds credential attempts per service; `--max-cve` (default 15) bounds CVE findings per host; `--max-hosts` (default 65536) refuses oversized CIDR expansions before allocating them.

### Options

| Option | Meaning |
| --- | --- |
| `-t, --target <CIDR>` | Target network, repeatable |
| `--auto` | Detect the local /24 |
| `--exclude <CIDR>` | Skip a network, repeatable |
| `--fast` / `--deep` | Port-set selection |
| `--ports <SPEC>` | `22,80,443,8000-8100` |
| `--passive` | Discovery only |
| `--no-creds` / `--no-cve` | Disable a probe family |
| `-j, --threads <N>` | Workers (64) |
| `--rate-limit <N>` | Max simultaneous sockets (auto) |
| `--timeout <MS>` | Per-probe timeout (800) |
| `--min-severity <S>` | `info\|low\|medium\|high\|critical` |
| `--fail-on <S>` | Exit 2 when a finding reaches this severity |
| `--output text\|json\|jsonl` | Report format |
| `--out <FILE>` | Write to file |
| `--cve-file` / `--creds-file` | Override databases |
| `-v` | Progress on stderr |

Exit codes: `0` clean, `1` usage/scan/update error, `2` `--fail-on` threshold reached.

## Databases and updates

| File | Contents | Local override |
| --- | --- | --- |
| `db/cves.json` | 677 CVEs and weak-config rules | `~/.boggy/cves.json` or `--cve-file` |
| `db/creds.json` | 278 credential pairs + SNMP communities | `~/.boggy/creds.json` or `--creds-file` |
| `db/manifest.json` | SHA-256 digests and entry counts | `~/.boggy/manifest.json` |

```sh
boggy update-db                    # both databases, verified
boggy update-db --cves-only
boggy update-db --creds-only
boggy update-db --dry-run          # validate and print, write nothing
boggy update                       # release check + database refresh
boggy update --self                # verified binary self-update
boggy update --check-only
boggy update-check
boggy db-info
boggy selftest
```

`boggy selftest` runs 13 integrity and parser checks inside the binary, so a Pi with no cargo installed can still verify its installation. `boggy db-info` prints the embedded hashes and shows whether a local override is active.

## Security model

- HTTPS is required by default; `--allow-http` is an explicit opt-in for private mirrors.
- `curl` (or `wget` as fallback) performs certificate validation; TLS 1.2 is the minimum. No TLS library is linked into the binary.
- Redirects are disabled for database downloads. Release assets may redirect only to GitHub-controlled hosts.
- Downloads are size-bounded (8 MB databases, 48 MB binary) and SHA-256 checked against `db/manifest.json` or the release digest / `SHA256SUMS`. Digests are compared in constant time.
- Both databases are fetched and structurally validated before either destination is touched. Writes use a create-new temp file, `fsync` and atomic rename; databases are mode 0600, the binary 0755. Symlinks are never followed.
- The in-tree JSON parser enforces depth, node, string and UTF-8 limits. Malformed input is rejected without panics.
- `--max-hosts` and `--cred-limit` bound resource usage; a counting semaphore caps simultaneous sockets.

Out of scope: TLS inspection, active exploitation, version confirmation via authenticated scans, and zero-day discovery. A CVE match means "this device looks affected" — confirm with the vendor advisory or an authenticated scanner.

Only scan networks you own or are authorized to test.

## Building and testing

```sh
cargo build --release
cargo test                 # 39 unit tests + 8 end-to-end tests
cargo run -- selftest      # in-binary checks
cargo fmt --check
```

Cross-compile:

```sh
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/boggy pi@host:/usr/local/bin/
```

CI enforces zero crate dependencies, formatting, clippy, database hashes, tests and a <5 MB binary on x86_64, aarch64 and armv7.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `plain HTTP refused` | Use HTTPS or pass `--allow-http` |
| `checksum mismatch` | Re-run `update-db`; your mirror or download is stale |
| `curl and wget are unavailable` | Install `curl` for HTTPS updates |
| `target expands to N hosts` | Narrow `--target` or raise `--max-hosts` |
| No CVE findings | Try `--deep`, or check that banners expose a vendor; use `--min-severity info` |

## Project

- [Architecture](docs/architecture.md)
- [Usage details](docs/usage.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
