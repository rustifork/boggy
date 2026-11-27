# boggy

Lightweight, agentless IoT network vulnerability scanner. Runs on Raspberry Pi and other small Linux devices.

> Boggy is neither affiliated with, nor used by, nor made by the Iranian APT group Boggy Serpens.

## Features

- Local subnet auto-detection, manual CIDR and exclusions
- Discovery: TCP liveness, ARP sweep, mDNS (6 service types), SSDP/UPnP (3 search targets)
- TCP port scanning with fast / common / deep / custom port sets
- Banner grabbing plus HTTP `Server`, `WWW-Authenticate` and page-title extraction
- Device, vendor and model fingerprinting (150+ signatures)
- Default credential checks: HTTP Basic, HTTP Digest, web login forms, Telnet, FTP, RTSP
- Protocol probes: MQTT anonymous, CoAP, SNMP community strings, Redis, Memcached, Modbus, Docker, Elasticsearch, ADB, TR-069
- UPnP device description parsing (manufacturer, model, firmware, IGD detection)
- 677-entry CVE database (NVD-derived IoT/OT coverage + curated core) with version-aware matching
- Vendor-aware credential database with 278 username/password pairs
- JSON, JSONL and human-readable reports, severity summary, `--fail-on` CI gate
- Verified, atomic database and binary updates (SHA-256, no redirects, no plain HTTP)
- Single static-ish binary around 2.6 MB, no root privileges required

## Build

```sh
cargo build --release
```

Cross-compile for Raspberry Pi:

```sh
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

## Usage

```sh
./target/release/boggy --auto
./target/release/boggy --target 192.168.1.0/24 --deep --output json --out report.json
./target/release/boggy --target 192.168.1.0/24 --exclude 192.168.1.50/32 --fast
./target/release/boggy --target 192.168.1.0/24 --ports 22,80,443,8000-8100
./target/release/boggy --target 192.168.1.0/24 --passive
./target/release/boggy --target 192.168.1.0/24 --rate-limit 32 --timeout 500
./target/release/boggy --target 192.168.1.0/24 --min-severity high --fail-on critical
./target/release/boggy update-db
```

## Concurrency & rate limiting

Boggy uses a bounded worker pool over hosts; each host scans its ports sequentially.
A counting semaphore caps concurrent connections (`--rate-limit`, default `threads*2`)
to avoid overwhelming fragile IoT devices. Use `--passive` for discovery-only scanning
with no active probes. `--cred-limit` bounds credential attempts per service (default 24).

## Databases

Two JSON databases ship embedded in the binary and can be overridden at runtime:

| File | Purpose | Local override |
| --- | --- | --- |
| `db/cves.json` | CVEs, weak configs, version constraints | `~/.boggy/cves.json` or `--cve-file` |
| `db/creds.json` | Generic and vendor-specific credential pairs, SNMP communities | `~/.boggy/creds.json` or `--creds-file` |

CVE entries can require a banner keyword, an open port, a device class or an affected
version below a threshold; findings are de-duplicated, ranked by CVSS and capped per
host with `--max-cve`.

## Secure updates

```sh
boggy update-db                 # verified CVE + credential databases
boggy update-db --cves-only     # one database only
boggy update                    # release check + verified database refresh
boggy update --self             # verified binary self-update
boggy update-check              # version check only, no writes
boggy db-info                   # embedded hashes and active override paths
```

Every download is bounded (8 MB for databases, 48 MB for binaries), refuses redirects
and plain HTTP by default, and is verified against SHA-256 digests from
`db/manifest.json` before anything is written. Both databases are fetched and validated
first; writes use a create-new temp file, `fsync` and atomic rename (0600 for databases,
0755 for the binary), so a failed update never leaves a half-written or symlink-hijacked
file. `--no-verify` and `--allow-http` are available for private mirrors but are not
recommended.

`boggy update --self` downloads the release asset matching the local architecture,
checks it is an ELF binary, verifies its SHA-256 (release digest or `SHA256SUMS`), then
atomically replaces the running executable. `boggy update-check` compares the latest
GitHub release tag with the running version without changing anything.

Coverage is intentionally IoT-focused and agentless: a match means "this device looks
affected", not "this vulnerability is confirmed exploitable". Confirm findings with an
authenticated scan or a vendor advisory before acting.

## Safety

Only scan networks you own or are authorized to test.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Dual-licensed under MIT or Apache-2.0.
