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

`boggy update-db` downloads both into `~/.boggy/`. CVE entries can require a banner
keyword, an open port, a device class or an affected version below a threshold; findings
are de-duplicated, ranked by CVSS and capped per host with `--max-cve`.

Coverage is intentionally IoT-focused and agentless: a match means "this device looks
affected", not "this vulnerability is confirmed exploitable". Confirm findings with an
authenticated scan or a vendor advisory before acting.

## Safety

Only scan networks you own or are authorized to test.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Dual-licensed under MIT or Apache-2.0.
