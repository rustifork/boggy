# boggy

Lightweight, agentless IoT network vulnerability scanner. Runs on Raspberry Pi and other small Linux devices.

> Boggy is neither affiliated with, nor used by, nor made by the Iranian APT group Boggy Serpens.

## Features

- Local subnet auto-detection (or manual CIDR)
- Host discovery: TCP connect probes, mDNS, SSDP/UPnP, CoAP, MQTT hints
- TCP port scanning with configurable port sets
- Service banner grabbing and fingerprinting
- Default credential probing (HTTP basic, MQTT anonymous, RTSP open, Telnet/CoAP exposed)
- UPnP device description parsing
- Embedded CVE / weak-config matching database
- JSON and human-readable reports
- Single static-ish binary, target < 5 MB

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
./target/release/boggy --target 192.168.1.0/24
./target/release/boggy --auto --deep --output json --out report.json
./target/release/boggy --target 192.168.1.0/24 --passive
./target/release/boggy --target 192.168.1.0/24 --rate-limit 32 --timeout 500
./target/release/boggy update-db
```

## Concurrency & rate limiting

Boggy uses a bounded worker pool over hosts; each host scans its ports sequentially.
A counting semaphore caps concurrent connections (`--rate-limit`, default `threads*2`)
to avoid overwhelming fragile IoT devices. Use `--passive` for discovery-only scanning
(mDNS/SSDP/ARP) with no active probes.

## CVE database

Embedded at build time. Refresh with `boggy update-db` (downloads to `~/.boggy/cves.json`,
used automatically if present; HTTPS is built in by default). Boggy does not replace a
full vulnerability scanner; it
detects the most common IoT flaws and weak configurations. Coverage is intentionally
limited and focused on IoT.

## Safety

Only scan networks you own or are authorized to test.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Dual-licensed under MIT or Apache-2.0.
