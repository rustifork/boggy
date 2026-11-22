# boggy

Lightweight, agentless IoT network vulnerability scanner. Runs on Raspberry Pi and other small Linux devices.

## Features

- Local subnet auto-detection (or manual CIDR)
- Host discovery: TCP connect probes, mDNS, SSDP/UPnP, CoAP, MQTT hints
- TCP port scanning with configurable port sets
- Service banner grabbing and fingerprinting
- Default credential probing (HTTP basic/digest, RTSP, MQTT, Telnet)
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
sudo ./target/release/boggy --target 192.168.1.0/24
./target/release/boggy --auto --deep --output json --out report.json
```

## Safety

Only scan networks you own or are authorized to test.
