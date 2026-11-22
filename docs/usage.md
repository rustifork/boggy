# Usage

## Basic

```sh
boggy --auto
boggy --target 192.168.1.0/24
```

## Deep scan

```sh
boggy --target 192.168.1.0/24 --deep --output json --out report.json
```

## Options

- `--target CIDR` target network
- `--auto` auto-detect local /24
- `--deep` extended ports, default creds, CVE matching
- `--fast` top ports only
- `-j, --threads N` workers (default 64)
- `--timeout MS` per probe timeout (default 800)
- `--output text|json`
- `--out FILE` write report to file

## Raspberry Pi

Cross-compile:

```sh
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/boggy pi@host:/usr/local/bin/
```

Run with sudo for ARP enrichment (optional): `sudo boggy --auto`.