# Contributing

## Build

```sh
cargo fmt
cargo test
cargo build --release
```

CI additionally builds for x86_64, aarch64 and armv7 and checks the binary stays under 5 MB.

## Guidelines

- Keep the release binary under 5 MB. Prefer `std` over new dependencies.
- Add unit tests for new parsing/scanning logic; no network calls in unit tests.
- Keep probes bounded: timeouts, attempt limits and a socket semaphore are mandatory.
- Do not add root-dependent operations (raw sockets) to the scanning path.

## Adding CVEs

Append entries to `db/cves.json` (or let `tools/refresh_cves.py` extend it):

```json
{
  "id": "CVE-2021-36260",
  "cve": "CVE-2021-36260",
  "severity": "critical",
  "cvss": 9.8,
  "title": "Hikvision command injection",
  "detail": "Unauthenticated command injection in the web server",
  "vendor": "Hikvision",
  "ports": [80, 443, 8000],
  "keywords": ["hikvision", "dvrdvs"],
  "device_types": ["camera"],
  "affected": [{"product": "apache", "below": "2.4.51"}],
  "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-36260"
}
```

- `keywords` / `ports` / `device_types` are alternative gates; at least one is required.
- `affected` replaces keyword matching with a version comparison extracted from banners.
- `all_keywords` and `exclude_keywords` tighten or suppress matches.
- Prefer specific keywords to avoid false positives.

## Adding credentials

Edit `db/creds.json`: add pairs under `generic.<protocol>` or create a vendor block with
`http`, `telnet`, `ftp` and `rtsp` lists. Vendor pairs are tried first. SNMP communities
go in the top-level `snmp` array.
