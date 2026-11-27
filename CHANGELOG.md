# Changelog

## 0.3.0

- Update commands: `update-db` (verified), `update` (release check + DB refresh or
  `--self`), `update-check`, `db-info`.
- Download hardening: HTTPS-only by default, redirects disabled, size limits, SHA-256
  pinning via `db/manifest.json`, constant-time digest comparison.
- Strict structural validation of both databases before writing; fetch-all-then-write
  so a bad file never leaves a partial update.
- Atomic writes with create-new temp files, `fsync` and rename; 0600 for databases,
  0755 for the self-updated binary; no symlink following.
- Self-update resolves the architecture-specific release asset, checks the ELF magic
  and verifies SHA-256 from the release digest or `SHA256SUMS`.
- Removed per-attempt memory leaks in form-login probing; added `--max-hosts` guard.
- `net/sha256` added without new dependencies; 30 unit tests.

## 0.2.0

- CVE database: 43 → 677 entries (NVD-derived IoT/OT coverage plus curated core),
  with CVSS, vendor, device class, version constraints and NVD references.
- New `db/creds.json`: 278 vendor-aware credential pairs plus SNMP communities.
- HTTP Basic, Digest and web-form login checks; Telnet, FTP and RTSP credential checks.
- New protocol probes: SNMPv1/v2c, Redis, Memcached, Modbus device ID, Docker,
  Elasticsearch, ADB, MQTT, CoAP, TR-069.
- HTTP banner grabbing now extracts `Server`, `X-Powered-By`, `WWW-Authenticate` and
  page titles; 150+ fingerprint signatures with vendor and version extraction.
- ARP sweep, six mDNS service queries, three SSDP search targets.
- Custom ports/ranges, exclusions, severity filtering, `--fail-on` CI exit code,
  JSONL output, per-host CVE cap, progress output.
- `update-db` refreshes both databases; `tools/refresh_cves.py` rebuilds CVE coverage.
- 22 unit tests, CI format/test/database/build matrix, ~2.6 MB release binary.

## 0.1.0

- Initial lightweight agentless IoT scanner.
