# Changelog

## 0.7.0

Completeness release:

- CVE database grown from 677 to **1200** entries; NVD refresh default cap raised to 12/vendor.
- New OT/UDP probes (enabled with `--deep`): NTP monlist, BACnet Who-Is/I-Am, EtherNet/IP List Identity.
- CoAP responses now report discovered `.well-known/core` resources.
- UPnP IGD SOAP queries enumerate the WAN IP and up to 8 active port mappings.
- mDNS TXT records are parsed and fed to the fingerprint/CVE correlator.
- `--output sarif` emits SARIF 2.1.0 for CI code-scanning ingestion.
- 51 unit + 13 end-to-end tests, 17 in-binary checks.

## 0.6.3

Speed and stability:

- Port lists of 24+ entries scan in four bounded threads; results are sorted by port.
- HTTP reads stop once Content-Length/chunk framing is satisfied instead of waiting for close.
- CoAP reply window capped at 250 ms, liveness at 150 ms, worker count limited to hosts.
- New `--discovery-ms` flag to shorten the multicast window (default unchanged at 1500).
- Semaphore slots are released via RAII guards; interrupted reads are retried.
- End-to-end test with keep-alive HTTP servers proves concurrent ports finish quickly.

## 0.6.2

Performance pass:

- One TCP connection per port: the liveness socket now carries the banner probe
  instead of opening a second connection (halves handshakes).
- Connect timeout capped at 400 ms while banner reads keep the full `--timeout`.
- Liveness reduced to 4 probes with a 200 ms cap; mDNS and SSDP discovery run in parallel.
- CVE and credential databases are parsed once per scan and shared by all workers
  instead of being re-read and re-parsed for every host and every probe.
- SNMP limited to the two common communities with short, single-shot requests;
  HTTP/Telnet/FTP/RTSP credential attempts are individually time-capped.
- Custom ports get an HTTP probe, so non-standard web interfaces are detected.

## 0.6.1

- Fixed: liveness probe now includes custom ports, so non-standard IoT devices are no longer skipped.
- Fixed: plaintext credential probes skip TLS ports; UDP CoAP is always probed.
- Fixed: Telnet and FTP retry on a fresh connection after a failed login.
- Fixed: web-form success requires a real success marker, not just a session cookie; form parsing is bounded to the form.
- Fixed: deterministic finding de-duplication by id + detail; report files written atomically.
- Fixed: `--threads * 2` overflow, invalid `--output`/severity values, trailing subcommand arguments and `--fast` + `--deep`.
- Fixed: safe subnet enumeration for `/0`, divisor overflow gone; local database overrides are validated before use.
- Security: CRLF injection blocked in HTTP requests, chunked decoding, HTTP Digest MD5-sess, per-host semaphore, unique temp files, ELF architecture check.
- `db-info` now flags local overrides that differ from the manifest; 46 unit and 11 end-to-end tests, 15 in-binary checks.

## 0.6.0

- `boggy update` now updates **source code from GitHub** via git (fetch/reset or clone),
  with `--dir`, `--repo`, `--branch`, `--force`, `--build`, `--install` and `--dry-run`.
- `boggy self-update` remains the verified binary update; `update-db` remains data only.
- Source updates refuse dirty trees unless `--force`; branch names and URLs are validated.
- End-to-end offline git test covering clone, fetch, dirty-tree guard and `--force`.
- README redesigned: banner, at-a-glance table, grouped commands, Mermaid diagram,
  security model and troubleshooting.

## 0.5.0

- `boggy selftest`: 13 in-binary integrity/parser checks for devices without cargo.
- `update-db --dry-run`: validates and prints without writing anything.
- wget fallback when curl is missing or fails; HTTPS certificate checks preserved.
- `--max-hosts` now checked before enumerating CIDRs, so oversized targets fail fast.
- 8 end-to-end tests against the built binary (39 unit tests total: 47 checks).
- README rewritten: quickstart, option table, exit codes, security model, troubleshooting.

## 0.4.0

- **Zero external crates**: removed clap, serde, serde_json and ureq. CLI parsing,
  JSON reading/writing and SHA-256/MD5 are implemented in-tree with hard input limits.
- Release binary drops from ~2.7 MB to ~1.2 MB; offline builds with no crate downloads.
- HTTPS updates via system `curl` (wget fallback): certificate verification, TLS >= 1.2,
  `--proto =https`, no redirects, host allowlist for release asset redirects.
- Bounded JSON parser (depth 64, node/string caps, strict UTF-8 and escapes); malformed
  databases are rejected without panics.
- 38 unit tests, including CLI parsing, JSON roundtrips and manifest consistency.

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
