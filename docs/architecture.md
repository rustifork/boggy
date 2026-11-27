# Architecture

boggy is a single-binary, dependency-free Rust scanner with three JSON data files embedded at build time.

Modules:

- `net/subnet`: CIDR parsing, host enumeration, auto-detection
- `net/discover`: TCP liveness, ARP sweep, mDNS, SSDP/UPnP
- `net/ports`: port sets, custom ranges, TCP connect and banner grabbing
- `net/http`: minimal HTTP/1.0 client, Basic/Digest headers, title extraction
- `net/md5`: MD5 for HTTP Digest (no crypto dependency)
- `net/sha256`: SHA-256 for database and release integrity
- `json`: bounded JSON reader/writer (no serde, no panics on malformed input)
- `iot/fingerprints`: 150+ vendor/device signatures, version extraction
- `iot/upnp`: UPnP device description fetch/parse
- `iot/creds`: credential database, HTTP Basic/Digest/form, Telnet, FTP, RTSP
- `iot/protocols`: SNMP, MQTT, CoAP, Redis, Memcached, Modbus, Docker, Elasticsearch, ADB, TR-069
- `iot/cve`: embedded CVE + weak-config matching, version constraints, CVSS ranking
- `types`: serializable report model and severity ordering
- `update`: verified downloads via system curl/wget (wget fallback), strict schema validation, atomic writes, release check and self-update
- `selftest`: in-binary integrity and parser checks
- `tests/cli.rs`: end-to-end tests spawning the built binary

Concurrency: worker pool over hosts, ports scanned sequentially per host, with a
counting semaphore capping simultaneous sockets. UDP probes are issued once per host.
Both JSON databases are parsed once per scan and shared by all workers; the liveness
socket is reused for the banner grab, and mDNS/SSDP discovery run concurrently.

Matching: CVE entries combine banner keywords, open ports, device classes and optional
`affected` version bounds. Findings are de-duplicated by id, sorted by CVSS, capped per
host and filtered by `--min-severity`.

Size: release profile uses opt-level z, LTO, single codegen unit, panic abort and symbol
stripping. The current release binary is ~1.2 MB, including all three databases.
No external crates are compiled: CLI parsing, JSON and crypto hashes are in-tree.

Update safety: URLs are scheme-checked, redirects disabled (release assets only to
GitHub-controlled hosts), downloads size-bounded, TLS certificate checked by curl,
digests compared in constant time, JSON validated structurally, and files replaced via
create-new temp file + fsync + rename. `--max-hosts` (default 65536) bounds scan expansion.
