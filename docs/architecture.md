# Architecture

boggy is a single-binary Rust scanner with two JSON data files embedded at build time.

Modules:

- `net/subnet`: CIDR parsing, host enumeration, auto-detection
- `net/discover`: TCP liveness, ARP sweep, mDNS, SSDP/UPnP
- `net/ports`: port sets, custom ranges, TCP connect and banner grabbing
- `net/http`: minimal HTTP/1.0 client, Basic/Digest headers, title extraction
- `net/md5`: MD5 for HTTP Digest (no crypto dependency)
- `iot/fingerprints`: 150+ vendor/device signatures, version extraction
- `iot/upnp`: UPnP device description fetch/parse
- `iot/creds`: credential database, HTTP Basic/Digest/form, Telnet, FTP, RTSP
- `iot/protocols`: SNMP, MQTT, CoAP, Redis, Memcached, Modbus, Docker, Elasticsearch, ADB, TR-069
- `iot/cve`: embedded CVE + weak-config matching, version constraints, CVSS ranking
- `types`: serializable report model and severity ordering

Concurrency: worker pool over hosts, ports scanned sequentially per host, with a
counting semaphore capping simultaneous sockets. UDP probes are issued once per host.

Matching: CVE entries combine banner keywords, open ports, device classes and optional
`affected` version bounds. Findings are de-duplicated by id, sorted by CVSS, capped per
host and filtered by `--min-severity`.

Size: release profile uses opt-level z, LTO, single codegen unit, panic abort and symbol
stripping. The current release binary is ~2.6 MB, including both databases.
