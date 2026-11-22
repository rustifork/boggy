# Architecture

boggy is a single-binary Rust scanner.

Modules:
- `net/subnet`: CIDR parsing, host enumeration, auto-detection
- `net/discover`: TCP liveness, mDNS, SSDP/UPnP, ARP table
- `net/ports`: TCP connect scan, banner grabbing, port sets
- `iot/fingerprints`: service/device classification
- `iot/upnp`: UPnP device description fetch/parse
- `iot/default_creds`: HTTP/MQTT/CoAP/RTSP probes
- `iot/cve`: embedded CVE + weak service matching
- `types`: serializable report model

Concurrency: worker pool over hosts, each host scans its ports sequentially.

Size: release profile uses opt-level z, LTO, single codegen unit, panic abort, symbol stripping.