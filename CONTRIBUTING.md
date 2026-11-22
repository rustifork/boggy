# Contributing

## Build

```sh
cargo build
cargo test
cargo build --release
```

## Guidelines

- Keep the binary small (< 5 MB). Prefer `std` over new dependencies.
- Add tests for new parsing/scanning logic.
- Run `cargo fmt` and `cargo clippy` before PR.
- Do not add network calls in unit tests.

## Adding CVEs

Append entries to `db/cves.json` with `id`, `severity`, `title`, `detail`, `ports`, `keywords`. Prefer specific keywords to avoid false positives.