# Contributing to dig-ip

Thanks for your interest in improving dig-ip. This is the canonical DIG Network implementation
of IPv6-first, IPv4-fallback peer communication (CLAUDE.md §5.2) — a single ecosystem implementation
that replaces three drifting copies in other crates.

## Prerequisites

- [Rust](https://rustup.rs), pinned to **1.75.0** via `Cargo.toml` (`rust-version`).

## Build & test

```sh
# build the crate
cargo build

# run the full test suite
cargo test
```

## The gate (must pass before a PR is merged)

CI runs these on every PR (`.github/workflows/ci.yml`); run them locally first:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo doc --no-deps
cargo llvm-cov nextest --all --retries 2 --fail-under-lines 80 --lcov --output-path lcov.info
```

The coverage gate is **≥80% lines**. The test suite is deterministic (no real sockets — the
dial itself is a closure supplied by the caller), so every path is exercised by the integration
tests.

## Commit conventions

- Use clear, imperative commit subjects (e.g. `feat: …`, `fix: …`, `docs: …`, `test: …`, `refactor: …`).
  Conventional Commits style: `type(optional scope): summary`.
- **Add a `Co-Authored-By:` trailer** if Claude Code helped author the commit:
  ```
  Co-Authored-By: Claude <noreply@anthropic.com>
  ```
- Keep one logical change per commit where practical.

## Versioning

This is a library crate published to crates.io. Every PR must bump the version in `Cargo.toml`
and `Cargo.lock` (`[package] version` fields). Use SemVer:
- **patch**: bugfix or docs-only change
- **minor**: new capability (backwards compatible)
- **major**: breaking change (removed/renamed API, wire/format break)

## Pull requests

1. Branch from `main`.
2. Make the gate green locally (run the commands above).
3. Open a PR with a clear description of the change and its rationale; reference any related issue.
4. Keep the diff focused.
5. A PR stays in **Draft** until all review threads are resolved and the gate verdicts have returned.

