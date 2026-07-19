# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.1.2] - 2026-07-19

### Bug Fixes
- **dig-ip:** Fail open on low-confidence local-stack detection so a reachable peer is never stranded (#1102). An empty local∩peer family intersection over a peer that HAS candidates now attempts all of them (IPv6-first) instead of returning `NoCommonFamily`, and an empty `LocalStack.families()` is treated as dual-stack — negative detection is unreliable on overlay/split-tunnel/pre-route networks (Tailscale/WireGuard, isolated LANs, containers). Affirmative-detection filtering (G1/G2), IPv6-first ordering, and IPv4 fallback are unchanged; a `warn!` is emitted on the fail-open path. `NoCommonFamily` is now returned only when the peer offers no candidate at all.

## [0.1.1] - 2026-07-18

### Chores
- **dig-ip:** Relicense GPL-2.0 → Apache-2.0 OR MIT (#1038) (#1)

## [0.1.0] - 2026-07-18

### Features
- **dig-ip:** Address-family discovery + IPv6-first happy-eyeballs dial with local∩peer intersection (#1020 IP-1)


