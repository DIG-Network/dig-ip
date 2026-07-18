# dig-ip — normative specification

`dig-ip` is the DIG Network's single, canonical implementation of address-family discovery and
IPv6-first / IPv4-fallback peer dialing (CLAUDE.md §5.2). This document is the normative contract an
independent reimplementation MUST satisfy. It is authoritative over any prose in READMEs.

## 1. Scope

`dig-ip` owns four responsibilities for the whole ecosystem:

1. **Local stack detection** — which address families THIS host can originate connections on.
2. **Peer-candidate aggregation** — a peer's candidate addresses, gathered from every discovery
   source, family-tagged and de-duplicated.
3. **Dial order** — the local∩peer family INTERSECTION, in IPv6-first preference order.
4. **Happy-eyeballs connect** — an RFC-8305-style racer over that order, IPv6-preferred with graceful
   IPv4 fallback.

It is a **leaf crate**: it MUST NOT depend on any other DIG crate, so every peer crate (including
those that vendor rather than depend on `dig-nat`) can consume it. The transport dial itself is a
caller-supplied closure; `dig-ip` MUST NOT pull in a TLS/socket/transport dependency for it.

## 2. `Family`

`Family` is `V6` or `V4`. `Family::of(addr)` returns the family of a `SocketAddr` with ONE required
subtlety: an **IPv4-mapped IPv6 address** (`::ffff:a.b.c.d`) MUST be classified as `V4`. Such an
address is IPv4 reachability, so classifying it as `V6` would let an IPv6-only host believe it can
reach a v4-only peer. `Family` MUST order `V6` before `V4` (IPv6-first).

## 3. `LocalStack`

`LocalStack` records whether the host has working IPv6 and working IPv4.

- `detect()` MUST determine each family's capability WITHOUT sending network traffic. The reference
  method is the "connect a UDP socket to a documentation address" trick (`2001:db8::/32` for IPv6,
  `203.0.113.0/24` for IPv4): connecting a UDP socket forces the OS to pick a source address it would
  route from; a family with no route fails and is recorded absent.
- `cached()` MUST return a process-wide detection re-probed at most once per a bounded TTL, so the
  dial hot path pays no per-connect syscall while still noticing an interface change within the
  window.
- `from_flags(has_v6, has_v4)` is the deterministic constructor (no I/O) for tests.
- `families()` MUST return the present families in preference order (IPv6 before IPv4), present-only.

## 4. Candidate aggregation

`CandidateSource` enumerates provenance: `RelayIntroduction`, `Pex`, `Dht`, `DnsAAAA`, `DnsA`,
`StunReflexive`, `ListenAddr`, `PriorDial`. Provenance is observability only; it MUST NOT influence
the intersection rule (which is family-only).

`PeerCandidates` aggregates a peer's addresses:

- `add(addr, source)` derives the family from the address, de-duplicates by address (a duplicate
  keeps the FIRST source it was seen from), and returns whether the address was new.
- `extend(addrs, source)` adds many with the same dedup.
- `families()` returns the set of families the peer offers.
- `of_family(f)` yields the peer's addresses of family `f` in DISCOVERY (insertion) order.

## 5. `dial_order` — the intersection rule (core contract)

`dial_order(local, peer) -> Result<Vec<SocketAddr>, NoCommonFamily>` computes the dial order.

For each family the LOCAL host has (IPv6 then IPv4), if the PEER also offers that family, the peer's
addresses of that family are appended in discovery order. The result MUST satisfy, as a structural
GUARANTEE (not by convention):

- **G1** — it NEVER contains an address of a family the LOCAL host lacks.
- **G2** — it NEVER contains an address of a family the PEER lacks.
- **G3** — all IPv6 addresses precede all IPv4 addresses (IPv6-first).
- **G4** — when the intersection is empty it returns `Err(NoCommonFamily { local, peer })`, a clean,
  immediate, non-hanging outcome (e.g. an IPv6-only peer from an IPv4-only host). It MUST NOT return
  an empty success.

## 6. `connect` — happy-eyeballs racer (RFC 8305)

`connect(local, peer, config, dial_fn) -> Result<DialWinner<C>, ConnectError<E>>`.

- The attempt list MUST be built ONLY from `dial_order`, so `connect` structurally cannot attempt a
  family excluded by §5 (G1/G2 hold transitively).
- `dial_fn(addr)` performs one candidate's transport connect (async, family-aware via `addr`).
- Attempts are launched IPv6-first with a `DialConfig::attempt_delay` stagger: the most-preferred
  candidate starts first; the next candidate is ALSO started once the current has not completed within
  the stagger (RFC 8305 "Connection Attempt Delay"). Each attempt is bounded by
  `DialConfig::per_attempt_timeout`.
- **IPv6 is the PREFERENCE, not merely first to start.** A lower-priority (IPv4) success MUST be held
  and only returned once every higher-priority (IPv6) attempt has concluded (failed/timed out). So a
  viable IPv6 candidate wins even if a hedged IPv4 attempt connects sooner; IPv4 wins only when IPv6
  genuinely fails.
- On success, `DialWinner { conn, addr, family }` reports which candidate/family won.
- On failure: `ConnectError::NoCommonFamily` when nothing was dialable (no attempt started), or
  `ConnectError::AllFailed(Vec<(addr, E)>)` when every candidate was attempted and failed.
- A per-attempt timeout synthesizes an error of the caller's error type `E` via the `FromTimeout`
  trait (implemented for `String` and `std::io::Error`).

## 7. Conformance

The intersection matrix (§5/§6) MUST be tested deterministically via `LocalStack::from_flags` and a
canned `dial_fn` (no real sockets):

1. v6-only peer, v4-only local → `NoCommonFamily`, zero dials attempted, no hang.
2. dual-stack both → IPv6 wins.
3. dual-stack both, IPv6 fails → IPv4 fallback wins.
4. dual-stack local, v4-only peer → only IPv4 addresses dialed (G2).
5. v4-only local, dual-stack peer → only IPv4 addresses dialed (G1).
6. slow-but-viable IPv6 vs fast IPv4 → IPv6 still wins (preference, not first-to-start).
7. IPv4 hedged only after the stagger while IPv6 is in flight.

## 8. Consumers (CLAUDE.md §5.2)

`dig-nat`, `dig-relay`, `dig-gossip`, `dig-pex`, `dig-dht`, `dig-node`, and the relay infra MUST use
`dig_ip::dial_order` / `dig_ip::connect` rather than hand-rolling candidate ordering or a
happy-eyeballs racer. This is the single source of truth for the address-family/dial contract; see
`SYSTEM.md` (the cross-repo interaction map) and the `canonical` skill.
