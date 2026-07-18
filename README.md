# dig-ip

Canonical DIG Network **address-family discovery + IPv6-first happy-eyeballs dial**.

`dig-ip` is the single ecosystem implementation of CLAUDE.md §5.2 (IPv6-first, IPv4-fallback for peer
communication). It replaces three drifting copies of the happy-eyeballs racer (in `dig-nat`,
`dig-gossip`, and `dig-node-core`) and adds the half none of them had: the **local∩peer family
intersection**, so an IPv6-only host never tries to reach an IPv4-only peer (and vice-versa).

## The pipeline

```rust
use dig_ip::{connect, dial_order, CandidateSource, DialConfig, LocalStack, PeerCandidates};

// 1. Which families can THIS host reach?
let local = LocalStack::cached();

// 2. Aggregate a peer's candidates from every discovery source (family-tagged, de-duplicated).
let mut peer = PeerCandidates::new();
peer.add("[2001:db8::1]:443".parse().unwrap(), CandidateSource::Dht);
peer.add("203.0.113.1:443".parse().unwrap(), CandidateSource::DnsA);

// 3. The intersection dial order (IPv6-first). Err(NoCommonFamily) if disjoint.
let order = dial_order(&local, &peer)?;

// 4. Race it IPv6-first with graceful IPv4 fallback. The transport dial is YOUR closure,
//    so dig-ip needs no TLS/socket dependency.
let winner = connect(&local, &peer, DialConfig::default(), |addr| async move {
    tokio::net::TcpStream::connect(addr).await
})
.await?;
println!("connected to {} over {:?}", winner.addr, winner.family);
```

## The core guarantee

`dial_order` NEVER emits an address of a family the local host lacks OR the peer lacks — enforced
structurally, and `connect` builds its attempt list only from `dial_order`. A disjoint pair is a
clean `NoCommonFamily` error, never a doomed attempt that hangs.

## Specification

The normative contract is [`SPEC.md`](./SPEC.md). This crate is a **leaf** (no `dig-*` dependencies)
so every peer crate can consume it.

## License

GPL-2.0.
