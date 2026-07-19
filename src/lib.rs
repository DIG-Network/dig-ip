//! # dig-ip — canonical address-family discovery + IPv6-first happy-eyeballs dial
//!
//! The ONE ecosystem implementation of CLAUDE.md §5.2 (IPv6-first, IPv4-fallback for peer comms).
//! Before this crate, three drifting copies of the happy-eyeballs racer lived in `dig-nat`,
//! `dig-gossip`, and `dig-node-core`, and NONE of them filtered by LOCAL capability — so an
//! IPv4-only host still emitted IPv6 SYNs, and an IPv6-only peer from an IPv4-only host was
//! attempted-then-timed-out rather than reported cleanly unreachable. `dig-ip` consolidates them and
//! adds the missing half: the local∩peer family INTERSECTION.
//!
//! ## The pipeline
//!
//! 1. [`LocalStack`] — which families THIS host can reach (`detect` / `cached` / `from_flags`).
//! 2. [`PeerCandidates`] — a peer's family-tagged candidate addresses, aggregated from every
//!    discovery source ([`CandidateSource`]) and de-duplicated.
//! 3. [`dial_order`] — the local∩peer family intersection, IPv6-first, that FAILS OPEN when local
//!    detection cannot confidently name a common family; a typed [`NoCommonFamily`] only when the peer
//!    offers no candidate at all.
//! 4. [`connect`] — the RFC-8305 happy-eyeballs racer over that order, IPv6-preferred with graceful
//!    IPv4 fallback; the transport dial is a caller-supplied closure so this crate stays a leaf with
//!    no TLS/socket dependency.
//!
//! ## The core guarantee
//!
//! When local detection is AFFIRMATIVE for at least one of the peer's families, the intersection is an
//! optimization: an address of a family the local host affirmatively lacks, or a family the peer lacks,
//! is not dialed ("an IPv6 client doesn't try to connect to an IPv4-only client", and vice-versa).
//! Because negative detection is unreliable — an overlay / split-tunnel / pre-route host probes
//! `ENETUNREACH` for a family it can actually reach — an EMPTY intersection over a peer that has
//! candidates fails OPEN (attempts them all, IPv6-first) rather than stranding a reachable peer;
//! [`NoCommonFamily`] means only "the peer offered nothing to dial".

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod candidate;
mod connect;
mod dial;
mod family;
mod local;

pub use candidate::{Candidate, CandidateSource, PeerCandidates};
pub use connect::{connect, ConnectError, DialConfig, DialWinner, FromTimeout};
pub use dial::{dial_order, NoCommonFamily};
pub use family::Family;
pub use local::LocalStack;
