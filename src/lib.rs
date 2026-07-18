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
//! 3. [`dial_order`] — the local∩peer family intersection, IPv6-first; a typed [`NoCommonFamily`]
//!    when disjoint. Its output NEVER contains a family the local host or the peer lacks.
//! 4. [`connect`] — the RFC-8305 happy-eyeballs racer over that order, IPv6-preferred with graceful
//!    IPv4 fallback; the transport dial is a caller-supplied closure so this crate stays a leaf with
//!    no TLS/socket dependency.
//!
//! ## The core guarantee
//!
//! An address of a family the LOCAL host lacks, or a family the PEER lacks, is NEVER dialed — this is
//! enforced structurally by [`dial_order`] (which [`connect`] builds its attempt list from), not by
//! convention. That is the anti-mis-dial rule the user asked for: "an IPv6 client doesn't try to
//! connect to an IPv4-only client" (and vice-versa).

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
