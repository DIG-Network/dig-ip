//! Family-tagged peer candidate addresses aggregated from every discovery source.
//!
//! CLAUDE.md §5.2 requires that peer addresses be "stored/returned with the family recorded so the
//! preference is explicit". A DIG node learns a peer's candidate addresses from many places — relay
//! introduction, PEX, the DHT, DNS (AAAA/A), STUN reflexive discovery, advertised listen addresses,
//! prior successful dials — and must aggregate ALL of them ("use as many methods as available"),
//! tag each with its family, and dedup. [`PeerCandidates`] is that aggregate.

use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;

use crate::family::Family;

/// Where a candidate address was learned — provenance, kept for observability and so a future policy
/// could weight sources. It does not affect the family-intersection rule (that is family-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateSource {
    /// Introduced by the relay during rendezvous.
    RelayIntroduction,
    /// Learned via peer exchange (PEX).
    Pex,
    /// Learned from the distributed hash table.
    Dht,
    /// A DNS AAAA (IPv6) record.
    DnsAAAA,
    /// A DNS A (IPv4) record.
    DnsA,
    /// A server-reflexive address discovered via STUN.
    StunReflexive,
    /// An address the peer advertised as a listen address.
    ListenAddr,
    /// An address that succeeded on a prior dial.
    PriorDial,
}

/// A single family-tagged candidate address for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The address to dial.
    pub addr: SocketAddr,
    /// The address family (derived from `addr`; stored so preference is explicit end-to-end).
    pub family: Family,
    /// Where this address was learned.
    pub source: CandidateSource,
}

impl Candidate {
    /// Build a candidate, deriving its family from the address.
    pub fn new(addr: SocketAddr, source: CandidateSource) -> Candidate {
        Candidate {
            addr,
            family: Family::of(&addr),
            source,
        }
    }
}

/// A peer's aggregated, family-tagged, de-duplicated candidate addresses.
///
/// Addresses are kept in insertion (discovery) order within each family so the caller's
/// source ordering is preserved; a duplicate address keeps the FIRST source it was seen from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCandidates {
    candidates: Vec<Candidate>,
    seen: HashSet<SocketAddr>,
}

impl PeerCandidates {
    /// An empty candidate set.
    pub fn new() -> PeerCandidates {
        PeerCandidates::default()
    }

    /// Add one discovered address (family derived, deduplicated). Returns `true` if it was new.
    pub fn add(&mut self, addr: SocketAddr, source: CandidateSource) -> bool {
        if !self.seen.insert(addr) {
            return false;
        }
        self.candidates.push(Candidate::new(addr, source));
        true
    }

    /// Add many addresses from one discovery source (dedup applies).
    pub fn extend<I>(&mut self, addrs: I, source: CandidateSource)
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        for addr in addrs {
            self.add(addr, source);
        }
    }

    /// The families this peer offers at least one candidate on.
    pub fn families(&self) -> BTreeSet<Family> {
        self.candidates.iter().map(|c| c.family).collect()
    }

    /// The candidate addresses of `family`, in discovery order.
    pub fn of_family(&self, family: Family) -> impl Iterator<Item = SocketAddr> + '_ {
        self.candidates
            .iter()
            .filter(move |c| c.family == family)
            .map(|c| c.addr)
    }

    /// Every candidate, in discovery order (family-tagged).
    pub fn all(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Whether this peer has no candidates at all.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn derives_family_on_add() {
        let mut p = PeerCandidates::new();
        p.add(sa("[2001:db8::1]:443"), CandidateSource::Dht);
        p.add(sa("203.0.113.1:443"), CandidateSource::DnsA);
        assert_eq!(p.families(), BTreeSet::from([Family::V6, Family::V4]));
    }

    #[test]
    fn dedups_and_keeps_first_source() {
        let mut p = PeerCandidates::new();
        assert!(p.add(sa("203.0.113.1:443"), CandidateSource::Pex));
        assert!(!p.add(sa("203.0.113.1:443"), CandidateSource::Dht));
        assert_eq!(p.all().len(), 1);
        assert_eq!(p.all()[0].source, CandidateSource::Pex);
    }

    #[test]
    fn of_family_preserves_discovery_order() {
        let mut p = PeerCandidates::new();
        p.extend(
            [sa("[2001:db8::2]:443"), sa("[2001:db8::1]:443")],
            CandidateSource::ListenAddr,
        );
        let v6: Vec<_> = p.of_family(Family::V6).collect();
        assert_eq!(v6, vec![sa("[2001:db8::2]:443"), sa("[2001:db8::1]:443")]);
        assert!(p.of_family(Family::V4).next().is_none());
    }

    #[test]
    fn v4_mapped_v6_aggregates_as_v4() {
        let mut p = PeerCandidates::new();
        p.add(
            sa("[::ffff:203.0.113.9]:443"),
            CandidateSource::StunReflexive,
        );
        assert_eq!(p.families(), BTreeSet::from([Family::V4]));
    }
}
