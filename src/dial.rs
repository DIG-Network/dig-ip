//! [`dial_order`] — THE local∩peer family-intersection rule, the reason this crate exists.
//!
//! Every prior ecosystem copy sorted candidates IPv6-first and raced them, but none removed a family
//! the LOCAL host cannot reach. [`dial_order`] computes the INTERSECTION of the families the local
//! host has and the families the peer offers, then emits the peer's addresses of those families in
//! IPv6-first preference order. Its output is GUARANTEED never to contain a family absent from the
//! local host — so an IPv4-only host physically cannot emit an IPv6 SYN, and an IPv6-only peer from
//! an IPv4-only host yields a clean [`NoCommonFamily`] error instead of a doomed attempt that hangs.

use std::net::SocketAddr;

use crate::candidate::PeerCandidates;
use crate::family::Family;
use crate::local::LocalStack;

/// The local host and the peer share no reachable address family, so there is no address to dial.
///
/// This is a clean, immediate, non-hanging outcome (e.g. an IPv6-only peer from an IPv4-only host):
/// the caller reports the peer unreachable rather than launching attempts that can only time out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoCommonFamily {
    /// The families the local host can originate on.
    pub local: Vec<Family>,
    /// The families the peer offers candidates on.
    pub peer: Vec<Family>,
}

impl std::fmt::Display for NoCommonFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no common address family: local has {:?}, peer offers {:?}",
            self.local, self.peer
        )
    }
}

impl std::error::Error for NoCommonFamily {}

/// The addresses to dial, in IPv6-first preference order over the local∩peer family intersection.
///
/// For each family the LOCAL host has (IPv6 then IPv4), if the PEER also offers that family, the
/// peer's addresses of that family are appended in discovery order. The result therefore:
///
/// - NEVER contains an address of a family the local host lacks (structural anti-mis-dial guarantee);
/// - NEVER contains an address of a family the peer lacks (only the peer's own candidates are used);
/// - lists all viable IPv6 addresses before any IPv4 address (IPv6-first, CLAUDE.md §5.2).
///
/// When the intersection is empty the result is [`Err(NoCommonFamily)`] — a clean unreachable, never
/// an empty attempt list that would silently do nothing.
pub fn dial_order(
    local: &LocalStack,
    peer: &PeerCandidates,
) -> Result<Vec<SocketAddr>, NoCommonFamily> {
    let peer_families = peer.families();
    let mut ordered = Vec::new();
    for family in local.families() {
        if peer_families.contains(&family) {
            ordered.extend(peer.of_family(family));
        }
    }
    if ordered.is_empty() {
        return Err(NoCommonFamily {
            local: local.families(),
            peer: peer_families.into_iter().collect(),
        });
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::CandidateSource;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A peer reachable on the given families (one canned address each).
    fn peer_with(v6: bool, v4: bool) -> PeerCandidates {
        let mut p = PeerCandidates::new();
        if v6 {
            p.add(sa("[2001:db8::1]:443"), CandidateSource::Dht);
        }
        if v4 {
            p.add(sa("203.0.113.1:443"), CandidateSource::DnsA);
        }
        p
    }

    // (a) v6-only peer, v4-only local host → clean NoCommonFamily, no address emitted, no hang.
    #[test]
    fn disjoint_families_report_no_common_family() {
        let local = LocalStack::from_flags(false, true);
        let peer = peer_with(true, false);
        let err = dial_order(&local, &peer).unwrap_err();
        assert_eq!(err.local, vec![Family::V4]);
        assert_eq!(err.peer, vec![Family::V6]);
    }

    // (b) dual-stack both → IPv6 leads the order.
    #[test]
    fn dual_stack_prefers_ipv6() {
        let local = LocalStack::from_flags(true, true);
        let peer = peer_with(true, true);
        let order = dial_order(&local, &peer).unwrap();
        assert_eq!(order, vec![sa("[2001:db8::1]:443"), sa("203.0.113.1:443")]);
    }

    // (d) NEVER dial a family the PEER lacks: v4-only peer, dual-stack local → only v4.
    #[test]
    fn never_dials_a_family_the_peer_lacks() {
        let local = LocalStack::from_flags(true, true);
        let peer = peer_with(false, true);
        let order = dial_order(&local, &peer).unwrap();
        assert_eq!(order, vec![sa("203.0.113.1:443")]);
        assert!(order.iter().all(|a| Family::of(a) == Family::V4));
    }

    // (e) NEVER dial a family the LOCAL host lacks: v4-only local, dual-stack peer → only v4.
    #[test]
    fn never_dials_a_family_the_local_host_lacks() {
        let local = LocalStack::from_flags(false, true);
        let peer = peer_with(true, true);
        let order = dial_order(&local, &peer).unwrap();
        assert_eq!(order, vec![sa("203.0.113.1:443")]);
        assert!(order.iter().all(|a| Family::of(a) == Family::V4));
    }

    #[test]
    fn v6_only_local_and_dual_peer_yields_only_v6() {
        let local = LocalStack::from_flags(true, false);
        let peer = peer_with(true, true);
        let order = dial_order(&local, &peer).unwrap();
        assert_eq!(order, vec![sa("[2001:db8::1]:443")]);
    }

    #[test]
    fn empty_peer_is_no_common_family() {
        let local = LocalStack::from_flags(true, true);
        let err = dial_order(&local, &PeerCandidates::new()).unwrap_err();
        assert!(err.peer.is_empty());
    }

    #[test]
    fn multiple_addresses_per_family_keep_discovery_order() {
        let local = LocalStack::from_flags(true, true);
        let mut peer = PeerCandidates::new();
        peer.add(sa("[2001:db8::2]:443"), CandidateSource::ListenAddr);
        peer.add(sa("198.51.100.7:443"), CandidateSource::Pex);
        peer.add(sa("[2001:db8::1]:443"), CandidateSource::Dht);
        let order = dial_order(&local, &peer).unwrap();
        assert_eq!(
            order,
            vec![
                sa("[2001:db8::2]:443"),
                sa("[2001:db8::1]:443"),
                sa("198.51.100.7:443"),
            ]
        );
    }
}
