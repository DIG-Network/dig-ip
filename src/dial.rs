//! [`dial_order`] — THE local∩peer family-intersection rule, the reason this crate exists.
//!
//! Every prior ecosystem copy sorted candidates IPv6-first and raced them, but none removed a family
//! the LOCAL host cannot reach. [`dial_order`] computes the INTERSECTION of the families the local
//! host has and the families the peer offers, then emits the peer's addresses of those families in
//! IPv6-first preference order — so an IPv4-only host prefers not to emit an IPv6 SYN.
//!
//! ## Detection confidence — fail OPEN, never strand a reachable peer
//!
//! [`LocalStack`] detection is affirmative-only: a probe that SUCCEEDS proves the host has a routable
//! source address for that family, but a probe that FAILS proves only that there is no *default* route
//! to the public documentation address — NOT that the family is unreachable. On overlay / split-tunnel
//! / subnet-routed networks (Tailscale/WireGuard `100.64/10`·`10.x`, isolated LANs, containers) and in
//! the window before the route is up at boot, the probe returns `ENETUNREACH` even though peers on a
//! specific route ARE reachable. Treating that false negative as "family absent" made the intersection
//! fail CLOSED and refuse to dial a peer that was actually reachable (the regression this crate fixes).
//!
//! So the intersection is an OPTIMIZATION applied ONLY when local detection is affirmative for at least
//! one of the peer's families. When the intersection is empty but the peer HAS candidates, dialing
//! fails OPEN: it attempts ALL of the peer's candidates (IPv6-first) rather than stranding a peer the
//! (unreliable) negative detection cannot honestly rule out. [`NoCommonFamily`] is reserved for the one
//! case with genuinely nothing to dial — a peer with no candidates at all.

use std::net::SocketAddr;

use tracing::warn;

use crate::candidate::PeerCandidates;
use crate::family::Family;
use crate::local::LocalStack;

/// The peer offers no candidate address at all, so there is nothing to dial.
///
/// This is a clean, immediate, non-hanging outcome: the caller reports the peer unreachable rather
/// than launching attempts that can only time out. It is NOT returned merely because local stack
/// detection failed to find a common family — negative detection is unreliable (see the module docs),
/// so an empty local∩peer intersection over a peer that HAS candidates fails OPEN instead.
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

/// The addresses to dial, in IPv6-first preference order.
///
/// When local detection is affirmative for at least one of the peer's families, the result is the
/// local∩peer INTERSECTION and therefore:
///
/// - contains no family the local host affirmatively lacks (the anti-mis-dial optimization, G1);
/// - contains no family the peer lacks (only the peer's own candidates are used, G2);
/// - lists all viable IPv6 addresses before any IPv4 address (IPv6-first, CLAUDE.md §5.2, G3).
///
/// When that intersection is empty but the peer HAS candidates, the result FAILS OPEN: it is ALL of
/// the peer's candidates, IPv6-first — because negative local detection is unreliable and must not
/// strand a reachable peer (see the module docs). This path emits a `warn!` so the connectivity gap
/// is observable. [`Err(NoCommonFamily)`] is returned ONLY when the peer offers no candidate at all.
pub fn dial_order(
    local: &LocalStack,
    peer: &PeerCandidates,
) -> Result<Vec<SocketAddr>, NoCommonFamily> {
    match plan(local, peer) {
        DialPlan::Intersection(order) => Ok(order),
        DialPlan::FailOpen(order) => {
            warn!(
                local = ?local.families(),
                peer = ?peer.families(),
                candidates = order.len(),
                "local∩peer address-family intersection is empty; failing OPEN to all peer \
                 candidates (IPv6-first) — local-stack detection may be a false negative on an \
                 overlay/split-tunnel/pre-route network"
            );
            Ok(order)
        }
        DialPlan::NoCandidates => Err(NoCommonFamily {
            local: local.families(),
            peer: peer.families().into_iter().collect(),
        }),
    }
}

/// The dial selection outcome, split out from [`dial_order`] as a side-effect-free test seam so the
/// confident-intersection, fail-open, and nothing-to-dial paths can each be asserted directly.
#[derive(Debug, PartialEq, Eq)]
enum DialPlan {
    /// Local detection is affirmative for ≥1 of the peer's families: the filtered local∩peer
    /// intersection, IPv6-first (G1/G2/G3 hold).
    Intersection(Vec<SocketAddr>),
    /// The intersection is empty but the peer has candidates: fail OPEN to ALL peer candidates,
    /// IPv6-first, because negative local detection is unreliable and must not strand the peer.
    FailOpen(Vec<SocketAddr>),
    /// The peer offers no candidate at all — genuinely nothing to dial.
    NoCandidates,
}

/// Decide how to dial `peer` from `local` (see [`DialPlan`]). Pure: no logging, no I/O.
fn plan(local: &LocalStack, peer: &PeerCandidates) -> DialPlan {
    let intersection = candidates_in_preference_order(peer, |family| local.has(family));
    if !intersection.is_empty() {
        return DialPlan::Intersection(intersection);
    }
    if peer.is_empty() {
        return DialPlan::NoCandidates;
    }
    // Empty intersection over a peer that HAS candidates: the negative detection cannot be trusted,
    // so attempt every candidate the peer offers rather than stranding it.
    DialPlan::FailOpen(candidates_in_preference_order(peer, |_| true))
}

/// The peer's candidate addresses whose family passes `accept`, emitted IPv6-first (all V6 before any
/// V4) with each family's discovery order preserved.
fn candidates_in_preference_order(
    peer: &PeerCandidates,
    accept: impl Fn(Family) -> bool,
) -> Vec<SocketAddr> {
    let mut ordered = Vec::new();
    for family in Family::PREFERENCE {
        if accept(family) {
            ordered.extend(peer.of_family(family));
        }
    }
    ordered
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

    // (a) Disjoint AFFIRMATIVE detection is no longer stranded: a v4-only-detected local dialing a
    // v6-only peer FAILS OPEN to the peer's v6 candidate — the negative v6 detection may be a false
    // negative (overlay/pre-route), and the peer HAS a candidate, so it must be attempted.
    #[test]
    fn empty_intersection_over_a_reachable_peer_fails_open() {
        let local = LocalStack::from_flags(false, true);
        let peer = peer_with(true, false);
        assert_eq!(
            plan(&local, &peer),
            DialPlan::FailOpen(vec![sa("[2001:db8::1]:443")])
        );
        // The public API still yields the peer's candidate (no NoCommonFamily strand).
        assert_eq!(
            dial_order(&local, &peer).unwrap(),
            vec![sa("[2001:db8::1]:443")]
        );
    }

    // No default route at all (both probes false → empty families) is treated as dual-stack: attempt
    // every candidate the peer offers, IPv6-first.
    #[test]
    fn no_default_route_local_dials_all_peer_candidates_ipv6_first() {
        let local = LocalStack::from_flags(false, false);
        let peer = peer_with(true, true);
        assert_eq!(
            plan(&local, &peer),
            DialPlan::FailOpen(vec![sa("[2001:db8::1]:443"), sa("203.0.113.1:443")])
        );
        assert_eq!(
            dial_order(&local, &peer).unwrap(),
            vec![sa("[2001:db8::1]:443"), sa("203.0.113.1:443")]
        );
    }

    // The overlay case: a host with a public IPv6 route but only an overlay IPv4 route (v4 probe is a
    // false negative) reaching a v4-only peer must still dial the peer's v4 candidate.
    #[test]
    fn v6_affirmative_local_still_dials_a_v4_only_peer() {
        let local = LocalStack::from_flags(true, false);
        let peer = peer_with(false, true);
        assert_eq!(
            plan(&local, &peer),
            DialPlan::FailOpen(vec![sa("203.0.113.1:443")])
        );
        assert_eq!(
            dial_order(&local, &peer).unwrap(),
            vec![sa("203.0.113.1:443")]
        );
    }

    // A confident common family keeps the intersection as an optimization (not a fail-open).
    #[test]
    fn affirmative_common_family_uses_the_intersection() {
        let local = LocalStack::from_flags(false, true);
        let peer = peer_with(true, true);
        assert_eq!(
            plan(&local, &peer),
            DialPlan::Intersection(vec![sa("203.0.113.1:443")])
        );
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
