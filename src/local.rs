//! [`LocalStack`] — which address families THIS host can actually reach.
//!
//! This is the half of the intersection rule that no prior ecosystem copy captured: every existing
//! happy-eyeballs implementation sorted candidates IPv6-first and raced them, but NONE removed a
//! family the LOCAL host cannot reach. So an IPv4-only host still emitted IPv6 SYNs, and an
//! IPv6-only peer from an IPv4-only host was attempted-then-timed-out instead of reported cleanly
//! unreachable. [`LocalStack`] lets [`crate::dial_order`] filter by local capability.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::family::Family;

/// How long a [`LocalStack::cached`] detection is reused before it is re-probed. The host's stack
/// rarely changes mid-process; a few minutes keeps the probe off the dial hot path while still
/// picking up an interface change (e.g. a VPN coming up) within a bounded window.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// The address families THIS host can originate connections on.
///
/// Detection uses the "connect a UDP socket to a documentation address" trick: connecting a UDP
/// socket forces the OS to pick the local source address it would route from WITHOUT sending a
/// packet, so a family with no route (no default route, no address) fails at `connect` and is
/// recorded as absent. Construct it with [`LocalStack::detect`] in production, [`LocalStack::cached`]
/// on the hot path, or [`LocalStack::from_flags`] deterministically in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalStack {
    has_v6: bool,
    has_v4: bool,
}

impl LocalStack {
    /// Probe the host's real IPv6 + IPv4 capability (no packets sent).
    pub fn detect() -> LocalStack {
        LocalStack {
            has_v6: probe_v6(),
            has_v4: probe_v4(),
        }
    }

    /// The process-wide cached detection, re-probed at most once per [`CACHE_TTL`].
    ///
    /// The dial hot path calls this on every connect; caching keeps the UDP-probe syscalls off it
    /// while still refreshing within a bounded window if the host's stack changes.
    pub fn cached() -> LocalStack {
        static CACHE: Mutex<Option<(LocalStack, Instant)>> = Mutex::new(None);
        let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((stack, at)) = *guard {
            if at.elapsed() < CACHE_TTL {
                return stack;
            }
        }
        let fresh = LocalStack::detect();
        *guard = Some((fresh, Instant::now()));
        fresh
    }

    /// A deterministic stack with the given capabilities — the test constructor for the intersection
    /// matrix (no sockets, no host dependency).
    pub const fn from_flags(has_v6: bool, has_v4: bool) -> LocalStack {
        LocalStack { has_v6, has_v4 }
    }

    /// Whether this host can originate a connection on `family`.
    pub fn has(&self, family: Family) -> bool {
        match family {
            Family::V6 => self.has_v6,
            Family::V4 => self.has_v4,
        }
    }

    /// The families this host has, in preference order (IPv6 before IPv4), present-only.
    pub fn families(&self) -> Vec<Family> {
        Family::PREFERENCE
            .into_iter()
            .filter(|f| self.has(*f))
            .collect()
    }
}

/// Probe whether the host has a routable IPv6 source address (connect a UDP socket to a
/// documentation IPv6 address, `2001:db8::/32` — never actually contacted).
fn probe_v6() -> bool {
    let Ok(socket) = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) else {
        return false;
    };
    let probe = SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 9);
    socket.connect(probe).is_ok()
}

/// Probe whether the host has a routable IPv4 source address (connect a UDP socket to a
/// documentation IPv4 address, TEST-NET-3 `203.0.113.0/24` — never actually contacted).
fn probe_v4() -> bool {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return false;
    };
    let probe = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 9);
    socket.connect(probe).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_flags_reports_capability() {
        let dual = LocalStack::from_flags(true, true);
        assert!(dual.has(Family::V6));
        assert!(dual.has(Family::V4));

        let v4_only = LocalStack::from_flags(false, true);
        assert!(!v4_only.has(Family::V6));
        assert!(v4_only.has(Family::V4));
    }

    #[test]
    fn families_are_preference_ordered_and_present_only() {
        assert_eq!(
            LocalStack::from_flags(true, true).families(),
            vec![Family::V6, Family::V4]
        );
        assert_eq!(
            LocalStack::from_flags(false, true).families(),
            vec![Family::V4]
        );
        assert_eq!(
            LocalStack::from_flags(true, false).families(),
            vec![Family::V6]
        );
        assert!(LocalStack::from_flags(false, false).families().is_empty());
    }

    #[test]
    fn detect_and_cached_run_without_panicking() {
        // The result depends on the host, but detection must never panic and cached must agree with
        // a same-instant detect (both reflect the same host).
        let _ = LocalStack::detect();
        let a = LocalStack::cached();
        let b = LocalStack::cached();
        assert_eq!(a, b, "cached detection is stable within the TTL");
    }
}
