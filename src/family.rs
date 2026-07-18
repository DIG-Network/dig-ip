//! The address-family primitive every other type in this crate is tagged with.

use std::net::SocketAddr;

/// An IP address family: IPv6 (preferred) or IPv4 (fallback).
///
/// This is the axis the whole crate reasons over — local capability, peer reachability, dial order,
/// and the winning connection are all expressed in terms of a [`Family`]. IPv6 sorts before IPv4
/// everywhere so the ecosystem's IPv6-first rule (CLAUDE.md §5.2) falls out of the ordinary
/// [`Ord`]/[`PartialOrd`] derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// IPv6 — the preferred family.
    V6,
    /// IPv4 — the fallback family.
    V4,
}

impl Family {
    /// The family of a socket address.
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is classified as [`Family::V4`]: it is IPv4
    /// reachability wearing an IPv6 costume, so treating it as V6 would let an IPv6-only host think
    /// it can reach a v4-only peer. Canonicalizing first keeps the family tag honest.
    pub fn of(addr: &SocketAddr) -> Family {
        match addr {
            SocketAddr::V6(a) if a.ip().to_ipv4_mapped().is_none() => Family::V6,
            _ => Family::V4,
        }
    }

    /// The preference-ordered list of both families, IPv6 first.
    pub const PREFERENCE: [Family; 2] = [Family::V6, Family::V4];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_plain_v6_as_v6() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(Family::of(&addr), Family::V6);
    }

    #[test]
    fn classifies_v4_as_v4() {
        let addr: SocketAddr = "203.0.113.1:443".parse().unwrap();
        assert_eq!(Family::of(&addr), Family::V4);
    }

    #[test]
    fn classifies_v4_mapped_v6_as_v4() {
        // `::ffff:203.0.113.1` is IPv4 reachability, so it must NOT be treated as V6.
        let addr: SocketAddr = "[::ffff:203.0.113.1]:443".parse().unwrap();
        assert_eq!(Family::of(&addr), Family::V4);
    }

    #[test]
    fn v6_sorts_before_v4() {
        assert!(Family::V6 < Family::V4);
        assert_eq!(Family::PREFERENCE, [Family::V6, Family::V4]);
    }
}
