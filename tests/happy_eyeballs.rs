//! The happy-eyeballs [`connect`] racer — the intersection acceptance matrix + RFC-8305 timing,
//! all driven with a canned dial closure (no real sockets) so the behaviour is deterministic.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dig_ip::CandidateSource;
use dig_ip::{connect, ConnectError, DialConfig, Family, LocalStack, PeerCandidates};

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn cfg() -> DialConfig {
    DialConfig {
        per_attempt_timeout: Duration::from_secs(5),
        attempt_delay: Duration::from_millis(50),
    }
}

/// A peer reachable on the requested families (one canned address per family).
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

// (a) A peer with NO candidates is the only clean unreachable: no dial attempted, no hang.
#[tokio::test]
async fn peer_without_candidates_is_clean_unreachable() {
    let local = LocalStack::from_flags(true, true);
    let peer = PeerCandidates::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();

    let res: Result<dig_ip::DialWinner<()>, ConnectError<String>> =
        connect(&local, &peer, cfg(), move |_addr| {
            let a = a.clone();
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

    assert!(matches!(res, Err(ConnectError::NoCommonFamily(_))));
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        0,
        "no dial may be attempted when the peer offers no candidate"
    );
}

// (a') FAIL OPEN: a v6-only peer from a v4-only-DETECTED host is NOT stranded — the negative v6
// detection may be a false negative on an overlay/pre-route network, so the peer's v6 candidate is
// attempted (and here connects) rather than refused.
#[tokio::test]
async fn empty_intersection_over_a_reachable_peer_still_dials() {
    let local = LocalStack::from_flags(false, true);
    let peer = peer_with(true, false);
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();

    let winner = connect(&local, &peer, cfg(), move |addr| {
        let a = a.clone();
        async move {
            a.fetch_add(1, Ordering::SeqCst);
            Ok::<SocketAddr, String>(addr)
        }
    })
    .await
    .expect("the reachable peer's candidate must be attempted, not stranded");

    assert_eq!(winner.addr, sa("[2001:db8::1]:443"));
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "the peer's v6 candidate is dialed"
    );
}

// (b) dual-stack both → IPv6 wins.
#[tokio::test]
async fn dual_stack_ipv6_wins() {
    let local = LocalStack::from_flags(true, true);
    let peer = peer_with(true, true);

    let winner = connect(&local, &peer, cfg(), |addr| async move {
        Ok::<SocketAddr, String>(addr)
    })
    .await
    .expect("a candidate should win");

    assert_eq!(winner.family, Family::V6);
    assert_eq!(winner.addr, sa("[2001:db8::1]:443"));
}

// (c) IPv6 fails → graceful IPv4 fallback (and the winner is the v4 addr).
#[tokio::test]
async fn ipv6_failure_falls_back_to_ipv4() {
    let local = LocalStack::from_flags(true, true);
    let peer = peer_with(true, true);

    let winner = connect(&local, &peer, cfg(), |addr| async move {
        if Family::of(&addr) == Family::V6 {
            Err("v6 route down".to_string())
        } else {
            Ok(addr)
        }
    })
    .await
    .expect("IPv4 should win when IPv6 fails");

    assert_eq!(winner.family, Family::V4);
    assert_eq!(winner.addr, sa("203.0.113.1:443"));
}

// (d) NEVER dial a family the peer lacks: dual-stack local, v4-only peer → only v4 addrs are dialed.
#[tokio::test]
async fn never_dials_a_family_the_peer_lacks() {
    let local = LocalStack::from_flags(true, true);
    let peer = peer_with(false, true);
    let dialed: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
    let d = dialed.clone();

    let winner = connect(&local, &peer, cfg(), move |addr| {
        let d = d.clone();
        async move {
            d.lock().unwrap().push(addr);
            Ok::<SocketAddr, String>(addr)
        }
    })
    .await
    .unwrap();

    let dialed = dialed.lock().unwrap();
    assert!(
        dialed.iter().all(|a| Family::of(a) == Family::V4),
        "only IPv4 addresses may be dialed for a v4-only peer, got {dialed:?}"
    );
    assert_eq!(winner.family, Family::V4);
}

// (e) NEVER dial a family the local host lacks: v4-only host, dual-stack peer → only v4 dialed.
#[tokio::test]
async fn never_dials_a_family_the_local_host_lacks() {
    let local = LocalStack::from_flags(false, true);
    let peer = peer_with(true, true);
    let dialed: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
    let d = dialed.clone();

    connect(&local, &peer, cfg(), move |addr| {
        let d = d.clone();
        async move {
            d.lock().unwrap().push(addr);
            Ok::<SocketAddr, String>(addr)
        }
    })
    .await
    .unwrap();

    let dialed = dialed.lock().unwrap();
    assert!(
        dialed.iter().all(|a| Family::of(a) == Family::V4),
        "an IPv4-only host must never emit an IPv6 SYN, got {dialed:?}"
    );
}

// A viable IPv6 is PREFERRED even when a hedged IPv4 attempt connects sooner: the IPv6 attempt is
// slow (but succeeds), the IPv4 attempt is instant; IPv6 must still win.
#[tokio::test]
async fn slow_but_viable_ipv6_beats_fast_ipv4() {
    let local = LocalStack::from_flags(true, true);
    let peer = peer_with(true, true);

    let winner = connect(&local, &peer, cfg(), |addr| async move {
        if Family::of(&addr) == Family::V6 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok::<SocketAddr, String>(addr)
    })
    .await
    .unwrap();

    assert_eq!(
        winner.family,
        Family::V6,
        "a viable IPv6 candidate is preferred even if IPv4 connects first"
    );
}

// The IPv4 candidate is only STARTED after the attempt_delay stagger while IPv6 is in flight: with a
// large attempt_delay and a fast-failing IPv6, IPv4 is launched on the failure, not before.
#[tokio::test]
async fn ipv4_is_hedged_after_the_attempt_delay() {
    let local = LocalStack::from_flags(true, true);
    let peer = peer_with(true, true);
    let order: Arc<Mutex<Vec<Family>>> = Arc::new(Mutex::new(Vec::new()));
    let o = order.clone();

    let config = DialConfig {
        per_attempt_timeout: Duration::from_secs(5),
        attempt_delay: Duration::from_secs(1),
    };

    let winner = connect(&local, &peer, config, move |addr| {
        let o = o.clone();
        async move {
            o.lock().unwrap().push(Family::of(&addr));
            if Family::of(&addr) == Family::V6 {
                // IPv6 stalls past the stagger, so IPv4 gets hedged in.
                tokio::time::sleep(Duration::from_millis(1200)).await;
                Err("v6 stalled".to_string())
            } else {
                Ok(addr)
            }
        }
    })
    .await
    .unwrap();

    let order = order.lock().unwrap();
    assert_eq!(order.first(), Some(&Family::V6), "IPv6 is attempted first");
    assert!(
        order.contains(&Family::V4),
        "IPv4 is hedged in after the stagger"
    );
    assert_eq!(winner.family, Family::V4);
}

// Every candidate failing yields AllFailed with a per-candidate error each.
#[tokio::test]
async fn all_candidates_failing_reports_all_failed() {
    let local = LocalStack::from_flags(true, true);
    let peer = peer_with(true, true);

    let res: Result<dig_ip::DialWinner<()>, ConnectError<String>> =
        connect(&local, &peer, cfg(), |addr| async move {
            Err::<(), String>(format!("boom {addr}"))
        })
        .await;

    match res {
        Err(ConnectError::AllFailed(errs)) => assert_eq!(errs.len(), 2),
        other => panic!("expected AllFailed, got {other:?}"),
    }
}

// A candidate that never completes hits the per-attempt timeout, which synthesizes the caller's
// error type via `FromTimeout` — every candidate then times out → AllFailed of timeout errors.
#[tokio::test]
async fn per_attempt_timeout_synthesizes_error() {
    let local = LocalStack::from_flags(true, true);
    let peer = peer_with(true, true);
    let config = DialConfig {
        per_attempt_timeout: Duration::from_millis(30),
        attempt_delay: Duration::from_millis(5),
    };

    let res: Result<dig_ip::DialWinner<()>, ConnectError<String>> =
        connect(&local, &peer, config, |_addr| async move {
            // Never completes within the per-attempt timeout.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok::<(), String>(())
        })
        .await;

    match res {
        Err(ConnectError::AllFailed(errs)) => {
            assert_eq!(errs.len(), 2);
            assert!(errs.iter().all(|(_, e)| e.contains("timed out")));
        }
        other => panic!("expected AllFailed of timeouts, got {other:?}"),
    }
}

// A default config is usable and the winning connection value is returned to the caller.
#[tokio::test]
async fn default_config_returns_the_connection() {
    let local = LocalStack::from_flags(true, true);
    let peer = peer_with(true, true);

    let winner = connect(&local, &peer, DialConfig::default(), |addr| async move {
        Ok::<String, String>(format!("conn to {addr}"))
    })
    .await
    .unwrap();

    assert_eq!(winner.conn, "conn to [2001:db8::1]:443");
}

// The error types render human-readable messages (Display) for logs.
#[test]
fn connect_errors_display_readably() {
    let local = LocalStack::from_flags(false, true);
    let peer = PeerCandidates::new();
    let no_common = dig_ip::dial_order(&local, &peer).unwrap_err();
    let msg = no_common.to_string();
    assert!(msg.contains("no common address family"), "{msg}");

    let err: ConnectError<String> = ConnectError::NoCommonFamily(no_common);
    assert!(err.to_string().contains("no common address family"));

    let failed: ConnectError<String> = ConnectError::AllFailed(vec![(
        "203.0.113.1:443".parse().unwrap(),
        "nope".to_string(),
    )]);
    assert!(failed.to_string().contains("all candidates failed"));
}
