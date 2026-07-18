//! [`connect`] — the RFC-8305 (Happy Eyeballs v2) dial racer.
//!
//! `connect` builds its attempt list ONLY from [`dial_order`], so it structurally cannot SYN a
//! family the local host or the peer lacks. Over that intersection it races the caller's transport
//! dial closure IPv6-first: it starts the most-preferred (IPv6) candidate, and after a short
//! [`DialConfig::attempt_delay`] ALSO starts the next candidate if the first has not completed — so a
//! viable IPv6 candidate is preferred and IPv4 is used only as a fallback when IPv6 fails or stalls.
//! IPv6 is the PREFERENCE, not merely first to start: a lower-priority success is returned only once
//! every higher-priority attempt has concluded, so a viable IPv6 wins even when a hedged IPv4 attempt
//! connects sooner.
//!
//! The transport dial stays a caller-supplied `async` closure (`dial_fn`), so this crate needs no
//! TLS/socket dependency — dig-nat supplies the real mTLS `TcpStream::connect` + rustls closure; a
//! test supplies a canned one.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use crate::candidate::PeerCandidates;
use crate::dial::{dial_order, NoCommonFamily};
use crate::family::Family;
use crate::local::LocalStack;

/// Tuning for the happy-eyeballs candidate race.
#[derive(Debug, Clone, Copy)]
pub struct DialConfig {
    /// Hard timeout for a single candidate's connect attempt.
    pub per_attempt_timeout: Duration,
    /// Delay before ALSO starting the next (lower-priority) candidate while the current is still in
    /// flight — RFC 8305's "Connection Attempt Delay". A small value (~250ms) hedges a stalled IPv6
    /// without racing so hard that IPv4 routinely beats a viable IPv6.
    pub attempt_delay: Duration,
}

impl Default for DialConfig {
    fn default() -> Self {
        // RFC 8305 recommends a ~250ms connection-attempt delay; the per-attempt timeout is kept
        // generous so a caller's outer per-dial bound is the real ceiling.
        DialConfig {
            per_attempt_timeout: Duration::from_secs(10),
            attempt_delay: Duration::from_millis(250),
        }
    }
}

/// The winning connection plus which candidate/family established it.
#[derive(Debug)]
pub struct DialWinner<C> {
    /// The connection returned by the caller's `dial_fn`.
    pub conn: C,
    /// The address that won.
    pub addr: SocketAddr,
    /// The family of the winning address (so the caller can record the preference that held).
    pub family: Family,
}

/// Why a [`connect`] attempt produced no connection.
#[derive(Debug)]
pub enum ConnectError<E> {
    /// The local host and the peer share no reachable family — no attempt was even started.
    NoCommonFamily(NoCommonFamily),
    /// Every candidate in the intersection was attempted and failed.
    AllFailed(Vec<(SocketAddr, E)>),
}

impl<E: fmt::Display> fmt::Display for ConnectError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::NoCommonFamily(e) => write!(f, "{e}"),
            ConnectError::AllFailed(errs) => {
                let joined = errs
                    .iter()
                    .map(|(a, e)| format!("{a}: {e}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                write!(f, "all candidates failed: [{joined}]")
            }
        }
    }
}

impl<E: fmt::Display + fmt::Debug> std::error::Error for ConnectError<E> {}

/// Establish a connection to `peer`, IPv6-first with graceful IPv4 fallback, over the local∩peer
/// family intersection ([`dial_order`]).
///
/// `dial_fn` performs one candidate's transport connect (async, family-aware via the [`SocketAddr`]
/// it is handed). On success the returned [`DialWinner`] reports the winning address + family; on
/// failure [`ConnectError::NoCommonFamily`] (nothing dialable) or [`ConnectError::AllFailed`] (every
/// candidate tried and failed).
pub async fn connect<C, E, F, Fut>(
    local: &LocalStack,
    peer: &PeerCandidates,
    config: DialConfig,
    dial_fn: F,
) -> Result<DialWinner<C>, ConnectError<E>>
where
    E: fmt::Display + FromTimeout,
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: Future<Output = Result<C, E>> + Send,
    C: Send,
{
    // The intersection filter: the attempt list is derived ONLY from dial_order, so a family the
    // local host or the peer lacks can never be attempted. A disjoint pair fails immediately.
    let ordered = dial_order(local, peer).map_err(ConnectError::NoCommonFamily)?;

    let total = ordered.len();
    // Each attempt yields (priority, addr, result); FuturesUnordered runs them concurrently.
    type Attempt<'f, U, Er> =
        std::pin::Pin<Box<dyn Future<Output = (usize, SocketAddr, Result<U, Er>)> + Send + 'f>>;
    let mut attempts: futures::stream::FuturesUnordered<Attempt<'_, C, E>> =
        futures::stream::FuturesUnordered::new();
    // Priority indices still in flight; a held fallback success is only returned once no live
    // attempt is more preferred than it.
    let mut live: BTreeSet<usize> = BTreeSet::new();
    let mut errors: Vec<(SocketAddr, E)> = Vec::with_capacity(total);
    let mut next_prio = 0usize;
    // The most-preferred success seen so far, held until no more-preferred candidate can beat it.
    let mut best_success: Option<(usize, SocketAddr, C)> = None;

    // Launch candidate `next_prio` as a bounded attempt.
    macro_rules! launch {
        () => {
            if next_prio < total {
                let prio = next_prio;
                let addr = ordered[prio];
                next_prio += 1;
                live.insert(prio);
                let fut = &dial_fn;
                attempts.push(Box::pin(async move {
                    let res =
                        match tokio::time::timeout(config.per_attempt_timeout, fut(addr)).await {
                            Ok(Ok(conn)) => Ok(conn),
                            Ok(Err(e)) => Err(e),
                            Err(_) => Err(TimedOut.into_e()),
                        };
                    (prio, addr, res)
                }));
            }
        };
    }

    // Prime the most-preferred (IPv6) candidate.
    launch!();

    loop {
        // Settle a held success once no still-live AND no unlaunched candidate is more preferred.
        if let Some((p, _, _)) = &best_success {
            let more_preferred_live = live.iter().next().map(|lo| *lo < *p).unwrap_or(false);
            let more_preferred_unlaunched = next_prio <= *p;
            if !more_preferred_live && !more_preferred_unlaunched {
                let (_, addr, conn) = best_success.take().unwrap();
                return Ok(DialWinner {
                    conn,
                    addr,
                    family: Family::of(&addr),
                });
            }
        }

        // Nothing running and nothing left to launch → done.
        if live.is_empty() && next_prio >= total {
            break;
        }

        let stagger = tokio::time::sleep(config.attempt_delay);
        tokio::select! {
            biased;
            finished = futures::StreamExt::next(&mut attempts), if !live.is_empty() => {
                match finished {
                    Some((prio, addr, Ok(conn))) => {
                        live.remove(&prio);
                        // Top-priority (index 0, most-preferred IPv6) success wins outright.
                        if prio == 0 {
                            return Ok(DialWinner { conn, addr, family: Family::of(&addr) });
                        }
                        // Otherwise hold the most-preferred success; keep racing more-preferred ones.
                        let keep = best_success.as_ref().map(|(bp, _, _)| prio < *bp).unwrap_or(true);
                        if keep {
                            best_success = Some((prio, addr, conn));
                        }
                        launch!();
                    }
                    Some((prio, addr, Err(e))) => {
                        live.remove(&prio);
                        errors.push((addr, e));
                        launch!();
                    }
                    None => break,
                }
            }
            _ = stagger, if !live.is_empty() && next_prio < total => {
                // The preferred candidate is stalling — hedge by ALSO starting the next candidate.
                launch!();
            }
        }
    }

    // Nothing left in flight: return the most-preferred held success, else the collected errors.
    if let Some((_, addr, conn)) = best_success {
        return Ok(DialWinner {
            conn,
            addr,
            family: Family::of(&addr),
        });
    }
    Err(ConnectError::AllFailed(errors))
}

/// A private timeout marker so the racer can synthesize a per-attempt-timeout error of the caller's
/// error type `E` without requiring `E: From<std::io::Error>`. The caller's `E` must be constructible
/// from a `&str`-ish description; we route through the [`FromTimeout`] shim implemented for the common
/// case (`String`) and any `E: From<std::io::Error>`.
struct TimedOut;

impl TimedOut {
    fn into_e<E: FromTimeout>(self) -> E {
        E::timed_out()
    }
}

/// How to construct the caller's error type for a per-attempt timeout. Implemented for `String` (the
/// common test/closure error) and any type convertible from a `std::io::Error`.
pub trait FromTimeout {
    /// Build the "connect attempt timed out" value of this error type.
    fn timed_out() -> Self;
}

impl FromTimeout for String {
    fn timed_out() -> Self {
        "connect attempt timed out".to_string()
    }
}

impl FromTimeout for std::io::Error {
    fn timed_out() -> Self {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect attempt timed out")
    }
}
