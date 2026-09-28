//! Peer-credential attestation: **who is actually connected**, according to the
//! kernel.
//!
//! This is the mechanism the whole trust boundary rests on. Over a Unix domain
//! socket the kernel reports the connecting process's uid/pid from data the
//! client never supplies — a caller cannot claim a uid it does not have, the way
//! it can claim any `principal` it likes inside an event body. Two distinct uses:
//!
//! 1. **Control-plane authorization** — the privileged socket accepts
//!    policy mutations only from an allowlisted uid. This is the *entire*
//!    authorization scheme for authoring; on a single machine "who may author
//!    policy" is fully answered by "which OS user are you," and the OS already
//!    owns that identity and its revocation.
//! 2. **Trustworthy request context** — the attested uid/pid of a data
//!    caller is ground truth a policy can be written against, unlike the
//!    self-asserted `principal` in an event.
//!
//! # Fail-closed
//!
//! Every failure path here denies. If the kernel will not tell us who the peer
//! is, we do not guess, and we do not fall back to trusting the connection: an
//! unattributable caller on the control socket is refused. This matters because
//! the alternative failure mode — "credentials unavailable, allow" — would turn
//! any platform gap into a full control-plane bypass.

use std::os::unix::net::UnixStream;

/// The kernel-attested identity of a connected peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// The peer's user id.
    pub uid: u32,
    /// The peer's process id. Useful for audit/diagnostics; deliberately **not**
    /// used for authorization, since a pid is reusable and racy in a way a uid
    /// is not.
    pub pid: Option<i32>,
}

/// Read the peer's credentials from a connected stream.
///
/// Returns `Err` when the platform cannot attest the peer, which callers must
/// treat as a denial rather than a soft failure.
#[cfg(target_os = "linux")]
pub fn peer_cred(stream: &UnixStream) -> Result<PeerCred, String> {
    // `SO_PEERCRED` is captured by the kernel at connect time — it reflects the
    // process that actually connected, and cannot be altered by the client
    // afterwards.
    rustix::net::sockopt::socket_peercred(stream)
        .map(|ucred| PeerCred {
            uid: ucred.uid.as_raw(),
            pid: Some(ucred.pid.as_raw_nonzero().get()),
        })
        .map_err(|e| format!("SO_PEERCRED: {e}"))
}

/// Read the peer's credentials from a connected stream.
///
/// On non-Linux Unix, `SO_PEERCRED` does not exist; the BSD/macOS equivalent is
/// `getpeereid`/`LOCAL_PEERCRED`, which yields a uid but no pid. `std` exposes
/// neither, so rather than hand-roll an unsafe FFI path we cannot test here,
/// this returns an error — which fails closed: the control plane refuses every
/// connection, so the server is unusable rather than *insecurely* usable on a
/// platform where the boundary is not actually enforced. Wiring `getpeereid` is
/// a small, well-understood addition when a non-Linux target is a real
/// requirement.
#[cfg(not(target_os = "linux"))]
pub fn peer_cred(_stream: &UnixStream) -> Result<PeerCred, String> {
    Err(
        "peer-credential attestation is only implemented for Linux; \
         refusing to run the trust boundary unverified"
            .to_string(),
    )
}

/// The set of uids permitted on the control socket.
///
/// The default is the server's own uid — the operator who owns the process, who
/// is already outside the threat model. Additional uids may be
/// configured (e.g. an ops user).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlAllowlist {
    uids: Vec<u32>,
}

impl ControlAllowlist {
    /// The default allowlist: the current process's real uid, alone.
    pub fn own_uid() -> Self {
        ControlAllowlist {
            uids: vec![rustix::process::getuid().as_raw()],
        }
    }

    /// The default allowlist plus `extra`.
    pub fn with_extra(extra: impl IntoIterator<Item = u32>) -> Self {
        let mut allowlist = Self::own_uid();
        for uid in extra {
            if !allowlist.uids.contains(&uid) {
                allowlist.uids.push(uid);
            }
        }
        allowlist
    }

    /// Whether `uid` may issue control-plane requests.
    pub fn permits(&self, uid: u32) -> bool {
        self.uids.contains(&uid)
    }

    /// The allowed uids, for `status` reporting.
    pub fn uids(&self) -> &[u32] {
        &self.uids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default allowlist contains this process's uid and nothing else.
    /// A regression here would silently widen who can author
    /// policy.
    #[test]
    fn default_allowlist_is_exactly_the_own_uid() {
        let allowlist = ControlAllowlist::own_uid();
        let me = rustix::process::getuid().as_raw();
        assert_eq!(allowlist.uids(), &[me]);
        assert!(allowlist.permits(me));
        // Some uid that is certainly not ours (root unless we *are* root).
        let other = if me == 0 { 65534 } else { 0 };
        assert!(!allowlist.permits(other), "uid {other} must be refused");
    }

    /// Extra uids are additive and deduplicated against the own-uid default.
    #[test]
    fn extra_uids_are_added_without_duplicating_own_uid() {
        let me = rustix::process::getuid().as_raw();
        let allowlist = ControlAllowlist::with_extra([me, 4242]);
        assert_eq!(allowlist.uids().len(), 2, "own uid must not be duplicated");
        assert!(allowlist.permits(me));
        assert!(allowlist.permits(4242));
        assert!(!allowlist.permits(4243));
    }

    /// Peer credentials of a real socketpair report *our* uid: the attestation
    /// path works end-to-end, so the control-plane gate is not accidentally
    /// erroring open on this platform.
    #[test]
    #[cfg(target_os = "linux")]
    fn peer_cred_reads_our_own_uid_over_a_socketpair() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let cred = peer_cred(&a).expect("peer credentials are available on Linux");
        assert_eq!(cred.uid, rustix::process::getuid().as_raw());
        assert_eq!(cred.pid, Some(std::process::id() as i32));
    }
}
