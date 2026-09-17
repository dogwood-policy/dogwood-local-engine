//! The listener: two Unix sockets, two verb sets, one shared state.
//!
//! # The two sockets ARE the boundary
//!
//! `DESIGN.md` §8.1 puts the control plane on a **separate** socket from the data
//! path, and that separation is what makes the "agent has no policy verb"
//! guarantee structural rather than procedural. Three layers enforce it, and the
//! redundancy is deliberate — each catches what the others cannot:
//!
//! 1. **File permissions.** The control socket is created `0700`, so a
//!    lower-privileged uid cannot even `connect()`. The OS refuses before a byte
//!    is exchanged.
//! 2. **Peer-credential uid allowlist.** Every control connection's uid is
//!    checked against the allowlist (§8.1). This is what still holds if the
//!    socket's mode is wrong — a misconfigured deployment degrades to
//!    "authenticated" rather than to "open".
//! 3. **Type-level verb separation.** The data socket deserializes
//!    [`DataRequest`], which has no policy-mutating variant. Even a total
//!    dispatch bug on the data path cannot reach `apply`, because there is no
//!    `apply` to reach.
//!
//! # Threading
//!
//! A thread per connection, each briefly taking the state mutex. This suits the
//! expected load — §3.3 anticipates many concurrent decision callers (an agent
//! spawning sub-agents), each of which does one small blocking round trip — and
//! it keeps the append point the single linearization point the timestamp model
//! requires. A thread pool would bound thread count under pathological
//! connection churn; it would not change the concurrency model, since the
//! critical section is already serialized.

use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dogwood_local_engine::{
    Applied, BatchResult, DurableError, DurableTemporalEngine, Outcome, PolicyToken, Submitted,
    Verb,
};

use crate::codec::to_event_builder;
use crate::peer::{ControlAllowlist, peer_cred};
use crate::protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, FrameError, PolicySummary,
    WireVerb, read_frame, write_frame,
};

/// Map a wire verb to the engine's [`Verb`]. The wire's `Add` carries no id (the
/// engine mints an opaque handle); per-policy verbs carry the opaque handle
/// string, wrapped into [`PolicyToken`].
fn to_verb(verb: WireVerb) -> Verb {
    match verb {
        WireVerb::Add { policy } => Verb::Add { policy },
        WireVerb::Update { id, policy } => Verb::Update {
            id: PolicyToken(id),
            policy,
        },
        WireVerb::Delete { id } => Verb::Delete {
            id: PolicyToken(id),
        },
        WireVerb::Reset { id } => Verb::Reset {
            id: PolicyToken(id),
        },
        WireVerb::DeleteAll => Verb::DeleteAll,
        WireVerb::ResetAll => Verb::ResetAll,
        WireVerb::SetActionSchema { action_schema } => Verb::SetActionSchema { action_schema },
        WireVerb::AppendActionSchema { fragment } => Verb::AppendActionSchema { fragment },
    }
}

/// The server's version, reported by `Ping`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where the server's files live.
///
/// # The layout is the permission model
///
/// §7's privilege asymmetry has to be expressible in file modes, and a single
/// flat directory cannot express it: the state directory must be **unreachable**
/// by the agent (it holds the policy set and the log), while the data socket must
/// be **reachable** by the agent — and on Linux, connecting to a Unix socket
/// requires write permission on the socket file *and* execute (search)
/// permission on every directory above it. One directory cannot be both.
///
/// So the sockets live in their own directory, split by audience:
///
/// ```text
///   <dir>/                     0700  — private: only the server's uid
///     dogwood.redb                   — log, snapshots, policy bundle
///     control.sock             0700  — the privileged authoring socket
///     run/                     0711  — search-only: an agent can traverse it
///       dogwood.sock           0666  — the data socket, connectable by others
/// ```
///
/// `run/` is `0711` (`--x` for others), which grants *traversal* to a known name
/// without granting `readdir` — an agent can connect to the socket it was told
/// about but cannot enumerate the directory. The data socket itself is `0666`
/// because a *connect* needs write permission, and the socket's mode is not what
/// protects it: the data verb set contains nothing that can read or mutate policy
/// (see [`DataRequest`]), so reaching it grants only the ability to submit events
/// about oneself. The control socket, by contrast, stays `0700` **and** inside the
/// private directory, so it is doubly unreachable — and is additionally guarded by
/// the uid allowlist.
#[derive(Debug, Clone)]
pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Paths {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    /// The redb store holding the event log, snapshots, and policy bundle.
    /// Inside the private directory.
    pub fn store(&self) -> PathBuf {
        self.dir.join("dogwood.redb")
    }

    /// The world-traversable subdirectory holding the data socket.
    pub fn run_dir(&self) -> PathBuf {
        self.dir.join("run")
    }

    /// The data socket — reachable by the monitored agent's uid.
    pub fn data_socket(&self) -> PathBuf {
        self.run_dir().join("dogwood.sock")
    }

    /// The control socket — `0700` inside the private directory, privileged uids
    /// only.
    pub fn control_socket(&self) -> PathBuf {
        self.dir.join("control.sock")
    }
}

/// A running server.
pub struct Server {
    state: Arc<Mutex<DurableTemporalEngine>>,
    allowlist: ControlAllowlist,
    paths: Paths,
    shutdown: Arc<AtomicBool>,
    /// How long a connection may sit idle before being reclaimed. Configurable
    /// mainly so tests can assert slot reclamation without waiting out the
    /// production default.
    idle_timeout: std::time::Duration,
}

impl Server {
    /// Open the durable store and prepare to listen. Recovers any previously
    /// installed policy set and its monitor state.
    pub fn open(
        paths: Paths,
        allowlist: ControlAllowlist,
        snapshot_interval: u64,
    ) -> Result<Self, String> {
        std::fs::create_dir_all(&paths.dir)
            .map_err(|e| format!("create {}: {e}", paths.dir.display()))?;
        // The state directory holds the policy set, the log, and the control
        // socket; only the server's own uid has any business in it (§7's
        // privilege asymmetry). Set the mode explicitly rather than relying on
        // umask, which a caller's environment controls.
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", paths.dir.display()))?;

        // The run directory is the one thing an agent of another uid must be able
        // to traverse, so it is `0711` — search without readdir (see `Paths`).
        std::fs::create_dir_all(paths.run_dir())
            .map_err(|e| format!("create {}: {e}", paths.run_dir().display()))?;
        std::fs::set_permissions(paths.run_dir(), std::fs::Permissions::from_mode(0o711))
            .map_err(|e| format!("chmod {}: {e}", paths.run_dir().display()))?;

        let state = DurableTemporalEngine::open(paths.store(), snapshot_interval)
            .map_err(|e| format!("open store: {e}"))?;
        Ok(Server {
            state: Arc::new(Mutex::new(state)),
            allowlist,
            paths,
            shutdown: Arc::new(AtomicBool::new(false)),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        })
    }

    /// Override the idle timeout (see [`DEFAULT_IDLE_TIMEOUT`]).
    ///
    /// Exposed for tests, which need to observe a reclaimed slot without waiting
    /// out the production default. Shortening it in a real deployment only costs
    /// reconnects; lengthening it widens the starvation window.
    pub fn with_idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// A handle that stops [`serve`](Self::serve) at the next connection.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Bind both sockets and serve until shutdown.
    ///
    /// On a clean stop the state is checkpointed unconditionally (`DESIGN.md`
    /// §6.3), so a normal restart replays ≈nothing.
    pub fn serve(&self) -> Result<(), String> {
        // `0666` on the data socket: a connect() needs write permission, and the
        // agent runs as a different uid by design. What protects this socket is
        // not its mode but its verb set — `DataRequest` cannot read or mutate
        // policy. Reachability is gated one level up, by `run/`'s `0711`.
        let data = bind(&self.paths.data_socket(), 0o666)?;
        // `0700` on the control socket, inside the `0700` state directory: two
        // independent reasons another uid cannot reach it, before the uid
        // allowlist is even consulted.
        let control = bind(&self.paths.control_socket(), 0o700)?;

        // Both listeners run on their own thread; the shutdown flag is checked
        // per accepted connection, and a self-connect wakes a blocked `accept`.
        let data_state = Arc::clone(&self.state);
        let data_stop = Arc::clone(&self.shutdown);
        let data_idle = self.idle_timeout;
        let data_thread = std::thread::spawn(move || {
            accept_loop(data, data_stop, data_idle, move |stream| {
                serve_data(stream, &data_state)
            })
        });

        let ctl_state = Arc::clone(&self.state);
        let ctl_stop = Arc::clone(&self.shutdown);
        let ctl_idle = self.idle_timeout;
        let allowlist = self.allowlist.clone();
        let control_thread = std::thread::spawn(move || {
            accept_loop(control, ctl_stop, ctl_idle, move |stream| {
                serve_control(stream, &ctl_state, &allowlist)
            })
        });

        let _ = data_thread.join();
        let _ = control_thread.join();

        // Clean-shutdown checkpoint (§6.3).
        if let Ok(mut state) = self.state.lock() {
            let _ = state.checkpoint();
        }
        let _ = std::fs::remove_file(self.paths.data_socket());
        let _ = std::fs::remove_file(self.paths.control_socket());
        Ok(())
    }

    /// Ask the server to stop, waking both `accept` calls.
    pub fn stop(&self) {
        stop_listening(&self.shutdown, &self.paths);
    }
}

/// Signal shutdown and wake both blocked `accept` calls by connecting to each
/// socket once. Without the self-connect, a server with no traffic would not
/// notice the flag until its next client.
pub fn stop_listening(shutdown: &AtomicBool, paths: &Paths) {
    shutdown.store(true, Ordering::SeqCst);
    let _ = UnixStream::connect(paths.data_socket());
    let _ = UnixStream::connect(paths.control_socket());
}

/// Bind a Unix socket at `path` with mode `mode`, with no window in which the
/// socket exists at the wrong permissions.
///
/// `bind()` creates the socket subject to the process **umask**, and a plain
/// `bind`-then-`chmod` leaves a window in which the socket is accepting
/// connections at whatever the umask allowed. For the control socket that window
/// is a privilege-escalation opportunity, however brief. The fix is to clamp the
/// umask across the `bind` so the socket is *born* no more permissive than
/// intended, then `chmod` to set the exact mode (needed because umask can only
/// remove bits, so a deliberately-permissive mode like the data socket's `0666`
/// still has to be granted explicitly).
///
/// A stale socket file from a previous run is removed first — a crashed server
/// leaves its socket behind, and refusing to start until an operator deletes a
/// file by hand is a worse failure than reclaiming it. (Two servers cannot race
/// here in practice: they would both open the same redb store, and redb holds an
/// exclusive lock, so the second one fails at open before reaching this point.)
fn bind(path: &Path, mode: u32) -> Result<UnixListener, String> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove stale socket {}: {e}", path.display())),
    }

    // Deny every bit `mode` does not grant while the socket is created. Restored
    // immediately after, so this does not leak into anything else the process
    // does. (`umask` is per-process, and both sockets are bound from `serve`
    // before any connection thread starts, so no concurrent file creation can be
    // caught by the clamp.)
    let listener = {
        let previous = unsafe { libc_umask(!mode & 0o777) };
        let result = UnixListener::bind(path);
        unsafe { libc_umask(previous) };
        result.map_err(|e| format!("bind {}: {e}", path.display()))?
    };

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(listener)
}

/// `umask(2)` — set the file-mode creation mask, returning the previous value.
///
/// Declared here rather than taken from a crate: `rustix` (already a dependency,
/// for peer credentials) does not expose `umask`, and pulling in `libc` for one
/// infallible call is not worth a dependency. `umask` cannot fail and has no
/// error path — it only reads and replaces a per-process integer.
unsafe fn libc_umask(mask: u32) -> u32 {
    unsafe extern "C" {
        fn umask(mask: u32) -> u32;
    }
    unsafe { umask(mask) }
}

/// Maximum concurrent connections served per socket.
///
/// A thread per connection with no ceiling means a caller that opens connections
/// in a loop can exhaust the server's memory or thread limit — and the data socket
/// is reachable by exactly the process we do not trust. Refusing the excess turns
/// that from "the server dies" (which fails **open**: no server, no policy
/// enforcement) into "the abusive caller's extra connections are rejected while
/// existing ones keep being served".
///
/// Generous relative to the expected shape (§3.3: many concurrent callers, each
/// doing one short blocking round trip), so a legitimate burst is unaffected.
///
/// A cap **alone is not enough**: a caller that opens exactly the cap's worth of
/// connections and then goes silent holds every slot forever, starving legitimate
/// callers without ever tripping the limit. That is why every connection also
/// carries an idle timeout ([`DEFAULT_IDLE_TIMEOUT`]) — the cap bounds
/// concurrency, the timeout bounds how long a connection may occupy a slot
/// without doing anything. Neither is sufficient by itself.
const MAX_CONNECTIONS: usize = 256;

/// How long a connection may sit idle (no complete request) before the server
/// closes it.
///
/// Connections are persistent by design, so this is a *keep-alive* timeout, not a
/// request deadline: it fires only when a peer has sent nothing at all for this
/// long. A legitimate client that is reaped simply reconnects — the protocol is
/// connectionless in effect, since every request is self-contained.
///
/// The value trades starvation resistance against reconnect churn. 30s is long
/// enough that a client submitting an event even occasionally keeps its
/// connection, and short enough that a hoarded slot is reclaimed promptly.
pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Accept connections until the shutdown flag is set, handling each on its own
/// thread, with at most [`MAX_CONNECTIONS`] in flight.
fn accept_loop<H>(
    listener: UnixListener,
    shutdown: Arc<AtomicBool>,
    idle_timeout: std::time::Duration,
    handler: H,
) where
    H: Fn(UnixStream) + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for stream in listener.incoming() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let stream = match stream {
            Ok(s) => s,
            // A failed accept (fd exhaustion, interrupted) is transient; keep
            // serving rather than exiting the loop.
            Err(_) => continue,
        };

        // Bound how long this connection may hold its slot while sending nothing.
        // Applied to reads only: a write blocking indefinitely would need a peer
        // that never drains its socket, which costs it the same memory it costs
        // us, and a write deadline risks truncating a legitimate large response.
        let _ = stream.set_read_timeout(Some(idle_timeout));

        // Claim a slot, or drop the connection. Closing the stream immediately is
        // the right refusal: it costs the server nothing, and a client sees a
        // clean disconnect it can retry.
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            live.fetch_sub(1, Ordering::SeqCst);
            drop(stream);
            continue;
        }

        let handler = Arc::clone(&handler);
        let live = Arc::clone(&live);
        // A panic in one connection must not take the server down — it would be a
        // denial of service triggerable by whatever input caused it. `spawn`
        // isolates it: the thread dies, the server serves on. The slot is released
        // either way, since `Live`'s drop runs during unwinding.
        std::thread::spawn(move || {
            let _slot = Slot(live);
            handler(stream);
        });
    }
}

/// Releases a connection slot on drop, including while a panic unwinds — so a
/// panicking connection cannot permanently consume capacity.
struct Slot(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

// ─── The data path ───────────────────────────────────────────────────

/// Serve one data connection: framed [`DataRequest`]s until the peer closes.
///
/// Connections are **persistent** (many requests per connection), because the
/// expected caller submits a decision request and later its history event, and
/// paying a connect per event would dominate the cost of everything but the
/// fsync.
fn serve_data(mut stream: UnixStream, state: &Arc<Mutex<DurableTemporalEngine>>) {
    loop {
        let request: DataRequest = match read_frame(&mut stream) {
            Ok(r) => r,
            // A clean close, or a silent peer reaped by the idle timeout:
            // both end the connection with nothing to report.
            Err(FrameError::Eof { .. } | FrameError::IdleTimeout) => return,
            Err(e) => {
                // Report the framing error, then close: after a bad frame the
                // stream position is unknown, so continuing to read would
                // interpret payload bytes as a length header.
                let _ = write_frame(
                    &mut stream,
                    &DataResponse::Error {
                        message: e.to_string(),
                    },
                );
                return;
            }
        };

        let response = handle_data(request, state);
        if write_frame(&mut stream, &response).is_err() {
            return;
        }
    }
}

/// Handle one data request.
fn handle_data(request: DataRequest, state: &Arc<Mutex<DurableTemporalEngine>>) -> DataResponse {
    match request {
        DataRequest::Ping => DataResponse::Pong {
            version: VERSION.to_string(),
        },
        DataRequest::Submit { event } => {
            let mut guard = match state.lock() {
                Ok(g) => g,
                // A poisoned state mutex means a previous request panicked
                // mid-mutation. Refusing is the only safe answer: the log is
                // durable, so a restart recovers, but continuing against
                // possibly-torn state could produce a wrong Allow.
                Err(_) => {
                    return DataResponse::Error {
                        message: "server state unavailable; restart required".to_string(),
                    };
                }
            };
            // The offset stops here — an internal identifier, and the peer on
            // this socket is the policed agent. The assigned timestamp travels:
            // it is a fact about the event that the caller cannot derive.
            match guard.submit(to_event_builder(&event)) {
                Ok(Submitted {
                    ts,
                    outcome: Outcome::Decision(response),
                    ..
                }) => DataResponse::Decision {
                    recorded_at_nanos: ts,
                    allowed: response.allowed(),
                    reason: response
                        .diagnostics()
                        .reason()
                        .map(|r| r.token.to_string())
                        .collect(),
                    errors: response.diagnostics().errors().map(String::from).collect(),
                },
                Ok(Submitted {
                    ts,
                    outcome: Outcome::Recorded,
                    ..
                }) => DataResponse::Recorded {
                    recorded_at_nanos: ts,
                },
                Err(e) => DataResponse::Error {
                    message: e.to_string(),
                },
            }
        }
    }
}

// ─── The control path ────────────────────────────────────────────────

/// Serve one control connection, after authorizing the peer's uid (§8.1).
fn serve_control(
    mut stream: UnixStream,
    state: &Arc<Mutex<DurableTemporalEngine>>,
    allowlist: &ControlAllowlist,
) {
    // Authorize BEFORE reading a request. An unauthorized peer's payload is
    // never parsed, so a caller who may not author policy cannot reach the
    // deserializer for policy-bearing types at all. The uid is used only to gate
    // access here; it is not forwarded to the engine, which records no attributed
    // audit trail (docs/design/DURABLE_ENGINE_REFACTOR.md §5.3).
    match peer_cred(&stream) {
        Ok(cred) if allowlist.permits(cred.uid) => {}
        Ok(cred) => {
            let _ = write_frame(
                &mut stream,
                &ControlResponse::Error {
                    message: format!(
                        "uid {} is not permitted on the control plane (allowed: {:?})",
                        cred.uid,
                        allowlist.uids()
                    ),
                },
            );
            return;
        }
        // Cannot attest the peer ⇒ refuse. See `peer.rs`: an unattributable
        // caller is denied rather than trusted.
        Err(e) => {
            let _ = write_frame(
                &mut stream,
                &ControlResponse::Error {
                    message: format!("peer attestation failed: {e}"),
                },
            );
            return;
        }
    };

    loop {
        let request: ControlRequest = match read_frame(&mut stream) {
            Ok(r) => r,
            // A clean close, or a silent peer reaped by the idle timeout:
            // both end the connection with nothing to report.
            Err(FrameError::Eof { .. } | FrameError::IdleTimeout) => return,
            Err(e) => {
                let _ = write_frame(
                    &mut stream,
                    &ControlResponse::Error {
                        message: e.to_string(),
                    },
                );
                return;
            }
        };

        let response = handle_control(request, state, allowlist);
        if write_frame(&mut stream, &response).is_err() {
            return;
        }
    }
}

/// Handle one control request. The caller has already been authorized by
/// [`serve_control`]; the engine records no attribution, so the uid is not
/// threaded through.
fn handle_control(
    request: ControlRequest,
    state: &Arc<Mutex<DurableTemporalEngine>>,
    allowlist: &ControlAllowlist,
) -> ControlResponse {
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => {
            return ControlResponse::Error {
                message: "server state unavailable; restart required".to_string(),
            };
        }
    };

    match request {
        ControlRequest::Install {
            policy,
            action_schema,
            event_schema,
        } => match guard.install(&policy, &action_schema, event_schema.as_deref(), None) {
            // `Applied::offset` stops here. An offset is only comparable to other
            // offsets and the data plane returns none, so an operator would hold a
            // linearization boundary with nothing to apply it to; the timestamp is
            // the currency both planes share.
            Ok(Applied {
                ts,
                rule_count,
                leaf_count,
                leaves_retained,
                leaves_prospective,
                ..
            }) => ControlResponse::Applied {
                applied_at_nanos: ts,
                rule_count,
                leaf_count,
                leaves_retained,
                leaves_prospective,
            },
            Err(e) => ControlResponse::Error {
                message: e.to_string(),
            },
        },
        ControlRequest::Batch { verbs } => {
            match guard.batch(verbs.into_iter().map(to_verb).collect()) {
                Ok(BatchResult { minted, ts, .. }) => ControlResponse::Batched {
                    minted: minted.into_iter().map(|t| t.0).collect(),
                    applied_at_nanos: ts,
                },
                Err(e) => ControlResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        ControlRequest::List {
            max_results: Some(0),
            ..
        } => {
            // A zero-size page can never make progress: it returns nothing, and any
            // continuation token would just re-request the same empty page forever.
            // Reject it rather than silently reply with an empty page and no token,
            // which a paginating client reads as "the set is empty".
            ControlResponse::Error {
                message: "max_results must be greater than zero".to_string(),
            }
        }
        ControlRequest::List {
            max_results,
            next_token,
        } => {
            // The engine hands back the whole set under one lock (§2.7), in
            // creation order; pagination is this transport concern over that owned
            // snapshot. `next_token` is the last handle of the previous page —
            // resume at the entry *after* the one that bears it. An unknown token
            // (or one past the end) yields an empty final page.
            //
            // Best-effort under concurrent mutation: if the policy named by
            // `next_token` is DELETED between pages, its handle is no longer in the
            // set, so this resumes at the end — the remaining tail is skipped. That
            // is an accepted limitation (a control plane rarely deletes mid-listing,
            // and the caller can always re-list from the top); making it robust
            // would need a monotone cursor decoupled from the handle.
            let all = guard.list();
            let start = match &next_token {
                None => 0,
                Some(after) => all
                    .iter()
                    .position(|e| e.token.0 == *after)
                    .map(|i| i + 1)
                    .unwrap_or(all.len()),
            };
            let remaining = &all[start..];
            let take = max_results.unwrap_or(remaining.len());
            let page = &remaining[..take.min(remaining.len())];
            let policies: Vec<PolicySummary> = page
                .iter()
                .map(|e| PolicySummary {
                    id: e.token.0.clone(),
                    created: e.created,
                    updated: e.updated,
                })
                .collect();
            // A continuation token only when the page did not reach the end — the
            // last handle on this page, so the next call resumes after it.
            let next = (start + page.len() < all.len())
                .then(|| page.last().map(|e| e.token.0.clone()))
                .flatten();
            ControlResponse::PolicyList {
                policies,
                next_token: next,
            }
        }
        ControlRequest::Status => {
            let status = guard.status();
            ControlResponse::Status {
                rule_count: status.rule_count,
                leaf_count: status.leaf_count,
                incremental_leaves: status.incremental_leaves,
                decision_kinds: status.decision_kinds,
                partition_key: status.partition_key,
                log_offset: guard.log_offset(),
                control_uids: allowlist.uids().to_vec(),
            }
        }
        ControlRequest::GetPolicy => match guard.policy_source() {
            Some(source) => ControlResponse::Policy {
                source: source.to_string(),
            },
            None => ControlResponse::Error {
                message: DurableError::NoPolicy.to_string(),
            },
        },
        ControlRequest::GetPolicyById { id } => match guard.get_policy(&PolicyToken(id.clone())) {
            Some(entry) => ControlResponse::Policy {
                source: entry.statement,
            },
            None => ControlResponse::Error {
                message: format!("no such policy: {id}"),
            },
        },
        ControlRequest::GetSchema => match guard.action_schema() {
            Some(action_schema) => ControlResponse::Schema {
                action_schema,
                event_schema: guard.event_schema(),
            },
            None => ControlResponse::Error {
                message: DurableError::NoPolicy.to_string(),
            },
        },
        ControlRequest::Checkpoint => match guard.checkpoint() {
            Ok(up_to_offset) => ControlResponse::Checkpointed { up_to_offset },
            Err(e) => ControlResponse::Error {
                message: e.to_string(),
            },
        },
    }
}
