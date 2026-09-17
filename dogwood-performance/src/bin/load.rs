//! Open-loop concurrency harness: offer requests at a fixed **rate** and report
//! the resulting latency distribution.
//!
//! # Why this is not a criterion benchmark
//!
//! Criterion measures how long a closure it controls takes — a *closed* loop: it
//! never issues request N+1 until N returns. That is the wrong instrument for the
//! question "what happens at 500 requests/second", because the interesting
//! behaviour is precisely what a closed loop cannot produce: once the offered rate
//! exceeds service capacity, requests **queue**, and latency grows without bound
//! while throughput flatlines. A closed loop silently reduces its own offered rate
//! when the server slows down, so it reports a comfortable latency and never
//! reveals the cliff.
//!
//! So this harness offers load on a schedule and measures each request against the
//! time it was *supposed* to start, not the time it actually did. That difference —
//! **coordinated omission** — is the classic way load tests understate latency: if
//! a request is stuck behind a slow predecessor, its queueing delay belongs in the
//! measurement, and dropping it flatters the result exactly when the system is
//! struggling.
//!
//! # What it drives
//!
//! Real clients over the server's real Unix socket, so the numbers include framing,
//! the syscall round trip, the state lock, and the `fsync`. The reference
//! implementation is deliberately **not** load-tested: it is a single-threaded,
//! non-durable in-process library with no concurrency story at all, so "the
//! reference at 500 rps" would be a measurement of a mutex the harness itself
//! added, not of Dogwood.
//!
//! # Usage
//!
//! ```text
//! cargo run --release -p dogwood-performance --bin load -- \
//!     [--policies 10,100,1000] [--rates 50,200,500,1000] [--seconds 5] [--clients 16]
//! ```

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dogwood_performance::driver::{fsync_floor, to_wire};
use dogwood_performance::workload::{
    ACTION_SCHEMA, Pinning, WINDOW_SECONDS, event_stream, policy_set,
};
use dogwood_server::protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, read_frame, write_frame,
};
use dogwood_server::{ControlAllowlist, ControlClient, Paths, Server};

const SESSIONS: usize = 10;
const SERVERS: usize = 49;
const LOGIN_EVERY: usize = 5;

fn main() {
    let cfg = Config::from_args();

    let floor = fsync_floor(200);
    println!("# Dogwood concurrency load test");
    println!("#");
    println!(
        "# durability floor (one fsync'd append): {:.3} ms",
        floor.as_secs_f64() * 1000.0
    );
    println!(
        "#   => single-instance throughput ceiling ~{:.0} req/s. Offered rates above",
        1.0 / floor.as_secs_f64()
    );
    println!("#      this CANNOT be served; latency will grow without bound, which is");
    println!("#      the expected result, not a bug.");
    println!("#");
    println!("# Latency is measured from each request's SCHEDULED start, so queueing");
    println!("# delay is included (no coordinated omission).");
    println!("#");
    match cfg.reset {
        Reset::PerRate => println!(
            "# Each row gets a FRESH server, so rows are independent and the rate list\n\
             # may be reordered without changing them."
        ),
        Reset::Never => println!(
            "# --reset none: ONE server is shared across the whole rate list, so each row\n\
             # inherits every earlier row's history. Later rows are penalised; the numbers\n\
             # depend on the order of --rates. For comparison only."
        ),
    }
    if cfg.initial_events > 0 {
        println!(
            "# Pre-load: {} events submitted before each measurement. Timestamps are epoch\n\
             # nanoseconds, so the whole pre-load sits inside the {WINDOW_SECONDS}s rule window\n\
             # and retained depth is the full count.",
            cfg.initial_events
        );
    }
    println!("#");
    println!("# p50/p90/p99 print '-' when too few samples were collected for the quantile");
    println!("# to be anything but the maximum.");
    println!();
    println!(
        "{:<10} {:>7} {:>8} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7} {:>6}",
        "pinning",
        "policies",
        "offered",
        "achieved",
        "p50_ms",
        "p90_ms",
        "p99_ms",
        "max_ms",
        "errs",
        "init"
    );

    let init_depth = cfg.initial_events;
    for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
        for &policies in &cfg.policies {
            // Held across the rate loop only under `--reset none`; otherwise
            // replaced (and so torn down) before every rate. Assigning `None`
            // first runs the old server's `Drop` — which stops it and removes its
            // directory — before the replacement binds the same socket path.
            let mut server: Option<TestServer> = None;
            for &rate in &cfg.rates {
                if cfg.reset == Reset::PerRate || server.is_none() {
                    // Explicit: the old server must be fully torn down BEFORE the
                    // replacement is built, because they share a directory and
                    // socket path and `start` wipes that directory.
                    drop(server.take());
                    server = Some(TestServer::start(policies, pinning, cfg.initial_events));
                }
                let r = run_one(
                    server.as_ref().expect("server"),
                    rate,
                    cfg.seconds,
                    cfg.clients,
                );
                let q = |v: Option<f64>| match v {
                    Some(x) => format!("{x:.2}"),
                    None => "-".to_string(),
                };
                println!(
                    "{:<10} {:>7} {:>8} {:>9.0} {:>9} {:>9} {:>9} {:>9.2} {:>7} {:>6}",
                    pinning.label(),
                    policies,
                    rate,
                    r.achieved,
                    q(r.p50),
                    q(r.p90),
                    q(r.p99),
                    r.max,
                    r.errors,
                    init_depth,
                );
            }
        }
    }
}

// ─── configuration ───────────────────────────────────────────────────

struct Config {
    policies: Vec<usize>,
    rates: Vec<u64>,
    seconds: u64,
    clients: usize,
    /// Events submitted before measurement starts, so a row can be measured
    /// against a non-empty history instead of a cold store.
    initial_events: usize,
    reset: Reset,
}

/// When the server under test is rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reset {
    /// A fresh server (and a fresh pre-load) before every rate. The default,
    /// because it is what makes rows comparable: without it a single server is
    /// shared across the whole rate list, so each row inherits every earlier
    /// row's history and the last row is always the most penalised.
    PerRate,
    /// One server for the whole rate list — the old behaviour, kept so the bias
    /// above can be demonstrated rather than merely asserted.
    Never,
}

impl Config {
    fn from_args() -> Config {
        let mut cfg = Config {
            policies: vec![10, 100, 1000, 10_000],
            // Spans four orders of magnitude on purpose. The low rates (1, 10, 100)
            // are the *realistic* operating region — an agent making a decision per
            // second is 1 rps — and they answer a different question from the high
            // ones: not "where does it break" but "what latency does a caller
            // actually see when the server is idle". The high rates (500, 1000)
            // straddle the fsync ceiling so the saturation cliff is visible.
            //
            // Both matter. A benchmark that only reported saturation would imply the
            // server is marginal; one that only reported 1 rps would hide that it has
            // a hard ceiling.
            rates: vec![1, 10, 100, 500, 1000],
            seconds: 5,
            clients: 16,
            initial_events: 0,
            reset: Reset::PerRate,
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i + 1 < args.len() {
            let list = |s: &str| -> Vec<u64> {
                s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
            };
            match args[i].as_str() {
                "--policies" => {
                    cfg.policies = list(&args[i + 1]).into_iter().map(|v| v as usize).collect()
                }
                "--rates" => cfg.rates = list(&args[i + 1]),
                "--seconds" => cfg.seconds = args[i + 1].parse().unwrap_or(cfg.seconds),
                "--clients" => cfg.clients = args[i + 1].parse().unwrap_or(cfg.clients),
                "--initial-events" => {
                    cfg.initial_events = args[i + 1].parse().unwrap_or(cfg.initial_events)
                }
                "--reset" => {
                    cfg.reset = match args[i + 1].as_str() {
                        "per-rate" => Reset::PerRate,
                        "none" | "never" => Reset::Never,
                        other => {
                            eprintln!("warning: unknown --reset {other}, keeping per-rate");
                            cfg.reset
                        }
                    }
                }
                other => eprintln!("warning: ignoring unknown flag {other}"),
            }
            i += 2;
        }
        cfg
    }
}

// ─── the server under test ───────────────────────────────────────────

struct TestServer {
    paths: Paths,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(policies: usize, pinning: Pinning, initial_events: usize) -> TestServer {
        let dir = std::env::temp_dir().join(format!(
            "dogwood_load_{}_{policies}_{}",
            std::process::id(),
            pinning.label()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths::new(&dir);
        // Periodic snapshots disabled: a checkpoint mid-run would appear as a
        // latency spike attributable to bookkeeping rather than to load.
        let server =
            Server::open(paths.clone(), ControlAllowlist::own_uid(), 0).expect("server opens");
        let shutdown = server.shutdown_handle();
        let handle = std::thread::spawn(move || {
            server.serve().expect("serve");
        });
        let this = TestServer {
            paths,
            shutdown,
            handle: Some(handle),
        };
        this.wait_ready();
        this.install(policies, pinning);
        this.preload(initial_events);
        this
    }

    /// Submit `n` events before measurement, so the row is measured against a
    /// non-empty retained window rather than a cold store.
    ///
    /// Goes through the ordinary `submit` path rather than seeding the store
    /// directly: the state a row starts from is then, by construction, a state
    /// the server could actually have reached, with store-assigned timestamps
    /// and monitors stepped exactly as in production.
    ///
    /// The stream is a fixed prefix of the generator and does NOT depend on the
    /// offered rate, so `--initial-events` varies the starting state without
    /// also varying what is measured from it.
    fn preload(&self, n: usize) {
        if n == 0 {
            return;
        }
        let mut stream = UnixStream::connect(self.paths.data_socket()).expect("preload connects");
        for e in event_stream(n, SESSIONS, SERVERS, LOGIN_EVERY) {
            let request = DataRequest::Submit { event: to_wire(&e) };
            assert!(
                round_trip(&mut stream, &request),
                "pre-load submission failed"
            );
        }
        // A partial pre-load would show up only as unexplained capacity, so
        // check it: every event must be durably appended. With nanosecond
        // timestamps the whole pre-load stays inside the rule window, so the
        // retained depth is the requested `n`.
        let want = n as u64;
        let got = self.log_offset();
        assert!(
            got >= want,
            "pre-load appended {got} events, expected at least {want}"
        );
    }

    /// The log offset reported by the control plane — the number of events
    /// appended so far.
    fn log_offset(&self) -> u64 {
        match ControlClient::connect(self.paths.control_socket())
            .expect("control connects")
            .call(&ControlRequest::Status)
            .expect("status call")
        {
            ControlResponse::Status { log_offset, .. } => log_offset,
            other => panic!("expected status, got {other:?}"),
        }
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(mut s) = UnixStream::connect(self.paths.data_socket())
                && write_frame(&mut s, &DataRequest::Ping).is_ok()
                && matches!(
                    read_frame::<_, DataResponse>(&mut s),
                    Ok(DataResponse::Pong { .. })
                )
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("server did not become ready");
    }

    fn install(&self, policies: usize, pinning: Pinning) {
        let response = ControlClient::connect(self.paths.control_socket())
            .expect("control connects")
            .call(&ControlRequest::Install {
                policy: policy_set(policies),
                action_schema: ACTION_SCHEMA.to_string(),
                event_schema: Some(pinning.event_schema().to_string()),
            })
            .expect("apply call");
        assert!(
            !matches!(
                response,
                dogwood_server::protocol::ControlResponse::Error { .. }
            ),
            "policy install failed: {response:?}"
        );
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            self.shutdown.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(self.paths.data_socket());
            let _ = UnixStream::connect(self.paths.control_socket());
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(&self.paths.dir);
    }
}

// ─── the load run ────────────────────────────────────────────────────

struct RunResult {
    achieved: f64,
    /// `None` when too few samples were collected for the quantile to mean
    /// anything more than the maximum — see `pick` in `run_one`.
    p50: Option<f64>,
    p90: Option<f64>,
    p99: Option<f64>,
    max: f64,
    errors: u64,
}

/// Offer `rate` requests/second for `seconds`, spread across `clients` threads,
/// and return the latency distribution.
///
/// Each client owns a persistent connection (matching how a real caller behaves,
/// and avoiding measuring connection setup) and is assigned a **pre-computed
/// schedule** of absolute deadlines. Measuring from the deadline rather than from
/// the send is what avoids coordinated omission: a request that could not be sent
/// on time has already accrued latency, and that delay is real.
/// `clients` is an upper bound, not a fixed count: see the client-scaling note
/// below.
fn run_one(server: &TestServer, rate: u64, seconds: u64, clients: usize) -> RunResult {
    let total: u64 = rate * seconds;

    // Scale the client count down to the offered load. With a fixed 16 clients, a
    // low rate breaks the schedule: at 1 rps for 5s the total is 5 requests, so
    // `total / 16` truncates to 0, gets clamped to 1, and 16 requests are actually
    // sent — offering 3.2× the requested rate and reporting it as "1 rps". Capping
    // clients at `total` keeps offered == requested at every rate.
    //
    // This also matches how low rates arise in practice: 1 rps is one caller acting
    // once a second, not sixteen callers idling.
    let clients = clients.min(total.max(1) as usize);
    let per_client = (total / clients as u64).max(1);
    let interval = Duration::from_secs_f64(clients as f64 / rate as f64);

    let events = event_stream((per_client as usize).max(2), SESSIONS, SERVERS, LOGIN_EVERY);

    let errors = Arc::new(AtomicU64::new(0));
    let start = Instant::now() + Duration::from_millis(100);
    let mut threads = Vec::with_capacity(clients);

    for c in 0..clients {
        let socket = server.paths.data_socket();
        let events = events.clone();
        let errors = Arc::clone(&errors);
        // Stagger client phases so all N do not fire on the same instant.
        let offset = interval.mul_f64(c as f64 / clients as f64);
        threads.push(std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&socket).expect("client connects");
            let mut samples: Vec<f64> = Vec::with_capacity(per_client as usize);

            for i in 0..per_client {
                let scheduled = start + offset + interval.mul_f64(i as f64);
                let now = Instant::now();
                if scheduled > now {
                    std::thread::sleep(scheduled - now);
                }
                let event = &events[i as usize % events.len()];
                let request = DataRequest::Submit {
                    event: to_wire(event),
                };
                // Latency from the SCHEDULED start, so queueing counts.
                let ok = round_trip(&mut stream, &request);
                let elapsed = scheduled.elapsed().as_secs_f64() * 1000.0;
                if ok {
                    samples.push(elapsed);
                } else {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            samples
        }));
    }

    let mut samples: Vec<f64> = Vec::new();
    for t in threads {
        samples.extend(t.join().expect("client thread"));
    }
    let wall = start.elapsed().as_secs_f64();

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    // A quantile is only reportable if its nearest-rank index falls strictly
    // below the last sample. With few samples `round((n-1) * 0.99)` lands ON the
    // last one, so the "p99" would just be the maximum re-printed under a name
    // that implies a tail estimate — at 1 rps for 5s there are 5 samples and
    // p90, p99 and max are all the same number. Reporting `None` there keeps the
    // table honest about what it does and does not know.
    let pick = |q: f64| -> Option<f64> {
        let n = samples.len();
        if n == 0 {
            return None;
        }
        let idx = ((n as f64 - 1.0) * q).round() as usize;
        (idx + 1 < n).then(|| samples[idx])
    };

    RunResult {
        achieved: samples.len() as f64 / wall.max(f64::EPSILON),
        p50: pick(0.50),
        p90: pick(0.90),
        p99: pick(0.99),
        max: samples.last().copied().unwrap_or(f64::NAN),
        errors: errors.load(Ordering::Relaxed),
    }
}

/// One framed request/response on a persistent connection. Returns whether the
/// server answered with a verdict or an ack (an `Error` response counts as a
/// failure, since it means the request was not served).
fn round_trip<S: Read + Write>(stream: &mut S, request: &DataRequest) -> bool {
    if write_frame(stream, request).is_err() {
        return false;
    }
    matches!(
        read_frame::<_, DataResponse>(stream),
        Ok(DataResponse::Decision { .. }) | Ok(DataResponse::Recorded { .. })
    )
}
