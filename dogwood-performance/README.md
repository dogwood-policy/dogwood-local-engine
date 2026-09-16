# dogwood-performance

Benchmark harness comparing Dogwood's engine implementations. Currently: the
**in-memory reference** (`InMemoryTemporalEngine`, the correctness oracle) against
the **durable server** (`dogwood-server`), across policy count (10 / 100 / 1000 /
10 000), session pinning (on / off, by predicate shape), and concurrent request rate
(1 → 500 rps).

> **Looking for the numbers and what they mean?** See **[RESULTS.md](RESULTS.md)** —
> the findings, with the caveats and known confounds spelled out. This file is the
> harness: how to run it and why each benchmark is built the way it is.

## Running it

```text
# Sequential per-decision latency (criterion). ~25 min including 10 000 policies.
cargo bench -p dogwood-performance --bench decide_latency

# Does pinning help? Sweeps balanced session count against predicate shape.
cargo bench -p dogwood-performance --bench pinning_sessions

# Policy installation cost: lower / validate / prepare monitors.
cargo bench -p dogwood-performance --bench install_policies

# Snapshot decode/restore latency through 65,536 retained records.
cargo bench -p dogwood-performance --bench snapshot_restore

# Compare a decoder change against a saved Criterion baseline.
cargo bench -p dogwood-performance --bench snapshot_restore -- \
    --save-baseline before
cargo bench -p dogwood-performance --bench snapshot_restore -- \
    --baseline before

# Open-loop concurrency: offer a fixed rate, report the latency distribution.
cargo run --release -p dogwood-performance --bin load -- \
    --policies 10,100,1000 --rates 1,10,100,500 --seconds 5 --clients 16
```

The load harness scales its client count down to the offered rate, so low rates are
honest: at 1 rps it uses one client, because a fixed pool of 16 would each have to
send at least one request and would silently offer 16× the requested load.

## Read this before reading any number

**The two implementations do different amounts of work by design.** A naive
"which is faster" reading is wrong in both directions:

- The **server `fsync`s every event before answering.** Its per-event latency
  cannot go below the storage floor no matter what the engine does. Every harness
  measures and prints that floor so it can be subtracted.
- The **reference is not durable at all**, and rescans history at each decision. It
  wins on small workloads for a reason that does not survive a restart, and loses
  on large ones for an algorithmic reason that *is* a genuine finding.

So: comparisons **within** an implementation across an axis are directly
meaningful. Comparisons **across** implementations are only meaningful once the
durability floor is accounted for.

## Results (16-core Xeon 8259CL @ 2.50GHz, NVMe/ext4, load ~0.2)

Machine-specific; re-run before trusting these. **Durability floor measured at
1.18 ms per fsync'd append → ~845 events/s single-instance ceiling.**

### Per-decision latency (200 events of history)

| policies | reference | server | ratio |
|---|---|---|---|
| 10 | **0.30 ms** | 1.23 ms | reference 4.1× |
| 100 | 2.30 ms | **1.70 ms** | server 1.4× |
| 1000 | 22.3 ms | **6.45 ms** | server 3.5× |
| 10 000 | 233 ms | **72.4 ms** | server 3.2× |

Three findings:

1. **The crossover is between 10 and 100 policies.** Below it the reference is
   faster only because it does not persist anything: at 10 policies the gap
   (0.93 ms) is essentially exactly the measured fsync floor (1.18 ms), i.e. the
   engines' *compute* is comparable and storage is the whole difference.
2. **Above the crossover the server wins on algorithm, not despite it.** The
   reference grows ~780× across the range (0.30 → 233 ms) for 1000× the policies —
   it rescans history per leaf. The server grows ~59× (1.23 → 72.4 ms) and is
   3–3.5× faster from 1000 policies up, *while also* doing a durable write the
   reference never does.
3. **At 10 000 policies, evaluation dominates storage completely.** The server's
   72 ms is ~61× the 1.18 ms fsync floor, so durability has become a rounding error
   and the two engines are being compared on evaluation alone. The server's lead
   holding at 3.2× there is the cleanest evidence that incremental beats rescan.

### Pinning: it depends entirely on predicate shape

The first version of this harness reported "pinning has no measurable effect". That
was true for the policies being benchmarked and **wrong as a general claim** — the
workload had accidentally made the pin redundant. Sweeping predicate shape against
session count (`benches/pinning_sessions.rs`) shows the real picture:

| balanced sessions | broad: unpinned | broad: pinned | speedup |
|---|---|---|---|
| 1 | 4.57 ms | 5.22 ms | **0.88×** (slower) |
| 2 | 4.62 ms | 3.46 ms | 1.34× |
| 4 | 4.54 ms | 2.34 ms | 1.94× |
| 8 | 4.57 ms | 1.91 ms | 2.40× |
| 16 | 4.51 ms | 1.74 ms | 2.60× |
| 32 | 4.62 ms | 1.62 ms | **2.84×** |

Against **selective** predicates, by contrast, pinning is flat at every session
count (~0.92–0.95 ms either way).

The mechanism: a pin filters other sessions' events out of a `formerly` scan, which
only saves work if those rows would otherwise be examined.

- A **selective** predicate (`Login{ input.user: "blocked7" }`) already rejects
  nearly every history row on the literal alone. The pin removes rows that were
  being rejected anyway — pure overhead, no benefit.
- A **broad** predicate (`count … Login{ input.user: _, input.server: _ }`) scans
  *all* logins, so the pin is the only thing confining it.

Two details in that table are worth reading deliberately. At **one session** the pin
is measurably *slower* (0.88×) — nothing to filter, so only its cost remains, which
is the clearest confirmation that the win is filtering and not an artifact. And the
growth is **sub-linear**: 32 sessions give 2.84×, not 32×, because filtering removes
candidate rows but not the per-timepoint walk over the retained window. There is a
floor no amount of filtering removes.

So pinning is worth up to ~2.8× on scan-heavy policies with many concurrent
sessions, and is a small tax on already-selective ones. Its non-performance value
is unchanged and arguably larger: an unforgeable correlation, and the property that
makes the stream partitionable at all (`DESIGN.md` §3.3).

### Policy installation (what `policy apply` costs)

| policies | generate source | lower | server apply (lower + validate + prepare + persist) |
|---|---|---|---|
| 10 | 1.4 µs | 2.14 ms | **29.3 ms** |
| 100 | 11.4 µs | 7.31 ms | **40.4 ms** |
| 1000 | 105.9 µs | 58.6 ms | **160 ms** |
| 10 000 | ~1.1 ms | 633 ms | **1.77 s** |

Pinning makes no difference here either (within ~1%). Two observations:

- **Sub-linear at small sizes, super-linear at large ones.** 10 → 100 policies
  (10×) costs only 1.38× (29 → 40 ms), because a per-apply floor of roughly 27 ms —
  validator construction and the durable bundle write — is most of what 10 policies
  pay. But that floor is *not* the whole story at scale: subtracting lowering leaves
  27 → 33 → 102 → 1134 ms, so the non-lowering work grows ~42× across the range
  rather than staying constant. By 1000 → 10 000 the total is growing faster than
  linearly (11.0× for 10×), which points at Cedar validation rather than a fixed
  cost.
- **Lowering is not the bottleneck; the server's extra work is.** At 10 policies,
  lowering is 2.1 ms of a 29.3 ms apply; at 10 000 it is 633 ms of 1.77 s. The
  remainder is Cedar validation plus monitor preparation throughout.

160 ms for a 1000-policy swap is comfortably interactive. **1.77 s for 10 000 is
not** — an operator would notice it, and since `apply` validates and swaps
synchronously, that is a real (if tolerable) pause. Worth knowing before anyone
plans a policy set that large.

### Concurrency (5s runs, latency from scheduled start, unpinned)

Rates span the realistic operating region (1–100 rps) and the saturation region
(500 rps), because they answer different questions.

| policies | offered | achieved | p50 | p99 | verdict |
|---|---|---|---|---|---|
| 10 | 1 | 1 | 1.63 ms | 3.73 ms | idle |
| 10 | 10 | 10 | 1.55 ms | 3.79 ms | healthy |
| 10 | 100 | 100 | 1.48 ms | 3.53 ms | healthy |
| 10 | 500 | 500 | 4.00 ms | 10.7 ms | at capacity |
| 100 | 1 | 1 | 2.11 ms | 2.32 ms | idle |
| 100 | 10 | 10 | 2.04 ms | 4.88 ms | healthy |
| 100 | 100 | 100 | 2.21 ms | 4.48 ms | healthy |
| 100 | 500 | **246** | 1653 ms | 5051 ms | **saturated** |
| 1000 | 1 | 1 | 5.44 ms | 7.08 ms | idle |
| 1000 | 10 | 10 | 5.77 ms | 8.21 ms | healthy |
| 1000 | 100 | **97** | 9.08 ms | 171 ms | **at the edge** |
| 1000 | 500 | **35** | 22 825 ms | 64 679 ms | **collapsed** |

**The realistic region is comfortable.** At 1–100 rps with up to 1000 policies, p50
is 1.5–9 ms and p99 stays in single-digit-to-low-double-digit milliseconds. For an
agent making a decision per action, that is not a bottleneck.

**Capacity is set by evaluation, not by the fsync ceiling.** The floor predicts
~835 rps, but actual capacity falls well below it and *drops with policy count*: 10
policies sustain 500 rps, 100 policies saturate before it (246 of 500), and 1000
policies are already at the edge at 100 rps (97 achieved, p99 jumping to 171 ms).
The floor is a ceiling you never reach, not a forecast.

**The cliff is worth seeing.** Below capacity, latency is flat and achieved ≈
offered. Above it, achieved throughput *falls* while latency grows into seconds —
the classic queueing signature, and the reason the harness is open-loop (a closed
loop would have quietly throttled itself and reported healthy latency at 500 rps).

Pinning changes none of this materially on the selective workload the load test
uses, consistent with the pinning results above.

### If you need more throughput

Three levers, in the order they are likely to pay:

1. **Fewer or cheaper policies.** Capacity tracks evaluation cost, and the 1000 →
   100 → 10 progression above shows how directly.
2. **Pinning, on scan-heavy policies with many sessions** — up to ~2.8× per the
   sweep above.
3. **Pin-sharded instances** (`DESIGN.md` §3.3). This is the only lever that moves
   the fsync ceiling itself, since each partition gets its own log and therefore its
   own append point. The routing layer exists; running N instances does not yet.

**Group-commit is the untested fourth.** Batching the fsync across concurrent
submits would raise the storage ceiling without sharding, and §10 anticipated it,
but it is not implemented — so its value here is a hypothesis, not a number.

## Design notes

**Why the concurrency harness is not criterion.** Criterion runs a *closed* loop:
it never issues request N+1 until N returns, so when the server slows it silently
reduces its own offered rate and reports a comfortable latency — never revealing
the cliff above. An open-loop test must hold an offered rate independently of
service time. Latency is measured from each request's **scheduled** start, not its
actual send, so queueing delay is counted (avoiding *coordinated omission*, the
standard way load tests flatter a struggling system).

**Why the reference is not load-tested.** It is a single-threaded, non-durable,
in-process library with no concurrency story. "The reference at 500 rps" would
measure a mutex the harness itself added.

**Guards against measuring nothing.** Benchmarking is unusually easy to get
silently wrong, so the harness asserts its own workload is sound before timing
anything. Three real bugs these caught while building it:

- The first policy generator used a *literal* server (`Login{ input.server: "s0" }`),
  uncorrelated with the request — so once any matching login occurred, every
  subsequent decision denied forever. **0 allows of 60 decisions.**
- After correlating it, the event generator assigned servers `s{i % 50}` with a
  login every 5 events. Since 5 divides 50, login servers were exactly the
  multiples of 5 and read servers exactly the non-multiples — disjoint sets, so no
  read could ever match a login. **0 denies of 160 decisions**, the mirror failure.
  Fixed by making the server pool coprime to the login interval (49).
- The probe event was taken as the stream's last element, which landed on a
  multiple of the login interval — a history-only event yielding no verdict, so the
  "decision latency" benchmark would have measured the append path.

The harness now asserts: both engines agree on which events decide and on the
allow count; the verdict mix is genuinely mixed; the probe decides; and the
"pinned" variant really registers a partition key (`ShardPlan::Sharded`) rather
than silently degrading to unpinned.
