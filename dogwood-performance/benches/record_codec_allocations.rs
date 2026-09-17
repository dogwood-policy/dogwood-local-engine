//! Allocation companion to the `record_codec` Criterion benchmark.
//!
//! Kept in a separate executable because a counting global allocator adds work
//! to every allocation and would otherwise perturb the latency comparison.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use dogwood_local_engine::Record;

#[allow(dead_code)]
#[path = "support/record_codec_cases.rs"]
mod record_codec_cases;

use record_codec_cases::{CodecCase, cases};

const ITERATIONS: u64 = 100;

static ALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static REALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: this wrapper forwards the allocator contract unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: this wrapper forwards the allocator contract unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: this wrapper forwards the allocator contract unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        // SAFETY: this wrapper forwards the allocator contract unchanged.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

fn reset_counters() {
    ALLOCATION_CALLS.store(0, Ordering::Relaxed);
    REALLOCATION_CALLS.store(0, Ordering::Relaxed);
    REQUESTED_BYTES.store(0, Ordering::Relaxed);
}

fn report(case: &CodecCase) {
    black_box(Record::decode(&case.encoded).expect("benchmark record decodes"));
    reset_counters();
    for _ in 0..ITERATIONS {
        black_box(Record::decode(black_box(&case.encoded)).expect("benchmark record decodes"));
    }
    let allocations = ALLOCATION_CALLS.load(Ordering::Relaxed);
    let reallocations = REALLOCATION_CALLS.load(Ordering::Relaxed);
    let bytes = REQUESTED_BYTES.load(Ordering::Relaxed);
    println!(
        "{:<32} {:>6.2} alloc {:>5.2} realloc {:>10.1} B",
        case.name,
        allocations as f64 / ITERATIONS as f64,
        reallocations as f64 / ITERATIONS as f64,
        bytes as f64 / ITERATIONS as f64,
    );
}

fn main() {
    println!(
        "record codec allocations: calls and requested bytes per decode \
         (average of {ITERATIONS})"
    );
    for case in cases() {
        report(&case);
    }
}
