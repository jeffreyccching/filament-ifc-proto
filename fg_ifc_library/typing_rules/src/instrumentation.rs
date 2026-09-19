//! Zeroize instrumentation. Cheap (atomic counters + one `Instant::now` per
//! drop) and unconditional per-event logging — every recorded zeroize event
//! prints a `[zeroize] <tag>: N ns / cumulative=M ns` line on stderr.
//!
//! Public API:
//!   - `record_zeroize(f)` — wrapper used by the `Drop` / `Zeroize` impls.
//!     Times `f`, accumulates into the atomics, and prints the line.
//!   - `zeroize_total_ns()` / `zeroize_count()` — read accumulated stats.
//!   - `zeroize_reset()` — zero the counters (handy for benchmarks).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Total nanoseconds spent inside `zeroize` calls across the whole process.
pub static ZEROIZE_TOTAL_NS: AtomicU64 = AtomicU64::new(0);

/// Number of `zeroize` invocations recorded so far.
pub static ZEROIZE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Time `f` (which is expected to perform a zeroization), update the
/// global counters, and print a per-event line on stderr. The `tag` is a
/// short label printed in the log so call sites are distinguishable.
pub fn record_zeroize<F: FnOnce()>(tag: &'static str, f: F) {
    let start = Instant::now();
    f();
    let ns = start.elapsed().as_nanos() as u64;
    let cumulative = ZEROIZE_TOTAL_NS.fetch_add(ns, Ordering::Relaxed) + ns;
    ZEROIZE_COUNT.fetch_add(1, Ordering::Relaxed);
    eprintln!("[zeroize] {tag}: {ns} ns (cumulative {cumulative} ns)");
}

/// Total nanoseconds spent zeroizing since process start (or last reset).
pub fn zeroize_total_ns() -> u64 {
    ZEROIZE_TOTAL_NS.load(Ordering::Relaxed)
}

/// Number of zeroize events since process start (or last reset).
pub fn zeroize_count() -> u64 {
    ZEROIZE_COUNT.load(Ordering::Relaxed)
}

/// Reset both counters to zero. Useful at the start of a benchmark.
pub fn zeroize_reset() {
    ZEROIZE_TOTAL_NS.store(0, Ordering::Relaxed);
    ZEROIZE_COUNT.store(0, Ordering::Relaxed);
}
