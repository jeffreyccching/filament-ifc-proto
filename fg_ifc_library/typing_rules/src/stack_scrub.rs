//! Best-effort stack scrubbing for erasure-targeted call sites.
//!
//! `scrub_stack_best_effort` writes zeros over ~4 KB of stack memory
//! above current SP. The `ScrubPolicy` trait (defined here, impl'd in
//! `lattice.rs`) controls *whether* the scrub fires per call site,
//! dispatched at compile time on the label.
//!
//! Policy: only `T` (top of the lattice — the erasure target) triggers
//! a real scrub. Every other label is a `#[inline(always)]` no-op, so
//! the optimizer emits zero extra instructions at non-T call sites.
//!
//! Limitations:
//!   - Covers ~4 KB above SP; deeper callee frames are NOT reached.
//!   - Does NOT scrub registers.
//!   - Best effort — relies on `#[inline(never)]` placing this in its
//!     own frame and `black_box` defeating DCE.

const SCRUB_BYTES: usize = 4096;

/// Diagnostic counter — bumped on every scrub call. Used by benchmarks
/// to verify the scrub is firing.
pub static SCRUB_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Runtime toggle for the scrub body. Default `true` — flip to `false`
/// for A/B benchmarking without recompiling. Does NOT affect call
/// dispatch (the function is still called, just becomes a counter bump).
pub static SCRUB_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Write zeros over ~4 KB of stack memory above the current SP. Forced
/// into its own non-inlined frame so the buffer reuses the stack region
/// the just-returned-from caller was using. `black_box` keeps the write
/// alive against DCE.
#[doc(hidden)]
#[inline(never)]
pub fn scrub_stack_best_effort() {
    SCRUB_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if !SCRUB_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let mut scrub = [0u8; SCRUB_BYTES];
    scrub.fill(0);
    std::hint::black_box(&mut scrub);
}

/// Compile-time dispatch: should a scrub fire for this label?
///
/// Impl'd per label in `lattice.rs`. Only `T` calls
/// `scrub_stack_best_effort()`; every other label is a no-op.
pub trait ScrubPolicy {
    fn scrub();
}

/// Run `f`, then scrub unconditionally. User-facing scope helper for
/// wrapping whole regions that handled erasure-target data.
#[inline(never)]
pub fn clear_on_return<R, F: FnOnce() -> R>(f: F) -> R {
    let r = f();
    scrub_stack_best_effort();
    r
}
