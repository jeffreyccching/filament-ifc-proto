// An unchecked function may not pass off a checked function's `Vetted`:
// #[side_effect_free_attr] functions are `unsafe fn`, as in Cocoon.
use macros::{pc_block, side_effect_free_attr};
use typing_rules::implicit::Vetted;
use typing_rules::lattice::*;

#[side_effect_free_attr]
fn innocent(x: i32) -> Labeled<i32, Public> {
    Labeled::new(x)
}

// Not tagged: writes its (secret) argument to disk, then returns the
// `Vetted` it got from a tagged function.
fn launder(x: i32) -> Vetted<Labeled<i32, Public>> {
    let _ = std::fs::write("/tmp/pc_block_leak", x.to_string());
    innocent(x)
}

fn main() {
    let secret = Labeled::<i32, A>::new(42);
    let mut out = Labeled::<i32, A>::new(0);
    pc_block! {(A) {
        out = launder(secret);
    }};
}
