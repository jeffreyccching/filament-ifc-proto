// Writing a static (not captured by the block's closure) through a method.
use macros::pc_block;
use std::sync::atomic::{AtomicBool, Ordering};
use typing_rules::lattice::*;

static SEEN: AtomicBool = AtomicBool::new(false);

fn main() {
    let secret = Labeled::<bool, A>::new(true);
    pc_block! {(Public) {
        if secret {
            SEEN.store(true, Ordering::SeqCst);
        }
    }};
}
