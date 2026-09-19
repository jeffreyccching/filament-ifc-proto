// The block may not mutate an unlabeled variable from outside it (Cocoon's
// VisibleSideEffectFree capture rule).
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let mut count = 0;
    pc_block! {(Public) {
        count += 1;
    }};
    let _ = count;
}
