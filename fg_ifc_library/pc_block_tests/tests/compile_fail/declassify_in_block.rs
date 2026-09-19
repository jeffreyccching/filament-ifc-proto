// Laundering a write to a Public value through declassify_ref_mut() under a
// secret branch.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let secret = Labeled::<bool, A>::new(true);
    let mut public_v = Labeled::<Vec<i32>, Public>::new(Vec::new());
    pc_block! {(Public) {
        if secret {
            public_v.declassify_ref_mut().push(1);
        }
    }};
}
