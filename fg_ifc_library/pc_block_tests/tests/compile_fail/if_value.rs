// The value of an `if` on a secret leaves the branch; as a raw value it
// would carry the secret without a label.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let secret = Labeled::<bool, A>::new(true);
    let mut public_x = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        let t = if secret { 1 } else { 0 };
        public_x = Labeled::new(t);
    }};
}
