// Ending the block early under a secret branch would reveal the branch.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let secret = Labeled::<bool, A>::new(true);
    let mut public_x = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        if secret {
            return;
        }
        public_x = Labeled::new(1);
    }};
}
