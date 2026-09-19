// The classic implicit flow: writing a Public value inside a secret branch.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let secret = Labeled::<bool, B>::new(true);
    let mut leaked = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        if secret {
            leaked = Labeled::<i32, Public>::new(1);
        }
    }};
}
