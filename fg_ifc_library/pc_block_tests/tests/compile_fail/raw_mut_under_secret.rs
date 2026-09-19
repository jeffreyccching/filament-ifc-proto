// Mutating an unlabeled local under a secret PC: the local outlives the
// branch and its length would reveal the secret.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let secret = Labeled::<bool, A>::new(true);
    let mut n = Labeled::<usize, Public>::new(0);
    pc_block! {(Public) {
        let mut v = ::std::vec::Vec::new();
        if secret {
            v.push(1u8);
        }
        n = Labeled::new(v.len());
    }};
}
