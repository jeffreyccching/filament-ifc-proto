// Macro expansions cannot be checked, so macros are rejected.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let secret = Labeled::<bool, A>::new(true);
    pc_block! {(Public) {
        if secret {
            println!("taken");
        }
    }};
}
