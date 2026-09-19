// A value with a custom Drop created in a secret branch: the destructor runs
// application code invisibly.
use macros::pc_block;
use typing_rules::lattice::*;

struct Loud;

impl Drop for Loud {
    fn drop(&mut self) {
        let _ = std::fs::write("/tmp/pc_block_leak", b"x");
    }
}

fn main() {
    let secret = Labeled::<bool, A>::new(true);
    pc_block! {(Public) {
        if secret {
            let _l = Loud {};
        }
    }};
}
