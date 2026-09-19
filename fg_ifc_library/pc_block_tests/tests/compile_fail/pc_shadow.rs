// User code cannot reset the PC by shadowing the macro's internal `__pc`.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let secret = Labeled::<bool, A>::new(true);
    let mut public_x = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        if secret {
            let __pc = ::typing_rules::lattice::Public;
            public_x = Labeled::new(1);
        }
    }};
}
