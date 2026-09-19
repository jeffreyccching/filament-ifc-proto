// A callee receives unwrapped (secret) arguments; a `&mut` passed alongside
// them — even through a variable — would let it store the secret in a
// Public location.
use macros::{pc_block, side_effect_free_attr};
use typing_rules::lattice::*;

#[side_effect_free_attr]
fn stash(dst: &mut Labeled<i32, Public>, v: i32) -> Labeled<(), Public> {
    *dst = Labeled::new(v);
    Labeled::new(())
}

fn main() {
    let secret = Labeled::<i32, A>::new(42);
    let mut public_x = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        let r = &mut public_x;
        let _u = stash(r, secret);
    }};
}
