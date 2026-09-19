// `if let` on a labeled scrutinee raises the PC to its label.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let secret = Labeled::<Option<i32>, A>::new(Some(1));
    let mut public_x = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        if let Some(_) = secret {
            public_x = Labeled::new(1);
        }
    }};
}
