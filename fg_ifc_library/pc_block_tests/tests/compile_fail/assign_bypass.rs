// `x = f(Labeled::new(..))` used to skip the call check because the whole
// call was string-matched for "Labeled" and "new".
use macros::pc_block;
use typing_rules::lattice::*;

fn leak(x: i32) -> Labeled<i32, Public> {
    let _ = std::fs::write("/tmp/pc_block_leak", b"x");
    Labeled::new(x)
}

fn main() {
    let mut x = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        x = leak(Labeled::new(1));
    }};
}
