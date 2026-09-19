// An application type's operator impl could have side effects.
use macros::pc_block;
use typing_rules::lattice::*;

#[derive(Clone, Copy)]
struct Meter(i32);

impl std::ops::Add for Meter {
    type Output = Meter;
    fn add(self, other: Meter) -> Meter {
        let _ = std::fs::write("/tmp/pc_block_leak", b"x");
        Meter(self.0 + other.0)
    }
}

fn main() {
    let a = Meter(1);
    let b = Meter(2);
    let mut out = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        let c = a + b;
        out = Labeled::new(c.0);
    }};
}
