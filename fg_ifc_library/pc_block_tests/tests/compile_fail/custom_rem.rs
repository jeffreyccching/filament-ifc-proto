// The newly supported operators must still reject application types, whose
// operator impls could have side effects. Mirrors custom_add.rs for `%`.
use macros::pc_block;
use typing_rules::lattice::*;

#[derive(Clone, Copy)]
struct Meter(i32);

impl std::ops::Rem for Meter {
    type Output = Meter;
    fn rem(self, other: Meter) -> Meter {
        let _ = std::fs::write("/tmp/pc_block_leak", b"x");
        Meter(self.0 % other.0)
    }
}

fn main() {
    let a = Meter(7);
    let b = Meter(3);
    let mut out = Labeled::<i32, Public>::new(0);
    pc_block! {(Public) {
        let c = a % b;
        out = Labeled::new(c.0);
    }};
}
