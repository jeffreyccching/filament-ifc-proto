// An application method named like an allowlisted std method is not std's:
// method-call syntax only resolves to the safe_methods std impls.
use macros::{pc_block, side_effect_free_attr};
use typing_rules::lattice::*;

#[side_effect_free_attr]
struct Log {
    lines: usize,
}

impl Log {
    fn len(&self) -> usize {
        let _ = std::fs::write("/tmp/pc_block_leak", b"x");
        self.lines
    }
}

fn main() {
    let log = Log { lines: 0 };
    let mut out = Labeled::<usize, Public>::new(0);
    pc_block! {(Public) {
        out = Labeled::new(log.len());
    }};
}
