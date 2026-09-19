// There is no unchecked capture form: `pc_block!` has no trusted variant.
use macros::pc_block;
use typing_rules::lattice::*;

fn main() {
    let n = Labeled::<usize, A>::new(3);
    pc_block!((A)[n] {
        let _x = n;
    });
}
