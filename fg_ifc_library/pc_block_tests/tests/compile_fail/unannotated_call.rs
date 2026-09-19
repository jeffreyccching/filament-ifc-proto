// A function without #[side_effect_free_attr] cannot be called inside
// pc_block!: it could do I/O while the PC is secret.
use macros::pc_block;
use typing_rules::lattice::*;

fn log_to_disk(_x: i32) -> Labeled<(), Public> {
    let _ = std::fs::write("/tmp/pc_block_leak", b"x");
    Labeled::new(())
}

fn main() {
    let secret = Labeled::<i32, A>::new(1);
    pc_block! {(A) {
        let _r = log_to_disk(secret);
    }};
}
