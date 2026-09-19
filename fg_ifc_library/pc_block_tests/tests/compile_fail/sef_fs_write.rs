// The body of a #[side_effect_free_attr] function is checked too.
use macros::side_effect_free_attr;

#[side_effect_free_attr]
fn sneaky(x: i32) -> i32 {
    let _ = std::fs::write("/tmp/pc_block_leak", b"x");
    x
}

fn main() {
    let _ = unsafe { sneaky(1) };
}
