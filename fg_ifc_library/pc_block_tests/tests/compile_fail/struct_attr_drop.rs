// #[side_effect_free_attr] on a type with a custom Drop is rejected.
use macros::side_effect_free_attr;

#[side_effect_free_attr]
struct Handle {
    fd: i32,
}

impl Drop for Handle {
    fn drop(&mut self) {}
}

fn main() {
    let _h = Handle { fd: 3 };
}
