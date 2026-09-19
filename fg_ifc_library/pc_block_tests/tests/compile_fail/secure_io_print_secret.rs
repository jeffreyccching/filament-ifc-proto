// Console output is Public-only: printing an A-labeled value is rejected.
use typing_rules::lattice::*;
use typing_rules::secure_io::secure_println;

fn main() {
    let secret = Labeled::<String, A>::new("hunter2".to_string());
    secure_println(&secret);
}
