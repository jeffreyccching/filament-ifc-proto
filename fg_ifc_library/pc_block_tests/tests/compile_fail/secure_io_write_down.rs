// No-write-down: an A-labeled value may not be written to a Public file.
use std::path::PathBuf;
use typing_rules::lattice::*;
use typing_rules::secure_io::SecureFile;

fn main() {
    let public_file = SecureFile::<Public>::open(PathBuf::from("/tmp/pc_block_leak"));
    let secret = Labeled::<String, A>::new("hunter2".to_string());
    let _ = public_file.write(&secret);
}
