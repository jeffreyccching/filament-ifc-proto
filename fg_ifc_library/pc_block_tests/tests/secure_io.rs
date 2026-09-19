//! `secure_io` guarantees: reads carry the handle's label by signature, and
//! writes require `Src: LEQ<L>`. The rejection cases live in
//! `tests/compile_fail/secure_io_*.rs`.

use std::path::PathBuf;
use typing_rules::lattice::*;
use typing_rules::secure_io::SecureFile;

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("filament_secure_io_{}_{}", name, std::process::id()));
    p
}

/// Write a labeled value and read it back; the round trip preserves both the
/// contents and the label.
#[test]
fn file_round_trip_preserves_label() {
    let path = tmp("round_trip");
    let file = SecureFile::<A>::open(path.clone());

    let secret = Labeled::<String, A>::new("hunter2".to_string());
    file.write(&secret).expect("write failed");

    // The explicit annotation is the point of the test: if `read_to_string`
    // regressed to returning a raw String, this stops compiling.
    let read_back: Labeled<String, A> = file.read_to_string().expect("read failed");
    assert_eq!(declassify(read_back), "hunter2");

    let bytes: Labeled<Vec<u8>, A> = file.read().expect("read bytes failed");
    assert_eq!(declassify(bytes), b"hunter2".to_vec());

    let _ = std::fs::remove_file(&path);
}

/// Writing up the lattice is allowed: Public data may go to an A-labeled sink.
#[test]
fn write_up_is_allowed() {
    let path = tmp("write_up");
    let file = SecureFile::<A>::open(path.clone());

    let public = Labeled::<String, Public>::new("not a secret".to_string());
    file.write(&public).expect("write-up should be allowed");

    assert_eq!(declassify(file.read_to_string().unwrap()), "not a secret");
    let _ = std::fs::remove_file(&path);
}
