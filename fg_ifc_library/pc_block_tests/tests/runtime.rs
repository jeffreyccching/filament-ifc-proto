//! Programs `pc_block!` must accept, and its run-time behavior.

use macros::{pc_block, side_effect_free_attr};
use std::collections::HashMap;
use typing_rules::lattice::*;

#[side_effect_free_attr]
fn safe_add(x: i32, y: i32) -> Labeled<i32, Public> {
    Labeled::new(x + y)
}

/// The paper's running example (Cocoon Fig. 2).
#[test]
fn calendar_overlap() {
    let alice: HashMap<&str, Labeled<bool, A>> = HashMap::from([("Mon", Labeled::new(true)), ("Tue", Labeled::new(false))]);
    let bob: HashMap<&str, Labeled<bool, B>> = HashMap::from([("Mon", Labeled::new(true)), ("Tue", Labeled::new(true))]);
    let mut count = Labeled::<i32, AB>::new(0);
    for (day, available) in &alice {
        let bob_avail = bob.get(day).unwrap();
        pc_block! {(AB) {
            if *available && *bob_avail {
                count = count + 1;
            }
        }};
    }
    assert_eq!(declassify(count), 1);
}

/// Unlabeled locals may be mutated while the PC is Public.
#[test]
fn raw_locals_under_public_pc() {
    let mut out = Labeled::<usize, Public>::new(0);
    pc_block! {(Public) {
        let mut v = ::std::vec::Vec::new();
        v.push(1u8);
        v.push(2u8);
        let mut i = 0;
        while i < 3 {
            i += 1;
        }
        out = Labeled::new(v.len() + i);
    }};
    assert_eq!(declassify(out), 5);
}

/// Writes inside a secret branch are allowed to targets at least as secret.
#[test]
fn labeled_writes_follow_pc() {
    let secret = Labeled::<bool, A>::new(true);
    let mut total = Labeled::<i32, A>::new(1);
    pc_block! {(Public) {
        if secret {
            total += 5;
        }
    }};
    assert_eq!(declassify(total), 6);
}

/// `#[side_effect_free_attr]` callees are allowed; a branch value carries the
/// condition's label.
#[test]
fn vetted_call_and_branch_value() {
    let a = Labeled::<i32, A>::new(7);
    let b = Labeled::<i32, A>::new(35);
    let flag = Labeled::<bool, A>::new(false);
    let mut total = Labeled::<i32, A>::new(0);
    pc_block! {(A) {
        let sum = safe_add(a, b);
        let picked = if flag { Labeled::<i32, A>::new(1) } else { sum };
        total = picked;
    }};
    assert_eq!(declassify(total), 42);
}

#[side_effect_free_attr]
fn double(x: i32) -> Labeled<i32, Public> {
    safe_add(x, x)
}

/// A tagged function calls another as `f(x)`; outside pc_block a tagged
/// function is called with `unsafe`, as in Cocoon.
#[test]
fn tagged_calls_tagged() {
    assert_eq!(declassify(unsafe { double(21) }.unwrap()), 42);
    let a = Labeled::<i32, A>::new(4);
    let mut total = Labeled::<i32, A>::new(0);
    pc_block! {(A) {
        total = double(a);
    }};
    assert_eq!(declassify(total), 8);
}

/// `if let` on a labeled scrutinee raises the PC to the scrutinee's label.
#[test]
fn if_let_on_labeled_option() {
    let maybe = Labeled::<Option<i32>, A>::new(Some(9));
    let mut total = Labeled::<i32, A>::new(0);
    pc_block! {(Public) {
        if let Some(v) = maybe {
            total = Labeled::new(v);
        }
    }};
    assert_eq!(declassify(total), 9);
}

/// A panic inside pc_block! aborts the process: recovering would let the
/// program observe that the block stopped early, possibly because of a
/// secret. Runs the block in a child process.
#[test]
fn panic_inside_block_aborts() {
    if std::env::var_os("PC_BLOCK_PANIC_CHILD").is_some() {
        let secret = Labeled::<bool, A>::new(true);
        let v: Vec<i32> = Vec::new();
        let mut out = Labeled::<i32, A>::new(0);
        pc_block! {(A) {
            if secret {
                out = Labeled::new(*v.get(3).unwrap());
            }
        }};
        let _ = out;
        return;
    }

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "panic_inside_block_aborts", "--nocapture", "--test-threads=1"])
        .env("PC_BLOCK_PANIC_CHILD", "1")
        .status()
        .unwrap();
    assert!(!status.success());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6), "expected SIGABRT, got {status:?}");
    }
}

/// The panic hook is installed process-wide and gated on a thread-local flag,
/// so it must stay invisible outside `pc_block!`: a panic *after* a block has
/// run, and its guard dropped, must still print its message. Guards against silencing the whole program by accident.
#[test]
fn panic_outside_block_still_reports() {
    if std::env::var_os("PC_BLOCK_OUTSIDE_CHILD").is_some() {
        let secret = Labeled::<bool, A>::new(true);
        let mut out = Labeled::<i32, A>::new(0);
        // Run a block first so the hook is definitely installed, and the
        // guard has been dropped, before the panic below.
        pc_block! {(A) {
            if secret {
                out = Labeled::new(1);
            }
        }};
        let _ = out;
        panic!("this message must be visible");
    }

    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "panic_outside_block_still_reports", "--nocapture", "--test-threads=1"])
        .env("PC_BLOCK_OUTSIDE_CHILD", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("this message must be visible"),
        "panic outside pc_block! was silenced; stderr was: {stderr}"
    );
}

/// `%`, `<<`, `>>`, `|` and the compound bit/shift assigns work on std types
/// inside a `pc_block!`, on both labeled and raw operands, and join labels.
#[test]
fn extra_operators_in_block() {
    let a = Labeled::<i32, A>::new(17);
    let b = Labeled::<i32, B>::new(5);
    let mut rem: Labeled<i32, AB> = Labeled::new(0);
    let mut shifted: Labeled<i32, A> = Labeled::new(0);
    let mut flags: Labeled<i32, A> = Labeled::new(0b1000);

    // PC = AB here, so only AB-labeled targets may be written.
    pc_block! {(AB) {
        rem = a % b;              // label join: A ⊔ B = AB
    }};
    // A-labeled targets need a PC of A.
    pc_block! {(A) {
        shifted = a << 2;         // labeled << raw, label preserved
        flags |= 0b0001;          // compound bit-assign
        flags ^= 0b1000;
        flags &= 0b1111;
    }};

    assert_eq!(declassify(rem), 17 % 5);
    assert_eq!(declassify(shifted), 17 << 2);
    assert_eq!(declassify(flags), 0b0001);
}

#[side_effect_free_attr]
fn mix(x: i32, y: i32) -> Labeled<i32, Public> {
    // the same operators must work in a #[side_effect_free_attr] body, on raw types
    let mut acc = x % y;
    acc |= 1;
    acc <<= 1;
    Labeled::new(acc >> 1 | (x & y) ^ 0)
}

/// The second macro has its own operator table; make sure it was wired too.
#[test]
fn extra_operators_in_sef_function() {
    let x = Labeled::<i32, A>::new(17);
    let mut out = Labeled::<i32, A>::new(0);
    pc_block! {(A) {
        out = mix(x, 5);
    }};
    let expected = { let mut acc = 17 % 5; acc |= 1; acc <<= 1; acc >> 1 | (17 & 5) ^ 0 };
    assert_eq!(declassify(out), expected);
}
