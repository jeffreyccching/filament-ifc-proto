use macros::*;
use std::collections::HashMap;
use typing_rules::*;

fn main() {
    // Insecure
    // example_insecure();

    // Secure
    example_secure();
}

// fn overlap_insecure(map1: &HashMap<String, bool>, map2: &HashMap<String, bool>) -> i32 {
//     let mut count = 0;
//     for (day, available) in map1 {
//         if *available && *map2.get(day).unwrap() {
//             count += 1;
//         }
//     }
//     count
// }

fn overlap_secure(cal1: &HashMap<String, Labeled<bool, A>>, cal2: &HashMap<String, Labeled<bool, B>>) -> Labeled<i32, AB> {
    let mut count = Labeled::<i32, AB>::new(0);
    for (day, available) in cal1 {
        if let Some(bob_avail) = cal2.get(day) {
            pc_block! {(AB) {
                    if *available && *bob_avail {
                        count = count + 1;
                    }
                }
            }
        };
    }
    count
}

// fn overlap_secure_alt(cal1: &HashMap<String, Labeled<bool, A>>, cal2: &HashMap<String, Labeled<bool, B>>) -> Labeled<i32, AB> {
//     let mut count = Labeled::<i32, AB>::new(0);
//     for (day, available) in cal1 {
//         if let Some(bob_avail) = cal2.get(day) {
//             pc_block! {(AB) {
//                     if *available && *bob_avail {
//                         count = count + 1;
//                     }
//                 }
//             }
//         };
//     }
//     count
// }

fn example_insecure() {
    let alice_cal = HashMap::from([
        (String::from("Monday"), true),
        (String::from("Tuesday"), false),
        (String::from("Wednesday"), true),
        (String::from("Thursday"), false),
    ]);
    let bob_cal = HashMap::from([
        (String::from("Monday"), true),
        (String::from("Tuesday"), true),
        (String::from("Wednesday"), true),
        (String::from("Thursday"), false),
    ]);
    // let count = overlap_insecure(&alice_cal, &bob_cal);
    // println!("Overlapping days: {}", count);
}

// =========================================================================
// IMPLICIT FLOW LEAK — Cocoon vs pc_block!
// =========================================================================
//
// Cocoon's secret_block! only tracks EXPLICIT flows (label on the data).
// It does NOT track the program counter (PC). So this attack compiles in cocoon:
//
//   let mut leaked = 0;                           // plain i32, no label
//   secret_block!(Label_AB {
//       if *unwrap_secret_ref(bob_cal.get("Monday").unwrap()) {
//           *&mut leaked = 1;                     // write to public var inside secret branch
//       }
//   });
//   println!("Bob available Monday: {}", leaked); // secret is out!
//
// The branch depends on Bob's secret, but cocoon lets you write to `leaked`
// because it's not a Secret<_, _> — cocoon only guards wrap/unwrap, not
// assignments to non-secret variables inside a secret-dependent branch.
//
// Our pc_block! catches this. Uncomment the function below to see the
// compile error: PC(B) does not FlowsTo Public.

// fn implicit_flow_leak(bob_cal: &HashMap<String, Labeled<bool, B>>) {
//     let mut leaked = Labeled::<i32, Public>::new(0);
//     pc_block! {(Public) {
//         if let Some(bob_avail) = bob_cal.get("Monday") {
//             if *bob_avail {
//                 // PC is now B (from branching on Labeled<bool, B>)
//                 // Assigning to Labeled<_, Public> requires PC FlowsTo Public
//                 // But B does NOT FlowsTo Public → COMPILE ERROR
//                 leaked = Labeled::<i32, Public>::new(1);
//             }
//         }
//     }};
//     println!("Leaked: {}", declassify(leaked));
// }

fn example_secure() {
    let alice_cal = HashMap::from([
        (String::from("Monday"), Labeled::<bool, A>::new(true)),
        (String::from("Tuesday"), Labeled::<bool, A>::new(false)),
        (String::from("Wednesday"), Labeled::<bool, A>::new(true)),
        (String::from("Thursday"), Labeled::<bool, A>::new(false)),
    ]);
    let bob_cal = HashMap::from([
        (String::from("Monday"), Labeled::<bool, B>::new(true)),
        (String::from("Tuesday"), Labeled::<bool, B>::new(true)),
        (String::from("Wednesday"), Labeled::<bool, B>::new(true)),
        (String::from("Thursday"), Labeled::<bool, B>::new(false)),
    ]);

    let count: Labeled<i32, AB> = overlap_secure(&alice_cal, &bob_cal);
    println!("Available days: {}", declassify(count));

    // let count: Labeled<i32, AB> = overlap_secure_alt(&alice_cal, &bob_cal);
    // println!("Available days (alt): {}", declassify(count));
}
