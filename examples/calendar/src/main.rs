use macros::*;
use std::collections::HashMap;
use typing_rules::*;

fn main() {
    
    example_secure();
}

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
    
}

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

}
