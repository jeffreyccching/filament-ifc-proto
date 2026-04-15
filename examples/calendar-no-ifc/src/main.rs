use std::collections::HashMap;

fn main() {
    example_insecure();
}

fn overlap_insecure(map1: &HashMap<String, bool>, map2: &HashMap<String, bool>) -> i32 {
    let mut count = 0;
    for (day, available) in map1 {
        if *available && *map2.get(day).unwrap() {
            count += 1;
        }
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
    let count = overlap_insecure(&alice_cal, &bob_cal);
    println!("Overlapping days: {}", count);
}
