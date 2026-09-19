// A map lookup keyed by a labeled value returns a raw bool that reveals it.
use macros::pc_block;
use std::collections::HashMap;
use typing_rules::lattice::*;

fn main() {
    let key = Labeled::<u32, A>::new(7);
    let mut table: HashMap<Labeled<u32, A>, u32> = HashMap::new();
    table.insert(Labeled::new(7), 1);
    let mut found = Labeled::<bool, Public>::new(false);
    pc_block! {(Public) {
        if table.contains_key(&key) {
            found = Labeled::new(true);
        }
    }};
}
