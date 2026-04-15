use std::sync::atomic::Ordering;

use macros::*;
use typing_rules::*;

pub fn bidding_game() {
    println!("Bidding Game");
    type OutputLabel = A;
    
    let output_label = DRLabel::<_, TrueB1, OutputLabel, OutputLabel>::new(());
    let bid1 = DRLabel::<i32, TrueB1, AB, A>::new(40);
    let bid2 = DRLabel::<i32, TrueB1, AB, A>::new(55);

    let _bid3 = DRLabel::<i32, TrueB1, AB, A>::new(100);

    let mut higher_bid = DRLabel::<i32, TrueB1, AB, A>::new(0);

    if bid1 > bid2 {
        bid1.assign_to(&mut higher_bid);
    } else {
        bid2.assign_to(&mut higher_bid);
    }
    
    eventoff(&mut higher_bid);
    
    eventon(&mut higher_bid);

    let conditions = GUARDS.lock().unwrap();
    let mut wbid = DRLabel::<i32, TrueB1, A, A>::new(0);

    let relabel_result = relabel!(higher_bid, &conditions, A, OutputLabel);
    relabel_result.assign_to(&mut wbid);

    let cloned_conditions = conditions.clone();
    drop(conditions);
    println!("wbid value: {}", wbid.cond());
    output_to(&wbid, &output_label, &cloned_conditions);
    println!("Bidding Game Finished\n");
}

pub fn credit_card() {
    println!("Credit Card Example");
    let card = DRLabel::<String, FalseB1, A, AB>::new("1234-5678-9012-3456".to_string());
    let mut copy = DRLabel::<String, FalseB1, A, AB>::new("".to_string());
    let shop_output = DRLabel::<_, FalseB1, A, A>::new(());
    card.assign_to(&mut copy);

    eventoff(&mut copy);
    
    println!("Credit Card value: {}", copy.cond());
    
    let conditions = GUARDS.lock().unwrap();
    let cloned_conditions = conditions.clone();
    std::mem::drop(conditions); 
    output_from(&copy, &shop_output, &cloned_conditions);
    println!("Credit Card Example Finished\n");
}

pub fn library() {
    println!("\nLibrary Example");
    let mut book = DRLabel::<_, FalseB1, A, AB>::new("Who are you?".to_string());
    let mut note = DRLabel::<_, FalseB1, A, AB>::new("".to_string());
    
    let output_to_alice = DRLabel::<_, FalseB1, A, A>::new(());
    
    eventoff(&mut book);
    eventoff(&mut note);
    book.assign_to(&mut note);
    
    let conditions = GUARDS.lock().unwrap();
    let cloned_conditions = conditions.clone();
    drop(conditions); 

    output_from(&note.clone(), &output_to_alice, &cloned_conditions);
    print!("Output-Per is:");
    output_per(OUTPUTTED.load(Ordering::SeqCst), &note);
    println!("Library Example Finished\n");
}

fn main() {
    bidding_game();
    credit_card();
    library();
}
