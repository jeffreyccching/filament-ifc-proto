use macros::relabel;
use typing_rules::dynamic_release::*;
use typing_rules::lattice::*;

fn main() {
    println!("=== 1. Simple Dynamic Label ===");
    simple_dynamic_label();

    println!("\n=== 2. Output Examples ===");
    output_examples();

    println!("\n=== 3. Relabel Examples ===");
    relabel_examples();

    println!("\n=== 4. Nested Dynamic Label (fire outer first) ===");
    nested_dynamic_label();

    println!("\n=== 5. Nested Dynamic Label (fire inner first, same label) ===");
    nested_inner_first();
}

fn simple_dynamic_label() {
    
    let mut secret: DRLabel<i32, TrueB1, A, AB> = DRLabel::new(42);
    println!("Created DRLabel<i32, TrueB1, A, AB> with value 42");

    eventon(&mut secret);
    println!("Event fired: label now at AB");

    let mut target: DRLabel<i32, TrueB1, AB, AB> = DRLabel::new(0);
    secret.assign_to(&mut target);
    println!("Assigned to AB target: {:?}", target.declassify_ref());

    eventoff(&mut secret);
    println!("Event turned off");
}

fn output_examples() {
    let mut data: DRLabel<i32, TrueB1, A, AB> = DRLabel::new(100);

    let out_ab: DRLabel<(), TrueB1, AB, AB> = DRLabel::new(());

    let guards_before = GUARDS.lock().unwrap().clone();
    output_to(&data, &out_ab, &guards_before);
    println!("  output_from succeeded (A ≤ AB, event not fired)");

    eventon(&mut data);
    let guards_after = GUARDS.lock().unwrap().clone();
    output_to(&data, &out_ab, &guards_after);
    println!("  output_to succeeded (AB ≤ AB, event fired)");

    eventoff(&mut data);
}

fn relabel_examples() {
    let mut data: DRLabel<i32, TrueB1, A, AB> = DRLabel::new(77);

    eventon(&mut data);
    let guards = GUARDS.lock().unwrap().clone();

    let relabeled = relabel!(data, &guards, AB, AB);
    println!("Relabeled value: {:?}", relabeled.declassify_ref());

    let public_val = Labeled::<i32, Public>::new(10);
    let upgraded: Labeled<i32, A> = relabel!(public_val, A);
    println!("Static relabel Public → A: {:?}", upgraded.declassify_ref());
}

fn nested_dynamic_label() {
    
    type Ev1 = TrueB1; 
    type Ev2 = TrueB1; 

    let mut doc: DRLabel<String, Ev1, DRLabel<(), Ev2, AB, A>, Public> = DRLabel::new("classified document".to_string());
    println!("Created nested label: Ev1?((Ev2?AB→A)→Public)");
    println!("Value: {:?}", doc.declassify_ref());

    eventon(&mut doc);
    println!("\nOuter event fired (Ev1)");

    let out_pub: DRLabel<(), Ev1, Public, Public> = DRLabel::new(());
    let guards = GUARDS.lock().unwrap().clone();

    output_to(&doc, &out_pub, &guards);
    println!("  output_to Public succeeded (outer event resolved to Public)");

    let relabeled: DRLabel<String, Ev1, Public, Public> = relabel!(doc, &guards, Public, Public);
    println!("  Relabeled to Public: {:?}", relabeled.declassify_ref());

    let mut pub_target: DRLabel<String, Ev1, Public, Public> = DRLabel::new(String::new());
    relabeled.assign_to(&mut pub_target);
    println!("  Assigned to Public target: {:?}", pub_target.declassify_ref());

    eventoff(&mut doc);
    println!("\nDone.");
}

fn nested_inner_first() {
    type Ev1 = TrueB1; 
    type Ev2 = TrueB1; 

    let mut doc: DRLabel<DRLabel<String, Ev2, AB, A>, Ev1, AB, Public> = DRLabel::new(DRLabel::new("classified document".to_string()));
    println!("Created nested label (non-phantom): DRLabel<DRLabel<String, Ev2, AB, A>, Ev1, AB, Public>");
    println!("  Value: {:?}", doc.declassify_ref().declassify_ref());

    eventon(doc.inner_mut());
    let events = GUARDS.lock().unwrap().clone();
    let mut doc: DRLabel<String, Ev1, A, Public> = relabel!(doc, &events, A);
    println!("\nStage 0: Inner layer peeled — label is now Ev1?(A→Public)");

    eventon(&mut doc);
    let guards = GUARDS.lock().unwrap().clone();
    println!("\nStage 1: Outer event fired (Ev1)");

    let out_pub: DRLabel<(), Ev1, Public, Public> = DRLabel::new(());
    output_to(&doc, &out_pub, &guards);
    println!("  output_to Public succeeded!");

    let final_doc: DRLabel<String, Ev1, Public, Public> = relabel!(doc, &guards, Public, Public);
    println!("  Relabeled to Public: {:?}", final_doc.declassify_ref());

    println!("\nDone — two-stage declassification on same label: AB → A → Public");
}
