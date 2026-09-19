use macros::*;
use serde::{Deserialize, Serialize};
use typing_rules::lattice::*;

struct DangerousHandle;
fn example_math() {
    // Two secret values
    let val_1 = Labeled::<u32, A>::new(100);
    let val_2 = Labeled::<u32, B>::new(50);

    // The result is Join of A and B.
    let _result = fcall!(u32::saturating_mul(val_1, val_2));
    // result type is Labeled<u32, AB>
}
fn example_write() {
    // 1. Define Labeled Data
    // We treat the filename as 'Public' (or Label A) and content as 'Secret' (Label A)
    let path = Labeled::<String, Public>::new("secret.txt".to_string());
    let content = Labeled::<String, A>::new("This is top secret data.".to_string());

    // 2. Call Write
    // The macro unwraps 'path' -> String
    // The macro unwraps 'content' -> String
    // It calls fs::write(String, String)
    // Returns: Labeled<Result<(), Error>, A>  (Label is joined: Public + A = A)
    let write_result: Labeled<Result<(), std::io::Error>, A> = fcall!(std::fs::write(path, content));
}
fn example_serde() {
    #[derive(Serialize, Deserialize, Debug)]
    struct User {
        name: String,
        age: u32,
    }

    let user = User { name: "Alice".to_string(), age: 30 };

    // 1. fcall! executes serde_json::to_string(&user)
    // 2. Returns Labeled<Result<String, Error>, Public>
    let json_labeled = fcall!(serde_json::to_string(&user));

    // 3. Access .value (which is the Result) and unwrap it
    // Note: In production, handle errors instead of .unwrap()
    // match json_labeled.value {
    //     Ok(json_string) => println!("Serialized user: {}", json_string),
    //     Err(e) => println!("Serialization failed: {:?}", e),
    // }
}

fn example_read() {
    let path = Labeled::<String, A>::new("secret.txt".to_string());

    let path_no_label = "secret.txt".to_string();

    // 1. Call Read
    // Input: Labeled<String, Public>
    // Output: Labeled<Result<String, Error>, Public>
    // Note: If 'path' was Label A, the output would automatically be Label A.
    let read_result = fcall!(std::fs::read_to_string(path));

    // 2. Access Data via transpose + declassify
    if let Ok(contents) = read_result.transpose() {
        let public_contents = declassify(contents);
        println!("Read contents: {}", public_contents);
    }
}

fn example_string_ops() {
    let secret_number = Labeled::<i32, B>::new(42);

    // 1. Call a method using "Fully Qualified Syntax"
    // Instead of secret_number.to_string(), we use i32::to_string(...)
    // Note: to_string expects a reference, so we use .as_ref()
    let secret_string = fcall!(i32::to_string(secret_number.as_ref()));

    // secret_string is now Labeled<String, B> containing "42"
    let public_string = declassify(secret_string);
    println!("Secret string is: {}", public_string);
}

fn example_relabel() {
    // 1. Start with Public data
    let public_val = Labeled::<i32, A>::new(100);
    let mut secret_val = Labeled::<i32, AB>::new(100);
    let mid_val = Labeled::<i32, A>::new(100);
    // secret_val = public_val.clone(); // ERROR: Public cannot flow to AB
    // fail_val = relabel!(public_val, B);
    // 2. VALID: Upgrade Public -> A
    // (Public flows to A, so this compiles)
    let val_a = relabel!(public_val, A);
    let val_a2 = relabel!(mid_val.clone(), AB);
    let hello = secret_val + relabel!(mid_val, AB);
    secret_val = hello;
    // if val_a == Labeled::<i32, A>::new(90) {
    //     println!("Value is 100");
    // }
    let y: Labeled<i32, A> = Labeled::new(10);
    let mut x: i32 = 0;
    // x = y; // cannot type check

    // 3. VALID: Upgrade A -> AB
    // (A flows to AB, so this compiles)
    let _val_ab = relabel!(val_a.clone(), AB);

    // 5. SAME LABEL: A -> A
    // (A flows to A, so this works without extra checks)
    let _same_val = relabel!(val_a, A);
}

fn open_network_connection() -> DangerousHandle {
    println!("Opening connection..."); // Side effect!
    DangerousHandle
}

// pc_block! chain-unwraps labeled args to raw inner types before calling, so
// to be callable from inside a pc_block this function must take raw `i32`.
// It returns Labeled<i32, Public>; pc_block's chain combinator joins the
// callers' labels onto the result, so `safe_add(a, b)` where
// `a, b: Labeled<i32, A>` produces `Labeled<i32, A>`.
#[side_effect_free_attr]
fn safe_add(x: i32, y: i32) -> Labeled<i32, Public> {
    Labeled::new(x + y)
}

// Side-effect-free function with labeled parameters and labeled return.
// Cannot be called from inside `pc_block!{...}` (the macro chain-unwraps
// args to raw types, which would mismatch the `Labeled<_, _>` params).
// Call it directly — see `example_call_foo_labeled` below.
#[side_effect_free_attr]
fn foo_labeled(mut data: Labeled<i32, A>, _config: Labeled<i32, B>) -> Labeled<i32, A> {
    data = Labeled::new(1);
    data
}

fn implicit_flow_example() {
    // 1. SETUP DATA
    // A Secret Boolean (Label A).
    // The value 'true' is secret.
    let is_vip_user = Labeled::<bool, A>::new(true);

    // A Public Counter (Label Public).
    // Everyone can see this.
    let mut public_counter = Labeled::<i32, Public>::new(0);

    // A Secret Log (Label A).
    // Only authorized users can see this.
    let mut secret_user = Labeled::<i32, A>::new(0);
    let secret_A = Labeled::<i32, A>::new(0);
    let mut public_log = Labeled::<i32, Public>::new(0);

    // 2. THE SECURE BLOCK
    pc_block! { (A) {
        if is_vip_user {
            secret_user = secret_A;
            // secret_B = relabel!(1, B);
            // println!("hello");
        }
        // let x = Labeled::<i32, A>::new(5);
        // let y = Labeled::<i32, A>::new(3);
        // let result = x + y;
    } };

    println!("Execution finished safely.");
}

fn hello<L: Label>(val: Labeled<i32, L>, val2: i32) {
    let v3 = val + val2;
}

fn secure_func<L: Label>(val: Labeled<i32, L>)
where
    L: LEQ<Public>,
{
    pc_block!((L) { // PC starts as L
        let mut public_var = Labeled::new(0); // Label is Public
        let mut public_num = Labeled::<i32, Public>::new(1);

        // Assignment check: Does L <= Public?
        // If L is generic, this fails to compile UNLESS you add 'where L: Flow<Public>'
        public_var = public_num;
    })
}

fn example_fail() {
    let s1: Labeled<i32, A> = Labeled::<i32, A>::new(1);
    let s2 = Labeled::<i32, A>::new(1);
    let len_pub = Labeled::<i32, Public>::new(1);

    let s3 = s1.clone() + s2.clone();
    // let mut local_tasks = vec![s1, s2];

    let mut local_tasks = vec![s1, s2];
    let hello = local_tasks.dedup();

    let mut labeled_tasks = Labeled::<&Vec<Labeled<i32, A>>, A>::new(&local_tasks);
    // (*labeled_tasks).len();
    let len = mcall!(labeled_tasks.len());

    let mut x: Labeled<String, A> = Labeled::<String, A>::new("hello".to_string());
    let hello = mcall!(x.len());

    // *x;
}
/// Demonstrates panic suppression inside pc_block!.
///
/// A branch conditioned on a secret value triggers a panic.  Without
/// suppression, the panic message could leak secret data (e.g., formatted
/// secret values in the panic payload) and the crash itself reveals which
/// branch was taken.
///
/// The pc_block! macro installs a silent panic hook for the duration of
/// the block, so the panic message is suppressed.  After the block exits
/// (or the panic is caught), the original hook is restored.
// fn example_panic_suppression() {
//     let secret_flag = Labeled::<bool, A>::new(true);

//     // Wrap in catch_unwind so the example can continue after the panic.
//     let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
//         pc_block! { (Public) {
//             if secret_flag {
//                 // This branch panics.  The message "SECRET DATA LEAKED"
//                 // would normally be printed to stderr, but the pc_block!
//                 // macro's silent hook suppresses it entirely.
//                panic!("SECRET DATA LEAKED");
//             }
//         }}
//     }));

//     match outcome {
//         Ok(()) => println!("[panic_test] Block completed without panic."),
//         Err(_) => println!("[panic_test] Panic caught — message was suppressed by pc_block!."),
//     }

//     // Verify the original panic hook was restored after the pc_block!.
//     let hook_test = std::panic::catch_unwind(|| {
//         panic!("Hook restoration test");
//     });
//     match hook_test {
//         Err(_) => println!("[panic_test] Original hook restored — normal panic messages work."),
//         Ok(_) => unreachable!(),
//     }
// }

/// Demonstrates panic suppression inside fcall!.
///
/// When a function called via fcall! panics, the unwrapped secret values
/// could leak through the panic message.  fcall! installs a silent panic
/// hook for the duration of the call, suppressing the message.
fn example_fcall_panic_suppression() {
    fn panicking_func(secret: String) -> String {
        panic!("LEAKED: {}", secret);
    }

    let secret = Labeled::<String, A>::new("password123".to_string());

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Without suppression, the panic would print "LEAKED: password123".
        // With fcall!'s silent hook, the message is suppressed.
        let _result = fcall!(panicking_func(secret));
    }));

    match outcome {
        Ok(()) => println!("[fcall_panic] No panic (unexpected)."),
        Err(_) => println!("[fcall_panic] Panic caught — message was suppressed by fcall!."),
    }

    // Verify the original hook was restored.
    let hook_test = std::panic::catch_unwind(|| {
        panic!("fcall hook restoration test");
    });
    match hook_test {
        Err(_) => println!("[fcall_panic] Original hook restored."),
        Ok(_) => unreachable!(),
    }
}

/// Demonstrates format! as a special case of fcall — outside pc_block!
fn example_format_outside_pc_block() {
    let username = Labeled::<String, A>::new("Alice".to_string());
    let age = Labeled::<u32, Public>::new(30);

    // Before: Labeled::new(format!("User: {}, Age: {}", declassify(username), declassify(age)))
    // After:  fcall!(format!(...)) chains the labeled args automatically
    let greeting: Labeled<String, A> = fcall!(format!("User: {}, Age: {}", username, age));
    println!("format outside pc_block: {}", declassify(greeting));

    // No args — just wraps in Labeled<String, Public>
    let plain: Labeled<String, Public> = fcall!(format!("no args here"));
    println!("format no args: {}", declassify(plain));
}

/// Demonstrates format! inside pc_block! — the expand_expr path handles it
// fn example_format_inside_pc_block() {
//     let secret_name = Labeled::<String, A>::new("Bob".to_string());
//     let mut result = Labeled::<String, A>::new(String::new());

//     pc_block! { (A) {
//         // format! inside pc_block is handled by expand_expr's Expr::Macro arm
//         let msg = format!("Hello, {}!", secret_name);
//         result = msg;
//     }};

//     println!("format inside pc_block: {}", declassify(result));
// }

fn foo<L: Label>(val: Labeled<i32, L>, val2: i32) -> Labeled<i32, L> {
    val + val2
    // let v3 = val + val2;
    // v3
    // relabel!(val2, L)
}

/// Demonstrates the most common `fcall!` type error: passing labeled args
/// to a function whose parameters are themselves `Labeled<...>`.
///
/// `fcall!` rewrites `expects_labeled(x, y)` as
///   `x.__chain(|__v0| y.__chain(|__v1| expects_labeled(__v0, __v1)))`
/// where `__v0, __v1` are the *unwrapped inner values* (`i32`). The callee
/// declared `Labeled<i32, _>` parameters, so the call sites mismatch:
///
///   error[E0308]: arguments to this function are incorrect
///     | let bad = fcall!(expects_labeled(x, y));
///     |                  ^^^^^^^^^^^^^^^
///     = note: expected `Labeled<i32, _>`, found `i32`
///
/// Fix: have the callee accept raw values (`fn expects_raw(x: i32, y: i32)`),
/// or call it directly without `fcall!` since the args are already labeled.
fn example_fcall_error_labeled_arg() {
    // `Label` now carries `Join<Self, Out = Self>`, so the join resolves to `L` and
    // needs no hand-written bounds.
    fn expects_labeled<L: Label>(x: Labeled<i32, L>, y: Labeled<i32, L>) -> Labeled<i32, L> {
        x + y
    }

    fn expects_raw(x: i32, y: i32) -> i32 {
        x + y
    }

    let x = Labeled::<i32, A>::new(10);
    let y = Labeled::<i32, A>::new(32);

    // ERROR: fcall! chain-unwraps `x` and `y` to `i32`, but `expects_labeled`
    // wants `Labeled<i32, L>`. Uncomment to see the E0308 mismatch:
    //   "expected `Labeled<i32, {unknown}>`, found `i32`"
    // let bad = fcall!(expects_labeled(x, y));

    // OK path #1: callee takes raw values; chain re-labels the result.
    let ok_raw: Labeled<i32, A> = fcall!(expects_raw(x.clone(), y.clone()));
    println!("fcall ok_raw = {}", declassify(ok_raw));

    // OK path #2: callee takes Labeled<...>; just call it directly,
    // no fcall! needed because the args are already labeled.
    let ok_direct = expects_labeled(x, y);
    println!("fcall ok_direct = {}", declassify(ok_direct));
}

/// Demonstrates a `#[side_effect_free_attr]` function whose parameters and
/// return are labeled (`foo_labeled`), called directly.
///
/// Such a function CANNOT be invoked from inside `pc_block!{...}` — the
/// macro chain-unwraps args to raw types, which mismatches the labeled
/// params. A direct call works fine: the result type is precisely
/// `Labeled<i32, A>` (no join with B), and `.unwrap()` peels the `Vetted`
/// wrapper introduced by `#[side_effect_free_attr]`.
fn example_call_foo_labeled() {
    let a = Labeled::<i32, A>::new(10);
    let b = Labeled::<i32, B>::new(20);
    let _y = Labeled::<bool, B>::new(true);

    // ATTEMPT: call foo_labeled INSIDE pc_block!. Fails to compile —
    // pc_block chain-unwraps `a` and `b` to raw `i32`, but foo_labeled
    // declared Labeled<_, _> parameters. Uncomment to reproduce:
    //
    //   error: expected `Labeled<i32, A>`, found `i32`
    //   error: expected `Labeled<i32, B>`, found `i32`
    //
    // let mut result = Labeled::<i32, AB>::new(0);
    // pc_block! { (B) {
    //     if _y {
    //         result = foo_labeled(a.clone(), b.clone());
    //     }
    // }};

    // Working path: call foo_labeled directly (outside pc_block).
    // Result is precisely Labeled<i32, A> — B is dropped at the type level.
    // As in Cocoon, a #[side_effect_free_attr] function is an `unsafe fn`, so
    // unchecked code cannot pass off its `Vetted`; a direct call says `unsafe`.
    let result: Labeled<i32, A> = unsafe { foo_labeled(a, b) }.unwrap();
    println!("foo_labeled (direct) = {}", declassify(result));
}

/// Demonstrates calling a `#[side_effect_free_attr]` function (`safe_add`)
/// from inside a `pc_block!`.
///
/// pc_block runs with PC = A: any value assigned inside must be at least as
/// confidential as A. The macro chain-unwraps `a` and `b` to raw `i32`s and
/// calls `safe_add(i32, i32)`. Inside pc_block every callee must be
/// `#[side_effect_free_attr]`; its `Vetted<Labeled<i32, Public>>` return is
/// unwrapped, and the chain combinator joins the callers' label `A` onto
/// `Public`, yielding `Labeled<i32, A>`.
fn example_pc_block_safe_add() {
    let a = Labeled::<i32, A>::new(7);
    let b = Labeled::<i32, A>::new(35);
    let mut total = Labeled::<i32, A>::new(0);

    pc_block! { (A) {
        let sum = safe_add(a, b);
        total = sum;
    }};

    println!("pc_block + safe_add: total = {}", declassify(total));
}

fn main() {
    let v1 = Labeled::<i32, A>::new(10);
    let v2 = 11;
    // let z = foo(v1, v2);

    fn foo(x: i32, y: i32) -> i32 {
        x + y
    }
    let x = Labeled::<i32, A>::new(1);
    let y = 2;
    let z = fcall!(foo(x, relabel!(y, A)));

    example_math();
    example_write();
    example_read();
    implicit_flow_example();
    example_serde();
    // example_panic_suppression();
    example_fcall_panic_suppression();
    example_format_outside_pc_block();
    // example_format_inside_pc_block();
    example_pc_block_safe_add();
    example_fcall_error_labeled_arg();
    example_call_foo_labeled();
}
