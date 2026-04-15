use macros::*;
use serde::{Deserialize, Serialize};
use typing_rules::lattice::*;

struct DangerousHandle;
fn example_math() {
    
    let val_1 = Labeled::<u32, A>::new(100);
    let val_2 = Labeled::<u32, B>::new(50);

    let _result = fcall!(u32::saturating_mul(val_1, val_2));
    
}
fn example_write() {
    
    let path = Labeled::<String, Public>::new("secret.txt".to_string());
    let content = Labeled::<String, A>::new("This is top secret data.".to_string());

    let write_result: Labeled<Result<(), std::io::Error>, A> = fcall!(std::fs::write(path, content));
}
fn example_serde() {
    #[derive(Serialize, Deserialize, Debug)]
    struct User {
        name: String,
        age: u32,
    }

    let user = User { name: "Alice".to_string(), age: 30 };

    let json_labeled = fcall!(serde_json::to_string(&user));

}

fn example_read() {
    let path = Labeled::<String, A>::new("secret.txt".to_string());

    let read_result = fcall!(std::fs::read_to_string(path));

    if let Ok(contents) = read_result.transpose() {
        let public_contents = declassify(contents);
        println!("Read contents: {}", public_contents);
    }
}

fn example_string_ops() {
    let secret_number = Labeled::<i32, B>::new(42);

    let secret_string = fcall!(i32::to_string(secret_number.as_ref()));

    let public_string = declassify(secret_string);
    println!("Secret string is: {}", public_string);
}

fn example_relabel() {
    
    let public_val = Labeled::<i32, Public>::new(100);
    let mut secret_val = Labeled::<i32, AB>::new(100);
    let mid_val = Labeled::<i32, A>::new(100);

    let val_a = relabel!(public_val, A);
    let val_a2 = relabel!(mid_val.clone(), AB);
    let hello = secret_val + relabel!(mid_val, AB);
    secret_val = hello;
    
    let y: Labeled<i32, A> = Labeled::new(10);
    let mut x: i32 = 0;
    
    let _val_ab = relabel!(val_a.clone(), AB);

    let _same_val = relabel!(val_a, A);
}

fn open_network_connection() -> DangerousHandle {
    println!("Opening connection..."); 
    DangerousHandle
}

fn implicit_flow_example() {
    
    let is_vip_user = Labeled::<bool, A>::new(true);

    let mut public_counter = Labeled::<i32, Public>::new(0);

    let mut secret_log = Labeled::<i32, A>::new(0);
    let mut secret_B = Labeled::<i32, B>::new(0);
    let mut public_log = Labeled::<i32, Public>::new(0);

    pc_block! { (A) {
        if is_vip_user {
            
        }
        let x = Labeled::<i32, A>::new(5);
        let y = Labeled::<i32, A>::new(3);
        let result = x + y;
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
    pc_block!((L) { 
        let mut public_var = Labeled::new(0); 
        let mut public_num = Labeled::<i32, Public>::new(1);

        public_var = public_num;
    })
}

fn example_fail() {
    let s1 = Labeled::<i32, A>::new(1);
    let s2 = Labeled::<i32, A>::new(1);
    let len_pub = Labeled::<i32, Public>::new(1);

    let s3 = s1.clone() + s2.clone();
    
    let mut local_tasks = vec![s1, s2];
    let hello = local_tasks.dedup();

    let labeled_tasks = Labeled::<&Vec<Labeled<i32, A>>, A>::new(&local_tasks);
    
    let len = mcall!(labeled_tasks.len());

    let x: Labeled<String, A> = Labeled::<String, A>::new("hello".to_string());
    let hello = mcall!(x.len());

}

fn example_panic_suppression() {
    let secret_flag = Labeled::<bool, A>::new(true);

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pc_block! { (Public) {
            if secret_flag {
                
               panic!("SECRET DATA LEAKED");
            }
        }}
    }));

    match outcome {
        Ok(()) => println!("[panic_test] Block completed without panic."),
        Err(_) => println!("[panic_test] Panic caught — message was suppressed by pc_block!."),
    }

    let hook_test = std::panic::catch_unwind(|| {
        panic!("Hook restoration test");
    });
    match hook_test {
        Err(_) => println!("[panic_test] Original hook restored — normal panic messages work."),
        Ok(_) => unreachable!(),
    }
}

fn example_fcall_panic_suppression() {
    fn panicking_func(secret: String) -> String {
        panic!("LEAKED: {}", secret);
    }

    let secret = Labeled::<String, A>::new("password123".to_string());

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        
        let _result = fcall!(panicking_func(secret));
    }));

    match outcome {
        Ok(()) => println!("[fcall_panic] No panic (unexpected)."),
        Err(_) => println!("[fcall_panic] Panic caught — message was suppressed by fcall!."),
    }

    let hook_test = std::panic::catch_unwind(|| {
        panic!("fcall hook restoration test");
    });
    match hook_test {
        Err(_) => println!("[fcall_panic] Original hook restored."),
        Ok(_) => unreachable!(),
    }
}

fn example_format_outside_pc_block() {
    let username = Labeled::<String, A>::new("Alice".to_string());
    let age = Labeled::<u32, Public>::new(30);

    let greeting: Labeled<String, A> = fcall!(format!("User: {}, Age: {}", username, age));
    println!("format outside pc_block: {}", declassify(greeting));

    let plain: Labeled<String, Public> = fcall!(format!("no args here"));
    println!("format no args: {}", declassify(plain));
}

fn example_format_inside_pc_block() {
    let secret_name = Labeled::<String, A>::new("Bob".to_string());
    let mut result = Labeled::<String, A>::new(String::new());

    pc_block! { (A) {
        
        let msg = format!("Hello, {}!", secret_name);
        result = msg;
    }};

    println!("format inside pc_block: {}", declassify(result));
}

fn foo<L: Label>(val: Labeled<i32, L>, val2: i32) -> Labeled<i32, L> {
    val + val2
    
}
fn main() {
    let v1 = Labeled::<i32, A>::new(10);
    let v2 = 11;
    
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
    example_panic_suppression();
    example_fcall_panic_suppression();
    example_format_outside_pc_block();
    example_format_inside_pc_block();
}
