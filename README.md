# Filament - Static Fine-grained Rust information flow tool

A fine-grained **Information Flow Control (IFC)** library for Rust. Sensitive values are wrapped in a
type carrying a security label; everything else is `Public` by default. Flow rules are enforced
entirely at compile time, with no run-time representation cost.

Filament is a Denning-style system: it tracks a program counter label so that *implicit* flows
(through control flow) are checked as well as explicit ones. See `pc_block!` below.


---

## Requirements

**A nightly Rust toolchain is required.** The library uses
`#![feature(auto_traits, negative_impls)]` to express the traits that gate what may appear
inside a `pc_block!`; neither is available on stable. `rust-toolchain.toml` pins the channel,
so `cargo` picks it up automatically — no manual `+nightly` needed.

## The Static Security Lattice

Every sensitive value is a `Labeled<T, L>`, where `L` is a label drawn from the lattice below. The
lattice is a partial order over security labels. It answers: *"can information from level X flow to
level Y?"*

### Labels

The default lattice is the powerset of `{A, B, C}` ordered by inclusion, plus a top element `T`.

| Label    | Meaning                              |
|----------|--------------------------------------|
| `Public` | No restrictions (bottom of lattice)  |
| `A`      | Label A          |
| `B`      | Label B         |
| `C`      | Label C          |
| `AB`     | Joint secret between A and B         |
| `AC`     | Joint secret between A and C         |
| `BC`     | Joint secret between B and C         |
| `ABC`    | Joint secret between A, B, and C     |
| `T`      | Top — most sensitive, memory-erased  |

### Flow Order (⊑)

Information may only flow **upward** in the lattice:

```
          T          top
          |
         ABC
       /  |  \
     AB   AC   BC     AB = {A,B}   AC = {A,C}   BC = {B,C}
       \  |  /
      A   B   C
       \  |  /
        Public        bottom
```

Each joint label sits above both of its components, which the diagram cannot show without
crossing lines. The covering relations are:

```
Public ⊑ A, B, C
A ⊑ AB, AC        B ⊑ AB, BC        C ⊑ AC, BC
AB, AC, BC ⊑ ABC        ABC ⊑ T
```

For example, `A ⊑ AB ⊑ ABC ⊑ T` — Alice's secret can be raised to a joint secret or top, but never lowered back to `Public`.

The `LEQ<Target>` trait encodes this: `impl LEQ<AB> for A {}` means `A` can flow to `AB`.

### Join (⊔)

When two labeled values are combined, the result carries the **least upper bound** of their labels. This is computed via the `Join<Other>` trait at compile time:

```
A ⊔ B   = AB
A ⊔ AB  = AB
B ⊔ T   = T
Public ⊔ X = X
```

---

## Label Types

### `Labeled<T, L>`

A wrapper around a value `T` tagged with label `L`. The inner value is inaccessible without an explicit operation.

```rust
let secret: Labeled<u32, A> = Labeled::new(42);

// Read without consuming
let val: &u32 = secret.declassify_ref();

// Consume and strip the label entirely
let raw: u32 = declassify(secret);
```

**Memory erasure**: a value at the top label (`Labeled<V, T>`) uses `write_volatile` to zero the value's memory bytes on drop. If the value has already been consumed via `declassify`, the `Drop` impl is a no-op.

---

## Macros

### `fcall!` — Function Calls with Label Propagation

`fcall!` rewrites a function call so that labels are automatically joined across all arguments and the result is re-wrapped:

```rust
fn add(x: u32, y: u32) -> u32 { x + y }

let a: Labeled<u32, A> = Labeled::new(10);
let b: Labeled<u32, B> = Labeled::new(20);

// result: Labeled<u32, AB>  (A ⊔ B = AB)
let result = fcall!(add(a, b));
```

**Supported variants**:

```rust
// Owned arguments
let r = fcall!(func(x, y));

// Reference arguments (label still propagates)
let r = fcall!(func(&x, &y));

// Error propagation
let r = fcall!(func(x)?);

// Async functions
let r = fcall!(func(x).await);

// format! (labeled args, Public result)
let s = fcall!(format!("Hello {}", name));
```

**Unlabeled (plain) values** passed to `fcall!` are treated as `Public` automatically via a blanket `SecureChain` impl.

---

### `mcall!` — Method Calls Preserving Label

`mcall!` calls a method or accesses a field on a labeled value while **preserving the receiver's label exactly** — no join with other labels.

```rust
let name: Labeled<String, A> = Labeled::new("alice".into());

// result: Labeled<usize, A>  — label unchanged
let len = mcall!(name.len());

// Field access
let first = mcall!(record.field_name);
```

Use `mcall!` for structural transformations that don't introduce new secrets (conversions, length, splitting, etc.).

---

### `relabel!` — Label Upgrades

`relabel!` changes a value's label, subject to a compile-time flow check.

**Static upgrade** — move a value to a higher label:

```rust
let public_val: Labeled<u32, Public> = Labeled::new(5);

// OK: Public ⊑ A  (checked via LEQ at compile time)
let secret_val: Labeled<u32, A> = relabel!(public_val, A);

// Compile error: A ⊄ Public
// let bad = relabel!(secret_val, Public);
```

A raw (unlabeled) value is treated as `Public`, so `relabel!(5, A)` produces a `Labeled<u32, A>`.

`relabel!` rejects mutable references: `relabel!(&mut x, A)` is a compile error.

---

### `pc_block!` — Implicit Flow Control

`pc_block!` tracks the **program counter (PC)** label inside a block and prevents assignments that would leak information through control flow.

```rust
let mut result: Labeled<u32, AB> = Labeled::new(0);
let condition: Labeled<bool, A>  = Labeled::new(true);

pc_block! {
    (Public) {                       // starting PC = Public
        if condition {               // PC becomes A inside this branch
            // Compile error if trying to assign to Labeled<_, Public> here
            result = Labeled::new(1);   // OK: AB >= A
        }
    }
}
```

`pc_block!` follows Cocoon's `secret_block!`: the macro emits the block twice, once to run and once — never executed — carrying the checks, so a program that could leak or cause a side effect does not compile. Inside the block:

- **Writes**: every write (`=`, `+=`, `&mut`, `push`, …) must satisfy *current PC ⊑ label of the target*; an unlabeled target counts as `Public`. Labels of values must match exactly (no implicit upgrade). The PC is raised inside `if` / `if let` / `while` / `for` on labeled values, and a value leaving such a branch carries the condition's label.
- **Calls**: every callee must be `#[side_effect_free_attr]` (whose body is itself checked) or one of a few allowlisted std functions. Calls may not receive `&mut` arguments. As in Cocoon, the attribute makes the function an `unsafe fn` returning `Vetted`, so unchecked code cannot pass off its result: inside a block call it as `f(x)`; elsewhere, `unsafe { f(x) }.unwrap()`.
- **Methods and operators**: only the std methods in `typing_rules::safe_methods` (`len`, `get`, `push`, `iter`, …) and the std operators in `typing_rules::safe_ops`; application types cannot supply their own.
- **Values**: every value read must be `InvisibleSideEffectFree` (no custom `Drop` / `Deref`); the block may not mutate unlabeled variables from outside it.
- **Rejected**: macros, `match`, closures, `return`, `break` / `continue`, `?`, `while let`, `let … else`, and any item other than `const` / `use`. Most report *syntax not supported in `pc_block!`*. Keep blocks small and put the work in `#[side_effect_free_attr]` functions, which accept ordinary Rust.
- **Panics**: a panic inside a block aborts the process rather than being caught. Because the PC drops back after a branch, resuming after a panic would reveal that the block stopped early — and panic messages can themselves carry secret-derived data, so they are suppressed while a block runs. (Cocoon catches and returns a default, which is sound there because every write in a secret block is at the block's own label.)

A generic start label works without extra bounds — `Label` carries the join laws, so
`fn f<L: Label>()` containing `pc_block!((L) { .. })` needs no `where L: Join<L, Out = L>`.

There is no unchecked variant of `pc_block!`. Code that genuinely cannot be checked should `declassify` the values it needs and then be plain Rust, so the trust is visible and counted. The rules are documented in `fg_ifc_library/macros/src/pc_block_expand.rs`, and `fg_ifc_library/pc_block_tests` has one compile-fail test per rejected leak.

---

## Quick Start

Add the crates to your `Cargo.toml`:

```toml
[dependencies]
typing_rules = { path = "fg_ifc_library/typing_rules" }
macros        = { path = "fg_ifc_library/macros" }
```

```rust
use typing_rules::*;
use macros::{fcall, mcall, relabel};

fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

fn main() {
    let user: Labeled<String, A> = Labeled::new("Alice".into());

    // Call greet with a labeled argument; result label = A
    let msg: Labeled<String, A> = fcall!(greet(&user));

    // Read the value explicitly
    println!("{}", msg.declassify_ref());
}
```

---

## Examples

| Example | Description |
|---------|-------------|
| `all_function_calls` | Exercises the full `fcall!`/`mcall!`/`relabel!` API surface — math, file I/O, serialization, and string operations. Good first read. |
| `calendar` | Two users' calendars labeled `A` and `B`; counts overlapping availability using `pc_block!`. Result is labeled `AB`. This is the example that exercises `pc_block!`. |
| `battleship_new` | Two-player Battleship over `session_types`, each player's ship positions labeled. Needs no `pc_block!`, because placement never reads a secret — see its own README. |
| `jpmail` | Email system with per-recipient label policies enforced through labeled message fields. |
| `spotify-tui` | The Spotify TUI client, retrofitted with IFC on the client secret. **Outside the workspace** — see below. |
| `*-no-ifc`, `spotify-tui-original` | Unmodified baselines, for comparing against their IFC ports. |

## Building and Running

```bash
git clone https://github.com/jeffreyccching/filament-ifc.git
cd filament-ifc

cargo build --workspace
cargo test  --workspace

# the pc_block! rules: one compile-fail case per rejected leak, plus run-time behaviour
cargo test -p pc_block_tests

cargo run -p calendar          # prints "Available days: 2"
```

`examples/spotify-tui` and `examples/spotify-tui-original` are listed in `workspace.exclude` — they
pull a large dependency tree and need their own `[patch.crates-io]` for `chrono`, so `--workspace`
skips them. Build them separately:

```bash
cd examples/spotify-tui          && cargo build
cd examples/spotify-tui-original && cargo build
```

## Trusted operations

Everything below bypasses a check and is the surface to audit; the rest of a program is
verified by the compiler.

| Operation | What it bypasses |
|---|---|
| `declassify(x)`, `declassify_ref(x)` | lowers a label to `Public` |
| `unchecked_operation(e)` | side-effect checks inside a `pc_block!` |
| `unsafe` | including calling a `#[side_effect_free_attr]` function directly |

`fcall!` and `mcall!` operate on labeled values outside any `pc_block!`, so the functions they
call are trusted not to have side effects — they are not verified. Treat them as part of the
audit surface when reviewing.

## References
Andrew C. Myers, Lantian Zheng, Steve Zdancewic, Stephen Chong, and Nathaniel Nystrom. 2006. Jif 3.0: Java information flow. http://www.cs.cornell.edu/jif.

Ada Lamba, Max Taylor, Vincent Beardsley, Jacob Bambeck, Michael D. Bond, and Zhiqiang Lin. Cocoon: Static Information Flow Control in Rust. https://github.com/PLaSSticity/Cocoon-implementation/
