# Filament - Static Fine-grained Rust information flow tool

A fine-grained **Information Flow Control (IFC)** library for Rust. It prevents unauthorized information leaks by tagging every value with a security label, enforcing flow rules at compile time, and supporting runtime-conditional label changes through a dynamic release mechanism.

### Rust version
- Set Rustc to <= 1.82 

---

## There are two type of labels:
- Static Label: Labeled
- Dyanmic Label: DRLabel

## The Static Security Lattice

The lattice is a partial order over security labels. It answers: *"can information from level X flow to level Y?"*

### Labels
Three level lattice

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
        T
       /|\
      AB AC BC
     /|  |  |\
    A  B  B  C
     \ |  | /
      Public
```

For example, `A ⊑ AB ⊑ T` — Alice's secret can be raised to a joint secret or top, but never lowered back to `Public`.

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

**Memory erasure**: `Labeled<T, T>` (top label) uses `write_volatile` to zero the value's memory bytes on drop. If the value has already been consumed via `declassify`, the `Drop` impl is a no-op.

**Conversions**:
```rust
// Labeled<T, L> → DRLabel<T, S, L, L>  (no dynamic transition)
let dr = labeled.to_dr_label::<TrueB1>();

// DRLabel<T, S, L, L> → Labeled<T, L>  (resolved label, from == to)
let back: Labeled<T, L> = dr.to_labeled();
```

---

### `DRLabel<T, S, F1, F2>`

A value whose effective label changes at runtime when a **security event** fires.

| Parameter | Meaning |
|-----------|---------|
| `T`       | Wrapped value type |
| `S`       | Security Event |
| `F1`      | Label **before** the event fires |
| `F2`      | Label **after** the event fires |

```rust
// A credit card number: secret until payment is authorized
let mut card: DRLabel<String, TrueB1, AB, A> = DRLabel::new("4111-1111".into());

// Fire the release event (payment authorized)
eventon(&mut card);

// Deactivate if needed
eventoff(&mut card);
```

**Event control** modifies a `bool` field (`cond`) inside the label and registers its address in the global `GUARDS` set (event trace in theory). This set is used at runtime to verify that a label's event has actually been fired before allowing a flow.

**Assignment** between `DRLabel`s checks the `DRFlowsTo` trait at compile time:
```rust
source.assign_to(&mut target); // compile error if flow is not allowed
```

**Nesting** is supported: `F1` and `F2` can themselves be `DRLabel<(), S, ...>`, enabling multi-layer conditional release like `S1?((S2?AB→A)→Public)`.

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

`relabel!` changes a value's label, subject to flow checks. It has three forms:

**1. Static upgrade** — move a value to a higher label (compile-time only):

```rust
let public_val: Labeled<u32, Public> = Labeled::new(5);

// OK: Public ⊑ A  (checked via LEQ at compile time)
let secret_val: Labeled<u32, A> = relabel!(public_val, A);

// Compile error: A ⊄ Public
// let bad = relabel!(secret_val, Public);
```

**2. Nested DRLabel peel** — strip one layer from a nested dynamic label, with a runtime guard check:

```rust
// 3-arg form: relabel!(expr, &events, IntermediateLabel)
let resolved = relabel!(nested_dr, &guards, AB);
```

**3. Dynamic resolve** — convert a `DRLabel<T, S, F1, F2>` to a resolved static-equivalent, via a two-stage flow check and runtime guard check:

```rust
// 4-arg form: relabel!(expr, &events, IntermediateLabel, TargetLabel)
let static_like = relabel!(dr_val, &guards, AB, A);
```

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

Inside a `pc_block!`, every assignment goes through `secure_assign_with_pc`, which enforces two rules simultaneously:
- **Explicit flow**: source label ⊑ destination label
- **Implicit flow**: current PC ⊑ destination label

Side-effecting operations (like `println!`) inside a non-`Public` PC block are rejected at compile time via the `InvisibleSideEffectFree` trait.

---

## Output Functions

For `DRLabel` values, output is gated on whether the event has fired:

```rust
// Output only if event fired (cond == true)
output_to(&dr_val, &output_label, &guards);

// Output only if event has NOT fired (cond == false)
output_from(&dr_val, &output_label, &guards);
```

Both check the flow rule at compile time via `ReleaseTo` and perform a runtime guard membership check.

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
| `toy_examples` | Three small scenarios: a bidding game, a credit card number with conditional release, and a shared library system. Good first read. |
| `all_function_calls` | Exercises the full `fcall!`/`mcall!`/`relabel!` API surface — math, file I/O, serialization, and string operations. |
| `calendar` | Two users' calendars labeled `A` and `B`; finds free-slot overlap using `pc_block!` for implicit flow control. Result is labeled `AB`. |
| `battleship_new` | A full Battleship game demonstrating complex control flow, session types, and IFC across a multi-round game loop. |
| `dynamic_examples` | Advanced `DRLabel` scenarios: nested release, bidirectional events, and multi-level label resolution. |
| `jpmail` | Email system with per-recipient label policies enforced through labeled message fields. |
| `spotify-tui` | The open-source Spotify TUI client, retrofitted with IFC labels on user credentials and playback state. |


```

## References
Andrew C. Myers, Lantian Zheng, Steve Zdancewic, Stephen Chong, and Nathaniel Nystrom. 2006. Jif 3.0: Java information flow. http://www.cs.cornell.edu/jif.

Ada Lamba, Max Taylor, Vincent Beardsley, Jacob Bambeck, Michael D. Bond, and Zhiqiang Lin. Cocoon: Static Information Flow Control in Rust. https://github.com/PLaSSticity/Cocoon-implementation/
