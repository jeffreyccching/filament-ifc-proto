# How `pc_block!` enforces side-effect freedom

`pc_block!` is Filament's counterpart to Cocoon's `secret_block!`. The two differ in what they
track — Cocoon assigns one label to a whole block, Filament tracks a flow-sensitive program
counter — but the machinery that stops a block from *having side effects* is the same design,
ported construct by construct.

This note describes that machinery, maps each piece to its Cocoon original, records the
deliberate departures, and states what is and is not guaranteed.

- Cocoon paper: Lamba et al., *Cocoon: Static Information Flow Control in Rust*, OOPSLA 2024.
- Cocoon code: <https://github.com/PLaSSticity/Cocoon-implementation>

| File | Contents |
|---|---|
| `fg_ifc_library/macros/src/pc_block_expand.rs` | `pc_block!`, the expression rewriter (Cocoon's τ), the safe-method table |
| `fg_ifc_library/macros/src/side_effect_free.rs` | `#[side_effect_free_attr]` on functions, structs, enums |
| `fg_ifc_library/macros/src/lib.rs` | macro entry points, std allowlist (`allowlisted_path`) |
| `fg_ifc_library/typing_rules/src/implicit.rs` | `InvisibleSideEffectFree`, `Vetted`, the capture gate, `check_isef*`, `PanicSilencer` |
| `fg_ifc_library/typing_rules/src/safe_ops.rs` | operator whitelist (`SafeAdd`, `SafeCmp`, …) |
| `fg_ifc_library/typing_rules/src/safe_methods.rs` | std method whitelist (`SafeLen`, `SafePush`, …) |
| `fg_ifc_library/typing_rules/src/secure_io.rs` | labeled I/O: `SecureFile`, `SecureStream`, `SecureCommand`, console output |
| `fg_ifc_library/pc_block_tests/` | 24 compile-fail tests (trybuild), 12 run-time tests |

---

## 1. The two-copy expansion

As in Cocoon (paper Fig. 4a), the macro emits the block twice:

```rust
if true {
    // executed copy
    let guard = PanicSilencer::new();
    let outcome = call_pc_closure(|| catch_unwind(AssertUnwindSafe(|| { <executed copy> })));
    match outcome { Ok(()) => {}, Err(_) => std::process::abort() }
    drop(guard);
} else {
    // checked copy: never runs, only type-checked
    call_pc_closure(|| {
        let __pc: StartLabel = Default::default();
        <checked copy>
    });
}
```

Both copies come from one rewrite function, `tx_expr(expr, Mode)` — Cocoon's τ(expr, isExec).
The executed copy gets only the rewrites that change types, so both copies see the same types;
the checked copy additionally carries the checks. A program that could cause a side effect
therefore fails to compile, and the checks cost nothing at run time.

---

## 2. What blocks each channel

| Side-effect channel | Mechanism |
|---|---|
| Mutating a variable from outside the block | Both copies are closures passed to `call_pc_closure`, which requires the auto trait `PcVisibleSideEffectFree`. Negative impls for `&mut T` (unlabeled `T`), `*mut T`, `UnsafeCell<T>`; a captured `&T` is allowed only if `T: InvisibleSideEffectFree` |
| Calling a function that does I/O or writes a static | The callee must return `Vetted<_>`, which only `#[side_effect_free_attr]` produces, or be on the std allowlist |
| Passing off a checked function's `Vetted` from unchecked code | `#[side_effect_free_attr]` produces an `unsafe fn`, so unchecked code must write `unsafe` to obtain one |
| Method calls (`x.store(..)`, an application `len()`) | Method-call syntax is limited to std methods routed through `safe_methods` traits, implemented only for std types |
| Overloaded operators on application types | Operators routed through `safe_ops` traits, implemented only for std types |
| Invisible code: custom `Drop` / `Deref` | Every read goes through `check_isef_unsafe`, every borrow through `check_isef_ref` / `check_isef_mut`, every struct literal through `check_isef` — all requiring `InvisibleSideEffectFree` |
| Macros (`println!`, …) | Rejected: their expansion cannot be inspected |
| `&mut` passed to a callee | Each argument of a label-unwrapping call must satisfy the `NoMutRef` auto trait, which also catches a `&mut` hidden behind a variable |
| Panics | Abort — see §4 |

### Labeled I/O (Filament only)

Cocoon has no equivalent: every OS-level entity is untrusted, so a secret must be declassified
before it reaches one. Filament instead mediates the boundary with labeled handles in
`secure_io.rs`, and the guarantee runs in both directions:

- **writes** take `Src: Label + LEQ<L>`, so no-write-down is enforced at the type level — an
  `A`-labeled value cannot reach a `SecureFile<Public>`, and console output requires
  `Src: LEQ<Public>`;
- **reads** return `Labeled<_, L>` by *signature*, so data out of an `L` source carries `L`
  without the caller having to remember anything.

The handles are not themselves wrapped in `Labeled` — the handle type already carries `L` in
its `PhantomData<L>` — so methods are called directly and no unchecked `mcall!` is involved.

---

## 3. Mapping to Cocoon

### Ported directly

| Cocoon | Filament |
|---|---|
| `call_closure(F: FnOnce() -> R + VisibleSideEffectFree)` around both copies | `call_pc_closure(F: FnOnce() -> R + PcVisibleSideEffectFree)` around both copies |
| auto trait `VisibleSideEffectFree`: negative impls for `&mut T` (`T: NotSecret`), `*mut T`, `UnsafeCell`; `&T` gated by the `Wrapped<T>` double-negation trick | same structure, with `NotLabeled` in place of `NotSecret` and `__PcWrap` in place of `Wrapped` |
| `check_ISEF`, `check_ISEF_unsafe`, `check_expr_secret_block_safe_ref`, `check_ISEF_mut_ref` | `check_isef`, `check_isef_unsafe`, `check_isef_ref`, `check_isef_mut` |
| `InvisibleSideEffectFree` (unsafe trait, impls for std types) | same |
| `Vetted<T>` with an `unsafe` constructor; non-allowlisted calls must return it | same (`require_vetted(unsafe { f(..) })`) |
| `#[side_effect_free_attr]` (Fig. 4b): `unsafe fn f(..) -> Vetted<R>` wrapping safe trampolines for the body | same layout; the trampolines are nested inside `f` so associated functions work |
| `SafeAdd`, `SafeAddAssign`, `SafePartialEq`, … | `safe_ops` operator traits, dispatched through one shared table (`safe_binop` / `safe_unop` in `macros/src/lib.rs`) so `pc_block!` and `#[side_effect_free_attr]` cannot diverge |
| allowlist of fully qualified std functions | same idea (`allowlisted_path`), emitted as canonical `::std::…` paths so a user `mod std` cannot impersonate it |
| two copies, `if true { exec } else { checked }`, rewriter τ(e, isExec) | same, `tx_expr(e, Mode)` |

### Same goal, different technique

| Topic | Cocoon | Filament | Why |
|---|---|---|---|
| Custom `Drop` / `Deref` | derive emits `impl !Drop`, `impl !Deref` | overlapping-impl trick (`impl<T: Drop> NoCustomDrop for T` conflicts with `impl NoCustomDrop for S` iff `S: Drop`) | rustc now rejects `impl !Drop` ("negative `Drop` impls are not supported"); Cocoon targeted 1.69-nightly |
| Method calls | must be fully qualified | `v.len()` rewritten to `SafeLen::safe_len(&v)` | labeled values have no `unwrap_secret`, so fully qualified calls could not operate on them |
| `unsafe {}` inside a block | passed through unchecked | still checked | deliberately stricter |
| Writes | `check_not_mut_secret` bans writing a `Secret` directly | `PcWrite` guard allows it when PC ⊑ label | Filament's labeled-write design (the Denning-style part) |
| Panics | caught, default value returned | abort | see §4 |

### Not needed in Filament

`wrap_secret` / `unwrap_secret*` with `MoreSecretThan` bounds, and the `SecretTrait<L>` bound on
the block result: labeled values keep their labels and the PC does the checking, so `pc_block!`
returns `()`.

---

## 4. Panics

Cocoon catches a panic and returns a `Secret`-wrapped default. That is sound there because
every write a secret block performs is at the block's own label, so an observer at that label
learns nothing from a skipped write.

It is not sound under a flow-sensitive PC, which may sit *below* the label of the data that
triggers the panic:

```rust
pc_block!((Public) {
    let _t = a_A / d_A;        // panics iff d_A == 0   (A-labeled)
    pub_y = Labeled::new(1);   // allowed: the PC is Public here
});                            // on recovery, pub_y == 0 reveals d_A == 0 to a Public observer
```

So a panic inside `pc_block!` aborts the process. What an observer learns is that the program
stopped — the termination channel, which termination-insensitive noninterference (Cocoon's
stated guarantee as well) excludes. `return` is rejected for the same reason.

Panic messages can carry secret-derived data (`index out of bounds: the len is 3 but the index
is 7`), so output is suppressed while a block runs. This is done with a hook installed **once**
that consults a thread-local flag (`PanicSilencer`), not by swapping the global hook per block:
swapping mutates process-global state, which is neither thread-safe nor free when a block sits
inside a loop. Cocoon does not touch the panic hook at all.

---

## 5. Is it side-effect free?

**Inside `pc_block!` and `#[side_effect_free_attr]` functions: yes, to the same standard as
Cocoon.** A program that performs I/O, writes outside state, runs application code through
operators / methods / `Drop` / `Deref`, or writes data whose label is below the PC does not
compile.

Evidence beyond the design: 24 compile-fail tests (one per rejected leak) and 12 run-time tests
in `fg_ifc_library/pc_block_tests`, plus independent probes, each of which is correctly
rejected while a legitimate tagged call chain still compiles and runs:

| Probe | Rejected by |
|---|---|
| interior mutability via a captured `&Cell` | `Cell<i32>: InvisibleSideEffectFree` not satisfied |
| a type with a custom `Deref` that writes a file | same ISEF bound |
| mutating an outer `&mut Vec` under a **Public** PC | capture gate: `&mut &mut Vec<i32>: PcVisibleSideEffectFree` |
| the same write under a **secret** PC | PC write guard: `expected &Public, found &A` |
| a tagged function calling an untagged one that does I/O | callee does not return `Vetted` |

This holds assuming the trusted base is correct: the std allowlist and the `safe_ops` /
`safe_methods` impls, every `unsafe impl InvisibleSideEffectFree`, `typing_rules` and the
macros themselves, and the audited escape hatches — `declassify*`, `unchecked_operation(..)`,
and any `unsafe`.

### What this does not cover

**`fcall!` and `mcall!` outside `pc_block!` are not checked.** They unwrap a label and hand the
raw value to an arbitrary function, with no requirement that it be side-effect free:

```rust
fn exfiltrate(s: &str) -> usize { std::fs::write("/tmp/leak", s).unwrap(); s.len() }
let secret = Labeled::<String, A>::new("hunter2".to_string());
let n = fcall!(exfiltrate(&secret));     // compiles; secret written to disk
```

No `pc_block`, no `declassify`, no `unsafe`. The same applies to a closure inside `mcall!`,
which may capture and write outer state:

```rust
let n = mcall!(secret.chars().all(|c| { stolen.push(c); true }));   // stolen == "hunter2"
```

Cocoon has no equivalent gap, because secrets cannot be touched outside a secret block. Closing
it means applying the `Vetted` rule to `fcall!` / `mcall!` and routing `mcall!`'s generated
closure through the capture gate — the same two mechanisms described above.

So the accurate claim is scoped to the construct: *inside `pc_block!` and
`#[side_effect_free_attr]`, Filament enforces side-effect freedom to Cocoon's standard.*
Whole-program side-effect freedom does not follow while `fcall!` / `mcall!` remain unchecked.

Nothing here is proved; the evidence is the design and the tests. Cocoon's guarantee is
likewise unproved.
