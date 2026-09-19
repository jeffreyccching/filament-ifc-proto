use crate::lattice::{Join, Label, Labeled, Public, LEQ};

// =========================================================================
// 1. SIDE EFFECT TRAITS
// =========================================================================

/// Marker trait asserting that a type has **no observable side effects in any context**:
/// - Operator application (`+`, `-`, `*`, `[]`, etc.)
/// - Construction and cloning
/// - Iteration (if the type is an iterator, `next()` must be side-effect free)
/// - Dropping
///
/// This is stronger than "safe to drop/clone" — it covers every operation the
/// macro may invoke on a value inside a `pc_block`. The `unsafe` keyword is
/// load-bearing: the implementor asserts **all** of the above guarantees hold.
///
/// Violating this contract (e.g. an `Add` impl that writes to a global counter)
/// allows secret branch conditions to leak through observable side effects.
pub unsafe trait InvisibleSideEffectFree {
    /// No-op compile-time hook. Can be called to assert that all type parameters
    /// in a generic context implement `InvisibleSideEffectFree`.
    unsafe fn check_all_types() {}
}

pub struct Vetted<T>
where
    T: InvisibleSideEffectFree,
{
    item: T,
}

impl<T> Vetted<T>
where
    T: InvisibleSideEffectFree,
{
    /// Wraps `item` in a `Vetted<T>`, asserting that its return value is side-effect free.
    /// Called by `#[side_effect_free_attr]` functions to tag their return value so
    /// `PcCallResult` can unwrap it without boxing it inside a `Labeled`.
    pub unsafe fn wrap(item: T) -> Self {
        Vetted::<T> { item }
    }

    /// Unwraps the inner value, consuming the `Vetted` wrapper.
    pub fn unwrap(self) -> T {
        self.item
    }
}

unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for Vetted<T> {}

/// Identity gate that only compiles if `v` is a `Vetted<T>` — i.e. if the callee
/// that produced it was annotated `#[side_effect_free_attr]`.
///
/// Emitted by `#[side_effect_free_attr]`'s *checking* path around every call
/// whose callee is not on the allowlist. This is the mechanism that makes the
/// effect system transitive: a side-effect-free function may only call other
/// side-effect-free (or allowlisted) functions.
///
/// It returns the `Vetted` wrapper rather than unwrapping it so the checking
/// path stays type-compatible with the executed path, where the caller writes
/// the `.unwrap()` itself.
#[inline(always)]
pub fn require_vetted<T: InvisibleSideEffectFree>(v: Vetted<T>) -> Vetted<T> {
    v
}

/// Identity function that acts as a compile-time gate: returns `x` unchanged, but only
/// compiles if `T: InvisibleSideEffectFree`. The macro wraps expressions in this call so
/// that any type without the trait produces a type error at the point of use.
#[inline(always)]
pub fn check_isef<T: InvisibleSideEffectFree>(x: T) -> T {
    x
}

// =========================================================================
// 2. InvisibleSideEffectFree IMPLEMENTATIONS
// =========================================================================

// Primitives
unsafe impl InvisibleSideEffectFree for i8 {}
unsafe impl InvisibleSideEffectFree for i16 {}
unsafe impl InvisibleSideEffectFree for i32 {}
unsafe impl InvisibleSideEffectFree for i64 {}
unsafe impl InvisibleSideEffectFree for i128 {}
unsafe impl InvisibleSideEffectFree for isize {}
unsafe impl InvisibleSideEffectFree for u8 {}
unsafe impl InvisibleSideEffectFree for u16 {}
unsafe impl InvisibleSideEffectFree for u32 {}
unsafe impl InvisibleSideEffectFree for u64 {}
unsafe impl InvisibleSideEffectFree for u128 {}
unsafe impl InvisibleSideEffectFree for usize {}
unsafe impl InvisibleSideEffectFree for f32 {}
unsafe impl InvisibleSideEffectFree for f64 {}
unsafe impl InvisibleSideEffectFree for bool {}
unsafe impl InvisibleSideEffectFree for char {}
unsafe impl InvisibleSideEffectFree for () {}
unsafe impl InvisibleSideEffectFree for str {}
unsafe impl InvisibleSideEffectFree for &str {}
unsafe impl InvisibleSideEffectFree for String {}

// References and pointers
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for &T {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for &mut T {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for *const T {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for *mut T {}

// Slices and arrays
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for [T] {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for &[T] {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for &mut [T] {}
unsafe impl<T: InvisibleSideEffectFree, const N: usize> InvisibleSideEffectFree for [T; N] {}

// Standard containers
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for Option<T> {}
unsafe impl<T: InvisibleSideEffectFree, E: InvisibleSideEffectFree> InvisibleSideEffectFree for Result<T, E> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for Vec<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for Box<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::mem::MaybeUninit<T> {}

// Tuples
unsafe impl<T: InvisibleSideEffectFree, U: InvisibleSideEffectFree> InvisibleSideEffectFree for (T, U) {}
unsafe impl<T: InvisibleSideEffectFree, U: InvisibleSideEffectFree, V: InvisibleSideEffectFree> InvisibleSideEffectFree for (T, U, V) {}
unsafe impl<T: InvisibleSideEffectFree, U: InvisibleSideEffectFree, V: InvisibleSideEffectFree, W: InvisibleSideEffectFree> InvisibleSideEffectFree for (T, U, V, W) {}

// Reference-counted pointers
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::sync::Arc<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::rc::Rc<T> {}

// Collections
unsafe impl<K: InvisibleSideEffectFree, V: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::HashMap<K, V> {}
unsafe impl<K: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::HashSet<K> {}
unsafe impl<K: InvisibleSideEffectFree, V: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::BTreeMap<K, V> {}
unsafe impl<K: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::BTreeSet<K> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::VecDeque<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::LinkedList<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::BinaryHeap<T> {}

// Ranges
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::ops::Range<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::ops::RangeFrom<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::ops::RangeTo<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::ops::RangeInclusive<T> {}
unsafe impl InvisibleSideEffectFree for std::ops::RangeFull {}

// Iterators
unsafe impl<'a, T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::slice::Iter<'a, T> {}
unsafe impl<'a, T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::slice::IterMut<'a, T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::vec::IntoIter<T> {}
unsafe impl InvisibleSideEffectFree for std::str::Chars<'_> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Copied<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Cloned<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Cycle<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Take<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Skip<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Rev<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Enumerate<T> {}
unsafe impl<T: Iterator + InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Peekable<T> where T::Item: InvisibleSideEffectFree {}
unsafe impl<A: InvisibleSideEffectFree, B: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Zip<A, B> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Chain<T, T> {}

// Labeled types
unsafe impl<T: InvisibleSideEffectFree, L: Label> InvisibleSideEffectFree for Labeled<T, L> {}

// Misc
unsafe impl InvisibleSideEffectFree for std::time::Instant {}

// x86_64 SIMD
#[cfg(target_arch = "x86_64")]
unsafe impl InvisibleSideEffectFree for std::arch::x86_64::__m256d {}
#[cfg(target_arch = "x86_64")]
unsafe impl InvisibleSideEffectFree for std::arch::x86_64::__m128 {}

// =========================================================================
// 3. CONDITION HANDLING (Extract Label from Boolean)
// =========================================================================

/// Trait to inspect a condition and retrieve its security label.
pub trait ConditionInspect {
    type Label: Label;
    /// Consumes the condition and returns the raw boolean alongside a label token
    /// representing the condition's security level. The label token is used by
    /// `join_labels` to tighten the PC when entering an `if` or `while` branch.
    fn inspect(self) -> (bool, Self::Label);
}

// Case A: Standard boolean (Public condition)
impl ConditionInspect for bool {
    type Label = Public;
    /// A plain `bool` carries no secret information, so the label is `Public`
    /// and the PC does not need to be raised when branching on it.
    fn inspect(self) -> (bool, Self::Label) {
        (self, Public)
    }
}

// Case B: Labeled boolean (Secret condition)
impl<L: Label + Default> ConditionInspect for Labeled<bool, L> {
    type Label = L;
    /// Strips the `Labeled` wrapper to obtain the raw boolean for branching, and
    /// returns a default instance of `L` as the label token. The macro passes this
    /// token to `join_labels` so the PC inside the branch is at least as secret as `L`.
    fn inspect(mut self) -> (bool, Self::Label) {
        (self.value.take().unwrap(), L::default())
    }
}

/// Dispatches to the correct `ConditionInspect` impl for the given condition type.
/// Called by the macro at every `if`/`while` site to extract both the boolean
/// value and the security label before evaluating the branch.
#[inline(always)]
pub fn inspect_condition<C: ConditionInspect>(cond: C) -> (bool, C::Label) {
    cond.inspect()
}

/// Escape hatch that passes `val` through without any IFC checks. Use only when
/// an operation is intentionally exempt from information-flow enforcement (e.g.
/// debug logging that is acceptable regardless of the current PC).
pub fn unchecked_operation<T>(val: T) -> T {
    val
}

// =========================================================================
// 4. PC TRACKING (Label Join)
// =========================================================================

/// Computes the join (least upper bound) of the current PC and a new condition label,
/// returning a phantom token for the tighter security context. Called by the macro each
/// time a secret-conditioned branch is entered so that all assignments inside inherit
/// the combined PC.
#[inline(always)]
pub fn join_labels<L1: Label, L2: Label>(_current_pc: L1, _new_label: L2) -> <L1 as Join<L2>>::Out
where
    L1: Join<L2>,
    <L1 as Join<L2>>::Out: Label,
{
    // Returns a zeroed-initialized value of the joined label type.
    // Safe because Labels are Copy and contain no significant data.
    unsafe { std::mem::zeroed() }
}

// =========================================================================
// 5. SECURE ASSIGNMENT (Implicit Flow Check)
// =========================================================================

/// PC-only guard for assignments where the source label equals the destination
/// (e.g. `x = Labeled::new(val)` where `L` is inferred from `x`'s type).
/// Only enforces the implicit-flow rule: PC must flow to the destination label.
#[inline(always)]
pub fn pc_guard_assign<T, Dest, PC>(_dest: &mut Labeled<T, Dest>, _pc: PC)
where
    Dest: Label,
    PC: Label + LEQ<Dest>,
{
}

/// Performs a secure assignment enforcing both Explicit and Implicit flow.
///
/// Security Rules:
/// 1. **Explicit Flow:** Source Label (`Src`) must flow to Destination Label (`Dest`).
/// 2. **Implicit Flow:** Current PC (`PC`) must flow to Destination Label (`Dest`).
///
/// This prevents writing to a Public variable while inside a Secret 'if' block.
#[inline(always)]
pub fn secure_assign_with_pc<T, Dest, Src, PC>(dest: &mut Labeled<T, Dest>, mut src: Labeled<T, Src>, _pc: PC)
where
    Dest: Label,
    Src: Label + LEQ<Dest>, // Check 1: Value Flow
    PC: Label + LEQ<Dest>,  // Check 2: Context Flow (PC guard)
{
    dest.value = src.value.take();
}

// =========================================================================
// 6. PC-GUARDED WRITES (Autoref Specialization)
// =========================================================================

/// Target of a write inside `pc_block!`'s checking path: the left-hand side
/// of `=` and of compound assignment, the operand of `&mut`, and the receiver
/// of a mutating safe method.
///
/// `PcWrite(&mut target).guard(&__pc)` compiles only if the write respects
/// the PC:
/// - `Labeled<T, L>` target (inherent method, chosen first): `PC ⊑ L`.
/// - any other target (trait fallback): the target is unlabeled, i.e.
///   Public, so the PC must be `Public`. Writing a raw value under a raised
///   PC would let secret-dependent data outlive the branch unlabeled.
pub struct PcWrite<'a, T: ?Sized>(pub &'a mut T);

impl<'a, T, L: Label> PcWrite<'a, Labeled<T, L>> {
    /// Accepts the write when the current PC flows to the target's label.
    #[inline(always)]
    pub fn guard<PC: Label + LEQ<L>>(self, _pc: &PC) -> &'a mut Labeled<T, L> {
        self.0
    }
}

pub trait PcWriteFallback<'a, T: ?Sized> {
    /// Accepts a write to an unlabeled target only under a `Public` PC.
    fn guard(self, pc: &Public) -> &'a mut T;
}

impl<'a, T: ?Sized> PcWriteFallback<'a, T> for PcWrite<'a, T> {
    #[inline(always)]
    fn guard(self, _pc: &Public) -> &'a mut T {
        self.0
    }
}

/// Cocoon's `check_ISEF_mut_ref`: identity on `&mut T` that only compiles if
/// `T: InvisibleSideEffectFree`.
#[inline(always)]
pub fn check_isef_mut<T: InvisibleSideEffectFree + ?Sized>(x: &mut T) -> &mut T {
    x
}

/// Cocoon's `check_expr_secret_block_safe_ref`: identity on `&T` that only
/// compiles if `T: InvisibleSideEffectFree`.
#[inline(always)]
pub fn check_isef_ref<T: InvisibleSideEffectFree + ?Sized>(x: &T) -> &T {
    x
}

/// Implemented for every type that contains no mutable reference, raw
/// mutable pointer or interior mutability.
pub unsafe auto trait NoMutRef {}
impl<T: ?Sized> !NoMutRef for &mut T {}
impl<T: ?Sized> !NoMutRef for *mut T {}
impl<T: ?Sized> !NoMutRef for ::std::cell::UnsafeCell<T> {}

/// Gate on each argument of a call inside `pc_block!` whose labeled arguments
/// are unwrapped (`__chain`). The callee sees those arguments raw, so a
/// mutable reference among its arguments would let it store secret data
/// somewhere the PC never checks.
#[inline(always)]
pub fn check_call_arg<T: NoMutRef>(x: T) -> T {
    x
}

/// Cocoon's `check_ISEF_unsafe`: a bitwise copy of a variable, so the
/// checking path can require `T: InvisibleSideEffectFree` on every variable
/// the block reads without moving or borrowing it for real. Emitted only in
/// the checking path, which never runs.
#[inline(always)]
pub unsafe fn check_isef_unsafe<T: InvisibleSideEffectFree>(x: &T) -> T {
    std::ptr::read(x)
}

// =========================================================================
// 7. BRANCH VALUES AND `if let` SCRUTINEES (Autoref Specialization)
// =========================================================================

/// The value of an `if` / `if let` expression inside `pc_block!`.
///
/// The PC is raised only inside the branches, so a value leaving a branch
/// must carry the condition's label itself:
/// - `Labeled<T, L>` → `Labeled<T, L ⊔ C>`;
/// - `()` → `()`;
/// - any other (raw) value (trait fallback) → only when the condition is
///   `Public`.
pub struct BranchValue<T>(pub T);

impl<T, L: Label> BranchValue<Labeled<T, L>> {
    #[inline(always)]
    pub fn lift<C: Label>(self, _cond: &C) -> Labeled<T, <L as Join<C>>::Out>
    where
        L: Join<C>,
    {
        let mut v = self.0;
        Labeled::new(v.value.take().unwrap())
    }
}

impl BranchValue<()> {
    #[inline(always)]
    pub fn lift<C: Label>(self, _cond: &C) {}
}

pub trait BranchValueFallback<T> {
    fn lift(self, cond: &Public) -> T;
}

impl<T> BranchValueFallback<T> for BranchValue<T> {
    #[inline(always)]
    fn lift(self, _cond: &Public) -> T {
        self.0
    }
}

/// The scrutinee of an `if let` inside `pc_block!`. A labeled scrutinee is
/// unwrapped for matching and its label returned so the macro can raise the
/// PC inside the branches; a raw scrutinee is Public.
pub struct Scrutinee<T>(pub T);

impl<T, L: Label> Scrutinee<Labeled<T, L>> {
    #[inline(always)]
    pub fn inspect_scrutinee(self) -> (T, L) {
        let mut v = self.0;
        (v.value.take().unwrap(), L::default())
    }
}

impl<'a, T, L: Label> Scrutinee<&'a Labeled<T, L>> {
    #[inline(always)]
    pub fn inspect_scrutinee(self) -> (&'a T, L) {
        (self.0.value.as_ref().unwrap(), L::default())
    }
}

pub trait ScrutineeFallback<T> {
    fn inspect_scrutinee(self) -> (T, Public);
}

impl<T> ScrutineeFallback<T> for Scrutinee<T> {
    #[inline(always)]
    fn inspect_scrutinee(self) -> (T, Public) {
        (self.0, Public)
    }
}

// =========================================================================
// 8. LOOP ITERATOR LABEL INSPECTION
// =========================================================================

/// Wrapper used by `pc_block!` to extract the security label from a `for`
/// loop's iterator expression before entering the loop body.
///
/// Uses autoref specialization (same pattern as `PcCallResult`):
/// - Inherent method (high priority): `Labeled<I, L>` → strips the label,
///   returns the inner iterator and label `L`.
/// - Trait fallback (low priority): any plain `IntoIterator` → returns the
///   iterator with a `Public` label (no information flow concern).
pub struct IterWrapper<I>(pub I);

// Inherent (high priority): Labeled<I, L> — extract inner iterator and label.
impl<T: IntoIterator, L: Label + Default> IterWrapper<Labeled<T, L>> {
    /// Strips the `Labeled` wrapper from the iterator, returning the raw iterator
    /// and a default `L` token. The macro passes the token to `join_labels` so the
    /// PC inside the loop body is raised to at least `L`. Takes priority over the
    /// trait fallback via autoref specialization.
    #[inline(always)]
    pub fn inspect_iter(mut self) -> (T::IntoIter, L) {
        (self.0.value.take().unwrap().into_iter(), L::default())
    }
}

// Trait (low priority): any plain IntoIterator — treat as Public.
pub trait IterWrapperFallback {
    type Item;
    type Iter: Iterator<Item = Self::Item>;
    /// Returns the iterator unchanged alongside a `Public` label, indicating that
    /// iterating over this collection cannot leak secret information on its own.
    fn inspect_iter(self) -> (Self::Iter, Public);
}

impl<I: IntoIterator> IterWrapperFallback for IterWrapper<I>
where
    I: InvisibleSideEffectFree,
    I::IntoIter: InvisibleSideEffectFree,
{
    type Item = I::Item;
    type Iter = I::IntoIter;
    /// Fallback for plain (non-labeled) iterators: converts to `IntoIter` and
    /// pairs it with `Public` so the PC stays unchanged inside the loop.
    /// Both `I` and its `IntoIter` must be `InvisibleSideEffectFree` to ensure
    /// that neither `into_iter()` nor `next()` can leak the secret condition.
    #[inline(always)]
    fn inspect_iter(self) -> (I::IntoIter, Public) {
        (self.0.into_iter(), Public)
    }
}

// =========================================================================
// 9. SAFE RANGE BOUNDS
// =========================================================================

/// Marker trait for range types that are safe to use as `for` loop bounds inside
/// a `pc_block`. Prevents custom range/iterator types whose `into_iter()` or
/// `next()` has side effects from leaking the secret condition that triggered
/// the loop.
///
/// Only standard library range types over `InvisibleSideEffectFree` bounds are
/// implemented here. Custom range types must implement this `unsafe` trait and
/// assert that their iteration is side-effect free.
pub unsafe trait SafeRangeBounds {}

unsafe impl<T: InvisibleSideEffectFree> SafeRangeBounds for std::ops::Range<T> {}
unsafe impl<T: InvisibleSideEffectFree> SafeRangeBounds for std::ops::RangeFrom<T> {}
unsafe impl<T: InvisibleSideEffectFree> SafeRangeBounds for std::ops::RangeTo<T> {}
unsafe impl<T: InvisibleSideEffectFree> SafeRangeBounds for std::ops::RangeInclusive<T> {}
unsafe impl SafeRangeBounds for std::ops::RangeFull {}
unsafe impl<T: InvisibleSideEffectFree> SafeRangeBounds for std::ops::RangeToInclusive<T> {}

// =========================================================================
// 10. MUTATION BAN SUPPORT (NotLabeled) + CLOSURE CAPTURE GATE
// =========================================================================

/// Implemented for every type except `Labeled<T, L>`.
/// Used by `PcVisibleSideEffectFree` to ban capturing `&mut` to plain
/// (non-Labeled) variables from outside a `pc_block!`.
pub unsafe auto trait NotLabeled {}
impl<T, L: crate::lattice::Label> !NotLabeled for crate::lattice::Labeled<T, L> {}

// ── Closure-capture gate (mirrors Cocoon's VisibleSideEffectFree) ────────────

/// Auto trait: the checking-path closure of `pc_block!` must satisfy this.
/// A closure satisfies it only if every reference it captures does too.
/// Negative impls below ban `&mut` / `*mut` to non-Labeled captures —
/// the primary write channels that could leak through a secret PC.
pub unsafe auto trait PcVisibleSideEffectFree {}

// Mutable refs/ptrs to plain (non-Labeled) types are banned — write channels.
impl<T: NotLabeled> !PcVisibleSideEffectFree for &mut T {}
impl<T: NotLabeled> !PcVisibleSideEffectFree for *mut T {}
// Interior mutability is a write channel even behind `&`. (A negative impl may
// not add bounds the struct itself lacks (E0367), so this covers every T.)
impl<T: ?Sized> !PcVisibleSideEffectFree for ::std::cell::UnsafeCell<T> {}

// Mutable refs to Labeled values are allowed — the only valid mutation targets.
// The inner type must be ISEF (Cocoon's `SecretValueSafe`), so a captured
// `Labeled<RefCell<_>, _>` cannot be mutated through shared access.
unsafe impl<T: InvisibleSideEffectFree, L: crate::lattice::Label> PcVisibleSideEffectFree
    for &mut crate::lattice::Labeled<T, L> {}
unsafe impl<T: InvisibleSideEffectFree, L: crate::lattice::Label> PcVisibleSideEffectFree
    for &mut &mut crate::lattice::Labeled<T, L> {}

// Shared (`&T`) captures need a different rule than mutable ones: reading a
// value isn't a write channel, but it can still leak via an observable Drop /
// Display / Deref on that value if the type isn't ISEF.
//
// Rust has no direct "trait NOT implemented" bound, so this uses Cocoon's
// double-negation trick. Note the `T: InvisibleSideEffectFree` bound sits on
// the *struct definition* — a negative impl may not add bounds the type itself
// doesn't declare (E0367).
struct __PcWrap<T: InvisibleSideEffectFree> {
    _pd: ::std::marker::PhantomData<T>,
}

unsafe auto trait __WrappedNotPcISEF {}
impl<T: InvisibleSideEffectFree> !__WrappedNotPcISEF for __PcWrap<T> {}

// If `__PcWrap<T>` still implements `__WrappedNotPcISEF` (i.e. T is NOT ISEF),
// then `&T` is barred from being captured.
impl<T> !PcVisibleSideEffectFree for &T where __PcWrap<T>: __WrappedNotPcISEF {}
unsafe impl<T: InvisibleSideEffectFree> PcVisibleSideEffectFree for &T {}

/// Invokes a closure, gating on `PcVisibleSideEffectFree`.
/// Used only in the checking path (the `else` branch of `if true`), so it
/// never actually runs — only the type-check matters.
pub fn call_pc_closure<F, R>(clos: F) -> R
where
    F: FnOnce() -> R + PcVisibleSideEffectFree,
{
    clos()
}

// =========================================================================
// PANIC OUTPUT SUPPRESSION INSIDE `pc_block!`
//
// A panic message can carry secret-derived data ("index out of bounds: the
// len is 3 but the index is 7"), so output is suppressed while a block runs.
// The block still aborts on panic — see `pc_block!`'s expansion for why
// recovery would leak once the PC can drop back after a branch.
//
// The hook is installed ONCE and consults a thread-local flag, rather than
// being swapped per block. Swapping `std::panic::set_hook` around every
// block mutates process-global state: two threads in `pc_block!` at once
// interleave, and one restores the other's silencing hook permanently. It
// also costs two global RwLock acquisitions and an allocation per entry,
// which is paid every iteration when a block sits inside a loop.
// =========================================================================

static PC_HOOK_INIT: ::std::sync::Once = ::std::sync::Once::new();

thread_local! {
    /// True while this thread is inside a `pc_block!`.
    static PC_SILENCE: ::std::cell::Cell<bool> = const { ::std::cell::Cell::new(false) };
}

/// Suppresses panic output on the current thread for as long as it is alive.
/// Created by `pc_block!` outside the block's closure, so it is not captured
/// and does not affect the `PcVisibleSideEffectFree` capture gate.
///
/// Note: an application that installs its own panic hook *after* the first
/// `pc_block!` has run replaces the hook below and disables suppression.
/// That is the application's choice, and it cannot re-enable a leak that the
/// abort-on-panic rule already prevents.
pub struct PanicSilencer(bool);

impl PanicSilencer {
    pub fn new() -> Self {
        PC_HOOK_INIT.call_once(|| {
            let prev = ::std::panic::take_hook();
            ::std::panic::set_hook(::std::boxed::Box::new(move |info| {
                // Inside a block: stay quiet. Outside: behave exactly as before.
                if PC_SILENCE.with(|s| s.get()) {
                    return;
                }
                prev(info);
            }));
        });
        // Save the previous value so nested blocks compose.
        Self(PC_SILENCE.with(|s| s.replace(true)))
    }
}

impl Default for PanicSilencer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PanicSilencer {
    fn drop(&mut self) {
        PC_SILENCE.with(|s| s.set(self.0));
    }
}
