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
// 6. PC BLOCK FUNCTION CALL RESULT HANDLING (Autoref Specialization)
// =========================================================================

/// Autoref specialization for handling function call results inside pc_block.
/// - For functions with #[side_effect_free_attr] that return Vetted<T>: unwraps Vetted, returns T
/// - For other functions returning raw T: wraps in Labeled<T, Public>
pub struct PcCallResult;

// High priority (inherent method): matches Vetted<T> → unwraps to T
impl PcCallResult {
    /// Unwraps a `Vetted<T>` returned by a `#[side_effect_free_attr]` function,
    /// yielding the bare `T`. Takes priority over the trait fallback because
    /// inherent methods are preferred in autoref resolution.
    pub fn wrap_result<T: InvisibleSideEffectFree>(&self, x: Vetted<T>) -> T {
        x.unwrap()
    }
}

// Low priority (trait method): matches any T → wraps in Labeled<T, Public>
pub trait PcCallResultFallback {
    /// Wraps a plain `T` returned by an ordinary (non-vetted) function call inside
    /// `Labeled<T, Public>`, treating the result as public. This is the fallback path
    /// when the function is not annotated with `#[side_effect_free_attr]`.
    fn wrap_result<T: InvisibleSideEffectFree>(&self, x: T) -> Labeled<T, Public>;
}

impl PcCallResultFallback for PcCallResult {
    /// Fallback: boxes the value as `Labeled<T, Public>` so the macro can assign it
    /// to a labeled destination with the usual flow checks.
    fn wrap_result<T: InvisibleSideEffectFree>(&self, x: T) -> Labeled<T, Public> {
        Labeled::new(x)
    }
}

// =========================================================================
// 7. PC-AWARE ISEF CHECK (Autoref Specialization)
// =========================================================================

/// PC-aware side-effect checker.
/// When PC is Public, no InvisibleSideEffectFree check is required
/// (no information leak risk in a Public context).
/// When PC is Secret (A, B, AB, etc.), InvisibleSideEffectFree is enforced.
///
/// Uses the same autoref specialization pattern as PcCallResult:
/// - PcIsef<Public> has an inherent `check<T>` (no ISEF bound) → higher priority
/// - PcIsefFallback trait has `check<T: ISEF>` → lower priority, used for non-Public PCs
pub struct PcIsef<PC: Label>(std::marker::PhantomData<PC>);

impl<PC: Label> PcIsef<PC> {
    /// Constructs a `PcIsef` token from a reference to the current PC label.
    /// The PC value itself is not stored; only its type is captured via `PhantomData`
    /// so the correct `check` overload is selected at compile time.
    #[inline(always)]
    pub fn new(_pc: &PC) -> Self {
        PcIsef(std::marker::PhantomData)
    }
}

// Public PC: no ISEF check needed (inherent method → higher priority)
impl PcIsef<Public> {
    /// Identity function with no `InvisibleSideEffectFree` bound. When the PC is
    /// `Public` there is no risk of leaking secrets through side effects, so any
    /// type is accepted. Takes priority over the trait fallback via autoref.
    #[inline(always)]
    pub fn check<T>(&self, x: T) -> T {
        x
    }
    /// Identity function that accepts macros unconditionally under a `Public` PC.
    /// When the PC is secret the trait fallback requires `MacroSideEffectFree`,
    /// which nothing implements, causing a compile error for macros like `println!`.
    #[inline(always)]
    pub fn reject_side_effecting_macro<T>(&self, x: T) -> T {
        x
    }
}

/// Marker trait that nothing implements. Used to reject side-effecting macros
/// (like println!) under a non-Public PC. The non-Public fallback trait requires
/// this bound, which always fails, producing a compile error. The Public inherent
/// method has no such bound, so it compiles fine.
pub trait MacroSideEffectFree {}

// Any PC: requires ISEF (trait method → lower priority, used for non-Public)
pub trait PcIsefFallback {
    /// Enforces `InvisibleSideEffectFree` on `T` when the PC is secret. If `T`
    /// does not implement the trait the call site fails to compile, preventing
    /// side-effecting values from leaking the secret condition.
    fn check<T: InvisibleSideEffectFree>(&self, x: T) -> T;
    /// Rejects side-effecting macros (e.g. `println!`) under a secret PC by
    /// requiring `MacroSideEffectFree`, a trait with no implementations. This
    /// makes any such macro call a compile error inside a secret branch.
    fn reject_side_effecting_macro<T: MacroSideEffectFree>(&self, x: T) -> T;
}

impl<PC: Label> PcIsefFallback for PcIsef<PC> {
    /// Passes `x` through after the `InvisibleSideEffectFree` bound is satisfied.
    #[inline(always)]
    fn check<T: InvisibleSideEffectFree>(&self, x: T) -> T {
        x
    }
    /// Passes `x` through after the `MacroSideEffectFree` bound is satisfied
    /// (which it never is — this path exists only to produce compile errors).
    #[inline(always)]
    fn reject_side_effecting_macro<T: MacroSideEffectFree>(&self, x: T) -> T {
        x
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
