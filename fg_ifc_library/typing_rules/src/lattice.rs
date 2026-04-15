use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

// LABEL TRAITS
// The core security labels used to tag data and execution contexts.
pub trait Label: Clone + Default + 'static {
    const PROTECTED: bool = false;
}

// LABEL COMPONENT TRAIT
// A label component is anything that can appear in a label position (F1/F2).
// This includes both static lattice labels (Public, A, B, AB) and nested
// dynamic release labels (DRLabel<(), S, F1, F2>). This trait enables
// multi-level nesting like S1?((S2?Secret→Medium)→Public).
//
// Every Label is automatically a LabelComponent via the blanket impl below.
pub trait LabelComponent: Clone + 'static {}

// All static labels are automatically label components.
impl<L: Label> LabelComponent for L {}

#[derive(Clone, Default)]
pub struct Public;
#[derive(Clone, Default)]
pub struct A;
#[derive(Clone, Default)]
pub struct B;
#[derive(Clone, Default)]
pub struct C;
#[derive(Clone, Default)]
pub struct AB; // Represents the Join of A and B (Top Secret / Shared)
#[derive(Clone, Default)]
pub struct AC; // Represents the Join of A and C
#[derive(Clone, Default)]
pub struct BC; // Represents the Join of B and C
#[derive(Clone, Default)]
pub struct ABC;
#[derive(Clone, Default)]
pub struct T; // Top

impl Label for Public {}
impl Label for A {}
impl Label for B {}
impl Label for C {}
impl Label for AB {}
impl Label for BC {}
impl Label for AC {}
impl Label for ABC {}
impl Label for T {
    const PROTECTED: bool = true;
}

// JOIN OPERATION
// This trait calculates the Least Upper Bound (LUB) of two labels.
// It answers: "If I combine data from L1 and L2, what is the new security level?"
pub trait Join<Other: Label>: Label {
    type Out: Label;
}

impl<L: Label> Join<L> for Public {
    type Out = L;
}

// A Joins (A + Public = A, A + B = AB)
impl Join<Public> for A {
    type Out = A;
}
impl Join<A> for A {
    type Out = A;
}
impl Join<B> for A {
    type Out = AB;
}
impl Join<AB> for A {
    type Out = AB;
}
impl Join<AC> for A {
    type Out = AC;
}
impl Join<BC> for A {
    type Out = ABC;
}
impl Join<ABC> for A {
    type Out = ABC;
}
impl Join<T> for A {
    type Out = T;
}

// B Joins (B + Public = B, B + A = AB)
impl Join<Public> for B {
    type Out = B;
}
impl Join<A> for B {
    type Out = AB;
}
impl Join<B> for B {
    type Out = B;
}

impl Join<BC> for B {
    type Out = BC;
}
impl Join<AC> for B {
    type Out = ABC;
}
impl Join<AB> for B {
    type Out = AB;
}
impl Join<ABC> for B {
    type Out = ABC;
}
impl Join<T> for B {
    type Out = T;
}

impl Join<Public> for C {
    type Out = C;
}
impl Join<C> for C {
    type Out = C;
}
impl Join<A> for C {
    type Out = AC;
}
impl Join<B> for C {
    type Out = BC;
}
impl Join<AB> for C {
    type Out = ABC;
}
impl Join<AC> for C {
    type Out = AC;
}
impl Join<BC> for C {
    type Out = BC;
}
impl Join<ABC> for C {
    type Out = ABC;
}
impl Join<T> for C {
    type Out = T;
}

// AB Joins (Top level dominates everything)
impl Join<Public> for AB {
    type Out = AB;
}
impl Join<A> for AB {
    type Out = AB;
}
impl Join<B> for AB {
    type Out = AB;
}
impl Join<AB> for AB {
    type Out = AB;
}
impl Join<AC> for AB {
    type Out = ABC;
}
impl Join<BC> for AB {
    type Out = ABC;
}
impl Join<ABC> for AB {
    type Out = ABC;
}
impl Join<T> for AB {
    type Out = T;
}

impl Join<Public> for AC {
    type Out = AC;
}
impl Join<A> for AC {
    type Out = AC;
}
impl Join<B> for AC {
    type Out = ABC;
}
impl Join<AB> for AC {
    type Out = ABC;
}
impl Join<AC> for AC {
    type Out = AC;
}
impl Join<BC> for AC {
    type Out = ABC;
}
impl Join<ABC> for AC {
    type Out = ABC;
}
impl Join<T> for AC {
    type Out = T;
}

impl Join<Public> for BC {
    type Out = BC;
}
impl Join<A> for BC {
    type Out = ABC;
}
impl Join<B> for BC {
    type Out = BC;
}
impl Join<AB> for BC {
    type Out = ABC;
}
impl Join<AC> for BC {
    type Out = ABC;
}
impl Join<BC> for BC {
    type Out = BC;
}
impl Join<ABC> for BC {
    type Out = ABC;
}
impl Join<T> for BC {
    type Out = T;
}

// T Joins (Top dominates all)
impl Join<Public> for T {
    type Out = T;
}
impl Join<A> for T {
    type Out = T;
}
impl Join<B> for T {
    type Out = T;
}
impl Join<AB> for T {
    type Out = T;
}
impl Join<C> for T {
    type Out = T;
}
impl Join<AC> for T {
    type Out = T;
}
impl Join<BC> for T {
    type Out = T;
}
impl Join<ABC> for T {
    type Out = T;
}
impl Join<T> for T {
    type Out = T;
}

// ABC Joins (ABC dominates all non-T principals)
impl Join<Public> for ABC {
    type Out = ABC;
}
impl Join<A> for ABC {
    type Out = ABC;
}
impl Join<B> for ABC {
    type Out = ABC;
}
impl Join<C> for ABC {
    type Out = ABC;
}
impl Join<AB> for ABC {
    type Out = ABC;
}
impl Join<AC> for ABC {
    type Out = ABC;
}
impl Join<BC> for ABC {
    type Out = ABC;
}
impl Join<ABC> for ABC {
    type Out = ABC;
}
impl Join<T> for ABC {
    type Out = T;
}

// --- [FLOWSTO OPERATION] ---
// Logic: "Can information flow from Self to Target?" (Self <= Target)
// This is used for Write Control (No Write Down).
pub trait LEQ<Target: Label>: Label {}

impl<L: Label> LEQ<L> for L {}

// Public flows upward to every label
impl LEQ<A> for Public {}
impl LEQ<B> for Public {}
impl LEQ<C> for Public {}
impl LEQ<AB> for Public {}
impl LEQ<AC> for Public {}
impl LEQ<BC> for Public {}
impl LEQ<ABC> for Public {}
impl LEQ<T> for Public {}

// A flows to its supersets
impl LEQ<AB> for A {}
impl LEQ<AC> for A {}
impl LEQ<ABC> for A {}
impl LEQ<T> for A {}

// B flows to its supersets
impl LEQ<AB> for B {}
impl LEQ<BC> for B {}
impl LEQ<ABC> for B {}
impl LEQ<T> for B {}

// C flows to its supersets
impl LEQ<AC> for C {}
impl LEQ<BC> for C {}
impl LEQ<ABC> for C {}
impl LEQ<T> for C {}

// AB, AC, BC flow upward
impl LEQ<ABC> for AB {}
impl LEQ<T> for AB {}
impl LEQ<ABC> for AC {}
impl LEQ<T> for AC {}
impl LEQ<ABC> for BC {}
impl LEQ<T> for BC {}

// ABC flows only to T
impl LEQ<T> for ABC {}
                      // RELABEL HELPER
                      // Used by relabel! macro to enforce LEQ when upgrading labels.
                      // Raw values are first wrapped as Labeled<T, Public> by the macro,
                      // then this function checks OldLabel: LEQ<NewLabel>.
#[doc(hidden)]
#[inline(always)]
pub fn __relabel_checked<T, OldL: Label + LEQ<NewL>, NewL: Label>(mut v: Labeled<T, OldL>) -> Labeled<T, NewL> {
    Labeled {
        value: v.value.take(),
        _marker: PhantomData,
    }
}

// Label Wrapper
// Wraps data 'T' with a security label 'L'.
// The data inside is inaccessible unless properly unwrapped.
// value is Option<T> so that Drop can safely run after the value is consumed
// (e.g. via declassify): take() replaces with None, drop() sees None and skips erasure.
#[derive(Clone)]
pub struct Labeled<T, L: Label> {
    pub(crate) value: Option<T>,
    pub(crate) _marker: PhantomData<L>,
}

impl<T, L: Label> Drop for Labeled<T, L> {
    fn drop(&mut self) {
        if L::PROTECTED {
            if let Some(ref mut v) = self.value {
                let size = std::mem::size_of::<T>();
                if size > 0 {
                    unsafe {
                        let ptr = v as *mut T as *mut u8;
                        for i in 0..size {
                            // Secure volatile write to ensure hardware-level zeroing
                            std::ptr::write_volatile(ptr.add(i), 0);
                        }
                    }
                }
            }
            // If None (already taken via declassify), nothing to erase
        }
    }
}

impl<T, L: Label> Labeled<T, L> {
    /// Internal accessor for macro-generated code. Not part of the public API.
    #[doc(hidden)]
    #[inline(always)]
    pub fn __private_value(&self) -> &T {
        self.value.as_ref().unwrap()
    }

    /// Internal mutable accessor for macro-generated code. Not part of the public API.
    #[doc(hidden)]
    #[inline(always)]
    pub fn __private_value_mut(&mut self) -> &mut T {
        self.value.as_mut().unwrap()
    }

    /// Internal consuming accessor for macro-generated code. Not part of the public API.
    #[doc(hidden)]
    #[inline(always)]
    pub fn __private_into_value(mut self) -> T {
        self.value.take().unwrap()
    }
}

// Implement PartialEq for Labeled types
impl<T: PartialEq, L: Label> PartialEq for Labeled<T, L> {
    fn eq(&self, other: &Self) -> bool {
        self.value.as_ref().unwrap() == other.value.as_ref().unwrap()
    }
}

// Implement Eq for Labeled types (needed for HashMap keys, etc.)
impl<T: Eq, L: Label> Eq for Labeled<T, L> {}

// Implement Hash for Labeled types (needed for HashMap keys, etc.)
impl<T: Hash, L: Label> Hash for Labeled<T, L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.as_ref().unwrap().hash(state);
    }
}

impl<T, L: Label> Labeled<T, L> {
    // Standard constructor
    pub fn new(value: T) -> Self {
        Self {
            value: Some(value),
            _marker: PhantomData,
        }
    }

    // Helper for references (Essential for fs::write, etc.)
    pub fn as_ref(&self) -> Labeled<&T, L> {
        Labeled {
            value: Some(self.value.as_ref().unwrap()),
            _marker: PhantomData,
        }
    }

    /// For macro use only: consume and transform the inner value while preserving label L.
    #[doc(hidden)]
    pub fn __map<R, F: FnOnce(T) -> R>(mut self, f: F) -> Labeled<R, L> {
        Labeled::new(f(self.value.take().unwrap()))
    }

    /// Declassify by reference — strips the label and returns &T.
    pub fn declassify_ref(&self) -> &T {
        self.value.as_ref().unwrap()
    }

    /// Declassify by mutable reference — strips the label and returns &mut T.
    pub fn declassify_ref_mut(&mut self) -> &mut T {
        self.value.as_mut().unwrap()
    }
}

// Helper for Labeled<Option<T>, L> — enables pattern matching without .value
impl<T, L: Label> Labeled<Option<T>, L> {
    pub fn as_option_ref(&self) -> Option<Labeled<&T, L>> {
        self.value.as_ref().unwrap().as_ref().map(|v| Labeled::new(v))
    }
}

// Implement Default for Labeled<T, L> where T implements Default
impl<T: Default, L: Label> Default for Labeled<T, L> {
    fn default() -> Self {
        Self {
            value: Some(T::default()),
            _marker: PhantomData,
        }
    }
}

// Declassification Function
// Turn a secret to public by stripping the label entirely and returning the raw value.
// take() leaves None so Drop skips erasure — intentional (caller owns the value now).
pub fn declassify<T, L: Label>(mut secret: Labeled<T, L>) -> T {
    secret.value.take().unwrap()
}

/// Convert `Labeled<Option<T>, L>` into `Option<Labeled<T, L>>`.
/// Preserves the label through an Option without declassifying.
pub fn labeled_transpose<T, L: Label>(mut lo: Labeled<Option<T>, L>) -> Option<Labeled<T, L>> {
    lo.value.take().unwrap().map(|v| Labeled::new(v))
}
