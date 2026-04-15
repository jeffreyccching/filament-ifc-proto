use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    LazyLock, Mutex,
};

use crate::lattice::{Label, LabelComponent, Labeled, Public, LEQ};

// =========================================================================
// SecureErase — in-place memory scrubbing for T-labeled values
// =========================================================================
// Temp solution for secure erasure of sensitive data in DRLabels.

/// Trait for types that can be securely zeroed in memory.
/// Implemented for `DRLabel<V, S, T, T>` so erasure happens through
/// the label — no declassify required.
// pub trait SecureErase {
//     fn erase(&mut self);
// }

// impl SecureErase for Vec<u8> {
//     fn erase(&mut self) {
//         self.fill(0);
//         self.clear();
//     }
// }

// impl SecureErase for Vec<f64> {
//     fn erase(&mut self) {
//         self.fill(0.0);
//         self.clear();
//     }
// }

// /// Erase a T-labeled value in-place — never exposes the inner value.
// impl<V: SecureErase, S> SecureErase for DRLabel<V, S, TopLabel, TopLabel> {
//     fn erase(&mut self) {
//         self.value.erase();
//     }
// }

// =========================================================================
// Security Events
// =========================================================================

pub struct SEvent<B1> {
    pub _phantom: PhantomData<B1>,
}

#[derive(Debug, Clone, Copy)]
pub struct TrueB1;
#[derive(Debug, Clone, Copy)]
pub struct FalseB1;

pub trait Holds {
    fn holds() -> bool;
}

impl Holds for SEvent<TrueB1> {
    fn holds() -> bool {
        true
    }
}

impl Holds for SEvent<FalseB1> {
    fn holds() -> bool {
        false
    }
}

/// S ⊨ ¬s — the event does NOT hold (opposite of Holds).
pub trait NotHolds: Holds {}

impl<S> NotHolds for SEvent<S>
where
    SEvent<S>: Holds,
    SEvent<S>: sealed::IsFalse,
{
}

mod sealed {
    use super::*;
    pub trait IsFalse {}
    impl IsFalse for SEvent<FalseB1> {}
}

/// s₁ ⟹ s₂ — if event s₁ holds then event s₂ must also hold.
/// Used to encode ¬s₂ ⟹ ¬s₁ (the contrapositive).
pub trait Implies<Target> {}

impl<S> Implies<SEvent<S>> for SEvent<FalseB1> {} // false ⟹ anything
impl Implies<SEvent<TrueB1>> for SEvent<TrueB1> {} // true ⟹ true

// =========================================================================
// Global State
// =========================================================================

/// Global set S: stores `(address, was_true)` pairs for guard conditions.
/// `was_true` is always `true` at insertion time (eventon sets cond = true
/// before pushing). Stored explicitly so `output_from` (R-From-F) can verify
/// the event was genuinely fired, not just that the address is present.
pub static GUARDS: LazyLock<Mutex<Vec<(usize, bool)>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Tracks whether an output has occurred (output-per rule).
pub static OUTPUTTED: AtomicBool = AtomicBool::new(false);

/// Boolean-level type tag used to select release rules (R-From-P vs R-From-F).
pub struct ConstBool<const B: bool>;

//false for R true for D
#[allow(dead_code)]
pub struct RD<const D: bool>;
//false for to true for from
#[allow(dead_code)]
pub struct RF<const F: bool>;

// =========================================================================
// Dynamic Release Label
// =========================================================================

/// The dynamic release label wrapper.
///
/// - `T`:  the wrapped value type
/// - `S`:  security event marker (`TrueB1` or `FalseB1`)
/// - `F1`: the "from" label (before event fires)
/// - `F2`: the "to" label (after event fires)
///
/// `cond` is the runtime guard: `true` means the security event has fired.
#[derive(Debug, Clone, Copy)]
pub struct DRLabel<T, S, F1, F2> {
    pub(crate) value: T,
    pub(crate) cond: bool,
    pub(crate) s_event: PhantomData<SEvent<S>>,
    pub(crate) dynamic_label: PhantomData<DynamicLabel<F1, F2>>,
}

impl<T: PartialEq, S, F1, F2> PartialEq for DRLabel<T, S, F1, F2> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: PartialOrd, S, F1, F2> PartialOrd for DRLabel<T, S, F1, F2> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<T: Eq, S, F1, F2> Eq for DRLabel<T, S, F1, F2> {}

impl<T: Ord, S, F1, F2> Ord for DRLabel<T, S, F1, F2> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

// -------------------------------------------------------------------------
// Nested Label Support: DRLabel<(), S, F1, F2> as a LabelComponent
// -------------------------------------------------------------------------
// A DRLabel with unit value (no data, just label info) can itself appear
// in a label position. This enables nesting like:
//
//   DRLabel<T, S1, DRLabel<(), S2, Secret, Medium>, Public>
//
// which represents S1?((S2?Secret→Medium)→Public) — a two-layer
// dynamic release where each event is checked independently.
// The recursion is: F1 and F2 must themselves be LabelComponents,
// so nesting can go arbitrarily deep.
impl<S, F1, F2> LabelComponent for DRLabel<(), S, F1, F2>
where
    F1: LabelComponent,
    F2: LabelComponent,
    S: Copy + 'static,
{
}

/// Specialized impl for nested DRLabels: outer wraps inner as its value type.
/// Provides `inner_mut()` so `eventon` can be called on the inner label
/// directly, without exposing raw value access.
impl<InnerT, S1, S2, F1, F2, PfFrom, PfTo> DRLabel<DRLabel<InnerT, S2, F1, F2>, S1, PfFrom, PfTo> {
    /// Mutable access to the inner DRLabel for calling `eventon`.
    pub fn inner_mut(&mut self) -> &mut DRLabel<InnerT, S2, F1, F2> {
        &mut self.value
    }
}

impl<T, S, F1, F2> DRLabel<T, S, F1, F2> {
    /// Construct a new DRLabel. The event starts as not fired (cond = false).
    pub fn new(value: T) -> Self {
        Self {
            value,
            cond: false,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }

    /// Declassify by reference — strips the label and returns &T.
    pub fn declassify_ref(&self) -> &T {
        &self.value
    }

    /// Declassify by consuming — strips the label and returns T.
    pub fn declassify(self) -> T {
        self.value
    }

    /// Chain (owned): extracts the inner `T` and passes it to the closure by value.
    /// Used by `fcall!` for owned DRLabel arguments — the function receives `T`.
    /// Wraps `Labeled<R, Public>` result back into `DRLabel<R, S, F1, F2>`.
    #[doc(hidden)]
    pub fn __chain<R, F>(self, f: F) -> DRLabel<R, S, F1, F2>
    where
        F: FnOnce(T) -> Labeled<R, Public>,
    {
        let mut result = f(self.value);
        DRLabel {
            value: result.value.take().unwrap(),
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }

    /// Chain-ref: passes `&self` (the full DRLabel) to the closure.
    /// Used by `fcall!` for `&dr_val` reference arguments where the function
    /// takes `&DRLabel<...>` directly (e.g. receives the labeled wrapper itself).
    #[doc(hidden)]
    pub fn __chain_ref<R, F>(&self, f: F) -> DRLabel<R, S, F1, F2>
    where
        F: FnOnce(&Self) -> Labeled<R, Public>,
    {
        let mut result = f(self);
        DRLabel {
            value: result.value.take().unwrap(),
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }

    /// Returns the current runtime condition (whether the security event has fired).
    pub fn cond(&self) -> bool {
        self.cond
    }
}

// =========================================================================
// Transformation between Labeled and DRLabel
// =========================================================================

/// Lift: Labeled<T, L> → DRLabel<T, S, L, L>
/// A static label is a dynamic label where from == to (no transition).
impl<T, L: Label, S> From<Labeled<T, L>> for DRLabel<T, S, L, L> {
    fn from(mut labeled: Labeled<T, L>) -> Self {
        DRLabel {
            value: labeled.value.take().unwrap(),
            cond: false,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

/// Lower: DRLabel<T, S, L, L> → Labeled<T, L>
/// A resolved dynamic label (from == to) can be converted back to static.
impl<T, L: Label, S> From<DRLabel<T, S, L, L>> for Labeled<T, L> {
    fn from(dr: DRLabel<T, S, L, L>) -> Self {
        Labeled::new(dr.value)
    }
}

impl<T, S, L: Label> DRLabel<T, S, L, L> {
    /// Convert a resolved DRLabel (from == to) back to a static Labeled.
    pub fn to_labeled(self) -> Labeled<T, L> {
        Labeled::new(self.value)
    }
}

impl<T, L: Label> Labeled<T, L> {
    /// Lift a static Labeled into a DRLabel with no dynamic transition (from == to).
    pub fn to_dr_label<S>(mut self) -> DRLabel<T, S, L, L> {
        DRLabel {
            value: self.value.take().unwrap(),
            cond: false,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DynamicLabel<From, To> {
    pub _phantom: PhantomData<(From, To)>,
}

// =========================================================================
// Event Control
// =========================================================================

/// Activate the dynamic transition: sets `cond = true` and records the
/// guard address in the global `GUARDS` set.
pub fn eventon<T, S, F1, F2>(label: &mut DRLabel<T, S, F1, F2>) {
    let addr = &label.cond as *const bool as usize;
    let mut guards = GUARDS.lock().unwrap();
    if !guards.iter().any(|(a, _)| *a == addr) {
        guards.push((addr, true));
    }
    label.cond = true;
}

/// Deactivate the dynamic transition: sets `cond = false`.
pub fn eventoff<T, S, F1, F2>(label: &mut DRLabel<T, S, F1, F2>) {
    label.cond = false;
}

/// Activate an event using a standalone condition boolean directly.
/// Registers the address of `cond` in `GUARDS` and sets it to `true`.
/// Use this when you want to control the guard without a DRLabel wrapper.
pub fn eventon_cond(cond: &mut bool) {
    let addr = cond as *const bool as usize;
    let mut guards = GUARDS.lock().unwrap();
    if !guards.iter().any(|(a, _)| *a == addr) {
        guards.push((addr, true));
    }
    *cond = true;
}

/// Deactivate a standalone condition boolean.
pub fn eventoff_cond(cond: &mut bool) {
    *cond = false;
}

/// Returns the address of the guard condition inside a DRLabel.
/// Used to check whether a label's event has been registered in GUARDS.
pub fn guard_addr<T, S, F1, F2>(label: &DRLabel<T, S, F1, F2>) -> usize {
    &label.cond as *const bool as usize
}

// =========================================================================
// DRFlowsTo — flow rules for dynamic release labels
// =========================================================================

/// Flow checking trait for dynamic release labels.
/// Separate from the static `FlowsTo` to avoid blanket-impl conflicts.
pub trait DRFlowsTo<To> {}

/// Release checking trait for dynamic release labels.
pub trait ReleaseTo<To> {}

// =========================================================================
// ComponentFlowsTo — generalized flow check for label components
// =========================================================================
// Bridges between the static lattice (LEQ) and the dynamic label system
// (DRFlowsTo). This is what enables nesting: when a DRLabel<(), S, F1, F2>
// appears as a label component, ComponentFlowsTo dispatches to the right
// rule based on whether the source/target is static or nested.
//
// The cases are:
//   Case 1: Static → Static  (delegates to LEQ)
//   Case 2: Nested DRLabel → Static  (R-From at component level)
//   Case 3: Nested → Nested same structure (componentwise recursive)
//   Case 4: Static → Nested DRLabel  (R-To at component level)

pub trait ComponentFlowsTo<Target> {}

// Case 1: Static → Static — delegates to the lattice LEQ relation.
// This is the base case that terminates recursion for nested labels.
impl<F, T> ComponentFlowsTo<T> for F
where
    F: Label + LEQ<T>,
    T: Label,
{
}

// Case 2: Nested DRLabel → Static (R-From at component level).
// A nested dynamic label S2?F1→F2 can flow to a static label L
// when its "to" component F2 flows to L (after the inner event fires).
// F2 itself may be nested, so we use ComponentFlowsTo recursively.
impl<S2, F1, F2, L> ComponentFlowsTo<L> for DRLabel<(), S2, F1, F2>
where
    F2: ComponentFlowsTo<L>,
    F1: LabelComponent,
    L: Label,
    S2: 'static,
    SEvent<S2>: Holds,
{
}

// Case 3: Nested → Nested (componentwise check, same event structure).
// DRLabel<(), Sx, F1, F2> flows to DRLabel<(), Sx, G1, G2> when
// F1 flows to G1 and F2 flows to G2 (recursive on each component).
impl<Sx, F1, F2, G1, G2> ComponentFlowsTo<DRLabel<(), Sx, G1, G2>> for DRLabel<(), Sx, F1, F2>
where
    F1: ComponentFlowsTo<G1>,
    F2: ComponentFlowsTo<G2>,
    F1: LabelComponent,
    F2: LabelComponent,
    G1: LabelComponent,
    G2: LabelComponent,
    Sx: 'static,
{
}

// Case 4: Static → Nested DRLabel (R-To at component level).
// A static label L can flow to a nested dynamic label S2?G1→G2
// when L flows to G2 (the inner "to" label, after event fires).
impl<Sx, L, G1, G2> ComponentFlowsTo<DRLabel<(), Sx, G1, G2>> for L
where
    L: Label + ComponentFlowsTo<G2>,
    G1: LabelComponent,
    G2: LabelComponent,
    Sx: 'static,
    SEvent<Sx>: Holds,
{
}

// -------------------------------------------------------------------------
// Rule: Static → Static (generalized for nesting)
// DRLabel{F1,F2} flows to DRLabel{T1,T2} when F1 ⊑ T1 and F2 ⊑ T2.
// ComponentFlowsTo dispatches to LEQ for static labels or recurses
// for nested DRLabel components. This is the key rule that enables
// multi-level nesting like S1?((S2?AB→A)→Public).
// -------------------------------------------------------------------------
impl<F1, F2, S, T1, T2> DRFlowsTo<DRLabel<(), S, T1, T2>> for DRLabel<(), S, F1, F2>
where
    F1: ComponentFlowsTo<T1>,
    F2: ComponentFlowsTo<T2>,
    F1: LabelComponent,
    F2: LabelComponent,
    T1: LabelComponent,
    T2: LabelComponent,
    S: 'static,
{
}

// =========================================================================
// Release-to-Dynamic Rules
// =========================================================================

// -------------------------------------------------------------------------
// R-From-P: Release when cond == true (event has fired).
// The "to" label (F2/Pp) must flow to the target label L.
// P is LabelComponent since it may be a nested DRLabel (not checked here).
// -------------------------------------------------------------------------
// Need to fix release to semantics

impl<'a, T, S, P, Pp, L> ReleaseTo<DRLabel<(), S, L, L>> for (&'a DRLabel<T, S, P, Pp>, DynamicLabel<P, Pp>, ConstBool<true>)
where
    Pp: Label + LEQ<L>,
    P: LabelComponent, // Changed: may be nested DRLabel
    L: Label,
    S: 'static,
    SEvent<S>: Holds,
{
}

// -------------------------------------------------------------------------
// R-From-F: Release when cond == false (event has NOT fired).
// The "from" label (P) must flow to the target label L.
// Pp is LabelComponent since it may be a nested DRLabel (not checked here).
// -------------------------------------------------------------------------
impl<'a, T, P, Pp, L> ReleaseTo<DRLabel<(), FalseB1, L, L>> for (&'a DRLabel<T, FalseB1, P, Pp>, DynamicLabel<P, Pp>, ConstBool<false>)
where
    P: Label + LEQ<L>,
    Pp: LabelComponent,
    L: Label,
{
}

// -------------------------------------------------------------------------
// Release-Bi-LF: Bidirectional release between two dynamic labels.
// All label params are LabelComponent to support nesting.
// -------------------------------------------------------------------------
impl<S, P, Pp, Q, Qp> ReleaseTo<(DRLabel<(), S, Q, Qp>, DynamicLabel<Q, Qp>)> for (DRLabel<(), S, P, Pp>, DynamicLabel<P, Pp>)
where
    (DRLabel<(), S, P, Pp>, DynamicLabel<P, Pp>): ReleaseTo<DRLabel<(), S, Q, Qp>>,
    P: LabelComponent,  // Changed: may be nested
    Pp: LabelComponent, // Changed: may be nested
    Q: LabelComponent,  // Changed: may be nested
    Qp: LabelComponent, // Changed: may be nested
    S: 'static,
{
}

// =========================================================================
// Flows-to-Dynamic Rules
// =========================================================================

// -------------------------------------------------------------------------
// R-From: Dynamic → Static
// (DRLabel{P,Pp}, DynamicLabel{P,Pp}) flows to DRLabel{L,L} when Pp ≤ L.
// P is LabelComponent — it may be a nested DRLabel but is not checked
// (only Pp, the "to" label, matters for R-From).
// -------------------------------------------------------------------------
impl<T, S, P, Pp, L> DRFlowsTo<DRLabel<T, S, L, L>> for (DRLabel<T, S, P, Pp>, DynamicLabel<P, Pp>)
where
    Pp: Label + LEQ<L>,
    P: LabelComponent, // Changed: may be nested DRLabel
    L: Label,
    S: 'static,
    SEvent<S>: Holds,
{
}

// -------------------------------------------------------------------------
// R-To: Static → Dynamic
// DRLabel{L,L} flows to (DRLabel{Q,Qq}, DynamicLabel{Q,Qq}) when L ≤ Qq.
// Q is LabelComponent — may be nested but is not part of the LEQ check.
// -------------------------------------------------------------------------
impl<L, S, Q, Qq> DRFlowsTo<(DRLabel<(), S, Q, Qq>, DynamicLabel<Q, Qq>)> for DRLabel<(), S, L, L>
where
    L: Label + LEQ<Qq>,
    Q: LabelComponent, // Changed: may be nested DRLabel
    Qq: Label,
    S: 'static,
    SEvent<S>: Holds,
{
}

// -------------------------------------------------------------------------
// R-To Two: Dynamic → Dynamic (via R-To composition)
// All label params are LabelComponent — components may be nested DRLabels.
// -------------------------------------------------------------------------
impl<S, P, Pp, Q, Qp> DRFlowsTo<(DRLabel<(), S, Q, Qp>, DynamicLabel<Q, Qp>)> for (DRLabel<(), S, P, Pp>, DynamicLabel<P, Pp>, RD<false>, RF<false>)
where
    DRLabel<(), S, P, P>: DRFlowsTo<(DRLabel<(), S, Q, Qp>, DynamicLabel<Q, Qp>)>,
    DRLabel<(), S, Pp, Pp>: DRFlowsTo<(DRLabel<(), S, Q, Qp>, DynamicLabel<Q, Qp>)>,
    P: LabelComponent,
    Pp: LabelComponent,
    Q: LabelComponent,
    Qp: LabelComponent,
    S: 'static,
{
}

// R-From Two
// All label params are LabelComponent — components may be nested DRLabels.
impl<S, P, Pp, Q, Qp> DRFlowsTo<(DRLabel<(), S, Q, Qp>, DynamicLabel<Q, Qp>)> for (DRLabel<(), S, P, Pp>, DynamicLabel<P, Pp>, RD<false>, RF<true>)
where
    (DRLabel<(), S, P, Pp>, DynamicLabel<P, Pp>): DRFlowsTo<DRLabel<(), S, Q, Q>>,
    (DRLabel<(), S, P, Pp>, DynamicLabel<P, Pp>): DRFlowsTo<DRLabel<(), S, Qp, Qp>>,
    P: LabelComponent,
    Pp: LabelComponent,
    Q: LabelComponent,
    Qp: LabelComponent,
    S: 'static,
{
}

// -------------------------------------------------------------------------
// D-From: Dynamic → Dynamic (different events, from direction)
// S ⊨ ¬s₁, ¬s₂ ⟹ ¬s₁, ⊢ p' ⊑ s₂?q → q'
// All label params are LabelComponent — components may be nested DRLabels.
// -------------------------------------------------------------------------
impl<S1, S2, P, Pp, Q, Qp> DRFlowsTo<(DRLabel<(), S2, Q, Qp>, DynamicLabel<Q, Qp>)> for (DRLabel<(), S1, P, Pp>, DynamicLabel<P, Pp>, RD<true>, RF<true>)
where
    SEvent<S1>: NotHolds,                                                              // S ⊨ ¬s₁
    SEvent<S1>: Implies<SEvent<S2>>,                                                   // ¬s₂ ⟹ ¬s₁  (contrapositive: s₁ ⟹ s₂)
    DRLabel<(), S2, Pp, Pp>: DRFlowsTo<(DRLabel<(), S2, Q, Qp>, DynamicLabel<Q, Qp>)>, // ⊢ p' ⊑ s₂?q → q'
    P: LabelComponent,                                                                 // Changed: may be nested
    Pp: LabelComponent,                                                                // Changed: may be nested
    Q: LabelComponent,                                                                 // Changed: may be nested
    Qp: LabelComponent,                                                                // Changed: may be nested
    S1: 'static,
    S2: 'static,
{
}

// -------------------------------------------------------------------------
// D-To: Dynamic → Dynamic (different events, to direction)
// S ⊨ ¬s₂, ¬s₁ ⟹ ¬s₂, ⊢ s₁?p → p' ⊑ q'
// All label params are LabelComponent — components may be nested DRLabels.
// -------------------------------------------------------------------------
impl<S1, S2, P, Pp, Q, Qp> DRFlowsTo<(DRLabel<(), S2, Q, Qp>, DynamicLabel<Q, Qp>)> for (DRLabel<(), S1, P, Pp>, DynamicLabel<P, Pp>, RD<true>, RF<false>)
where
    SEvent<S2>: NotHolds,                                                              // S ⊨ ¬s₂
    SEvent<S2>: Implies<SEvent<S1>>,                                                   // ¬s₁ ⟹ ¬s₂  (contrapositive: s₂ ⟹ s₁)
    (DRLabel<(), S1, P, Pp>, DynamicLabel<P, Pp>): DRFlowsTo<DRLabel<(), S1, Qp, Qp>>, // ⊢ s₁?p → p' ⊑ q'
    P: LabelComponent,                                                                 // Changed: may be nested
    Pp: LabelComponent,                                                                // Changed: may be nested
    Q: LabelComponent,                                                                 // Changed: may be nested
    Qp: LabelComponent,                                                                // Changed: may be nested
    S1: 'static,
    S2: 'static,
{
}

// =========================================================================
// Assignment
// =========================================================================

impl<T, S, PfFrom, PfTo> DRLabel<T, S, PfFrom, PfTo> {
    /// Assign this label's value to a target label, checking flow at compile time.
    /// Label params are LabelComponent to support nested DRLabels.
    pub fn assign_to<TPfFrom, TPfTo>(&self, target: &mut DRLabel<T, S, TPfFrom, TPfTo>)
    where
        DRLabel<(), S, PfFrom, PfTo>: DRFlowsTo<DRLabel<(), S, TPfFrom, TPfTo>>,
        PfFrom: LabelComponent,  // Changed: may be nested
        PfTo: LabelComponent,    // Changed: may be nested
        TPfFrom: LabelComponent, // Changed: may be nested
        TPfTo: LabelComponent,   // Changed: may be nested
        S: 'static,
        T: Clone,
    {
        target.value = self.value.clone();
        target.cond = self.cond;
    }
}

// =========================================================================
// Output Functions
// =========================================================================

/// Output when the event has fired (`cond == true`). Uses R-From-P rule.
/// S is fixed to TrueB1 — the type statically proves the event has fired.
pub fn output_to<T, PfFrom, PfTo, L>(val: &DRLabel<T, TrueB1, PfFrom, PfTo>, _out: &DRLabel<(), TrueB1, L, L>, _events: &[(usize, bool)])
where
    for<'a> (&'a DRLabel<T, TrueB1, PfFrom, PfTo>, DynamicLabel<PfFrom, PfTo>, ConstBool<true>): ReleaseTo<DRLabel<(), TrueB1, L, L>>,
    T: Debug + Clone,
    PfFrom: LabelComponent,
    PfTo: Label,
    L: Label,
{
    if val.cond {
        println!("{:?}", val.value);
    } else {
        panic!("Output blocked: event has not fired");
    }
    let addr = (&val.cond as *const bool) as usize;
    GUARDS.lock().unwrap().push((addr, true));
    OUTPUTTED.store(true, Ordering::SeqCst);
}

/// Output when the event has NOT fired (`cond == false`). Uses R-From-F rule.
/// S is fixed to FalseB1 — the type statically proves the event has not fired.
///
/// Additionally enforces the historical-truth check: the guard address must
/// appear in GUARDS, meaning `eventon` was called on this label at least once
/// in the past. An event that was never turned on cannot satisfy R-From-F —
/// the "false" must represent a genuine post-fire return to false, not just
/// the initial uninitialised state.
pub fn output_from<T, PfFrom, PfTo, L>(val: &DRLabel<T, FalseB1, PfFrom, PfTo>, _out: &DRLabel<(), FalseB1, L, L>, _guards: &[(usize, bool)])
where
    for<'a> (&'a DRLabel<T, FalseB1, PfFrom, PfTo>, DynamicLabel<PfFrom, PfTo>, ConstBool<false>): ReleaseTo<DRLabel<(), FalseB1, L, L>>,
    T: Debug + Clone,
    PfFrom: Label,
    PfTo: LabelComponent,
    L: Label,
{
    let addr = (&val.cond as *const bool) as usize;
    let was_ever_true = GUARDS.lock().unwrap().iter().any(|(a, was_true)| *a == addr && *was_true);
    if val.cond {
        panic!("Output blocked: event has fired");
    } else if !was_ever_true {
        panic!("Output blocked: event was never fired (R-From-F requires prior eventon)");
    }
    println!("{:?}", val.value);
    GUARDS.lock().unwrap().push((addr, true));
    OUTPUTTED.store(true, Ordering::SeqCst);
}

/// Output-per: output gated by an external indicator boolean.
pub fn output_per<T: Debug, S, PfFrom, PfTo>(indicator: bool, val: &DRLabel<T, S, PfFrom, PfTo>) {
    if indicator {
        println!("{:?}", val.value);
    } else {
        panic!("Output blocked");
    }
}

// =========================================================================
// Relabel (Dynamic)
// =========================================================================

/// Relabel a `DRLabel` to a new static label `Lx`, going through an
/// intermediate label `Lt`. Checks both compile-time flow bounds and
/// runtime guard membership in `GUARDS`.
///
/// For nested labels, each layer's event must be in the guards set.
/// PfFrom is LabelComponent since it may be a nested DRLabel.
pub fn relabel<T, S, PfFrom, PfTo, Lt, Lx>(expr: &DRLabel<T, S, PfFrom, PfTo>, events: &[(usize, bool)]) -> DRLabel<T, S, Lx, Lx>
where
    T: Clone,
    (DRLabel<T, S, PfFrom, PfTo>, DynamicLabel<PfFrom, PfTo>): DRFlowsTo<DRLabel<T, S, Lt, Lt>>,
    DRLabel<(), S, Lt, Lt>: DRFlowsTo<DRLabel<(), S, Lx, Lx>>,
    SEvent<S>: Holds,
    PfFrom: LabelComponent, // Changed: may be nested DRLabel
    PfTo: Label,
    Lt: Label,
    Lx: Label,
    S: 'static,
{
    let secure_event_address = &expr.cond as *const bool as usize;
    let in_s_set = events.iter().any(|(a, _)| *a == secure_event_address);

    if in_s_set {
        DRLabel {
            value: expr.value.clone(),
            cond: expr.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    } else {
        panic!("Relabel failed: guard condition not in S set");
    }
}

/// Internal helper for the 3-arg `relabel!(expr, &events, Lt)` macro form.
/// Peels the inner layer of a nested DRLabel where the inner DRLabel is the
/// value type: `DRLabel<DRLabel<T,S2,F1,F2>, S1, PfFrom, PfTo>`.
/// The inner DRLabel has its own `cond` — fire it with `eventon(expr.value_mut())`
/// before calling this. Checks that the inner `cond` address is in `events`.
///
/// Not intended to be called directly. Use `relabel!(expr, &events, Lt)` instead.
#[doc(hidden)]
pub fn relabel_inner<T, S1, S2, F1, F2, PfFrom, PfTo, Lt>(expr: DRLabel<DRLabel<T, S2, F1, F2>, S1, PfFrom, PfTo>, events: &[(usize, bool)]) -> DRLabel<T, S1, Lt, PfTo>
where
    (DRLabel<T, S2, F1, F2>, DynamicLabel<F1, F2>): DRFlowsTo<DRLabel<T, S2, Lt, Lt>>,
    SEvent<S2>: Holds,
    F1: LabelComponent,
    F2: Label,
    Lt: Label,
    PfFrom: LabelComponent,
    PfTo: LabelComponent,
    S1: 'static,
    S2: 'static,
{
    let inner_addr = &expr.value.cond as *const bool as usize;
    let in_guards = events.iter().any(|(a, _)| *a == inner_addr);
    if in_guards {
        DRLabel {
            value: expr.value.value,
            cond: expr.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    } else {
        panic!("relabel_inner failed: inner event not fired");
    }
}
