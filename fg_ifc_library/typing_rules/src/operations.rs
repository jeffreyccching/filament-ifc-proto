use std::marker::PhantomData;
use std::ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Div, DivAssign, Index, IndexMut, Mul, MulAssign, Neg, Not, Rem, Shl, Shr, Sub, SubAssign};
use std::path::{Path, PathBuf};

use crate::dynamic_release::DRLabel;
use crate::implicit::InvisibleSideEffectFree;
use crate::lattice::{Join, Label, LabelComponent, Labeled};

// --- [ 1. ARITHMETIC OPERATORS ] ---
// ADDITION (+)
impl<T, L1, L2> Add<Labeled<T, L2>> for Labeled<T, L1>
where
    T: Add<Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn add(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() + rhs.value.take().unwrap())
    }
}

impl<T, L> Add<T> for Labeled<T, L>
where
    T: Add<Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn add(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() + rhs)
    }
}

// COMPOUND ASSIGNMENT OPERATORS (+=, -=, *=, /=)
// These take &mut self so they never move the Labeled value.
impl<T: AddAssign + InvisibleSideEffectFree, L: Label> AddAssign<T> for Labeled<T, L> {
    fn add_assign(&mut self, rhs: T) {
        *self.value.as_mut().unwrap() += rhs;
    }
}
impl<T: SubAssign + InvisibleSideEffectFree, L: Label> SubAssign<T> for Labeled<T, L> {
    fn sub_assign(&mut self, rhs: T) {
        *self.value.as_mut().unwrap() -= rhs;
    }
}
impl<T: MulAssign + InvisibleSideEffectFree, L: Label> MulAssign<T> for Labeled<T, L> {
    fn mul_assign(&mut self, rhs: T) {
        *self.value.as_mut().unwrap() *= rhs;
    }
}
impl<T: DivAssign + InvisibleSideEffectFree, L: Label> DivAssign<T> for Labeled<T, L> {
    fn div_assign(&mut self, rhs: T) {
        *self.value.as_mut().unwrap() /= rhs;
    }
}

// SUBTRACTION (-)
impl<T, L1, L2> Sub<Labeled<T, L2>> for Labeled<T, L1>
where
    T: Sub<Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn sub(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() - rhs.value.take().unwrap())
    }
}

impl<T, L> Sub<T> for Labeled<T, L>
where
    T: Sub<Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn sub(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() - rhs)
    }
}

// MULTIPLICATION (*)
impl<T, L1, L2> Mul<Labeled<T, L2>> for Labeled<T, L1>
where
    T: Mul<Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn mul(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() * rhs.value.take().unwrap())
    }
}

impl<T, L> Mul<T> for Labeled<T, L>
where
    T: Mul<Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn mul(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() * rhs)
    }
}

// DIVISION (/)
impl<T, L1, L2> Div<Labeled<T, L2>> for Labeled<T, L1>
where
    T: Div<Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn div(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() / rhs.value.take().unwrap())
    }
}

impl<T, L> Div<T> for Labeled<T, L>
where
    T: Div<Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn div(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() / rhs)
    }
}

// REMAINDER (%)
impl<T, L1, L2> Rem<Labeled<T, L2>> for Labeled<T, L1>
where
    T: Rem<Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn rem(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() % rhs.value.take().unwrap())
    }
}

impl<T, L> Rem<T> for Labeled<T, L>
where
    T: Rem<Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn rem(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() % rhs)
    }
}

// ARRAY INDEXING
// Safety: this cast is only valid for types where Option<T> has the same memory
// layout as T (niche-optimized types: bool, references, NonNull, etc.).
// For non-niche types (i32, u64, etc.) this is unsound and needs redesign.
impl<T, L, const N: usize> Index<usize> for Labeled<[T; N], L>
where
    L: Label,
{
    type Output = Labeled<T, L>;

    fn index(&self, index: usize) -> &Self::Output {
        let inner_ref = &self.value.as_ref().unwrap()[index];
        unsafe { &*(inner_ref as *const T as *const Labeled<T, L>) }
    }
}

impl<T, L, L2, const N: usize> Index<Labeled<usize, L2>> for Labeled<[T; N], L>
where
    L: Label,
    L2: Label,
{
    type Output = Labeled<T, L>;

    fn index(&self, index: Labeled<usize, L2>) -> &Self::Output {
        let inner_ref = &self.value.as_ref().unwrap()[*index.value.as_ref().unwrap()];
        unsafe { &*(inner_ref as *const T as *const Labeled<T, L>) }
    }
}

impl<T, L, const N: usize> IndexMut<usize> for Labeled<[T; N], L>
where
    L: Label,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let inner_mut = &mut self.value.as_mut().unwrap()[index];
        unsafe { &mut *(inner_mut as *mut T as *mut Labeled<T, L>) }
    }
}

impl<T, L, L2, const N: usize> IndexMut<Labeled<usize, L2>> for Labeled<[T; N], L>
where
    L: Label,
    L2: Label,
{
    fn index_mut(&mut self, index: Labeled<usize, L2>) -> &mut Self::Output {
        let inner_mut = &mut self.value.as_mut().unwrap()[*index.value.as_ref().unwrap()];
        unsafe { &mut *(inner_mut as *mut T as *mut Labeled<T, L>) }
    }
}

// VEC INDEXING
impl<T, L: Label> Index<usize> for Labeled<Vec<T>, L> {
    type Output = Labeled<T, L>;

    fn index(&self, index: usize) -> &Self::Output {
        let inner_ref = &self.value.as_ref().unwrap()[index];
        unsafe { &*(inner_ref as *const T as *const Labeled<T, L>) }
    }
}

impl<T, L, L2> Index<Labeled<usize, L2>> for Labeled<Vec<T>, L>
where
    L: Label,
    L2: Label,
{
    type Output = Labeled<T, L>;

    fn index(&self, index: Labeled<usize, L2>) -> &Self::Output {
        let inner_ref = &self.value.as_ref().unwrap()[*index.value.as_ref().unwrap()];
        unsafe { &*(inner_ref as *const T as *const Labeled<T, L>) }
    }
}

impl<T, L: Label> IndexMut<usize> for Labeled<Vec<T>, L> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let inner_mut = &mut self.value.as_mut().unwrap()[index];
        unsafe { &mut *(inner_mut as *mut T as *mut Labeled<T, L>) }
    }
}

impl<T, L, L2> IndexMut<Labeled<usize, L2>> for Labeled<Vec<T>, L>
where
    L: Label,
    L2: Label,
{
    fn index_mut(&mut self, index: Labeled<usize, L2>) -> &mut Self::Output {
        let inner_mut = &mut self.value.as_mut().unwrap()[*index.value.as_ref().unwrap()];
        unsafe { &mut *(inner_mut as *mut T as *mut Labeled<T, L>) }
    }
}

// BITWISE OR (|)
impl<T, L1, L2> BitOr<Labeled<T, L2>> for Labeled<T, L1>
where
    T: BitOr<Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn bitor(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() | rhs.value.take().unwrap())
    }
}

impl<T, L> BitOr<T> for Labeled<T, L>
where
    T: BitOr<Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn bitor(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() | rhs)
    }
}

// BITWISE AND (&)
impl<T, L1, L2> BitAnd<Labeled<T, L2>> for Labeled<T, L1>
where
    T: BitAnd<Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn bitand(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() & rhs.value.take().unwrap())
    }
}

impl<T, L> BitAnd<T> for Labeled<T, L>
where
    T: BitAnd<Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn bitand(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() & rhs)
    }
}

// BITWISE XOR (^)
impl<T, L1, L2> BitXor<Labeled<T, L2>> for Labeled<T, L1>
where
    T: BitXor<Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn bitxor(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() ^ rhs.value.take().unwrap())
    }
}

impl<T, L> BitXor<T> for Labeled<T, L>
where
    T: BitXor<Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn bitxor(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() ^ rhs)
    }
}

// SHIFT LEFT (<<)
impl<T, L1, L2> Shl<Labeled<T, L2>> for Labeled<T, L1>
where
    T: Shl<T, Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn shl(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() << rhs.value.take().unwrap())
    }
}

impl<T, L> Shl<T> for Labeled<T, L>
where
    T: Shl<T, Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn shl(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() << rhs)
    }
}

// SHIFT RIGHT (>>)
impl<T, L1, L2> Shr<Labeled<T, L2>> for Labeled<T, L1>
where
    T: Shr<T, Output = T>,
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<T, <L1 as Join<L2>>::Out>;

    fn shr(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() >> rhs.value.take().unwrap())
    }
}

impl<T, L> Shr<T> for Labeled<T, L>
where
    T: Shr<T, Output = T> + InvisibleSideEffectFree,
    L: Label,
{
    type Output = Labeled<T, L>;

    fn shr(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() >> rhs)
    }
}

impl<L: Label> AsRef<Path> for Labeled<PathBuf, L> {
    fn as_ref(&self) -> &Path {
        self.value.as_ref().unwrap().as_path()
    }
}

impl<T, E, L: Label> Labeled<Result<T, E>, L> {
    /// Swaps Labeled<Result<T, E>> -> Result<Labeled<T>>
    /// This allows you to use '?' on a Labeled Result.
    pub fn transpose(mut self) -> Result<Labeled<T, L>, E> {
        match self.value.take().unwrap() {
            Ok(v) => Ok(Labeled::new(v)),
            Err(e) => Err(e),
        }
    }
}

impl<T: PartialEq + InvisibleSideEffectFree, L: Label> PartialEq<T> for Labeled<T, L> {
    fn eq(&self, other: &T) -> bool {
        self.value.as_ref().unwrap() == other
    }
}

// --- LABELED COMPARISON TRAITS ---
pub trait LabeledCmp<Rhs> {
    type Output;
    fn labeled_eq(self, rhs: Rhs) -> Self::Output;
    fn labeled_ne(self, rhs: Rhs) -> Self::Output;
    fn labeled_lt(self, rhs: Rhs) -> Self::Output;
    fn labeled_gt(self, rhs: Rhs) -> Self::Output;
    fn labeled_le(self, rhs: Rhs) -> Self::Output;
    fn labeled_ge(self, rhs: Rhs) -> Self::Output;
}

impl<T: PartialEq + PartialOrd, L1, L2> LabeledCmp<Labeled<T, L2>> for Labeled<T, L1>
where
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<bool, <L1 as Join<L2>>::Out>;
    fn labeled_eq(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() == rhs.value.take().unwrap())
    }
    fn labeled_ne(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() != rhs.value.take().unwrap())
    }
    fn labeled_lt(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() < rhs.value.take().unwrap())
    }
    fn labeled_gt(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() > rhs.value.take().unwrap())
    }
    fn labeled_le(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() <= rhs.value.take().unwrap())
    }
    fn labeled_ge(mut self, mut rhs: Labeled<T, L2>) -> Self::Output {
        Labeled::new(self.value.take().unwrap() >= rhs.value.take().unwrap())
    }
}

impl<T: PartialEq + PartialOrd + InvisibleSideEffectFree, L: Label> LabeledCmp<T> for Labeled<T, L> {
    type Output = Labeled<bool, L>;
    fn labeled_eq(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() == rhs)
    }
    fn labeled_ne(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() != rhs)
    }
    fn labeled_lt(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() < rhs)
    }
    fn labeled_gt(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() > rhs)
    }
    fn labeled_le(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() <= rhs)
    }
    fn labeled_ge(mut self, rhs: T) -> Self::Output {
        Labeled::new(self.value.take().unwrap() >= rhs)
    }
}

// --- LABELED LOGICAL OPERATORS ---
pub trait LabeledAnd<Rhs> {
    type Output;
    fn labeled_and(&self, rhs: Rhs) -> Self::Output;
}

pub trait LabeledOr<Rhs> {
    type Output;
    fn labeled_or(&self, rhs: Rhs) -> Self::Output;
}

impl<L1, L2> LabeledAnd<Labeled<bool, L2>> for Labeled<bool, L1>
where
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<bool, <L1 as Join<L2>>::Out>;
    fn labeled_and(&self, rhs: Labeled<bool, L2>) -> Self::Output {
        Labeled::new(*self.value.as_ref().unwrap() && *rhs.value.as_ref().unwrap())
    }
}

impl<L: Label> LabeledAnd<bool> for Labeled<bool, L> {
    type Output = Labeled<bool, L>;
    fn labeled_and(&self, rhs: bool) -> Self::Output {
        Labeled::new(*self.value.as_ref().unwrap() && rhs)
    }
}

impl LabeledAnd<bool> for bool {
    type Output = bool;
    fn labeled_and(&self, rhs: bool) -> bool {
        *self && rhs
    }
}

impl<L1, L2> LabeledOr<Labeled<bool, L2>> for Labeled<bool, L1>
where
    L1: Label + Join<L2>,
    L2: Label,
    <L1 as Join<L2>>::Out: Label,
{
    type Output = Labeled<bool, <L1 as Join<L2>>::Out>;
    fn labeled_or(&self, rhs: Labeled<bool, L2>) -> Self::Output {
        Labeled::new(*self.value.as_ref().unwrap() || *rhs.value.as_ref().unwrap())
    }
}

impl<L: Label> LabeledOr<bool> for Labeled<bool, L> {
    type Output = Labeled<bool, L>;
    fn labeled_or(&self, rhs: bool) -> Self::Output {
        Labeled::new(*self.value.as_ref().unwrap() || rhs)
    }
}

impl LabeledOr<bool> for bool {
    type Output = bool;
    fn labeled_or(&self, rhs: bool) -> bool {
        *self || rhs
    }
}

// NEGATION (unary -)
impl<T, L> Neg for Labeled<T, L>
where
    T: Neg<Output = T>,
    L: Label,
{
    type Output = Labeled<T, L>;
    fn neg(mut self) -> Self::Output {
        Labeled::new(-self.value.take().unwrap())
    }
}

// NEGATION (!)
impl<L: Label> Not for Labeled<bool, L> {
    type Output = Labeled<bool, L>;
    fn not(mut self) -> Self::Output {
        Labeled::new(!self.value.take().unwrap())
    }
}

// PartialOrd
impl<T: PartialOrd, L: Label> PartialOrd for Labeled<T, L> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.as_ref().unwrap().partial_cmp(other.value.as_ref().unwrap())
    }
}

impl<T: PartialOrd + InvisibleSideEffectFree, L: Label> PartialOrd<T> for Labeled<T, L> {
    fn partial_cmp(&self, other: &T) -> Option<std::cmp::Ordering> {
        self.value.as_ref().unwrap().partial_cmp(other)
    }
}

// --- [ DRLABEL ARITHMETIC OPERATORS ] ---
impl<T, S, F1, F2, Rhs> Add<Rhs> for DRLabel<T, S, F1, F2>
where
    T: Add<Rhs, Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn add(self, rhs: Rhs) -> Self::Output {
        DRLabel {
            value: self.value + rhs,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2, Rhs> Sub<Rhs> for DRLabel<T, S, F1, F2>
where
    T: Sub<Rhs, Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn sub(self, rhs: Rhs) -> Self::Output {
        DRLabel {
            value: self.value - rhs,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2, Rhs> Mul<Rhs> for DRLabel<T, S, F1, F2>
where
    T: Mul<Rhs, Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn mul(self, rhs: Rhs) -> Self::Output {
        DRLabel {
            value: self.value * rhs,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2, Rhs> Div<Rhs> for DRLabel<T, S, F1, F2>
where
    T: Div<Rhs, Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn div(self, rhs: Rhs) -> Self::Output {
        DRLabel {
            value: self.value / rhs,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2, Rhs> Rem<Rhs> for DRLabel<T, S, F1, F2>
where
    T: Rem<Rhs, Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn rem(self, rhs: Rhs) -> Self::Output {
        DRLabel {
            value: self.value % rhs,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2, Rhs> BitAnd<Rhs> for DRLabel<T, S, F1, F2>
where
    T: BitAnd<Rhs, Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn bitand(self, rhs: Rhs) -> Self::Output {
        DRLabel {
            value: self.value & rhs,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2, Rhs> BitOr<Rhs> for DRLabel<T, S, F1, F2>
where
    T: BitOr<Rhs, Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn bitor(self, rhs: Rhs) -> Self::Output {
        DRLabel {
            value: self.value | rhs,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2, Rhs> BitXor<Rhs> for DRLabel<T, S, F1, F2>
where
    T: BitXor<Rhs, Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn bitxor(self, rhs: Rhs) -> Self::Output {
        DRLabel {
            value: self.value ^ rhs,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2> Neg for DRLabel<T, S, F1, F2>
where
    T: Neg<Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn neg(self) -> Self::Output {
        DRLabel {
            value: -self.value,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}

impl<T, S, F1, F2> Not for DRLabel<T, S, F1, F2>
where
    T: Not<Output = T>,
    F1: LabelComponent,
    F2: LabelComponent,
    S: 'static,
{
    type Output = DRLabel<T, S, F1, F2>;
    fn not(self) -> Self::Output {
        DRLabel {
            value: !self.value,
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
    }
}
