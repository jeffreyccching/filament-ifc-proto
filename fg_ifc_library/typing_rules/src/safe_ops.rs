// Safe* traits are ONLY called in pc_block!'s checking path (never executed).
// They take &self / &Rhs so captured variables are never moved out of the
// non-move closure that wraps the checking path.

use crate::lattice::{Join, Label, Labeled};

// ── Shared shapes ───────────────────────────────────────────────────────────
// One macro per impl *shape*, not per operator: adding an operator is a single
// invocation rather than a new copy of these bodies.

macro_rules! labeled_safe_binop_impl {
    ($tr:ident, $m:ident, $op:tt, $($t:ty)*) => ($(
        unsafe impl<L1, L2> $tr<Labeled<$t, L2>> for Labeled<$t, L1>
        where L1: Label + Join<L2>, L2: Label, <L1 as Join<L2>>::Out: Label,
        {
            type Output = Labeled<$t, <L1 as Join<L2>>::Out>;
            #[inline]
            fn $m(&self, rhs: &Labeled<$t, L2>) -> Self::Output {
                Labeled::new(*self.value.as_ref().unwrap() $op *rhs.value.as_ref().unwrap())
            }
        }
        unsafe impl<L: Label> $tr<$t> for Labeled<$t, L> {
            type Output = Labeled<$t, L>;
            #[inline]
            fn $m(&self, rhs: &$t) -> Self::Output {
                Labeled::new(*self.value.as_ref().unwrap() $op *rhs)
            }
        }
    )*)
}

macro_rules! labeled_safe_assign_impl {
    ($tr:ident, $m:ident, $op:tt, $($t:ty)*) => ($(
        unsafe impl<L: Label> $tr<$t> for Labeled<$t, L> {
            #[inline]
            fn $m(&mut self, rhs: $t) { *self.value.as_mut().unwrap() $op rhs; }
        }
    )*)
}

// ── ADDITION ────────────────────────────────────────────────────────────────

pub unsafe trait SafeAdd<Rhs = Self> {
    type Output;
    fn safe_add(&self, rhs: &Rhs) -> Self::Output;
}


labeled_safe_binop_impl!(SafeAdd, safe_add, +, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

unsafe impl<L: Label> SafeAdd<String> for Labeled<String, L> {
    type Output = Labeled<String, L>;
    #[inline]
    fn safe_add(&self, rhs: &String) -> Self::Output {
        Labeled::new(self.value.as_ref().unwrap().clone() + rhs.as_str())
    }
}

pub unsafe trait SafeAddAssign<Rhs = Self> {
    fn safe_add_assign(&mut self, rhs: Rhs);
}

labeled_safe_assign_impl!(SafeAddAssign, safe_add_assign, +=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

// ── SUBTRACTION ─────────────────────────────────────────────────────────────

pub unsafe trait SafeSub<Rhs = Self> {
    type Output;
    fn safe_sub(&self, rhs: &Rhs) -> Self::Output;
}

labeled_safe_binop_impl!(SafeSub, safe_sub, -, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

pub unsafe trait SafeSubAssign<Rhs = Self> {
    fn safe_sub_assign(&mut self, rhs: Rhs);
}

labeled_safe_assign_impl!(SafeSubAssign, safe_sub_assign, -=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

// ── MULTIPLICATION ──────────────────────────────────────────────────────────

pub unsafe trait SafeMul<Rhs = Self> {
    type Output;
    fn safe_mul(&self, rhs: &Rhs) -> Self::Output;
}

labeled_safe_binop_impl!(SafeMul, safe_mul, *, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

pub unsafe trait SafeMulAssign<Rhs = Self> {
    fn safe_mul_assign(&mut self, rhs: Rhs);
}

labeled_safe_assign_impl!(SafeMulAssign, safe_mul_assign, *=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

// ── DIVISION ────────────────────────────────────────────────────────────────

pub unsafe trait SafeDiv<Rhs = Self> {
    type Output;
    fn safe_div(&self, rhs: &Rhs) -> Self::Output;
}

labeled_safe_binop_impl!(SafeDiv, safe_div, /, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

pub unsafe trait SafeDivAssign<Rhs = Self> {
    fn safe_div_assign(&mut self, rhs: Rhs);
}

labeled_safe_assign_impl!(SafeDivAssign, safe_div_assign, /=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

// ── BITWISE AND / XOR (non-assign only) ─────────────────────────────────────

pub unsafe trait SafeBitAnd<Rhs = Self> {
    type Output;
    fn safe_bitand(&self, rhs: &Rhs) -> Self::Output;
}
macro_rules! labeled_safe_bitand_impl {
    ($($t:ty)*) => ($(
        unsafe impl<L1, L2> SafeBitAnd<Labeled<$t, L2>> for Labeled<$t, L1>
        where L1: Label + Join<L2>, L2: Label, <L1 as Join<L2>>::Out: Label,
        {
            type Output = Labeled<$t, <L1 as Join<L2>>::Out>;
            #[inline]
            fn safe_bitand(&self, rhs: &Labeled<$t, L2>) -> Self::Output {
                Labeled::new(*self.value.as_ref().unwrap() & *rhs.value.as_ref().unwrap())
            }
        }
    )*)
}
labeled_safe_bitand_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool }

pub unsafe trait SafeBitXor<Rhs = Self> {
    type Output;
    fn safe_bitxor(&self, rhs: &Rhs) -> Self::Output;
}
macro_rules! labeled_safe_bitxor_impl {
    ($($t:ty)*) => ($(
        unsafe impl<L1, L2> SafeBitXor<Labeled<$t, L2>> for Labeled<$t, L1>
        where L1: Label + Join<L2>, L2: Label, <L1 as Join<L2>>::Out: Label,
        {
            type Output = Labeled<$t, <L1 as Join<L2>>::Out>;
            #[inline]
            fn safe_bitxor(&self, rhs: &Labeled<$t, L2>) -> Self::Output {
                Labeled::new(*self.value.as_ref().unwrap() ^ *rhs.value.as_ref().unwrap())
            }
        }
    )*)
}
labeled_safe_bitxor_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool }

// ── UNARY NEG / NOT ─────────────────────────────────────────────────────────

pub unsafe trait SafeNeg {
    type Output;
    fn safe_neg(&self) -> Self::Output;
}
macro_rules! labeled_safe_neg_impl {
    ($($t:ty)*) => ($(
        unsafe impl<L: Label> SafeNeg for Labeled<$t, L> {
            type Output = Labeled<$t, L>;
            #[inline]
            fn safe_neg(&self) -> Self::Output {
                Labeled::new(-*self.value.as_ref().unwrap())
            }
        }
    )*)
}
labeled_safe_neg_impl! { isize i8 i16 i32 i64 i128 f32 f64 }

pub unsafe trait SafeNot {
    type Output;
    fn safe_not(&self) -> Self::Output;
}
macro_rules! labeled_safe_not_impl {
    ($($t:ty)*) => ($(
        unsafe impl<L: Label> SafeNot for Labeled<$t, L> {
            type Output = Labeled<$t, L>;
            #[inline]
            fn safe_not(&self) -> Self::Output {
                Labeled::new(!*self.value.as_ref().unwrap())
            }
        }
    )*)
}
labeled_safe_not_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool }

// ── COMPARISONS ─────────────────────────────────────────────────────────────

pub unsafe trait SafeCmp<Rhs = Self> {
    type BoolOut;
    fn safe_eq(&self, rhs: &Rhs) -> Self::BoolOut;
    fn safe_ne(&self, rhs: &Rhs) -> Self::BoolOut;
    fn safe_lt(&self, rhs: &Rhs) -> Self::BoolOut;
    fn safe_gt(&self, rhs: &Rhs) -> Self::BoolOut;
    fn safe_le(&self, rhs: &Rhs) -> Self::BoolOut;
    fn safe_ge(&self, rhs: &Rhs) -> Self::BoolOut;
}
macro_rules! labeled_safe_cmp_impl {
    ($($t:ty)*) => ($(
        unsafe impl<L1, L2> SafeCmp<Labeled<$t, L2>> for Labeled<$t, L1>
        where L1: Label + Join<L2>, L2: Label, <L1 as Join<L2>>::Out: Label,
        {
            type BoolOut = Labeled<bool, <L1 as Join<L2>>::Out>;
            #[inline] fn safe_eq(&self, rhs: &Labeled<$t, L2>) -> Self::BoolOut {
                Labeled::new(*self.value.as_ref().unwrap() == *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_ne(&self, rhs: &Labeled<$t, L2>) -> Self::BoolOut {
                Labeled::new(*self.value.as_ref().unwrap() != *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_lt(&self, rhs: &Labeled<$t, L2>) -> Self::BoolOut {
                Labeled::new(*self.value.as_ref().unwrap() < *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_gt(&self, rhs: &Labeled<$t, L2>) -> Self::BoolOut {
                Labeled::new(*self.value.as_ref().unwrap() > *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_le(&self, rhs: &Labeled<$t, L2>) -> Self::BoolOut {
                Labeled::new(*self.value.as_ref().unwrap() <= *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_ge(&self, rhs: &Labeled<$t, L2>) -> Self::BoolOut {
                Labeled::new(*self.value.as_ref().unwrap() >= *rhs.value.as_ref().unwrap()) }
        }
    )*)
}
labeled_safe_cmp_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64 bool char }

// ── REMAINDER, SHIFTS, BIT-OR, AND THE COMPOUND BIT/SHIFT ASSIGNS ───────────
//
// Shifts are same-type only (`u8 << u8`), as every operator here is; a
// mixed-width shift such as `u8 << u32` does not compile inside a checked
// context. Floats are excluded from shifts and bit ops, as in Rust itself.


pub unsafe trait SafeRem<Rhs = Self> {
    type Output;
    fn safe_rem(&self, rhs: &Rhs) -> Self::Output;
}
labeled_safe_binop_impl!(SafeRem, safe_rem, %, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

pub unsafe trait SafeShl<Rhs = Self> {
    type Output;
    fn safe_shl(&self, rhs: &Rhs) -> Self::Output;
}
labeled_safe_binop_impl!(SafeShl, safe_shl, <<, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128);

pub unsafe trait SafeShr<Rhs = Self> {
    type Output;
    fn safe_shr(&self, rhs: &Rhs) -> Self::Output;
}
labeled_safe_binop_impl!(SafeShr, safe_shr, >>, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128);

pub unsafe trait SafeBitOr<Rhs = Self> {
    type Output;
    fn safe_bitor(&self, rhs: &Rhs) -> Self::Output;
}
labeled_safe_binop_impl!(SafeBitOr, safe_bitor, |, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);

pub unsafe trait SafeRemAssign<Rhs = Self> { fn safe_rem_assign(&mut self, rhs: Rhs); }
labeled_safe_assign_impl!(SafeRemAssign, safe_rem_assign, %=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

pub unsafe trait SafeBitAndAssign<Rhs = Self> { fn safe_bitand_assign(&mut self, rhs: Rhs); }
labeled_safe_assign_impl!(SafeBitAndAssign, safe_bitand_assign, &=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);

pub unsafe trait SafeBitOrAssign<Rhs = Self> { fn safe_bitor_assign(&mut self, rhs: Rhs); }
labeled_safe_assign_impl!(SafeBitOrAssign, safe_bitor_assign, |=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);

pub unsafe trait SafeBitXorAssign<Rhs = Self> { fn safe_bitxor_assign(&mut self, rhs: Rhs); }
labeled_safe_assign_impl!(SafeBitXorAssign, safe_bitxor_assign, ^=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);

pub unsafe trait SafeShlAssign<Rhs = Self> { fn safe_shl_assign(&mut self, rhs: Rhs); }
labeled_safe_assign_impl!(SafeShlAssign, safe_shl_assign, <<=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128);

pub unsafe trait SafeShrAssign<Rhs = Self> { fn safe_shr_assign(&mut self, rhs: Rhs); }
labeled_safe_assign_impl!(SafeShrAssign, safe_shr_assign, >>=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128);

// ════════════════════════════════════════════════════════════════════════════
// RAW (UNLABELED) STANDARD-TYPE IMPLS
//
// Cocoon implements its Safe* operator traits "for all applicable standard
// Rust types" so that a side-effect-free context can use operators on standard
// types while any use on an application-defined type (whose operator impl could
// have a side effect) fails to compile.
//
// The Labeled impls above cover `pc_block!`, where every value is wrapped. The
// body of a `#[side_effect_free_attr]` function operates on *raw* types, so the
// checked path emitted by that macro needs these impls too.
// ════════════════════════════════════════════════════════════════════════════

macro_rules! raw_safe_binop_impl {
    ($tr:ident, $m:ident, $op:tt, $($t:ty)*) => ($(
        unsafe impl $tr<$t> for $t {
            type Output = $t;
            #[inline]
            fn $m(&self, rhs: &$t) -> $t { (*self) $op (*rhs) }
        }
    )*)
}

raw_safe_binop_impl!(SafeAdd, safe_add, +, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_binop_impl!(SafeSub, safe_sub, -, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_binop_impl!(SafeMul, safe_mul, *, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_binop_impl!(SafeDiv, safe_div, /, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_binop_impl!(SafeBitAnd, safe_bitand, &, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);
raw_safe_binop_impl!(SafeBitXor, safe_bitxor, ^, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);
raw_safe_binop_impl!(SafeRem,   safe_rem,   %, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_binop_impl!(SafeBitOr, safe_bitor, |, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);
raw_safe_binop_impl!(SafeShl,   safe_shl,  <<, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128);
raw_safe_binop_impl!(SafeShr,   safe_shr,  >>, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128);

// String concatenation (`String + &str`) — the one non-Copy std `Add` we allow.
unsafe impl SafeAdd<&str> for String {
    type Output = String;
    #[inline]
    fn safe_add(&self, rhs: &&str) -> String {
        let mut s = self.clone();
        s.push_str(rhs);
        s
    }
}

macro_rules! raw_safe_assign_impl {
    ($tr:ident, $m:ident, $op:tt, $($t:ty)*) => ($(
        unsafe impl $tr<$t> for $t {
            #[inline]
            fn $m(&mut self, rhs: $t) { *self $op rhs; }
        }
    )*)
}

raw_safe_assign_impl!(SafeAddAssign, safe_add_assign, +=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_assign_impl!(SafeSubAssign, safe_sub_assign, -=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_assign_impl!(SafeMulAssign, safe_mul_assign, *=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_assign_impl!(SafeDivAssign, safe_div_assign, /=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_assign_impl!(SafeRemAssign,    safe_rem_assign,    %=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_safe_assign_impl!(SafeBitAndAssign, safe_bitand_assign, &=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);
raw_safe_assign_impl!(SafeBitOrAssign,  safe_bitor_assign,  |=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);
raw_safe_assign_impl!(SafeBitXorAssign, safe_bitxor_assign, ^=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);
raw_safe_assign_impl!(SafeShlAssign,    safe_shl_assign,   <<=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128);
raw_safe_assign_impl!(SafeShrAssign,    safe_shr_assign,   >>=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128);

macro_rules! raw_safe_neg_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeNeg for $t {
            type Output = $t;
            #[inline]
            fn safe_neg(&self) -> $t { -(*self) }
        }
    )*)
}
raw_safe_neg_impl! { isize i8 i16 i32 i64 i128 f32 f64 }

macro_rules! raw_safe_not_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeNot for $t {
            type Output = $t;
            #[inline]
            fn safe_not(&self) -> $t { !(*self) }
        }
    )*)
}
raw_safe_not_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool }

macro_rules! raw_safe_cmp_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeCmp<$t> for $t {
            type BoolOut = bool;
            #[inline] fn safe_eq(&self, rhs: &$t) -> bool { *self == *rhs }
            #[inline] fn safe_ne(&self, rhs: &$t) -> bool { *self != *rhs }
            #[inline] fn safe_lt(&self, rhs: &$t) -> bool { *self <  *rhs }
            #[inline] fn safe_gt(&self, rhs: &$t) -> bool { *self >  *rhs }
            #[inline] fn safe_le(&self, rhs: &$t) -> bool { *self <= *rhs }
            #[inline] fn safe_ge(&self, rhs: &$t) -> bool { *self >= *rhs }
        }
    )*)
}
raw_safe_cmp_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64 bool char }

unsafe impl SafeCmp<&str> for &str {
    type BoolOut = bool;
    #[inline] fn safe_eq(&self, rhs: &&str) -> bool { *self == *rhs }
    #[inline] fn safe_ne(&self, rhs: &&str) -> bool { *self != *rhs }
    #[inline] fn safe_lt(&self, rhs: &&str) -> bool { *self <  *rhs }
    #[inline] fn safe_gt(&self, rhs: &&str) -> bool { *self >  *rhs }
    #[inline] fn safe_le(&self, rhs: &&str) -> bool { *self <= *rhs }
    #[inline] fn safe_ge(&self, rhs: &&str) -> bool { *self >= *rhs }
}

unsafe impl SafeCmp<String> for String {
    type BoolOut = bool;
    #[inline] fn safe_eq(&self, rhs: &String) -> bool { self == rhs }
    #[inline] fn safe_ne(&self, rhs: &String) -> bool { self != rhs }
    #[inline] fn safe_lt(&self, rhs: &String) -> bool { self <  rhs }
    #[inline] fn safe_gt(&self, rhs: &String) -> bool { self >  rhs }
    #[inline] fn safe_le(&self, rhs: &String) -> bool { self <= rhs }
    #[inline] fn safe_ge(&self, rhs: &String) -> bool { self >= rhs }
}

// ════════════════════════════════════════════════════════════════════════════
// MIXED LABELED / RAW OPERANDS
//
// `labeled op raw` and `raw op labeled` keep the labeled side's label. A
// labeled right-hand side of a compound assignment must flow to the target.
// ════════════════════════════════════════════════════════════════════════════

macro_rules! raw_lhs_labeled_rhs_impl {
    ($tr:ident, $m:ident, $op:tt, $($t:ty)*) => ($(
        unsafe impl<L: Label> $tr<Labeled<$t, L>> for $t {
            type Output = Labeled<$t, L>;
            #[inline]
            fn $m(&self, rhs: &Labeled<$t, L>) -> Self::Output {
                Labeled::new((*self) $op *rhs.value.as_ref().unwrap())
            }
        }
    )*)
}

raw_lhs_labeled_rhs_impl!(SafeAdd, safe_add, +, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_lhs_labeled_rhs_impl!(SafeSub, safe_sub, -, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_lhs_labeled_rhs_impl!(SafeMul, safe_mul, *, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
raw_lhs_labeled_rhs_impl!(SafeDiv, safe_div, /, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

macro_rules! labeled_lhs_raw_rhs_bit_impl {
    ($tr:ident, $m:ident, $op:tt, $($t:ty)*) => ($(
        unsafe impl<L: Label> $tr<$t> for Labeled<$t, L> {
            type Output = Labeled<$t, L>;
            #[inline]
            fn $m(&self, rhs: &$t) -> Self::Output {
                Labeled::new(*self.value.as_ref().unwrap() $op *rhs)
            }
        }
    )*)
}

labeled_lhs_raw_rhs_bit_impl!(SafeBitAnd, safe_bitand, &, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);
labeled_lhs_raw_rhs_bit_impl!(SafeBitXor, safe_bitxor, ^, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool);

macro_rules! mixed_cmp_impl {
    ($($t:ty)*) => ($(
        unsafe impl<L: Label> SafeCmp<$t> for Labeled<$t, L> {
            type BoolOut = Labeled<bool, L>;
            #[inline] fn safe_eq(&self, rhs: &$t) -> Self::BoolOut { Labeled::new(*self.value.as_ref().unwrap() == *rhs) }
            #[inline] fn safe_ne(&self, rhs: &$t) -> Self::BoolOut { Labeled::new(*self.value.as_ref().unwrap() != *rhs) }
            #[inline] fn safe_lt(&self, rhs: &$t) -> Self::BoolOut { Labeled::new(*self.value.as_ref().unwrap() <  *rhs) }
            #[inline] fn safe_gt(&self, rhs: &$t) -> Self::BoolOut { Labeled::new(*self.value.as_ref().unwrap() >  *rhs) }
            #[inline] fn safe_le(&self, rhs: &$t) -> Self::BoolOut { Labeled::new(*self.value.as_ref().unwrap() <= *rhs) }
            #[inline] fn safe_ge(&self, rhs: &$t) -> Self::BoolOut { Labeled::new(*self.value.as_ref().unwrap() >= *rhs) }
        }
        unsafe impl<L: Label> SafeCmp<Labeled<$t, L>> for $t {
            type BoolOut = Labeled<bool, L>;
            #[inline] fn safe_eq(&self, rhs: &Labeled<$t, L>) -> Self::BoolOut { Labeled::new(*self == *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_ne(&self, rhs: &Labeled<$t, L>) -> Self::BoolOut { Labeled::new(*self != *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_lt(&self, rhs: &Labeled<$t, L>) -> Self::BoolOut { Labeled::new(*self <  *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_gt(&self, rhs: &Labeled<$t, L>) -> Self::BoolOut { Labeled::new(*self >  *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_le(&self, rhs: &Labeled<$t, L>) -> Self::BoolOut { Labeled::new(*self <= *rhs.value.as_ref().unwrap()) }
            #[inline] fn safe_ge(&self, rhs: &Labeled<$t, L>) -> Self::BoolOut { Labeled::new(*self >= *rhs.value.as_ref().unwrap()) }
        }
    )*)
}
mixed_cmp_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64 bool char }

macro_rules! labeled_rhs_assign_impl {
    ($tr:ident, $m:ident, $op:tt, $($t:ty)*) => ($(
        unsafe impl<L: Label, L2: crate::lattice::LEQ<L>> $tr<Labeled<$t, L2>> for Labeled<$t, L> {
            #[inline]
            fn $m(&mut self, rhs: Labeled<$t, L2>) {
                *self.value.as_mut().unwrap() $op *rhs.value.as_ref().unwrap();
            }
        }
    )*)
}

labeled_rhs_assign_impl!(SafeAddAssign, safe_add_assign, +=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
labeled_rhs_assign_impl!(SafeSubAssign, safe_sub_assign, -=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
labeled_rhs_assign_impl!(SafeMulAssign, safe_mul_assign, *=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
labeled_rhs_assign_impl!(SafeDivAssign, safe_div_assign, /=, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
