//! Std methods that may be called with method-call syntax inside `pc_block!`
//! (and inside the checked copy of a `#[side_effect_free_attr]` body).
//!
//! Cocoon only accepts fully qualified calls to allowlisted std functions: a
//! proc macro has no type information, so `x.len()` could resolve to an
//! application method with side effects. Here the macro instead rewrites
//! `x.len()` to `SafeLen::safe_len(&x)`. Each trait is implemented only for
//! std types, so the call compiles only when the receiver really is one of
//! them — the technique `safe_ops` uses for operators. The traits are
//! `unsafe` so application code cannot add impls for its own types.
//!
//! On a `Labeled<T, L>` receiver the result is `Labeled<_, L>`: method calls
//! keep the receiver's label. Lookups whose raw result depends on element
//! contents (`contains`, map `get`, `insert`, `remove`) require unlabeled
//! std keys (`SafeKey`) or elements with the std `==` (`SafeCmp`), otherwise
//! the raw result would reveal labeled data.

use crate::implicit::InvisibleSideEffectFree;
use crate::lattice::{Join, Label, Labeled};
use crate::safe_ops::SafeCmp;
use std::collections::{HashMap, HashSet, VecDeque};

/// Key types whose `Hash` / `Eq` are the std ones, so map and set operations
/// on them cannot run application code. Not implemented for `Labeled`.
pub unsafe trait SafeKey: Eq + std::hash::Hash {}

macro_rules! safe_key {
    ($($t:ty)*) => ($( unsafe impl SafeKey for $t {} )*)
}
safe_key! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 bool char String }
unsafe impl<'a> SafeKey for &'a str {}

// ── Trait shapes ────────────────────────────────────────────────────────────

/// `&self` method without arguments: declares the trait, forwards it through
/// `&T` / `&mut T` (auto-ref receivers), and lifts it to `Labeled` receivers.
macro_rules! ref0_trait {
    ($(#[$doc:meta])* $tr:ident, $m:ident) => {
        $(#[$doc])*
        pub unsafe trait $tr {
            type Output;
            fn $m(&self) -> Self::Output;
        }
        unsafe impl<T: $tr + ?Sized> $tr for &T {
            type Output = T::Output;
            #[inline]
            fn $m(&self) -> T::Output { <T as $tr>::$m(&**self) }
        }
        unsafe impl<T: $tr + ?Sized> $tr for &mut T {
            type Output = T::Output;
            #[inline]
            fn $m(&self) -> T::Output { <T as $tr>::$m(&**self) }
        }
        unsafe impl<T: $tr, L: Label> $tr for Labeled<T, L> {
            type Output = Labeled<T::Output, L>;
            #[inline]
            fn $m(&self) -> Self::Output {
                Labeled::new(<T as $tr>::$m(self.value.as_ref().unwrap()))
            }
        }
    };
}

/// `&'a self` method without arguments whose result borrows from `self`.
macro_rules! ref0_lt_trait {
    ($(#[$doc:meta])* $tr:ident, $m:ident) => {
        $(#[$doc])*
        pub unsafe trait $tr<'a> {
            type Output;
            fn $m(&'a self) -> Self::Output;
        }
        unsafe impl<'a, 'b: 'a, T: $tr<'a> + ?Sized + 'a> $tr<'a> for &'b T {
            type Output = T::Output;
            #[inline]
            fn $m(&'a self) -> T::Output { <T as $tr<'a>>::$m(&**self) }
        }
        unsafe impl<'a, 'b: 'a, T: $tr<'a> + ?Sized + 'a> $tr<'a> for &'b mut T {
            type Output = T::Output;
            #[inline]
            fn $m(&'a self) -> T::Output { <T as $tr<'a>>::$m(&**self) }
        }
        unsafe impl<'a, T: $tr<'a> + 'a, L: Label> $tr<'a> for Labeled<T, L> {
            type Output = Labeled<T::Output, L>;
            #[inline]
            fn $m(&'a self) -> Self::Output {
                Labeled::new(<T as $tr<'a>>::$m(self.value.as_ref().unwrap()))
            }
        }
    };
}

/// `&self` method with one argument.
macro_rules! ref1_trait {
    ($(#[$doc:meta])* $tr:ident, $m:ident) => {
        $(#[$doc])*
        pub unsafe trait $tr<A> {
            type Output;
            fn $m(&self, arg: A) -> Self::Output;
        }
        unsafe impl<A, T: $tr<A> + ?Sized> $tr<A> for &T {
            type Output = T::Output;
            #[inline]
            fn $m(&self, arg: A) -> T::Output { <T as $tr<A>>::$m(&**self, arg) }
        }
        unsafe impl<A, T: $tr<A> + ?Sized> $tr<A> for &mut T {
            type Output = T::Output;
            #[inline]
            fn $m(&self, arg: A) -> T::Output { <T as $tr<A>>::$m(&**self, arg) }
        }
    };
}

/// Lifts a `ref1_trait` to `Labeled` receivers taking a raw argument.
macro_rules! lift_ref1 {
    ($tr:ident, $m:ident) => {
        unsafe impl<A, T: $tr<A>, L: Label> $tr<A> for Labeled<T, L> {
            type Output = Labeled<T::Output, L>;
            #[inline]
            fn $m(&self, arg: A) -> Self::Output {
                Labeled::new(<T as $tr<A>>::$m(self.value.as_ref().unwrap(), arg))
            }
        }
    };
}

/// `self` method (consumes the receiver), lifted to `Labeled` receivers.
macro_rules! value_trait {
    ($(#[$doc:meta])* $tr:ident, $m:ident) => {
        $(#[$doc])*
        pub unsafe trait $tr {
            type Output;
            fn $m(self) -> Self::Output;
        }
        unsafe impl<T: $tr, L: Label> $tr for Labeled<T, L> {
            type Output = Labeled<T::Output, L>;
            #[inline]
            fn $m(self) -> Self::Output {
                let mut s = self;
                Labeled::new(<T as $tr>::$m(s.value.take().unwrap()))
            }
        }
    };
}

/// `&mut self` method returning a value, forwarded through `&mut T` and
/// lifted to `Labeled` receivers (the result keeps the label).
macro_rules! mut_trait {
    ($(#[$doc:meta])* $tr:ident, $m:ident $(, $a:ident: $A:ident)*) => {
        $(#[$doc])*
        pub unsafe trait $tr<$($A),*> {
            type Output;
            fn $m(&mut self $(, $a: $A)*) -> Self::Output;
        }
        unsafe impl<$($A,)* T: $tr<$($A),*> + ?Sized> $tr<$($A),*> for &mut T {
            type Output = T::Output;
            #[inline]
            fn $m(&mut self $(, $a: $A)*) -> T::Output { <T as $tr<$($A),*>>::$m(&mut **self $(, $a)*) }
        }
    };
}

/// `&mut self` method returning `()`, forwarded through `&mut T` and to the
/// inner value of `Labeled` receivers.
macro_rules! mut_unit_trait {
    ($(#[$doc:meta])* $tr:ident, $m:ident $(, $a:ident: $A:ident)*) => {
        $(#[$doc])*
        pub unsafe trait $tr<$($A),*> {
            fn $m(&mut self $(, $a: $A)*);
        }
        unsafe impl<$($A,)* T: $tr<$($A),*> + ?Sized> $tr<$($A),*> for &mut T {
            #[inline]
            fn $m(&mut self $(, $a: $A)*) { <T as $tr<$($A),*>>::$m(&mut **self $(, $a)*) }
        }
        unsafe impl<$($A,)* T: $tr<$($A),*>, L: Label> $tr<$($A),*> for Labeled<T, L> {
            #[inline]
            fn $m(&mut self $(, $a: $A)*) { <T as $tr<$($A),*>>::$m(self.value.as_mut().unwrap() $(, $a)*) }
        }
    };
}

/// Lifts a `mut_trait` to `Labeled` receivers (result keeps the label).
macro_rules! lift_mut {
    ($tr:ident, $m:ident $(, $a:ident: $A:ident)*) => {
        unsafe impl<$($A,)* T: $tr<$($A),*>, L: Label> $tr<$($A),*> for Labeled<T, L> {
            type Output = Labeled<T::Output, L>;
            #[inline]
            fn $m(&mut self $(, $a: $A)*) -> Self::Output {
                Labeled::new(<T as $tr<$($A),*>>::$m(self.value.as_mut().unwrap() $(, $a)*))
            }
        }
    };
}

// ── Size / emptiness ────────────────────────────────────────────────────────

ref0_trait!(SafeLen, safe_len);
ref0_trait!(SafeIsEmpty, safe_is_empty);

macro_rules! len_impls {
    ($(impl[$($g:tt)*] $t:ty;)*) => ($(
        unsafe impl<$($g)*> SafeLen for $t {
            type Output = usize;
            #[inline] fn safe_len(&self) -> usize { <$t>::len(self) }
        }
        unsafe impl<$($g)*> SafeIsEmpty for $t {
            type Output = bool;
            #[inline] fn safe_is_empty(&self) -> bool { <$t>::is_empty(self) }
        }
    )*)
}
len_impls! {
    impl[T] Vec<T>;
    impl[T] [T];
    impl[T] VecDeque<T>;
    impl[K, V] HashMap<K, V>;
    impl[T] HashSet<T>;
    impl[] String;
    impl[] str;
}

// ── Option / Result inspection ──────────────────────────────────────────────

ref0_trait!(SafeIsSome, safe_is_some);
ref0_trait!(SafeIsNone, safe_is_none);
ref0_trait!(SafeIsOk, safe_is_ok);
ref0_trait!(SafeIsErr, safe_is_err);

unsafe impl<T> SafeIsSome for Option<T> {
    type Output = bool;
    #[inline] fn safe_is_some(&self) -> bool { Option::is_some(self) }
}
unsafe impl<T> SafeIsNone for Option<T> {
    type Output = bool;
    #[inline] fn safe_is_none(&self) -> bool { Option::is_none(self) }
}
unsafe impl<T, E> SafeIsOk for Result<T, E> {
    type Output = bool;
    #[inline] fn safe_is_ok(&self) -> bool { Result::is_ok(self) }
}
unsafe impl<T, E> SafeIsErr for Result<T, E> {
    type Output = bool;
    #[inline] fn safe_is_err(&self) -> bool { Result::is_err(self) }
}

// ── Cloning and conversions ─────────────────────────────────────────────────

ref0_trait!(SafeClone, safe_clone);
ref0_trait!(SafeToString, safe_to_string);
ref0_trait!(SafeToOwned, safe_to_owned);
ref0_trait!(SafeToVec, safe_to_vec);

macro_rules! prim_clone_to_string {
    ($($t:ty)*) => ($(
        unsafe impl SafeClone for $t {
            type Output = $t;
            #[inline] fn safe_clone(&self) -> $t { *self }
        }
        unsafe impl SafeToString for $t {
            type Output = String;
            #[inline] fn safe_to_string(&self) -> String { ToString::to_string(self) }
        }
    )*)
}
prim_clone_to_string! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64 bool char }

unsafe impl SafeClone for String {
    type Output = String;
    #[inline] fn safe_clone(&self) -> String { String::clone(self) }
}
unsafe impl<T: SafeClone<Output = T>> SafeClone for Vec<T> {
    type Output = Vec<T>;
    #[inline] fn safe_clone(&self) -> Vec<T> { self.iter().map(<T as SafeClone>::safe_clone).collect() }
}
unsafe impl<T: SafeClone<Output = T>> SafeClone for Option<T> {
    type Output = Option<T>;
    #[inline] fn safe_clone(&self) -> Option<T> { self.as_ref().map(<T as SafeClone>::safe_clone) }
}

unsafe impl SafeToString for String {
    type Output = String;
    #[inline] fn safe_to_string(&self) -> String { String::clone(self) }
}
unsafe impl SafeToString for str {
    type Output = String;
    #[inline] fn safe_to_string(&self) -> String { String::from(self) }
}

unsafe impl SafeToOwned for str {
    type Output = String;
    #[inline] fn safe_to_owned(&self) -> String { String::from(self) }
}
unsafe impl SafeToOwned for String {
    type Output = String;
    #[inline] fn safe_to_owned(&self) -> String { String::clone(self) }
}
unsafe impl<T: SafeClone<Output = T>> SafeToOwned for [T] {
    type Output = Vec<T>;
    #[inline] fn safe_to_owned(&self) -> Vec<T> { self.iter().map(<T as SafeClone>::safe_clone).collect() }
}

unsafe impl<T: SafeClone<Output = T>> SafeToVec for [T] {
    type Output = Vec<T>;
    #[inline] fn safe_to_vec(&self) -> Vec<T> { self.iter().map(<T as SafeClone>::safe_clone).collect() }
}
unsafe impl<T: SafeClone<Output = T>> SafeToVec for Vec<T> {
    type Output = Vec<T>;
    #[inline] fn safe_to_vec(&self) -> Vec<T> { self.iter().map(<T as SafeClone>::safe_clone).collect() }
}

// ── Numeric helpers ─────────────────────────────────────────────────────────

ref0_trait!(SafeAbs, safe_abs);
ref0_trait!(SafeSqrt, safe_sqrt);

macro_rules! abs_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeAbs for $t {
            type Output = $t;
            #[inline] fn safe_abs(&self) -> $t { <$t>::abs(*self) }
        }
    )*)
}
abs_impl! { isize i8 i16 i32 i64 i128 f32 f64 }

unsafe impl SafeSqrt for f32 {
    type Output = f32;
    #[inline] fn safe_sqrt(&self) -> f32 { f32::sqrt(*self) }
}
unsafe impl SafeSqrt for f64 {
    type Output = f64;
    #[inline] fn safe_sqrt(&self) -> f64 { f64::sqrt(*self) }
}

ref1_trait!(SafePow, safe_pow);
lift_ref1!(SafePow, safe_pow);

macro_rules! pow_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafePow<u32> for $t {
            type Output = $t;
            #[inline] fn safe_pow(&self, exp: u32) -> $t { <$t>::pow(*self, exp) }
        }
    )*)
}
pow_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 }

ref1_trait!(SafeMin, safe_min);
ref1_trait!(SafeMax, safe_max);

macro_rules! minmax_impl {
    ($tr:ident, $m:ident, $f:ident, $($t:ty)*) => ($(
        unsafe impl $tr<$t> for $t {
            type Output = $t;
            #[inline] fn $m(&self, rhs: $t) -> $t { <$t>::$f(*self, rhs) }
        }
        unsafe impl<L: Label> $tr<$t> for Labeled<$t, L> {
            type Output = Labeled<$t, L>;
            #[inline] fn $m(&self, rhs: $t) -> Self::Output {
                Labeled::new(<$t>::$f(*self.value.as_ref().unwrap(), rhs))
            }
        }
        unsafe impl<L: Label> $tr<Labeled<$t, L>> for $t {
            type Output = Labeled<$t, L>;
            #[inline] fn $m(&self, rhs: Labeled<$t, L>) -> Self::Output {
                Labeled::new(<$t>::$f(*self, *rhs.value.as_ref().unwrap()))
            }
        }
        unsafe impl<L1, L2> $tr<Labeled<$t, L2>> for Labeled<$t, L1>
        where L1: Label + Join<L2>, L2: Label, <L1 as Join<L2>>::Out: Label,
        {
            type Output = Labeled<$t, <L1 as Join<L2>>::Out>;
            #[inline] fn $m(&self, rhs: Labeled<$t, L2>) -> Self::Output {
                Labeled::new(<$t>::$f(*self.value.as_ref().unwrap(), *rhs.value.as_ref().unwrap()))
            }
        }
    )*)
}
minmax_impl!(SafeMin, safe_min, min, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);
minmax_impl!(SafeMax, safe_max, max, usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64);

// ── Lookups ─────────────────────────────────────────────────────────────────

/// `get(index)` / `get(&key)`. The result borrows from the receiver.
pub unsafe trait SafeGet<'a, I> {
    type Output;
    fn safe_get(&'a self, index: I) -> Self::Output;
}
unsafe impl<'a, 'b: 'a, I, C: SafeGet<'a, I> + ?Sized + 'a> SafeGet<'a, I> for &'b C {
    type Output = C::Output;
    #[inline] fn safe_get(&'a self, index: I) -> C::Output { <C as SafeGet<'a, I>>::safe_get(&**self, index) }
}
unsafe impl<'a, 'b: 'a, I, C: SafeGet<'a, I> + ?Sized + 'a> SafeGet<'a, I> for &'b mut C {
    type Output = C::Output;
    #[inline] fn safe_get(&'a self, index: I) -> C::Output { <C as SafeGet<'a, I>>::safe_get(&**self, index) }
}
unsafe impl<'a, I, C: SafeGet<'a, I> + 'a, L: Label> SafeGet<'a, I> for Labeled<C, L> {
    type Output = Labeled<C::Output, L>;
    #[inline] fn safe_get(&'a self, index: I) -> Self::Output {
        Labeled::new(<C as SafeGet<'a, I>>::safe_get(self.value.as_ref().unwrap(), index))
    }
}
unsafe impl<'a, T: 'a> SafeGet<'a, usize> for Vec<T> {
    type Output = Option<&'a T>;
    #[inline] fn safe_get(&'a self, index: usize) -> Option<&'a T> { <[T]>::get(self, index) }
}
unsafe impl<'a, T: 'a> SafeGet<'a, usize> for [T] {
    type Output = Option<&'a T>;
    #[inline] fn safe_get(&'a self, index: usize) -> Option<&'a T> { <[T]>::get(self, index) }
}
unsafe impl<'a, 'k, K: SafeKey + 'a, V: 'a> SafeGet<'a, &'k K> for HashMap<K, V> {
    type Output = Option<&'a V>;
    #[inline] fn safe_get(&'a self, key: &'k K) -> Option<&'a V> { HashMap::get(self, key) }
}
unsafe impl<'a, 'k, V: 'a> SafeGet<'a, &'k str> for HashMap<String, V> {
    type Output = Option<&'a V>;
    #[inline] fn safe_get(&'a self, key: &'k str) -> Option<&'a V> { HashMap::get(self, key) }
}

ref1_trait!(SafeContains, safe_contains);
lift_ref1!(SafeContains, safe_contains);

unsafe impl<'q, T: SafeCmp<T, BoolOut = bool>> SafeContains<&'q T> for Vec<T> {
    type Output = bool;
    #[inline] fn safe_contains(&self, x: &'q T) -> bool { self.iter().any(|e| SafeCmp::safe_eq(e, x)) }
}
unsafe impl<'q, T: SafeCmp<T, BoolOut = bool>> SafeContains<&'q T> for [T] {
    type Output = bool;
    #[inline] fn safe_contains(&self, x: &'q T) -> bool { self.iter().any(|e| SafeCmp::safe_eq(e, x)) }
}
unsafe impl<'q, T: SafeKey> SafeContains<&'q T> for HashSet<T> {
    type Output = bool;
    #[inline] fn safe_contains(&self, x: &'q T) -> bool { HashSet::contains(self, x) }
}
unsafe impl<'q> SafeContains<&'q str> for String {
    type Output = bool;
    #[inline] fn safe_contains(&self, x: &'q str) -> bool { str::contains(self, x) }
}
unsafe impl<'q> SafeContains<&'q str> for str {
    type Output = bool;
    #[inline] fn safe_contains(&self, x: &'q str) -> bool { str::contains(self, x) }
}

ref1_trait!(SafeContainsKey, safe_contains_key);
lift_ref1!(SafeContainsKey, safe_contains_key);

unsafe impl<'q, K: SafeKey, V> SafeContainsKey<&'q K> for HashMap<K, V> {
    type Output = bool;
    #[inline] fn safe_contains_key(&self, key: &'q K) -> bool { HashMap::contains_key(self, key) }
}
unsafe impl<'q, V> SafeContainsKey<&'q str> for HashMap<String, V> {
    type Output = bool;
    #[inline] fn safe_contains_key(&self, key: &'q str) -> bool { HashMap::contains_key(self, key) }
}

// ── Iteration and borrowing views ───────────────────────────────────────────

ref0_lt_trait!(SafeIter, safe_iter);
ref0_lt_trait!(SafeChars, safe_chars);
ref0_lt_trait!(SafeBytes, safe_bytes);
ref0_lt_trait!(SafeAsStr, safe_as_str);

unsafe impl<'a, T: 'a> SafeIter<'a> for Vec<T> {
    type Output = std::slice::Iter<'a, T>;
    #[inline] fn safe_iter(&'a self) -> Self::Output { <[T]>::iter(self) }
}
unsafe impl<'a, T: 'a> SafeIter<'a> for [T] {
    type Output = std::slice::Iter<'a, T>;
    #[inline] fn safe_iter(&'a self) -> Self::Output { <[T]>::iter(self) }
}
unsafe impl<'a, T: 'a, const N: usize> SafeIter<'a> for [T; N] {
    type Output = std::slice::Iter<'a, T>;
    #[inline] fn safe_iter(&'a self) -> Self::Output { <[T]>::iter(self) }
}
unsafe impl<'a> SafeChars<'a> for str {
    type Output = std::str::Chars<'a>;
    #[inline] fn safe_chars(&'a self) -> Self::Output { str::chars(self) }
}
unsafe impl<'a> SafeChars<'a> for String {
    type Output = std::str::Chars<'a>;
    #[inline] fn safe_chars(&'a self) -> Self::Output { str::chars(self) }
}
unsafe impl<'a> SafeBytes<'a> for str {
    type Output = std::str::Bytes<'a>;
    #[inline] fn safe_bytes(&'a self) -> Self::Output { str::bytes(self) }
}
unsafe impl<'a> SafeBytes<'a> for String {
    type Output = std::str::Bytes<'a>;
    #[inline] fn safe_bytes(&'a self) -> Self::Output { str::bytes(self) }
}
unsafe impl<'a> SafeAsStr<'a> for String {
    type Output = &'a str;
    #[inline] fn safe_as_str(&'a self) -> &'a str { String::as_str(self) }
}

value_trait!(SafeIntoIter, safe_into_iter);

unsafe impl<T> SafeIntoIter for Vec<T> {
    type Output = std::vec::IntoIter<T>;
    #[inline] fn safe_into_iter(self) -> Self::Output { IntoIterator::into_iter(self) }
}
unsafe impl<'a, T> SafeIntoIter for &'a Vec<T> {
    type Output = std::slice::Iter<'a, T>;
    #[inline] fn safe_into_iter(self) -> Self::Output { <[T]>::iter(self) }
}
unsafe impl<'a, T> SafeIntoIter for &'a [T] {
    type Output = std::slice::Iter<'a, T>;
    #[inline] fn safe_into_iter(self) -> Self::Output { <[T]>::iter(self) }
}

// ── Unwrapping (panics abort the process inside pc_block!) ──────────────────

value_trait!(SafeUnwrap, safe_unwrap);
value_trait!(SafeUnwrapOrDefault, safe_unwrap_or_default);

unsafe impl<T> SafeUnwrap for Option<T> {
    type Output = T;
    #[inline] fn safe_unwrap(self) -> T {
        match self {
            Some(v) => v,
            None => panic!("called `unwrap()` on a `None` value"),
        }
    }
}
unsafe impl<T, E> SafeUnwrap for Result<T, E> {
    type Output = T;
    // Matches instead of calling `Result::unwrap`, which would run `E`'s
    // `Debug` impl (possibly application code) to build the panic message.
    #[inline] fn safe_unwrap(self) -> T {
        match self {
            Ok(v) => v,
            Err(_) => panic!("called `unwrap()` on an `Err` value"),
        }
    }
}
// `helper(x).unwrap()` on a `#[side_effect_free_attr]` result.
unsafe impl<T: InvisibleSideEffectFree> SafeUnwrap for crate::implicit::Vetted<T> {
    type Output = T;
    #[inline] fn safe_unwrap(self) -> T { self.unwrap() }
}

unsafe impl<T: Default + InvisibleSideEffectFree> SafeUnwrapOrDefault for Option<T> {
    type Output = T;
    #[inline] fn safe_unwrap_or_default(self) -> T { Option::unwrap_or_default(self) }
}
unsafe impl<T: Default + InvisibleSideEffectFree, E> SafeUnwrapOrDefault for Result<T, E> {
    type Output = T;
    #[inline] fn safe_unwrap_or_default(self) -> T {
        match self {
            Ok(v) => v,
            Err(_) => T::default(),
        }
    }
}

/// `unwrap_or(default)`; on a `Labeled` receiver the default is raw.
pub unsafe trait SafeUnwrapOr<D> {
    type Output;
    fn safe_unwrap_or(self, default: D) -> Self::Output;
}
unsafe impl<T> SafeUnwrapOr<T> for Option<T> {
    type Output = T;
    #[inline] fn safe_unwrap_or(self, default: T) -> T { Option::unwrap_or(self, default) }
}
unsafe impl<T, E> SafeUnwrapOr<T> for Result<T, E> {
    type Output = T;
    #[inline] fn safe_unwrap_or(self, default: T) -> T {
        match self {
            Ok(v) => v,
            Err(_) => default,
        }
    }
}
unsafe impl<D, C: SafeUnwrapOr<D>, L: Label> SafeUnwrapOr<D> for Labeled<C, L> {
    type Output = Labeled<C::Output, L>;
    #[inline] fn safe_unwrap_or(self, default: D) -> Self::Output {
        let mut s = self;
        Labeled::new(<C as SafeUnwrapOr<D>>::safe_unwrap_or(s.value.take().unwrap(), default))
    }
}

// ── Mutation (the receiver goes through the macro's PC write guard) ─────────

mut_unit_trait!(SafePush, safe_push, x: X);
mut_unit_trait!(SafeClear, safe_clear);

unsafe impl<T> SafePush<T> for Vec<T> {
    #[inline] fn safe_push(&mut self, x: T) { Vec::push(self, x) }
}
unsafe impl SafePush<char> for String {
    #[inline] fn safe_push(&mut self, x: char) { String::push(self, x) }
}
unsafe impl<T> SafeClear for Vec<T> {
    #[inline] fn safe_clear(&mut self) { Vec::clear(self) }
}
unsafe impl<T> SafeClear for VecDeque<T> {
    #[inline] fn safe_clear(&mut self) { VecDeque::clear(self) }
}
unsafe impl SafeClear for String {
    #[inline] fn safe_clear(&mut self) { String::clear(self) }
}
unsafe impl<K, V> SafeClear for HashMap<K, V> {
    #[inline] fn safe_clear(&mut self) { HashMap::clear(self) }
}
unsafe impl<T> SafeClear for HashSet<T> {
    #[inline] fn safe_clear(&mut self) { HashSet::clear(self) }
}

mut_trait!(SafePop, safe_pop);
lift_mut!(SafePop, safe_pop);

unsafe impl<T> SafePop for Vec<T> {
    type Output = Option<T>;
    #[inline] fn safe_pop(&mut self) -> Option<T> { Vec::pop(self) }
}
unsafe impl SafePop for String {
    type Output = Option<char>;
    #[inline] fn safe_pop(&mut self) -> Option<char> { String::pop(self) }
}

mut_trait!(SafeInsert1, safe_insert, x: X);
lift_mut!(SafeInsert1, safe_insert, x: X);

unsafe impl<T: SafeKey> SafeInsert1<T> for HashSet<T> {
    type Output = bool;
    #[inline] fn safe_insert(&mut self, x: T) -> bool { HashSet::insert(self, x) }
}

mut_trait!(SafeInsert2, safe_insert, a: A, b: B);

unsafe impl<T> SafeInsert2<usize, T> for Vec<T> {
    type Output = ();
    #[inline] fn safe_insert(&mut self, index: usize, x: T) { Vec::insert(self, index, x) }
}
unsafe impl<K: SafeKey, V> SafeInsert2<K, V> for HashMap<K, V> {
    type Output = Option<V>;
    #[inline] fn safe_insert(&mut self, key: K, value: V) -> Option<V> { HashMap::insert(self, key, value) }
}
// Labeled receivers: `Vec::insert` returns `()`, so it is forwarded rather
// than lifted (a `Labeled<(), L>` would not fit statement position).
unsafe impl<T, L: Label> SafeInsert2<usize, T> for Labeled<Vec<T>, L> {
    type Output = ();
    #[inline] fn safe_insert(&mut self, index: usize, x: T) { Vec::insert(self.value.as_mut().unwrap(), index, x) }
}
unsafe impl<K: SafeKey, V, L: Label> SafeInsert2<K, V> for Labeled<HashMap<K, V>, L> {
    type Output = Labeled<Option<V>, L>;
    #[inline] fn safe_insert(&mut self, key: K, value: V) -> Self::Output {
        Labeled::new(HashMap::insert(self.value.as_mut().unwrap(), key, value))
    }
}

mut_trait!(SafeRemove, safe_remove, x: X);
lift_mut!(SafeRemove, safe_remove, x: X);

unsafe impl<T> SafeRemove<usize> for Vec<T> {
    type Output = T;
    #[inline] fn safe_remove(&mut self, index: usize) -> T { Vec::remove(self, index) }
}
unsafe impl<'q, K: SafeKey, V> SafeRemove<&'q K> for HashMap<K, V> {
    type Output = Option<V>;
    #[inline] fn safe_remove(&mut self, key: &'q K) -> Option<V> { HashMap::remove(self, key) }
}
unsafe impl<'q, T: SafeKey> SafeRemove<&'q T> for HashSet<T> {
    type Output = bool;
    #[inline] fn safe_remove(&mut self, x: &'q T) -> bool { HashSet::remove(self, x) }
}
