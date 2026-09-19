use crate::lattice::*;
use std::marker::PhantomData;

// =========================================================================
//  SecureChainCombine: determines the output type of a chain step.
//
//  Both Labeled → join labels: Output = Labeled<R, OuterL Join L2>.
// =========================================================================
#[doc(hidden)]
pub trait SecureChainCombine<OuterL: Label> {
    type Output;
    fn combine(self) -> Self::Output;
}

impl<T, L2, OuterL> SecureChainCombine<OuterL> for Labeled<T, L2>
where
    L2: Label,
    OuterL: Label + Join<L2>,
{
    type Output = Labeled<T, <OuterL as Join<L2>>::Out>;
    fn combine(mut self) -> Self::Output {
        Labeled { value: self.value.take(), _marker: PhantomData }
    }
}

impl<T, L: Label> Labeled<T, L> {
    #[doc(hidden)]
    pub fn __chain<Ret, F>(mut self, f: F) -> <Ret as SecureChainCombine<L>>::Output
    where
        Ret: SecureChainCombine<L>,
        F: FnOnce(T) -> Ret,
    {
        let __r = f(self.value.take().unwrap()).combine();
        <L as crate::stack_scrub::ScrubPolicy>::scrub();
        __r
    }

    /// Like `__chain` but borrows `self`, giving the closure `&T`.
    /// Used by `fcall!` for `&expr` arguments so the label `L` is propagated.
    #[doc(hidden)]
    pub fn __chain_ref<'a, Ret, F>(&'a self, f: F) -> <Ret as SecureChainCombine<L>>::Output
    where
        Ret: SecureChainCombine<L>,
        F: FnOnce(&'a T) -> Ret,
    {
        let __r = f(self.value.as_ref().unwrap()).combine();
        <L as crate::stack_scrub::ScrubPolicy>::scrub();
        __r
    }

    /// Mutable-ref chain. Used by `fcall!` for `&mut expr` arguments so the
    /// closure can mutate the inner value while the label `L` propagates.
    #[doc(hidden)]
    pub fn __chain_mut_ref<'a, Ret, F>(&'a mut self, f: F) -> <Ret as SecureChainCombine<L>>::Output
    where
        Ret: SecureChainCombine<L>,
        F: FnOnce(&'a mut T) -> Ret,
    {
        let __r = f(self.value.as_mut().unwrap()).combine();
        <L as crate::stack_scrub::ScrubPolicy>::scrub();
        __r
    }
}

// =========================================================================
//  THE TRAIT: FOR RAW VALUES (Priority #2)
// =========================================================================
// This is needed so you can pass raw '5' or '"filename"' to the macro.
#[doc(hidden)]
pub trait SecureChain<T, L: Label> {
    fn __chain<Ret, F>(self, f: F) -> <Ret as SecureChainCombine<L>>::Output
    where
        Ret: SecureChainCombine<L>,
        F: FnOnce(T) -> Ret;
}

// Blanket implementation for ANY type T that isn't caught by the inherent impl above.
// Treats the value as 'Public'.
impl<T> SecureChain<T, Public> for T
where
    T: Sized,
{
    fn __chain<Ret, F>(self, f: F) -> <Ret as SecureChainCombine<Public>>::Output
    where
        Ret: SecureChainCombine<Public>,
        F: FnOnce(T) -> Ret,
    {
        f(self).combine()
    }
}

// =========================================================================
//  CHAIN_REF TRAIT: FOR PLAIN (non-Labeled) REFERENCE ARGUMENTS
// =========================================================================
// `fcall!(func(&plain_val))` strips the `&` and calls `plain_val.chain_ref(...)`.
// For Labeled<T, L>: the inherent `chain_ref` above takes priority → label propagates.
// For any other T:   this blanket trait kicks in → treats the value as Public.
#[doc(hidden)]
pub trait SecureChainRef<T, L: Label> {
    fn __chain_ref<Ret, F>(&self, f: F) -> <Ret as SecureChainCombine<L>>::Output
    where
        Ret: SecureChainCombine<L>,
        F: FnOnce(&T) -> Ret;
}

impl<T> SecureChainRef<T, Public> for T
where
    T: Sized,
{
    fn __chain_ref<Ret, F>(&self, f: F) -> <Ret as SecureChainCombine<Public>>::Output
    where
        Ret: SecureChainCombine<Public>,
        F: FnOnce(&T) -> Ret,
    {
        f(self).combine()
    }
}

// =========================================================================
//  CHAIN_MUT_REF TRAIT: FOR PLAIN (non-Labeled) MUTABLE REFERENCE ARGUMENTS
// =========================================================================
// Mirrors `SecureChainRef` for `&mut x` plain values (treats them as Public).
#[doc(hidden)]
pub trait SecureChainMutRef<T, L: Label> {
    fn __chain_mut_ref<Ret, F>(&mut self, f: F) -> <Ret as SecureChainCombine<L>>::Output
    where
        Ret: SecureChainCombine<L>,
        F: FnOnce(&mut T) -> Ret;
}

impl<T> SecureChainMutRef<T, Public> for T
where
    T: Sized,
{
    fn __chain_mut_ref<Ret, F>(&mut self, f: F) -> <Ret as SecureChainCombine<Public>>::Output
    where
        Ret: SecureChainCombine<Public>,
        F: FnOnce(&mut T) -> Ret,
    {
        f(self).combine()
    }
}

// =========================================================================
//  __mcall — inherent methods on Labeled (not a trait).
//
//  The `mcall!` macro emits `(receiver).__mcall(|inner| ...)`; method
//  resolution finds the inherent method on the receiver type.
//  The `SecureMethodCall` trait is kept (empty marker — same name) so the
//  macro's `use SecureMethodCall as __SecureMethodCall;` import doesn't
//  break, but it's not needed for dispatch any more.
//
//  Labeled<T, L> → __mcall returns Labeled<U, L> (label preserved)
// =========================================================================
#[doc(hidden)]
pub trait SecureMethodCall {}  // no-op marker, kept for macro `use ... as` compat
impl<T, L: Label> SecureMethodCall for Labeled<T, L> {}

impl<T, L: Label> Labeled<T, L> {
    /// `&self` form. Closure receives `&T`. The `mcall!` macro emits the
    /// `__mcall_mut` form below by default; this is kept for shared-only
    /// call sites (e.g. `mcall!(msg.body.len())` where `msg: &Foo` so a
    /// `&mut` borrow isn't possible). Bypass the macro and call this method
    /// directly when that situation arises.
    #[doc(hidden)]
    pub fn __mcall<U, F>(&self, f: F) -> Labeled<U, L>
    where
        F: FnOnce(&T) -> U,
    {
        let __r = Labeled { value: Some(f(self.value.as_ref().unwrap())), _marker: PhantomData };
        <L as crate::stack_scrub::ScrubPolicy>::scrub();
        __r
    }

    /// `&mut self` form. Closure receives `&mut T`. The `mcall!` macro emits
    /// `(&mut $receiver).__mcall_mut(...)` so both `&self` stdlib methods
    /// (auto-deref `&mut T → &T`) and `&mut self` stdlib methods compile in
    /// the closure body.
    #[doc(hidden)]
    pub fn __mcall_mut<U, F>(&mut self, f: F) -> Labeled<U, L>
    where
        F: FnOnce(&mut T) -> U,
    {
        let __r = Labeled { value: Some(f(self.value.as_mut().unwrap())), _marker: PhantomData };
        <L as crate::stack_scrub::ScrubPolicy>::scrub();
        __r
    }
}

use std::future::Future;
use std::pin::Pin;

/// Async version of SecureChain: returns a boxed Future so chains can compose over async calls.
pub trait SecureAsyncChain<T, L: Label> {
    fn async_chain<R, L2, F, Fut>(self, f: F) -> Pin<Box<dyn Future<Output = Labeled<R, <L as Join<L2>>::Out>>>>
    where
        L2: Label,
        L: Join<L2>,
        F: FnOnce(T) -> Fut + 'static,
        Fut: Future<Output = Labeled<R, L2>> + 'static;
}

// Async chain inherent impl for owned Labeled
impl<T, L: Label> SecureAsyncChain<T, L> for Labeled<T, L>
where
    T: 'static,
    L: 'static,
{
    fn async_chain<R, L2, F, Fut>(mut self, f: F) -> Pin<Box<dyn Future<Output = Labeled<R, <L as Join<L2>>::Out>>>>
    where
        L2: Label,
        L: Join<L2>,
        F: FnOnce(T) -> Fut + 'static,
        Fut: Future<Output = Labeled<R, L2>> + 'static,
    {
        let val = self.value.take().unwrap();
        Box::pin(async move {
            let mut inner_res = f(val).await;
            let __r = Labeled {
                value: inner_res.value.take(),
                _marker: PhantomData,
            };
            <L as crate::stack_scrub::ScrubPolicy>::scrub();
            __r
        })
    }
}

// Async chain for raw/public values
impl<T> SecureAsyncChain<T, Public> for T
where
    T: 'static,
{
    fn async_chain<R, L2, F, Fut>(self, f: F) -> Pin<Box<dyn Future<Output = Labeled<R, <Public as Join<L2>>::Out>>>>
    where
        L2: Label,
        Public: Join<L2>,
        F: FnOnce(T) -> Fut + 'static,
        Fut: Future<Output = Labeled<R, L2>> + 'static,
    {
        Box::pin(async move {
            let mut inner_res = f(self).await;
            Labeled {
                value: inner_res.value.take(),
                _marker: PhantomData,
            }
        })
    }
}
