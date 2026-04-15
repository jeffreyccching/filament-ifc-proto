use crate::dynamic_release::DRLabel;
use crate::lattice::*;
use std::marker::PhantomData;

// =========================================================================
//  SecureChainCombine: determines the output type of a chain step.
//
//  Both Labeled → join labels: Output = Labeled<R, OuterL Join L2>.
//  One Labeled + one DRLabel → pass DRLabel through: Output = DRLabel<R, S, F1, F2>.
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

impl<T, S, F1, F2, OuterL: Label> SecureChainCombine<OuterL> for DRLabel<T, S, F1, F2> {
    type Output = DRLabel<T, S, F1, F2>;
    fn combine(self) -> Self::Output { self }
}

impl<T, L: Label> Labeled<T, L> {
    #[doc(hidden)]
    pub fn __chain<Ret, F>(mut self, f: F) -> <Ret as SecureChainCombine<L>>::Output
    where
        Ret: SecureChainCombine<L>,
        F: FnOnce(T) -> Ret,
    {
        f(self.value.take().unwrap()).combine()
    }

    /// Like `__chain` but borrows `self`, giving the closure `&T`.
    /// Used by `fcall!` for `&expr` arguments so the label `L` is propagated.
    #[doc(hidden)]
    pub fn __chain_ref<'a, Ret, F>(&'a self, f: F) -> <Ret as SecureChainCombine<L>>::Output
    where
        Ret: SecureChainCombine<L>,
        F: FnOnce(&'a T) -> Ret,
    {
        f(self.value.as_ref().unwrap()).combine()
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
//  SecureMethodCall: trait-based mcall! dispatch for Labeled and DRLabel.
//
//  Labeled<T, L>        → __mcall returns Labeled<U, L>   (label preserved)
//  DRLabel<T, S, F1, F2> → __mcall returns DRLabel<U, S, F1, F2> (event preserved)
// =========================================================================
#[doc(hidden)]
pub trait SecureMethodCall {
    type Inner;
    type Wrapped<U>;
    fn __mcall<U, F>(&self, f: F) -> Self::Wrapped<U>
    where
        F: FnOnce(&Self::Inner) -> U;
}

impl<T, L: Label> SecureMethodCall for Labeled<T, L> {
    type Inner = T;
    type Wrapped<U> = Labeled<U, L>;
    fn __mcall<U, F>(&self, f: F) -> Labeled<U, L>
    where
        F: FnOnce(&T) -> U,
    {
        Labeled { value: Some(f(self.value.as_ref().unwrap())), _marker: PhantomData }
    }
}

impl<T, S, F1, F2> SecureMethodCall for DRLabel<T, S, F1, F2> {
    type Inner = T;
    type Wrapped<U> = DRLabel<U, S, F1, F2>;
    fn __mcall<U, F>(&self, f: F) -> DRLabel<U, S, F1, F2>
    where
        F: FnOnce(&T) -> U,
    {
        DRLabel {
            value: f(&self.value),
            cond: self.cond,
            s_event: PhantomData,
            dynamic_label: PhantomData,
        }
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
            Labeled {
                value: inner_res.value.take(),
                _marker: PhantomData,
            }
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
