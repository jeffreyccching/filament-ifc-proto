//! `#[side_effect_free_attr]` — Cocoon's `#[side_effect_free_attr]`
//! (Fig. 4b) and `#[derive(InvisibleSideEffectFree)]` (Fig. 3f).
//!
//! On a function it follows Cocoon's layout:
//!
//! ```text
//! unsafe fn f(args) -> Vetted<R> {
//!     fn __f_secret_trampoline_unchecked(params) -> R { <body> }          // runs
//!     fn __f_secret_trampoline_checked(params) -> R { <checked copy> }    // never runs
//!     Vetted::wrap(__f_secret_trampoline_unchecked(args))
//! }
//! ```
//!
//! `f` is an `unsafe fn`, so code that is not itself checked can obtain a
//! `Vetted` only by writing `unsafe` (audited). Otherwise an unchecked
//! function could call a checked one and return its `Vetted`, passing off its
//! own side effects. The body lives in the nested safe functions, so it does
//! not run in an unsafe context.
//!
//! The checked copy is Cocoon's τ(body, F): calls must reach another
//! side-effect-free function or an allowlisted std function, operators and
//! methods go through the `safe_ops` / `safe_methods` whitelists, values read
//! must be `InvisibleSideEffectFree`, and macros are rejected. There is no PC
//! here: a function, unlike a closure, reaches outside memory only through
//! its parameters (Cocoon §4.2.2). In the executed copy (τ(body, T)) each
//! call to another side-effect-free function becomes
//! `Vetted::unwrap(unsafe { f(..) })`, so bodies call each other as `f(x)`.
//!
//! On a struct or enum it implements `InvisibleSideEffectFree`, requiring
//! every field type to be ISEF and the type to have no custom `Drop` or
//! `Deref`.
//!
//! Escape hatches, as in Cocoon: `unsafe { .. }` blocks and
//! `unchecked_operation(..)` are passed through untransformed.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, ToTokens};
use syn::{parse_macro_input, visit_mut::VisitMut, Expr, Ident};

use crate::pc_block_expand::{is_labeled_new, is_unchecked_operation, labeled_new_path, prelude_constructor, safe_method, Recv};
use crate::{allowlisted_path, comma_separate, is_comparison_op, is_compound_assign, is_logical_op, safe_binop, safe_unop, SUPPORTED_OPS};

pub(crate) fn side_effect_free_attr_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::Item);
    let expanded = match input {
        syn::Item::Fn(func) => vet_fn(func),
        syn::Item::Struct(s) => {
            let fields = s.fields.iter().map(|f| f.ty.clone()).collect();
            isef_type(&s.ident, &s.generics, fields, s.to_token_stream())
        }
        syn::Item::Enum(e) => {
            let fields = e.variants.iter().flat_map(|v| v.fields.iter().map(|f| f.ty.clone())).collect();
            isef_type(&e.ident, &e.generics, fields, e.to_token_stream())
        }
        other => err(&other, "#[side_effect_free_attr] applies to functions, structs and enums"),
    };
    expanded.into()
}

fn err<T: ToTokens>(node: &T, msg: &str) -> TokenStream2 {
    syn::Error::new_spanned(node, msg).to_compile_error()
}

/// Macro-internal local names (mixed-site hygiene: invisible to user code).
fn local(name: &str) -> Ident {
    Ident::new(name, Span::mixed_site())
}

/// Function: Cocoon's layout (see the module docs).
fn vet_fn(func: syn::ItemFn) -> TokenStream2 {
    let syn::ItemFn { attrs, vis, sig, block } = func;
    if let Some(receiver) = sig.receiver() {
        return err(receiver, "#[side_effect_free_attr] does not support methods (`self`); use a free function");
    }
    if let Some(asyncness) = &sig.asyncness {
        return err(asyncness, "#[side_effect_free_attr] does not support async functions");
    }

    let ret = match &sig.output {
        syn::ReturnType::Default => quote! { () },
        syn::ReturnType::Type(_, ty) => quote! { #ty },
    };

    // The outer function: `unsafe`, returns `Vetted<R>`, with parameters
    // renamed so they can be forwarded (the trampolines keep the original
    // patterns).
    let mut outer = sig.clone();
    outer.unsafety = Some(Default::default());
    outer.output = syn::parse_quote! { -> ::typing_rules::implicit::Vetted<#ret> };
    let mut forwarded = Vec::new();
    for (i, input) in outer.inputs.iter_mut().enumerate() {
        if let syn::FnArg::Typed(pt) = input {
            let name = local(&format!("__sef_arg{}", i));
            pt.pat = Box::new(syn::parse_quote! { #name });
            forwarded.push(name);
        }
    }

    // Type and const parameters are passed on explicitly (they may not be
    // inferable from the arguments), unless `impl Trait` arguments forbid it.
    let uses_impl_trait = sig.inputs.iter().any(|a| quote!(#a).to_string().contains("impl "));
    let generic_args: Vec<TokenStream2> = sig
        .generics
        .params
        .iter()
        .filter_map(|p| match p {
            syn::GenericParam::Type(t) => Some(t.ident.to_token_stream()),
            syn::GenericParam::Const(c) => Some(c.ident.to_token_stream()),
            syn::GenericParam::Lifetime(_) => None,
        })
        .collect();
    let turbofish = if uses_impl_trait || generic_args.is_empty() {
        quote! {}
    } else {
        quote! { ::<#(#generic_args),*> }
    };

    let unchecked_name = format_ident!("__{}_secret_trampoline_unchecked", sig.ident);
    let checked_name = format_ident!("__{}_secret_trampoline_checked", sig.ident);
    let mut unchecked_sig = sig.clone();
    unchecked_sig.ident = unchecked_name.clone();
    let mut checked_sig = sig;
    checked_sig.ident = checked_name;

    let executed_body = exec_block(&block);
    let checked_body = check_block(&block);

    quote! {
        #(#attrs)*
        #[inline(always)]
        #[allow(unused_unsafe)]
        #vis #outer {
            #[allow(clippy::all, non_snake_case, unused_braces, unused_mut, unused_parens, unused_variables)]
            #unchecked_sig #executed_body

            // Never called; exists only so rustc type-checks it.
            #[allow(clippy::all, dead_code, non_snake_case, unreachable_code, unused_braces, unused_mut, unused_parens, unused_variables)]
            #checked_sig #checked_body

            unsafe { ::typing_rules::implicit::Vetted::wrap(#unchecked_name #turbofish(#(#forwarded),*)) }
        }
    }
}

/// Struct / enum: `InvisibleSideEffectFree` if every field is, and only if
/// the type has no custom `Drop` or `Deref`.
fn isef_type(name: &syn::Ident, generics: &syn::Generics, field_tys: Vec<syn::Type>, item: TokenStream2) -> TokenStream2 {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut isef_generics = generics.clone();
    let wc = isef_generics.make_where_clause();
    for ty in &field_tys {
        wc.predicates.push(syn::parse_quote! { #ty: ::typing_rules::implicit::InvisibleSideEffectFree });
    }
    let (_, _, isef_where) = isef_generics.split_for_impl();

    quote! {
        #item

        unsafe impl #impl_generics ::typing_rules::implicit::InvisibleSideEffectFree for #name #ty_generics #isef_where {}

        // A custom `Drop` or `Deref` runs arbitrary code invisibly (Cocoon
        // §4.2.3). The second impl of each helper trait overlaps the blanket
        // one exactly when the type implements that trait, so such a type
        // fails to compile here.
        #[allow(dead_code, drop_bounds)]
        const _: () = {
            trait NoCustomDrop {}
            impl<T: ::std::ops::Drop> NoCustomDrop for T {}
            impl #impl_generics NoCustomDrop for #name #ty_generics #where_clause {}

            trait NoCustomDeref {}
            impl<T: ::std::ops::Deref> NoCustomDeref for T {}
            impl #impl_generics NoCustomDeref for #name #ty_generics #where_clause {}
        };
    }
}

// =========================================================================
// EXECUTED COPY — Cocoon's τ(body, T)
// =========================================================================

/// The body as written, except that calls are emitted exactly as the checked
/// copy validated them: a call to another side-effect-free function becomes
/// `Vetted::unwrap(unsafe { f(..) })` with its arguments evaluated outside
/// the `unsafe`, and allowlisted functions and constructors use the same
/// canonical paths.
fn exec_block(block: &syn::Block) -> TokenStream2 {
    let mut block = block.clone();
    ExecCalls.visit_block_mut(&mut block);
    block.to_token_stream()
}

struct ExecCalls;

impl VisitMut for ExecCalls {
    // Nested items are separate functions with their own checks.
    fn visit_item_mut(&mut self, _: &mut syn::Item) {}

    fn visit_expr_mut(&mut self, e: &mut Expr) {
        // `unsafe {}` is the escape hatch; macros are rejected by the checked copy.
        if matches!(e, Expr::Unsafe(_) | Expr::Macro(_)) {
            return;
        }
        syn::visit_mut::visit_expr_mut(self, e);
        if let Expr::Call(call) = e {
            if let Some(rewritten) = exec_call(call) {
                *e = rewritten;
            }
        }
    }
}

fn exec_call(call: &syn::ExprCall) -> Option<Expr> {
    let args = &call.args;
    let tokens = if is_unchecked_operation(&call.func) {
        let inner = call.args.first()?;
        quote! { #inner }
    } else if let Some(path) = allowlisted_path(call) {
        quote! { #path(#args) }
    } else if let Some(ctor) = prelude_constructor(&call.func) {
        quote! { #ctor(#args) }
    } else if is_labeled_new(&call.func) {
        let path = labeled_new_path(&call.func);
        quote! { #path(#args) }
    } else if let Expr::Path(func) = &*call.func {
        let names: Vec<Ident> = (0..args.len()).map(|i| local(&format!("__sef_a{}", i))).collect();
        let values = args.iter();
        quote! { { #(let #names = #values;)* ::typing_rules::implicit::Vetted::unwrap(unsafe { #func(#(#names),*) }) } }
    } else {
        // Rejected by the checked copy.
        return None;
    };
    Some(syn::parse_quote! { #tokens })
}

// =========================================================================
// CHECKED COPY — Cocoon's τ(body, F) for a side-effect-free function
// =========================================================================

const MACRO_MSG: &str =
    "macros are not allowed in a #[side_effect_free_attr] function (their expansion cannot be checked); \
     wrap in `unsafe {}` to opt out";

fn check_block(input: &syn::Block) -> TokenStream2 {
    let stmts = input.stmts.iter().map(|stmt| match stmt {
        syn::Stmt::Expr(e, semi) => {
            let checked = check_expr(e);
            quote! { #checked #semi }
        }
        syn::Stmt::Local(l) => {
            let pat = &l.pat;
            let init = l.init.as_ref().map(|init| {
                let ex = check_expr(&init.expr);
                match &init.diverge {
                    Some((_, d)) => {
                        let d = check_expr(d);
                        quote! { = #ex else { #d } }
                    }
                    None => quote! { = #ex },
                }
            });
            quote! { let #pat #init; }
        }
        syn::Stmt::Macro(m) => {
            let e = err(m, MACRO_MSG);
            quote! { #e; }
        }
        syn::Stmt::Item(item) => item.to_token_stream(),
    });
    quote! { { #(#stmts)* } }
}

/// A place expression: variables stay real places so borrows and writes
/// refer to the actual variable.
fn check_place(e: &Expr) -> TokenStream2 {
    match e {
        Expr::Path(p) => p.to_token_stream(),
        Expr::Paren(p) => {
            let inner = check_place(&p.expr);
            quote! { (#inner) }
        }
        Expr::Group(g) => check_place(&g.expr),
        Expr::Field(f) => {
            let base = check_place(&f.base);
            let member = &f.member;
            quote! { (#base).#member }
        }
        Expr::Index(i) => {
            let base = check_place(&i.expr);
            let index = check_expr(&i.index);
            quote! { (#base)[#index] }
        }
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
            let inner = check_place(&u.expr);
            quote! { *(#inner) }
        }
        other => check_expr(other),
    }
}

fn check_expr(expr: &Expr) -> TokenStream2 {
    match expr {
        // ── CALLS ──────────────────────────────────────────────────────────
        // Non-allowlisted callees must return Vetted<_>, i.e. must themselves
        // carry #[side_effect_free_attr]. This is the transitivity rule.
        Expr::Call(call) => {
            if is_unchecked_operation(&call.func) {
                return match call.args.first() {
                    Some(inner) => inner.to_token_stream(),
                    None => err(call, "unchecked_operation needs an argument"),
                };
            }
            let args: Vec<_> = call.args.iter().map(check_expr).collect();
            if let Some(path) = allowlisted_path(call) {
                quote! { ::typing_rules::implicit::check_isef(#path(#(#args),*)) }
            } else if let Some(ctor) = prelude_constructor(&call.func) {
                quote! { #ctor(#(#args),*) }
            } else if is_labeled_new(&call.func) {
                let path = labeled_new_path(&call.func);
                quote! { #path(#(#args),*) }
            } else if let Expr::Path(_) = &*call.func {
                // Side-effect-free functions are `unsafe fn`: only the call
                // itself — arguments already evaluated — sits in `unsafe`.
                let func = &call.func;
                let names: Vec<Ident> = (0..args.len()).map(|i| local(&format!("__sef_a{}", i))).collect();
                quote! { { #(let #names = #args;)* ::typing_rules::implicit::require_vetted(unsafe { #func(#(#names),*) }).unwrap() } }
            } else {
                err(&call.func, "only named #[side_effect_free_attr] functions can be called here")
            }
        }

        // ── METHOD CALLS ───────────────────────────────────────────────────
        // Only std methods, through the `safe_methods` traits.
        Expr::MethodCall(m) => {
            let args: Vec<_> = m.args.iter().map(check_expr).collect();
            let entry = if m.turbofish.is_none() { safe_method(&m.method.to_string(), m.args.len()) } else { None };
            match entry {
                Some((tr, f, recv)) => {
                    let recv = match recv {
                        Recv::Ref => {
                            let p = check_place(&m.receiver);
                            quote! { ::typing_rules::implicit::check_isef_ref(&#p) }
                        }
                        Recv::Mut => {
                            let p = check_place(&m.receiver);
                            quote! { ::typing_rules::implicit::check_isef_mut(&mut #p) }
                        }
                        Recv::Value => check_expr(&m.receiver),
                    };
                    let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
                    quote! { ::typing_rules::safe_methods::#tr::#f(#recv #(, #args)*) }
                }
                None => err(
                    &m.method,
                    "only the std methods in `typing_rules::safe_methods` can be called with method syntax here; \
                     call #[side_effect_free_attr] functions as `f(x)`",
                ),
            }
        }

        // ── MACROS ─────────────────────────────────────────────────────────
        Expr::Macro(_) => err(expr, MACRO_MSG),

        // ── ESCAPE HATCH: unsafe blocks are not transformed (Cocoon §5.4) ───
        Expr::Unsafe(u) => {
            let b = &u.block;
            quote! { unsafe #b }
        }

        // ── OPERATORS ──────────────────────────────────────────────────────
        // Routed through the Safe* traits so an application type with a custom
        // (possibly side-effecting) operator impl fails to compile.
        Expr::Binary(b) if matches!(&*b.left, Expr::Lit(_)) && matches!(&*b.right, Expr::Lit(_)) => {
            // Literal-only arithmetic: constant, and keeps literal type inference.
            b.to_token_stream()
        }
        Expr::Binary(b) if is_comparison_op(&b.op) => {
            let lhs = check_expr(&b.left);
            let rhs = check_expr(&b.right);
            let (tr, f) = safe_binop(&b.op).expect("is_comparison_op implies safe_binop");
            let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
            quote! { ::typing_rules::safe_ops::#tr::#f(&(#lhs), &(#rhs)) }
        }
        // `&&` / `||` are not overloadable in Rust, so they pass through
        // (Cocoon Fig. 5c does the same).
        Expr::Binary(b) if is_logical_op(&b.op) => {
            let lhs = check_expr(&b.left);
            let rhs = check_expr(&b.right);
            let op = &b.op;
            quote! { ((#lhs) #op (#rhs)) }
        }
        Expr::Binary(b) if is_compound_assign(&b.op) => {
            let place = check_place(&b.left);
            let rhs = check_expr(&b.right);
            let target = quote! { ::typing_rules::implicit::check_isef_mut(&mut #place) };
            // `is_compound_assign` and `safe_binop` read the same table.
            let (tr, f) = safe_binop(&b.op).expect("is_compound_assign implies safe_binop");
            let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
            quote! { ::typing_rules::safe_ops::#tr::#f(#target, #rhs) }
        }
        Expr::Binary(b) => {
            let lhs = check_expr(&b.left);
            let rhs = check_expr(&b.right);
            match safe_binop(&b.op) {
                Some((tr, f)) => {
                    let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
                    quote! { ::typing_rules::safe_ops::#tr::#f(&(#lhs), &(#rhs)) }
                }
                None => err(
                    b,
                    &format!("operator not supported in a #[side_effect_free_attr] function (supported: {SUPPORTED_OPS})"),
                ),
            }
        }
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) && matches!(&*u.expr, Expr::Lit(_)) => u.to_token_stream(),
        Expr::Unary(u) => {
            let inner = check_expr(&u.expr);
            if matches!(u.op, syn::UnOp::Deref(_)) {
                return quote! { (*#inner) };
            }
            match safe_unop(&u.op) {
                Some((tr, f)) => {
                    let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
                    quote! { ::typing_rules::safe_ops::#tr::#f(&(#inner)) }
                }
                None => err(u, "unsupported unary operator in a #[side_effect_free_attr] function"),
            }
        }

        // ── CONTROL FLOW ───────────────────────────────────────────────────
        Expr::If(i) => {
            let cond = match i.cond.as_ref() {
                Expr::Let(l) => {
                    let pat = &l.pat;
                    let scrutinee = check_expr(&l.expr);
                    quote! { let #pat = #scrutinee }
                }
                other => check_expr(other),
            };
            let then_branch = check_block(&i.then_branch);
            let else_branch = i.else_branch.as_ref().map(|(_, e)| {
                let e = check_expr(e);
                quote! { else #e }
            });
            quote! { if #cond #then_branch #else_branch }
        }
        Expr::While(w) => {
            let cond = match w.cond.as_ref() {
                Expr::Let(l) => {
                    let pat = &l.pat;
                    let scrutinee = check_expr(&l.expr);
                    quote! { let #pat = #scrutinee }
                }
                other => check_expr(other),
            };
            let body = check_block(&w.body);
            let label = &w.label;
            quote! { #label while #cond #body }
        }
        Expr::ForLoop(f) => {
            let pat = &f.pat;
            let iter = check_expr(&f.expr);
            let body = check_block(&f.body);
            let label = &f.label;
            // The iterated collection and its iterator must both be ISEF, or
            // `into_iter()` / `next()` could themselves have a side effect.
            quote! { #label for #pat in ::typing_rules::implicit::check_isef(#iter) #body }
        }
        Expr::Loop(l) => {
            let body = check_block(&l.body);
            let label = &l.label;
            quote! { #label loop #body }
        }
        Expr::Match(m) => {
            let scrutinee = check_expr(&m.expr);
            let arms = m.arms.iter().map(|arm| {
                let pat = &arm.pat;
                let guard = arm.guard.as_ref().map(|(_, g)| {
                    let g = check_expr(g);
                    quote! { if #g }
                });
                let body = check_expr(&arm.body);
                quote! { #pat #guard => { #body } }
            });
            quote! { match #scrutinee { #(#arms)* } }
        }
        Expr::Block(b) => {
            let label = &b.label;
            let inner = check_block(&b.block);
            quote! { #label #inner }
        }
        Expr::Return(r) => {
            let val = r.expr.as_ref().map(|e| check_expr(e));
            quote! { return #val }
        }
        Expr::Break(b) => {
            let label = &b.label;
            let val = b.expr.as_ref().map(|e| check_expr(e));
            quote! { break #label #val }
        }
        Expr::Continue(c) => {
            let label = &c.label;
            quote! { continue #label }
        }
        Expr::Try(t) => {
            let inner = check_expr(&t.expr);
            quote! { (#inner)? }
        }
        Expr::Closure(c) => {
            // A closure definition is harmless; calling it goes through the
            // Call arm above, which demands a named side-effect-free function.
            let mut c = c.clone();
            let body = check_expr(&c.body);
            c.body = Box::new(syn::parse_quote! { { #body } });
            c.to_token_stream()
        }

        // ── WRITES AND BORROWS ─────────────────────────────────────────────
        Expr::Assign(a) => {
            let place = check_place(&a.left);
            let rhs = check_expr(&a.right);
            quote! { #place = #rhs }
        }
        Expr::Reference(r) => {
            let place = check_place(&r.expr);
            if r.mutability.is_some() {
                quote! { ::typing_rules::implicit::check_isef_mut(&mut #place) }
            } else {
                quote! { ::typing_rules::implicit::check_isef_ref(&#place) }
            }
        }

        // ── STRUCTURAL / LEAF ──────────────────────────────────────────────
        Expr::Paren(p) => {
            let inner = check_expr(&p.expr);
            quote! { (#inner) }
        }
        Expr::Field(f) => {
            let base = check_expr(&f.base);
            let member = &f.member;
            quote! { (#base).#member }
        }
        Expr::Index(i) => {
            let base = check_expr(&i.expr);
            let index = check_expr(&i.index);
            quote! { (#base)[#index] }
        }
        Expr::Array(a) => {
            let elems = comma_separate(a.elems.iter().map(check_expr));
            quote! { [#elems] }
        }
        Expr::Repeat(r) => {
            let elem = check_expr(&r.expr);
            let len = &r.len;
            quote! { [#elem; #len] }
        }
        Expr::Tuple(t) => {
            let elems = t.elems.iter().map(check_expr);
            if t.elems.is_empty() {
                quote! { () }
            } else {
                quote! { (#(#elems,)*) }
            }
        }
        Expr::Struct(s) => {
            let path = &s.path;
            let fields = s.fields.iter().map(|f| {
                let member = &f.member;
                let val = check_expr(&f.expr);
                quote! { #member: #val }
            });
            let rest = s.rest.as_ref().map(|r| {
                let r = check_expr(r);
                quote! { ..#r }
            });
            quote! { ::typing_rules::implicit::check_isef(#path { #(#fields,)* #rest }) }
        }
        Expr::Cast(c) => {
            let inner = check_expr(&c.expr);
            let ty = &c.ty;
            quote! { ((#inner) as #ty) }
        }
        Expr::Range(r) => {
            let start = r.start.as_ref().map(|e| check_expr(e));
            let end = r.end.as_ref().map(|e| check_expr(e));
            let limits = &r.limits;
            quote! { (#start #limits #end) }
        }
        Expr::Group(g) => check_expr(&g.expr),
        // Cocoon's `check_ISEF_unsafe`: every value read must be ISEF (no
        // custom Drop/Deref/operator side effects).
        Expr::Path(p) => {
            let t = local("__sef_read");
            quote! { { let #t = &#p; unsafe { ::typing_rules::implicit::check_isef_unsafe(#t) } } }
        }
        Expr::Lit(l) => l.to_token_stream(),

        // Unrecognized syntax could conceal a side effect the pass cannot see.
        other => err(other, "syntax not supported in a #[side_effect_free_attr] function (checked copy)"),
    }
}
