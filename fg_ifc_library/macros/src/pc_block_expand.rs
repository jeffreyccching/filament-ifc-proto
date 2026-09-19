//! `pc_block!` — Filament's counterpart of Cocoon's `secret_block!`.
//!
//! As in Cocoon (Fig. 4a) the macro emits two copies of the block:
//!
//! ```text
//! if true { PanicSilencer; call_pc_closure(|| catch_unwind(|| { <executed copy> })) }
//! else    { call_pc_closure(|| { <checked copy> }) }   // never runs
//! ```
//!
//! The checked copy (`Mode::Check`) exists only to be type-checked: every
//! call must return `Vetted` (a `#[side_effect_free_attr]` callee) or be an
//! allowlisted std function, operators and methods go through the
//! `safe_ops` / `safe_methods` whitelists, every value read must be
//! `InvisibleSideEffectFree`, macros are rejected, and the closure's
//! captures must satisfy `PcVisibleSideEffectFree`.
//!
//! Filament adds a flow-sensitive PC label: `__pc` starts at the block's
//! label, is raised inside branches on labeled conditions, and every write
//! must satisfy `PC ⊑ label(target)` (`PcWrite`). Because the PC drops back
//! after a branch, ending the block early under a raised PC would reveal the
//! branch: `return` is rejected and a panic aborts the process — the
//! termination channel, outside termination-insensitive noninterference
//! (the guarantee Cocoon claims as well).

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Expr, Ident, Token,
};

use crate::{allowlisted_path, comma_separate, is_comparison_op, is_compound_assign, is_logical_op, safe_binop, safe_unop, SUPPORTED_OPS};

// =========================================================================
// INPUT
// =========================================================================

struct PcBlockInput {
    start_label: syn::Type,
    /// Parsed only so the `[..]` form can be rejected with a useful message.
    captures: Vec<Ident>,
    block: syn::Block,
}

impl Parse for PcBlockInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Optional label: (Label). Defaults to Public.
        let start_label = if input.peek(syn::token::Paren) {
            let content;
            syn::parenthesized!(content in input);
            content.parse()?
        } else {
            syn::parse_quote!(::typing_rules::lattice::Public)
        };

        // The `[cap1, cap2, ...]` form is parsed only so it can be rejected
        // with a useful message; `pc_block!` has no unchecked variant.
        let captures = if input.peek(syn::token::Bracket) {
            let content;
            syn::bracketed!(content in input);
            let parsed: Punctuated<Ident, Token![,]> = content.parse_terminated(Ident::parse, Token![,])?;
            parsed.into_iter().collect()
        } else {
            Vec::new()
        };

        let block = input.parse()?;
        Ok(PcBlockInput { start_label, captures, block })
    }
}

// =========================================================================
// ENTRY POINTS
// =========================================================================

/// Internal identifiers use mixed-site hygiene so code inside the block can
/// neither read nor shadow them (a user `let __pc = Public;` would otherwise
/// reset the PC).
fn id(name: &str) -> Ident {
    Ident::new(name, Span::mixed_site())
}

/// Checked copy: `let __pc = __pc ⊔ label;` at the start of a branch or loop
/// body. `Clone::clone(&x)` rather than `x.clone()`: the label's type can
/// still be an unresolved projection here, and method-call syntax needs it
/// resolved.
fn raise_pc(m: Mode, label: &Ident) -> TokenStream2 {
    match m {
        Mode::Check => {
            let pc = id("__pc");
            quote! {
                let #pc = ::typing_rules::implicit::join_labels(
                    ::std::clone::Clone::clone(&#pc),
                    ::std::clone::Clone::clone(&#label),
                );
            }
        }
        Mode::Exec => quote! {},
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Exec,
    Check,
}

pub(crate) fn pc_block_impl(tokens: TokenStream) -> TokenStream {
    let PcBlockInput { start_label, captures, block } = parse_macro_input!(tokens as PcBlockInput);
    if let Some(first) = captures.first() {
        return syn::Error::new_spanned(
            first,
            "pc_block! does not take a capture list: the `[..]` form would run its body unchecked. \
             If the body genuinely cannot be checked, `declassify` the values it needs and write \
             plain Rust — that keeps the trust visible and counted.",
        )
        .to_compile_error()
        .into();
    }

    let executed = tx_block(&block, Mode::Exec);
    let checked = tx_block(&block, Mode::Check);
    let pc = id("__pc");
    let guard = id("__pc_panic_guard");
    let outcome = id("__pc_outcome");

    let expanded = quote! {
        {
            if true {
                // A panic message can contain secret data, so output is
                // suppressed while the block runs. The guard sets a
                // thread-local flag read by a hook installed once; it is
                // created outside the closure below so it is not captured and
                // does not affect the capture gate. (Cocoon does not touch the
                // panic hook at all; swapping it per block, as this used to,
                // mutates process-global state and is neither thread-safe nor
                // free in a loop.)
                let #guard = ::typing_rules::implicit::PanicSilencer::new();
                // As in Cocoon, the executed copy also goes through the
                // capture gate.
                #[allow(unused_variables, unused_mut, unused_braces, unused_parens, unused_imports, unreachable_code)]
                let #outcome = ::typing_rules::implicit::call_pc_closure(|| {
                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                        use ::typing_rules::implicit::{BranchValueFallback as _, IterWrapperFallback as _, ScrutineeFallback as _};
                        #executed
                    }))
                });
                match #outcome {
                    ::std::result::Result::Ok(()) => {}
                    // Recovering would let the rest of the program observe that
                    // the block stopped early — possibly because of a secret —
                    // so a panic ends the process instead.
                    ::std::result::Result::Err(_) => ::std::process::abort(),
                }
                ::std::mem::drop(#guard);
            } else {
                // Checked copy: never runs. The non-move closure makes rustc
                // check `PcVisibleSideEffectFree` on everything it captures.
                #[allow(unused_variables, unused_mut, unused_braces, unused_parens, unused_imports, unreachable_code)]
                let _ = ::typing_rules::implicit::call_pc_closure(|| {
                    use ::typing_rules::implicit::{
                        BranchValueFallback as _, IterWrapperFallback as _, PcWriteFallback as _, ScrutineeFallback as _,
                    };
                    let #pc: #start_label = <#start_label as ::std::default::Default>::default();
                    #checked
                });
            }
        }
    };
    expanded.into()
}

// =========================================================================
// TRANSFORMATION — Cocoon's τ(e, isExec)
//
// `Mode::Exec` emits the code that runs; `Mode::Check` the never-executed
// copy that carries the checks. Both apply the same type-changing rewrites
// (safe operators/methods, branch-value lifting, `if let` peeling) so the
// two copies see the same types.
// =========================================================================

const MACRO_MSG: &str = "macros are not allowed in pc_block! (their expansion cannot be checked for side effects)";

/// Unsupported syntax: a compile error in the checked copy. The executed copy
/// keeps the original tokens (compilation already fails on the error).
fn reject<T: ToTokens>(m: Mode, node: &T, msg: &str) -> TokenStream2 {
    match m {
        Mode::Check => syn::Error::new_spanned(node, msg).to_compile_error(),
        Mode::Exec => node.to_token_stream(),
    }
}

fn tx_block(block: &syn::Block, m: Mode) -> TokenStream2 {
    let stmts = block.stmts.iter().map(|s| tx_stmt(s, m));
    quote! { { #(#stmts)* } }
}

fn tx_stmt(stmt: &syn::Stmt, m: Mode) -> TokenStream2 {
    match stmt {
        syn::Stmt::Local(l) => {
            let pat = &l.pat;
            match &l.init {
                None => quote! { let #pat; },
                Some(init) if init.diverge.is_some() => reject(m, stmt, "`let ... else` is not supported in pc_block!"),
                Some(init) => {
                    let e = tx_expr(&init.expr, m);
                    quote! { let #pat = #e; }
                }
            }
        }
        syn::Stmt::Expr(e, semi) => {
            let e = tx_expr(e, m);
            quote! { #e #semi }
        }
        syn::Stmt::Macro(_) => reject(m, stmt, MACRO_MSG),
        syn::Stmt::Item(item) => match item {
            syn::Item::Const(_) | syn::Item::Use(_) => item.to_token_stream(),
            _ => reject(m, stmt, "only `const` and `use` items are allowed in pc_block!"),
        },
    }
}

fn tx_expr(expr: &Expr, m: Mode) -> TokenStream2 {
    let ck = m == Mode::Check;
    match expr {
        Expr::Lit(l) => l.to_token_stream(),
        Expr::Path(p) => {
            if ck {
                // Cocoon's `check_ISEF_unsafe`: every value read must be ISEF
                // (no custom Drop/Deref/operator side effects).
                let t = id("__pc_read");
                quote! { { let #t = &#p; unsafe { ::typing_rules::implicit::check_isef_unsafe(#t) } } }
            } else {
                p.to_token_stream()
            }
        }
        Expr::Paren(p) => {
            let inner = tx_expr(&p.expr, m);
            quote! { (#inner) }
        }
        Expr::Group(g) => tx_expr(&g.expr, m),
        Expr::Block(b) if b.label.is_none() => tx_block(&b.block, m),
        Expr::Unsafe(u) => {
            let inner = tx_block(&u.block, m);
            quote! { unsafe #inner }
        }
        Expr::Assign(a) => tx_assign(a, m),
        Expr::Binary(b) => tx_binary(b, m),
        Expr::Unary(u) => tx_unary(u, m),
        Expr::Reference(r) => {
            if r.mutability.is_some() {
                write_target(&r.expr, m)
            } else {
                shared_ref(&r.expr, m)
            }
        }
        Expr::Field(f) => {
            let base = tx_expr(&f.base, m);
            let member = &f.member;
            quote! { (#base).#member }
        }
        Expr::Index(i) => {
            let base = tx_expr(&i.expr, m);
            let index = tx_expr(&i.index, m);
            quote! { (#base)[#index] }
        }
        Expr::Array(a) => {
            let elems = comma_separate(a.elems.iter().map(|e| tx_expr(e, m)));
            quote! { [#elems] }
        }
        Expr::Repeat(r) => {
            let e = tx_expr(&r.expr, m);
            let len = &r.len;
            quote! { [#e; #len] }
        }
        Expr::Tuple(t) => {
            let elems = t.elems.iter().map(|e| tx_expr(e, m));
            if t.elems.is_empty() {
                quote! { () }
            } else {
                quote! { (#(#elems,)*) }
            }
        }
        Expr::Cast(c) => {
            let inner = tx_expr(&c.expr, m);
            let ty = &c.ty;
            quote! { ((#inner) as #ty) }
        }
        Expr::Range(r) => {
            let start = r.start.as_ref().map(|e| tx_expr(e, m));
            let end = r.end.as_ref().map(|e| tx_expr(e, m));
            let limits = &r.limits;
            quote! { (#start #limits #end) }
        }
        Expr::Struct(s) => {
            let path = &s.path;
            let fields = s.fields.iter().map(|f| {
                let member = &f.member;
                let v = tx_expr(&f.expr, m);
                quote! { #member: #v }
            });
            let rest = s.rest.as_ref().map(|r| {
                let r = tx_expr(r, m);
                quote! { ..#r }
            });
            let lit = quote! { #path { #(#fields,)* #rest } };
            if ck {
                quote! { ::typing_rules::implicit::check_isef(#lit) }
            } else {
                lit
            }
        }
        Expr::Call(c) => tx_call(c, m),
        Expr::MethodCall(mc) => tx_method(mc, m),
        Expr::If(i) => tx_if(i, m),
        Expr::While(w) => tx_while(w, m),
        Expr::ForLoop(f) => tx_for(f, m),
        Expr::Loop(l) => {
            let label = &l.label;
            let body = tx_block(&l.body, m);
            quote! { #label loop #body }
        }
        Expr::Return(_) => reject(
            m,
            expr,
            "`return` is not allowed in pc_block!: leaving the block early under a raised PC would reveal the branch taken",
        ),
        Expr::Macro(_) => reject(m, expr, MACRO_MSG),
        _ => reject(m, expr, "syntax not supported in pc_block!"),
    }
}

/// A place expression (assignment target, `&` / `&mut` operand, receiver).
/// Variables are kept as real places rather than ISEF-checked copies, so
/// borrows refer to (and closure captures see) the actual variable.
fn tx_place(e: &Expr, m: Mode) -> TokenStream2 {
    match e {
        Expr::Path(p) => p.to_token_stream(),
        Expr::Paren(p) => {
            let inner = tx_place(&p.expr, m);
            quote! { (#inner) }
        }
        Expr::Group(g) => tx_place(&g.expr, m),
        Expr::Field(f) => {
            let base = tx_place(&f.base, m);
            let member = &f.member;
            quote! { (#base).#member }
        }
        Expr::Index(i) => {
            let base = tx_place(&i.expr, m);
            let index = tx_expr(&i.index, m);
            quote! { (#base)[#index] }
        }
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
            let inner = tx_place(&u.expr, m);
            quote! { *(#inner) }
        }
        other => tx_expr(other, m),
    }
}

/// `&place`; checked: the referent must be ISEF (Cocoon's
/// `check_expr_secret_block_safe_ref`).
fn shared_ref(e: &Expr, m: Mode) -> TokenStream2 {
    let p = tx_place(e, m);
    match m {
        Mode::Exec => quote! { &#p },
        Mode::Check => quote! { ::typing_rules::implicit::check_isef_ref(&#p) },
    }
}

/// `&mut place` for a write; checked: the reference goes through the PC
/// guard (`PC ⊑ label(target)`) and the target must be ISEF.
fn write_target(e: &Expr, m: Mode) -> TokenStream2 {
    let p = tx_place(e, m);
    match m {
        Mode::Exec => quote! { &mut #p },
        Mode::Check => {
            let pc = id("__pc");
            quote! {
                ::typing_rules::implicit::check_isef_mut(::typing_rules::implicit::PcWrite(&mut #p).guard(&#pc))
            }
        }
    }
}

fn tx_assign(a: &syn::ExprAssign, m: Mode) -> TokenStream2 {
    // `x = Labeled::new(v)` without a turbofish is emitted without chaining
    // so the label is inferred from `x`.
    let rhs = match &*a.right {
        Expr::Call(c) if is_labeled_new(&c.func) && !labeled_new_has_turbofish(&c.func) => {
            let path = labeled_new_path(&c.func);
            let args = c.args.iter().map(|x| call_arg(x, m));
            quote! { #path(#(#args),*) }
        }
        other => tx_expr(other, m),
    };
    let target = write_target(&a.left, m);
    let v = id("__pc_rhs");
    quote! { { let #v = #rhs; *#target = #v; } }
}

fn tx_binary(b: &syn::ExprBinary, m: Mode) -> TokenStream2 {
    use syn::BinOp::*;

    if is_compound_assign(&b.op) {
        // `is_compound_assign` and `safe_binop` read the same table, so this
        // cannot be `None` here.
        let (tr, f) = safe_binop(&b.op).expect("is_compound_assign implies safe_binop");
        let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
        let target = write_target(&b.left, m);
        let rhs = tx_expr(&b.right, m);
        return quote! { ::typing_rules::safe_ops::#tr::#f(#target, #rhs) };
    }

    // Literal-only arithmetic cannot have side effects; keeping it native
    // preserves integer-literal type inference.
    if matches!(&*b.left, Expr::Lit(_)) && matches!(&*b.right, Expr::Lit(_)) {
        return b.to_token_stream();
    }

    let lhs = tx_expr(&b.left, m);
    let rhs = tx_expr(&b.right, m);

    if is_logical_op(&b.op) {
        // Path syntax: the operand types can still be unresolved here, and
        // method-call syntax needs them resolved.
        return match b.op {
            And(_) => quote! { ::typing_rules::operations::LabeledAnd::labeled_and(&(#lhs), ::std::clone::Clone::clone(&(#rhs))) },
            _ => quote! { ::typing_rules::operations::LabeledOr::labeled_or(&(#lhs), ::std::clone::Clone::clone(&(#rhs))) },
        };
    }

    let Some((tr, f)) = safe_binop(&b.op) else {
        return reject(m, b, &format!("operator not supported in pc_block! (supported: {SUPPORTED_OPS})"));
    };
    debug_assert!(is_comparison_op(&b.op) || !tr.starts_with("SafeCmp"));
    let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
    quote! { ::typing_rules::safe_ops::#tr::#f(&(#lhs), &(#rhs)) }
}

fn tx_unary(u: &syn::ExprUnary, m: Mode) -> TokenStream2 {
    // `-1` etc.: a negated literal is a constant.
    if matches!(u.op, syn::UnOp::Neg(_)) && matches!(&*u.expr, Expr::Lit(_)) {
        return u.to_token_stream();
    }
    let inner = tx_expr(&u.expr, m);
    if matches!(u.op, syn::UnOp::Deref(_)) {
        return quote! { *(#inner) };
    }
    match safe_unop(&u.op) {
        Some((tr, f)) => {
            let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
            quote! { ::typing_rules::safe_ops::#tr::#f(&(#inner)) }
        }
        None => reject(m, u, "unary operator not supported in pc_block!"),
    }
}

/// An argument of a chained call. Checked: must not contain a mutable
/// reference — the callee receives unwrapped (possibly secret) arguments and
/// could store them through it, bypassing the PC.
fn call_arg(arg: &Expr, m: Mode) -> TokenStream2 {
    let a = tx_expr(arg, m);
    match m {
        Mode::Exec => a,
        Mode::Check => quote! { ::typing_rules::implicit::check_call_arg(#a) },
    }
}

fn tx_call(call: &syn::ExprCall, m: Mode) -> TokenStream2 {
    if is_unchecked_operation(&call.func) {
        // Escape hatch, audited like `declassify`: the argument is emitted untransformed.
        return match call.args.first() {
            Some(inner) => inner.to_token_stream(),
            None => reject(m, call, "unchecked_operation needs an argument"),
        };
    }

    // Allowlisted std functions do not unwrap labeled arguments, so a `&mut`
    // argument is safe there: it goes through the PC write guard.
    if let Some(path) = allowlisted_path(call) {
        let args = call.args.iter().map(|a| tx_expr(a, m));
        return quote! { #path(#(#args),*) };
    }
    if let Some(ctor) = prelude_constructor(&call.func) {
        let args = call.args.iter().map(|a| tx_expr(a, m));
        return quote! { #ctor(#(#args),*) };
    }

    if m == Mode::Check {
        if let Some(arg) = call.args.iter().find(|a| matches!(a, Expr::Reference(r) if r.mutability.is_some())) {
            return syn::Error::new_spanned(
                arg,
                "`&mut` arguments are not allowed in calls inside pc_block!: the callee could store data derived \
                 from its other (possibly secret) arguments in it. Return the value and assign it instead.",
            )
            .to_compile_error();
        }
    }

    if m == Mode::Check && !matches!(&*call.func, Expr::Path(_)) {
        return syn::Error::new_spanned(&call.func, "only named #[side_effect_free_attr] functions can be called inside pc_block!")
            .to_compile_error();
    }

    // Labeled arguments are unwrapped with `__chain`; the result is
    // re-labeled with the join of their labels.
    let args: Vec<TokenStream2> = call.args.iter().map(|a| call_arg(a, m)).collect();
    let names: Vec<Ident> = (0..args.len()).map(|i| id(&format!("__pc_arg{}", i))).collect();
    let mut expanded = if is_labeled_new(&call.func) {
        let path = labeled_new_path(&call.func);
        quote! { #path(#(#names),*) }
    } else {
        // Cocoon's transitivity rule: the callee must return `Vetted`, i.e.
        // carry #[side_effect_free_attr]. Such functions are `unsafe fn`, so
        // only the call itself — arguments already evaluated — sits in `unsafe`.
        let func = &call.func;
        match m {
            Mode::Check => quote! { ::typing_rules::implicit::require_vetted(unsafe { #func(#(#names),*) }).unwrap() },
            Mode::Exec => quote! { ::typing_rules::implicit::Vetted::unwrap(unsafe { #func(#(#names),*) }) },
        }
    };
    for (arg, name) in args.iter().zip(names.iter()).rev() {
        expanded = quote! { (#arg).__chain(|#name| { #expanded }) };
    }
    quote! { { use ::typing_rules::function_rewrite::SecureChain; #expanded } }
}

fn tx_method(mc: &syn::ExprMethodCall, m: Mode) -> TokenStream2 {
    let name = mc.method.to_string();
    let entry = if mc.turbofish.is_none() { safe_method(&name, mc.args.len()) } else { None };
    let args: Vec<TokenStream2> = mc.args.iter().map(|a| tx_expr(a, m)).collect();

    match (entry, m) {
        (Some((tr, f, recv_mode)), _) => {
            let (tr, f) = (format_ident!("{}", tr), format_ident!("{}", f));
            let recv = match recv_mode {
                Recv::Ref => shared_ref(&mc.receiver, m),
                Recv::Mut => write_target(&mc.receiver, m),
                Recv::Value => tx_expr(&mc.receiver, m),
            };
            quote! { ::typing_rules::safe_methods::#tr::#f(#recv #(, #args)*) }
        }
        (None, Mode::Check) => syn::Error::new_spanned(
            &mc.method,
            format!(
                "`.{}()` is not allowed in pc_block!: method-call syntax is limited to the std methods in \
                 `typing_rules::safe_methods`. Call a #[side_effect_free_attr] function with path syntax instead.",
                name
            ),
        )
        .to_compile_error(),
        (None, Mode::Exec) => {
            let recv = tx_expr(&mc.receiver, m);
            let method = &mc.method;
            let turbofish = &mc.turbofish;
            quote! { (#recv).#method #turbofish (#(#args),*) }
        }
    }
}

fn tx_if(i: &syn::ExprIf, m: Mode) -> TokenStream2 {
    let label = id("__pc_cond_label");
    let value = id("__pc_branch");

    // Checked copy: inside either branch the PC is raised to PC ⊔ label(cond).
    let raise = raise_pc(m, &label);
    let then_branch = tx_block(&i.then_branch, m);
    let else_branch = i.else_branch.as_ref().map(|(_, e)| {
        let e = tx_expr(e, m);
        quote! { else { #raise #e } }
    });

    let (head, test) = match &*i.cond {
        Expr::Let(l) => {
            let pat = &l.pat;
            let scrutinee = tx_expr(&l.expr, m);
            let s = id("__pc_scrutinee");
            (
                quote! { let (#s, #label) = ::typing_rules::implicit::Scrutinee(#scrutinee).inspect_scrutinee(); },
                quote! { let #pat = #s },
            )
        }
        cond => {
            let c = tx_expr(cond, m);
            let v = id("__pc_cond");
            (quote! { let (#v, #label) = ::typing_rules::implicit::inspect_condition(#c); }, quote! { #v })
        }
    };

    // The value leaving the branch carries the condition's label.
    quote! {
        {
            #head
            let #value = if #test { #raise #then_branch } #else_branch;
            ::typing_rules::implicit::BranchValue(#value).lift(&#label)
        }
    }
}

fn tx_while(w: &syn::ExprWhile, m: Mode) -> TokenStream2 {
    if matches!(&*w.cond, Expr::Let(_)) {
        return reject(m, w, "`while let` is not supported in pc_block!");
    }
    let label = id("__pc_cond_label");
    let v = id("__pc_cond");
    let raise = raise_pc(m, &label);
    let cond = tx_expr(&w.cond, m);
    let body = tx_block(&w.body, m);
    let loop_label = &w.label;
    // `loop` + `break` so the condition's label is captured every iteration.
    quote! {
        #loop_label loop {
            let (#v, #label) = ::typing_rules::implicit::inspect_condition(#cond);
            if !#v { break; }
            #raise
            #body
        }
    }
}

fn tx_for(f: &syn::ExprForLoop, m: Mode) -> TokenStream2 {
    let iter = id("__pc_iter");
    let label = id("__pc_iter_label");
    let raise = raise_pc(m, &label);
    let pat = &f.pat;
    let e = tx_expr(&f.expr, m);
    let body = tx_block(&f.body, m);
    let loop_label = &f.label;
    // A labeled iterator is unwrapped and raises the PC for the body.
    quote! {
        {
            let (#iter, #label) = ::typing_rules::implicit::IterWrapper(#e).inspect_iter();
            #raise
            #loop_label for #pat in #iter #body
        }
    }
}

// =========================================================================
// HELPERS (shared with the #[side_effect_free_attr] checker in lib.rs)
// =========================================================================

/// `Labeled::new` / `Labeled::<T, L>::new` (any path ending in those two
/// segments). Always re-emitted as `::typing_rules::lattice::Labeled`, so an
/// application type named `Labeled` cannot pass itself off as the real one.
pub(crate) fn is_labeled_new(func: &Expr) -> bool {
    match func {
        Expr::Path(p) if p.qself.is_none() => {
            let n = p.path.segments.len();
            n >= 2 && p.path.segments[n - 1].ident == "new" && p.path.segments[n - 2].ident == "Labeled"
        }
        _ => false,
    }
}

fn labeled_new_has_turbofish(func: &Expr) -> bool {
    match func {
        Expr::Path(p) => p.path.segments.iter().rev().take(2).any(|s| !s.arguments.is_empty()),
        _ => false,
    }
}

/// Canonical path for a call that `is_labeled_new` accepted.
pub(crate) fn labeled_new_path(func: &Expr) -> TokenStream2 {
    match func {
        Expr::Path(p) => {
            let n = p.path.segments.len();
            let labeled_args = &p.path.segments[n - 2].arguments;
            let new_args = &p.path.segments[n - 1].arguments;
            quote! { ::typing_rules::lattice::Labeled #labeled_args ::new #new_args }
        }
        _ => unreachable!("is_labeled_new accepts only paths"),
    }
}

/// `unchecked_operation(e)` — the explicit escape hatch.
pub(crate) fn is_unchecked_operation(func: &Expr) -> bool {
    match func {
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident == "unchecked_operation").unwrap_or(false),
        _ => false,
    }
}

/// `Some(..)`, `Ok(..)`, `Err(..)` — constructors cannot run code. Emitted
/// fully qualified so a same-named application function is not called.
pub(crate) fn prelude_constructor(func: &Expr) -> Option<TokenStream2> {
    let Expr::Path(p) = func else { return None };
    if p.qself.is_some() || p.path.leading_colon.is_some() || p.path.segments.len() != 1 || !p.path.segments[0].arguments.is_empty() {
        return None;
    }
    match p.path.segments[0].ident.to_string().as_str() {
        "Some" => Some(quote! { ::std::option::Option::Some }),
        "Ok" => Some(quote! { ::std::result::Result::Ok }),
        "Err" => Some(quote! { ::std::result::Result::Err }),
        _ => None,
    }
}

/// How a safe method takes its receiver.
#[derive(Clone, Copy)]
pub(crate) enum Recv {
    Ref,
    Mut,
    Value,
}

/// Std methods callable with method-call syntax in checked code, as
/// `(trait, method, receiver)` in `typing_rules::safe_methods`.
pub(crate) fn safe_method(name: &str, nargs: usize) -> Option<(&'static str, &'static str, Recv)> {
    use Recv::*;
    Some(match (name, nargs) {
        ("len", 0) => ("SafeLen", "safe_len", Ref),
        ("is_empty", 0) => ("SafeIsEmpty", "safe_is_empty", Ref),
        ("is_some", 0) => ("SafeIsSome", "safe_is_some", Ref),
        ("is_none", 0) => ("SafeIsNone", "safe_is_none", Ref),
        ("is_ok", 0) => ("SafeIsOk", "safe_is_ok", Ref),
        ("is_err", 0) => ("SafeIsErr", "safe_is_err", Ref),
        ("clone", 0) => ("SafeClone", "safe_clone", Ref),
        ("to_string", 0) => ("SafeToString", "safe_to_string", Ref),
        ("to_owned", 0) => ("SafeToOwned", "safe_to_owned", Ref),
        ("to_vec", 0) => ("SafeToVec", "safe_to_vec", Ref),
        ("abs", 0) => ("SafeAbs", "safe_abs", Ref),
        ("sqrt", 0) => ("SafeSqrt", "safe_sqrt", Ref),
        ("pow", 1) => ("SafePow", "safe_pow", Ref),
        ("min", 1) => ("SafeMin", "safe_min", Ref),
        ("max", 1) => ("SafeMax", "safe_max", Ref),
        ("get", 1) => ("SafeGet", "safe_get", Ref),
        ("contains", 1) => ("SafeContains", "safe_contains", Ref),
        ("contains_key", 1) => ("SafeContainsKey", "safe_contains_key", Ref),
        ("iter", 0) => ("SafeIter", "safe_iter", Ref),
        ("chars", 0) => ("SafeChars", "safe_chars", Ref),
        ("bytes", 0) => ("SafeBytes", "safe_bytes", Ref),
        ("as_str", 0) => ("SafeAsStr", "safe_as_str", Ref),
        ("into_iter", 0) => ("SafeIntoIter", "safe_into_iter", Value),
        ("unwrap", 0) => ("SafeUnwrap", "safe_unwrap", Value),
        ("unwrap_or", 1) => ("SafeUnwrapOr", "safe_unwrap_or", Value),
        ("unwrap_or_default", 0) => ("SafeUnwrapOrDefault", "safe_unwrap_or_default", Value),
        ("push", 1) => ("SafePush", "safe_push", Mut),
        ("pop", 0) => ("SafePop", "safe_pop", Mut),
        ("clear", 0) => ("SafeClear", "safe_clear", Mut),
        ("insert", 1) => ("SafeInsert1", "safe_insert", Mut),
        ("insert", 2) => ("SafeInsert2", "safe_insert", Mut),
        ("remove", 1) => ("SafeRemove", "safe_remove", Mut),
        _ => return None,
    })
}
