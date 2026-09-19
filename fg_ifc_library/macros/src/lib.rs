use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Expr, Token, Type,
};

// =========================================================================
// Helper Functions
// =========================================================================

/// Custom parser for the relabel! syntax:
///   relabel!(expr, Label)              → static Labeled (2 args)
struct RelabelInput {
    var: Expr,
    label: Type,
}

impl Parse for RelabelInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let var: Expr = input.parse()?;
        let _comma: Token![,] = input.parse()?;
        let label: Type = input.parse()?;
        if !input.is_empty() {
            return Err(input.error("relabel! takes exactly two arguments: `relabel!(expr, Label)`"));
        }
        Ok(RelabelInput { var, label })
    }
}

// =========================================================================
// THE FCALL MACRO (Function Calls)
// =========================================================================

#[proc_macro]
pub fn fcall(input: TokenStream) -> TokenStream {
    // 1. Parse as a generic Expression first
    let expr = parse_macro_input!(input as Expr);

    // 2. Check if it ends with '?' (ExprTry), or is an awaited call (Expr::Await), or is a plain call
    let mut has_question_mark = false;
    let mut has_await = false;
    // Work with a mutable ownership of the expression so we can peel layers
    let mut expr_to_check = expr;

    // Unwrap await: fcall!( ... .await ) -> treat inner expression as the call but remember await
    if let syn::Expr::Await(await_expr) = expr_to_check {
        has_await = true;
        expr_to_check = *await_expr.base;
    }

    // Special case: fcall!(format!("...", arg1, arg2))
    // Chains labeled arguments through __chain(), calls format! with unwrapped values,
    // wraps result in Labeled<String, Public>.
    if let syn::Expr::Macro(ref mac) = expr_to_check {
        let is_format = mac.mac.path.segments.last().map(|s| s.ident == "format").unwrap_or(false);
        if is_format {
            let tokens = mac.mac.tokens.clone();
            let parsed = syn::parse::Parser::parse2(syn::punctuated::Punctuated::<Expr, Token![,]>::parse_terminated, tokens).expect("format! should contain comma-separated expressions");
            let mut items = parsed.iter();
            let fmt_str = items.next().expect("format! needs a format string");
            let args: Vec<&Expr> = items.collect();

            if args.is_empty() {
                return TokenStream::from(quote! {
                    ::typing_rules::lattice::Labeled::<_, ::typing_rules::lattice::Public>::new(
                        format!(#fmt_str)
                    )
                });
            }

            let unwrapped_names: Vec<_> = (0..args.len()).map(|i| format_ident!("__v{}", i)).collect();

            let mut expanded = quote! {
                ::typing_rules::lattice::Labeled::<_, ::typing_rules::lattice::Public>::new(
                    format!(#fmt_str, #(#unwrapped_names),*)
                )
            };

            for (arg, name) in args.iter().zip(unwrapped_names.iter()).rev() {
                expanded = quote! { (#arg).__chain(|#name| { #expanded }) };
            }

            return TokenStream::from(quote! {
                {
                    use ::typing_rules::function_rewrite::SecureChain;
                    use ::typing_rules::function_rewrite::SecureChainRef;
                    #expanded
                }
            });
        }
    }

    // Special case: fcall!(x as Type) — labeled-aware `as` cast.
    // Chains through `x` so labeled values keep their label; the inner closure
    // performs the cast and re-wraps as Labeled<_, Public>, which the chain
    // combinator lifts back to the appropriate label form.
    if let syn::Expr::Cast(ref cast) = expr_to_check {
        let val = &cast.expr;
        let ty = &cast.ty;
        let expanded = quote! {
            (#val).__chain(|__v0| {
                ::typing_rules::lattice::Labeled::<_, ::typing_rules::lattice::Public>::new(__v0 as #ty)
            })
        };
        return TokenStream::from(quote! {
            {
                use ::typing_rules::function_rewrite::SecureChain;
                #expanded
            }
        });
    }

    let call = match expr_to_check {
        syn::Expr::Try(expr_try) => {
            has_question_mark = true;
            if let syn::Expr::Call(call) = *expr_try.expr {
                call // It was func(...)?
            } else {
                return syn::Error::new_spanned(expr_try, "fcall! expects a function call").to_compile_error().into();
            }
        }
        syn::Expr::Call(call) => call, // It was func(...)
        _ => return syn::Error::new_spanned(expr_to_check, "fcall! expects a function call or awaited call").to_compile_error().into(),
    };

    let func = call.func;
    let args = call.args;

    // 3. Prepare chain variables
    let arg_count = args.len();
    let unwrapped_names: Vec<_> = (0..arg_count).map(|i| format_ident!("__v{}", i)).collect();

    // 3a. Classify each argument:
    //   &expr   → use chain_ref on `expr` (inherent for Labeled)
    //             closure receives &T, label propagates from Labeled or defaults to Public
    //   &mut expr → same but mutable (chain_mut_ref, future extension; treat as chain_ref for now)
    //   anything else → existing chain() behaviour, closure receives T by value
    //
    // chain_method[i] — "chain", "chain_ref", or "chain_mut_ref" token
    // chain_target[i] — expression we call the method on (strips outer & for ref args)
    // inner_arg[i]    — what we pass to the function inside the closure (__vi or &__vi)
    enum ChainKind {
        Owned,
        Ref,
        MutRef,
    }
    struct ArgInfo {
        kind: ChainKind,
        target: TokenStream2,
        inner_arg: TokenStream2,
    }
    let arg_infos: Vec<ArgInfo> = args
        .iter()
        .zip(unwrapped_names.iter())
        .map(|(arg, name)| {
            match arg {
                syn::Expr::Reference(r) if r.mutability.is_none() => ArgInfo {
                    kind: ChainKind::Ref,
                    target: {
                        let e = &r.expr;
                        quote! { #e }
                    },
                    inner_arg: quote! { #name }, // closure already receives &T from chain_ref
                },
                syn::Expr::Reference(r) if r.mutability.is_some() => ArgInfo {
                    kind: ChainKind::MutRef,
                    target: {
                        let e = &r.expr;
                        quote! { #e }
                    },
                    inner_arg: quote! { #name }, // closure receives &mut T from chain_mut_ref
                },
                other => ArgInfo {
                    kind: ChainKind::Owned,
                    target: quote! { (#other) },
                    inner_arg: quote! { #name },
                },
            }
        })
        .collect();

    // 4. Inner Execution Logic
    let inner_call_args: Vec<&TokenStream2> = arg_infos.iter().map(|a| &a.inner_arg).collect();
    let mut expanded = if has_await {
        quote! {
            ::typing_rules::lattice::Labeled::<_, ::typing_rules::lattice::Public>::new(
                #func( #(#inner_call_args),* ).await
            )
        }
    } else {
        quote! {
            ::typing_rules::lattice::Labeled::<_, ::typing_rules::lattice::Public>::new(
                #func( #(#inner_call_args),* )
            )
        }
    };

    // 5. Wrap args in .chain() / .chain_ref() / .async_chain()
    if has_await {
        for (info, name) in arg_infos.iter().zip(unwrapped_names.iter()).rev() {
            let target = &info.target;
            expanded = quote! {
                (#target).async_chain(|#name| async move {
                    #expanded
                })
            };
        }
    } else {
        for (info, name) in arg_infos.iter().zip(unwrapped_names.iter()).rev() {
            let target = &info.target;
            expanded = match info.kind {
                ChainKind::Ref => quote! {
                    (#target).__chain_ref(|#name| {
                        #expanded
                    })
                },
                ChainKind::MutRef => quote! {
                    (#target).__chain_mut_ref(|#name| {
                        #expanded
                    })
                },
                ChainKind::Owned => quote! {
                    (#target).__chain(|#name| {
                        #expanded
                    })
                },
            };
        }
    }

    // 6. Handle the '?' operator if present
    if has_question_mark {
        expanded = quote! {
            (#expanded).transpose()?
        };
    }

    // 7. Panic hook suppression guard
    //    Suppress panic messages while the unwrapped secret values are
    //    in scope.  This prevents secret data from leaking through panic
    //    payloads (e.g., `format!("{}", secret_value)` inside a panicking
    //    function).
    let panic_guard = quote! {
        let __fcall_prev_hook = ::std::panic::take_hook();
        ::std::panic::set_hook(::std::boxed::Box::new(|_| {}));

        struct __FcallPanicGuard(
            ::std::option::Option<
                ::std::boxed::Box<dyn ::std::ops::FnMut()>
            >
        );
        impl ::std::ops::Drop for __FcallPanicGuard {
            fn drop(&mut self) {
                if !::std::thread::panicking() {
                    if let ::std::option::Option::Some(mut f) = self.0.take() {
                        f();
                    }
                }
            }
        }
        let mut __fcall_hook_opt = ::std::option::Option::Some(__fcall_prev_hook);
        let __fcall_panic_guard = __FcallPanicGuard(
            ::std::option::Option::Some(::std::boxed::Box::new(move || {
                if let ::std::option::Option::Some(hook) = __fcall_hook_opt.take() {
                    ::std::panic::set_hook(hook);
                }
            }))
        );
    };

    // 8. Final Output
    let final_output = if has_await {
        quote! {
            {
                use ::typing_rules::function_rewrite::SecureAsyncChain;
                #panic_guard
                let __fcall_result = { #expanded };
                drop(__fcall_panic_guard);
                __fcall_result
            }
        }
    } else {
        quote! {
            {
                use ::typing_rules::function_rewrite::SecureChain;
                use ::typing_rules::function_rewrite::SecureChainRef;
                #panic_guard
                let __fcall_result = { #expanded };
                drop(__fcall_panic_guard);
                __fcall_result
            }
        }
    };

    TokenStream::from(final_output)
}

// Macro for method calls AND field access on Labeled values.
//
//   mcall!(obj.method(args))  — method call:  preserves label, calls method on &inner
//   mcall!(obj.method(args)?) — fallible call: preserves label, propagates error via ?
//   mcall!(obj.field)         — field access:  preserves label, reads field from &inner
//   mcall!(obj.0)             — tuple index:   preserves label, reads .0 from &inner
//
// Both forms use the same internal helper so the label is preserved exactly
// (no join needed — the field/method result inherits the receiver's label L).
#[proc_macro]
pub fn mcall(input: TokenStream) -> TokenStream {
    // 1. Parse as a general expression first to prevent strict-parsing panics
    let expr = parse_macro_input!(input as Expr);

    // 2. The trait import emitted inline in every expansion so __mcall resolves.
    let helper = quote! {
        use ::typing_rules::function_rewrite::SecureMethodCall as __SecureMethodCall;
    };

    // 3. Match method call, field access, or awaited method call
    let expanded = match expr {
        // --- awaited method call: mcall!(obj.method(args).await) ---
        //     Unwraps the receiver via .value, extracts inner values from each
        //     argument via chain (works for both Labeled and raw args),
        //     calls the async method, awaits, and returns the raw result.
        Expr::Await(await_expr) => {
            match *await_expr.base {
                Expr::MethodCall(mc) => {
                    let receiver = &mc.receiver;
                    let method = &mc.method;
                    let args = &mc.args;

                    // Classify each argument:
                    //   &expr  → reference arg: pass through inline
                    //            to avoid temporary lifetime issues
                    //   other  → may be Labeled or raw: extract via chain into
                    //            a let binding so the label is checked
                    let mut extractions: Vec<TokenStream2> = Vec::new();
                    let mut call_args: Vec<TokenStream2> = Vec::new();
                    let mut needs_chain = false;

                    for (i, arg) in args.iter().enumerate() {
                        match arg {
                            Expr::Reference(_) => {
                                // Pass reference args directly — avoids
                                // dropping the temporary before the await.
                                call_args.push(quote! { #arg });
                            }
                            _ => {
                                let name = format_ident!("__mv{}", i);
                                extractions.push(quote! {
                                    let #name = (#arg).__chain(|__v| {
                                        ::typing_rules::lattice::Labeled::<_, ::typing_rules::lattice::Public>::new(__v)
                                    }).__private_into_value();
                                });
                                call_args.push(quote! { #name });
                                needs_chain = true;
                            }
                        }
                    }

                    if needs_chain {
                        quote! {
                            {
                                use ::typing_rules::function_rewrite::SecureChain;
                                #(#extractions)*
                                (#receiver).__private_value_mut().#method(#(#call_args),*).await
                            }
                        }
                    } else {
                        // All args are references or no args — direct call
                        quote! {
                            {
                                (#receiver).__private_value_mut().#method(#(#call_args),*).await
                            }
                        }
                    }
                }
                _ => {
                    return syn::Error::new_spanned(await_expr, "mcall! with .await expects a method call `obj.method(args).await`")
                        .to_compile_error()
                        .into();
                }
            }
        }

        // --- fallible method call: mcall!(obj.method(args)?) ---
        // Same as the method call case, but wraps with .transpose()? to
        // propagate errors while preserving the label on the success value.
        // e.g. mcall!(file.read_to_string()?) where read_to_string returns Result<T, E>
        //   → __mcall_preserve_label(&file, |inner| inner.read_to_string()).transpose()?
        //   → Result<Labeled<T, L>, E> after transpose, then ? yields Labeled<T, L>
        Expr::Try(expr_try) => {
            if let Expr::MethodCall(mc) = *expr_try.expr {
                fn peel_try(
                    expr: &Expr,
                ) -> (
                    &Expr,
                    Vec<(&syn::Ident, Option<&syn::AngleBracketedGenericArguments>, &syn::punctuated::Punctuated<Expr, syn::token::Comma>)>,
                ) {
                    if let Expr::MethodCall(mc) = expr {
                        let (base, mut chain) = peel_try(&mc.receiver);
                        chain.push((&mc.method, mc.turbofish.as_ref(), &mc.args));
                        (base, chain)
                    } else {
                        (expr, vec![])
                    }
                }
                let mc_expr = Expr::MethodCall(mc);
                let (base, chain) = peel_try(&mc_expr);
                let closure_body = chain.iter().fold(quote! { inner }, |acc, (method, turbofish, args)| {
                    if let Some(tf) = turbofish {
                        quote! { #acc.#method::<#tf>(#args) }
                    } else {
                        quote! { #acc.#method(#args) }
                    }
                });
                quote! {
                    {
                        #helper
                        (&mut #base).__mcall_mut(|inner| #closure_body).transpose()?
                    }
                }
            } else {
                return syn::Error::new_spanned(expr_try, "mcall! with ? expects a method call `obj.method(args)?`").to_compile_error().into();
            }
        }

        // --- method call: mcall!(obj.method(args)) or mcall!(obj.m1().m2().m3(args)) ---
        // Recursively peels the chain to find the root labeled receiver,
        // then rebuilds the full chain as the closure body.
        // e.g. mcall!(key.chars().all(f)) → __mcall_preserve_label(&key, |inner| inner.chars().all(f))
        // Also handles `Expr::Index` at the leaf (e.g. mcall!(input[..4].to_vec())):
        // the index is folded into the closure body as `inner[idx]`.
        Expr::MethodCall(mc) => {
            #[allow(clippy::type_complexity)]
            fn peel<'a>(
                expr: &'a Expr,
            ) -> (
                &'a Expr,
                Option<&'a Expr>,
                Vec<(&'a syn::Ident, Option<&'a syn::AngleBracketedGenericArguments>, &'a syn::punctuated::Punctuated<Expr, syn::token::Comma>)>,
            ) {
                if let Expr::MethodCall(mc) = expr {
                    let (base, leaf_idx, mut chain) = peel(&mc.receiver);
                    chain.push((&mc.method, mc.turbofish.as_ref(), &mc.args));
                    (base, leaf_idx, chain)
                } else if let Expr::Index(ix) = expr {
                    // Indexed receiver — the labeled root is `ix.expr` and
                    // `ix.index` becomes the first operation inside the closure.
                    (&ix.expr, Some(&ix.index), vec![])
                } else {
                    (expr, None, vec![])
                }
            }
            let mc_expr = Expr::MethodCall(mc);
            let (base, leaf_idx, chain) = peel(&mc_expr);

            // Collect `&ident`-style arguments across all methods in the chain
            // and prepare per-arg `__chain_ref` wrappers. This lets user code
            // write `mcall!(buf.extend_from_slice(&block))` where `block` is a
            // labeled `Labeled<Vec<u8>, L>` and have the macro peel it to
            // `&Vec<u8>` automatically (auto-deref to `&[u8]` for the call).
            // Raw (`T: Public`) values pass through the `SecureChainRef`
            // blanket impl as a no-op chain — so this works for both labeled
            // and plain references uniformly.
            //
            // For each `&ident` arg we generate a fresh `__ma<N>` capture and
            // rewrite the chain's arg list to use the capture name; later we
            // wrap the whole `(&mut base).__mcall_mut(…)` in matching
            // `(ident).__chain_ref(|__ma<N>| …)` calls.
            let mut ref_captures: Vec<(TokenStream2 /* target ident, sans & */, syn::Ident /* fresh cap */)> = Vec::new();
            let chain_rewritten: Vec<(syn::Ident, Option<syn::AngleBracketedGenericArguments>, Vec<TokenStream2>)> =
                chain.iter().map(|(method, turbofish, args)| {
                    let new_args: Vec<TokenStream2> = args.iter().map(|arg| {
                        if let Expr::Reference(r) = arg {
                            if r.mutability.is_none() {
                                if let Expr::Path(p) = &*r.expr {
                                    if p.qself.is_none() && p.path.segments.len() == 1
                                        && p.path.segments[0].arguments.is_empty()
                                    {
                                        let target = quote! { #p };
                                        let cap_name = format_ident!("__ma{}", ref_captures.len());
                                        ref_captures.push((target, cap_name.clone()));
                                        return quote! { #cap_name };
                                    }
                                }
                            }
                        }
                        quote! { #arg }
                    }).collect();
                    ((*method).clone(), turbofish.cloned(), new_args)
                }).collect();

            // Start the closure body with `inner` or `inner[leaf_idx]` depending
            // on whether the chain root was an index expression.
            let start = if let Some(idx) = leaf_idx {
                quote! { inner[#idx] }
            } else {
                quote! { inner }
            };
            let closure_body = chain_rewritten.iter().fold(start, |acc, (method, turbofish, new_args)| {
                if let Some(tf) = turbofish {
                    quote! { #acc.#method::<#tf>(#(#new_args),*) }
                } else {
                    quote! { #acc.#method(#(#new_args),*) }
                }
            });

            let mut wrapped = quote! {
                {
                    #helper
                    (&mut #base).__mcall_mut(|inner| #closure_body)
                }
            };

            // Wrap with one `__chain_ref` per `&ident` arg, innermost call first.
            for (target, cap_name) in ref_captures.iter().rev() {
                wrapped = quote! {
                    {
                        use ::typing_rules::function_rewrite::SecureChainRef;
                        (#target).__chain_ref(|#cap_name| {
                            #wrapped
                        })
                    }
                };
            }

            wrapped
        }

        // --- field access: mcall!(obj.field) or mcall!(obj.0) ---
        Expr::Field(f) => {
            let base = &f.base;
            let member = &f.member;
            quote! {
                {
                    #helper
                    (&mut #base).__mcall_mut(|inner| inner.#member)
                }
            }
        }

        // --- bare index expression: mcall!(obj[idx]) ---
        // Returns the indexed value cloned (since the closure must produce a
        // sized owned value). For chained `mcall!(obj[idx].method())` see the
        // `Expr::MethodCall` arm above which folds index into the chain.
        Expr::Index(idx) => {
            let base = &idx.expr;
            let index = &idx.index;
            quote! {
                {
                    #helper
                    (&mut #base).__mcall_mut(|inner| inner[#index].clone())
                }
            }
        }

        _ => {
            return syn::Error::new_spanned(expr, "mcall! expects a method call `obj.method(args)`, field access `obj.field`, or index `obj[i]`")
                .to_compile_error()
                .into();
        }
    };

    expanded.into()
}

// =========================================================================
// 3. THE RELABEL MACRO (Updating Labels)
// and its helper function __relabel_checked (enforces LEQ on label upgrades)
// =========================================================================

#[proc_macro]
pub fn relabel(input: TokenStream) -> TokenStream {
    let RelabelInput { var, label } = parse_macro_input!(input as RelabelInput);

    // Reject mutable references: relabel!(&mut x, Label) is not allowed.
    if let syn::Expr::Reference(ref_expr) = &var {
        if ref_expr.mutability.is_some() {
            return syn::Error::new_spanned(&var, "relabel! cannot be used on mutable references (`&mut`)").to_compile_error().into();
        }
    }

    let expanded = quote! {
        {
            // Step 1: Normalize input via autoref specialization.
            // Labeled<T, L> → kept as Labeled<T, L>.
            // Raw T → wrapped as Labeled<T, Public>.
            struct __Wrap<V>(V);

            // Inherent: Labeled values pass through unchanged
            impl<T, L: typing_rules::lattice::Label> __Wrap<typing_rules::lattice::Labeled<T, L>> {
                fn __to_labeled(self) -> typing_rules::lattice::Labeled<T, L> {
                    self.0
                }
            }

            // Trait fallback: raw values get wrapped as Labeled<T, Public>
            trait __AsPublic {
                type Inner;
                fn __to_labeled(self) -> typing_rules::lattice::Labeled<Self::Inner, typing_rules::lattice::Public>;
            }
            impl<T> __AsPublic for __Wrap<T> {
                type Inner = T;
                fn __to_labeled(self) -> typing_rules::lattice::Labeled<T, typing_rules::lattice::Public> {
                    typing_rules::lattice::Labeled::new(self.0)
                }
            }

            // Step 2: Check LEQ and relabel.
            typing_rules::__relabel_checked::<_, _, #label>(__Wrap(#var).__to_labeled())
        }
    };
    TokenStream::from(expanded)
}

// =========================================================================
// PC BLOCK (implementation in pc_block_expand.rs)
// =========================================================================

mod pc_block_expand;

/// `pc_block!((Label) { .. })`: runs a block under a PC label with
/// Cocoon-style side-effect checking. See `pc_block_expand` for the rules.
#[proc_macro]
pub fn pc_block(tokens: TokenStream) -> TokenStream {
    pc_block_expand::pc_block_impl(tokens)
}


// =========================================================================
// SIDE-EFFECT-FREE ATTRIBUTE (implementation in side_effect_free.rs)
// =========================================================================

mod side_effect_free;

/// Cocoon's `#[side_effect_free_attr]`: on a function, adds a checked copy of
/// the body and wraps the result in `Vetted`; on a struct or enum, implements
/// `InvisibleSideEffectFree` (Cocoon's `#[derive(InvisibleSideEffectFree)]`).
#[proc_macro_attribute]
pub fn side_effect_free_attr(attr: TokenStream, item: TokenStream) -> TokenStream {
    side_effect_free::side_effect_free_attr_impl(attr, item)
}

// =========================================================================
// HELPERS & ALLOWLIST
// =========================================================================

/// The operator whitelist: which binary operators may appear in a checked
/// context, and the `safe_ops` trait and method each maps to.
///
/// Single source of truth — both `pc_block!` and `#[side_effect_free_attr]`
/// dispatch through this, so an operator cannot be accepted by one and
/// rejected by the other. `None` means "not permitted"; each caller turns
/// that into its own diagnostic.
pub(crate) fn safe_binop(op: &syn::BinOp) -> Option<(&'static str, &'static str)> {
    use syn::BinOp::*;
    Some(match op {
        // comparisons
        Eq(_) => ("SafeCmp", "safe_eq"),
        Ne(_) => ("SafeCmp", "safe_ne"),
        Lt(_) => ("SafeCmp", "safe_lt"),
        Gt(_) => ("SafeCmp", "safe_gt"),
        Le(_) => ("SafeCmp", "safe_le"),
        Ge(_) => ("SafeCmp", "safe_ge"),
        // arithmetic and bitwise
        Add(_) => ("SafeAdd", "safe_add"),
        Sub(_) => ("SafeSub", "safe_sub"),
        Mul(_) => ("SafeMul", "safe_mul"),
        Div(_) => ("SafeDiv", "safe_div"),
        Rem(_) => ("SafeRem", "safe_rem"),
        BitAnd(_) => ("SafeBitAnd", "safe_bitand"),
        BitOr(_) => ("SafeBitOr", "safe_bitor"),
        BitXor(_) => ("SafeBitXor", "safe_bitxor"),
        Shl(_) => ("SafeShl", "safe_shl"),
        Shr(_) => ("SafeShr", "safe_shr"),
        // compound assigns — `is_compound_assign` selects exactly this set
        AddAssign(_) => ("SafeAddAssign", "safe_add_assign"),
        SubAssign(_) => ("SafeSubAssign", "safe_sub_assign"),
        MulAssign(_) => ("SafeMulAssign", "safe_mul_assign"),
        DivAssign(_) => ("SafeDivAssign", "safe_div_assign"),
        RemAssign(_) => ("SafeRemAssign", "safe_rem_assign"),
        BitAndAssign(_) => ("SafeBitAndAssign", "safe_bitand_assign"),
        BitOrAssign(_) => ("SafeBitOrAssign", "safe_bitor_assign"),
        BitXorAssign(_) => ("SafeBitXorAssign", "safe_bitxor_assign"),
        ShlAssign(_) => ("SafeShlAssign", "safe_shl_assign"),
        ShrAssign(_) => ("SafeShrAssign", "safe_shr_assign"),
        _ => return None,
    })
}

/// Unary `-` and `!`. Companion to [`safe_binop`].
pub(crate) fn safe_unop(op: &syn::UnOp) -> Option<(&'static str, &'static str)> {
    Some(match op {
        syn::UnOp::Neg(_) => ("SafeNeg", "safe_neg"),
        syn::UnOp::Not(_) => ("SafeNot", "safe_not"),
        _ => return None,
    })
}

/// The operators `safe_binop` accepts, for diagnostics. Kept next to the
/// table so the message cannot drift from what is actually permitted.
pub(crate) const SUPPORTED_OPS: &str =
    "+ - * / % & | ^ << >> == != < > <= >= && || and their compound assigns";

fn is_compound_assign(op: &syn::BinOp) -> bool {
    matches!(
        op,
        syn::BinOp::AddAssign(_)
            | syn::BinOp::SubAssign(_)
            | syn::BinOp::MulAssign(_)
            | syn::BinOp::DivAssign(_)
            | syn::BinOp::RemAssign(_)
            | syn::BinOp::BitAndAssign(_)
            | syn::BinOp::BitOrAssign(_)
            | syn::BinOp::BitXorAssign(_)
            | syn::BinOp::ShlAssign(_)
            | syn::BinOp::ShrAssign(_)
    )
}

fn is_comparison_op(op: &syn::BinOp) -> bool {
    matches!(
        op,
        syn::BinOp::Eq(_)
            | syn::BinOp::Ne(_)
            | syn::BinOp::Lt(_)
            | syn::BinOp::Gt(_)
            | syn::BinOp::Le(_)
            | syn::BinOp::Ge(_)
    )
}

fn is_logical_op(op: &syn::BinOp) -> bool {
    matches!(op, syn::BinOp::And(_) | syn::BinOp::Or(_))
}

fn comma_separate<T: Iterator<Item = TokenStream2>>(ts: T) -> TokenStream2 {
    let mut tokens = TokenStream2::new();
    for (i, t) in ts.enumerate() {
        if i > 0 {
            tokens.extend(quote! {,});
        }
        tokens.extend(t);
    }
    tokens
}

/// Std functions callable, fully qualified, from checked code (Cocoon's
/// allowlist). Returns the canonical absolute path to emit, so neither an
/// application module named `std` nor a type shadowing a primitive can stand
/// in for the real item.
///
/// Left out on purpose: functions that run application code through a
/// generic bound (`Clone::clone`, `cmp::min` / `max`, `Iterator::next` /
/// `take`, `iter::zip`, `String::from`), map and set operations whose result
/// reveals labeled keys (`HashMap::get` / `insert`, `HashSet::insert` — the
/// `safe_methods` versions restrict keys), and I/O (`File::open`).
fn allowlisted_path(call: &syn::ExprCall) -> Option<TokenStream2> {
    let Expr::Path(p) = &*call.func else { return None };
    if p.qself.is_some() {
        return None;
    }
    let mut full = quote!(#p).to_string();
    full.retain(|c| !c.is_whitespace());
    let key = full.strip_prefix("::").unwrap_or(&full);
    Some(match key {
        "char::is_digit" | "core::primitive::char::is_digit" => quote! { ::core::primitive::char::is_digit },
        "str::len" | "core::primitive::str::len" => quote! { ::core::primitive::str::len },
        "str::to_string" => quote! { <::core::primitive::str as ::std::string::ToString>::to_string },
        "usize::to_string" => quote! { <::core::primitive::usize as ::std::string::ToString>::to_string },
        "std::option::Option::Some" => quote! { ::std::option::Option::Some },
        "std::option::Option::unwrap" => quote! { ::std::option::Option::unwrap },
        "std::string::String::new" => quote! { ::std::string::String::new },
        "std::string::String::clear" => quote! { ::std::string::String::clear },
        "std::string::String::len" => quote! { ::std::string::String::len },
        "std::time::Instant::now" => quote! { ::std::time::Instant::now },
        "std::vec::Vec::new" => quote! { ::std::vec::Vec::new },
        "std::vec::Vec::with_capacity" => quote! { ::std::vec::Vec::with_capacity },
        "std::vec::Vec::push" => quote! { ::std::vec::Vec::push },
        "std::vec::Vec::len" => quote! { ::std::vec::Vec::len },
        _ => return None,
    })
}
