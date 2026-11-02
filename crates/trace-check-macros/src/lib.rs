//! Attribute macros for constant-time contracts and tests.
//!
//! Both macros are deliberately thin. Neither performs analysis — that is the
//! runner's job — and `#[constant_time]` never alters the compiled body of the
//! function it annotates.
//!
//! # Three properties the generated code is responsible for
//!
//! **Discovery must not execute ordinary tests.** Metadata is emitted by
//! *separate* generated tests whose names begin with `__trace_check_`, so the
//! runner can enumerate with libtest's `--list` and then execute only those.
//! An earlier design ran every test in "list mode", which executed the
//! consumer's whole unit-test suite during discovery.
//!
//! **An unrun check must not look like a passing test.** Generated tests carry
//! `#[ignore]`, so plain `cargo test` reports them as `ignored` rather than
//! `ok`. A developer must not see a green test for a security assertion that
//! never ran.
//!
//! **A contract is only covered if its function was actually invoked.** A
//! `target` is not a mere label: `#[constant_time]` emits a `#[cfg(test)]`
//! counter and an `#[inline(never)]` adapter, and `#[ct_test(target = …)]`
//! fails unless that counter advanced during the analyzed call. The adapter
//! delegates to the untouched function, so the code being analyzed is the real
//! one.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Expr, ExprLit, FnArg, Ident, ItemFn, Lit, Meta, Pat, ReturnType, Token, Type,
};

/// Declares that a function must execute in constant time with respect to the
/// named parameters.
///
/// ```ignore
/// #[constant_time(secret = "expected")]
/// pub fn verify_tag(expected: &[u8; 32], supplied: &[u8; 32]) -> bool { … }
/// ```
///
/// Emits three things:
///
/// * the function **verbatim** — no wrapper, no instrumentation, so production
///   behavior is untouched;
/// * under `#[cfg(test)]`, a call counter and an `#[inline(never)]` adapter
///   named `<function>_ct` with the same signature, which counts and delegates.
///   Tests call the adapter so invocation can be proven; the analyzed
///   function's own compiled code is unchanged;
/// * under `#[cfg(test)]`, a metadata test declaring the contract, so a
///   contract with no covering test is still discoverable.
///
/// Parameter names are validated against the signature at compile time, so a
/// typo is an error rather than a contract that silently covers nothing.
#[proc_macro_attribute]
pub fn constant_time(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as SecretArgs);
    let function = parse_macro_input!(item as ItemFn);

    if let Err(error) = reject_unsupported_signature(&function) {
        return error.to_compile_error().into();
    }

    let parameters = parameter_names(&function);
    for secret in &args.secrets {
        if !parameters.iter().any(|name| name == secret) {
            return syn::Error::new(
                args.span,
                format!(
                    "`{secret}` is not a parameter of `{}`. Declared parameters: {}",
                    function.sig.ident,
                    if parameters.is_empty() {
                        "(none)".to_string()
                    } else {
                        parameters.join(", ")
                    }
                ),
            )
            .to_compile_error()
            .into();
        }
    }
    if args.secrets.is_empty() {
        return syn::Error::new(
            args.span,
            "`constant_time` needs at least one `secret = \"param\"`; a contract with no \
             secret declares nothing",
        )
        .to_compile_error()
        .into();
    }

    let name = function.sig.ident.clone();
    let name_literal = name.to_string();
    let secrets = args.secrets.clone();
    let visibility = function.vis.clone();

    let counter = counter_ident(&name_literal);
    let adapter = adapter_ident(&name_literal);
    let meta_fn = format_ident!("__trace_check_contract_{}", name);

    // Rebuild the signature so the adapter can delegate with the same
    // arguments. Only simple ident patterns reach here; the signature check
    // above rejects everything else.
    let (arg_decls, arg_names) = match adapter_arguments(&function) {
        Ok(parts) => parts,
        Err(error) => return error.to_compile_error().into(),
    };
    let return_type = match &function.sig.output {
        ReturnType::Default => quote! {},
        ReturnType::Type(arrow, ty) => quote! { #arrow #ty },
    };

    quote! {
        #function

        /// Counts invocations made through the contract adapter. Test-only.
        #[cfg(test)]
        #[allow(non_upper_case_globals)]
        #visibility static #counter: ::std::sync::atomic::AtomicU64 =
            ::std::sync::atomic::AtomicU64::new(0);

        /// Contract adapter: counts the call and delegates to the untouched
        /// function. `#[inline(never)]` keeps it a separate frame so it cannot
        /// perturb the analysis of the function itself.
        #[cfg(test)]
        #[inline(never)]
        #[allow(non_snake_case)]
        #visibility fn #adapter( #( #arg_decls ),* ) #return_type {
            #counter.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed);
            #name( #( #arg_names ),* )
        }

        #[cfg(test)]
        #[test]
        #[ignore = "trace-check contract metadata; run `cargo trace-check test`"]
        #[allow(non_snake_case)]
        fn #meta_fn() {
            ::trace_check_test::meta::emit_contract(
                &::trace_check_test::meta::qualified(module_path!(), #name_literal),
                #name_literal,
                &[ #( #secrets ),* ],
                file!(),
                line!(),
            );
        }
    }
    .into()
}

/// Marks a test as a constant-time check.
///
/// ```ignore
/// #[ct_test]
/// fn tag_compare_is_constant_time() { … }
///
/// #[ct_test(target = "verify_tag")]
/// fn covers_the_contract() {
///     // must call the generated adapter `verify_tag_ct`, not `verify_tag`
/// }
/// ```
///
/// Expands to an `#[ignore]`d `#[test]` whose body runs only under the
/// instrumented runner, plus a separate metadata test for discovery.
///
/// With `target`, the generated code requires the contract's call counter to
/// advance during the test. Calling the raw function instead of its `_ct`
/// adapter leaves the counter at zero and fails the test, so a contract cannot
/// be reported as covered by a test that never exercised it.
#[proc_macro_attribute]
pub fn ct_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as TestArgs);
    let function = parse_macro_input!(item as ItemFn);

    if !function.sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &function.sig.inputs,
            "a `ct_test` takes no arguments; construct inputs in the body",
        )
        .to_compile_error()
        .into();
    }
    if function.sig.asyncness.is_some() {
        return syn::Error::new_spanned(
            function.sig.asyncness,
            "`ct_test` does not support async functions in M3",
        )
        .to_compile_error()
        .into();
    }

    let name = function.sig.ident.clone();
    let name_literal = name.to_string();
    let body = function.block.clone();
    let attrs = function.attrs.clone();
    let meta_fn = format_ident!("__trace_check_meta_{}", name);

    let (target_meta, before, after) = match &args.target {
        Some(target) => {
            // A target may be a path (`authentication::verify`), so the
            // generated item names are built per segment rather than by
            // pasting the whole string into one identifier.
            let Some(parts) = TargetPaths::parse(target) else {
                return syn::Error::new(
                    proc_macro2::Span::call_site(),
                    format!(
                        "`target = \"{target}\"` is not a function path; expected something \
                         like \"verify_tag\" or \"module::verify_tag\""
                    ),
                )
                .to_compile_error()
                .into();
            };
            let counter = parts.counter;
            let adapter = parts.adapter;
            let target_ident = parts.function;
            (
                quote! { Some(#target) },
                quote! {
                    // Proves the contract's function and its adapter are in
                    // scope: a typo in `target` is a compile error, not a
                    // contract that silently covers nothing.
                    let _ = &#target_ident;
                    let _ = &#adapter;
                    let __trace_check_calls_before =
                        #counter.load(::std::sync::atomic::Ordering::Relaxed);
                },
                quote! {
                    let __trace_check_calls_after =
                        #counter.load(::std::sync::atomic::Ordering::Relaxed);
                    assert!(
                        __trace_check_calls_after > __trace_check_calls_before,
                        concat!(
                            "trace-check: this test declares `target = \"", #target,
                            "\"` but never invoked it through the contract adapter `",
                            stringify!(#adapter),
                            "`. A contract must not be reported as covered by a test that \
                             did not exercise it. Call `",
                            stringify!(#adapter),
                            "(..)` inside `assert_constant_time!`."
                        )
                    );
                    // Tool-controlled evidence that the contract was exercised.
                    // The bare target name, matching what the metadata record
                    // declares, so the runner compares like with like.
                    println!("trace-check-invoked: {}", #target);
                },
            )
        }
        None => (quote! { None }, quote! {}, quote! {}),
    };

    quote! {
        #( #attrs )*
        #[test]
        #[ignore = "trace-check constant-time check; run `cargo trace-check test`"]
        fn #name() {
            // Reached only under the instrumented runner. Plain `cargo test`
            // reports this test as `ignored`, never as `ok`.
            ::trace_check_test::require_run_mode(
                &::trace_check_test::meta::qualified(module_path!(), #name_literal),
            );
            #before
            #body
            #after
            // The runner requires this marker, so it cannot mistake a filtered
            // or renamed test for an executed one.
            println!(
                "trace-check-executed: {}",
                ::trace_check_test::meta::qualified(module_path!(), #name_literal),
            );
        }

        #[cfg(test)]
        #[test]
        #[ignore = "trace-check test metadata; run `cargo trace-check test`"]
        #[allow(non_snake_case)]
        fn #meta_fn() {
            ::trace_check_test::meta::emit_test(
                &::trace_check_test::meta::harness_path(module_path!(), #name_literal),
                &::trace_check_test::meta::qualified(module_path!(), #name_literal),
                #target_meta,
            );
        }
    }
    .into()
}

/// Name of the generated invocation counter for a contract.
fn counter_ident(function: &str) -> Ident {
    format_ident!("__TRACE_CHECK_CALLS_{}", function)
}

/// Name of the generated contract adapter: `verify_tag` -> `verify_tag_ct`.
fn adapter_ident(function: &str) -> Ident {
    format_ident!("{}_ct", function)
}

/// The three paths a `target` refers to, with any module prefix preserved.
struct TargetPaths {
    function: proc_macro2::TokenStream,
    adapter: proc_macro2::TokenStream,
    counter: proc_macro2::TokenStream,
}

impl TargetPaths {
    /// Splits `module::path::function` into the generated item paths, or
    /// returns `None` when a segment is not a valid identifier.
    fn parse(target: &str) -> Option<TargetPaths> {
        let mut segments: Vec<&str> = target.split("::").map(str::trim).collect();
        let name = segments.pop()?;
        if name.is_empty() || !is_identifier(name) {
            return None;
        }
        if segments.iter().any(|segment| !is_identifier(segment)) {
            return None;
        }
        let prefix: Vec<Ident> = segments
            .iter()
            .map(|segment| format_ident!("{}", segment))
            .collect();
        let function = format_ident!("{}", name);
        let adapter = adapter_ident(name);
        let counter = counter_ident(name);
        let lead = if prefix.is_empty() {
            quote! {}
        } else {
            quote! { #( #prefix :: )* }
        };
        Some(TargetPaths {
            function: quote! { #lead #function },
            adapter: quote! { #lead #adapter },
            counter: quote! { #lead #counter },
        })
    }
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && !text.chars().next().is_some_and(|c| c.is_ascii_digit())
        && text.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Splits a signature into declarations and argument names for the adapter.
fn adapter_arguments(
    function: &ItemFn,
) -> syn::Result<(Vec<proc_macro2::TokenStream>, Vec<Ident>)> {
    let mut declarations = Vec::new();
    let mut names = Vec::new();
    for argument in &function.sig.inputs {
        let FnArg::Typed(typed) = argument else {
            return Err(syn::Error::new_spanned(
                argument,
                "`constant_time` supports only free functions in M3, not methods",
            ));
        };
        let Pat::Ident(pattern) = &*typed.pat else {
            return Err(syn::Error::new_spanned(
                &typed.pat,
                "`constant_time` needs plain parameter names so it can generate the contract \
                 adapter; destructuring patterns are not supported in M3",
            ));
        };
        let ident = pattern.ident.clone();
        let ty: &Type = &typed.ty;
        declarations.push(quote! { #ident: #ty });
        names.push(ident);
    }
    Ok((declarations, names))
}

/// Rejects signatures M3 does not support, so an annotation never claims more
/// coverage than the implementation can deliver.
fn reject_unsupported_signature(function: &ItemFn) -> syn::Result<()> {
    if !function.sig.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &function.sig.generics,
            "`constant_time` supports only non-generic free functions in M3; the compiled \
             code of a generic function depends on its instantiation",
        ));
    }
    if function.sig.asyncness.is_some() {
        return Err(syn::Error::new_spanned(
            function.sig.asyncness,
            "`constant_time` does not support async functions in M3",
        ));
    }
    if let Some(receiver) = function.sig.inputs.iter().find_map(|arg| match arg {
        FnArg::Receiver(receiver) => Some(receiver),
        FnArg::Typed(_) => None,
    }) {
        return Err(syn::Error::new_spanned(
            receiver,
            "`constant_time` supports only free functions in M3, not methods",
        ));
    }
    Ok(())
}

fn parameter_names(function: &ItemFn) -> Vec<String> {
    function
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(typed) => match &*typed.pat {
                Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => None,
            },
            FnArg::Receiver(_) => None,
        })
        .collect()
}

/// `secret = "a", secret = "b"`
struct SecretArgs {
    secrets: Vec<String>,
    span: proc_macro2::Span,
}

impl Parse for SecretArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let span = input.span();
        let metas = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;
        let mut secrets = Vec::new();
        for meta in metas {
            match &meta {
                Meta::NameValue(pair) if pair.path.is_ident("secret") => {
                    secrets.push(string_value(&pair.value)?);
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "expected `secret = \"parameter\"`",
                    ))
                }
            }
        }
        Ok(SecretArgs { secrets, span })
    }
}

/// `target = "function"`, optional.
struct TestArgs {
    target: Option<String>,
}

impl Parse for TestArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(TestArgs { target: None });
        }
        let metas = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;
        let mut target = None;
        for meta in metas {
            match &meta {
                Meta::NameValue(pair) if pair.path.is_ident("target") => {
                    target = Some(string_value(&pair.value)?);
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "expected `target = \"function\"`",
                    ))
                }
            }
        }
        Ok(TestArgs { target })
    }
}

fn string_value(expr: &Expr) -> syn::Result<String> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(text),
            ..
        }) => Ok(text.value()),
        other => Err(syn::Error::new_spanned(
            other,
            "expected a string literal naming a parameter",
        )),
    }
}
