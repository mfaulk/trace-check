//! Attribute macros for constant-time contracts and tests.
//!
//! Both macros are deliberately thin. `#[ct_test]` wraps a test body in mode
//! dispatch; `#[constant_time]` emits its function **byte-for-byte unchanged**
//! and adds test-only metadata. Neither performs analysis — that is the
//! runner's job — and neither may change production behavior.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Expr, ExprLit, FnArg, Ident, ItemFn, Lit, Meta, Pat, Token,
};

/// Declares that a function must execute in constant time with respect to the
/// named parameters.
///
/// ```ignore
/// #[constant_time(secret = "expected")]
/// pub fn verify_tag(expected: &[u8; 32], supplied: &[u8; 32]) -> bool { … }
/// ```
///
/// The function is emitted unchanged. A `#[cfg(test)]` metadata test is added
/// so the contract is discoverable even with no `ct_test` covering it, which is
/// what makes an untested contract reportable.
///
/// Parameter names are checked against the signature at compile time, so a typo
/// is an error rather than a contract that silently covers nothing.
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
    let meta_fn = format_ident!("__trace_check_contract_{}", name);

    // The function is reproduced verbatim: no wrapper, no instrumentation, and
    // therefore no way for the annotation to alter production behavior.
    quote! {
        #function

        #[cfg(test)]
        #[test]
        #[allow(non_snake_case)]
        fn #meta_fn() {
            if ::trace_check_test::Mode::from_env() == ::trace_check_test::Mode::List {
                ::trace_check_test::meta::emit_contract(
                    #name_literal,
                    &[ #( #secrets ),* ],
                    file!(),
                    line!(),
                );
            }
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
/// fn covers_the_contract() { … }
/// ```
///
/// Expands to an ordinary `#[test]` whose body runs only under the instrumented
/// runner. Plain `cargo test` prints a skip notice and passes, so a developer
/// without Valgrind is not blocked — but the notice says the check did not run.
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
    let target = match &args.target {
        Some(target) => quote! { Some(#target) },
        None => quote! { None },
    };

    quote! {
        #( #attrs )*
        #[test]
        fn #name() {
            match ::trace_check_test::Mode::from_env() {
                ::trace_check_test::Mode::Skip => {
                    ::trace_check_test::print_skip_notice(
                        concat!(module_path!(), "::", #name_literal),
                    );
                }
                ::trace_check_test::Mode::List => {
                    ::trace_check_test::meta::emit_test(
                        &::trace_check_test::meta::harness_path(module_path!(), #name_literal),
                        #target,
                        &[],
                    );
                }
                ::trace_check_test::Mode::Run => {
                    ::trace_check_test::require_instrumentation(
                        concat!(module_path!(), "::", #name_literal),
                    );
                    #body
                }
            }
        }
    }
    .into()
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

/// Keeps `Ident` in scope for `format_ident!` without an unused import.
#[allow(dead_code)]
fn _ident_marker(_: Option<Ident>) {}
