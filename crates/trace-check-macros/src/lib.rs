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
//!
//! **Symbolic verification needs the contract in a non-test build.** The
//! adapter, the counter and the metadata test are M3's dynamic-coverage
//! machinery and stay `#[cfg(test)]`. The *descriptor* — identity, parameter
//! roles, representations and widths, read straight off the signature — is
//! emitted unconditionally as `#[doc(hidden)]` string constants, because a
//! verification harness links the ordinary library build. A `&'static str`
//! const is not codegen'd unless something reads it, so a production build is
//! unchanged.

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
/// * under `#[cfg(test)]`, an **analysis adapter** named `<function>_ct`, plus
///   an invocation counter;
/// * under `#[cfg(test)]`, a metadata test declaring the contract, so a
///   contract with no covering test is still discoverable.
///
/// # The adapter owns the declared secrets
///
/// The adapter takes each declared secret **by value**, launders it through an
/// optimization barrier, marks it, calls the untouched function with that value
/// in its declared parameter slot, and declassifies the result. It also runs the
/// positive control.
///
/// That shape is what makes a contract claim mean something. Two escapes exist
/// if the test is left to do the marking itself:
///
/// * it can invoke the contract with public inputs and mark a secret in a
///   *separate* assertion, so nothing secret ever reaches the function;
/// * it can mark a secret and pass it to the wrong parameter, leaving the
///   declared one public.
///
/// Both were reachable in review and both reported `covered` with exit 0 for a
/// function that is vulnerable with respect to its declared secret. Neither is
/// expressible now: marking happens inside the adapter, bound to the declared
/// slot by the generated signature.
///
/// A declared secret must be a sized value or a reference to one — the adapter
/// has to own it. `&[u8]` is rejected with an explanation; use
/// `assert_constant_time!(secret_bytes = …)` without a contract for that.
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
    let descriptor_const = descriptor_ident(&name_literal);
    let module_const = module_ident(&name_literal);
    let site_const = site_ident(&name_literal);
    let descriptor = describe_contract(&function, &args.secrets);

    let adapter_parts = match adapter_signature(&function, &args.secrets) {
        Ok(parts) => parts,
        Err(error) => return error.to_compile_error().into(),
    };
    let AdapterSignature {
        declarations: arg_decls,
        call_arguments,
        secret_bindings,
        secret_marks,
    } = adapter_parts;
    let return_type = match &function.sig.output {
        ReturnType::Default => quote! {},
        ReturnType::Type(arrow, ty) => quote! { #arrow #ty },
    };

    quote! {
        #function

        /// Module this contract was declared in, so a verifier can qualify its
        /// identity the same way the reports do. Not test-only: a verification
        /// harness links the ordinary library build.
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        #visibility const #module_const: &str = module_path!();

        /// Where the contract is declared, so a report names the developer's
        /// own source rather than a generated harness.
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        #visibility const #site_const: &str = concat!(file!(), ":", line!());

        /// Machine-readable contract descriptor, derived from this function's
        /// own signature at expansion time so it cannot drift from it.
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        #visibility const #descriptor_const: &str = #descriptor;

        /// Counts invocations made through the contract adapter. Test-only.
        #[cfg(test)]
        #[allow(non_upper_case_globals)]
        #visibility static #counter: ::std::sync::atomic::AtomicU64 =
            ::std::sync::atomic::AtomicU64::new(0);

        /// Analysis adapter: owns and marks the declared secrets, runs the
        /// positive control, invokes the untouched function with each secret in
        /// its declared slot, and declassifies the result.
        ///
        /// `#[inline(never)]` keeps this a separate frame so it cannot perturb
        /// the analysis of the function itself.
        #[cfg(test)]
        #[inline(never)]
        #[allow(non_snake_case)]
        #visibility fn #adapter( #( #arg_decls ),* ) #return_type {
            #counter.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed);
            ::trace_check_test::contract_begin(
                &::trace_check_test::meta::qualified(module_path!(), #name_literal),
            );
            // Laundered before marking: interprocedural constant propagation
            // would otherwise let the optimizer use an immediate and never read
            // the marked storage.
            #( #secret_bindings )*
            let __trace_check_guards = ( #( #secret_marks, )* );
            let __trace_check_result = #name( #( #call_arguments ),* );
            drop(__trace_check_guards);
            ::trace_check_test::finish(__trace_check_result)
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

/// Name of the generated contract descriptor constant.
fn descriptor_ident(function: &str) -> Ident {
    format_ident!("__TRACE_CHECK_CONTRACT_{}", function)
}

/// Name of the generated module-path constant.
fn module_ident(function: &str) -> Ident {
    format_ident!("__TRACE_CHECK_MODULE_{}", function)
}

/// Name of the generated declaration-site constant.
fn site_ident(function: &str) -> Ident {
    format_ident!("__TRACE_CHECK_SITE_{}", function)
}

/// Schema version of the emitted descriptor. A verifier that does not
/// understand it refuses rather than guessing at the fields.
const DESCRIPTOR_SCHEMA_VERSION: u32 = 1;

/// Builds the JSON descriptor for a contract from its parsed signature.
///
/// Emitted for every annotated function, including ones whose parameters the
/// symbolic backend cannot represent: an unsupported parameter is recorded as
/// `repr: "unsupported"` with its rendered Rust type, and the *verifier*
/// refuses the run. Rejecting it here instead would stop an existing M3
/// contract from compiling, which M5 is not entitled to do.
fn describe_contract(function: &ItemFn, secrets: &[String]) -> String {
    let mut parameters = Vec::new();
    for (position, argument) in function.sig.inputs.iter().enumerate() {
        let FnArg::Typed(typed) = argument else {
            continue;
        };
        let name = match &*typed.pat {
            Pat::Ident(pattern) => pattern.ident.to_string(),
            _ => continue,
        };
        let role = if secrets.contains(&name) {
            "secret"
        } else {
            "public"
        };
        let mut fields = vec![
            format!("\"name\":\"{}\"", json_escape(&name)),
            format!("\"position\":{position}"),
            format!("\"role\":\"{role}\""),
        ];
        fields.extend(describe_type(&typed.ty));
        parameters.push(format!("{{{}}}", fields.join(",")));
    }

    let returns = match &function.sig.output {
        ReturnType::Default => "{\"repr\":\"unit\"}".to_string(),
        ReturnType::Type(_, ty) => format!("{{{}}}", describe_type(ty).join(",")),
    };

    format!(
        "{{\"schema_version\":{DESCRIPTOR_SCHEMA_VERSION},\"function\":\"{}\",\
         \"parameters\":[{}],\"returns\":{returns}}}",
        json_escape(&function.sig.ident.to_string()),
        parameters.join(","),
    )
}

/// Classifies one type into the representation the symbolic backend uses, as
/// JSON object fields.
///
/// Array lengths must be literal. A proc macro sees the token `TAG_LEN`, not
/// `32`, and a guessed width would be marked into the analysis as fact — so an
/// unresolvable length is `unsupported` and the verifier says why.
fn describe_type(ty: &Type) -> Vec<String> {
    let rust_type = format!("\"rust_type\":\"{}\"", json_escape(&render_type(ty)));
    let mut fields = match ty {
        Type::Path(path) => match path.path.get_ident().map(Ident::to_string).as_deref() {
            Some(name @ ("u8" | "u16" | "u32" | "u64" | "bool")) => {
                vec![format!("\"repr\":\"{name}\"")]
            }
            _ => vec!["\"repr\":\"unsupported\"".to_string()],
        },
        Type::Array(array) => match byte_array_length(array) {
            Some(length) => vec![
                "\"repr\":\"byte-array\"".to_string(),
                format!("\"length\":{length}"),
            ],
            None => vec!["\"repr\":\"unsupported\"".to_string()],
        },
        Type::Reference(reference) if reference.mutability.is_none() => match &*reference.elem {
            Type::Array(array) => match byte_array_length(array) {
                Some(length) => vec![
                    "\"repr\":\"ref-byte-array\"".to_string(),
                    format!("\"length\":{length}"),
                ],
                None => vec!["\"repr\":\"unsupported\"".to_string()],
            },
            _ => vec!["\"repr\":\"unsupported\"".to_string()],
        },
        _ => vec!["\"repr\":\"unsupported\"".to_string()],
    };
    fields.push(rust_type);
    fields
}

/// The literal length of a `[u8; N]`, or `None` for any other array.
fn byte_array_length(array: &syn::TypeArray) -> Option<u64> {
    let Type::Path(element) = &*array.elem else {
        return None;
    };
    if !element.path.is_ident("u8") {
        return None;
    }
    match &array.len {
        Expr::Lit(ExprLit {
            lit: Lit::Int(value),
            ..
        }) => value.base10_parse().ok(),
        _ => None,
    }
}

/// Renders a type for human-readable errors, with `quote`'s token spacing
/// tidied so `& [u8 ; 16]` reads as `&[u8; 16]`.
fn render_type(ty: &Type) -> String {
    let tokens = quote! { #ty }.to_string();
    let mut out = String::with_capacity(tokens.len());
    for character in tokens.chars() {
        match character {
            ' ' => {
                if !matches!(
                    out.chars().next_back(),
                    None | Some('&' | '[' | '(' | '<' | ' ')
                ) {
                    out.push(' ');
                }
            }
            ';' | ',' | ']' | ')' | '>' | '<' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(character);
            }
            other => out.push(other),
        }
    }
    out.trim().to_string()
}

/// Escapes a string for the emitted JSON. The inputs are identifiers and
/// rendered types, so the surface is small, but it is escaped rather than
/// trusted.
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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

/// The pieces needed to generate the analysis adapter.
struct AdapterSignature {
    /// Adapter parameter declarations. A declared secret of type `&T` becomes
    /// `T`, because the adapter must own what it marks.
    declarations: Vec<proc_macro2::TokenStream>,
    /// Expressions passed to the original function, restoring `&` where the
    /// original took a reference.
    call_arguments: Vec<proc_macro2::TokenStream>,
    /// `let x = launder(x);` for each declared secret.
    secret_bindings: Vec<proc_macro2::TokenStream>,
    /// `mark(&x)` for each declared secret.
    secret_marks: Vec<proc_macro2::TokenStream>,
}

/// Builds the adapter signature, taking ownership of the declared secrets.
fn adapter_signature(function: &ItemFn, secrets: &[String]) -> syn::Result<AdapterSignature> {
    let mut parts = AdapterSignature {
        declarations: Vec::new(),
        call_arguments: Vec::new(),
        secret_bindings: Vec::new(),
        secret_marks: Vec::new(),
    };

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

        if !secrets.iter().any(|secret| ident == secret) {
            // A public parameter passes through unchanged.
            parts.declarations.push(quote! { #ident: #ty });
            parts.call_arguments.push(quote! { #ident });
            continue;
        }

        match ty {
            Type::Reference(reference) if reference.mutability.is_none() => {
                let owned = &*reference.elem;
                reject_unowned_secret(owned, &ident)?;
                // Own the value, then hand the function a reference to it.
                parts.declarations.push(quote! { #ident: #owned });
                parts.call_arguments.push(quote! { &#ident });
            }
            Type::Reference(reference) => {
                return Err(syn::Error::new_spanned(
                    reference,
                    "a declared secret cannot be a `&mut` parameter in M3; the adapter must own \
                     what it marks",
                ))
            }
            other => {
                reject_unowned_secret(other, &ident)?;
                parts.declarations.push(quote! { #ident: #other });
                parts.call_arguments.push(quote! { #ident });
            }
        }

        parts
            .secret_bindings
            .push(quote! { let #ident = ::trace_check_test::launder(#ident); });
        parts
            .secret_marks
            .push(quote! { ::trace_check_test::mark(&#ident) });
    }

    Ok(parts)
}

/// Rejects a declared secret the adapter cannot own.
///
/// An unsized type has no owned form to mark, so the contract could not bind
/// marking to the parameter. Saying so at compile time beats generating an
/// adapter that marks the wrong thing.
fn reject_unowned_secret(ty: &Type, ident: &Ident) -> syn::Result<()> {
    let unsized_shape = match ty {
        Type::Slice(_) => Some("a slice"),
        Type::TraitObject(_) => Some("a trait object"),
        Type::Path(path) if path.path.is_ident("str") => Some("a `str`"),
        _ => None,
    };
    if let Some(shape) = unsized_shape {
        return Err(syn::Error::new_spanned(
            ty,
            format!(
                "the declared secret `{ident}` is {shape}, which the contract adapter cannot \
                 own. Use a fixed-size array such as `&[u8; 32]`, or drop the contract and use \
                 `assert_constant_time!(secret_bytes = …)` directly"
            ),
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    /// A supported signature is described with each parameter's role, position,
    /// representation and width, read off the declaration itself.
    #[test]
    fn a_supported_signature_is_described_fully() {
        let function: ItemFn = parse_quote! {
            pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool { true }
        };
        let descriptor = describe_contract(&function, &["expected".to_string()]);
        assert!(descriptor.contains("\"schema_version\":1"), "{descriptor}");
        assert!(
            descriptor.contains("\"function\":\"verify_tag\""),
            "{descriptor}"
        );
        assert!(
            descriptor.contains(
                "{\"name\":\"expected\",\"position\":0,\"role\":\"secret\",\
                 \"repr\":\"ref-byte-array\",\"length\":16,\"rust_type\":\"&[u8; 16]\"}"
            ),
            "{descriptor}"
        );
        assert!(
            descriptor.contains("\"name\":\"supplied\",\"position\":1,\"role\":\"public\""),
            "{descriptor}"
        );
        assert!(
            descriptor.contains("\"returns\":{\"repr\":\"bool\""),
            "{descriptor}"
        );
    }

    /// Scalars carry their width through the representation name.
    #[test]
    fn scalar_parameters_keep_their_width() {
        let function: ItemFn = parse_quote! {
            pub fn reduce(value: u32, modulus: u64) -> u32 { value }
        };
        let descriptor = describe_contract(&function, &["value".to_string()]);
        assert!(
            descriptor.contains("\"role\":\"secret\",\"repr\":\"u32\""),
            "{descriptor}"
        );
        assert!(
            descriptor.contains("\"role\":\"public\",\"repr\":\"u64\""),
            "{descriptor}"
        );
    }

    /// An owned byte array is described by value, distinct from a reference.
    #[test]
    fn an_owned_byte_array_is_distinguished_from_a_reference() {
        let function: ItemFn = parse_quote! {
            pub fn f(key: [u8; 32]) -> u8 { key[0] }
        };
        let descriptor = describe_contract(&function, &["key".to_string()]);
        assert!(
            descriptor.contains("\"repr\":\"byte-array\",\"length\":32"),
            "{descriptor}"
        );
    }

    /// A shape the backend cannot represent is recorded as unsupported with its
    /// rendered type, so the verifier can refuse and name it. Rejecting it in
    /// the macro would stop an existing M3 contract from compiling.
    #[test]
    fn an_unsupported_shape_is_recorded_rather_than_rejected() {
        let function: ItemFn = parse_quote! {
            pub fn f(table: &[u8; TAG_LEN], other: &str) -> bool { true }
        };
        let descriptor = describe_contract(&function, &["table".to_string()]);
        assert!(
            descriptor.contains("\"repr\":\"unsupported\",\"rust_type\":\"&[u8; TAG_LEN]\""),
            "{descriptor}"
        );
        assert!(
            descriptor.contains("\"repr\":\"unsupported\",\"rust_type\":\"&str\""),
            "{descriptor}"
        );
    }

    /// A non-literal array length is never guessed at: a proc macro sees the
    /// token, not the value, and a wrong width would be marked into the
    /// analysis as fact.
    #[test]
    fn a_named_array_length_is_not_guessed() {
        let array: syn::TypeArray = parse_quote! { [u8; TAG_LEN] };
        assert_eq!(byte_array_length(&array), None);
        let literal: syn::TypeArray = parse_quote! { [u8; 16] };
        assert_eq!(byte_array_length(&literal), Some(16));
        let wrong_element: syn::TypeArray = parse_quote! { [u16; 16] };
        assert_eq!(byte_array_length(&wrong_element), None);
    }

    /// A function with no return value is described, not skipped.
    #[test]
    fn a_unit_return_is_described() {
        let function: ItemFn = parse_quote! { pub fn f(secret: u8) {} };
        let descriptor = describe_contract(&function, &["secret".to_string()]);
        assert!(
            descriptor.contains("\"returns\":{\"repr\":\"unit\"}"),
            "{descriptor}"
        );
    }

    /// The emitted descriptor is valid JSON with escaped strings.
    #[test]
    fn the_descriptor_is_well_formed_json() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        let function: ItemFn = parse_quote! {
            pub fn f(secret: &[u8; 8], mode: u8) -> u8 { mode }
        };
        let descriptor = describe_contract(&function, &["secret".to_string()]);
        // Balanced and quote-consistent: a hand-built JSON string has to be
        // checked, not assumed.
        assert_eq!(
            descriptor.chars().filter(|c| *c == '{').count(),
            descriptor.chars().filter(|c| *c == '}').count(),
            "{descriptor}"
        );
        assert!(
            descriptor.chars().filter(|c| *c == '"').count() % 2 == 0,
            "{descriptor}"
        );
    }

    /// Rendered types read the way a developer wrote them.
    #[test]
    fn rendered_types_are_readable() {
        assert_eq!(render_type(&parse_quote! { &[u8; 16] }), "&[u8; 16]");
        assert_eq!(render_type(&parse_quote! { [u8; 16] }), "[u8; 16]");
        assert_eq!(render_type(&parse_quote! { Vec<u8> }), "Vec<u8>");
        assert_eq!(render_type(&parse_quote! { &[u8] }), "&[u8]");
    }
}
