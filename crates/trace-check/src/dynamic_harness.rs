//! Generating an ordinary Rust harness around a real library function, and
//! running a batch of generated cases under Memcheck.
//!
//! This is M6's artifact source. Where [`crate::harness`] builds a freestanding
//! `no_std` static ELF because BINSEC must not explore program startup, this
//! module builds a **conventional** Rust binary: the existing Valgrind runtime
//! is what consumes it, so there is nothing to gain from freestanding code and a
//! `std` library to lose.
//!
//! # Two artifacts from one generator
//!
//! M7 added a second [`HarnessKind`]. The security harness marks the declared
//! secrets and runs under Memcheck; the discovery harness marks nothing, writes
//! one LLVM coverage profile per case, and exists only to find interesting
//! inputs ([`crate::coverage`]).
//!
//! They come from the same generator rather than from two, because the part
//! that must not diverge is the part a shared generator cannot diverge in: the
//! decoders, the compile-time descriptor check, and the positional argument
//! mapping. An input selected in one artifact is only worth running in the
//! other if it means the same thing in both. Everything that *should* differ —
//! marking, calibration, instrumentation, the dependency on
//! `trace-check-test` — differs structurally, so neither artifact can be
//! argued into having done the other's job.
//!
//! # What keeps the result about the real function
//!
//! **The harness contains no algorithm.** It decodes a generated corpus, marks
//! the declared secret, calls the library, and declassifies the result.
//!
//! **The call is type-checked by rustc.** The generated call names the real
//! parameter types in the real order, and the harness embeds the contract
//! descriptor it was generated from and compares it against the library's own at
//! compile time. A signature that moved does not compile.
//!
//! **Marking is bound to the storage the call receives.** Each case hands the
//! bytes it is about to pass to
//! [`trace_check_test::calibration::secret_binding_probe`]. Calibration alone
//! cannot establish that: it marks its own byte and succeeds whether or not the
//! developer's secret ever reached the function.
//!
//! # Why the target is *not* reified here
//!
//! M5 has to launder the target through a function pointer, because rustc marks
//! small non-generic functions cross-crate-inlinable and a dissolved target
//! leaves no symbol for the analyzer to start at. The M6.1 spike measured the
//! dynamic case and found a plain cross-crate call keeps the target in the
//! primary stack within [`crate::memcheck::ATTRIBUTION_DEPTH`], so the simpler
//! form is used. A target that *is* inlined away shows up as a finding that
//! cannot be attributed, which is reported rather than guessed at.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::contract::{Contract, ContractError, Descriptor, Repr, Role};
use crate::generate::Corpus;
use crate::harness::{Artifact, Library};
use crate::memcheck::{self, MemcheckRun};
use crate::native::{self, Limits};

/// Printed once per process, in the shape the native backend already requires.
pub const RUN_MODE_MARKER: &str = "trace-check-harness:";

/// Printed by a case as its last act, after declassification.
///
/// Followed by the run's nonce and the case id. Completion evidence has to be
/// something the *function under analysis* cannot produce: it runs in this
/// process and can print anything it likes, and a case that forged a marker and
/// then exited would otherwise be credited as having completed. The nonce is
/// generated per run and passed in on the command line, so it is not in the
/// library's source.
pub const CASE_MARKER: &str = "trace-check-case:";

/// Printed once, after every selected case has completed.
///
/// The decisive piece of evidence. A process that died partway through -- or
/// that something terminated early -- never prints this, and Valgrind's
/// `--error-exitcode` masks the program's own status whenever Memcheck reported
/// anything, so the exit code alone cannot distinguish a finished run from an
/// abandoned one.
pub const RUN_COMPLETE_MARKER: &str = "trace-check-run-complete:";

/// Printed once by a discovery harness, before any case runs.
///
/// Carries the status of the baseline profile write. A discovery run whose
/// baseline could not be written has no reference length to validate the
/// per-case profiles against, so its observations are refused.
pub const DISCOVERY_MODE_MARKER: &str = "trace-check-discovery:";

/// Profile written after the first counter reset and before any case.
///
/// Its byte length is the expected length of every per-case profile for this
/// artifact, which is how a profile carrying a duplicate record — the hazard
/// the M7.1 spike found in the persistent-process approach — is detected
/// without a second subprocess per case.
pub const BASELINE_PROFILE: &str = "baseline.profraw";

/// Where the profiling runtime's at-exit write is sent, so it cannot append a
/// stale record to the last case's profile.
pub const DRAIN_PROFILE: &str = "at-exit.profraw";

/// Compilation settings for the analysis artifact, recorded because a result
/// describes one build rather than the library in general.
pub const PROFILE: &str = "release: opt-level=3, debug=true, lto=off, codegen-units=1";

/// Environment override for the path to `trace-check-test`.
pub const TEST_CRATE_ENV: &str = "TRACE_CHECK_TEST_PATH";

/// Stand-in path the generated package's own directory is remapped to, so an
/// artifact hash does not depend on which temporary directory built it.
///
/// It also gives the harness's own coverage regions a fixed, recognizable
/// source path, which is what lets M7 exclude them from target feedback by
/// file identity rather than by guessing.
pub const REMAPPED_HARNESS_DIR: &str = "/trace-check/generated";

/// Compilation settings for the **discovery** artifact.
pub const DISCOVERY_PROFILE: &str =
    "release: opt-level=3, debug=true, lto=off, codegen-units=1, -C instrument-coverage";

/// The instrumentation flag the discovery artifact is built with.
///
/// Written without a space because each `rustflags` array element is one argv
/// entry: `"-C instrument-coverage"` would reach rustc as a single argument
/// whose value has a leading space.
pub const INSTRUMENT_FLAG: &str = "-Cinstrument-coverage";

/// Which of the two artifacts a harness is for.
///
/// The milestone's central constraint, made unrepresentable rather than
/// documented: a discovery harness marks nothing, so it cannot produce the
/// evidence a security conclusion is drawn from, and a security harness writes
/// no coverage profile, so it cannot be mistaken for a discovery run.
///
/// What the two share is the part that must not differ — the decoders, the
/// compile-time descriptor check, and the positional argument mapping — because
/// an input has to mean the same thing in both artifacts for a candidate
/// selected by one to be worth running in the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessKind {
    /// Marks the declared secrets and runs under Memcheck. Produces security
    /// evidence and no coverage.
    Security,
    /// Writes one LLVM profile per case and marks nothing. Produces coverage
    /// feedback and no security evidence whatsoever.
    Discovery,
}

impl HarnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HarnessKind::Security => "security",
            HarnessKind::Discovery => "discovery",
        }
    }

    /// Whether this kind marks secrets. Only a marking harness can produce
    /// evidence about secret dependence.
    pub fn marks_secrets(self) -> bool {
        matches!(self, HarnessKind::Security)
    }

    /// The compilation settings a report records for this artifact.
    pub fn profile(self) -> &'static str {
        match self {
            HarnessKind::Security => PROFILE,
            HarnessKind::Discovery => DISCOVERY_PROFILE,
        }
    }
}

/// A generated dynamic harness.
#[derive(Debug, Clone, Serialize)]
pub struct DynamicHarness {
    pub kind: HarnessKind,
    pub source: String,
    pub source_sha256: String,
    /// Declared secrets, in positional order.
    ///
    /// Recorded for both kinds, because a report has to be able to say that the
    /// discovery artifact knew the roles and still marked nothing.
    pub secret_parameters: Vec<String>,
    /// Bytes marked per case, summed over the declared secrets. Always zero for
    /// [`HarnessKind::Discovery`].
    pub marked_bytes: u64,
}

/// Locates the `trace-check-test` package the generated harness depends on.
///
/// A generated harness needs the marking API, and the developer's library may
/// not depend on it at all — an annotation-only consumer with
/// `dynamic = false` deliberately does not. So the harness brings its own.
///
/// None of these crates is published yet, so the path is resolved from this
/// build rather than from a registry. [`TEST_CRATE_ENV`] overrides it. When
/// neither works the error says so instead of emitting a manifest that cannot
/// resolve.
pub fn test_crate_path() -> Result<PathBuf, DynamicError> {
    if let Some(from_env) = std::env::var_os(TEST_CRATE_ENV) {
        let path = PathBuf::from(from_env);
        if path.join("Cargo.toml").is_file() {
            return Ok(path);
        }
        return Err(DynamicError::TestCrateMissing {
            tried: path.display().to_string(),
            from_env: true,
        });
    }
    // `crates/trace-check` -> `crates/trace-check-test`, which holds while the
    // workspace layout does.
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|crates| crates.join("trace-check-test"));
    match sibling {
        Some(path) if path.join("Cargo.toml").is_file() => Ok(path),
        Some(path) => Err(DynamicError::TestCrateMissing {
            tried: path.display().to_string(),
            from_env: false,
        }),
        None => Err(DynamicError::TestCrateMissing {
            tried: env!("CARGO_MANIFEST_DIR").to_string(),
            from_env: false,
        }),
    }
}

/// Generates the harness source for one contract.
///
/// Deterministic: the same contract and library produce the same bytes, which
/// is what makes [`DynamicHarness::source_sha256`] provenance rather than noise.
pub fn generate(contract: &Contract) -> Result<DynamicHarness, DynamicError> {
    generate_kind(contract, HarnessKind::Security)
}

/// Generates the **discovery** harness for one contract.
///
/// Accepts exactly the contracts [`generate`] accepts, deliberately. A
/// contract that cannot be analyzed is rejected before anything is built, so a
/// developer is never told about a coverage tool when the problem is their
/// annotation — and an exploration run can never be the only thing that
/// succeeded.
pub fn generate_discovery(contract: &Contract) -> Result<DynamicHarness, DynamicError> {
    generate_kind(contract, HarnessKind::Discovery)
}

/// Generates the harness source for one contract and one artifact kind.
pub fn generate_kind(
    contract: &Contract,
    kind: HarnessKind,
) -> Result<DynamicHarness, DynamicError> {
    let descriptor = &contract.descriptor;
    if descriptor.secrets().next().is_none() {
        return Err(DynamicError::Contract(ContractError::Unsupported {
            contract: contract.id.clone(),
            detail: "the contract declares no secret parameter, so there is nothing to mark"
                .to_string(),
        }));
    }
    for parameter in &descriptor.parameters {
        if parameter.repr.bytes().is_none() {
            return Err(DynamicError::Contract(ContractError::Unsupported {
                contract: contract.id.clone(),
                detail: format!(
                    "parameter `{}` has type `{}`, for which no concrete value can be \
                     generated or marked",
                    parameter.name, parameter.rust_type
                ),
            }));
        }
        if parameter.repr == Repr::Bool && parameter.role == Role::Secret {
            return Err(DynamicError::Contract(ContractError::Unsupported {
                contract: contract.id.clone(),
                detail: format!(
                    "parameter `{}` is a secret `bool`; a one-bit secret is disclosed by any \
                     branch on it",
                    parameter.name
                ),
            }));
        }
    }

    let source = render_source(contract, kind)?;
    let secret_parameters: Vec<String> = descriptor
        .secrets()
        .map(|parameter| parameter.name.clone())
        .collect();
    let marked_bytes = if kind.marks_secrets() {
        descriptor
            .secrets()
            .filter_map(|parameter| parameter.repr.bytes())
            .sum()
    } else {
        0
    };
    Ok(DynamicHarness {
        kind,
        source_sha256: format!("{:x}", Sha256::digest(source.as_bytes())),
        source,
        secret_parameters,
        marked_bytes,
    })
}

/// The decoders every generated harness carries. Fixed text, so the
/// case-specific part of the source stays small and readable.
const DECODERS: &str = r#"
/// Decodes `s:<decimal>` and checks it against the parameter's width.
fn decode_scalar(field: &str, bits: u32) -> Result<u64, String> {
    let Some(body) = field.strip_prefix("s:") else {
        return Err(format!("expected a scalar `s:` field, got {field:?}"));
    };
    let value: u64 = body
        .parse()
        .map_err(|_| format!("{body:?} is not an unsigned integer"))?;
    // A value wider than its parameter would be truncated on binding, so the
    // case is refused before anything is marked.
    if bits < 64 && value > (1u64 << bits) - 1 {
        return Err(format!("{value} does not fit in {bits} bits"));
    }
    Ok(value)
}

/// Decodes `b:0` or `b:1`. Rust has exactly two valid `bool` bytes.
fn decode_bool(field: &str) -> Result<bool, String> {
    match field {
        "b:0" => Ok(false),
        "b:1" => Ok(true),
        other => Err(format!("expected `b:0` or `b:1`, got {other:?}")),
    }
}

/// Decodes `x:<hex>` of exactly `len` bytes.
fn decode_bytes(field: &str, len: usize) -> Result<Vec<u8>, String> {
    let Some(body) = field.strip_prefix("x:") else {
        return Err(format!("expected a byte-array `x:` field, got {field:?}"));
    };
    if body.len() != len * 2 {
        return Err(format!(
            "expected {len} bytes ({} hex digits), got {} digits",
            len * 2,
            body.len()
        ));
    }
    let mut bytes = Vec::with_capacity(len);
    for index in (0..body.len()).step_by(2) {
        bytes.push(
            u8::from_str_radix(&body[index..index + 2], 16)
                .map_err(|_| format!("{:?} is not hex", &body[index..index + 2]))?,
        );
    }
    Ok(bytes)
}
"#;

/// The LLVM profiling-runtime entry points a discovery harness calls.
///
/// Declaring them makes instrumentation a **link-time** requirement: without
/// `-C instrument-coverage` the profiling runtime is not linked and the
/// discovery artifact does not build. An uninstrumented discovery binary — one
/// that would run every candidate and report no coverage at all — is therefore
/// not something this pipeline can accidentally produce.
const PROFILE_RUNTIME: &str = r#"
extern "C" {
    fn __llvm_profile_reset_counters();
    fn __llvm_profile_set_filename(name: *const std::os::raw::c_char);
    fn __llvm_profile_write_file() -> std::os::raw::c_int;
}

/// Points the profiling runtime at `path` and writes the current counters.
///
/// Returns the runtime's own status, which the caller reports rather than
/// assumes: a profile that was not written must not be read as a case that
/// covered nothing.
fn write_profile(path: &str) -> i32 {
    let encoded = match std::ffi::CString::new(path) {
        Ok(encoded) => encoded,
        Err(_) => return -1,
    };
    // SAFETY: both are the profiling runtime's documented entry points, linked
    // in by `-C instrument-coverage`. `set_filename` copies the string, so the
    // CString may be dropped afterwards.
    unsafe {
        __llvm_profile_set_filename(encoded.as_ptr());
        __llvm_profile_write_file() as i32
    }
}
"#;

fn render_source(contract: &Contract, kind: HarnessKind) -> Result<String, DynamicError> {
    let descriptor = &contract.descriptor;
    let parameters = &descriptor.parameters;
    let discovery = kind == HarnessKind::Discovery;
    let mut out = String::new();

    out.push_str(&format!(
        "// Generated by trace-check for `{}`. Not written into any source tree,\n\
         // not edited by hand, and containing no copy of the library's implementation.\n\
         //\n\
         // Artifact kind: {}.\n\
         {}\n",
        contract.id,
        kind.as_str(),
        if discovery {
            "// It decodes generated inputs, calls the real function, and writes one LLVM\n\
             // coverage profile per case. It marks NO secret and makes NO security claim:\n\
             // this artifact exists to discover interesting inputs, and a clean run of it\n\
             // says nothing whatsoever about constant-time behavior."
        } else {
            "// It decodes generated inputs, marks the declared secret, calls the real\n\
             // function, and declassifies the result."
        }
    ));

    // Bound at compile time to the descriptor this harness was generated from,
    // so a signature that moved between the probe and this build does not
    // compile and the argument mapping below is certified by rustc.
    out.push_str(&format!(
        "/// The contract descriptor this harness was generated from.\n\
         const CONTRACT: &str = {:?};\n\n\
         const _: () = {{\n\
         \x20   let generated = CONTRACT.as_bytes();\n\
         \x20   let library = {}.as_bytes();\n\
         \x20   assert!(\n\
         \x20       generated.len() == library.len(),\n\
         \x20       \"the library's contract descriptor changed after this harness was generated\"\n\
         \x20   );\n\
         \x20   let mut index = 0;\n\
         \x20   while index < generated.len() {{\n\
         \x20       assert!(\n\
         \x20           generated[index] == library[index],\n\
         \x20           \"the library's contract descriptor changed after this harness was generated\"\n\
         \x20       );\n\
         \x20       index += 1;\n\
         \x20   }}\n\
         }};\n",
        contract.descriptor_json,
        contract.descriptor_const()
    ));
    out.push_str(DECODERS);
    if discovery {
        out.push_str(PROFILE_RUNTIME);
    }

    // One case: decode, then (security) mark, call, declassify — or
    // (discovery) reset counters, call, write the profile.
    out.push_str(&format!(
        "\n/// Runs one generated case.\n\
         ///\n\
         /// {}\n\
         fn run_case({}nonce: &str, id: usize, fields: &[&str]) -> Result<(), String> {{\n\
         \x20   if fields.len() != {} {{\n\
         \x20       return Err(format!(\n\
         \x20           \"case {{id}} has {{}} input(s), but `{}` declares {}\",\n\
         \x20           fields.len()\n\
         \x20       ));\n\
         \x20   }}\n",
        if discovery {
            "Decoding happens before the counters are reset, so the harness's own input\n\
             /// handling is not part of the measured coverage. It is excluded a second time\n\
             /// by source-file identity when the profile is read."
        } else {
            "Nothing is decoded, formatted or compared while a value is marked:\n\
             /// those operations would produce findings belonging to the harness."
        },
        if discovery { "profile_dir: &str, " } else { "" },
        parameters.len(),
        contract.id,
        parameters.len()
    ));

    for (position, parameter) in parameters.iter().enumerate() {
        let name = &parameter.name;
        match &parameter.repr {
            Repr::Scalar(bits) => {
                let ty = format!("u{bits}");
                out.push_str(&format!(
                    "\x20   let {name}: {ty} = decode_scalar(fields[{position}], {bits})?\n\
                     \x20       .try_into()\n\
                     \x20       .map_err(|_| \"a decoded value did not fit its width\".to_string())?;\n"
                ));
            }
            Repr::Bool => {
                out.push_str(&format!(
                    "\x20   let {name}: bool = decode_bool(fields[{position}])?;\n"
                ));
            }
            Repr::ByteArray(length) | Repr::RefByteArray(length) => {
                out.push_str(&format!(
                    "\x20   let {name}: [u8; {length}] = decode_bytes(fields[{position}], {length})?\n\
                     \x20       .try_into()\n\
                     \x20       .map_err(|_| \"a decoded array had the wrong length\".to_string())?;\n"
                ));
            }
            Repr::Unit | Repr::Unsupported => {
                return Err(DynamicError::Contract(ContractError::Unsupported {
                    contract: contract.id.clone(),
                    detail: format!("parameter `{name}` cannot be decoded"),
                }))
            }
        }
    }

    if discovery {
        // Laundered for the same reason the security harness launders: a value
        // the optimizer can see through may be folded into the call and change
        // which regions the library executes. Discovery has to execute the
        // same code the security artifact will be asked about.
        for parameter in parameters {
            out.push_str(&format!(
                "\x20   let {0} = std::hint::black_box({0});\n",
                parameter.name
            ));
        }
        out.push_str(
            "\x20   // Reset last, so nothing above this line is attributed to the case.\n\
             \x20   // SAFETY: the profiling runtime's documented entry point.\n\
             \x20   unsafe { __llvm_profile_reset_counters() };\n",
        );
    } else {
        // Launder before marking. `#[inline(never)]` would not stop
        // interprocedural constant propagation from specializing on a known
        // value and never reading the marked storage.
        for parameter in descriptor.secrets() {
            out.push_str(&format!(
                "\x20   // Laundered before marking: the optimizer must not be able to\n\
                 \x20   // use an immediate and bypass the marked storage.\n\
                 \x20   let {0} = ::trace_check_test::launder({0});\n",
                parameter.name
            ));
        }
        for parameter in descriptor.secrets() {
            out.push_str(&format!(
                "\x20   let __guard_{0} = ::trace_check_test::mark(&{0});\n",
                parameter.name
            ));
        }
        // The binding control, over the bytes the call is about to receive.
        for parameter in descriptor.secrets() {
            let bytes = match &parameter.repr {
                Repr::ByteArray(_) | Repr::RefByteArray(_) => format!("&{}[..]", parameter.name),
                // Reading the marked scalar to build its bytes is itself the
                // evidence: the copy is undefined only if the storage was.
                _ => format!("&{}.to_le_bytes()[..]", parameter.name),
            };
            out.push_str(&format!(
                "\x20   // Proves *this* secret's storage is marked at the call site, which\n\
                 \x20   // calibration cannot: it marks its own byte and passes either way.\n\
                 \x20   ::trace_check_test::calibration::confirm_binding({bytes});\n"
            ));
        }
    }

    let arguments: Vec<String> = parameters
        .iter()
        .map(|parameter| {
            if parameter.repr.passed_by_reference() {
                format!("&{}", parameter.name)
            } else {
                parameter.name.clone()
            }
        })
        .collect();
    let guards: Vec<String> = descriptor
        .secrets()
        .map(|parameter| format!("__guard_{}", parameter.name))
        .collect();

    if discovery {
        // The call, then the profile, then the marker. The marker comes last so
        // a case credited as complete is one whose coverage was already on
        // disk: the ordering is what makes "completed" and "observed" the same
        // set rather than two sets that happen to agree.
        match descriptor.returns {
            Repr::Unit => out.push_str(&format!(
                "\x20   {}({});\n\
                 \x20   let written = write_profile(&format!(\"{{profile_dir}}/case-{{id}}.profraw\"));\n\
                 \x20   println!(\"{CASE_MARKER} {{nonce}} {{id}} produced=unit written={{written}}\");\n",
                contract.call_path(),
                arguments.join(", ")
            )),
            _ => out.push_str(&format!(
                "\x20   let produced = {}({});\n\
                 \x20   let written = write_profile(&format!(\"{{profile_dir}}/case-{{id}}.profraw\"));\n\
                 \x20   // Consumed through a barrier so the call cannot be elided as dead.\n\
                 \x20   let produced = std::hint::black_box(produced);\n\
                 \x20   println!(\"{CASE_MARKER} {{nonce}} {{id}} produced={{}} written={{written}}\", produced as u64);\n",
                contract.call_path(),
                arguments.join(", ")
            )),
        }
    } else {
        match descriptor.returns {
            Repr::Unit => {
                out.push_str(&format!(
                    "\x20   {}({});\n\
                     \x20   drop(({},));\n\
                     \x20   println!(\"{CASE_MARKER} {{nonce}} {{id}} produced=unit\");\n",
                    contract.call_path(),
                    arguments.join(", "),
                    guards.join(", ")
                ));
            }
            _ => {
                out.push_str(&format!(
                    "\x20   let produced = {}({});\n\
                     \x20   drop(({},));\n\
                     \x20   // Declassified before it is formatted, so printing the value cannot\n\
                     \x20   // produce findings inside `core::fmt`.\n\
                     \x20   let produced = ::trace_check_test::finish(produced);\n\
                     \x20   println!(\"{CASE_MARKER} {{nonce}} {{id}} produced={{}}\", produced as u64);\n",
                    contract.call_path(),
                    arguments.join(", "),
                    guards.join(", ")
                ));
            }
        }
    }
    out.push_str("\x20   Ok(())\n}\n");

    // The driver: read the corpus, select the requested cases, run them in the
    // order given.
    let (destructure, usage) = if discovery {
        (
            "[_, corpus_path, selection, nonce, profile_dir]",
            "usage: <harness> <corpus-path> all|<id>[,<id>...] <nonce> <profile-dir>",
        )
    } else {
        (
            "[_, corpus_path, selection, nonce]",
            "usage: <harness> <corpus-path> all|<id>[,<id>...] <nonce>",
        )
    };
    // Security: announce the run mode, refuse an uninstrumented process, and
    // calibrate. Discovery: write the post-reset baseline profile, whose byte
    // length is the expected length of every per-case profile and so is how a
    // profile with a duplicate record is caught.
    let preamble = if discovery {
        format!(
            r#"    // SAFETY: the profiling runtime's documented entry point.
    unsafe {{ __llvm_profile_reset_counters() }};
    let baseline = write_profile(&format!("{{profile_dir}}/{BASELINE_PROFILE}"));
    println!("{DISCOVERY_MODE_MARKER} {{nonce}} baseline={{baseline}}");
"#
        )
    } else {
        format!(
            r#"    // The structured run-mode line the runner requires. A clean result from an
    // uninstrumented process is rejected rather than believed.
    println!(
        "{RUN_MODE_MARKER} run_mode={{}}",
        ::trace_check_test::run_mode()
    );
    ::trace_check_test::require_instrumentation("{}");
    // Calibration once per process: marking reaches compiled code here.
    ::trace_check_test::calibration::run();
"#,
            contract.id
        )
    };
    // Discovery: the profiling runtime writes the profile once more at exit, to
    // whatever filename is current — which would append a second, stale record
    // to the last case's file and silently double its counters. Draining it to
    // a scratch path makes the last case no different from the others.
    let epilogue = if discovery {
        format!(
            "    let drained = write_profile(&format!(\"{{profile_dir}}/{DRAIN_PROFILE}\"));\n\
             \x20   let _ = drained;\n"
        )
    } else {
        String::new()
    };
    let call = if discovery {
        "run_case(profile_dir, nonce, *id, &borrowed)"
    } else {
        "run_case(nonce, *id, &borrowed)"
    };
    out.push_str(&format!(
        r#"
fn main() {{
    let argv: Vec<String> = std::env::args().collect();
    let {destructure} = argv.as_slice() else {{
        eprintln!("{usage}");
        std::process::exit(2);
    }};
    let text = match std::fs::read_to_string(corpus_path) {{
        Ok(text) => text,
        Err(error) => {{
            eprintln!("cannot read the corpus at {{corpus_path}}: {{error}}");
            std::process::exit(2);
        }}
    }};

    // `# `-prefixed lines are the corpus header.
    let mut cases: Vec<(usize, Vec<String>)> = Vec::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {{
        let fields: Vec<&str> = line.split(' ').filter(|f| !f.is_empty()).collect();
        if fields.is_empty() {{
            continue;
        }}
        let Ok(id) = fields[0].parse::<usize>() else {{
            eprintln!("malformed corpus line: {{line:?}}");
            std::process::exit(2);
        }};
        // fields[1] is the strategy, which the harness does not need.
        cases.push((id, fields[2..].iter().map(|f| f.to_string()).collect()));
    }}

    let selected: Vec<usize> = if selection == "all" {{
        cases.iter().map(|(id, _)| *id).collect()
    }} else {{
        let mut ids = Vec::new();
        for field in selection.split(',').filter(|f| !f.is_empty()) {{
            match field.parse::<usize>() {{
                Ok(id) => ids.push(id),
                Err(_) => {{
                    eprintln!("not a case id: {{field:?}}");
                    std::process::exit(2);
                }}
            }}
        }}
        ids
    }};
    if selected.is_empty() {{
        eprintln!("no cases selected; a run that checks nothing is not a pass");
        std::process::exit(2);
    }}

{preamble}
    let mut completed = 0usize;
    for id in &selected {{
        let Some((_, fields)) = cases.iter().find(|(case_id, _)| case_id == id) else {{
            eprintln!("case {{id}} is not in the corpus");
            std::process::exit(2);
        }};
        let borrowed: Vec<&str> = fields.iter().map(String::as_str).collect();
        if let Err(error) = {call} {{
            // An invalid input is refused before analysis rather than bound to
            // the wrong width.
            eprintln!("case {{id}} was rejected: {{error}}");
            std::process::exit(2);
        }}
        completed += 1;
    }}
{epilogue}    println!("{RUN_COMPLETE_MARKER} {{nonce}} cases={{completed}}");
}}
"#
    ));

    Ok(out)
}

/// Builds the analysis artifact: the generated harness plus the real library.
pub fn build(
    library: &Library,
    harness: &DynamicHarness,
    contract: &str,
    work_dir: &Path,
    target_dir: &Path,
) -> Result<Artifact, DynamicError> {
    let crate_dir = work_dir.join(match harness.kind {
        HarnessKind::Security => "dynamic-harness",
        // A separate directory, so the two artifacts never share a generated
        // source file, a lockfile or a build cache entry. They are different
        // programs and a report names both.
        HarnessKind::Discovery => "discovery-harness",
    });
    let package = format!(
        "{}-{}",
        match harness.kind {
            HarnessKind::Security => "tc-check",
            HarnessKind::Discovery => "tc-explore",
        },
        contract.replace("::", "-")
    );
    std::fs::create_dir_all(crate_dir.join("src"))
        .map_err(|e| DynamicError::Io(format!("{}: {e}", crate_dir.display())))?;

    // Only the security harness needs the marking API. The discovery harness
    // deliberately does not depend on it at all: a harness that cannot call
    // `mark` cannot be argued into having marked anything.
    let test_dependency = if harness.kind.marks_secrets() {
        format!(
            "[dependencies.trace-check-test]\npath = {:?}\n\n",
            test_crate_path()?.display().to_string()
        )
    } else {
        String::new()
    };
    // `[workspace]` makes the generated package its own root, so it is never
    // absorbed into whatever workspace the temporary directory sits inside.
    //
    // `debug = true` and `strip = false` because a finding without a source
    // location is not actionable; `lto = false` so the target keeps a frame the
    // finding can be attributed to. The discovery artifact keeps the same
    // settings so the two builds differ in exactly one documented respect.
    let manifest = format!(
        "[package]\nname = {package:?}\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         publish = false\n\n[[bin]]\nname = {package:?}\npath = \"src/main.rs\"\n\n\
         {}\n{test_dependency}\
         [profile.release]\nopt-level = 3\ndebug = true\npanic = \"unwind\"\n\
         codegen-units = 1\nlto = false\nincremental = false\nstrip = false\n\n\
         [workspace]\n",
        library.dependency_stanza(),
    );
    // The work directory is random, and `debug = true` bakes the generated
    // source's absolute path into the artifact — so without remapping, two runs
    // of the same contract produce different hashes and `--replay` could never
    // report that it ran against the same build. Remapping makes the hash a
    // function of the inputs rather than of the temporary directory.
    //
    // For the discovery artifact it does a second job: the harness's own
    // coverage regions get the fixed `REMAPPED_HARNESS_DIR` path, so excluding
    // them from target feedback is an exact comparison rather than a heuristic.
    std::fs::create_dir_all(crate_dir.join(".cargo"))
        .map_err(|e| DynamicError::Io(format!("{}: {e}", crate_dir.display())))?;
    let instrumentation = if harness.kind.marks_secrets() {
        String::new()
    } else {
        format!(", {INSTRUMENT_FLAG:?}")
    };
    let cargo_config = format!(
        "[build]\nrustflags = [\"--remap-path-prefix\", {:?}{instrumentation}]\n",
        format!("{}={REMAPPED_HARNESS_DIR}", crate_dir.display())
    );
    write(&crate_dir.join(".cargo/config.toml"), &cargo_config)?;
    write(&crate_dir.join("Cargo.toml"), &manifest)?;
    write(&crate_dir.join("src/main.rs"), &harness.source)?;

    // Run from inside the generated package: Cargo discovers
    // `.cargo/config.toml` relative to the working directory, not to
    // `--manifest-path`, so the remapping above is only honored this way.
    let output = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--message-format=json-render-diagnostics",
        ])
        .arg("--target-dir")
        .arg(target_dir)
        .current_dir(&crate_dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| DynamicError::Io(format!("cannot run cargo: {e}")))?;
    if !output.status.success() {
        return Err(DynamicError::Build {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    // Cargo's own structured output, never a constructed path: `target/release/
    // <name>` is wrong whenever `CARGO_TARGET_DIR` is set.
    let path = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .filter_map(|message| message["executable"].as_str().map(PathBuf::from))
        .next_back()
        .ok_or_else(|| DynamicError::Build {
            stderr: "cargo reported no executable for the generated harness".to_string(),
        })?;

    let bytes =
        std::fs::read(&path).map_err(|e| DynamicError::Io(format!("{}: {e}", path.display())))?;
    let lockfile_sha256 = std::fs::read(crate_dir.join("Cargo.lock"))
        .map(|bytes| format!("{:x}", Sha256::digest(&bytes)))
        .unwrap_or_else(|_| "unavailable".to_string());
    Ok(Artifact {
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        path,
        lockfile_sha256,
    })
}

/// What one batched Memcheck run produced.
///
/// Deliberately evidence rather than a verdict: classification needs the
/// contract's policy and belongs to the caller.
#[derive(Debug)]
pub struct BatchRun {
    /// Case ids this run was asked to execute, in order.
    ///
    /// Always taken from the corpus or the caller's selection — never from the
    /// harness's own output, which would make the comparison below vacuous.
    pub requested: Vec<usize>,
    /// Case ids that printed their completion marker, in the order printed.
    pub completed: Vec<usize>,
    /// Case count from the final run-completion marker, when it was printed.
    pub run_complete: Option<usize>,
    /// Whether the harness reported running under Valgrind.
    pub instrumented: bool,
    /// The parsed Memcheck report, when the XML was complete.
    pub run: Option<MemcheckRun>,
    /// Why the XML could not be trusted, when it could not.
    pub parse_error: Option<String>,
    pub exit_code: Option<i32>,
    /// Whether the exit status is one a finished harness can produce.
    pub status_ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl BatchRun {
    /// Whether this run is trustworthy evidence that every requested case ran.
    ///
    /// Four independent conditions, because the obvious one is not enough:
    ///
    /// * the exit status is one a finished harness can produce,
    /// * the final run-completion marker was printed,
    /// * its case count matches what was requested,
    /// * and the completed ids are *exactly* the requested ids, in order.
    ///
    /// Counting completions against requests was the original check, and it
    /// could be satisfied by a case that printed a plausible marker and then
    /// terminated the process. Every marker now carries a per-run nonce, so the
    /// code under analysis cannot produce one, and the final marker closes the
    /// early-exit case that no amount of per-case evidence can.
    pub fn all_completed(&self) -> bool {
        self.status_ok
            && self.run_complete == Some(self.requested.len())
            && self.completed == self.requested
    }

    /// Why this run is not complete evidence, for a report.
    pub fn incompleteness(&self) -> Option<String> {
        if self.all_completed() {
            return None;
        }
        if !self.status_ok {
            return Some(format!(
                "the harness exited with {}, which a finished run does not",
                self.exit_code
                    .map_or_else(|| "a signal".to_string(), |code| format!("code {code}"))
            ));
        }
        match self.run_complete {
            None => Some(
                "the harness never printed its run-completion marker, so it did not \
                 finish; a case may have terminated the process early"
                    .to_string(),
            ),
            Some(count) if count != self.requested.len() => Some(format!(
                "the harness reported finishing {count} case(s) but {} were requested",
                self.requested.len()
            )),
            _ => Some(format!(
                "the completed cases {:?} are not exactly the requested cases {:?}",
                self.completed, self.requested
            )),
        }
    }
}

/// Runs the selected cases of a corpus in one Memcheck process.
///
/// `None` for `ids` runs the whole corpus.
pub fn run_batch(
    valgrind: &Path,
    artifact: &Path,
    corpus_path: &Path,
    ids: Option<&[usize]>,
    limits: Limits,
) -> Result<BatchRun, DynamicError> {
    let selection = match ids {
        None => "all".to_string(),
        Some([]) => {
            return Err(DynamicError::NothingSelected);
        }
        Some(ids) => ids
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(","),
    };
    // Resolved before the run, from the corpus itself. Reconstructing the
    // request from the harness's own completion markers made `all_completed`
    // trivially true for the whole-corpus path: a harness that ran three of
    // thirty cases reported three requested and three completed.
    let requested: Vec<usize> = match ids {
        Some(ids) => ids.to_vec(),
        None => corpus_case_ids(corpus_path)?,
    };
    if requested.is_empty() {
        return Err(DynamicError::NothingSelected);
    }

    let nonce = run_nonce();
    let args = vec![corpus_path.display().to_string(), selection, nonce.clone()];
    let output = native::run_under_memcheck(valgrind, artifact, &args, &[], limits)
        .map_err(|e| DynamicError::Memcheck(e.to_string()))?;

    let (run, parse_error) = match memcheck::parse(&output.xml) {
        Ok(run) => (Some(run), None),
        Err(error) => (None, Some(error.to_string())),
    };
    // Valgrind's `--error-exitcode` replaces the program's own status whenever
    // Memcheck reported anything, so a findings exit is indistinguishable from
    // a clean one here and both are acceptable. Anything else means the harness
    // itself failed, which is not a security result.
    let status_ok = output.exit_code == Some(0) || output.exited_with_findings();
    Ok(BatchRun {
        requested,
        completed: completed_cases(&output.stdout, &nonce),
        run_complete: run_complete_count(&output.stdout, &nonce),
        instrumented: instrumented(&output.stdout),
        run,
        parse_error,
        exit_code: output.exit_code,
        status_ok,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

/// A value the code under analysis cannot know.
///
/// Public because the discovery backend needs the same evidence discipline for
/// its completion markers.
///
/// It is compiled before this runs, and the nonce never reaches it as an input
/// — only as an argument the generated harness echoes. That is what makes a
/// completion marker evidence rather than a string anything in the process
/// could print.
pub fn run_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = nanos
        ^ (u64::from(std::process::id()) << 32)
        ^ SEQUENCE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    format!("{mixed:016x}")
}

/// Case ids in a staged corpus, in file order.
///
/// The corpus is the authority on what a whole-corpus run was asked to do.
fn corpus_case_ids(corpus_path: &Path) -> Result<Vec<usize>, DynamicError> {
    let text = std::fs::read_to_string(corpus_path)
        .map_err(|e| DynamicError::Io(format!("{}: {e}", corpus_path.display())))?;
    let mut ids = Vec::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let Some(field) = line.split(' ').find(|field| !field.is_empty()) else {
            continue;
        };
        let id = field.parse().map_err(|_| {
            DynamicError::Io(format!(
                "{}: {field:?} is not a case id",
                corpus_path.display()
            ))
        })?;
        ids.push(id);
    }
    Ok(ids)
}

/// Case ids that printed their completion marker with this run's nonce.
///
/// Anchored at the start of a line *and* matched against the nonce. Accepting
/// the marker anywhere in a line meant the function under analysis could emit
/// one: it shares this process's stdout, so "a case completed" was not
/// tool-controlled evidence at all.
pub fn completed_cases(stdout: &str, nonce: &str) -> Vec<usize> {
    let prefix = format!("{CASE_MARKER} {nonce} ");
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|id| id.parse().ok())
        .collect()
}

/// The case count from the final run-completion marker, if it was printed.
pub fn run_complete_count(stdout: &str, nonce: &str) -> Option<usize> {
    let prefix = format!("{RUN_COMPLETE_MARKER} {nonce} ");
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .filter_map(|rest| rest.trim().strip_prefix("cases="))
        .filter_map(|count| count.trim().parse().ok())
        .next_back()
}

/// Whether the harness reported running under Valgrind.
fn instrumented(stdout: &str) -> bool {
    stdout
        .lines()
        .filter_map(|line| line.find(RUN_MODE_MARKER).map(|at| &line[at..]))
        .filter_map(|rest| {
            rest.split_whitespace()
                .find_map(|field| field.strip_prefix("run_mode="))
        })
        .any(|mode| mode == "valgrind")
}

fn write(path: &Path, contents: &str) -> Result<(), DynamicError> {
    std::fs::write(path, contents).map_err(|e| DynamicError::Io(format!("{}: {e}", path.display())))
}

/// Writes a corpus where the generated harness can read it.
pub fn stage_corpus(corpus: &Corpus, work_dir: &Path) -> Result<PathBuf, DynamicError> {
    let path = work_dir.join("corpus.tcc");
    write(&path, &corpus.to_wire())?;
    Ok(path)
}

#[derive(Debug)]
pub enum DynamicError {
    Io(String),
    Contract(ContractError),
    Build { stderr: String },
    Memcheck(String),
    NothingSelected,
    TestCrateMissing { tried: String, from_env: bool },
}

impl From<ContractError> for DynamicError {
    fn from(error: ContractError) -> Self {
        DynamicError::Contract(error)
    }
}

impl fmt::Display for DynamicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DynamicError::Io(message) => write!(f, "{message}"),
            DynamicError::Contract(error) => write!(f, "{error}"),
            DynamicError::Build { stderr } => write!(
                f,
                "building the generated harness failed:\n{}",
                stderr
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("Compiling"))
                    .take(12)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            DynamicError::Memcheck(message) => write!(f, "{message}"),
            DynamicError::NothingSelected => write!(
                f,
                "no cases were selected for this batch, and a run that checks nothing is not a \
                 pass"
            ),
            DynamicError::TestCrateMissing { tried, from_env } => write!(
                f,
                "the generated harness needs the `trace-check-test` package for secret \
                 marking, which was not found at {tried}. {}",
                if *from_env {
                    format!("{TEST_CRATE_ENV} names a directory with no Cargo.toml")
                } else {
                    format!(
                        "These crates are not published yet, so the path is resolved from this \
                         build; set {TEST_CRATE_ENV} to the package directory"
                    )
                }
            ),
        }
    }
}

impl std::error::Error for DynamicError {}

/// The return type's width, used to decide how a value is consumed.
pub fn consumes_value(descriptor: &Descriptor) -> bool {
    !matches!(descriptor.returns, Repr::Unit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::Descriptor;

    const SUBSTITUTE_MODE: &str = r#"{"schema_version":1,"function":"substitute_mode","parameters":[{"name":"index","position":0,"role":"secret","repr":"u8","rust_type":"u8"},{"name":"mode","position":1,"role":"public","repr":"u8","rust_type":"u8"}],"returns":{"repr":"u8","rust_type":"u8"}}"#;

    const VERIFY_TAG: &str = r#"{"schema_version":1,"function":"verify_tag","parameters":[{"name":"expected","position":0,"role":"secret","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"},{"name":"supplied","position":1,"role":"public","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"}],"returns":{"repr":"bool","rust_type":"bool"}}"#;

    fn contract(json: &str, module: &str, function: &str) -> Contract {
        Contract {
            id: format!("{module}::{function}"),
            module: module.into(),
            function: function.into(),
            site: "src/lookup.rs:51".into(),
            descriptor: Descriptor::parse(json).expect("parses"),
            descriptor_json: json.to_string(),
        }
    }

    /// The generated harness calls the real function positionally, with the
    /// declared types, so a wrong order or width is a compile error.
    #[test]
    fn the_generated_call_is_positional_and_typed() {
        let harness = generate(&contract(
            SUBSTITUTE_MODE,
            "crypto::lookup",
            "substitute_mode",
        ))
        .expect("generated");
        assert!(
            harness
                .source
                .contains("crypto::lookup::substitute_mode(index, mode)"),
            "{}",
            harness.source
        );
        assert!(harness
            .source
            .contains("let index: u8 = decode_scalar(fields[0], 8)?"));
        assert!(harness
            .source
            .contains("let mode: u8 = decode_scalar(fields[1], 8)?"));
    }

    /// A by-reference parameter is owned by the harness and passed as a
    /// reference, so the marked bytes are the ones the call receives.
    #[test]
    fn reference_parameters_are_owned_and_borrowed_at_the_call() {
        let harness =
            generate(&contract(VERIFY_TAG, "crypto::tag", "verify_tag")).expect("generated");
        assert!(harness
            .source
            .contains("let expected: [u8; 16] = decode_bytes(fields[0], 16)?"));
        assert!(harness
            .source
            .contains("crypto::tag::verify_tag(&expected, &supplied)"));
        assert_eq!(harness.marked_bytes, 16);
        assert_eq!(harness.secret_parameters, vec!["expected"]);
    }

    /// Only declared secrets are marked, and each is laundered first.
    #[test]
    fn only_declared_secrets_are_marked() {
        let harness = generate(&contract(
            SUBSTITUTE_MODE,
            "crypto::lookup",
            "substitute_mode",
        ))
        .expect("generated");
        assert!(harness
            .source
            .contains("let index = ::trace_check_test::launder(index);"));
        assert!(harness
            .source
            .contains("let __guard_index = ::trace_check_test::mark(&index);"));
        // The public parameter is neither laundered nor marked.
        assert!(
            !harness.source.contains("mark(&mode)"),
            "{}",
            harness.source
        );
        assert!(
            !harness.source.contains("launder(mode)"),
            "{}",
            harness.source
        );
        assert_eq!(harness.secret_parameters, vec!["index"]);
        assert_eq!(harness.marked_bytes, 1);
    }

    /// Every case runs the binding control over the bytes it is about to pass,
    /// which is the thing calibration cannot establish.
    #[test]
    fn every_case_confirms_the_secret_binding() {
        let scalar = generate(&contract(
            SUBSTITUTE_MODE,
            "crypto::lookup",
            "substitute_mode",
        ))
        .expect("generated");
        assert!(
            scalar
                .source
                .contains("confirm_binding(&index.to_le_bytes()[..])"),
            "{}",
            scalar.source
        );
        let array =
            generate(&contract(VERIFY_TAG, "crypto::tag", "verify_tag")).expect("generated");
        assert!(
            array.source.contains("confirm_binding(&expected[..])"),
            "{}",
            array.source
        );
    }

    /// The harness is bound at compile time to the descriptor it was generated
    /// from, so a signature that moved under it does not build.
    #[test]
    fn the_harness_is_bound_to_its_descriptor() {
        let harness = generate(&contract(
            SUBSTITUTE_MODE,
            "crypto::lookup",
            "substitute_mode",
        ))
        .expect("generated");
        assert!(harness
            .source
            .contains("crypto::lookup::__TRACE_CHECK_CONTRACT_substitute_mode.as_bytes()"));
        assert!(harness.source.contains("const _: () = {"));
    }

    /// The result is declassified before it is formatted, so printing it cannot
    /// produce findings inside `core::fmt`.
    #[test]
    fn the_result_is_declassified_before_it_is_printed() {
        let harness = generate(&contract(
            SUBSTITUTE_MODE,
            "crypto::lookup",
            "substitute_mode",
        ))
        .expect("generated");
        let source = &harness.source;
        let finish = source
            .find("::trace_check_test::finish(produced)")
            .expect("finish");
        let print = source.find("println!(\"trace-check-case:").expect("marker");
        assert!(
            finish < print,
            "the value is printed before declassification"
        );
    }

    /// Every marker the harness prints carries the run's nonce, so the runner
    /// can tell its own evidence from anything else on stdout.
    #[test]
    fn generated_markers_carry_the_run_nonce() {
        let harness = generate(&contract(
            SUBSTITUTE_MODE,
            "crypto::lookup",
            "substitute_mode",
        ))
        .expect("generated");
        assert!(
            harness
                .source
                .contains(r#"println!("trace-check-case: {nonce} {id} produced={}""#),
            "{}",
            harness.source
        );
        assert!(
            harness
                .source
                .contains(r#"println!("trace-check-run-complete: {nonce} cases={completed}")"#),
            "{}",
            harness.source
        );
        // The nonce arrives on the command line, not from the corpus.
        assert!(harness
            .source
            .contains("let [_, corpus_path, selection, nonce] = argv.as_slice()"));
    }

    /// A unit return is still called and still records completion.
    #[test]
    fn a_unit_return_is_handled() {
        let json = r#"{"schema_version":1,"function":"absorb","parameters":[{"name":"value","position":0,"role":"secret","repr":"u32","rust_type":"u32"}],"returns":{"repr":"unit","rust_type":""}}"#;
        let harness = generate(&contract(json, "crypto::reduce", "absorb")).expect("generated");
        assert!(harness.source.contains("crypto::reduce::absorb(value);"));
        assert!(harness.source.contains("produced=unit"));
        assert_eq!(harness.marked_bytes, 4);
    }

    /// Generation is deterministic, which is what makes the source hash
    /// provenance rather than noise.
    #[test]
    fn generation_is_deterministic() {
        let subject = contract(SUBSTITUTE_MODE, "crypto::lookup", "substitute_mode");
        let first = generate(&subject).expect("generated");
        let second = generate(&subject).expect("generated");
        assert_eq!(first.source_sha256, second.source_sha256);
        assert_eq!(first.source, second.source);
        assert_eq!(first.source_sha256.len(), 64);
    }

    /// A contract with no declared secret is refused: there is nothing to mark,
    /// so a clean run would mean nothing.
    #[test]
    fn a_contract_without_a_secret_is_refused() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[{"name":"a","position":0,"role":"public","repr":"u8","rust_type":"u8"}],"returns":{"repr":"u8","rust_type":"u8"}}"#;
        let error = generate(&contract(json, "crypto", "f")).expect_err("refused");
        assert!(error.to_string().contains("no secret parameter"), "{error}");
    }

    /// A secret `bool` is refused, matching the symbolic backend's rule.
    #[test]
    fn a_secret_bool_is_refused() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[{"name":"flag","position":0,"role":"secret","repr":"bool","rust_type":"bool"}],"returns":{"repr":"u8","rust_type":"u8"}}"#;
        let error = generate(&contract(json, "crypto", "f")).expect_err("refused");
        assert!(error.to_string().contains("one-bit secret"), "{error}");
    }

    /// An unsupported parameter is refused with the type as written.
    #[test]
    fn an_unsupported_parameter_is_refused() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[{"name":"key","position":0,"role":"secret","repr":"unsupported","rust_type":"&[u8]"}],"returns":{"repr":"u8","rust_type":"u8"}}"#;
        let error = generate(&contract(json, "crypto", "f")).expect_err("refused");
        assert!(error.to_string().contains("&[u8]"), "{error}");
    }

    /// Completed cases come from a line-anchored, nonce-matched marker.
    #[test]
    fn completed_cases_come_from_the_marker() {
        let stdout = "\
trace-check-harness: run_mode=valgrind
trace-check-case: abc123 0 produced=3
trace-check-case: abc123 11 produced=7
trace-check-run-complete: abc123 cases=2
";
        assert_eq!(completed_cases(stdout, "abc123"), vec![0, 11]);
        assert_eq!(run_complete_count(stdout, "abc123"), Some(2));
        assert!(instrumented(stdout));
        assert!(!instrumented("trace-check-harness: run_mode=native"));
        assert!(!instrumented("nothing here"));
        assert!(completed_cases("no markers at all", "abc123").is_empty());
    }

    /// Output the *function under analysis* printed is not completion evidence.
    ///
    /// The regression: the marker was matched anywhere in a line and carried no
    /// nonce, so a case could print a plausible marker and terminate the
    /// process, and the runner would credit it as finished. Both halves are
    /// covered here — a wrong nonce, and a marker embedded mid-line.
    #[test]
    fn forged_completion_markers_are_rejected() {
        let forged = "\
trace-check-harness: run_mode=valgrind
trace-check-case: deadbeef 0 produced=3
the library printed this: trace-check-case: abc123 1 produced=9
trace-check-run-complete: deadbeef cases=2
";
        // A marker stamped with a different nonce is not this run's.
        assert!(
            completed_cases(forged, "abc123").is_empty(),
            "a mid-line marker with the right nonce must still be rejected"
        );
        assert_eq!(run_complete_count(forged, "abc123"), None);
        // And the run's own nonce only matches its own line-anchored markers.
        assert_eq!(completed_cases(forged, "deadbeef"), vec![0]);
    }

    /// A run is complete evidence only when the status, the final marker, its
    /// count, and the exact ordered case identities all agree.
    #[test]
    fn completion_requires_all_four_conditions() {
        let complete = |requested: Vec<usize>,
                        completed: Vec<usize>,
                        run_complete: Option<usize>,
                        status_ok: bool| BatchRun {
            requested,
            completed,
            run_complete,
            instrumented: true,
            run: None,
            parse_error: None,
            exit_code: Some(0),
            status_ok,
            stdout: String::new(),
            stderr: String::new(),
        };

        let good = complete(vec![0, 1], vec![0, 1], Some(2), true);
        assert!(good.all_completed());
        assert!(good.incompleteness().is_none());

        // The original check: counts match, identities do not.
        let swapped = complete(vec![0, 1], vec![0, 5], Some(2), true);
        assert!(!swapped.all_completed(), "counting is not identity");
        assert!(swapped
            .incompleteness()
            .expect("explained")
            .contains("not exactly the requested"));

        // Out of order is also not the requested sequence.
        assert!(!complete(vec![0, 1], vec![1, 0], Some(2), true).all_completed());

        // The process died before printing its final marker.
        let truncated = complete(vec![0, 1], vec![0, 1], None, true);
        assert!(!truncated.all_completed());
        assert!(truncated
            .incompleteness()
            .expect("explained")
            .contains("did not finish"));

        // The final marker disagrees with the request.
        let miscounted = complete(vec![0, 1], vec![0, 1], Some(1), true);
        assert!(!miscounted.all_completed());
        assert!(miscounted
            .incompleteness()
            .expect("explained")
            .contains("but 2 were requested"));

        // A status no finished harness produces.
        let failed = complete(vec![0, 1], vec![0, 1], Some(2), false);
        assert!(!failed.all_completed());
        assert!(failed
            .incompleteness()
            .expect("explained")
            .contains("exited with"));
    }

    /// A whole-corpus run takes its requested ids from the corpus file, so a
    /// harness that ran only part of it cannot report itself complete.
    ///
    /// The regression: `requested` was reconstructed from the harness's own
    /// completion markers, which made `all_completed()` unconditionally true
    /// for this path.
    #[test]
    fn whole_corpus_requests_come_from_the_corpus() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("corpus.tcc");
        std::fs::write(
            &path,
            "# trace-check corpus v1 contract=c::f seed=1 cases=3\n\
             0 boundaries s:0\n\
             1 boundaries s:1\n\
             2 random s:200\n",
        )
        .expect("written");
        assert_eq!(corpus_case_ids(&path).expect("parsed"), vec![0, 1, 2]);

        // Only two of the three cases reported completion: not complete.
        let partial = BatchRun {
            requested: corpus_case_ids(&path).expect("parsed"),
            completed: vec![0, 1],
            run_complete: Some(2),
            instrumented: true,
            run: None,
            parse_error: None,
            exit_code: Some(0),
            status_ok: true,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(!partial.all_completed());

        // A malformed corpus is an error rather than a silently empty request.
        let bad = directory.path().join("bad.tcc");
        std::fs::write(&bad, "not-an-id boundaries s:0\n").expect("written");
        assert!(corpus_case_ids(&bad).is_err());
    }

    /// An empty batch is refused rather than reported as a clean run.
    #[test]
    fn an_empty_batch_is_refused() {
        let error = run_batch(
            Path::new("/nonexistent/valgrind"),
            Path::new("/nonexistent/artifact"),
            Path::new("/nonexistent/corpus"),
            Some(&[]),
            Limits::default(),
        )
        .expect_err("refused");
        assert!(matches!(error, DynamicError::NothingSelected), "{error}");
        assert!(error.to_string().contains("not a pass"), "{error}");
    }

    /// The `trace-check-test` package is locatable from this build, which is
    /// what the generated manifest depends on.
    #[test]
    fn the_test_crate_is_locatable() {
        let path = test_crate_path().expect("found");
        assert!(path.join("Cargo.toml").is_file(), "{}", path.display());
    }

    /// An override naming a directory without a manifest is an explicit error
    /// rather than a manifest that cannot resolve.
    #[test]
    fn a_bad_override_is_explained() {
        let error = DynamicError::TestCrateMissing {
            tried: "/tmp/nope".to_string(),
            from_env: true,
        };
        assert!(error.to_string().contains(TEST_CRATE_ENV), "{error}");
    }

    /// The decoder prelude refuses a value wider than its parameter, a bool
    /// outside Rust's two valid bytes, and a hex field of the wrong length.
    ///
    /// Exercised here against the same source text the harness embeds, because
    /// the generated copy cannot be unit-tested in place.
    #[test]
    fn the_decoders_reject_malformed_fields() {
        // Mirrors the generated prelude; see `DECODERS`.
        fn decode_scalar(field: &str, bits: u32) -> Result<u64, String> {
            let Some(body) = field.strip_prefix("s:") else {
                return Err(format!("expected a scalar `s:` field, got {field:?}"));
            };
            let value: u64 = body
                .parse()
                .map_err(|_| format!("{body:?} is not an unsigned integer"))?;
            if bits < 64 && value > (1u64 << bits) - 1 {
                return Err(format!("{value} does not fit in {bits} bits"));
            }
            Ok(value)
        }
        assert_eq!(decode_scalar("s:255", 8), Ok(255));
        assert!(decode_scalar("s:256", 8).is_err());
        assert!(decode_scalar("x:ff", 8).is_err());
        assert!(decode_scalar("s:-1", 8).is_err());
        // The prelude the harness embeds is the text these mirror.
        assert!(DECODERS.contains("does not fit in {bits} bits"));
        assert!(DECODERS.contains("expected `b:0` or `b:1`"));
        assert!(DECODERS.contains("hex digits"));
    }
}
