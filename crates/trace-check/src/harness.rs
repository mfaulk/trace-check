//! Building a verification artifact out of a real Cargo library.
//!
//! This is M5's second artifact source. Where M4 compiles one hand-written
//! `no_std` file with `rustc`, this module generates a `no_std` harness
//! *package*, takes the developer's library as an ordinary Cargo path
//! dependency, and links the two into the same kind of freestanding static ELF
//! the M4 engine already analyzes. The symbolic engine is untouched.
//!
//! # The three things that make the result about the real function
//!
//! **The harness contains no algorithm.** It declares symbolic globals, reads
//! them, calls the library, and halts. Changing the library therefore changes
//! the verdict, which is the standing regression that proves there is no copy.
//!
//! **The call is type-checked by rustc, not by this tool.** The generated call
//! names the real parameter types in the real order, and the harness embeds the
//! contract descriptor it was generated from and compares it against the
//! library's own at compile time. A signature that changed under us does not
//! compile.
//!
//! **The target is kept out of line on purpose.** rustc marks small
//! non-generic functions cross-crate-inlinable by default, so a four-instruction
//! library function dissolves into the harness and leaves no symbol at all —
//! measured, not hypothesised. The harness therefore reifies the target as a
//! function pointer and launders it through `black_box`, which forces a
//! distinct callable instance to exist. The cost is recorded rather than
//! hidden: the verified instance is an out-of-line copy, and a production
//! caller that inlines the function gets code this run did not analyze.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::contract::{Contract, ContractError, ContractSettings, Descriptor, Repr, Role};
use crate::symbolic::{VerificationCase, SUPPORTED_TARGET};

/// Entry symbol the analyzer starts at.
pub const ENTRY_SYMBOL: &str = "tc_verify_entry";

/// Symbol the analyzer halts at.
pub const HALT_SYMBOL: &str = "tc_halt";

/// Where the harness writes the call's value so it cannot be optimized away.
pub const OUTPUT_GLOBAL: &str = "TC_OUT";

/// Compilation settings for the verification artifact, recorded in reports
/// because a result describes one build and not the library in general.
pub const PROFILE: &str = "release: opt-level=3, debug=true, lto=off, codegen-units=1";

/// Panic strategy. Freestanding code has no unwinder.
pub const PANIC_STRATEGY: &str = "abort";

/// Flags that make the artifact freestanding and keep the target out of line.
pub const RUSTFLAGS: [&str; 8] = [
    "-C",
    "panic=abort",
    "-C",
    "relocation-model=static",
    "-C",
    "link-arg=-nostdlib",
    "-C",
    "link-arg=-static",
];

/// Where generated packages, their Cargo output and the analyzed artifacts
/// live for one run.
///
/// Created atomically with a random name, never at a predictable path. A
/// verification run writes a Cargo manifest, a `.cargo/config.toml`, a Rust
/// source file and a linked executable; with a guessable directory name, a
/// pre-existing directory or a symlink planted by another user on a shared
/// machine would be followed by those writes, and stale files from an earlier
/// invocation could be picked up by a later one. The same hazard was closed in
/// the dynamic backends; it is closed the same way here.
pub enum Workspace {
    /// A private directory removed when the run ends. The default: a result is
    /// pinned to its artifact's **hash**, not to a path.
    Ephemeral(tempfile::TempDir),
    /// A fresh directory inside a caller-named one, kept after the run so the
    /// evidence bundle can be inspected. The caller owns the parent; the run
    /// directory inside it is still created atomically and never reused.
    Kept(PathBuf),
}

impl Workspace {
    /// A private directory, removed when this value is dropped.
    pub fn ephemeral() -> Result<Workspace, HarnessError> {
        let directory = tempfile::Builder::new()
            .prefix("trace-check-verify-")
            .tempdir()
            .map_err(|e| {
                HarnessError::Io(format!("cannot create a private work directory: {e}"))
            })?;
        restrict(directory.path())?;
        Ok(Workspace::Ephemeral(directory))
    }

    /// A kept directory beneath `parent`, which is created if it does not
    /// exist.
    ///
    /// The run directory itself is created with a random name through
    /// `tempfile`, so two runs never share one and nothing pre-existing is
    /// written through — even though the caller named the parent.
    pub fn kept_in(parent: &Path) -> Result<Workspace, HarnessError> {
        std::fs::create_dir_all(parent)
            .map_err(|e| HarnessError::Io(format!("{}: {e}", parent.display())))?;
        let run = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(parent)
            .map_err(|e| HarnessError::Io(format!("{}: {e}", parent.display())))?;
        restrict(run.path())?;
        Ok(Workspace::Kept(run.keep()))
    }

    pub fn root(&self) -> &Path {
        match self {
            Workspace::Ephemeral(directory) => directory.path(),
            Workspace::Kept(path) => path,
        }
    }

    /// Whether the directory survives the run, which a report states so a
    /// recorded artifact path is not read as still existing.
    pub fn is_kept(&self) -> bool {
        matches!(self, Workspace::Kept(_))
    }

    /// A fresh directory for one contract's generated packages.
    ///
    /// `create_dir`, not `create_dir_all`: inside an atomically created private
    /// root nothing can pre-exist, so an `AlreadyExists` here means two
    /// contracts collided on a name and is reported rather than written into.
    fn contract_dir(&self, contract: &str) -> Result<PathBuf, HarnessError> {
        let contracts = self.root().join("contracts");
        if !contracts.exists() {
            std::fs::create_dir(&contracts)
                .map_err(|e| HarnessError::Io(format!("{}: {e}", contracts.display())))?;
        }
        let directory = contracts.join(package_suffix(contract));
        std::fs::create_dir(&directory)
            .map_err(|e| HarnessError::Io(format!("{}: {e}", directory.display())))?;
        Ok(directory)
    }

    /// The Cargo target directory shared by every generated package in this
    /// run.
    ///
    /// Shared on purpose: per-contract target directories rebuilt `core`, the
    /// library and its dependencies for every contract and left hundreds of
    /// megabytes behind. Each generated package is named after its contract, so
    /// their binaries do not collide.
    fn target_dir(&self) -> Result<PathBuf, HarnessError> {
        let directory = self.root().join("target");
        if !directory.exists() {
            std::fs::create_dir(&directory)
                .map_err(|e| HarnessError::Io(format!("{}: {e}", directory.display())))?;
        }
        Ok(directory)
    }

    /// The two directories one contract's build needs.
    pub fn directories_for(&self, contract: &str) -> Result<(PathBuf, PathBuf), HarnessError> {
        Ok((self.contract_dir(contract)?, self.target_dir()?))
    }
}

/// Makes a directory private to this user.
///
/// `tempfile` picks an unpredictable name and creates it atomically, which is
/// what defeats a planted directory or symlink — but it leaves the mode to the
/// umask, so a default `022` yields a world-readable `0755`. The analyzer
/// mounts its own staging directory, not this one, so nothing here needs to be
/// readable by another user.
fn restrict(directory: &Path) -> Result<(), HarnessError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| HarnessError::Io(format!("{}: {e}", directory.display())))
}

/// The library a contract is verified from.
#[derive(Debug, Clone, Serialize)]
pub struct Library {
    pub package: String,
    pub version: String,
    /// Lib target name, which is what a contract identity is qualified by.
    pub lib_name: String,
    pub manifest_path: String,
    /// Cargo features enabled for the verification build.
    pub features: Vec<String>,
}

impl Library {
    /// Resolves the package a manifest describes, through `cargo metadata`
    /// rather than by reading the manifest: feature inheritance, workspace
    /// defaults and target renaming are Cargo's business, not ours.
    pub fn resolve(manifest_path: &Path, features: &[String]) -> Result<Library, HarnessError> {
        let manifest_path = manifest_path
            .canonicalize()
            .map_err(|e| HarnessError::Io(format!("{}: {e}", manifest_path.display())))?;
        let output = Command::new("cargo")
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .arg("--manifest-path")
            .arg(&manifest_path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| HarnessError::Io(format!("cannot run cargo metadata: {e}")))?;
        if !output.status.success() {
            return Err(HarnessError::Metadata(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| HarnessError::Metadata(format!("cannot parse cargo metadata: {e}")))?;

        // `--no-deps` still reports every workspace member, so the package is
        // selected by its manifest rather than by taking the first one.
        let packages = metadata["packages"].as_array().cloned().unwrap_or_default();
        let package = packages
            .iter()
            .find(|package| {
                package["manifest_path"].as_str().map(Path::new) == Some(manifest_path.as_path())
            })
            .ok_or_else(|| {
                HarnessError::Metadata(format!(
                    "cargo metadata reported no package for {}",
                    manifest_path.display()
                ))
            })?;

        let lib_name = package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|target| {
                target["kind"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|kind| kind == "lib" || kind == "rlib")
            })
            .and_then(|target| target["name"].as_str())
            .ok_or_else(|| {
                HarnessError::Metadata(format!(
                    "{} defines no library target, so it has no functions to verify",
                    manifest_path.display()
                ))
            })?
            // Cargo reports the crate name with dashes, which is not how Rust
            // paths spell it.
            .replace('-', "_");

        Ok(Library {
            package: package["name"].as_str().unwrap_or_default().to_string(),
            version: package["version"].as_str().unwrap_or_default().to_string(),
            lib_name,
            manifest_path: manifest_path.display().to_string(),
            features: features.to_vec(),
        })
    }

    fn manifest_dir(&self) -> PathBuf {
        Path::new(&self.manifest_path)
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf()
    }

    /// The dependency stanza a generated package uses to take this library.
    ///
    /// `package = …` plus an explicit key lets the harness refer to the library
    /// by its *lib* name, which is what a contract identity is qualified by and
    /// therefore what the generated call has to spell.
    fn dependency_stanza(&self) -> String {
        let mut stanza = format!(
            "[dependencies.{}]\npackage = {:?}\npath = {:?}\n",
            self.lib_name,
            self.package,
            self.manifest_dir().display().to_string()
        );
        if !self.features.is_empty() {
            stanza.push_str(&format!("features = {:?}\n", self.features));
        }
        stanza
    }
}

/// Splits a qualified contract identity into its module path and function.
///
/// The identity must start at the library's lib name, because that is what
/// `module_path!()` inside the library expands to and therefore what the
/// generated call and the generated constants are spelled with.
pub fn split_contract(library: &Library, contract: &str) -> Result<(String, String), HarnessError> {
    let (module, function) = contract.rsplit_once("::").ok_or_else(|| {
        HarnessError::Contract(ContractError::NotAnnotated {
            contract: contract.to_string(),
            detail: format!(
                "a contract identity is qualified, e.g. `{}::verify_tag` or \
                 `{}::tag::verify_tag`",
                library.lib_name, library.lib_name
            ),
        })
    })?;
    let crate_segment = module.split("::").next().unwrap_or(module);
    if crate_segment != library.lib_name {
        return Err(HarnessError::Contract(ContractError::NotAnnotated {
            contract: contract.to_string(),
            detail: format!(
                "the identity starts at `{crate_segment}`, but {} builds the library crate \
                 `{}`; qualify the contract from the crate root",
                library.manifest_path, library.lib_name
            ),
        }));
    }
    if !is_rust_path(module) || !is_rust_identifier(function) {
        return Err(HarnessError::Contract(ContractError::NotAnnotated {
            contract: contract.to_string(),
            detail: "the identity is not a Rust path".to_string(),
        }));
    }
    Ok((module.to_string(), function.to_string()))
}

/// A contract identity as a Cargo package-name suffix. Identities are Rust
/// paths, already validated, so only the separator needs replacing.
fn package_suffix(contract: &str) -> String {
    contract.replace("::", "-")
}

fn is_rust_identifier(text: &str) -> bool {
    !text.is_empty()
        && !text.chars().next().is_some_and(|c| c.is_ascii_digit())
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_rust_path(text: &str) -> bool {
    !text.is_empty() && text.split("::").all(is_rust_identifier)
}

/// Reads a contract's descriptor out of the compiled library.
///
/// A generated single-expression probe takes the library as a path dependency
/// and prints the three constants `#[constant_time]` emitted. The descriptor is
/// therefore the macro's own output from the real signature, and a contract
/// that does not exist, is not annotated, or is not visible from outside the
/// crate fails to compile — each with a different actionable message.
///
/// Source parsing was the alternative and was rejected: `cfg`, macros and
/// `include!` make a text scan either wrong or a second parser to maintain.
pub fn probe_contract(
    library: &Library,
    contract: &str,
    work_dir: &Path,
    target_dir: &Path,
) -> Result<Contract, HarnessError> {
    let (module, function) = split_contract(library, contract)?;
    let crate_dir = work_dir.join("contract-probe");
    // Unique per contract, so several generated packages can share one target
    // directory without overwriting each other's binary.
    let package = format!("tc-probe-{}", package_suffix(contract));
    std::fs::create_dir_all(crate_dir.join("src"))
        .map_err(|e| HarnessError::Io(format!("{}: {e}", crate_dir.display())))?;

    // `[workspace]` makes the generated package its own workspace root, so it
    // is never absorbed into whatever workspace the temporary directory
    // happens to sit inside.
    let manifest = format!(
        "[package]\nname = {package:?}\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         publish = false\n\n[[bin]]\nname = {package:?}\npath = \"src/main.rs\"\n\n\
         {}\n[workspace]\n",
        library.dependency_stanza()
    );
    let source = format!(
        "// Generated by trace-check. Reads the contract descriptor \
         `#[constant_time]` emitted for `{contract}`.\n\
         fn main() {{\n\
         \x20   print!(\"{{}}\\u{{1}}{{}}\\u{{1}}{{}}\",\n\
         \x20       {module}::__TRACE_CHECK_MODULE_{function},\n\
         \x20       {module}::__TRACE_CHECK_SITE_{function},\n\
         \x20       {module}::__TRACE_CHECK_CONTRACT_{function});\n\
         }}\n"
    );
    write(&crate_dir.join("Cargo.toml"), &manifest)?;
    write(&crate_dir.join("src/main.rs"), &source)?;

    // Run from inside the generated package. Cargo discovers
    // `.cargo/config.toml` relative to the **working directory**, not to
    // `--manifest-path`, so a generated package's own configuration is only
    // honored when it is also the working directory. The harness build below
    // depends on that; the probe uses it for the same hermeticity.
    let output = Command::new("cargo")
        .args(["run", "--quiet"])
        .arg("--target-dir")
        .arg(target_dir)
        .current_dir(&crate_dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| HarnessError::Io(format!("cannot run cargo: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(HarnessError::Contract(ContractError::NotAnnotated {
            contract: contract.to_string(),
            detail: explain_probe_failure(&stderr, &module, &function, library),
        }));
    }

    let printed = String::from_utf8_lossy(&output.stdout).into_owned();
    let fields: Vec<&str> = printed.split('\u{1}').collect();
    let [declared_module, site, descriptor] = fields.as_slice() else {
        return Err(HarnessError::Contract(ContractError::Descriptor(format!(
            "the probe for `{contract}` printed {} field(s), expected 3",
            fields.len()
        ))));
    };
    // The module the annotation actually expanded in has to be the one the
    // caller named. A re-exported function would otherwise be verified under
    // an identity that does not describe where its code lives.
    if *declared_module != module {
        return Err(HarnessError::Contract(ContractError::NotAnnotated {
            contract: contract.to_string(),
            detail: format!(
                "the annotation expanded in `{declared_module}`, not `{module}`; name the \
                 contract by the module it is declared in rather than by a re-export"
            ),
        }));
    }

    let descriptor_json = (*descriptor).to_string();
    let descriptor = Descriptor::parse(&descriptor_json)?;
    if descriptor.function != function {
        return Err(HarnessError::Contract(ContractError::Descriptor(format!(
            "the descriptor at `{module}` describes `{}`, not `{function}`",
            descriptor.function
        ))));
    }
    descriptor.validate(contract)?;

    Ok(Contract {
        id: contract.to_string(),
        module,
        function,
        site: site.to_string(),
        descriptor,
        descriptor_json,
    })
}

/// Turns the probe's compiler diagnostics into an actionable sentence.
fn explain_probe_failure(stderr: &str, module: &str, function: &str, library: &Library) -> String {
    let descriptor = format!("__TRACE_CHECK_CONTRACT_{function}");
    if stderr.contains(&descriptor) && stderr.contains("is private") {
        return format!(
            "the contract is declared but not public, so it cannot be verified from outside \
             `{}`. Make `{module}::{function}` `pub`",
            library.lib_name
        );
    }
    if stderr.contains(&descriptor) {
        return format!(
            "`{module}` defines no `{descriptor}`. Either `{function}` carries no \
             `#[constant_time]` annotation, or the module path is wrong. The compiler said:\n{}",
            first_diagnostics(stderr)
        );
    }
    if stderr.contains("unresolved") || stderr.contains("could not find") {
        return format!(
            "`{module}` could not be resolved in `{}`. The compiler said:\n{}",
            library.lib_name,
            first_diagnostics(stderr)
        );
    }
    format!(
        "reading it from the library failed. The compiler said:\n{}",
        first_diagnostics(stderr)
    )
}

/// The first few diagnostic lines, so an error message stays readable.
fn first_diagnostics(stderr: &str) -> String {
    stderr
        .lines()
        .filter(|line| !line.trim_start().starts_with("Compiling"))
        .take(12)
        .collect::<Vec<_>>()
        .join("\n")
}

/// A symbolic input declared in the generated harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymbolicInput {
    /// Parameter the input stands for.
    pub parameter: String,
    pub role: Role,
    /// Global the analyzer declares secret or public.
    pub global: String,
    /// Representation as the annotation described it.
    pub repr: String,
    /// Width of the symbolic storage, in bits.
    pub bits: u64,
    /// How the value reaches the function.
    pub passing: &'static str,
    /// A domain restriction the generator had to add for this input to model
    /// Rust's valid values, if any. Reported, never silent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// A generated harness: its source, its symbolic inputs, and the lattice the
/// analyzer is told about.
#[derive(Debug, Clone)]
pub struct Harness {
    pub source: String,
    pub source_sha256: String,
    pub inputs: Vec<SymbolicInput>,
    pub secret_globals: Vec<String>,
    pub public_globals: Vec<String>,
    /// `assume` constraints the generator added so the analyzed domain matches
    /// Rust's valid values. Kept apart from the developer's own assumptions,
    /// which a report reproduces verbatim.
    pub generated_assumptions: Vec<String>,
}

/// Generates the harness for one contract.
///
/// Deterministic: the same contract and the same library produce the same
/// bytes, which is what makes [`Harness::source_sha256`] a provenance field
/// rather than noise.
pub fn generate(library: &Library, contract: &Contract) -> Result<Harness, HarnessError> {
    let mut inputs = Vec::new();
    let mut globals: BTreeMap<String, String> = BTreeMap::new();
    for parameter in &contract.descriptor.parameters {
        let global = format!(
            "TC_{}_{}",
            parameter.role.as_str().to_ascii_uppercase(),
            parameter.name.to_ascii_uppercase()
        );
        // Two parameters differing only in case would otherwise share one
        // global, which would silently alias a secret onto a public input.
        if let Some(first) = globals.insert(global.clone(), parameter.name.clone()) {
            return Err(HarnessError::Collision {
                contract: contract.id.clone(),
                global,
                first,
                second: parameter.name.clone(),
            });
        }
        let bits = parameter
            .repr
            .bytes()
            .map(|bytes| bytes * 8)
            .ok_or_else(|| {
                HarnessError::Contract(ContractError::Unsupported {
                    contract: contract.id.clone(),
                    detail: format!("parameter `{}` has no symbolic width", parameter.name),
                })
            })?;
        // A symbolic byte is a machine byte; Rust's `bool` has exactly two
        // valid ones. Without this the analyzer would explore states the
        // compiled program can never be in, and the reported input domain would
        // not be the one that was searched.
        let domain = match parameter.repr {
            Repr::Bool => Some(format!("{global} <= 1")),
            _ => None,
        };
        inputs.push(SymbolicInput {
            parameter: parameter.name.clone(),
            role: parameter.role,
            global: global.clone(),
            repr: parameter.repr.describe(),
            bits,
            passing: if parameter.repr.passed_by_reference() {
                "by reference; the bytes are the input and the pointer is public"
            } else {
                "by value"
            },
            domain,
        });
    }

    let source = render_source(library, contract, &inputs)?;
    let source_sha256 = format!("{:x}", Sha256::digest(source.as_bytes()));
    let generated_assumptions: Vec<String> = inputs
        .iter()
        .filter_map(|input| input.domain.clone())
        .collect();
    let secret_globals = inputs
        .iter()
        .filter(|input| input.role == Role::Secret)
        .map(|input| input.global.clone())
        .collect();
    let public_globals = inputs
        .iter()
        .filter(|input| input.role == Role::Public)
        .map(|input| input.global.clone())
        .collect();
    Ok(Harness {
        source,
        source_sha256,
        inputs,
        secret_globals,
        public_globals,
        generated_assumptions,
    })
}

fn render_source(
    library: &Library,
    contract: &Contract,
    inputs: &[SymbolicInput],
) -> Result<String, HarnessError> {
    let parameters = &contract.descriptor.parameters;
    let mut out = String::new();
    out.push_str(&format!(
        "// Generated by trace-check for `{}`. Not written into any source tree,\n\
         // not edited by hand, and containing no copy of the library's implementation:\n\
         // it declares symbolic storage, calls the real function, and halts.\n\
         #![no_std]\n#![no_main]\n\n",
        contract.id
    ));

    // The descriptor this harness was generated from, checked against the
    // library's own at compile time. A signature that changed between the probe
    // and this build does not compile, so the argument mapping below is
    // certified by rustc rather than by this tool.
    out.push_str(&format!(
        "/// The contract descriptor this harness was generated from.\n\
         const CONTRACT: &str = {:?};\n\n\
         // Refuses to build if the library's own descriptor has moved since the\n\
         // probe read it, which would mean the call below was generated against a\n\
         // signature that no longer exists.\n\
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
         }};\n\n",
        contract.descriptor_json,
        contract.descriptor_const()
    ));

    out.push_str(
        "// Symbolic inputs. BINSEC declares its security lattice by symbol name, so\n\
                  // each one is a named global with its own storage.\n",
    );
    for (input, parameter) in inputs.iter().zip(parameters) {
        let storage = parameter.repr.owned_rust_type().expect("width checked");
        let initializer = match &parameter.repr {
            Repr::ByteArray(length) | Repr::RefByteArray(length) => format!("[0; {length}]"),
            Repr::Bool => "false".to_string(),
            _ => "0".to_string(),
        };
        // A `bool` global is read as a `bool`, which has two valid byte values.
        // The analyzer is told so through a generated `assume`; without it the
        // search would cover bytes this program can never hold.
        let note = match &input.domain {
            Some(domain) => format!(
                "///\n/// Restricted to Rust's valid values by the generated \
             constraint `{domain}`.\n"
            ),
            None => String::new(),
        };
        out.push_str(&format!(
            "/// `{}`, declared {} by the contract.\n{note}\
             #[no_mangle]\npub static mut {}: {storage} = {initializer};\n\n",
            parameter.name,
            input.role.as_str(),
            input.global
        ));
    }
    out.push_str(&format!(
        "/// Where the call's value is written, so the call cannot be optimized away.\n\
         #[no_mangle]\npub static mut {OUTPUT_GLOBAL}: u64 = 0;\n\n"
    ));

    out.push_str(&format!(
        "/// Where the analyzer halts. Nothing past the call is explored.\n\
         #[inline(never)]\n#[no_mangle]\npub extern \"C\" fn {HALT_SYMBOL}() -> ! {{\n\
         \x20   unsafe {{\n\
         \x20       core::ptr::read_volatile(&raw const {OUTPUT_GLOBAL});\n\
         \x20   }}\n\
         \x20   loop {{}}\n\
         }}\n\n"
    ));

    out.push_str(&format!(
        "/// Where the analyzer starts.\n\
         #[inline(never)]\n#[no_mangle]\npub extern \"C\" fn {ENTRY_SYMBOL}() -> ! {{\n"
    ));
    for (input, parameter) in inputs.iter().zip(parameters) {
        let storage = parameter.repr.owned_rust_type().expect("width checked");
        out.push_str(&format!(
            "\x20   // Volatile, so the value genuinely comes from the memory the\n\
             \x20   // analyzer made symbolic rather than from a constant.\n\
             \x20   let {}: {storage} =\n\
             \x20       unsafe {{ core::ptr::read_volatile(&raw const {}) }};\n",
            parameter.name, input.global
        ));
    }
    // Reified and laundered: see the module documentation for why a direct
    // call is not enough.
    out.push_str(&format!(
        "\x20   // Reified as a function pointer and laundered, so a distinct callable\n\
         \x20   // instance of the library's function must exist for the analyzer to\n\
         \x20   // reach. A direct call is dissolved by cross-crate inlining.\n\
         \x20   let target: {} = {};\n\
         \x20   let target = core::hint::black_box(target);\n",
        function_pointer_type(&contract.descriptor),
        contract.call_path()
    ));
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
    match contract.descriptor.returns {
        Repr::Unit => {
            out.push_str(&format!(
                "\x20   target({});\n\
                 \x20   unsafe {{ core::ptr::write_volatile(&raw mut {OUTPUT_GLOBAL}, 0) }};\n",
                arguments.join(", ")
            ));
        }
        _ => {
            out.push_str(&format!(
                "\x20   let produced = target({});\n\
                 \x20   unsafe {{ core::ptr::write_volatile(&raw mut {OUTPUT_GLOBAL}, produced as u64) }};\n",
                arguments.join(", ")
            ));
        }
    }
    out.push_str(&format!("\x20   {HALT_SYMBOL}()\n}}\n\n"));

    out.push_str(&format!(
        "/// Keeps the entry reachable. `-nostdlib` leaves the linker with no entry\n\
         /// symbol, and anything `_start` does not reach is dropped as dead code.\n\
         /// The analyzer starts at `{ENTRY_SYMBOL}` directly, so this is never explored.\n\
         #[no_mangle]\npub extern \"C\" fn _start() -> ! {{\n\x20   {ENTRY_SYMBOL}()\n}}\n\n\
         #[panic_handler]\nfn tc_panic(_: &core::panic::PanicInfo) -> ! {{\n\x20   loop {{}}\n}}\n"
    ));

    let _ = library;
    Ok(out)
}

/// The function-pointer type for a contract, spelled with the real parameter
/// types so rustc rejects a wrong width, a wrong shape or a wrong order.
fn function_pointer_type(descriptor: &Descriptor) -> String {
    let parameters: Vec<String> = descriptor
        .parameters
        .iter()
        .map(|parameter| match &parameter.repr {
            Repr::RefByteArray(length) => format!("&[u8; {length}]"),
            other => other.describe(),
        })
        .collect();
    match &descriptor.returns {
        Repr::Unit => format!("fn({})", parameters.join(", ")),
        returns => format!("fn({}) -> {}", parameters.join(", "), returns.describe()),
    }
}

/// A built verification artifact.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
    /// Fingerprint of the harness's resolved dependency graph.
    pub lockfile_sha256: String,
}

/// Builds the verification artifact: a generated harness package plus the
/// library it depends on, linked freestanding and static.
///
/// The executable's path comes from Cargo's own structured output. Constructing
/// `target/<triple>/release/<name>` is wrong whenever `CARGO_TARGET_DIR` is set,
/// which is how this was found.
pub fn build(
    library: &Library,
    harness: &Harness,
    contract: &str,
    work_dir: &Path,
    target_dir: &Path,
) -> Result<Artifact, HarnessError> {
    let crate_dir = work_dir.join("verify-harness");
    let package = format!("tc-verify-{}", package_suffix(contract));
    std::fs::create_dir_all(crate_dir.join("src"))
        .map_err(|e| HarnessError::Io(format!("{}: {e}", crate_dir.display())))?;
    std::fs::create_dir_all(crate_dir.join(".cargo"))
        .map_err(|e| HarnessError::Io(format!("{}: {e}", crate_dir.display())))?;

    // `lto = false` is load-bearing: link-time optimization would inline the
    // target through the function pointer and leave nothing to attribute.
    let manifest = format!(
        "[package]\nname = {package:?}\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         publish = false\n\n[[bin]]\nname = {package:?}\npath = \"src/main.rs\"\n\n\
         {}\n[profile.release]\nopt-level = 3\ndebug = true\npanic = \"abort\"\n\
         codegen-units = 1\nlto = false\nincremental = false\nstrip = false\n\n[workspace]\n",
        library.dependency_stanza()
    );
    // Target-scoped rather than in `RUSTFLAGS`, and `--target` is passed
    // explicitly below, so freestanding link flags never reach a host build
    // script or proc-macro crate.
    let cargo_config = format!(
        "[target.{SUPPORTED_TARGET}]\nrustflags = [{}]\n",
        RUSTFLAGS
            .iter()
            .map(|flag| format!("{flag:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    write(&crate_dir.join("Cargo.toml"), &manifest)?;
    write(&crate_dir.join(".cargo/config.toml"), &cargo_config)?;
    write(&crate_dir.join("src/main.rs"), &harness.source)?;

    // Run from inside the generated package so Cargo finds the
    // `.cargo/config.toml` written above: configuration discovery is relative
    // to the working directory, not to `--manifest-path`. With the manifest
    // named instead, the freestanding link flags were silently dropped and the
    // link failed on a duplicate `_start` against the C runtime's `Scrt1.o`.
    //
    // `--target` is named explicitly for the other half of the same concern:
    // it keeps those flags off host build scripts and proc-macro crates.
    let output = Command::new("cargo")
        .args(["build", "--release", "--target", SUPPORTED_TARGET])
        .arg("--target-dir")
        .arg(target_dir)
        .arg("--message-format=json-render-diagnostics")
        .current_dir(&crate_dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| HarnessError::Io(format!("cannot run cargo: {e}")))?;
    if !output.status.success() {
        return Err(HarnessError::Build {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let path = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .filter_map(|message| message["executable"].as_str().map(PathBuf::from))
        .next_back()
        .ok_or_else(|| HarnessError::Build {
            stderr: "cargo reported no executable for the verification harness".to_string(),
        })?;

    let bytes =
        std::fs::read(&path).map_err(|e| HarnessError::Io(format!("{}: {e}", path.display())))?;
    let lockfile = crate_dir.join("Cargo.lock");
    let lockfile_sha256 = std::fs::read(&lockfile)
        .map(|bytes| format!("{:x}", Sha256::digest(&bytes)))
        .unwrap_or_else(|_| "unavailable".to_string());

    Ok(Artifact {
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        path,
        lockfile_sha256,
    })
}

/// The compiled function a contract resolves to.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedSymbol {
    /// Contract identity, as the developer named it.
    pub contract: String,
    /// The symbol the analyzer is pointed at.
    pub mangled: String,
    /// Its address in the artifact.
    pub address: String,
}

/// Resolves a contract identity to exactly one symbol in the artifact.
///
/// The mangled name cannot be predicted: v0 mangling carries a crate
/// disambiguator hash that moves with the package's version, path and
/// metadata, and the symbol is usually *local*, so it is not reachable by
/// linker name either. Resolution therefore demangles the artifact's own
/// symbol table and matches the qualified identity exactly.
///
/// Zero matches and more than one match are both errors. Zero means the
/// function was inlined, removed or misnamed and there is nothing to analyze;
/// more than one means the tool would have to choose, and a verified result
/// must not rest on a choice this tool made silently.
pub fn resolve_symbol(artifact: &Path, contract: &str) -> Result<ResolvedSymbol, HarnessError> {
    let demangled = symbol_table(artifact, true)?;
    let mangled = symbol_table(artifact, false)?;

    let mut addresses: Vec<u64> = demangled
        .iter()
        .filter(|(_, name)| name == contract)
        .map(|(address, _)| *address)
        .collect();
    addresses.sort_unstable();
    addresses.dedup();

    if addresses.is_empty() {
        let similar: Vec<String> = demangled
            .iter()
            .map(|(_, name)| name.clone())
            .filter(|name| {
                contract
                    .rsplit("::")
                    .next()
                    .is_some_and(|tail| name.ends_with(tail))
            })
            .collect();
        return Err(HarnessError::SymbolMissing {
            contract: contract.to_string(),
            artifact: artifact.display().to_string(),
            similar,
        });
    }
    if addresses.len() > 1 {
        return Err(HarnessError::SymbolAmbiguous {
            contract: contract.to_string(),
            count: addresses.len(),
        });
    }

    let address = addresses[0];
    let candidates: Vec<&String> = mangled
        .iter()
        .filter(|(at, _)| *at == address)
        .map(|(_, name)| name)
        .collect();
    let [symbol] = candidates.as_slice() else {
        return Err(HarnessError::SymbolAmbiguous {
            contract: contract.to_string(),
            count: candidates.len(),
        });
    };

    Ok(ResolvedSymbol {
        contract: contract.to_string(),
        mangled: (*symbol).clone(),
        address: format!("0x{address:x}"),
    })
}

/// Reads defined symbols as (address, name) pairs.
///
/// Sorted numerically in both renderings so the two tables can be joined by
/// address rather than by line order, which `-C` changes.
fn symbol_table(artifact: &Path, demangle: bool) -> Result<Vec<(u64, String)>, HarnessError> {
    let mut command = Command::new("nm");
    command.args(["-n", "--defined-only"]);
    if demangle {
        command.arg("-C");
    }
    let output = command
        .arg(artifact)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| HarnessError::Io(format!("cannot run nm: {e}")))?;
    if !output.status.success() {
        return Err(HarnessError::Io(format!(
            "nm failed on {}: {}",
            artifact.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(parse_symbol_table(&String::from_utf8_lossy(&output.stdout)))
}

/// Parses `nm -n --defined-only` output.
///
/// A demangled name can contain spaces, so everything after the symbol type is
/// the name rather than the third whitespace-separated field.
fn parse_symbol_table(text: &str) -> Vec<(u64, String)> {
    text.lines()
        .filter_map(|line| {
            let (address, rest) = line.split_once(' ')?;
            let address = u64::from_str_radix(address.trim(), 16).ok()?;
            let rest = rest.trim_start();
            let (_kind, name) = rest.split_once(' ')?;
            let name = name.trim();
            (!name.is_empty()).then(|| (address, name.to_string()))
        })
        .collect()
}

/// Builds the verification case the M4 engine consumes.
///
/// Everything here comes from evidence or from the contract: the function is
/// the *resolved* symbol, the globals are the generated harness's, and the
/// lattice is the annotation's. The settings contribute only bounds and the
/// declared expectation.
pub fn verification_case(
    contract: &Contract,
    symbol: &ResolvedSymbol,
    harness: &Harness,
    settings: &ContractSettings,
) -> VerificationCase {
    // Generated restrictions first, so the analyzer never sees a state the
    // compiled program cannot be in, and the developer's own assumptions are
    // still carried through unchanged.
    let assumptions: Vec<String> = harness
        .generated_assumptions
        .iter()
        .chain(&settings.assumptions)
        .cloned()
        .collect();
    VerificationCase {
        id: contract.id.clone(),
        description: settings.description.clone(),
        function: symbol.mangled.clone(),
        entry_symbol: ENTRY_SYMBOL.to_string(),
        halt_symbol: HALT_SYMBOL.to_string(),
        secret_globals: harness.secret_globals.clone(),
        public_globals: harness.public_globals.clone(),
        assumptions,
        features: settings.checks.clone(),
        max_depth: settings.max_depth,
        solver_timeout_secs: settings.solver_timeout_secs,
        wall_timeout_secs: settings.wall_timeout_secs,
        expected_outcome: settings.expected_outcome.clone(),
        rationale: settings.rationale.clone(),
    }
}

fn write(path: &Path, contents: &str) -> Result<(), HarnessError> {
    std::fs::write(path, contents).map_err(|e| HarnessError::Io(format!("{}: {e}", path.display())))
}

#[derive(Debug)]
pub enum HarnessError {
    Io(String),
    Metadata(String),
    Contract(ContractError),
    Build {
        stderr: String,
    },
    /// Two parameters map to one symbolic global.
    Collision {
        contract: String,
        global: String,
        first: String,
        second: String,
    },
    SymbolMissing {
        contract: String,
        artifact: String,
        similar: Vec<String>,
    },
    SymbolAmbiguous {
        contract: String,
        count: usize,
    },
    /// Unsupported check classes, missing analyzer, and everything else the
    /// symbolic engine itself refuses.
    Symbolic(crate::symbolic::SymbolicError),
}

impl From<ContractError> for HarnessError {
    fn from(error: ContractError) -> Self {
        HarnessError::Contract(error)
    }
}

impl From<crate::symbolic::SymbolicError> for HarnessError {
    fn from(error: crate::symbolic::SymbolicError) -> Self {
        HarnessError::Symbolic(error)
    }
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HarnessError::Io(message) => write!(f, "{message}"),
            HarnessError::Metadata(message) => write!(f, "cargo metadata: {message}"),
            HarnessError::Contract(error) => write!(f, "{error}"),
            HarnessError::Build { stderr } => write!(
                f,
                "building the verification artifact failed:\n{}",
                first_diagnostics(stderr)
            ),
            HarnessError::Collision {
                contract,
                global,
                first,
                second,
            } => write!(
                f,
                "`{contract}` has parameters `{first}` and `{second}`, which both map to the \
                 symbolic global {global}; rename one so a secret cannot be aliased onto a \
                 public input"
            ),
            HarnessError::SymbolMissing {
                contract,
                artifact,
                similar,
            } => write!(
                f,
                "`{contract}` resolves to no symbol in {artifact}, so there is nothing to \
                 analyze. The function was inlined away, removed, or the identity is wrong. \
                 Defined symbols with that name: {}",
                if similar.is_empty() {
                    "(none)".to_string()
                } else {
                    similar.join(", ")
                }
            ),
            HarnessError::SymbolAmbiguous { contract, count } => write!(
                f,
                "`{contract}` resolves to {count} symbols in the verification artifact. \
                 trace-check refuses to choose: a verified result must name one compiled \
                 function"
            ),
            HarnessError::Symbolic(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for HarnessError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::Descriptor;
    use crate::symbolic::CheckFeature;

    const VERIFY_TAG: &str = r#"{"schema_version":1,"function":"verify_tag","parameters":[{"name":"expected","position":0,"role":"secret","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"},{"name":"supplied","position":1,"role":"public","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"}],"returns":{"repr":"bool","rust_type":"bool"}}"#;

    fn library() -> Library {
        Library {
            package: "crypto-library".into(),
            version: "0.1.0".into(),
            lib_name: "crypto".into(),
            manifest_path: "/w/examples/crypto-library/Cargo.toml".into(),
            features: Vec::new(),
        }
    }

    fn settings() -> ContractSettings {
        ContractSettings {
            description: "d".into(),
            rationale: "r".into(),
            max_depth: 4000,
            solver_timeout_secs: 30,
            wall_timeout_secs: 900,
            checks: vec![CheckFeature::ControlFlow, CheckFeature::MemoryAccess],
            assumptions: Vec::new(),
            expected_outcome: "VERIFIED_BOUNDED".into(),
            inputs: Default::default(),
        }
    }

    fn contract(json: &str, module: &str, function: &str) -> Contract {
        Contract {
            id: format!("{module}::{function}"),
            module: module.into(),
            function: function.into(),
            site: "src/tag.rs:21".into(),
            descriptor: Descriptor::parse(json).expect("parses"),
            descriptor_json: json.to_string(),
        }
    }

    /// A qualified identity splits into its module and function, and must start
    /// at the library's crate name.
    #[test]
    fn a_contract_identity_is_split_and_checked() {
        let library = library();
        assert_eq!(
            split_contract(&library, "crypto::tag::verify_tag").unwrap(),
            ("crypto::tag".to_string(), "verify_tag".to_string())
        );
        assert_eq!(
            split_contract(&library, "crypto::verify_tag").unwrap(),
            ("crypto".to_string(), "verify_tag".to_string())
        );
        // A bare name says nothing about where the code lives.
        assert!(split_contract(&library, "verify_tag").is_err());
        // A different crate's name cannot be verified from this manifest.
        let error = split_contract(&library, "other::tag::verify_tag").expect_err("rejected");
        assert!(error.to_string().contains("crate `crypto`"), "{error}");
    }

    /// The generated harness declares one global per parameter, with the role
    /// the annotation gave it and the full width of the value.
    #[test]
    fn every_parameter_becomes_a_named_global_of_the_declared_width() {
        let harness = generate(
            &library(),
            &contract(VERIFY_TAG, "crypto::tag", "verify_tag"),
        )
        .unwrap();
        assert_eq!(harness.secret_globals, vec!["TC_SECRET_EXPECTED"]);
        assert_eq!(harness.public_globals, vec!["TC_PUBLIC_SUPPLIED"]);
        // All 16 bytes, not a pointer: the secret is the array's contents.
        let secret = &harness.inputs[0];
        assert_eq!(secret.bits, 128);
        assert_eq!(secret.repr, "&[u8; 16]");
        assert!(secret.passing.contains("pointer is public"));
        assert!(
            harness
                .source
                .contains("pub static mut TC_SECRET_EXPECTED: [u8; 16] = [0; 16];"),
            "{}",
            harness.source
        );
    }

    /// The call is positional and spelled with the real types, so a wrong
    /// order or a wrong width is a compile error rather than a silent remap.
    #[test]
    fn the_generated_call_is_positional_and_typed() {
        let harness = generate(
            &library(),
            &contract(VERIFY_TAG, "crypto::tag", "verify_tag"),
        )
        .unwrap();
        assert!(
            harness.source.contains(
                "let target: fn(&[u8; 16], &[u8; 16]) -> bool = crypto::tag::verify_tag;"
            ),
            "{}",
            harness.source
        );
        assert!(
            harness.source.contains("target(&expected, &supplied)"),
            "{}",
            harness.source
        );
    }

    /// The target is reached through a laundered function pointer. A direct
    /// call is dissolved by cross-crate inlining, which leaves no symbol to
    /// attribute a result to.
    #[test]
    fn the_target_is_reified_and_laundered() {
        let harness = generate(
            &library(),
            &contract(VERIFY_TAG, "crypto::tag", "verify_tag"),
        )
        .unwrap();
        assert!(harness.source.contains("core::hint::black_box(target)"));
    }

    /// The harness references the library in exactly two places — the call and
    /// the descriptor constant — and reproduces no part of its body. Changing
    /// the library is what changes the verdict, and
    /// `the_verdict_follows_the_library` in `tests/library.rs` is the standing
    /// proof; this pins the shape down cheaply.
    #[test]
    fn the_harness_references_the_library_only_to_call_it() {
        let contract = contract(VERIFY_TAG, "crypto::tag", "verify_tag");
        let harness = generate(&library(), &contract).unwrap();
        let mut referenced: Vec<&str> = harness
            .source
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
            .filter(|token| token.starts_with("crypto::"))
            .collect();
        referenced.sort_unstable();
        referenced.dedup();
        assert_eq!(
            referenced,
            vec![
                "crypto::tag::__TRACE_CHECK_CONTRACT_verify_tag",
                "crypto::tag::verify_tag",
            ],
            "{}",
            harness.source
        );
        // Each parameter is bound once from its own global and used once as a
        // call argument, and appears nowhere else: no expression of its own.
        for parameter in ["expected", "supplied"] {
            let uses: Vec<&str> = harness
                .source
                .lines()
                .map(str::trim)
                // The embedded descriptor names every parameter by
                // construction; it is data, not code.
                .filter(|line| !line.starts_with("//") && !line.starts_with("const CONTRACT"))
                .filter(|line| line.contains(parameter))
                .collect();
            assert_eq!(
                uses,
                vec![
                    format!("let {parameter}: [u8; 16] ="),
                    "let produced = target(&expected, &supplied);".to_string(),
                ],
                "{}",
                harness.source
            );
        }
    }

    /// The harness is bound at compile time to the descriptor it was generated
    /// from, so a signature that moved under it does not build.
    #[test]
    fn the_harness_is_bound_to_its_descriptor() {
        let harness = generate(
            &library(),
            &contract(VERIFY_TAG, "crypto::tag", "verify_tag"),
        )
        .unwrap();
        assert!(harness
            .source
            .contains("crypto::tag::__TRACE_CHECK_CONTRACT_verify_tag.as_bytes()"));
        assert!(harness.source.contains("const _: () = {"));
        assert!(harness
            .source
            .contains("descriptor changed after this harness was generated"));
    }

    /// Generation is deterministic, which is what makes the harness hash a
    /// provenance field rather than noise.
    #[test]
    fn generation_is_deterministic() {
        let first = generate(
            &library(),
            &contract(VERIFY_TAG, "crypto::tag", "verify_tag"),
        )
        .unwrap();
        let second = generate(
            &library(),
            &contract(VERIFY_TAG, "crypto::tag", "verify_tag"),
        )
        .unwrap();
        assert_eq!(first.source_sha256, second.source_sha256);
        assert_eq!(first.source, second.source);
    }

    /// A scalar secret becomes a global of its own width, and a unit return is
    /// still called and still cannot be optimized away.
    #[test]
    fn a_scalar_secret_and_a_unit_return_are_handled() {
        let json = r#"{"schema_version":1,"function":"absorb","parameters":[{"name":"value","position":0,"role":"secret","repr":"u32","rust_type":"u32"}],"returns":{"repr":"unit","rust_type":""}}"#;
        let harness = generate(&library(), &contract(json, "crypto::reduce", "absorb")).unwrap();
        assert_eq!(harness.inputs[0].bits, 32);
        assert!(harness
            .source
            .contains("pub static mut TC_SECRET_VALUE: u32 = 0;"));
        assert!(harness
            .source
            .contains("let target: fn(u32) = crypto::reduce::absorb;"));
        assert!(harness.source.contains("target(value);"));
        assert!(harness
            .source
            .contains("write_volatile(&raw mut TC_OUT, 0)"));
    }

    /// Two parameters that would share one global are refused: a secret must
    /// not be aliased onto a public input.
    #[test]
    fn colliding_globals_are_refused() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[{"name":"key","position":0,"role":"secret","repr":"u8","rust_type":"u8"},{"name":"KEY","position":1,"role":"secret","repr":"u8","rust_type":"u8"}],"returns":{"repr":"u8","rust_type":"u8"}}"#;
        let error = generate(&library(), &contract(json, "crypto", "f")).expect_err("refused");
        assert!(error.to_string().contains("aliased"), "{error}");
    }

    /// The verification case the engine consumes names the *resolved* symbol,
    /// the generated globals, and the configured bounds.
    #[test]
    fn the_verification_case_is_built_from_evidence() {
        let contract = contract(VERIFY_TAG, "crypto::tag", "verify_tag");
        let harness = generate(&library(), &contract).unwrap();
        let symbol = ResolvedSymbol {
            contract: contract.id.clone(),
            mangled: "_RNvCs1_6crypto3tag10verify_tag".to_string(),
            address: "0x2012b0".to_string(),
        };
        let settings = crate::contract::ContractSettings {
            description: "d".into(),
            rationale: "r".into(),
            max_depth: 4000,
            solver_timeout_secs: 30,
            wall_timeout_secs: 900,
            checks: vec![CheckFeature::ControlFlow, CheckFeature::MemoryAccess],
            assumptions: vec!["TC_PUBLIC_SUPPLIED < 4".into()],
            expected_outcome: "VERIFIED_BOUNDED".into(),
            inputs: Default::default(),
        };
        let case = verification_case(&contract, &symbol, &harness, &settings);
        assert_eq!(case.function, symbol.mangled);
        assert_eq!(case.entry_symbol, ENTRY_SYMBOL);
        assert_eq!(case.halt_symbol, HALT_SYMBOL);
        assert_eq!(case.secret_globals, vec!["TC_SECRET_EXPECTED"]);
        assert_eq!(case.public_globals, vec!["TC_PUBLIC_SUPPLIED"]);
        assert_eq!(case.assumptions, vec!["TC_PUBLIC_SUPPLIED < 4"]);
        assert_eq!(case.max_depth, 4000);
    }

    /// A public `bool` gets a generated domain restriction, because a symbolic
    /// byte has 256 values and Rust's `bool` has two. Other representations get
    /// none, so the restriction is not noise.
    #[test]
    fn a_public_bool_is_restricted_to_rusts_valid_values() {
        let json = r#"{"schema_version":1,"function":"mix_when","parameters":[{"name":"secret","position":0,"role":"secret","repr":"u32","rust_type":"u32"},{"name":"enabled","position":1,"role":"public","repr":"bool","rust_type":"bool"}],"returns":{"repr":"u32","rust_type":"u32"}}"#;
        let contract = contract(json, "crypto::controls", "mix_when");
        let harness = generate(&library(), &contract).unwrap();
        assert_eq!(
            harness.generated_assumptions,
            vec!["TC_PUBLIC_ENABLED <= 1"]
        );
        let bool_input = harness
            .inputs
            .iter()
            .find(|input| input.parameter == "enabled")
            .expect("the bool input");
        assert_eq!(bool_input.domain.as_deref(), Some("TC_PUBLIC_ENABLED <= 1"));
        // The scalar secret needs no restriction: every byte pattern is a valid
        // u32.
        assert!(harness.inputs[0].domain.is_none());
        // And the generated source says why the constraint exists.
        assert!(
            harness.source.contains("Restricted to Rust's valid values"),
            "{}",
            harness.source
        );
    }

    /// Generated restrictions reach the analyzer ahead of the developer's own
    /// assumptions, and the developer's are carried through unchanged.
    #[test]
    fn generated_restrictions_reach_the_case_before_declared_ones() {
        let json = r#"{"schema_version":1,"function":"mix_when","parameters":[{"name":"secret","position":0,"role":"secret","repr":"u32","rust_type":"u32"},{"name":"enabled","position":1,"role":"public","repr":"bool","rust_type":"bool"}],"returns":{"repr":"u32","rust_type":"u32"}}"#;
        let contract = contract(json, "crypto::controls", "mix_when");
        let harness = generate(&library(), &contract).unwrap();
        let symbol = ResolvedSymbol {
            contract: contract.id.clone(),
            mangled: "_RNvCs1_6crypto8controls8mix_when".to_string(),
            address: "0x201290".to_string(),
        };
        let mut settings = settings();
        settings.assumptions = vec!["TC_SECRET_SECRET < 1024".to_string()];
        let case = verification_case(&contract, &symbol, &harness, &settings);
        assert_eq!(
            case.assumptions,
            vec!["TC_PUBLIC_ENABLED <= 1", "TC_SECRET_SECRET < 1024"]
        );
    }

    /// An ephemeral workspace is created atomically at a name nothing can have
    /// pre-arranged, and removed when the run ends.
    ///
    /// The predictable `/tmp/trace-check-contract-verify-<pid>` this replaced
    /// could be pre-created or symlinked by another user on a shared machine,
    /// and the run writes a manifest, a source file and a linked executable
    /// into it.
    #[test]
    fn an_ephemeral_workspace_is_private_and_removed() {
        let path = {
            let workspace = Workspace::ephemeral().expect("created");
            let root = workspace.root().to_path_buf();
            assert!(root.is_dir());
            assert!(!workspace.is_kept());
            // Private to this user.
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&root)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "work directory must not be shared");
            root
        };
        assert!(!path.exists(), "the workspace must not outlive the run");
    }

    /// A kept workspace puts each run in its own freshly created directory
    /// inside the caller's, so nothing pre-existing there is reused or written
    /// through -- including a planted symlink -- and two runs never collide.
    #[test]
    fn a_kept_workspace_never_reuses_an_existing_entry() {
        let parent = tempfile::tempdir().expect("temp dir");
        // Stale contents and a symlink pointing somewhere a run must not write.
        let elsewhere = parent.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("decoy target");
        std::os::unix::fs::symlink(&elsewhere, parent.path().join("run-decoy"))
            .expect("plant a symlink");
        std::fs::write(parent.path().join("stale.txt"), "old").expect("stale file");

        let first = Workspace::kept_in(parent.path()).expect("created");
        let second = Workspace::kept_in(parent.path()).expect("created");
        assert!(first.is_kept() && second.is_kept());
        assert_ne!(first.root(), second.root());
        for workspace in [&first, &second] {
            assert!(workspace.root().starts_with(parent.path()));
            assert_ne!(workspace.root(), parent.path());
            assert_ne!(
                workspace.root(),
                parent.path().join("run-decoy"),
                "a planted entry must never be chosen as the run directory"
            );
            // Fresh: a run directory starts empty.
            assert_eq!(
                std::fs::read_dir(workspace.root())
                    .expect("readable")
                    .count(),
                0
            );
        }
        // The decoy was left alone.
        assert!(std::fs::read_dir(&elsewhere).expect("readable").count() == 0);
        assert!(parent.path().join("stale.txt").exists());
    }

    /// A contract directory is created atomically, so a name collision is
    /// reported rather than written into.
    #[test]
    fn a_contract_directory_is_not_reused() {
        let workspace = Workspace::ephemeral().expect("created");
        let (first, target) = workspace
            .directories_for("crypto::tag::verify_tag")
            .expect("created");
        assert!(first.is_dir() && target.is_dir());
        let error = workspace
            .directories_for("crypto::tag::verify_tag")
            .expect_err("a second use of one contract id must be refused");
        assert!(error.to_string().contains("verify_tag"), "{error}");
        // A different contract is fine, and shares the target directory.
        let (other, same_target) = workspace
            .directories_for("crypto::tag::other")
            .expect("created");
        assert_ne!(first, other);
        assert_eq!(target, same_target);
    }

    /// `nm` output parses to addresses and names, including demangled names
    /// that contain spaces.
    #[test]
    fn symbol_tables_parse() {
        let text = "\
00000000002012b0 t crypto::tag::verify_tag
00000000002012d0 T _start
0000000000201300 t core::ptr::drop_in_place<alloc::string::String>
";
        let parsed = parse_symbol_table(text);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], (0x2012b0, "crypto::tag::verify_tag".to_string()));
        assert_eq!(parsed[1].1, "_start");
        assert!(parsed[2].1.contains("String"));
    }

    /// The function-pointer type is rendered from the descriptor, which is what
    /// makes rustc the certifier of the argument mapping.
    #[test]
    fn function_pointer_types_are_rendered_from_the_descriptor() {
        let descriptor = Descriptor::parse(VERIFY_TAG).unwrap();
        assert_eq!(
            function_pointer_type(&descriptor),
            "fn(&[u8; 16], &[u8; 16]) -> bool"
        );
    }

    /// A probe failure naming the missing descriptor constant is explained as a
    /// missing annotation rather than as a compiler error to decipher.
    #[test]
    fn a_missing_annotation_is_explained() {
        let stderr = "error[E0425]: cannot find value `__TRACE_CHECK_CONTRACT_verify_tag` in \
                      module `crypto::tag`";
        let message = explain_probe_failure(stderr, "crypto::tag", "verify_tag", &library());
        assert!(
            message.contains("no `__TRACE_CHECK_CONTRACT_verify_tag`"),
            "{message}"
        );
        assert!(message.contains("#[constant_time]"), "{message}");

        let private = "error[E0603]: constant `__TRACE_CHECK_CONTRACT_verify_tag` is private";
        let message = explain_probe_failure(private, "crypto::tag", "verify_tag", &library());
        assert!(message.contains("not public"), "{message}");
    }

    /// The library's dependency stanza names the lib target, so the generated
    /// call can be spelled with the contract's own path.
    #[test]
    fn the_dependency_stanza_names_the_lib_target() {
        let stanza = library().dependency_stanza();
        assert!(stanza.contains("[dependencies.crypto]"), "{stanza}");
        assert!(stanza.contains("package = \"crypto-library\""), "{stanza}");
        let mut with_features = library();
        with_features.features = vec!["experimental".to_string()];
        assert!(with_features
            .dependency_stanza()
            .contains("features = [\"experimental\"]"));
    }
}
