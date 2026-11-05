//! The Rust toolchain a generated build must use.
//!
//! # Why this exists
//!
//! `rustup` resolves a toolchain by walking up from the **working directory**.
//! trace-check runs in the developer's project, which may carry a
//! `rust-toolchain.toml`; the harnesses it generates are built in a private work
//! directory, which for an ephemeral workspace is under `/tmp` and sees no such
//! file. So the two resolved differently, and nothing noticed:
//!
//! * `rustc --version` was measured where trace-check runs — the pinned
//!   toolchain — and recorded as the artifact's compiler.
//! * the artifact was built where the harness lives — the *default* toolchain.
//!
//! Demonstrated against a library pinning 1.88.0 while the default was 1.97.0:
//! the report said `rustc 1.88.0` and the analyzed executable was byte-identical
//! to the 1.97.0 build. A recorded compiler that is not the one that compiled
//! the code makes the whole artifact identity untrustworthy, and a result is a
//! claim about one executable.
//!
//! It is also wrong on its own terms. A developer who pins a toolchain pins the
//! code their project compiles; verifying a build by a different compiler
//! analyzes code they do not ship.
//!
//! # What this does
//!
//! Resolves the toolchain once from the **library's** manifest directory — the
//! project whose pin is the one that matters — and forces it on every generated
//! build through `RUSTUP_TOOLCHAIN`, which rustup honours over directory
//! resolution. The version is then measured through that same toolchain, so the
//! recorded compiler is the one that ran.
//!
//! Without rustup the name is `None`, nothing is forced, and the version is
//! whatever `rustc` the build will find. That is the honest answer for a distro
//! toolchain: there is no pin to respect and none to misreport.

use std::path::Path;
use std::process::Command;

use serde::Serialize;

/// The toolchain every build in one run uses, and what it reports about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Toolchain {
    /// rustup toolchain name, when rustup resolved one for the library.
    ///
    /// `None` when rustup is not in use. Serialized so a reader can tell "the
    /// project pinned this" from "whatever was on PATH".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `rustc --version`, measured through [`Toolchain::name`] when there is
    /// one.
    pub rustc_version: String,
    /// `cargo --version`, measured the same way.
    pub cargo_version: String,
}

impl Toolchain {
    /// Resolves the toolchain `directory`'s project pins.
    ///
    /// Never fails: a missing rustup, a missing `rustc` and an unreadable
    /// version are all recorded as unavailable rather than aborting a run. The
    /// identity has to say what it knows, and "unavailable" is a fact a reader
    /// can act on — guessing a version would not be.
    pub fn resolve(directory: &Path) -> Toolchain {
        let name = active_toolchain(directory);
        Toolchain {
            rustc_version: version("rustc", name.as_deref()),
            cargo_version: version("cargo", name.as_deref()),
            name,
        }
    }

    /// Forces this toolchain on a generated build.
    ///
    /// `RUSTUP_TOOLCHAIN` overrides directory resolution, which is the whole
    /// point: the generated package lives outside the project and must not pick
    /// up the machine's default.
    pub fn apply(&self, command: &mut Command) {
        if let Some(name) = &self.name {
            command.env("RUSTUP_TOOLCHAIN", name);
        }
    }

    /// A toolchain with nothing resolved, for a test that is not about
    /// provenance.
    pub fn unresolved() -> Toolchain {
        Toolchain {
            name: None,
            rustc_version: version("rustc", None),
            cargo_version: version("cargo", None),
        }
    }
}

/// The rustup toolchain name active in `directory`, if rustup resolves one.
///
/// Run with `directory` as the working directory, because that is what rustup's
/// own resolution reads. The name is the first whitespace-delimited token:
/// `rustup show active-toolchain` prints
/// `1.97.0-x86_64-unknown-linux-gnu (overridden by '…/rust-toolchain.toml')`.
///
/// # The ambient variable is cleared, deliberately
///
/// `RUSTUP_TOOLCHAIN` outranks directory resolution, and rustup's cargo shim
/// **sets it for every child process** — so when trace-check runs as
/// `cargo trace-check`, it inherits the toolchain resolved from the *invocation*
/// directory. That is not the same as the library's. `--manifest-path` pointing
/// at a project with its own pin is exactly the case this repository's own CI
/// uses, and the inherited value would silently win.
///
/// The library's pin is the authority, because the library is the code being
/// analyzed and its pin is what decides the machine code a developer ships.
///
/// The cost is that `cargo +1.99 trace-check verify` no longer selects 1.99 for
/// the analysis build. That is a real loss and the right trade: verifying a
/// project pinned at 1.88 with a 1.99 compiler analyzes code the project does
/// not produce. `rustup override set` and `rust-toolchain.toml` both still work,
/// because both are directory resolution.
fn active_toolchain(directory: &Path) -> Option<String> {
    let output = Command::new("rustup")
        .args(["show", "active-toolchain"])
        .current_dir(directory)
        .env_remove("RUSTUP_TOOLCHAIN")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let name = text.split_whitespace().next()?.to_string();
    (!name.is_empty()).then_some(name)
}

/// `<tool> --version` as the named toolchain reports it.
fn version(tool: &str, toolchain: Option<&str>) -> String {
    let mut command = Command::new(tool);
    command.arg("--version");
    if let Some(name) = toolchain {
        command.env("RUSTUP_TOOLCHAIN", name);
    }
    // Cleared for the same reason resolution clears it: the measurement must
    // describe the toolchain that will build, which is the resolved one.
    if toolchain.is_none() {
        command.env_remove("RUSTUP_TOOLCHAIN");
    }
    match command.output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if text.is_empty() {
                format!("{tool} (version unavailable)")
            } else {
                text
            }
        }
        _ => format!("{tool} (version unavailable)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This repository pins a toolchain, so resolution finds it rather than the
    /// machine default — and the version is measured through it.
    #[test]
    fn a_pinned_toolchain_is_resolved_from_the_directory() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the crate lives two levels below the workspace root");
        let pinned = std::fs::read_to_string(repo.join("rust-toolchain.toml"))
            .expect("this repository pins a toolchain");
        let channel = pinned
            .lines()
            .find_map(|line| line.trim().strip_prefix("channel = "))
            .map(|value| value.trim().trim_matches('"').to_string())
            .expect("the pin names a channel");

        let resolved = Toolchain::resolve(repo);
        // Skipped rather than failed without rustup: a distro toolchain has no
        // pin to resolve, which is a legitimate environment.
        let Some(name) = &resolved.name else {
            eprintln!("skipping: rustup did not resolve a toolchain");
            return;
        };
        assert!(
            name.starts_with(&channel),
            "resolved {name:?}, which is not the pinned {channel:?}"
        );
        assert!(
            resolved.rustc_version.contains(&channel),
            "the version must be measured through the resolved toolchain: {} is not {channel}",
            resolved.rustc_version
        );
    }

    /// Applying a resolved toolchain forces it on a build; applying an
    /// unresolved one forces nothing.
    #[test]
    fn applying_a_toolchain_overrides_directory_resolution() {
        let toolchain = Toolchain {
            name: Some("1.88.0-x86_64-unknown-linux-gnu".to_string()),
            rustc_version: "rustc 1.88.0".to_string(),
            cargo_version: "cargo 1.88.0".to_string(),
        };
        let mut command = Command::new("cargo");
        toolchain.apply(&mut command);
        let forced: Vec<_> = command
            .get_envs()
            .filter(|(key, _)| *key == "RUSTUP_TOOLCHAIN")
            .collect();
        assert_eq!(forced.len(), 1, "the toolchain must be forced exactly once");
        assert_eq!(
            forced[0]
                .1
                .map(|value| value.to_string_lossy().into_owned()),
            Some("1.88.0-x86_64-unknown-linux-gnu".to_string())
        );

        let mut command = Command::new("cargo");
        Toolchain {
            name: None,
            rustc_version: "rustc 1.97.0".to_string(),
            cargo_version: "cargo 1.97.0".to_string(),
        }
        .apply(&mut command);
        assert!(
            !command.get_envs().any(|(key, _)| key == "RUSTUP_TOOLCHAIN"),
            "with no resolved toolchain nothing may be forced"
        );
    }
}
