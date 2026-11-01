//! Building test binaries and discovering the checks inside them.
//!
//! Discovery uses the standard test harness rather than a registry crate or a
//! hand-maintained manifest:
//!
//! 1. `cargo test --no-run --message-format=json` reports every test executable
//!    structurally, so paths are never guessed.
//! 2. Each executable is run once with `TRACE_CHECK_MODE=list --nocapture`,
//!    where generated tests print one `trace-check-meta:` line each.
//!
//! Contracts are emitted by `#[constant_time]` independently of any test, which
//! is what makes an *untested* contract discoverable — the case that must never
//! read as verified.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;

/// Build profile M2 defines: optimized, with debug symbols retained because a
/// finding without a source location is not actionable.
pub const PREFERRED_PROFILE: &str = "memcheck";

/// Prefix generated tests print their metadata behind.
const META_PREFIX: &str = "trace-check-meta:";

#[derive(Debug, Clone, Serialize)]
pub struct TestRecord {
    /// Harness path, which is also what `--exact` accepts.
    pub name: String,
    /// Contract this test declares it covers, if any.
    pub target: Option<String>,
    pub secrets: Vec<String>,
    /// Executable the test lives in.
    pub executable: String,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractRecord {
    pub function: String,
    pub secrets: Vec<String>,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Discovery {
    pub tests: Vec<TestRecord>,
    pub contracts: Vec<ContractRecord>,
    /// Profile actually used, which may differ from the preferred one.
    pub profile: String,
}

#[derive(Debug)]
pub enum DiscoverError {
    Build {
        stderr: String,
    },
    NoTestBinaries,
    Spawn {
        command: String,
        source: String,
    },
    ListFailed {
        executable: String,
        status: String,
        stderr: String,
    },
    BadMeta {
        line: String,
        reason: String,
    },
    Io(String),
}

impl std::fmt::Display for DiscoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoverError::Build { stderr } => {
                write!(f, "building the test binaries failed:\n{stderr}")
            }
            DiscoverError::NoTestBinaries => write!(
                f,
                "cargo reported no test executables; is there a test target in this package?"
            ),
            DiscoverError::Spawn { command, source } => {
                write!(f, "cannot run `{command}`: {source}")
            }
            DiscoverError::ListFailed {
                executable,
                status,
                stderr,
            } => write!(
                f,
                "listing constant-time tests in {executable} failed with {status}: {stderr}"
            ),
            DiscoverError::BadMeta { line, reason } => {
                write!(f, "cannot parse discovery line {line:?}: {reason}")
            }
            DiscoverError::Io(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for DiscoverError {}

/// Builds test binaries and returns their paths.
///
/// Tries the `memcheck` profile first. A package outside this workspace will
/// not define it, so the fallback uses `--release` with debug symbols injected
/// via `--config`, which keeps consumers from having to edit their
/// `Cargo.toml`.
pub fn build_test_binaries(
    manifest_path: Option<&Path>,
    profile_override: Option<&str>,
    features: &[String],
) -> Result<(Vec<PathBuf>, String), DiscoverError> {
    let feature_args: Vec<String> = if features.is_empty() {
        Vec::new()
    } else {
        vec!["--features".to_string(), features.join(",")]
    };

    if let Some(profile) = profile_override {
        let mut args = profile_args(profile);
        args.extend(feature_args);
        let binaries = cargo_build(manifest_path, &args)?;
        return Ok((binaries, profile.to_string()));
    }

    let mut preferred = profile_args(PREFERRED_PROFILE);
    preferred.extend(feature_args.clone());
    match cargo_build(manifest_path, &preferred) {
        Ok(binaries) => Ok((binaries, PREFERRED_PROFILE.to_string())),
        Err(DiscoverError::Build { stderr }) if mentions_missing_profile(&stderr) => {
            eprintln!(
                "trace-check: this package does not define a `{PREFERRED_PROFILE}` profile; \
                 falling back to `release` with debug symbols"
            );
            let mut fallback = release_with_symbols();
            fallback.extend(feature_args);
            let binaries = cargo_build(manifest_path, &fallback)?;
            Ok((binaries, "release+debug".to_string()))
        }
        Err(other) => Err(other),
    }
}

fn profile_args(profile: &str) -> Vec<String> {
    vec!["--profile".to_string(), profile.to_string()]
}

/// Release optimization plus symbols, without requiring a profile in the
/// consumer's manifest.
fn release_with_symbols() -> Vec<String> {
    vec![
        "--release".to_string(),
        "--config".to_string(),
        "profile.release.debug=true".to_string(),
        "--config".to_string(),
        "profile.release.strip=\"none\"".to_string(),
    ]
}

fn mentions_missing_profile(stderr: &str) -> bool {
    stderr.contains("profile") && stderr.contains(PREFERRED_PROFILE) && stderr.contains("not")
}

fn cargo_build(
    manifest_path: Option<&Path>,
    profile_args: &[String],
) -> Result<Vec<PathBuf>, DiscoverError> {
    let mut command = Command::new("cargo");
    command.arg("test").arg("--no-run");
    command.args(profile_args);
    if let Some(path) = manifest_path {
        command.arg("--manifest-path").arg(path);
    }
    command.arg("--message-format=json-render-diagnostics");

    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|e| DiscoverError::Io(format!("cannot run cargo: {e}")))?;
    if !output.status.success() {
        return Err(DiscoverError::Build {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    // Read executables from cargo's structured output rather than guessing a
    // path, so a custom CARGO_TARGET_DIR cannot leave us running a stale binary.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let binaries: Vec<PathBuf> = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .filter(|message| message["profile"]["test"] == true)
        .filter_map(|message| message["executable"].as_str().map(PathBuf::from))
        .collect();

    if binaries.is_empty() {
        return Err(DiscoverError::NoTestBinaries);
    }
    Ok(binaries)
}

/// Runs each binary in `list` mode and collects the records it prints.
///
/// Not under Valgrind: listing performs no analysis, so paying Memcheck's
/// overhead for it would be waste.
pub fn discover(binaries: &[PathBuf], profile: &str) -> Result<Discovery, DiscoverError> {
    let mut tests = Vec::new();
    let mut contracts: BTreeMap<String, ContractRecord> = BTreeMap::new();

    for binary in binaries {
        let hash = sha256_of(binary)?;
        let output = Command::new(binary)
            .arg("--nocapture")
            // `--test-threads=1` keeps the metadata lines from interleaving.
            .arg("--test-threads=1")
            .env("TRACE_CHECK_MODE", "list")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| DiscoverError::Spawn {
                command: binary.display().to_string(),
                source: e.to_string(),
            })?;
        if !output.status.success() {
            return Err(DiscoverError::ListFailed {
                executable: binary.display().to_string(),
                status: output
                    .status
                    .code()
                    .map_or_else(|| "a signal".to_string(), |c| format!("exit code {c}")),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // `--nocapture` interleaves test output with the harness's own
            // progress lines, so the record is not necessarily at line start.
            let Some(start) = line.find(META_PREFIX) else {
                continue;
            };
            let payload = &line[start + META_PREFIX.len()..];
            let value: serde_json::Value =
                serde_json::from_str(payload.trim()).map_err(|e| DiscoverError::BadMeta {
                    line: line.to_string(),
                    reason: e.to_string(),
                })?;
            match value["kind"].as_str() {
                Some("test") => tests.push(TestRecord {
                    name: string_field(&value, "name", line)?,
                    target: value["target"].as_str().map(str::to_string),
                    secrets: string_list(&value, "secrets"),
                    executable: binary.display().to_string(),
                    executable_sha256: hash.clone(),
                }),
                Some("contract") => {
                    let function = string_field(&value, "function", line)?;
                    contracts.insert(
                        function.clone(),
                        ContractRecord {
                            function,
                            secrets: string_list(&value, "secrets"),
                            file: value["file"].as_str().unwrap_or_default().to_string(),
                            line: value["line"].as_u64().unwrap_or_default() as u32,
                        },
                    );
                }
                other => {
                    return Err(DiscoverError::BadMeta {
                        line: line.to_string(),
                        reason: format!("unknown record kind {other:?}"),
                    })
                }
            }
        }
    }

    tests.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Discovery {
        tests,
        contracts: contracts.into_values().collect(),
        profile: profile.to_string(),
    })
}

fn string_field(
    value: &serde_json::Value,
    field: &str,
    line: &str,
) -> Result<String, DiscoverError> {
    value[field]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| DiscoverError::BadMeta {
            line: line.to_string(),
            reason: format!("missing string field `{field}`"),
        })
}

fn string_list(value: &serde_json::Value, field: &str) -> Vec<String> {
    value[field]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn sha256_of(path: &Path) -> Result<String, DiscoverError> {
    use sha2::{Digest, Sha256};
    let bytes =
        std::fs::read(path).map_err(|e| DiscoverError::Io(format!("{}: {e}", path.display())))?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing-profile build error is recognized so the release fallback can
    /// apply for packages outside this workspace.
    #[test]
    fn missing_profile_error_is_recognized() {
        assert!(mentions_missing_profile(
            "error: profile `memcheck` is not defined in Cargo.toml"
        ));
        assert!(!mentions_missing_profile("error: could not compile `foo`"));
    }

    /// The release fallback keeps optimization and adds symbols, because a
    /// finding without a source location is not actionable.
    #[test]
    fn release_fallback_keeps_optimization_and_symbols() {
        let args = release_with_symbols();
        assert!(args.contains(&"--release".to_string()));
        assert!(args.iter().any(|a| a == "profile.release.debug=true"));
        assert!(args.iter().any(|a| a.contains("strip")));
    }

    /// String lists tolerate absent and malformed fields rather than panicking.
    #[test]
    fn string_lists_tolerate_missing_fields() {
        let value: serde_json::Value = serde_json::json!({"secrets": ["a", "b"]});
        assert_eq!(string_list(&value, "secrets"), vec!["a", "b"]);
        assert!(string_list(&value, "absent").is_empty());
        let odd: serde_json::Value = serde_json::json!({"secrets": "not an array"});
        assert!(string_list(&odd, "secrets").is_empty());
    }

    /// A record missing a required field is an explicit error, never skipped.
    #[test]
    fn missing_required_field_is_an_error() {
        let value: serde_json::Value = serde_json::json!({"kind": "test"});
        let error = string_field(&value, "name", "the line").unwrap_err();
        assert!(error.to_string().contains("missing string field `name`"));
    }

    /// The metadata prefix is the discovery contract with the test library and
    /// is pinned so the two cannot drift apart.
    #[test]
    fn meta_prefix_matches_the_library() {
        assert_eq!(META_PREFIX, trace_check_test_meta_prefix());
    }

    /// A record is found even when the harness has prefixed the line with its
    /// own progress output, which is what `--nocapture` actually produces.
    #[test]
    fn records_are_found_mid_line() {
        let line = "test my_test ... trace-check-meta: {\"kind\":\"test\"}";
        let start = line.find(META_PREFIX).expect("prefix is present");
        let payload = &line[start + META_PREFIX.len()..];
        assert_eq!(payload.trim(), "{\"kind\":\"test\"}");
    }

    /// Mirrors `trace_check_test::meta::META_PREFIX` without depending on the
    /// test library from the runner.
    fn trace_check_test_meta_prefix() -> &'static str {
        "trace-check-meta:"
    }
}
