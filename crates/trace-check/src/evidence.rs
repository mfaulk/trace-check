//! What decides which executable a result is about.
//!
//! A security result is a claim about one compiled artifact, never about a
//! function in general. M10 runs more than one backend over one contract, and
//! each builds its own executable from its own generated harness with its own
//! flags — so "the artifact" is ambiguous unless every result carries the
//! identity of the one it analyzed.
//!
//! [`ArtifactIdentity`] is that identity, in one shape for every backend. The
//! enforcement layer compares evidence against the obligation's artifact before
//! the evidence can discharge it; a reader compares two identities to see
//! exactly how two results about one contract differ.
//!
//! # Why a hash alone is not an identity
//!
//! A hash says two artifacts are the same bytes. It cannot say *why* they
//! differ, and a developer looking at two results — one clean, one not — needs
//! that. The fields here are the inputs that decide those bytes: the library and
//! its version, the enabled features, the dependency lockfile, the generated
//! harness source, the compiler, the build settings, and the backend. A
//! difference in the hash is explained by a difference in one of them.
//!
//! The descriptor fingerprint is here for a narrower reason. It is the
//! annotation's own output, so a changed secret role or parameter width changes
//! it — and a result recorded against one descriptor cannot be read as covering
//! a contract that now declares something else.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::harness::{Artifact, Library};
use crate::toolchain::Toolchain;

/// Which backend produced a result, and what it was.
///
/// Named rather than inferred from the evidence payload, because
/// [`ArtifactIdentity`] is compared and reported on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Backend {
    /// Valgrind Memcheck over a generated corpus.
    #[serde(rename = "valgrind-memcheck")]
    Memcheck,
    /// BINSEC relational symbolic execution.
    #[serde(rename = "binsec-relational")]
    Symbolic,
    /// Valgrind Memcheck over developer-written `#[ct_test]`s.
    ///
    /// The same analyzer as [`Backend::Memcheck`] and a different *source of
    /// inputs*, which is what the name records. A developer choosing the
    /// inputs and a generator choosing them are different evidence about the
    /// same property, and a reader comparing two results needs to know which
    /// one they are looking at.
    #[serde(rename = "valgrind-ct-test")]
    DeveloperTest,
}

impl Backend {
    /// The same spelling the serialized form uses, so a report and a rendered
    /// line never name one backend two ways.
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Memcheck => "valgrind-memcheck",
            Backend::Symbolic => "binsec-relational",
            Backend::DeveloperTest => "valgrind-ct-test",
        }
    }
}

/// Everything that decides which executable a result describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactIdentity {
    /// The contract this artifact was built to analyze.
    pub contract: String,
    /// `sha256` of the descriptor `#[constant_time]` emitted.
    ///
    /// The annotation's own output, so a changed secret role or parameter width
    /// changes it. A result recorded against one descriptor says nothing about
    /// a contract that now declares something else.
    pub descriptor_sha256: String,
    pub library_package: String,
    pub library_version: String,
    /// Cargo features enabled for the build. Another combination is another
    /// library and another artifact.
    pub features: Vec<String>,
    pub target: String,
    /// The toolchain that compiled this artifact, measured through itself.
    pub toolchain: Toolchain,
    /// Build settings, as the backend that chose them describes them.
    pub profile: String,
    /// The analyzed executable.
    pub artifact_sha256: String,
    /// The resolved dependency graph, which decides the library code compiled
    /// into it.
    pub lockfile_sha256: String,
    /// The generated harness source, which decides the surroundings.
    pub harness_sha256: String,
    pub backend: Backend,
    /// What the backend reports about itself, e.g. `valgrind-3.28.0`.
    pub backend_version: String,
    /// The analyzer container image, by digest. Symbolic only: the image *is*
    /// the analyzer and its solver, so a result is only reproducible against
    /// the exact one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analyzer_image: Option<String>,
}

impl ArtifactIdentity {
    /// The identity of a generated dynamic check's security artifact.
    ///
    /// The *security* artifact, deliberately, even for evidence folded against
    /// an `explore` requirement: coverage feedback chooses inputs and
    /// establishes nothing, so every security conclusion comes from this
    /// uninstrumented executable. The instrumented discovery artifact is
    /// recorded separately, in the discovery evidence.
    pub fn generated(
        contract: &str,
        descriptor_json: &str,
        library: &Library,
        artifact: &Artifact,
        harness_sha256: &str,
        valgrind_version: &str,
    ) -> ArtifactIdentity {
        ArtifactIdentity {
            contract: contract.to_string(),
            descriptor_sha256: fingerprint(descriptor_json),
            library_package: library.package.clone(),
            library_version: library.version.clone(),
            features: library.features.clone(),
            target: crate::symbolic::SUPPORTED_TARGET.to_string(),
            toolchain: library.toolchain.clone(),
            // Spelled out rather than taken from `dynamic_harness::PROFILE`
            // alone, which is the *same string* as the symbolic backend's and
            // so described two different builds identically. `panic` is the
            // difference that matters here: this harness unwinds, because a
            // finding needs a frame to attribute.
            profile: format!("{}, panic=unwind, hosted", crate::dynamic_harness::PROFILE),
            artifact_sha256: artifact.sha256.clone(),
            lockfile_sha256: artifact.lockfile_sha256.clone(),
            harness_sha256: harness_sha256.to_string(),
            backend: Backend::Memcheck,
            backend_version: valgrind_version.to_string(),
            analyzer_image: None,
        }
    }

    /// The identity of a symbolic verification artifact.
    pub fn symbolic(
        contract: &str,
        descriptor_json: &str,
        library: &Library,
        artifact: &Artifact,
        harness_sha256: &str,
        analyzer: &crate::symbolic::AnalyzerIdentity,
    ) -> ArtifactIdentity {
        ArtifactIdentity {
            contract: contract.to_string(),
            descriptor_sha256: fingerprint(descriptor_json),
            library_package: library.package.clone(),
            library_version: library.version.clone(),
            features: library.features.clone(),
            target: crate::symbolic::SUPPORTED_TARGET.to_string(),
            toolchain: library.toolchain.clone(),
            // The freestanding build: `panic=abort`, static relocation and
            // `-nostdlib`, which is what makes this a different executable
            // from the dynamic backend's and not merely a different copy.
            profile: format!(
                "{}, panic={}, freestanding ({})",
                crate::harness::PROFILE,
                crate::harness::PANIC_STRATEGY,
                crate::harness::RUSTFLAGS.join(" ")
            ),
            artifact_sha256: artifact.sha256.clone(),
            lockfile_sha256: artifact.lockfile_sha256.clone(),
            harness_sha256: harness_sha256.to_string(),
            backend: Backend::Symbolic,
            backend_version: analyzer
                .analyzer_build
                .clone()
                .unwrap_or_else(|| analyzer.analyzer.clone()),
            analyzer_image: Some(analyzer.analyzer_image.clone()),
        }
    }

    /// The identity of the test executables a developer-written `#[ct_test]`
    /// result rests on.
    ///
    /// `harness_sha256` names the same executable as `artifact_sha256` when one
    /// test target participates. That is not a fudge: for a developer-written
    /// test there is no *generated* harness to fingerprint separately — the
    /// test code is the harness, and it is compiled into the executable being
    /// analyzed.
    pub fn developer_test(
        contract: &str,
        descriptor_json: &str,
        library: &Library,
        artifact_sha256: &str,
        lockfile_sha256: &str,
        profile: &str,
        valgrind_version: &str,
    ) -> ArtifactIdentity {
        ArtifactIdentity {
            contract: contract.to_string(),
            descriptor_sha256: fingerprint(descriptor_json),
            library_package: library.package.clone(),
            library_version: library.version.clone(),
            features: library.features.clone(),
            target: crate::symbolic::SUPPORTED_TARGET.to_string(),
            toolchain: library.toolchain.clone(),
            profile: profile.to_string(),
            artifact_sha256: artifact_sha256.to_string(),
            lockfile_sha256: lockfile_sha256.to_string(),
            harness_sha256: artifact_sha256.to_string(),
            backend: Backend::DeveloperTest,
            backend_version: valgrind_version.to_string(),
            analyzer_image: None,
        }
    }

    /// Why this identity is not the one an obligation is about, if it is not.
    ///
    /// Only the fields that decide *which executable and which contract*. The
    /// toolchain, the profile and the backend version are recorded for a reader
    /// and deliberately not compared: they are inputs to the hash, so a
    /// difference in any of them already shows up as a different
    /// `artifact_sha256`, and comparing them again would reject evidence for
    /// disagreeing about something it cannot disagree about.
    pub fn mismatch(&self, contract: &str, artifact_sha256: &str) -> Option<String> {
        if self.contract != contract {
            return Some(format!("it is about `{}`, not `{contract}`", self.contract));
        }
        if self.artifact_sha256 != artifact_sha256 {
            return Some(format!(
                "it describes artifact {} and this obligation is about {}; a result is a claim \
                 about one executable",
                short(&self.artifact_sha256),
                short(artifact_sha256)
            ));
        }
        None
    }

    /// How two identities for one contract differ, for a report that shows two
    /// results side by side.
    ///
    /// Names the inputs rather than only the hashes, because "these are two
    /// different binaries" is not actionable and "they were built with
    /// different profiles by different compilers" is.
    pub fn differences(&self, other: &ArtifactIdentity) -> Vec<String> {
        let mut out = Vec::new();
        let mut note = |field: &str, left: &str, right: &str| {
            if left != right {
                out.push(format!("{field}: {left} vs {right}"));
            }
        };
        note("contract", &self.contract, &other.contract);
        note(
            "descriptor",
            &short(&self.descriptor_sha256),
            &short(&other.descriptor_sha256),
        );
        note("library", &self.library_version, &other.library_version);
        note(
            "features",
            &self.features.join(","),
            &other.features.join(","),
        );
        note("target", &self.target, &other.target);
        note(
            "compiler",
            &self.toolchain.rustc_version,
            &other.toolchain.rustc_version,
        );
        note("profile", &self.profile, &other.profile);
        note(
            "lockfile",
            &short(&self.lockfile_sha256),
            &short(&other.lockfile_sha256),
        );
        note(
            "harness",
            &short(&self.harness_sha256),
            &short(&other.harness_sha256),
        );
        note("backend", self.backend.as_str(), other.backend.as_str());
        note(
            "artifact",
            &short(&self.artifact_sha256),
            &short(&other.artifact_sha256),
        );
        out
    }
}

fn fingerprint(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn short(sha256: &str) -> String {
    sha256.chars().take(12).collect()
}

/// An identity for a test that is about enforcement rather than provenance.
#[cfg(test)]
pub(crate) fn sample_identity(contract: &str, artifact_sha256: &str) -> ArtifactIdentity {
    ArtifactIdentity {
        contract: contract.to_string(),
        descriptor_sha256: fingerprint("{}"),
        library_package: "crypto-library".to_string(),
        library_version: "0.1.0".to_string(),
        features: Vec::new(),
        target: crate::symbolic::SUPPORTED_TARGET.to_string(),
        toolchain: Toolchain {
            name: Some("1.97.0-x86_64-unknown-linux-gnu".to_string()),
            rustc_version: "rustc 1.97.0".to_string(),
            cargo_version: "cargo 1.97.0".to_string(),
        },
        profile: "test".to_string(),
        artifact_sha256: artifact_sha256.to_string(),
        lockfile_sha256: "lock".to_string(),
        harness_sha256: "harness".to_string(),
        backend: Backend::Memcheck,
        backend_version: "valgrind-3.28.0".to_string(),
        analyzer_image: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const DESCRIPTOR: &str = r#"{"schema_version":1,"function":"verify_tag"}"#;

    fn library() -> Library {
        Library {
            package: "crypto-library".into(),
            version: "0.1.0".into(),
            lib_name: "crypto".into(),
            manifest_path: "/w/Cargo.toml".into(),
            features: Vec::new(),
            toolchain: Toolchain {
                name: Some("1.97.0-x86_64-unknown-linux-gnu".into()),
                rustc_version: "rustc 1.97.0".into(),
                cargo_version: "cargo 1.97.0".into(),
            },
        }
    }

    fn artifact(sha: &str) -> Artifact {
        Artifact {
            path: PathBuf::from("/tmp/artifact"),
            sha256: sha.into(),
            lockfile_sha256: "lock".into(),
        }
    }

    fn generated(sha: &str) -> ArtifactIdentity {
        ArtifactIdentity::generated(
            "crypto::tag::verify_tag",
            DESCRIPTOR,
            &library(),
            &artifact(sha),
            "harness",
            "valgrind-3.28.0",
        )
    }

    /// The serialized backend name and the rendered one agree, so a JSON
    /// report and a text line never name one backend two ways.
    #[test]
    fn the_backend_name_is_spelled_one_way() {
        for backend in [Backend::Memcheck, Backend::Symbolic] {
            let json = serde_json::to_string(&backend).expect("serializable");
            assert_eq!(json, format!("{:?}", backend.as_str()));
        }
    }

    /// An identity matches the obligation it was built for, and names the
    /// mismatch when the contract or the executable is not the one asked about.
    #[test]
    fn an_identity_is_checked_against_its_obligation() {
        let identity = generated("aaaa");
        assert_eq!(identity.mismatch("crypto::tag::verify_tag", "aaaa"), None);

        let wrong_contract = identity
            .mismatch("crypto::tag::other", "aaaa")
            .expect("a mismatch");
        assert!(
            wrong_contract.contains("not `crypto::tag::other`"),
            "{wrong_contract}"
        );

        let wrong_artifact = identity
            .mismatch("crypto::tag::verify_tag", "bbbb")
            .expect("a mismatch");
        assert!(
            wrong_artifact.contains("one executable"),
            "{wrong_artifact}"
        );
    }

    /// The descriptor fingerprint tracks the annotation, so a contract that
    /// changes what it declares no longer matches evidence recorded before.
    #[test]
    fn the_descriptor_fingerprint_follows_the_annotation() {
        let before = generated("aaaa");
        let after = ArtifactIdentity::generated(
            "crypto::tag::verify_tag",
            r#"{"schema_version":1,"function":"verify_tag","changed":true}"#,
            &library(),
            &artifact("aaaa"),
            "harness",
            "valgrind-3.28.0",
        );
        assert_ne!(before.descriptor_sha256, after.descriptor_sha256);
        assert_eq!(
            before.differences(&after),
            vec![format!(
                "descriptor: {} vs {}",
                short(&before.descriptor_sha256),
                short(&after.descriptor_sha256)
            )]
        );
    }

    /// Two backends' identities for one contract differ in the inputs that
    /// explain the different executables, not only in the hash.
    #[test]
    fn two_backends_differ_in_named_inputs() {
        let analyzer = crate::symbolic::AnalyzerIdentity {
            rustc_version: "rustc 1.97.0".into(),
            analyzer: crate::symbolic::ANALYZER_NAME.into(),
            analyzer_build: Some("binsec 0.11.2".into()),
            analyzer_image: crate::symbolic::ANALYZER_IMAGE.into(),
            solver: crate::symbolic::ANALYZER_SOLVER.into(),
            container_tool: "podman".into(),
            target: crate::symbolic::SUPPORTED_TARGET.into(),
        };
        let symbolic = ArtifactIdentity::symbolic(
            "crypto::tag::verify_tag",
            DESCRIPTOR,
            &library(),
            &artifact("bbbb"),
            "symbolic-harness",
            &analyzer,
        );
        let differences = generated("aaaa").differences(&symbolic);
        let joined = differences.join("; ");
        for expected in ["profile", "harness", "backend", "artifact"] {
            assert!(
                differences.iter().any(|line| line.starts_with(expected)),
                "{expected} must be named among the differences: {joined}"
            );
        }
        // The contract, the descriptor and the library are the *same*, which is
        // what makes the two results comparable at all.
        for same in ["contract", "descriptor", "library", "compiler"] {
            assert!(
                !differences.iter().any(|line| line.starts_with(same)),
                "{same} must not differ between two backends of one contract: {joined}"
            );
        }
        assert_eq!(
            symbolic.analyzer_image.as_deref(),
            Some(crate::symbolic::ANALYZER_IMAGE),
            "a symbolic result is only reproducible against the exact analyzer image"
        );
        assert!(generated("aaaa").analyzer_image.is_none());
    }
}
