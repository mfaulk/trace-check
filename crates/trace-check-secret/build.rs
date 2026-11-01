//! Locates Valgrind's client-request headers and builds the shim.
//!
//! Discovery is ordered most-explicit first. When no headers are found the
//! crate still builds, but without the shim and with a cfg that makes
//! `run_mode()` report `Unsupported`. That is deliberate: a clean result from
//! an uninstrumented run is rejected by the analysis backend, so degrading is
//! safe, and it keeps the fast test suite buildable without Valgrind.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=csrc/shim.c");
    println!("cargo:rerun-if-env-changed=VALGRIND_INCLUDE");

    // Only Linux is supported; elsewhere compile a stub so the crate still
    // builds and reports instrumentation as unavailable at runtime.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        println!("cargo:rustc-cfg=trace_check_no_valgrind");
        return;
    }

    // Without headers we build no shim and set a cfg that makes `run_mode`
    // report `Unsupported`. That is safe because an uninstrumented run can
    // never be read as a pass, and it keeps the fast test suite buildable on a
    // machine with no Valgrind installed.
    let Some(include) = discover() else {
        println!(
            "cargo:warning=Valgrind headers (valgrind/memcheck.h) not found; \
             building trace-check-secret without instrumentation. Secret marking \
             will be inert and run_mode() will report `unsupported`. \
             Install Valgrind (Debian/Ubuntu: apt-get install valgrind, \
             Fedora: dnf install valgrind-devel) or set VALGRIND_INCLUDE."
        );
        println!("cargo:rustc-cfg=trace_check_no_valgrind");
        return;
    };

    cc::Build::new()
        .file("csrc/shim.c")
        .include(&include)
        .warnings(true)
        .compile("trace_check_shim");
}

fn discover() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("VALGRIND_INCLUDE") {
        let path = PathBuf::from(path);
        assert!(
            path.join("valgrind/memcheck.h").is_file(),
            "VALGRIND_INCLUDE={} does not contain valgrind/memcheck.h",
            path.display()
        );
        return Some(path);
    }

    if let Some(path) = pkg_config() {
        return Some(path);
    }

    // The prefix of whichever `valgrind` is on PATH, for local source installs.
    if let Ok(output) = Command::new("sh")
        .args(["-c", "command -v valgrind"])
        .output()
    {
        if output.status.success() {
            let binary = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
            if let Ok(resolved) = std::fs::canonicalize(&binary) {
                if let Some(prefix) = resolved.parent().and_then(|p| p.parent()) {
                    let include = prefix.join("include");
                    if include.join("valgrind/memcheck.h").is_file() {
                        return Some(include);
                    }
                }
            }
        }
    }

    let system = PathBuf::from("/usr/include");
    system
        .join("valgrind/memcheck.h")
        .is_file()
        .then_some(system)
}

fn pkg_config() -> Option<PathBuf> {
    let output = Command::new("pkg-config")
        .args(["--variable=includedir", "valgrind"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.join("valgrind/memcheck.h").is_file().then_some(path)
}
