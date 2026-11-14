//! `cargo trace-check doctor` end to end. Forced failures use a fabricated
//! `PATH` and need no Valgrind; the self-test cases skip without Valgrind
//! unless `TRACE_CHECK_REQUIRE_BACKEND=1` demands it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cargo-trace-check"))
}

fn valgrind_available() -> bool {
    let present = Command::new("valgrind")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !present {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
            "TRACE_CHECK_REQUIRE_BACKEND is set but valgrind is not on PATH"
        );
        eprintln!("skipping: valgrind is not on PATH");
    }
    present
}

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// A `bin` directory holding only the Rust toolchain proxies, plus `extra`.
fn fake_path(root: &Path, with_cc: bool, extra: &[(&str, &str)]) -> PathBuf {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let mut tools = vec!["rustc", "cargo", "rustup"];
    if with_cc {
        tools.push("cc");
    }
    for tool in tools {
        if let Some(real) = which(tool) {
            std::os::unix::fs::symlink(real, bin.join(tool)).unwrap();
        }
    }
    for (name, script) in extra {
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

fn doctor_json(path: Option<&Path>, envs: &[(&str, &Path)]) -> (Output, Value) {
    let mut command = Command::new(cli());
    command
        .args(["doctor", "--format", "json"])
        .env_remove("CC");
    if let Some(path) = path {
        command.env("PATH", path);
    }
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("the CLI runs");
    let json = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "doctor printed invalid JSON ({error}): {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, json)
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == id)
        .unwrap_or_else(|| panic!("no `{id}` check in {report}"))
}

/// Without `valgrind` on PATH doctor exits 1 and names the package to install.
#[test]
fn missing_valgrind_fails_with_remediation() {
    let root = tempfile::tempdir().unwrap();
    let bin = fake_path(root.path(), true, &[]);
    let (output, report) = doctor_json(Some(&bin), &[]);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(report["required_ok"], false);
    let valgrind = check(&report, "valgrind");
    assert_eq!(valgrind["status"], "missing");
    assert!(valgrind["remediation"]
        .as_str()
        .unwrap()
        .contains("apt-get install valgrind"));
    assert_eq!(check(&report, "self-test")["status"], "skipped");
}

/// A version banner below the floor fails as incompatible and names the floor.
#[test]
fn old_valgrind_banner_fails() {
    let root = tempfile::tempdir().unwrap();
    let bin = fake_path(root.path(), true, &[("valgrind", "echo valgrind-3.10.1")]);
    let (output, report) = doctor_json(Some(&bin), &[]);
    assert_eq!(output.status.code(), Some(1), "{report}");
    let valgrind = check(&report, "valgrind");
    assert_eq!(valgrind["status"], "incompatible");
    assert!(valgrind["detail"].as_str().unwrap().contains("3.22.0"));
    assert!(valgrind["remediation"]
        .as_str()
        .unwrap()
        .contains("dnf install valgrind valgrind-devel"));
}

/// Without a C compiler doctor exits 1 and names the package to install.
#[test]
fn missing_c_compiler_fails() {
    let root = tempfile::tempdir().unwrap();
    let bin = fake_path(root.path(), false, &[("valgrind", "echo valgrind-3.28.0")]);
    let (output, report) = doctor_json(Some(&bin), &[]);
    assert_eq!(output.status.code(), Some(1), "{report}");
    let compiler = check(&report, "c-compiler");
    assert_eq!(compiler["status"], "missing");
    assert!(compiler["remediation"]
        .as_str()
        .unwrap()
        .contains("build-essential"));
}

/// Optional backends never fail the run: their checks are only ever pass, warn or skip.
#[test]
fn optional_checks_never_fail() {
    let root = tempfile::tempdir().unwrap();
    let bin = fake_path(root.path(), true, &[]);
    let (_, report) = doctor_json(Some(&bin), &[]);
    for id in ["llvm-tools", "container-runtime", "analyzer-image"] {
        let optional = check(&report, id);
        assert_eq!(optional["requirement"], "optional");
        assert_ne!(optional["verdict"], "fail", "{optional}");
    }
}

/// On a working machine every required check passes, and two runs agree byte for byte apart from durations.
#[test]
fn healthy_machine_passes_and_json_is_stable() {
    if !valgrind_available() {
        return;
    }
    let strip = |mut report: Value| {
        for check in report["checks"].as_array_mut().unwrap() {
            check["duration_ms"] = Value::Null;
        }
        report.to_string()
    };
    let (first_output, first) = doctor_json(None, &[]);
    assert_eq!(first_output.status.code(), Some(0), "{first}");
    assert_eq!(first["required_ok"], true);
    assert_eq!(check(&first, "self-test")["status"], "ok");
    let (_, second) = doctor_json(None, &[]);
    assert_eq!(strip(first), strip(second));
}

/// Pointing header discovery at an empty directory fails the header check and the self-test with a named cause.
#[test]
fn empty_valgrind_include_fails_the_self_test() {
    if !valgrind_available() {
        return;
    }
    let empty = tempfile::tempdir().unwrap();
    let (output, report) = doctor_json(None, &[("VALGRIND_INCLUDE", empty.path())]);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(check(&report, "valgrind-headers")["status"], "incompatible");
    let self_test = check(&report, "self-test");
    assert_eq!(self_test["status"], "incompatible");
    assert!(
        self_test["detail"]
            .as_str()
            .unwrap()
            .contains("VALGRIND_INCLUDE"),
        "{self_test}"
    );
}

/// With every header location hidden (possible only without system headers), the self-test names the inert shim.
#[test]
fn inert_shim_is_named() {
    if !valgrind_available() {
        return;
    }
    let system_headers = Path::new("/usr/include/valgrind/memcheck.h").is_file()
        || Command::new("pkg-config")
            .args(["--exists", "valgrind"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
    if system_headers {
        eprintln!("skipping: system headers cannot be hidden on this machine");
        return;
    }
    let found = which("valgrind").unwrap();
    let valgrind_dir = found.parent().unwrap().to_path_buf();
    if valgrind_dir == Path::new("/usr/bin") || valgrind_dir == Path::new("/bin") {
        eprintln!("skipping: valgrind shares a directory with the rest of the toolchain");
        return;
    }
    let real = std::fs::canonicalize(&found).unwrap();
    let wrapper = tempfile::tempdir().unwrap();
    let script = wrapper.path().join("valgrind");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nexec {} \"$@\"\n", real.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Every real PATH entry except valgrind's own, behind a wrapper whose
    // prefix holds no headers.
    let path = std::env::join_paths(
        std::iter::once(wrapper.path().to_path_buf()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .filter(|dir| *dir != valgrind_dir),
        ),
    )
    .unwrap();
    let (output, report) = doctor_json(Some(Path::new(&path)), &[]);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(check(&report, "valgrind-headers")["status"], "missing");
    let self_test = check(&report, "self-test");
    assert!(
        self_test["detail"].as_str().unwrap().contains("inert"),
        "{self_test}"
    );
}
