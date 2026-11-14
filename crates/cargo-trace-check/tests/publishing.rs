use std::path::Path;
use std::process::Command;

fn consumer() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("consumer directory");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository");
    let dependency = root.join("crates/trace-check-test");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"release-consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\ntrace-check-test = {{ path = {:?} }}\nsubtle = \"2.6\"\n",
            dependency.display().to_string()
        ),
    )
    .expect("manifest");
    std::fs::copy(
        root.join("rust-toolchain.toml"),
        dir.path().join("rust-toolchain.toml"),
    )
    .expect("toolchain");
    std::fs::create_dir(dir.path().join("src")).expect("source directory");
    std::fs::write(
        dir.path().join("src/lib.rs"),
        include_str!("fixtures/publish-consumer.rs"),
    )
    .expect("source");
    dir
}

fn run(dir: &Path, args: &[&str], expected: i32) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-trace-check"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run CLI");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout.into_owned()
}

fn backend_available() -> bool {
    let present = Command::new("valgrind")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    assert!(
        present || std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
        "Valgrind is required"
    );
    present
}

// Generated checks declassify array-derived results and detect scalar-dependent addresses.
#[test]
fn generated_checks_support_an_external_consumer() {
    if !backend_available() {
        return;
    }
    let dir = consumer();
    let clean = run(
        dir.path(),
        &["check", "--contract", "release_consumer::verify_tag"],
        0,
    );
    assert!(clean.contains("NO_LEAK_OBSERVED"), "{clean}");
    let leak = run(
        dir.path(),
        &["check", "--contract", "release_consumer::lookup"],
        1,
    );
    assert!(leak.contains("LEAK_DETECTED"), "{leak}");
}

// A targeted security test can assert on the comparison result without spurious findings.
#[test]
fn targeted_checks_declassify_results_before_assertions() {
    if !backend_available() {
        return;
    }
    let dir = consumer();
    let source = dir.path().join("src/lib.rs");
    let text = std::fs::read_to_string(&source).expect("source");
    std::fs::write(
        &source,
        text.replace("#[trace_check_test::constant_time(secret = \"index\")]", ""),
    )
    .expect("only the tested contract remains");
    let output = run(dir.path(), &["test"], 0);
    assert!(output.contains("NO_LEAK_OBSERVED"), "{output}");
}
