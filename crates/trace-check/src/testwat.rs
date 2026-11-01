//! Test-only helper for compiling inline `.wat` source with WABT.
//!
//! Returns `None` when `wat2wasm` is absent so the unit suite stays usable on a
//! bare machine, but panics if `TRACE_CHECK_REQUIRE_BACKEND` is set — the same
//! contract the integration tests use, so a skip can never pass for a success.

use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn compile(source: &str) -> Option<Vec<u8>> {
    if !available() {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
            "TRACE_CHECK_REQUIRE_BACKEND is set but wat2wasm is not on PATH"
        );
        eprintln!("skipping: wat2wasm is not on PATH");
        return None;
    }

    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("trace-check-wat-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let wat_path = dir.join("m.wat");
    let wasm_path = dir.join("m.wasm");
    std::fs::write(&wat_path, source).unwrap();

    let output = std::process::Command::new("wat2wasm")
        .arg(&wat_path)
        .arg("--debug-names")
        .arg("-o")
        .arg(&wasm_path)
        .output()
        .expect("wat2wasm is available");
    assert!(
        output.status.success(),
        "wat2wasm rejected the test module: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read(&wasm_path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    Some(bytes)
}

fn available() -> bool {
    std::process::Command::new("wat2wasm")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Compiles `source` or returns from the calling test with a skip notice.
macro_rules! wat_or_skip {
    ($source:expr $(,)?) => {
        match crate::testwat::compile($source) {
            Some(bytes) => bytes,
            None => return,
        }
    };
}

pub(crate) use wat_or_skip;
