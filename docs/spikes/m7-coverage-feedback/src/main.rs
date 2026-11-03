//! M7.1 feasibility spike: a discovery harness shaped like the real one.
//!
//! Usage:
//!   tc-spike-coverage once <stage> <gate> <trigger> <index>
//!   tc-spike-coverage persistent <profraw-dir> <cases-file>
//!
//!   tc-spike-coverage magic      <profraw-dir> <cases-file>
//!   tc-spike-coverage mode       <profraw-dir> <cases-file>
//!
//! `cases-file` holds one whitespace-separated case per line. See README.md for
//! what each mode measures.

use std::ffi::CString;

// The LLVM profiling runtime, linked in by `-C instrument-coverage`. Declaring
// these makes the instrumented build a *link-time* requirement rather than a
// runtime hope: an uninstrumented discovery artifact cannot be produced by
// accident. See README.md.
extern "C" {
    fn __llvm_profile_reset_counters();
    fn __llvm_profile_set_filename(name: *const std::os::raw::c_char);
    fn __llvm_profile_write_file() -> std::os::raw::c_int;
}

fn run_case(stage: u8, gate: u8, trigger: u8, index: u8) -> u8 {
    crypto::hidden::nested_modes(index, stage, gate, trigger)
}

/// `magic_gate`, whose public token is a full 32 bits, for experiment C3.
fn run_magic(token: u32, index: u8) -> u8 {
    crypto::hidden::magic_gate(index, token)
}

/// `substitute_mode`, the M6 public-branch case, for experiment C1.
fn run_mode(mode: u8, index: u8) -> u8 {
    crypto::lookup::substitute_mode(index, mode)
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    match argv.get(1).map(String::as_str) {
        Some("once") => {
            let n = |i: usize| argv[i].parse::<u8>().expect("a u8");
            let produced = run_case(n(2), n(3), n(4), n(5));
            println!("case produced={produced}");
        }
        Some("persistent") => {
            let dir = &argv[2];
            let text = std::fs::read_to_string(&argv[3]).expect("the cases file");
            for (id, line) in text.lines().enumerate() {
                let fields: Vec<u8> = line
                    .split_whitespace()
                    .map(|f| f.parse::<u8>().expect("a u8"))
                    .collect();
                // SAFETY: the profiling runtime is linked in by
                // `-C instrument-coverage`; both calls are its documented
                // entry points and neither takes ownership of anything.
                unsafe { __llvm_profile_reset_counters() };
                let produced = run_case(fields[0], fields[1], fields[2], fields[3]);
                let path = CString::new(format!("{dir}/case-{id}.profraw")).expect("no NUL");
                let written = unsafe {
                    __llvm_profile_set_filename(path.as_ptr());
                    __llvm_profile_write_file()
                };
                println!("case {id} produced={produced} written={written}");
            }
            // The profiling runtime writes the profile once more at exit, to
            // whatever filename is current — which would append a second,
            // stale record to the last case's file. Point it at a scratch path
            // so the last case is no different from the others.
            let drain = CString::new(format!("{dir}/at-exit.profraw")).expect("no NUL");
            unsafe { __llvm_profile_set_filename(drain.as_ptr()) };
        }
        Some("magic") => {
            let dir = &argv[2];
            let text = std::fs::read_to_string(&argv[3]).expect("the cases file");
            for (id, line) in text.lines().enumerate() {
                let f: Vec<u64> = line
                    .split_whitespace()
                    .map(|f| f.parse::<u64>().expect("an integer"))
                    .collect();
                unsafe { __llvm_profile_reset_counters() };
                let produced = run_magic(f[0] as u32, f[1] as u8);
                let path = CString::new(format!("{dir}/case-{id}.profraw")).expect("no NUL");
                unsafe {
                    __llvm_profile_set_filename(path.as_ptr());
                    __llvm_profile_write_file()
                };
                println!("case {id} produced={produced}");
            }
            let drain = CString::new(format!("{dir}/at-exit.profraw")).expect("no NUL");
            unsafe { __llvm_profile_set_filename(drain.as_ptr()) };
        }
        Some("mode") => {
            let dir = &argv[2];
            let text = std::fs::read_to_string(&argv[3]).expect("the cases file");
            for (id, line) in text.lines().enumerate() {
                let f: Vec<u8> = line
                    .split_whitespace()
                    .map(|f| f.parse::<u8>().expect("a u8"))
                    .collect();
                unsafe { __llvm_profile_reset_counters() };
                let produced = run_mode(f[0], f[1]);
                let path = CString::new(format!("{dir}/case-{id}.profraw")).expect("no NUL");
                unsafe {
                    __llvm_profile_set_filename(path.as_ptr());
                    __llvm_profile_write_file()
                };
                println!("case {id} produced={produced}");
            }
            let drain = CString::new(format!("{dir}/at-exit.profraw")).expect("no NUL");
            unsafe { __llvm_profile_set_filename(drain.as_ptr()) };
        }
        _ => {
            eprintln!("usage: once|persistent|magic|mode ...");
            std::process::exit(2);
        }
    }
}
