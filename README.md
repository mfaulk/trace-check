# Detecting Side-Channel Vulnerabilities with Execution Traces

Side-channel attacks are a subtle yet powerful class of vulnerabilities, where an attacker can infer secret information from indirect signals such as timing differences, power consumption, or electromagnetic radiation emitted during program execution. One of the most common forms is a timing side-channel, where variations in how long a computation takes—depending on secret inputs like cryptographic keys—can expose sensitive information to an attacker. This makes it critical that cryptographic software operates in "constant time," meaning its execution path, memory accesses, and runtime should not depend on secret inputs.

In this guide, we'll explore how to use instruction-level execution tracing on small Rust or WebAssembly programs to detect potential timing side-channels. By running the program with different inputs and comparing the resulting execution traces, we can verify whether the program truly behaves independently of secret values, ensuring robust protection against side-channel attacks.

## Documentation

* [`docs/MILESTONE-01.md`](docs/MILESTONE-01.md) — planned Milestone 01: a reproducible, automated
  trace comparison tool built around a MAC authentication-tag comparison example, using WABT's
  `wasm-interp` as the tracing backend.

## Project Setup

### Prerequisites

* Rust: [Install Rust](https://rustup.rs)
* WebAssembly target: `rustup target add wasm32-wasi`
* Valgrind: `sudo apt-get install valgrind`
* WABT (WebAssembly Binary Toolkit): [Installation Instructions](https://github.com/WebAssembly/wabt)

### Compiling the Rust Example

```sh
cargo build
```

### Compiling to WebAssembly

```sh
cargo build --target wasm32-wasi
```

### Creating Execution Traces

#### Rust Binary Trace

```sh
valgrind --tool=lackey --trace-mem=yes --trace-superblocks=yes \
    ./target/debug/ai-const-time input_value 2> trace.log
```

#### WebAssembly Trace

```sh
wasm-interp ./target/wasm32-wasi/debug/ai-const-time.wasm --run-all-exports --trace > wasm_trace.log
```

### Evaluating Execution Traces

```sh
diff trace_input1.log trace_input2.log
```

Differences indicate potential side-channel vulnerabilities where execution depends on secret input values.
