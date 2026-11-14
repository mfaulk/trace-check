# Publishing trace-check

The initial release is **0.1.0**. The workspace is prepared for crates.io, but
preparing or validating a release does not publish it. There is no automated
upload workflow.

## Validate a release

Use the pinned Rust 1.97.0 toolchain and Python 3.11 or newer. Rust 1.97 is the
minimum tested and declared supported compiler for the CLI and runtime crates.
The annotation-only `trace-check-macros` crate supports Rust 1.88 so symbolic
analysis can honor a library's older toolchain pin.
Native smoke tests require Linux x86-64, a C compiler, Valgrind 3.28.0 or newer,
and its client-request headers. Install the headers before compiling the support
crates; set `VALGRIND_INCLUDE` if they are outside the discovered include paths.

From a clean checkout:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --lib --bins
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo test --workspace --doc
TRACE_CHECK_REQUIRE_BACKEND=1 cargo test -p cargo-trace-check --test publishing
python3 ci/verify-release.py
```

During development, `python3 ci/verify-release.py --allow-dirty` also accepts
uncommitted changes. Release candidates should pass without that option.

The script:

1. Runs `cargo publish --dry-run --workspace`, which validates all five
   publishable crates in dependency order without uploading. Cargo stages
   unpublished workspace dependencies in a temporary registry.
2. Emits `.crate` archives with `cargo package` and checks the normalized
   manifests, exact internal dependency versions, READMEs, license texts,
   size limit, and the secret-marking C shim.
3. Extracts those archives into a temporary directory, installs the CLI from
   the extracted package, and checks a separate consumer. Temporary Cargo
   patches resolve unpublished dependencies from the extracted archives;
   no source-checkout dependencies or authentication credentials are used.
4. Requires a clean tag comparison, detection of a deliberate secret-indexed
   lookup, correct CI exit codes, a passing targeted security test, and ignored
   security checks under ordinary `cargo test`.

The installed engine's source directory has a versioned package name rather
than the development workspace layout, so the smoke test also exercises the
generated harness's registry-version fallback. Patches are confined to a
temporary Cargo configuration. The user's registry cache may be reused, but
their configuration and installed binaries are not changed.

Archives are written to `target/release-validation/package` (or the equivalent
under `CARGO_TARGET_DIR`). Release builds and smoke tests use separate target
directories so they cannot overwrite a binary used by concurrent checkout tests. The existing Linux CI job runs the same script.
This script has no option to perform an upload.

## Release contents

All five crates share version `0.1.0`, license `MIT OR Apache-2.0`, repository
metadata. The CLI, engine, and runtime crates require Rust 1.97; the macro crate
requires Rust 1.88 and is tested on that compiler. Each archive carries its own README and both
license texts. Update copied license texts together if their contents change;
the validator checks that they match the root copies.

Internal dependencies use both a workspace path and an exact registry version.
Update those versions together with `[workspace.package].version`, including
the engine's dev-dependency and versioned README/install examples. Generated harnesses request the engine's exact
version of `trace-check-test`. All examples remain `publish = false`.

Publishable packages, in dependency order:

1. `trace-check-macros` and `trace-check-secret` (independent).
2. `trace-check-test`.
3. `trace-check`.
4. `cargo-trace-check`.

Registry-installed `test`, `check`, and `verify --contract` need no trace-check
checkout. Bundled demonstration commands still require one; pass
`--workspace-root /path/to/trace-check` to an installed binary. See the
[technical reference](technical-reference.md#installed-cli-and-support-crates).

## Upload only when a release is authorized

The following steps perform the actual release and are separate from validation:

1. Confirm the crate names are still available or owned by the intended
   crates.io account. Name availability is not a reservation.
2. Create or sign in to the crates.io account, verify its email address, and
   configure a publishing token with `cargo login`. Keep tokens out of the
   repository and command output.
3. Review changes and CI, update the [changelog](../CHANGELOG.md), and commit
   the release candidate. Re-run validation from that clean commit.
4. Run `cargo publish --workspace`. On the pinned Cargo version this publishes
   the enabled workspace packages in dependency order; examples are excluded
   by their `publish = false` setting. If interrupted, inspect crates.io before
   retrying or publish only the remaining packages individually with
   `cargo publish -p PACKAGE`.
5. Tag the published commit as `v0.1.0` and push the tag. Confirm crate pages,
   documentation builds, ownership, and a fresh registry installation:

   ```sh
   cargo install cargo-trace-check --version 0.1.0 --locked
   ```

After the first upload, replace the README's unpublished/local-path setup note
with registry dependency instructions. A published version cannot be overwritten;
any subsequent changes need a new version.

See Cargo's [publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html)
and [`cargo publish` reference](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).
