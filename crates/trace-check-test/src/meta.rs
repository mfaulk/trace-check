//! The discovery protocol between generated tests and the runner.
//!
//! Generated tests print one line per record in `list` mode:
//!
//! ```text
//! trace-check-meta: {"kind":"test","name":"…","target":"…","secrets":[…]}
//! ```
//!
//! A line-oriented protocol over stdout rather than a registry crate: it needs
//! no extra dependency, works on stable, and relies only on the standard test
//! harness's `--nocapture`. The runner reads these lines, so a crate with
//! contracts but no tests is still discoverable — which is exactly the
//! "untested contract" case that has to be detectable.
//!
//! JSON is emitted by hand to keep `serde` out of consumers' dev-dependency
//! graphs. Only strings are escaped, and the fields are all identifiers or
//! paths, so the surface is small.

/// Prefix the runner greps for.
///
/// The runner searches for this *anywhere* in a line, because `--nocapture`
/// interleaves a test's own output with the harness's `test NAME ... ok`
/// progress line.
pub const META_PREFIX: &str = "trace-check-meta:";

/// Builds the name the libtest harness uses, which is what `--exact` matches.
///
/// `module_path!()` is crate-qualified (`consumer_crate::tests`) but the
/// harness drops the crate root (`tests::my_test`). Stripping the first
/// segment produces the harness form for a lib test, and for an integration
/// test — where the crate root *is* the test file — it correctly leaves just
/// the inner path.
pub fn harness_path(module_path: &str, test: &str) -> String {
    match module_path.split_once("::") {
        Some((_crate_root, rest)) if !rest.is_empty() => format!("{rest}::{test}"),
        _ => test.to_string(),
    }
}

/// Builds a module-qualified identity, e.g. `my_crate::auth::verify`.
///
/// Contract identity has to be qualified. Two modules can each define a
/// `verify`, and keying anything on the bare name silently loses one of them —
/// along with any claim that it was tested.
pub fn qualified(module_path: &str, name: &str) -> String {
    format!("{module_path}::{name}")
}

/// Emits a constant-time test record.
///
/// `harness_name` is what `--exact` takes; `id` is the qualified identity used
/// in reports. `target` is the qualified contract this test covers, if any.
pub fn emit_test(harness_name: &str, id: &str, target: Option<&str>) {
    let target = match target {
        Some(target) => format!("\"{}\"", escape(target)),
        None => "null".to_string(),
    };
    println!(
        "{META_PREFIX} {{\"kind\":\"test\",\"name\":\"{}\",\"id\":\"{}\",\"target\":{}}}",
        escape(harness_name),
        escape(id),
        target,
    );
}

/// Emits a declared contract record.
///
/// Emitted by `#[constant_time]` independently of any test, so a contract with
/// no coverage is still discovered and can be reported as `untested`.
///
/// `id` is module-qualified; `function` is the bare name, for display.
pub fn emit_contract(id: &str, function: &str, secrets: &[&str], file: &str, line: u32) {
    println!(
        "{META_PREFIX} {{\"kind\":\"contract\",\"id\":\"{}\",\"function\":\"{}\",\
         \"secrets\":[{}],\"file\":\"{}\",\"line\":{line}}}",
        escape(id),
        escape(function),
        join_strings(secrets),
        escape(file),
    );
}

fn join_strings(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("\"{}\"", escape(value)))
        .collect::<Vec<_>>()
        .join(",")
}

/// Escapes the characters JSON requires in a string. Control characters are
/// emitted as `\u00XX` so the output is always valid even for odd input.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strings that would break the JSON are escaped.
    #[test]
    fn escaping_covers_json_specials() {
        assert_eq!(escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape(r"a\b"), r"a\\b");
        assert_eq!(escape("a\nb"), "a\\nb");
        assert_eq!(escape("a\u{1}b"), "a\\u0001b");
        assert_eq!(escape("ordinary::path"), "ordinary::path");
    }

    /// A secret list renders as a JSON array of quoted strings.
    #[test]
    fn secret_lists_render_as_json_arrays() {
        assert_eq!(join_strings(&[]), "");
        assert_eq!(join_strings(&["a"]), "\"a\"");
        assert_eq!(join_strings(&["a", "b"]), "\"a\",\"b\"");
    }

    /// The prefix is what the runner matches; changing it breaks discovery, so
    /// it is pinned by a test.
    #[test]
    fn prefix_is_stable() {
        assert_eq!(META_PREFIX, "trace-check-meta:");
    }

    /// A lib test's harness name drops the crate root, which is what `--exact`
    /// expects. Emitting the crate-qualified path would select zero tests.
    #[test]
    fn harness_path_drops_the_crate_root() {
        assert_eq!(
            harness_path("consumer_crate::tests", "verify_tag_is_constant_time"),
            "tests::verify_tag_is_constant_time"
        );
        assert_eq!(
            harness_path("consumer_crate::tests::inner", "t"),
            "tests::inner::t"
        );
    }

    /// At an integration test's root there is no inner module, so the harness
    /// name is the bare test name.
    #[test]
    fn harness_path_at_the_crate_root_is_the_bare_name() {
        assert_eq!(harness_path("my_integration_test", "t"), "t");
    }

    /// Identities are module-qualified, so two modules each defining `verify`
    /// produce distinct contracts instead of silently overwriting each other.
    #[test]
    fn qualified_identities_distinguish_same_named_functions() {
        let first = qualified("my_crate::authentication", "verify");
        let second = qualified("my_crate::encryption", "verify");
        assert_ne!(first, second);
        assert_eq!(first, "my_crate::authentication::verify");
    }
}
