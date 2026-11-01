//! Tier 1: static taint analysis for secret-dependent control flow.
//!
//! A forward abstract interpretation over WASM's operand stack, locals and
//! globals. Each abstract value carries whether it is secret, whether it
//! derives from a declared secret-pointer parameter, and how many loads deep
//! its derivation is. Findings are raised where a secret value reaches a
//! branch condition, a memory address, or an indirect call target.
//!
//! # What this proves, and what it does not
//!
//! The analysis is **intraprocedural** and **does not track taint through
//! linear memory**: a store of a secret value does not taint subsequent loads.
//! Secrets must therefore be declared at the boundary of the function being
//! screened, which is why [`LoadPolicy`] exists — the caller states how
//! secrets reach the function.
//!
//! It **over-approximates** control flow. Loop-carried taint is propagated by
//! re-running the function to a fixpoint with locals seeded from the previous
//! pass, so a local that becomes secret inside a loop is treated as secret
//! throughout the function, including before the loop. That direction of error
//! is deliberate: a screen should report too much rather than too little.
//!
//! Consequently a finding is a *candidate* that must be confirmed — by reading
//! the artifact, or by differential tracing — and the absence of findings is
//! only as strong as the declared [`LoadPolicy`].

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::wasm::{Function, Instr};

/// Analysis version, recorded in reports so stored results stay interpretable.
pub const TAINT_ANALYSIS_VERSION: u32 = 1;

/// Guards against a non-converging fixpoint. Taint is monotone and bounded by
/// the number of slots, so exceeding this means the model is wrong, not slow.
const MAX_ITERATIONS: usize = 64;

/// How secrets reach the function being screened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadPolicy {
    /// Only the declared parameters are secret. A load is secret only when its
    /// address is secret. Use when secrets arrive as scalars.
    Params,
    /// Additionally, any load addressed through a declared secret parameter is
    /// secret. Use when a parameter is a pointer directly to secret bytes.
    PointerParams,
    /// Additionally, any load reached by dereferencing *through* a load from a
    /// declared secret parameter is secret, while the first level is treated as
    /// public metadata. Use for descriptor ABIs such as `&[u8]`, where the
    /// first level holds the data pointer and length.
    PointerParamsIndirect,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TaintConfig {
    /// Parameter indices carrying (or pointing to) the secret.
    pub secret_params: Vec<u32>,
    pub load_policy: LoadPolicy,
}

/// An abstract value. `join` is pointwise, which makes the lattice monotone and
/// the fixpoint terminating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Val {
    secret: bool,
    /// Derives from a declared secret-pointer parameter.
    ptr_origin: bool,
    /// Saturating count of loads in this value's derivation.
    load_depth: u8,
}

impl Val {
    const SECRET: Val = Val {
        secret: true,
        ptr_origin: false,
        load_depth: 0,
    };

    fn join(self, other: Val) -> Val {
        Val {
            secret: self.secret || other.secret,
            ptr_origin: self.ptr_origin || other.ptr_origin,
            load_depth: self.load_depth.max(other.load_depth),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// A branch condition derives from the secret: secret-dependent control
    /// flow, the property this tool screens for.
    SecretDependentBranch,
    /// A load or store address derives from the secret. The instruction path
    /// may be identical while the memory access pattern leaks.
    SecretDependentAddress,
    /// An indirect call target derives from the secret.
    SecretDependentCallTarget,
    /// A `select` with a secret condition. Branchless, so *not* a leak of this
    /// kind; reported so the reader can see it was considered.
    SecretSelect,
}

impl FindingKind {
    pub fn is_leak(self) -> bool {
        !matches!(self, FindingKind::SecretSelect)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::SecretDependentBranch => "secret_dependent_branch",
            FindingKind::SecretDependentAddress => "secret_dependent_address",
            FindingKind::SecretDependentCallTarget => "secret_dependent_call_target",
            FindingKind::SecretSelect => "secret_select",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    /// Index into the function's lowered instruction sequence.
    pub instruction_index: usize,
    pub instruction: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionVerdict {
    pub function: String,
    pub analyzed: bool,
    /// Why the function could not be analyzed, when `analyzed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inconclusive_reason: Option<String>,
    pub findings: Vec<Finding>,
    pub iterations: usize,
}

impl FunctionVerdict {
    pub fn leaks(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.kind.is_leak())
    }

    pub fn is_clean(&self) -> bool {
        self.analyzed && self.leaks().count() == 0
    }
}

#[derive(Debug)]
pub enum TaintError {
    StackUnderflow {
        instruction_index: usize,
        instruction: String,
    },
    UnbalancedControlFlow {
        instruction_index: usize,
    },
    NotConverged,
    UnsupportedInstruction(String),
    ParamOutOfRange {
        param: u32,
        param_count: u32,
    },
}

impl fmt::Display for TaintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaintError::StackUnderflow { instruction_index, instruction } => write!(
                f,
                "operand stack underflow at instruction {instruction_index} ({instruction}); the \
                 abstract model does not match this function"
            ),
            TaintError::UnbalancedControlFlow { instruction_index } => {
                write!(f, "unbalanced control flow at instruction {instruction_index}")
            }
            TaintError::NotConverged => {
                write!(f, "taint fixpoint did not converge within {MAX_ITERATIONS} iterations")
            }
            TaintError::UnsupportedInstruction(name) => write!(
                f,
                "function contains the unmodeled instruction {name:?}; refusing to report a verdict"
            ),
            TaintError::ParamOutOfRange { param, param_count } => write!(
                f,
                "secret parameter {param} is out of range for a function with {param_count} parameters"
            ),
        }
    }
}

impl std::error::Error for TaintError {}

/// Analyzes one function, returning a verdict even when analysis is refused so
/// the caller can report *why* rather than silently omitting the function.
pub fn analyze(function: &Function, config: &TaintConfig) -> FunctionVerdict {
    let name = function.display_name();
    match analyze_inner(function, config) {
        Ok((findings, iterations)) => FunctionVerdict {
            function: name,
            analyzed: true,
            inconclusive_reason: None,
            findings,
            iterations,
        },
        Err(error) => FunctionVerdict {
            function: name,
            analyzed: false,
            inconclusive_reason: Some(error.to_string()),
            findings: Vec::new(),
            iterations: 0,
        },
    }
}

fn analyze_inner(
    function: &Function,
    config: &TaintConfig,
) -> Result<(Vec<Finding>, usize), TaintError> {
    if let Some(name) = function.has_unsupported() {
        return Err(TaintError::UnsupportedInstruction(name.to_string()));
    }
    for param in &config.secret_params {
        if *param >= function.param_count {
            return Err(TaintError::ParamOutOfRange {
                param: *param,
                param_count: function.param_count,
            });
        }
    }

    // Entry state: declared secret parameters are secret; pointer policies also
    // mark them as pointer origins so loads through them can be recognized.
    let mut entry = vec![Val::default(); function.local_count as usize];
    let pointer_policy = config.load_policy != LoadPolicy::Params;
    for param in &config.secret_params {
        entry[*param as usize] = Val {
            secret: !pointer_policy,
            ptr_origin: pointer_policy,
            load_depth: 0,
        };
    }

    let mut seed = entry.clone();
    let mut globals: BTreeMap<u32, Val> = BTreeMap::new();

    for iteration in 1..=MAX_ITERATIONS {
        let pass = run_pass(function, config, &seed, &globals)?;

        let mut next_seed = seed.clone();
        for (slot, value) in pass.locals.iter().enumerate() {
            next_seed[slot] = next_seed[slot].join(*value);
        }
        let mut next_globals = globals.clone();
        for (index, value) in &pass.globals {
            let entry = next_globals.entry(*index).or_default();
            *entry = entry.join(*value);
        }

        if next_seed == seed && next_globals == globals {
            return Ok((pass.findings, iteration));
        }
        seed = next_seed;
        globals = next_globals;
    }

    Err(TaintError::NotConverged)
}

struct PassResult {
    findings: Vec<Finding>,
    locals: Vec<Val>,
    globals: BTreeMap<u32, Val>,
}

/// One control frame. `height` is the operand-stack depth on entry, which is
/// what lets `End` discard whatever the block left behind.
struct Frame {
    height: usize,
    results: u32,
    is_loop: bool,
    /// Join of values carried by branches targeting this frame's label.
    carried: Val,
}

fn run_pass(
    function: &Function,
    config: &TaintConfig,
    seed: &[Val],
    seed_globals: &BTreeMap<u32, Val>,
) -> Result<PassResult, TaintError> {
    let mut locals = seed.to_vec();
    let mut globals = seed_globals.clone();
    let mut stack: Vec<Val> = Vec::new();
    let mut findings = Vec::new();
    // The function body behaves as an outermost block returning the results.
    let mut frames = vec![Frame {
        height: 0,
        results: function.result_count,
        is_loop: false,
        carried: Val::default(),
    }];
    // Depth of control frames entered while the code is unreachable.
    let mut skipped: Option<usize> = None;

    for (index, instr) in function.body.iter().enumerate() {
        // While unreachable, only track nesting so the matching End is found.
        if let Some(depth) = skipped {
            match instr {
                Instr::Block { .. } | Instr::Loop { .. } | Instr::If { .. } => {
                    skipped = Some(depth + 1);
                }
                Instr::Else if depth == 0 => {
                    let frame = frames.last().ok_or(TaintError::UnbalancedControlFlow {
                        instruction_index: index,
                    })?;
                    stack.truncate(frame.height);
                    skipped = None;
                }
                Instr::End => {
                    if depth == 0 {
                        let frame = frames.pop().ok_or(TaintError::UnbalancedControlFlow {
                            instruction_index: index,
                        })?;
                        stack.truncate(frame.height);
                        for _ in 0..frame.results {
                            stack.push(frame.carried);
                        }
                        skipped = None;
                    } else {
                        skipped = Some(depth - 1);
                    }
                }
                _ => {}
            }
            continue;
        }

        let pop = |stack: &mut Vec<Val>| -> Result<Val, TaintError> {
            stack.pop().ok_or_else(|| TaintError::StackUnderflow {
                instruction_index: index,
                instruction: format!("{instr:?}"),
            })
        };
        let mut record = |kind: FindingKind| {
            findings.push(Finding {
                kind,
                instruction_index: index,
                instruction: format!("{instr:?}"),
            });
        };

        match instr {
            Instr::Unsupported(name) => {
                return Err(TaintError::UnsupportedInstruction(name.clone()))
            }
            Instr::Nop => {}
            Instr::Const => stack.push(Val::default()),
            Instr::Drop => {
                pop(&mut stack)?;
            }
            Instr::Unop => {
                let value = pop(&mut stack)?;
                stack.push(value);
            }
            Instr::Binop => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(a.join(b));
            }
            Instr::Select => {
                let condition = pop(&mut stack)?;
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                if condition.secret {
                    record(FindingKind::SecretSelect);
                }
                stack.push(a.join(b).join(Val {
                    secret: condition.secret,
                    ..Val::default()
                }));
            }

            Instr::LocalGet(slot) => stack.push(slot_value(&locals, *slot)),
            Instr::LocalSet(slot) => {
                let value = pop(&mut stack)?;
                set_slot(&mut locals, *slot, value);
            }
            Instr::LocalTee(slot) => {
                let value = pop(&mut stack)?;
                set_slot(&mut locals, *slot, value);
                stack.push(value);
            }
            Instr::GlobalGet(index) => stack.push(globals.get(index).copied().unwrap_or_default()),
            Instr::GlobalSet(index) => {
                let value = pop(&mut stack)?;
                globals.insert(*index, value);
            }

            Instr::Load => {
                let address = pop(&mut stack)?;
                if address.secret {
                    record(FindingKind::SecretDependentAddress);
                }
                stack.push(load_result(address, config.load_policy));
            }
            Instr::Store => {
                let _value = pop(&mut stack)?;
                let address = pop(&mut stack)?;
                if address.secret {
                    record(FindingKind::SecretDependentAddress);
                }
            }

            Instr::Call {
                params, results, ..
            } => {
                let mut joined = Val::default();
                for _ in 0..*params {
                    joined = joined.join(pop(&mut stack)?);
                }
                for _ in 0..*results {
                    stack.push(joined);
                }
            }
            Instr::CallIndirect { params, results } => {
                let target = pop(&mut stack)?;
                if target.secret {
                    record(FindingKind::SecretDependentCallTarget);
                }
                let mut joined = Val {
                    secret: target.secret,
                    ..Val::default()
                };
                for _ in 0..*params {
                    joined = joined.join(pop(&mut stack)?);
                }
                for _ in 0..*results {
                    stack.push(joined);
                }
            }

            Instr::Block { results } | Instr::Loop { results } => {
                frames.push(Frame {
                    height: stack.len(),
                    results: *results,
                    is_loop: matches!(instr, Instr::Loop { .. }),
                    carried: Val::default(),
                });
            }
            Instr::If { results } => {
                let condition = pop(&mut stack)?;
                if condition.secret {
                    record(FindingKind::SecretDependentBranch);
                }
                frames.push(Frame {
                    height: stack.len(),
                    results: *results,
                    is_loop: false,
                    carried: Val::default(),
                });
            }
            Instr::Else => {
                let frame = frames.last().ok_or(TaintError::UnbalancedControlFlow {
                    instruction_index: index,
                })?;
                stack.truncate(frame.height);
            }
            Instr::End => {
                let mut frame = frames.pop().ok_or(TaintError::UnbalancedControlFlow {
                    instruction_index: index,
                })?;
                // Fall-through results sit above the frame's entry height.
                let mut result = frame.carried;
                for value in stack.iter().skip(frame.height) {
                    result = result.join(*value);
                }
                frame.carried = result;
                stack.truncate(frame.height);
                for _ in 0..frame.results {
                    stack.push(result);
                }
            }

            Instr::Br { depth } => {
                carry_to_target(&mut frames, &mut stack, *depth, index)?;
                skipped = Some(0);
            }
            Instr::BrIf { depth } => {
                let condition = pop(&mut stack)?;
                if condition.secret {
                    record(FindingKind::SecretDependentBranch);
                }
                carry_to_target(&mut frames, &mut stack, *depth, index)?;
            }
            Instr::BrTable { depths } => {
                let selector = pop(&mut stack)?;
                if selector.secret {
                    record(FindingKind::SecretDependentBranch);
                }
                for depth in depths {
                    carry_to_target(&mut frames, &mut stack, *depth, index)?;
                }
                skipped = Some(0);
            }
            Instr::Return => {
                let outermost = frames
                    .first_mut()
                    .ok_or(TaintError::UnbalancedControlFlow {
                        instruction_index: index,
                    })?;
                for value in stack.iter().rev().take(outermost.results as usize) {
                    outermost.carried = outermost.carried.join(*value);
                }
                skipped = Some(0);
            }
            Instr::Unreachable => skipped = Some(0),
        }
    }

    Ok(PassResult {
        findings,
        locals,
        globals,
    })
}

/// Joins the values a branch carries into its target label. A branch to a loop
/// label re-enters the loop and carries the loop's parameters (none in the
/// modeled subset), so only block labels receive results.
fn carry_to_target(
    frames: &mut [Frame],
    stack: &mut [Val],
    depth: u32,
    instruction_index: usize,
) -> Result<(), TaintError> {
    let position = frames
        .len()
        .checked_sub(depth as usize + 1)
        .ok_or(TaintError::UnbalancedControlFlow { instruction_index })?;
    let frame = frames
        .get_mut(position)
        .ok_or(TaintError::UnbalancedControlFlow { instruction_index })?;
    if frame.is_loop {
        return Ok(());
    }
    let carried = frame.results as usize;
    let mut result = frame.carried;
    for value in stack.iter().rev().take(carried) {
        result = result.join(*value);
    }
    frame.carried = result;
    Ok(())
}

fn load_result(address: Val, policy: LoadPolicy) -> Val {
    let from_pointer = match policy {
        LoadPolicy::Params => false,
        LoadPolicy::PointerParams => address.ptr_origin,
        // The first dereference reads public metadata; deeper reads hit data.
        LoadPolicy::PointerParamsIndirect => address.ptr_origin && address.load_depth >= 1,
    };
    Val {
        secret: address.secret || from_pointer,
        ptr_origin: address.ptr_origin,
        load_depth: address.load_depth.saturating_add(1),
    }
}

fn slot_value(locals: &[Val], slot: u32) -> Val {
    locals.get(slot as usize).copied().unwrap_or(Val::SECRET)
}

/// Out-of-range slots cannot happen in a validated module; if one appears the
/// model is wrong, so the write is dropped rather than silently widening.
fn set_slot(locals: &mut [Val], slot: u32, value: Val) {
    if let Some(entry) = locals.get_mut(slot as usize) {
        *entry = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testwat::wat_or_skip;
    use crate::wasm;

    fn verdict(source: &str, config: &TaintConfig) -> FunctionVerdict {
        let bytes = crate::testwat::compile(source).expect("wat2wasm available");
        let module = wasm::parse(&bytes).unwrap();
        analyze(&module.functions[0], config)
    }

    fn params(secret: &[u32]) -> TaintConfig {
        TaintConfig {
            secret_params: secret.to_vec(),
            load_policy: LoadPolicy::Params,
        }
    }

    /// A branch on a secret parameter is reported as secret-dependent control flow.
    #[test]
    fn branch_on_secret_param_is_flagged() {
        let source = r#"(module (func $f (param i32) (result i32)
            block
              local.get 0
              br_if 0
              i32.const 1
              return
            end
            i32.const 0))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        assert!(v.analyzed, "{:?}", v.inconclusive_reason);
        assert_eq!(v.leaks().count(), 1);
        assert_eq!(v.findings[0].kind, FindingKind::SecretDependentBranch);
    }

    /// A branch on a public parameter is not flagged, even in the same shape.
    #[test]
    fn branch_on_public_param_is_not_flagged() {
        let source = r#"(module (func $f (param i32 i32) (result i32)
            block
              local.get 1
              br_if 0
              i32.const 1
              return
            end
            i32.const 0))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        assert!(v.analyzed);
        assert_eq!(v.leaks().count(), 0);
    }

    /// Taint flows through arithmetic into a branch condition.
    #[test]
    fn taint_flows_through_arithmetic() {
        let source = r#"(module (func $f (param i32 i32)
            block
              local.get 0
              local.get 1
              i32.xor
              i32.eqz
              br_if 0
            end))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        assert_eq!(v.leaks().count(), 1);
    }

    /// Taint flows through a local round-trip.
    #[test]
    fn taint_flows_through_locals() {
        let source = r#"(module (func $f (param i32) (local i32)
            local.get 0
            local.set 1
            block
              local.get 1
              br_if 0
            end))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        assert_eq!(verdict(source, &params(&[0])).leaks().count(), 1);
    }

    /// A secret load address is reported as a secret-dependent memory access
    /// even though the instruction path does not change.
    #[test]
    fn secret_load_address_is_flagged() {
        let source = r#"(module (memory 1) (func $f (param i32) (result i32)
            local.get 0
            i32.load8_u))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        assert_eq!(v.findings.len(), 1);
        assert_eq!(v.findings[0].kind, FindingKind::SecretDependentAddress);
    }

    /// A secret store address is flagged too.
    #[test]
    fn secret_store_address_is_flagged() {
        let source = r#"(module (memory 1) (func $f (param i32)
            local.get 0
            i32.const 7
            i32.store))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        assert_eq!(v.findings[0].kind, FindingKind::SecretDependentAddress);
    }

    /// `select` on a secret is branchless, so it is reported but not as a leak.
    #[test]
    fn secret_select_is_reported_but_not_a_leak() {
        let source = r#"(module (func $f (param i32) (result i32)
            i32.const 1
            i32.const 2
            local.get 0
            select))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        assert_eq!(v.findings.len(), 1);
        assert_eq!(v.findings[0].kind, FindingKind::SecretSelect);
        assert_eq!(v.leaks().count(), 0);
        assert!(v.is_clean());
    }

    /// Declaring a pointer parameter secret under the Params policy makes the
    /// pointer *value* secret, so the load address is flagged. This documents
    /// why a pointer parameter needs one of the pointer policies instead.
    #[test]
    fn params_policy_treats_a_secret_pointer_value_as_a_secret_address() {
        let source = r#"(module (memory 1) (func $f (param i32)
            block
              local.get 0
              i32.load8_u
              br_if 0
            end))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        let kinds: Vec<FindingKind> = v.findings.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FindingKind::SecretDependentAddress,
                FindingKind::SecretDependentBranch
            ]
        );
    }

    /// Under PointerParams the pointer itself is public, so no address finding
    /// is raised, but the loaded byte is secret and the branch is flagged.
    #[test]
    fn pointer_params_policy_taints_pointee_loads() {
        let source = r#"(module (memory 1) (func $f (param i32)
            block
              local.get 0
              i32.load8_u
              br_if 0
            end))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let config = TaintConfig {
            secret_params: vec![0],
            load_policy: LoadPolicy::PointerParams,
        };
        let v = verdict(source, &config);
        assert_eq!(v.findings.len(), 1, "the address must not be flagged");
        assert_eq!(v.findings[0].kind, FindingKind::SecretDependentBranch);
    }

    /// PointerParamsIndirect treats the first dereference as public metadata,
    /// which is what keeps a length check from reading as a leak.
    #[test]
    fn indirect_policy_treats_first_dereference_as_metadata() {
        let metadata = r#"(module (memory 1) (func $f (param i32)
            block
              local.get 0
              i32.load offset=4
              br_if 0
            end))"#;
        if crate::testwat::compile(metadata).is_none() {
            return;
        }
        let config = TaintConfig {
            secret_params: vec![0],
            load_policy: LoadPolicy::PointerParamsIndirect,
        };
        assert_eq!(verdict(metadata, &config).leaks().count(), 0);

        // A second dereference reaches the pointed-to data and is secret.
        let data = r#"(module (memory 1) (func $f (param i32)
            block
              local.get 0
              i32.load
              i32.load8_u
              br_if 0
            end))"#;
        assert_eq!(verdict(data, &config).leaks().count(), 1);
    }

    /// Loop-carried taint reaches a branch, which requires more than one pass.
    #[test]
    fn loop_carried_taint_is_found() {
        let source = r#"(module (func $f (param i32) (local i32)
            loop
              local.get 1
              br_if 0
              local.get 0
              local.set 1
            end))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        assert!(v.analyzed, "{:?}", v.inconclusive_reason);
        assert_eq!(v.leaks().count(), 1, "taint must flow around the back edge");
        assert!(v.iterations > 1, "a second pass is required to see it");
    }

    /// A function containing an unmodeled instruction gets no verdict.
    #[test]
    fn unmodeled_instruction_refuses_a_verdict() {
        let source = r#"(module (memory 1) (func $f
            i32.const 0 i32.const 0 i32.const 0 memory.fill))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[]));
        assert!(!v.analyzed);
        assert!(v
            .inconclusive_reason
            .as_deref()
            .unwrap()
            .contains("unmodeled"));
        assert!(
            !v.is_clean(),
            "an unanalyzed function must not count as clean"
        );
    }

    /// A secret parameter index outside the signature is an error, not ignored.
    #[test]
    fn out_of_range_secret_param_is_refused() {
        let source = r#"(module (func $f (param i32)))"#;
        let _ = wat_or_skip!(source);
        let v = verdict(source, &params(&[5]));
        assert!(!v.analyzed);
        assert!(v
            .inconclusive_reason
            .as_deref()
            .unwrap()
            .contains("out of range"));
    }

    /// Taint reaching an indirect call target is flagged.
    #[test]
    fn secret_call_target_is_flagged() {
        let source = r#"(module
            (type $t (func))
            (table 1 funcref)
            (func $f (param i32)
              local.get 0
              call_indirect (type $t)))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let v = verdict(source, &params(&[0]));
        assert_eq!(v.findings[0].kind, FindingKind::SecretDependentCallTarget);
    }

    /// A call propagates argument taint to its results.
    #[test]
    fn call_propagates_argument_taint() {
        let source = r#"(module
            (func $g (param i32) (result i32) local.get 0)
            (func $f (param i32)
              block
                local.get 0
                call $g
                br_if 0
              end))"#;
        if crate::testwat::compile(source).is_none() {
            return;
        }
        let bytes = crate::testwat::compile(source).unwrap();
        let module = wasm::parse(&bytes).unwrap();
        let f = module.function("f").expect("function f");
        let v = analyze(f, &params(&[0]));
        assert!(v.analyzed, "{:?}", v.inconclusive_reason);
        assert_eq!(v.leaks().count(), 1);
    }
}
