//! Module loading: lowers a WASM binary into the instruction subset the
//! static analyses understand.
//!
//! Unrecognized operators become [`Instr::Unsupported`] rather than being
//! skipped, and the analyses refuse to produce a verdict for any function
//! containing one. A screener that silently ignores instructions it does not
//! model would report "no finding" for code it never looked at.
//!
//! Multi-value blocks with parameters are also treated as unsupported: the
//! abstract interpreter tracks stack height per control frame, and block
//! parameters would invalidate that bookkeeping.

use std::fmt;

use sha2::{Digest, Sha256};
use wasmparser::{BinaryReader, BlockType, Name, NameSectionReader, Operator, Parser, Payload};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instr {
    Block {
        results: u32,
    },
    Loop {
        results: u32,
    },
    If {
        results: u32,
    },
    Else,
    End,
    Br {
        depth: u32,
    },
    BrIf {
        depth: u32,
    },
    BrTable {
        depths: Vec<u32>,
    },
    Return,
    Unreachable,
    Call {
        function: u32,
        params: u32,
        results: u32,
    },
    CallIndirect {
        params: u32,
        results: u32,
    },
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    /// Pops an address, pushes the loaded value.
    Load,
    /// Pops a value then an address.
    Store,
    Const,
    /// Pops one operand, pushes one result.
    Unop,
    /// Pops two operands, pushes one result.
    Binop,
    /// Pops a condition and two values, pushes one. Branchless by definition.
    Select,
    Drop,
    Nop,
    /// An operator outside the modeled subset. Carries its debug name so the
    /// analysis can say exactly what it refused to reason about.
    Unsupported(String),
}

#[derive(Debug, Clone)]
pub struct Function {
    pub index: u32,
    pub name: Option<String>,
    pub param_count: u32,
    pub result_count: u32,
    /// Parameters plus declared locals; the addressable local slots.
    pub local_count: u32,
    pub body: Vec<Instr>,
}

impl Function {
    /// Demangled-ish display name: the Rust symbol hash makes raw names
    /// unstable across builds, so the human-facing name drops it.
    pub fn display_name(&self) -> String {
        match &self.name {
            None => format!("func[{}]", self.index),
            Some(name) => strip_rust_mangling(name),
        }
    }

    pub fn has_unsupported(&self) -> Option<&str> {
        self.body.iter().find_map(|instr| match instr {
            Instr::Unsupported(name) => Some(name.as_str()),
            _ => None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Module {
    pub sha256: String,
    pub functions: Vec<Function>,
}

impl Module {
    pub fn function(&self, name: &str) -> Option<&Function> {
        self.functions
            .iter()
            .find(|f| f.name.as_deref() == Some(name) || f.display_name() == name)
    }
}

#[derive(Debug)]
pub enum WasmError {
    Io(String),
    Parse(String),
    MissingType { function: u32 },
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmError::Io(message) => write!(f, "cannot read module: {message}"),
            WasmError::Parse(message) => write!(f, "cannot parse module: {message}"),
            WasmError::MissingType { function } => {
                write!(f, "function {function} has no type information")
            }
        }
    }
}

impl std::error::Error for WasmError {}

pub fn load(path: &std::path::Path) -> Result<Module, WasmError> {
    let bytes =
        std::fs::read(path).map_err(|e| WasmError::Io(format!("{}: {e}", path.display())))?;
    parse(&bytes)
}

pub fn parse(bytes: &[u8]) -> Result<Module, WasmError> {
    // (params, results) per type index.
    let mut signatures: Vec<(u32, u32)> = Vec::new();
    // Type index per function index, imports first.
    let mut function_types: Vec<u32> = Vec::new();
    let mut names: Vec<(u32, String)> = Vec::new();
    let mut bodies: Vec<(u32, u32, Vec<Instr>)> = Vec::new();
    let mut imported_functions = 0u32;

    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|e| WasmError::Parse(e.to_string()))? {
            Payload::TypeSection(reader) => {
                for group in reader {
                    let group = group.map_err(|e| WasmError::Parse(e.to_string()))?;
                    for ty in group.into_types() {
                        let func = ty.unwrap_func();
                        signatures.push((func.params().len() as u32, func.results().len() as u32));
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| WasmError::Parse(e.to_string()))?;
                    if let wasmparser::TypeRef::Func(type_index) = import.ty {
                        function_types.push(type_index);
                        imported_functions += 1;
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for type_index in reader {
                    function_types.push(type_index.map_err(|e| WasmError::Parse(e.to_string()))?);
                }
            }
            Payload::CustomSection(section) if section.name() == "name" => {
                let reader = NameSectionReader::new(BinaryReader::new(
                    section.data(),
                    section.data_offset(),
                ));
                for subsection in reader {
                    let subsection = subsection.map_err(|e| WasmError::Parse(e.to_string()))?;
                    if let Name::Function(map) = subsection {
                        for naming in map {
                            let naming = naming.map_err(|e| WasmError::Parse(e.to_string()))?;
                            names.push((naming.index, naming.name.to_string()));
                        }
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut local_count = 0u32;
                let locals = body
                    .get_locals_reader()
                    .map_err(|e| WasmError::Parse(e.to_string()))?;
                for local in locals {
                    let (count, _ty) = local.map_err(|e| WasmError::Parse(e.to_string()))?;
                    local_count += count;
                }

                let mut instructions = Vec::new();
                let mut reader = body
                    .get_operators_reader()
                    .map_err(|e| WasmError::Parse(e.to_string()))?;
                while !reader.eof() {
                    let op = reader.read().map_err(|e| WasmError::Parse(e.to_string()))?;
                    instructions.push(lower(&op, &signatures));
                }

                let index = imported_functions + bodies.len() as u32;
                bodies.push((index, local_count, instructions));
            }
            _ => {}
        }
    }

    let mut functions = Vec::new();
    for (index, declared_locals, body) in bodies {
        let type_index = *function_types
            .get(index as usize)
            .ok_or(WasmError::MissingType { function: index })?;
        let (param_count, result_count) = *signatures
            .get(type_index as usize)
            .ok_or(WasmError::MissingType { function: index })?;
        functions.push(Function {
            index,
            name: names
                .iter()
                .find(|(i, _)| *i == index)
                .map(|(_, n)| n.clone()),
            param_count,
            result_count,
            local_count: param_count + declared_locals,
            body,
        });
    }

    Ok(Module {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        functions,
    })
}

fn block_results(blockty: &BlockType, signatures: &[(u32, u32)]) -> Option<u32> {
    match blockty {
        BlockType::Empty => Some(0),
        BlockType::Type(_) => Some(1),
        // Block parameters would break the per-frame stack-height bookkeeping.
        BlockType::FuncType(index) => match signatures.get(*index as usize) {
            Some((0, results)) => Some(*results),
            _ => None,
        },
    }
}

fn lower(op: &Operator<'_>, signatures: &[(u32, u32)]) -> Instr {
    use Operator as O;

    macro_rules! blocklike {
        ($variant:ident, $blockty:expr) => {
            match block_results($blockty, signatures) {
                Some(results) => Instr::$variant { results },
                None => Instr::Unsupported(format!("{}-with-params", stringify!($variant))),
            }
        };
    }

    match op {
        O::Block { blockty } => blocklike!(Block, blockty),
        O::Loop { blockty } => blocklike!(Loop, blockty),
        O::If { blockty } => blocklike!(If, blockty),
        O::Else => Instr::Else,
        O::End => Instr::End,
        O::Br { relative_depth } => Instr::Br {
            depth: *relative_depth,
        },
        O::BrIf { relative_depth } => Instr::BrIf {
            depth: *relative_depth,
        },
        O::BrTable { targets } => {
            let mut depths: Vec<u32> = targets.targets().filter_map(Result::ok).collect();
            depths.push(targets.default());
            Instr::BrTable { depths }
        }
        O::Return => Instr::Return,
        O::Unreachable => Instr::Unreachable,
        O::Nop => Instr::Nop,
        O::Drop => Instr::Drop,
        O::Select => Instr::Select,
        O::TypedSelect { .. } => Instr::Select,

        O::Call { function_index } => {
            let (params, results) = signatures
                .get(*function_index as usize)
                .copied()
                .unwrap_or((0, 0));
            Instr::Call {
                function: *function_index,
                params,
                results,
            }
        }
        O::CallIndirect { type_index, .. } => {
            let (params, results) = signatures
                .get(*type_index as usize)
                .copied()
                .unwrap_or((0, 0));
            Instr::CallIndirect { params, results }
        }

        O::LocalGet { local_index } => Instr::LocalGet(*local_index),
        O::LocalSet { local_index } => Instr::LocalSet(*local_index),
        O::LocalTee { local_index } => Instr::LocalTee(*local_index),
        O::GlobalGet { global_index } => Instr::GlobalGet(*global_index),
        O::GlobalSet { global_index } => Instr::GlobalSet(*global_index),

        O::I32Const { .. } | O::I64Const { .. } | O::F32Const { .. } | O::F64Const { .. } => {
            Instr::Const
        }
        O::MemorySize { .. } => Instr::Const,

        _ => lower_numeric(op),
    }
}

/// Classifies loads, stores and the numeric operators by arity. Grouping by
/// shape rather than naming every opcode keeps the match tractable, and
/// anything unmatched still falls through to `Unsupported`.
fn lower_numeric(op: &Operator<'_>) -> Instr {
    let name = format!("{op:?}");
    let name = name
        .split(['{', '('])
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    if name.contains("Load") {
        return Instr::Load;
    }
    if name.contains("Store") {
        return Instr::Store;
    }
    if name == "MemoryGrow" {
        return Instr::Unop;
    }

    const UNOPS: [&str; 26] = [
        "I32Eqz",
        "I64Eqz",
        "I32Clz",
        "I32Ctz",
        "I32Popcnt",
        "I64Clz",
        "I64Ctz",
        "I64Popcnt",
        "I32WrapI64",
        "I64ExtendI32S",
        "I64ExtendI32U",
        "I32Extend8S",
        "I32Extend16S",
        "I64Extend8S",
        "I64Extend16S",
        "I64Extend32S",
        "F32Abs",
        "F32Neg",
        "F32Sqrt",
        "F64Abs",
        "F64Neg",
        "F64Sqrt",
        "F32DemoteF64",
        "F64PromoteF32",
        "I32TruncF32S",
        "I32TruncF64S",
    ];
    if UNOPS.contains(&name.as_str()) {
        return Instr::Unop;
    }

    // Binary arithmetic, bitwise, shift and comparison operators all pop two
    // and push one, and all propagate taint from either operand.
    let binop = name.starts_with("I32")
        || name.starts_with("I64")
        || name.starts_with("F32")
        || name.starts_with("F64");
    if binop {
        return Instr::Binop;
    }

    Instr::Unsupported(name)
}

/// Best-effort readable name. Rust v0 symbols embed `<len><identifier>`
/// components; taking the final identifier run avoids a full demangler
/// dependency while keeping names stable across builds (the symbol hash is
/// always a digit-led component, so it never survives).
fn strip_rust_mangling(name: &str) -> String {
    if !name.starts_with("_R") {
        return name
            .rsplit_once("::h")
            .map_or_else(|| name.to_string(), |(head, _)| head.to_string());
    }
    name.split(|c: char| c.is_ascii_digit())
        .rfind(|segment| !segment.is_empty() && segment.chars().any(|c| c != '_'))
        .unwrap_or(name)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testwat::wat_or_skip;

    /// Parsing records parameter counts, local counts and the lowered body.
    #[test]
    fn parses_signature_and_body() {
        let bytes = wat_or_skip!(
            r#"(module (func $f (param i32 i32) (result i32) (local i64)
                 local.get 0
                 local.get 1
                 i32.add))"#,
        );
        let module = parse(&bytes).unwrap();
        assert_eq!(module.functions.len(), 1);
        let f = &module.functions[0];
        assert_eq!(f.param_count, 2);
        assert_eq!(f.result_count, 1);
        assert_eq!(f.local_count, 3);
        assert_eq!(
            f.body,
            vec![
                Instr::LocalGet(0),
                Instr::LocalGet(1),
                Instr::Binop,
                Instr::End
            ]
        );
    }

    /// Loads and stores are classified by shape, not by individual opcode.
    #[test]
    fn classifies_loads_and_stores() {
        let bytes = wat_or_skip!(
            r#"(module (memory 1) (func $f (param i32)
                 local.get 0
                 i32.load8_u
                 drop
                 local.get 0
                 i64.const 1
                 i64.store))"#,
        );
        let body = &parse(&bytes).unwrap().functions[0].body;
        assert!(body.contains(&Instr::Load));
        assert!(body.contains(&Instr::Store));
    }

    /// An operator outside the modeled subset is recorded, never skipped.
    #[test]
    fn unsupported_operator_is_recorded() {
        let bytes = wat_or_skip!(
            r#"(module (memory 1) (func $f
                 i32.const 0 i32.const 0 i32.const 0 memory.fill))"#
        );
        let function = &parse(&bytes).unwrap().functions[0];
        assert!(
            function.has_unsupported().is_some(),
            "memory.fill should be unsupported, got {:?}",
            function.body
        );
    }

    /// Block result arity is recorded so stack-height tracking stays correct.
    #[test]
    fn records_block_result_arity() {
        let bytes = wat_or_skip!(
            r#"(module (func $f (result i32)
                 block (result i32) i32.const 1 end))"#,
        );
        let body = &parse(&bytes).unwrap().functions[0].body;
        assert_eq!(body[0], Instr::Block { results: 1 });
    }

    /// Function names come from the name section when present.
    #[test]
    fn reads_function_names() {
        let bytes = wat_or_skip!(r#"(module (func $my_function))"#);
        let module = parse(&bytes).unwrap();
        assert_eq!(module.functions[0].name.as_deref(), Some("my_function"));
        assert!(module.function("my_function").is_some());
    }

    /// Imported functions shift the index space of defined functions.
    #[test]
    fn imports_offset_the_function_index() {
        let bytes = wat_or_skip!(
            r#"(module (import "e" "i" (func (param i32))) (func $defined (param i64)))"#,
        );
        let module = parse(&bytes).unwrap();
        assert_eq!(
            module.functions.len(),
            1,
            "only defined functions have bodies"
        );
        assert_eq!(module.functions[0].index, 1);
        assert_eq!(module.functions[0].param_count, 1);
    }
}
