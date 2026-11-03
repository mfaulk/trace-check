//! Enumerating every `#[constant_time]` declaration in a compiled library.
//!
//! The question M8 exists to answer is *which contracts are there?*, and the
//! only honest source for it is the compilation itself. A procedural attribute
//! macro sees one item at a time and cannot enumerate the rest of the crate; a
//! source parser cannot know which items survived `cfg`, feature selection,
//! macro expansion or target choice. So `#[constant_time]` emits a `#[used]`
//! static into [`SECTION`], and this module reads those records back out of the
//! library's own `rlib`.
//!
//! # No external tools, for a reason
//!
//! The obvious reader is `llvm-objcopy --dump-section`, and it **silently loses
//! records**: it returns only the *first* section with a given name, while a
//! Rust object routinely holds several named [`SECTION`] — one per `#[used]`
//! static. The M8.1 spike measured a debug build reporting 1 of 23 records and
//! looking like a success. So this module parses `ar` and ELF directly. Both
//! formats are small and fully specified for what is needed, and reading them
//! in process makes "every section with this name" the straightforward reading
//! rather than the careful one.
//!
//! # An empty inventory and an unreadable one are different results
//!
//! This is the module's central discipline. A library may legitimately declare
//! no contracts. But an archive whose objects could not be read also yields no
//! records, and reporting that as "nothing declared" would turn a tooling
//! failure into a clean bill of health for every contract it failed to see.
//!
//! The M8.1 spike found exactly that in this repository: under `lto = true`,
//! rustc fills an rlib's `.o` members with LLVM bitcode instead of machine
//! code, and the ELF walk correctly found nothing in the real example library.
//! So [`read_archive`] counts object members and how many it could read, and
//! an archive with objects but none readable is [`InventoryError::NotObjects`]
//! — never an empty inventory.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::contract::{Descriptor, Parameter};
use crate::harness::Library;

/// Inventory schema this build emits and understands.
pub const SCHEMA_VERSION: u32 = 1;

/// Section the macro places its `#[used]` statics in.
pub const SECTION: &str = ".trace_check.contracts";

/// Record magic. Scanned for rather than assumed at a fixed offset, so
/// alignment padding between statics cannot desynchronize the parse.
pub const MAGIC: &[u8] = b"TCCONTR1";

/// Record schema the macro emits.
pub const RECORD_SCHEMA: u16 = 1;

/// Magic, schema and length, ahead of the payload.
const HEADER: usize = 8 + 2 + 4;

/// LLVM bitcode magic, recognized only so the error can say what happened.
const BITCODE_MAGIC: &[u8] = b"BC\xc0\xde";

/// Compilation settings the inventory build pins.
///
/// `lto = off` is load-bearing, not a preference: with fat LTO an rlib's
/// members are bitcode and carry no ELF sections at all. The inventory build is
/// trace-check's own build, exactly as M5's, M6's and M7's artifacts are, so its
/// flags are ours to choose and are recorded alongside the result.
pub const PROFILE: &str = "release: lto=off (inventory requires ELF objects, not bitcode)";

/// One declared contract, as the compiler recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContractDeclaration {
    /// Fully qualified identity: crate-qualified module path plus function.
    pub id: String,
    /// Module path the annotation expanded in.
    pub module: String,
    pub function: String,
    /// The developer's own source, not a generated harness.
    pub source_file: String,
    pub source_line: u32,
    /// Whether the macro emitted M3's `#[cfg(test)]` adapter for it.
    ///
    /// Recorded, never used to decide whether the declaration exists: a
    /// `dynamic = false` contract is inventoried like any other, which is the
    /// asymmetry M8 exists to remove.
    pub dynamic_adapter_enabled: bool,
    /// The descriptor the macro derived from this function's own signature.
    pub descriptor: Descriptor,
    /// That descriptor's exact bytes, so a report can pin what was read.
    pub descriptor_json: String,
    pub descriptor_sha256: String,
}

impl ContractDeclaration {
    /// `file:line`, in the shape the rest of the reports use.
    pub fn site(&self) -> String {
        format!("{}:{}", self.source_file, self.source_line)
    }

    pub fn secrets(&self) -> impl Iterator<Item = &Parameter> {
        self.descriptor.secrets()
    }
}

/// Which compilation an inventory describes.
///
/// An inventory is never a statement about a repository. It describes one
/// library target, built with one feature selection for one target triple by
/// one compiler. Two variants of the same package can declare different
/// contracts and compile the same contract to different code, so the identity
/// travels with the result and is compared rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildIdentity {
    pub package: String,
    pub version: String,
    /// Library target name, which is what a contract identity is qualified by.
    pub lib_target: String,
    pub manifest_path: String,
    /// Cargo features enabled for this build, sorted.
    pub features: Vec<String>,
    pub target_triple: String,
    pub rustc_version: String,
    pub profile: String,
    /// The artifact the records were read from.
    pub artifact_path: String,
    pub artifact_sha256: String,
}

impl BuildIdentity {
    /// A short, stable name for this variant, for reports that compare two.
    pub fn variant(&self) -> String {
        let features = if self.features.is_empty() {
            "default".to_string()
        } else {
            self.features.join("+")
        };
        format!("{}/{} [{}]", self.package, self.lib_target, features)
    }
}

/// Every declaration in one compiled library target.
#[derive(Debug, Clone, Serialize)]
pub struct ContractInventory {
    pub schema_version: u32,
    pub build: BuildIdentity,
    /// Declarations, ordered by canonical identity.
    ///
    /// Sorted rather than left in discovery order: records arrive in whatever
    /// order the codegen units happened to be laid out, and an inventory whose
    /// contents depended on that would not be comparable between runs.
    pub contracts: Vec<ContractDeclaration>,
    /// Hash over the ordered declarations, so two inventories can be compared
    /// without comparing their contents field by field.
    pub id: String,
    /// Object members found in the archive.
    pub objects_inspected: usize,
    /// Of those, how many were ELF this reader could walk.
    ///
    /// Present so `contracts.is_empty()` can be interpreted. Zero readable
    /// objects is an error, not an empty inventory; see the module docs.
    pub objects_read: usize,
}

impl ContractInventory {
    /// Whether this inventory is a complete account of the compilation.
    ///
    /// True only when every object member was read. It says nothing about
    /// whether the contracts are secure, nor about feature combinations other
    /// than the one built.
    pub fn complete(&self) -> bool {
        self.objects_inspected == self.objects_read
    }

    pub fn contract(&self, id: &str) -> Option<&ContractDeclaration> {
        self.contracts.iter().find(|entry| entry.id == id)
    }

    pub fn ids(&self) -> Vec<&str> {
        self.contracts
            .iter()
            .map(|entry| entry.id.as_str())
            .collect()
    }

    /// What this inventory does and does not establish, restated because a
    /// stored result outlives the conversation that produced it.
    pub fn limitations(&self) -> Vec<String> {
        vec![
            format!(
                "This inventory describes one compilation: {} for {}, built by {}. Another \
                 feature selection may declare different contracts.",
                self.build.variant(),
                self.build.target_triple,
                self.build.rustc_version
            ),
            "It enumerates `#[constant_time]` declarations that were compiled. It does not \
             discover functions that ought to carry one, and says nothing about whether any \
             declared function is constant-time."
                .to_string(),
            "Declarations in dependencies are not inventoried; only the selected library \
             target is read."
                .to_string(),
        ]
    }
}

/// Builds the library and reads its contract inventory.
///
/// # Why a dedicated build
///
/// The developer's own profile may enable LTO, and an LTO rlib holds bitcode
/// rather than ELF objects — no sections, no records, and an inventory that
/// would look empty. So this builds the library itself, into its own target
/// directory, with LTO forced off, and records the flags it used. That mirrors
/// what every other backend here does: analyze an artifact you built and can
/// name, never one you found.
///
/// The build is **not** the developer's test suite. Nothing is executed: the
/// records are ordinary object data.
pub fn build_and_read(
    library: &Library,
    target_dir: &Path,
) -> Result<ContractInventory, InventoryError> {
    let artifact = build_library(library, target_dir)?;
    read_artifact(library, &artifact)
}

/// Compiles the library for inventory and returns its `rlib`.
fn build_library(library: &Library, target_dir: &Path) -> Result<PathBuf, InventoryError> {
    let mut command = Command::new("cargo");
    command
        .args([
            "build",
            "--release",
            "--lib",
            "--message-format=json-render-diagnostics",
        ])
        .arg("--manifest-path")
        .arg(&library.manifest_path)
        .arg("--target-dir")
        .arg(target_dir)
        // The reason this build exists; see the module documentation.
        .env("CARGO_PROFILE_RELEASE_LTO", "off")
        .stdin(Stdio::null());
    if !library.features.is_empty() {
        command.arg("--features").arg(library.features.join(","));
    }
    let output = command
        .output()
        .map_err(|e| InventoryError::Io(format!("cannot run cargo: {e}")))?;
    if !output.status.success() {
        return Err(InventoryError::Build {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    // Cargo's own structured output, never a constructed path: anything under
    // `target/` might belong to a different build, and the milestone is
    // explicit that an inventory must be tied to the artifact it was read
    // from.
    let mut candidates: Vec<PathBuf> = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        if message["target"]["name"].as_str() != Some(library.lib_name.as_str()) {
            continue;
        }
        for filename in message["filenames"].as_array().into_iter().flatten() {
            let Some(path) = filename.as_str() else {
                continue;
            };
            if path.ends_with(".rlib") {
                candidates.push(PathBuf::from(path));
            }
        }
    }
    candidates.pop().ok_or_else(|| InventoryError::NoArtifact {
        package: library.package.clone(),
        lib_target: library.lib_name.clone(),
    })
}

/// Reads an inventory out of an already-built artifact.
pub fn read_artifact(
    library: &Library,
    artifact: &Path,
) -> Result<ContractInventory, InventoryError> {
    let bytes = std::fs::read(artifact)
        .map_err(|e| InventoryError::Io(format!("{}: {e}", artifact.display())))?;
    let read = read_archive(&bytes)?;

    let mut features = library.features.clone();
    features.sort();
    features.dedup();
    let build = BuildIdentity {
        package: library.package.clone(),
        version: library.version.clone(),
        lib_target: library.lib_name.clone(),
        manifest_path: library.manifest_path.clone(),
        features,
        target_triple: crate::symbolic::SUPPORTED_TARGET.to_string(),
        rustc_version: crate::native::tool_version(Path::new("rustc"), &["--version"])
            .unwrap_or_else(|_| "rustc (version unavailable)".to_string()),
        profile: PROFILE.to_string(),
        artifact_path: artifact.display().to_string(),
        artifact_sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    Ok(assemble(build, read))
}

/// What a successful archive read produced.
///
/// Public because the counts are the only thing that makes an empty result
/// interpretable: a caller has to be able to tell "nothing declared" from
/// "nothing readable".
#[derive(Debug)]
pub struct ArchiveRead {
    pub contracts: Vec<ContractDeclaration>,
    pub objects_inspected: usize,
    pub objects_read: usize,
}

fn assemble(build: BuildIdentity, read: ArchiveRead) -> ContractInventory {
    let mut contracts = read.contracts;
    contracts.sort_by(|left, right| left.id.cmp(&right.id));
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.to_le_bytes());
    for contract in &contracts {
        hasher.update(contract.id.as_bytes());
        hasher.update([0]);
        hasher.update(contract.descriptor_sha256.as_bytes());
        hasher.update([0]);
    }
    ContractInventory {
        schema_version: SCHEMA_VERSION,
        build,
        contracts,
        id: format!("{:x}", hasher.finalize()),
        objects_inspected: read.objects_inspected,
        objects_read: read.objects_read,
    }
}

/// Reads every contract record out of an `ar` archive's ELF members.
///
/// Public so the boundary between record *emission* and record *extraction* can
/// be tested from both sides, as the milestone's implementation plan asks.
pub fn read_archive(bytes: &[u8]) -> Result<ArchiveRead, InventoryError> {
    let mut contracts: Vec<ContractDeclaration> = Vec::new();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut objects_inspected = 0usize;
    let mut objects_read = 0usize;
    let mut bitcode = 0usize;

    for member in ar_members(bytes)? {
        let (name, body) = member;
        // `lib.rmeta` is an ELF container too, and deliberately carries no such
        // section: the record is object data belonging to a `#[used]` static.
        if !name.ends_with(".o") {
            continue;
        }
        objects_inspected += 1;
        if body.starts_with(BITCODE_MAGIC) {
            bitcode += 1;
            continue;
        }
        let sections = match elf_sections(body, SECTION) {
            Ok(sections) => sections,
            Err(error) => return Err(error.in_member(&name)),
        };
        objects_read += 1;
        for section in sections {
            for record in parse_records(section).map_err(|error| error.in_member(&name))? {
                if let Some(previous) = seen.get(&record.id) {
                    // Two records for one identity means either a duplicated
                    // emission or two different declarations claiming the same
                    // name. Identical bytes are tolerated -- a codegen unit may
                    // legitimately be duplicated -- and anything else is not,
                    // because the inventory would then depend on which record
                    // was read first.
                    if previous != &record.descriptor_sha256 {
                        return Err(InventoryError::Conflict {
                            id: record.id.clone(),
                        });
                    }
                    continue;
                }
                seen.insert(record.id.clone(), record.descriptor_sha256.clone());
                contracts.push(record);
            }
        }
    }

    if objects_inspected > 0 && objects_read == 0 {
        return Err(InventoryError::NotObjects {
            objects: objects_inspected,
            bitcode,
        });
    }
    Ok(ArchiveRead {
        contracts,
        objects_inspected,
        objects_read,
    })
}

/// One framed record's decoded payload.
fn parse_records(section: &[u8]) -> Result<Vec<ContractDeclaration>, SectionError> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(found) = find(&section[at..], MAGIC) {
        let start = at + found;
        if start + HEADER > section.len() {
            return Err(SectionError::TruncatedHeader);
        }
        let version = u16::from_le_bytes([section[start + 8], section[start + 9]]);
        if version != RECORD_SCHEMA {
            return Err(SectionError::UnknownSchema { found: version });
        }
        let length = u32::from_le_bytes([
            section[start + 10],
            section[start + 11],
            section[start + 12],
            section[start + 13],
        ]) as usize;
        let body = start + HEADER;
        if body + length > section.len() {
            return Err(SectionError::TruncatedPayload {
                claimed: length,
                available: section.len() - body,
            });
        }
        let payload = std::str::from_utf8(&section[body..body + length])
            .map_err(|_| SectionError::NotUtf8)?;
        out.push(decode(payload)?);
        at = body + length;
    }
    Ok(out)
}

/// Decodes one record payload into a declaration.
///
/// The embedded descriptor is parsed with the same [`Descriptor::parse`] the
/// rest of the project uses, which is the integrity check that matters: a
/// record whose descriptor does not model is refused rather than carried
/// forward as an identity with no signature behind it.
fn decode(payload: &str) -> Result<ContractDeclaration, SectionError> {
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| SectionError::NotJson(e.to_string()))?;
    let field = |name: &str| -> Result<String, SectionError> {
        value[name]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| SectionError::MissingField(name.to_string()))
    };
    let schema = value["schema_version"]
        .as_u64()
        .ok_or_else(|| SectionError::MissingField("schema_version".to_string()))?;
    if schema != u64::from(RECORD_SCHEMA) {
        return Err(SectionError::UnknownSchema {
            found: schema as u16,
        });
    }
    let descriptor_json = value
        .get("descriptor")
        .ok_or_else(|| SectionError::MissingField("descriptor".to_string()))?
        .to_string();
    let descriptor =
        Descriptor::parse(&descriptor_json).map_err(|e| SectionError::Descriptor(e.to_string()))?;
    Ok(ContractDeclaration {
        id: field("id")?,
        module: field("module")?,
        function: field("function")?,
        source_file: field("file")?,
        source_line: value["line"]
            .as_u64()
            .ok_or_else(|| SectionError::MissingField("line".to_string()))?
            as u32,
        dynamic_adapter_enabled: value["dynamic"]
            .as_bool()
            .ok_or_else(|| SectionError::MissingField("dynamic".to_string()))?,
        descriptor_sha256: format!("{:x}", Sha256::digest(descriptor_json.as_bytes())),
        descriptor,
        descriptor_json,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// `ar`
// ---------------------------------------------------------------------------

/// Members of a GNU `ar` archive, as `(name, body)`.
///
/// Rust's rlibs are GNU archives with a long-name string table, which is the
/// only variation this needs to handle. The format is 60 bytes of ASCII per
/// member followed by its body, padded to an even offset.
fn ar_members(data: &[u8]) -> Result<Vec<(String, &[u8])>, InventoryError> {
    const GLOBAL: &[u8] = b"!<arch>\n";
    if !data.starts_with(GLOBAL) {
        return Err(InventoryError::NotAnArchive);
    }
    let mut out = Vec::new();
    let mut longnames: &[u8] = &[];
    let mut at = GLOBAL.len();
    while at + 60 <= data.len() {
        let header = &data[at..at + 60];
        if &header[58..60] != b"`\n" {
            return Err(InventoryError::BadMember { offset: at });
        }
        let size: usize = std::str::from_utf8(&header[48..58])
            .ok()
            .map(str::trim)
            .and_then(|text| text.parse().ok())
            .ok_or(InventoryError::BadMember { offset: at })?;
        let start = at + 60;
        if start + size > data.len() {
            return Err(InventoryError::BadMember { offset: at });
        }
        let body = &data[start..start + size];
        let raw = trim_ascii_end(&header[0..16]);
        if raw == b"//" {
            longnames = body;
        } else if raw.first() == Some(&b'/')
            && raw.len() > 1
            && raw[1..].iter().all(u8::is_ascii_digit)
        {
            let offset: usize = std::str::from_utf8(&raw[1..])
                .ok()
                .and_then(|text| text.parse().ok())
                .ok_or(InventoryError::BadMember { offset: at })?;
            let name =
                longname(longnames, offset).ok_or(InventoryError::BadMember { offset: at })?;
            out.push((name, body));
        } else if raw != b"/" && raw != b"/SYM64/" {
            let name = String::from_utf8_lossy(raw)
                .trim_end_matches('/')
                .to_string();
            out.push((name, body));
        }
        at = start + size + (size & 1);
    }
    Ok(out)
}

fn longname(table: &[u8], offset: usize) -> Option<String> {
    let rest = table.get(offset..)?;
    let end = find(rest, b"/\n").unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

fn trim_ascii_end(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[..end]
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

/// Section type `SHT_NOBITS`: occupies no file space, so there is nothing to
/// read even though a header describes it.
const SHT_NOBITS: u32 = 8;

/// The bytes of **every** section named `want` in an ELF64 object.
///
/// Every, not the first: one Rust object routinely holds several sections
/// named [`SECTION`], and taking only the first is the bug that made
/// `llvm-objcopy --dump-section` unusable here.
fn elf_sections<'a>(data: &'a [u8], want: &str) -> Result<Vec<&'a [u8]>, SectionError> {
    // Not an ELF64 little-endian object. Reported by the caller as a
    // non-object member rather than as a corrupt one.
    if data.len() < 0x40 || !data.starts_with(b"\x7fELF") || data[4] != 2 || data[5] != 1 {
        return Err(SectionError::NotElf);
    }
    let word = |at: usize| -> Option<u64> {
        data.get(at..at + 8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
    };
    let half = |at: usize| -> Option<u16> {
        data.get(at..at + 2)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("two bytes")))
    };
    let shoff = word(0x28).ok_or(SectionError::Malformed)? as usize;
    let shentsize = half(0x3a).ok_or(SectionError::Malformed)? as usize;
    let shnum = half(0x3c).ok_or(SectionError::Malformed)? as usize;
    let shstrndx = half(0x3e).ok_or(SectionError::Malformed)? as usize;
    if shoff == 0 || shnum == 0 {
        // No section table. An object with none declares nothing, which is a
        // valid answer rather than an error.
        return Ok(Vec::new());
    }
    if shentsize < 0x40 {
        return Err(SectionError::Malformed);
    }
    let header = |index: usize| -> Option<(u32, u32, usize, usize)> {
        let base = shoff.checked_add(index.checked_mul(shentsize)?)?;
        let name = u32::from_le_bytes(data.get(base..base + 4)?.try_into().ok()?);
        let kind = u32::from_le_bytes(data.get(base + 4..base + 8)?.try_into().ok()?);
        let offset = word(base + 0x18)? as usize;
        let size = word(base + 0x20)? as usize;
        Some((name, kind, offset, size))
    };
    if shstrndx >= shnum {
        return Err(SectionError::Malformed);
    }
    let (_, _, str_offset, str_size) = header(shstrndx).ok_or(SectionError::Malformed)?;
    let strtab = data
        .get(str_offset..str_offset + str_size)
        .ok_or(SectionError::Malformed)?;

    let mut out = Vec::new();
    for index in 0..shnum {
        let (name, kind, offset, size) = header(index).ok_or(SectionError::Malformed)?;
        if kind == SHT_NOBITS {
            continue;
        }
        let start = name as usize;
        let rest = strtab.get(start..).ok_or(SectionError::Malformed)?;
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(rest.len());
        if std::str::from_utf8(&rest[..end]).ok() != Some(want) {
            continue;
        }
        let body = data
            .get(offset..offset + size)
            .ok_or(SectionError::SectionOutOfBounds { index })?;
        out.push(body);
    }
    Ok(out)
}

/// A problem reading one archive member.
#[derive(Debug)]
enum SectionError {
    NotElf,
    Malformed,
    SectionOutOfBounds { index: usize },
    TruncatedHeader,
    TruncatedPayload { claimed: usize, available: usize },
    UnknownSchema { found: u16 },
    NotUtf8,
    NotJson(String),
    MissingField(String),
    Descriptor(String),
}

impl SectionError {
    fn in_member(self, member: &str) -> InventoryError {
        match self {
            // A member that is not ELF is counted, not an error: the caller
            // decides what "no readable objects" means.
            SectionError::NotElf => InventoryError::Record {
                member: member.to_string(),
                detail: "the member is not an ELF64 little-endian object".to_string(),
            },
            other => InventoryError::Record {
                member: member.to_string(),
                detail: other.describe(),
            },
        }
    }

    fn describe(&self) -> String {
        match self {
            SectionError::NotElf => "not an ELF64 little-endian object".to_string(),
            SectionError::Malformed => "the ELF section table could not be read".to_string(),
            SectionError::SectionOutOfBounds { index } => {
                format!("section {index} runs past the end of the object")
            }
            SectionError::TruncatedHeader => "a record header is truncated".to_string(),
            SectionError::TruncatedPayload { claimed, available } => format!(
                "a record claims {claimed} payload byte(s) but only {available} are present"
            ),
            SectionError::UnknownSchema { found } => format!(
                "record schema version {found} is not understood; this build emits and reads \
                 version {RECORD_SCHEMA}"
            ),
            SectionError::NotUtf8 => "a record payload is not UTF-8".to_string(),
            SectionError::NotJson(detail) => format!("a record payload is not JSON: {detail}"),
            SectionError::MissingField(name) => {
                format!("a record has no `{name}` field")
            }
            SectionError::Descriptor(detail) => {
                format!("a record's embedded descriptor is not usable: {detail}")
            }
        }
    }
}

#[derive(Debug)]
pub enum InventoryError {
    Io(String),
    Build {
        stderr: String,
    },
    NoArtifact {
        package: String,
        lib_target: String,
    },
    NotAnArchive,
    BadMember {
        offset: usize,
    },
    /// Object members were present but none could be read.
    ///
    /// The failure the M8.1 spike found: under LTO an rlib holds bitcode, and
    /// an ELF walk legitimately finds nothing. Reporting that as an empty
    /// inventory would give every contract it failed to see a clean bill of
    /// health.
    NotObjects {
        objects: usize,
        bitcode: usize,
    },
    Record {
        member: String,
        detail: String,
    },
    Conflict {
        id: String,
    },
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InventoryError::Io(message) => write!(f, "{message}"),
            InventoryError::Build { stderr } => write!(
                f,
                "building the library for its contract inventory failed:\n{}",
                stderr
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("Compiling"))
                    .take(12)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            InventoryError::NoArtifact {
                package,
                lib_target,
            } => write!(
                f,
                "cargo built `{package}` but reported no rlib for its `{lib_target}` library \
                 target, so there is no artifact to read an inventory from"
            ),
            InventoryError::NotAnArchive => write!(
                f,
                "the library artifact is not an `ar` archive, so its object members cannot be \
                 located"
            ),
            InventoryError::BadMember { offset } => write!(
                f,
                "the library archive has a malformed member header at offset {offset}"
            ),
            InventoryError::NotObjects { objects, bitcode } => write!(
                f,
                "none of the {objects} object member(s) of the library archive could be read as \
                 an ELF object{}. The contract inventory is refused rather than reported as \
                 empty: an unreadable artifact and a library that declares no contracts are \
                 different results, and treating one as the other would give every contract it \
                 failed to see a clean bill of health",
                if *bitcode > 0 {
                    format!(
                        " ({bitcode} contain LLVM bitcode, which is what link-time optimization \
                         produces -- the inventory build sets `lto = off` for exactly this \
                         reason, so a profile or RUSTFLAGS setting is overriding it)"
                    )
                } else {
                    String::new()
                }
            ),
            InventoryError::Record { member, detail } => write!(
                f,
                "a contract record in `{member}` could not be read: {detail}. The inventory is \
                 refused rather than silently short one declaration"
            ),
            InventoryError::Conflict { id } => write!(
                f,
                "two different contract records both claim the identity `{id}`. An inventory \
                 that picked one would depend on which was read first"
            ),
        }
    }
}

impl std::error::Error for InventoryError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a framed record around a payload.
    fn framed(schema: u16, payload: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&schema.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload.as_bytes());
        out
    }

    const DESCRIPTOR: &str = r#"{"schema_version":1,"function":"probe","parameters":[{"name":"key","position":0,"role":"secret","repr":"u8","rust_type":"u8"}],"returns":{"repr":"u8","rust_type":"u8"}}"#;

    fn payload(id: &str) -> String {
        format!(
            r#"{{"schema_version":1,"id":"{id}","module":"crypto::shadow","function":"probe","file":"src/shadow.rs","line":7,"dynamic":false,"descriptor":{DESCRIPTOR}}}"#
        )
    }

    /// A well-formed record decodes into a declaration with its site and
    /// descriptor intact.
    #[test]
    fn a_record_decodes_with_its_descriptor() {
        let section = framed(1, &payload("crypto::shadow::left::probe"));
        let found = parse_records(&section).expect("the record parses");
        assert_eq!(found.len(), 1);
        let declaration = &found[0];
        assert_eq!(declaration.id, "crypto::shadow::left::probe");
        assert_eq!(declaration.function, "probe");
        assert_eq!(declaration.site(), "src/shadow.rs:7");
        assert!(!declaration.dynamic_adapter_enabled);
        assert_eq!(declaration.descriptor.parameters.len(), 1);
        assert_eq!(declaration.secrets().count(), 1);
        assert_eq!(declaration.descriptor_sha256.len(), 64);
    }

    /// Several records in one section are all read, and padding between them
    /// does not desynchronize the scan.
    #[test]
    fn padded_records_are_all_read() {
        let mut section = framed(1, &payload("crypto::a::probe"));
        section.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
        section.extend_from_slice(&framed(1, &payload("crypto::b::probe")));
        let found = parse_records(&section).expect("both records parse");
        assert_eq!(
            found.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            vec!["crypto::a::probe", "crypto::b::probe"]
        );
    }

    /// A length past the end of the section is refused rather than read as a
    /// short record.
    #[test]
    fn a_length_past_the_section_end_is_refused() {
        let mut section = framed(1, &payload("crypto::a::probe"));
        let claimed = (section.len() as u32) + 500;
        section[10..14].copy_from_slice(&claimed.to_le_bytes());
        let error = parse_records(&section).expect_err("a long length must be refused");
        assert!(error.describe().contains("payload byte(s)"), "{error:?}");
    }

    /// An unframed header at the very end of a section is refused.
    #[test]
    fn a_truncated_header_is_refused() {
        let mut section = Vec::from(MAGIC);
        section.push(1);
        let error = parse_records(&section).expect_err("a truncated header must be refused");
        assert!(error.describe().contains("truncated"), "{error:?}");
    }

    /// A record from a future schema is refused, named, and the reader says
    /// which version it does understand.
    #[test]
    fn a_future_schema_is_refused() {
        let section = framed(99, &payload("crypto::a::probe"));
        let error = parse_records(&section).expect_err("a future schema must be refused");
        let message = error.describe();
        assert!(message.contains("99"), "{message}");
        assert!(message.contains("version 1"), "{message}");
    }

    /// A payload whose descriptor does not model is refused: an identity with
    /// no usable signature behind it is not a declaration.
    #[test]
    fn an_unusable_descriptor_is_refused() {
        let broken = r#"{"schema_version":1,"id":"a::b","module":"a","function":"b","file":"f","line":1,"dynamic":true,"descriptor":{"schema_version":99}}"#;
        let section = framed(1, broken);
        let error = parse_records(&section).expect_err("a bad descriptor must be refused");
        assert!(error.describe().contains("descriptor"), "{error:?}");
    }

    /// A missing field is named rather than defaulted.
    #[test]
    fn a_missing_field_is_named() {
        let short = format!(
            r#"{{"schema_version":1,"id":"a::b","module":"a","function":"b","line":1,"dynamic":true,"descriptor":{DESCRIPTOR}}}"#
        );
        let section = framed(1, &short);
        let error = parse_records(&section).expect_err("a missing field must be refused");
        assert!(error.describe().contains("`file`"), "{error:?}");
    }

    /// Bytes that are not an archive are refused by name.
    #[test]
    fn a_non_archive_is_refused() {
        let error = read_archive(b"not an archive at all").expect_err("must be refused");
        assert!(matches!(error, InventoryError::NotAnArchive));
        assert!(error.to_string().contains("ar` archive"));
    }

    /// An archive whose only object member is LLVM bitcode is refused, and the
    /// message names LTO as the cause.
    ///
    /// The failure mode the M8.1 spike found: an ELF walk legitimately finds
    /// nothing in a bitcode rlib, and calling that an empty inventory would
    /// clear every contract it failed to see.
    #[test]
    fn a_bitcode_archive_is_refused_not_reported_empty() {
        let archive = archive_of(&[("crate.rcgu.o", BITCODE_MAGIC)]);
        let error = read_archive(&archive).expect_err("bitcode must be refused");
        match error {
            InventoryError::NotObjects { objects, bitcode } => {
                assert_eq!((objects, bitcode), (1, 1));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let message = error.to_string();
        assert!(message.contains("lto = off"), "{message}");
        assert!(message.contains("different results"), "{message}");
    }

    /// An archive with no object members at all is a valid empty inventory:
    /// there was nothing to fail to read.
    #[test]
    fn an_archive_with_no_objects_is_empty_not_an_error() {
        let archive = archive_of(&[("lib.rmeta", b"\x7fELF")]);
        let read = read_archive(&archive).expect("an rmeta-only archive is readable");
        assert_eq!(read.objects_inspected, 0);
        assert!(read.contracts.is_empty());
    }

    /// Builds a minimal GNU `ar` archive, for the reader's negative tests.
    fn archive_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::from(&b"!<arch>\n"[..]);
        for (name, body) in members {
            let header = format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                format!("{name}/"),
                0,
                0,
                0,
                644,
                body.len()
            );
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(body);
            if body.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    /// Declarations are sorted by identity, so an inventory does not depend on
    /// codegen-unit layout.
    #[test]
    fn declarations_are_sorted_by_identity() {
        let mut section = framed(1, &payload("crypto::z::probe"));
        section.extend_from_slice(&framed(1, &payload("crypto::a::probe")));
        let read = ArchiveRead {
            contracts: parse_records(&section).expect("both parse"),
            objects_inspected: 1,
            objects_read: 1,
        };
        let inventory = assemble(identity(), read);
        assert_eq!(
            inventory.ids(),
            vec!["crypto::a::probe", "crypto::z::probe"]
        );
        assert!(inventory.complete());
    }

    /// The inventory identity changes when a declaration does, and not
    /// otherwise.
    #[test]
    fn the_inventory_identity_follows_its_contents() {
        let one = |ids: &[&str]| {
            let mut section = Vec::new();
            for id in ids {
                section.extend_from_slice(&framed(1, &payload(id)));
            }
            assemble(
                identity(),
                ArchiveRead {
                    contracts: parse_records(&section).expect("parses"),
                    objects_inspected: 1,
                    objects_read: 1,
                },
            )
            .id
        };
        // Order of discovery must not matter; contents must.
        assert_eq!(
            one(&["crypto::a::probe", "crypto::b::probe"]),
            one(&["crypto::b::probe", "crypto::a::probe"])
        );
        assert_ne!(
            one(&["crypto::a::probe"]),
            one(&["crypto::a::probe", "crypto::b::probe"])
        );
    }

    fn identity() -> BuildIdentity {
        BuildIdentity {
            package: "crypto-library".to_string(),
            version: "0.1.0".to_string(),
            lib_target: "crypto".to_string(),
            manifest_path: "/x/Cargo.toml".to_string(),
            features: Vec::new(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            rustc_version: "rustc 1.97.0".to_string(),
            profile: PROFILE.to_string(),
            artifact_path: "/x/libcrypto.rlib".to_string(),
            artifact_sha256: "deadbeef".to_string(),
        }
    }

    /// A variant name distinguishes feature selections, so two inventories of
    /// one package are not confused.
    #[test]
    fn a_variant_name_distinguishes_feature_selections() {
        let mut plain = identity();
        let mut fast = identity();
        fast.features = vec!["fast".to_string()];
        assert_ne!(plain.variant(), fast.variant());
        assert!(plain.variant().contains("default"));
        assert!(fast.variant().contains("fast"));
        plain.features = vec!["fast".to_string()];
        assert_eq!(plain.variant(), fast.variant());
    }
}
