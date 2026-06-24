#![allow(clippy::too_many_arguments)]

pub mod maps;

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::raw::c_long;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use gimli::{EndianRcSlice, Reader, RunTimeEndian};
use heapify_core::glibc::{
    decode_safe_linked_ptr, select_glibc_profile, suggest_glibc_profile_for_version, BinExperiment,
    BinExperimentRole, BinPointerCandidate, FastbinChain, FastbinExperiment, FastbinExperimentRole,
    FastbinHead, FastbinNode, FastbinPointerCandidate, FastbinsSnapshot, GlibcChunkHeader,
    GlibcHeapSnapshot, GlibcProfile, GlibcProfileSelection, LargebinChain, LargebinNode,
    LargebinsSnapshot, RegularBinHead, RegularBinRole, RegularBinsSnapshot, SmallbinChain,
    SmallbinNode, SmallbinsSnapshot, TcacheBinSnapshot, TcacheEntryCandidate,
    TcacheSnapshotCandidate, TcacheStructCandidate, UnsortedBinChain, UnsortedBinExperiment,
    UnsortedBinNode, UnsortedBinPointerCandidate, UnsortedBinSnapshot, UnsortedExperimentRole,
    GLIBC_X86_64_MODERN,
};
pub use heapify_core::glibc::{
    MainArenaCandidate, MainArenaExperiment, MainArenaPointerCandidate, MainArenaRoleHint,
    MainArenaSource, MainArenaTopCandidate, MainArenaTopStatus,
};
use heapify_core::tracker::{HeapTracker, ObservedChunkState};
use heapify_core::HeapTraceEvent;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};
use maps::{
    find_executable_mapping, find_libc_mapping, mapping_load_base, read_process_maps, MemoryMapping,
};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
pub use nix::unistd::Pid;
use nix::unistd::{execvp, fork, ForkResult};
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};

mod snapshots;
use snapshots::decoded_instruction_fallthrough;
pub use snapshots::{
    decode_instruction_at_rip, format_register_value_hex, read_disassembly_snapshot,
    read_disassembly_snapshot_with_reader, read_process_maps_snapshot, read_register_snapshot,
    read_stack_snapshot, DecodedInstruction, DisassemblyFlowControl, DisassemblyLine,
    DisassemblySnapshot, ProcessMapEntry, ProcessMapsSnapshot, RegisterArch, RegisterRole,
    RegisterSnapshot, RegisterValue, StackSnapshot, StackWord, TargetMemoryReader,
    DEFAULT_DISASSEMBLY_AFTER_BYTES, DEFAULT_DISASSEMBLY_BEFORE_BYTES,
    DEFAULT_DISASSEMBLY_MAX_INSTRUCTIONS, DEFAULT_STACK_SNAPSHOT_WORDS,
};
#[cfg(test)]
pub(crate) use snapshots::{
    decode_x86_64_instruction, read_stack_snapshot_with_reader, register_snapshot_from_x86_64_regs,
};
mod process;
mod run_control;
pub use process::{
    build_exec_plan, ExecPlan, LaunchConfig, LaunchMode, StdinConfig, TargetCommand,
};
pub use run_control::{
    validate_live_command, AllocatorEventControl, DebuggerStopReason, LiveCommand, LiveCommandId,
    LiveCommandMessage, LiveCommandStatus, LiveTargetStatus, MemoryInspectionRequest,
    MemoryViewFormat, StepKind,
};
use run_control::{
    LiveControlOutcome, LiveTraceRunMode, LiveWorkerPauseState, PendingInstructionStepOver,
    TraceWaitMode,
};

const DEFAULT_SOURCE_STEP_BUDGET: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationTraceMode {
    TargetPlt,
    LibcSymbols,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceStepKind {
    Into,
    Over,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceStepState {
    kind: SourceStepKind,
    origin: SourceLocation,
    origin_rip: u64,
    instructions_executed: u64,
    instruction_budget: u64,
}

impl AllocationTraceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AllocationTraceMode::TargetPlt => "target_plt",
            AllocationTraceMode::LibcSymbols => "libc_symbols",
        }
    }
}

mod breakpoint;
pub use breakpoint::{
    Breakpoint, BreakpointKind, BreakpointManager, BreakpointOwner, BreakpointPurpose,
    ManagedBreakpoint, SourceBreakpointResolution, UserBreakpoint, UserBreakpointId,
    UserBreakpointSpec,
};

struct TraceHeapState<F>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    event_id: usize,
    heap_mapping: Option<MemoryMapping>,
    heap_mapping_printed: bool,
    libc_metadata: Option<LibcMetadata>,
    libc_metadata_printed: bool,
    supplied_libc_path: Option<PathBuf>,
    glibc_profile_suggestion_printed: bool,
    show_status: bool,
    glibc_profile: GlibcProfile,
    on_event: F,
}

impl<F> TraceHeapState<F>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    fn new(
        on_event: F,
        show_status: bool,
        libc_metadata: Option<LibcMetadata>,
        supplied_libc_path: Option<PathBuf>,
        glibc_profile: GlibcProfile,
    ) -> Self {
        let libc_metadata_printed = libc_metadata.is_some();
        let glibc_profile_suggestion_printed = show_status && libc_metadata.is_some();
        Self {
            event_id: 1,
            heap_mapping: None,
            heap_mapping_printed: false,
            libc_metadata,
            libc_metadata_printed,
            supplied_libc_path,
            glibc_profile_suggestion_printed,
            show_status,
            glibc_profile,
            on_event,
        }
    }

    fn next_event_id(&mut self) -> usize {
        let event_id = self.event_id;
        self.event_id += 1;
        event_id
    }
}

#[derive(Debug, Clone)]
pub struct TraceHeapContext {
    pub pid: Pid,
    pub heap_mapping: Option<MemoryMapping>,
    pub glibc_profile: GlibcProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibcMetadata {
    pub path: String,
    pub supplied_path: Option<String>,
    pub paths_match: Option<bool>,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TraceSessionContext {
    pub pid: Pid,
    pub libc: Option<LibcMetadata>,
    pub glibc_profile: GlibcProfile,
    pub glibc_profile_selection: GlibcProfileSelection,
    pub launch: ExecPlan,
    pub process_maps: Option<ProcessMapsSnapshot>,
    pub process_maps_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSymbol {
    pub object_path: String,
    pub object_name: String,
    pub name: String,
    pub runtime_addr: u64,
    pub size: u64,
    pub is_main_object: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolizedAddress {
    pub addr: u64,
    pub object_name: Option<String>,
    pub symbol: String,
    pub symbol_addr: u64,
    pub offset: u64,
    pub source: Option<SourceLocation>,
}

type SourceDwarfReader = EndianRcSlice<RunTimeEndian>;

#[derive(Debug, Clone)]
pub struct ProcessSymbolizer {
    symbols: Vec<RuntimeSymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeObject {
    path: String,
    object_name: String,
    load_base: u64,
    is_main_object: bool,
}

impl ProcessSymbolizer {
    const MAX_ZERO_SIZE_SYMBOL_OFFSET: u64 = 0x10000;

    pub fn from_process(pid: Pid, program_path: &str) -> Result<Self> {
        let maps = read_process_maps(pid)?;
        let objects = runtime_objects_from_mappings(&maps, program_path)?;
        let mut symbols = Vec::new();

        for object in objects {
            let Ok(elf_symbols) = heapify_elf::list_symbols(&object.path) else {
                continue;
            };
            for symbol in elf_symbols {
                let Some(runtime_addr) = object.load_base.checked_add(symbol.addr) else {
                    continue;
                };
                symbols.push(RuntimeSymbol {
                    object_path: object.path.clone(),
                    object_name: object.object_name.clone(),
                    name: symbol.name,
                    runtime_addr,
                    size: symbol.size,
                    is_main_object: object.is_main_object,
                });
            }
        }

        if !symbols.iter().any(|symbol| symbol.is_main_object) {
            symbols.extend(main_executable_runtime_symbols(pid, program_path)?);
        }

        Ok(Self::from_runtime_symbols(symbols))
    }

    pub fn from_runtime_symbols(mut symbols: Vec<RuntimeSymbol>) -> Self {
        symbols.sort_by(|left, right| {
            left.runtime_addr
                .cmp(&right.runtime_addr)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.size.cmp(&right.size))
        });
        Self { symbols }
    }

    pub fn symbolize(&self, addr: u64) -> Option<SymbolizedAddress> {
        let index = self
            .symbols
            .partition_point(|symbol| symbol.runtime_addr <= addr);
        let symbol = self.symbols.get(index.checked_sub(1)?)?;
        let offset = addr.checked_sub(symbol.runtime_addr)?;

        if symbol.size > 0 {
            if offset > symbol.size {
                return None;
            }
        } else if offset > Self::MAX_ZERO_SIZE_SYMBOL_OFFSET {
            return None;
        }

        Some(SymbolizedAddress {
            addr,
            object_name: (!symbol.is_main_object).then(|| symbol.object_name.clone()),
            symbol: symbol.name.clone(),
            symbol_addr: symbol.runtime_addr,
            offset,
            source: None,
        })
    }

    pub fn resolve_breakpoint_symbol(&self, requested: &str) -> Result<(String, u64)> {
        let mut exact = self
            .symbols
            .iter()
            .filter(|symbol| symbol.name == requested)
            .collect::<Vec<_>>();
        exact.sort_by_key(|symbol| (!symbol.is_main_object, symbol.runtime_addr));
        exact.dedup_by_key(|symbol| (symbol.name.as_str(), symbol.runtime_addr));
        if exact.len() == 1 {
            let symbol = exact[0];
            return Ok((symbol.name.clone(), symbol.runtime_addr));
        }
        if exact.len() > 1 {
            bail!(
                "ambiguous breakpoint symbol: {requested}; candidates: {}",
                format_symbol_candidates(&exact)
            );
        }

        let versioned_prefix = format!("{requested}@");
        let mut versioned = self
            .symbols
            .iter()
            .filter(|symbol| symbol.name.starts_with(&versioned_prefix))
            .collect::<Vec<_>>();
        versioned.sort_by_key(|symbol| (!symbol.is_main_object, symbol.runtime_addr));
        versioned.dedup_by_key(|symbol| (symbol.name.as_str(), symbol.runtime_addr));
        if versioned.len() == 1 {
            let symbol = versioned[0];
            return Ok((symbol.name.clone(), symbol.runtime_addr));
        }
        if versioned.len() > 1 {
            bail!(
                "ambiguous breakpoint symbol: {requested}; candidates: {}",
                format_symbol_candidates(&versioned)
            );
        }

        bail!("could not resolve breakpoint symbol: {requested}");
    }

    pub fn breakpoint_metadata(
        &self,
        addr: u64,
        source_mapper: Option<&TargetSourceMapper>,
    ) -> (Option<String>, Option<SourceLocation>) {
        let symbolized = self.symbolize(addr);
        let resolved_symbol = symbolized.as_ref().map(|symbol| {
            let mut label = symbol.symbol.clone();
            if symbol.offset > 0 {
                label.push_str(&format!("+0x{:x}", symbol.offset));
            }
            if let Some(object) = symbol.object_name.as_deref() {
                if !object.is_empty() {
                    label = format!("{object}!{label}");
                }
            }
            label
        });
        let source = symbolized
            .and_then(|symbol| symbol.source)
            .or_else(|| source_mapper.and_then(|source_mapper| source_mapper.lookup(addr)));
        (resolved_symbol, source)
    }
}

fn format_symbol_candidates(symbols: &[&RuntimeSymbol]) -> String {
    symbols
        .iter()
        .take(5)
        .map(|symbol| {
            if symbol.is_main_object {
                format!("{} at 0x{:x}", symbol.name, symbol.runtime_addr)
            } else {
                format!(
                    "{}!{} at 0x{:x}",
                    symbol.object_name, symbol.name, symbol.runtime_addr
                )
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub struct TargetSourceMapper {
    context: addr2line::Context<SourceDwarfReader>,
    load_base: u64,
}

impl TargetSourceMapper {
    pub fn from_process(pid: Pid, program_path: &str) -> Result<Self> {
        let bytes = std::fs::read(program_path)
            .with_context(|| format!("failed to read target executable: {program_path}"))?;
        let object = object::File::parse(bytes.as_slice())
            .with_context(|| format!("failed to parse target executable: {program_path}"))?;
        let endian = if object.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let mut dwarf =
            gimli::Dwarf::load(|section_id| load_dwarf_section(&object, section_id.name(), endian))
                .context("failed to load target DWARF sections")?;
        dwarf.populate_abbreviations_cache(gimli::AbbreviationsCacheStrategy::Duplicates);
        let context =
            addr2line::Context::from_dwarf(dwarf).context("failed to build addr2line context")?;

        let load_base = target_runtime_load_bias(pid, program_path)?;

        Ok(Self { context, load_base })
    }

    pub fn lookup(&self, runtime_addr: u64) -> Option<SourceLocation> {
        let relative = runtime_addr_to_source_relative_addr(runtime_addr, self.load_base)?;
        let adjusted = return_address_source_lookup_addr(relative);
        let location = self.context.find_location(adjusted).ok().flatten()?;
        let source = SourceLocation {
            file: location.file.map(str::to_string),
            line: location.line,
            column: location.column,
        };
        (source.file.is_some() || source.line.is_some() || source.column.is_some())
            .then_some(source)
    }
}

fn target_runtime_load_bias(pid: Pid, program_path: &str) -> Result<u64> {
    if heapify_elf::is_pie(program_path)? {
        let mapping = find_executable_mapping(pid, program_path)?.with_context(|| {
            format!("failed to find executable mapping for PIE target: {program_path}")
        })?;
        mapping_load_base(&mapping)
    } else {
        Ok(0)
    }
}

pub fn resolve_source_line_breakpoint(
    target_elf_path: &Path,
    target_runtime_load_bias: u64,
    requested_path: &str,
    requested_line: u64,
) -> Result<SourceBreakpointResolution> {
    if requested_line == 0 {
        bail!("source breakpoint line must be greater than 0");
    }
    let path = target_elf_path
        .to_str()
        .context("target executable path is not valid UTF-8")?;
    if matches!(
        heapify_elf::elf_file_type(path)?,
        heapify_elf::ElfFileType::SharedObject
    ) {
        bail!("source breakpoints currently support the target executable only");
    }
    let bytes = std::fs::read(target_elf_path)
        .with_context(|| format!("failed to read ELF file: {path}"))?;
    let object = object::File::parse(bytes.as_slice())
        .with_context(|| format!("failed to parse ELF file: {path}"))?;
    let endian = if object.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let mut dwarf =
        gimli::Dwarf::load(|section_id| load_dwarf_section(&object, section_id.name(), endian))
            .context("failed to load target DWARF sections")?;
    dwarf.populate_abbreviations_cache(gimli::AbbreviationsCacheStrategy::Duplicates);

    let mut rows = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next().context("failed to read DWARF unit header")? {
        let unit = dwarf.unit(header).context("failed to read DWARF unit")?;
        let Some(program) = unit.line_program.clone() else {
            continue;
        };
        let mut line_rows = program.rows();
        while let Some((header, row)) = line_rows.next_row().context("failed to read line row")? {
            if row.end_sequence() {
                continue;
            }
            let Some(line) = row.line().map(|line| line.get()) else {
                continue;
            };
            let Some(file) = row.file(header) else {
                continue;
            };
            let Some(path) = line_file_path(&dwarf, &unit, header, file)? else {
                continue;
            };
            rows.push(SourceLineRow {
                path,
                line,
                address: row.address(),
            });
        }
    }

    let candidates = select_source_path_candidates(&rows, requested_path)?;
    let best = candidates
        .into_iter()
        .filter(|row| row.line == requested_line)
        .min_by_key(|row| row.address)
        .with_context(|| {
            format!("no executable statement found for {requested_path}:{requested_line}")
        })?;
    let resolved_address = target_runtime_load_bias
        .checked_add(best.address)
        .context("runtime source breakpoint address overflow")?;
    let symbol = heapify_elf::list_symbols(path).ok().and_then(|symbols| {
        symbols
            .into_iter()
            .filter(|symbol| symbol.addr <= best.address)
            .max_by_key(|symbol| symbol.addr)
            .map(|symbol| {
                if best.address > symbol.addr {
                    format!("{}+0x{:x}", symbol.name, best.address - symbol.addr)
                } else {
                    symbol.name
                }
            })
    });

    Ok(SourceBreakpointResolution {
        requested_path: requested_path.to_string(),
        requested_line,
        resolved_path: best.path.clone(),
        resolved_line: best.line,
        resolved_address,
        symbol,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLineRow {
    pub path: String,
    pub line: u64,
    pub address: u64,
}

fn line_file_path(
    dwarf: &gimli::Dwarf<SourceDwarfReader>,
    unit: &gimli::Unit<SourceDwarfReader>,
    header: &gimli::LineProgramHeader<SourceDwarfReader>,
    file: &gimli::FileEntry<SourceDwarfReader>,
) -> Result<Option<String>> {
    let Some(path_name) = dwarf_attr_string(dwarf, unit, file.path_name())? else {
        return Ok(None);
    };
    let path = Path::new(&path_name);
    if path.is_absolute() {
        return Ok(Some(normalize_source_path(&path_name)));
    }
    let directory = file
        .directory(header)
        .and_then(|directory| dwarf_attr_string(dwarf, unit, directory).transpose())
        .transpose()?
        .or_else(|| {
            unit.comp_dir.as_ref().and_then(|dir| {
                dir.clone()
                    .to_string_lossy()
                    .ok()
                    .map(|dir| dir.into_owned())
            })
        });
    Ok(Some(match directory {
        Some(directory) if !directory.is_empty() => {
            normalize_source_path(&format!("{directory}/{path_name}"))
        }
        _ => normalize_source_path(&path_name),
    }))
}

fn dwarf_attr_string(
    dwarf: &gimli::Dwarf<SourceDwarfReader>,
    unit: &gimli::Unit<SourceDwarfReader>,
    value: gimli::AttributeValue<SourceDwarfReader>,
) -> Result<Option<String>> {
    Ok(Some(
        dwarf
            .attr_string(unit, value)?
            .to_string_lossy()?
            .into_owned(),
    ))
}

pub fn normalize_source_path(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let absolute = replaced.starts_with('/');
    let mut parts = Vec::new();
    for part in replaced.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if !parts.is_empty() && parts.last() != Some(&"..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(part);
                }
            }
            _ => parts.push(part),
        }
    }
    let mut normalized = parts.join("/");
    if absolute {
        normalized.insert(0, '/');
    }
    if normalized.is_empty() {
        ".".to_string()
    } else {
        normalized
    }
}

pub fn source_location_changed(origin: &SourceLocation, current: &SourceLocation) -> bool {
    let origin_file = origin.file.as_deref().map(normalize_source_path);
    let current_file = current.file.as_deref().map(normalize_source_path);
    origin_file != current_file || origin.line != current.line
}

pub fn format_source_location_short(source: &SourceLocation) -> String {
    match (source.file.as_deref(), source.line) {
        (Some(file), Some(line)) => format!("{}:{line}", normalize_source_path(file)),
        (Some(file), None) => normalize_source_path(file),
        (None, Some(line)) => format!(":{line}"),
        (None, None) => "unknown".to_string(),
    }
}

pub fn format_source_location_delta(origin: &SourceLocation, current: &SourceLocation) -> String {
    let origin_file = origin.file.as_deref().map(normalize_source_path);
    let current_file = current.file.as_deref().map(normalize_source_path);
    match (origin_file, current_file, current.line) {
        (Some(origin_file), Some(current_file), Some(line)) if origin_file == current_file => {
            format!(":{line}")
        }
        (_, _, _) => format_source_location_short(current),
    }
}

pub fn select_source_path_candidates<'a>(
    rows: &'a [SourceLineRow],
    requested_path: &str,
) -> Result<Vec<&'a SourceLineRow>> {
    let requested = normalize_source_path(requested_path);
    let mut exact = rows
        .iter()
        .filter(|row| normalize_source_path(&row.path) == requested)
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        exact.sort_by_key(|row| (row.path.as_str(), row.line, row.address));
        return Ok(exact);
    }

    let suffix = format!("/{requested}");
    let mut suffix_matches = rows
        .iter()
        .filter(|row| normalize_source_path(&row.path).ends_with(&suffix))
        .collect::<Vec<_>>();
    if !suffix_matches.is_empty() {
        let suffix_paths = suffix_matches
            .iter()
            .map(|row| row.path.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if suffix_paths.len() > 1 {
            let candidates = suffix_paths
                .iter()
                .take(5)
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            bail!("ambiguous source path {requested_path}; candidates: {candidates}");
        }
        suffix_matches.sort_by_key(|row| (row.path.as_str(), row.line, row.address));
        return Ok(suffix_matches);
    }

    let requested_basename = Path::new(&requested)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(requested.as_str());
    let basename_paths = rows
        .iter()
        .filter(|row| {
            Path::new(&row.path)
                .file_name()
                .and_then(|name| name.to_str())
                == Some(requested_basename)
        })
        .map(|row| row.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if basename_paths.len() == 1 {
        return Ok(rows
            .iter()
            .filter(|row| basename_paths.contains(row.path.as_str()))
            .collect());
    }
    if basename_paths.len() > 1 {
        let candidates = basename_paths
            .iter()
            .take(5)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        bail!("ambiguous source path {requested_path}; candidates: {candidates}");
    }

    bail!("source breakpoints currently support the target executable only");
}

fn load_dwarf_section(
    object: &object::File<'_>,
    name: &str,
    endian: RunTimeEndian,
) -> std::result::Result<SourceDwarfReader, gimli::Error> {
    let data = match object.section_by_name(name) {
        Some(section) => section.data().map_err(|_| gimli::Error::Io)?,
        None => &[],
    };
    let data: Rc<[u8]> = Rc::from(data);
    Ok(EndianRcSlice::new(data, endian))
}

fn runtime_addr_to_source_relative_addr(runtime_addr: u64, load_base: u64) -> Option<u64> {
    if load_base == 0 {
        Some(runtime_addr)
    } else {
        runtime_addr.checked_sub(load_base)
    }
}

fn return_address_source_lookup_addr(relative_addr: u64) -> u64 {
    relative_addr.saturating_sub(1)
}

#[derive(Debug, Clone)]
pub struct TargetSymbolizer {
    process: ProcessSymbolizer,
}

impl TargetSymbolizer {
    pub fn from_process(pid: Pid, program_path: &str) -> Result<Self> {
        let symbols = main_executable_runtime_symbols(pid, program_path)?;
        Ok(Self {
            process: ProcessSymbolizer::from_runtime_symbols(symbols),
        })
    }

    pub fn from_runtime_symbols(symbols: Vec<RuntimeSymbol>) -> Self {
        Self {
            process: ProcessSymbolizer::from_runtime_symbols(symbols),
        }
    }

    pub fn symbolize(&self, addr: u64) -> Option<SymbolizedAddress> {
        self.process.symbolize(addr)
    }
}

fn main_executable_runtime_symbols(pid: Pid, program_path: &str) -> Result<Vec<RuntimeSymbol>> {
    let object_path =
        canonical_path_string(program_path).unwrap_or_else(|| program_path.to_string());
    let object_name = object_name(&object_path);
    let elf_symbols = heapify_elf::list_symbols(program_path)?;
    let load_base = if heapify_elf::is_pie(program_path)? {
        let mapping = find_executable_mapping(pid, program_path)?.with_context(|| {
            format!("failed to find executable mapping for PIE target: {program_path}")
        })?;
        mapping_load_base(&mapping)?
    } else {
        0
    };

    let mut symbols = Vec::new();
    for symbol in elf_symbols {
        let runtime_addr = load_base
            .checked_add(symbol.addr)
            .with_context(|| format!("runtime symbol address overflow for {}", symbol.name))?;
        symbols.push(RuntimeSymbol {
            object_path: object_path.clone(),
            object_name: object_name.clone(),
            name: symbol.name,
            runtime_addr,
            size: symbol.size,
            is_main_object: true,
        });
    }

    Ok(symbols)
}

fn runtime_objects_from_mappings(
    mappings: &[MemoryMapping],
    program_path: &str,
) -> Result<Vec<RuntimeObject>> {
    let canonical_program = canonical_path_string(program_path);
    let mut seen = HashSet::new();
    let mut objects = Vec::new();

    for mapping in mappings {
        if !is_executable_file_mapping(mapping) {
            continue;
        }

        let Some(path) = mapping.pathname.as_deref() else {
            continue;
        };
        let Some(canonical_path) = canonical_path_string(path) else {
            continue;
        };
        let Ok(load_base) = mapping_load_base(mapping) else {
            continue;
        };
        if !seen.insert((canonical_path.clone(), load_base)) {
            continue;
        }

        let is_main_object = canonical_program.as_deref() == Some(canonical_path.as_str());
        objects.push(RuntimeObject {
            object_name: object_name(&canonical_path),
            path: canonical_path,
            load_base,
            is_main_object,
        });
    }

    Ok(objects)
}

fn is_executable_file_mapping(mapping: &MemoryMapping) -> bool {
    if !mapping.permissions.contains('x') {
        return false;
    }

    let Some(pathname) = mapping.pathname.as_deref() else {
        return false;
    };
    if !pathname.starts_with('/') {
        return false;
    }

    std::fs::metadata(pathname)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

fn canonical_path_string(path: &str) -> Option<String> {
    std::fs::canonicalize(path)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn object_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

pub fn run(target: TargetCommand) -> Result<()> {
    match unsafe { fork() }.context("failed to fork target process")? {
        ForkResult::Child => run_child(target),
        ForkResult::Parent { child } => run_parent(child),
    }
}

pub fn run_with_breakpoint(target: TargetCommand, addr: u64) -> Result<()> {
    match unsafe { fork() }.context("failed to fork target process")? {
        ForkResult::Child => run_child(target),
        ForkResult::Parent { child } => run_parent_with_breakpoint(child, addr),
    }
}

pub fn run_with_symbol_breakpoint(target: TargetCommand, symbol_name: &str) -> Result<()> {
    match unsafe { fork() }.context("failed to fork target process")? {
        ForkResult::Child => run_child(target),
        ForkResult::Parent { child } => {
            run_parent_with_symbol_breakpoint(child, &target.program, symbol_name)
        }
    }
}

pub fn trace_heap<F>(program: &str, args: &[String], on_event: F) -> Result<()>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<()>,
{
    trace_heap_with_status(program, args, on_event, true)
}

pub fn trace_heap_with_status<F>(
    program: &str,
    args: &[String],
    on_event: F,
    show_status: bool,
) -> Result<()>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<()>,
{
    trace_heap_with_status_and_mode(
        program,
        args,
        on_event,
        show_status,
        AllocationTraceMode::TargetPlt,
    )
}

pub fn trace_heap_with_status_and_mode<F>(
    program: &str,
    args: &[String],
    on_event: F,
    show_status: bool,
    trace_mode: AllocationTraceMode,
) -> Result<()>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<()>,
{
    trace_heap_with_status_mode_and_session(
        program,
        args,
        on_event,
        |_| Ok(()),
        show_status,
        trace_mode,
    )
}

pub fn trace_heap_with_status_mode_and_session<F, S>(
    program: &str,
    args: &[String],
    on_event: F,
    on_session: S,
    show_status: bool,
    trace_mode: AllocationTraceMode,
) -> Result<()>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<()>,
    S: FnMut(TraceSessionContext) -> Result<()>,
{
    trace_heap_with_status_mode_profile_and_session(
        program,
        args,
        on_event,
        on_session,
        show_status,
        trace_mode,
        GLIBC_X86_64_MODERN.name,
        None,
        None,
        None,
        None,
        None,
        false,
        Vec::new(),
        Vec::new(),
        StdinConfig::Inherit,
    )
}

pub fn trace_heap_with_status_mode_profile_and_session<F, S>(
    program: &str,
    args: &[String],
    on_event: F,
    on_session: S,
    show_status: bool,
    trace_mode: AllocationTraceMode,
    glibc_profile_request: &str,
    supplied_libc_path: Option<&Path>,
    loader_path: Option<&Path>,
    library_path: Option<&Path>,
    preload_path: Option<&Path>,
    cwd: Option<&Path>,
    clear_env: bool,
    set_env: Vec<(String, String)>,
    unset_env: Vec<String>,
    stdin: StdinConfig,
) -> Result<()>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<()>,
    S: FnMut(TraceSessionContext) -> Result<()>,
{
    let mut on_event = on_event;
    let on_event_control = move |event, context| {
        on_event(event, context)?;
        Ok(AllocatorEventControl::Continue)
    };
    trace_heap_with_status_mode_profile_session_control(
        program,
        args,
        on_event_control,
        on_session,
        show_status,
        trace_mode,
        glibc_profile_request,
        supplied_libc_path,
        loader_path,
        library_path,
        preload_path,
        cwd,
        clear_env,
        set_env,
        unset_env,
        stdin,
        || None,
        |_, _, _, _, _| Ok(()),
        |_, _, _, _| Ok(()),
        |_| Ok(()),
        |_, _, _| Ok(()),
        |_, _| Ok(()),
        TraceWaitMode::Blocking,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn trace_heap_with_status_mode_profile_session_live_control<F, S, C, T, R, U, I, M>(
    program: &str,
    args: &[String],
    on_event: F,
    on_session: S,
    show_status: bool,
    trace_mode: AllocationTraceMode,
    glibc_profile_request: &str,
    supplied_libc_path: Option<&Path>,
    loader_path: Option<&Path>,
    library_path: Option<&Path>,
    preload_path: Option<&Path>,
    cwd: Option<&Path>,
    clear_env: bool,
    set_env: Vec<(String, String)>,
    unset_env: Vec<String>,
    stdin: StdinConfig,
    poll_control: C,
    on_control_status: T,
    on_register_snapshot: R,
    on_user_breakpoints: U,
    on_code_inspection: I,
    on_memory_inspection: M,
) -> Result<()>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
    S: FnMut(TraceSessionContext) -> Result<()>,
    C: FnMut() -> Option<LiveCommandMessage>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    U: FnMut(Vec<UserBreakpoint>) -> Result<()>,
    I: FnMut(u64, Option<UserBreakpointId>, Pid) -> Result<()>,
    M: FnMut(MemoryInspectionRequest, Pid) -> Result<()>,
{
    trace_heap_with_status_mode_profile_session_control(
        program,
        args,
        on_event,
        on_session,
        show_status,
        trace_mode,
        glibc_profile_request,
        supplied_libc_path,
        loader_path,
        library_path,
        preload_path,
        cwd,
        clear_env,
        set_env,
        unset_env,
        stdin,
        poll_control,
        on_control_status,
        on_register_snapshot,
        on_user_breakpoints,
        on_code_inspection,
        on_memory_inspection,
        TraceWaitMode::Controlled,
    )
}

#[allow(clippy::too_many_arguments)]
fn trace_heap_with_status_mode_profile_session_control<F, S, C, T, R, U, I, M>(
    program: &str,
    args: &[String],
    on_event: F,
    on_session: S,
    show_status: bool,
    trace_mode: AllocationTraceMode,
    glibc_profile_request: &str,
    supplied_libc_path: Option<&Path>,
    loader_path: Option<&Path>,
    library_path: Option<&Path>,
    preload_path: Option<&Path>,
    cwd: Option<&Path>,
    clear_env: bool,
    set_env: Vec<(String, String)>,
    unset_env: Vec<String>,
    stdin: StdinConfig,
    poll_control: C,
    on_control_status: T,
    on_register_snapshot: R,
    on_user_breakpoints: U,
    on_code_inspection: I,
    on_memory_inspection: M,
    wait_mode: TraceWaitMode,
) -> Result<()>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
    S: FnMut(TraceSessionContext) -> Result<()>,
    C: FnMut() -> Option<LiveCommandMessage>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    U: FnMut(Vec<UserBreakpoint>) -> Result<()>,
    I: FnMut(u64, Option<UserBreakpointId>, Pid) -> Result<()>,
    M: FnMut(MemoryInspectionRequest, Pid) -> Result<()>,
{
    let launch_config = LaunchConfig {
        target_program: PathBuf::from(program),
        target_args: args.to_vec(),
        loader_path: loader_path.map(Path::to_path_buf),
        library_path: library_path.map(Path::to_path_buf),
        preload_path: preload_path.map(Path::to_path_buf),
        supplied_libc_path: supplied_libc_path.map(Path::to_path_buf),
        cwd: cwd.map(Path::to_path_buf),
        clear_env,
        set_env,
        unset_env,
        stdin,
    };
    let exec_plan = build_exec_plan(&launch_config)?;
    let glibc_profile_request = glibc_profile_request.to_string();
    let supplied_libc_path = supplied_libc_path.map(Path::to_path_buf);
    let stdin_pipe = StdinTextPipe::from_plan(&exec_plan)?;
    match unsafe { fork() }.context("failed to fork target process")? {
        ForkResult::Child => {
            if let Some(pipe) = stdin_pipe {
                pipe.close_write();
                run_child_exec_plan(exec_plan, Some(pipe.read_fd))
            } else {
                run_child_exec_plan(exec_plan, None)
            }
        }
        ForkResult::Parent { child } => {
            let stdin_writer = stdin_pipe
                .map(|pipe| pipe.spawn_writer(&exec_plan.stdin))
                .transpose()?;
            run_parent_trace_heap(
                child,
                exec_plan,
                trace_mode,
                glibc_profile_request,
                supplied_libc_path,
                on_event,
                on_session,
                show_status,
                stdin_writer,
                poll_control,
                on_control_status,
                on_register_snapshot,
                on_user_breakpoints,
                on_code_inspection,
                on_memory_inspection,
                wait_mode,
            )
        }
    }
}

fn run_child_exec_plan(plan: ExecPlan, stdin_text_read_fd: Option<RawFd>) -> Result<()> {
    ptrace::traceme().context("failed to request tracing in child")?;

    if let Some(cwd) = plan.cwd.as_ref() {
        std::env::set_current_dir(cwd)
            .with_context(|| format!("failed to change cwd to {}", cwd.display()))?;
    }
    if plan.clear_env {
        let keys = std::env::vars_os().map(|(key, _)| key).collect::<Vec<_>>();
        for key in keys {
            std::env::remove_var(key);
        }
    }
    for key in plan.env_unsets {
        std::env::remove_var(key);
    }
    for (key, value) in plan.env_overrides {
        std::env::set_var(key, value);
    }
    apply_child_stdin(&plan.stdin, stdin_text_read_fd)?;

    let program = CString::new(plan.exec_program.to_string_lossy().into_owned())
        .context("exec program contains a nul byte")?;
    let argv = plan
        .exec_args
        .iter()
        .map(|arg| CString::new(arg.as_str()).context("argument contains a nul byte"))
        .collect::<Result<Vec<_>>>()?;
    let argv_refs = argv.iter().map(|arg| arg.as_c_str()).collect::<Vec<_>>();
    execvp(&program, &argv_refs).context("failed to exec target program")?;

    unreachable!("execvp only returns on error");
}

struct StdinTextPipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl StdinTextPipe {
    fn from_plan(plan: &ExecPlan) -> Result<Option<Self>> {
        if !matches!(plan.stdin, StdinConfig::Text(_)) {
            return Ok(None);
        }

        let mut fds = [0; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("failed to create stdin pipe");
        }
        Ok(Some(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        }))
    }

    fn close_write(&self) {
        close_fd(self.write_fd);
    }

    fn spawn_writer(self, stdin: &StdinConfig) -> Result<JoinHandle<Result<()>>> {
        close_fd(self.read_fd);
        let StdinConfig::Text(text) = stdin else {
            bail!("stdin text pipe requested for non-text stdin plan");
        };
        let bytes = text.as_bytes().to_vec();
        Ok(std::thread::spawn(move || {
            write_all_to_fd(self.write_fd, &bytes)
        }))
    }
}

fn apply_child_stdin(stdin: &StdinConfig, stdin_text_read_fd: Option<RawFd>) -> Result<()> {
    match stdin {
        StdinConfig::Inherit => Ok(()),
        StdinConfig::File(path) => {
            let file = std::fs::File::open(path)
                .with_context(|| format!("failed to open stdin file {}", path.display()))?;
            dup2_to_stdin(file.as_raw_fd()).context("failed to redirect stdin from file")
        }
        StdinConfig::Text(_) => {
            let read_fd = stdin_text_read_fd.context("missing stdin text pipe read fd")?;
            dup2_to_stdin(read_fd).context("failed to redirect stdin from text pipe")?;
            close_fd(read_fd);
            Ok(())
        }
    }
}

fn dup2_to_stdin(fd: RawFd) -> Result<()> {
    if unsafe { libc::dup2(fd, libc::STDIN_FILENO) } < 0 {
        return Err(std::io::Error::last_os_error()).context("dup2 failed");
    }
    Ok(())
}

fn write_all_to_fd(fd: RawFd, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EPIPE) => {
                    close_fd(fd);
                    return Ok(());
                }
                _ => {
                    close_fd(fd);
                    return Err(err).context("failed to write stdin text");
                }
            }
        }
        bytes = &bytes[written as usize..];
    }
    close_fd(fd);
    Ok(())
}

fn close_fd(fd: RawFd) {
    let _ = unsafe { libc::close(fd) };
}

fn finish_stdin_writer(stdin_writer: Option<JoinHandle<Result<()>>>) -> Result<()> {
    if let Some(writer) = stdin_writer {
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("stdin writer thread panicked"))??;
    }
    Ok(())
}

fn run_child(target: TargetCommand) -> Result<()> {
    ptrace::traceme().context("failed to request tracing in child")?;

    let program = CString::new(target.program.clone()).context("program contains a nul byte")?;
    let mut argv = Vec::with_capacity(target.args.len() + 1);
    argv.push(program.clone());

    for arg in target.args {
        argv.push(CString::new(arg).context("argument contains a nul byte")?);
    }

    let argv_refs = argv.iter().map(|arg| arg.as_c_str()).collect::<Vec<_>>();
    execvp(&program, &argv_refs).context("failed to exec target program")?;

    unreachable!("execvp only returns on error");
}

fn run_parent_trace_heap<F, C, T, R, I, M>(
    child: Pid,
    exec_plan: ExecPlan,
    trace_mode: AllocationTraceMode,
    glibc_profile_request: String,
    supplied_libc_path: Option<PathBuf>,
    on_event: F,
    mut on_session: impl FnMut(TraceSessionContext) -> Result<()>,
    show_status: bool,
    mut stdin_writer: Option<JoinHandle<Result<()>>>,
    mut poll_control: C,
    mut on_control_status: T,
    mut on_register_snapshot: R,
    mut on_user_breakpoints: impl FnMut(Vec<UserBreakpoint>) -> Result<()>,
    mut on_code_inspection: I,
    mut on_memory_inspection: M,
    wait_mode: TraceWaitMode,
) -> Result<()>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
    C: FnMut() -> Option<LiveCommandMessage>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    I: FnMut(u64, Option<UserBreakpointId>, Pid) -> Result<()>,
    M: FnMut(MemoryInspectionRequest, Pid) -> Result<()>,
{
    wait_for_initial_stop_with_status(child, show_status)?;
    let program_path = exec_plan
        .target_program_for_symbols
        .to_string_lossy()
        .into_owned();
    if trace_mode == AllocationTraceMode::LibcSymbols {
        stop_at_target_entry_if_needed(child, &program_path, show_status)?;
    }

    let libc_metadata =
        detect_libc_metadata_with_supplied(child, supplied_libc_path.as_deref()).unwrap_or(None);
    let (glibc_profile, glibc_profile_selection) = select_glibc_profile(
        &glibc_profile_request,
        libc_metadata
            .as_ref()
            .and_then(|metadata| metadata.version.as_deref()),
        libc_metadata
            .as_ref()
            .map(|metadata| Path::new(metadata.path.as_str())),
        supplied_libc_path.as_deref(),
    )?;
    if show_status {
        print_trace_session_profile_selection(&glibc_profile_selection);
        print_launch_metadata(&exec_plan);
        if let Some(libc_metadata) = libc_metadata.as_ref() {
            print_libc_metadata(libc_metadata);
        }
    }
    let (process_maps, process_maps_error) = match read_process_maps_snapshot(child) {
        Ok(snapshot) => (Some(snapshot), None),
        Err(err) => (None, Some(err.to_string())),
    };
    on_session(TraceSessionContext {
        pid: child,
        libc: libc_metadata.clone(),
        glibc_profile,
        glibc_profile_selection: glibc_profile_selection.clone(),
        launch: exec_plan.clone(),
        process_maps,
        process_maps_error,
    })?;

    let symbols = resolve_allocation_symbols(
        child,
        &program_path,
        trace_mode,
        supplied_libc_path.as_deref(),
    )?;
    let malloc = symbols.malloc;
    let free = symbols.free;
    let calloc = symbols.calloc;
    let realloc = symbols.realloc;

    if malloc.is_none() && free.is_none() && calloc.is_none() && realloc.is_none() {
        bail!("malloc/free/calloc/realloc symbols not found");
    }

    if show_status {
        if let Some((malloc_name, malloc_addr)) = &malloc {
            println!("[heapify] symbol {malloc_name} = 0x{malloc_addr:x}");
        }
        if let Some((free_name, free_addr)) = &free {
            println!("[heapify] symbol {free_name} = 0x{free_addr:x}");
        }
        if let Some((calloc_name, calloc_addr)) = &calloc {
            println!("[heapify] symbol {calloc_name} = 0x{calloc_addr:x}");
        }
        if let Some((realloc_name, realloc_addr)) = &realloc {
            println!("[heapify] symbol {realloc_name} = 0x{realloc_addr:x}");
        }
    }

    let mut breakpoints = BreakpointManager::default();
    let mut state = TraceHeapState::new(
        on_event,
        show_status,
        libc_metadata,
        supplied_libc_path,
        glibc_profile,
    );
    try_print_heap_mapping(child, &mut state);
    let malloc_addr = malloc.map(|(_, addr)| addr);
    let free_addr = free.map(|(_, addr)| addr);
    let calloc_addr = calloc.map(|(_, addr)| addr);
    let realloc_addr = realloc.map(|(_, addr)| addr);
    if let Some(malloc_addr) = malloc_addr {
        breakpoints.set_breakpoint(child, malloc_addr, BreakpointKind::MallocEntry)?;
        if show_status {
            println!("breakpoint set at malloc 0x{malloc_addr:x}");
        }
    }

    if let Some(free_addr) = free_addr {
        breakpoints.set_breakpoint(child, free_addr, BreakpointKind::FreeEntry)?;
        if show_status {
            println!("breakpoint set at free 0x{free_addr:x}");
        }
    }
    if let Some(calloc_addr) = calloc_addr {
        breakpoints.set_breakpoint(child, calloc_addr, BreakpointKind::CallocEntry)?;
        if show_status {
            println!("breakpoint set at calloc 0x{calloc_addr:x}");
        }
    }
    if let Some(realloc_addr) = realloc_addr {
        breakpoints.set_breakpoint(child, realloc_addr, BreakpointKind::ReallocEntry)?;
        if show_status {
            println!("breakpoint set at realloc 0x{realloc_addr:x}");
        }
    }

    ptrace::cont(child, None).context("failed to continue child")?;

    let mut paused = false;
    let mut pause_requested = false;
    let mut run_mode = LiveTraceRunMode::Continuous;
    let mut target_status = LiveTargetStatus::Running;
    let mut pending_pause_command_id = None;
    let mut pending_step_command_id = None;
    let mut pending_nexti = None;
    let mut pending_source_step: Option<SourceStepState> = None;
    let mut stop_requested_at = None;
    loop {
        if matches!(wait_mode, TraceWaitMode::Controlled) {
            if handle_live_trace_controls(
                child,
                &mut poll_control,
                &mut on_control_status,
                &mut paused,
                &mut pause_requested,
                &mut run_mode,
                &mut target_status,
                &mut pending_pause_command_id,
                &mut pending_step_command_id,
                &mut pending_nexti,
                &mut pending_source_step,
                &mut stop_requested_at,
                &mut breakpoints,
                &mut state,
                &program_path,
                &mut on_register_snapshot,
                &mut on_user_breakpoints,
                &mut on_code_inspection,
                &mut on_memory_inspection,
            )? == LiveControlOutcome::TargetExited
            {
                print_missing_libc_metadata_at_trace_end(&mut state);
                finish_stdin_writer(stdin_writer.take())?;
                return Ok(());
            }
            if paused {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
        }

        let wait_flags = match wait_mode {
            TraceWaitMode::Blocking => None,
            TraceWaitMode::Controlled => Some(WaitPidFlag::WNOHANG),
        };

        match waitpid(child, wait_flags).context("failed waiting for child status")? {
            WaitStatus::StillAlive => {
                if let Some(requested_at) = stop_requested_at {
                    if requested_at.elapsed() >= Duration::from_secs(2) {
                        send_signal_best_effort(child, Signal::SIGKILL);
                        target_status = LiveTargetStatus::Stopping;
                        on_control_status(
                            None,
                            None,
                            LiveCommandStatus::Completed,
                            target_status,
                            "stop grace period elapsed; sent SIGKILL".to_string(),
                        )?;
                        stop_requested_at = None;
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            WaitStatus::Exited(pid, code) if pid == child => {
                print_missing_libc_metadata_at_trace_end(&mut state);
                finish_stdin_writer(stdin_writer.take())?;
                if show_status {
                    println!("child exited with status {code}");
                }
                target_status = LiveTargetStatus::Exited;
                on_control_status(
                    None,
                    None,
                    LiveCommandStatus::Completed,
                    target_status,
                    format!("target exited with status {code}"),
                )?;
                return Ok(());
            }
            WaitStatus::Signaled(pid, signal, _) if pid == child => {
                print_missing_libc_metadata_at_trace_end(&mut state);
                finish_stdin_writer(stdin_writer.take())?;
                if show_status {
                    println!("child terminated by signal {signal:?}");
                }
                target_status = LiveTargetStatus::Exited;
                on_control_status(
                    None,
                    None,
                    LiveCommandStatus::Completed,
                    target_status,
                    format!("target terminated by signal {signal:?}"),
                )?;
                return Ok(());
            }
            WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {
                let hit_addr = ptrace::getregs(child)
                    .ok()
                    .map(|regs| regs.rip.saturating_sub(1));
                if pending_nexti
                    .zip(hit_addr)
                    .map(|(pending, hit_addr)| {
                        pending.breakpoint_addr == hit_addr
                            && breakpoints.user_step_over_owner(hit_addr).is_some()
                    })
                    .unwrap_or(false)
                {
                    let pending = pending_nexti.take().unwrap();
                    handle_user_step_over_breakpoint_hit(
                        child,
                        &mut breakpoints,
                        pending,
                        &mut on_register_snapshot,
                        &mut on_control_status,
                    )?;
                    run_mode = LiveTraceRunMode::Continuous;
                    paused = true;
                    pause_requested = false;
                    target_status = LiveTargetStatus::Paused;
                    continue;
                }

                if let Some(hit_addr) = hit_addr {
                    let user_breakpoint_ids = breakpoints.persistent_user_owners_at(hit_addr);
                    if !user_breakpoint_ids.is_empty() {
                        let emitted_allocator_event =
                            if breakpoints.allocator_owner(hit_addr).is_some() {
                                handle_managed_breakpoint_hit(child, &mut breakpoints, &mut state)?
                            } else {
                                handle_persistent_user_breakpoint_step_over(
                                    child,
                                    &mut breakpoints,
                                    hit_addr,
                                )?;
                                None
                            };
                        if let Some((event_id, _)) = emitted_allocator_event {
                            emit_register_snapshot_best_effort(
                                child,
                                Some(event_id),
                                &mut on_register_snapshot,
                                &mut on_control_status,
                                target_status,
                            )?;
                        }
                        let hit_breakpoints =
                            breakpoints.record_user_breakpoint_hits(&user_breakpoint_ids);
                        on_user_breakpoints(breakpoints.list_user_breakpoints())?;
                        if let Some(primary) = hit_breakpoints.first() {
                            for extra in hit_breakpoints.iter().skip(1) {
                                on_control_status(
                                    None,
                                    None,
                                    LiveCommandStatus::Completed,
                                    LiveTargetStatus::Paused,
                                    format!(
                                        "breakpoint {} also hit at {}",
                                        extra.id.as_u64(),
                                        extra.location_line()
                                    ),
                                )?;
                            }
                            let message = format!(
                                "breakpoint {} hit at {}",
                                primary.id.as_u64(),
                                primary.location_line()
                            );
                            run_mode = LiveTraceRunMode::Continuous;
                            pending_source_step = None;
                            pending_step_command_id.take();
                            paused = true;
                            pause_requested = false;
                            target_status = LiveTargetStatus::Paused;
                            emit_register_snapshot_best_effort(
                                child,
                                None,
                                &mut on_register_snapshot,
                                &mut on_control_status,
                                target_status,
                            )?;
                            on_control_status(
                                None,
                                None,
                                LiveCommandStatus::Completed,
                                target_status,
                                message,
                            )?;
                            continue;
                        }
                    }
                }

                let emitted_allocator_event =
                    handle_managed_breakpoint_hit(child, &mut breakpoints, &mut state)?;
                if let Some((event_id, _)) = emitted_allocator_event {
                    emit_register_snapshot_best_effort(
                        child,
                        Some(event_id),
                        &mut on_register_snapshot,
                        &mut on_control_status,
                        target_status,
                    )?;
                }
                if matches!(wait_mode, TraceWaitMode::Controlled) {
                    if let Some((event_id, event_control)) = emitted_allocator_event {
                        if should_pause_after_allocator_event(run_mode, event_control) {
                            let break_pause = event_control == AllocatorEventControl::Pause;
                            run_mode = LiveTraceRunMode::Continuous;
                            paused = true;
                            pause_requested = false;
                            target_status = LiveTargetStatus::Paused;
                            if !break_pause {
                                on_control_status(
                                    pending_step_command_id.take(),
                                    Some(LiveCommand::StepAllocatorEvent),
                                    LiveCommandStatus::Completed,
                                    target_status,
                                    format!("paused after allocator event #{event_id}"),
                                )?;
                            } else {
                                pending_step_command_id.take();
                                if let Some(pending) = pending_nexti.take() {
                                    breakpoints.remove_user_step_over_breakpoint(
                                        child,
                                        pending.breakpoint_addr,
                                    )?;
                                    on_control_status(
                                        Some(pending.command_id),
                                        Some(LiveCommand::StepInstructionOver),
                                        LiveCommandStatus::Failed,
                                        target_status,
                                        format!("nexti interrupted: break condition matched after event #{event_id}"),
                                    )?;
                                }
                                pending_source_step = None;
                            }
                        }
                    }
                    if handle_live_trace_controls(
                        child,
                        &mut poll_control,
                        &mut on_control_status,
                        &mut paused,
                        &mut pause_requested,
                        &mut run_mode,
                        &mut target_status,
                        &mut pending_pause_command_id,
                        &mut pending_step_command_id,
                        &mut pending_nexti,
                        &mut pending_source_step,
                        &mut stop_requested_at,
                        &mut breakpoints,
                        &mut state,
                        &program_path,
                        &mut on_register_snapshot,
                        &mut on_user_breakpoints,
                        &mut on_code_inspection,
                        &mut on_memory_inspection,
                    )? == LiveControlOutcome::TargetExited
                    {
                        print_missing_libc_metadata_at_trace_end(&mut state);
                        finish_stdin_writer(stdin_writer.take())?;
                        return Ok(());
                    }
                }
                if !paused {
                    ptrace::cont(child, None)
                        .context("failed to continue child after breakpoint")?;
                }
            }
            WaitStatus::Stopped(pid, Signal::SIGSTOP) if pid == child && pause_requested => {
                pause_requested = false;
                paused = true;
                target_status = LiveTargetStatus::Paused;
                on_control_status(
                    pending_pause_command_id.take(),
                    Some(LiveCommand::Pause),
                    LiveCommandStatus::Completed,
                    target_status,
                    "target paused; inspect panes or resume".to_string(),
                )?;
                emit_register_snapshot_best_effort(
                    child,
                    None,
                    &mut on_register_snapshot,
                    &mut on_control_status,
                    target_status,
                )?;
            }
            WaitStatus::Stopped(pid, signal) if pid == child => {
                if signal == Signal::SIGSTOP && matches!(wait_mode, TraceWaitMode::Controlled) {
                    paused = true;
                    target_status = LiveTargetStatus::Paused;
                    on_control_status(
                        pending_pause_command_id.take(),
                        Some(LiveCommand::Pause),
                        LiveCommandStatus::Completed,
                        target_status,
                        "target paused; inspect panes or resume".to_string(),
                    )?;
                    emit_register_snapshot_best_effort(
                        child,
                        None,
                        &mut on_register_snapshot,
                        &mut on_control_status,
                        target_status,
                    )?;
                } else if let Some(pending) = pending_nexti.take() {
                    breakpoints.remove_user_step_over_breakpoint(child, pending.breakpoint_addr)?;
                    paused = true;
                    target_status = LiveTargetStatus::Paused;
                    emit_register_snapshot_best_effort(
                        child,
                        None,
                        &mut on_register_snapshot,
                        &mut on_control_status,
                        target_status,
                    )?;
                    on_control_status(
                        Some(pending.command_id),
                        Some(LiveCommand::StepInstructionOver),
                        LiveCommandStatus::Failed,
                        target_status,
                        format_instruction_step_signal(
                            signal,
                            read_register_snapshot(child)
                                .ok()
                                .map(|snapshot| snapshot.instruction_pointer),
                        ),
                    )?;
                } else {
                    pending_source_step = None;
                    ptrace::cont(child, signal_to_deliver(signal))
                        .with_context(|| format!("failed to continue child after {signal:?}"))?;
                }
            }
            WaitStatus::PtraceEvent(pid, signal, _) if pid == child => {
                ptrace::cont(child, signal_to_deliver(signal)).with_context(|| {
                    format!("failed to continue child after ptrace event {signal:?}")
                })?;
            }
            WaitStatus::PtraceSyscall(pid) if pid == child => {
                ptrace::cont(child, None).context("failed to continue child after syscall stop")?;
            }
            status => bail!("unexpected child wait status: {status:?}"),
        }
    }
}

fn handle_live_trace_controls<C, T, R, U, I, M, F>(
    child: Pid,
    poll_control: &mut C,
    on_control_status: &mut T,
    paused: &mut bool,
    pause_requested: &mut bool,
    run_mode: &mut LiveTraceRunMode,
    target_status: &mut LiveTargetStatus,
    pending_pause_command_id: &mut Option<LiveCommandId>,
    pending_step_command_id: &mut Option<LiveCommandId>,
    pending_nexti: &mut Option<PendingInstructionStepOver>,
    pending_source_step: &mut Option<SourceStepState>,
    stop_requested_at: &mut Option<Instant>,
    breakpoints: &mut BreakpointManager,
    state: &mut TraceHeapState<F>,
    program_path: &str,
    on_register_snapshot: &mut R,
    on_user_breakpoints: &mut U,
    on_code_inspection: &mut I,
    on_memory_inspection: &mut M,
) -> Result<LiveControlOutcome>
where
    C: FnMut() -> Option<LiveCommandMessage>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    U: FnMut(Vec<UserBreakpoint>) -> Result<()>,
    I: FnMut(u64, Option<UserBreakpointId>, Pid) -> Result<()>,
    M: FnMut(MemoryInspectionRequest, Pid) -> Result<()>,
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    while let Some(message) = poll_control() {
        let command = message.command.clone();
        if let Err(reason) = validate_live_command(*target_status, command.clone()) {
            on_control_status(
                Some(message.id),
                Some(command.clone()),
                LiveCommandStatus::Rejected,
                *target_status,
                reason,
            )?;
            continue;
        }

        match command.clone() {
            LiveCommand::InspectCodeAt {
                address,
                breakpoint_id,
            } => {
                let pause_state = LiveWorkerPauseState {
                    ptrace_stopped: *paused,
                    user_visible_paused: *target_status == LiveTargetStatus::Paused,
                    step_in_flight: None,
                    temporary_return_breakpoint_in_flight: breakpoints
                        .has_temporary_return_breakpoints(),
                    managed_breakpoints_rearmed: breakpoints.all_breakpoints_rearmed(),
                };
                if let Err(reason) = pause_state.can_user_step_instruction() {
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Rejected,
                        *target_status,
                        reason,
                    )?;
                    continue;
                }
                on_control_status(
                    Some(message.id),
                    Some(command.clone()),
                    LiveCommandStatus::Accepted,
                    *target_status,
                    format!("inspecting code at 0x{address:x}"),
                )?;
                match on_code_inspection(address, breakpoint_id, child) {
                    Ok(()) => on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Completed,
                        *target_status,
                        match breakpoint_id {
                            Some(id) => {
                                format!("inspecting breakpoint {} at 0x{address:x}", id.as_u64())
                            }
                            None => format!("inspecting code at 0x{address:x}"),
                        },
                    )?,
                    Err(err) => on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Failed,
                        *target_status,
                        format!("code inspection failed: {err}"),
                    )?,
                }
            }
            LiveCommand::InspectMemory(request) => {
                let pause_state = LiveWorkerPauseState {
                    ptrace_stopped: *paused,
                    user_visible_paused: *target_status == LiveTargetStatus::Paused,
                    step_in_flight: None,
                    temporary_return_breakpoint_in_flight: breakpoints
                        .has_temporary_return_breakpoints(),
                    managed_breakpoints_rearmed: breakpoints.all_breakpoints_rearmed(),
                };
                if let Err(reason) = pause_state.can_user_step_instruction() {
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Rejected,
                        *target_status,
                        reason,
                    )?;
                    continue;
                }
                on_control_status(
                    Some(message.id),
                    Some(command.clone()),
                    LiveCommandStatus::Accepted,
                    *target_status,
                    format!("inspecting memory at 0x{:x}", request.address),
                )?;
                match on_memory_inspection(request.clone(), child) {
                    Ok(()) => on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Completed,
                        *target_status,
                        format!(
                            "inspected {} {} at 0x{:x}",
                            request.count,
                            match request.format {
                                MemoryViewFormat::HexWords => "words",
                                MemoryViewFormat::HexBytes => "bytes",
                            },
                            request.address
                        ),
                    )?,
                    Err(err) => on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Failed,
                        *target_status,
                        format!("memory inspection failed: {err}"),
                    )?,
                }
            }
            LiveCommand::AddUserBreakpointAddress(addr) => {
                let symbolizer = ProcessSymbolizer::from_process(child, program_path).ok();
                let source_mapper = TargetSourceMapper::from_process(child, program_path).ok();
                let (resolved_symbol, source) = symbolizer
                    .as_ref()
                    .map(|symbolizer| symbolizer.breakpoint_metadata(addr, source_mapper.as_ref()))
                    .unwrap_or_else(|| {
                        (
                            None,
                            source_mapper
                                .as_ref()
                                .and_then(|source_mapper| source_mapper.lookup(addr)),
                        )
                    });
                let label = resolved_symbol
                    .clone()
                    .unwrap_or_else(|| format!("0x{addr:x}"));
                let result = breakpoints.add_user_breakpoint(
                    child,
                    UserBreakpointSpec::Address(addr),
                    addr,
                    label,
                    resolved_symbol,
                    source,
                    None,
                );
                complete_breakpoint_management_command(
                    result,
                    message.id,
                    command,
                    *target_status,
                    breakpoints,
                    on_control_status,
                    on_user_breakpoints,
                    |breakpoint| {
                        format!(
                            "breakpoint {} set at {}",
                            breakpoint.id.as_u64(),
                            breakpoint.location_line()
                        )
                    },
                )?;
            }
            LiveCommand::AddUserBreakpointSymbol(symbol) => {
                let result = ProcessSymbolizer::from_process(child, program_path)
                    .and_then(|symbolizer| {
                        let source_mapper =
                            TargetSourceMapper::from_process(child, program_path).ok();
                        symbolizer.resolve_breakpoint_symbol(&symbol).map(
                            |(resolved_name, addr)| {
                                let (resolved_symbol, source) =
                                    symbolizer.breakpoint_metadata(addr, source_mapper.as_ref());
                                (resolved_name, addr, resolved_symbol, source)
                            },
                        )
                    })
                    .and_then(|(resolved_name, addr, resolved_symbol, source)| {
                        let label = resolved_symbol.clone().unwrap_or(resolved_name);
                        breakpoints.add_user_breakpoint(
                            child,
                            UserBreakpointSpec::Symbol(symbol),
                            addr,
                            label,
                            resolved_symbol,
                            source,
                            None,
                        )
                    });
                complete_breakpoint_management_command(
                    result,
                    message.id,
                    command,
                    *target_status,
                    breakpoints,
                    on_control_status,
                    on_user_breakpoints,
                    |breakpoint| {
                        format!(
                            "breakpoint {} set at {}",
                            breakpoint.id.as_u64(),
                            breakpoint.location_line()
                        )
                    },
                )?;
            }
            LiveCommand::AddUserBreakpointSourceLine { path, line } => {
                let result = target_runtime_load_bias(child, program_path)
                    .and_then(|load_bias| {
                        resolve_source_line_breakpoint(
                            Path::new(program_path),
                            load_bias,
                            &path,
                            line,
                        )
                    })
                    .and_then(|resolution| {
                        let symbolizer = ProcessSymbolizer::from_process(child, program_path).ok();
                        let source_mapper =
                            TargetSourceMapper::from_process(child, program_path).ok();
                        let (resolved_symbol, source) = symbolizer
                            .as_ref()
                            .map(|symbolizer| {
                                symbolizer.breakpoint_metadata(
                                    resolution.resolved_address,
                                    source_mapper.as_ref(),
                                )
                            })
                            .unwrap_or_else(|| {
                                (
                                    resolution.symbol.clone(),
                                    Some(SourceLocation {
                                        file: Some(resolution.resolved_path.clone()),
                                        line: u32::try_from(resolution.resolved_line).ok(),
                                        column: None,
                                    }),
                                )
                            });
                        let label = resolved_symbol.clone().unwrap_or_else(|| {
                            format!("{}:{}", resolution.resolved_path, resolution.resolved_line)
                        });
                        breakpoints.add_user_breakpoint(
                            child,
                            UserBreakpointSpec::SourceLine {
                                path: path.clone(),
                                line,
                            },
                            resolution.resolved_address,
                            label,
                            resolved_symbol.or_else(|| resolution.symbol.clone()),
                            source.or_else(|| {
                                Some(SourceLocation {
                                    file: Some(resolution.resolved_path.clone()),
                                    line: u32::try_from(resolution.resolved_line).ok(),
                                    column: None,
                                })
                            }),
                            Some(resolution),
                        )
                    });
                complete_breakpoint_management_command(
                    result,
                    message.id,
                    command,
                    *target_status,
                    breakpoints,
                    on_control_status,
                    on_user_breakpoints,
                    |breakpoint| {
                        let source = breakpoint
                            .source_summary()
                            .unwrap_or_else(|| breakpoint.label.clone());
                        format!(
                            "breakpoint {} set at 0x{:x} ({source})",
                            breakpoint.id.as_u64(),
                            breakpoint.resolved_address
                        )
                    },
                )?;
            }
            LiveCommand::DeleteUserBreakpoint(id) => {
                complete_breakpoint_management_command(
                    breakpoints.delete_user_breakpoint(child, id),
                    message.id,
                    command,
                    *target_status,
                    breakpoints,
                    on_control_status,
                    on_user_breakpoints,
                    |breakpoint| format!("breakpoint {} deleted", breakpoint.id.as_u64()),
                )?;
            }
            LiveCommand::EnableUserBreakpoint(id) => {
                complete_breakpoint_management_command(
                    breakpoints.enable_user_breakpoint(child, id),
                    message.id,
                    command,
                    *target_status,
                    breakpoints,
                    on_control_status,
                    on_user_breakpoints,
                    |breakpoint| format!("breakpoint {} enabled", breakpoint.id.as_u64()),
                )?;
            }
            LiveCommand::DisableUserBreakpoint(id) => {
                complete_breakpoint_management_command(
                    breakpoints.disable_user_breakpoint(child, id),
                    message.id,
                    command,
                    *target_status,
                    breakpoints,
                    on_control_status,
                    on_user_breakpoints,
                    |breakpoint| format!("breakpoint {} disabled", breakpoint.id.as_u64()),
                )?;
            }
            LiveCommand::Stop => {
                *run_mode = LiveTraceRunMode::Continuous;
                *pending_pause_command_id = None;
                *pending_step_command_id = None;
                if let Some(pending) = pending_nexti.take() {
                    let _ = breakpoints
                        .remove_user_step_over_breakpoint(child, pending.breakpoint_addr);
                }
                on_control_status(
                    Some(message.id),
                    Some(command.clone()),
                    LiveCommandStatus::Accepted,
                    *target_status,
                    "stop accepted".to_string(),
                )?;
                if stop_requested_at.is_none() {
                    send_signal_best_effort(child, Signal::SIGTERM);
                    *stop_requested_at = Some(Instant::now());
                    *target_status = LiveTargetStatus::Stopping;
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Completed,
                        *target_status,
                        "stopping target...".to_string(),
                    )?;
                }
                if *paused {
                    let _ = ptrace::cont(child, None);
                    *paused = false;
                    *pause_requested = false;
                }
            }
            LiveCommand::Pause => {
                *run_mode = LiveTraceRunMode::Continuous;
                send_signal_best_effort(child, Signal::SIGSTOP);
                *pause_requested = true;
                *pending_pause_command_id = Some(message.id);
                on_control_status(
                    Some(message.id),
                    Some(command.clone()),
                    LiveCommandStatus::Accepted,
                    *target_status,
                    "pause requested...".to_string(),
                )?;
            }
            LiveCommand::Resume => {
                *run_mode = LiveTraceRunMode::Continuous;
                if *paused {
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Accepted,
                        *target_status,
                        "resume accepted".to_string(),
                    )?;
                    match ptrace::cont(child, None) {
                        Ok(()) => {
                            *paused = false;
                            *pause_requested = false;
                            *target_status = LiveTargetStatus::Running;
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Completed,
                                *target_status,
                                "target running".to_string(),
                            )?;
                        }
                        Err(err) => {
                            *target_status = LiveTargetStatus::Paused;
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Failed,
                                *target_status,
                                format!("resume failed: {err}"),
                            )?;
                        }
                    }
                }
            }
            LiveCommand::Continue => {
                *run_mode = LiveTraceRunMode::Continuous;
                if let Some(pending) = pending_nexti.take() {
                    let _ = breakpoints
                        .remove_user_step_over_breakpoint(child, pending.breakpoint_addr);
                }
                on_control_status(
                    Some(message.id),
                    Some(command.clone()),
                    LiveCommandStatus::Accepted,
                    *target_status,
                    "continue accepted".to_string(),
                )?;
                if *paused {
                    match ptrace::cont(child, None) {
                        Ok(()) => {
                            *paused = false;
                            *pause_requested = false;
                            *target_status = LiveTargetStatus::Running;
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Completed,
                                *target_status,
                                "target running".to_string(),
                            )?;
                        }
                        Err(err) => {
                            *target_status = LiveTargetStatus::Paused;
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Failed,
                                *target_status,
                                format!("continue failed: {err}"),
                            )?;
                        }
                    }
                } else {
                    *target_status = LiveTargetStatus::Running;
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Completed,
                        *target_status,
                        "target running".to_string(),
                    )?;
                }
            }
            LiveCommand::StepAllocatorEvent => {
                if *paused {
                    match ptrace::cont(child, None) {
                        Ok(()) => {
                            *paused = false;
                            *pause_requested = false;
                            *run_mode = LiveTraceRunMode::StepAllocatorEvent;
                            *target_status = LiveTargetStatus::SteppingToNextAllocatorEvent;
                            *pending_step_command_id = Some(message.id);
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Accepted,
                                *target_status,
                                "stepping to next allocator event...".to_string(),
                            )?;
                        }
                        Err(err) => {
                            *target_status = LiveTargetStatus::Paused;
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Failed,
                                *target_status,
                                format!("step failed: {err}"),
                            )?;
                        }
                    }
                }
            }
            LiveCommand::SourceStep | LiveCommand::SourceStepOver => {
                let kind = if matches!(command, LiveCommand::SourceStepOver) {
                    SourceStepKind::Over
                } else {
                    SourceStepKind::Into
                };
                let status = if kind == SourceStepKind::Over {
                    LiveTargetStatus::SourceSteppingOver
                } else {
                    LiveTargetStatus::SourceStepping
                };
                let pause_state = LiveWorkerPauseState {
                    ptrace_stopped: *paused,
                    user_visible_paused: *target_status == LiveTargetStatus::Paused,
                    step_in_flight: None,
                    temporary_return_breakpoint_in_flight: breakpoints
                        .has_temporary_return_breakpoints(),
                    managed_breakpoints_rearmed: breakpoints.all_breakpoints_rearmed(),
                };
                if let Err(reason) = pause_state.can_user_step_instruction() {
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Rejected,
                        *target_status,
                        reason,
                    )?;
                    continue;
                }
                let snapshot = match read_register_snapshot(child) {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format!("source stepping failed: {err}"),
                        )?;
                        continue;
                    }
                };
                let rip = snapshot.instruction_pointer;
                let executable = find_executable_mapping(child, program_path)?;
                if !executable
                    .as_ref()
                    .map(|mapping| rip >= mapping.start && rip < mapping.end)
                    .unwrap_or(false)
                {
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Rejected,
                        *target_status,
                        "source stepping currently supports the target executable only".to_string(),
                    )?;
                    continue;
                }
                let source_mapper = match TargetSourceMapper::from_process(child, program_path) {
                    Ok(mapper) => mapper,
                    Err(_) => {
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Rejected,
                            *target_status,
                            "source stepping requires DWARF source information for the current target location".to_string(),
                        )?;
                        continue;
                    }
                };
                let origin = match source_mapper.lookup(rip) {
                    Some(source) => source,
                    None => {
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Rejected,
                            *target_status,
                            "source stepping requires DWARF source information for the current target location".to_string(),
                        )?;
                        continue;
                    }
                };
                *target_status = status;
                *run_mode = match kind {
                    SourceStepKind::Into => LiveTraceRunMode::SourceStepInto,
                    SourceStepKind::Over => LiveTraceRunMode::SourceStepOver,
                };
                *pending_source_step = Some(SourceStepState {
                    kind,
                    origin: origin.clone(),
                    origin_rip: rip,
                    instructions_executed: 0,
                    instruction_budget: DEFAULT_SOURCE_STEP_BUDGET,
                });
                on_control_status(
                    Some(message.id),
                    Some(command.clone()),
                    LiveCommandStatus::Accepted,
                    *target_status,
                    match kind {
                        SourceStepKind::Into => format!(
                            "stepping to next source location from {}",
                            format_source_location_short(&origin)
                        ),
                        SourceStepKind::Over => format!(
                            "stepping over to next source location from {}",
                            format_source_location_short(&origin)
                        ),
                    },
                )?;
                let result = run_source_step_to_completion(
                    child,
                    message.id,
                    command.clone(),
                    pending_source_step,
                    &source_mapper,
                    breakpoints,
                    state,
                    on_register_snapshot,
                    on_user_breakpoints,
                    on_control_status,
                )?;
                *paused = true;
                *pause_requested = false;
                *target_status = result;
                *run_mode = LiveTraceRunMode::Continuous;
            }
            LiveCommand::StepInstruction => {
                let pause_state = LiveWorkerPauseState {
                    ptrace_stopped: *paused,
                    user_visible_paused: *target_status == LiveTargetStatus::Paused,
                    step_in_flight: None,
                    temporary_return_breakpoint_in_flight: breakpoints
                        .has_temporary_return_breakpoints(),
                    managed_breakpoints_rearmed: breakpoints.all_breakpoints_rearmed(),
                };
                if let Err(reason) = pause_state.can_user_step_instruction() {
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Rejected,
                        *target_status,
                        reason,
                    )?;
                    continue;
                }

                let before_rip = read_register_snapshot(child)
                    .ok()
                    .map(|snapshot| snapshot.instruction_pointer);
                *target_status = LiveTargetStatus::SteppingInstruction;
                on_control_status(
                    Some(message.id),
                    Some(command.clone()),
                    LiveCommandStatus::Accepted,
                    *target_status,
                    match before_rip {
                        Some(rip) => format!("stepping instruction at RIP=0x{rip:x}"),
                        None => "stepping instruction at RIP=unknown".to_string(),
                    },
                )?;

                let step_kind = StepKind::UserInstructionStep;
                debug_assert_eq!(step_kind, StepKind::UserInstructionStep);
                match ptrace::step(child, None) {
                    Ok(()) => {}
                    Err(err) => {
                        *target_status = LiveTargetStatus::Paused;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format!("instruction step failed: {err}"),
                        )?;
                        continue;
                    }
                }

                match waitpid(child, None).context("failed waiting for instruction step stop")? {
                    WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {
                        *paused = true;
                        *target_status = LiveTargetStatus::Paused;
                        let after_rip = emit_register_snapshot_best_effort(
                            child,
                            None,
                            on_register_snapshot,
                            on_control_status,
                            *target_status,
                        )
                        .ok()
                        .and_then(|_| read_register_snapshot(child).ok())
                        .map(|snapshot| snapshot.instruction_pointer);
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Completed,
                            *target_status,
                            format_instruction_step_completed(before_rip, after_rip),
                        )?;
                    }
                    WaitStatus::Stopped(pid, signal) if pid == child => {
                        *paused = true;
                        *target_status = LiveTargetStatus::Paused;
                        let after_rip = emit_register_snapshot_best_effort(
                            child,
                            None,
                            on_register_snapshot,
                            on_control_status,
                            *target_status,
                        )
                        .ok()
                        .and_then(|_| read_register_snapshot(child).ok())
                        .map(|snapshot| snapshot.instruction_pointer);
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format_instruction_step_signal(signal, after_rip),
                        )?;
                    }
                    WaitStatus::Exited(pid, code) if pid == child => {
                        *paused = false;
                        *target_status = LiveTargetStatus::Exited;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Completed,
                            *target_status,
                            format!("target exited with status {code}"),
                        )?;
                        return Ok(LiveControlOutcome::TargetExited);
                    }
                    WaitStatus::Signaled(pid, signal, _) if pid == child => {
                        *paused = false;
                        *target_status = LiveTargetStatus::Exited;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Completed,
                            *target_status,
                            format!("target terminated by signal {signal:?}"),
                        )?;
                        return Ok(LiveControlOutcome::TargetExited);
                    }
                    status => {
                        *paused = true;
                        *target_status = LiveTargetStatus::Paused;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format!("instruction step stopped unexpectedly: {status:?}"),
                        )?;
                    }
                }
            }
            LiveCommand::StepInstructionOver => {
                let pause_state = LiveWorkerPauseState {
                    ptrace_stopped: *paused,
                    user_visible_paused: *target_status == LiveTargetStatus::Paused,
                    step_in_flight: None,
                    temporary_return_breakpoint_in_flight: breakpoints
                        .has_temporary_return_breakpoints(),
                    managed_breakpoints_rearmed: breakpoints.all_breakpoints_rearmed(),
                };
                if let Err(reason) = pause_state.can_user_step_instruction() {
                    on_control_status(
                        Some(message.id),
                        Some(command.clone()),
                        LiveCommandStatus::Rejected,
                        *target_status,
                        reason,
                    )?;
                    continue;
                }

                let before_snapshot = match read_register_snapshot(child) {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format!("nexti failed: {err}"),
                        )?;
                        continue;
                    }
                };
                let before_rip = before_snapshot.instruction_pointer;
                let decoded = match decode_instruction_at_rip(child, before_rip) {
                    Ok(decoded) => decoded,
                    Err(err) => {
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format!("nexti decode failed at RIP=0x{before_rip:x}: {err}"),
                        )?;
                        continue;
                    }
                };
                let fallthrough = decoded_instruction_fallthrough(&decoded);

                if decoded.is_call {
                    match breakpoints.set_user_step_over_breakpoint(
                        child,
                        fallthrough,
                        message.id,
                        before_rip,
                    ) {
                        Ok(()) => {}
                        Err(err) => {
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Failed,
                                *target_status,
                                format!("nexti failed: {err}"),
                            )?;
                            continue;
                        }
                    }
                    match ptrace::cont(child, None) {
                        Ok(()) => {
                            *paused = false;
                            *pause_requested = false;
                            *run_mode = LiveTraceRunMode::UserInstructionStepOver;
                            *target_status = LiveTargetStatus::SteppingInstructionOver;
                            *pending_nexti = Some(PendingInstructionStepOver {
                                command_id: message.id,
                                from_rip: before_rip,
                                breakpoint_addr: fallthrough,
                            });
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Accepted,
                                *target_status,
                                format!(
                                    "stepping over call from 0x{before_rip:x} to 0x{fallthrough:x}"
                                ),
                            )?;
                        }
                        Err(err) => {
                            let _ =
                                breakpoints.remove_user_step_over_breakpoint(child, fallthrough);
                            *target_status = LiveTargetStatus::Paused;
                            on_control_status(
                                Some(message.id),
                                Some(command.clone()),
                                LiveCommandStatus::Failed,
                                *target_status,
                                format!("nexti failed: {err}"),
                            )?;
                        }
                    }
                    continue;
                }

                *target_status = LiveTargetStatus::SteppingInstructionOver;
                on_control_status(
                    Some(message.id),
                    Some(command.clone()),
                    LiveCommandStatus::Accepted,
                    *target_status,
                    format!("nexti non-call single-step at RIP=0x{before_rip:x}"),
                )?;
                let step_kind = StepKind::UserInstructionStepOver;
                debug_assert_eq!(step_kind, StepKind::UserInstructionStepOver);
                match ptrace::step(child, None) {
                    Ok(()) => {}
                    Err(err) => {
                        *target_status = LiveTargetStatus::Paused;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format!("nexti failed: {err}"),
                        )?;
                        continue;
                    }
                }
                match waitpid(child, None).context("failed waiting for nexti single-step stop")? {
                    WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {
                        *paused = true;
                        *target_status = LiveTargetStatus::Paused;
                        let after_rip = read_register_snapshot(child)
                            .ok()
                            .map(|snapshot| snapshot.instruction_pointer);
                        emit_register_snapshot_best_effort(
                            child,
                            None,
                            on_register_snapshot,
                            on_control_status,
                            *target_status,
                        )?;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Completed,
                            *target_status,
                            format_instruction_step_over_completed(Some(before_rip), after_rip),
                        )?;
                    }
                    WaitStatus::Stopped(pid, signal) if pid == child => {
                        *paused = true;
                        *target_status = LiveTargetStatus::Paused;
                        emit_register_snapshot_best_effort(
                            child,
                            None,
                            on_register_snapshot,
                            on_control_status,
                            *target_status,
                        )?;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format_instruction_step_signal(
                                signal,
                                read_register_snapshot(child)
                                    .ok()
                                    .map(|snapshot| snapshot.instruction_pointer),
                            ),
                        )?;
                    }
                    WaitStatus::Exited(pid, code) if pid == child => {
                        *paused = false;
                        *target_status = LiveTargetStatus::Exited;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Completed,
                            *target_status,
                            format!("target exited with status {code}"),
                        )?;
                        return Ok(LiveControlOutcome::TargetExited);
                    }
                    WaitStatus::Signaled(pid, signal, _) if pid == child => {
                        *paused = false;
                        *target_status = LiveTargetStatus::Exited;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Completed,
                            *target_status,
                            format!("target terminated by signal {signal:?}"),
                        )?;
                        return Ok(LiveControlOutcome::TargetExited);
                    }
                    status => {
                        *paused = true;
                        *target_status = LiveTargetStatus::Paused;
                        on_control_status(
                            Some(message.id),
                            Some(command.clone()),
                            LiveCommandStatus::Failed,
                            *target_status,
                            format!("nexti stopped unexpectedly: {status:?}"),
                        )?;
                    }
                }
            }
        }
    }

    Ok(LiveControlOutcome::Continue)
}

fn should_continue_after_allocator_event(run_mode: LiveTraceRunMode) -> bool {
    matches!(
        run_mode,
        LiveTraceRunMode::Continuous | LiveTraceRunMode::UserInstructionStepOver
    )
}

fn run_source_step_to_completion<R, U, T, F>(
    child: Pid,
    command_id: LiveCommandId,
    command: LiveCommand,
    source_step: &mut Option<SourceStepState>,
    source_mapper: &TargetSourceMapper,
    breakpoints: &mut BreakpointManager,
    state: &mut TraceHeapState<F>,
    on_register_snapshot: &mut R,
    on_user_breakpoints: &mut U,
    on_control_status: &mut T,
) -> Result<LiveTargetStatus>
where
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    U: FnMut(Vec<UserBreakpoint>) -> Result<()>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    loop {
        let Some(step) = source_step.as_mut() else {
            return Ok(LiveTargetStatus::Paused);
        };
        if step.instructions_executed >= step.instruction_budget {
            let instructions = step.instructions_executed;
            source_step.take();
            emit_register_snapshot_best_effort(
                child,
                None,
                on_register_snapshot,
                on_control_status,
                LiveTargetStatus::Paused,
            )?;
            on_control_status(
                Some(command_id),
                Some(command),
                LiveCommandStatus::Completed,
                LiveTargetStatus::Paused,
                format!("source-step limit reached after {instructions} instructions"),
            )?;
            return Ok(LiveTargetStatus::Paused);
        }

        let before_rip = read_register_snapshot(child)?.instruction_pointer;
        if step.kind == SourceStepKind::Over {
            let decoded = decode_instruction_at_rip(child, before_rip)?;
            if decoded.is_call {
                let fallthrough = decoded_instruction_fallthrough(&decoded);
                breakpoints.set_user_step_over_breakpoint(
                    child,
                    fallthrough,
                    command_id,
                    before_rip,
                )?;
                ptrace::cont(child, None).context("failed to continue source-next over call")?;
                loop {
                    match waitpid(child, None)
                        .context("failed waiting for source-next call step-over")?
                    {
                        WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {
                            let hit_addr = ptrace::getregs(child)?.rip.saturating_sub(1);
                            if hit_addr == fallthrough {
                                let pending = PendingInstructionStepOver {
                                    command_id,
                                    from_rip: before_rip,
                                    breakpoint_addr: fallthrough,
                                };
                                restore_user_step_over_breakpoint_hit(child, breakpoints, pending)?;
                                break;
                            }
                            if handle_source_step_breakpoint_stop(
                                child,
                                hit_addr,
                                breakpoints,
                                state,
                                on_user_breakpoints,
                                on_register_snapshot,
                                on_control_status,
                                command_id,
                                command.clone(),
                            )? {
                                let _ = breakpoints
                                    .remove_user_step_over_breakpoint(child, fallthrough);
                                source_step.take();
                                return Ok(LiveTargetStatus::Paused);
                            }
                            ptrace::cont(child, None)
                                .context("failed to continue during source-next")?;
                        }
                        WaitStatus::Stopped(pid, signal) if pid == child => {
                            let _ =
                                breakpoints.remove_user_step_over_breakpoint(child, fallthrough);
                            source_step.take();
                            emit_register_snapshot_best_effort(
                                child,
                                None,
                                on_register_snapshot,
                                on_control_status,
                                LiveTargetStatus::Paused,
                            )?;
                            on_control_status(
                                Some(command_id),
                                Some(command),
                                LiveCommandStatus::Failed,
                                LiveTargetStatus::Paused,
                                format_instruction_step_signal(
                                    signal,
                                    read_register_snapshot(child)
                                        .ok()
                                        .map(|snapshot| snapshot.instruction_pointer),
                                ),
                            )?;
                            return Ok(LiveTargetStatus::Paused);
                        }
                        WaitStatus::Exited(pid, code) if pid == child => {
                            source_step.take();
                            on_control_status(
                                Some(command_id),
                                Some(command),
                                LiveCommandStatus::Completed,
                                LiveTargetStatus::Exited,
                                format!("target exited with status {code}"),
                            )?;
                            return Ok(LiveTargetStatus::Exited);
                        }
                        WaitStatus::Signaled(pid, signal, _) if pid == child => {
                            source_step.take();
                            on_control_status(
                                Some(command_id),
                                Some(command),
                                LiveCommandStatus::Completed,
                                LiveTargetStatus::Exited,
                                format!("target terminated by signal {signal:?}"),
                            )?;
                            return Ok(LiveTargetStatus::Exited);
                        }
                        status => bail!("source-next stopped unexpectedly: {status:?}"),
                    }
                }
                step.instructions_executed += 1;
            } else {
                ptrace::step(child, None).context("failed to source-next single-step")?;
                wait_source_step_single_stop(
                    child,
                    command_id,
                    command.clone(),
                    source_step,
                    on_register_snapshot,
                    on_control_status,
                )?;
                if source_step.is_none() {
                    return Ok(LiveTargetStatus::Paused);
                }
                source_step.as_mut().unwrap().instructions_executed += 1;
            }
        } else {
            ptrace::step(child, None).context("failed to source-step instruction")?;
            wait_source_step_single_stop(
                child,
                command_id,
                command.clone(),
                source_step,
                on_register_snapshot,
                on_control_status,
            )?;
            if source_step.is_none() {
                return Ok(LiveTargetStatus::Paused);
            }
            source_step.as_mut().unwrap().instructions_executed += 1;
        }

        let current_rip = read_register_snapshot(child)?.instruction_pointer;
        if let Some(current) = source_mapper.lookup(current_rip) {
            let step = source_step.as_ref().unwrap();
            if source_location_changed(&step.origin, &current) {
                let origin = step.origin.clone();
                let instructions = step.instructions_executed;
                let kind = step.kind;
                source_step.take();
                emit_register_snapshot_best_effort(
                    child,
                    None,
                    on_register_snapshot,
                    on_control_status,
                    LiveTargetStatus::Paused,
                )?;
                let message = match kind {
                    SourceStepKind::Into => format!(
                        "source-step: {} -> {} after {} instructions",
                        format_source_location_short(&origin),
                        format_source_location_delta(&origin, &current),
                        instructions
                    ),
                    SourceStepKind::Over => format!(
                        "source-next: {} -> {} after {} instructions",
                        format_source_location_short(&origin),
                        format_source_location_delta(&origin, &current),
                        instructions
                    ),
                };
                on_control_status(
                    Some(command_id),
                    Some(command),
                    LiveCommandStatus::Completed,
                    LiveTargetStatus::Paused,
                    message,
                )?;
                return Ok(LiveTargetStatus::Paused);
            }
        }
    }
}

fn wait_source_step_single_stop<R, T>(
    child: Pid,
    command_id: LiveCommandId,
    command: LiveCommand,
    source_step: &mut Option<SourceStepState>,
    on_register_snapshot: &mut R,
    on_control_status: &mut T,
) -> Result<()>
where
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
{
    match waitpid(child, None).context("failed waiting for source-step stop")? {
        WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => Ok(()),
        WaitStatus::Stopped(pid, signal) if pid == child => {
            source_step.take();
            emit_register_snapshot_best_effort(
                child,
                None,
                on_register_snapshot,
                on_control_status,
                LiveTargetStatus::Paused,
            )?;
            on_control_status(
                Some(command_id),
                Some(command),
                LiveCommandStatus::Failed,
                LiveTargetStatus::Paused,
                format_instruction_step_signal(
                    signal,
                    read_register_snapshot(child)
                        .ok()
                        .map(|snapshot| snapshot.instruction_pointer),
                ),
            )
        }
        WaitStatus::Exited(pid, code) if pid == child => {
            source_step.take();
            on_control_status(
                Some(command_id),
                Some(command),
                LiveCommandStatus::Completed,
                LiveTargetStatus::Exited,
                format!("target exited with status {code}"),
            )
        }
        WaitStatus::Signaled(pid, signal, _) if pid == child => {
            source_step.take();
            on_control_status(
                Some(command_id),
                Some(command),
                LiveCommandStatus::Completed,
                LiveTargetStatus::Exited,
                format!("target terminated by signal {signal:?}"),
            )
        }
        status => bail!("source-step stopped unexpectedly: {status:?}"),
    }
}

fn handle_source_step_breakpoint_stop<R, U, T, F>(
    child: Pid,
    hit_addr: u64,
    breakpoints: &mut BreakpointManager,
    state: &mut TraceHeapState<F>,
    on_user_breakpoints: &mut U,
    on_register_snapshot: &mut R,
    on_control_status: &mut T,
    command_id: LiveCommandId,
    command: LiveCommand,
) -> Result<bool>
where
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    U: FnMut(Vec<UserBreakpoint>) -> Result<()>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    let user_breakpoint_ids = breakpoints.persistent_user_owners_at(hit_addr);
    if !user_breakpoint_ids.is_empty() {
        if breakpoints.allocator_owner(hit_addr).is_some() {
            let _ = handle_managed_breakpoint_hit(child, breakpoints, state)?;
        } else {
            handle_persistent_user_breakpoint_step_over(child, breakpoints, hit_addr)?;
        }
        let hit_breakpoints = breakpoints.record_user_breakpoint_hits(&user_breakpoint_ids);
        on_user_breakpoints(breakpoints.list_user_breakpoints())?;
        if let Some(primary) = hit_breakpoints.first() {
            emit_register_snapshot_best_effort(
                child,
                None,
                on_register_snapshot,
                on_control_status,
                LiveTargetStatus::Paused,
            )?;
            on_control_status(
                Some(command_id),
                Some(command),
                LiveCommandStatus::Failed,
                LiveTargetStatus::Paused,
                format!(
                    "source-next interrupted: breakpoint {} hit",
                    primary.id.as_u64()
                ),
            )?;
            on_control_status(
                None,
                None,
                LiveCommandStatus::Completed,
                LiveTargetStatus::Paused,
                format!(
                    "breakpoint {} hit at {}",
                    primary.id.as_u64(),
                    primary.location_line()
                ),
            )?;
            return Ok(true);
        }
    }

    if let Some((event_id, event_control)) =
        handle_managed_breakpoint_hit(child, breakpoints, state)?
    {
        emit_register_snapshot_best_effort(
            child,
            Some(event_id),
            on_register_snapshot,
            on_control_status,
            LiveTargetStatus::SourceSteppingOver,
        )?;
        if event_control == AllocatorEventControl::Pause {
            on_control_status(
                Some(command_id),
                Some(command),
                LiveCommandStatus::Failed,
                LiveTargetStatus::Paused,
                format!("source-next interrupted: break condition matched after event #{event_id}"),
            )?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn restore_user_step_over_breakpoint_hit(
    child: Pid,
    manager: &mut BreakpointManager,
    pending: PendingInstructionStepOver,
) -> Result<()> {
    let mut regs = ptrace::getregs(child).context("failed to read child registers")?;
    let hit_addr = regs.rip.saturating_sub(1);
    if hit_addr != pending.breakpoint_addr {
        bail!(
            "unexpected nexti SIGTRAP at rip=0x{:x} (hit address 0x{:x}, expected 0x{:x})",
            regs.rip,
            hit_addr,
            pending.breakpoint_addr
        );
    }
    regs.rip = hit_addr;
    ptrace::setregs(child, regs).context("failed to restore RIP after nexti breakpoint")?;
    manager.remove_user_step_over_breakpoint(child, hit_addr)?;
    if let Some(managed) = manager.get_mut(hit_addr) {
        managed
            .breakpoint
            .enable(child)
            .with_context(|| format!("failed to re-enable breakpoint at 0x{hit_addr:x}"))?;
    }
    Ok(())
}

fn complete_breakpoint_management_command<T, U>(
    result: Result<UserBreakpoint>,
    command_id: LiveCommandId,
    command: LiveCommand,
    target_status: LiveTargetStatus,
    breakpoints: &BreakpointManager,
    on_control_status: &mut T,
    on_user_breakpoints: &mut U,
    message: impl FnOnce(&UserBreakpoint) -> String,
) -> Result<()>
where
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
    U: FnMut(Vec<UserBreakpoint>) -> Result<()>,
{
    on_control_status(
        Some(command_id),
        Some(command.clone()),
        LiveCommandStatus::Accepted,
        target_status,
        format!("{} accepted", command.as_str()),
    )?;
    match result {
        Ok(breakpoint) => {
            on_user_breakpoints(breakpoints.list_user_breakpoints())?;
            on_control_status(
                Some(command_id),
                Some(command.clone()),
                LiveCommandStatus::Completed,
                target_status,
                message(&breakpoint),
            )
        }
        Err(err) => on_control_status(
            Some(command_id),
            Some(command.clone()),
            LiveCommandStatus::Failed,
            target_status,
            err.to_string(),
        ),
    }
}

fn should_pause_after_allocator_event(
    run_mode: LiveTraceRunMode,
    event_control: AllocatorEventControl,
) -> bool {
    event_control == AllocatorEventControl::Pause
        || !should_continue_after_allocator_event(run_mode)
}

fn send_signal_best_effort(child: Pid, signal: Signal) {
    let _ = unsafe { libc::kill(child.as_raw(), signal as libc::c_int) };
}

fn emit_register_snapshot_best_effort<R, T>(
    child: Pid,
    event_id: Option<usize>,
    on_register_snapshot: &mut R,
    on_control_status: &mut T,
    target_status: LiveTargetStatus,
) -> Result<()>
where
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
{
    match read_register_snapshot(child) {
        Ok(snapshot) => {
            let stack_snapshot =
                read_stack_snapshot(child, snapshot.stack_pointer, DEFAULT_STACK_SNAPSHOT_WORDS);
            on_register_snapshot(event_id, snapshot, stack_snapshot, child)
        }
        Err(err) => on_control_status(
            None,
            None,
            LiveCommandStatus::Failed,
            target_status,
            format!("register snapshot failed: {err}"),
        ),
    }
}

fn format_instruction_step_completed(before_rip: Option<u64>, after_rip: Option<u64>) -> String {
    match (before_rip, after_rip) {
        (Some(before), Some(after)) => {
            format!("stepped instruction: 0x{before:x} -> 0x{after:x}")
        }
        (Some(before), None) => format!("stepped instruction: 0x{before:x} -> unknown"),
        (None, Some(after)) => format!("stepped instruction: unknown -> 0x{after:x}"),
        (None, None) => "stepped instruction".to_string(),
    }
}

fn format_instruction_step_over_completed(
    before_rip: Option<u64>,
    after_rip: Option<u64>,
) -> String {
    match (before_rip, after_rip) {
        (Some(before), Some(after)) => format!("nexti completed: 0x{before:x} -> 0x{after:x}"),
        (Some(before), None) => format!("nexti completed: 0x{before:x} -> unknown"),
        (None, Some(after)) => format!("nexti completed: unknown -> 0x{after:x}"),
        (None, None) => "nexti completed".to_string(),
    }
}

fn format_instruction_step_signal(signal: Signal, rip: Option<u64>) -> String {
    match rip {
        Some(rip) => format!("instruction step stopped by {signal:?} at RIP=0x{rip:x}"),
        None => format!("instruction step stopped by {signal:?} at RIP=unknown"),
    }
}

fn stop_at_target_entry_if_needed(child: Pid, program_path: &str, show_status: bool) -> Result<()> {
    if find_libc_mapping(child)?.is_some() {
        return Ok(());
    }

    let entry_addr = resolve_runtime_entry_point(child, program_path)?;
    let mut entry_breakpoint = Breakpoint::new(entry_addr);
    entry_breakpoint
        .enable(child)
        .with_context(|| format!("failed to enable target entry breakpoint at 0x{entry_addr:x}"))?;

    if show_status {
        println!("[heapify] waiting for libc mapping at target entry 0x{entry_addr:x}");
    }

    ptrace::cont(child, None).context("failed to continue child to target entry")?;

    loop {
        match waitpid(child, None).context("failed waiting for target entry stop")? {
            WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {
                let mut regs = ptrace::getregs(child).context("failed to read child registers")?;
                let hit_addr = regs.rip.saturating_sub(1);
                if hit_addr != entry_addr {
                    bail!(
                        "unexpected SIGTRAP while waiting for target entry at rip=0x{:x}",
                        regs.rip
                    );
                }

                regs.rip = hit_addr;
                ptrace::setregs(child, regs)
                    .context("failed to restore RIP after target entry breakpoint")?;
                entry_breakpoint
                    .disable(child)
                    .context("failed to disable target entry breakpoint")?;
                return Ok(());
            }
            WaitStatus::Stopped(pid, signal) if pid == child => {
                ptrace::cont(child, signal_to_deliver(signal))
                    .with_context(|| format!("failed to continue child after {signal:?}"))?;
            }
            WaitStatus::PtraceEvent(pid, signal, _) if pid == child => {
                ptrace::cont(child, signal_to_deliver(signal)).with_context(|| {
                    format!("failed to continue child after ptrace event {signal:?}")
                })?;
            }
            WaitStatus::PtraceSyscall(pid) if pid == child => {
                ptrace::cont(child, None).context("failed to continue child after syscall stop")?;
            }
            WaitStatus::Exited(pid, code) if pid == child => {
                bail!("child exited with status {code} before target entry");
            }
            WaitStatus::Signaled(pid, signal, _) if pid == child => {
                bail!("child terminated by signal {signal:?} before target entry");
            }
            status => bail!("unexpected child wait status before target entry: {status:?}"),
        }
    }
}

fn resolve_runtime_entry_point(pid: Pid, program_path: &str) -> Result<u64> {
    let elf_entry = heapify_elf::entry_point(program_path)?;
    if !heapify_elf::is_pie(program_path)? {
        return Ok(elf_entry);
    }

    let mapping = find_executable_mapping(pid, program_path)?.with_context(|| {
        format!("failed to find executable mapping for PIE target: {program_path}")
    })?;
    let load_base = mapping_load_base(&mapping)?;

    load_base
        .checked_add(elf_entry)
        .with_context(|| format!("runtime entry address overflow at 0x{elf_entry:x}"))
}

struct AllocationSymbols {
    malloc: Option<(String, u64)>,
    free: Option<(String, u64)>,
    calloc: Option<(String, u64)>,
    realloc: Option<(String, u64)>,
}

fn resolve_allocation_symbols(
    child: Pid,
    program_path: &str,
    trace_mode: AllocationTraceMode,
    supplied_libc_path: Option<&Path>,
) -> Result<AllocationSymbols> {
    match trace_mode {
        AllocationTraceMode::TargetPlt => Ok(AllocationSymbols {
            malloc: resolve_runtime_symbol_by_prefix(child, program_path, "malloc")?,
            free: resolve_runtime_symbol_by_prefix(child, program_path, "free")?,
            calloc: resolve_runtime_symbol_by_prefix(child, program_path, "calloc")?,
            realloc: resolve_runtime_symbol_by_prefix(child, program_path, "realloc")?,
        }),
        AllocationTraceMode::LibcSymbols => Ok(AllocationSymbols {
            malloc: resolve_runtime_libc_symbol(
                child,
                &["__libc_malloc", "malloc"],
                supplied_libc_path,
            )?,
            free: resolve_runtime_libc_symbol(child, &["__libc_free", "free"], supplied_libc_path)?,
            calloc: resolve_runtime_libc_symbol(
                child,
                &["__libc_calloc", "calloc"],
                supplied_libc_path,
            )?,
            realloc: resolve_runtime_libc_symbol(
                child,
                &["__libc_realloc", "realloc"],
                supplied_libc_path,
            )?,
        }),
    }
}

fn run_parent(child: Pid) -> Result<()> {
    wait_for_initial_stop(child)?;
    ptrace::cont(child, None).context("failed to continue child")?;
    wait_until_exit(child)
}

fn run_parent_with_breakpoint(child: Pid, addr: u64) -> Result<()> {
    wait_for_initial_stop(child)?;
    run_breakpoint_loop(child, addr)
}

fn run_parent_with_symbol_breakpoint(
    child: Pid,
    program_path: &str,
    symbol_name: &str,
) -> Result<()> {
    wait_for_initial_stop(child)?;

    let (resolved_name, addr) = resolve_runtime_symbol_exact(child, program_path, symbol_name)?
        .with_context(|| format!("symbol not found: {symbol_name}"))?;
    println!("[heapify] symbol {resolved_name} = 0x{addr:x}");

    run_breakpoint_loop(child, addr)
}

fn run_breakpoint_loop(child: Pid, addr: u64) -> Result<()> {
    let mut breakpoint = Breakpoint::new(addr);
    breakpoint
        .enable(child)
        .with_context(|| format!("failed to enable breakpoint at 0x{addr:x}"))?;
    println!("breakpoint set at 0x{addr:x}");

    ptrace::cont(child, None).context("failed to continue child")?;

    loop {
        match waitpid(child, None).context("failed waiting for child status")? {
            WaitStatus::Exited(pid, code) if pid == child => {
                println!("child exited with status {code}");
                return Ok(());
            }
            WaitStatus::Signaled(pid, signal, _) if pid == child => {
                println!("child terminated by signal {signal:?}");
                return Ok(());
            }
            WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {
                handle_breakpoint_hit(child, &mut breakpoint)?;
                ptrace::cont(child, None).context("failed to continue child after breakpoint")?;
            }
            WaitStatus::Stopped(pid, signal) if pid == child => {
                ptrace::cont(child, signal_to_deliver(signal))
                    .with_context(|| format!("failed to continue child after {signal:?}"))?;
            }
            WaitStatus::PtraceEvent(pid, signal, _) if pid == child => {
                ptrace::cont(child, signal_to_deliver(signal)).with_context(|| {
                    format!("failed to continue child after ptrace event {signal:?}")
                })?;
            }
            WaitStatus::PtraceSyscall(pid) if pid == child => {
                ptrace::cont(child, None).context("failed to continue child after syscall stop")?;
            }
            status => bail!("unexpected child wait status: {status:?}"),
        }
    }
}

fn wait_for_initial_stop(child: Pid) -> Result<()> {
    wait_for_initial_stop_with_status(child, true)
}

fn wait_for_initial_stop_with_status(child: Pid, show_status: bool) -> Result<()> {
    match waitpid(child, None).context("failed waiting for initial child stop")? {
        WaitStatus::Stopped(pid, signal) if pid == child => {
            if show_status {
                println!("child pid: {pid}");
                println!("initial stop: {signal:?}");
            }
        }
        status => bail!("expected initial child stop, got {status:?}"),
    }
    Ok(())
}

fn wait_until_exit(child: Pid) -> Result<()> {
    loop {
        match waitpid(child, None).context("failed waiting for child status")? {
            WaitStatus::Exited(pid, code) if pid == child => {
                println!("child exited with status {code}");
                return Ok(());
            }
            WaitStatus::Signaled(pid, signal, _) if pid == child => {
                println!("child terminated by signal {signal:?}");
                return Ok(());
            }
            WaitStatus::Stopped(pid, signal) if pid == child => {
                ptrace::cont(child, signal_to_deliver(signal))
                    .with_context(|| format!("failed to continue child after {signal:?}"))?;
            }
            WaitStatus::PtraceEvent(pid, signal, _) if pid == child => {
                ptrace::cont(child, signal_to_deliver(signal)).with_context(|| {
                    format!("failed to continue child after ptrace event {signal:?}")
                })?;
            }
            WaitStatus::PtraceSyscall(pid) if pid == child => {
                ptrace::cont(child, None).context("failed to continue child after syscall stop")?;
            }
            status => bail!("unexpected child wait status: {status:?}"),
        }
    }
}

fn handle_managed_breakpoint_hit<F>(
    child: Pid,
    manager: &mut BreakpointManager,
    state: &mut TraceHeapState<F>,
) -> Result<Option<(usize, AllocatorEventControl)>>
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    let mut regs = ptrace::getregs(child).context("failed to read child registers")?;
    let hit_addr = regs.rip.saturating_sub(1);

    if !manager.contains(hit_addr) {
        bail!(
            "unexpected SIGTRAP at rip=0x{:x} (hit address 0x{:x})",
            regs.rip,
            hit_addr
        );
    }

    regs.rip = hit_addr;
    ptrace::setregs(child, regs).context("failed to restore RIP after breakpoint")?;

    let breakpoint_kind = manager
        .allocator_owner(hit_addr)
        .with_context(|| format!("missing allocator breakpoint owner at 0x{hit_addr:x}"))?;
    manager
        .get_mut(hit_addr)
        .with_context(|| format!("missing managed breakpoint at 0x{hit_addr:x}"))?
        .breakpoint
        .disable(child)
        .with_context(|| format!("failed to disable breakpoint at 0x{hit_addr:x}"))?;

    let mut emitted_allocator_event = None;
    let remove_after_step = match breakpoint_kind.clone() {
        BreakpointKind::MallocEntry => {
            let event_id = state.next_event_id();
            let requested_size = regs.rdi;
            if let Some(return_addr) = capture_caller_addr(child, regs.rsp) {
                manager.set_breakpoint(
                    child,
                    return_addr,
                    BreakpointKind::MallocReturn {
                        requested_size,
                        event_id,
                        caller_addr: Some(return_addr),
                    },
                )?;
            }
            false
        }
        BreakpointKind::FreeEntry => {
            let event_id = state.next_event_id();
            let ptr = regs.rdi;
            let _chunk_before = read_optional_glibc_chunk_header(child, ptr, state.glibc_profile);
            if let Some(return_addr) = capture_caller_addr(child, regs.rsp) {
                manager.set_breakpoint(
                    child,
                    return_addr,
                    BreakpointKind::FreeReturn {
                        ptr,
                        event_id,
                        caller_addr: Some(return_addr),
                    },
                )?;
            }
            false
        }
        BreakpointKind::CallocEntry => {
            let event_id = state.next_event_id();
            let nmemb = regs.rdi;
            let size = regs.rsi;
            if let Some(return_addr) = capture_caller_addr(child, regs.rsp) {
                manager.set_breakpoint(
                    child,
                    return_addr,
                    BreakpointKind::CallocReturn {
                        nmemb,
                        size,
                        event_id,
                        caller_addr: Some(return_addr),
                    },
                )?;
            }
            false
        }
        BreakpointKind::ReallocEntry => {
            let event_id = state.next_event_id();
            let old_ptr = regs.rdi;
            let new_size = regs.rsi;
            let old_chunk = read_optional_glibc_chunk_header(child, old_ptr, state.glibc_profile);
            if let Some(return_addr) = capture_caller_addr(child, regs.rsp) {
                manager.set_breakpoint(
                    child,
                    return_addr,
                    BreakpointKind::ReallocReturn {
                        old_ptr,
                        new_size,
                        event_id,
                        old_chunk,
                        caller_addr: Some(return_addr),
                    },
                )?;
            }
            false
        }
        BreakpointKind::MallocReturn {
            requested_size,
            event_id,
            caller_addr,
        } => {
            let returned_ptr = regs.rax;
            let chunk = read_optional_glibc_chunk_header(child, returned_ptr, state.glibc_profile);
            try_discover_heap_mapping(child, state);
            let event = HeapTraceEvent::Malloc {
                event_id,
                requested_size,
                returned_ptr,
                chunk,
                caller_addr,
            };
            let context = trace_heap_context(child, state);
            let control = (state.on_event)(event, context)?;
            emitted_allocator_event = Some((event_id, control));
            try_detect_and_print_libc_metadata(child, state);
            print_heap_mapping_once(state);
            true
        }
        BreakpointKind::FreeReturn {
            ptr,
            event_id,
            caller_addr,
        } => {
            let chunk = read_optional_glibc_chunk_header(child, ptr, state.glibc_profile);
            let tcache_entry = read_optional_tcache_entry_candidate(child, ptr);
            let event = HeapTraceEvent::Free {
                event_id,
                ptr,
                chunk,
                tcache_entry,
                caller_addr,
            };
            let context = trace_heap_context(child, state);
            let control = (state.on_event)(event, context)?;
            emitted_allocator_event = Some((event_id, control));
            try_detect_and_print_libc_metadata(child, state);
            true
        }
        BreakpointKind::CallocReturn {
            nmemb,
            size,
            event_id,
            caller_addr,
        } => {
            let returned_ptr = regs.rax;
            let chunk = read_optional_glibc_chunk_header(child, returned_ptr, state.glibc_profile);
            try_discover_heap_mapping(child, state);
            let event = HeapTraceEvent::Calloc {
                event_id,
                nmemb,
                size,
                returned_ptr,
                chunk,
                caller_addr,
            };
            let context = trace_heap_context(child, state);
            let control = (state.on_event)(event, context)?;
            emitted_allocator_event = Some((event_id, control));
            try_detect_and_print_libc_metadata(child, state);
            print_heap_mapping_once(state);
            true
        }
        BreakpointKind::ReallocReturn {
            old_ptr,
            new_size,
            event_id,
            old_chunk,
            caller_addr,
        } => {
            let returned_ptr = regs.rax;
            let old_chunk = old_chunk
                .or_else(|| read_optional_glibc_chunk_header(child, old_ptr, state.glibc_profile));
            let new_chunk =
                read_optional_glibc_chunk_header(child, returned_ptr, state.glibc_profile);
            try_discover_heap_mapping(child, state);
            let event = HeapTraceEvent::Realloc {
                event_id,
                old_ptr,
                new_size,
                returned_ptr,
                old_chunk,
                new_chunk,
                caller_addr,
            };
            let context = trace_heap_context(child, state);
            let control = (state.on_event)(event, context)?;
            emitted_allocator_event = Some((event_id, control));
            try_detect_and_print_libc_metadata(child, state);
            print_heap_mapping_once(state);
            true
        }
    };

    let step_kind = StepKind::InternalBreakpointStepOver;
    debug_assert_eq!(step_kind, StepKind::InternalBreakpointStepOver);
    ptrace::step(child, None).context("failed to single-step child")?;
    match waitpid(child, None).context("failed waiting for single-step stop")? {
        WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {}
        status => bail!("expected SIGTRAP after single-step, got {status:?}"),
    }

    if remove_after_step {
        manager.remove_owner_at(child, hit_addr, |owner| {
            matches!(owner, BreakpointOwner::Allocator(kind) if breakpoint_kind_matches(kind, &breakpoint_kind))
        })?;
    }
    if let Some(managed) = manager.get_mut(hit_addr) {
        managed
            .breakpoint
            .enable(child)
            .with_context(|| format!("failed to re-enable breakpoint at 0x{hit_addr:x}"))?;
    }

    Ok(emitted_allocator_event)
}

fn breakpoint_kind_matches(left: &BreakpointKind, right: &BreakpointKind) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}

fn handle_user_step_over_breakpoint_hit<R, T>(
    child: Pid,
    manager: &mut BreakpointManager,
    pending: PendingInstructionStepOver,
    on_register_snapshot: &mut R,
    on_control_status: &mut T,
) -> Result<()>
where
    R: FnMut(Option<usize>, RegisterSnapshot, StackSnapshot, Pid) -> Result<()>,
    T: FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>,
{
    let mut regs = ptrace::getregs(child).context("failed to read child registers")?;
    let hit_addr = regs.rip.saturating_sub(1);
    if hit_addr != pending.breakpoint_addr {
        bail!(
            "unexpected nexti SIGTRAP at rip=0x{:x} (hit address 0x{:x}, expected 0x{:x})",
            regs.rip,
            hit_addr,
            pending.breakpoint_addr
        );
    }

    regs.rip = hit_addr;
    ptrace::setregs(child, regs).context("failed to restore RIP after nexti breakpoint")?;

    manager.remove_user_step_over_breakpoint(child, hit_addr)?;
    if let Some(managed) = manager.get_mut(hit_addr) {
        managed
            .breakpoint
            .enable(child)
            .with_context(|| format!("failed to re-enable breakpoint at 0x{hit_addr:x}"))?;
    }

    let after_rip = read_register_snapshot(child)
        .ok()
        .map(|snapshot| snapshot.instruction_pointer);
    emit_register_snapshot_best_effort(
        child,
        None,
        on_register_snapshot,
        on_control_status,
        LiveTargetStatus::Paused,
    )?;
    on_control_status(
        Some(pending.command_id),
        Some(LiveCommand::StepInstructionOver),
        LiveCommandStatus::Completed,
        LiveTargetStatus::Paused,
        format_instruction_step_over_completed(Some(pending.from_rip), after_rip),
    )
}

fn handle_persistent_user_breakpoint_step_over(
    child: Pid,
    manager: &mut BreakpointManager,
    hit_addr: u64,
) -> Result<()> {
    let mut regs = ptrace::getregs(child).context("failed to read child registers")?;
    if regs.rip.saturating_sub(1) != hit_addr {
        bail!(
            "unexpected user breakpoint SIGTRAP at rip=0x{:x} (hit address 0x{hit_addr:x})",
            regs.rip
        );
    }

    regs.rip = hit_addr;
    ptrace::setregs(child, regs).context("failed to restore RIP after user breakpoint")?;
    manager
        .get_mut(hit_addr)
        .with_context(|| format!("missing user breakpoint at 0x{hit_addr:x}"))?
        .breakpoint
        .disable(child)
        .with_context(|| format!("failed to disable breakpoint at 0x{hit_addr:x}"))?;

    let step_kind = StepKind::InternalBreakpointStepOver;
    debug_assert_eq!(step_kind, StepKind::InternalBreakpointStepOver);
    ptrace::step(child, None).context("failed to single-step child")?;
    match waitpid(child, None).context("failed waiting for single-step stop")? {
        WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {}
        status => bail!("expected SIGTRAP after single-step, got {status:?}"),
    }

    if let Some(managed) = manager.get_mut(hit_addr) {
        managed
            .breakpoint
            .enable(child)
            .with_context(|| format!("failed to re-enable breakpoint at 0x{hit_addr:x}"))?;
    }

    Ok(())
}

fn handle_breakpoint_hit(child: Pid, breakpoint: &mut Breakpoint) -> Result<()> {
    let mut regs = ptrace::getregs(child).context("failed to read child registers")?;
    let hit_addr = regs.rip.saturating_sub(1);

    if hit_addr != breakpoint.addr {
        bail!(
            "unexpected SIGTRAP at rip=0x{:x} (hit address 0x{:x})",
            regs.rip,
            hit_addr
        );
    }

    println!("breakpoint hit at 0x{hit_addr:x}");

    regs.rip = breakpoint.addr;
    ptrace::setregs(child, regs).context("failed to restore RIP after breakpoint")?;

    breakpoint
        .disable(child)
        .with_context(|| format!("failed to disable breakpoint at 0x{:x}", breakpoint.addr))?;

    ptrace::step(child, None).context("failed to single-step child")?;
    match waitpid(child, None).context("failed waiting for single-step stop")? {
        WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {}
        status => bail!("expected SIGTRAP after single-step, got {status:?}"),
    }

    breakpoint
        .enable(child)
        .with_context(|| format!("failed to re-enable breakpoint at 0x{:x}", breakpoint.addr))?;

    Ok(())
}

pub fn read_word(pid: Pid, addr: u64) -> Result<u64> {
    let word = ptrace::read(pid, addr as ptrace::AddressType)
        .with_context(|| format!("failed to read word at 0x{addr:x}"))?;
    Ok(word as u64)
}

pub fn read_target_memory(pid: Pid, address: u64, size: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(size);
    let mut offset = 0usize;
    while offset < size {
        let addr = address
            .checked_add(offset as u64)
            .context("process memory address overflow")?;
        let word = read_word(pid, addr)?;
        let word_bytes = word.to_le_bytes();
        let len = (size - offset).min(word_bytes.len());
        bytes.extend_from_slice(&word_bytes[..len]);
        offset += len;
    }
    Ok(bytes)
}

fn capture_caller_addr(pid: Pid, rsp: u64) -> Option<u64> {
    capture_caller_addr_with(|| read_word(pid, rsp))
}

fn capture_caller_addr_with(mut read_stack_word: impl FnMut() -> Result<u64>) -> Option<u64> {
    read_stack_word().ok()
}

pub fn read_u16(pid: Pid, addr: u64) -> Result<u16> {
    let aligned_addr = addr & !0x7;
    let offset = (addr & 0x7) as usize;
    let word = read_word(pid, aligned_addr)?;

    extract_u16_from_word_le(word, offset)
        .with_context(|| format!("failed to read u16 at 0x{addr:x}"))
}

fn extract_u16_from_word_le(word: u64, offset: usize) -> Result<u16> {
    if offset > 6 {
        bail!("u16 extraction crosses word boundary at offset {offset}");
    }

    Ok(((word >> (offset * 8)) & 0xffff) as u16)
}

pub fn read_glibc_chunk_header(pid: Pid, user_addr: u64) -> Result<GlibcChunkHeader> {
    read_glibc_chunk_header_with_profile(pid, user_addr, GLIBC_X86_64_MODERN)
}

pub fn read_glibc_chunk_header_with_profile(
    pid: Pid,
    user_addr: u64,
    profile: GlibcProfile,
) -> Result<GlibcChunkHeader> {
    GlibcChunkHeader::read_with_profile(user_addr, profile, |addr| read_word(pid, addr))
}

pub fn resolve_runtime_symbol_exact(
    pid: Pid,
    program_path: &str,
    symbol_name: &str,
) -> Result<Option<(String, u64)>> {
    let Some(elf_symbol_addr) = heapify_elf::find_symbol(program_path, symbol_name)? else {
        return Ok(None);
    };

    let runtime_addr =
        rebase_target_symbol_if_needed(pid, program_path, symbol_name, elf_symbol_addr)?;
    Ok(Some((symbol_name.to_string(), runtime_addr)))
}

pub fn resolve_runtime_symbol_by_prefix(
    pid: Pid,
    program_path: &str,
    symbol_prefix: &str,
) -> Result<Option<(String, u64)>> {
    let Some((symbol_name, elf_symbol_addr)) =
        heapify_elf::find_symbol_by_prefix(program_path, symbol_prefix)?
    else {
        return Ok(None);
    };

    let runtime_addr =
        rebase_target_symbol_if_needed(pid, program_path, &symbol_name, elf_symbol_addr)?;
    Ok(Some((symbol_name, runtime_addr)))
}

fn rebase_target_symbol_if_needed(
    pid: Pid,
    program_path: &str,
    symbol_name: &str,
    elf_symbol_addr: u64,
) -> Result<u64> {
    if !heapify_elf::is_pie(program_path)? {
        return Ok(elf_symbol_addr);
    }

    let mapping = find_executable_mapping(pid, program_path)?.with_context(|| {
        format!("failed to find executable mapping for PIE target: {program_path}")
    })?;
    let load_base = mapping_load_base(&mapping)?;
    runtime_symbol_addr(symbol_name, elf_symbol_addr, load_base)
}

fn runtime_symbol_addr(symbol_name: &str, symbol_addr: u64, load_base: u64) -> Result<u64> {
    load_base
        .checked_add(symbol_addr)
        .with_context(|| format!("runtime address overflow for {symbol_name} at 0x{symbol_addr:x}"))
}

pub fn resolve_runtime_libc_symbol(
    pid: Pid,
    symbol_names: &[&str],
    supplied_libc_path: Option<&Path>,
) -> Result<Option<(String, u64)>> {
    let Some(mapping) = find_libc_mapping(pid)? else {
        return Ok(None);
    };
    let loaded_libc_path = mapping
        .pathname
        .as_deref()
        .context("libc mapping did not include a pathname")?;
    let load_base = mapping_load_base(&mapping)?;
    let symbol_file = libc_symbol_file(loaded_libc_path, supplied_libc_path);

    resolve_libc_symbol_from_file(
        symbol_file,
        load_base,
        symbol_names,
        supplied_libc_path.is_some(),
    )
}

fn resolve_libc_symbol_from_file(
    symbol_file: &Path,
    load_base: u64,
    symbol_names: &[&str],
    supplied: bool,
) -> Result<Option<(String, u64)>> {
    for symbol_name in symbol_names {
        match heapify_elf::find_symbol(symbol_file.to_string_lossy().as_ref(), symbol_name) {
            Ok(Some(symbol_addr)) => {
                return Ok(Some(runtime_libc_symbol(
                    symbol_name,
                    symbol_addr,
                    load_base,
                )?));
            }
            Ok(None) => {}
            Err(err) if supplied => {
                return Err(err).with_context(|| {
                    format!("failed to parse supplied libc: {}", symbol_file.display())
                });
            }
            Err(err) => return Err(err),
        }
    }

    for symbol_name in symbol_names {
        match heapify_elf::find_symbol_by_prefix(
            symbol_file.to_string_lossy().as_ref(),
            symbol_name,
        ) {
            Ok(Some((found_name, symbol_addr))) => {
                return Ok(Some(runtime_libc_symbol(
                    &found_name,
                    symbol_addr,
                    load_base,
                )?));
            }
            Ok(None) => {}
            Err(err) if supplied => {
                return Err(err).with_context(|| {
                    format!("failed to parse supplied libc: {}", symbol_file.display())
                });
            }
            Err(err) => return Err(err),
        }
    }

    if supplied {
        bail!(
            "supplied libc {} does not define any of: {}",
            symbol_file.display(),
            symbol_names.join(", ")
        );
    }

    Ok(None)
}

fn runtime_libc_symbol(
    symbol_name: &str,
    symbol_addr: u64,
    load_base: u64,
) -> Result<(String, u64)> {
    let runtime_addr = load_base.checked_add(symbol_addr).with_context(|| {
        format!("runtime address overflow for {symbol_name} at 0x{symbol_addr:x}")
    })?;
    Ok((symbol_name.to_string(), runtime_addr))
}

fn libc_symbol_file<'a>(
    loaded_libc_path: &'a str,
    supplied_libc_path: Option<&'a Path>,
) -> &'a Path {
    supplied_libc_path.unwrap_or_else(|| Path::new(loaded_libc_path))
}

pub fn resolve_main_arena_candidate(pid: Pid) -> Result<Option<MainArenaCandidate>> {
    resolve_main_arena_candidate_with_offset(pid, None, None)
}

pub fn resolve_main_arena_candidate_with_offset(
    pid: Pid,
    user_offset: Option<u64>,
    supplied_libc_path: Option<&Path>,
) -> Result<Option<MainArenaCandidate>> {
    let Some(mapping) = find_libc_mapping(pid)? else {
        return Ok(None);
    };
    let Some(libc_path) = mapping.pathname.as_deref() else {
        return Ok(None);
    };
    let load_base = mapping_load_base(&mapping)?;

    if let Some(offset) = user_offset {
        let runtime_addr = runtime_symbol_addr("main_arena", offset, load_base)?;
        return Ok(Some(MainArenaCandidate {
            libc_path: libc_path.to_string(),
            symbol_name: "main_arena".to_string(),
            runtime_addr,
            source: MainArenaSource::UserOffset,
            offset: Some(offset),
        }));
    }

    let symbol_file = libc_symbol_file(libc_path, supplied_libc_path);
    let Some(symbol_addr) =
        heapify_elf::find_symbol(symbol_file.to_string_lossy().as_ref(), "main_arena")
            .with_context(|| {
                format!(
                    "failed to parse libc for main_arena: {}",
                    symbol_file.display()
                )
            })?
    else {
        return Ok(None);
    };

    let runtime_addr = runtime_symbol_addr("main_arena", symbol_addr, load_base)?;
    Ok(Some(MainArenaCandidate {
        libc_path: libc_path.to_string(),
        symbol_name: "main_arena".to_string(),
        runtime_addr,
        source: MainArenaSource::LibcSymbol,
        offset: Some(symbol_addr),
    }))
}

pub fn read_main_arena_experiment(
    pid: Pid,
    arena_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
) -> Result<MainArenaExperiment> {
    let mut candidates = Vec::new();
    let mut read_any = false;

    for field_offset in (0..0x200u64).step_by(8) {
        let field_addr = arena_addr
            .checked_add(field_offset)
            .with_context(|| format!("main_arena field address overflow at 0x{field_offset:x}"))?;
        let Ok(value) = read_word(pid, field_addr) else {
            continue;
        };
        read_any = true;

        if let Some(candidate) =
            classify_main_arena_pointer_candidate(field_offset, value, heap_snapshot)
        {
            candidates.push(candidate);
        }
    }

    if !read_any {
        bail!("failed to read any main_arena pointer fields");
    }

    Ok(MainArenaExperiment {
        arena_addr,
        candidates,
    })
}

pub fn read_fastbin_experiment(
    pid: Pid,
    arena_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Result<FastbinExperiment> {
    let mut candidates = Vec::new();
    let mut read_any = false;

    for field_offset in fastbin_experiment_scan_offsets(profile) {
        let field_addr = arena_addr.checked_add(field_offset).with_context(|| {
            format!("main_arena fastbin field address overflow at 0x{field_offset:x}")
        })?;
        let Ok(value) = read_word(pid, field_addr) else {
            continue;
        };
        read_any = true;

        if value == 0 {
            continue;
        }

        if let Some(candidate) = classify_fastbin_pointer_candidate(
            field_offset,
            value,
            heap_snapshot,
            heap_tracker,
            profile,
        ) {
            candidates.push(candidate);
        }
    }

    if !read_any {
        bail!("failed to read any main_arena fastbin candidate fields");
    }

    Ok(FastbinExperiment {
        arena_addr,
        candidates,
    })
}

pub fn read_unsorted_bin_experiment(
    pid: Pid,
    arena_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Result<UnsortedBinExperiment> {
    let mut candidates = Vec::new();
    let mut read_any = false;

    for field_offset in (0x60..0x200u64).step_by(0x10) {
        let fd_addr = arena_addr.checked_add(field_offset).with_context(|| {
            format!("main_arena unsorted candidate fd address overflow at 0x{field_offset:x}")
        })?;
        let bk_offset = field_offset
            .checked_add(profile.pointer_size)
            .context("main_arena unsorted candidate bk offset overflow")?;
        let bk_addr = arena_addr.checked_add(bk_offset).with_context(|| {
            format!("main_arena unsorted candidate bk address overflow at 0x{bk_offset:x}")
        })?;

        let fd = read_word(pid, fd_addr);
        let bk = read_word(pid, bk_addr);
        read_any |= fd.is_ok() || bk.is_ok();
        let (Ok(fd), Ok(bk)) = (fd, bk) else {
            continue;
        };

        if let Some(candidate) = classify_unsorted_bin_pointer_candidate(
            field_offset,
            fd,
            bk,
            heap_snapshot,
            heap_tracker,
            profile,
        ) {
            candidates.push(candidate);
        }
    }

    if !read_any {
        bail!("failed to read any main_arena unsorted candidate fields");
    }

    Ok(UnsortedBinExperiment {
        arena_addr,
        candidates,
    })
}

pub fn read_bin_experiment(
    pid: Pid,
    arena_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Result<BinExperiment> {
    let mut candidates = Vec::new();
    let mut read_any = false;
    let scan_start = profile.main_arena_unsorted_bin_offset.unwrap_or(0x70);
    let scan_end = scan_start
        .checked_add(0x800)
        .context("main_arena regular bin experiment scan end overflow")?;

    for field_offset in (scan_start..scan_end).step_by(0x10) {
        let fd_addr = arena_addr.checked_add(field_offset).with_context(|| {
            format!("main_arena bin candidate fd address overflow at 0x{field_offset:x}")
        })?;
        let bk_offset = field_offset
            .checked_add(profile.pointer_size)
            .context("main_arena bin candidate bk offset overflow")?;
        let bk_addr = arena_addr.checked_add(bk_offset).with_context(|| {
            format!("main_arena bin candidate bk address overflow at 0x{bk_offset:x}")
        })?;

        let fd = read_word(pid, fd_addr);
        let bk = read_word(pid, bk_addr);
        read_any |= fd.is_ok() || bk.is_ok();
        let (Ok(fd), Ok(bk)) = (fd, bk) else {
            continue;
        };

        if let Some(candidate) = classify_bin_pointer_candidate(
            arena_addr,
            field_offset,
            fd,
            bk,
            heap_snapshot,
            heap_tracker,
            profile,
        ) {
            candidates.push(candidate);
        }
    }

    if !read_any {
        bail!("failed to read any main_arena regular bin candidate fields");
    }

    Ok(BinExperiment {
        arena_addr,
        candidates,
    })
}

pub fn read_unsorted_bin_snapshot(
    pid: Pid,
    arena_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_unsorted_chain: usize,
) -> Result<Option<UnsortedBinSnapshot>> {
    let Some(field_offset) = profile.main_arena_unsorted_bin_offset else {
        return Ok(None);
    };
    let fd_addr = arena_addr.checked_add(field_offset).with_context(|| {
        format!("main_arena unsorted fd address overflow at 0x{field_offset:x}")
    })?;
    let bk_offset = field_offset
        .checked_add(profile.pointer_size)
        .context("main_arena unsorted bk offset overflow")?;
    let bk_addr = arena_addr
        .checked_add(bk_offset)
        .with_context(|| format!("main_arena unsorted bk address overflow at 0x{bk_offset:x}"))?;

    let fd = read_word(pid, fd_addr)?;
    let bk = read_word(pid, bk_addr)?;

    let sentinel_addr = arena_addr.checked_add(field_offset).with_context(|| {
        format!("main_arena unsorted sentinel address overflow at 0x{field_offset:x}")
    })?;
    let chain = read_unsorted_bin_chain(
        pid,
        sentinel_addr,
        fd,
        bk,
        heap_snapshot,
        heap_tracker,
        profile,
        max_unsorted_chain,
    );

    Ok(Some(classify_unsorted_bin_snapshot(
        arena_addr,
        field_offset,
        fd,
        bk,
        heap_snapshot,
        heap_tracker,
        profile,
        Some(chain),
    )))
}

pub fn read_regular_bins_snapshot(
    pid: Pid,
    arena_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_bins: usize,
) -> Result<Option<RegularBinsSnapshot>> {
    let Some(bins_offset) = profile.main_arena_bins_offset else {
        return Ok(None);
    };
    let Some(bin_count) = profile.main_arena_bin_count else {
        return Ok(None);
    };

    let limit = regular_bin_snapshot_limit(profile, max_bins).unwrap_or(bin_count.min(max_bins));
    let mut heads = Vec::new();
    let mut read_any = false;

    for index in 0..limit {
        let index_offset = (index as u64)
            .checked_mul(profile.pointer_size)
            .and_then(|offset| offset.checked_mul(2))
            .with_context(|| format!("regular bin index offset overflow for bin {index}"))?;
        let field_offset = bins_offset
            .checked_add(index_offset)
            .with_context(|| format!("regular bin field offset overflow for bin {index}"))?;
        let fd_addr = arena_addr.checked_add(field_offset).with_context(|| {
            format!("main_arena regular bin fd address overflow at 0x{field_offset:x}")
        })?;
        let bk_offset = field_offset
            .checked_add(profile.pointer_size)
            .context("main_arena regular bin bk offset overflow")?;
        let bk_addr = arena_addr.checked_add(bk_offset).with_context(|| {
            format!("main_arena regular bin bk address overflow at 0x{bk_offset:x}")
        })?;

        let fd = read_word(pid, fd_addr);
        let bk = read_word(pid, bk_addr);
        read_any |= fd.is_ok() || bk.is_ok();
        let (Ok(fd), Ok(bk)) = (fd, bk) else {
            continue;
        };

        heads.push(classify_regular_bin_head(
            arena_addr,
            index,
            field_offset,
            fd,
            bk,
            heap_snapshot,
            heap_tracker,
            profile,
        )?);
    }

    if !read_any {
        bail!("failed to read any main_arena regular bin head fields");
    }

    Ok(Some(RegularBinsSnapshot {
        arena_addr,
        bins_offset,
        heads,
    }))
}

fn regular_bin_snapshot_limit(profile: GlibcProfile, max_bins: usize) -> Option<usize> {
    Some(profile.main_arena_bin_count?.min(max_bins))
}

pub fn read_smallbins_snapshot(
    pid: Pid,
    arena_addr: u64,
    regular_bins: &RegularBinsSnapshot,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_smallbin_chain: usize,
) -> Result<SmallbinsSnapshot> {
    let mut chains = Vec::new();

    for head in regular_bins
        .heads
        .iter()
        .filter(|head| head.role == RegularBinRole::Smallbin)
    {
        let Some(expected_chunk_size) = head.chunk_size else {
            continue;
        };
        let sentinel_addr = arena_addr.checked_add(head.field_offset).with_context(|| {
            format!(
                "main_arena smallbin sentinel address overflow at 0x{:x}",
                head.field_offset
            )
        })?;
        chains.push(read_smallbin_chain(
            pid,
            head.index,
            head.glibc_bin_index,
            expected_chunk_size,
            sentinel_addr,
            head.fd,
            head.bk,
            heap_snapshot,
            heap_tracker,
            profile,
            max_smallbin_chain,
        ));
    }

    Ok(SmallbinsSnapshot {
        arena_addr,
        bins_offset: regular_bins.bins_offset,
        chains,
    })
}

pub fn read_largebins_snapshot(
    pid: Pid,
    arena_addr: u64,
    regular_bins: &RegularBinsSnapshot,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_largebin_chain: usize,
) -> Result<LargebinsSnapshot> {
    let mut chains = Vec::new();

    for head in regular_bins
        .heads
        .iter()
        .filter(|head| head.role == RegularBinRole::Largebin)
    {
        let sentinel_addr = arena_addr.checked_add(head.field_offset).with_context(|| {
            format!(
                "main_arena largebin sentinel address overflow at 0x{:x}",
                head.field_offset
            )
        })?;
        chains.push(read_largebin_chain(
            pid,
            arena_addr,
            head.index,
            head.glibc_bin_index,
            sentinel_addr,
            head.fd,
            head.bk,
            heap_snapshot,
            heap_tracker,
            profile,
            max_largebin_chain,
        ));
    }

    Ok(LargebinsSnapshot {
        arena_addr,
        bins_offset: regular_bins.bins_offset,
        chains,
    })
}

pub fn read_fastbins_snapshot(
    pid: Pid,
    arena_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_fastbin_chain: usize,
) -> Result<Option<FastbinsSnapshot>> {
    let Some(fastbins_offset) = profile.main_arena_fastbins_offset else {
        return Ok(None);
    };
    let Some(fastbin_count) = profile.main_arena_fastbin_count else {
        return Ok(None);
    };

    let mut heads = Vec::new();
    let mut chains = Vec::new();
    let mut read_any = false;

    for index in 0..fastbin_count {
        let index_offset = (index as u64)
            .checked_mul(profile.pointer_size)
            .with_context(|| format!("fastbin index offset overflow for bin {index}"))?;
        let field_offset = fastbins_offset
            .checked_add(index_offset)
            .with_context(|| format!("fastbin field offset overflow for bin {index}"))?;
        let field_addr = arena_addr.checked_add(field_offset).with_context(|| {
            format!("main_arena fastbin field address overflow at 0x{field_offset:x}")
        })?;

        let Ok(head) = read_word(pid, field_addr) else {
            continue;
        };
        read_any = true;

        let fastbin_head = classify_fastbin_head(
            index,
            field_offset,
            head,
            heap_snapshot,
            heap_tracker,
            profile,
        );
        if head != 0 {
            chains.push(read_fastbin_chain(
                pid,
                index,
                profile.fastbin_chunk_size_for_index(index),
                head,
                heap_snapshot,
                heap_tracker,
                profile,
                max_fastbin_chain,
            ));
        }
        heads.push(fastbin_head);
    }

    if !read_any {
        bail!("failed to read any main_arena fastbin head fields");
    }

    Ok(Some(FastbinsSnapshot {
        arena_addr,
        heads,
        chains,
    }))
}

fn read_fastbin_chain(
    pid: Pid,
    index: usize,
    chunk_size: u64,
    head: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_fastbin_chain: usize,
) -> FastbinChain {
    let mut current = head;
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut truncated = false;
    let mut stopped_on_unknown_next = false;
    let mut cycle_detected = false;

    while current != 0 {
        if nodes.len() >= max_fastbin_chain {
            truncated = true;
            break;
        }
        if !seen.insert(current) {
            cycle_detected = true;
            truncated = true;
            break;
        }

        let user_addr = fastbin_head_user_addr(current, profile);
        let Ok(encoded_next) = read_word(pid, user_addr) else {
            stopped_on_unknown_next = true;
            break;
        };
        let decoded_next = decode_safe_linked_ptr(encoded_next, user_addr);
        nodes.push(classify_fastbin_node(
            current,
            user_addr,
            encoded_next,
            decoded_next,
            heap_snapshot,
            heap_tracker,
        ));

        if decoded_next == 0 {
            break;
        }
        if !fastbin_chain_next_is_plausible(decoded_next, heap_snapshot, profile) {
            stopped_on_unknown_next = true;
            break;
        }

        current = decoded_next;
    }

    FastbinChain {
        index,
        chunk_size,
        head,
        nodes,
        truncated,
        stopped_on_unknown_next,
        cycle_detected,
    }
}

#[allow(clippy::too_many_arguments)]
fn read_unsorted_bin_chain(
    pid: Pid,
    sentinel_addr: u64,
    head: u64,
    tail: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_unsorted_chain: usize,
) -> UnsortedBinChain {
    let empty = head == sentinel_addr && tail == sentinel_addr;
    if empty {
        return UnsortedBinChain {
            sentinel_addr,
            head,
            tail,
            nodes: Vec::new(),
            empty: true,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        };
    }

    let mut current = head;
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut truncated = false;
    let mut stopped_on_unknown_next = false;
    let mut cycle_detected = false;

    while current != sentinel_addr {
        if nodes.len() >= max_unsorted_chain {
            truncated = true;
            break;
        }
        if !seen.insert(current) {
            cycle_detected = true;
            truncated = true;
            break;
        }
        if !unsorted_chain_next_is_plausible(current, heap_snapshot, profile) {
            stopped_on_unknown_next = true;
            break;
        }

        let user_addr = current + profile.chunk_header_size;
        let Ok(node_fd) = read_word(pid, user_addr) else {
            stopped_on_unknown_next = true;
            break;
        };
        let Ok(node_bk) = read_word(pid, user_addr + profile.pointer_size) else {
            stopped_on_unknown_next = true;
            break;
        };

        nodes.push(classify_unsorted_bin_node(
            current,
            user_addr,
            node_fd,
            node_bk,
            sentinel_addr,
            heap_snapshot,
            heap_tracker,
        ));

        if node_fd == sentinel_addr {
            break;
        }
        if !unsorted_chain_next_is_plausible(node_fd, heap_snapshot, profile) {
            stopped_on_unknown_next = true;
            break;
        }

        current = node_fd;
    }

    let fd_bk_consistent = unsorted_chain_fd_bk_consistent(
        sentinel_addr,
        &nodes,
        truncated,
        stopped_on_unknown_next,
        cycle_detected,
    );

    UnsortedBinChain {
        sentinel_addr,
        head,
        tail,
        nodes,
        empty: false,
        truncated,
        stopped_on_unknown_next,
        cycle_detected,
        fd_bk_consistent,
    }
}

#[allow(clippy::too_many_arguments)]
fn read_smallbin_chain(
    pid: Pid,
    regular_index: usize,
    glibc_bin_index: usize,
    expected_chunk_size: u64,
    sentinel_addr: u64,
    head: u64,
    tail: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_smallbin_chain: usize,
) -> SmallbinChain {
    let empty = head == sentinel_addr && tail == sentinel_addr;
    if empty {
        return SmallbinChain {
            regular_index,
            glibc_bin_index,
            expected_chunk_size,
            sentinel_addr,
            head,
            tail,
            nodes: Vec::new(),
            empty: true,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        };
    }

    let mut current = head;
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut truncated = false;
    let mut stopped_on_unknown_next = false;
    let mut cycle_detected = false;

    while current != sentinel_addr {
        if nodes.len() >= max_smallbin_chain {
            truncated = true;
            break;
        }
        if !seen.insert(current) {
            cycle_detected = true;
            truncated = true;
            break;
        }
        if !unsorted_chain_next_is_plausible(current, heap_snapshot, profile) {
            stopped_on_unknown_next = true;
            break;
        }

        let user_addr = current + profile.chunk_header_size;
        let Ok(node_fd) = read_word(pid, user_addr) else {
            stopped_on_unknown_next = true;
            break;
        };
        let Ok(node_bk) = read_word(pid, user_addr + profile.pointer_size) else {
            stopped_on_unknown_next = true;
            break;
        };

        nodes.push(classify_smallbin_node(
            current,
            user_addr,
            node_fd,
            node_bk,
            sentinel_addr,
            heap_snapshot,
            heap_tracker,
        ));

        if node_fd == sentinel_addr {
            break;
        }
        if !unsorted_chain_next_is_plausible(node_fd, heap_snapshot, profile) {
            stopped_on_unknown_next = true;
            break;
        }

        current = node_fd;
    }

    let fd_bk_consistent = smallbin_chain_fd_bk_consistent(
        sentinel_addr,
        &nodes,
        truncated,
        stopped_on_unknown_next,
        cycle_detected,
    );

    SmallbinChain {
        regular_index,
        glibc_bin_index,
        expected_chunk_size,
        sentinel_addr,
        head,
        tail,
        nodes,
        empty: false,
        truncated,
        stopped_on_unknown_next,
        cycle_detected,
        fd_bk_consistent,
    }
}

#[allow(clippy::too_many_arguments)]
fn read_largebin_chain(
    pid: Pid,
    arena_addr: u64,
    regular_index: usize,
    glibc_bin_index: usize,
    sentinel_addr: u64,
    head: u64,
    tail: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    max_largebin_chain: usize,
) -> LargebinChain {
    let empty = head == sentinel_addr && tail == sentinel_addr;
    if empty {
        return LargebinChain {
            regular_index,
            glibc_bin_index,
            sentinel_addr,
            head,
            tail,
            nodes: Vec::new(),
            empty: true,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        };
    }

    let mut current = head;
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut truncated = false;
    let mut stopped_on_unknown_next = false;
    let mut cycle_detected = false;

    while current != sentinel_addr {
        if nodes.len() >= max_largebin_chain {
            truncated = true;
            break;
        }
        if !seen.insert(current) {
            cycle_detected = true;
            truncated = true;
            break;
        }
        if !unsorted_chain_next_is_plausible(current, heap_snapshot, profile) {
            stopped_on_unknown_next = true;
            break;
        }

        let user_addr = current + profile.chunk_header_size;
        let Ok(fd) = read_word(pid, user_addr) else {
            stopped_on_unknown_next = true;
            break;
        };
        let Ok(bk) = read_word(pid, user_addr + profile.pointer_size) else {
            stopped_on_unknown_next = true;
            break;
        };
        let fd_nextsize_addr = user_addr + 2 * profile.pointer_size;
        let bk_nextsize_addr = user_addr + 3 * profile.pointer_size;
        let Ok(fd_nextsize) = read_word(pid, fd_nextsize_addr) else {
            stopped_on_unknown_next = true;
            break;
        };
        let Ok(bk_nextsize) = read_word(pid, bk_nextsize_addr) else {
            stopped_on_unknown_next = true;
            break;
        };

        nodes.push(classify_largebin_node(
            arena_addr,
            current,
            user_addr,
            fd,
            bk,
            fd_nextsize,
            bk_nextsize,
            sentinel_addr,
            heap_snapshot,
            heap_tracker,
        ));

        if fd == sentinel_addr {
            break;
        }
        if !unsorted_chain_next_is_plausible(fd, heap_snapshot, profile) {
            stopped_on_unknown_next = true;
            break;
        }

        current = fd;
    }

    let fd_bk_consistent = largebin_chain_fd_bk_consistent(
        sentinel_addr,
        &nodes,
        truncated,
        stopped_on_unknown_next,
        cycle_detected,
    );

    LargebinChain {
        regular_index,
        glibc_bin_index,
        sentinel_addr,
        head,
        tail,
        nodes,
        empty: false,
        truncated,
        stopped_on_unknown_next,
        cycle_detected,
        fd_bk_consistent,
    }
}

fn fastbin_experiment_scan_offsets(profile: GlibcProfile) -> Vec<u64> {
    let end = profile.main_arena_top_offset.unwrap_or(0x80);
    (0..end)
        .step_by(profile.pointer_size as usize)
        .collect::<Vec<_>>()
}

pub fn read_main_arena_top_candidate(
    pid: Pid,
    arena_addr: u64,
    top_field_offset: u64,
    heap_snapshot: &GlibcHeapSnapshot,
) -> Result<MainArenaTopCandidate> {
    let field_addr = arena_addr.checked_add(top_field_offset).with_context(|| {
        format!("main_arena top field address overflow at 0x{top_field_offset:x}")
    })?;
    let top_addr = read_word(pid, field_addr)?;

    Ok(classify_main_arena_top_candidate(
        arena_addr,
        top_field_offset,
        top_addr,
        heap_snapshot,
    ))
}

fn classify_fastbin_pointer_candidate(
    field_offset: u64,
    value: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Option<FastbinPointerCandidate> {
    let points_into_heap = heap_snapshot.heap_start <= value && value < heap_snapshot.heap_end;
    if !points_into_heap {
        return None;
    }

    let matched_chunk = heap_snapshot
        .chunks
        .iter()
        .find(|chunk| chunk.chunk_addr == value);
    let user_addr = fastbin_candidate_user_addr(value, profile);
    let known_freed = heap_tracker
        .state_for_user_addr(user_addr)
        .map(|state| state == ObservedChunkState::Freed);

    Some(FastbinPointerCandidate {
        field_offset,
        value,
        possible_chunk_size: matched_chunk.map(|chunk| chunk.size),
        points_into_heap,
        matches_heap_chunk: matched_chunk.is_some(),
        known_freed,
        role: FastbinExperimentRole::FastbinCandidate,
    })
}

fn classify_unsorted_bin_pointer_candidate(
    field_offset: u64,
    fd: u64,
    bk: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Option<UnsortedBinPointerCandidate> {
    let fd_points_into_heap = points_into_heap(fd, heap_snapshot);
    let bk_points_into_heap = points_into_heap(bk, heap_snapshot);
    if !fd_points_into_heap && !bk_points_into_heap {
        return None;
    }

    Some(UnsortedBinPointerCandidate {
        field_offset,
        fd,
        bk,
        fd_points_into_heap,
        bk_points_into_heap,
        fd_matches_heap_chunk: matches_heap_chunk(fd, heap_snapshot),
        bk_matches_heap_chunk: matches_heap_chunk(bk, heap_snapshot),
        fd_known_freed: unsorted_candidate_known_freed(
            fd,
            fd_points_into_heap,
            heap_tracker,
            profile,
        ),
        bk_known_freed: unsorted_candidate_known_freed(
            bk,
            bk_points_into_heap,
            heap_tracker,
            profile,
        ),
        role: UnsortedExperimentRole::UnsortedCandidate,
    })
}

fn classify_bin_pointer_candidate(
    arena_addr: u64,
    field_offset: u64,
    fd: u64,
    bk: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Option<BinPointerCandidate> {
    let fd_points_into_heap = points_into_heap(fd, heap_snapshot);
    let bk_points_into_heap = points_into_heap(bk, heap_snapshot);
    let fd_points_into_arena = points_into_arena(fd, arena_addr);
    let bk_points_into_arena = points_into_arena(bk, arena_addr);
    if !fd_points_into_heap
        && !bk_points_into_heap
        && !fd_points_into_arena
        && !bk_points_into_arena
    {
        return None;
    }

    Some(BinPointerCandidate {
        field_offset,
        fd,
        bk,
        fd_points_into_heap,
        bk_points_into_heap,
        fd_points_into_arena,
        bk_points_into_arena,
        fd_matches_heap_chunk: matches_heap_chunk(fd, heap_snapshot),
        bk_matches_heap_chunk: matches_heap_chunk(bk, heap_snapshot),
        fd_known_freed: bin_candidate_known_freed(fd, fd_points_into_heap, heap_tracker, profile),
        bk_known_freed: bin_candidate_known_freed(bk, bk_points_into_heap, heap_tracker, profile),
        role: BinExperimentRole::BinSentinelCandidate,
    })
}

#[allow(clippy::too_many_arguments)]
fn classify_regular_bin_head(
    arena_addr: u64,
    index: usize,
    field_offset: u64,
    fd: u64,
    bk: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Result<RegularBinHead> {
    let sentinel_addr = arena_addr.checked_add(field_offset).with_context(|| {
        format!("main_arena regular bin sentinel address overflow at 0x{field_offset:x}")
    })?;
    let fd_points_into_heap = points_into_heap(fd, heap_snapshot);
    let bk_points_into_heap = points_into_heap(bk, heap_snapshot);
    let fd_points_into_arena = points_into_arena_wide(fd, arena_addr);
    let bk_points_into_arena = points_into_arena_wide(bk, arena_addr);
    let (glibc_bin_index, role, chunk_size) =
        heapify_core::glibc::regular_bin_metadata(index, profile);

    Ok(RegularBinHead {
        index,
        glibc_bin_index,
        role,
        chunk_size,
        field_offset,
        fd,
        bk,
        empty: fd == sentinel_addr && bk == sentinel_addr,
        fd_points_into_heap,
        bk_points_into_heap,
        fd_points_into_arena,
        bk_points_into_arena,
        fd_matches_heap_chunk: matches_heap_chunk(fd, heap_snapshot),
        bk_matches_heap_chunk: matches_heap_chunk(bk, heap_snapshot),
        fd_known_freed: bin_candidate_known_freed(fd, fd_points_into_heap, heap_tracker, profile),
        bk_known_freed: bin_candidate_known_freed(bk, bk_points_into_heap, heap_tracker, profile),
    })
}

fn classify_unsorted_bin_snapshot(
    arena_addr: u64,
    field_offset: u64,
    fd: u64,
    bk: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
    chain: Option<UnsortedBinChain>,
) -> UnsortedBinSnapshot {
    let fd_points_into_heap = points_into_heap(fd, heap_snapshot);
    let bk_points_into_heap = points_into_heap(bk, heap_snapshot);

    UnsortedBinSnapshot {
        arena_addr,
        field_offset,
        fd,
        bk,
        fd_points_into_heap,
        bk_points_into_heap,
        fd_matches_heap_chunk: matches_heap_chunk(fd, heap_snapshot),
        bk_matches_heap_chunk: matches_heap_chunk(bk, heap_snapshot),
        fd_known_freed: unsorted_candidate_known_freed(
            fd,
            fd_points_into_heap,
            heap_tracker,
            profile,
        ),
        bk_known_freed: unsorted_candidate_known_freed(
            bk,
            bk_points_into_heap,
            heap_tracker,
            profile,
        ),
        chain,
    }
}

fn classify_unsorted_bin_node(
    chunk_addr: u64,
    user_addr: u64,
    fd: u64,
    bk: u64,
    sentinel_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
) -> UnsortedBinNode {
    let matched_chunk = heap_snapshot
        .chunks
        .iter()
        .find(|chunk| chunk.chunk_addr == chunk_addr);
    let known_freed = heap_tracker
        .state_for_user_addr(user_addr)
        .map(|state| state == ObservedChunkState::Freed);

    UnsortedBinNode {
        chunk_addr,
        user_addr,
        fd,
        bk,
        chunk_size: matched_chunk.map(|chunk| chunk.size),
        matches_heap_chunk: matched_chunk.is_some(),
        known_freed,
        fd_points_to_sentinel: fd == sentinel_addr,
        bk_points_to_sentinel: bk == sentinel_addr,
    }
}

fn classify_smallbin_node(
    chunk_addr: u64,
    user_addr: u64,
    fd: u64,
    bk: u64,
    sentinel_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
) -> SmallbinNode {
    let matched_chunk = heap_snapshot
        .chunks
        .iter()
        .find(|chunk| chunk.chunk_addr == chunk_addr);
    let known_freed = heap_tracker
        .state_for_user_addr(user_addr)
        .map(|state| state == ObservedChunkState::Freed);

    SmallbinNode {
        chunk_addr,
        user_addr,
        fd,
        bk,
        chunk_size: matched_chunk.map(|chunk| chunk.size),
        matches_heap_chunk: matched_chunk.is_some(),
        known_freed,
        fd_points_to_sentinel: fd == sentinel_addr,
        bk_points_to_sentinel: bk == sentinel_addr,
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_largebin_node(
    arena_addr: u64,
    chunk_addr: u64,
    user_addr: u64,
    fd: u64,
    bk: u64,
    fd_nextsize: u64,
    bk_nextsize: u64,
    sentinel_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
) -> LargebinNode {
    let matched_chunk = heap_snapshot
        .chunks
        .iter()
        .find(|chunk| chunk.chunk_addr == chunk_addr);
    let known_freed = heap_tracker
        .state_for_user_addr(user_addr)
        .map(|state| state == ObservedChunkState::Freed);

    LargebinNode {
        chunk_addr,
        user_addr,
        fd,
        bk,
        fd_nextsize,
        bk_nextsize,
        chunk_size: matched_chunk.map(|chunk| chunk.size),
        matches_heap_chunk: matched_chunk.is_some(),
        known_freed,
        fd_points_to_sentinel: fd == sentinel_addr,
        bk_points_to_sentinel: bk == sentinel_addr,
        fd_nextsize_points_into_heap: points_into_heap(fd_nextsize, heap_snapshot),
        bk_nextsize_points_into_heap: points_into_heap(bk_nextsize, heap_snapshot),
        fd_nextsize_points_into_arena: points_into_arena_wide(fd_nextsize, arena_addr),
        bk_nextsize_points_into_arena: points_into_arena_wide(bk_nextsize, arena_addr),
    }
}

fn unsorted_chain_fd_bk_consistent(
    sentinel_addr: u64,
    nodes: &[UnsortedBinNode],
    truncated: bool,
    stopped_on_unknown_next: bool,
    cycle_detected: bool,
) -> bool {
    if truncated || stopped_on_unknown_next || cycle_detected || nodes.is_empty() {
        return false;
    }
    if nodes.first().is_some_and(|node| node.bk != sentinel_addr) {
        return false;
    }
    if nodes.last().is_some_and(|node| node.fd != sentinel_addr) {
        return false;
    }

    nodes.windows(2).all(|pair| {
        let current = &pair[0];
        let next = &pair[1];
        current.fd == next.chunk_addr && next.bk == current.chunk_addr
    })
}

fn largebin_chain_fd_bk_consistent(
    sentinel_addr: u64,
    nodes: &[LargebinNode],
    truncated: bool,
    stopped_on_unknown_next: bool,
    cycle_detected: bool,
) -> bool {
    if truncated || stopped_on_unknown_next || cycle_detected || nodes.is_empty() {
        return false;
    }
    if nodes.first().is_some_and(|node| node.bk != sentinel_addr) {
        return false;
    }
    if nodes.last().is_some_and(|node| node.fd != sentinel_addr) {
        return false;
    }

    nodes.windows(2).all(|pair| {
        let current = &pair[0];
        let next = &pair[1];
        current.fd == next.chunk_addr && next.bk == current.chunk_addr
    })
}

fn smallbin_chain_fd_bk_consistent(
    sentinel_addr: u64,
    nodes: &[SmallbinNode],
    truncated: bool,
    stopped_on_unknown_next: bool,
    cycle_detected: bool,
) -> bool {
    if truncated || stopped_on_unknown_next || cycle_detected || nodes.is_empty() {
        return false;
    }
    if nodes.first().is_some_and(|node| node.bk != sentinel_addr) {
        return false;
    }
    if nodes.last().is_some_and(|node| node.fd != sentinel_addr) {
        return false;
    }

    nodes.windows(2).all(|pair| {
        let current = &pair[0];
        let next = &pair[1];
        current.fd == next.chunk_addr && next.bk == current.chunk_addr
    })
}

fn unsorted_candidate_known_freed(
    ptr: u64,
    points_into_heap: bool,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Option<bool> {
    if !points_into_heap {
        return None;
    }

    heap_tracker
        .state_for_user_addr(ptr + profile.chunk_header_size)
        .map(|state| state == ObservedChunkState::Freed)
}

fn bin_candidate_known_freed(
    ptr: u64,
    points_into_heap: bool,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> Option<bool> {
    if !points_into_heap {
        return None;
    }

    heap_tracker
        .state_for_user_addr(ptr + profile.chunk_header_size)
        .map(|state| state == ObservedChunkState::Freed)
}

fn points_into_heap(ptr: u64, heap_snapshot: &GlibcHeapSnapshot) -> bool {
    heap_snapshot.heap_start <= ptr && ptr < heap_snapshot.heap_end
}

fn points_into_arena(ptr: u64, arena_addr: u64) -> bool {
    arena_addr <= ptr && ptr < arena_addr.saturating_add(0x1000)
}

fn points_into_arena_wide(ptr: u64, arena_addr: u64) -> bool {
    arena_addr <= ptr && ptr < arena_addr.saturating_add(0x2000)
}

fn matches_heap_chunk(ptr: u64, heap_snapshot: &GlibcHeapSnapshot) -> bool {
    heap_snapshot
        .chunks
        .iter()
        .any(|chunk| chunk.chunk_addr == ptr)
}

fn classify_fastbin_head(
    index: usize,
    field_offset: u64,
    head: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) -> FastbinHead {
    let points_into_heap =
        head != 0 && heap_snapshot.heap_start <= head && head < heap_snapshot.heap_end;
    let matches_heap_chunk = head != 0
        && heap_snapshot
            .chunks
            .iter()
            .any(|chunk| chunk.chunk_addr == head);
    let known_freed = if head == 0 {
        None
    } else {
        heap_tracker
            .state_for_user_addr(fastbin_head_user_addr(head, profile))
            .map(|state| state == ObservedChunkState::Freed)
    };

    FastbinHead {
        index,
        chunk_size: profile.fastbin_chunk_size_for_index(index),
        field_offset,
        head,
        points_into_heap,
        matches_heap_chunk,
        known_freed,
    }
}

fn classify_fastbin_node(
    chunk_addr: u64,
    user_addr: u64,
    encoded_next: u64,
    decoded_next: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    heap_tracker: &HeapTracker,
) -> FastbinNode {
    let matched_chunk = heap_snapshot
        .chunks
        .iter()
        .find(|chunk| chunk.chunk_addr == chunk_addr);
    let known_freed = heap_tracker
        .state_for_user_addr(user_addr)
        .map(|state| state == ObservedChunkState::Freed);

    FastbinNode {
        chunk_addr,
        user_addr,
        encoded_next,
        decoded_next,
        chunk_size: matched_chunk.map(|chunk| chunk.size),
        matches_heap_chunk: matched_chunk.is_some(),
        known_freed,
    }
}

fn fastbin_chain_next_is_plausible(
    decoded_next: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    profile: GlibcProfile,
) -> bool {
    heap_snapshot.heap_start <= decoded_next
        && decoded_next < heap_snapshot.heap_end
        && decoded_next % profile.malloc_alignment == 0
}

fn unsorted_chain_next_is_plausible(
    decoded_next: u64,
    heap_snapshot: &GlibcHeapSnapshot,
    profile: GlibcProfile,
) -> bool {
    heap_snapshot.heap_start <= decoded_next
        && decoded_next < heap_snapshot.heap_end
        && decoded_next % profile.malloc_alignment == 0
}

fn fastbin_head_user_addr(chunk_addr: u64, profile: GlibcProfile) -> u64 {
    chunk_addr + profile.chunk_header_size
}

fn fastbin_candidate_user_addr(chunk_addr: u64, profile: GlibcProfile) -> u64 {
    chunk_addr + profile.chunk_header_size
}

fn classify_main_arena_top_candidate(
    arena_addr: u64,
    field_offset: u64,
    top_addr: u64,
    heap_snapshot: &GlibcHeapSnapshot,
) -> MainArenaTopCandidate {
    let points_into_heap =
        heap_snapshot.heap_start <= top_addr && top_addr < heap_snapshot.heap_end;
    let matched_chunk = heap_snapshot
        .chunks
        .iter()
        .find(|chunk| chunk.chunk_addr == top_addr);
    let matches_heap_chunk = matched_chunk.is_some();
    let status = if matches_heap_chunk {
        MainArenaTopStatus::MatchesWalkedChunk
    } else if points_into_heap {
        MainArenaTopStatus::PointsIntoHeap
    } else {
        MainArenaTopStatus::OutsideHeap
    };

    MainArenaTopCandidate {
        arena_addr,
        field_offset,
        top_addr,
        points_into_heap,
        matches_heap_chunk,
        chunk_size: matched_chunk.map(|chunk| chunk.size),
        status,
        source: heapify_core::glibc::MainArenaFieldSource::UserOffset,
        profile_name: None,
    }
}

fn classify_main_arena_pointer_candidate(
    field_offset: u64,
    value: u64,
    heap_snapshot: &GlibcHeapSnapshot,
) -> Option<MainArenaPointerCandidate> {
    let points_into_heap = heap_snapshot.heap_start <= value && value < heap_snapshot.heap_end;
    if !points_into_heap {
        return None;
    }

    let matched_chunk = heap_snapshot
        .chunks
        .iter()
        .find(|chunk| chunk.chunk_addr == value);
    let last_chunk_addr = heap_snapshot.chunks.last().map(|chunk| chunk.chunk_addr);
    let role_hint = if Some(value) == last_chunk_addr {
        MainArenaRoleHint::CandidateTop
    } else {
        MainArenaRoleHint::HeapPointer
    };

    Some(MainArenaPointerCandidate {
        field_offset,
        value,
        points_into_heap,
        matches_heap_chunk: matched_chunk.is_some(),
        matched_chunk_size: matched_chunk.map(|chunk| chunk.size),
        role_hint,
    })
}

pub fn detect_glibc_version_from_file(path: &Path) -> Result<Option<String>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read libc file {}", path.display()))?;
    Ok(detect_glibc_version_from_bytes(&bytes))
}

pub fn detect_glibc_version_from_bytes(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    if let Some(index) = text.find("GNU C Library") {
        if let Some(version) = find_glibc_numeric_version(&text[index..]) {
            return Some(version);
        }
    }

    highest_glibc_symbol_version(&text)
}

pub fn detect_libc_metadata(pid: Pid) -> Result<Option<LibcMetadata>> {
    detect_libc_metadata_with_supplied(pid, None)
}

pub fn detect_libc_metadata_with_supplied(
    pid: Pid,
    supplied_libc_path: Option<&Path>,
) -> Result<Option<LibcMetadata>> {
    let Some(mapping) = find_libc_mapping(pid)? else {
        return Ok(None);
    };
    let Some(path) = mapping.pathname else {
        return Ok(None);
    };

    let supplied_path = supplied_libc_path.map(|path| path.to_string_lossy().into_owned());
    let paths_match =
        supplied_libc_path.and_then(|supplied| paths_same_best_effort(supplied, Path::new(&path)));
    let version_path = supplied_libc_path.unwrap_or_else(|| Path::new(&path));
    let version = detect_glibc_version_from_file(version_path).unwrap_or(None);
    Ok(Some(LibcMetadata {
        path,
        supplied_path,
        paths_match,
        version,
    }))
}

pub fn paths_same_best_effort(a: &Path, b: &Path) -> Option<bool> {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => Some(a == b),
        _ if a.is_absolute() && b.is_absolute() => Some(a == b),
        _ => None,
    }
}

fn find_glibc_numeric_version(text: &str) -> Option<String> {
    for (index, _) in text.match_indices("2.") {
        let version = read_dotted_numeric_version(&text[index..])?;
        if version_components(&version).len() >= 2 {
            return Some(version);
        }
    }

    None
}

fn highest_glibc_symbol_version(text: &str) -> Option<String> {
    let mut highest = None::<String>;
    for (index, _) in text.match_indices("GLIBC_2.") {
        let version_start = index + "GLIBC_".len();
        let Some(version) = read_dotted_numeric_version(&text[version_start..]) else {
            continue;
        };

        if highest
            .as_ref()
            .map(|current| compare_versions(&version, current).is_gt())
            .unwrap_or(true)
        {
            highest = Some(version);
        }
    }

    highest
}

fn read_dotted_numeric_version(text: &str) -> Option<String> {
    let mut version = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            version.push(ch);
        } else {
            break;
        }
    }

    while version.ends_with('.') {
        version.pop();
    }

    if version.is_empty() || !version.contains('.') {
        None
    } else {
        Some(version)
    }
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left = version_components(left);
    let right = version_components(right);
    let max_len = left.len().max(right.len());

    for index in 0..max_len {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }

    std::cmp::Ordering::Equal
}

fn version_components(version: &str) -> Vec<u64> {
    version
        .split('.')
        .filter_map(|part| part.parse::<u64>().ok())
        .collect()
}

pub fn read_tcache_entry_candidate(pid: Pid, user_addr: u64) -> Result<TcacheEntryCandidate> {
    let encoded_next = read_word(pid, user_addr)?;
    let decoded_next = decode_safe_linked_ptr(encoded_next, user_addr);

    Ok(TcacheEntryCandidate {
        storage_addr: user_addr,
        encoded_next,
        decoded_next,
    })
}

pub fn read_tcache_snapshot_candidate(
    pid: Pid,
    candidate: &TcacheStructCandidate,
) -> Result<TcacheSnapshotCandidate> {
    read_tcache_snapshot_candidate_with_profile(pid, candidate, GLIBC_X86_64_MODERN)
}

pub fn read_tcache_snapshot_candidate_with_profile(
    pid: Pid,
    candidate: &TcacheStructCandidate,
    profile: GlibcProfile,
) -> Result<TcacheSnapshotCandidate> {
    let counts_base = candidate.user_addr + profile.tcache_counts_offset;
    let entries_base = candidate.user_addr + profile.tcache_entries_offset;
    let mut bins = Vec::new();

    for index in 0..profile.tcache_bin_count {
        let count = read_u16(pid, counts_base + index as u64 * profile.tcache_count_size)?;
        let head = read_word(pid, entries_base + index as u64 * profile.pointer_size)?;

        if count != 0 || head != 0 {
            bins.push(TcacheBinSnapshot {
                index,
                chunk_size: profile.tcache_chunk_size_for_index(index),
                count,
                head,
            });
        }
    }

    Ok(TcacheSnapshotCandidate {
        struct_user_addr: candidate.user_addr,
        bins,
    })
}

pub fn read_glibc_heap_snapshot(
    pid: Pid,
    heap_start: u64,
    heap_end: u64,
) -> Result<GlibcHeapSnapshot> {
    read_glibc_heap_snapshot_with_profile(pid, heap_start, heap_end, GLIBC_X86_64_MODERN)
}

pub fn read_glibc_heap_snapshot_with_profile(
    pid: Pid,
    heap_start: u64,
    heap_end: u64,
    profile: GlibcProfile,
) -> Result<GlibcHeapSnapshot> {
    let mut current = heap_start;
    let mut chunks = Vec::new();
    let mut truncated = false;

    while current < heap_end {
        if chunks.len() >= 4096 {
            truncated = true;
            break;
        }

        let prev_size = match read_word(pid, current) {
            Ok(prev_size) => prev_size,
            Err(err) if chunks.is_empty() => return Err(err),
            Err(_) => {
                truncated = true;
                break;
            }
        };
        let size_raw = match read_word(pid, current + profile.pointer_size) {
            Ok(size_raw) => size_raw,
            Err(err) if chunks.is_empty() => return Err(err),
            Err(_) => {
                truncated = true;
                break;
            }
        };

        let header =
            GlibcChunkHeader::from_chunk_parts_with_profile(current, prev_size, size_raw, profile);
        let size = header.size;
        chunks.push(header);

        if size == 0 || size < profile.min_chunk_size || !profile.is_aligned_chunk_size(size) {
            truncated = true;
            break;
        }

        let Some(next) = current.checked_add(size) else {
            truncated = true;
            break;
        };
        if next > heap_end {
            truncated = true;
            break;
        }

        current = next;
    }

    Ok(GlibcHeapSnapshot {
        heap_start,
        heap_end,
        chunks,
        truncated,
    })
}

fn read_optional_glibc_chunk_header(
    pid: Pid,
    user_addr: u64,
    profile: GlibcProfile,
) -> Option<GlibcChunkHeader> {
    if user_addr == 0 {
        return None;
    }

    read_glibc_chunk_header_with_profile(pid, user_addr, profile).ok()
}

fn read_optional_tcache_entry_candidate(pid: Pid, user_addr: u64) -> Option<TcacheEntryCandidate> {
    if user_addr == 0 {
        return None;
    }

    read_tcache_entry_candidate(pid, user_addr).ok()
}

fn try_discover_heap_mapping<F>(pid: Pid, state: &mut TraceHeapState<F>)
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    if state.heap_mapping.is_some() {
        return;
    }

    let Ok(Some(mapping)) = maps::find_heap_mapping(pid) else {
        return;
    };

    state.heap_mapping = Some(mapping);
}

fn try_print_heap_mapping<F>(pid: Pid, state: &mut TraceHeapState<F>)
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    try_discover_heap_mapping(pid, state);
    print_heap_mapping_once(state);
}

fn print_heap_mapping_once<F>(state: &mut TraceHeapState<F>)
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    if state.heap_mapping_printed {
        return;
    }

    if !state.show_status {
        return;
    }

    let Some(mapping) = &state.heap_mapping else {
        return;
    };

    print_heap_mapping(mapping);
    state.heap_mapping_printed = true;
}

fn try_detect_and_print_libc_metadata<F>(pid: Pid, state: &mut TraceHeapState<F>)
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    if state.libc_metadata.is_some() {
        return;
    }

    let Some(metadata) =
        detect_libc_metadata_with_supplied(pid, state.supplied_libc_path.as_deref())
            .unwrap_or(None)
    else {
        return;
    };

    if state.show_status && !state.libc_metadata_printed {
        print_libc_metadata(&metadata);
        if !state.glibc_profile_suggestion_printed {
            print_suggested_glibc_profile(state.glibc_profile, &metadata);
            state.glibc_profile_suggestion_printed = true;
        }
        state.libc_metadata_printed = true;
    }
    state.libc_metadata = Some(metadata);
}

fn print_missing_libc_metadata_at_trace_end<F>(state: &mut TraceHeapState<F>)
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    if !state.show_status || state.libc_metadata.is_some() || state.libc_metadata_printed {
        return;
    }

    print_unknown_libc_metadata();
    state.libc_metadata_printed = true;
}

fn trace_heap_context<F>(pid: Pid, state: &TraceHeapState<F>) -> TraceHeapContext
where
    F: FnMut(HeapTraceEvent, TraceHeapContext) -> Result<AllocatorEventControl>,
{
    TraceHeapContext {
        pid,
        heap_mapping: state.heap_mapping.clone(),
        glibc_profile: state.glibc_profile,
    }
}

fn print_heap_mapping(mapping: &MemoryMapping) {
    println!(
        "[heapify] heap mapping: 0x{:x}-0x{:x} {} [heap]",
        mapping.start, mapping.end, mapping.permissions
    );
}

fn print_trace_session_profile_selection(selection: &GlibcProfileSelection) {
    println!(
        "[heapify] glibc profile: requested={} selected={} confidence={}",
        selection.requested,
        selection.selected,
        glibc_profile_confidence_label(selection.confidence)
    );
    println!("[heapify] glibc profile reason: {}", selection.reason);
    for warning in &selection.warnings {
        println!("[heapify] warning: {warning}");
    }
}

fn glibc_profile_confidence_label(
    confidence: heapify_core::glibc::GlibcProfileConfidence,
) -> &'static str {
    match confidence {
        heapify_core::glibc::GlibcProfileConfidence::High => "high",
        heapify_core::glibc::GlibcProfileConfidence::Medium => "medium",
        heapify_core::glibc::GlibcProfileConfidence::Low => "low",
    }
}

fn print_launch_metadata(plan: &ExecPlan) {
    println!("[heapify] launch mode: {}", plan.launch_mode.as_str());
    if let Some(cwd) = plan.cwd.as_ref() {
        println!("[heapify] cwd: {}", cwd.display());
    }
    if let Some(loader) = plan.loader_path.as_ref() {
        println!("[heapify] loader: {}", loader.display());
    }
    if let Some(library_path) = plan.effective_library_path.as_ref() {
        println!("[heapify] library path: {}", library_path.display());
    }
    if let Some(preload) = plan.preload_path.as_ref() {
        println!("[heapify] preload: {}", preload.display());
    }
    match &plan.stdin {
        StdinConfig::Inherit => {}
        StdinConfig::File(path) => println!("[heapify] stdin: file {}", path.display()),
        StdinConfig::Text(text) => println!("[heapify] stdin: text {} bytes", text.len()),
    }
    let user_env_set_keys = user_env_set_keys(plan);
    if plan.clear_env || !user_env_set_keys.is_empty() || !plan.env_unsets.is_empty() {
        println!(
            "[heapify] env: clear={} set={} unset={}",
            plan.clear_env,
            user_env_set_keys.len(),
            plan.env_unsets.len()
        );
        if !user_env_set_keys.is_empty() {
            println!("[heapify] env set: {}", user_env_set_keys.join(", "));
        }
        if !plan.env_unsets.is_empty() {
            println!("[heapify] env unset: {}", plan.env_unsets.join(", "));
        }
    }
}

fn user_env_set_keys(plan: &ExecPlan) -> Vec<String> {
    let auto_preload_count = usize::from(plan.preload_path.is_some());
    let user_len = plan.env_overrides.len().saturating_sub(auto_preload_count);
    plan.env_overrides
        .iter()
        .take(user_len)
        .map(|(key, _)| key.clone())
        .collect()
}

fn print_libc_metadata(libc: &LibcMetadata) {
    println!("[heapify] libc: {}", libc.path);
    if let Some(supplied_path) = libc.supplied_path.as_deref() {
        println!("[heapify] supplied libc: {supplied_path}");
    }
    println!(
        "[heapify] glibc version: {}",
        libc.version.as_deref().unwrap_or("unknown")
    );
    if libc.paths_match == Some(false) {
        println!(
            "[heapify] warning: supplied libc differs from loaded libc; symbol offsets may be wrong"
        );
    }
}

fn print_suggested_glibc_profile(selected_profile: GlibcProfile, libc: &LibcMetadata) {
    let Some(lines) = suggested_glibc_profile_hint_lines(selected_profile, libc) else {
        return;
    };

    for line in lines {
        println!("{line}");
    }
}

fn suggested_glibc_profile_hint_lines(
    selected_profile: GlibcProfile,
    libc: &LibcMetadata,
) -> Option<Vec<String>> {
    let Some(version) = libc.version.as_deref() else {
        return None;
    };
    let Some(suggested) = suggest_glibc_profile_for_version(version) else {
        return None;
    };
    if selected_profile.name == suggested.name {
        return None;
    }

    Some(vec![
        format!(
            "[heapify] detected glibc {version}; suggested profile: {}",
            suggested.name
        ),
        format!(
            "[heapify] hint: rerun with --glibc-profile {} for version-specific arena offsets",
            suggested.name
        ),
    ])
}

fn print_unknown_libc_metadata() {
    println!("[heapify] libc: unknown");
    println!("[heapify] glibc version: unknown");
}

fn write_word(pid: Pid, addr: u64, word: u64) -> Result<()> {
    ptrace::write(pid, addr as ptrace::AddressType, word as c_long)
        .with_context(|| format!("failed to write word at 0x{addr:x}"))
}

fn signal_to_deliver(signal: Signal) -> Option<Signal> {
    match signal {
        Signal::SIGTRAP | Signal::SIGSTOP => None,
        other => Some(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_exec_plan, capture_caller_addr_with, classify_bin_pointer_candidate,
        classify_fastbin_pointer_candidate, classify_main_arena_pointer_candidate,
        classify_main_arena_top_candidate, classify_regular_bin_head,
        classify_unsorted_bin_pointer_candidate, classify_unsorted_bin_snapshot,
        decode_x86_64_instruction, decoded_instruction_fallthrough,
        detect_glibc_version_from_bytes, extract_u16_from_word_le, fastbin_candidate_user_addr,
        fastbin_chain_next_is_plausible, fastbin_experiment_scan_offsets, fastbin_head_user_addr,
        libc_symbol_file, paths_same_best_effort, print_missing_libc_metadata_at_trace_end,
        read_disassembly_snapshot_with_reader, read_fastbin_chain,
        register_snapshot_from_x86_64_regs, regular_bin_snapshot_limit,
        return_address_source_lookup_addr, runtime_addr_to_source_relative_addr,
        runtime_objects_from_mappings, runtime_symbol_addr, select_source_path_candidates,
        should_continue_after_allocator_event, should_pause_after_allocator_event,
        signal_to_deliver, suggested_glibc_profile_hint_lines, target_runtime_load_bias,
        trace_heap_with_status, write_all_to_fd, AllocationTraceMode, AllocatorEventControl,
        Breakpoint, BreakpointManager, BreakpointOwner, BreakpointPurpose, DebuggerStopReason,
        DisassemblyFlowControl, LaunchConfig, LaunchMode, LibcMetadata, LiveCommand, LiveCommandId,
        LiveTargetStatus, LiveTraceRunMode, LiveWorkerPauseState, ManagedBreakpoint, MemoryMapping,
        ProcessSymbolizer, RegisterArch, RegisterRole, RuntimeSymbol, SourceBreakpointResolution,
        SourceLineRow, SourceLocation, StdinConfig, StepKind, TargetMemoryReader, TargetSymbolizer,
        TraceHeapState, UserBreakpoint, UserBreakpointId, UserBreakpointSpec,
    };
    use heapify_core::glibc::{
        BinExperimentRole, GlibcChunkHeader, GlibcHeapSnapshot, MainArenaRoleHint,
        MainArenaTopStatus, RegularBinRole, UnsortedExperimentRole, GLIBC_2_35_X86_64,
        GLIBC_X86_64_MODERN,
    };
    use heapify_core::tracker::HeapTracker;
    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::Pid;
    use nix::unistd::{execvp, fork, ForkResult};
    use std::path::{Path, PathBuf};

    struct SliceMemoryReader {
        base: u64,
        bytes: Vec<u8>,
    }

    impl TargetMemoryReader for SliceMemoryReader {
        fn read_memory(&self, address: u64, size: usize) -> anyhow::Result<Vec<u8>> {
            let offset = address
                .checked_sub(self.base)
                .ok_or_else(|| anyhow::anyhow!("address before test buffer"))?
                as usize;
            let end = offset
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("test read overflow"))?;
            if end > self.bytes.len() {
                anyhow::bail!("test read beyond buffer");
            }
            Ok(self.bytes[offset..end].to_vec())
        }
    }

    #[test]
    fn register_snapshot_get_and_summary_line_use_named_registers() {
        let regs = libc::user_regs_struct {
            r15: 0x15,
            r14: 0x14,
            r13: 0x13,
            r12: 0x12,
            rbp: 0x7fffffffdc80,
            rbx: 0xb,
            r11: 0x11,
            r10: 0x10,
            r9: 0x9,
            r8: 0x8,
            rax: 0xd972a0,
            rcx: 0x4,
            rdx: 0x3,
            rsi: 0x2,
            rdi: 0x1,
            orig_rax: 0xffff_ffff_ffff_ffff,
            rip: 0x4011a5,
            cs: 0x33,
            eflags: 0x246,
            rsp: 0x7fffffffdc30,
            ss: 0x2b,
            fs_base: 0x7000,
            gs_base: 0x8000,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        };

        let snapshot = register_snapshot_from_x86_64_regs(regs);

        assert_eq!(snapshot.arch, RegisterArch::X86_64);
        assert_eq!(snapshot.get("rip"), Some(0x4011a5));
        assert_eq!(snapshot.get("rax"), Some(0xd972a0));
        assert_eq!(snapshot.get("missing"), None);
        assert_eq!(
            snapshot.summary_line(),
            "rip=0x4011a5 rsp=0x7fffffffdc30 rbp=0x7fffffffdc80 rax=0xd972a0"
        );
    }

    #[test]
    fn register_snapshot_conversion_assigns_x86_64_roles() {
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.rip = 0x401000;
        regs.rsp = 0x7fff0000;
        regs.rbp = 0x7fff1000;
        regs.rax = 0x1234;
        regs.rdi = 1;
        regs.rsi = 2;
        regs.rdx = 3;
        regs.rcx = 4;
        regs.r8 = 5;
        regs.r9 = 6;
        regs.eflags = 0x246;

        let snapshot = register_snapshot_from_x86_64_regs(regs);
        let role = |name: &str| {
            snapshot
                .registers
                .iter()
                .find(|register| register.name == name)
                .and_then(|register| register.role)
        };

        assert_eq!(role("rip"), Some(RegisterRole::InstructionPointer));
        assert_eq!(role("rsp"), Some(RegisterRole::StackPointer));
        assert_eq!(role("rbp"), Some(RegisterRole::FramePointer));
        assert_eq!(role("rax"), Some(RegisterRole::ReturnValue));
        assert_eq!(role("rdi"), Some(RegisterRole::Argument));
        assert_eq!(role("r9"), Some(RegisterRole::Argument));
        assert_eq!(role("eflags"), Some(RegisterRole::Flags));
        assert_eq!(role("rbx"), Some(RegisterRole::General));
    }

    #[test]
    fn stack_snapshot_reader_collects_words_until_error() {
        let snapshot =
            super::read_stack_snapshot_with_reader(0x7fffffffdc30, 4, |addr| match addr {
                0x7fffffffdc30 => Ok(0x1111),
                0x7fffffffdc38 => Ok(0x2222),
                _ => anyhow::bail!("read failed"),
            });

        assert_eq!(snapshot.stack_pointer, 0x7fffffffdc30);
        assert_eq!(snapshot.word_size, 8);
        assert_eq!(snapshot.words.len(), 2);
        assert_eq!(snapshot.words[0].offset_from_sp, 0);
        assert_eq!(snapshot.words[0].address, 0x7fffffffdc30);
        assert_eq!(snapshot.words[0].value, 0x1111);
        assert_eq!(snapshot.words[1].offset_from_sp, 8);
        assert_eq!(snapshot.words[1].address, 0x7fffffffdc38);
        assert_eq!(snapshot.words[1].value, 0x2222);
        assert!(snapshot.truncated);
        assert!(snapshot
            .read_error
            .as_deref()
            .unwrap()
            .contains("read failed"));
    }

    #[test]
    fn extracts_u16_from_little_endian_word() {
        let word = 0x8877665544332211;

        assert_eq!(extract_u16_from_word_le(word, 0).unwrap(), 0x2211);
        assert_eq!(extract_u16_from_word_le(word, 2).unwrap(), 0x4433);
        assert_eq!(extract_u16_from_word_le(word, 6).unwrap(), 0x8877);
    }

    #[test]
    fn allocation_trace_mode_serializes_as_stable_string() {
        assert_eq!(AllocationTraceMode::TargetPlt.as_str(), "target_plt");
        assert_eq!(AllocationTraceMode::LibcSymbols.as_str(), "libc_symbols");
    }

    #[test]
    fn step_allocator_event_mode_does_not_continue_after_event() {
        assert!(should_continue_after_allocator_event(
            LiveTraceRunMode::Continuous
        ));
        assert!(should_continue_after_allocator_event(
            LiveTraceRunMode::UserInstructionStepOver
        ));
        assert!(!should_continue_after_allocator_event(
            LiveTraceRunMode::StepAllocatorEvent
        ));
    }

    #[test]
    fn step_allocator_event_and_break_condition_pause_once() {
        assert!(should_pause_after_allocator_event(
            LiveTraceRunMode::StepAllocatorEvent,
            AllocatorEventControl::Pause
        ));
        assert!(should_pause_after_allocator_event(
            LiveTraceRunMode::StepAllocatorEvent,
            AllocatorEventControl::Continue
        ));
        assert!(should_pause_after_allocator_event(
            LiveTraceRunMode::Continuous,
            AllocatorEventControl::Pause
        ));
        assert!(!should_pause_after_allocator_event(
            LiveTraceRunMode::Continuous,
            AllocatorEventControl::Continue
        ));
    }

    #[test]
    fn validate_live_command_allows_step_instruction_only_while_paused() {
        assert!(super::validate_live_command(
            LiveTargetStatus::Paused,
            LiveCommand::StepInstruction
        )
        .is_ok());
        for status in [
            LiveTargetStatus::NotStarted,
            LiveTargetStatus::Running,
            LiveTargetStatus::SteppingToNextAllocatorEvent,
            LiveTargetStatus::SteppingInstruction,
            LiveTargetStatus::Stopping,
            LiveTargetStatus::Exited,
        ] {
            assert!(super::validate_live_command(status, LiveCommand::StepInstruction).is_err());
        }
    }

    #[test]
    fn validate_live_command_allows_step_instruction_over_only_while_paused() {
        assert!(super::validate_live_command(
            LiveTargetStatus::Paused,
            LiveCommand::StepInstructionOver
        )
        .is_ok());
        for status in [
            LiveTargetStatus::NotStarted,
            LiveTargetStatus::Running,
            LiveTargetStatus::SteppingToNextAllocatorEvent,
            LiveTargetStatus::SteppingInstruction,
            LiveTargetStatus::SteppingInstructionOver,
            LiveTargetStatus::Stopping,
            LiveTargetStatus::Exited,
        ] {
            assert!(
                super::validate_live_command(status, LiveCommand::StepInstructionOver).is_err()
            );
        }
    }

    #[test]
    fn validate_live_command_allows_source_commands_only_while_paused() {
        for command in [LiveCommand::SourceStep, LiveCommand::SourceStepOver] {
            assert!(
                super::validate_live_command(LiveTargetStatus::Paused, command.clone()).is_ok()
            );
            for status in [
                LiveTargetStatus::NotStarted,
                LiveTargetStatus::Running,
                LiveTargetStatus::SteppingToNextAllocatorEvent,
                LiveTargetStatus::SteppingInstruction,
                LiveTargetStatus::SteppingInstructionOver,
                LiveTargetStatus::SourceStepping,
                LiveTargetStatus::SourceSteppingOver,
                LiveTargetStatus::Stopping,
                LiveTargetStatus::Exited,
            ] {
                assert!(super::validate_live_command(status, command.clone()).is_err());
            }
        }
    }

    #[test]
    fn validate_live_command_allows_inspect_code_only_while_paused() {
        let command = LiveCommand::InspectCodeAt {
            address: 0x4011a5,
            breakpoint_id: Some(UserBreakpointId(1)),
        };
        assert!(super::validate_live_command(LiveTargetStatus::Paused, command.clone()).is_ok());
        for status in [
            LiveTargetStatus::NotStarted,
            LiveTargetStatus::Running,
            LiveTargetStatus::SteppingToNextAllocatorEvent,
            LiveTargetStatus::SteppingInstruction,
            LiveTargetStatus::SteppingInstructionOver,
            LiveTargetStatus::Stopping,
            LiveTargetStatus::Exited,
        ] {
            assert!(super::validate_live_command(status, command.clone()).is_err());
        }
    }

    #[test]
    fn stable_pause_guard_rejects_internal_breakpoint_step_over() {
        let state = LiveWorkerPauseState {
            step_in_flight: Some(StepKind::InternalBreakpointStepOver),
            ..LiveWorkerPauseState::stable_user_pause()
        };

        let err = state.can_user_step_instruction().unwrap_err();

        assert_eq!(
            err,
            "cannot step instruction while Heapify is resolving an internal breakpoint"
        );
    }

    #[test]
    fn stable_pause_guard_requires_rearmed_breakpoints_and_no_return_breakpoint() {
        let disabled_breakpoint_state = LiveWorkerPauseState {
            managed_breakpoints_rearmed: false,
            ..LiveWorkerPauseState::stable_user_pause()
        };
        let temporary_return_state = LiveWorkerPauseState {
            temporary_return_breakpoint_in_flight: true,
            ..LiveWorkerPauseState::stable_user_pause()
        };

        assert!(disabled_breakpoint_state
            .can_user_step_instruction()
            .is_err());
        assert!(temporary_return_state.can_user_step_instruction().is_err());
        assert!(LiveWorkerPauseState::stable_user_pause()
            .can_user_step_instruction()
            .is_ok());
    }

    #[test]
    fn user_instruction_step_kind_is_distinct_from_internal_step_over() {
        assert_ne!(
            StepKind::UserInstructionStep,
            StepKind::InternalBreakpointStepOver
        );
        assert_ne!(
            StepKind::UserInstructionStepOver,
            StepKind::InternalBreakpointStepOver
        );
    }

    #[test]
    fn debugger_stop_reason_summary_lines_are_stable() {
        assert_eq!(
            DebuggerStopReason::InstructionStepOver {
                from_rip: 0x401000,
                to_rip: 0x401005
            }
            .summary_line(),
            "nexti completed: 0x401000 -> 0x401005"
        );
        assert_eq!(
            DebuggerStopReason::AllocatorEventStep { event_id: 7 }.summary_line(),
            "paused after allocator event #7"
        );
        assert_eq!(
            DebuggerStopReason::UserBreakpoint {
                breakpoint_id: UserBreakpointId(2),
                address: 0x4011a5,
                label: "main+0x37".to_string()
            }
            .summary_line(),
            "breakpoint 2 hit at 0x4011a5 (main+0x37)"
        );
        assert_eq!(
            DebuggerStopReason::SourceStep {
                from: SourceLocation {
                    file: Some("src/main.c".to_string()),
                    line: Some(12),
                    column: Some(1),
                },
                to: SourceLocation {
                    file: Some("src/main.c".to_string()),
                    line: Some(13),
                    column: Some(9),
                },
                instructions_executed: 8,
            }
            .summary_line(),
            "source-step: src/main.c:12 -> :13 after 8 instructions"
        );
        assert_eq!(
            DebuggerStopReason::SourceStepLimit {
                from: SourceLocation {
                    file: Some("src/main.c".to_string()),
                    line: Some(12),
                    column: None,
                },
                instructions_executed: 10000,
            }
            .summary_line(),
            "source-step limit reached after 10000 instructions"
        );
    }

    #[test]
    fn source_location_changed_uses_file_and_line_only() {
        let origin = SourceLocation {
            file: Some("src/./main.c".to_string()),
            line: Some(12),
            column: Some(1),
        };
        assert!(!super::source_location_changed(
            &origin,
            &SourceLocation {
                file: Some("src/main.c".to_string()),
                line: Some(12),
                column: Some(9),
            }
        ));
        assert!(super::source_location_changed(
            &origin,
            &SourceLocation {
                file: Some("src/main.c".to_string()),
                line: Some(13),
                column: Some(1),
            }
        ));
        assert!(super::source_location_changed(
            &origin,
            &SourceLocation {
                file: Some("src/other.c".to_string()),
                line: Some(12),
                column: Some(1),
            }
        ));
    }

    #[test]
    fn direct_call_instruction_decoding_computes_fallthrough() {
        let decoded = decode_x86_64_instruction(0x401000, &[0xe8, 0x01, 0x00, 0x00, 0x00]).unwrap();

        assert!(decoded.is_call);
        assert_eq!(decoded.length, 5);
        assert_eq!(decoded_instruction_fallthrough(&decoded), 0x401005);
    }

    #[test]
    fn disassembly_snapshot_extracts_direct_call_target() {
        let reader = SliceMemoryReader {
            base: 0x401000,
            bytes: [&[0xe8, 0x01, 0x00, 0x00, 0x00][..], &[0x90; 32][..]].concat(),
        };

        let snapshot = read_disassembly_snapshot_with_reader(&reader, 0x401000, 0, 16, 4);

        let current = snapshot.lines.iter().find(|line| line.is_current).unwrap();
        assert_eq!(current.bytes, vec![0xe8, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(current.mnemonic, "call");
        assert_eq!(current.target, Some(0x401006));
        assert_eq!(current.flow_control, Some(DisassemblyFlowControl::Call));
    }

    #[test]
    fn disassembly_snapshot_extracts_conditional_branch_target() {
        let reader = SliceMemoryReader {
            base: 0x401000,
            bytes: [&[0x75, 0x05][..], &[0x90; 32][..]].concat(),
        };

        let snapshot = read_disassembly_snapshot_with_reader(&reader, 0x401000, 0, 16, 4);

        let current = snapshot.lines.iter().find(|line| line.is_current).unwrap();
        assert_eq!(current.mnemonic, "jne");
        assert_eq!(current.target, Some(0x401007));
        assert_eq!(
            current.flow_control,
            Some(DisassemblyFlowControl::ConditionalBranch)
        );
    }

    #[test]
    fn disassembly_snapshot_leaves_indirect_call_target_unknown() {
        let reader = SliceMemoryReader {
            base: 0x401000,
            bytes: [&[0xff, 0xd0][..], &[0x90; 32][..]].concat(),
        };

        let snapshot = read_disassembly_snapshot_with_reader(&reader, 0x401000, 0, 16, 4);

        let current = snapshot.lines.iter().find(|line| line.is_current).unwrap();
        assert_eq!(current.mnemonic, "call");
        assert_eq!(current.target, None);
        assert_eq!(current.flow_control, Some(DisassemblyFlowControl::Call));
    }

    #[test]
    fn disassembly_snapshot_marks_current_rip_line() {
        let reader = SliceMemoryReader {
            base: 0x401000,
            bytes: [&[0x55, 0x48, 0x89, 0xe5, 0x90][..], &[0x90; 32][..]].concat(),
        };

        let snapshot = read_disassembly_snapshot_with_reader(&reader, 0x401004, 4, 16, 8);

        assert!(snapshot
            .lines
            .iter()
            .any(|line| { line.address == 0x401004 && line.is_current && line.mnemonic == "nop" }));
        assert!(snapshot.lines.iter().any(|line| line.address == 0x401000));
        assert!(snapshot.lines.iter().any(|line| line.address == 0x401001));
    }

    #[test]
    fn disassembly_snapshot_handles_truncated_memory_without_panic() {
        let reader = SliceMemoryReader {
            base: 0x401000,
            bytes: vec![0x0f],
        };

        let snapshot = read_disassembly_snapshot_with_reader(&reader, 0x401000, 0, 8, 4);

        assert!(snapshot.lines.is_empty());
        assert!(snapshot.read_error.is_some());
        assert!(snapshot.truncated_before || snapshot.truncated_after);
    }

    #[test]
    fn disassembly_snapshot_forward_decodes_from_rip() {
        let reader = SliceMemoryReader {
            base: 0x401000,
            bytes: [&[0x90, 0x90, 0xc3][..], &[0x90; 32][..]].concat(),
        };

        let snapshot = read_disassembly_snapshot_with_reader(&reader, 0x401000, 0, 8, 3);

        assert_eq!(
            snapshot
                .lines
                .iter()
                .map(|line| line.mnemonic.as_str())
                .collect::<Vec<_>>(),
            vec!["nop", "nop", "ret"]
        );
    }

    #[test]
    fn disassembly_snapshot_recovers_preceding_instructions_that_land_on_rip() {
        let reader = SliceMemoryReader {
            base: 0x401000,
            bytes: [&[0x55, 0x48, 0x89, 0xe5, 0x90][..], &[0x90; 32][..]].concat(),
        };

        let snapshot = read_disassembly_snapshot_with_reader(&reader, 0x401004, 4, 8, 8);

        assert_eq!(snapshot.lines[0].address, 0x401000);
        assert_eq!(snapshot.lines[1].address, 0x401001);
        assert!(snapshot.lines.iter().any(|line| line.address == 0x401004));
    }

    #[test]
    fn disassembly_snapshot_omits_uncertain_preceding_boundaries() {
        let reader = SliceMemoryReader {
            base: 0x401000,
            bytes: [&[0xff, 0xff, 0x90][..], &[0x90; 32][..]].concat(),
        };

        let snapshot = read_disassembly_snapshot_with_reader(&reader, 0x401002, 2, 8, 6);

        assert!(snapshot.lines.iter().all(|line| line.address >= 0x401002));
        assert!(snapshot.truncated_before);
    }

    #[test]
    fn breakpoint_owner_reports_purpose() {
        assert_eq!(
            BreakpointOwner::Allocator(super::BreakpointKind::MallocEntry).purpose(),
            BreakpointPurpose::ManagedAllocatorEntry
        );
        assert_eq!(
            BreakpointOwner::UserInstructionStepOver {
                command_id: LiveCommandId(1),
                from_rip: 0x401000,
            }
            .purpose(),
            BreakpointPurpose::UserInstructionStepOver
        );
        assert_eq!(
            BreakpointOwner::UserPersistent {
                breakpoint_id: UserBreakpointId(1)
            }
            .purpose(),
            BreakpointPurpose::UserPersistent
        );
    }

    #[test]
    fn breakpoint_ownership_removal_preserves_other_owner_at_same_address() {
        let mut manager = BreakpointManager::default();
        manager.breakpoints.insert(
            0x401005,
            ManagedBreakpoint {
                breakpoint: Breakpoint {
                    addr: 0x401005,
                    original_byte: 0x90,
                    enabled: true,
                },
                owners: vec![
                    BreakpointOwner::Allocator(super::BreakpointKind::MallocEntry),
                    BreakpointOwner::UserInstructionStepOver {
                        command_id: LiveCommandId(7),
                        from_rip: 0x401000,
                    },
                ],
            },
        );

        manager
            .remove_user_step_over_breakpoint(Pid::from_raw(999999), 0x401005)
            .unwrap();

        let managed = manager.breakpoints.get(&0x401005).unwrap();
        assert_eq!(managed.owners.len(), 1);
        assert!(matches!(
            managed.owners[0],
            BreakpointOwner::Allocator(super::BreakpointKind::MallocEntry)
        ));
        assert!(managed.breakpoint.enabled);
    }

    #[test]
    fn user_breakpoint_ids_are_monotonic_and_not_reused() {
        let mut manager = manager_with_enabled_allocator_owner(0x401005);
        let first = manager
            .add_user_breakpoint(
                Pid::from_raw(999999),
                UserBreakpointSpec::Address(0x401005),
                0x401005,
                "main".to_string(),
                None,
                None,
                None,
            )
            .unwrap();
        let second = manager
            .add_user_breakpoint(
                Pid::from_raw(999999),
                UserBreakpointSpec::Address(0x401005),
                0x401005,
                "main+0x1".to_string(),
                None,
                None,
                None,
            )
            .unwrap();
        manager
            .delete_user_breakpoint(Pid::from_raw(999999), first.id)
            .unwrap();
        let third = manager
            .add_user_breakpoint(
                Pid::from_raw(999999),
                UserBreakpointSpec::Address(0x401005),
                0x401005,
                "main+0x2".to_string(),
                None,
                None,
                None,
            )
            .unwrap();

        assert_eq!(first.id.as_u64(), 1);
        assert_eq!(second.id.as_u64(), 2);
        assert_eq!(third.id.as_u64(), 3);
    }

    #[test]
    fn persistent_owner_shares_existing_physical_breakpoint_without_duplication() {
        let mut manager = manager_with_enabled_allocator_owner(0x401005);

        let breakpoint = manager
            .add_user_breakpoint(
                Pid::from_raw(999999),
                UserBreakpointSpec::Address(0x401005),
                0x401005,
                "main".to_string(),
                None,
                None,
                None,
            )
            .unwrap();
        manager
            .enable_user_breakpoint(Pid::from_raw(999999), breakpoint.id)
            .unwrap();

        let managed = manager.breakpoints.get(&0x401005).unwrap();
        assert_eq!(managed.owners.len(), 2);
        assert_eq!(
            manager.persistent_user_owners_at(0x401005),
            vec![breakpoint.id]
        );
        assert!(managed.breakpoint.enabled);
    }

    #[test]
    fn removing_persistent_owner_preserves_allocator_owner() {
        let mut manager = manager_with_enabled_allocator_owner(0x401005);
        let breakpoint = manager
            .add_user_breakpoint(
                Pid::from_raw(999999),
                UserBreakpointSpec::Address(0x401005),
                0x401005,
                "main".to_string(),
                None,
                None,
                None,
            )
            .unwrap();

        manager
            .disable_user_breakpoint(Pid::from_raw(999999), breakpoint.id)
            .unwrap();

        let managed = manager.breakpoints.get(&0x401005).unwrap();
        assert_eq!(managed.owners.len(), 1);
        assert!(matches!(
            managed.owners[0],
            BreakpointOwner::Allocator(super::BreakpointKind::MallocEntry)
        ));
        assert!(managed.breakpoint.enabled);
    }

    #[test]
    fn removing_allocator_owner_preserves_persistent_owner() {
        let mut manager = manager_with_enabled_allocator_owner(0x401005);
        let breakpoint = manager
            .add_user_breakpoint(
                Pid::from_raw(999999),
                UserBreakpointSpec::Address(0x401005),
                0x401005,
                "main".to_string(),
                None,
                None,
                None,
            )
            .unwrap();

        manager
            .remove_owner_at(Pid::from_raw(999999), 0x401005, |owner| {
                matches!(owner, BreakpointOwner::Allocator(_))
            })
            .unwrap();

        let managed = manager.breakpoints.get(&0x401005).unwrap();
        assert_eq!(managed.owners.len(), 1);
        assert!(matches!(
            managed.owners[0],
            BreakpointOwner::UserPersistent { breakpoint_id } if breakpoint_id == breakpoint.id
        ));
        assert!(managed.breakpoint.enabled);
    }

    #[test]
    fn disabling_and_reenabling_preserves_registry_state_and_hit_count() {
        let mut manager = manager_with_enabled_allocator_owner(0x401005);
        let breakpoint = manager
            .add_user_breakpoint(
                Pid::from_raw(999999),
                UserBreakpointSpec::Address(0x401005),
                0x401005,
                "main".to_string(),
                None,
                None,
                None,
            )
            .unwrap();
        manager.record_user_breakpoint_hits(&[breakpoint.id]);

        let disabled = manager
            .disable_user_breakpoint(Pid::from_raw(999999), breakpoint.id)
            .unwrap();
        let enabled = manager
            .enable_user_breakpoint(Pid::from_raw(999999), breakpoint.id)
            .unwrap();

        assert!(!disabled.enabled);
        assert!(enabled.enabled);
        assert_eq!(enabled.hit_count, 1);
        assert_eq!(enabled.resolved_address, 0x401005);
    }

    #[test]
    fn deleting_unknown_user_breakpoint_errors() {
        let mut manager = BreakpointManager::default();

        let err = manager
            .delete_user_breakpoint(Pid::from_raw(999999), UserBreakpointId(99))
            .unwrap_err();

        assert!(err.to_string().contains("unknown breakpoint id 99"));
    }

    #[test]
    fn user_breakpoint_formatting_is_stable() {
        let breakpoint = UserBreakpoint {
            id: UserBreakpointId(2),
            spec: UserBreakpointSpec::Symbol("main".to_string()),
            resolved_address: 0x4011a5,
            enabled: true,
            hit_count: 3,
            label: "main+0x37".to_string(),
            resolved_symbol: Some("main+0x37".to_string()),
            source: None,
            source_resolution: None,
        };

        assert_eq!(breakpoint.location_line(), "0x4011a5 (main+0x37)");
        assert_eq!(
            breakpoint.summary_line(),
            "2    y   3      0x4011a5 main+0x37"
        );
    }

    #[test]
    fn user_breakpoint_source_summary_is_used_in_location_line() {
        let breakpoint = UserBreakpoint {
            id: UserBreakpointId(3),
            spec: UserBreakpointSpec::SourceLine {
                path: "main.c".to_string(),
                line: 12,
            },
            resolved_address: 0x4011a1,
            enabled: true,
            hit_count: 0,
            label: "main+0x33".to_string(),
            resolved_symbol: Some("main+0x33".to_string()),
            source: None,
            source_resolution: Some(SourceBreakpointResolution {
                requested_path: "main.c".to_string(),
                requested_line: 12,
                resolved_path: "examples/simple_malloc.c".to_string(),
                resolved_line: 12,
                resolved_address: 0x4011a1,
                symbol: Some("main+0x33".to_string()),
            }),
        };

        assert_eq!(
            breakpoint.location_line(),
            "0x4011a1 (examples/simple_malloc.c:12; main+0x33)"
        );
        assert_eq!(
            DebuggerStopReason::UserBreakpoint {
                breakpoint_id: UserBreakpointId(3),
                address: breakpoint.resolved_address,
                label: "examples/simple_malloc.c:12 (main+0x33)".to_string(),
            }
            .summary_line(),
            "breakpoint 3 hit at 0x4011a1 (examples/simple_malloc.c:12 (main+0x33))"
        );
    }

    fn manager_with_enabled_allocator_owner(addr: u64) -> BreakpointManager {
        let mut manager = BreakpointManager::default();
        manager.breakpoints.insert(
            addr,
            ManagedBreakpoint {
                breakpoint: Breakpoint {
                    addr,
                    original_byte: 0x90,
                    enabled: true,
                },
                owners: vec![BreakpointOwner::Allocator(
                    super::BreakpointKind::MallocEntry,
                )],
            },
        );
        manager
    }

    #[test]
    #[ignore = "ptrace integration test; run via scripts/test-integration.sh on Linux x86-64"]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn source_breakpoint_resolves_for_pie_and_non_pie_fixtures() {
        let fixture = compile_source_breakpoint_fixture("resolve", false);
        let non_pie = compile_source_breakpoint_fixture("resolve-nopie", true);

        let pie_resolution =
            super::resolve_source_line_breakpoint(&fixture.binary, 0x5555_0000, "source_bp.c", 6)
                .unwrap();
        let non_pie_resolution =
            super::resolve_source_line_breakpoint(&non_pie.binary, 0, "source_bp.c", 6).unwrap();

        assert_eq!(pie_resolution.resolved_line, 6);
        assert!(pie_resolution.resolved_address >= 0x5555_0000);
        assert_eq!(non_pie_resolution.resolved_line, 6);
        assert!(non_pie_resolution.resolved_address < 0x5555_0000);
    }

    #[test]
    #[ignore = "ptrace integration test; run via scripts/test-integration.sh on Linux x86-64"]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn source_breakpoint_hits_and_allocator_tracing_continues() {
        let fixture = compile_source_breakpoint_fixture("hit", false);
        let child = spawn_traced_fixture(&fixture.binary);
        let load_bias = target_runtime_load_bias(child, fixture.binary.to_str().unwrap()).unwrap();
        let resolution =
            super::resolve_source_line_breakpoint(&fixture.binary, load_bias, "source_bp.c", 6)
                .unwrap();
        let mut breakpoint = Breakpoint::new(resolution.resolved_address);
        breakpoint.enable(child).unwrap();

        ptrace::cont(child, None).unwrap();
        let hit = wait_for_source_breakpoint_hit(child, resolution.resolved_address);
        assert!(hit, "source breakpoint did not hit");

        breakpoint.disable(child).unwrap();
        let mut regs = ptrace::getregs(child).unwrap();
        regs.rip = resolution.resolved_address;
        ptrace::setregs(child, regs).unwrap();
        ptrace::cont(child, None).unwrap();
        wait_for_fixture_exit(child);

        let mut events = 0usize;
        trace_heap_with_status(
            fixture.binary.to_str().unwrap(),
            &[],
            |_event, _context| {
                events += 1;
                Ok(())
            },
            false,
        )
        .unwrap();
        assert!(events >= 1, "allocator tracing produced no events");
    }

    #[test]
    #[ignore = "ptrace integration test; run via scripts/test-integration.sh on Linux x86-64"]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn disabled_source_breakpoint_does_not_stop() {
        let fixture = compile_source_breakpoint_fixture("disabled", false);
        let child = spawn_traced_fixture(&fixture.binary);
        let load_bias = target_runtime_load_bias(child, fixture.binary.to_str().unwrap()).unwrap();
        let resolution =
            super::resolve_source_line_breakpoint(&fixture.binary, load_bias, "source_bp.c", 6)
                .unwrap();
        let mut breakpoint = Breakpoint::new(resolution.resolved_address);
        breakpoint.enable(child).unwrap();
        breakpoint.disable(child).unwrap();

        ptrace::cont(child, None).unwrap();

        assert!(!wait_for_source_breakpoint_hit(
            child,
            resolution.resolved_address
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    struct SourceBreakpointFixture {
        binary: std::path::PathBuf,
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn compile_source_breakpoint_fixture(name: &str, no_pie: bool) -> SourceBreakpointFixture {
        let dir =
            std::env::temp_dir().join(format!("heapify-source-bp-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source_bp.c");
        let binary = dir.join("source_bp");
        std::fs::write(
            &source,
            "#include <stdlib.h>\n#include <unistd.h>\n\nint main(void) {\n    sleep(1);\n    void *p = malloc(0x30);\n    free(p);\n    return 0;\n}\n",
        )
        .unwrap();
        let mut command = std::process::Command::new("gcc");
        command.args(["-g", "-O0", "-fno-omit-frame-pointer"]);
        if no_pie {
            command.arg("-no-pie");
        }
        let status = command
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap();
        assert!(status.success());
        SourceBreakpointFixture { binary }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn spawn_traced_fixture(binary: &std::path::Path) -> Pid {
        match unsafe { fork() }.unwrap() {
            ForkResult::Child => {
                ptrace::traceme().unwrap();
                let program = std::ffi::CString::new(binary.to_str().unwrap()).unwrap();
                execvp(&program, &[program.clone()]).unwrap();
                unreachable!();
            }
            ForkResult::Parent { child } => match waitpid(child, None).unwrap() {
                WaitStatus::Stopped(pid, _) if pid == child => child,
                status => panic!("unexpected initial wait status: {status:?}"),
            },
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn wait_for_source_breakpoint_hit(child: Pid, expected_address: u64) -> bool {
        loop {
            match waitpid(child, None).unwrap() {
                WaitStatus::Stopped(pid, Signal::SIGTRAP) if pid == child => {
                    let regs = ptrace::getregs(child).unwrap();
                    return regs.rip.saturating_sub(1) == expected_address;
                }
                WaitStatus::Stopped(pid, signal) if pid == child => {
                    ptrace::cont(child, signal_to_deliver(signal)).unwrap();
                }
                WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) if pid == child => {
                    return false;
                }
                _ => {}
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn wait_for_fixture_exit(child: Pid) {
        loop {
            match waitpid(child, None).unwrap() {
                WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) if pid == child => {
                    return;
                }
                WaitStatus::Stopped(pid, signal) if pid == child => {
                    ptrace::cont(child, signal_to_deliver(signal)).unwrap();
                }
                _ => {}
            }
        }
    }

    #[test]
    fn instruction_step_status_messages_include_rip_and_signal() {
        assert_eq!(
            super::format_instruction_step_completed(Some(0x401000), Some(0x401001)),
            "stepped instruction: 0x401000 -> 0x401001"
        );
        assert_eq!(
            super::format_instruction_step_signal(
                nix::sys::signal::Signal::SIGSEGV,
                Some(0x401000)
            ),
            "instruction step stopped by SIGSEGV at RIP=0x401000"
        );
    }

    #[test]
    fn rejects_u16_extraction_crossing_word_boundary() {
        assert!(extract_u16_from_word_le(0, 7).is_err());
    }

    #[test]
    fn caller_addr_capture_failure_is_non_fatal() {
        let caller_addr = capture_caller_addr_with(|| anyhow::bail!("stack read failed"));

        assert_eq!(caller_addr, None);
    }

    #[test]
    fn paths_same_best_effort_matches_same_canonical_file() {
        let path = Path::new("Cargo.toml");
        let canonical = std::fs::canonicalize(path).unwrap();

        assert_eq!(paths_same_best_effort(path, &canonical), Some(true));
    }

    #[test]
    fn paths_same_best_effort_compares_different_absolute_paths() {
        assert_eq!(
            paths_same_best_effort(Path::new("/tmp/libc.so.6"), Path::new("/usr/lib/libc.so.6")),
            Some(false)
        );
    }

    #[test]
    fn libc_symbol_file_prefers_supplied_path() {
        let loaded = "/usr/lib/libc.so.6";
        let supplied = Path::new("/tmp/challenge/libc.so.6");

        assert_eq!(libc_symbol_file(loaded, Some(supplied)), supplied);
        assert_eq!(libc_symbol_file(loaded, None), Path::new(loaded));
    }

    #[test]
    fn build_exec_plan_normal_launches_target_directly() {
        let plan = build_exec_plan(&launch_config()).unwrap();

        assert_eq!(plan.exec_program, PathBuf::from("./chall"));
        assert_eq!(plan.exec_args, vec!["./chall", "arg"]);
        assert_eq!(plan.cwd, None);
        assert!(!plan.clear_env);
        assert!(plan.env_unsets.is_empty());
        assert!(plan.env_overrides.is_empty());
        assert_eq!(plan.stdin, StdinConfig::Inherit);
        assert_eq!(plan.target_program_for_symbols, PathBuf::from("./chall"));
        assert_eq!(plan.launch_mode, LaunchMode::Normal);
        assert_eq!(plan.effective_library_path, None);
    }

    #[test]
    fn build_exec_plan_preload_only_sets_ld_preload() {
        let mut config = launch_config();
        config.preload_path = Some(PathBuf::from("./libc.so.6"));

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(plan.exec_program, PathBuf::from("./chall"));
        assert_eq!(
            plan.env_overrides,
            vec![("LD_PRELOAD".to_string(), "./libc.so.6".to_string())]
        );
        assert_eq!(plan.launch_mode, LaunchMode::LdPreload);
    }

    #[test]
    fn build_exec_plan_uses_stdin_file() {
        let mut config = launch_config();
        config.stdin = StdinConfig::File(PathBuf::from("script.txt"));

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(plan.stdin, StdinConfig::File(PathBuf::from("script.txt")));
    }

    #[test]
    fn build_exec_plan_uses_stdin_text() {
        let mut config = launch_config();
        config.stdin = StdinConfig::Text("1\n2\n".to_string());

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(plan.stdin, StdinConfig::Text("1\n2\n".to_string()));
    }

    #[test]
    fn stdin_text_fd_writer_writes_expected_bytes() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let writer = std::thread::spawn(move || write_all_to_fd(fds[1], b"1\n2\n"));
        let mut buffer = [0u8; 16];
        let read_count = unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) };
        super::close_fd(fds[0]);

        writer.join().unwrap().unwrap();
        assert_eq!(read_count, 4);
        assert_eq!(&buffer[..read_count as usize], b"1\n2\n");
    }

    #[test]
    fn build_exec_plan_includes_cwd_and_user_env_controls() {
        let mut config = launch_config();
        config.cwd = Some(PathBuf::from("./challenge"));
        config.clear_env = true;
        config.set_env = vec![
            ("FOO".to_string(), "bar".to_string()),
            ("EMPTY".to_string(), "".to_string()),
        ];
        config.unset_env = vec!["LD_DEBUG".to_string()];

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(plan.cwd, Some(PathBuf::from("./challenge")));
        assert!(plan.clear_env);
        assert_eq!(plan.env_unsets, vec!["LD_DEBUG".to_string()]);
        assert_eq!(
            plan.env_overrides,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("EMPTY".to_string(), "".to_string())
            ]
        );
    }

    #[test]
    fn build_exec_plan_preload_overrides_user_ld_preload_by_ordering() {
        let mut config = launch_config();
        config.set_env = vec![("LD_PRELOAD".to_string(), "foo.so".to_string())];
        config.preload_path = Some(PathBuf::from("bar.so"));

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(
            plan.env_overrides,
            vec![
                ("LD_PRELOAD".to_string(), "foo.so".to_string()),
                ("LD_PRELOAD".to_string(), "bar.so".to_string())
            ]
        );
    }

    #[test]
    fn build_exec_plan_loader_only_runs_loader_with_target() {
        let mut config = launch_config();
        config.loader_path = Some(PathBuf::from("./ld-linux-x86-64.so.2"));

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(plan.exec_program, PathBuf::from("./ld-linux-x86-64.so.2"));
        assert_eq!(
            plan.exec_args,
            vec!["./ld-linux-x86-64.so.2", "./chall", "arg"]
        );
        assert_eq!(plan.launch_mode, LaunchMode::CustomLoader);
        assert_eq!(plan.target_program_for_symbols, PathBuf::from("./chall"));
    }

    #[test]
    fn build_exec_plan_loader_with_libc_derives_library_path() {
        let mut config = launch_config();
        config.loader_path = Some(PathBuf::from("./ld-linux-x86-64.so.2"));
        config.supplied_libc_path = Some(PathBuf::from("./ctf/libc.so.6"));

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(plan.effective_library_path, Some(PathBuf::from("./ctf")));
        assert_eq!(
            plan.exec_args,
            vec![
                "./ld-linux-x86-64.so.2",
                "--library-path",
                "./ctf",
                "./chall",
                "arg"
            ]
        );
    }

    #[test]
    fn build_exec_plan_explicit_library_path_overrides_libc_parent() {
        let mut config = launch_config();
        config.loader_path = Some(PathBuf::from("./ld-linux-x86-64.so.2"));
        config.library_path = Some(PathBuf::from("."));
        config.supplied_libc_path = Some(PathBuf::from("./ctf/libc.so.6"));

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(plan.effective_library_path, Some(PathBuf::from(".")));
        assert_eq!(
            plan.exec_args,
            vec![
                "./ld-linux-x86-64.so.2",
                "--library-path",
                ".",
                "./chall",
                "arg"
            ]
        );
    }

    #[test]
    fn build_exec_plan_loader_with_preload_marks_combined_mode() {
        let mut config = launch_config();
        config.loader_path = Some(PathBuf::from("./ld-linux-x86-64.so.2"));
        config.preload_path = Some(PathBuf::from("./libc.so.6"));

        let plan = build_exec_plan(&config).unwrap();

        assert_eq!(plan.launch_mode, LaunchMode::CustomLoaderWithPreload);
        assert_eq!(
            plan.env_overrides,
            vec![("LD_PRELOAD".to_string(), "./libc.so.6".to_string())]
        );
    }

    #[test]
    fn target_symbolizer_finds_nearest_previous_symbol() {
        let symbolizer = TargetSymbolizer::from_runtime_symbols(vec![
            runtime_symbol("target", "later", 0x2000, 0x20, true),
            runtime_symbol("target", "main", 0x1000, 0x40, true),
        ]);

        let symbol = symbolizer.symbolize(0x1014).unwrap();

        assert_eq!(symbol.symbol, "main");
        assert_eq!(symbol.symbol_addr, 0x1000);
        assert_eq!(symbol.offset, 0x14);
    }

    #[test]
    fn target_symbolizer_tolerates_return_address_at_symbol_end() {
        let symbolizer = TargetSymbolizer::from_runtime_symbols(vec![runtime_symbol(
            "target",
            "call_malloc",
            0x1000,
            0x20,
            true,
        )]);

        assert!(symbolizer.symbolize(0x1020).is_some());
        assert!(symbolizer.symbolize(0x1021).is_none());
    }

    #[test]
    fn source_lookup_address_adjusts_return_address_after_load_base() {
        let relative = runtime_addr_to_source_relative_addr(0x5555555551b8, 0x555555554000);

        assert_eq!(relative, Some(0x11b8));
        assert_eq!(
            relative.map(return_address_source_lookup_addr),
            Some(0x11b7)
        );
        assert_eq!(
            runtime_addr_to_source_relative_addr(0x1000, 0x2000)
                .map(return_address_source_lookup_addr),
            None
        );
        assert_eq!(return_address_source_lookup_addr(0), 0);
    }

    #[test]
    fn source_path_matching_prefers_exact_normalized_path() {
        let rows = source_rows();

        let selected = select_source_path_candidates(&rows, "/tmp/project/src/./main.c").unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].path, "/tmp/project/src/main.c");
    }

    #[test]
    fn source_path_matching_accepts_exact_suffix() {
        let rows = source_rows();

        let selected = select_source_path_candidates(&rows, "project/src/main.c").unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].path, "/tmp/project/src/main.c");
    }

    #[test]
    fn source_path_matching_accepts_unambiguous_basename() {
        let rows = source_rows();

        let selected = select_source_path_candidates(&rows, "helper.c").unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].path, "/tmp/project/lib/helper.c");
    }

    #[test]
    fn source_path_matching_rejects_ambiguous_basename() {
        let rows = source_rows();

        let error = select_source_path_candidates(&rows, "main.c").unwrap_err();

        assert!(error.to_string().contains("ambiguous source path"));
        assert!(error.to_string().contains("/tmp/project/src/main.c"));
    }

    fn source_rows() -> Vec<SourceLineRow> {
        vec![
            SourceLineRow {
                path: "/tmp/project/src/main.c".to_string(),
                line: 42,
                address: 0x1000,
            },
            SourceLineRow {
                path: "/tmp/other/main.c".to_string(),
                line: 7,
                address: 0x2000,
            },
            SourceLineRow {
                path: "/tmp/project/lib/helper.c".to_string(),
                line: 3,
                address: 0x3000,
            },
        ]
    }

    #[test]
    fn process_symbolizer_finds_nearest_previous_symbol_with_object_name() {
        let symbolizer = ProcessSymbolizer::from_runtime_symbols(vec![
            runtime_symbol("target", "main", 0x1000, 0x40, true),
            runtime_symbol("libc.so.6", "__libc_malloc", 0x7000, 0x30, false),
        ]);

        let target_symbol = symbolizer.symbolize(0x1010).unwrap();
        let libc_symbol = symbolizer.symbolize(0x7010).unwrap();

        assert_eq!(target_symbol.object_name, None);
        assert_eq!(target_symbol.symbol, "main");
        assert_eq!(libc_symbol.object_name, Some("libc.so.6".to_string()));
        assert_eq!(libc_symbol.symbol, "__libc_malloc");
        assert_eq!(libc_symbol.offset, 0x10);
    }

    #[test]
    fn runtime_object_selection_skips_special_and_anonymous_mappings() {
        let file_path = std::fs::canonicalize("Cargo.toml").unwrap();
        let file_path = file_path.to_string_lossy().into_owned();
        let mappings = vec![
            MemoryMapping {
                start: 0x1000,
                end: 0x2000,
                permissions: "r-xp".to_string(),
                offset: 0,
                dev: "00:00".to_string(),
                inode: 0,
                pathname: Some("[vdso]".to_string()),
            },
            MemoryMapping {
                start: 0x2000,
                end: 0x3000,
                permissions: "r-xp".to_string(),
                offset: 0,
                dev: "00:00".to_string(),
                inode: 0,
                pathname: None,
            },
            MemoryMapping {
                start: 0x3000,
                end: 0x4000,
                permissions: "r--p".to_string(),
                offset: 0,
                dev: "00:00".to_string(),
                inode: 0,
                pathname: Some(file_path.clone()),
            },
            MemoryMapping {
                start: 0x5000,
                end: 0x6000,
                permissions: "r-xp".to_string(),
                offset: 0x1000,
                dev: "00:00".to_string(),
                inode: 1,
                pathname: Some(file_path.clone()),
            },
        ];

        let objects = runtime_objects_from_mappings(&mappings, &file_path).unwrap();

        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].path, file_path);
        assert_eq!(objects[0].load_base, 0x4000);
        assert!(objects[0].is_main_object);
    }

    #[test]
    fn detects_gnu_c_library_release_version() {
        let bytes = b"GNU C Library stable release version 2.39, by Roland McGrath et al.";

        assert_eq!(
            detect_glibc_version_from_bytes(bytes),
            Some("2.39".to_string())
        );
    }

    #[test]
    fn detects_highest_glibc_symbol_version() {
        let bytes = b"GLIBC_2.2.5\0GLIBC_2.17\0GLIBC_2.39\0GLIBC_2.34";

        assert_eq!(
            detect_glibc_version_from_bytes(bytes),
            Some("2.39".to_string())
        );
    }

    #[test]
    fn detects_no_glibc_version_as_none() {
        assert_eq!(detect_glibc_version_from_bytes(b"not libc"), None);
    }

    #[test]
    fn runtime_symbol_addr_adds_load_base() {
        assert_eq!(
            runtime_symbol_addr("marker", 0x1234, 0x5555_0000).unwrap(),
            0x5555_1234
        );
    }

    #[test]
    fn runtime_symbol_addr_adds_user_offset() {
        assert_eq!(
            runtime_symbol_addr("main_arena", 0x1d3c60, 0x7ffff7a00000).unwrap(),
            0x7ffff7bd3c60
        );
    }

    #[test]
    fn classifies_last_heap_chunk_pointer_as_candidate_top() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![
                GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x31),
                GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x91),
            ],
            truncated: false,
        };

        let candidate = classify_main_arena_pointer_candidate(0x60, 0x2000, &snapshot).unwrap();

        assert_eq!(candidate.role_hint, MainArenaRoleHint::CandidateTop);
        assert!(candidate.points_into_heap);
        assert!(candidate.matches_heap_chunk);
        assert_eq!(candidate.matched_chunk_size, Some(0x90));
    }

    #[test]
    fn classifies_non_top_heap_pointer_as_heap_pointer() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x91)],
            truncated: false,
        };

        let candidate = classify_main_arena_pointer_candidate(0x68, 0x1800, &snapshot).unwrap();

        assert_eq!(candidate.role_hint, MainArenaRoleHint::HeapPointer);
        assert!(candidate.points_into_heap);
        assert!(!candidate.matches_heap_chunk);
        assert_eq!(candidate.matched_chunk_size, None);
    }

    #[test]
    fn ignores_main_arena_pointer_outside_heap() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x91)],
            truncated: false,
        };

        assert_eq!(
            classify_main_arena_pointer_candidate(0x70, 0x4000, &snapshot),
            None
        );
    }

    #[test]
    fn classifies_top_matching_walked_chunk() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x91)],
            truncated: false,
        };

        let candidate = classify_main_arena_top_candidate(0x7000, 0x60, 0x2000, &snapshot);

        assert_eq!(candidate.status, MainArenaTopStatus::MatchesWalkedChunk);
        assert!(candidate.points_into_heap);
        assert!(candidate.matches_heap_chunk);
        assert_eq!(candidate.chunk_size, Some(0x90));
    }

    #[test]
    fn classifies_top_inside_heap_without_walked_chunk_match() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x91)],
            truncated: false,
        };

        let candidate = classify_main_arena_top_candidate(0x7000, 0x60, 0x1800, &snapshot);

        assert_eq!(candidate.status, MainArenaTopStatus::PointsIntoHeap);
        assert!(candidate.points_into_heap);
        assert!(!candidate.matches_heap_chunk);
        assert_eq!(candidate.chunk_size, None);
    }

    #[test]
    fn classifies_top_outside_heap() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x91)],
            truncated: false,
        };

        let candidate = classify_main_arena_top_candidate(0x7000, 0x60, 0x4000, &snapshot);

        assert_eq!(candidate.status, MainArenaTopStatus::OutsideHeap);
        assert!(!candidate.points_into_heap);
        assert!(!candidate.matches_heap_chunk);
        assert_eq!(candidate.chunk_size, None);
    }

    #[test]
    fn fastbin_candidate_user_addr_uses_profile_header_size() {
        assert_eq!(
            fastbin_candidate_user_addr(0x1000, GLIBC_X86_64_MODERN),
            0x1010
        );
    }

    #[test]
    fn fastbin_head_user_addr_uses_profile_header_size() {
        assert_eq!(fastbin_head_user_addr(0x1000, GLIBC_X86_64_MODERN), 0x1010);
    }

    #[test]
    fn fastbin_scan_range_uses_profile_top_offset_when_available() {
        assert_eq!(
            fastbin_experiment_scan_offsets(GLIBC_2_35_X86_64),
            vec![0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58]
        );
    }

    #[test]
    fn fastbin_scan_range_falls_back_without_profile_top_offset() {
        let offsets = fastbin_experiment_scan_offsets(GLIBC_X86_64_MODERN);

        assert_eq!(offsets.first(), Some(&0x0));
        assert_eq!(offsets.last(), Some(&0x78));
    }

    #[test]
    fn classifies_fastbin_candidate_known_freed_from_tracker_user_addr() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x31)],
            truncated: false,
        };
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x2010, Some(0x30));
        tracker.observe_free(2, 0x2010);

        let candidate = classify_fastbin_pointer_candidate(
            0x20,
            0x2000,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
        )
        .unwrap();

        assert_eq!(candidate.possible_chunk_size, Some(0x30));
        assert_eq!(candidate.known_freed, Some(true));
    }

    #[test]
    fn classifies_unsorted_candidate_known_freed_from_chunk_plus_header_user_addr() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x511)],
            truncated: false,
        };
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x500, 0x2010, Some(0x510));
        tracker.observe_free(2, 0x2010);

        let candidate = classify_unsorted_bin_pointer_candidate(
            0x70,
            0x2000,
            0x4000,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
        )
        .unwrap();

        assert_eq!(candidate.fd_known_freed, Some(true));
        assert_eq!(candidate.bk_known_freed, None);
    }

    #[test]
    fn includes_unsorted_candidate_when_fd_points_into_heap() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x511)],
            truncated: false,
        };
        let tracker = HeapTracker::new();

        let candidate = classify_unsorted_bin_pointer_candidate(
            0x70,
            0x2000,
            0x4000,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
        )
        .unwrap();

        assert!(candidate.fd_points_into_heap);
        assert!(!candidate.bk_points_into_heap);
        assert!(candidate.fd_matches_heap_chunk);
        assert_eq!(candidate.role, UnsortedExperimentRole::UnsortedCandidate);
    }

    #[test]
    fn includes_unsorted_candidate_when_bk_points_into_heap() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x511)],
            truncated: false,
        };
        let tracker = HeapTracker::new();

        let candidate = classify_unsorted_bin_pointer_candidate(
            0x70,
            0x4000,
            0x2000,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
        )
        .unwrap();

        assert!(!candidate.fd_points_into_heap);
        assert!(candidate.bk_points_into_heap);
        assert!(candidate.bk_matches_heap_chunk);
    }

    #[test]
    fn excludes_unsorted_pair_when_neither_pointer_points_into_heap() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: Vec::new(),
            truncated: false,
        };
        let tracker = HeapTracker::new();

        assert_eq!(
            classify_unsorted_bin_pointer_candidate(
                0x70,
                0x4000,
                0x5000,
                &snapshot,
                &tracker,
                GLIBC_X86_64_MODERN,
            ),
            None
        );
    }

    #[test]
    fn includes_bin_candidate_when_fd_points_into_heap() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x511)],
            truncated: false,
        };
        let tracker = HeapTracker::new();

        let candidate = classify_bin_pointer_candidate(
            0x7000,
            0x90,
            0x2000,
            0x5000,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
        )
        .unwrap();

        assert!(candidate.fd_points_into_heap);
        assert!(!candidate.bk_points_into_heap);
        assert!(!candidate.fd_points_into_arena);
        assert!(!candidate.bk_points_into_arena);
        assert!(candidate.fd_matches_heap_chunk);
        assert_eq!(candidate.role, BinExperimentRole::BinSentinelCandidate);
    }

    #[test]
    fn classifies_empty_regular_bin_when_fd_bk_equal_sentinel() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: Vec::new(),
            truncated: false,
        };
        let tracker = HeapTracker::new();

        let head = classify_regular_bin_head(
            0x7000,
            1,
            0x80,
            0x7080,
            0x7080,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
        )
        .unwrap();

        assert_eq!(head.glibc_bin_index, 2);
        assert_eq!(head.role, RegularBinRole::Smallbin);
        assert_eq!(head.chunk_size, Some(0x20));
        assert!(head.empty);
        assert!(head.fd_points_into_arena);
        assert!(head.bk_points_into_arena);
        assert!(!head.fd_points_into_heap);
        assert_eq!(head.fd_known_freed, None);
    }

    #[test]
    fn regular_bin_snapshot_limit_caps_profile_count() {
        assert_eq!(regular_bin_snapshot_limit(GLIBC_2_35_X86_64, 16), Some(16));
        assert_eq!(
            regular_bin_snapshot_limit(GLIBC_2_35_X86_64, 126),
            Some(126)
        );
        assert_eq!(
            regular_bin_snapshot_limit(GLIBC_2_35_X86_64, 200),
            Some(126)
        );
        assert_eq!(regular_bin_snapshot_limit(GLIBC_X86_64_MODERN, 16), None);
    }

    #[test]
    fn includes_bin_candidate_when_bk_points_into_arena() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: Vec::new(),
            truncated: false,
        };
        let tracker = HeapTracker::new();

        let candidate = classify_bin_pointer_candidate(
            0x7000,
            0x90,
            0x5000,
            0x70f0,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
        )
        .unwrap();

        assert!(!candidate.fd_points_into_heap);
        assert!(candidate.bk_points_into_arena);
        assert_eq!(candidate.bk_known_freed, None);
    }

    #[test]
    fn excludes_bin_pair_when_neither_pointer_points_into_heap_nor_arena() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: Vec::new(),
            truncated: false,
        };
        let tracker = HeapTracker::new();

        assert_eq!(
            classify_bin_pointer_candidate(
                0x7000,
                0x90,
                0x5000,
                0x9000,
                &snapshot,
                &tracker,
                GLIBC_X86_64_MODERN,
            ),
            None
        );
    }

    #[test]
    fn bin_candidate_known_freed_uses_chunk_plus_header_user_addr() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x511)],
            truncated: false,
        };
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x500, 0x2010, Some(0x510));
        tracker.observe_free(2, 0x2010);

        let candidate = classify_bin_pointer_candidate(
            0x7000,
            0x90,
            0x2000,
            0x70f0,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
        )
        .unwrap();

        assert_eq!(candidate.fd_known_freed, Some(true));
    }

    #[test]
    fn classifies_unsorted_snapshot_heap_and_tracker_state() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x4000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x511)],
            truncated: false,
        };
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x500, 0x2010, Some(0x510));
        tracker.observe_free(2, 0x2010);

        let unsorted = classify_unsorted_bin_snapshot(
            0x7000,
            0x70,
            0x2000,
            0x5000,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
            None,
        );

        assert_eq!(unsorted.arena_addr, 0x7000);
        assert_eq!(unsorted.field_offset, 0x70);
        assert!(unsorted.fd_points_into_heap);
        assert!(!unsorted.bk_points_into_heap);
        assert!(unsorted.fd_matches_heap_chunk);
        assert!(!unsorted.bk_matches_heap_chunk);
        assert_eq!(unsorted.fd_known_freed, Some(true));
        assert_eq!(unsorted.bk_known_freed, None);
    }

    #[test]
    fn max_fastbin_chain_zero_truncates_non_null_head_without_reading() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: Vec::new(),
            truncated: false,
        };
        let tracker = HeapTracker::new();

        let chain = read_fastbin_chain(
            Pid::from_raw(0),
            1,
            0x30,
            0x2000,
            &snapshot,
            &tracker,
            GLIBC_X86_64_MODERN,
            0,
        );

        assert!(chain.nodes.is_empty());
        assert!(chain.truncated);
        assert!(!chain.stopped_on_unknown_next);
        assert!(!chain.cycle_detected);
    }

    #[test]
    fn fastbin_chain_next_rejects_outside_heap_and_misaligned_values() {
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: Vec::new(),
            truncated: false,
        };

        assert!(fastbin_chain_next_is_plausible(
            0x2000,
            &snapshot,
            GLIBC_X86_64_MODERN
        ));
        assert!(!fastbin_chain_next_is_plausible(
            0x4000,
            &snapshot,
            GLIBC_X86_64_MODERN
        ));
        assert!(!fastbin_chain_next_is_plausible(
            0x2008,
            &snapshot,
            GLIBC_X86_64_MODERN
        ));
    }

    #[test]
    fn trace_state_tracks_libc_metadata_print_once() {
        let metadata = LibcMetadata {
            path: "/lib/libc.so.6".to_string(),
            supplied_path: None,
            paths_match: None,
            version: Some("2.39".to_string()),
        };
        let state = TraceHeapState::new(
            |_, _| Ok(AllocatorEventControl::Continue),
            true,
            Some(metadata),
            None,
            GLIBC_X86_64_MODERN,
        );

        assert!(state.libc_metadata.is_some());
        assert!(state.libc_metadata_printed);

        let mut missing_state = TraceHeapState::new(
            |_, _| Ok(AllocatorEventControl::Continue),
            true,
            None,
            None,
            GLIBC_X86_64_MODERN,
        );
        assert!(!missing_state.libc_metadata_printed);

        print_missing_libc_metadata_at_trace_end(&mut missing_state);
        assert!(missing_state.libc_metadata_printed);

        print_missing_libc_metadata_at_trace_end(&mut missing_state);
        assert!(missing_state.libc_metadata_printed);
    }

    #[test]
    fn suggested_profile_is_suppressed_when_selected_profile_matches() {
        let metadata = LibcMetadata {
            path: "/lib/libc.so.6".to_string(),
            supplied_path: None,
            paths_match: None,
            version: Some("2.35".to_string()),
        };

        assert_eq!(
            suggested_glibc_profile_hint_lines(GLIBC_2_35_X86_64, &metadata),
            None
        );
        assert!(
            suggested_glibc_profile_hint_lines(GLIBC_X86_64_MODERN, &metadata)
                .unwrap()
                .iter()
                .any(|line| line.contains("--glibc-profile glibc-2.35-x86_64"))
        );
    }

    fn runtime_symbol(
        object_name: &str,
        name: &str,
        runtime_addr: u64,
        size: u64,
        is_main_object: bool,
    ) -> RuntimeSymbol {
        RuntimeSymbol {
            object_path: format!("/tmp/{object_name}"),
            object_name: object_name.to_string(),
            name: name.to_string(),
            runtime_addr,
            size,
            is_main_object,
        }
    }

    fn launch_config() -> LaunchConfig {
        LaunchConfig {
            target_program: PathBuf::from("./chall"),
            target_args: vec!["arg".to_string()],
            loader_path: None,
            library_path: None,
            preload_path: None,
            supplied_libc_path: None,
            cwd: None,
            clear_env: false,
            set_env: Vec::new(),
            unset_env: Vec::new(),
            stdin: StdinConfig::Inherit,
        }
    }
}
