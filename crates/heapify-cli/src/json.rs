#![allow(clippy::too_many_arguments)]

use heapify_core::allocator_sources::{
    allocator_source_kind_str, allocator_warning_kind_str, AllocatorSourceDelta,
    AllocatorSourceMembership, AllocatorSourceSummary, AllocatorWarning,
};
use heapify_core::glibc::{
    main_arena_view_status_from_top_status, validate_fastbins_snapshot,
    validate_largebins_snapshot, validate_smallbins_snapshot, BinExperiment, BinExperimentRole,
    BinPointerCandidate, FastbinBinValidation, FastbinChain, FastbinExperiment,
    FastbinExperimentRole, FastbinHead, FastbinNode, FastbinPointerCandidate,
    FastbinValidationStatus, FastbinValidationValue, FastbinsSnapshot, GlibcChunkHeader,
    GlibcHeapSnapshot, GlibcProfile, GlibcProfileSelection, LargebinBinValidation, LargebinChain,
    LargebinNode, LargebinValidationStatus, LargebinValidationValue, LargebinsSnapshot,
    MainArenaCandidate, MainArenaFieldSource, MainArenaSource, MainArenaViewStatus, RegularBinHead,
    RegularBinRole, RegularBinsSnapshot, SmallbinBinValidation, SmallbinChain, SmallbinNode,
    SmallbinValidationStatus, SmallbinValidationValue, SmallbinsSnapshot, TcacheEntryCandidate,
    TcacheSnapshotCandidate, TcacheStructCandidate, UnsortedBinChain, UnsortedBinExperiment,
    UnsortedBinNode, UnsortedBinPointerCandidate, UnsortedBinSnapshot, UnsortedBinValidation,
    UnsortedBinValidationStatus, UnsortedBinValidationValue, UnsortedExperimentRole,
};
use heapify_core::heap_scan::{
    heap_scan_finding_severity_str, heap_scan_status_str, HeapScanFinding, HeapScanReport,
};
use heapify_core::tcache::{
    compare_tcache_snapshot_with_observed, validate_tcache_snapshot_candidate,
    ObservedTcacheTracker, TcacheBinComparison, TcacheBinValidation, TcacheComparisonStatus,
    TcacheValidationStatus, TcacheValidationValue,
};
use heapify_core::tracker::{
    HeapTracker, HeapTrackerExplanation, HeapTrackerNote, ObservedChunkState,
};
use heapify_core::HeapTraceEvent;
use heapify_debugger::{MainArenaExperiment, MainArenaPointerCandidate, MainArenaRoleHint};
use heapify_debugger::{MainArenaTopCandidate, MainArenaTopStatus};
use heapify_debugger::{SourceLocation, SymbolizedAddress};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonChunk {
    pub chunk_addr: String,
    pub user_addr: String,
    pub prev_size: String,
    pub size_raw: String,
    pub size: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTcacheEntry {
    pub storage_addr: String,
    pub encoded_next: String,
    pub decoded_next: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonSourceLocation {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub column: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonCallerSymbol {
    #[serde(default)]
    pub object: Option<String>,
    pub symbol: String,
    pub symbol_addr: String,
    pub offset: String,
    #[serde(default)]
    pub source: Option<JsonSourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonStdinMetadata {
    #[serde(default = "default_stdin_kind")]
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub bytes: Option<usize>,
}

fn default_stdin_kind() -> String {
    "inherit".to_string()
}

impl Default for JsonStdinMetadata {
    fn default() -> Self {
        Self {
            kind: default_stdin_kind(),
            path: None,
            bytes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonLaunchMetadata {
    pub mode: String,
    #[serde(default)]
    pub loader: Option<String>,
    #[serde(default)]
    pub library_path: Option<String>,
    #[serde(default)]
    pub preload: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub clear_env: bool,
    #[serde(default)]
    pub set_env: Vec<String>,
    #[serde(default)]
    pub unset_env: Vec<String>,
    #[serde(default)]
    pub stdin: JsonStdinMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JsonTraceRecord {
    #[serde(rename = "session_start")]
    SessionStart {
        heapify_version: String,
        program: String,
        args: Vec<String>,
        trace_mode: String,
        arch: String,
        os: String,
        #[serde(default)]
        glibc_profile: String,
        #[serde(default)]
        suggested_glibc_profile: Option<String>,
        #[serde(default)]
        glibc_profile_selection: Option<GlibcProfileSelection>,
        #[serde(default)]
        libc: Option<JsonLibcMetadata>,
        #[serde(default)]
        launch: Option<JsonLaunchMetadata>,
        #[serde(default = "default_allocator_views_preset")]
        allocator_views_preset: String,
        features: JsonTraceFeatures,
    },
    #[serde(rename = "session_end")]
    SessionEnd {
        exit_status: String,
        event_count: usize,
    },
    #[serde(rename = "event")]
    Event { event: JsonHeapEvent },
    #[serde(rename = "heap_layout")]
    HeapLayout {
        event_id: usize,
        heap_start: String,
        heap_end: String,
        chunks: Vec<JsonLayoutChunk>,
        truncated: bool,
        chunks_omitted: usize,
    },
    #[serde(rename = "observed_tcache_chains")]
    ObservedTcacheChains {
        event_id: usize,
        chains: Vec<JsonObservedTcacheChain>,
    },
    #[serde(rename = "tcache_struct_candidate")]
    TcacheStructCandidate {
        event_id: usize,
        candidate: JsonTcacheStructCandidate,
        snapshot: Option<JsonTcacheSnapshotCandidate>,
    },
    #[serde(rename = "main_arena_candidate")]
    MainArenaCandidate {
        event_id: usize,
        candidate: JsonMainArenaCandidate,
    },
    #[serde(rename = "main_arena_experiment")]
    MainArenaExperiment {
        event_id: usize,
        arena_addr: String,
        candidates: Vec<JsonMainArenaPointerCandidate>,
    },
    #[serde(rename = "main_arena_top_candidate")]
    MainArenaTopCandidate {
        event_id: usize,
        arena_addr: String,
        field_offset: String,
        top_addr: String,
        points_into_heap: bool,
        matches_heap_chunk: bool,
        chunk_size: Option<String>,
        status: String,
        #[serde(default = "default_main_arena_top_source")]
        source: String,
        #[serde(default)]
        profile: Option<String>,
    },
    #[serde(rename = "main_arena_view")]
    MainArenaView {
        event_id: usize,
        arena: JsonMainArenaViewArena,
        top: Option<JsonMainArenaViewTop>,
    },
    #[serde(rename = "fastbin_experiment")]
    FastbinExperiment {
        event_id: usize,
        arena_addr: String,
        candidates: Vec<JsonFastbinPointerCandidate>,
    },
    #[serde(rename = "unsorted_bin_experiment")]
    UnsortedBinExperiment {
        event_id: usize,
        arena_addr: String,
        candidates: Vec<JsonUnsortedBinPointerCandidate>,
    },
    #[serde(rename = "bin_experiment")]
    BinExperiment {
        event_id: usize,
        arena_addr: String,
        candidates: Vec<JsonBinPointerCandidate>,
    },
    #[serde(rename = "unsorted_bin")]
    UnsortedBin {
        event_id: usize,
        arena_addr: String,
        field_offset: String,
        fd: String,
        bk: String,
        fd_points_into_heap: bool,
        bk_points_into_heap: bool,
        fd_matches_heap_chunk: bool,
        bk_matches_heap_chunk: bool,
        fd_known_freed: Option<bool>,
        bk_known_freed: Option<bool>,
        #[serde(default)]
        chain: Option<JsonUnsortedBinChain>,
    },
    #[serde(rename = "unsorted_bin_validation")]
    UnsortedBinValidation {
        event_id: usize,
        validation: JsonUnsortedBinValidation,
    },
    #[serde(rename = "fastbins")]
    Fastbins {
        event_id: usize,
        arena_addr: String,
        heads: Vec<JsonFastbinHead>,
        #[serde(default)]
        chains: Vec<JsonFastbinChain>,
    },
    #[serde(rename = "regular_bins")]
    RegularBins {
        event_id: usize,
        arena_addr: String,
        bins_offset: String,
        heads: Vec<JsonRegularBinHead>,
    },
    #[serde(rename = "smallbins")]
    Smallbins {
        event_id: usize,
        arena_addr: String,
        bins_offset: String,
        chains: Vec<JsonSmallbinChain>,
    },
    #[serde(rename = "smallbin_validation")]
    SmallbinValidation {
        event_id: usize,
        validations: Vec<JsonSmallbinBinValidation>,
    },
    #[serde(rename = "largebins")]
    Largebins {
        event_id: usize,
        arena_addr: String,
        bins_offset: String,
        chains: Vec<JsonLargebinChain>,
    },
    #[serde(rename = "largebin_validation")]
    LargebinValidation {
        event_id: usize,
        validations: Vec<JsonLargebinBinValidation>,
    },
    #[serde(rename = "fastbin_validation")]
    FastbinValidation {
        event_id: usize,
        validations: Vec<JsonFastbinBinValidation>,
    },
    #[serde(rename = "tcache_comparison")]
    TcacheComparison {
        event_id: usize,
        comparisons: Vec<JsonTcacheBinComparison>,
    },
    #[serde(rename = "tcache_validation")]
    TcacheValidation {
        event_id: usize,
        validations: Vec<JsonTcacheBinValidation>,
    },
    #[serde(rename = "allocator_warnings")]
    AllocatorWarnings {
        event_id: usize,
        warnings: Vec<JsonAllocatorWarning>,
    },
    #[serde(rename = "allocator_source_summary")]
    AllocatorSourceSummary {
        event_id: usize,
        tcache_candidate_chunks: usize,
        fastbin_chunks: usize,
        unsorted_chunks: usize,
        #[serde(default)]
        smallbin_chunks: usize,
        #[serde(default)]
        largebin_chunks: usize,
        total_free_list_chunks: usize,
        warning_count: usize,
    },
    #[serde(rename = "allocator_source_delta")]
    AllocatorSourceDelta {
        event_id: usize,
        tcache_candidate_chunks_delta: isize,
        fastbin_chunks_delta: isize,
        unsorted_chunks_delta: isize,
        #[serde(default)]
        smallbin_chunks_delta: isize,
        #[serde(default)]
        largebin_chunks_delta: isize,
        total_free_list_chunks_delta: isize,
        warning_count_delta: isize,
    },
    #[serde(rename = "heap_scan")]
    HeapScan {
        event_id: usize,
        report: JsonHeapScanReport,
    },
}

fn default_main_arena_top_source() -> String {
    "user_offset".to_string()
}

fn default_allocator_views_preset() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonTraceFeatures {
    pub layout: bool,
    pub tcache_candidates: bool,
    pub tcache_struct: bool,
    pub libc_symbols: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonLibcMetadata {
    pub path: Option<String>,
    #[serde(default)]
    pub supplied_path: Option<String>,
    #[serde(default)]
    pub paths_match: Option<bool>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JsonHeapEvent {
    #[serde(rename = "malloc")]
    Malloc {
        event_id: usize,
        requested_size: String,
        returned_ptr: String,
        chunk: Option<JsonChunk>,
        #[serde(default)]
        caller_addr: Option<String>,
        #[serde(default)]
        caller_symbol: Option<JsonCallerSymbol>,
        tracker_note: String,
        tracker_explanation: Option<String>,
    },
    #[serde(rename = "free")]
    Free {
        event_id: usize,
        ptr: String,
        chunk: Option<JsonChunk>,
        tcache_entry: Option<JsonTcacheEntry>,
        #[serde(default)]
        caller_addr: Option<String>,
        #[serde(default)]
        caller_symbol: Option<JsonCallerSymbol>,
        tracker_note: String,
        tracker_explanation: Option<String>,
    },
    #[serde(rename = "calloc")]
    Calloc {
        event_id: usize,
        nmemb: String,
        size: String,
        returned_ptr: String,
        chunk: Option<JsonChunk>,
        #[serde(default)]
        caller_addr: Option<String>,
        #[serde(default)]
        caller_symbol: Option<JsonCallerSymbol>,
        tracker_note: String,
        tracker_explanation: Option<String>,
    },
    #[serde(rename = "realloc")]
    Realloc {
        event_id: usize,
        old_ptr: String,
        new_size: String,
        returned_ptr: String,
        old_chunk: Option<JsonChunk>,
        new_chunk: Option<JsonChunk>,
        #[serde(default)]
        caller_addr: Option<String>,
        #[serde(default)]
        caller_symbol: Option<JsonCallerSymbol>,
        tracker_note: String,
        tracker_explanation: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonLayoutChunk {
    pub chunk_addr: String,
    pub user_addr: String,
    #[serde(default)]
    pub prev_size: String,
    #[serde(default)]
    pub size_raw: String,
    pub size: String,
    pub flags: Vec<String>,
    pub state: String,
    pub tcache_candidate: Option<JsonObservedTcacheMembership>,
    #[serde(default)]
    pub allocator_source: Option<JsonAllocatorSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonObservedTcacheMembership {
    pub chunk_size: String,
    pub index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonAllocatorSource {
    pub kind: String,
    pub chunk_size: String,
    pub index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonAllocatorWarning {
    pub kind: String,
    pub chunk_addr: String,
    pub user_addr: String,
    pub sources: Vec<JsonAllocatorSourceMembership>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonHeapScanReport {
    pub chunks_walked: usize,
    pub allocated_observed: usize,
    pub freed_observed: usize,
    pub unknown_observed: usize,
    pub allocator_source_chunks: usize,
    pub warning_count: usize,
    pub suspicious_count: usize,
    pub top_validated: Option<bool>,
    pub heap_snapshot_truncated: bool,
    pub status: String,
    pub findings: Vec<JsonHeapScanFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonHeapScanFinding {
    pub severity: String,
    pub kind: String,
    pub chunk_addr: Option<String>,
    pub user_addr: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonAllocatorSourceMembership {
    pub kind: String,
    pub chunk_size: Option<String>,
    pub index: Option<usize>,
    pub chunk_addr: String,
    pub user_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonObservedTcacheChain {
    pub chunk_size: String,
    pub head: Option<String>,
    pub entries: Vec<String>,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTcacheStructCandidate {
    pub chunk_addr: String,
    pub user_addr: String,
    pub size: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonMainArenaCandidate {
    pub libc_path: String,
    pub symbol_name: String,
    pub runtime_addr: String,
    pub source: String,
    pub offset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonMainArenaPointerCandidate {
    pub field_offset: String,
    pub value: String,
    pub points_into_heap: bool,
    pub matches_heap_chunk: bool,
    pub matched_chunk_size: Option<String>,
    pub role_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonMainArenaViewArena {
    pub addr: String,
    pub source: String,
    pub offset: Option<String>,
    pub libc_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonMainArenaViewTop {
    pub field_offset: String,
    pub value: String,
    pub size: Option<String>,
    pub source: String,
    pub profile: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFastbinPointerCandidate {
    pub field_offset: String,
    pub value: String,
    pub possible_chunk_size: Option<String>,
    pub points_into_heap: bool,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonUnsortedBinPointerCandidate {
    pub field_offset: String,
    pub fd: String,
    pub bk: String,
    pub fd_points_into_heap: bool,
    pub bk_points_into_heap: bool,
    pub fd_matches_heap_chunk: bool,
    pub bk_matches_heap_chunk: bool,
    pub fd_known_freed: Option<bool>,
    pub bk_known_freed: Option<bool>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonBinPointerCandidate {
    pub field_offset: String,
    pub fd: String,
    pub bk: String,
    pub fd_points_into_heap: bool,
    pub bk_points_into_heap: bool,
    pub fd_points_into_arena: bool,
    pub bk_points_into_arena: bool,
    pub fd_matches_heap_chunk: bool,
    pub bk_matches_heap_chunk: bool,
    pub fd_known_freed: Option<bool>,
    pub bk_known_freed: Option<bool>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRegularBinHead {
    pub index: usize,
    pub glibc_bin_index: usize,
    pub role: String,
    pub chunk_size: Option<String>,
    pub field_offset: String,
    pub fd: String,
    pub bk: String,
    pub empty: bool,
    pub fd_points_into_heap: bool,
    pub bk_points_into_heap: bool,
    pub fd_points_into_arena: bool,
    pub bk_points_into_arena: bool,
    pub fd_matches_heap_chunk: bool,
    pub bk_matches_heap_chunk: bool,
    pub fd_known_freed: Option<bool>,
    pub bk_known_freed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSmallbinChain {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub expected_chunk_size: String,
    pub sentinel_addr: String,
    pub head: String,
    pub tail: String,
    pub nodes: Vec<JsonSmallbinNode>,
    pub empty: bool,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
    pub cycle_detected: bool,
    pub fd_bk_consistent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSmallbinNode {
    pub chunk_addr: String,
    pub user_addr: String,
    pub fd: String,
    pub bk: String,
    pub chunk_size: Option<String>,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
    pub fd_points_to_sentinel: bool,
    pub bk_points_to_sentinel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSmallbinBinValidation {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub expected_chunk_size: String,
    pub head: String,
    pub head_in_heap: String,
    pub nodes_same_size: String,
    pub fd_bk_consistent: String,
    pub nodes_known_freed: String,
    pub chain_complete: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonLargebinChain {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub sentinel_addr: String,
    pub head: String,
    pub tail: String,
    pub nodes: Vec<JsonLargebinNode>,
    pub empty: bool,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
    pub cycle_detected: bool,
    pub fd_bk_consistent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonLargebinNode {
    pub chunk_addr: String,
    pub user_addr: String,
    pub fd: String,
    pub bk: String,
    pub fd_nextsize: String,
    pub bk_nextsize: String,
    pub chunk_size: Option<String>,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
    pub fd_points_to_sentinel: bool,
    pub bk_points_to_sentinel: bool,
    pub fd_nextsize_points_into_heap: bool,
    pub bk_nextsize_points_into_heap: bool,
    pub fd_nextsize_points_into_arena: bool,
    pub bk_nextsize_points_into_arena: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonLargebinBinValidation {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub head: String,
    pub head_in_heap: String,
    pub fd_bk_consistent: String,
    pub nodes_known_freed: String,
    pub chain_complete: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonUnsortedBinChain {
    pub sentinel_addr: String,
    pub head: String,
    pub tail: String,
    pub nodes: Vec<JsonUnsortedBinNode>,
    pub empty: bool,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
    pub cycle_detected: bool,
    pub fd_bk_consistent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonUnsortedBinNode {
    pub chunk_addr: String,
    pub user_addr: String,
    pub fd: String,
    pub bk: String,
    pub chunk_size: Option<String>,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
    pub fd_points_to_sentinel: bool,
    pub bk_points_to_sentinel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonUnsortedBinValidation {
    pub head_in_heap: String,
    pub fd_bk_consistent: String,
    pub nodes_known_freed: String,
    pub chain_complete: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFastbinHead {
    pub index: usize,
    pub chunk_size: String,
    pub field_offset: String,
    pub head: String,
    pub points_into_heap: bool,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFastbinChain {
    pub index: usize,
    pub chunk_size: String,
    pub head: String,
    pub nodes: Vec<JsonFastbinNode>,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
    pub cycle_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFastbinNode {
    pub chunk_addr: String,
    pub user_addr: String,
    pub encoded_next: String,
    pub decoded_next: String,
    pub chunk_size: Option<String>,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFastbinBinValidation {
    pub index: usize,
    pub chunk_size: String,
    pub head: String,
    pub head_in_heap: String,
    pub nodes_same_size: String,
    pub nodes_known_freed: String,
    pub chain_complete: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTcacheSnapshotCandidate {
    pub struct_user_addr: String,
    pub bins: Vec<JsonTcacheBinSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTcacheBinSnapshot {
    pub index: usize,
    pub chunk_size: String,
    pub count: u16,
    pub head: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTcacheBinComparison {
    pub index: usize,
    pub chunk_size: String,
    pub struct_count: u16,
    pub struct_head: String,
    pub observed_entries: Vec<String>,
    pub observed_truncated: bool,
    pub observed_stopped_on_unknown_next: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTcacheBinValidation {
    pub index: usize,
    pub chunk_size: String,
    pub head: String,
    pub count: u16,
    pub head_in_heap: String,
    pub head_known_freed: String,
    pub observed_nodes_same_size: String,
    pub count_matches_observed: String,
    pub status: String,
}

pub fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

pub fn json_session_start_record(
    program: &str,
    args: &[String],
    trace_mode: &str,
    glibc_profile: &str,
    suggested_glibc_profile: Option<&str>,
    glibc_profile_selection: Option<GlibcProfileSelection>,
    libc: Option<JsonLibcMetadata>,
    launch: Option<JsonLaunchMetadata>,
    allocator_views_preset: &str,
    features: JsonTraceFeatures,
) -> JsonTraceRecord {
    JsonTraceRecord::SessionStart {
        heapify_version: env!("CARGO_PKG_VERSION").to_string(),
        program: program.to_string(),
        args: args.to_vec(),
        trace_mode: trace_mode.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        os: std::env::consts::OS.to_string(),
        glibc_profile: glibc_profile.to_string(),
        suggested_glibc_profile: suggested_glibc_profile.map(str::to_string),
        glibc_profile_selection,
        libc,
        launch,
        allocator_views_preset: allocator_views_preset.to_string(),
        features,
    }
}

pub fn json_session_end_record(exit_status: &str, event_count: usize) -> JsonTraceRecord {
    JsonTraceRecord::SessionEnd {
        exit_status: exit_status.to_string(),
        event_count,
    }
}

pub fn json_chunk(chunk: &GlibcChunkHeader) -> JsonChunk {
    JsonChunk {
        chunk_addr: hex(chunk.chunk_addr),
        user_addr: hex(chunk.user_addr),
        prev_size: hex(chunk.prev_size),
        size_raw: hex(chunk.size_raw),
        size: hex(chunk.size),
        flags: chunk
            .flags
            .labels()
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

pub fn json_tcache_entry(candidate: &TcacheEntryCandidate) -> JsonTcacheEntry {
    JsonTcacheEntry {
        storage_addr: hex(candidate.storage_addr),
        encoded_next: hex(candidate.encoded_next),
        decoded_next: hex(candidate.decoded_next),
    }
}

pub fn json_trace_event_record(
    event: &HeapTraceEvent,
    tracker_note: HeapTrackerNote,
    explanation: HeapTrackerExplanation,
) -> JsonTraceRecord {
    json_trace_event_record_with_caller_symbol(event, tracker_note, explanation, None)
}

pub fn json_trace_event_record_with_caller_symbol(
    event: &HeapTraceEvent,
    tracker_note: HeapTrackerNote,
    explanation: HeapTrackerExplanation,
    caller_symbol: Option<&SymbolizedAddress>,
) -> JsonTraceRecord {
    JsonTraceRecord::Event {
        event: json_event_with_caller_symbol(event, tracker_note, explanation, caller_symbol),
    }
}

pub fn json_event(
    event: &HeapTraceEvent,
    tracker_note: HeapTrackerNote,
    explanation: HeapTrackerExplanation,
) -> JsonHeapEvent {
    json_event_with_caller_symbol(event, tracker_note, explanation, None)
}

pub fn json_event_with_caller_symbol(
    event: &HeapTraceEvent,
    tracker_note: HeapTrackerNote,
    explanation: HeapTrackerExplanation,
    caller_symbol: Option<&SymbolizedAddress>,
) -> JsonHeapEvent {
    let tracker_note = json_tracker_note(tracker_note).to_string();
    let tracker_explanation = json_tracker_explanation(explanation).map(str::to_string);
    let caller_symbol = caller_symbol.map(json_caller_symbol);

    match event {
        HeapTraceEvent::Malloc {
            event_id,
            requested_size,
            returned_ptr,
            chunk,
            caller_addr,
        } => JsonHeapEvent::Malloc {
            event_id: *event_id,
            requested_size: hex(*requested_size),
            returned_ptr: hex(*returned_ptr),
            chunk: chunk.as_ref().map(json_chunk),
            caller_addr: caller_addr.map(hex),
            caller_symbol,
            tracker_note,
            tracker_explanation,
        },
        HeapTraceEvent::Free {
            event_id,
            ptr,
            chunk,
            tcache_entry,
            caller_addr,
        } => JsonHeapEvent::Free {
            event_id: *event_id,
            ptr: hex(*ptr),
            chunk: chunk.as_ref().map(json_chunk),
            tcache_entry: tcache_entry.as_ref().map(json_tcache_entry),
            caller_addr: caller_addr.map(hex),
            caller_symbol,
            tracker_note,
            tracker_explanation,
        },
        HeapTraceEvent::Calloc {
            event_id,
            nmemb,
            size,
            returned_ptr,
            chunk,
            caller_addr,
        } => JsonHeapEvent::Calloc {
            event_id: *event_id,
            nmemb: hex(*nmemb),
            size: hex(*size),
            returned_ptr: hex(*returned_ptr),
            chunk: chunk.as_ref().map(json_chunk),
            caller_addr: caller_addr.map(hex),
            caller_symbol,
            tracker_note,
            tracker_explanation,
        },
        HeapTraceEvent::Realloc {
            event_id,
            old_ptr,
            new_size,
            returned_ptr,
            old_chunk,
            new_chunk,
            caller_addr,
        } => JsonHeapEvent::Realloc {
            event_id: *event_id,
            old_ptr: hex(*old_ptr),
            new_size: hex(*new_size),
            returned_ptr: hex(*returned_ptr),
            old_chunk: old_chunk.as_ref().map(json_chunk),
            new_chunk: new_chunk.as_ref().map(json_chunk),
            caller_addr: caller_addr.map(hex),
            caller_symbol,
            tracker_note,
            tracker_explanation,
        },
    }
}

fn json_caller_symbol(symbol: &SymbolizedAddress) -> JsonCallerSymbol {
    JsonCallerSymbol {
        object: symbol.object_name.clone(),
        symbol: symbol.symbol.clone(),
        symbol_addr: hex(symbol.symbol_addr),
        offset: hex(symbol.offset),
        source: symbol.source.as_ref().map(json_source_location),
    }
}

fn json_source_location(source: &SourceLocation) -> JsonSourceLocation {
    JsonSourceLocation {
        file: source.file.clone(),
        line: source.line,
        column: source.column,
    }
}

pub fn json_layout_record(
    event_id: usize,
    snapshot: &GlibcHeapSnapshot,
    tracker: &HeapTracker,
    tcache_tracker: Option<&ObservedTcacheTracker>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    profile: GlibcProfile,
    max_chunks: usize,
    max_tcache_chain: usize,
) -> JsonTraceRecord {
    JsonTraceRecord::HeapLayout {
        event_id,
        heap_start: hex(snapshot.heap_start),
        heap_end: hex(snapshot.heap_end),
        chunks: snapshot
            .chunks
            .iter()
            .take(max_chunks)
            .map(|chunk| {
                json_layout_chunk(
                    chunk,
                    tracker,
                    tcache_tracker,
                    fastbins,
                    unsorted_bin,
                    smallbins,
                    largebins,
                    profile,
                    max_tcache_chain,
                )
            })
            .collect(),
        truncated: snapshot.truncated,
        chunks_omitted: snapshot.chunks.len().saturating_sub(max_chunks),
    }
}

pub fn json_observed_tcache_chains_record(
    event_id: usize,
    tracker: &ObservedTcacheTracker,
    max_entries: usize,
) -> JsonTraceRecord {
    JsonTraceRecord::ObservedTcacheChains {
        event_id,
        chains: tracker
            .chains(max_entries)
            .iter()
            .map(json_observed_tcache_chain)
            .collect(),
    }
}

pub fn json_tcache_struct_candidate_record(
    event_id: usize,
    candidate: &TcacheStructCandidate,
    snapshot: Option<&TcacheSnapshotCandidate>,
) -> JsonTraceRecord {
    JsonTraceRecord::TcacheStructCandidate {
        event_id,
        candidate: json_tcache_struct_candidate(candidate),
        snapshot: snapshot.map(json_tcache_snapshot_candidate),
    }
}

pub fn json_main_arena_candidate_record(
    event_id: usize,
    candidate: &MainArenaCandidate,
) -> JsonTraceRecord {
    JsonTraceRecord::MainArenaCandidate {
        event_id,
        candidate: json_main_arena_candidate(candidate),
    }
}

pub fn json_main_arena_experiment_record(
    event_id: usize,
    experiment: &MainArenaExperiment,
) -> JsonTraceRecord {
    JsonTraceRecord::MainArenaExperiment {
        event_id,
        arena_addr: hex(experiment.arena_addr),
        candidates: experiment
            .candidates
            .iter()
            .map(json_main_arena_pointer_candidate)
            .collect(),
    }
}

pub fn json_main_arena_top_candidate_record(
    event_id: usize,
    candidate: &MainArenaTopCandidate,
) -> JsonTraceRecord {
    JsonTraceRecord::MainArenaTopCandidate {
        event_id,
        arena_addr: hex(candidate.arena_addr),
        field_offset: hex(candidate.field_offset),
        top_addr: hex(candidate.top_addr),
        points_into_heap: candidate.points_into_heap,
        matches_heap_chunk: candidate.matches_heap_chunk,
        chunk_size: candidate.chunk_size.map(hex),
        status: json_main_arena_top_status(candidate.status).to_string(),
        source: json_main_arena_field_source(candidate.source).to_string(),
        profile: candidate.profile_name.clone(),
    }
}

pub fn json_main_arena_view_record(
    event_id: usize,
    arena: &MainArenaCandidate,
    top: Option<&MainArenaTopCandidate>,
) -> JsonTraceRecord {
    JsonTraceRecord::MainArenaView {
        event_id,
        arena: JsonMainArenaViewArena {
            addr: hex(arena.runtime_addr),
            source: json_main_arena_source(arena.source).to_string(),
            offset: arena.offset.map(hex),
            libc_path: Some(arena.libc_path.clone()),
        },
        top: top.map(json_main_arena_view_top),
    }
}

pub fn json_fastbin_experiment_record(
    event_id: usize,
    experiment: &FastbinExperiment,
) -> JsonTraceRecord {
    JsonTraceRecord::FastbinExperiment {
        event_id,
        arena_addr: hex(experiment.arena_addr),
        candidates: experiment
            .candidates
            .iter()
            .map(json_fastbin_pointer_candidate)
            .collect(),
    }
}

pub fn json_unsorted_bin_experiment_record(
    event_id: usize,
    experiment: &UnsortedBinExperiment,
) -> JsonTraceRecord {
    JsonTraceRecord::UnsortedBinExperiment {
        event_id,
        arena_addr: hex(experiment.arena_addr),
        candidates: experiment
            .candidates
            .iter()
            .map(json_unsorted_bin_pointer_candidate)
            .collect(),
    }
}

pub fn json_bin_experiment_record(event_id: usize, experiment: &BinExperiment) -> JsonTraceRecord {
    JsonTraceRecord::BinExperiment {
        event_id,
        arena_addr: hex(experiment.arena_addr),
        candidates: experiment
            .candidates
            .iter()
            .map(json_bin_pointer_candidate)
            .collect(),
    }
}

pub fn json_unsorted_bin_record(
    event_id: usize,
    snapshot: &UnsortedBinSnapshot,
) -> JsonTraceRecord {
    JsonTraceRecord::UnsortedBin {
        event_id,
        arena_addr: hex(snapshot.arena_addr),
        field_offset: hex(snapshot.field_offset),
        fd: hex(snapshot.fd),
        bk: hex(snapshot.bk),
        fd_points_into_heap: snapshot.fd_points_into_heap,
        bk_points_into_heap: snapshot.bk_points_into_heap,
        fd_matches_heap_chunk: snapshot.fd_matches_heap_chunk,
        bk_matches_heap_chunk: snapshot.bk_matches_heap_chunk,
        fd_known_freed: snapshot.fd_known_freed,
        bk_known_freed: snapshot.bk_known_freed,
        chain: snapshot.chain.as_ref().map(json_unsorted_bin_chain),
    }
}

pub fn json_unsorted_bin_validation_record(
    event_id: usize,
    validation: &UnsortedBinValidation,
) -> JsonTraceRecord {
    JsonTraceRecord::UnsortedBinValidation {
        event_id,
        validation: json_unsorted_bin_validation(validation),
    }
}

pub fn json_fastbins_record(event_id: usize, snapshot: &FastbinsSnapshot) -> JsonTraceRecord {
    JsonTraceRecord::Fastbins {
        event_id,
        arena_addr: hex(snapshot.arena_addr),
        heads: snapshot.heads.iter().map(json_fastbin_head).collect(),
        chains: snapshot.chains.iter().map(json_fastbin_chain).collect(),
    }
}

pub fn json_regular_bins_record(
    event_id: usize,
    snapshot: &RegularBinsSnapshot,
) -> JsonTraceRecord {
    JsonTraceRecord::RegularBins {
        event_id,
        arena_addr: hex(snapshot.arena_addr),
        bins_offset: hex(snapshot.bins_offset),
        heads: snapshot.heads.iter().map(json_regular_bin_head).collect(),
    }
}

pub fn json_smallbins_record(event_id: usize, snapshot: &SmallbinsSnapshot) -> JsonTraceRecord {
    JsonTraceRecord::Smallbins {
        event_id,
        arena_addr: hex(snapshot.arena_addr),
        bins_offset: hex(snapshot.bins_offset),
        chains: snapshot.chains.iter().map(json_smallbin_chain).collect(),
    }
}

pub fn json_smallbin_validation_record(
    event_id: usize,
    snapshot: &SmallbinsSnapshot,
) -> JsonTraceRecord {
    JsonTraceRecord::SmallbinValidation {
        event_id,
        validations: validate_smallbins_snapshot(snapshot)
            .iter()
            .map(json_smallbin_bin_validation)
            .collect(),
    }
}

pub fn json_largebins_record(event_id: usize, snapshot: &LargebinsSnapshot) -> JsonTraceRecord {
    JsonTraceRecord::Largebins {
        event_id,
        arena_addr: hex(snapshot.arena_addr),
        bins_offset: hex(snapshot.bins_offset),
        chains: snapshot.chains.iter().map(json_largebin_chain).collect(),
    }
}

pub fn json_largebin_validation_record(
    event_id: usize,
    snapshot: &LargebinsSnapshot,
) -> JsonTraceRecord {
    JsonTraceRecord::LargebinValidation {
        event_id,
        validations: validate_largebins_snapshot(snapshot)
            .iter()
            .map(json_largebin_bin_validation)
            .collect(),
    }
}

pub fn json_fastbin_validation_record(
    event_id: usize,
    snapshot: &FastbinsSnapshot,
) -> JsonTraceRecord {
    JsonTraceRecord::FastbinValidation {
        event_id,
        validations: validate_fastbins_snapshot(snapshot)
            .iter()
            .map(json_fastbin_bin_validation)
            .collect(),
    }
}

pub fn json_tcache_comparison_record(
    event_id: usize,
    snapshot: &TcacheSnapshotCandidate,
    observed: &ObservedTcacheTracker,
    max_entries: usize,
) -> JsonTraceRecord {
    JsonTraceRecord::TcacheComparison {
        event_id,
        comparisons: compare_tcache_snapshot_with_observed(snapshot, observed, max_entries)
            .iter()
            .map(json_tcache_bin_comparison)
            .collect(),
    }
}

pub fn json_tcache_validation_record(
    event_id: usize,
    snapshot: &TcacheSnapshotCandidate,
    observed: &ObservedTcacheTracker,
    heap_tracker: &HeapTracker,
    heap_range: Option<(u64, u64)>,
    max_entries: usize,
) -> JsonTraceRecord {
    JsonTraceRecord::TcacheValidation {
        event_id,
        validations: validate_tcache_snapshot_candidate(
            snapshot,
            observed,
            heap_tracker,
            heap_range,
            max_entries,
        )
        .iter()
        .map(json_tcache_bin_validation)
        .collect(),
    }
}

pub fn json_allocator_warnings_record(
    event_id: usize,
    warnings: &[AllocatorWarning],
) -> JsonTraceRecord {
    JsonTraceRecord::AllocatorWarnings {
        event_id,
        warnings: warnings.iter().map(json_allocator_warning).collect(),
    }
}

pub fn json_allocator_source_summary_record(
    event_id: usize,
    summary: &AllocatorSourceSummary,
) -> JsonTraceRecord {
    JsonTraceRecord::AllocatorSourceSummary {
        event_id,
        tcache_candidate_chunks: summary.tcache_candidate_chunks,
        fastbin_chunks: summary.fastbin_chunks,
        unsorted_chunks: summary.unsorted_chunks,
        smallbin_chunks: summary.smallbin_chunks,
        largebin_chunks: summary.largebin_chunks,
        total_free_list_chunks: summary.total_free_list_chunks,
        warning_count: summary.warning_count,
    }
}

pub fn json_allocator_source_delta_record(
    event_id: usize,
    delta: &AllocatorSourceDelta,
) -> JsonTraceRecord {
    JsonTraceRecord::AllocatorSourceDelta {
        event_id,
        tcache_candidate_chunks_delta: delta.tcache_candidate_chunks_delta,
        fastbin_chunks_delta: delta.fastbin_chunks_delta,
        unsorted_chunks_delta: delta.unsorted_chunks_delta,
        smallbin_chunks_delta: delta.smallbin_chunks_delta,
        largebin_chunks_delta: delta.largebin_chunks_delta,
        total_free_list_chunks_delta: delta.total_free_list_chunks_delta,
        warning_count_delta: delta.warning_count_delta,
    }
}

pub fn json_heap_scan_record(event_id: usize, report: &HeapScanReport) -> JsonTraceRecord {
    JsonTraceRecord::HeapScan {
        event_id,
        report: json_heap_scan_report(report),
    }
}

fn json_layout_chunk(
    chunk: &GlibcChunkHeader,
    tracker: &HeapTracker,
    tcache_tracker: Option<&ObservedTcacheTracker>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    profile: GlibcProfile,
    max_tcache_chain: usize,
) -> JsonLayoutChunk {
    let tcache_candidate = tcache_tracker
        .and_then(|tracker| tracker.membership_for_ptr(chunk.user_addr, max_tcache_chain))
        .map(|membership| JsonObservedTcacheMembership {
            chunk_size: hex(membership.chunk_size),
            index: membership.index,
        });
    let allocator_source = largebins
        .and_then(|largebins| largebins.membership_for_user_addr(chunk.user_addr, profile))
        .map(|membership| JsonAllocatorSource {
            kind: "largebin".to_string(),
            chunk_size: membership
                .chunk_size
                .map(hex)
                .unwrap_or_else(|| "unknown".to_string()),
            index: membership.node_index,
        })
        .or_else(|| {
            smallbins
                .and_then(|smallbins| smallbins.membership_for_user_addr(chunk.user_addr, profile))
                .map(|membership| JsonAllocatorSource {
                    kind: "smallbin".to_string(),
                    chunk_size: hex(membership.chunk_size),
                    index: membership.node_index,
                })
        })
        .or_else(|| {
            unsorted_bin
                .and_then(|unsorted_bin| {
                    unsorted_bin.membership_for_user_addr(chunk.user_addr, profile)
                })
                .map(|membership| JsonAllocatorSource {
                    kind: "unsorted".to_string(),
                    chunk_size: membership
                        .chunk_size
                        .map(hex)
                        .unwrap_or_else(|| "unknown".to_string()),
                    index: membership.node_index,
                })
        })
        .or_else(|| {
            fastbins
                .and_then(|fastbins| fastbins.membership_for_user_addr(chunk.user_addr, profile))
                .map(|membership| JsonAllocatorSource {
                    kind: "fastbin".to_string(),
                    chunk_size: hex(membership.chunk_size),
                    index: membership.chain_index,
                })
        })
        .or_else(|| {
            tcache_tracker
                .and_then(|tracker| tracker.membership_for_ptr(chunk.user_addr, max_tcache_chain))
                .map(|membership| JsonAllocatorSource {
                    kind: "tcache_candidate".to_string(),
                    chunk_size: hex(membership.chunk_size),
                    index: membership.index,
                })
        });

    JsonLayoutChunk {
        chunk_addr: hex(chunk.chunk_addr),
        user_addr: hex(chunk.user_addr),
        prev_size: hex(chunk.prev_size),
        size_raw: hex(chunk.size_raw),
        size: hex(chunk.size),
        flags: chunk
            .flags
            .labels()
            .into_iter()
            .map(str::to_string)
            .collect(),
        state: json_observed_state(tracker.state_for_user_addr(chunk.user_addr)).to_string(),
        tcache_candidate,
        allocator_source,
    }
}

fn json_heap_scan_report(report: &HeapScanReport) -> JsonHeapScanReport {
    JsonHeapScanReport {
        chunks_walked: report.chunks_walked,
        allocated_observed: report.allocated_observed,
        freed_observed: report.freed_observed,
        unknown_observed: report.unknown_observed,
        allocator_source_chunks: report.allocator_source_chunks,
        warning_count: report.warning_count,
        suspicious_count: report.suspicious_count,
        top_validated: report.top_validated,
        heap_snapshot_truncated: report.heap_snapshot_truncated,
        status: heap_scan_status_str(report.status).to_string(),
        findings: report.findings.iter().map(json_heap_scan_finding).collect(),
    }
}

fn json_heap_scan_finding(finding: &HeapScanFinding) -> JsonHeapScanFinding {
    JsonHeapScanFinding {
        severity: heap_scan_finding_severity_str(finding.severity).to_string(),
        kind: finding.kind.clone(),
        chunk_addr: finding.chunk_addr.map(hex),
        user_addr: finding.user_addr.map(hex),
        message: finding.message.clone(),
    }
}

fn json_allocator_warning(warning: &AllocatorWarning) -> JsonAllocatorWarning {
    JsonAllocatorWarning {
        kind: allocator_warning_kind_str(warning.kind).to_string(),
        chunk_addr: hex(warning.chunk_addr),
        user_addr: hex(warning.user_addr),
        sources: warning
            .sources
            .iter()
            .map(json_allocator_source_membership)
            .collect(),
        message: warning.message.clone(),
    }
}

fn json_allocator_source_membership(
    source: &AllocatorSourceMembership,
) -> JsonAllocatorSourceMembership {
    JsonAllocatorSourceMembership {
        kind: allocator_source_kind_str(source.kind).to_string(),
        chunk_size: source.chunk_size.map(hex),
        index: source.index,
        chunk_addr: hex(source.chunk_addr),
        user_addr: hex(source.user_addr),
    }
}

fn json_observed_tcache_chain(
    chain: &heapify_core::tcache::ObservedTcacheChain,
) -> JsonObservedTcacheChain {
    JsonObservedTcacheChain {
        chunk_size: hex(chain.chunk_size),
        head: chain.head.map(hex),
        entries: chain.entries.iter().copied().map(hex).collect(),
        truncated: chain.truncated,
        stopped_on_unknown_next: chain.stopped_on_unknown_next,
    }
}

fn json_tcache_struct_candidate(candidate: &TcacheStructCandidate) -> JsonTcacheStructCandidate {
    JsonTcacheStructCandidate {
        chunk_addr: hex(candidate.chunk_addr),
        user_addr: hex(candidate.user_addr),
        size: hex(candidate.size),
        reason: candidate.reason.clone(),
    }
}

pub fn json_main_arena_source(source: MainArenaSource) -> &'static str {
    match source {
        MainArenaSource::LibcSymbol => "libc_symbol",
        MainArenaSource::UserOffset => "user_offset",
    }
}

fn json_main_arena_candidate(candidate: &MainArenaCandidate) -> JsonMainArenaCandidate {
    JsonMainArenaCandidate {
        libc_path: candidate.libc_path.clone(),
        symbol_name: candidate.symbol_name.clone(),
        runtime_addr: hex(candidate.runtime_addr),
        source: json_main_arena_source(candidate.source).to_string(),
        offset: candidate.offset.map(hex),
    }
}

pub fn json_main_arena_role_hint(role_hint: &MainArenaRoleHint) -> &'static str {
    match role_hint {
        MainArenaRoleHint::CandidateTop => "candidate_top",
        MainArenaRoleHint::HeapPointer => "heap_pointer",
    }
}

pub fn json_main_arena_top_status(status: MainArenaTopStatus) -> &'static str {
    match status {
        MainArenaTopStatus::MatchesWalkedChunk => "matches_walked_chunk",
        MainArenaTopStatus::PointsIntoHeap => "points_into_heap",
        MainArenaTopStatus::OutsideHeap => "outside_heap",
        MainArenaTopStatus::Unavailable => "unavailable",
    }
}

pub fn json_main_arena_view_status(status: MainArenaViewStatus) -> &'static str {
    match status {
        MainArenaViewStatus::Validated => "validated",
        MainArenaViewStatus::PointsIntoHeap => "points_into_heap",
        MainArenaViewStatus::OutsideHeap => "outside_heap",
        MainArenaViewStatus::Unavailable => "unavailable",
    }
}

pub fn json_main_arena_field_source(source: MainArenaFieldSource) -> &'static str {
    match source {
        MainArenaFieldSource::UserOffset => "user_offset",
        MainArenaFieldSource::GlibcProfile => "glibc_profile",
    }
}

fn json_main_arena_view_top(candidate: &MainArenaTopCandidate) -> JsonMainArenaViewTop {
    JsonMainArenaViewTop {
        field_offset: hex(candidate.field_offset),
        value: hex(candidate.top_addr),
        size: candidate.chunk_size.map(hex),
        source: json_main_arena_field_source(candidate.source).to_string(),
        profile: candidate.profile_name.clone(),
        status: json_main_arena_view_status(main_arena_view_status_from_top_status(
            candidate.status,
        ))
        .to_string(),
    }
}

pub fn json_fastbin_experiment_role(role: FastbinExperimentRole) -> &'static str {
    match role {
        FastbinExperimentRole::FastbinCandidate => "fastbin_candidate",
    }
}

pub fn json_unsorted_experiment_role(role: UnsortedExperimentRole) -> &'static str {
    match role {
        UnsortedExperimentRole::UnsortedCandidate => "unsorted_candidate",
    }
}

pub fn json_bin_experiment_role(role: BinExperimentRole) -> &'static str {
    match role {
        BinExperimentRole::BinSentinelCandidate => "bin_sentinel_candidate",
    }
}

pub fn json_regular_bin_role(role: RegularBinRole) -> &'static str {
    match role {
        RegularBinRole::Unsorted => "unsorted",
        RegularBinRole::Smallbin => "smallbin",
        RegularBinRole::Largebin => "largebin",
    }
}

fn json_fastbin_pointer_candidate(
    candidate: &FastbinPointerCandidate,
) -> JsonFastbinPointerCandidate {
    JsonFastbinPointerCandidate {
        field_offset: hex(candidate.field_offset),
        value: hex(candidate.value),
        possible_chunk_size: candidate.possible_chunk_size.map(hex),
        points_into_heap: candidate.points_into_heap,
        matches_heap_chunk: candidate.matches_heap_chunk,
        known_freed: candidate.known_freed,
        role: json_fastbin_experiment_role(candidate.role).to_string(),
    }
}

fn json_unsorted_bin_pointer_candidate(
    candidate: &UnsortedBinPointerCandidate,
) -> JsonUnsortedBinPointerCandidate {
    JsonUnsortedBinPointerCandidate {
        field_offset: hex(candidate.field_offset),
        fd: hex(candidate.fd),
        bk: hex(candidate.bk),
        fd_points_into_heap: candidate.fd_points_into_heap,
        bk_points_into_heap: candidate.bk_points_into_heap,
        fd_matches_heap_chunk: candidate.fd_matches_heap_chunk,
        bk_matches_heap_chunk: candidate.bk_matches_heap_chunk,
        fd_known_freed: candidate.fd_known_freed,
        bk_known_freed: candidate.bk_known_freed,
        role: json_unsorted_experiment_role(candidate.role).to_string(),
    }
}

fn json_bin_pointer_candidate(candidate: &BinPointerCandidate) -> JsonBinPointerCandidate {
    JsonBinPointerCandidate {
        field_offset: hex(candidate.field_offset),
        fd: hex(candidate.fd),
        bk: hex(candidate.bk),
        fd_points_into_heap: candidate.fd_points_into_heap,
        bk_points_into_heap: candidate.bk_points_into_heap,
        fd_points_into_arena: candidate.fd_points_into_arena,
        bk_points_into_arena: candidate.bk_points_into_arena,
        fd_matches_heap_chunk: candidate.fd_matches_heap_chunk,
        bk_matches_heap_chunk: candidate.bk_matches_heap_chunk,
        fd_known_freed: candidate.fd_known_freed,
        bk_known_freed: candidate.bk_known_freed,
        role: json_bin_experiment_role(candidate.role).to_string(),
    }
}

fn json_regular_bin_head(head: &RegularBinHead) -> JsonRegularBinHead {
    JsonRegularBinHead {
        index: head.index,
        glibc_bin_index: head.glibc_bin_index,
        role: json_regular_bin_role(head.role).to_string(),
        chunk_size: head.chunk_size.map(hex),
        field_offset: hex(head.field_offset),
        fd: hex(head.fd),
        bk: hex(head.bk),
        empty: head.empty,
        fd_points_into_heap: head.fd_points_into_heap,
        bk_points_into_heap: head.bk_points_into_heap,
        fd_points_into_arena: head.fd_points_into_arena,
        bk_points_into_arena: head.bk_points_into_arena,
        fd_matches_heap_chunk: head.fd_matches_heap_chunk,
        bk_matches_heap_chunk: head.bk_matches_heap_chunk,
        fd_known_freed: head.fd_known_freed,
        bk_known_freed: head.bk_known_freed,
    }
}

fn json_smallbin_chain(chain: &SmallbinChain) -> JsonSmallbinChain {
    JsonSmallbinChain {
        regular_index: chain.regular_index,
        glibc_bin_index: chain.glibc_bin_index,
        expected_chunk_size: hex(chain.expected_chunk_size),
        sentinel_addr: hex(chain.sentinel_addr),
        head: hex(chain.head),
        tail: hex(chain.tail),
        nodes: chain.nodes.iter().map(json_smallbin_node).collect(),
        empty: chain.empty,
        truncated: chain.truncated,
        stopped_on_unknown_next: chain.stopped_on_unknown_next,
        cycle_detected: chain.cycle_detected,
        fd_bk_consistent: chain.fd_bk_consistent,
    }
}

fn json_smallbin_node(node: &SmallbinNode) -> JsonSmallbinNode {
    JsonSmallbinNode {
        chunk_addr: hex(node.chunk_addr),
        user_addr: hex(node.user_addr),
        fd: hex(node.fd),
        bk: hex(node.bk),
        chunk_size: node.chunk_size.map(hex),
        matches_heap_chunk: node.matches_heap_chunk,
        known_freed: node.known_freed,
        fd_points_to_sentinel: node.fd_points_to_sentinel,
        bk_points_to_sentinel: node.bk_points_to_sentinel,
    }
}

fn json_smallbin_bin_validation(validation: &SmallbinBinValidation) -> JsonSmallbinBinValidation {
    JsonSmallbinBinValidation {
        regular_index: validation.regular_index,
        glibc_bin_index: validation.glibc_bin_index,
        expected_chunk_size: hex(validation.expected_chunk_size),
        head: hex(validation.head),
        head_in_heap: json_smallbin_validation_value(validation.head_in_heap).to_string(),
        nodes_same_size: json_smallbin_validation_value(validation.nodes_same_size).to_string(),
        fd_bk_consistent: json_smallbin_validation_value(validation.fd_bk_consistent).to_string(),
        nodes_known_freed: json_smallbin_validation_value(validation.nodes_known_freed).to_string(),
        chain_complete: json_smallbin_validation_value(validation.chain_complete).to_string(),
        status: json_smallbin_validation_status(validation.status).to_string(),
    }
}

pub fn json_smallbin_validation_value(value: SmallbinValidationValue) -> &'static str {
    match value {
        SmallbinValidationValue::Yes => "yes",
        SmallbinValidationValue::No => "no",
        SmallbinValidationValue::Unknown => "unknown",
    }
}

pub fn json_smallbin_validation_status(status: SmallbinValidationStatus) -> &'static str {
    match status {
        SmallbinValidationStatus::Plausible => "plausible",
        SmallbinValidationStatus::Incomplete => "incomplete",
        SmallbinValidationStatus::Suspicious => "suspicious",
    }
}

fn json_largebin_chain(chain: &LargebinChain) -> JsonLargebinChain {
    JsonLargebinChain {
        regular_index: chain.regular_index,
        glibc_bin_index: chain.glibc_bin_index,
        sentinel_addr: hex(chain.sentinel_addr),
        head: hex(chain.head),
        tail: hex(chain.tail),
        nodes: chain.nodes.iter().map(json_largebin_node).collect(),
        empty: chain.empty,
        truncated: chain.truncated,
        stopped_on_unknown_next: chain.stopped_on_unknown_next,
        cycle_detected: chain.cycle_detected,
        fd_bk_consistent: chain.fd_bk_consistent,
    }
}

fn json_largebin_node(node: &LargebinNode) -> JsonLargebinNode {
    JsonLargebinNode {
        chunk_addr: hex(node.chunk_addr),
        user_addr: hex(node.user_addr),
        fd: hex(node.fd),
        bk: hex(node.bk),
        fd_nextsize: hex(node.fd_nextsize),
        bk_nextsize: hex(node.bk_nextsize),
        chunk_size: node.chunk_size.map(hex),
        matches_heap_chunk: node.matches_heap_chunk,
        known_freed: node.known_freed,
        fd_points_to_sentinel: node.fd_points_to_sentinel,
        bk_points_to_sentinel: node.bk_points_to_sentinel,
        fd_nextsize_points_into_heap: node.fd_nextsize_points_into_heap,
        bk_nextsize_points_into_heap: node.bk_nextsize_points_into_heap,
        fd_nextsize_points_into_arena: node.fd_nextsize_points_into_arena,
        bk_nextsize_points_into_arena: node.bk_nextsize_points_into_arena,
    }
}

fn json_largebin_bin_validation(validation: &LargebinBinValidation) -> JsonLargebinBinValidation {
    JsonLargebinBinValidation {
        regular_index: validation.regular_index,
        glibc_bin_index: validation.glibc_bin_index,
        head: hex(validation.head),
        head_in_heap: json_largebin_validation_value(validation.head_in_heap).to_string(),
        fd_bk_consistent: json_largebin_validation_value(validation.fd_bk_consistent).to_string(),
        nodes_known_freed: json_largebin_validation_value(validation.nodes_known_freed).to_string(),
        chain_complete: json_largebin_validation_value(validation.chain_complete).to_string(),
        status: json_largebin_validation_status(validation.status).to_string(),
    }
}

pub fn json_largebin_validation_value(value: LargebinValidationValue) -> &'static str {
    match value {
        LargebinValidationValue::Yes => "yes",
        LargebinValidationValue::No => "no",
        LargebinValidationValue::Unknown => "unknown",
    }
}

pub fn json_largebin_validation_status(status: LargebinValidationStatus) -> &'static str {
    match status {
        LargebinValidationStatus::Plausible => "plausible",
        LargebinValidationStatus::Incomplete => "incomplete",
        LargebinValidationStatus::Suspicious => "suspicious",
    }
}

fn json_unsorted_bin_chain(chain: &UnsortedBinChain) -> JsonUnsortedBinChain {
    JsonUnsortedBinChain {
        sentinel_addr: hex(chain.sentinel_addr),
        head: hex(chain.head),
        tail: hex(chain.tail),
        nodes: chain.nodes.iter().map(json_unsorted_bin_node).collect(),
        empty: chain.empty,
        truncated: chain.truncated,
        stopped_on_unknown_next: chain.stopped_on_unknown_next,
        cycle_detected: chain.cycle_detected,
        fd_bk_consistent: chain.fd_bk_consistent,
    }
}

fn json_unsorted_bin_node(node: &UnsortedBinNode) -> JsonUnsortedBinNode {
    JsonUnsortedBinNode {
        chunk_addr: hex(node.chunk_addr),
        user_addr: hex(node.user_addr),
        fd: hex(node.fd),
        bk: hex(node.bk),
        chunk_size: node.chunk_size.map(hex),
        matches_heap_chunk: node.matches_heap_chunk,
        known_freed: node.known_freed,
        fd_points_to_sentinel: node.fd_points_to_sentinel,
        bk_points_to_sentinel: node.bk_points_to_sentinel,
    }
}

fn json_unsorted_bin_validation(validation: &UnsortedBinValidation) -> JsonUnsortedBinValidation {
    JsonUnsortedBinValidation {
        head_in_heap: json_unsorted_bin_validation_value(validation.head_in_heap).to_string(),
        fd_bk_consistent: json_unsorted_bin_validation_value(validation.fd_bk_consistent)
            .to_string(),
        nodes_known_freed: json_unsorted_bin_validation_value(validation.nodes_known_freed)
            .to_string(),
        chain_complete: json_unsorted_bin_validation_value(validation.chain_complete).to_string(),
        status: json_unsorted_bin_validation_status(validation.status).to_string(),
    }
}

pub fn json_unsorted_bin_validation_value(value: UnsortedBinValidationValue) -> &'static str {
    match value {
        UnsortedBinValidationValue::Yes => "yes",
        UnsortedBinValidationValue::No => "no",
        UnsortedBinValidationValue::Unknown => "unknown",
    }
}

pub fn json_unsorted_bin_validation_status(status: UnsortedBinValidationStatus) -> &'static str {
    match status {
        UnsortedBinValidationStatus::Plausible => "plausible",
        UnsortedBinValidationStatus::Incomplete => "incomplete",
        UnsortedBinValidationStatus::Suspicious => "suspicious",
    }
}

fn json_fastbin_head(head: &FastbinHead) -> JsonFastbinHead {
    JsonFastbinHead {
        index: head.index,
        chunk_size: hex(head.chunk_size),
        field_offset: hex(head.field_offset),
        head: hex(head.head),
        points_into_heap: head.points_into_heap,
        matches_heap_chunk: head.matches_heap_chunk,
        known_freed: head.known_freed,
    }
}

fn json_fastbin_chain(chain: &FastbinChain) -> JsonFastbinChain {
    JsonFastbinChain {
        index: chain.index,
        chunk_size: hex(chain.chunk_size),
        head: hex(chain.head),
        nodes: chain.nodes.iter().map(json_fastbin_node).collect(),
        truncated: chain.truncated,
        stopped_on_unknown_next: chain.stopped_on_unknown_next,
        cycle_detected: chain.cycle_detected,
    }
}

fn json_fastbin_node(node: &FastbinNode) -> JsonFastbinNode {
    JsonFastbinNode {
        chunk_addr: hex(node.chunk_addr),
        user_addr: hex(node.user_addr),
        encoded_next: hex(node.encoded_next),
        decoded_next: hex(node.decoded_next),
        chunk_size: node.chunk_size.map(hex),
        matches_heap_chunk: node.matches_heap_chunk,
        known_freed: node.known_freed,
    }
}

fn json_fastbin_bin_validation(validation: &FastbinBinValidation) -> JsonFastbinBinValidation {
    JsonFastbinBinValidation {
        index: validation.index,
        chunk_size: hex(validation.chunk_size),
        head: hex(validation.head),
        head_in_heap: json_fastbin_validation_value(validation.head_in_heap).to_string(),
        nodes_same_size: json_fastbin_validation_value(validation.nodes_same_size).to_string(),
        nodes_known_freed: json_fastbin_validation_value(validation.nodes_known_freed).to_string(),
        chain_complete: json_fastbin_validation_value(validation.chain_complete).to_string(),
        status: json_fastbin_validation_status(validation.status).to_string(),
    }
}

pub fn json_fastbin_validation_value(value: FastbinValidationValue) -> &'static str {
    match value {
        FastbinValidationValue::Yes => "yes",
        FastbinValidationValue::No => "no",
        FastbinValidationValue::Unknown => "unknown",
    }
}

pub fn json_fastbin_validation_status(status: FastbinValidationStatus) -> &'static str {
    match status {
        FastbinValidationStatus::Plausible => "plausible",
        FastbinValidationStatus::Incomplete => "incomplete",
        FastbinValidationStatus::Suspicious => "suspicious",
    }
}

fn json_main_arena_pointer_candidate(
    candidate: &MainArenaPointerCandidate,
) -> JsonMainArenaPointerCandidate {
    JsonMainArenaPointerCandidate {
        field_offset: hex(candidate.field_offset),
        value: hex(candidate.value),
        points_into_heap: candidate.points_into_heap,
        matches_heap_chunk: candidate.matches_heap_chunk,
        matched_chunk_size: candidate.matched_chunk_size.map(hex),
        role_hint: json_main_arena_role_hint(&candidate.role_hint).to_string(),
    }
}

fn json_tcache_snapshot_candidate(
    snapshot: &TcacheSnapshotCandidate,
) -> JsonTcacheSnapshotCandidate {
    JsonTcacheSnapshotCandidate {
        struct_user_addr: hex(snapshot.struct_user_addr),
        bins: snapshot
            .bins
            .iter()
            .map(|bin| JsonTcacheBinSnapshot {
                index: bin.index,
                chunk_size: hex(bin.chunk_size),
                count: bin.count,
                head: hex(bin.head),
            })
            .collect(),
    }
}

fn json_tcache_bin_comparison(comparison: &TcacheBinComparison) -> JsonTcacheBinComparison {
    JsonTcacheBinComparison {
        index: comparison.index,
        chunk_size: hex(comparison.chunk_size),
        struct_count: comparison.struct_count,
        struct_head: hex(comparison.struct_head),
        observed_entries: comparison
            .observed_entries
            .iter()
            .copied()
            .map(hex)
            .collect(),
        observed_truncated: comparison.observed_truncated,
        observed_stopped_on_unknown_next: comparison.observed_stopped_on_unknown_next,
        status: json_tcache_comparison_status(comparison.status).to_string(),
    }
}

fn json_tcache_bin_validation(validation: &TcacheBinValidation) -> JsonTcacheBinValidation {
    JsonTcacheBinValidation {
        index: validation.index,
        chunk_size: hex(validation.chunk_size),
        head: hex(validation.head),
        count: validation.count,
        head_in_heap: json_tcache_validation_value(validation.head_in_heap).to_string(),
        head_known_freed: json_tcache_validation_value(validation.head_known_freed).to_string(),
        observed_nodes_same_size: json_tcache_validation_value(validation.observed_nodes_same_size)
            .to_string(),
        count_matches_observed: json_tcache_validation_value(validation.count_matches_observed)
            .to_string(),
        status: json_tcache_validation_status(validation.status).to_string(),
    }
}

fn json_observed_state(state: Option<ObservedChunkState>) -> &'static str {
    match state {
        Some(ObservedChunkState::Allocated) => "allocated",
        Some(ObservedChunkState::Freed) => "freed",
        None => "unknown",
    }
}

pub fn json_tcache_comparison_status(status: TcacheComparisonStatus) -> &'static str {
    match status {
        TcacheComparisonStatus::MatchesObservedHeadAndCount => "MatchesObservedHeadAndCount",
        TcacheComparisonStatus::HeadMatchesCountDiffers => "HeadMatchesCountDiffers",
        TcacheComparisonStatus::HeadMatchesObservedChainIncomplete => {
            "HeadMatchesObservedChainIncomplete"
        }
        TcacheComparisonStatus::HeadDiffers => "HeadDiffers",
        TcacheComparisonStatus::MissingObservedChain => "MissingObservedChain",
    }
}

pub fn json_tcache_validation_value(value: TcacheValidationValue) -> &'static str {
    match value {
        TcacheValidationValue::Yes => "yes",
        TcacheValidationValue::No => "no",
        TcacheValidationValue::Unknown => "unknown",
    }
}

pub fn json_tcache_validation_status(status: TcacheValidationStatus) -> &'static str {
    match status {
        TcacheValidationStatus::Plausible => "plausible",
        TcacheValidationStatus::Incomplete => "incomplete",
        TcacheValidationStatus::Suspicious => "suspicious",
    }
}

pub fn json_tracker_note(note: HeapTrackerNote) -> &'static str {
    match note {
        HeapTrackerNote::NewAllocation => "NewAllocation",
        HeapTrackerNote::ReusedFreedChunk => "ReusedFreedChunk",
        HeapTrackerNote::FreedKnownChunk => "FreedKnownChunk",
        HeapTrackerNote::DoubleFree => "DoubleFree",
        HeapTrackerNote::FreeUnknownPointer => "FreeUnknownPointer",
        HeapTrackerNote::NullMalloc => "NullMalloc",
        HeapTrackerNote::NullFree => "NullFree",
        HeapTrackerNote::AllocatedPointerReturnedAgain => "AllocatedPointerReturnedAgain",
        HeapTrackerNote::NullCalloc => "NullCalloc",
        HeapTrackerNote::ReallocNullActsLikeMalloc => "ReallocNullActsLikeMalloc",
        HeapTrackerNote::ReallocInPlace => "ReallocInPlace",
        HeapTrackerNote::ReallocMovedAllocation => "ReallocMovedAllocation",
        HeapTrackerNote::ReallocFailedKeepsOldPointer => "ReallocFailedKeepsOldPointer",
        HeapTrackerNote::ReallocPtrZeroFreedOldPointer => "ReallocPtrZeroFreedOldPointer",
        HeapTrackerNote::ReallocUnknownOldPointer => "ReallocUnknownOldPointer",
    }
}

pub fn json_tracker_explanation(explanation: HeapTrackerExplanation) -> Option<&'static str> {
    match explanation {
        HeapTrackerExplanation::LikelyTcacheOrFastbinReuse { .. } => {
            Some("LikelyTcacheOrFastbinReuse")
        }
        HeapTrackerExplanation::NoExtraExplanation => None,
    }
}

#[cfg(test)]
mod tests {
    use heapify_core::allocator_sources::{
        AllocatorSourceDelta, AllocatorSourceKind, AllocatorSourceMembership,
        AllocatorSourceSummary, AllocatorWarning, AllocatorWarningKind,
    };
    use heapify_core::glibc::{
        BinExperiment, BinExperimentRole, BinPointerCandidate, FastbinChain, FastbinExperiment,
        FastbinExperimentRole, FastbinHead, FastbinNode, FastbinPointerCandidate, FastbinsSnapshot,
        GlibcChunkHeader, GlibcHeapSnapshot, LargebinChain, LargebinNode, LargebinsSnapshot,
        MainArenaCandidate, MainArenaFieldSource, MainArenaSource, RegularBinHead, RegularBinRole,
        RegularBinsSnapshot, SmallbinChain, SmallbinNode, SmallbinsSnapshot, TcacheBinSnapshot,
        TcacheEntryCandidate, TcacheSnapshotCandidate, UnsortedBinChain, UnsortedBinExperiment,
        UnsortedBinNode, UnsortedBinPointerCandidate, UnsortedBinSnapshot, UnsortedExperimentRole,
    };
    use heapify_core::heap_scan::{
        HeapScanFinding, HeapScanFindingSeverity, HeapScanReport, HeapScanStatus,
    };
    use heapify_core::tcache::ObservedTcacheTracker;
    use heapify_core::tracker::{HeapTracker, HeapTrackerExplanation, HeapTrackerNote};
    use heapify_core::HeapTraceEvent;
    use heapify_debugger::{MainArenaExperiment, MainArenaPointerCandidate, MainArenaRoleHint};
    use heapify_debugger::{MainArenaTopCandidate, MainArenaTopStatus};
    use heapify_debugger::{SourceLocation, SymbolizedAddress};
    use serde_json::Value;

    use super::{
        hex, json_allocator_source_delta_record, json_allocator_source_summary_record,
        json_allocator_warnings_record, json_bin_experiment_record, json_bin_experiment_role,
        json_chunk, json_event, json_event_with_caller_symbol, json_fastbin_experiment_record,
        json_fastbin_experiment_role, json_fastbin_validation_record, json_fastbins_record,
        json_heap_scan_record, json_largebin_validation_record, json_largebins_record,
        json_layout_record, json_main_arena_candidate_record, json_main_arena_experiment_record,
        json_main_arena_field_source, json_main_arena_role_hint, json_main_arena_source,
        json_main_arena_top_candidate_record, json_main_arena_top_status,
        json_main_arena_view_record, json_observed_tcache_chains_record, json_regular_bin_role,
        json_regular_bins_record, json_session_end_record, json_session_start_record,
        json_smallbins_record, json_tcache_comparison_record, json_tcache_validation_record,
        json_trace_event_record, json_unsorted_bin_experiment_record, json_unsorted_bin_record,
        json_unsorted_experiment_role, JsonCallerSymbol, JsonTraceFeatures, JsonTraceRecord,
    };

    #[test]
    fn hex_formats_values_as_lowercase_hex_strings() {
        assert_eq!(hex(0), "0x0");
        assert_eq!(hex(0x55d64e1792a0), "0x55d64e1792a0");
    }

    #[test]
    fn chunk_flags_serialize_as_label_array() {
        let chunk = GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x35);

        let value = serde_json::to_value(json_chunk(&chunk)).unwrap();

        assert_eq!(
            value["flags"],
            serde_json::json!(["PREV_INUSE", "NON_MAIN_ARENA"])
        );
    }

    #[test]
    fn malloc_event_serializes_type_and_hex_fields() {
        let event = HeapTraceEvent::Malloc {
            event_id: 1,
            requested_size: 0x20,
            returned_ptr: 0x1010,
            chunk: Some(GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x31)),
            caller_addr: None,
        };

        let value: Value = serde_json::to_value(json_event(
            &event,
            HeapTrackerNote::NewAllocation,
            HeapTrackerExplanation::NoExtraExplanation,
        ))
        .unwrap();

        assert_eq!(value["type"], "malloc");
        assert_eq!(value["event_id"], 1);
        assert_eq!(value["requested_size"], "0x20");
        assert_eq!(value["returned_ptr"], "0x1010");
        assert_eq!(value["chunk"]["size"], "0x30");
        assert!(value["caller_symbol"].is_null());
        assert_eq!(value["tracker_note"], "NewAllocation");
        assert!(value["tracker_explanation"].is_null());
    }

    #[test]
    fn heap_event_serializes_caller_addr_as_hex() {
        let event = HeapTraceEvent::Malloc {
            event_id: 1,
            requested_size: 0x20,
            returned_ptr: 0x1010,
            chunk: None,
            caller_addr: Some(0x5555555551b4),
        };

        let value: Value = serde_json::to_value(json_event(
            &event,
            HeapTrackerNote::NewAllocation,
            HeapTrackerExplanation::NoExtraExplanation,
        ))
        .unwrap();

        assert_eq!(value["caller_addr"], "0x5555555551b4");
        assert!(value["caller_symbol"].is_null());
    }

    #[test]
    fn heap_event_serializes_caller_symbol_hex_fields() {
        let event = HeapTraceEvent::Malloc {
            event_id: 1,
            requested_size: 0x20,
            returned_ptr: 0x1010,
            chunk: None,
            caller_addr: Some(0x5555555551b8),
        };
        let caller_symbol = SymbolizedAddress {
            addr: 0x5555555551b8,
            object_name: Some("libhelper.so".to_string()),
            symbol: "allocate_from_main".to_string(),
            symbol_addr: 0x555555555180,
            offset: 0x38,
            source: None,
        };

        let value: Value = serde_json::to_value(json_event_with_caller_symbol(
            &event,
            HeapTrackerNote::NewAllocation,
            HeapTrackerExplanation::NoExtraExplanation,
            Some(&caller_symbol),
        ))
        .unwrap();

        assert_eq!(value["caller_addr"], "0x5555555551b8");
        assert_eq!(value["caller_symbol"]["object"], "libhelper.so");
        assert_eq!(value["caller_symbol"]["symbol"], "allocate_from_main");
        assert_eq!(value["caller_symbol"]["symbol_addr"], "0x555555555180");
        assert_eq!(value["caller_symbol"]["offset"], "0x38");
    }

    #[test]
    fn heap_event_serializes_caller_symbol_source_location() {
        let event = HeapTraceEvent::Malloc {
            event_id: 1,
            requested_size: 0x20,
            returned_ptr: 0x1010,
            chunk: None,
            caller_addr: Some(0x5555555551b8),
        };
        let caller_symbol = SymbolizedAddress {
            addr: 0x5555555551b8,
            object_name: None,
            symbol: "allocate_from_main".to_string(),
            symbol_addr: 0x555555555180,
            offset: 0x38,
            source: Some(SourceLocation {
                file: Some("examples/simple_malloc.c".to_string()),
                line: Some(12),
                column: Some(7),
            }),
        };

        let value: Value = serde_json::to_value(json_event_with_caller_symbol(
            &event,
            HeapTrackerNote::NewAllocation,
            HeapTrackerExplanation::NoExtraExplanation,
            Some(&caller_symbol),
        ))
        .unwrap();

        assert_eq!(
            value["caller_symbol"]["source"]["file"],
            "examples/simple_malloc.c"
        );
        assert_eq!(value["caller_symbol"]["source"]["line"], 12);
        assert_eq!(value["caller_symbol"]["source"]["column"], 7);
    }

    #[test]
    fn caller_symbol_parses_with_and_without_source() {
        let without_object: JsonCallerSymbol = serde_json::from_value(serde_json::json!({
            "symbol": "main",
            "symbol_addr": "0x1000",
            "offset": "0x10"
        }))
        .unwrap();
        let with_source: JsonCallerSymbol = serde_json::from_value(serde_json::json!({
            "object": "libc.so.6",
            "symbol": "__libc_malloc",
            "symbol_addr": "0x7000",
            "offset": "0x20",
            "source": {
                "file": "main.c",
                "line": 10,
                "column": 4
            }
        }))
        .unwrap();

        assert_eq!(without_object.object, None);
        assert_eq!(without_object.source, None);
        assert_eq!(with_source.object, Some("libc.so.6".to_string()));
        assert_eq!(with_source.source.unwrap().file, Some("main.c".to_string()));
    }

    #[test]
    fn trace_event_record_wraps_heap_event() {
        let event = HeapTraceEvent::Malloc {
            event_id: 1,
            requested_size: 0x20,
            returned_ptr: 0x1010,
            chunk: None,
            caller_addr: None,
        };

        let value: Value = serde_json::to_value(json_trace_event_record(
            &event,
            HeapTrackerNote::NewAllocation,
            HeapTrackerExplanation::NoExtraExplanation,
        ))
        .unwrap();

        assert_eq!(value["type"], "event");
        assert_eq!(value["event"]["type"], "malloc");
    }

    #[test]
    fn session_start_serializes_type_and_metadata() {
        let value: Value = serde_json::to_value(json_session_start_record(
            "./prog",
            &["a".to_string()],
            "target_plt",
            "glibc-x86_64-modern",
            Some("glibc-2.35-x86_64"),
            None,
            Some(super::JsonLibcMetadata {
                path: Some("/lib/libc.so.6".to_string()),
                supplied_path: Some("./libc.so.6".to_string()),
                paths_match: Some(false),
                version: Some("2.39".to_string()),
            }),
            Some(super::JsonLaunchMetadata {
                mode: "custom_loader_with_preload".to_string(),
                loader: Some("./ld-linux-x86-64.so.2".to_string()),
                library_path: Some(".".to_string()),
                preload: Some("./libc.so.6".to_string()),
                cwd: Some("./challenge".to_string()),
                clear_env: true,
                set_env: vec!["PATH".to_string()],
                unset_env: vec!["LD_DEBUG".to_string()],
                stdin: super::JsonStdinMetadata {
                    kind: "text".to_string(),
                    path: None,
                    bytes: Some(4),
                },
            }),
            "basic",
            JsonTraceFeatures {
                layout: true,
                tcache_candidates: false,
                tcache_struct: false,
                libc_symbols: false,
            },
        ))
        .unwrap();

        assert_eq!(value["type"], "session_start");
        assert_eq!(value["libc"]["supplied_path"], "./libc.so.6");
        assert_eq!(value["libc"]["paths_match"], false);
        assert_eq!(value["program"], "./prog");
        assert_eq!(value["args"], serde_json::json!(["a"]));
        assert_eq!(value["trace_mode"], "target_plt");
        assert_eq!(value["glibc_profile"], "glibc-x86_64-modern");
        assert_eq!(value["suggested_glibc_profile"], "glibc-2.35-x86_64");
        assert_eq!(value["libc"]["path"], "/lib/libc.so.6");
        assert_eq!(value["libc"]["version"], "2.39");
        assert_eq!(value["launch"]["mode"], "custom_loader_with_preload");
        assert_eq!(value["launch"]["loader"], "./ld-linux-x86-64.so.2");
        assert_eq!(value["launch"]["library_path"], ".");
        assert_eq!(value["launch"]["preload"], "./libc.so.6");
        assert_eq!(value["launch"]["cwd"], "./challenge");
        assert_eq!(value["launch"]["clear_env"], true);
        assert_eq!(value["launch"]["set_env"], serde_json::json!(["PATH"]));
        assert_eq!(
            value["launch"]["unset_env"],
            serde_json::json!(["LD_DEBUG"])
        );
        assert_eq!(value["launch"]["stdin"]["kind"], "text");
        assert_eq!(value["launch"]["stdin"]["bytes"], 4);
        assert_eq!(value["allocator_views_preset"], "basic");
        assert!(
            !value.to_string().contains("/secret/bin"),
            "launch metadata must not serialize environment values"
        );
        assert_eq!(value["features"]["layout"], true);
    }

    #[test]
    fn session_start_serializes_selected_glibc_profile() {
        let value: Value = serde_json::to_value(json_session_start_record(
            "./prog",
            &[],
            "target_plt",
            "glibc-2.35-x86_64",
            None,
            Some(heapify_core::glibc::GlibcProfileSelection {
                requested: "auto".to_string(),
                selected: "glibc-2.35-x86_64".to_string(),
                detected_version: Some("2.35".to_string()),
                detected_libc_path: Some("/lib/libc.so.6".to_string()),
                supplied_libc_path: None,
                confidence: heapify_core::glibc::GlibcProfileConfidence::High,
                reason: "detected glibc 2.35 maps to glibc-2.35-x86_64".to_string(),
                warnings: Vec::new(),
            }),
            None,
            None,
            "none",
            JsonTraceFeatures {
                layout: false,
                tcache_candidates: false,
                tcache_struct: false,
                libc_symbols: false,
            },
        ))
        .unwrap();

        assert_eq!(value["glibc_profile"], "glibc-2.35-x86_64");
        assert_eq!(value["glibc_profile_selection"]["requested"], "auto");
        assert_eq!(value["glibc_profile_selection"]["confidence"], "high");
    }

    #[test]
    fn session_end_serializes_type_and_counts() {
        let value: Value = serde_json::to_value(json_session_end_record("unknown", 3)).unwrap();

        assert_eq!(value["type"], "session_end");
        assert_eq!(value["exit_status"], "unknown");
        assert_eq!(value["event_count"], 3);
    }

    #[test]
    fn main_arena_source_serializes_as_stable_string() {
        assert_eq!(
            json_main_arena_source(MainArenaSource::LibcSymbol),
            "libc_symbol"
        );
        assert_eq!(
            json_main_arena_source(MainArenaSource::UserOffset),
            "user_offset"
        );
    }

    #[test]
    fn main_arena_candidate_serializes_hex_runtime_addr() {
        let candidate = MainArenaCandidate {
            libc_path: "/lib/libc.so.6".to_string(),
            symbol_name: "main_arena".to_string(),
            runtime_addr: 0x7ffff7dd1b80,
            source: MainArenaSource::LibcSymbol,
            offset: Some(0x1d3c60),
        };

        let value: Value =
            serde_json::to_value(json_main_arena_candidate_record(2, &candidate)).unwrap();

        assert_eq!(value["type"], "main_arena_candidate");
        assert_eq!(value["event_id"], 2);
        assert_eq!(value["candidate"]["libc_path"], "/lib/libc.so.6");
        assert_eq!(value["candidate"]["symbol_name"], "main_arena");
        assert_eq!(value["candidate"]["runtime_addr"], "0x7ffff7dd1b80");
        assert_eq!(value["candidate"]["source"], "libc_symbol");
        assert_eq!(value["candidate"]["offset"], "0x1d3c60");
    }

    #[test]
    fn main_arena_role_hint_serializes_as_stable_string() {
        assert_eq!(
            json_main_arena_role_hint(&MainArenaRoleHint::CandidateTop),
            "candidate_top"
        );
        assert_eq!(
            json_main_arena_role_hint(&MainArenaRoleHint::HeapPointer),
            "heap_pointer"
        );
    }

    #[test]
    fn main_arena_experiment_serializes_hex_fields() {
        let experiment = MainArenaExperiment {
            arena_addr: 0x7ffff7bd3c60,
            candidates: vec![MainArenaPointerCandidate {
                field_offset: 0x60,
                value: 0x55555555a000,
                points_into_heap: true,
                matches_heap_chunk: true,
                matched_chunk_size: Some(0x21000),
                role_hint: MainArenaRoleHint::CandidateTop,
            }],
        };

        let value: Value =
            serde_json::to_value(json_main_arena_experiment_record(3, &experiment)).unwrap();

        assert_eq!(value["type"], "main_arena_experiment");
        assert_eq!(value["event_id"], 3);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["candidates"][0]["field_offset"], "0x60");
        assert_eq!(value["candidates"][0]["value"], "0x55555555a000");
        assert_eq!(value["candidates"][0]["matched_chunk_size"], "0x21000");
        assert_eq!(value["candidates"][0]["role_hint"], "candidate_top");
    }

    #[test]
    fn main_arena_top_status_serializes_as_stable_string() {
        assert_eq!(
            json_main_arena_top_status(MainArenaTopStatus::MatchesWalkedChunk),
            "matches_walked_chunk"
        );
        assert_eq!(
            json_main_arena_top_status(MainArenaTopStatus::PointsIntoHeap),
            "points_into_heap"
        );
        assert_eq!(
            json_main_arena_top_status(MainArenaTopStatus::OutsideHeap),
            "outside_heap"
        );
        assert_eq!(
            json_main_arena_top_status(MainArenaTopStatus::Unavailable),
            "unavailable"
        );
    }

    #[test]
    fn main_arena_field_source_serializes_as_stable_string() {
        assert_eq!(
            json_main_arena_field_source(MainArenaFieldSource::UserOffset),
            "user_offset"
        );
        assert_eq!(
            json_main_arena_field_source(MainArenaFieldSource::GlibcProfile),
            "glibc_profile"
        );
    }

    #[test]
    fn main_arena_top_candidate_serializes_hex_fields() {
        let candidate = MainArenaTopCandidate {
            arena_addr: 0x7ffff7bd3c60,
            field_offset: 0x60,
            top_addr: 0x55555555a000,
            points_into_heap: true,
            matches_heap_chunk: true,
            chunk_size: Some(0x21000),
            status: MainArenaTopStatus::MatchesWalkedChunk,
            source: MainArenaFieldSource::GlibcProfile,
            profile_name: Some("glibc-test".to_string()),
        };

        let value: Value =
            serde_json::to_value(json_main_arena_top_candidate_record(4, &candidate)).unwrap();

        assert_eq!(value["type"], "main_arena_top_candidate");
        assert_eq!(value["event_id"], 4);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["field_offset"], "0x60");
        assert_eq!(value["top_addr"], "0x55555555a000");
        assert_eq!(value["chunk_size"], "0x21000");
        assert_eq!(value["status"], "matches_walked_chunk");
        assert_eq!(value["source"], "glibc_profile");
        assert_eq!(value["profile"], "glibc-test");
    }

    #[test]
    fn main_arena_view_serializes_hex_fields_and_validated_status() {
        let arena = MainArenaCandidate {
            libc_path: "/lib/libc.so.6".to_string(),
            symbol_name: "main_arena".to_string(),
            runtime_addr: 0x7ffff7bd3c60,
            source: MainArenaSource::UserOffset,
            offset: Some(0x1d3c60),
        };
        let top = MainArenaTopCandidate {
            arena_addr: 0x7ffff7bd3c60,
            field_offset: 0x60,
            top_addr: 0x55555555a000,
            points_into_heap: true,
            matches_heap_chunk: true,
            chunk_size: Some(0x21000),
            status: MainArenaTopStatus::MatchesWalkedChunk,
            source: MainArenaFieldSource::GlibcProfile,
            profile_name: Some("glibc-2.35-x86_64".to_string()),
        };

        let value: Value =
            serde_json::to_value(json_main_arena_view_record(4, &arena, Some(&top))).unwrap();

        assert_eq!(value["type"], "main_arena_view");
        assert_eq!(value["arena"]["addr"], "0x7ffff7bd3c60");
        assert_eq!(value["arena"]["offset"], "0x1d3c60");
        assert_eq!(value["top"]["field_offset"], "0x60");
        assert_eq!(value["top"]["value"], "0x55555555a000");
        assert_eq!(value["top"]["size"], "0x21000");
        assert_eq!(value["top"]["source"], "glibc_profile");
        assert_eq!(value["top"]["profile"], "glibc-2.35-x86_64");
        assert_eq!(value["top"]["status"], "validated");
    }

    #[test]
    fn fastbin_role_serializes_as_stable_string() {
        assert_eq!(
            json_fastbin_experiment_role(FastbinExperimentRole::FastbinCandidate),
            "fastbin_candidate"
        );
    }

    #[test]
    fn fastbin_experiment_serializes_hex_fields() {
        let experiment = FastbinExperiment {
            arena_addr: 0x7ffff7bd3c60,
            candidates: vec![FastbinPointerCandidate {
                field_offset: 0x20,
                value: 0x55555555a000,
                possible_chunk_size: Some(0x30),
                points_into_heap: true,
                matches_heap_chunk: true,
                known_freed: Some(true),
                role: FastbinExperimentRole::FastbinCandidate,
            }],
        };

        let value: Value =
            serde_json::to_value(json_fastbin_experiment_record(5, &experiment)).unwrap();

        assert_eq!(value["type"], "fastbin_experiment");
        assert_eq!(value["event_id"], 5);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["candidates"][0]["field_offset"], "0x20");
        assert_eq!(value["candidates"][0]["value"], "0x55555555a000");
        assert_eq!(value["candidates"][0]["possible_chunk_size"], "0x30");
        assert_eq!(value["candidates"][0]["known_freed"], true);
        assert_eq!(value["candidates"][0]["role"], "fastbin_candidate");
    }

    #[test]
    fn unsorted_role_serializes_as_stable_string() {
        assert_eq!(
            json_unsorted_experiment_role(UnsortedExperimentRole::UnsortedCandidate),
            "unsorted_candidate"
        );
    }

    #[test]
    fn unsorted_bin_experiment_serializes_hex_fields() {
        let experiment = UnsortedBinExperiment {
            arena_addr: 0x7ffff7bd3c60,
            candidates: vec![UnsortedBinPointerCandidate {
                field_offset: 0x70,
                fd: 0x55555555a000,
                bk: 0x55555555b000,
                fd_points_into_heap: true,
                bk_points_into_heap: true,
                fd_matches_heap_chunk: true,
                bk_matches_heap_chunk: false,
                fd_known_freed: Some(true),
                bk_known_freed: Some(false),
                role: UnsortedExperimentRole::UnsortedCandidate,
            }],
        };

        let value: Value =
            serde_json::to_value(json_unsorted_bin_experiment_record(6, &experiment)).unwrap();

        assert_eq!(value["type"], "unsorted_bin_experiment");
        assert_eq!(value["event_id"], 6);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["candidates"][0]["field_offset"], "0x70");
        assert_eq!(value["candidates"][0]["fd"], "0x55555555a000");
        assert_eq!(value["candidates"][0]["bk"], "0x55555555b000");
        assert_eq!(value["candidates"][0]["fd_known_freed"], true);
        assert_eq!(value["candidates"][0]["bk_known_freed"], false);
        assert_eq!(value["candidates"][0]["role"], "unsorted_candidate");
    }

    #[test]
    fn bin_role_serializes_as_stable_string() {
        assert_eq!(
            json_bin_experiment_role(BinExperimentRole::BinSentinelCandidate),
            "bin_sentinel_candidate"
        );
    }

    #[test]
    fn bin_experiment_serializes_hex_fields() {
        let experiment = BinExperiment {
            arena_addr: 0x7ffff7bd3c60,
            candidates: vec![BinPointerCandidate {
                field_offset: 0x90,
                fd: 0x55555555a000,
                bk: 0x7ffff7bd3cf0,
                fd_points_into_heap: true,
                bk_points_into_heap: false,
                fd_points_into_arena: false,
                bk_points_into_arena: true,
                fd_matches_heap_chunk: true,
                bk_matches_heap_chunk: false,
                fd_known_freed: Some(true),
                bk_known_freed: None,
                role: BinExperimentRole::BinSentinelCandidate,
            }],
        };

        let value: Value =
            serde_json::to_value(json_bin_experiment_record(7, &experiment)).unwrap();

        assert_eq!(value["type"], "bin_experiment");
        assert_eq!(value["event_id"], 7);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["candidates"][0]["field_offset"], "0x90");
        assert_eq!(value["candidates"][0]["fd"], "0x55555555a000");
        assert_eq!(value["candidates"][0]["bk"], "0x7ffff7bd3cf0");
        assert_eq!(value["candidates"][0]["fd_points_into_heap"], true);
        assert_eq!(value["candidates"][0]["bk_points_into_arena"], true);
        assert_eq!(value["candidates"][0]["fd_known_freed"], true);
        assert_eq!(value["candidates"][0]["bk_known_freed"], Value::Null);
        assert_eq!(value["candidates"][0]["role"], "bin_sentinel_candidate");
    }

    #[test]
    fn regular_bin_role_serializes_as_stable_string() {
        assert_eq!(json_regular_bin_role(RegularBinRole::Unsorted), "unsorted");
        assert_eq!(json_regular_bin_role(RegularBinRole::Smallbin), "smallbin");
        assert_eq!(json_regular_bin_role(RegularBinRole::Largebin), "largebin");
    }

    #[test]
    fn regular_bins_record_serializes_hex_fields() {
        let snapshot = RegularBinsSnapshot {
            arena_addr: 0x7ffff7bd3c60,
            bins_offset: 0x70,
            heads: vec![RegularBinHead {
                index: 0,
                glibc_bin_index: 1,
                role: RegularBinRole::Unsorted,
                chunk_size: None,
                field_offset: 0x70,
                fd: 0x7ffff7bd3cd0,
                bk: 0x7ffff7bd3cd0,
                empty: true,
                fd_points_into_heap: false,
                bk_points_into_heap: false,
                fd_points_into_arena: true,
                bk_points_into_arena: true,
                fd_matches_heap_chunk: false,
                bk_matches_heap_chunk: false,
                fd_known_freed: None,
                bk_known_freed: None,
            }],
        };

        let value: Value = serde_json::to_value(json_regular_bins_record(8, &snapshot)).unwrap();

        assert_eq!(value["type"], "regular_bins");
        assert_eq!(value["event_id"], 8);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["bins_offset"], "0x70");
        assert_eq!(value["heads"][0]["index"], 0);
        assert_eq!(value["heads"][0]["role"], "unsorted");
        assert_eq!(value["heads"][0]["field_offset"], "0x70");
        assert_eq!(value["heads"][0]["fd"], "0x7ffff7bd3cd0");
        assert_eq!(value["heads"][0]["bk"], "0x7ffff7bd3cd0");
        assert_eq!(value["heads"][0]["empty"], true);
        assert_eq!(value["heads"][0]["fd_points_into_arena"], true);
        assert_eq!(value["heads"][0]["fd_known_freed"], Value::Null);
    }

    #[test]
    fn smallbins_record_serializes_hex_fields() {
        let snapshot = SmallbinsSnapshot {
            arena_addr: 0x7ffff7bd3c60,
            bins_offset: 0x70,
            chains: vec![SmallbinChain {
                regular_index: 31,
                glibc_bin_index: 32,
                expected_chunk_size: 0x200,
                sentinel_addr: 0x7ffff7bd3ec0,
                head: 0x55555555a000,
                tail: 0x55555555a000,
                nodes: vec![SmallbinNode {
                    chunk_addr: 0x55555555a000,
                    user_addr: 0x55555555a010,
                    fd: 0x7ffff7bd3ec0,
                    bk: 0x7ffff7bd3ec0,
                    chunk_size: Some(0x200),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
                fd_bk_consistent: true,
            }],
        };

        let value: Value = serde_json::to_value(json_smallbins_record(8, &snapshot)).unwrap();

        assert_eq!(value["type"], "smallbins");
        assert_eq!(value["event_id"], 8);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["bins_offset"], "0x70");
        assert_eq!(value["chains"][0]["glibc_bin_index"], 32);
        assert_eq!(value["chains"][0]["expected_chunk_size"], "0x200");
        assert_eq!(value["chains"][0]["sentinel_addr"], "0x7ffff7bd3ec0");
        assert_eq!(
            value["chains"][0]["nodes"][0]["chunk_addr"],
            "0x55555555a000"
        );
        assert_eq!(value["chains"][0]["nodes"][0]["known_freed"], true);
    }

    #[test]
    fn largebins_record_serializes_hex_fields() {
        let snapshot = LargebinsSnapshot {
            arena_addr: 0x7ffff7bd3c60,
            bins_offset: 0x70,
            chains: vec![LargebinChain {
                regular_index: 64,
                glibc_bin_index: 65,
                sentinel_addr: 0x7ffff7bd4500,
                head: 0x55555555a000,
                tail: 0x55555555a000,
                nodes: vec![LargebinNode {
                    chunk_addr: 0x55555555a000,
                    user_addr: 0x55555555a010,
                    fd: 0x7ffff7bd4500,
                    bk: 0x7ffff7bd4500,
                    fd_nextsize: 0x55555555b000,
                    bk_nextsize: 0x55555555b000,
                    chunk_size: Some(0x510),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                    fd_nextsize_points_into_heap: true,
                    bk_nextsize_points_into_heap: true,
                    fd_nextsize_points_into_arena: false,
                    bk_nextsize_points_into_arena: false,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
                fd_bk_consistent: true,
            }],
        };

        let value: Value = serde_json::to_value(json_largebins_record(8, &snapshot)).unwrap();

        assert_eq!(value["type"], "largebins");
        assert_eq!(value["event_id"], 8);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["bins_offset"], "0x70");
        assert_eq!(value["chains"][0]["glibc_bin_index"], 65);
        assert_eq!(
            value["chains"][0]["nodes"][0]["fd_nextsize"],
            "0x55555555b000"
        );
        assert_eq!(value["chains"][0]["nodes"][0]["chunk_size"], "0x510");

        let validation: Value =
            serde_json::to_value(json_largebin_validation_record(8, &snapshot)).unwrap();
        assert_eq!(validation["type"], "largebin_validation");
        assert_eq!(validation["validations"][0]["status"], "plausible");
        assert!(validation["validations"][0].get("nextsize_order").is_none());
    }

    #[test]
    fn unsorted_bin_record_serializes_hex_fields() {
        let snapshot = UnsortedBinSnapshot {
            arena_addr: 0x7ffff7bd3c60,
            field_offset: 0x70,
            fd: 0x55555555a000,
            bk: 0x55555555b000,
            fd_points_into_heap: true,
            bk_points_into_heap: true,
            fd_matches_heap_chunk: true,
            bk_matches_heap_chunk: false,
            fd_known_freed: Some(true),
            bk_known_freed: Some(false),
            chain: Some(UnsortedBinChain {
                sentinel_addr: 0x7ffff7bd3cd0,
                head: 0x55555555a000,
                tail: 0x55555555a000,
                nodes: vec![UnsortedBinNode {
                    chunk_addr: 0x55555555a000,
                    user_addr: 0x55555555a010,
                    fd: 0x7ffff7bd3cd0,
                    bk: 0x7ffff7bd3cd0,
                    chunk_size: Some(0x510),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
                fd_bk_consistent: true,
            }),
        };

        let value: Value = serde_json::to_value(json_unsorted_bin_record(6, &snapshot)).unwrap();

        assert_eq!(value["type"], "unsorted_bin");
        assert_eq!(value["event_id"], 6);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["field_offset"], "0x70");
        assert_eq!(value["fd"], "0x55555555a000");
        assert_eq!(value["bk"], "0x55555555b000");
        assert_eq!(value["fd_known_freed"], true);
        assert_eq!(value["bk_known_freed"], false);
        assert_eq!(value["chain"]["sentinel_addr"], "0x7ffff7bd3cd0");
        assert_eq!(value["chain"]["nodes"][0]["chunk_addr"], "0x55555555a000");
        assert_eq!(value["chain"]["nodes"][0]["fd"], "0x7ffff7bd3cd0");
        assert_eq!(value["chain"]["nodes"][0]["chunk_size"], "0x510");
    }

    #[test]
    fn allocator_warning_serializes_hex_addresses() {
        let warnings = vec![AllocatorWarning {
            kind: AllocatorWarningKind::ConflictingAllocatorSources,
            chunk_addr: 0x1000,
            user_addr: 0x1010,
            sources: vec![AllocatorSourceMembership {
                kind: AllocatorSourceKind::Fastbin,
                chunk_size: Some(0x30),
                index: Some(0),
                chunk_addr: 0x1000,
                user_addr: 0x1010,
            }],
            message: "chunk appears in multiple allocator sources".to_string(),
        }];

        let value: Value =
            serde_json::to_value(json_allocator_warnings_record(9, &warnings)).unwrap();

        assert_eq!(value["type"], "allocator_warnings");
        assert_eq!(value["event_id"], 9);
        assert_eq!(
            value["warnings"][0]["kind"],
            "conflicting_allocator_sources"
        );
        assert_eq!(value["warnings"][0]["chunk_addr"], "0x1000");
        assert_eq!(value["warnings"][0]["user_addr"], "0x1010");
        assert_eq!(value["warnings"][0]["sources"][0]["kind"], "fastbin");
        assert_eq!(value["warnings"][0]["sources"][0]["chunk_size"], "0x30");
        assert_eq!(value["warnings"][0]["sources"][0]["chunk_addr"], "0x1000");
        assert_eq!(value["warnings"][0]["sources"][0]["user_addr"], "0x1010");
    }

    #[test]
    fn heap_scan_serializes_optional_addresses_as_hex() {
        let report = HeapScanReport {
            chunks_walked: 1,
            allocated_observed: 1,
            freed_observed: 0,
            unknown_observed: 0,
            allocator_source_chunks: 1,
            warning_count: 1,
            suspicious_count: 1,
            top_validated: Some(false),
            heap_snapshot_truncated: false,
            status: HeapScanStatus::Suspicious,
            findings: vec![HeapScanFinding {
                severity: HeapScanFindingSeverity::Suspicious,
                kind: "free_list_size_mismatch".to_string(),
                chunk_addr: Some(0x1000),
                user_addr: Some(0x1010),
                message: "fastbin[0x30] expected size 0x30 but chunk has size 0x40".to_string(),
            }],
        };

        let value: Value = serde_json::to_value(json_heap_scan_record(9, &report)).unwrap();

        assert_eq!(value["type"], "heap_scan");
        assert_eq!(value["event_id"], 9);
        assert_eq!(value["report"]["status"], "suspicious");
        assert_eq!(value["report"]["findings"][0]["severity"], "suspicious");
        assert_eq!(
            value["report"]["findings"][0]["kind"],
            "free_list_size_mismatch"
        );
        assert_eq!(value["report"]["findings"][0]["chunk_addr"], "0x1000");
        assert_eq!(value["report"]["findings"][0]["user_addr"], "0x1010");
    }

    #[test]
    fn allocator_source_summary_serializes_expected_fields() {
        let summary = AllocatorSourceSummary {
            tcache_candidate_chunks: 1,
            fastbin_chunks: 2,
            unsorted_chunks: 3,
            smallbin_chunks: 4,
            largebin_chunks: 5,
            total_free_list_chunks: 4,
            warning_count: 5,
        };

        let value: Value =
            serde_json::to_value(json_allocator_source_summary_record(9, &summary)).unwrap();

        assert_eq!(value["type"], "allocator_source_summary");
        assert_eq!(value["event_id"], 9);
        assert_eq!(value["tcache_candidate_chunks"], 1);
        assert_eq!(value["fastbin_chunks"], 2);
        assert_eq!(value["unsorted_chunks"], 3);
        assert_eq!(value["smallbin_chunks"], 4);
        assert_eq!(value["largebin_chunks"], 5);
        assert_eq!(value["total_free_list_chunks"], 4);
        assert_eq!(value["warning_count"], 5);
    }

    #[test]
    fn allocator_source_delta_serializes_expected_fields() {
        let delta = AllocatorSourceDelta {
            tcache_candidate_chunks_delta: 1,
            fastbin_chunks_delta: -2,
            unsorted_chunks_delta: 0,
            smallbin_chunks_delta: 2,
            largebin_chunks_delta: -1,
            total_free_list_chunks_delta: 3,
            warning_count_delta: -4,
        };

        let value: Value =
            serde_json::to_value(json_allocator_source_delta_record(9, &delta)).unwrap();

        assert_eq!(value["type"], "allocator_source_delta");
        assert_eq!(value["event_id"], 9);
        assert_eq!(value["tcache_candidate_chunks_delta"], 1);
        assert_eq!(value["fastbin_chunks_delta"], -2);
        assert_eq!(value["unsorted_chunks_delta"], 0);
        assert_eq!(value["smallbin_chunks_delta"], 2);
        assert_eq!(value["largebin_chunks_delta"], -1);
        assert_eq!(value["total_free_list_chunks_delta"], 3);
        assert_eq!(value["warning_count_delta"], -4);
    }

    #[test]
    fn fastbins_record_serializes_hex_fields() {
        let snapshot = FastbinsSnapshot {
            arena_addr: 0x7ffff7bd3c60,
            heads: vec![FastbinHead {
                index: 1,
                chunk_size: 0x30,
                field_offset: 0x18,
                head: 0x55555555a000,
                points_into_heap: true,
                matches_heap_chunk: true,
                known_freed: Some(true),
            }],
            chains: vec![FastbinChain {
                index: 1,
                chunk_size: 0x30,
                head: 0x55555555a000,
                nodes: vec![FastbinNode {
                    chunk_addr: 0x55555555a000,
                    user_addr: 0x55555555a010,
                    encoded_next: 0x55500000f,
                    decoded_next: 0x0,
                    chunk_size: Some(0x30),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                }],
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
            }],
        };

        let value: Value = serde_json::to_value(json_fastbins_record(6, &snapshot)).unwrap();

        assert_eq!(value["type"], "fastbins");
        assert_eq!(value["event_id"], 6);
        assert_eq!(value["arena_addr"], "0x7ffff7bd3c60");
        assert_eq!(value["heads"][0]["index"], 1);
        assert_eq!(value["heads"][0]["chunk_size"], "0x30");
        assert_eq!(value["heads"][0]["field_offset"], "0x18");
        assert_eq!(value["heads"][0]["head"], "0x55555555a000");
        assert_eq!(value["heads"][0]["points_into_heap"], true);
        assert_eq!(value["heads"][0]["matches_heap_chunk"], true);
        assert_eq!(value["heads"][0]["known_freed"], true);
        assert_eq!(value["chains"][0]["index"], 1);
        assert_eq!(value["chains"][0]["chunk_size"], "0x30");
        assert_eq!(value["chains"][0]["head"], "0x55555555a000");
        assert_eq!(
            value["chains"][0]["nodes"][0]["chunk_addr"],
            "0x55555555a000"
        );
        assert_eq!(
            value["chains"][0]["nodes"][0]["user_addr"],
            "0x55555555a010"
        );
        assert_eq!(
            value["chains"][0]["nodes"][0]["encoded_next"],
            "0x55500000f"
        );
        assert_eq!(value["chains"][0]["nodes"][0]["decoded_next"], "0x0");
        assert_eq!(value["chains"][0]["nodes"][0]["chunk_size"], "0x30");
        assert_eq!(value["chains"][0]["nodes"][0]["matches_heap_chunk"], true);
        assert_eq!(value["chains"][0]["nodes"][0]["known_freed"], true);
        assert_eq!(value["chains"][0]["truncated"], false);
        assert_eq!(value["chains"][0]["stopped_on_unknown_next"], false);
        assert_eq!(value["chains"][0]["cycle_detected"], false);
    }

    #[test]
    fn fastbin_validation_serializes_stable_strings() {
        let snapshot = FastbinsSnapshot {
            arena_addr: 0x7ffff7bd3c60,
            heads: vec![FastbinHead {
                index: 1,
                chunk_size: 0x30,
                field_offset: 0x18,
                head: 0x55555555a000,
                points_into_heap: true,
                matches_heap_chunk: true,
                known_freed: Some(true),
            }],
            chains: vec![FastbinChain {
                index: 1,
                chunk_size: 0x30,
                head: 0x55555555a000,
                nodes: vec![FastbinNode {
                    chunk_addr: 0x55555555a000,
                    user_addr: 0x55555555a010,
                    encoded_next: 0,
                    decoded_next: 0,
                    chunk_size: Some(0x30),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                }],
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
            }],
        };

        let value: Value =
            serde_json::to_value(json_fastbin_validation_record(7, &snapshot)).unwrap();

        assert_eq!(value["type"], "fastbin_validation");
        assert_eq!(value["event_id"], 7);
        assert_eq!(value["validations"][0]["index"], 1);
        assert_eq!(value["validations"][0]["chunk_size"], "0x30");
        assert_eq!(value["validations"][0]["head"], "0x55555555a000");
        assert_eq!(value["validations"][0]["head_in_heap"], "yes");
        assert_eq!(value["validations"][0]["nodes_same_size"], "yes");
        assert_eq!(value["validations"][0]["nodes_known_freed"], "yes");
        assert_eq!(value["validations"][0]["chain_complete"], "yes");
        assert_eq!(value["validations"][0]["status"], "plausible");
    }

    #[test]
    fn trace_record_json_roundtrips_through_dto() {
        let event = HeapTraceEvent::Malloc {
            event_id: 1,
            requested_size: 0x20,
            returned_ptr: 0x1010,
            chunk: Some(GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x31)),
            caller_addr: None,
        };
        let record = json_trace_event_record(
            &event,
            HeapTrackerNote::NewAllocation,
            HeapTrackerExplanation::NoExtraExplanation,
        );
        let before = serde_json::to_value(record).unwrap();

        let decoded: JsonTraceRecord = serde_json::from_value(before.clone()).unwrap();
        let after = serde_json::to_value(decoded).unwrap();

        assert_eq!(after, before);
    }

    #[test]
    fn layout_chunk_state_serializes_as_stable_string() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1010, Some(0x30));
        tracker.observe_malloc(2, 0x20, 0x2010, Some(0x30));
        tracker.observe_free(3, 0x2010);
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x4000,
            chunks: vec![
                GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x31),
                GlibcChunkHeader::from_chunk_parts(0x2000, 0, 0x31),
                GlibcChunkHeader::from_chunk_parts(0x3000, 0, 0x31),
            ],
            truncated: false,
        };

        let value: Value = serde_json::to_value(json_layout_record(
            3,
            &snapshot,
            &tracker,
            None,
            None,
            None,
            None,
            None,
            heapify_core::glibc::GLIBC_X86_64_MODERN,
            32,
            32,
        ))
        .unwrap();

        assert_eq!(value["type"], "heap_layout");
        assert_eq!(value["chunks"][0]["state"], "allocated");
        assert_eq!(value["chunks"][1]["state"], "freed");
        assert_eq!(value["chunks"][2]["state"], "unknown");
    }

    #[test]
    fn layout_allocator_source_prefers_fastbin_over_tcache_candidate() {
        let tracker = HeapTracker::new();
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x31)],
            truncated: false,
        };
        let mut tcache_tracker = ObservedTcacheTracker::new();
        tcache_tracker.observe_event(&HeapTraceEvent::Free {
            event_id: 1,
            ptr: 0x1010,
            chunk: Some(GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x31)),
            tcache_entry: Some(TcacheEntryCandidate {
                storage_addr: 0x1010,
                encoded_next: 0,
                decoded_next: 0,
            }),
            caller_addr: None,
        });
        let fastbins = FastbinsSnapshot {
            arena_addr: 0x7000,
            heads: Vec::new(),
            chains: vec![FastbinChain {
                index: 1,
                chunk_size: 0x30,
                head: 0x1000,
                nodes: vec![FastbinNode {
                    chunk_addr: 0x1000,
                    user_addr: 0x1010,
                    encoded_next: 0,
                    decoded_next: 0,
                    chunk_size: Some(0x30),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                }],
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
            }],
        };

        let value: Value = serde_json::to_value(json_layout_record(
            2,
            &snapshot,
            &tracker,
            Some(&tcache_tracker),
            Some(&fastbins),
            None,
            None,
            None,
            heapify_core::glibc::GLIBC_X86_64_MODERN,
            32,
            32,
        ))
        .unwrap();

        assert_eq!(value["chunks"][0]["tcache_candidate"]["chunk_size"], "0x30");
        assert_eq!(value["chunks"][0]["allocator_source"]["kind"], "fastbin");
        assert_eq!(value["chunks"][0]["allocator_source"]["chunk_size"], "0x30");
        assert_eq!(value["chunks"][0]["allocator_source"]["index"], 0);
    }

    #[test]
    fn layout_allocator_source_prefers_unsorted_over_fastbin_and_tcache() {
        let tracker = HeapTracker::new();
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x511)],
            truncated: false,
        };
        let mut tcache_tracker = ObservedTcacheTracker::new();
        tcache_tracker.observe_event(&HeapTraceEvent::Free {
            event_id: 1,
            ptr: 0x1010,
            chunk: Some(GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x511)),
            tcache_entry: Some(TcacheEntryCandidate {
                storage_addr: 0x1010,
                encoded_next: 0,
                decoded_next: 0,
            }),
            caller_addr: None,
        });
        let fastbins = FastbinsSnapshot {
            arena_addr: 0x7000,
            heads: Vec::new(),
            chains: vec![FastbinChain {
                index: 1,
                chunk_size: 0x30,
                head: 0x1000,
                nodes: vec![FastbinNode {
                    chunk_addr: 0x1000,
                    user_addr: 0x1010,
                    encoded_next: 0,
                    decoded_next: 0,
                    chunk_size: Some(0x30),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                }],
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
            }],
        };
        let unsorted = UnsortedBinSnapshot {
            arena_addr: 0x7000,
            field_offset: 0x70,
            fd: 0x1000,
            bk: 0x1000,
            fd_points_into_heap: true,
            bk_points_into_heap: true,
            fd_matches_heap_chunk: true,
            bk_matches_heap_chunk: true,
            fd_known_freed: Some(true),
            bk_known_freed: Some(true),
            chain: Some(UnsortedBinChain {
                sentinel_addr: 0x7070,
                head: 0x1000,
                tail: 0x1000,
                nodes: vec![UnsortedBinNode {
                    chunk_addr: 0x1000,
                    user_addr: 0x1010,
                    fd: 0x7070,
                    bk: 0x7070,
                    chunk_size: Some(0x510),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
                fd_bk_consistent: true,
            }),
        };

        let value: Value = serde_json::to_value(json_layout_record(
            2,
            &snapshot,
            &tracker,
            Some(&tcache_tracker),
            Some(&fastbins),
            Some(&unsorted),
            None,
            None,
            heapify_core::glibc::GLIBC_X86_64_MODERN,
            32,
            32,
        ))
        .unwrap();

        assert_eq!(value["chunks"][0]["allocator_source"]["kind"], "unsorted");
        assert_eq!(
            value["chunks"][0]["allocator_source"]["chunk_size"],
            "0x510"
        );
        assert_eq!(value["chunks"][0]["allocator_source"]["index"], 0);
    }

    #[test]
    fn layout_allocator_source_prefers_smallbin_over_unsorted_fastbin_and_tcache() {
        let tracker = HeapTracker::new();
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x211)],
            truncated: false,
        };
        let mut tcache_tracker = ObservedTcacheTracker::new();
        tcache_tracker.observe_free(0x1010, 0x200, 0);
        let fastbins = FastbinsSnapshot {
            arena_addr: 0x7000,
            heads: Vec::new(),
            chains: vec![FastbinChain {
                index: 1,
                chunk_size: 0x30,
                head: 0x1000,
                nodes: vec![FastbinNode {
                    chunk_addr: 0x1000,
                    user_addr: 0x1010,
                    encoded_next: 0,
                    decoded_next: 0,
                    chunk_size: Some(0x30),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                }],
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
            }],
        };
        let unsorted = UnsortedBinSnapshot {
            arena_addr: 0x7000,
            field_offset: 0x70,
            fd: 0x1000,
            bk: 0x1000,
            fd_points_into_heap: true,
            bk_points_into_heap: true,
            fd_matches_heap_chunk: true,
            bk_matches_heap_chunk: true,
            fd_known_freed: Some(true),
            bk_known_freed: Some(true),
            chain: Some(UnsortedBinChain {
                sentinel_addr: 0x7070,
                head: 0x1000,
                tail: 0x1000,
                nodes: vec![UnsortedBinNode {
                    chunk_addr: 0x1000,
                    user_addr: 0x1010,
                    fd: 0x7070,
                    bk: 0x7070,
                    chunk_size: Some(0x210),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
                fd_bk_consistent: true,
            }),
        };
        let smallbins = SmallbinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![SmallbinChain {
                regular_index: 31,
                glibc_bin_index: 32,
                expected_chunk_size: 0x200,
                sentinel_addr: 0x7270,
                head: 0x1000,
                tail: 0x1000,
                nodes: vec![SmallbinNode {
                    chunk_addr: 0x1000,
                    user_addr: 0x1010,
                    fd: 0x7270,
                    bk: 0x7270,
                    chunk_size: Some(0x200),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
                fd_bk_consistent: true,
            }],
        };

        let value: Value = serde_json::to_value(json_layout_record(
            2,
            &snapshot,
            &tracker,
            Some(&tcache_tracker),
            Some(&fastbins),
            Some(&unsorted),
            Some(&smallbins),
            None,
            heapify_core::glibc::GLIBC_X86_64_MODERN,
            32,
            32,
        ))
        .unwrap();

        assert_eq!(value["chunks"][0]["allocator_source"]["kind"], "smallbin");
        assert_eq!(
            value["chunks"][0]["allocator_source"]["chunk_size"],
            "0x200"
        );
        assert_eq!(value["chunks"][0]["allocator_source"]["index"], 0);
    }

    #[test]
    fn layout_allocator_source_prefers_largebin_over_smallbin() {
        let tracker = HeapTracker::new();
        let snapshot = GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x3000,
            chunks: vec![GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x511)],
            truncated: false,
        };
        let smallbins = SmallbinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![SmallbinChain {
                regular_index: 31,
                glibc_bin_index: 32,
                expected_chunk_size: 0x200,
                sentinel_addr: 0x7270,
                head: 0x1000,
                tail: 0x1000,
                nodes: vec![SmallbinNode {
                    chunk_addr: 0x1000,
                    user_addr: 0x1010,
                    fd: 0x7270,
                    bk: 0x7270,
                    chunk_size: Some(0x200),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
                fd_bk_consistent: true,
            }],
        };
        let largebins = LargebinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![LargebinChain {
                regular_index: 64,
                glibc_bin_index: 65,
                sentinel_addr: 0x7470,
                head: 0x1000,
                tail: 0x1000,
                nodes: vec![LargebinNode {
                    chunk_addr: 0x1000,
                    user_addr: 0x1010,
                    fd: 0x7470,
                    bk: 0x7470,
                    fd_nextsize: 0,
                    bk_nextsize: 0,
                    chunk_size: Some(0x510),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                    fd_nextsize_points_into_heap: false,
                    bk_nextsize_points_into_heap: false,
                    fd_nextsize_points_into_arena: false,
                    bk_nextsize_points_into_arena: false,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
                fd_bk_consistent: true,
            }],
        };

        let value: Value = serde_json::to_value(json_layout_record(
            2,
            &snapshot,
            &tracker,
            None,
            None,
            None,
            Some(&smallbins),
            Some(&largebins),
            heapify_core::glibc::GLIBC_X86_64_MODERN,
            32,
            32,
        ))
        .unwrap();

        assert_eq!(value["chunks"][0]["allocator_source"]["kind"], "largebin");
        assert_eq!(
            value["chunks"][0]["allocator_source"]["chunk_size"],
            "0x510"
        );
    }

    #[test]
    fn observed_tcache_chain_serializes_addresses_as_hex_strings() {
        let mut tracker = ObservedTcacheTracker::new();
        tracker.observe_free(0x2000, 0x30, 0x1000);
        tracker.observe_free(0x1000, 0x30, 0);

        let value: Value =
            serde_json::to_value(json_observed_tcache_chains_record(2, &tracker, 32)).unwrap();

        assert_eq!(value["type"], "observed_tcache_chains");
        assert_eq!(value["chains"][0]["chunk_size"], "0x30");
        assert_eq!(value["chains"][0]["head"], "0x1000");
        assert_eq!(value["chains"][0]["entries"], serde_json::json!(["0x1000"]));
    }

    #[test]
    fn tcache_comparison_status_serializes_as_stable_string() {
        let mut tracker = ObservedTcacheTracker::new();
        tracker.observe_free(0x1000, 0x30, 0);
        let snapshot = TcacheSnapshotCandidate {
            struct_user_addr: 0x5000,
            bins: vec![TcacheBinSnapshot {
                index: 1,
                chunk_size: 0x30,
                count: 1,
                head: 0x1000,
            }],
        };

        let value: Value =
            serde_json::to_value(json_tcache_comparison_record(2, &snapshot, &tracker, 32))
                .unwrap();

        assert_eq!(value["type"], "tcache_comparison");
        assert_eq!(
            value["comparisons"][0]["status"],
            "MatchesObservedHeadAndCount"
        );
        assert_eq!(value["comparisons"][0]["struct_head"], "0x1000");
    }

    #[test]
    fn tcache_validation_serializes_lowercase_status() {
        let mut observed = ObservedTcacheTracker::new();
        observed.observe_free(0x1000, 0x30, 0);
        let mut heap_tracker = HeapTracker::new();
        heap_tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));
        heap_tracker.observe_free(2, 0x1000);
        let snapshot = TcacheSnapshotCandidate {
            struct_user_addr: 0x5000,
            bins: vec![TcacheBinSnapshot {
                index: 1,
                chunk_size: 0x30,
                count: 1,
                head: 0x1000,
            }],
        };

        let value: Value = serde_json::to_value(json_tcache_validation_record(
            2,
            &snapshot,
            &observed,
            &heap_tracker,
            Some((0x1000, 0x2000)),
            32,
        ))
        .unwrap();

        assert_eq!(value["type"], "tcache_validation");
        assert_eq!(value["validations"][0]["chunk_size"], "0x30");
        assert_eq!(value["validations"][0]["head_in_heap"], "yes");
        assert_eq!(value["validations"][0]["status"], "plausible");
    }
}
