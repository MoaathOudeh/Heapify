use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlibcProfile {
    pub name: &'static str,
    pub pointer_size: u64,
    pub malloc_alignment: u64,
    pub chunk_header_size: u64,
    pub min_chunk_size: u64,
    pub tcache_bin_count: usize,
    pub tcache_counts_offset: u64,
    pub tcache_entries_offset: u64,
    pub tcache_count_size: u64,
    pub tcache_struct_min_chunk_size: u64,
    pub tcache_struct_max_chunk_size: u64,
    pub tcache_struct_candidate_scan_chunks: usize,
    pub main_arena_top_offset: Option<u64>,
    pub main_arena_fastbins_offset: Option<u64>,
    pub main_arena_fastbin_count: Option<usize>,
    pub main_arena_unsorted_bin_offset: Option<u64>,
    pub main_arena_bins_offset: Option<u64>,
    pub main_arena_bin_count: Option<usize>,
}

pub const GLIBC_X86_64_MODERN: GlibcProfile = GlibcProfile {
    name: "glibc-x86_64-modern",
    pointer_size: 8,
    malloc_alignment: 0x10,
    chunk_header_size: 0x10,
    min_chunk_size: 0x20,
    tcache_bin_count: 64,
    tcache_counts_offset: 0x0,
    tcache_entries_offset: 0x80,
    tcache_count_size: 2,
    tcache_struct_min_chunk_size: 0x280,
    tcache_struct_max_chunk_size: 0x2a0,
    tcache_struct_candidate_scan_chunks: 8,
    main_arena_top_offset: None,
    main_arena_fastbins_offset: None,
    main_arena_fastbin_count: None,
    main_arena_unsorted_bin_offset: None,
    main_arena_bins_offset: None,
    main_arena_bin_count: None,
};

pub const GLIBC_2_35_X86_64: GlibcProfile = GlibcProfile {
    name: "glibc-2.35-x86_64",
    pointer_size: 8,
    malloc_alignment: 0x10,
    chunk_header_size: 0x10,
    min_chunk_size: 0x20,
    tcache_bin_count: 64,
    tcache_counts_offset: 0x0,
    tcache_entries_offset: 0x80,
    tcache_count_size: 2,
    tcache_struct_min_chunk_size: 0x280,
    tcache_struct_max_chunk_size: 0x2a0,
    tcache_struct_candidate_scan_chunks: 8,
    main_arena_top_offset: Some(0x60),
    main_arena_fastbins_offset: Some(0x10),
    main_arena_fastbin_count: Some(10),
    main_arena_unsorted_bin_offset: Some(0x70),
    main_arena_bins_offset: Some(0x70),
    main_arena_bin_count: Some(126),
};

const GLIBC_PROFILES: &[GlibcProfile] = &[GLIBC_X86_64_MODERN, GLIBC_2_35_X86_64];

pub fn available_glibc_profiles() -> &'static [GlibcProfile] {
    GLIBC_PROFILES
}

pub fn glibc_profile_by_name(name: &str) -> Option<GlibcProfile> {
    available_glibc_profiles()
        .iter()
        .copied()
        .find(|profile| profile.name == name)
}

pub fn suggest_glibc_profile_for_version(version: &str) -> Option<GlibcProfile> {
    profile_for_detected_glibc_version(version).and_then(glibc_profile_by_name)
}

pub fn profile_version(profile_name: &str) -> Option<&'static str> {
    match profile_name {
        "glibc-2.35-x86_64" => Some("2.35"),
        _ => None,
    }
}

pub fn profile_for_detected_glibc_version(version: &str) -> Option<&'static str> {
    match version.trim() {
        "2.35" => Some("glibc-2.35-x86_64"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlibcProfileConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlibcProfileSelection {
    pub requested: String,
    pub selected: String,
    pub detected_version: Option<String>,
    pub detected_libc_path: Option<String>,
    pub supplied_libc_path: Option<String>,
    pub confidence: GlibcProfileConfidence,
    pub reason: String,
    pub warnings: Vec<String>,
}

pub fn select_glibc_profile(
    requested: &str,
    detected_version: Option<&str>,
    detected_libc_path: Option<&Path>,
    supplied_libc_path: Option<&Path>,
) -> Result<(GlibcProfile, GlibcProfileSelection)> {
    let requested = requested.trim();
    let detected_version = detected_version
        .map(str::trim)
        .filter(|version| !version.is_empty());
    let detected_libc_path = detected_libc_path.map(|path| path.display().to_string());
    let supplied_libc_path = supplied_libc_path.map(|path| path.display().to_string());

    if requested == "auto" {
        if let Some(version) = detected_version {
            if let Some(profile_name) = profile_for_detected_glibc_version(version) {
                let profile = glibc_profile_by_name(profile_name).expect("known profile exists");
                return Ok((
                    profile,
                    GlibcProfileSelection {
                        requested: requested.to_string(),
                        selected: profile.name.to_string(),
                        detected_version: Some(version.to_string()),
                        detected_libc_path,
                        supplied_libc_path,
                        confidence: GlibcProfileConfidence::High,
                        reason: format!("detected glibc {version} maps to {}", profile.name),
                        warnings: Vec::new(),
                    },
                ));
            }
        }

        let mut warnings = Vec::new();
        let reason = match detected_version {
            Some(version) => {
                warnings.push(format!(
                    "no exact glibc profile for detected version {version}; falling back to {}",
                    GLIBC_X86_64_MODERN.name
                ));
                format!(
                    "detected glibc {version} has no exact profile; using generic modern profile"
                )
            }
            None => {
                warnings.push(format!(
                    "glibc version unavailable; falling back to {}",
                    GLIBC_X86_64_MODERN.name
                ));
                "glibc version unavailable; using generic modern profile".to_string()
            }
        };
        return Ok((
            GLIBC_X86_64_MODERN,
            GlibcProfileSelection {
                requested: requested.to_string(),
                selected: GLIBC_X86_64_MODERN.name.to_string(),
                detected_version: detected_version.map(str::to_string),
                detected_libc_path,
                supplied_libc_path,
                confidence: GlibcProfileConfidence::Low,
                reason,
                warnings,
            },
        ));
    }

    let Some(profile) = glibc_profile_by_name(requested) else {
        bail!(
            "unknown glibc profile `{requested}`\n\navailable profiles:\n{}",
            available_glibc_profiles()
                .iter()
                .map(|profile| format!("  {}", profile.name))
                .collect::<Vec<_>>()
                .join("\n")
        );
    };

    let expected_version = profile_version(profile.name);
    let (confidence, reason, warnings) = match (expected_version, detected_version) {
        (Some(expected), Some(detected)) if expected == detected => (
            GlibcProfileConfidence::High,
            format!("requested profile matches detected glibc {detected}"),
            Vec::new(),
        ),
        (Some(expected), Some(detected)) => (
            GlibcProfileConfidence::Low,
            format!("requested profile expects glibc {expected}, detected {detected}"),
            vec![format!(
                "requested profile {} expects glibc {expected}, but detected {detected}",
                profile.name
            )],
        ),
        (_, None) => (
            GlibcProfileConfidence::Medium,
            "glibc version unavailable; using requested profile".to_string(),
            Vec::new(),
        ),
        (None, Some(detected)) => (
            GlibcProfileConfidence::Medium,
            format!("requested profile has no exact version mapping; detected glibc {detected}"),
            Vec::new(),
        ),
    };

    Ok((
        profile,
        GlibcProfileSelection {
            requested: requested.to_string(),
            selected: profile.name.to_string(),
            detected_version: detected_version.map(str::to_string),
            detected_libc_path,
            supplied_libc_path,
            confidence,
            reason,
            warnings,
        },
    ))
}

impl GlibcProfile {
    pub fn size_mask(&self) -> u64 {
        !(self.malloc_alignment - 1)
    }

    pub fn normalize_chunk_size(&self, size_raw: u64) -> u64 {
        size_raw & self.size_mask()
    }

    pub fn is_aligned_chunk_size(&self, size: u64) -> bool {
        size % self.malloc_alignment == 0
    }

    pub fn tcache_chunk_size_for_index(&self, index: usize) -> u64 {
        self.min_chunk_size + index as u64 * self.malloc_alignment
    }

    pub fn fastbin_chunk_size_for_index(&self, index: usize) -> u64 {
        self.min_chunk_size + index as u64 * self.malloc_alignment
    }
}

#[derive(Debug, Clone)]
pub struct GlibcChunkHeader {
    pub chunk_addr: u64,
    pub user_addr: u64,
    pub prev_size: u64,
    pub size_raw: u64,
    pub size: u64,
    pub flags: ChunkFlags,
}

#[derive(Debug, Clone)]
pub struct ChunkFlags {
    pub prev_inuse: bool,
    pub is_mmapped: bool,
    pub non_main_arena: bool,
}

#[derive(Debug, Clone)]
pub struct GlibcHeapSnapshot {
    pub heap_start: u64,
    pub heap_end: u64,
    pub chunks: Vec<GlibcChunkHeader>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcacheEntryCandidate {
    pub storage_addr: u64,
    pub encoded_next: u64,
    pub decoded_next: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainArenaCandidate {
    pub libc_path: String,
    pub symbol_name: String,
    pub runtime_addr: u64,
    pub source: MainArenaSource,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainArenaSource {
    LibcSymbol,
    UserOffset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainArenaRoleHint {
    CandidateTop,
    HeapPointer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainArenaPointerCandidate {
    pub field_offset: u64,
    pub value: u64,
    pub points_into_heap: bool,
    pub matches_heap_chunk: bool,
    pub matched_chunk_size: Option<u64>,
    pub role_hint: MainArenaRoleHint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainArenaExperiment {
    pub arena_addr: u64,
    pub candidates: Vec<MainArenaPointerCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastbinExperimentRole {
    FastbinCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastbinPointerCandidate {
    pub field_offset: u64,
    pub value: u64,
    pub possible_chunk_size: Option<u64>,
    pub points_into_heap: bool,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
    pub role: FastbinExperimentRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastbinExperiment {
    pub arena_addr: u64,
    pub candidates: Vec<FastbinPointerCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsortedExperimentRole {
    UnsortedCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsortedBinPointerCandidate {
    pub field_offset: u64,
    pub fd: u64,
    pub bk: u64,
    pub fd_points_into_heap: bool,
    pub bk_points_into_heap: bool,
    pub fd_matches_heap_chunk: bool,
    pub bk_matches_heap_chunk: bool,
    pub fd_known_freed: Option<bool>,
    pub bk_known_freed: Option<bool>,
    pub role: UnsortedExperimentRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsortedBinExperiment {
    pub arena_addr: u64,
    pub candidates: Vec<UnsortedBinPointerCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinExperimentRole {
    BinSentinelCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinPointerCandidate {
    pub field_offset: u64,
    pub fd: u64,
    pub bk: u64,
    pub fd_points_into_heap: bool,
    pub bk_points_into_heap: bool,
    pub fd_points_into_arena: bool,
    pub bk_points_into_arena: bool,
    pub fd_matches_heap_chunk: bool,
    pub bk_matches_heap_chunk: bool,
    pub fd_known_freed: Option<bool>,
    pub bk_known_freed: Option<bool>,
    pub role: BinExperimentRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinExperiment {
    pub arena_addr: u64,
    pub candidates: Vec<BinPointerCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegularBinRole {
    Unsorted,
    Smallbin,
    Largebin,
}

pub fn regular_bin_role_str(role: RegularBinRole) -> &'static str {
    match role {
        RegularBinRole::Unsorted => "unsorted",
        RegularBinRole::Smallbin => "smallbin",
        RegularBinRole::Largebin => "largebin",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularBinHead {
    pub index: usize,
    pub glibc_bin_index: usize,
    pub role: RegularBinRole,
    pub chunk_size: Option<u64>,
    pub field_offset: u64,
    pub fd: u64,
    pub bk: u64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularBinsSnapshot {
    pub arena_addr: u64,
    pub bins_offset: u64,
    pub heads: Vec<RegularBinHead>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallbinNode {
    pub chunk_addr: u64,
    pub user_addr: u64,
    pub fd: u64,
    pub bk: u64,
    pub chunk_size: Option<u64>,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
    pub fd_points_to_sentinel: bool,
    pub bk_points_to_sentinel: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallbinChain {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub expected_chunk_size: u64,
    pub sentinel_addr: u64,
    pub head: u64,
    pub tail: u64,
    pub nodes: Vec<SmallbinNode>,
    pub empty: bool,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
    pub cycle_detected: bool,
    pub fd_bk_consistent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmallbinMembership {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub chunk_size: u64,
    pub node_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallbinsSnapshot {
    pub arena_addr: u64,
    pub bins_offset: u64,
    pub chains: Vec<SmallbinChain>,
}

impl SmallbinsSnapshot {
    pub fn membership_for_chunk_addr(&self, chunk_addr: u64) -> Option<SmallbinMembership> {
        self.chains.iter().find_map(|chain| {
            chain
                .nodes
                .iter()
                .position(|node| node.chunk_addr == chunk_addr)
                .map(|node_index| SmallbinMembership {
                    regular_index: chain.regular_index,
                    glibc_bin_index: chain.glibc_bin_index,
                    chunk_size: chain.expected_chunk_size,
                    node_index,
                })
        })
    }

    pub fn membership_for_user_addr(
        &self,
        user_addr: u64,
        profile: GlibcProfile,
    ) -> Option<SmallbinMembership> {
        user_addr
            .checked_sub(profile.chunk_header_size)
            .and_then(|chunk_addr| self.membership_for_chunk_addr(chunk_addr))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargebinNode {
    pub chunk_addr: u64,
    pub user_addr: u64,
    pub fd: u64,
    pub bk: u64,
    pub fd_nextsize: u64,
    pub bk_nextsize: u64,
    pub chunk_size: Option<u64>,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
    pub fd_points_to_sentinel: bool,
    pub bk_points_to_sentinel: bool,
    pub fd_nextsize_points_into_heap: bool,
    pub bk_nextsize_points_into_heap: bool,
    pub fd_nextsize_points_into_arena: bool,
    pub bk_nextsize_points_into_arena: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargebinChain {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub sentinel_addr: u64,
    pub head: u64,
    pub tail: u64,
    pub nodes: Vec<LargebinNode>,
    pub empty: bool,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
    pub cycle_detected: bool,
    pub fd_bk_consistent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LargebinMembership {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub chunk_size: Option<u64>,
    pub node_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargebinsSnapshot {
    pub arena_addr: u64,
    pub bins_offset: u64,
    pub chains: Vec<LargebinChain>,
}

impl LargebinsSnapshot {
    pub fn membership_for_chunk_addr(&self, chunk_addr: u64) -> Option<LargebinMembership> {
        self.chains.iter().find_map(|chain| {
            chain
                .nodes
                .iter()
                .position(|node| node.chunk_addr == chunk_addr)
                .map(|node_index| LargebinMembership {
                    regular_index: chain.regular_index,
                    glibc_bin_index: chain.glibc_bin_index,
                    chunk_size: chain.nodes[node_index].chunk_size,
                    node_index,
                })
        })
    }

    pub fn membership_for_user_addr(
        &self,
        user_addr: u64,
        profile: GlibcProfile,
    ) -> Option<LargebinMembership> {
        user_addr
            .checked_sub(profile.chunk_header_size)
            .and_then(|chunk_addr| self.membership_for_chunk_addr(chunk_addr))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmallbinValidationValue {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmallbinValidationStatus {
    Plausible,
    Incomplete,
    Suspicious,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallbinBinValidation {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub expected_chunk_size: u64,
    pub head: u64,
    pub head_in_heap: SmallbinValidationValue,
    pub nodes_same_size: SmallbinValidationValue,
    pub fd_bk_consistent: SmallbinValidationValue,
    pub nodes_known_freed: SmallbinValidationValue,
    pub chain_complete: SmallbinValidationValue,
    pub status: SmallbinValidationStatus,
}

pub fn regular_bin_metadata(
    regular_index: usize,
    profile: GlibcProfile,
) -> (usize, RegularBinRole, Option<u64>) {
    let glibc_bin_index = regular_index + 1;
    let role = if regular_index == 0 {
        RegularBinRole::Unsorted
    } else if (2..=63).contains(&glibc_bin_index) {
        RegularBinRole::Smallbin
    } else {
        RegularBinRole::Largebin
    };
    let chunk_size = match role {
        RegularBinRole::Smallbin => Some(glibc_bin_index as u64 * profile.malloc_alignment),
        RegularBinRole::Unsorted | RegularBinRole::Largebin => None,
    };

    (glibc_bin_index, role, chunk_size)
}

pub fn validate_smallbins_snapshot(snapshot: &SmallbinsSnapshot) -> Vec<SmallbinBinValidation> {
    snapshot
        .chains
        .iter()
        .filter(|chain| !chain.empty)
        .map(validate_smallbin_chain)
        .collect()
}

fn validate_smallbin_chain(chain: &SmallbinChain) -> SmallbinBinValidation {
    let head_in_heap = if chain
        .nodes
        .first()
        .is_some_and(|node| node.chunk_addr == chain.head)
    {
        SmallbinValidationValue::Yes
    } else if chain.stopped_on_unknown_next || chain.truncated || chain.cycle_detected {
        SmallbinValidationValue::Unknown
    } else {
        SmallbinValidationValue::No
    };
    let nodes_same_size = validate_smallbin_nodes_same_size(chain);
    let fd_bk_consistent = if chain.fd_bk_consistent {
        SmallbinValidationValue::Yes
    } else if chain.truncated || chain.stopped_on_unknown_next {
        SmallbinValidationValue::Unknown
    } else {
        SmallbinValidationValue::No
    };
    let nodes_known_freed = validate_smallbin_nodes_known_freed(chain);
    let chain_complete = if chain.cycle_detected {
        SmallbinValidationValue::No
    } else if chain.truncated || chain.stopped_on_unknown_next {
        SmallbinValidationValue::Unknown
    } else {
        SmallbinValidationValue::Yes
    };
    let status = smallbin_validation_status(&[
        head_in_heap,
        nodes_same_size,
        fd_bk_consistent,
        nodes_known_freed,
        chain_complete,
    ]);

    SmallbinBinValidation {
        regular_index: chain.regular_index,
        glibc_bin_index: chain.glibc_bin_index,
        expected_chunk_size: chain.expected_chunk_size,
        head: chain.head,
        head_in_heap,
        nodes_same_size,
        fd_bk_consistent,
        nodes_known_freed,
        chain_complete,
        status,
    }
}

fn validate_smallbin_nodes_same_size(chain: &SmallbinChain) -> SmallbinValidationValue {
    for node in &chain.nodes {
        match node.chunk_size {
            Some(size) if size == chain.expected_chunk_size => {}
            Some(_) => return SmallbinValidationValue::No,
            None => return SmallbinValidationValue::Unknown,
        }
    }

    SmallbinValidationValue::Yes
}

fn validate_smallbin_nodes_known_freed(chain: &SmallbinChain) -> SmallbinValidationValue {
    for node in &chain.nodes {
        match node.known_freed {
            Some(true) => {}
            Some(false) => return SmallbinValidationValue::No,
            None => return SmallbinValidationValue::Unknown,
        }
    }

    SmallbinValidationValue::Yes
}

fn smallbin_validation_status(values: &[SmallbinValidationValue]) -> SmallbinValidationStatus {
    if values.contains(&SmallbinValidationValue::No) {
        SmallbinValidationStatus::Suspicious
    } else if values.contains(&SmallbinValidationValue::Unknown) {
        SmallbinValidationStatus::Incomplete
    } else {
        SmallbinValidationStatus::Plausible
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LargebinValidationValue {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LargebinValidationStatus {
    Plausible,
    Incomplete,
    Suspicious,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargebinBinValidation {
    pub regular_index: usize,
    pub glibc_bin_index: usize,
    pub head: u64,
    pub head_in_heap: LargebinValidationValue,
    pub fd_bk_consistent: LargebinValidationValue,
    pub nodes_known_freed: LargebinValidationValue,
    pub chain_complete: LargebinValidationValue,
    pub status: LargebinValidationStatus,
}

pub fn validate_largebins_snapshot(snapshot: &LargebinsSnapshot) -> Vec<LargebinBinValidation> {
    snapshot
        .chains
        .iter()
        .filter(|chain| !chain.empty)
        .map(validate_largebin_chain)
        .collect()
}

fn validate_largebin_chain(chain: &LargebinChain) -> LargebinBinValidation {
    let head_in_heap = if chain
        .nodes
        .first()
        .is_some_and(|node| node.chunk_addr == chain.head)
    {
        LargebinValidationValue::Yes
    } else if chain.stopped_on_unknown_next || chain.truncated || chain.cycle_detected {
        LargebinValidationValue::Unknown
    } else {
        LargebinValidationValue::No
    };
    let fd_bk_consistent = if chain.fd_bk_consistent {
        LargebinValidationValue::Yes
    } else if chain.truncated || chain.stopped_on_unknown_next {
        LargebinValidationValue::Unknown
    } else {
        LargebinValidationValue::No
    };
    let nodes_known_freed = validate_largebin_nodes_known_freed(chain);
    let chain_complete = if chain.cycle_detected {
        LargebinValidationValue::No
    } else if chain.truncated || chain.stopped_on_unknown_next {
        LargebinValidationValue::Unknown
    } else {
        LargebinValidationValue::Yes
    };
    let status = largebin_validation_status(&[
        head_in_heap,
        fd_bk_consistent,
        nodes_known_freed,
        chain_complete,
    ]);

    LargebinBinValidation {
        regular_index: chain.regular_index,
        glibc_bin_index: chain.glibc_bin_index,
        head: chain.head,
        head_in_heap,
        fd_bk_consistent,
        nodes_known_freed,
        chain_complete,
        status,
    }
}

fn validate_largebin_nodes_known_freed(chain: &LargebinChain) -> LargebinValidationValue {
    for node in &chain.nodes {
        match node.known_freed {
            Some(true) => {}
            Some(false) => return LargebinValidationValue::No,
            None => return LargebinValidationValue::Unknown,
        }
    }

    LargebinValidationValue::Yes
}

fn largebin_validation_status(values: &[LargebinValidationValue]) -> LargebinValidationStatus {
    if values.contains(&LargebinValidationValue::No) {
        LargebinValidationStatus::Suspicious
    } else if values.contains(&LargebinValidationValue::Unknown) {
        LargebinValidationStatus::Incomplete
    } else {
        LargebinValidationStatus::Plausible
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsortedBinSnapshot {
    pub arena_addr: u64,
    pub field_offset: u64,
    pub fd: u64,
    pub bk: u64,
    pub fd_points_into_heap: bool,
    pub bk_points_into_heap: bool,
    pub fd_matches_heap_chunk: bool,
    pub bk_matches_heap_chunk: bool,
    pub fd_known_freed: Option<bool>,
    pub bk_known_freed: Option<bool>,
    pub chain: Option<UnsortedBinChain>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsortedBinNode {
    pub chunk_addr: u64,
    pub user_addr: u64,
    pub fd: u64,
    pub bk: u64,
    pub chunk_size: Option<u64>,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
    pub fd_points_to_sentinel: bool,
    pub bk_points_to_sentinel: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsortedBinChain {
    pub sentinel_addr: u64,
    pub head: u64,
    pub tail: u64,
    pub nodes: Vec<UnsortedBinNode>,
    pub empty: bool,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
    pub cycle_detected: bool,
    pub fd_bk_consistent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsortedBinMembership {
    pub node_index: usize,
    pub chunk_size: Option<u64>,
}

impl UnsortedBinSnapshot {
    pub fn membership_for_chunk_addr(&self, chunk_addr: u64) -> Option<UnsortedBinMembership> {
        let chain = self.chain.as_ref()?;
        chain
            .nodes
            .iter()
            .position(|node| node.chunk_addr == chunk_addr)
            .map(|node_index| UnsortedBinMembership {
                node_index,
                chunk_size: chain.nodes[node_index].chunk_size,
            })
    }

    pub fn membership_for_user_addr(
        &self,
        user_addr: u64,
        profile: GlibcProfile,
    ) -> Option<UnsortedBinMembership> {
        user_addr
            .checked_sub(profile.chunk_header_size)
            .and_then(|chunk_addr| self.membership_for_chunk_addr(chunk_addr))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsortedBinValidationValue {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsortedBinValidationStatus {
    Plausible,
    Incomplete,
    Suspicious,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsortedBinValidation {
    pub head_in_heap: UnsortedBinValidationValue,
    pub fd_bk_consistent: UnsortedBinValidationValue,
    pub nodes_known_freed: UnsortedBinValidationValue,
    pub chain_complete: UnsortedBinValidationValue,
    pub status: UnsortedBinValidationStatus,
}

pub fn validate_unsorted_bin_snapshot(
    snapshot: &UnsortedBinSnapshot,
) -> Option<UnsortedBinValidation> {
    let chain = snapshot.chain.as_ref()?;
    let head_in_heap = if chain.empty || snapshot.fd_points_into_heap {
        UnsortedBinValidationValue::Yes
    } else {
        UnsortedBinValidationValue::No
    };
    let fd_bk_consistent = if chain.empty || chain.fd_bk_consistent {
        UnsortedBinValidationValue::Yes
    } else if chain.truncated || chain.stopped_on_unknown_next {
        UnsortedBinValidationValue::Unknown
    } else {
        UnsortedBinValidationValue::No
    };
    let nodes_known_freed = validate_unsorted_nodes_known_freed(chain);
    let chain_complete = if chain.cycle_detected {
        UnsortedBinValidationValue::No
    } else if chain.truncated || chain.stopped_on_unknown_next {
        UnsortedBinValidationValue::Unknown
    } else {
        UnsortedBinValidationValue::Yes
    };
    let status = unsorted_bin_validation_status(&[
        head_in_heap,
        fd_bk_consistent,
        nodes_known_freed,
        chain_complete,
    ]);

    Some(UnsortedBinValidation {
        head_in_heap,
        fd_bk_consistent,
        nodes_known_freed,
        chain_complete,
        status,
    })
}

fn validate_unsorted_nodes_known_freed(chain: &UnsortedBinChain) -> UnsortedBinValidationValue {
    if chain.empty {
        return UnsortedBinValidationValue::Unknown;
    }

    for node in &chain.nodes {
        match node.known_freed {
            Some(false) => return UnsortedBinValidationValue::No,
            Some(true) => {}
            None => return UnsortedBinValidationValue::Unknown,
        }
    }

    UnsortedBinValidationValue::Yes
}

fn unsorted_bin_validation_status(
    values: &[UnsortedBinValidationValue],
) -> UnsortedBinValidationStatus {
    if values.contains(&UnsortedBinValidationValue::No) {
        UnsortedBinValidationStatus::Suspicious
    } else if values.contains(&UnsortedBinValidationValue::Unknown) {
        UnsortedBinValidationStatus::Incomplete
    } else {
        UnsortedBinValidationStatus::Plausible
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastbinHead {
    pub index: usize,
    pub chunk_size: u64,
    pub field_offset: u64,
    pub head: u64,
    pub points_into_heap: bool,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastbinNode {
    pub chunk_addr: u64,
    pub user_addr: u64,
    pub encoded_next: u64,
    pub decoded_next: u64,
    pub chunk_size: Option<u64>,
    pub matches_heap_chunk: bool,
    pub known_freed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastbinChain {
    pub index: usize,
    pub chunk_size: u64,
    pub head: u64,
    pub nodes: Vec<FastbinNode>,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
    pub cycle_detected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastbinMembership {
    pub index: usize,
    pub chunk_size: u64,
    pub chain_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastbinsSnapshot {
    pub arena_addr: u64,
    pub heads: Vec<FastbinHead>,
    pub chains: Vec<FastbinChain>,
}

impl FastbinsSnapshot {
    pub fn membership_for_chunk_addr(&self, chunk_addr: u64) -> Option<FastbinMembership> {
        self.chains.iter().find_map(|chain| {
            chain
                .nodes
                .iter()
                .position(|node| node.chunk_addr == chunk_addr)
                .map(|chain_index| FastbinMembership {
                    index: chain.index,
                    chunk_size: chain.chunk_size,
                    chain_index,
                })
        })
    }

    pub fn membership_for_user_addr(
        &self,
        user_addr: u64,
        profile: GlibcProfile,
    ) -> Option<FastbinMembership> {
        user_addr
            .checked_sub(profile.chunk_header_size)
            .and_then(|chunk_addr| self.membership_for_chunk_addr(chunk_addr))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastbinValidationValue {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastbinValidationStatus {
    Plausible,
    Incomplete,
    Suspicious,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastbinBinValidation {
    pub index: usize,
    pub chunk_size: u64,
    pub head: u64,
    pub head_in_heap: FastbinValidationValue,
    pub nodes_same_size: FastbinValidationValue,
    pub nodes_known_freed: FastbinValidationValue,
    pub chain_complete: FastbinValidationValue,
    pub status: FastbinValidationStatus,
}

pub fn validate_fastbins_snapshot(snapshot: &FastbinsSnapshot) -> Vec<FastbinBinValidation> {
    snapshot
        .chains
        .iter()
        .filter(|chain| chain.head != 0)
        .map(|chain| {
            let head_in_heap = snapshot
                .heads
                .iter()
                .find(|head| head.index == chain.index)
                .map(|head| {
                    if head.points_into_heap {
                        FastbinValidationValue::Yes
                    } else if head.head != 0 {
                        FastbinValidationValue::No
                    } else {
                        FastbinValidationValue::Unknown
                    }
                })
                .unwrap_or(FastbinValidationValue::Unknown);
            let nodes_same_size = validate_fastbin_nodes_same_size(chain);
            let nodes_known_freed = validate_fastbin_nodes_known_freed(chain);
            let chain_complete = if chain.cycle_detected {
                FastbinValidationValue::No
            } else if chain.truncated || chain.stopped_on_unknown_next {
                FastbinValidationValue::Unknown
            } else {
                FastbinValidationValue::Yes
            };
            let status = fastbin_validation_status(&[
                head_in_heap,
                nodes_same_size,
                nodes_known_freed,
                chain_complete,
            ]);

            FastbinBinValidation {
                index: chain.index,
                chunk_size: chain.chunk_size,
                head: chain.head,
                head_in_heap,
                nodes_same_size,
                nodes_known_freed,
                chain_complete,
                status,
            }
        })
        .collect()
}

fn validate_fastbin_nodes_same_size(chain: &FastbinChain) -> FastbinValidationValue {
    let mut saw_known = false;
    for node in &chain.nodes {
        let Some(size) = node.chunk_size else {
            continue;
        };
        if size != chain.chunk_size {
            return FastbinValidationValue::No;
        }
        saw_known = true;
    }

    if saw_known {
        FastbinValidationValue::Yes
    } else {
        FastbinValidationValue::Unknown
    }
}

fn validate_fastbin_nodes_known_freed(chain: &FastbinChain) -> FastbinValidationValue {
    let mut saw_freed = false;
    for node in &chain.nodes {
        match node.known_freed {
            Some(false) => return FastbinValidationValue::No,
            Some(true) => saw_freed = true,
            None => return FastbinValidationValue::Unknown,
        }
    }

    if saw_freed {
        FastbinValidationValue::Yes
    } else {
        FastbinValidationValue::Unknown
    }
}

fn fastbin_validation_status(values: &[FastbinValidationValue]) -> FastbinValidationStatus {
    if values.contains(&FastbinValidationValue::No) {
        FastbinValidationStatus::Suspicious
    } else if values.contains(&FastbinValidationValue::Unknown) {
        FastbinValidationStatus::Incomplete
    } else {
        FastbinValidationStatus::Plausible
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainArenaTopStatus {
    MatchesWalkedChunk,
    PointsIntoHeap,
    OutsideHeap,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainArenaViewStatus {
    Validated,
    PointsIntoHeap,
    OutsideHeap,
    Unavailable,
}

pub fn main_arena_view_status_from_top_status(status: MainArenaTopStatus) -> MainArenaViewStatus {
    match status {
        MainArenaTopStatus::MatchesWalkedChunk => MainArenaViewStatus::Validated,
        MainArenaTopStatus::PointsIntoHeap => MainArenaViewStatus::PointsIntoHeap,
        MainArenaTopStatus::OutsideHeap => MainArenaViewStatus::OutsideHeap,
        MainArenaTopStatus::Unavailable => MainArenaViewStatus::Unavailable,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainArenaFieldSource {
    UserOffset,
    GlibcProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainArenaTopCandidate {
    pub arena_addr: u64,
    pub field_offset: u64,
    pub top_addr: u64,
    pub points_into_heap: bool,
    pub matches_heap_chunk: bool,
    pub chunk_size: Option<u64>,
    pub status: MainArenaTopStatus,
    pub source: MainArenaFieldSource,
    pub profile_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcacheStructCandidate {
    pub chunk_addr: u64,
    pub user_addr: u64,
    pub size: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcacheBinSnapshot {
    pub index: usize,
    pub chunk_size: u64,
    pub count: u16,
    pub head: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcacheSnapshotCandidate {
    pub struct_user_addr: u64,
    pub bins: Vec<TcacheBinSnapshot>,
}

pub fn decode_safe_linked_ptr(encoded: u64, storage_addr: u64) -> u64 {
    encoded ^ (storage_addr >> 12)
}

pub fn tcache_chunk_size_for_index(index: usize) -> u64 {
    GLIBC_X86_64_MODERN.tcache_chunk_size_for_index(index)
}

pub fn find_tcache_struct_candidate(
    snapshot: &GlibcHeapSnapshot,
    observed_user_ptrs: &HashSet<u64>,
) -> Option<TcacheStructCandidate> {
    find_tcache_struct_candidate_with_profile(snapshot, observed_user_ptrs, GLIBC_X86_64_MODERN)
}

pub fn find_tcache_struct_candidate_with_profile(
    snapshot: &GlibcHeapSnapshot,
    observed_user_ptrs: &HashSet<u64>,
    profile: GlibcProfile,
) -> Option<TcacheStructCandidate> {
    snapshot
        .chunks
        .iter()
        .take(profile.tcache_struct_candidate_scan_chunks)
        .filter(|chunk| !observed_user_ptrs.contains(&chunk.user_addr))
        .find(|chunk| {
            (profile.tcache_struct_min_chunk_size..=profile.tcache_struct_max_chunk_size)
                .contains(&chunk.size)
        })
        .map(|chunk| TcacheStructCandidate {
            chunk_addr: chunk.chunk_addr,
            user_addr: chunk.user_addr,
            size: chunk.size,
            reason: "early heap chunk with plausible tcache_perthread_struct size".to_string(),
        })
}

impl ChunkFlags {
    pub fn from_size_raw(size_raw: u64) -> Self {
        Self {
            prev_inuse: size_raw & 0x1 != 0,
            is_mmapped: size_raw & 0x2 != 0,
            non_main_arena: size_raw & 0x4 != 0,
        }
    }

    pub fn labels(&self) -> Vec<&'static str> {
        let mut labels = Vec::new();
        if self.prev_inuse {
            labels.push("PREV_INUSE");
        }
        if self.is_mmapped {
            labels.push("IS_MMAPPED");
        }
        if self.non_main_arena {
            labels.push("NON_MAIN_ARENA");
        }
        labels
    }
}

impl GlibcChunkHeader {
    pub fn from_chunk_parts(chunk_addr: u64, prev_size: u64, size_raw: u64) -> Self {
        Self::from_chunk_parts_with_profile(chunk_addr, prev_size, size_raw, GLIBC_X86_64_MODERN)
    }

    pub fn from_chunk_parts_with_profile(
        chunk_addr: u64,
        prev_size: u64,
        size_raw: u64,
        profile: GlibcProfile,
    ) -> Self {
        let flags = ChunkFlags::from_size_raw(size_raw);
        let size = profile.normalize_chunk_size(size_raw);

        Self {
            chunk_addr,
            user_addr: chunk_addr + profile.chunk_header_size,
            prev_size,
            size_raw,
            size,
            flags,
        }
    }

    pub fn read_with(user_addr: u64, read_word: impl FnMut(u64) -> Result<u64>) -> Result<Self> {
        Self::read_with_profile(user_addr, GLIBC_X86_64_MODERN, read_word)
    }

    pub fn read_with_profile(
        user_addr: u64,
        profile: GlibcProfile,
        mut read_word: impl FnMut(u64) -> Result<u64>,
    ) -> Result<Self> {
        if user_addr == 0 {
            bail!("cannot read glibc chunk header for null user pointer");
        }
        if user_addr < profile.chunk_header_size {
            bail!("user pointer 0x{user_addr:x} is too small to contain a glibc chunk header");
        }

        let chunk_addr = user_addr - profile.chunk_header_size;
        let prev_size = read_word(chunk_addr)?;
        let size_raw = read_word(chunk_addr + profile.pointer_size)?;
        Ok(Self::from_chunk_parts_with_profile(
            chunk_addr, prev_size, size_raw, profile,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::Path;

    use super::{
        available_glibc_profiles, decode_safe_linked_ptr, find_tcache_struct_candidate,
        find_tcache_struct_candidate_with_profile, glibc_profile_by_name, select_glibc_profile,
        suggest_glibc_profile_for_version, tcache_chunk_size_for_index, validate_fastbins_snapshot,
        validate_largebins_snapshot, validate_smallbins_snapshot, validate_unsorted_bin_snapshot,
        ChunkFlags, FastbinChain, FastbinHead, FastbinNode, FastbinValidationStatus,
        FastbinValidationValue, FastbinsSnapshot, GlibcChunkHeader, GlibcHeapSnapshot,
        GlibcProfileConfidence, LargebinChain, LargebinNode, LargebinValidationStatus,
        LargebinValidationValue, LargebinsSnapshot, MainArenaTopStatus, MainArenaViewStatus,
        RegularBinRole, SmallbinChain, SmallbinNode, SmallbinValidationStatus,
        SmallbinValidationValue, SmallbinsSnapshot, TcacheBinSnapshot, TcacheSnapshotCandidate,
        TcacheStructCandidate, UnsortedBinChain, UnsortedBinNode, UnsortedBinSnapshot,
        UnsortedBinValidationStatus, UnsortedBinValidationValue, GLIBC_2_35_X86_64,
        GLIBC_X86_64_MODERN,
    };

    #[test]
    fn default_profile_fields_match_expected_values() {
        assert_eq!(GLIBC_X86_64_MODERN.name, "glibc-x86_64-modern");
        assert_eq!(GLIBC_X86_64_MODERN.pointer_size, 8);
        assert_eq!(GLIBC_X86_64_MODERN.malloc_alignment, 0x10);
        assert_eq!(GLIBC_X86_64_MODERN.chunk_header_size, 0x10);
        assert_eq!(GLIBC_X86_64_MODERN.min_chunk_size, 0x20);
        assert_eq!(GLIBC_X86_64_MODERN.tcache_bin_count, 64);
        assert_eq!(GLIBC_X86_64_MODERN.tcache_counts_offset, 0);
        assert_eq!(GLIBC_X86_64_MODERN.tcache_entries_offset, 0x80);
        assert_eq!(GLIBC_X86_64_MODERN.tcache_count_size, 2);
        assert_eq!(GLIBC_X86_64_MODERN.tcache_struct_min_chunk_size, 0x280);
        assert_eq!(GLIBC_X86_64_MODERN.tcache_struct_max_chunk_size, 0x2a0);
        assert_eq!(GLIBC_X86_64_MODERN.tcache_struct_candidate_scan_chunks, 8);
        assert_eq!(GLIBC_X86_64_MODERN.main_arena_top_offset, None);
        assert_eq!(GLIBC_X86_64_MODERN.main_arena_fastbins_offset, None);
        assert_eq!(GLIBC_X86_64_MODERN.main_arena_fastbin_count, None);
        assert_eq!(GLIBC_X86_64_MODERN.main_arena_unsorted_bin_offset, None);
        assert_eq!(GLIBC_X86_64_MODERN.main_arena_bins_offset, None);
        assert_eq!(GLIBC_X86_64_MODERN.main_arena_bin_count, None);
    }

    #[test]
    fn glibc_2_35_profile_fields_match_expected_values() {
        assert_eq!(GLIBC_2_35_X86_64.name, "glibc-2.35-x86_64");
        assert_eq!(GLIBC_2_35_X86_64.main_arena_top_offset, Some(0x60));
        assert_eq!(GLIBC_2_35_X86_64.main_arena_fastbins_offset, Some(0x10));
        assert_eq!(GLIBC_2_35_X86_64.main_arena_fastbin_count, Some(10));
        assert_eq!(GLIBC_2_35_X86_64.main_arena_unsorted_bin_offset, Some(0x70));
        assert_eq!(GLIBC_2_35_X86_64.main_arena_bins_offset, Some(0x70));
        assert_eq!(GLIBC_2_35_X86_64.main_arena_bin_count, Some(126));
    }

    #[test]
    fn regular_bin_role_renders_stable_string() {
        assert_eq!(
            super::regular_bin_role_str(RegularBinRole::Unsorted),
            "unsorted"
        );
        assert_eq!(
            super::regular_bin_role_str(RegularBinRole::Smallbin),
            "smallbin"
        );
        assert_eq!(
            super::regular_bin_role_str(RegularBinRole::Largebin),
            "largebin"
        );
    }

    #[test]
    fn regular_bin_metadata_classifies_glibc_bins_and_sizes() {
        assert_eq!(
            super::regular_bin_metadata(0, GLIBC_X86_64_MODERN),
            (1, RegularBinRole::Unsorted, None)
        );
        assert_eq!(
            super::regular_bin_metadata(1, GLIBC_X86_64_MODERN),
            (2, RegularBinRole::Smallbin, Some(0x20))
        );
        assert_eq!(
            super::regular_bin_metadata(62, GLIBC_X86_64_MODERN),
            (63, RegularBinRole::Smallbin, Some(0x3f0))
        );
        assert_eq!(
            super::regular_bin_metadata(63, GLIBC_X86_64_MODERN),
            (64, RegularBinRole::Largebin, None)
        );
    }

    #[test]
    fn available_profiles_include_default_and_version_specific_profiles() {
        let names: Vec<_> = available_glibc_profiles()
            .iter()
            .map(|profile| profile.name)
            .collect();

        assert!(names.contains(&GLIBC_X86_64_MODERN.name));
        assert!(names.contains(&GLIBC_2_35_X86_64.name));
    }

    #[test]
    fn finds_glibc_profile_by_exact_name() {
        assert_eq!(
            glibc_profile_by_name("glibc-2.35-x86_64"),
            Some(GLIBC_2_35_X86_64)
        );
    }

    #[test]
    fn unknown_glibc_profile_name_returns_none() {
        assert_eq!(glibc_profile_by_name("does-not-exist"), None);
    }

    #[test]
    fn suggests_glibc_2_35_profile_for_matching_version() {
        assert_eq!(
            suggest_glibc_profile_for_version("2.35"),
            Some(GLIBC_2_35_X86_64)
        );
    }

    #[test]
    fn unknown_glibc_version_has_no_suggested_profile() {
        assert_eq!(suggest_glibc_profile_for_version("2.39"), None);
    }

    #[test]
    fn glibc_profile_suggestion_tolerates_whitespace() {
        assert_eq!(
            suggest_glibc_profile_for_version(" 2.35\n"),
            Some(GLIBC_2_35_X86_64)
        );
    }

    #[test]
    fn auto_selects_glibc_2_35_with_high_confidence() {
        let (profile, selection) = select_glibc_profile(
            "auto",
            Some("2.35"),
            Some(Path::new("/lib/libc.so.6")),
            None,
        )
        .unwrap();

        assert_eq!(profile, GLIBC_2_35_X86_64);
        assert_eq!(selection.confidence, GlibcProfileConfidence::High);
        assert_eq!(selection.selected, "glibc-2.35-x86_64");
    }

    #[test]
    fn auto_selects_modern_for_unknown_version_with_low_confidence() {
        let (profile, selection) = select_glibc_profile("auto", Some("2.39"), None, None).unwrap();

        assert_eq!(profile, GLIBC_X86_64_MODERN);
        assert_eq!(selection.confidence, GlibcProfileConfidence::Low);
        assert!(!selection.warnings.is_empty());
    }

    #[test]
    fn exact_profile_matching_detected_version_is_high_confidence() {
        let (profile, selection) =
            select_glibc_profile("glibc-2.35-x86_64", Some("2.35"), None, None).unwrap();

        assert_eq!(profile, GLIBC_2_35_X86_64);
        assert_eq!(selection.confidence, GlibcProfileConfidence::High);
    }

    #[test]
    fn exact_profile_without_detected_version_is_medium_confidence() {
        let (_, selection) = select_glibc_profile("glibc-2.35-x86_64", None, None, None).unwrap();

        assert_eq!(selection.confidence, GlibcProfileConfidence::Medium);
    }

    #[test]
    fn exact_profile_conflicting_detected_version_is_low_confidence() {
        let (_, selection) =
            select_glibc_profile("glibc-2.35-x86_64", Some("2.39"), None, None).unwrap();

        assert_eq!(selection.confidence, GlibcProfileConfidence::Low);
        assert!(!selection.warnings.is_empty());
    }

    #[test]
    fn unknown_requested_profile_errors() {
        let error = select_glibc_profile("does-not-exist", Some("2.35"), None, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown glibc profile"));
    }

    #[test]
    fn maps_main_arena_top_status_to_view_status() {
        assert_eq!(
            super::main_arena_view_status_from_top_status(MainArenaTopStatus::MatchesWalkedChunk),
            MainArenaViewStatus::Validated
        );
        assert_eq!(
            super::main_arena_view_status_from_top_status(MainArenaTopStatus::PointsIntoHeap),
            MainArenaViewStatus::PointsIntoHeap
        );
        assert_eq!(
            super::main_arena_view_status_from_top_status(MainArenaTopStatus::OutsideHeap),
            MainArenaViewStatus::OutsideHeap
        );
        assert_eq!(
            super::main_arena_view_status_from_top_status(MainArenaTopStatus::Unavailable),
            MainArenaViewStatus::Unavailable
        );
    }

    #[test]
    fn profile_normalizes_chunk_sizes() {
        assert_eq!(GLIBC_X86_64_MODERN.normalize_chunk_size(0x31), 0x30);
        assert_eq!(GLIBC_X86_64_MODERN.normalize_chunk_size(0x41), 0x40);
    }

    #[test]
    fn profile_computes_tcache_chunk_sizes() {
        assert_eq!(GLIBC_X86_64_MODERN.tcache_chunk_size_for_index(0), 0x20);
        assert_eq!(GLIBC_X86_64_MODERN.tcache_chunk_size_for_index(1), 0x30);
    }

    #[test]
    fn profile_computes_fastbin_chunk_sizes() {
        assert_eq!(GLIBC_X86_64_MODERN.fastbin_chunk_size_for_index(0), 0x20);
        assert_eq!(GLIBC_X86_64_MODERN.fastbin_chunk_size_for_index(1), 0x30);
    }

    #[test]
    fn fastbin_membership_for_chunk_addr_finds_node_and_chain_index() {
        let snapshot = fastbins_snapshot_with_chain(vec![
            fastbin_node(0x2000, Some(0x30), Some(true)),
            fastbin_node(0x2030, Some(0x30), Some(true)),
        ]);

        let membership = snapshot.membership_for_chunk_addr(0x2030).unwrap();

        assert_eq!(membership.index, 1);
        assert_eq!(membership.chunk_size, 0x30);
        assert_eq!(membership.chain_index, 1);
    }

    #[test]
    fn fastbin_membership_for_user_addr_handles_underflow_and_conversion() {
        let snapshot =
            fastbins_snapshot_with_chain(vec![fastbin_node(0x2000, Some(0x30), Some(true))]);

        assert_eq!(
            snapshot.membership_for_user_addr(0x2010, GLIBC_X86_64_MODERN),
            Some(super::FastbinMembership {
                index: 1,
                chunk_size: 0x30,
                chain_index: 0
            })
        );
        assert_eq!(
            snapshot.membership_for_user_addr(0x8, GLIBC_X86_64_MODERN),
            None
        );
    }

    fn unsorted_snapshot_with_chain(chain: UnsortedBinChain) -> UnsortedBinSnapshot {
        UnsortedBinSnapshot {
            arena_addr: 0x7000,
            field_offset: 0x70,
            fd: chain.head,
            bk: chain.tail,
            fd_points_into_heap: chain.empty || (0x1000 <= chain.head && chain.head < 0x4000),
            bk_points_into_heap: chain.empty || (0x1000 <= chain.tail && chain.tail < 0x4000),
            fd_matches_heap_chunk: false,
            bk_matches_heap_chunk: false,
            fd_known_freed: None,
            bk_known_freed: None,
            chain: Some(chain),
        }
    }

    fn unsorted_node(
        chunk_addr: u64,
        fd: u64,
        bk: u64,
        known_freed: Option<bool>,
    ) -> UnsortedBinNode {
        UnsortedBinNode {
            chunk_addr,
            user_addr: chunk_addr + 0x10,
            fd,
            bk,
            chunk_size: Some(0x510),
            matches_heap_chunk: true,
            known_freed,
            fd_points_to_sentinel: fd == 0x7070,
            bk_points_to_sentinel: bk == 0x7070,
        }
    }

    #[test]
    fn unsorted_empty_chain_validation_is_incomplete() {
        let snapshot = unsorted_snapshot_with_chain(UnsortedBinChain {
            sentinel_addr: 0x7070,
            head: 0x7070,
            tail: 0x7070,
            nodes: Vec::new(),
            empty: true,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        });

        let validation = validate_unsorted_bin_snapshot(&snapshot).unwrap();

        assert_eq!(validation.head_in_heap, UnsortedBinValidationValue::Yes);
        assert_eq!(validation.fd_bk_consistent, UnsortedBinValidationValue::Yes);
        assert_eq!(
            validation.nodes_known_freed,
            UnsortedBinValidationValue::Unknown
        );
        assert_eq!(validation.chain_complete, UnsortedBinValidationValue::Yes);
        assert_eq!(validation.status, UnsortedBinValidationStatus::Incomplete);
    }

    #[test]
    fn unsorted_one_node_chain_validation_is_plausible() {
        let snapshot = unsorted_snapshot_with_chain(UnsortedBinChain {
            sentinel_addr: 0x7070,
            head: 0x2000,
            tail: 0x2000,
            nodes: vec![unsorted_node(0x2000, 0x7070, 0x7070, Some(true))],
            empty: false,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        });

        let validation = validate_unsorted_bin_snapshot(&snapshot).unwrap();

        assert_eq!(validation.status, UnsortedBinValidationStatus::Plausible);
    }

    #[test]
    fn unsorted_fd_bk_mismatch_validation_is_suspicious() {
        let snapshot = unsorted_snapshot_with_chain(UnsortedBinChain {
            sentinel_addr: 0x7070,
            head: 0x2000,
            tail: 0x2000,
            nodes: vec![unsorted_node(0x2000, 0x7070, 0x3000, Some(true))],
            empty: false,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: false,
        });

        let validation = validate_unsorted_bin_snapshot(&snapshot).unwrap();

        assert_eq!(validation.fd_bk_consistent, UnsortedBinValidationValue::No);
        assert_eq!(validation.status, UnsortedBinValidationStatus::Suspicious);
    }

    #[test]
    fn unsorted_known_allocated_node_validation_is_suspicious() {
        let snapshot = unsorted_snapshot_with_chain(UnsortedBinChain {
            sentinel_addr: 0x7070,
            head: 0x2000,
            tail: 0x2000,
            nodes: vec![unsorted_node(0x2000, 0x7070, 0x7070, Some(false))],
            empty: false,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        });

        let validation = validate_unsorted_bin_snapshot(&snapshot).unwrap();

        assert_eq!(validation.nodes_known_freed, UnsortedBinValidationValue::No);
        assert_eq!(validation.status, UnsortedBinValidationStatus::Suspicious);
    }

    #[test]
    fn unsorted_truncated_chain_validation_is_incomplete() {
        let snapshot = unsorted_snapshot_with_chain(UnsortedBinChain {
            sentinel_addr: 0x7070,
            head: 0x2000,
            tail: 0x2000,
            nodes: vec![unsorted_node(0x2000, 0x3000, 0x7070, Some(true))],
            empty: false,
            truncated: true,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: false,
        });

        let validation = validate_unsorted_bin_snapshot(&snapshot).unwrap();

        assert_eq!(
            validation.chain_complete,
            UnsortedBinValidationValue::Unknown
        );
        assert_eq!(validation.status, UnsortedBinValidationStatus::Incomplete);
    }

    #[test]
    fn unsorted_membership_returns_node_index() {
        let snapshot = unsorted_snapshot_with_chain(UnsortedBinChain {
            sentinel_addr: 0x7070,
            head: 0x2000,
            tail: 0x3000,
            nodes: vec![
                unsorted_node(0x2000, 0x3000, 0x7070, Some(true)),
                unsorted_node(0x3000, 0x7070, 0x2000, Some(true)),
            ],
            empty: false,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        });

        let membership = snapshot
            .membership_for_user_addr(0x3010, GLIBC_X86_64_MODERN)
            .unwrap();

        assert_eq!(membership.node_index, 1);
        assert_eq!(membership.chunk_size, Some(0x510));
    }

    fn smallbins_snapshot_with_chain(chain: SmallbinChain) -> SmallbinsSnapshot {
        SmallbinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![chain],
        }
    }

    fn smallbin_node(
        chunk_addr: u64,
        fd: u64,
        bk: u64,
        chunk_size: Option<u64>,
        known_freed: Option<bool>,
    ) -> SmallbinNode {
        SmallbinNode {
            chunk_addr,
            user_addr: chunk_addr + 0x10,
            fd,
            bk,
            chunk_size,
            matches_heap_chunk: chunk_size.is_some(),
            known_freed,
            fd_points_to_sentinel: fd == 0x7080,
            bk_points_to_sentinel: bk == 0x7080,
        }
    }

    fn one_node_smallbin_chain(
        chunk_size: Option<u64>,
        known_freed: Option<bool>,
    ) -> SmallbinChain {
        SmallbinChain {
            regular_index: 1,
            glibc_bin_index: 2,
            expected_chunk_size: 0x20,
            sentinel_addr: 0x7080,
            head: 0x2000,
            tail: 0x2000,
            nodes: vec![smallbin_node(
                0x2000,
                0x7080,
                0x7080,
                chunk_size,
                known_freed,
            )],
            empty: false,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        }
    }

    fn largebins_snapshot_with_chain(chain: LargebinChain) -> LargebinsSnapshot {
        LargebinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![chain],
        }
    }

    fn largebin_node(
        chunk_addr: u64,
        fd: u64,
        bk: u64,
        fd_nextsize: u64,
        bk_nextsize: u64,
        known_freed: Option<bool>,
    ) -> LargebinNode {
        LargebinNode {
            chunk_addr,
            user_addr: chunk_addr + 0x10,
            fd,
            bk,
            fd_nextsize,
            bk_nextsize,
            chunk_size: Some(0x510),
            matches_heap_chunk: true,
            known_freed,
            fd_points_to_sentinel: fd == 0x7080,
            bk_points_to_sentinel: bk == 0x7080,
            fd_nextsize_points_into_heap: true,
            bk_nextsize_points_into_heap: true,
            fd_nextsize_points_into_arena: false,
            bk_nextsize_points_into_arena: false,
        }
    }

    fn one_node_largebin_chain(known_freed: Option<bool>) -> LargebinChain {
        LargebinChain {
            regular_index: 64,
            glibc_bin_index: 65,
            sentinel_addr: 0x7080,
            head: 0x2000,
            tail: 0x2000,
            nodes: vec![largebin_node(
                0x2000,
                0x7080,
                0x7080,
                0x4000,
                0x3000,
                known_freed,
            )],
            empty: false,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        }
    }

    #[test]
    fn empty_smallbin_chain_has_no_validation() {
        let snapshot = smallbins_snapshot_with_chain(SmallbinChain {
            regular_index: 1,
            glibc_bin_index: 2,
            expected_chunk_size: 0x20,
            sentinel_addr: 0x7080,
            head: 0x7080,
            tail: 0x7080,
            nodes: Vec::new(),
            empty: true,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        });

        assert!(validate_smallbins_snapshot(&snapshot).is_empty());
    }

    #[test]
    fn one_node_smallbin_chain_validation_is_plausible() {
        let snapshot =
            smallbins_snapshot_with_chain(one_node_smallbin_chain(Some(0x20), Some(true)));
        let validations = validate_smallbins_snapshot(&snapshot);

        assert_eq!(validations[0].head_in_heap, SmallbinValidationValue::Yes);
        assert_eq!(validations[0].nodes_same_size, SmallbinValidationValue::Yes);
        assert_eq!(
            validations[0].fd_bk_consistent,
            SmallbinValidationValue::Yes
        );
        assert_eq!(
            validations[0].nodes_known_freed,
            SmallbinValidationValue::Yes
        );
        assert_eq!(validations[0].chain_complete, SmallbinValidationValue::Yes);
        assert_eq!(validations[0].status, SmallbinValidationStatus::Plausible);
    }

    #[test]
    fn smallbin_validation_size_mismatch_is_suspicious() {
        let snapshot =
            smallbins_snapshot_with_chain(one_node_smallbin_chain(Some(0x30), Some(true)));
        let validations = validate_smallbins_snapshot(&snapshot);

        assert_eq!(validations[0].nodes_same_size, SmallbinValidationValue::No);
        assert_eq!(validations[0].status, SmallbinValidationStatus::Suspicious);
    }

    #[test]
    fn smallbin_validation_truncated_unknown_is_incomplete() {
        let mut chain = one_node_smallbin_chain(None, Some(true));
        chain.truncated = true;
        chain.fd_bk_consistent = false;
        let snapshot = smallbins_snapshot_with_chain(chain);
        let validations = validate_smallbins_snapshot(&snapshot);

        assert_eq!(
            validations[0].nodes_same_size,
            SmallbinValidationValue::Unknown
        );
        assert_eq!(
            validations[0].chain_complete,
            SmallbinValidationValue::Unknown
        );
        assert_eq!(validations[0].status, SmallbinValidationStatus::Incomplete);
    }

    #[test]
    fn smallbin_membership_returns_node_index() {
        let snapshot = smallbins_snapshot_with_chain(SmallbinChain {
            regular_index: 1,
            glibc_bin_index: 2,
            expected_chunk_size: 0x20,
            sentinel_addr: 0x7080,
            head: 0x2000,
            tail: 0x2020,
            nodes: vec![
                smallbin_node(0x2000, 0x2020, 0x7080, Some(0x20), Some(true)),
                smallbin_node(0x2020, 0x7080, 0x2000, Some(0x20), Some(true)),
            ],
            empty: false,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        });

        let membership = snapshot
            .membership_for_user_addr(0x2030, GLIBC_X86_64_MODERN)
            .unwrap();

        assert_eq!(membership.glibc_bin_index, 2);
        assert_eq!(membership.chunk_size, 0x20);
        assert_eq!(membership.node_index, 1);
    }

    #[test]
    fn one_node_largebin_chain_validation_ignores_nextsize_ordering() {
        let snapshot = largebins_snapshot_with_chain(one_node_largebin_chain(Some(true)));
        let validations = validate_largebins_snapshot(&snapshot);

        assert_eq!(validations[0].head_in_heap, LargebinValidationValue::Yes);
        assert_eq!(
            validations[0].fd_bk_consistent,
            LargebinValidationValue::Yes
        );
        assert_eq!(
            validations[0].nodes_known_freed,
            LargebinValidationValue::Yes
        );
        assert_eq!(validations[0].chain_complete, LargebinValidationValue::Yes);
        assert_eq!(validations[0].status, LargebinValidationStatus::Plausible);
    }

    #[test]
    fn largebin_membership_returns_node_index_and_observed_size() {
        let snapshot = largebins_snapshot_with_chain(LargebinChain {
            regular_index: 64,
            glibc_bin_index: 65,
            sentinel_addr: 0x7080,
            head: 0x2000,
            tail: 0x2020,
            nodes: vec![
                largebin_node(0x2000, 0x2020, 0x7080, 0x4000, 0x3000, Some(true)),
                largebin_node(0x2020, 0x7080, 0x2000, 0x2000, 0x4000, Some(true)),
            ],
            empty: false,
            truncated: false,
            stopped_on_unknown_next: false,
            cycle_detected: false,
            fd_bk_consistent: true,
        });

        let membership = snapshot
            .membership_for_user_addr(0x2030, GLIBC_X86_64_MODERN)
            .unwrap();

        assert_eq!(membership.glibc_bin_index, 65);
        assert_eq!(membership.chunk_size, Some(0x510));
        assert_eq!(membership.node_index, 1);
    }

    #[test]
    fn fastbin_validation_plausible_case() {
        let snapshot =
            fastbins_snapshot_with_chain(vec![fastbin_node(0x2000, Some(0x30), Some(true))]);

        let validations = validate_fastbins_snapshot(&snapshot);

        assert_eq!(validations[0].head_in_heap, FastbinValidationValue::Yes);
        assert_eq!(validations[0].nodes_same_size, FastbinValidationValue::Yes);
        assert_eq!(
            validations[0].nodes_known_freed,
            FastbinValidationValue::Yes
        );
        assert_eq!(validations[0].chain_complete, FastbinValidationValue::Yes);
        assert_eq!(validations[0].status, FastbinValidationStatus::Plausible);
    }

    #[test]
    fn fastbin_validation_size_mismatch_is_suspicious() {
        let snapshot =
            fastbins_snapshot_with_chain(vec![fastbin_node(0x2000, Some(0x40), Some(true))]);

        let validations = validate_fastbins_snapshot(&snapshot);

        assert_eq!(validations[0].nodes_same_size, FastbinValidationValue::No);
        assert_eq!(validations[0].status, FastbinValidationStatus::Suspicious);
    }

    #[test]
    fn fastbin_validation_known_allocated_node_is_suspicious() {
        let snapshot =
            fastbins_snapshot_with_chain(vec![fastbin_node(0x2000, Some(0x30), Some(false))]);

        let validations = validate_fastbins_snapshot(&snapshot);

        assert_eq!(validations[0].nodes_known_freed, FastbinValidationValue::No);
        assert_eq!(validations[0].status, FastbinValidationStatus::Suspicious);
    }

    #[test]
    fn fastbin_validation_truncated_chain_is_incomplete() {
        let mut snapshot =
            fastbins_snapshot_with_chain(vec![fastbin_node(0x2000, Some(0x30), Some(true))]);
        snapshot.chains[0].truncated = true;

        let validations = validate_fastbins_snapshot(&snapshot);

        assert_eq!(
            validations[0].chain_complete,
            FastbinValidationValue::Unknown
        );
        assert_eq!(validations[0].status, FastbinValidationStatus::Incomplete);
    }

    #[test]
    fn decodes_chunk_flags_from_size_raw() {
        let flags = ChunkFlags::from_size_raw(0x37);

        assert!(flags.prev_inuse);
        assert!(flags.is_mmapped);
        assert!(flags.non_main_arena);
    }

    #[test]
    fn from_chunk_parts_normalizes_size_and_user_address() {
        let header = GlibcChunkHeader::from_chunk_parts(0x1000, 0, 0x35);

        assert_eq!(header.chunk_addr, 0x1000);
        assert_eq!(header.user_addr, 0x1010);
        assert_eq!(header.size_raw, 0x35);
        assert_eq!(header.size, 0x30);
        assert!(header.flags.prev_inuse);
        assert!(!header.flags.is_mmapped);
        assert!(header.flags.non_main_arena);
    }

    #[test]
    fn decodes_null_safe_linked_value_to_storage_key() {
        let decoded = decode_safe_linked_ptr(0, 0x5555555592a0);

        assert_eq!(decoded, 0x555555559);
    }

    #[test]
    fn encoded_storage_key_decodes_to_zero() {
        let storage_addr = 0x5555555592a0;
        let encoded = storage_addr >> 12;

        assert_eq!(decode_safe_linked_ptr(encoded, storage_addr), 0);
    }

    #[test]
    fn safe_linked_decode_round_trips_with_xor_encoding() {
        let storage_addr = 0x5555555592a0;
        let ptr = 0x5555555592d0;
        let encoded = ptr ^ (storage_addr >> 12);

        assert_eq!(decode_safe_linked_ptr(encoded, storage_addr), ptr);
    }

    #[test]
    fn finds_tcache_struct_candidate_for_early_unobserved_plausible_size() {
        let snapshot = snapshot_with_sizes(&[0x290]);
        let observed = HashSet::new();

        assert_eq!(
            find_tcache_struct_candidate(&snapshot, &observed),
            Some(TcacheStructCandidate {
                chunk_addr: 0x1000,
                user_addr: 0x1010,
                size: 0x290,
                reason: "early heap chunk with plausible tcache_perthread_struct size".to_string(),
            })
        );
    }

    #[test]
    fn finds_tcache_struct_candidate_with_default_profile() {
        let snapshot = snapshot_with_sizes(&[0x290]);
        let observed = HashSet::new();

        assert_eq!(
            find_tcache_struct_candidate_with_profile(&snapshot, &observed, GLIBC_X86_64_MODERN),
            find_tcache_struct_candidate(&snapshot, &observed)
        );
    }

    #[test]
    fn does_not_find_tcache_struct_candidate_for_observed_chunk() {
        let snapshot = snapshot_with_sizes(&[0x290]);
        let observed = HashSet::from([0x1010]);

        assert_eq!(find_tcache_struct_candidate(&snapshot, &observed), None);
    }

    #[test]
    fn does_not_find_tcache_struct_candidate_outside_size_range() {
        let snapshot = snapshot_with_sizes(&[0x270, 0x2b0]);
        let observed = HashSet::new();

        assert_eq!(find_tcache_struct_candidate(&snapshot, &observed), None);
    }

    #[test]
    fn does_not_find_tcache_struct_candidate_after_first_eight_chunks() {
        let snapshot =
            snapshot_with_sizes(&[0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x290]);
        let observed = HashSet::new();

        assert_eq!(find_tcache_struct_candidate(&snapshot, &observed), None);
    }

    #[test]
    fn computes_simplified_tcache_chunk_sizes() {
        assert_eq!(tcache_chunk_size_for_index(0), 0x20);
        assert_eq!(tcache_chunk_size_for_index(1), 0x30);
        assert_eq!(tcache_chunk_size_for_index(2), 0x40);
    }

    #[test]
    fn tcache_snapshot_candidate_holds_non_empty_bins() {
        let snapshot = TcacheSnapshotCandidate {
            struct_user_addr: 0x1000,
            bins: vec![TcacheBinSnapshot {
                index: 1,
                chunk_size: 0x30,
                count: 2,
                head: 0x2000,
            }],
        };

        assert_eq!(snapshot.struct_user_addr, 0x1000);
        assert_eq!(snapshot.bins.len(), 1);
        assert_eq!(snapshot.bins[0].index, 1);
        assert_eq!(snapshot.bins[0].chunk_size, 0x30);
        assert_eq!(snapshot.bins[0].count, 2);
        assert_eq!(snapshot.bins[0].head, 0x2000);
    }

    fn snapshot_with_sizes(sizes: &[u64]) -> GlibcHeapSnapshot {
        let chunks = sizes
            .iter()
            .enumerate()
            .map(|(index, size)| {
                GlibcChunkHeader::from_chunk_parts(0x1000 + index as u64 * 0x1000, 0, size | 0x1)
            })
            .collect();

        GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x1000 + sizes.len() as u64 * 0x1000,
            chunks,
            truncated: false,
        }
    }

    fn fastbins_snapshot_with_chain(nodes: Vec<FastbinNode>) -> FastbinsSnapshot {
        FastbinsSnapshot {
            arena_addr: 0x7000,
            heads: vec![FastbinHead {
                index: 1,
                chunk_size: 0x30,
                field_offset: 0x18,
                head: 0x2000,
                points_into_heap: true,
                matches_heap_chunk: true,
                known_freed: Some(true),
            }],
            chains: vec![FastbinChain {
                index: 1,
                chunk_size: 0x30,
                head: 0x2000,
                nodes,
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
            }],
        }
    }

    fn fastbin_node(
        chunk_addr: u64,
        chunk_size: Option<u64>,
        known_freed: Option<bool>,
    ) -> FastbinNode {
        FastbinNode {
            chunk_addr,
            user_addr: chunk_addr + GLIBC_X86_64_MODERN.chunk_header_size,
            encoded_next: 0,
            decoded_next: 0,
            chunk_size,
            matches_heap_chunk: chunk_size.is_some(),
            known_freed,
        }
    }
}
