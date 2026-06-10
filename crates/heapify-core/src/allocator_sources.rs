use std::collections::{BTreeMap, BTreeSet};

use crate::glibc::{
    FastbinsSnapshot, GlibcProfile, LargebinsSnapshot, SmallbinsSnapshot, UnsortedBinSnapshot,
};
use crate::tcache::ObservedTcacheTracker;
use crate::tracker::{HeapTracker, ObservedChunkState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AllocatorSourceKind {
    TcacheCandidate,
    Fastbin,
    Unsorted,
    Smallbin,
    Largebin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatorSourceMembership {
    pub kind: AllocatorSourceKind,
    pub chunk_size: Option<u64>,
    pub index: Option<usize>,
    pub user_addr: u64,
    pub chunk_addr: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorWarningKind {
    ConflictingAllocatorSources,
    AllocatorSourceButTrackerAllocated,
    SizeMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatorWarning {
    pub kind: AllocatorWarningKind,
    pub chunk_addr: u64,
    pub user_addr: u64,
    pub sources: Vec<AllocatorSourceMembership>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatorSourceSummary {
    pub tcache_candidate_chunks: usize,
    pub fastbin_chunks: usize,
    pub unsorted_chunks: usize,
    pub smallbin_chunks: usize,
    pub largebin_chunks: usize,
    pub total_free_list_chunks: usize,
    pub warning_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatorSourceDelta {
    pub tcache_candidate_chunks_delta: isize,
    pub fastbin_chunks_delta: isize,
    pub unsorted_chunks_delta: isize,
    pub smallbin_chunks_delta: isize,
    pub largebin_chunks_delta: isize,
    pub total_free_list_chunks_delta: isize,
    pub warning_count_delta: isize,
}

pub fn allocator_source_kind_str(kind: AllocatorSourceKind) -> &'static str {
    match kind {
        AllocatorSourceKind::TcacheCandidate => "tcache_candidate",
        AllocatorSourceKind::Fastbin => "fastbin",
        AllocatorSourceKind::Unsorted => "unsorted",
        AllocatorSourceKind::Smallbin => "smallbin",
        AllocatorSourceKind::Largebin => "largebin",
    }
}

pub fn allocator_warning_kind_str(kind: AllocatorWarningKind) -> &'static str {
    match kind {
        AllocatorWarningKind::ConflictingAllocatorSources => "conflicting_allocator_sources",
        AllocatorWarningKind::AllocatorSourceButTrackerAllocated => {
            "allocator_source_but_tracker_allocated"
        }
        AllocatorWarningKind::SizeMismatch => "size_mismatch",
    }
}

pub fn collect_allocator_warnings(
    heap_tracker: &HeapTracker,
    tcache: Option<&ObservedTcacheTracker>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    profile: GlibcProfile,
    max_tcache_chain: usize,
) -> Vec<AllocatorWarning> {
    let memberships = collect_allocator_source_memberships(
        tcache,
        fastbins,
        unsorted,
        smallbins,
        largebins,
        profile,
        max_tcache_chain,
    );
    let mut warnings = Vec::new();

    for (user_addr, sources) in &memberships {
        let distinct_kinds = sources
            .iter()
            .map(|source| source.kind)
            .collect::<BTreeSet<_>>();
        if distinct_kinds.len() > 1 {
            warnings.push(AllocatorWarning {
                kind: AllocatorWarningKind::ConflictingAllocatorSources,
                chunk_addr: sources[0].chunk_addr,
                user_addr: *user_addr,
                sources: sources.clone(),
                message: "chunk appears in multiple allocator sources".to_string(),
            });
        }

        if heap_tracker.state_for_user_addr(*user_addr) == Some(ObservedChunkState::Allocated) {
            warnings.push(AllocatorWarning {
                kind: AllocatorWarningKind::AllocatorSourceButTrackerAllocated,
                chunk_addr: sources[0].chunk_addr,
                user_addr: *user_addr,
                sources: sources.clone(),
                message:
                    "chunk appears in allocator free-list source but tracker state is allocated"
                        .to_string(),
            });
        }
    }

    if let Some(fastbins) = fastbins {
        for chain in &fastbins.chains {
            for (node_index, node) in chain.nodes.iter().enumerate() {
                if node.chunk_size.is_some_and(|size| size != chain.chunk_size) {
                    let source = AllocatorSourceMembership {
                        kind: AllocatorSourceKind::Fastbin,
                        chunk_size: Some(chain.chunk_size),
                        index: Some(node_index),
                        user_addr: node.user_addr,
                        chunk_addr: node.chunk_addr,
                    };
                    warnings.push(AllocatorWarning {
                        kind: AllocatorWarningKind::SizeMismatch,
                        chunk_addr: node.chunk_addr,
                        user_addr: node.user_addr,
                        sources: vec![source],
                        message:
                            "allocator source chunk size disagrees with walked heap chunk size"
                                .to_string(),
                    });
                }
            }
        }
    }

    if let Some(smallbins) = smallbins {
        for chain in &smallbins.chains {
            for (node_index, node) in chain.nodes.iter().enumerate() {
                if node
                    .chunk_size
                    .is_some_and(|size| size != chain.expected_chunk_size)
                {
                    let source = AllocatorSourceMembership {
                        kind: AllocatorSourceKind::Smallbin,
                        chunk_size: Some(chain.expected_chunk_size),
                        index: Some(node_index),
                        user_addr: node.user_addr,
                        chunk_addr: node.chunk_addr,
                    };
                    warnings.push(AllocatorWarning {
                        kind: AllocatorWarningKind::SizeMismatch,
                        chunk_addr: node.chunk_addr,
                        user_addr: node.user_addr,
                        sources: vec![source],
                        message:
                            "allocator source chunk size disagrees with walked heap chunk size"
                                .to_string(),
                    });
                }
            }
        }
    }

    warnings
}

pub fn collect_allocator_source_summary(
    tcache: Option<&ObservedTcacheTracker>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    warnings: &[AllocatorWarning],
    profile: GlibcProfile,
    max_tcache_chain: usize,
) -> AllocatorSourceSummary {
    let _ = profile;
    let mut unique_user_addrs = BTreeSet::new();
    let tcache_candidate_chunks = tcache
        .map(|tcache| {
            tcache
                .chains(max_tcache_chain)
                .iter()
                .map(|chain| {
                    unique_user_addrs.extend(chain.entries.iter().copied());
                    chain.entries.len()
                })
                .sum()
        })
        .unwrap_or_default();
    let fastbin_chunks = fastbins
        .map(|fastbins| {
            fastbins
                .chains
                .iter()
                .map(|chain| {
                    unique_user_addrs.extend(chain.nodes.iter().map(|node| node.user_addr));
                    chain.nodes.len()
                })
                .sum()
        })
        .unwrap_or_default();
    let unsorted_chunks = unsorted
        .and_then(|snapshot| snapshot.chain.as_ref())
        .filter(|chain| !chain.empty)
        .map(|chain| {
            unique_user_addrs.extend(chain.nodes.iter().map(|node| node.user_addr));
            chain.nodes.len()
        })
        .unwrap_or_default();
    let smallbin_chunks = smallbins
        .map(|smallbins| {
            smallbins
                .chains
                .iter()
                .filter(|chain| !chain.empty)
                .map(|chain| {
                    unique_user_addrs.extend(chain.nodes.iter().map(|node| node.user_addr));
                    chain.nodes.len()
                })
                .sum()
        })
        .unwrap_or_default();
    let largebin_chunks = largebins
        .map(|largebins| {
            largebins
                .chains
                .iter()
                .filter(|chain| !chain.empty)
                .map(|chain| {
                    unique_user_addrs.extend(chain.nodes.iter().map(|node| node.user_addr));
                    chain.nodes.len()
                })
                .sum()
        })
        .unwrap_or_default();

    AllocatorSourceSummary {
        tcache_candidate_chunks,
        fastbin_chunks,
        unsorted_chunks,
        smallbin_chunks,
        largebin_chunks,
        total_free_list_chunks: unique_user_addrs.len(),
        warning_count: warnings.len(),
    }
}

pub fn diff_allocator_source_summary(
    previous: Option<&AllocatorSourceSummary>,
    current: &AllocatorSourceSummary,
) -> AllocatorSourceDelta {
    let previous = previous.cloned().unwrap_or(AllocatorSourceSummary {
        tcache_candidate_chunks: 0,
        fastbin_chunks: 0,
        unsorted_chunks: 0,
        smallbin_chunks: 0,
        largebin_chunks: 0,
        total_free_list_chunks: 0,
        warning_count: 0,
    });

    AllocatorSourceDelta {
        tcache_candidate_chunks_delta: current.tcache_candidate_chunks as isize
            - previous.tcache_candidate_chunks as isize,
        fastbin_chunks_delta: current.fastbin_chunks as isize - previous.fastbin_chunks as isize,
        unsorted_chunks_delta: current.unsorted_chunks as isize - previous.unsorted_chunks as isize,
        smallbin_chunks_delta: current.smallbin_chunks as isize - previous.smallbin_chunks as isize,
        largebin_chunks_delta: current.largebin_chunks as isize - previous.largebin_chunks as isize,
        total_free_list_chunks_delta: current.total_free_list_chunks as isize
            - previous.total_free_list_chunks as isize,
        warning_count_delta: current.warning_count as isize - previous.warning_count as isize,
    }
}

fn collect_allocator_source_memberships(
    tcache: Option<&ObservedTcacheTracker>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    profile: GlibcProfile,
    max_tcache_chain: usize,
) -> BTreeMap<u64, Vec<AllocatorSourceMembership>> {
    let mut memberships: BTreeMap<u64, Vec<AllocatorSourceMembership>> = BTreeMap::new();

    if let Some(tcache) = tcache {
        for chain in tcache.chains(max_tcache_chain) {
            for (index, user_addr) in chain.entries.iter().copied().enumerate() {
                let Some(chunk_addr) = user_addr.checked_sub(profile.chunk_header_size) else {
                    continue;
                };
                memberships
                    .entry(user_addr)
                    .or_default()
                    .push(AllocatorSourceMembership {
                        kind: AllocatorSourceKind::TcacheCandidate,
                        chunk_size: Some(chain.chunk_size),
                        index: Some(index),
                        user_addr,
                        chunk_addr,
                    });
            }
        }
    }

    if let Some(fastbins) = fastbins {
        for chain in &fastbins.chains {
            for (index, node) in chain.nodes.iter().enumerate() {
                memberships
                    .entry(node.user_addr)
                    .or_default()
                    .push(AllocatorSourceMembership {
                        kind: AllocatorSourceKind::Fastbin,
                        chunk_size: Some(chain.chunk_size),
                        index: Some(index),
                        user_addr: node.user_addr,
                        chunk_addr: node.chunk_addr,
                    });
            }
        }
    }

    if let Some(chain) = unsorted.and_then(|snapshot| snapshot.chain.as_ref()) {
        for (index, node) in chain.nodes.iter().enumerate() {
            memberships
                .entry(node.user_addr)
                .or_default()
                .push(AllocatorSourceMembership {
                    kind: AllocatorSourceKind::Unsorted,
                    chunk_size: node.chunk_size,
                    index: Some(index),
                    user_addr: node.user_addr,
                    chunk_addr: node.chunk_addr,
                });
        }
    }

    if let Some(smallbins) = smallbins {
        for chain in &smallbins.chains {
            for (index, node) in chain.nodes.iter().enumerate() {
                memberships
                    .entry(node.user_addr)
                    .or_default()
                    .push(AllocatorSourceMembership {
                        kind: AllocatorSourceKind::Smallbin,
                        chunk_size: Some(chain.expected_chunk_size),
                        index: Some(index),
                        user_addr: node.user_addr,
                        chunk_addr: node.chunk_addr,
                    });
            }
        }
    }

    if let Some(largebins) = largebins {
        for chain in &largebins.chains {
            for (index, node) in chain.nodes.iter().enumerate() {
                memberships
                    .entry(node.user_addr)
                    .or_default()
                    .push(AllocatorSourceMembership {
                        kind: AllocatorSourceKind::Largebin,
                        chunk_size: node.chunk_size,
                        index: Some(index),
                        user_addr: node.user_addr,
                        chunk_addr: node.chunk_addr,
                    });
            }
        }
    }

    memberships
}

#[cfg(test)]
mod tests {
    use super::{
        allocator_source_kind_str, allocator_warning_kind_str, collect_allocator_source_summary,
        collect_allocator_warnings, diff_allocator_source_summary, AllocatorSourceKind,
        AllocatorSourceSummary, AllocatorWarning, AllocatorWarningKind,
    };
    use crate::glibc::{
        FastbinChain, FastbinNode, FastbinsSnapshot, LargebinChain, LargebinNode,
        LargebinsSnapshot, SmallbinChain, SmallbinNode, SmallbinsSnapshot, UnsortedBinChain,
        UnsortedBinNode, UnsortedBinSnapshot, GLIBC_X86_64_MODERN,
    };
    use crate::tcache::ObservedTcacheTracker;
    use crate::tracker::HeapTracker;

    #[test]
    fn source_kind_strings_are_stable() {
        assert_eq!(
            allocator_source_kind_str(AllocatorSourceKind::TcacheCandidate),
            "tcache_candidate"
        );
        assert_eq!(
            allocator_source_kind_str(AllocatorSourceKind::Fastbin),
            "fastbin"
        );
        assert_eq!(
            allocator_source_kind_str(AllocatorSourceKind::Unsorted),
            "unsorted"
        );
    }

    #[test]
    fn warning_kind_strings_are_stable() {
        assert_eq!(
            allocator_warning_kind_str(AllocatorWarningKind::ConflictingAllocatorSources),
            "conflicting_allocator_sources"
        );
        assert_eq!(
            allocator_warning_kind_str(AllocatorWarningKind::AllocatorSourceButTrackerAllocated),
            "allocator_source_but_tracker_allocated"
        );
        assert_eq!(
            allocator_warning_kind_str(AllocatorWarningKind::SizeMismatch),
            "size_mismatch"
        );
    }

    #[test]
    fn conflict_tcache_and_fastbin_same_user_pointer_warns() {
        let mut tcache = ObservedTcacheTracker::new();
        tcache.observe_free(0x1010, 0x30, 0);
        let fastbins = fastbins_with_node(0x1000, 0x1010, Some(0x30));
        let tracker = HeapTracker::new();

        let warnings = collect_allocator_warnings(
            &tracker,
            Some(&tcache),
            Some(&fastbins),
            None,
            None,
            None,
            GLIBC_X86_64_MODERN,
            32,
        );

        assert!(warnings
            .iter()
            .any(|warning| warning.kind == AllocatorWarningKind::ConflictingAllocatorSources));
    }

    #[test]
    fn fastbin_source_with_tracker_allocated_warns() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1010, Some(0x30));
        let fastbins = fastbins_with_node(0x1000, 0x1010, Some(0x30));

        let warnings = collect_allocator_warnings(
            &tracker,
            None,
            Some(&fastbins),
            None,
            None,
            None,
            GLIBC_X86_64_MODERN,
            32,
        );

        assert!(warnings.iter().any(|warning| {
            warning.kind == AllocatorWarningKind::AllocatorSourceButTrackerAllocated
        }));
    }

    #[test]
    fn single_freed_source_does_not_warn() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1010, Some(0x30));
        tracker.observe_free(2, 0x1010);
        let fastbins = fastbins_with_node(0x1000, 0x1010, Some(0x30));

        let warnings = collect_allocator_warnings(
            &tracker,
            None,
            Some(&fastbins),
            None,
            None,
            None,
            GLIBC_X86_64_MODERN,
            32,
        );

        assert!(warnings.is_empty());
    }

    #[test]
    fn empty_sources_have_zero_summary_counts() {
        assert_eq!(
            collect_allocator_source_summary(
                None,
                None,
                None,
                None,
                None,
                &[],
                GLIBC_X86_64_MODERN,
                32,
            ),
            super::AllocatorSourceSummary {
                tcache_candidate_chunks: 0,
                fastbin_chunks: 0,
                unsorted_chunks: 0,
                smallbin_chunks: 0,
                largebin_chunks: 0,
                total_free_list_chunks: 0,
                warning_count: 0,
            }
        );
    }

    #[test]
    fn summary_counts_tcache_only() {
        let mut tcache = ObservedTcacheTracker::new();
        tcache.observe_free(0x1010, 0x30, 0);

        let summary = collect_allocator_source_summary(
            Some(&tcache),
            None,
            None,
            None,
            None,
            &[],
            GLIBC_X86_64_MODERN,
            32,
        );

        assert_eq!(summary.tcache_candidate_chunks, 1);
        assert_eq!(summary.total_free_list_chunks, 1);
    }

    #[test]
    fn summary_counts_fastbins_only() {
        let fastbins = fastbins_with_node(0x1000, 0x1010, Some(0x30));

        let summary = collect_allocator_source_summary(
            None,
            Some(&fastbins),
            None,
            None,
            None,
            &[],
            GLIBC_X86_64_MODERN,
            32,
        );

        assert_eq!(summary.fastbin_chunks, 1);
        assert_eq!(summary.total_free_list_chunks, 1);
    }

    #[test]
    fn summary_counts_unsorted_only() {
        let unsorted = unsorted_with_node(0x1000, 0x1010);

        let summary = collect_allocator_source_summary(
            None,
            None,
            Some(&unsorted),
            None,
            None,
            &[],
            GLIBC_X86_64_MODERN,
            32,
        );

        assert_eq!(summary.unsorted_chunks, 1);
        assert_eq!(summary.total_free_list_chunks, 1);
    }

    #[test]
    fn summary_counts_smallbins_only() {
        let smallbins = smallbins_with_node(0x1000, 0x1010, Some(0x20));

        let summary = collect_allocator_source_summary(
            None,
            None,
            None,
            Some(&smallbins),
            None,
            &[],
            GLIBC_X86_64_MODERN,
            32,
        );

        assert_eq!(summary.smallbin_chunks, 1);
        assert_eq!(summary.total_free_list_chunks, 1);
    }

    #[test]
    fn summary_counts_largebins_only() {
        let largebins = largebins_with_node(0x1000, 0x1010, Some(0x510));

        let summary = collect_allocator_source_summary(
            None,
            None,
            None,
            None,
            Some(&largebins),
            &[],
            GLIBC_X86_64_MODERN,
            32,
        );

        assert_eq!(summary.largebin_chunks, 1);
        assert_eq!(summary.total_free_list_chunks, 1);
    }

    #[test]
    fn conflict_smallbin_and_fastbin_same_user_pointer_warns() {
        let fastbins = fastbins_with_node(0x1000, 0x1010, Some(0x30));
        let smallbins = smallbins_with_node(0x1000, 0x1010, Some(0x20));
        let tracker = HeapTracker::new();

        let warnings = collect_allocator_warnings(
            &tracker,
            None,
            Some(&fastbins),
            None,
            Some(&smallbins),
            None,
            GLIBC_X86_64_MODERN,
            32,
        );

        assert!(warnings
            .iter()
            .any(|warning| warning.kind == AllocatorWarningKind::ConflictingAllocatorSources));
    }

    #[test]
    fn summary_deduplicates_overlapping_tcache_and_fastbin_user_addresses() {
        let mut tcache = ObservedTcacheTracker::new();
        tcache.observe_free(0x1010, 0x30, 0);
        let fastbins = fastbins_with_node(0x1000, 0x1010, Some(0x30));

        let summary = collect_allocator_source_summary(
            Some(&tcache),
            Some(&fastbins),
            None,
            None,
            None,
            &[],
            GLIBC_X86_64_MODERN,
            32,
        );

        assert_eq!(summary.tcache_candidate_chunks, 1);
        assert_eq!(summary.fastbin_chunks, 1);
        assert_eq!(summary.total_free_list_chunks, 1);
    }

    #[test]
    fn summary_warning_count_matches_warning_slice_length() {
        let warnings = vec![AllocatorWarning {
            kind: AllocatorWarningKind::SizeMismatch,
            chunk_addr: 0x1000,
            user_addr: 0x1010,
            sources: Vec::new(),
            message: "test".to_string(),
        }];

        let summary = collect_allocator_source_summary(
            None,
            None,
            None,
            None,
            None,
            &warnings,
            GLIBC_X86_64_MODERN,
            32,
        );

        assert_eq!(summary.warning_count, warnings.len());
    }

    #[test]
    fn diff_without_previous_summary_uses_current_counts() {
        let current = AllocatorSourceSummary {
            tcache_candidate_chunks: 1,
            fastbin_chunks: 2,
            unsorted_chunks: 3,
            smallbin_chunks: 4,
            largebin_chunks: 5,
            total_free_list_chunks: 4,
            warning_count: 5,
        };

        let delta = diff_allocator_source_summary(None, &current);

        assert_eq!(delta.tcache_candidate_chunks_delta, 1);
        assert_eq!(delta.fastbin_chunks_delta, 2);
        assert_eq!(delta.unsorted_chunks_delta, 3);
        assert_eq!(delta.smallbin_chunks_delta, 4);
        assert_eq!(delta.largebin_chunks_delta, 5);
        assert_eq!(delta.total_free_list_chunks_delta, 4);
        assert_eq!(delta.warning_count_delta, 5);
    }

    #[test]
    fn diff_with_previous_summary_computes_positive_zero_and_negative_deltas() {
        let previous = AllocatorSourceSummary {
            tcache_candidate_chunks: 1,
            fastbin_chunks: 2,
            unsorted_chunks: 3,
            smallbin_chunks: 4,
            largebin_chunks: 5,
            total_free_list_chunks: 5,
            warning_count: 1,
        };
        let current = AllocatorSourceSummary {
            tcache_candidate_chunks: 2,
            fastbin_chunks: 2,
            unsorted_chunks: 1,
            smallbin_chunks: 4,
            largebin_chunks: 2,
            total_free_list_chunks: 4,
            warning_count: 3,
        };

        let delta = diff_allocator_source_summary(Some(&previous), &current);

        assert_eq!(delta.tcache_candidate_chunks_delta, 1);
        assert_eq!(delta.fastbin_chunks_delta, 0);
        assert_eq!(delta.unsorted_chunks_delta, -2);
        assert_eq!(delta.smallbin_chunks_delta, 0);
        assert_eq!(delta.largebin_chunks_delta, -3);
        assert_eq!(delta.total_free_list_chunks_delta, -1);
        assert_eq!(delta.warning_count_delta, 2);
    }

    fn fastbins_with_node(
        chunk_addr: u64,
        user_addr: u64,
        chunk_size: Option<u64>,
    ) -> FastbinsSnapshot {
        FastbinsSnapshot {
            arena_addr: 0x7000,
            heads: Vec::new(),
            chains: vec![FastbinChain {
                index: 0,
                chunk_size: 0x30,
                head: chunk_addr,
                nodes: vec![FastbinNode {
                    chunk_addr,
                    user_addr,
                    encoded_next: 0,
                    decoded_next: 0,
                    chunk_size,
                    matches_heap_chunk: chunk_size.is_some(),
                    known_freed: Some(true),
                }],
                truncated: false,
                stopped_on_unknown_next: false,
                cycle_detected: false,
            }],
        }
    }

    fn unsorted_with_node(chunk_addr: u64, user_addr: u64) -> UnsortedBinSnapshot {
        UnsortedBinSnapshot {
            arena_addr: 0x7000,
            field_offset: 0x70,
            fd: chunk_addr,
            bk: chunk_addr,
            fd_points_into_heap: true,
            bk_points_into_heap: true,
            fd_matches_heap_chunk: true,
            bk_matches_heap_chunk: true,
            fd_known_freed: Some(true),
            bk_known_freed: Some(true),
            chain: Some(UnsortedBinChain {
                sentinel_addr: 0x7070,
                head: chunk_addr,
                tail: chunk_addr,
                nodes: vec![UnsortedBinNode {
                    chunk_addr,
                    user_addr,
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
        }
    }

    fn smallbins_with_node(
        chunk_addr: u64,
        user_addr: u64,
        chunk_size: Option<u64>,
    ) -> SmallbinsSnapshot {
        SmallbinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![SmallbinChain {
                regular_index: 1,
                glibc_bin_index: 2,
                expected_chunk_size: 0x20,
                sentinel_addr: 0x7080,
                head: chunk_addr,
                tail: chunk_addr,
                nodes: vec![SmallbinNode {
                    chunk_addr,
                    user_addr,
                    fd: 0x7080,
                    bk: 0x7080,
                    chunk_size,
                    matches_heap_chunk: chunk_size.is_some(),
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
        }
    }

    fn largebins_with_node(
        chunk_addr: u64,
        user_addr: u64,
        chunk_size: Option<u64>,
    ) -> LargebinsSnapshot {
        LargebinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![LargebinChain {
                regular_index: 64,
                glibc_bin_index: 65,
                sentinel_addr: 0x7080,
                head: chunk_addr,
                tail: chunk_addr,
                nodes: vec![LargebinNode {
                    chunk_addr,
                    user_addr,
                    fd: 0x7080,
                    bk: 0x7080,
                    fd_nextsize: 0,
                    bk_nextsize: 0,
                    chunk_size,
                    matches_heap_chunk: chunk_size.is_some(),
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
        }
    }
}
