use std::collections::{BTreeMap, HashMap, HashSet};

use crate::glibc::TcacheSnapshotCandidate;
use crate::tracker::{HeapTracker, ObservedChunkState};
use crate::HeapTraceEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedTcacheChain {
    pub chunk_size: u64,
    pub head: Option<u64>,
    pub entries: Vec<u64>,
    pub truncated: bool,
    pub stopped_on_unknown_next: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedTcacheMembership {
    pub chunk_size: u64,
    pub index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcacheComparisonStatus {
    MatchesObservedHeadAndCount,
    HeadMatchesCountDiffers,
    HeadMatchesObservedChainIncomplete,
    HeadDiffers,
    MissingObservedChain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcacheBinComparison {
    pub index: usize,
    pub chunk_size: u64,
    pub struct_count: u16,
    pub struct_head: u64,
    pub observed_entries: Vec<u64>,
    pub observed_truncated: bool,
    pub observed_stopped_on_unknown_next: bool,
    pub status: TcacheComparisonStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcacheValidationValue {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcacheValidationStatus {
    Plausible,
    Incomplete,
    Suspicious,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcacheBinValidation {
    pub index: usize,
    pub chunk_size: u64,
    pub head: u64,
    pub count: u16,
    pub head_in_heap: TcacheValidationValue,
    pub head_known_freed: TcacheValidationValue,
    pub observed_nodes_same_size: TcacheValidationValue,
    pub count_matches_observed: TcacheValidationValue,
    pub status: TcacheValidationStatus,
}

#[derive(Debug, Default)]
pub struct ObservedTcacheTracker {
    head_by_size: BTreeMap<u64, u64>,
    next_by_ptr: HashMap<u64, u64>,
}

impl ObservedTcacheTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_event(&mut self, event: &HeapTraceEvent) {
        let HeapTraceEvent::Free {
            ptr,
            chunk,
            tcache_entry,
            ..
        } = event
        else {
            return;
        };

        if *ptr == 0 {
            return;
        }

        let (Some(chunk), Some(tcache_entry)) = (chunk, tcache_entry) else {
            return;
        };

        self.observe_free(*ptr, chunk.size, tcache_entry.decoded_next);
    }

    pub fn observe_free(&mut self, ptr: u64, chunk_size: u64, decoded_next: u64) {
        if ptr == 0 {
            return;
        }

        self.head_by_size.insert(chunk_size, ptr);
        self.next_by_ptr.insert(ptr, decoded_next);
    }

    pub fn chain_for_size(
        &self,
        chunk_size: u64,
        max_entries: usize,
    ) -> Option<ObservedTcacheChain> {
        let head = self.head_by_size.get(&chunk_size).copied();
        head.map(|head| self.build_chain(chunk_size, head, max_entries))
    }

    pub fn chains(&self, max_entries: usize) -> Vec<ObservedTcacheChain> {
        self.head_by_size
            .iter()
            .map(|(chunk_size, head)| self.build_chain(*chunk_size, *head, max_entries))
            .collect()
    }

    pub fn membership_for_ptr(
        &self,
        user_addr: u64,
        max_entries: usize,
    ) -> Option<ObservedTcacheMembership> {
        for chain in self.chains(max_entries) {
            if let Some(index) = chain.entries.iter().position(|entry| *entry == user_addr) {
                return Some(ObservedTcacheMembership {
                    chunk_size: chain.chunk_size,
                    index,
                });
            }
        }

        None
    }

    fn build_chain(&self, chunk_size: u64, head: u64, max_entries: usize) -> ObservedTcacheChain {
        let mut entries = Vec::new();
        let mut truncated = false;
        let mut stopped_on_unknown_next = false;

        if max_entries == 0 {
            return ObservedTcacheChain {
                chunk_size,
                head: Some(head),
                entries,
                truncated: true,
                stopped_on_unknown_next,
            };
        }

        let mut current = head;
        let mut seen = HashSet::new();

        loop {
            if !seen.insert(current) {
                truncated = true;
                break;
            }

            entries.push(current);
            if entries.len() >= max_entries {
                truncated = true;
                break;
            }

            let Some(next) = self.next_by_ptr.get(&current).copied() else {
                stopped_on_unknown_next = true;
                break;
            };

            if next == 0 {
                break;
            }

            if !self.next_by_ptr.contains_key(&next) {
                entries.push(next);
                stopped_on_unknown_next = true;
                break;
            }

            current = next;
        }

        ObservedTcacheChain {
            chunk_size,
            head: Some(head),
            entries,
            truncated,
            stopped_on_unknown_next,
        }
    }
}

pub fn compare_tcache_snapshot_with_observed(
    snapshot: &TcacheSnapshotCandidate,
    observed: &ObservedTcacheTracker,
    max_entries: usize,
) -> Vec<TcacheBinComparison> {
    snapshot
        .bins
        .iter()
        .map(|bin| {
            let Some(chain) = observed.chain_for_size(bin.chunk_size, max_entries) else {
                return TcacheBinComparison {
                    index: bin.index,
                    chunk_size: bin.chunk_size,
                    struct_count: bin.count,
                    struct_head: bin.head,
                    observed_entries: Vec::new(),
                    observed_truncated: false,
                    observed_stopped_on_unknown_next: false,
                    status: TcacheComparisonStatus::MissingObservedChain,
                };
            };

            let observed_head = chain.head.unwrap_or(0);
            let status = if bin.head != observed_head {
                TcacheComparisonStatus::HeadDiffers
            } else if chain.truncated || chain.stopped_on_unknown_next {
                TcacheComparisonStatus::HeadMatchesObservedChainIncomplete
            } else if bin.count as usize == chain.entries.len() {
                TcacheComparisonStatus::MatchesObservedHeadAndCount
            } else {
                TcacheComparisonStatus::HeadMatchesCountDiffers
            };

            TcacheBinComparison {
                index: bin.index,
                chunk_size: bin.chunk_size,
                struct_count: bin.count,
                struct_head: bin.head,
                observed_entries: chain.entries,
                observed_truncated: chain.truncated,
                observed_stopped_on_unknown_next: chain.stopped_on_unknown_next,
                status,
            }
        })
        .collect()
}

pub fn validate_tcache_snapshot_candidate(
    snapshot: &TcacheSnapshotCandidate,
    observed_tcache: &ObservedTcacheTracker,
    heap_tracker: &HeapTracker,
    heap_range: Option<(u64, u64)>,
    max_entries: usize,
) -> Vec<TcacheBinValidation> {
    snapshot
        .bins
        .iter()
        .map(|bin| {
            let head_in_heap = validate_head_in_heap(bin.head, heap_range);
            let head_known_freed = validate_head_known_freed(bin.head, heap_tracker);
            let observed_chain = observed_tcache.chain_for_size(bin.chunk_size, max_entries);
            let observed_nodes_same_size = validate_observed_nodes_same_size(
                bin.chunk_size,
                observed_chain.as_ref(),
                heap_tracker,
            );
            let count_matches_observed =
                validate_count_matches_observed(bin.count, observed_chain.as_ref());
            let status = validation_status(&[
                head_in_heap,
                head_known_freed,
                observed_nodes_same_size,
                count_matches_observed,
            ]);

            TcacheBinValidation {
                index: bin.index,
                chunk_size: bin.chunk_size,
                head: bin.head,
                count: bin.count,
                head_in_heap,
                head_known_freed,
                observed_nodes_same_size,
                count_matches_observed,
                status,
            }
        })
        .collect()
}

fn validate_head_in_heap(head: u64, heap_range: Option<(u64, u64)>) -> TcacheValidationValue {
    if head == 0 {
        return TcacheValidationValue::Unknown;
    }

    match heap_range {
        Some((start, end)) if start <= head && head < end => TcacheValidationValue::Yes,
        Some(_) => TcacheValidationValue::No,
        None => TcacheValidationValue::Unknown,
    }
}

fn validate_head_known_freed(head: u64, heap_tracker: &HeapTracker) -> TcacheValidationValue {
    if head == 0 {
        return TcacheValidationValue::Unknown;
    }

    match heap_tracker.state_for_user_addr(head) {
        Some(ObservedChunkState::Freed) => TcacheValidationValue::Yes,
        Some(ObservedChunkState::Allocated) => TcacheValidationValue::No,
        None => TcacheValidationValue::Unknown,
    }
}

fn validate_observed_nodes_same_size(
    chunk_size: u64,
    chain: Option<&ObservedTcacheChain>,
    heap_tracker: &HeapTracker,
) -> TcacheValidationValue {
    let Some(chain) = chain else {
        return TcacheValidationValue::Unknown;
    };
    if chain.entries.is_empty() {
        return TcacheValidationValue::Unknown;
    }

    let mut checked = false;
    for entry in &chain.entries {
        let Some(chunk) = heap_tracker.get_chunk(*entry) else {
            continue;
        };
        let Some(last_chunk_size) = chunk.last_chunk_size else {
            continue;
        };

        if last_chunk_size != chunk_size {
            return TcacheValidationValue::No;
        }
        checked = true;
    }

    if checked {
        TcacheValidationValue::Yes
    } else {
        TcacheValidationValue::Unknown
    }
}

fn validate_count_matches_observed(
    count: u16,
    chain: Option<&ObservedTcacheChain>,
) -> TcacheValidationValue {
    let Some(chain) = chain else {
        return TcacheValidationValue::Unknown;
    };

    if chain.truncated || chain.stopped_on_unknown_next {
        return TcacheValidationValue::Unknown;
    }

    if count as usize == chain.entries.len() {
        TcacheValidationValue::Yes
    } else {
        TcacheValidationValue::No
    }
}

fn validation_status(values: &[TcacheValidationValue]) -> TcacheValidationStatus {
    if values.contains(&TcacheValidationValue::No) {
        TcacheValidationStatus::Suspicious
    } else if values.contains(&TcacheValidationValue::Unknown) {
        TcacheValidationStatus::Incomplete
    } else {
        TcacheValidationStatus::Plausible
    }
}

#[cfg(test)]
mod tests {
    use super::{
        compare_tcache_snapshot_with_observed, validate_tcache_snapshot_candidate,
        ObservedTcacheChain, ObservedTcacheMembership, ObservedTcacheTracker,
        TcacheComparisonStatus, TcacheValidationStatus, TcacheValidationValue,
    };
    use crate::glibc::{
        ChunkFlags, GlibcChunkHeader, TcacheBinSnapshot, TcacheEntryCandidate,
        TcacheSnapshotCandidate,
    };
    use crate::tracker::HeapTracker;
    use crate::HeapTraceEvent;

    #[test]
    fn empty_tracker_returns_no_chains() {
        let tracker = ObservedTcacheTracker::new();

        assert!(tracker.chains(32).is_empty());
        assert_eq!(tracker.chain_for_size(0x30, 32), None);
    }

    #[test]
    fn one_freed_chunk_with_null_next_gives_one_entry_chain() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);

        assert_eq!(
            tracker.chain_for_size(0x30, 32),
            Some(ObservedTcacheChain {
                chunk_size: 0x30,
                head: Some(0x1000),
                entries: vec![0x1000],
                truncated: false,
                stopped_on_unknown_next: false,
            })
        );
    }

    #[test]
    fn two_freed_chunks_of_same_size_use_newest_to_older_order() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);
        tracker.observe_free(0x2000, 0x30, 0x1000);

        assert_eq!(
            tracker.chain_for_size(0x30, 32).unwrap().entries,
            vec![0x2000, 0x1000]
        );
    }

    #[test]
    fn different_sizes_produce_separate_chains() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);
        tracker.observe_free(0x2000, 0x40, 0);

        assert_eq!(tracker.chains(32).len(), 2);
        assert_eq!(
            tracker.chain_for_size(0x30, 32).unwrap().entries,
            vec![0x1000]
        );
        assert_eq!(
            tracker.chain_for_size(0x40, 32).unwrap().entries,
            vec![0x2000]
        );
    }

    #[test]
    fn unknown_next_pointer_is_included_and_marked() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0x41414141);

        assert_eq!(
            tracker.chain_for_size(0x30, 32),
            Some(ObservedTcacheChain {
                chunk_size: 0x30,
                head: Some(0x1000),
                entries: vec![0x1000, 0x41414141],
                truncated: false,
                stopped_on_unknown_next: true,
            })
        );
    }

    #[test]
    fn max_entries_truncates() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);
        tracker.observe_free(0x2000, 0x30, 0x1000);
        tracker.observe_free(0x3000, 0x30, 0x2000);

        assert_eq!(
            tracker.chain_for_size(0x30, 2),
            Some(ObservedTcacheChain {
                chunk_size: 0x30,
                head: Some(0x3000),
                entries: vec![0x3000, 0x2000],
                truncated: true,
                stopped_on_unknown_next: false,
            })
        );
    }

    #[test]
    fn max_entries_zero_returns_empty_truncated_chain_when_head_exists() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);

        assert_eq!(
            tracker.chain_for_size(0x30, 0),
            Some(ObservedTcacheChain {
                chunk_size: 0x30,
                head: Some(0x1000),
                entries: vec![],
                truncated: true,
                stopped_on_unknown_next: false,
            })
        );
    }

    #[test]
    fn cycle_detection_truncates() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0x2000);
        tracker.observe_free(0x2000, 0x30, 0x1000);

        assert_eq!(
            tracker.chain_for_size(0x30, 32),
            Some(ObservedTcacheChain {
                chunk_size: 0x30,
                head: Some(0x2000),
                entries: vec![0x2000, 0x1000],
                truncated: true,
                stopped_on_unknown_next: false,
            })
        );
    }

    #[test]
    fn observe_event_uses_free_chunk_and_tcache_candidate() {
        let mut tracker = ObservedTcacheTracker::new();
        let event = HeapTraceEvent::Free {
            event_id: 1,
            ptr: 0x1000,
            chunk: Some(chunk_header(0x30)),
            tcache_entry: Some(TcacheEntryCandidate {
                storage_addr: 0x1000,
                encoded_next: 0x1,
                decoded_next: 0,
            }),
            caller_addr: None,
        };

        tracker.observe_event(&event);

        assert_eq!(
            tracker.chain_for_size(0x30, 32).unwrap().entries,
            vec![0x1000]
        );
    }

    #[test]
    fn unknown_membership_pointer_returns_none() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);

        assert_eq!(tracker.membership_for_ptr(0x2000, 32), None);
    }

    #[test]
    fn one_entry_chain_membership_returns_index_zero() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);

        assert_eq!(
            tracker.membership_for_ptr(0x1000, 32),
            Some(ObservedTcacheMembership {
                chunk_size: 0x30,
                index: 0,
            })
        );
    }

    #[test]
    fn two_entry_chain_membership_returns_head_and_next_indices() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);
        tracker.observe_free(0x2000, 0x30, 0x1000);

        assert_eq!(
            tracker.membership_for_ptr(0x2000, 32),
            Some(ObservedTcacheMembership {
                chunk_size: 0x30,
                index: 0,
            })
        );
        assert_eq!(
            tracker.membership_for_ptr(0x1000, 32),
            Some(ObservedTcacheMembership {
                chunk_size: 0x30,
                index: 1,
            })
        );
    }

    #[test]
    fn membership_for_different_sizes_returns_correct_chunk_size() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);
        tracker.observe_free(0x2000, 0x40, 0);

        assert_eq!(
            tracker.membership_for_ptr(0x1000, 32),
            Some(ObservedTcacheMembership {
                chunk_size: 0x30,
                index: 0,
            })
        );
        assert_eq!(
            tracker.membership_for_ptr(0x2000, 32),
            Some(ObservedTcacheMembership {
                chunk_size: 0x40,
                index: 0,
            })
        );
    }

    #[test]
    fn max_entries_can_hide_membership_beyond_limit() {
        let mut tracker = ObservedTcacheTracker::new();

        tracker.observe_free(0x1000, 0x30, 0);
        tracker.observe_free(0x2000, 0x30, 0x1000);

        assert_eq!(
            tracker.membership_for_ptr(0x2000, 1),
            Some(ObservedTcacheMembership {
                chunk_size: 0x30,
                index: 0,
            })
        );
        assert_eq!(tracker.membership_for_ptr(0x1000, 1), None);
    }

    #[test]
    fn comparison_matches_observed_head_and_count() {
        let mut tracker = ObservedTcacheTracker::new();
        tracker.observe_free(0x1000, 0x30, 0);
        let snapshot = snapshot_with_bin(1, 0x30, 1, 0x1000);

        let comparisons = compare_tcache_snapshot_with_observed(&snapshot, &tracker, 32);

        assert_eq!(
            comparisons[0].status,
            TcacheComparisonStatus::MatchesObservedHeadAndCount
        );
    }

    #[test]
    fn comparison_head_matches_but_count_differs() {
        let mut tracker = ObservedTcacheTracker::new();
        tracker.observe_free(0x1000, 0x30, 0);
        let snapshot = snapshot_with_bin(1, 0x30, 2, 0x1000);

        let comparisons = compare_tcache_snapshot_with_observed(&snapshot, &tracker, 32);

        assert_eq!(
            comparisons[0].status,
            TcacheComparisonStatus::HeadMatchesCountDiffers
        );
    }

    #[test]
    fn comparison_head_matches_but_observed_chain_truncated() {
        let mut tracker = ObservedTcacheTracker::new();
        tracker.observe_free(0x1000, 0x30, 0);
        tracker.observe_free(0x2000, 0x30, 0x1000);
        let snapshot = snapshot_with_bin(1, 0x30, 2, 0x2000);

        let comparisons = compare_tcache_snapshot_with_observed(&snapshot, &tracker, 1);

        assert_eq!(
            comparisons[0].status,
            TcacheComparisonStatus::HeadMatchesObservedChainIncomplete
        );
    }

    #[test]
    fn comparison_head_differs() {
        let mut tracker = ObservedTcacheTracker::new();
        tracker.observe_free(0x1000, 0x30, 0);
        let snapshot = snapshot_with_bin(1, 0x30, 1, 0x2000);

        let comparisons = compare_tcache_snapshot_with_observed(&snapshot, &tracker, 32);

        assert_eq!(comparisons[0].status, TcacheComparisonStatus::HeadDiffers);
    }

    #[test]
    fn comparison_missing_observed_chain() {
        let tracker = ObservedTcacheTracker::new();
        let snapshot = snapshot_with_bin(1, 0x30, 1, 0x1000);

        let comparisons = compare_tcache_snapshot_with_observed(&snapshot, &tracker, 32);

        assert_eq!(
            comparisons[0].status,
            TcacheComparisonStatus::MissingObservedChain
        );
        assert!(comparisons[0].observed_entries.is_empty());
    }

    #[test]
    fn validation_all_yes_gives_plausible() {
        let (snapshot, observed, heap_tracker) = validation_fixture(1, 0x1000, 0x30);

        let validations = validate_tcache_snapshot_candidate(
            &snapshot,
            &observed,
            &heap_tracker,
            Some((0x1000, 0x2000)),
            32,
        );

        assert_eq!(validations[0].head_in_heap, TcacheValidationValue::Yes);
        assert_eq!(validations[0].head_known_freed, TcacheValidationValue::Yes);
        assert_eq!(
            validations[0].observed_nodes_same_size,
            TcacheValidationValue::Yes
        );
        assert_eq!(
            validations[0].count_matches_observed,
            TcacheValidationValue::Yes
        );
        assert_eq!(validations[0].status, TcacheValidationStatus::Plausible);
    }

    #[test]
    fn validation_head_outside_heap_gives_suspicious() {
        let (snapshot, observed, heap_tracker) = validation_fixture(1, 0x1000, 0x30);

        let validations = validate_tcache_snapshot_candidate(
            &snapshot,
            &observed,
            &heap_tracker,
            Some((0x2000, 0x3000)),
            32,
        );

        assert_eq!(validations[0].head_in_heap, TcacheValidationValue::No);
        assert_eq!(validations[0].status, TcacheValidationStatus::Suspicious);
    }

    #[test]
    fn validation_head_known_allocated_gives_suspicious() {
        let mut observed = ObservedTcacheTracker::new();
        observed.observe_free(0x1000, 0x30, 0);
        let mut heap_tracker = HeapTracker::new();
        heap_tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));
        let snapshot = snapshot_with_bin(1, 0x30, 1, 0x1000);

        let validations = validate_tcache_snapshot_candidate(
            &snapshot,
            &observed,
            &heap_tracker,
            Some((0x1000, 0x2000)),
            32,
        );

        assert_eq!(validations[0].head_known_freed, TcacheValidationValue::No);
        assert_eq!(validations[0].status, TcacheValidationStatus::Suspicious);
    }

    #[test]
    fn validation_count_mismatch_gives_suspicious() {
        let (snapshot, observed, heap_tracker) = validation_fixture(2, 0x1000, 0x30);

        let validations = validate_tcache_snapshot_candidate(
            &snapshot,
            &observed,
            &heap_tracker,
            Some((0x1000, 0x2000)),
            32,
        );

        assert_eq!(
            validations[0].count_matches_observed,
            TcacheValidationValue::No
        );
        assert_eq!(validations[0].status, TcacheValidationStatus::Suspicious);
    }

    #[test]
    fn validation_missing_heap_range_gives_incomplete() {
        let (snapshot, observed, heap_tracker) = validation_fixture(1, 0x1000, 0x30);

        let validations =
            validate_tcache_snapshot_candidate(&snapshot, &observed, &heap_tracker, None, 32);

        assert_eq!(validations[0].head_in_heap, TcacheValidationValue::Unknown);
        assert_eq!(validations[0].status, TcacheValidationStatus::Incomplete);
    }

    #[test]
    fn validation_missing_observed_chain_gives_incomplete() {
        let observed = ObservedTcacheTracker::new();
        let mut heap_tracker = HeapTracker::new();
        heap_tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));
        heap_tracker.observe_free(2, 0x1000);
        let snapshot = snapshot_with_bin(1, 0x30, 1, 0x1000);

        let validations = validate_tcache_snapshot_candidate(
            &snapshot,
            &observed,
            &heap_tracker,
            Some((0x1000, 0x2000)),
            32,
        );

        assert_eq!(
            validations[0].observed_nodes_same_size,
            TcacheValidationValue::Unknown
        );
        assert_eq!(
            validations[0].count_matches_observed,
            TcacheValidationValue::Unknown
        );
        assert_eq!(validations[0].status, TcacheValidationStatus::Incomplete);
    }

    #[test]
    fn validation_matching_observed_chain_count_and_sizes_gives_plausible() {
        let mut observed = ObservedTcacheTracker::new();
        observed.observe_free(0x1000, 0x30, 0);
        observed.observe_free(0x2000, 0x30, 0x1000);
        let mut heap_tracker = HeapTracker::new();
        heap_tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));
        heap_tracker.observe_malloc(2, 0x20, 0x2000, Some(0x30));
        heap_tracker.observe_free(3, 0x1000);
        heap_tracker.observe_free(4, 0x2000);
        let snapshot = snapshot_with_bin(1, 0x30, 2, 0x2000);

        let validations = validate_tcache_snapshot_candidate(
            &snapshot,
            &observed,
            &heap_tracker,
            Some((0x1000, 0x3000)),
            32,
        );

        assert_eq!(
            validations[0].observed_nodes_same_size,
            TcacheValidationValue::Yes
        );
        assert_eq!(
            validations[0].count_matches_observed,
            TcacheValidationValue::Yes
        );
        assert_eq!(validations[0].status, TcacheValidationStatus::Plausible);
    }

    fn chunk_header(size: u64) -> GlibcChunkHeader {
        GlibcChunkHeader {
            chunk_addr: 0xff0,
            user_addr: 0x1000,
            prev_size: 0,
            size_raw: size | 0x1,
            size,
            flags: ChunkFlags {
                prev_inuse: true,
                is_mmapped: false,
                non_main_arena: false,
            },
        }
    }

    fn snapshot_with_bin(
        index: usize,
        chunk_size: u64,
        count: u16,
        head: u64,
    ) -> TcacheSnapshotCandidate {
        TcacheSnapshotCandidate {
            struct_user_addr: 0x5000,
            bins: vec![TcacheBinSnapshot {
                index,
                chunk_size,
                count,
                head,
            }],
        }
    }

    fn validation_fixture(
        count: u16,
        head: u64,
        chunk_size: u64,
    ) -> (TcacheSnapshotCandidate, ObservedTcacheTracker, HeapTracker) {
        let mut observed = ObservedTcacheTracker::new();
        observed.observe_free(head, chunk_size, 0);
        let mut heap_tracker = HeapTracker::new();
        heap_tracker.observe_malloc(1, 0x20, head, Some(chunk_size));
        heap_tracker.observe_free(2, head);
        let snapshot = snapshot_with_bin(1, chunk_size, count, head);

        (snapshot, observed, heap_tracker)
    }
}
