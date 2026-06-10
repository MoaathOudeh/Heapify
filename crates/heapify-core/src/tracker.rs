use std::collections::{HashMap, HashSet};

use crate::HeapTraceEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedChunkState {
    Allocated,
    Freed,
}

#[derive(Debug, Clone)]
pub struct ObservedChunk {
    pub user_addr: u64,
    pub last_requested_size: Option<u64>,
    pub last_chunk_size: Option<u64>,
    pub state: ObservedChunkState,
    pub first_seen_event_id: usize,
    pub last_seen_event_id: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapTrackerNote {
    NewAllocation,
    ReusedFreedChunk,
    FreedKnownChunk,
    DoubleFree,
    FreeUnknownPointer,
    NullMalloc,
    NullFree,
    AllocatedPointerReturnedAgain,
    NullCalloc,
    ReallocNullActsLikeMalloc,
    ReallocInPlace,
    ReallocMovedAllocation,
    ReallocFailedKeepsOldPointer,
    ReallocPtrZeroFreedOldPointer,
    ReallocUnknownOldPointer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeapTrackerExplanation {
    LikelyTcacheOrFastbinReuse { chunk_size: u64 },
    NoExtraExplanation,
}

#[derive(Debug, Default)]
pub struct HeapTracker {
    chunks: HashMap<u64, ObservedChunk>,
}

impl HeapTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_chunk(&self, user_addr: u64) -> Option<&ObservedChunk> {
        self.chunks.get(&user_addr)
    }

    pub fn state_for_user_addr(&self, user_addr: u64) -> Option<ObservedChunkState> {
        self.get_chunk(user_addr).map(|chunk| chunk.state)
    }

    pub fn observed_user_addr_set(&self) -> HashSet<u64> {
        self.chunks.keys().copied().collect()
    }

    pub fn observe_event(&mut self, event: &HeapTraceEvent) -> HeapTrackerNote {
        match event {
            HeapTraceEvent::Malloc {
                event_id,
                requested_size,
                returned_ptr,
                chunk,
                ..
            } => self.observe_malloc(
                *event_id,
                *requested_size,
                *returned_ptr,
                chunk.as_ref().map(|chunk| chunk.size),
            ),
            HeapTraceEvent::Free { event_id, ptr, .. } => self.observe_free(*event_id, *ptr),
            HeapTraceEvent::Calloc {
                event_id,
                nmemb,
                size,
                returned_ptr,
                chunk,
                ..
            } => self.observe_calloc(
                *event_id,
                *nmemb,
                *size,
                *returned_ptr,
                chunk.as_ref().map(|chunk| chunk.size),
            ),
            HeapTraceEvent::Realloc {
                event_id,
                old_ptr,
                new_size,
                returned_ptr,
                new_chunk,
                ..
            } => self.observe_realloc(
                *event_id,
                *old_ptr,
                *new_size,
                *returned_ptr,
                new_chunk.as_ref().map(|chunk| chunk.size),
            ),
        }
    }

    pub fn observe_malloc(
        &mut self,
        event_id: usize,
        requested_size: u64,
        returned_ptr: u64,
        chunk_size: Option<u64>,
    ) -> HeapTrackerNote {
        if returned_ptr == 0 {
            return HeapTrackerNote::NullMalloc;
        }

        let Some(chunk) = self.chunks.get_mut(&returned_ptr) else {
            self.chunks.insert(
                returned_ptr,
                ObservedChunk {
                    user_addr: returned_ptr,
                    last_requested_size: Some(requested_size),
                    last_chunk_size: chunk_size,
                    state: ObservedChunkState::Allocated,
                    first_seen_event_id: event_id,
                    last_seen_event_id: event_id,
                },
            );
            return HeapTrackerNote::NewAllocation;
        };

        chunk.last_seen_event_id = event_id;
        chunk.last_requested_size = Some(requested_size);
        chunk.last_chunk_size = chunk_size;

        match chunk.state {
            ObservedChunkState::Freed => {
                chunk.state = ObservedChunkState::Allocated;
                HeapTrackerNote::ReusedFreedChunk
            }
            ObservedChunkState::Allocated => HeapTrackerNote::AllocatedPointerReturnedAgain,
        }
    }

    pub fn observe_free(&mut self, event_id: usize, ptr: u64) -> HeapTrackerNote {
        if ptr == 0 {
            return HeapTrackerNote::NullFree;
        }

        let Some(chunk) = self.chunks.get_mut(&ptr) else {
            return HeapTrackerNote::FreeUnknownPointer;
        };

        chunk.last_seen_event_id = event_id;
        match chunk.state {
            ObservedChunkState::Allocated => {
                chunk.state = ObservedChunkState::Freed;
                HeapTrackerNote::FreedKnownChunk
            }
            ObservedChunkState::Freed => HeapTrackerNote::DoubleFree,
        }
    }

    pub fn observe_calloc(
        &mut self,
        event_id: usize,
        nmemb: u64,
        size: u64,
        returned_ptr: u64,
        chunk_size: Option<u64>,
    ) -> HeapTrackerNote {
        if returned_ptr == 0 {
            return HeapTrackerNote::NullCalloc;
        }

        let requested_size = nmemb.checked_mul(size).unwrap_or(u64::MAX);
        self.observe_malloc(event_id, requested_size, returned_ptr, chunk_size)
    }

    pub fn observe_realloc(
        &mut self,
        event_id: usize,
        old_ptr: u64,
        new_size: u64,
        returned_ptr: u64,
        new_chunk_size: Option<u64>,
    ) -> HeapTrackerNote {
        if old_ptr == 0 {
            if returned_ptr != 0 {
                self.observe_malloc(event_id, new_size, returned_ptr, new_chunk_size);
            }
            return HeapTrackerNote::ReallocNullActsLikeMalloc;
        }

        if returned_ptr == old_ptr {
            if let Some(chunk) = self.chunks.get_mut(&old_ptr) {
                chunk.state = ObservedChunkState::Allocated;
                chunk.last_seen_event_id = event_id;
                chunk.last_requested_size = Some(new_size);
                chunk.last_chunk_size = new_chunk_size;
            }
            return HeapTrackerNote::ReallocInPlace;
        }

        if returned_ptr != 0 {
            let old_known = if let Some(old_chunk) = self.chunks.get_mut(&old_ptr) {
                old_chunk.state = ObservedChunkState::Freed;
                old_chunk.last_seen_event_id = event_id;
                true
            } else {
                false
            };

            self.observe_malloc(event_id, new_size, returned_ptr, new_chunk_size);
            return if old_known {
                HeapTrackerNote::ReallocMovedAllocation
            } else {
                HeapTrackerNote::ReallocUnknownOldPointer
            };
        }

        if new_size == 0 {
            if let Some(old_chunk) = self.chunks.get_mut(&old_ptr) {
                old_chunk.state = ObservedChunkState::Freed;
                old_chunk.last_seen_event_id = event_id;
            }
            return HeapTrackerNote::ReallocPtrZeroFreedOldPointer;
        }

        HeapTrackerNote::ReallocFailedKeepsOldPointer
    }
}

pub fn explain_event(event: &HeapTraceEvent, note: HeapTrackerNote) -> HeapTrackerExplanation {
    if note != HeapTrackerNote::ReusedFreedChunk {
        return HeapTrackerExplanation::NoExtraExplanation;
    }

    let chunk = match event {
        HeapTraceEvent::Malloc {
            chunk: Some(chunk), ..
        }
        | HeapTraceEvent::Calloc {
            chunk: Some(chunk), ..
        }
        | HeapTraceEvent::Realloc {
            new_chunk: Some(chunk),
            ..
        } => chunk,
        _ => return HeapTrackerExplanation::NoExtraExplanation,
    };

    // Approximation for now; this should become glibc-version-aware later.
    if chunk.size <= 0x80 {
        HeapTrackerExplanation::LikelyTcacheOrFastbinReuse {
            chunk_size: chunk.size,
        }
    } else {
        HeapTrackerExplanation::NoExtraExplanation
    }
}

#[cfg(test)]
mod tests {
    use super::{explain_event, HeapTracker, HeapTrackerExplanation, HeapTrackerNote};
    use crate::glibc::{ChunkFlags, GlibcChunkHeader};
    use crate::HeapTraceEvent;

    #[test]
    fn new_malloc_returns_new_allocation() {
        let mut tracker = HeapTracker::new();

        let note = tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));

        assert_eq!(note, HeapTrackerNote::NewAllocation);
    }

    #[test]
    fn malloc_reusing_freed_pointer_returns_reused_freed_chunk() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));
        tracker.observe_free(2, 0x1000);

        let note = tracker.observe_malloc(3, 0x20, 0x1000, Some(0x30));

        assert_eq!(note, HeapTrackerNote::ReusedFreedChunk);
    }

    #[test]
    fn free_allocated_pointer_returns_freed_known_chunk() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));

        let note = tracker.observe_free(2, 0x1000);

        assert_eq!(note, HeapTrackerNote::FreedKnownChunk);
    }

    #[test]
    fn double_free_returns_double_free() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));
        tracker.observe_free(2, 0x1000);

        let note = tracker.observe_free(3, 0x1000);

        assert_eq!(note, HeapTrackerNote::DoubleFree);
    }

    #[test]
    fn free_unknown_pointer_returns_free_unknown_pointer() {
        let mut tracker = HeapTracker::new();

        let note = tracker.observe_free(1, 0x1000);

        assert_eq!(note, HeapTrackerNote::FreeUnknownPointer);
    }

    #[test]
    fn malloc_returning_zero_returns_null_malloc() {
        let mut tracker = HeapTracker::new();

        let note = tracker.observe_malloc(1, 0x20, 0, None);

        assert_eq!(note, HeapTrackerNote::NullMalloc);
    }

    #[test]
    fn free_zero_returns_null_free() {
        let mut tracker = HeapTracker::new();

        let note = tracker.observe_free(1, 0);

        assert_eq!(note, HeapTrackerNote::NullFree);
    }

    #[test]
    fn calloc_returning_non_null_behaves_like_new_allocation() {
        let mut tracker = HeapTracker::new();

        let note = tracker.observe_calloc(1, 4, 0x10, 0x1000, Some(0x50));

        assert_eq!(note, HeapTrackerNote::NewAllocation);
        assert_eq!(
            tracker.state_for_user_addr(0x1000),
            Some(super::ObservedChunkState::Allocated)
        );
        assert_eq!(
            tracker.get_chunk(0x1000).unwrap().last_requested_size,
            Some(0x40)
        );
    }

    #[test]
    fn calloc_returning_zero_returns_null_calloc() {
        let mut tracker = HeapTracker::new();

        let note = tracker.observe_calloc(1, 4, 0x10, 0, None);

        assert_eq!(note, HeapTrackerNote::NullCalloc);
    }

    #[test]
    fn realloc_null_marks_returned_pointer_allocated() {
        let mut tracker = HeapTracker::new();

        let note = tracker.observe_realloc(1, 0, 0x80, 0x2000, Some(0x90));

        assert_eq!(note, HeapTrackerNote::ReallocNullActsLikeMalloc);
        assert_eq!(
            tracker.state_for_user_addr(0x2000),
            Some(super::ObservedChunkState::Allocated)
        );
    }

    #[test]
    fn realloc_in_place_keeps_pointer_allocated() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));

        let note = tracker.observe_realloc(2, 0x1000, 0x80, 0x1000, Some(0x90));

        assert_eq!(note, HeapTrackerNote::ReallocInPlace);
        assert_eq!(
            tracker.state_for_user_addr(0x1000),
            Some(super::ObservedChunkState::Allocated)
        );
        assert_eq!(
            tracker.get_chunk(0x1000).unwrap().last_requested_size,
            Some(0x80)
        );
    }

    #[test]
    fn realloc_moved_marks_old_freed_and_new_allocated() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));

        let note = tracker.observe_realloc(2, 0x1000, 0x80, 0x2000, Some(0x90));

        assert_eq!(note, HeapTrackerNote::ReallocMovedAllocation);
        assert_eq!(
            tracker.state_for_user_addr(0x1000),
            Some(super::ObservedChunkState::Freed)
        );
        assert_eq!(
            tracker.state_for_user_addr(0x2000),
            Some(super::ObservedChunkState::Allocated)
        );
    }

    #[test]
    fn realloc_failed_with_nonzero_size_keeps_old_allocated() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));

        let note = tracker.observe_realloc(2, 0x1000, 0x80, 0, None);

        assert_eq!(note, HeapTrackerNote::ReallocFailedKeepsOldPointer);
        assert_eq!(
            tracker.state_for_user_addr(0x1000),
            Some(super::ObservedChunkState::Allocated)
        );
    }

    #[test]
    fn realloc_zero_size_with_null_return_marks_old_freed_if_known() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));

        let note = tracker.observe_realloc(2, 0x1000, 0, 0, None);

        assert_eq!(note, HeapTrackerNote::ReallocPtrZeroFreedOldPointer);
        assert_eq!(
            tracker.state_for_user_addr(0x1000),
            Some(super::ObservedChunkState::Freed)
        );
    }

    #[test]
    fn unknown_address_state_query_returns_none() {
        let tracker = HeapTracker::new();

        assert_eq!(tracker.state_for_user_addr(0x1000), None);
        assert!(tracker.get_chunk(0x1000).is_none());
    }

    #[test]
    fn after_malloc_state_query_returns_allocated() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));

        assert_eq!(
            tracker.state_for_user_addr(0x1000),
            Some(super::ObservedChunkState::Allocated)
        );
        assert_eq!(tracker.get_chunk(0x1000).unwrap().user_addr, 0x1000);
    }

    #[test]
    fn after_free_state_query_returns_freed() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 0x20, 0x1000, Some(0x30));
        tracker.observe_free(2, 0x1000);

        assert_eq!(
            tracker.state_for_user_addr(0x1000),
            Some(super::ObservedChunkState::Freed)
        );
    }

    #[test]
    fn reused_malloc_with_small_chunk_explains_likely_tcache_or_fastbin_reuse() {
        let event = malloc_event_with_chunk_size(1, 0x30);

        let explanation = explain_event(&event, HeapTrackerNote::ReusedFreedChunk);

        assert_eq!(
            explanation,
            HeapTrackerExplanation::LikelyTcacheOrFastbinReuse { chunk_size: 0x30 }
        );
    }

    #[test]
    fn reused_malloc_with_large_chunk_has_no_extra_explanation() {
        let event = malloc_event_with_chunk_size(1, 0x90);

        let explanation = explain_event(&event, HeapTrackerNote::ReusedFreedChunk);

        assert_eq!(explanation, HeapTrackerExplanation::NoExtraExplanation);
    }

    #[test]
    fn new_allocation_has_no_extra_explanation() {
        let event = malloc_event_with_chunk_size(1, 0x30);

        let explanation = explain_event(&event, HeapTrackerNote::NewAllocation);

        assert_eq!(explanation, HeapTrackerExplanation::NoExtraExplanation);
    }

    #[test]
    fn free_event_has_no_extra_explanation() {
        let event = HeapTraceEvent::Free {
            event_id: 1,
            ptr: 0x1000,
            chunk: Some(chunk_header(0x30)),
            tcache_entry: None,
            caller_addr: None,
        };

        let explanation = explain_event(&event, HeapTrackerNote::ReusedFreedChunk);

        assert_eq!(explanation, HeapTrackerExplanation::NoExtraExplanation);
    }

    #[test]
    fn calloc_event_with_new_allocation_has_no_extra_explanation() {
        let event = HeapTraceEvent::Calloc {
            event_id: 1,
            nmemb: 4,
            size: 0x10,
            returned_ptr: 0x1000,
            chunk: Some(chunk_header(0x50)),
            caller_addr: None,
        };

        let explanation = explain_event(&event, HeapTrackerNote::NewAllocation);

        assert_eq!(explanation, HeapTrackerExplanation::NoExtraExplanation);
    }

    fn malloc_event_with_chunk_size(event_id: usize, chunk_size: u64) -> HeapTraceEvent {
        HeapTraceEvent::Malloc {
            event_id,
            requested_size: 0x20,
            returned_ptr: 0x1000,
            chunk: Some(chunk_header(chunk_size)),
            caller_addr: None,
        }
    }

    fn chunk_header(size: u64) -> GlibcChunkHeader {
        GlibcChunkHeader {
            chunk_addr: 0xff0,
            user_addr: 0x1000,
            prev_size: 0,
            size_raw: size | 0x1,
            size,
            flags: ChunkFlags::from_size_raw(size | 0x1),
        }
    }
}
