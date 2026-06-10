pub mod allocator_sources;
pub mod glibc;
pub mod heap_scan;
pub mod tcache;
pub mod tracker;

use glibc::{GlibcChunkHeader, TcacheEntryCandidate};

#[derive(Debug, Clone)]
pub enum HeapTraceEvent {
    Malloc {
        event_id: usize,
        requested_size: u64,
        returned_ptr: u64,
        chunk: Option<GlibcChunkHeader>,
        caller_addr: Option<u64>,
    },
    Free {
        event_id: usize,
        ptr: u64,
        chunk: Option<GlibcChunkHeader>,
        tcache_entry: Option<TcacheEntryCandidate>,
        caller_addr: Option<u64>,
    },
    Calloc {
        event_id: usize,
        nmemb: u64,
        size: u64,
        returned_ptr: u64,
        chunk: Option<GlibcChunkHeader>,
        caller_addr: Option<u64>,
    },
    Realloc {
        event_id: usize,
        old_ptr: u64,
        new_size: u64,
        returned_ptr: u64,
        old_chunk: Option<GlibcChunkHeader>,
        new_chunk: Option<GlibcChunkHeader>,
        caller_addr: Option<u64>,
    },
}
