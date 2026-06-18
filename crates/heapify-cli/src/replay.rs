use super::*;

#[derive(Debug, Clone)]
pub(crate) struct ReplayConfig {
    pub(crate) events_only: bool,
    pub(crate) show_chunks: bool,
    pub(crate) tui: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            events_only: false,
            show_chunks: true,
            tui: false,
        }
    }
}

pub(crate) fn replay_config_from_render_config(config: &RenderConfig) -> ReplayConfig {
    ReplayConfig {
        events_only: config.events_only(),
        show_chunks: config.show_chunks,
        tui: false,
    }
}

pub struct ReplaySession {
    pub records: Vec<json::JsonTraceRecord>,
    pub events: Vec<ReplayEventEntry>,
    pub session_start: Option<json::JsonTraceRecord>,
    pub session_end: Option<json::JsonTraceRecord>,
    pub allocator_states_by_event_id: BTreeMap<usize, ReplayEventAllocatorState>,
    pub allocator_deltas_by_event_id: BTreeMap<usize, ReplayEventAllocatorDelta>,
}

pub struct ReplayEventEntry {
    pub event_id: usize,
    pub record_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayEventAllocatorState {
    pub event_id: usize,
    pub tcache_candidate_chunks: usize,
    pub fastbin_chunks: usize,
    pub unsorted_chunks: usize,
    pub smallbin_chunks: usize,
    pub largebin_chunks: usize,
    pub total_free_list_chunks: usize,
    pub warning_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayEventAllocatorDelta {
    pub event_id: usize,
    pub tcache_candidate_chunks_delta: isize,
    pub fastbin_chunks_delta: isize,
    pub unsorted_chunks_delta: isize,
    pub smallbin_chunks_delta: isize,
    pub largebin_chunks_delta: isize,
    pub total_free_list_chunks_delta: isize,
    pub warning_count_delta: isize,
}

impl ReplaySession {
    pub(crate) fn from_records(records: Vec<json::JsonTraceRecord>) -> Self {
        let session_start = records
            .iter()
            .find(|record| matches!(record, json::JsonTraceRecord::SessionStart { .. }))
            .cloned();
        let session_end = records
            .iter()
            .rev()
            .find(|record| matches!(record, json::JsonTraceRecord::SessionEnd { .. }))
            .cloned();
        let events = records
            .iter()
            .enumerate()
            .filter_map(|(record_index, record)| {
                let json::JsonTraceRecord::Event { event } = record else {
                    return None;
                };

                Some(ReplayEventEntry {
                    event_id: replay_event_id(event),
                    record_index,
                })
            })
            .collect();
        let allocator_states_by_event_id = records
            .iter()
            .filter_map(|record| {
                let json::JsonTraceRecord::AllocatorSourceSummary {
                    event_id,
                    tcache_candidate_chunks,
                    fastbin_chunks,
                    unsorted_chunks,
                    smallbin_chunks,
                    largebin_chunks,
                    total_free_list_chunks,
                    warning_count,
                } = record
                else {
                    return None;
                };

                Some((
                    *event_id,
                    ReplayEventAllocatorState {
                        event_id: *event_id,
                        tcache_candidate_chunks: *tcache_candidate_chunks,
                        fastbin_chunks: *fastbin_chunks,
                        unsorted_chunks: *unsorted_chunks,
                        smallbin_chunks: *smallbin_chunks,
                        largebin_chunks: *largebin_chunks,
                        total_free_list_chunks: *total_free_list_chunks,
                        warning_count: *warning_count,
                    },
                ))
            })
            .collect();
        let allocator_deltas_by_event_id = records
            .iter()
            .filter_map(|record| {
                let json::JsonTraceRecord::AllocatorSourceDelta {
                    event_id,
                    tcache_candidate_chunks_delta,
                    fastbin_chunks_delta,
                    unsorted_chunks_delta,
                    smallbin_chunks_delta,
                    largebin_chunks_delta,
                    total_free_list_chunks_delta,
                    warning_count_delta,
                } = record
                else {
                    return None;
                };

                Some((
                    *event_id,
                    ReplayEventAllocatorDelta {
                        event_id: *event_id,
                        tcache_candidate_chunks_delta: *tcache_candidate_chunks_delta,
                        fastbin_chunks_delta: *fastbin_chunks_delta,
                        unsorted_chunks_delta: *unsorted_chunks_delta,
                        smallbin_chunks_delta: *smallbin_chunks_delta,
                        largebin_chunks_delta: *largebin_chunks_delta,
                        total_free_list_chunks_delta: *total_free_list_chunks_delta,
                        warning_count_delta: *warning_count_delta,
                    },
                ))
            })
            .collect();

        Self {
            records,
            events,
            session_start,
            session_end,
            allocator_states_by_event_id,
            allocator_deltas_by_event_id,
        }
    }

    pub(crate) fn event_count(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn event_record(
        &self,
        selected_event_index: usize,
    ) -> Option<&json::JsonTraceRecord> {
        let event = self.events.get(selected_event_index)?;
        self.records.get(event.record_index)
    }

    pub(crate) fn records_for_event(&self, event_id: usize) -> Vec<&json::JsonTraceRecord> {
        self.records
            .iter()
            .filter(|record| replay_record_event_id(record) == Some(event_id))
            .collect()
    }
}

pub(crate) struct ReplayTuiState {
    pub(crate) selected_event_index: usize,
    pub(crate) scroll_details: u16,
}
