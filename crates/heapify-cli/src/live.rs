#![allow(dead_code)]

use super::*;
pub struct LiveTuiApp {
    pub events: Vec<json::JsonTraceRecord>,
    pub related_by_event_id: BTreeMap<usize, Vec<json::JsonTraceRecord>>,
    pub selected_index: usize,
    pub follow_tail: bool,
    pub session_start: Option<JsonSessionStart>,
    pub session_end: Option<JsonSessionEnd>,
    pub status_line: String,
    pub target_status: LiveTargetStatus,
    pub next_command_id: u64,
    pub last_command: Option<LiveCommand>,
    pub last_command_status: Option<LiveCommandStatus>,
    pub last_command_message: Option<String>,
    pub last_break_match: Option<AllocatorBreakMatch>,
    pub latest_stop_reason: Option<DebuggerStopReason>,
    pub follow_tail_before_pause: Option<bool>,
    pub latest_heap_layout: Option<json::JsonTraceRecord>,
    pub latest_allocator_summary: Option<json::JsonTraceRecord>,
    pub latest_allocator_delta: Option<json::JsonTraceRecord>,
    pub latest_allocator_warnings: Option<json::JsonTraceRecord>,
    pub latest_heap_scan: Option<json::JsonTraceRecord>,
    pub latest_register_snapshot: Option<RegisterSnapshot>,
    pub previous_register_snapshot: Option<RegisterSnapshot>,
    pub changed_registers: BTreeSet<String>,
    pub register_snapshots_by_event_id: BTreeMap<usize, RegisterSnapshot>,
    pub latest_code_context: Option<CodeContext>,
    pub code_context_by_event_id: BTreeMap<usize, CodeContext>,
    pub latest_stack_snapshot: Option<StackSnapshot>,
    pub stack_snapshots_by_event_id: BTreeMap<usize, StackSnapshot>,
    pub latest_process_maps: Option<ProcessMapsSnapshot>,
    pub latest_memory_inspection: Option<MemoryInspectionSnapshot>,
    pub user_breakpoints: Vec<UserBreakpoint>,
    pub selected_user_breakpoint_index: Option<usize>,
    pub breakpoint_tab_scroll: usize,
    pub code_view_address: Option<u64>,
    pub code_view_breakpoint_id: Option<UserBreakpointId>,
    pub focused_debugger_pane: LiveDebuggerPane,
    pub active_right_tab: LiveRightTab,
    pub logs: VecDeque<String>,
    pub focused_pane: LiveTuiPane,
    pub register_pane_scroll: usize,
    pub code_pane_scroll: usize,
    pub source_pane_scroll: usize,
    pub code_follow_rip: bool,
    pub code_pane_mode: CodePaneMode,
    pub event_details_scroll: usize,
    pub heap_layout_scroll: usize,
    pub allocator_scan_scroll: usize,
    pub related_records_scroll: usize,
    pub stack_tab_scroll: usize,
    pub maps_tab_scroll: usize,
    pub memory_tab_scroll: usize,
    pub memory_view_format: MemoryViewFormat,
    pub memory_selected_row: Option<usize>,
    pub latest_memory_request: Option<MemoryInspectionRequest>,
    pub selected_chunk_index: Option<usize>,
    pub selected_chunk_addr: Option<u64>,
    pub selected_chunk_user_addr: Option<u64>,
    pub show_chunk_inspector: bool,
    pub chunk_inspector_scroll: usize,
    pub search_prompt_active: bool,
    pub search_prompt_input: String,
    pub search_status: Option<String>,
    pub console_input_active: bool,
    pub console_input: String,
    pub console_history: Vec<String>,
    pub console_history_index: Option<usize>,
    pub show_heap_pane: bool,
    pub show_scan_pane: bool,
}

fn parse_summary_source_location(text: &str) -> Option<SourceLocation> {
    if text == "unknown" {
        return Some(SourceLocation {
            file: None,
            line: None,
            column: None,
        });
    }
    if let Some(line) = text.strip_prefix(':') {
        return Some(SourceLocation {
            file: None,
            line: line.parse().ok(),
            column: None,
        });
    }
    let (file, line) = text.rsplit_once(':')?;
    Some(SourceLocation {
        file: Some(file.to_string()),
        line: line.parse().ok(),
        column: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveDebuggerPane {
    Registers,
    Code,
    Trace,
    Console,
    RightTab,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveRightTab {
    Heap,
    Stack,
    Logs,
    Maps,
    Breakpoints,
    Memory,
}

impl LiveRightTab {
    pub(crate) fn label(self) -> &'static str {
        match self {
            LiveRightTab::Heap => "heap",
            LiveRightTab::Stack => "stack",
            LiveRightTab::Logs => "logs",
            LiveRightTab::Maps => "maps",
            LiveRightTab::Breakpoints => "breaks",
            LiveRightTab::Memory => "memory",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedRegisterLine {
    pub name: String,
    pub value: String,
    pub role: Option<RegisterRole>,
    pub changed: bool,
    pub annotation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeContext {
    pub instruction_pointer: u64,
    pub symbol: Option<String>,
    pub symbol_addr: Option<u64>,
    pub symbol_offset: Option<u64>,
    pub object: Option<String>,
    pub source: Option<SourceLocation>,
    pub source_context: Option<SourceContext>,
    pub disassembly: Option<DisassemblySnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceContext {
    pub path: String,
    pub line: u64,
    pub column: Option<u64>,
    pub lines: Vec<SourceLine>,
    pub truncated: bool,
    pub read_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLine {
    pub number: u64,
    pub text: String,
    pub is_current: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePaneMode {
    Disassembly,
    Source,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressRegionKind {
    Heap,
    Stack,
    Code,
    Libc,
    Loader,
    MappedFile,
    Anonymous,
    Vdso,
    Vvar,
    Vsvar,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeapAddressDetail {
    ChunkHeader {
        chunk_addr: u64,
        user_addr: u64,
    },
    UserPointer {
        chunk_addr: u64,
        user_addr: u64,
    },
    Interior {
        chunk_addr: u64,
        user_addr: u64,
        offset: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressClassification {
    pub address: u64,
    pub kind: AddressRegionKind,
    pub label: String,
    pub map: Option<ProcessMapEntry>,
    pub heap_detail: Option<HeapAddressDetail>,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInspectionSnapshot {
    pub requested_address: u64,
    pub region_start: Option<u64>,
    pub region_end: Option<u64>,
    pub permissions: Option<String>,
    pub region_label: Option<String>,
    pub classification: AddressClassification,
    pub rows: Vec<MemoryInspectionRow>,
    pub truncated: bool,
    pub read_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInspectionRow {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub word_value: Option<u64>,
    pub ascii: Option<String>,
    pub annotation: Option<String>,
}

impl AddressClassification {
    pub(crate) fn short_label(&self) -> &str {
        &self.label
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapSearchMode {
    AnyAddress,
    UserAddress,
    ChunkAddress,
    Size,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapSearchQuery {
    AnyAddress(u64),
    UserAddress(u64),
    ChunkAddress(u64),
    Size(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleCommand {
    Help,
    Continue,
    Pause,
    Resume,
    NextAllocatorEvent,
    StepInstruction,
    StepInstructionOver,
    SourceStep,
    SourceStepOver,
    Stop,
    Registers,
    Disassemble,
    Source,
    Stack,
    Maps,
    HeapJump(HeapSearchQuery),
    InspectMemory(MemoryInspectionRequest),
    BreakAddress(u64),
    BreakSymbol(String),
    BreakSourceLine { path: String, line: u64 },
    InfoBreakpoints,
    DeleteBreakpoint(UserBreakpointId),
    EnableBreakpoint(UserBreakpointId),
    DisableBreakpoint(UserBreakpointId),
    SelectRightTab(LiveRightTab),
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveTuiPane {
    Events,
    EventDetails,
    HeapLayout,
    AllocatorScan,
    RelatedRecords,
}

impl Default for LiveTuiApp {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            related_by_event_id: BTreeMap::new(),
            selected_index: 0,
            follow_tail: true,
            session_start: None,
            session_end: None,
            status_line: "tracing...".to_string(),
            target_status: LiveTargetStatus::Running,
            next_command_id: 1,
            last_command: None,
            last_command_status: None,
            last_command_message: None,
            last_break_match: None,
            latest_stop_reason: None,
            follow_tail_before_pause: None,
            latest_heap_layout: None,
            latest_allocator_summary: None,
            latest_allocator_delta: None,
            latest_allocator_warnings: None,
            latest_heap_scan: None,
            latest_register_snapshot: None,
            previous_register_snapshot: None,
            changed_registers: BTreeSet::new(),
            register_snapshots_by_event_id: BTreeMap::new(),
            latest_code_context: None,
            code_context_by_event_id: BTreeMap::new(),
            latest_stack_snapshot: None,
            stack_snapshots_by_event_id: BTreeMap::new(),
            latest_process_maps: None,
            latest_memory_inspection: None,
            user_breakpoints: Vec::new(),
            selected_user_breakpoint_index: None,
            breakpoint_tab_scroll: 0,
            code_view_address: None,
            code_view_breakpoint_id: None,
            focused_debugger_pane: LiveDebuggerPane::Trace,
            active_right_tab: LiveRightTab::Heap,
            logs: VecDeque::new(),
            focused_pane: LiveTuiPane::Events,
            register_pane_scroll: 0,
            code_pane_scroll: 0,
            source_pane_scroll: 0,
            code_follow_rip: true,
            code_pane_mode: CodePaneMode::Disassembly,
            event_details_scroll: 0,
            heap_layout_scroll: 0,
            allocator_scan_scroll: 0,
            related_records_scroll: 0,
            stack_tab_scroll: 0,
            maps_tab_scroll: 0,
            memory_tab_scroll: 0,
            memory_view_format: MemoryViewFormat::HexWords,
            memory_selected_row: None,
            latest_memory_request: None,
            selected_chunk_index: None,
            selected_chunk_addr: None,
            selected_chunk_user_addr: None,
            show_chunk_inspector: false,
            chunk_inspector_scroll: 0,
            search_prompt_active: false,
            search_prompt_input: String::new(),
            search_status: None,
            console_input_active: false,
            console_input: String::new(),
            console_history: Vec::new(),
            console_history_index: None,
            show_heap_pane: true,
            show_scan_pane: true,
        }
    }
}

impl LiveTuiApp {
    pub(crate) fn apply_update(&mut self, update: LiveTraceUpdate) {
        match update {
            LiveTraceUpdate::SessionStart(session) => {
                self.session_start = Some(session);
                self.status_line = "tracing...".to_string();
                self.push_log_line("session started");
            }
            LiveTraceUpdate::Event {
                event,
                note,
                explanation,
                caller_symbol,
                ..
            } => {
                self.events
                    .push(json::json_trace_event_record_with_caller_symbol(
                        &event,
                        note,
                        explanation,
                        caller_symbol.as_ref(),
                    ));
                if self.follow_tail
                    && matches!(
                        self.target_status,
                        LiveTargetStatus::Running | LiveTargetStatus::SteppingToNextAllocatorEvent
                    )
                {
                    self.selected_index = self.events.len().saturating_sub(1);
                }
                self.status_line = format!("tracing... {} events", self.events.len());
            }
            LiveTraceUpdate::RelatedRecord { event_id, record } => {
                self.apply_latest_related_record(&record);
                self.related_by_event_id
                    .entry(event_id)
                    .or_default()
                    .push(record);
            }
            LiveTraceUpdate::Status { message } => {
                self.push_log_line(message.clone());
                self.status_line = message;
            }
            LiveTraceUpdate::CommandStatus {
                command,
                status,
                target_status,
                message,
                ..
            } => {
                self.apply_command_status(command, status, target_status, message);
            }
            LiveTraceUpdate::ProcessMaps { snapshot } => {
                self.latest_process_maps = Some(snapshot);
            }
            LiveTraceUpdate::MemoryInspection { snapshot } => {
                self.latest_memory_request = Some(MemoryInspectionRequest {
                    address: snapshot.requested_address,
                    count: match snapshot.rows.first() {
                        Some(row) if row.word_value.is_some() => snapshot.rows.len().max(1),
                        _ => snapshot
                            .rows
                            .iter()
                            .map(|row| row.bytes.len())
                            .sum::<usize>()
                            .max(1),
                    },
                    format: if snapshot
                        .rows
                        .first()
                        .and_then(|row| row.word_value)
                        .is_some()
                    {
                        MemoryViewFormat::HexWords
                    } else {
                        MemoryViewFormat::HexBytes
                    },
                });
                self.latest_memory_inspection = Some(snapshot);
                self.active_right_tab = LiveRightTab::Memory;
                self.focused_debugger_pane = LiveDebuggerPane::RightTab;
                self.memory_selected_row = self
                    .latest_memory_inspection
                    .as_ref()
                    .and_then(|snapshot| (!snapshot.rows.is_empty()).then_some(0));
                self.memory_tab_scroll = 0;
                self.sync_legacy_focus_from_debugger_pane();
            }
            LiveTraceUpdate::RegisterSnapshot { event_id, snapshot } => {
                let previous = self.latest_register_snapshot.clone();
                self.changed_registers = diff_register_snapshots(previous.as_ref(), &snapshot);
                self.previous_register_snapshot = previous;
                self.latest_register_snapshot = Some(snapshot.clone());
                if let Some(event_id) = event_id {
                    self.register_snapshots_by_event_id
                        .insert(event_id, snapshot);
                }
            }
            LiveTraceUpdate::StackSnapshot { event_id, snapshot } => {
                let snapshot = annotate_stack_snapshot(
                    snapshot,
                    self.latest_process_maps.as_ref(),
                    self.latest_heap_layout.as_ref(),
                    self.latest_register_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.instruction_pointer),
                );
                self.latest_stack_snapshot = Some(snapshot.clone());
                if let Some(event_id) = event_id {
                    self.stack_snapshots_by_event_id.insert(event_id, snapshot);
                }
            }
            LiveTraceUpdate::CodeContext { event_id, context } => {
                self.latest_code_context = Some(context.clone());
                if self.code_follow_rip {
                    self.recenter_code_on_rip();
                }
                if let Some(event_id) = event_id {
                    self.code_context_by_event_id.insert(event_id, context);
                }
            }
            LiveTraceUpdate::CodeInspection {
                address,
                breakpoint_id,
            } => {
                self.code_view_address = Some(address);
                self.code_view_breakpoint_id = breakpoint_id;
                self.code_follow_rip = false;
                self.focused_debugger_pane = LiveDebuggerPane::Code;
                self.sync_legacy_focus_from_debugger_pane();
                if let Some(id) = breakpoint_id {
                    self.push_log_line(format!(
                        "inspecting breakpoint {} at 0x{address:x}",
                        id.as_u64()
                    ));
                }
            }
            LiveTraceUpdate::BreakMatched(break_match) => {
                self.apply_break_match(break_match);
            }
            LiveTraceUpdate::UserBreakpoints { breakpoints } => {
                let selected_id = self.selected_breakpoint_id();
                self.user_breakpoints = breakpoints;
                self.normalize_selected_user_breakpoint_with_previous_id(selected_id);
            }
            LiveTraceUpdate::SessionEnd(session) => {
                let (exit_status, event_count) = match &session.record {
                    json::JsonTraceRecord::SessionEnd {
                        exit_status,
                        event_count,
                    } => (exit_status.clone(), *event_count),
                    _ => ("unknown".to_string(), self.events.len()),
                };
                self.session_end = Some(session);
                self.target_status = LiveTargetStatus::Exited;
                self.latest_stop_reason = Some(DebuggerStopReason::ProcessExit {
                    status: exit_status.clone(),
                });
                self.status_line =
                    format!("target exited: {exit_status}; {event_count} events; press q to quit");
                self.push_log_line(self.status_line.clone());
            }
        }
        self.clamp_scrolls_to_content();
    }

    pub(crate) fn push_log_line(&mut self, line: impl Into<String>) {
        const MAX_LOG_LINES: usize = 200;
        self.logs.push_back(line.into());
        while self.logs.len() > MAX_LOG_LINES {
            self.logs.pop_front();
        }
    }

    pub(crate) fn push_console_output(&mut self, line: impl Into<String>) {
        self.push_log_line(line);
    }

    pub(crate) fn selected_event_record(&self) -> Option<&json::JsonTraceRecord> {
        self.events.get(self.selected_index)
    }

    pub(crate) fn selected_event_id(&self) -> Option<usize> {
        self.selected_event_record()
            .and_then(replay_record_event_id)
    }

    pub(crate) fn select_previous(&mut self) {
        self.follow_tail = false;
        self.selected_index = self.selected_index.saturating_sub(1);
        self.reset_selection_scrolls();
    }

    pub(crate) fn select_next(&mut self) {
        let last_index = self.events.len().saturating_sub(1);
        self.follow_tail = false;
        self.selected_index = (self.selected_index + 1).min(last_index);
        self.reset_selection_scrolls();
    }

    pub(crate) fn select_page_up(&mut self) {
        self.follow_tail = false;
        self.selected_index = self.selected_index.saturating_sub(10);
        self.reset_selection_scrolls();
    }

    pub(crate) fn select_page_down(&mut self) {
        let last_index = self.events.len().saturating_sub(1);
        self.follow_tail = false;
        self.selected_index = (self.selected_index + 10).min(last_index);
        self.reset_selection_scrolls();
    }

    pub(crate) fn select_first(&mut self) {
        self.follow_tail = false;
        self.selected_index = 0;
        self.reset_selection_scrolls();
    }

    pub(crate) fn select_latest(&mut self) {
        self.follow_tail = true;
        self.selected_index = self.events.len().saturating_sub(1);
        self.reset_selection_scrolls();
    }

    pub(crate) fn apply_command_status(
        &mut self,
        command: Option<LiveCommand>,
        status: LiveCommandStatus,
        target_status: LiveTargetStatus,
        message: String,
    ) {
        if let Some(reason) =
            Self::infer_debugger_stop_reason(command.clone(), status, target_status, &message)
        {
            self.latest_stop_reason = Some(reason);
        }
        self.target_status = target_status;
        self.last_command = command.clone();
        self.last_command_status = Some(status);
        self.last_command_message = Some(message.clone());
        if target_status == LiveTargetStatus::Paused {
            if self.follow_tail_before_pause.is_none() {
                self.follow_tail_before_pause = Some(self.follow_tail);
            }
            self.follow_tail = false;
        }
        self.status_line = message;
        let command = command
            .as_ref()
            .map(LiveCommand::as_str)
            .unwrap_or("target");
        self.push_log_line(format!(
            "{command}: {} ({})",
            self.status_line,
            status.as_str()
        ));
    }

    pub(crate) fn apply_break_match(&mut self, break_match: AllocatorBreakMatch) {
        self.target_status = LiveTargetStatus::Paused;
        self.follow_tail = false;
        self.follow_tail_before_pause = Some(false);
        self.search_status = None;
        self.status_line = format!(
            "break condition matched: {} after event #{}",
            break_match.message, break_match.event_id
        );
        self.push_log_line(self.status_line.clone());
        if let Some(index) = self
            .events
            .iter()
            .position(|record| replay_record_event_id(record) == Some(break_match.event_id))
        {
            self.selected_index = index;
            self.reset_selection_scrolls();
        }
        if let Some(user_addr) = break_match.user_addr {
            if let Some(index) =
                self.find_chunk_in_latest_layout(HeapSearchQuery::UserAddress(user_addr))
            {
                self.select_chunk_index(index);
                self.focused_pane = LiveTuiPane::HeapLayout;
                self.focused_debugger_pane = LiveDebuggerPane::RightTab;
                self.active_right_tab = LiveRightTab::Heap;
                self.show_heap_pane = true;
                self.show_chunk_inspector = true;
                self.heap_layout_scroll = index.saturating_sub(3);
            }
        }
        self.latest_stop_reason = Some(DebuggerStopReason::AllocatorBreakCondition {
            event_id: break_match.event_id,
            message: break_match.message.clone(),
        });
        self.last_break_match = Some(break_match);
    }

    #[cfg(test)]
    pub(crate) fn inspection_mode(&self) -> bool {
        self.target_status == LiveTargetStatus::Paused
    }

    pub(crate) fn prepare_command(
        &mut self,
        command: LiveCommand,
    ) -> std::result::Result<LiveCommandMessage, String> {
        validate_live_command(self.target_status, command.clone()).map_err(|reason| {
            self.last_command = Some(command.clone());
            self.last_command_status = Some(LiveCommandStatus::Rejected);
            self.last_command_message = Some(reason.clone());
            self.status_line = reason.clone();
            reason
        })?;

        let message = LiveCommandMessage {
            id: LiveCommandId(self.next_command_id),
            command: command.clone(),
        };
        self.next_command_id += 1;
        self.last_command = Some(command.clone());
        self.last_command_status = Some(LiveCommandStatus::Accepted);
        self.last_command_message = Some(format!("{} accepted", command.as_str()));
        Ok(message)
    }

    pub(crate) fn apply_latest_related_record(&mut self, record: &json::JsonTraceRecord) {
        match record {
            json::JsonTraceRecord::HeapLayout { .. } => {
                self.latest_heap_layout = Some(record.clone());
                self.update_selected_chunk_after_layout_update();
            }
            json::JsonTraceRecord::AllocatorSourceSummary { .. } => {
                self.latest_allocator_summary = Some(record.clone());
            }
            json::JsonTraceRecord::AllocatorSourceDelta { .. } => {
                self.latest_allocator_delta = Some(record.clone());
            }
            json::JsonTraceRecord::AllocatorWarnings { .. } => {
                self.latest_allocator_warnings = Some(record.clone());
            }
            json::JsonTraceRecord::HeapScan { .. } => {
                self.latest_heap_scan = Some(record.clone());
            }
            _ => {}
        }
    }

    pub(crate) fn infer_debugger_stop_reason(
        command: Option<LiveCommand>,
        status: LiveCommandStatus,
        target_status: LiveTargetStatus,
        message: &str,
    ) -> Option<DebuggerStopReason> {
        if target_status == LiveTargetStatus::Exited {
            return Some(DebuggerStopReason::ProcessExit {
                status: message.to_string(),
            });
        }
        if target_status != LiveTargetStatus::Paused {
            return None;
        }
        if let Some(reason) = Self::parse_user_breakpoint_hit(message) {
            return Some(reason);
        }
        match (command, status) {
            (Some(LiveCommand::Pause), LiveCommandStatus::Completed) => {
                Some(DebuggerStopReason::UserPause)
            }
            (Some(LiveCommand::StepAllocatorEvent), LiveCommandStatus::Completed) => {
                Self::parse_allocator_event_id(message)
                    .map(|event_id| DebuggerStopReason::AllocatorEventStep { event_id })
            }
            (Some(LiveCommand::StepInstruction), LiveCommandStatus::Completed) => {
                Self::parse_hex_transition(message).map(|(from_rip, to_rip)| {
                    DebuggerStopReason::InstructionStep { from_rip, to_rip }
                })
            }
            (Some(LiveCommand::StepInstructionOver), LiveCommandStatus::Completed) => {
                Self::parse_hex_transition(message).map(|(from_rip, to_rip)| {
                    DebuggerStopReason::InstructionStepOver { from_rip, to_rip }
                })
            }
            (Some(LiveCommand::SourceStep), LiveCommandStatus::Completed) => {
                Self::parse_source_transition(message).map(|(from, to, instructions_executed)| {
                    DebuggerStopReason::SourceStep {
                        from,
                        to,
                        instructions_executed,
                    }
                })
            }
            (Some(LiveCommand::SourceStepOver), LiveCommandStatus::Completed) => {
                Self::parse_source_transition(message).map(|(from, to, instructions_executed)| {
                    DebuggerStopReason::SourceStepOver {
                        from,
                        to,
                        instructions_executed,
                    }
                })
            }
            (
                Some(LiveCommand::StepInstruction | LiveCommand::StepInstructionOver),
                LiveCommandStatus::Failed,
            ) if message.contains("stopped by SIG") => {
                let signal = Self::parse_signal_number_from_debug_label(message).unwrap_or(0);
                let instruction_pointer = Self::parse_rip_from_message(message);
                Some(DebuggerStopReason::Signal {
                    signal,
                    instruction_pointer,
                })
            }
            _ => None,
        }
    }

    fn parse_source_transition(message: &str) -> Option<(SourceLocation, SourceLocation, u64)> {
        let (_, rest) = message.split_once(": ")?;
        let (from, rest) = rest.split_once(" -> ")?;
        let (to, rest) = rest.split_once(" after ")?;
        let instructions = rest.strip_suffix(" instructions")?.parse().ok()?;
        let from = parse_summary_source_location(from)?;
        let to = if to.starts_with(':') {
            SourceLocation {
                file: from.file.clone(),
                line: to.strip_prefix(':')?.parse().ok(),
                column: None,
            }
        } else {
            parse_summary_source_location(to)?
        };
        Some((from, to, instructions))
    }

    fn parse_user_breakpoint_hit(message: &str) -> Option<DebuggerStopReason> {
        let rest = message.strip_prefix("breakpoint ")?;
        let (id, rest) = rest.split_once(" hit at ")?;
        let breakpoint_id = UserBreakpointId(id.parse().ok()?);
        let addr = Self::parse_rip_like_hex(rest)?;
        let label = rest
            .split_once('(')
            .and_then(|(_, label)| label.strip_suffix(')'))
            .unwrap_or("")
            .to_string();
        Some(DebuggerStopReason::UserBreakpoint {
            breakpoint_id,
            address: addr,
            label,
        })
    }

    fn parse_rip_like_hex(message: &str) -> Option<u64> {
        let index = message.find("0x")?;
        let hex = message[index + 2..]
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit())
            .collect::<String>();
        u64::from_str_radix(&hex, 16).ok()
    }

    pub(crate) fn parse_hex_transition(message: &str) -> Option<(u64, u64)> {
        let mut values = message
            .split(|ch: char| ch.is_whitespace() || ch == ':' || ch == '-' || ch == '>')
            .filter_map(|token| token.strip_prefix("0x"))
            .filter_map(|hex| u64::from_str_radix(hex, 16).ok());
        Some((values.next()?, values.next()?))
    }

    pub(crate) fn parse_allocator_event_id(message: &str) -> Option<usize> {
        let marker = '#';
        let index = message.find(marker)?;
        let digits = message[index + marker.len_utf8()..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        digits.parse().ok()
    }

    pub(crate) fn parse_rip_from_message(message: &str) -> Option<u64> {
        let marker = "RIP=0x";
        let index = message.find(marker)?;
        let hex = message[index + marker.len()..]
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit())
            .collect::<String>();
        u64::from_str_radix(&hex, 16).ok()
    }

    pub(crate) fn parse_signal_number_from_debug_label(message: &str) -> Option<i32> {
        let signal = message
            .split_whitespace()
            .find(|token| token.starts_with("SIG"))?;
        match signal.trim_end_matches(|ch: char| !ch.is_ascii_alphanumeric()) {
            "SIGILL" => Some(4),
            "SIGTRAP" => Some(5),
            "SIGBUS" => Some(7),
            "SIGFPE" => Some(8),
            "SIGSEGV" => Some(11),
            "SIGSTOP" => Some(19),
            _ => None,
        }
    }

    pub(crate) fn focus_next_pane(&mut self) {
        self.focused_debugger_pane = next_live_debugger_pane(self.focused_debugger_pane, 1);
        self.sync_legacy_focus_from_debugger_pane();
    }

    pub(crate) fn focus_previous_pane(&mut self) {
        self.focused_debugger_pane = next_live_debugger_pane(self.focused_debugger_pane, -1);
        self.sync_legacy_focus_from_debugger_pane();
    }

    pub(crate) fn ensure_focus_visible(&mut self) {
        self.sync_legacy_focus_from_debugger_pane();
    }

    pub(crate) fn scroll_focused(&mut self, amount: isize) {
        match self.focused_debugger_pane {
            LiveDebuggerPane::Registers => {
                self.register_pane_scroll = scroll_delta(self.register_pane_scroll, amount);
            }
            LiveDebuggerPane::Trace => {}
            LiveDebuggerPane::Code => {
                self.code_follow_rip = false;
                match self.code_pane_mode {
                    CodePaneMode::Disassembly => {
                        self.code_pane_scroll = scroll_delta(self.code_pane_scroll, amount)
                    }
                    CodePaneMode::Source => {
                        self.source_pane_scroll = scroll_delta(self.source_pane_scroll, amount)
                    }
                }
            }
            LiveDebuggerPane::RightTab => match self.active_right_tab {
                LiveRightTab::Heap => {
                    if self.show_chunk_inspector {
                        self.chunk_inspector_scroll =
                            scroll_delta(self.chunk_inspector_scroll, amount);
                    } else {
                        self.heap_layout_scroll = scroll_delta(self.heap_layout_scroll, amount);
                    }
                }
                LiveRightTab::Logs => {
                    self.related_records_scroll = scroll_delta(self.related_records_scroll, amount);
                }
                LiveRightTab::Stack => {
                    self.stack_tab_scroll = scroll_delta(self.stack_tab_scroll, amount);
                }
                LiveRightTab::Maps => {
                    self.maps_tab_scroll = scroll_delta(self.maps_tab_scroll, amount);
                }
                LiveRightTab::Breakpoints => {
                    self.breakpoint_tab_scroll = scroll_delta(self.breakpoint_tab_scroll, amount);
                }
                LiveRightTab::Memory => {
                    self.memory_tab_scroll = scroll_delta(self.memory_tab_scroll, amount);
                }
            },
            LiveDebuggerPane::Console => {}
        }
    }

    pub(crate) fn scroll_focused_top(&mut self) {
        match self.focused_debugger_pane {
            LiveDebuggerPane::Registers => self.register_pane_scroll = 0,
            LiveDebuggerPane::Trace => self.select_first(),
            LiveDebuggerPane::Code => {
                self.code_follow_rip = false;
                match self.code_pane_mode {
                    CodePaneMode::Disassembly => self.code_pane_scroll = 0,
                    CodePaneMode::Source => self.source_pane_scroll = 0,
                }
            }
            LiveDebuggerPane::RightTab => match self.active_right_tab {
                LiveRightTab::Heap => {
                    self.heap_layout_scroll = 0;
                    self.allocator_scan_scroll = 0;
                    self.chunk_inspector_scroll = 0;
                }
                LiveRightTab::Logs => self.related_records_scroll = 0,
                LiveRightTab::Stack => self.stack_tab_scroll = 0,
                LiveRightTab::Maps => self.maps_tab_scroll = 0,
                LiveRightTab::Memory => {
                    self.memory_tab_scroll = 0;
                    self.memory_selected_row = self
                        .latest_memory_inspection
                        .as_ref()
                        .and_then(|snapshot| (!snapshot.rows.is_empty()).then_some(0));
                }
                LiveRightTab::Breakpoints => {
                    self.breakpoint_tab_scroll = 0;
                    self.selected_user_breakpoint_index =
                        (!self.user_breakpoints.is_empty()).then_some(0);
                }
            },
            LiveDebuggerPane::Console => {}
        }
    }

    pub(crate) fn scroll_focused_bottom(&mut self) {
        match self.focused_debugger_pane {
            LiveDebuggerPane::Registers => self.register_pane_scroll = usize::MAX,
            LiveDebuggerPane::Trace => self.select_latest(),
            LiveDebuggerPane::Code => {
                self.code_follow_rip = false;
                match self.code_pane_mode {
                    CodePaneMode::Disassembly => self.code_pane_scroll = usize::MAX,
                    CodePaneMode::Source => self.source_pane_scroll = usize::MAX,
                }
            }
            LiveDebuggerPane::RightTab => match self.active_right_tab {
                LiveRightTab::Heap => {
                    self.heap_layout_scroll = usize::MAX;
                    self.allocator_scan_scroll = usize::MAX;
                    self.chunk_inspector_scroll = usize::MAX;
                }
                LiveRightTab::Logs => self.related_records_scroll = usize::MAX,
                LiveRightTab::Stack => self.stack_tab_scroll = usize::MAX,
                LiveRightTab::Maps => self.maps_tab_scroll = usize::MAX,
                LiveRightTab::Memory => {
                    self.memory_tab_scroll = usize::MAX;
                    self.memory_selected_row = self
                        .latest_memory_inspection
                        .as_ref()
                        .and_then(|snapshot| snapshot.rows.len().checked_sub(1));
                }
                LiveRightTab::Breakpoints => {
                    self.breakpoint_tab_scroll = usize::MAX;
                    self.selected_user_breakpoint_index =
                        self.user_breakpoints.len().checked_sub(1);
                }
            },
            LiveDebuggerPane::Console => {}
        }
    }

    pub(crate) fn sync_legacy_focus_from_debugger_pane(&mut self) {
        self.focused_pane = match self.focused_debugger_pane {
            LiveDebuggerPane::Registers | LiveDebuggerPane::Trace | LiveDebuggerPane::Console => {
                LiveTuiPane::Events
            }
            LiveDebuggerPane::Code => LiveTuiPane::EventDetails,
            LiveDebuggerPane::RightTab => match self.active_right_tab {
                LiveRightTab::Heap => LiveTuiPane::HeapLayout,
                LiveRightTab::Logs => LiveTuiPane::RelatedRecords,
                LiveRightTab::Stack
                | LiveRightTab::Maps
                | LiveRightTab::Breakpoints
                | LiveRightTab::Memory => LiveTuiPane::Events,
            },
        };
    }

    pub(crate) fn set_active_right_tab(&mut self, tab: LiveRightTab) {
        self.active_right_tab = tab;
        self.focused_debugger_pane = LiveDebuggerPane::RightTab;
        self.sync_legacy_focus_from_debugger_pane();
    }

    pub(crate) fn next_right_tab(&mut self) {
        self.active_right_tab = next_live_right_tab(self.active_right_tab, 1);
        self.focused_debugger_pane = LiveDebuggerPane::RightTab;
        self.sync_legacy_focus_from_debugger_pane();
    }

    pub(crate) fn previous_right_tab(&mut self) {
        self.active_right_tab = next_live_right_tab(self.active_right_tab, -1);
        self.focused_debugger_pane = LiveDebuggerPane::RightTab;
        self.sync_legacy_focus_from_debugger_pane();
    }

    pub(crate) fn normalize_memory_selection(&mut self) {
        let len = self
            .latest_memory_inspection
            .as_ref()
            .map(|snapshot| snapshot.rows.len())
            .unwrap_or(0);
        self.memory_selected_row = if len == 0 {
            None
        } else {
            Some(self.memory_selected_row.unwrap_or(0).min(len - 1))
        };
    }

    pub(crate) fn select_next_memory_row(&mut self) {
        self.normalize_memory_selection();
        if let Some(index) = self.memory_selected_row {
            let len = self
                .latest_memory_inspection
                .as_ref()
                .map(|snapshot| snapshot.rows.len())
                .unwrap_or(0);
            self.memory_selected_row = Some((index + 1).min(len.saturating_sub(1)));
            self.memory_tab_scroll = self.memory_selected_row.unwrap_or(0).saturating_sub(3);
        }
    }

    pub(crate) fn select_previous_memory_row(&mut self) {
        self.normalize_memory_selection();
        if let Some(index) = self.memory_selected_row {
            self.memory_selected_row = Some(index.saturating_sub(1));
            self.memory_tab_scroll = self.memory_selected_row.unwrap_or(0).saturating_sub(3);
        }
    }

    pub(crate) fn memory_selected_value(&self) -> Option<u64> {
        let snapshot = self.latest_memory_inspection.as_ref()?;
        let row = snapshot.rows.get(self.memory_selected_row?)?;
        let value = row.word_value?;
        let maps = self.latest_process_maps.as_ref()?;
        maps.entries
            .iter()
            .any(|entry| value >= entry.start && value < entry.end)
            .then_some(value)
    }

    pub(crate) fn focus_code_and_recenter(&mut self) {
        self.focused_debugger_pane = LiveDebuggerPane::Code;
        self.sync_legacy_focus_from_debugger_pane();
        self.code_view_address = None;
        self.code_view_breakpoint_id = None;
        self.code_follow_rip = true;
        self.recenter_code_on_rip();
    }

    pub(crate) fn focus_code_source(&mut self) {
        self.focused_debugger_pane = LiveDebuggerPane::Code;
        self.sync_legacy_focus_from_debugger_pane();
        self.code_pane_mode = CodePaneMode::Source;
        self.recenter_code_on_rip();
    }

    pub(crate) fn selected_user_breakpoint(&self) -> Option<&UserBreakpoint> {
        self.selected_user_breakpoint_index
            .and_then(|index| self.user_breakpoints.get(index))
    }

    pub(crate) fn selected_breakpoint_id(&self) -> Option<UserBreakpointId> {
        self.selected_user_breakpoint()
            .map(|breakpoint| breakpoint.id)
    }

    pub(crate) fn select_next_user_breakpoint(&mut self) {
        self.normalize_selected_user_breakpoint();
        if self.user_breakpoints.is_empty() {
            return;
        }
        let index = self.selected_user_breakpoint_index.unwrap_or(0);
        self.selected_user_breakpoint_index =
            Some((index + 1).min(self.user_breakpoints.len() - 1));
        self.scroll_selected_breakpoint_into_view();
    }

    pub(crate) fn select_previous_user_breakpoint(&mut self) {
        self.normalize_selected_user_breakpoint();
        if self.user_breakpoints.is_empty() {
            return;
        }
        let index = self.selected_user_breakpoint_index.unwrap_or(0);
        self.selected_user_breakpoint_index = Some(index.saturating_sub(1));
        self.scroll_selected_breakpoint_into_view();
    }

    pub(crate) fn normalize_selected_user_breakpoint(&mut self) {
        self.normalize_selected_user_breakpoint_with_previous_id(self.selected_breakpoint_id());
    }

    fn normalize_selected_user_breakpoint_with_previous_id(
        &mut self,
        previous_id: Option<UserBreakpointId>,
    ) {
        if self.user_breakpoints.is_empty() {
            self.selected_user_breakpoint_index = None;
            self.breakpoint_tab_scroll = 0;
            return;
        }
        if let Some(previous_id) = previous_id {
            if let Some(index) = self
                .user_breakpoints
                .iter()
                .position(|breakpoint| breakpoint.id == previous_id)
            {
                self.selected_user_breakpoint_index = Some(index);
                self.scroll_selected_breakpoint_into_view();
                return;
            }
        }
        let fallback = self
            .selected_user_breakpoint_index
            .unwrap_or(0)
            .min(self.user_breakpoints.len() - 1);
        self.selected_user_breakpoint_index = Some(fallback);
        self.scroll_selected_breakpoint_into_view();
    }

    fn scroll_selected_breakpoint_into_view(&mut self) {
        if let Some(index) = self.selected_user_breakpoint_index {
            if index < self.breakpoint_tab_scroll {
                self.breakpoint_tab_scroll = index;
            } else {
                let visible_rows = 8usize;
                let bottom = self.breakpoint_tab_scroll.saturating_add(visible_rows);
                if index >= bottom {
                    self.breakpoint_tab_scroll = index.saturating_sub(visible_rows - 1);
                }
            }
        }
    }

    pub(crate) fn recenter_code_on_rip(&mut self) {
        let Some(current_line) = self.current_code_render_line_index() else {
            self.code_pane_scroll = 0;
            return;
        };
        self.code_pane_scroll = current_line.saturating_sub(4);
        if let Some(current_line) = self.current_source_render_line_index() {
            self.source_pane_scroll = current_line.saturating_sub(4);
        }
    }

    pub(crate) fn current_code_render_line_index(&self) -> Option<usize> {
        self.latest_code_context
            .as_ref()
            .map(format_code_context_lines)?
            .iter()
            .position(|line| line.starts_with('>') || line.starts_with("*>"))
    }

    pub(crate) fn current_source_render_line_index(&self) -> Option<usize> {
        self.latest_code_context
            .as_ref()
            .map(format_source_context_lines)?
            .iter()
            .position(|line| line.starts_with(" >"))
    }

    pub(crate) fn reset_selection_scrolls(&mut self) {
        self.event_details_scroll = 0;
        self.related_records_scroll = 0;
    }

    pub(crate) fn clamp_scrolls_to_content(&mut self) {
        self.register_pane_scroll = clamp_scroll(
            self.register_pane_scroll,
            format_live_registers_pane(self).lines().count(),
            1,
        );
        self.code_pane_scroll = clamp_scroll(
            self.code_pane_scroll,
            format_live_code_context_disassembly(self).lines().count(),
            1,
        );
        self.source_pane_scroll = clamp_scroll(
            self.source_pane_scroll,
            format_live_code_context_source(self).lines().count(),
            1,
        );
        self.event_details_scroll = clamp_scroll(
            self.event_details_scroll,
            live_event_details_text(self, &ReplayConfig::default())
                .lines()
                .count(),
            1,
        );
        self.heap_layout_scroll = clamp_scroll(
            self.heap_layout_scroll,
            format_live_heap_layout_pane(self, usize::MAX)
                .lines()
                .count(),
            1,
        );
        self.allocator_scan_scroll = clamp_scroll(
            self.allocator_scan_scroll,
            format_live_allocator_scan_pane(self).lines().count(),
            1,
        );
        self.related_records_scroll = clamp_scroll(
            self.related_records_scroll,
            live_related_records_text(self, &ReplayConfig::default())
                .lines()
                .count(),
            1,
        );
        self.stack_tab_scroll = clamp_scroll(
            self.stack_tab_scroll,
            format_live_stack_tab(self).lines().count(),
            1,
        );
        self.maps_tab_scroll = clamp_scroll(
            self.maps_tab_scroll,
            format_live_maps_tab(self).lines().count(),
            1,
        );
        self.breakpoint_tab_scroll = clamp_scroll(
            self.breakpoint_tab_scroll,
            format_live_breakpoints_tab(self).lines().count(),
            1,
        );
        self.memory_tab_scroll = clamp_scroll(
            self.memory_tab_scroll,
            format_live_memory_tab(self).lines().count(),
            1,
        );
        self.normalize_memory_selection();
        self.chunk_inspector_scroll = clamp_scroll(
            self.chunk_inspector_scroll,
            live_chunk_inspector_text(self).lines().count(),
            1,
        );
    }

    pub(crate) fn select_next_chunk(&mut self) {
        let Some(chunks_len) = latest_layout_chunks_len(self.latest_heap_layout.as_ref()) else {
            self.clear_selected_chunk();
            return;
        };
        if chunks_len == 0 {
            self.clear_selected_chunk();
            return;
        }
        let next_index = self
            .selected_chunk_index
            .map(|index| (index + 1).min(chunks_len.saturating_sub(1)))
            .unwrap_or(0);
        self.select_chunk_index(next_index);
    }

    pub(crate) fn select_previous_chunk(&mut self) {
        let Some(chunks_len) = latest_layout_chunks_len(self.latest_heap_layout.as_ref()) else {
            self.clear_selected_chunk();
            return;
        };
        if chunks_len == 0 {
            self.clear_selected_chunk();
            return;
        }
        let previous_index = self
            .selected_chunk_index
            .map(|index| index.saturating_sub(1))
            .unwrap_or(0);
        self.select_chunk_index(previous_index);
    }

    pub(crate) fn select_chunk_at_current_layout_index(&mut self) {
        if self.selected_chunk_index.is_none() {
            self.select_next_chunk();
            return;
        }
        self.update_selected_chunk_after_layout_update();
    }

    pub(crate) fn update_selected_chunk_after_layout_update(&mut self) {
        let Some(json::JsonTraceRecord::HeapLayout { chunks, .. }) =
            self.latest_heap_layout.as_ref()
        else {
            self.clear_selected_chunk();
            return;
        };
        if chunks.is_empty() {
            self.clear_selected_chunk();
            return;
        }

        if let Some(user_addr) = self.selected_chunk_user_addr {
            if let Some(index) = chunks
                .iter()
                .position(|chunk| parse_json_addr(&chunk.user_addr) == Some(user_addr))
            {
                self.select_chunk_index(index);
                return;
            }
        }

        if let Some(index) = self.selected_chunk_index {
            self.select_chunk_index(index.min(chunks.len().saturating_sub(1)));
        }
    }

    pub(crate) fn selected_chunk_from_latest_layout(&self) -> Option<&json::JsonLayoutChunk> {
        let json::JsonTraceRecord::HeapLayout { chunks, .. } = self.latest_heap_layout.as_ref()?
        else {
            return None;
        };
        chunks.get(self.selected_chunk_index?)
    }

    pub(crate) fn select_chunk_index(&mut self, index: usize) {
        let Some((chunk_addr, user_addr)) =
            selected_layout_chunk_addrs(self.latest_heap_layout.as_ref(), index)
        else {
            self.clear_selected_chunk();
            return;
        };
        self.selected_chunk_index = Some(index);
        self.selected_chunk_addr = chunk_addr;
        self.selected_chunk_user_addr = user_addr;
        self.chunk_inspector_scroll = 0;
    }

    pub(crate) fn clear_selected_chunk(&mut self) {
        self.selected_chunk_index = None;
        self.selected_chunk_addr = None;
        self.selected_chunk_user_addr = None;
    }

    pub(crate) fn start_console_input(&mut self) {
        self.console_input_active = true;
        self.console_input.clear();
        self.console_history_index = None;
        self.focused_debugger_pane = LiveDebuggerPane::Console;
        self.sync_legacy_focus_from_debugger_pane();
    }

    pub(crate) fn cancel_console_input(&mut self) {
        self.console_input_active = false;
        self.console_input.clear();
        self.console_history_index = None;
    }

    pub(crate) fn push_console_char(&mut self, ch: char) {
        self.console_input.push(ch);
    }

    pub(crate) fn pop_console_char(&mut self) {
        self.console_input.pop();
    }

    pub(crate) fn history_previous(&mut self) {
        if self.console_history.is_empty() {
            return;
        }
        let index = self
            .console_history_index
            .map(|index| index.saturating_sub(1))
            .unwrap_or_else(|| self.console_history.len().saturating_sub(1));
        self.console_history_index = Some(index);
        self.console_input = self.console_history[index].clone();
    }

    pub(crate) fn history_next(&mut self) {
        let Some(index) = self.console_history_index else {
            return;
        };
        if index + 1 >= self.console_history.len() {
            self.console_history_index = None;
            self.console_input.clear();
        } else {
            let index = index + 1;
            self.console_history_index = Some(index);
            self.console_input = self.console_history[index].clone();
        }
    }

    pub(crate) fn remember_console_command(&mut self, command: &str) {
        if command.is_empty() {
            return;
        }
        if self
            .console_history
            .last()
            .is_some_and(|previous| previous == command)
        {
            return;
        }
        self.console_history.push(command.to_string());
    }

    pub(crate) fn start_heap_search_prompt(&mut self) {
        self.search_prompt_active = true;
        self.search_prompt_input.clear();
        self.search_status = None;
    }

    pub(crate) fn cancel_heap_search_prompt(&mut self) {
        self.search_prompt_active = false;
        self.search_prompt_input.clear();
    }

    pub(crate) fn push_search_char(&mut self, ch: char) {
        self.search_prompt_input.push(ch);
    }

    pub(crate) fn pop_search_char(&mut self) {
        self.search_prompt_input.pop();
    }

    pub(crate) fn execute_heap_search(&mut self) {
        let input = self.search_prompt_input.clone();
        let query = match parse_heap_search_query(&input) {
            Ok(query) => query,
            Err(err) => {
                self.search_prompt_active = false;
                self.search_status = Some(err.to_string());
                return;
            }
        };

        self.execute_heap_search_query(query);
    }

    pub(crate) fn execute_heap_search_query(&mut self, query: HeapSearchQuery) {
        let Some(json::JsonTraceRecord::HeapLayout { .. }) = self.latest_heap_layout.as_ref()
        else {
            self.search_prompt_active = false;
            self.search_status = Some(
                "heap layout unavailable; enable --layout or --allocator-views basic/full"
                    .to_string(),
            );
            return;
        };

        if let Some(index) = self.find_chunk_in_latest_layout(query) {
            self.jump_to_chunk_index(index);
            return;
        }

        self.search_prompt_active = false;
        self.search_status = Some(format_heap_search_failure(query));
    }

    pub(crate) fn find_chunk_in_latest_layout(&self, query: HeapSearchQuery) -> Option<usize> {
        let json::JsonTraceRecord::HeapLayout { chunks, .. } = self.latest_heap_layout.as_ref()?
        else {
            return None;
        };

        chunks
            .iter()
            .position(|chunk| heap_search_query_matches_chunk(query, chunk))
    }

    pub(crate) fn jump_to_chunk_index(&mut self, index: usize) {
        self.select_chunk_index(index);
        self.focused_pane = LiveTuiPane::HeapLayout;
        self.focused_debugger_pane = LiveDebuggerPane::RightTab;
        self.active_right_tab = LiveRightTab::Heap;
        self.show_heap_pane = true;
        self.show_chunk_inspector = true;
        self.heap_layout_scroll = index.saturating_sub(3);
        self.search_prompt_active = false;
        self.search_prompt_input.clear();
        self.search_status = Some(format!(
            "selected chunk {} user {}",
            self.selected_chunk_addr
                .map(format_hex_u64)
                .unwrap_or_else(|| "?".to_string()),
            self.selected_chunk_user_addr
                .map(format_hex_u64)
                .unwrap_or_else(|| "?".to_string())
        ));
    }
}
