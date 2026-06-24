use crate::UserBreakpointId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveCommand {
    Stop,
    Pause,
    Resume,
    Continue,
    StepAllocatorEvent,
    StepInstruction,
    StepInstructionOver,
    SourceStep,
    SourceStepOver,
    InspectMemory(MemoryInspectionRequest),
    AddUserBreakpointAddress(u64),
    AddUserBreakpointSymbol(String),
    AddUserBreakpointSourceLine {
        path: String,
        line: u64,
    },
    DeleteUserBreakpoint(UserBreakpointId),
    EnableUserBreakpoint(UserBreakpointId),
    DisableUserBreakpoint(UserBreakpointId),
    InspectCodeAt {
        address: u64,
        breakpoint_id: Option<UserBreakpointId>,
    },
}

impl LiveCommand {
    pub fn as_str(&self) -> &'static str {
        match self {
            LiveCommand::Stop => "stop",
            LiveCommand::Pause => "pause",
            LiveCommand::Resume => "resume",
            LiveCommand::Continue => "continue",
            LiveCommand::StepAllocatorEvent => "step_allocator_event",
            LiveCommand::StepInstruction => "step_instruction",
            LiveCommand::StepInstructionOver => "step_instruction_over",
            LiveCommand::SourceStep => "source_step",
            LiveCommand::SourceStepOver => "source_step_over",
            LiveCommand::InspectMemory(_) => "inspect_memory",
            LiveCommand::AddUserBreakpointAddress(_) => "break_address",
            LiveCommand::AddUserBreakpointSymbol(_) => "break_symbol",
            LiveCommand::AddUserBreakpointSourceLine { .. } => "break_source",
            LiveCommand::DeleteUserBreakpoint(_) => "delete_breakpoint",
            LiveCommand::EnableUserBreakpoint(_) => "enable_breakpoint",
            LiveCommand::DisableUserBreakpoint(_) => "disable_breakpoint",
            LiveCommand::InspectCodeAt { .. } => "inspect_code",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LiveCommandId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCommandMessage {
    pub id: LiveCommandId,
    pub command: LiveCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveTargetStatus {
    NotStarted,
    Running,
    Paused,
    SteppingToNextAllocatorEvent,
    SteppingInstruction,
    SteppingInstructionOver,
    SourceStepping,
    SourceSteppingOver,
    Stopping,
    Exited,
}

impl LiveTargetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            LiveTargetStatus::NotStarted => "not_started",
            LiveTargetStatus::Running => "running",
            LiveTargetStatus::Paused => "paused",
            LiveTargetStatus::SteppingToNextAllocatorEvent => "stepping_to_next_allocator_event",
            LiveTargetStatus::SteppingInstruction => "stepping_instruction",
            LiveTargetStatus::SteppingInstructionOver => "stepping_instruction_over",
            LiveTargetStatus::SourceStepping => "source_stepping",
            LiveTargetStatus::SourceSteppingOver => "source_stepping_over",
            LiveTargetStatus::Stopping => "stopping",
            LiveTargetStatus::Exited => "exited",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveCommandStatus {
    Accepted,
    Rejected,
    Completed,
    Failed,
}

impl LiveCommandStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            LiveCommandStatus::Accepted => "accepted",
            LiveCommandStatus::Rejected => "rejected",
            LiveCommandStatus::Completed => "completed",
            LiveCommandStatus::Failed => "failed",
        }
    }
}

pub fn validate_live_command(
    target_status: LiveTargetStatus,
    command: LiveCommand,
) -> std::result::Result<(), String> {
    let allowed = match command {
        LiveCommand::Stop => target_status != LiveTargetStatus::Exited,
        LiveCommand::Pause => matches!(
            target_status,
            LiveTargetStatus::Running
                | LiveTargetStatus::SteppingToNextAllocatorEvent
                | LiveTargetStatus::SteppingInstruction
                | LiveTargetStatus::SteppingInstructionOver
                | LiveTargetStatus::SourceStepping
                | LiveTargetStatus::SourceSteppingOver
        ),
        LiveCommand::Resume => target_status == LiveTargetStatus::Paused,
        LiveCommand::Continue => matches!(
            target_status,
            LiveTargetStatus::Paused | LiveTargetStatus::SteppingToNextAllocatorEvent
        ),
        LiveCommand::StepAllocatorEvent => target_status == LiveTargetStatus::Paused,
        LiveCommand::StepInstruction
        | LiveCommand::StepInstructionOver
        | LiveCommand::SourceStep
        | LiveCommand::SourceStepOver
        | LiveCommand::InspectMemory(_) => target_status == LiveTargetStatus::Paused,
        LiveCommand::AddUserBreakpointAddress(_)
        | LiveCommand::AddUserBreakpointSymbol(_)
        | LiveCommand::AddUserBreakpointSourceLine { .. }
        | LiveCommand::DeleteUserBreakpoint(_)
        | LiveCommand::EnableUserBreakpoint(_)
        | LiveCommand::DisableUserBreakpoint(_)
        | LiveCommand::InspectCodeAt { .. } => target_status == LiveTargetStatus::Paused,
    };

    if allowed {
        Ok(())
    } else {
        Err(format!(
            "{} not allowed while target is {}",
            command.as_str(),
            target_status.as_str()
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryViewFormat {
    HexWords,
    HexBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInspectionRequest {
    pub address: u64,
    pub count: usize,
    pub format: MemoryViewFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveTraceRunMode {
    Continuous,
    StepAllocatorEvent,
    UserInstructionStepOver,
    SourceStepInto,
    SourceStepOver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    InternalBreakpointStepOver,
    UserInstructionStep,
    UserInstructionStepOver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerStopReason {
    UserPause,
    AllocatorEventStep {
        event_id: usize,
    },
    InstructionStep {
        from_rip: u64,
        to_rip: u64,
    },
    InstructionStepOver {
        from_rip: u64,
        to_rip: u64,
    },
    SourceStep {
        from: crate::SourceLocation,
        to: crate::SourceLocation,
        instructions_executed: u64,
    },
    SourceStepOver {
        from: crate::SourceLocation,
        to: crate::SourceLocation,
        instructions_executed: u64,
    },
    SourceStepLimit {
        from: crate::SourceLocation,
        instructions_executed: u64,
    },
    AllocatorBreakCondition {
        event_id: usize,
        message: String,
    },
    UserBreakpoint {
        breakpoint_id: UserBreakpointId,
        address: u64,
        label: String,
    },
    Signal {
        signal: i32,
        instruction_pointer: Option<u64>,
    },
    ProcessExit {
        status: String,
    },
}

impl DebuggerStopReason {
    pub fn summary_line(&self) -> String {
        match self {
            DebuggerStopReason::UserPause => "paused by user".to_string(),
            DebuggerStopReason::AllocatorEventStep { event_id } => {
                format!("paused after allocator event #{event_id}")
            }
            DebuggerStopReason::InstructionStep { from_rip, to_rip } => {
                format!("stepped instruction: 0x{from_rip:x} -> 0x{to_rip:x}")
            }
            DebuggerStopReason::InstructionStepOver { from_rip, to_rip } => {
                format!("nexti completed: 0x{from_rip:x} -> 0x{to_rip:x}")
            }
            DebuggerStopReason::SourceStep {
                from,
                to,
                instructions_executed,
            } => format!(
                "source-step: {} -> {} after {} instructions",
                crate::format_source_location_short(from),
                crate::format_source_location_delta(from, to),
                instructions_executed
            ),
            DebuggerStopReason::SourceStepOver {
                from,
                to,
                instructions_executed,
            } => format!(
                "source-next: {} -> {} after {} instructions",
                crate::format_source_location_short(from),
                crate::format_source_location_delta(from, to),
                instructions_executed
            ),
            DebuggerStopReason::SourceStepLimit {
                instructions_executed,
                ..
            } => format!("source-step limit reached after {instructions_executed} instructions"),
            DebuggerStopReason::AllocatorBreakCondition { event_id, message } => {
                format!("break condition matched after event #{event_id}: {message}")
            }
            DebuggerStopReason::UserBreakpoint {
                breakpoint_id,
                address,
                label,
            } => format!(
                "breakpoint {} hit at 0x{address:x} ({label})",
                breakpoint_id.as_u64()
            ),
            DebuggerStopReason::Signal {
                signal,
                instruction_pointer,
            } => match instruction_pointer {
                Some(rip) => format!("stopped by signal {signal} at RIP=0x{rip:x}"),
                None => format!("stopped by signal {signal}"),
            },
            DebuggerStopReason::ProcessExit { status } => format!("target exited: {status}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LiveWorkerPauseState {
    pub(crate) ptrace_stopped: bool,
    pub(crate) user_visible_paused: bool,
    pub(crate) step_in_flight: Option<StepKind>,
    pub(crate) temporary_return_breakpoint_in_flight: bool,
    pub(crate) managed_breakpoints_rearmed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingInstructionStepOver {
    pub(crate) command_id: LiveCommandId,
    pub(crate) from_rip: u64,
    pub(crate) breakpoint_addr: u64,
}

impl LiveWorkerPauseState {
    #[cfg(test)]
    pub(crate) fn stable_user_pause() -> Self {
        Self {
            ptrace_stopped: true,
            user_visible_paused: true,
            step_in_flight: None,
            temporary_return_breakpoint_in_flight: false,
            managed_breakpoints_rearmed: true,
        }
    }

    pub(crate) fn can_user_step_instruction(&self) -> std::result::Result<(), String> {
        if self.ptrace_stopped
            && self.user_visible_paused
            && self.step_in_flight.is_none()
            && !self.temporary_return_breakpoint_in_flight
            && self.managed_breakpoints_rearmed
        {
            Ok(())
        } else {
            Err(
                "cannot step instruction while Heapify is resolving an internal breakpoint"
                    .to_string(),
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorEventControl {
    Continue,
    Pause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TraceWaitMode {
    Blocking,
    Controlled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveControlOutcome {
    Continue,
    TargetExited,
}
