use super::*;

pub(crate) struct JsonWriter {
    pub(crate) writer: Box<dyn Write>,
}

impl JsonWriter {
    pub(crate) fn stdout() -> Self {
        Self {
            writer: Box::new(std::io::stdout()),
        }
    }

    pub(crate) fn file(path: &Path) -> Result<Self> {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to create JSON output file {}", path.display()))?;
        Ok(Self {
            writer: Box::new(BufWriter::new(file)),
        })
    }

    pub(crate) fn write_record<T: serde::Serialize>(&mut self, record: &T) -> Result<()> {
        serde_json::to_writer(&mut self.writer, record)
            .context("failed to serialize JSON record")?;
        self.writer
            .write_all(b"\n")
            .context("failed to write JSON record newline")?;
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> Result<()> {
        self.writer.flush().context("failed to flush JSON writer")
    }
}
#[derive(Debug, Clone)]
pub struct JsonSessionStart {
    pub record: json::JsonTraceRecord,
}
#[derive(Debug, Clone)]
pub struct JsonSessionEnd {
    pub record: json::JsonTraceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocatorBreakCondition {
    Suspicious,
    DoubleFree,
    FreePtr(u64),
    AllocSize(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatorBreakMatch {
    pub condition: AllocatorBreakCondition,
    pub event_id: usize,
    pub user_addr: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum LiveTraceUpdate {
    SessionStart(JsonSessionStart),
    Event {
        event_id: usize,
        event: HeapTraceEvent,
        note: HeapTrackerNote,
        explanation: HeapTrackerExplanation,
        caller_symbol: Option<SymbolizedAddress>,
    },
    RelatedRecord {
        event_id: usize,
        record: json::JsonTraceRecord,
    },
    Status {
        message: String,
    },
    CommandStatus {
        command_id: Option<LiveCommandId>,
        command: Option<LiveCommand>,
        status: LiveCommandStatus,
        target_status: LiveTargetStatus,
        message: String,
    },
    ProcessMaps {
        snapshot: ProcessMapsSnapshot,
    },
    RegisterSnapshot {
        event_id: Option<usize>,
        snapshot: RegisterSnapshot,
    },
    StackSnapshot {
        event_id: Option<usize>,
        snapshot: StackSnapshot,
    },
    CodeContext {
        event_id: Option<usize>,
        context: CodeContext,
    },
    BreakMatched(AllocatorBreakMatch),
    SessionEnd(JsonSessionEnd),
}

pub trait LiveTraceSink {
    fn on_update(&mut self, update: &LiveTraceUpdate) -> Result<()>;
}

pub(crate) struct CurrentOutputSink<'a> {
    pub(crate) config: &'a RenderConfig,
    pub(crate) json_writer: Option<&'a mut JsonWriter>,
}

impl LiveTraceSink for CurrentOutputSink<'_> {
    fn on_update(&mut self, update: &LiveTraceUpdate) -> Result<()> {
        match update {
            LiveTraceUpdate::SessionStart(session) => {
                maybe_print_allocator_views_preset_status(self.config);
                maybe_print_low_confidence_profile_warning(&session.record, self.config);
                if let Some(writer) = self.json_writer.as_deref_mut() {
                    writer.write_record(&session.record)?;
                }
            }
            LiveTraceUpdate::Event {
                event,
                note,
                explanation,
                caller_symbol,
                ..
            } => {
                if let Some(writer) = self.json_writer.as_deref_mut() {
                    writer.write_record(&json::json_trace_event_record_with_caller_symbol(
                        event,
                        *note,
                        explanation.clone(),
                        caller_symbol.as_ref(),
                    ))?;
                    return Ok(());
                }

                print_heap_event(event, caller_symbol.as_ref(), *note, self.config);
                if self.config.show_explanations {
                    print_heap_explanation(explanation.clone());
                }
            }
            LiveTraceUpdate::RelatedRecord { record, .. } => {
                if let Some(writer) = self.json_writer.as_deref_mut() {
                    writer.write_record(record)?;
                    return Ok(());
                }

                let replay_config = replay_config_from_render_config(self.config);
                print_replay_text(format_replay_record(record, &replay_config));
            }
            LiveTraceUpdate::Status { .. }
            | LiveTraceUpdate::CommandStatus { .. }
            | LiveTraceUpdate::ProcessMaps { .. }
            | LiveTraceUpdate::RegisterSnapshot { .. }
            | LiveTraceUpdate::StackSnapshot { .. }
            | LiveTraceUpdate::CodeContext { .. } => {}
            LiveTraceUpdate::BreakMatched(break_match) => {
                if self.json_writer.is_none() {
                    println!(
                        "break condition matched: {} after event #{}",
                        break_match.message, break_match.event_id
                    );
                }
            }
            LiveTraceUpdate::SessionEnd(session) => {
                if let Some(writer) = self.json_writer.as_deref_mut() {
                    writer.write_record(&session.record)?;
                    writer.flush()?;
                }
                if let Some(path) = &self.config.json_out {
                    if !self.config.events_only() {
                        println!("[heapify] wrote trace records to {}", path.display());
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct LiveTuiSink<'a> {
    pub(crate) sender: mpsc::Sender<LiveTraceUpdate>,
    pub(crate) json_writer: Option<&'a mut JsonWriter>,
}

impl LiveTraceSink for LiveTuiSink<'_> {
    fn on_update(&mut self, update: &LiveTraceUpdate) -> Result<()> {
        self.sender
            .send(update.clone())
            .context("failed to send live trace update to TUI")?;

        if let Some(writer) = self.json_writer.as_deref_mut() {
            write_live_update_json(writer, update)?;
        }

        Ok(())
    }
}

pub(crate) struct RecordingRelatedSink<'a> {
    pub(crate) inner: &'a mut dyn LiveTraceSink,
    pub(crate) related_records: Vec<json::JsonTraceRecord>,
}

impl LiveTraceSink for RecordingRelatedSink<'_> {
    fn on_update(&mut self, update: &LiveTraceUpdate) -> Result<()> {
        if let LiveTraceUpdate::RelatedRecord { record, .. } = update {
            self.related_records.push(record.clone());
        }
        self.inner.on_update(update)
    }
}

pub(crate) fn write_live_update_json(
    writer: &mut JsonWriter,
    update: &LiveTraceUpdate,
) -> Result<()> {
    match update {
        LiveTraceUpdate::SessionStart(session) => writer.write_record(&session.record)?,
        LiveTraceUpdate::Event {
            event,
            note,
            explanation,
            caller_symbol,
            ..
        } => writer.write_record(&json::json_trace_event_record_with_caller_symbol(
            event,
            *note,
            explanation.clone(),
            caller_symbol.as_ref(),
        ))?,
        LiveTraceUpdate::RelatedRecord { record, .. } => writer.write_record(record)?,
        LiveTraceUpdate::Status { .. }
        | LiveTraceUpdate::CommandStatus { .. }
        | LiveTraceUpdate::ProcessMaps { .. }
        | LiveTraceUpdate::RegisterSnapshot { .. }
        | LiveTraceUpdate::StackSnapshot { .. }
        | LiveTraceUpdate::CodeContext { .. }
        | LiveTraceUpdate::BreakMatched(_) => {}
        LiveTraceUpdate::SessionEnd(session) => {
            writer.write_record(&session.record)?;
            writer.flush()?;
        }
    }

    Ok(())
}
