#![allow(
    clippy::field_reassign_with_default,
    clippy::too_many_arguments,
    dead_code,
    unused_imports
)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use heapify_core::allocator_sources::{
    allocator_source_kind_str, allocator_warning_kind_str, collect_allocator_source_summary,
    collect_allocator_warnings, diff_allocator_source_summary, AllocatorSourceDelta,
    AllocatorSourceMembership, AllocatorSourceSummary, AllocatorWarning,
};
use heapify_core::glibc::{
    available_glibc_profiles, find_tcache_struct_candidate_with_profile, glibc_profile_by_name,
    main_arena_view_status_from_top_status, validate_fastbins_snapshot,
    validate_largebins_snapshot, validate_smallbins_snapshot, validate_unsorted_bin_snapshot,
    BinExperiment, FastbinBinValidation, FastbinChain, FastbinExperiment, FastbinsSnapshot,
    GlibcChunkHeader, GlibcHeapSnapshot, GlibcProfile, GlibcProfileConfidence,
    LargebinBinValidation, LargebinValidationStatus, LargebinValidationValue, LargebinsSnapshot,
    MainArenaCandidate, MainArenaFieldSource, MainArenaSource, MainArenaViewStatus, RegularBinHead,
    RegularBinsSnapshot, SmallbinBinValidation, SmallbinValidationStatus, SmallbinValidationValue,
    SmallbinsSnapshot, TcacheEntryCandidate, TcacheSnapshotCandidate, TcacheStructCandidate,
    UnsortedBinExperiment, UnsortedBinSnapshot, UnsortedBinValidation, UnsortedBinValidationStatus,
    UnsortedBinValidationValue, GLIBC_X86_64_MODERN,
};
use heapify_core::heap_scan::{
    build_heap_scan_report, heap_scan_finding_severity_str, heap_scan_status_str, HeapScanInputs,
    HeapScanReport,
};
use heapify_core::tcache::{
    compare_tcache_snapshot_with_observed, validate_tcache_snapshot_candidate, ObservedTcacheChain,
    ObservedTcacheTracker, TcacheBinComparison, TcacheComparisonStatus, TcacheValidationStatus,
    TcacheValidationValue,
};
use heapify_core::tracker::{
    explain_event, HeapTracker, HeapTrackerExplanation, HeapTrackerNote, ObservedChunkState,
};
use heapify_core::HeapTraceEvent;
use heapify_debugger::{
    read_disassembly_snapshot, validate_live_command, AllocationTraceMode, AllocatorEventControl,
    DebuggerStopReason, DisassemblyFlowControl, DisassemblyLine, DisassemblySnapshot, LiveCommand,
    LiveCommandId, LiveCommandMessage, LiveCommandStatus, LiveTargetStatus, Pid, ProcessMapEntry,
    ProcessMapsSnapshot, ProcessSymbolizer, RegisterRole, RegisterSnapshot, SourceLocation,
    StackSnapshot, StackWord, StdinConfig, SymbolizedAddress, TargetCommand, TargetSourceMapper,
    TraceHeapContext, DEFAULT_DISASSEMBLY_AFTER_BYTES, DEFAULT_DISASSEMBLY_BEFORE_BYTES,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;

use crate::json;

#[path = "config.rs"]
mod config;
use config::{
    AllocatorViewsPreset, AllocatorViewsPresetArg, RenderConfig, SelectedMainArenaTopOffset,
    TraceModeArg,
};

#[path = "trace.rs"]
mod trace;
use trace::{
    AllocatorBreakCondition, AllocatorBreakMatch, CurrentOutputSink, JsonSessionEnd,
    JsonSessionStart, JsonWriter, LiveTraceSink, LiveTraceUpdate, LiveTuiSink,
    RecordingRelatedSink,
};

#[path = "live.rs"]
mod live;
use live::{
    AddressClassification, AddressRegionKind, CodeContext, ConsoleCommand, HeapAddressDetail,
    HeapSearchMode, HeapSearchQuery, LiveDebuggerPane, LiveRightTab, LiveTuiApp, LiveTuiPane,
    RenderedRegisterLine,
};

#[path = "replay.rs"]
mod replay;
use replay::{
    replay_config_from_render_config, ReplayConfig, ReplayEventAllocatorDelta,
    ReplayEventAllocatorState, ReplayEventEntry, ReplaySession, ReplayTuiState,
};

pub fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);

    match args.next().as_deref() {
        Some("run") => {
            let Some(program) = args.next() else {
                usage();
                bail!("missing program");
            };

            let target = TargetCommand::new(program, args.collect());
            heapify_debugger::run(target)
        }
        Some("break") => {
            let Some(program) = args.next() else {
                usage();
                bail!("missing program");
            };
            let Some(addr) = args.next() else {
                usage();
                bail!("missing breakpoint address");
            };

            let addr = parse_addr(&addr)?;
            let target = TargetCommand::new(program, args.collect());
            heapify_debugger::run_with_breakpoint(target, addr)
        }
        Some("break-symbol") => {
            let Some(program) = args.next() else {
                usage();
                bail!("missing program");
            };
            let Some(symbol) = args.next() else {
                usage();
                bail!("missing symbol");
            };

            let target = TargetCommand::new(program, args.collect());
            heapify_debugger::run_with_symbol_breakpoint(target, &symbol)
        }
        Some("trace-heap") => {
            let (config, program, target_args) = parse_trace_heap_args(args.collect())?;
            let trace_mode = resolve_trace_mode(config.trace_mode, config.libc_symbols)?;
            run_trace_heap_command(config, program, target_args, trace_mode)
        }
        Some("replay") => {
            let (config, trace_file) = parse_replay_args(args.collect())?;
            if config.tui {
                replay_trace_file_tui(&trace_file, &config)
            } else {
                replay_trace_file(&trace_file, &config)
            }
        }
        Some("-h") | Some("--help") | Some("help") => {
            usage();
            Ok(())
        }
        _ => {
            usage();
            bail!("unknown or missing command");
        }
    }
}

fn run_trace_heap_command(
    config: RenderConfig,
    program: String,
    target_args: Vec<String>,
    trace_mode: AllocationTraceMode,
) -> Result<()> {
    if config.live_tui {
        return run_trace_heap_live_tui(config, program, target_args, trace_mode);
    }

    run_trace_heap_worker(config, program, target_args, trace_mode, None, None)
}

fn run_trace_heap_worker(
    config: RenderConfig,
    program: String,
    target_args: Vec<String>,
    trace_mode: AllocationTraceMode,
    live_sender: Option<mpsc::Sender<LiveTraceUpdate>>,
    control_receiver: Option<mpsc::Receiver<LiveCommandMessage>>,
) -> Result<()> {
    let mut tracker = HeapTracker::new();
    let mut tcache_tracker = ObservedTcacheTracker::new();
    let mut tcache_struct_candidate = None;
    let mut printed_tcache_struct_candidate_block = false;
    let mut main_arena_candidate = None;
    let mut printed_main_arena_candidate_block = false;
    let mut printed_main_arena_experiment_block = false;
    let mut printed_fastbin_experiment_block = false;
    let mut printed_unsorted_experiment_block = false;
    let mut printed_bin_experiment_block = false;
    let mut printed_unsorted_bin_block = false;
    let mut printed_fastbins_block = false;
    let mut printed_regular_bins_block = false;
    let mut printed_smallbins_block = false;
    let mut printed_largebins_block = false;
    let mut fastbins_snapshot = None;
    let mut unsorted_bin_snapshot = None;
    let mut regular_bins_snapshot = None;
    let mut smallbins_snapshot = None;
    let mut largebins_snapshot = None;
    let mut previous_allocator_source_summary = None;
    let mut printed_main_arena_top_candidate_block = false;
    let mut event_count = 0usize;
    let json_enabled = config.json_enabled();
    let json_writer = RefCell::new(if json_enabled {
        Some(match &config.json_out {
            Some(path) => JsonWriter::file(path)?,
            None => JsonWriter::stdout(),
        })
    } else {
        None
    });
    let target_symbolizer = RefCell::new(None);
    let target_source_mapper = RefCell::new(None);
    let show_status = !config.events_only() && !json_enabled && !config.live_tui;
    let mut run_trace = |poll_control: &mut dyn FnMut() -> Option<LiveCommandMessage>,
                         on_control_status: &mut dyn FnMut(
        Option<LiveCommandId>,
        Option<LiveCommand>,
        LiveCommandStatus,
        LiveTargetStatus,
        String,
    ) -> Result<()>|
     -> Result<()> {
        if live_sender.is_some() {
            heapify_debugger::trace_heap_with_status_mode_profile_session_live_control(
                &program,
                &target_args,
                |event, context| {
                    event_count += 1;
                    let caller_symbol = symbolize_event_caller(
                        &event,
                        target_symbolizer.borrow().as_ref(),
                        target_source_mapper.borrow().as_ref(),
                    );
                    let note = tracker.observe_event(&event);
                    let explanation = explain_event(&event, note);
                    let mut json_writer = json_writer.borrow_mut();
                    if let Some(sender) = &live_sender {
                        let mut sink = LiveTuiSink {
                            sender: sender.clone(),
                            json_writer: json_writer.as_mut(),
                        };
                        let related_records = emit_live_trace_records(
                            &mut sink,
                            &event,
                            note,
                            explanation,
                            &context,
                            &tracker,
                            &mut tcache_tracker,
                            &config,
                            &mut tcache_struct_candidate,
                            &mut printed_tcache_struct_candidate_block,
                            &mut main_arena_candidate,
                            &mut printed_main_arena_candidate_block,
                            &mut printed_main_arena_experiment_block,
                            &mut printed_fastbin_experiment_block,
                            &mut printed_unsorted_experiment_block,
                            &mut printed_bin_experiment_block,
                            &mut printed_unsorted_bin_block,
                            &mut printed_fastbins_block,
                            &mut printed_regular_bins_block,
                            &mut printed_smallbins_block,
                            &mut printed_largebins_block,
                            &mut fastbins_snapshot,
                            &mut unsorted_bin_snapshot,
                            &mut regular_bins_snapshot,
                            &mut smallbins_snapshot,
                            &mut largebins_snapshot,
                            &mut printed_main_arena_top_candidate_block,
                            &mut previous_allocator_source_summary,
                            caller_symbol,
                        )?;
                        if let Some(break_match) = evaluate_allocator_break_conditions(
                            &config.break_conditions,
                            &event,
                            note,
                            &related_records,
                        ) {
                            sink.on_update(&LiveTraceUpdate::BreakMatched(break_match))?;
                            return Ok(AllocatorEventControl::Pause);
                        }
                    } else {
                        let mut sink = CurrentOutputSink {
                            config: &config,
                            json_writer: json_writer.as_mut(),
                        };
                        let related_records = emit_live_trace_records(
                            &mut sink,
                            &event,
                            note,
                            explanation,
                            &context,
                            &tracker,
                            &mut tcache_tracker,
                            &config,
                            &mut tcache_struct_candidate,
                            &mut printed_tcache_struct_candidate_block,
                            &mut main_arena_candidate,
                            &mut printed_main_arena_candidate_block,
                            &mut printed_main_arena_experiment_block,
                            &mut printed_fastbin_experiment_block,
                            &mut printed_unsorted_experiment_block,
                            &mut printed_bin_experiment_block,
                            &mut printed_unsorted_bin_block,
                            &mut printed_fastbins_block,
                            &mut printed_regular_bins_block,
                            &mut printed_smallbins_block,
                            &mut printed_largebins_block,
                            &mut fastbins_snapshot,
                            &mut unsorted_bin_snapshot,
                            &mut regular_bins_snapshot,
                            &mut smallbins_snapshot,
                            &mut largebins_snapshot,
                            &mut printed_main_arena_top_candidate_block,
                            &mut previous_allocator_source_summary,
                            caller_symbol,
                        )?;
                        if let Some(break_match) = evaluate_allocator_break_conditions(
                            &config.break_conditions,
                            &event,
                            note,
                            &related_records,
                        ) {
                            sink.on_update(&LiveTraceUpdate::BreakMatched(break_match))?;
                        }
                    }
                    Ok(AllocatorEventControl::Continue)
                },
                |session| {
                    let target_program_for_symbols = session
                        .launch
                        .target_program_for_symbols
                        .to_string_lossy()
                        .into_owned();
                    *target_symbolizer.borrow_mut() = ProcessSymbolizer::from_process(
                        session.pid,
                        target_program_for_symbols.as_str(),
                    )
                    .ok();
                    *target_source_mapper.borrow_mut() = TargetSourceMapper::from_process(
                        session.pid,
                        target_program_for_symbols.as_str(),
                    )
                    .ok();
                    let record = json::json_session_start_record(
                        &program,
                        &target_args,
                        trace_mode.as_str(),
                        session.glibc_profile.name,
                        None,
                        Some(session.glibc_profile_selection.clone()),
                        session.libc.clone().map(json_libc_metadata),
                        Some(json_launch_metadata(&session.launch)),
                        config.allocator_views_preset.as_str(),
                        json_trace_features(&config, trace_mode),
                    );
                    let update = LiveTraceUpdate::SessionStart(JsonSessionStart { record });
                    let mut json_writer = json_writer.borrow_mut();
                    if let Some(sender) = &live_sender {
                        let mut sink = LiveTuiSink {
                            sender: sender.clone(),
                            json_writer: json_writer.as_mut(),
                        };
                        sink.on_update(&update)?;
                        if let Some(snapshot) = session.process_maps.clone() {
                            sink.on_update(&LiveTraceUpdate::ProcessMaps { snapshot })?;
                        } else if let Some(error) = session.process_maps_error.as_ref() {
                            sink.on_update(&LiveTraceUpdate::Status {
                                message: format!("process maps read failed: {error}"),
                            })?;
                        }
                    } else {
                        let mut sink = CurrentOutputSink {
                            config: &config,
                            json_writer: json_writer.as_mut(),
                        };
                        sink.on_update(&update)?;
                    }
                    Ok(())
                },
                show_status,
                trace_mode,
                &config.glibc_profile_request,
                config.supplied_libc_path.as_deref(),
                config.loader_path.as_deref(),
                config.library_path.as_deref(),
                config.preload_path.as_deref(),
                config.cwd.as_deref(),
                config.clear_env,
                config.set_env.clone(),
                config.unset_env.clone(),
                config.stdin.clone(),
                poll_control,
                on_control_status,
                |event_id, snapshot, stack_snapshot, pid| {
                    if let Some(sender) = &live_sender {
                        let target_symbolizer = target_symbolizer.borrow();
                        let target_source_mapper = target_source_mapper.borrow();
                        let context = build_code_context(
                            pid,
                            snapshot.instruction_pointer,
                            target_symbolizer.as_ref(),
                            target_source_mapper.as_ref(),
                        );
                        let _ =
                            sender.send(LiveTraceUpdate::RegisterSnapshot { event_id, snapshot });
                        let _ = sender.send(LiveTraceUpdate::StackSnapshot {
                            event_id,
                            snapshot: stack_snapshot,
                        });
                        let _ = sender.send(LiveTraceUpdate::CodeContext { event_id, context });
                    }
                    Ok(())
                },
            )
        } else {
            heapify_debugger::trace_heap_with_status_mode_profile_and_session(
                &program,
                &target_args,
                |event, context| {
                    event_count += 1;
                    let caller_symbol = symbolize_event_caller(
                        &event,
                        target_symbolizer.borrow().as_ref(),
                        target_source_mapper.borrow().as_ref(),
                    );
                    let note = tracker.observe_event(&event);
                    let explanation = explain_event(&event, note);
                    let mut json_writer = json_writer.borrow_mut();
                    let mut sink = CurrentOutputSink {
                        config: &config,
                        json_writer: json_writer.as_mut(),
                    };
                    let related_records = emit_live_trace_records(
                        &mut sink,
                        &event,
                        note,
                        explanation,
                        &context,
                        &tracker,
                        &mut tcache_tracker,
                        &config,
                        &mut tcache_struct_candidate,
                        &mut printed_tcache_struct_candidate_block,
                        &mut main_arena_candidate,
                        &mut printed_main_arena_candidate_block,
                        &mut printed_main_arena_experiment_block,
                        &mut printed_fastbin_experiment_block,
                        &mut printed_unsorted_experiment_block,
                        &mut printed_bin_experiment_block,
                        &mut printed_unsorted_bin_block,
                        &mut printed_fastbins_block,
                        &mut printed_regular_bins_block,
                        &mut printed_smallbins_block,
                        &mut printed_largebins_block,
                        &mut fastbins_snapshot,
                        &mut unsorted_bin_snapshot,
                        &mut regular_bins_snapshot,
                        &mut smallbins_snapshot,
                        &mut largebins_snapshot,
                        &mut printed_main_arena_top_candidate_block,
                        &mut previous_allocator_source_summary,
                        caller_symbol,
                    )?;
                    if let Some(break_match) = evaluate_allocator_break_conditions(
                        &config.break_conditions,
                        &event,
                        note,
                        &related_records,
                    ) {
                        sink.on_update(&LiveTraceUpdate::BreakMatched(break_match))?;
                    }
                    Ok(())
                },
                |session| {
                    let target_program_for_symbols = session
                        .launch
                        .target_program_for_symbols
                        .to_string_lossy()
                        .into_owned();
                    *target_symbolizer.borrow_mut() = ProcessSymbolizer::from_process(
                        session.pid,
                        target_program_for_symbols.as_str(),
                    )
                    .ok();
                    *target_source_mapper.borrow_mut() = TargetSourceMapper::from_process(
                        session.pid,
                        target_program_for_symbols.as_str(),
                    )
                    .ok();
                    let record = json::json_session_start_record(
                        &program,
                        &target_args,
                        trace_mode.as_str(),
                        session.glibc_profile.name,
                        None,
                        Some(session.glibc_profile_selection.clone()),
                        session.libc.clone().map(json_libc_metadata),
                        Some(json_launch_metadata(&session.launch)),
                        config.allocator_views_preset.as_str(),
                        json_trace_features(&config, trace_mode),
                    );
                    let update = LiveTraceUpdate::SessionStart(JsonSessionStart { record });
                    let mut json_writer = json_writer.borrow_mut();
                    let mut sink = CurrentOutputSink {
                        config: &config,
                        json_writer: json_writer.as_mut(),
                    };
                    sink.on_update(&update)?;
                    Ok(())
                },
                show_status,
                trace_mode,
                &config.glibc_profile_request,
                config.supplied_libc_path.as_deref(),
                config.loader_path.as_deref(),
                config.library_path.as_deref(),
                config.preload_path.as_deref(),
                config.cwd.as_deref(),
                config.clear_env,
                config.set_env.clone(),
                config.unset_env.clone(),
                config.stdin.clone(),
            )
        }
    };
    let mut poll_control = || {
        control_receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok())
    };
    let mut on_control_status = |command_id: Option<LiveCommandId>,
                                 command: Option<LiveCommand>,
                                 status: LiveCommandStatus,
                                 target_status: LiveTargetStatus,
                                 message: String|
     -> Result<()> {
        if let Some(sender) = &live_sender {
            let _ = sender.send(LiveTraceUpdate::CommandStatus {
                command_id,
                command,
                status,
                target_status,
                message,
            });
        }
        Ok(())
    };
    let trace_result = run_trace(&mut poll_control, &mut on_control_status);
    trace_result?;
    let suppress_human = json_enabled || config.live_tui;
    maybe_print_unavailable_main_arena_candidate(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_main_arena_candidate_block,
    );
    maybe_print_unavailable_main_arena_experiment(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_main_arena_experiment_block,
    );
    maybe_print_unavailable_fastbin_experiment(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_fastbin_experiment_block,
    );
    maybe_print_unavailable_fastbins(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_fastbins_block,
    );
    maybe_print_unavailable_unsorted_bin(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_unsorted_bin_block,
    );
    maybe_print_unavailable_regular_bins(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_regular_bins_block,
    );
    maybe_print_unavailable_smallbins(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_smallbins_block,
    );
    maybe_print_unavailable_largebins(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_largebins_block,
    );
    maybe_print_unavailable_unsorted_bin_experiment(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_unsorted_experiment_block,
    );
    maybe_print_unavailable_bin_experiment(
        &config,
        suppress_human,
        main_arena_candidate.as_ref(),
        printed_bin_experiment_block,
    );
    maybe_print_unavailable_main_arena_top_candidate(
        &config,
        suppress_human,
        printed_main_arena_top_candidate_block,
    );
    let update = LiveTraceUpdate::SessionEnd(JsonSessionEnd {
        record: json::json_session_end_record("unknown", event_count),
    });
    let mut json_writer = json_writer.borrow_mut();
    if let Some(sender) = &live_sender {
        let mut sink = LiveTuiSink {
            sender: sender.clone(),
            json_writer: json_writer.as_mut(),
        };
        sink.on_update(&update)?;
    } else {
        let mut sink = CurrentOutputSink {
            config: &config,
            json_writer: json_writer.as_mut(),
        };
        sink.on_update(&update)?;
    }
    Ok(())
}

fn run_trace_heap_live_tui(
    config: RenderConfig,
    program: String,
    target_args: Vec<String>,
    trace_mode: AllocationTraceMode,
) -> Result<()> {
    let (sender, receiver) = mpsc::channel();
    let (control_sender, control_receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        run_trace_heap_worker(
            config,
            program,
            target_args,
            trace_mode,
            Some(sender),
            Some(control_receiver),
        )
    });

    let tui_result = run_live_tui_loop(receiver, control_sender);
    let worker_result = worker
        .join()
        .map_err(|_| anyhow::anyhow!("trace worker thread panicked"))?;

    tui_result?;
    worker_result
}

fn run_live_tui_loop(
    receiver: mpsc::Receiver<LiveTraceUpdate>,
    control_sender: mpsc::Sender<LiveCommandMessage>,
) -> Result<()> {
    let _guard = TerminalModeGuard::enter()?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal")?;
    let mut app = LiveTuiApp::default();
    let config = ReplayConfig::default();
    let mut input_closed = false;

    terminal.clear().context("failed to clear terminal")?;
    loop {
        while !input_closed {
            match receiver.try_recv() {
                Ok(update) => app.apply_update(update),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    input_closed = true;
                    if app.session_end.is_none() {
                        app.status_line =
                            "trace worker ended without session end; press q to quit".to_string();
                    }
                    break;
                }
            }
        }

        terminal
            .draw(|frame| draw_live_tui(frame, &app, &config))
            .context("failed to draw live TUI")?;

        if event::poll(Duration::from_millis(100)).context("failed to poll terminal events")? {
            let Event::Key(key) = event::read().context("failed to read terminal event")? else {
                continue;
            };

            if handle_live_tui_key(key, &mut app, input_closed, &control_sender) {
                break;
            }
        }
    }

    Ok(())
}

fn draw_live_tui(frame: &mut ratatui::Frame<'_>, app: &LiveTuiApp, config: &ReplayConfig) {
    let area = frame.size();
    if area.width < 80 || area.height < 20 {
        let message = Paragraph::new("terminal too small for debugger layout")
            .block(Block::default().title("Heapify").borders(Borders::ALL));
        frame.render_widget(message, area);
        return;
    }

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(19),
            Constraint::Percentage(24),
            Constraint::Percentage(38),
            Constraint::Min(5),
        ])
        .split(columns[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(columns[1]);

    render_live_registers_pane(frame, app, left[0]);
    render_live_code_pane(frame, app, config, left[1]);
    render_live_trace_pane(frame, app, left[2]);
    render_live_console_pane(frame, app, left[3]);
    render_live_right_tabs(frame, app, right[0]);
    render_live_right_tab_body(frame, app, config, right[1]);
}

fn render_live_trace_pane(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    area: ratatui::layout::Rect,
) {
    let timeline_inner_height = area.height.saturating_sub(2) as usize;
    let timeline_offset =
        visible_timeline_offset(app.selected_index, timeline_inner_height, app.events.len());
    let timeline_items = app
        .events
        .iter()
        .skip(timeline_offset)
        .take(timeline_inner_height.max(1))
        .filter_map(|record| {
            let json::JsonTraceRecord::Event { event } = record else {
                return None;
            };
            let state = allocator_state_for_live_event(app, replay_event_id(event));
            Some(ListItem::new(format_timeline_event_summary(
                event,
                state.as_ref(),
            )))
        })
        .collect::<Vec<_>>();
    let mut list_state = ListState::default();
    if !app.events.is_empty() {
        list_state.select(Some(app.selected_index.saturating_sub(timeline_offset)));
    }
    let timeline = List::new(timeline_items)
        .block(live_tui_block(
            "Trace",
            app.focused_debugger_pane == LiveDebuggerPane::Trace,
        ))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(timeline, area, &mut list_state);
}

fn render_live_code_pane(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    _config: &ReplayConfig,
    area: ratatui::layout::Rect,
) {
    let details_text = format_live_code_context(app);
    let details_scroll = clamped_scroll_for_text(
        &details_text,
        app.code_pane_scroll,
        area.height.saturating_sub(2) as usize,
    );
    let details_title = format!(
        "Code {}",
        format_scroll_indicator(
            details_scroll,
            text_line_count(&details_text),
            area.height.saturating_sub(2) as usize
        )
    );
    let details = Paragraph::new(text_from_string(&details_text))
        .block(live_tui_block(
            &details_title,
            app.focused_debugger_pane == LiveDebuggerPane::Code,
        ))
        .scroll((scroll_offset_u16(details_scroll), 0));
    frame.render_widget(details, area);
}

fn render_live_registers_pane(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    area: ratatui::layout::Rect,
) {
    let text = format_live_registers_pane(app);
    let register_scroll = clamped_scroll_for_text(
        &text,
        app.register_pane_scroll,
        area.height.saturating_sub(2) as usize,
    );
    let title = format!(
        "Registers {}",
        format_scroll_indicator(
            register_scroll,
            text_line_count(&text),
            area.height.saturating_sub(2) as usize
        )
    );
    let registers = Paragraph::new(text_from_string(&text))
        .block(live_tui_block(
            &title,
            app.focused_debugger_pane == LiveDebuggerPane::Registers,
        ))
        .scroll((scroll_offset_u16(register_scroll), 0));
    frame.render_widget(registers, area);
}

fn render_live_console_pane(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    area: ratatui::layout::Rect,
) {
    let text = format_live_console_pane(app, area.height.saturating_sub(2) as usize);
    let console = Paragraph::new(text_from_string(&text)).block(live_tui_block(
        "Console",
        app.focused_debugger_pane == LiveDebuggerPane::Console,
    ));
    frame.render_widget(console, area);
}

fn render_live_right_tabs(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    area: ratatui::layout::Rect,
) {
    let tabs = [
        LiveRightTab::Heap,
        LiveRightTab::Stack,
        LiveRightTab::Logs,
        LiveRightTab::Maps,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, tab)| {
        if tab == app.active_right_tab {
            format!("[{}:{}]", index + 1, tab.label())
        } else {
            format!(" {}:{} ", index + 1, tab.label())
        }
    })
    .collect::<Vec<_>>()
    .join(" ");
    let block = live_tui_block(
        "Right Tabs",
        app.focused_debugger_pane == LiveDebuggerPane::RightTab,
    );
    frame.render_widget(Paragraph::new(tabs).block(block), area);
}

fn render_live_right_tab_body(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    config: &ReplayConfig,
    area: ratatui::layout::Rect,
) {
    match app.active_right_tab {
        LiveRightTab::Heap => render_live_heap_tab(frame, app, area),
        LiveRightTab::Stack => render_live_stack_tab(frame, app, area),
        LiveRightTab::Logs => render_live_logs_tab(frame, app, area),
        LiveRightTab::Maps => render_live_maps_tab(frame, app, area),
    }

    let _ = config;
}

fn render_live_maps_tab(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    area: ratatui::layout::Rect,
) {
    let text = format_live_maps_tab(app);
    let scroll = clamped_scroll_for_text(
        &text,
        app.maps_tab_scroll,
        area.height.saturating_sub(2) as usize,
    );
    let title = format!(
        "Maps {}",
        format_scroll_indicator(
            scroll,
            text_line_count(&text),
            area.height.saturating_sub(2) as usize
        )
    );
    frame.render_widget(
        Paragraph::new(text_from_string(&text))
            .block(live_tui_block(
                &title,
                app.focused_debugger_pane == LiveDebuggerPane::RightTab
                    && app.active_right_tab == LiveRightTab::Maps,
            ))
            .scroll((scroll_offset_u16(scroll), 0)),
        area,
    );
}

fn render_live_stack_tab(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    area: ratatui::layout::Rect,
) {
    let text = format_live_stack_tab(app);
    let scroll = clamped_scroll_for_text(
        &text,
        app.stack_tab_scroll,
        area.height.saturating_sub(2) as usize,
    );
    let title = format!(
        "Stack {}",
        format_scroll_indicator(
            scroll,
            text_line_count(&text),
            area.height.saturating_sub(2) as usize
        )
    );
    frame.render_widget(
        Paragraph::new(text_from_string(&text))
            .block(live_tui_block(
                &title,
                app.focused_debugger_pane == LiveDebuggerPane::RightTab
                    && app.active_right_tab == LiveRightTab::Stack,
            ))
            .scroll((scroll_offset_u16(scroll), 0)),
        area,
    );
}

fn render_live_heap_tab(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    area: ratatui::layout::Rect,
) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(25),
            Constraint::Min(4),
        ])
        .split(area);

    let heap_text = format_live_heap_layout_pane(app, usize::MAX);
    let heap_scroll = clamped_scroll_for_text(
        &heap_text,
        app.heap_layout_scroll,
        sections[0].height.saturating_sub(2) as usize,
    );
    let heap_title = format!(
        "Heap Layout {}",
        format_scroll_indicator(
            heap_scroll,
            text_line_count(&heap_text),
            sections[0].height.saturating_sub(2) as usize
        )
    );
    frame.render_widget(
        Paragraph::new(text_from_string(&heap_text))
            .block(live_tui_block(
                &heap_title,
                app.focused_debugger_pane == LiveDebuggerPane::RightTab
                    && app.active_right_tab == LiveRightTab::Heap,
            ))
            .scroll((scroll_offset_u16(heap_scroll), 0)),
        sections[0],
    );

    let allocator_text = format_live_allocator_scan_pane(app);
    let allocator_scroll = clamped_scroll_for_text(
        &allocator_text,
        app.allocator_scan_scroll,
        sections[1].height.saturating_sub(2) as usize,
    );
    frame.render_widget(
        Paragraph::new(text_from_string(&allocator_text))
            .block(
                Block::default()
                    .title("Allocator / Scan")
                    .borders(Borders::ALL),
            )
            .scroll((scroll_offset_u16(allocator_scroll), 0)),
        sections[1],
    );

    let inspector_text = if app.show_chunk_inspector {
        live_chunk_inspector_text(app)
    } else {
        live_related_records_text(app, &ReplayConfig::default())
    };
    let inspector_scroll = if app.show_chunk_inspector {
        app.chunk_inspector_scroll
    } else {
        app.related_records_scroll
    };
    let inspector_scroll = clamped_scroll_for_text(
        &inspector_text,
        inspector_scroll,
        sections[2].height.saturating_sub(2) as usize,
    );
    frame.render_widget(
        Paragraph::new(text_from_string(&inspector_text))
            .block(
                Block::default()
                    .title(if app.show_chunk_inspector {
                        "Chunk Inspector"
                    } else {
                        "Related"
                    })
                    .borders(Borders::ALL),
            )
            .scroll((scroll_offset_u16(inspector_scroll), 0)),
        sections[2],
    );
}

fn render_live_logs_tab(
    frame: &mut ratatui::Frame<'_>,
    app: &LiveTuiApp,
    area: ratatui::layout::Rect,
) {
    let text = format_live_logs_pane(app);
    let scroll = clamped_scroll_for_text(
        &text,
        app.related_records_scroll,
        area.height.saturating_sub(2) as usize,
    );
    frame.render_widget(
        Paragraph::new(text_from_string(&text))
            .block(live_tui_block(
                "Logs",
                app.focused_debugger_pane == LiveDebuggerPane::RightTab,
            ))
            .scroll((scroll_offset_u16(scroll), 0)),
        area,
    );
}

fn handle_live_tui_key(
    key: KeyEvent,
    app: &mut LiveTuiApp,
    input_closed: bool,
    control_sender: &mpsc::Sender<LiveCommandMessage>,
) -> bool {
    if app.search_prompt_active {
        handle_live_tui_search_key(key, app);
        return false;
    }

    if app.console_input_active {
        return handle_live_tui_console_key(key, app, input_closed, control_sender);
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        request_live_stop(app, input_closed, control_sender);
        return false;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            if app.session_end.is_some() || input_closed {
                return true;
            }
            request_live_stop(app, input_closed, control_sender);
        }
        KeyCode::Char('p') => {
            send_live_command(app, control_sender, LiveCommand::Pause);
        }
        KeyCode::Char('r') => {
            send_live_command(app, control_sender, LiveCommand::Resume);
        }
        KeyCode::Char('n') => {
            send_live_command(app, control_sender, LiveCommand::StepAllocatorEvent);
        }
        KeyCode::Char('.') => {
            send_live_command(app, control_sender, LiveCommand::StepInstruction);
        }
        KeyCode::Char(',') => {
            send_live_command(app, control_sender, LiveCommand::StepInstructionOver);
        }
        KeyCode::Char('c') => {
            send_live_command(app, control_sender, LiveCommand::Continue);
        }
        KeyCode::Char(' ') => match app.target_status {
            LiveTargetStatus::Running => {
                send_live_command(app, control_sender, LiveCommand::Pause);
            }
            LiveTargetStatus::Paused => {
                send_live_command(app, control_sender, LiveCommand::Resume);
            }
            LiveTargetStatus::NotStarted
            | LiveTargetStatus::SteppingToNextAllocatorEvent
            | LiveTargetStatus::SteppingInstruction
            | LiveTargetStatus::SteppingInstructionOver
            | LiveTargetStatus::Stopping
            | LiveTargetStatus::Exited => {}
        },
        KeyCode::Char('h') => {
            app.show_heap_pane = !app.show_heap_pane;
            app.ensure_focus_visible();
        }
        KeyCode::Char('s') => {
            app.show_scan_pane = !app.show_scan_pane;
            app.ensure_focus_visible();
        }
        KeyCode::Char('i') => {
            app.show_chunk_inspector = !app.show_chunk_inspector;
            app.chunk_inspector_scroll = 0;
        }
        KeyCode::Char('g') => {
            app.start_heap_search_prompt();
        }
        KeyCode::Char(':') => {
            app.start_console_input();
        }
        KeyCode::Char('f') => {
            app.follow_tail = !app.follow_tail;
            if app.follow_tail {
                app.select_latest();
            }
        }
        KeyCode::Char('d') if app.focused_debugger_pane == LiveDebuggerPane::Code => {
            app.focus_code_and_recenter();
        }
        KeyCode::Char('1') => app.set_active_right_tab(LiveRightTab::Heap),
        KeyCode::Char('2') => app.set_active_right_tab(LiveRightTab::Stack),
        KeyCode::Char('3') => app.set_active_right_tab(LiveRightTab::Logs),
        KeyCode::Char('4') => app.set_active_right_tab(LiveRightTab::Maps),
        KeyCode::Char('[') => app.previous_right_tab(),
        KeyCode::Char(']') => app.next_right_tab(),
        KeyCode::Tab => app.focus_next_pane(),
        KeyCode::BackTab => app.focus_previous_pane(),
        KeyCode::Down | KeyCode::Char('j') => match app.focused_debugger_pane {
            LiveDebuggerPane::Trace => app.select_next(),
            LiveDebuggerPane::RightTab if app.active_right_tab == LiveRightTab::Heap => {
                app.select_next_chunk()
            }
            _ => app.scroll_focused(1),
        },
        KeyCode::Up | KeyCode::Char('k') => match app.focused_debugger_pane {
            LiveDebuggerPane::Trace => app.select_previous(),
            LiveDebuggerPane::RightTab if app.active_right_tab == LiveRightTab::Heap => {
                app.select_previous_chunk()
            }
            _ => app.scroll_focused(-1),
        },
        KeyCode::Enter => {
            if app.focused_debugger_pane == LiveDebuggerPane::RightTab
                && app.active_right_tab == LiveRightTab::Heap
            {
                app.select_chunk_at_current_layout_index();
                app.show_chunk_inspector = true;
                app.chunk_inspector_scroll = 0;
            }
        }
        KeyCode::PageDown => {
            if app.focused_debugger_pane == LiveDebuggerPane::Trace {
                app.select_page_down();
            } else {
                app.scroll_focused(10);
            }
        }
        KeyCode::PageUp => {
            if app.focused_debugger_pane == LiveDebuggerPane::Trace {
                app.select_page_up();
            } else {
                app.scroll_focused(-10);
            }
        }
        KeyCode::Home => app.scroll_focused_top(),
        KeyCode::End => app.scroll_focused_bottom(),
        _ => {}
    }

    false
}

fn handle_live_tui_console_key(
    key: KeyEvent,
    app: &mut LiveTuiApp,
    input_closed: bool,
    control_sender: &mpsc::Sender<LiveCommandMessage>,
) -> bool {
    match key.code {
        KeyCode::Enter => submit_console_input(app, input_closed, control_sender),
        KeyCode::Esc => {
            app.cancel_console_input();
            false
        }
        KeyCode::Backspace => {
            app.pop_console_char();
            false
        }
        KeyCode::Up => {
            app.history_previous();
            false
        }
        KeyCode::Down => {
            app.history_next();
            false
        }
        KeyCode::Char(ch)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            app.push_console_char(ch);
            false
        }
        _ => false,
    }
}

fn submit_console_input(
    app: &mut LiveTuiApp,
    input_closed: bool,
    control_sender: &mpsc::Sender<LiveCommandMessage>,
) -> bool {
    let input = app.console_input.trim().to_string();
    app.console_input_active = false;
    app.console_input.clear();
    app.console_history_index = None;
    if input.is_empty() {
        return false;
    }

    app.remember_console_command(&input);
    app.push_console_output(format!("heapify> {input}"));
    execute_console_command(
        app,
        parse_console_command(&input),
        &input,
        input_closed,
        control_sender,
    )
}

fn execute_console_command(
    app: &mut LiveTuiApp,
    command: ConsoleCommand,
    raw_input: &str,
    input_closed: bool,
    control_sender: &mpsc::Sender<LiveCommandMessage>,
) -> bool {
    match command {
        ConsoleCommand::Help => {
            app.push_console_output(
                "commands: help, continue, pause, resume, next, stepi, si, step, nexti, ni, disas, disassemble, stop, regs, stack, maps, heap ADDR, jump ADDR, tab NAME",
            );
        }
        ConsoleCommand::Continue => {
            send_console_live_command(app, control_sender, LiveCommand::Continue);
        }
        ConsoleCommand::Pause => {
            send_console_live_command(app, control_sender, LiveCommand::Pause);
        }
        ConsoleCommand::Resume => {
            send_console_live_command(app, control_sender, LiveCommand::Resume);
        }
        ConsoleCommand::NextAllocatorEvent => {
            send_console_live_command(app, control_sender, LiveCommand::StepAllocatorEvent);
        }
        ConsoleCommand::StepInstruction => {
            send_console_live_command(app, control_sender, LiveCommand::StepInstruction);
        }
        ConsoleCommand::StepInstructionOver => {
            send_console_live_command(app, control_sender, LiveCommand::StepInstructionOver);
        }
        ConsoleCommand::Stop => {
            if app.session_end.is_some() || input_closed {
                return true;
            }
            send_console_live_command(app, control_sender, LiveCommand::Stop);
        }
        ConsoleCommand::Registers => {
            app.focused_debugger_pane = LiveDebuggerPane::Registers;
            app.sync_legacy_focus_from_debugger_pane();
        }
        ConsoleCommand::Disassemble => {
            app.focus_code_and_recenter();
        }
        ConsoleCommand::Stack => {
            app.set_active_right_tab(LiveRightTab::Stack);
        }
        ConsoleCommand::Maps => {
            app.set_active_right_tab(LiveRightTab::Maps);
        }
        ConsoleCommand::HeapJump(query) => {
            app.execute_heap_search_query(query);
            if let Some(status) = app.search_status.clone() {
                app.push_console_output(status);
            }
        }
        ConsoleCommand::SelectRightTab(tab) => {
            app.set_active_right_tab(tab);
        }
        ConsoleCommand::Unknown(input) => {
            if !input.is_empty() {
                app.push_console_output(format!("unknown command: {raw_input}; try help"));
            }
        }
    }
    false
}

fn handle_live_tui_search_key(key: KeyEvent, app: &mut LiveTuiApp) {
    match key.code {
        KeyCode::Enter => app.execute_heap_search(),
        KeyCode::Esc => app.cancel_heap_search_prompt(),
        KeyCode::Backspace => app.pop_search_char(),
        KeyCode::Char(ch)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            app.push_search_char(ch);
        }
        _ => {}
    }
}

fn request_live_stop(
    app: &mut LiveTuiApp,
    input_closed: bool,
    control_sender: &mpsc::Sender<LiveCommandMessage>,
) {
    if app.session_end.is_some() || input_closed {
        return;
    }

    send_live_command(app, control_sender, LiveCommand::Stop);
}

fn send_live_command(
    app: &mut LiveTuiApp,
    control_sender: &mpsc::Sender<LiveCommandMessage>,
    command: LiveCommand,
) {
    let Ok(message) = app.prepare_command(command) else {
        return;
    };

    if control_sender.send(message).is_err() {
        app.last_command = Some(command);
        app.last_command_status = Some(LiveCommandStatus::Failed);
        app.last_command_message = Some("failed to send command to trace worker".to_string());
        app.status_line = "failed to send command to trace worker".to_string();
        return;
    }

    apply_sent_live_command(app, command);
}

fn send_console_live_command(
    app: &mut LiveTuiApp,
    control_sender: &mpsc::Sender<LiveCommandMessage>,
    command: LiveCommand,
) {
    let message = match app.prepare_command(command) {
        Ok(message) => message,
        Err(reason) => {
            app.push_console_output(reason);
            return;
        }
    };

    if control_sender.send(message).is_err() {
        app.last_command = Some(command);
        app.last_command_status = Some(LiveCommandStatus::Failed);
        app.last_command_message = Some("failed to send command to trace worker".to_string());
        app.status_line = "failed to send command to trace worker".to_string();
        app.push_console_output("failed to send command to trace worker");
        return;
    }

    apply_sent_live_command(app, command);
}

fn apply_sent_live_command(app: &mut LiveTuiApp, command: LiveCommand) {
    match command {
        LiveCommand::Stop => {
            app.target_status = LiveTargetStatus::Stopping;
            app.status_line = "stopping target...".to_string();
            app.last_command_message = Some("stopping target...".to_string());
        }
        LiveCommand::Pause => {
            app.follow_tail_before_pause = Some(app.follow_tail);
            app.follow_tail = false;
            app.status_line = "pause requested...".to_string();
            app.last_command_message = Some("pause requested...".to_string());
        }
        LiveCommand::Resume => {
            if let Some(follow_tail) = app.follow_tail_before_pause.take() {
                app.follow_tail = follow_tail;
                if app.follow_tail {
                    app.selected_index = app.events.len().saturating_sub(1);
                }
            }
            app.status_line = "resume requested...".to_string();
            app.last_command_message = Some("resume requested...".to_string());
        }
        LiveCommand::Continue => {
            app.target_status = LiveTargetStatus::Running;
            app.follow_tail_before_pause = None;
            app.follow_tail = true;
            app.selected_index = app.events.len().saturating_sub(1);
            app.status_line = "running".to_string();
            app.last_command_message = Some("running".to_string());
        }
        LiveCommand::StepAllocatorEvent => {
            app.target_status = LiveTargetStatus::SteppingToNextAllocatorEvent;
            app.follow_tail = true;
            app.selected_index = app.events.len().saturating_sub(1);
            app.status_line = "stepping to next allocator event...".to_string();
            app.last_command_message = Some("stepping to next allocator event...".to_string());
        }
        LiveCommand::StepInstruction => {
            app.target_status = LiveTargetStatus::SteppingInstruction;
            app.follow_tail = false;
            app.status_line = "waiting for next stop...".to_string();
            app.last_command_message = Some("waiting for next stop...".to_string());
        }
        LiveCommand::StepInstructionOver => {
            app.target_status = LiveTargetStatus::SteppingInstructionOver;
            app.follow_tail = false;
            app.status_line = "waiting for next stop...".to_string();
            app.last_command_message = Some("waiting for next stop...".to_string());
        }
    }
}

fn live_tui_block(title: &str, focused: bool) -> Block<'static> {
    let title = if focused {
        format!("{title} *")
    } else {
        title.to_string()
    };
    let block = Block::default().title(title).borders(Borders::ALL);
    if focused {
        block.border_style(Style::default().fg(Color::Yellow))
    } else {
        block
    }
}

fn next_live_debugger_pane(current: LiveDebuggerPane, direction: isize) -> LiveDebuggerPane {
    const PANES: [LiveDebuggerPane; 5] = [
        LiveDebuggerPane::Registers,
        LiveDebuggerPane::Code,
        LiveDebuggerPane::Trace,
        LiveDebuggerPane::Console,
        LiveDebuggerPane::RightTab,
    ];
    let current_index = PANES.iter().position(|pane| *pane == current).unwrap_or(0) as isize;
    let len = PANES.len() as isize;
    PANES[(current_index + direction).rem_euclid(len) as usize]
}

fn next_live_right_tab(current: LiveRightTab, direction: isize) -> LiveRightTab {
    const TABS: [LiveRightTab; 4] = [
        LiveRightTab::Heap,
        LiveRightTab::Stack,
        LiveRightTab::Logs,
        LiveRightTab::Maps,
    ];
    let current_index = TABS.iter().position(|tab| *tab == current).unwrap_or(0) as isize;
    let len = TABS.len() as isize;
    TABS[(current_index + direction).rem_euclid(len) as usize]
}

fn clamp_scroll(scroll: usize, line_count: usize, viewport_height: usize) -> usize {
    if viewport_height == 0 || line_count <= viewport_height {
        return 0;
    }
    scroll.min(line_count.saturating_sub(viewport_height))
}

fn scroll_delta(scroll: usize, delta: isize) -> usize {
    if delta.is_negative() {
        scroll.saturating_sub(delta.unsigned_abs())
    } else {
        scroll.saturating_add(delta as usize)
    }
}

fn format_scroll_indicator(scroll: usize, line_count: usize, viewport_height: usize) -> String {
    let clamped = clamp_scroll(scroll, line_count, viewport_height);
    if line_count <= viewport_height || viewport_height == 0 {
        return String::new();
    }
    let end = (clamped + viewport_height).min(line_count);
    format!("[{}-{}/{}]", clamped + 1, end, line_count)
}

fn clamped_scroll_for_text(text: &str, scroll: usize, viewport_height: usize) -> usize {
    clamp_scroll(scroll, text_line_count(text), viewport_height)
}

fn scroll_offset_u16(scroll: usize) -> u16 {
    scroll.min(u16::MAX as usize) as u16
}

fn text_line_count(text: &str) -> usize {
    text.lines().count().max(1)
}

fn live_event_details_text(app: &LiveTuiApp, config: &ReplayConfig) -> String {
    let Some(record) = app.selected_event_record() else {
        return app
            .latest_register_snapshot
            .as_ref()
            .map(|snapshot| format!("registers:\n    {}", snapshot.summary_line()))
            .unwrap_or_else(|| "waiting for events".to_string());
    };

    let mut text = format_replay_record(record, config);
    if let Some(event_id) = replay_record_event_id(record) {
        if let Some(snapshot) = app.register_snapshots_by_event_id.get(&event_id) {
            text.push_str("\nregisters:\n    ");
            text.push_str(&snapshot.summary_line());
        }
    }
    text
}

pub fn diff_register_snapshots(
    previous: Option<&RegisterSnapshot>,
    current: &RegisterSnapshot,
) -> BTreeSet<String> {
    let Some(previous) = previous else {
        return BTreeSet::new();
    };

    let previous_values = previous
        .registers
        .iter()
        .map(|register| (normalize_register_name(&register.name), register.value))
        .collect::<BTreeMap<_, _>>();
    current
        .registers
        .iter()
        .filter_map(|register| {
            let name = normalize_register_name(&register.name);
            match previous_values.get(&name) {
                Some(previous_value) if *previous_value == register.value => None,
                _ => Some(name),
            }
        })
        .collect()
}

pub fn render_register_lines(
    snapshot: &RegisterSnapshot,
    changed_registers: &BTreeSet<String>,
    maps: Option<&ProcessMapsSnapshot>,
    latest_heap_layout: Option<&json::JsonTraceRecord>,
    selected_chunk_user_addr: Option<u64>,
) -> Vec<RenderedRegisterLine> {
    const REGISTER_ORDER: [&str; 18] = [
        "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15", "eflags",
    ];

    let registers = snapshot
        .registers
        .iter()
        .map(|register| (normalize_register_name(&register.name), register))
        .collect::<BTreeMap<_, _>>();
    let mut rendered = Vec::new();
    let mut emitted = BTreeSet::new();

    for name in REGISTER_ORDER {
        if let Some(register) = registers.get(name) {
            emitted.insert(name.to_string());
            rendered.push(render_register_line(
                name,
                register.value,
                register.role,
                changed_registers,
                maps,
                latest_heap_layout,
                selected_chunk_user_addr,
            ));
        }
    }

    for (name, register) in registers {
        if emitted.contains(&name) {
            continue;
        }
        rendered.push(render_register_line(
            &name,
            register.value,
            register.role,
            changed_registers,
            maps,
            latest_heap_layout,
            selected_chunk_user_addr,
        ));
    }

    rendered
}

fn render_register_line(
    name: &str,
    value: u64,
    role: Option<RegisterRole>,
    changed_registers: &BTreeSet<String>,
    maps: Option<&ProcessMapsSnapshot>,
    latest_heap_layout: Option<&json::JsonTraceRecord>,
    selected_chunk_user_addr: Option<u64>,
) -> RenderedRegisterLine {
    let normalized_name = normalize_register_name(name);
    RenderedRegisterLine {
        name: normalized_name.to_uppercase(),
        value: format_register_value_fixed_hex(value),
        role,
        changed: changed_registers.contains(&normalized_name),
        annotation: annotate_register_value(
            value,
            maps,
            latest_heap_layout,
            selected_chunk_user_addr,
        ),
    }
}

fn normalize_register_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn format_register_value_fixed_hex(value: u64) -> String {
    format!("0x{value:016x}")
}

pub fn classify_address(
    address: u64,
    maps: Option<&ProcessMapsSnapshot>,
    latest_heap_layout: Option<&json::JsonTraceRecord>,
) -> AddressClassification {
    if let Some(classification) = classify_heap_address(address, latest_heap_layout) {
        return classification;
    }

    if let Some(entry) = maps.and_then(|snapshot| {
        snapshot
            .entries
            .iter()
            .find(|entry| entry.start <= address && address < entry.end)
    }) {
        let (kind, label) = classify_map_entry(entry);
        return AddressClassification {
            address,
            kind,
            label,
            map: Some(entry.clone()),
            heap_detail: None,
            symbol: None,
        };
    }

    AddressClassification {
        address,
        kind: AddressRegionKind::Unknown,
        label: "unmapped".to_string(),
        map: None,
        heap_detail: None,
        symbol: None,
    }
}

fn classify_heap_address(
    address: u64,
    latest_heap_layout: Option<&json::JsonTraceRecord>,
) -> Option<AddressClassification> {
    let json::JsonTraceRecord::HeapLayout { chunks, .. } = latest_heap_layout? else {
        return None;
    };

    for chunk in chunks {
        let chunk_addr = parse_json_addr(&chunk.chunk_addr)?;
        let user_addr = parse_json_addr(&chunk.user_addr)?;
        if address == user_addr {
            return Some(AddressClassification {
                address,
                kind: AddressRegionKind::Heap,
                label: "heap user".to_string(),
                map: None,
                heap_detail: Some(HeapAddressDetail::UserPointer {
                    chunk_addr,
                    user_addr,
                }),
                symbol: None,
            });
        }
        if address == chunk_addr {
            return Some(AddressClassification {
                address,
                kind: AddressRegionKind::Heap,
                label: "heap chunk".to_string(),
                map: None,
                heap_detail: Some(HeapAddressDetail::ChunkHeader {
                    chunk_addr,
                    user_addr,
                }),
                symbol: None,
            });
        }
    }

    for chunk in chunks {
        let Some(chunk_addr) = parse_json_addr(&chunk.chunk_addr) else {
            continue;
        };
        let Some(user_addr) = parse_json_addr(&chunk.user_addr) else {
            continue;
        };
        let Some(size) = parse_json_addr(&chunk.size) else {
            continue;
        };
        let Some(end) = chunk_addr.checked_add(size) else {
            continue;
        };
        if chunk_addr <= address && address < end {
            let offset = address.saturating_sub(user_addr);
            return Some(AddressClassification {
                address,
                kind: AddressRegionKind::Heap,
                label: format!("heap+0x{offset:x}"),
                map: None,
                heap_detail: Some(HeapAddressDetail::Interior {
                    chunk_addr,
                    user_addr,
                    offset,
                }),
                symbol: None,
            });
        }
    }

    None
}

fn classify_map_entry(entry: &ProcessMapEntry) -> (AddressRegionKind, String) {
    let pathname = entry.pathname.as_deref().unwrap_or_default();
    match pathname {
        "[heap]" => return (AddressRegionKind::Heap, "heap".to_string()),
        "[stack]" => return (AddressRegionKind::Stack, "stack".to_string()),
        "[vdso]" => return (AddressRegionKind::Vdso, "vdso".to_string()),
        "[vvar]" => return (AddressRegionKind::Vvar, "vvar".to_string()),
        "[vsyscall]" => return (AddressRegionKind::Vsvar, "vsyscall".to_string()),
        _ => {}
    }

    if pathname.contains("libc.so")
        || pathname.ends_with("/libc.so.6")
        || pathname.contains("libc-")
    {
        return (AddressRegionKind::Libc, "libc".to_string());
    }
    if pathname.contains("ld-linux") || pathname.contains("/ld-") {
        return (AddressRegionKind::Loader, "loader".to_string());
    }
    if pathname.is_empty() {
        return (AddressRegionKind::Anonymous, "anon".to_string());
    }
    if entry.permissions.contains('x') {
        return (AddressRegionKind::Code, "code".to_string());
    }

    (
        AddressRegionKind::MappedFile,
        map_path_label(pathname).to_string(),
    )
}

fn map_path_label(pathname: &str) -> &str {
    pathname
        .rsplit('/')
        .next()
        .filter(|basename| !basename.is_empty())
        .unwrap_or(pathname)
}

fn annotation_from_classification(classification: AddressClassification) -> Option<String> {
    match classification.kind {
        AddressRegionKind::Unknown => None,
        AddressRegionKind::Heap => match classification.heap_detail {
            Some(HeapAddressDetail::Interior { .. }) => Some("heap".to_string()),
            Some(HeapAddressDetail::ChunkHeader { .. }) => Some("heap chunk".to_string()),
            _ => Some(classification.label),
        },
        _ => Some(classification.label),
    }
}

fn annotate_register_value(
    value: u64,
    maps: Option<&ProcessMapsSnapshot>,
    latest_heap_layout: Option<&json::JsonTraceRecord>,
    selected_chunk_user_addr: Option<u64>,
) -> Option<String> {
    if selected_chunk_user_addr == Some(value) {
        return Some("selected chunk".to_string());
    }

    annotation_from_classification(classify_address(value, maps, latest_heap_layout))
}

fn annotate_stack_snapshot(
    mut snapshot: StackSnapshot,
    maps: Option<&ProcessMapsSnapshot>,
    latest_heap_layout: Option<&json::JsonTraceRecord>,
    current_rip: Option<u64>,
) -> StackSnapshot {
    for word in &mut snapshot.words {
        word.annotation = annotate_stack_value(word.value, maps, latest_heap_layout, current_rip);
    }
    snapshot
}

fn annotate_stack_value(
    value: u64,
    maps: Option<&ProcessMapsSnapshot>,
    latest_heap_layout: Option<&json::JsonTraceRecord>,
    current_rip: Option<u64>,
) -> Option<String> {
    if current_rip == Some(value) {
        return Some("rip".to_string());
    }

    annotation_from_classification(classify_address(value, maps, latest_heap_layout))
}

pub fn format_stack_word_line(word: &StackWord) -> String {
    let annotation = word
        .annotation
        .as_deref()
        .map(|annotation| format!(" ; {annotation}"))
        .unwrap_or_default();
    format!(
        "{}  {}  {}{}",
        format_stack_offset(word.offset_from_sp),
        format_register_value_fixed_hex(word.address),
        format_register_value_fixed_hex(word.value),
        annotation
    )
}

fn format_stack_offset(offset: i64) -> String {
    if offset < 0 {
        format!("-0x{:03x}", offset.unsigned_abs())
    } else {
        format!("+0x{offset:03x}")
    }
}

pub fn format_stack_snapshot_lines(snapshot: &StackSnapshot) -> Vec<String> {
    let mut lines = vec![
        format!(
            "RSP:       {}",
            format_register_value_fixed_hex(snapshot.stack_pointer)
        ),
        format!("Word size: {} bytes", snapshot.word_size),
    ];

    if snapshot.truncated {
        let warning = snapshot
            .read_error
            .as_deref()
            .map(|error| format!("truncated: {error}"))
            .unwrap_or_else(|| "truncated".to_string());
        lines.push(warning);
    }

    lines.push(String::new());
    lines.push("Offset  Address             Value".to_string());
    lines.extend(snapshot.words.iter().map(format_stack_word_line));
    lines
}

fn format_live_stack_tab(app: &LiveTuiApp) -> String {
    app.latest_stack_snapshot
        .as_ref()
        .map(format_stack_snapshot_lines)
        .map(|lines| lines.join("\n"))
        .unwrap_or_else(|| "stack snapshot unavailable".to_string())
}

pub fn format_process_map_entry(entry: &ProcessMapEntry) -> String {
    let pathname = entry.pathname.as_deref().unwrap_or("");
    let device = entry.device.as_deref().unwrap_or("??:??");
    let inode = entry
        .inode
        .map(|inode| inode.to_string())
        .unwrap_or_else(|| "?".to_string());
    if pathname.is_empty() {
        format!(
            "{:016x}-{:016x} {:<4} {:08x} {:>5} {:>8}",
            entry.start, entry.end, entry.permissions, entry.offset, device, inode
        )
    } else {
        format!(
            "{:016x}-{:016x} {:<4} {:08x} {:>5} {:>8} {}",
            entry.start, entry.end, entry.permissions, entry.offset, device, inode, pathname
        )
    }
}

pub fn format_process_maps_lines(snapshot: &ProcessMapsSnapshot) -> Vec<String> {
    let mut lines =
        vec!["Start-End                         Perm Offset   Dev    Inode Path".to_string()];
    lines.extend(snapshot.entries.iter().map(format_process_map_entry));
    lines
}

fn format_live_maps_tab(app: &LiveTuiApp) -> String {
    app.latest_process_maps
        .as_ref()
        .map(format_process_maps_lines)
        .map(|lines| lines.join("\n"))
        .unwrap_or_else(|| "process maps unavailable".to_string())
}

fn format_live_registers_pane(app: &LiveTuiApp) -> String {
    let Some(snapshot) = app.latest_register_snapshot.as_ref() else {
        return "registers unavailable".to_string();
    };

    render_register_lines(
        snapshot,
        &app.changed_registers,
        app.latest_process_maps.as_ref(),
        app.latest_heap_layout.as_ref(),
        app.selected_chunk_user_addr,
    )
    .into_iter()
    .map(|line| format_rendered_register_line(&line))
    .collect::<Vec<_>>()
    .join("\n")
}

fn format_rendered_register_line(line: &RenderedRegisterLine) -> String {
    let marker = if line.changed { "*" } else { " " };
    let annotation = line
        .annotation
        .as_deref()
        .map(|annotation| format!(" ; {annotation}"))
        .unwrap_or_default();
    format!("{marker} {:<7} {}{}", line.name, line.value, annotation)
}

pub fn build_minimal_code_context(rip: u64) -> CodeContext {
    CodeContext {
        instruction_pointer: rip,
        symbol: None,
        symbol_addr: None,
        symbol_offset: None,
        object: None,
        source: None,
        disassembly: None,
    }
}

fn build_code_context(
    pid: Pid,
    rip: u64,
    symbolizer: Option<&ProcessSymbolizer>,
    source_mapper: Option<&TargetSourceMapper>,
) -> CodeContext {
    let mut context = build_minimal_code_context(rip);

    if let Some(symbolized) = symbolizer.and_then(|symbolizer| symbolizer.symbolize(rip)) {
        context.symbol = Some(symbolized.symbol);
        context.symbol_addr = Some(symbolized.symbol_addr);
        context.symbol_offset = Some(symbolized.offset);
        context.object = symbolized.object_name;
        context.source = symbolized.source;
    }

    if context.source.is_none() {
        context.source = source_mapper.and_then(|source_mapper| source_mapper.lookup(rip));
    }

    let mut disassembly = read_disassembly_snapshot(
        pid,
        rip,
        DEFAULT_DISASSEMBLY_BEFORE_BYTES,
        DEFAULT_DISASSEMBLY_AFTER_BYTES,
    );
    annotate_disassembly_targets(&mut disassembly, symbolizer);
    context.disassembly = Some(disassembly);

    context
}

fn annotate_disassembly_targets(
    disassembly: &mut DisassemblySnapshot,
    symbolizer: Option<&ProcessSymbolizer>,
) {
    for line in &mut disassembly.lines {
        if let Some(target) = line.target {
            line.target_annotation = symbolizer
                .and_then(|symbolizer| symbolizer.symbolize(target).map(format_symbol_annotation));
        }
    }
}

fn format_symbol_annotation(symbolized: SymbolizedAddress) -> String {
    let mut formatted = symbolized.symbol;
    if symbolized.offset > 0 {
        formatted.push_str(&format!("+0x{:x}", symbolized.offset));
    }
    if let Some(object) = symbolized.object_name {
        if !object.is_empty() && !formatted.contains('!') {
            formatted = format!("{object}!{formatted}");
        }
    }
    formatted
}

pub fn format_code_symbol(
    symbol: Option<&str>,
    offset: Option<u64>,
    object: Option<&str>,
) -> String {
    let Some(symbol) = symbol else {
        return "unavailable".to_string();
    };

    let mut formatted = symbol.to_string();
    if let Some(offset) = offset {
        if offset > 0 {
            formatted.push_str(&format!("+0x{offset:x}"));
        }
    }
    if let Some(object) = object {
        formatted.push_str(&format!(" ({object})"));
    }
    formatted
}

pub fn format_source_location(source: Option<&SourceLocation>) -> String {
    let Some(source) = source else {
        return "unavailable".to_string();
    };

    let mut formatted = source.file.clone().unwrap_or_else(|| "?".to_string());
    if let Some(line) = source.line {
        formatted.push_str(&format!(":{line}"));
        if let Some(column) = source.column {
            formatted.push_str(&format!(":{column}"));
        }
    }
    formatted
}

pub fn format_code_context_lines(context: &CodeContext) -> Vec<String> {
    let mut lines = vec![
        format!(
            "RIP:     {}",
            format_register_value_fixed_hex(context.instruction_pointer)
        ),
        format!(
            "Symbol:  {}",
            format_code_symbol(
                context.symbol.as_deref(),
                context.symbol_offset,
                context.object.as_deref()
            )
        ),
        format!(
            "Source:  {}",
            format_source_location(context.source.as_ref())
        ),
        format!(
            "Object:  {}",
            context.object.as_deref().unwrap_or("unavailable")
        ),
        String::new(),
        "Disassembly:".to_string(),
    ];

    if let Some(disassembly) = &context.disassembly {
        if let Some(error) = disassembly.read_error.as_deref() {
            lines.push(format!("disassembly truncated: {error}"));
        } else if disassembly.truncated_before || disassembly.truncated_after {
            lines.push("disassembly truncated".to_string());
        }
        if disassembly.lines.is_empty() {
            lines.push("disassembly unavailable".to_string());
        } else {
            lines.extend(disassembly.lines.iter().map(format_disassembly_line));
        }
    } else {
        lines.push(format!(
            "> {}  <disassembly unavailable>",
            format_register_value_fixed_hex(context.instruction_pointer)
        ));
    }

    lines
}

fn format_disassembly_line(line: &DisassemblyLine) -> String {
    let marker = if line.is_current { ">" } else { " " };
    let bytes = format_instruction_bytes(&line.bytes);
    let mut text = if line.operands.is_empty() {
        line.mnemonic.clone()
    } else {
        format!("{:<7} {}", line.mnemonic, line.operands)
    };
    if let Some(target) = line.target {
        if let Some(annotation) = line.target_annotation.as_deref() {
            text.push_str(&format!(" <{annotation}>"));
        } else if matches!(
            line.flow_control,
            Some(
                DisassemblyFlowControl::Call
                    | DisassemblyFlowControl::ConditionalBranch
                    | DisassemblyFlowControl::UnconditionalBranch
            )
        ) {
            text.push_str(&format!(" <{}>", format_register_value_fixed_hex(target)));
        }
    }
    format!(
        "{marker} {}  {:<24} {}",
        format_register_value_fixed_hex(line.address),
        truncate_text(&bytes, 24),
        truncate_text(&text, 96)
    )
}

fn format_instruction_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }
    if max_chars == 1 {
        return "~".to_string();
    }
    let mut truncated = text.chars().take(max_chars - 1).collect::<String>();
    truncated.push('~');
    truncated
}

fn format_live_code_context(app: &LiveTuiApp) -> String {
    app.latest_code_context
        .as_ref()
        .map(format_code_context_lines)
        .map(|lines| lines.join("\n"))
        .unwrap_or_else(|| "code context unavailable".to_string())
}

fn format_live_console_pane(app: &LiveTuiApp, viewport_height: usize) -> String {
    let mut lines = Vec::new();
    let log_lines = viewport_height.saturating_sub(6);
    if log_lines > 0 {
        lines.extend(
            app.logs
                .iter()
                .rev()
                .take(log_lines)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .cloned(),
        );
    }
    lines.push(format!("target={}", app.target_status.as_str()));
    lines.push(format!(
        "follow: {}",
        if app.follow_tail { "on" } else { "off" }
    ));
    if let Some(status) = app.last_command_status {
        let command = app
            .last_command
            .map(LiveCommand::as_str)
            .unwrap_or("target");
        lines.push(format!("{command}: {}", status.as_str()));
    }
    if let Some(message) = app
        .search_status
        .as_deref()
        .or(app.last_command_message.as_deref())
        .or(Some(app.status_line.as_str()))
    {
        lines.push(message.to_string());
    }
    lines.push("keys: Tab focus | 1 heap 2 stack 3 logs 4 maps | Space pause/resume | . stepi | , nexti | n next alloc | c continue".to_string());
    if app.search_prompt_active {
        lines.push(format!("jump> {}", app.search_prompt_input));
    } else if app.console_input_active {
        lines.push(format!("heapify> {}", app.console_input));
    } else {
        lines.push("heapify> press ':' for command".to_string());
    }
    lines.join("\n")
}

fn format_live_logs_pane(app: &LiveTuiApp) -> String {
    if app.logs.is_empty() {
        return "no logs yet".to_string();
    }
    app.logs.iter().cloned().collect::<Vec<_>>().join("\n")
}

fn live_related_records_text(app: &LiveTuiApp, config: &ReplayConfig) -> String {
    app.selected_event_id()
        .and_then(|event_id| app.related_by_event_id.get(&event_id))
        .map(|records| format_live_related_records_with_headings(records, config))
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "no related records".to_string())
}

pub fn evaluate_allocator_break_conditions(
    conditions: &[AllocatorBreakCondition],
    event: &HeapTraceEvent,
    note: HeapTrackerNote,
    related_records_for_event: &[json::JsonTraceRecord],
) -> Option<AllocatorBreakMatch> {
    conditions.iter().find_map(|condition| {
        allocator_break_condition_matches(condition, event, note, related_records_for_event)
    })
}

fn allocator_break_condition_matches(
    condition: &AllocatorBreakCondition,
    event: &HeapTraceEvent,
    note: HeapTrackerNote,
    related_records_for_event: &[json::JsonTraceRecord],
) -> Option<AllocatorBreakMatch> {
    let event_id = heap_event_id(event);
    match condition {
        AllocatorBreakCondition::Suspicious => {
            suspicious_heap_scan_break_reason(related_records_for_event).map(|reason| {
                AllocatorBreakMatch {
                    condition: condition.clone(),
                    event_id,
                    user_addr: allocator_event_user_addr(event),
                    message: reason,
                }
            })
        }
        AllocatorBreakCondition::DoubleFree => {
            is_double_free_note(note).then(|| AllocatorBreakMatch {
                condition: condition.clone(),
                event_id,
                user_addr: allocator_event_user_addr(event),
                message: "possible double free".to_string(),
            })
        }
        AllocatorBreakCondition::FreePtr(ptr) => {
            let HeapTraceEvent::Free { ptr: event_ptr, .. } = event else {
                return None;
            };
            (*event_ptr == *ptr).then(|| AllocatorBreakMatch {
                condition: condition.clone(),
                event_id,
                user_addr: Some(*event_ptr),
                message: format!("free pointer {}", format_hex_u64(*ptr)),
            })
        }
        AllocatorBreakCondition::AllocSize(size) => allocator_event_alloc_size(event)
            .is_some_and(|event_size| event_size == *size)
            .then(|| AllocatorBreakMatch {
                condition: condition.clone(),
                event_id,
                user_addr: allocator_event_user_addr(event),
                message: format!("allocation size {}", format_hex_u64(*size)),
            }),
    }
}

fn suspicious_heap_scan_break_reason(
    related_records_for_event: &[json::JsonTraceRecord],
) -> Option<String> {
    related_records_for_event.iter().find_map(|record| {
        let json::JsonTraceRecord::HeapScan { report, .. } = record else {
            return None;
        };
        if let Some(finding) = report
            .findings
            .iter()
            .find(|finding| finding.severity == "suspicious")
            .or_else(|| {
                (report.status == "suspicious")
                    .then(|| report.findings.first())
                    .flatten()
            })
        {
            return Some(format!("suspicious heap scan finding {}", finding.kind));
        }
        (report.status == "suspicious").then(|| "suspicious heap scan".to_string())
    })
}

fn is_double_free_note(note: HeapTrackerNote) -> bool {
    note == HeapTrackerNote::DoubleFree
}

fn allocator_event_alloc_size(event: &HeapTraceEvent) -> Option<u64> {
    match event {
        HeapTraceEvent::Malloc { requested_size, .. } => Some(*requested_size),
        HeapTraceEvent::Calloc { nmemb, size, .. } => nmemb.checked_mul(*size),
        HeapTraceEvent::Realloc { new_size, .. } => Some(*new_size),
        HeapTraceEvent::Free { .. } => None,
    }
}

fn allocator_event_user_addr(event: &HeapTraceEvent) -> Option<u64> {
    match event {
        HeapTraceEvent::Malloc { returned_ptr, .. }
        | HeapTraceEvent::Calloc { returned_ptr, .. }
        | HeapTraceEvent::Realloc { returned_ptr, .. } => Some(*returned_ptr),
        HeapTraceEvent::Free { ptr, .. } => Some(*ptr),
    }
}

pub fn parse_heap_search_query(input: &str) -> Result<HeapSearchQuery> {
    let tokens = input.split_whitespace().collect::<Vec<_>>();
    match tokens.as_slice() {
        [] => bail!("empty heap jump query"),
        [value] => Ok(HeapSearchQuery::AnyAddress(parse_heap_search_number(
            value,
        )?)),
        [mode, value] => {
            let mode = parse_heap_search_mode(mode)?;
            let value = parse_heap_search_number(value)?;
            Ok(match mode {
                HeapSearchMode::AnyAddress => HeapSearchQuery::AnyAddress(value),
                HeapSearchMode::UserAddress => HeapSearchQuery::UserAddress(value),
                HeapSearchMode::ChunkAddress => HeapSearchQuery::ChunkAddress(value),
                HeapSearchMode::Size => HeapSearchQuery::Size(value),
            })
        }
        _ => bail!("too many tokens in heap jump query"),
    }
}

pub fn parse_console_command(input: &str) -> ConsoleCommand {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ConsoleCommand::Unknown(String::new());
    }

    let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
    match tokens.as_slice() {
        ["help" | "h" | "?"] => ConsoleCommand::Help,
        ["continue" | "c" | "run"] => ConsoleCommand::Continue,
        ["pause" | "p"] => ConsoleCommand::Pause,
        ["resume" | "r"] => ConsoleCommand::Resume,
        ["stepi" | "si" | "step"] => ConsoleCommand::StepInstruction,
        ["nexti" | "ni"] => ConsoleCommand::StepInstructionOver,
        ["next" | "n" | "next-alloc" | "next_allocator_event"] => {
            ConsoleCommand::NextAllocatorEvent
        }
        ["stop" | "quit" | "q"] => ConsoleCommand::Stop,
        ["regs" | "registers"] => ConsoleCommand::Registers,
        ["disas" | "disassemble"] => ConsoleCommand::Disassemble,
        ["stack"] => ConsoleCommand::Stack,
        ["maps"] => ConsoleCommand::Maps,
        ["heap", rest @ ..] | ["jump", rest @ ..] => {
            if rest.is_empty() {
                return ConsoleCommand::Unknown(trimmed.to_string());
            }
            parse_heap_search_query(&rest.join(" "))
                .map(ConsoleCommand::HeapJump)
                .unwrap_or_else(|_| ConsoleCommand::Unknown(trimmed.to_string()))
        }
        ["tab", tab] => parse_console_tab(tab)
            .map(ConsoleCommand::SelectRightTab)
            .unwrap_or_else(|| ConsoleCommand::Unknown(trimmed.to_string())),
        _ => ConsoleCommand::Unknown(trimmed.to_string()),
    }
}

fn parse_console_tab(tab: &str) -> Option<LiveRightTab> {
    match tab {
        "heap" => Some(LiveRightTab::Heap),
        "stack" => Some(LiveRightTab::Stack),
        "logs" => Some(LiveRightTab::Logs),
        "maps" => Some(LiveRightTab::Maps),
        _ => None,
    }
}

fn parse_heap_search_mode(mode: &str) -> Result<HeapSearchMode> {
    match mode {
        "a" | "any" => Ok(HeapSearchMode::AnyAddress),
        "u" | "user" => Ok(HeapSearchMode::UserAddress),
        "c" | "chunk" => Ok(HeapSearchMode::ChunkAddress),
        "s" | "size" => Ok(HeapSearchMode::Size),
        _ => bail!("bad heap jump mode: {mode}"),
    }
}

fn parse_allocator_break_on_condition(value: &str) -> Result<AllocatorBreakCondition> {
    match value {
        "suspicious" => Ok(AllocatorBreakCondition::Suspicious),
        "double-free" => Ok(AllocatorBreakCondition::DoubleFree),
        _ => bail!("invalid --break-on value: {value}; expected suspicious or double-free"),
    }
}

fn parse_heap_search_number(value: &str) -> Result<u64> {
    if value.is_empty() {
        bail!("bad heap jump number: empty");
    }

    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() {
            bail!("bad heap jump number: {value}");
        }
        u64::from_str_radix(hex, 16)
    } else if value.chars().any(|ch| matches!(ch, 'a'..='f' | 'A'..='F')) {
        u64::from_str_radix(value, 16)
    } else {
        value.parse()
    };

    parsed.with_context(|| format!("bad heap jump number: {value}"))
}

fn heap_search_query_matches_chunk(query: HeapSearchQuery, chunk: &json::JsonLayoutChunk) -> bool {
    match query {
        HeapSearchQuery::AnyAddress(addr) => {
            let chunk_addr = parse_json_addr(&chunk.chunk_addr);
            let user_addr = parse_json_addr(&chunk.user_addr);
            let size = parse_json_addr(&chunk.size);
            match (
                chunk_addr,
                size.and_then(|size| chunk_addr?.checked_add(size)),
            ) {
                (Some(start), Some(end)) => start <= addr && addr < end,
                _ => chunk_addr == Some(addr) || user_addr == Some(addr),
            }
        }
        HeapSearchQuery::UserAddress(addr) => parse_json_addr(&chunk.user_addr) == Some(addr),
        HeapSearchQuery::ChunkAddress(addr) => parse_json_addr(&chunk.chunk_addr) == Some(addr),
        HeapSearchQuery::Size(size) => parse_json_addr(&chunk.size) == Some(size),
    }
}

fn format_heap_search_failure(query: HeapSearchQuery) -> String {
    match query {
        HeapSearchQuery::AnyAddress(addr) => {
            format!("no heap chunk contains {}", format_hex_u64(addr))
        }
        HeapSearchQuery::UserAddress(addr) => {
            format!("no heap chunk with user address {}", format_hex_u64(addr))
        }
        HeapSearchQuery::ChunkAddress(addr) => {
            format!("no heap chunk with chunk address {}", format_hex_u64(addr))
        }
        HeapSearchQuery::Size(size) => {
            format!("no heap chunk with size {}", format_hex_u64(size))
        }
    }
}

fn format_hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn latest_layout_chunks_len(record: Option<&json::JsonTraceRecord>) -> Option<usize> {
    let json::JsonTraceRecord::HeapLayout { chunks, .. } = record? else {
        return None;
    };
    Some(chunks.len())
}

fn selected_layout_chunk_addrs(
    record: Option<&json::JsonTraceRecord>,
    index: usize,
) -> Option<(Option<u64>, Option<u64>)> {
    let json::JsonTraceRecord::HeapLayout { chunks, .. } = record? else {
        return None;
    };
    let chunk = chunks.get(index)?;
    Some((
        parse_json_addr(&chunk.chunk_addr),
        parse_json_addr(&chunk.user_addr),
    ))
}

fn parse_json_addr(addr: &str) -> Option<u64> {
    parse_u64_auto_radix(addr).ok()
}

fn live_chunk_inspector_text(app: &LiveTuiApp) -> String {
    let Some(json::JsonTraceRecord::HeapLayout { .. }) = app.latest_heap_layout.as_ref() else {
        return "heap layout unavailable; enable --layout or --allocator-views basic/full"
            .to_string();
    };
    let Some(chunk) = app.selected_chunk_from_latest_layout() else {
        return "no chunk selected".to_string();
    };

    let mut lines = vec![
        format!("chunk addr: {}", chunk.chunk_addr),
        format!("user addr:  {}", chunk.user_addr),
        format!("size:       {}", chunk.size),
    ];
    if !chunk.prev_size.is_empty() {
        lines.push(format!("prev size:  {}", chunk.prev_size));
    }
    if !chunk.size_raw.is_empty() {
        lines.push(format!("size raw:   {}", chunk.size_raw));
    }
    if !chunk.flags.is_empty() {
        lines.push(format!("flags:      {}", chunk.flags.join(",")));
    }
    lines.push(format!("tracker:    {}", chunk.state));
    if let Some(source) = &chunk.allocator_source {
        lines.push(format!(
            "allocator:  {} size={} index={}",
            source.kind, source.chunk_size, source.index
        ));
    }

    lines.push(String::new());
    lines.push("heap scan findings:".to_string());
    let findings = collect_heap_scan_findings_for_chunk(
        app.latest_heap_scan.as_ref(),
        app.selected_chunk_addr,
        app.selected_chunk_user_addr,
    );
    if findings.is_empty() {
        lines.push("  none".to_string());
    } else {
        lines.extend(
            findings
                .into_iter()
                .take(5)
                .map(|finding| format!("  {finding}")),
        );
    }

    lines.push(String::new());
    lines.push("event history:".to_string());
    let history = app
        .selected_chunk_user_addr
        .map(|user_addr| collect_event_history_for_user_addr(&app.events, user_addr))
        .unwrap_or_default();
    if history.is_empty() {
        lines.push("  none".to_string());
    } else {
        lines.extend(history.into_iter().map(|event| format!("  {event}")));
    }

    lines.join("\n")
}

fn collect_heap_scan_findings_for_chunk(
    record: Option<&json::JsonTraceRecord>,
    chunk_addr: Option<u64>,
    user_addr: Option<u64>,
) -> Vec<String> {
    let Some(json::JsonTraceRecord::HeapScan { report, .. }) = record else {
        return Vec::new();
    };

    report
        .findings
        .iter()
        .filter(|finding| {
            finding
                .chunk_addr
                .as_deref()
                .and_then(parse_json_addr)
                .is_some_and(|addr| Some(addr) == chunk_addr)
                || finding
                    .user_addr
                    .as_deref()
                    .and_then(parse_json_addr)
                    .is_some_and(|addr| Some(addr) == user_addr)
        })
        .map(|finding| {
            let mut lines = vec![format!(
                "{} {} chunk={} user={} {}",
                finding.severity,
                finding.kind,
                finding.chunk_addr.as_deref().unwrap_or("?"),
                finding.user_addr.as_deref().unwrap_or("?"),
                finding.message
            )];
            lines.extend(
                explain_heap_scan_finding(finding)
                    .into_iter()
                    .take(2)
                    .map(|line| format!("    {line}")),
            );
            lines.join("\n")
        })
        .collect()
}

pub fn explain_heap_scan_finding(finding: &json::JsonHeapScanFinding) -> Vec<String> {
    match finding.kind.as_str() {
        "heap_snapshot_unavailable" => vec![
            "Heapify could not walk the heap snapshot for this event.".to_string(),
            "Enable layout or allocator views when possible to collect stronger evidence."
                .to_string(),
        ],
        "heap_snapshot_truncated" => vec![
            "Heapify stopped the heap walk at the configured chunk limit.".to_string(),
            "Findings may be incomplete beyond the walked portion of the heap.".to_string(),
        ],
        "allocator_source_conflict" => vec![
            "The same chunk appears in multiple allocator sources.".to_string(),
            "That can indicate stale free-list metadata or overlapping allocator views."
                .to_string(),
        ],
        "allocator_source_allocated" => vec![
            "Allocator metadata references a chunk the tracker still considers allocated."
                .to_string(),
            "This often points to stale free-list state or a missed allocator transition."
                .to_string(),
        ],
        "free_list_size_mismatch" => vec![
            "Free-list metadata disagrees with the chunk size metadata.".to_string(),
            "Compare the expected bin size with the actual chunk size in the finding message."
                .to_string(),
        ],
        "free_list_node_outside_heap" => vec![
            "A free-list pointer references an address outside the walked heap.".to_string(),
            "This can happen with corrupted next/fd/bk metadata or an incomplete heap view."
                .to_string(),
        ],
        "free_list_cycle" => vec![
            "A free-list traversal encountered a cycle.".to_string(),
            "Allocator lists normally terminate or follow a bounded bin structure.".to_string(),
        ],
        "main_arena_top_not_validated" => vec![
            "The main_arena.top candidate did not match the walked heap boundary.".to_string(),
            "Check the glibc profile and main_arena offset before treating this as corruption."
                .to_string(),
        ],
        "bin_validation_suspicious" => vec![
            "A bin-specific consistency check reported suspicious metadata.".to_string(),
            "Inspect the corresponding bin view for fd/bk, size, or chain anomalies.".to_string(),
        ],
        "bin_validation_incomplete" => vec![
            "A bin-specific consistency check lacked enough data to validate fully.".to_string(),
            "Enable fuller allocator views or increase traversal limits for more context."
                .to_string(),
        ],
        _ => Vec::new(),
    }
}

fn collect_event_history_for_user_addr(
    events: &[json::JsonTraceRecord],
    user_addr: u64,
) -> Vec<String> {
    events
        .iter()
        .filter_map(|record| {
            let json::JsonTraceRecord::Event { event } = record else {
                return None;
            };
            event_matches_user_addr(event, user_addr).then(|| format_compact_event_history(event))
        })
        .collect()
}

fn event_matches_user_addr(event: &json::JsonHeapEvent, user_addr: u64) -> bool {
    match event {
        json::JsonHeapEvent::Malloc { returned_ptr, .. }
        | json::JsonHeapEvent::Calloc { returned_ptr, .. } => {
            parse_json_addr(returned_ptr) == Some(user_addr)
        }
        json::JsonHeapEvent::Free { ptr, .. } => parse_json_addr(ptr) == Some(user_addr),
        json::JsonHeapEvent::Realloc {
            old_ptr,
            returned_ptr,
            ..
        } => {
            parse_json_addr(old_ptr) == Some(user_addr)
                || parse_json_addr(returned_ptr) == Some(user_addr)
        }
    }
}

fn format_compact_event_history(event: &json::JsonHeapEvent) -> String {
    let mut text = format_replay_event_summary(event);
    let (caller_addr, caller_symbol) = match event {
        json::JsonHeapEvent::Malloc {
            caller_addr,
            caller_symbol,
            ..
        }
        | json::JsonHeapEvent::Free {
            caller_addr,
            caller_symbol,
            ..
        }
        | json::JsonHeapEvent::Calloc {
            caller_addr,
            caller_symbol,
            ..
        }
        | json::JsonHeapEvent::Realloc {
            caller_addr,
            caller_symbol,
            ..
        } => (caller_addr.as_deref(), caller_symbol.as_ref()),
    };
    if let Some(caller_symbol) = caller_symbol {
        text.push_str(" @ ");
        text.push_str(&format_json_caller_symbol(caller_symbol, caller_addr));
    } else if let Some(caller_addr) = caller_addr {
        text.push_str(" @ ");
        text.push_str(caller_addr);
    }
    text
}

fn format_live_heap_layout_pane(app: &LiveTuiApp, max_rows: usize) -> String {
    let record = app.latest_heap_layout.as_ref();
    let Some(json::JsonTraceRecord::HeapLayout {
        event_id,
        heap_start,
        heap_end,
        chunks,
        truncated,
        chunks_omitted,
    }) = record
    else {
        return "heap layout unavailable; enable --layout or --allocator-views basic/full"
            .to_string();
    };

    let mut lines = vec![format!(
        "event #{event_id} heap {heap_start}..{heap_end} chunks={}",
        chunks.len()
    )];
    for (index, chunk) in chunks.iter().take(max_rows).enumerate() {
        let annotation = chunk
            .allocator_source
            .as_ref()
            .map(|source| format!(" {}", source.kind))
            .unwrap_or_default();
        let marker = if app.selected_chunk_index == Some(index) {
            ">"
        } else {
            " "
        };
        lines.push(format!(
            "{marker} {} user={} size={} state={}{}",
            chunk.chunk_addr, chunk.user_addr, chunk.size, chunk.state, annotation
        ));
    }
    let hidden_by_pane = chunks.len().saturating_sub(max_rows);
    if hidden_by_pane > 0 {
        lines.push(format!("... {hidden_by_pane} more chunks hidden in pane"));
    }
    if *truncated {
        lines.push(format!(
            "... {chunks_omitted} chunks omitted by trace limit"
        ));
    }

    lines.join("\n")
}

fn format_live_allocator_scan_pane(app: &LiveTuiApp) -> String {
    let mut lines = Vec::new();

    lines.push(
        app.latest_allocator_summary
            .as_ref()
            .map(format_live_allocator_summary_compact)
            .unwrap_or_else(|| {
                "allocator summary unavailable; enable --allocator-views basic/full".to_string()
            }),
    );

    if let Some(delta) = app.latest_allocator_delta.as_ref() {
        lines.push(format_live_allocator_delta_compact(delta));
    }

    if let Some(warnings) = app.latest_allocator_warnings.as_ref() {
        lines.push(format_live_allocator_warnings_compact(warnings));
    }

    if let Some(scan) = app.latest_heap_scan.as_ref() {
        lines.push(format_live_heap_scan_compact(scan));
    } else {
        lines.push(
            "heap scan unavailable; enable --heap-scan or --allocator-views basic/full".to_string(),
        );
    }

    lines.join("\n")
}

fn format_live_allocator_summary_compact(record: &json::JsonTraceRecord) -> String {
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
        return String::new();
    };

    format!(
        "event #{event_id} allocator: tc={tcache_candidate_chunks} fb={fastbin_chunks} ub={unsorted_chunks} sb={smallbin_chunks} lb={largebin_chunks} total={total_free_list_chunks} warn={warning_count}"
    )
}

fn format_live_allocator_delta_compact(record: &json::JsonTraceRecord) -> String {
    let json::JsonTraceRecord::AllocatorSourceDelta {
        tcache_candidate_chunks_delta,
        fastbin_chunks_delta,
        unsorted_chunks_delta,
        smallbin_chunks_delta,
        largebin_chunks_delta,
        total_free_list_chunks_delta,
        warning_count_delta,
        ..
    } = record
    else {
        return String::new();
    };

    format!(
        "delta: tc={} fb={} ub={} sb={} lb={} total={} warn={}",
        format_allocator_source_delta(*tcache_candidate_chunks_delta),
        format_allocator_source_delta(*fastbin_chunks_delta),
        format_allocator_source_delta(*unsorted_chunks_delta),
        format_allocator_source_delta(*smallbin_chunks_delta),
        format_allocator_source_delta(*largebin_chunks_delta),
        format_allocator_source_delta(*total_free_list_chunks_delta),
        format_allocator_source_delta(*warning_count_delta)
    )
}

fn format_live_allocator_warnings_compact(record: &json::JsonTraceRecord) -> String {
    let json::JsonTraceRecord::AllocatorWarnings { event_id, warnings } = record else {
        return String::new();
    };

    format!("event #{event_id} allocator warnings: {}", warnings.len())
}

fn format_live_heap_scan_compact(record: &json::JsonTraceRecord) -> String {
    let json::JsonTraceRecord::HeapScan { event_id, report } = record else {
        return String::new();
    };

    let mut lines = vec![format!(
        "event #{event_id} heap scan: status={} chunks={} suspicious={}",
        report.status, report.chunks_walked, report.suspicious_count
    )];

    for finding in report.findings.iter().take(3) {
        lines.push(format!(
            "{} {}: {}",
            finding.severity, finding.kind, finding.message
        ));
        lines.extend(
            explain_heap_scan_finding(finding)
                .into_iter()
                .take(1)
                .map(|line| format!("  {line}")),
        );
    }
    if report.findings.len() > 3 {
        lines.push(format!(
            "... {} more findings",
            report.findings.len().saturating_sub(3)
        ));
    }

    lines.join("\n")
}

fn format_live_related_records_with_headings(
    records: &[json::JsonTraceRecord],
    config: &ReplayConfig,
) -> String {
    records
        .iter()
        .filter(|record| !matches!(record, json::JsonTraceRecord::Event { .. }))
        .map(|record| {
            let body = format_replay_record(record, config);
            if body.is_empty() {
                String::new()
            } else {
                format!("== {} ==\n{body}", live_record_type_label(record))
            }
        })
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn live_record_type_label(record: &json::JsonTraceRecord) -> &'static str {
    match record {
        json::JsonTraceRecord::SessionStart { .. } => "session_start",
        json::JsonTraceRecord::SessionEnd { .. } => "session_end",
        json::JsonTraceRecord::Event { .. } => "event",
        json::JsonTraceRecord::HeapLayout { .. } => "heap_layout",
        json::JsonTraceRecord::ObservedTcacheChains { .. } => "observed_tcache_chains",
        json::JsonTraceRecord::TcacheStructCandidate { .. } => "tcache_struct_candidate",
        json::JsonTraceRecord::MainArenaCandidate { .. } => "main_arena_candidate",
        json::JsonTraceRecord::MainArenaExperiment { .. } => "main_arena_experiment",
        json::JsonTraceRecord::MainArenaTopCandidate { .. } => "main_arena_top_candidate",
        json::JsonTraceRecord::MainArenaView { .. } => "main_arena_view",
        json::JsonTraceRecord::FastbinExperiment { .. } => "fastbin_experiment",
        json::JsonTraceRecord::UnsortedBinExperiment { .. } => "unsorted_bin_experiment",
        json::JsonTraceRecord::BinExperiment { .. } => "bin_experiment",
        json::JsonTraceRecord::UnsortedBin { .. } => "unsorted_bin",
        json::JsonTraceRecord::UnsortedBinValidation { .. } => "unsorted_bin_validation",
        json::JsonTraceRecord::Fastbins { .. } => "fastbins",
        json::JsonTraceRecord::RegularBins { .. } => "regular_bins",
        json::JsonTraceRecord::Smallbins { .. } => "smallbins",
        json::JsonTraceRecord::SmallbinValidation { .. } => "smallbin_validation",
        json::JsonTraceRecord::Largebins { .. } => "largebins",
        json::JsonTraceRecord::LargebinValidation { .. } => "largebin_validation",
        json::JsonTraceRecord::FastbinValidation { .. } => "fastbin_validation",
        json::JsonTraceRecord::TcacheComparison { .. } => "tcache_comparison",
        json::JsonTraceRecord::TcacheValidation { .. } => "tcache_validation",
        json::JsonTraceRecord::AllocatorWarnings { .. } => "allocator_warnings",
        json::JsonTraceRecord::AllocatorSourceSummary { .. } => "allocator_source_summary",
        json::JsonTraceRecord::AllocatorSourceDelta { .. } => "allocator_source_delta",
        json::JsonTraceRecord::HeapScan { .. } => "heap_scan",
    }
}

fn allocator_state_for_live_event(
    app: &LiveTuiApp,
    event_id: usize,
) -> Option<ReplayEventAllocatorState> {
    app.related_by_event_id
        .get(&event_id)?
        .iter()
        .find_map(|record| {
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

            Some(ReplayEventAllocatorState {
                event_id: *event_id,
                tcache_candidate_chunks: *tcache_candidate_chunks,
                fastbin_chunks: *fastbin_chunks,
                unsorted_chunks: *unsorted_chunks,
                smallbin_chunks: *smallbin_chunks,
                largebin_chunks: *largebin_chunks,
                total_free_list_chunks: *total_free_list_chunks,
                warning_count: *warning_count,
            })
        })
}

fn parse_trace_heap_args(args: Vec<String>) -> Result<(RenderConfig, String, Vec<String>)> {
    let mut config = RenderConfig::default();
    let mut remaining = Vec::new();
    let mut iter = args.into_iter();
    let mut allocator_views_arg = None;
    let mut all_allocator_views = false;
    let mut events_only_arg = false;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--events-only" => {
                events_only_arg = true;
                config.show_chunks = false;
                config.show_tracker_notes = false;
                config.show_explanations = false;
                config.show_layout = false;
            }
            "--no-chunks" => {
                config.show_chunks = false;
            }
            "--layout" => {
                if config.show_tracker_notes || config.show_chunks || config.show_explanations {
                    config.show_layout = true;
                }
            }
            "--max-layout-chunks" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --max-layout-chunks");
                };
                config.max_layout_chunks = value
                    .parse()
                    .with_context(|| format!("invalid --max-layout-chunks value: {value}"))?;
            }
            "--tcache-candidates" => {
                config.show_tcache_candidates = true;
            }
            "--tcache-struct" => {
                config.show_tcache_struct_candidate = true;
            }
            "--main-arena" => {
                config.show_main_arena_candidate = true;
            }
            "--arena-experiment" => {
                config.show_arena_experiment = true;
                config.show_main_arena_candidate = true;
            }
            "--fastbin-experiment" => {
                config.show_fastbin_experiment = true;
                config.show_main_arena_candidate = true;
            }
            "--unsorted-experiment" => {
                config.show_unsorted_experiment = true;
                config.show_main_arena_candidate = true;
            }
            "--bin-experiment" => {
                config.show_bin_experiment = true;
                config.show_main_arena_candidate = true;
            }
            "--unsorted-bin" => {
                config.show_unsorted_bin = true;
                config.show_main_arena_candidate = true;
            }
            "--fastbins" => {
                config.show_fastbins = true;
                config.show_main_arena_candidate = true;
            }
            "--regular-bins" => {
                config.show_regular_bins = true;
                config.show_main_arena_candidate = true;
            }
            "--smallbins" => {
                config.show_smallbins = true;
                config.show_regular_bins = true;
                config.show_main_arena_candidate = true;
            }
            "--largebins" => {
                config.show_largebins = true;
                config.show_regular_bins = true;
                config.show_main_arena_candidate = true;
            }
            "--heap-scan" => {
                config.show_heap_scan = true;
            }
            "--break-on" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --break-on");
                };
                config
                    .break_conditions
                    .push(parse_allocator_break_on_condition(&value)?);
            }
            "--break-on-free" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --break-on-free");
                };
                config
                    .break_conditions
                    .push(AllocatorBreakCondition::FreePtr(
                        parse_heap_search_number(&value)
                            .with_context(|| format!("invalid --break-on-free value: {value}"))?,
                    ));
            }
            "--break-on-alloc-size" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --break-on-alloc-size");
                };
                config
                    .break_conditions
                    .push(AllocatorBreakCondition::AllocSize(
                        parse_heap_search_number(&value).with_context(|| {
                            format!("invalid --break-on-alloc-size value: {value}")
                        })?,
                    ));
            }
            "--allocator-views" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --allocator-views");
                };
                allocator_views_arg = Some(
                    AllocatorViewsPresetArg::from_str(&value, true)
                        .map_err(|_| anyhow::anyhow!("invalid --allocator-views value: {value}"))?,
                );
            }
            "--all-allocator-views" => {
                all_allocator_views = true;
            }
            "--main-arena-offset" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --main-arena-offset");
                };
                config.main_arena_offset = Some(
                    parse_u64_auto_radix(&value)
                        .with_context(|| format!("invalid --main-arena-offset value: {value}"))?,
                );
                config.show_main_arena_candidate = true;
            }
            "--main-arena-top" => {
                config.show_main_arena_top_candidate = true;
                config.show_main_arena_candidate = true;
            }
            "--main-arena-top-offset" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --main-arena-top-offset");
                };
                config.main_arena_top_offset =
                    Some(parse_u64_auto_radix(&value).with_context(|| {
                        format!("invalid --main-arena-top-offset value: {value}")
                    })?);
                config.show_main_arena_top_candidate = true;
                config.show_main_arena_candidate = true;
            }
            "--max-tcache-chain" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --max-tcache-chain");
                };
                config.max_tcache_chain = value
                    .parse()
                    .with_context(|| format!("invalid --max-tcache-chain value: {value}"))?;
            }
            "--max-fastbin-chain" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --max-fastbin-chain");
                };
                config.max_fastbin_chain = value
                    .parse()
                    .with_context(|| format!("invalid --max-fastbin-chain value: {value}"))?;
            }
            "--max-unsorted-chain" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --max-unsorted-chain");
                };
                config.max_unsorted_chain = value
                    .parse()
                    .with_context(|| format!("invalid --max-unsorted-chain value: {value}"))?;
            }
            "--max-regular-bins" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --max-regular-bins");
                };
                config.max_regular_bins = value
                    .parse()
                    .with_context(|| format!("invalid --max-regular-bins value: {value}"))?;
            }
            "--max-smallbin-chain" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --max-smallbin-chain");
                };
                config.max_smallbin_chain = value
                    .parse()
                    .with_context(|| format!("invalid --max-smallbin-chain value: {value}"))?;
            }
            "--max-largebin-chain" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --max-largebin-chain");
                };
                config.max_largebin_chain = value
                    .parse()
                    .with_context(|| format!("invalid --max-largebin-chain value: {value}"))?;
            }
            "--trace-mode" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --trace-mode");
                };
                config.trace_mode = Some(
                    TraceModeArg::from_str(&value, true)
                        .map_err(|_| anyhow::anyhow!("invalid --trace-mode value: {value}"))?,
                );
            }
            "--libc-symbols" => {
                config.libc_symbols = true;
            }
            "--libc" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --libc");
                };
                config.supplied_libc_path = Some(PathBuf::from(value));
            }
            "--ld" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --ld");
                };
                config.loader_path = Some(PathBuf::from(value));
            }
            "--library-path" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --library-path");
                };
                config.library_path = Some(PathBuf::from(value));
            }
            "--preload" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --preload");
                };
                config.preload_path = Some(PathBuf::from(value));
            }
            "--cwd" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --cwd");
                };
                config.cwd = Some(PathBuf::from(value));
            }
            "--set-env" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --set-env");
                };
                config.set_env.push(parse_env_assignment(&value)?);
            }
            "--unset-env" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --unset-env");
                };
                if value.is_empty() {
                    bail!("invalid --unset-env value: key must not be empty");
                }
                config.unset_env.push(value);
            }
            "--clear-env" => {
                config.clear_env = true;
            }
            "--stdin-file" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --stdin-file");
                };
                if !matches!(config.stdin, StdinConfig::Inherit) {
                    bail!("--stdin-file and --stdin-text are mutually exclusive");
                }
                config.stdin = StdinConfig::File(PathBuf::from(value));
            }
            "--stdin-text" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --stdin-text");
                };
                if !matches!(config.stdin, StdinConfig::Inherit) {
                    bail!("--stdin-file and --stdin-text are mutually exclusive");
                }
                config.stdin = StdinConfig::Text(value);
            }
            "--glibc-profile" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --glibc-profile");
                };
                config.glibc_profile_request = value.clone();
                if value == "auto" {
                    config.glibc_profile = GLIBC_X86_64_MODERN;
                } else {
                    config.glibc_profile = resolve_glibc_profile(&value)?;
                }
            }
            "--json" => {
                config.json = true;
            }
            "--json-out" => {
                let Some(value) = iter.next() else {
                    bail!("missing value for --json-out");
                };
                config.json_out = Some(PathBuf::from(value));
            }
            "--live-tui" => {
                config.live_tui = true;
            }
            _ => {
                remaining.push(arg);
                remaining.extend(iter);
                break;
            }
        }
    }

    let allocator_views_preset =
        resolve_allocator_views_preset(allocator_views_arg, all_allocator_views)?;
    apply_allocator_views_preset(&mut config, allocator_views_preset);

    if !config.show_chunks && !config.show_tracker_notes && !config.show_explanations {
        config.show_layout = false;
        config.show_heap_scan = false;
    }

    if config.live_tui && config.json {
        bail!("--live-tui conflicts with --json stdout mode; use --json-out PATH to save a trace");
    }
    if config.live_tui && events_only_arg {
        bail!("--live-tui conflicts with --events-only");
    }

    let Some(program) = remaining.first().cloned() else {
        usage();
        bail!("missing program");
    };
    let target_args = remaining.into_iter().skip(1).collect();

    Ok((config, program, target_args))
}

fn resolve_allocator_views_preset(
    allocator_views_arg: Option<AllocatorViewsPresetArg>,
    all_allocator_views: bool,
) -> Result<AllocatorViewsPreset> {
    if allocator_views_arg.is_some() && all_allocator_views {
        bail!("--all-allocator-views conflicts with --allocator-views");
    }

    if all_allocator_views {
        return Ok(AllocatorViewsPreset::Full);
    }

    Ok(allocator_views_arg
        .map(AllocatorViewsPreset::from)
        .unwrap_or(AllocatorViewsPreset::None))
}

fn apply_allocator_views_preset(config: &mut RenderConfig, preset: AllocatorViewsPreset) {
    config.allocator_views_preset = preset;

    match preset {
        AllocatorViewsPreset::None => {}
        AllocatorViewsPreset::Basic => {
            config.show_layout = true;
            config.show_tcache_candidates = true;
            config.show_heap_scan = true;
        }
        AllocatorViewsPreset::Full => {
            config.show_layout = true;
            config.show_tcache_candidates = true;
            config.show_main_arena_candidate = true;
            config.show_main_arena_top_candidate = true;
            config.show_fastbins = true;
            config.show_unsorted_bin = true;
            config.show_regular_bins = true;
            config.show_smallbins = true;
            config.show_largebins = true;
            config.show_heap_scan = true;
        }
    }
}

fn maybe_print_allocator_views_preset_status(config: &RenderConfig) {
    if config.allocator_views_preset == AllocatorViewsPreset::None
        || config.events_only()
        || (config.json && config.json_out.is_none())
    {
        return;
    }

    println!(
        "[heapify] allocator views preset: {}",
        config.allocator_views_preset.as_str()
    );
}

fn maybe_print_low_confidence_profile_warning(
    record: &json::JsonTraceRecord,
    config: &RenderConfig,
) {
    if config.events_only()
        || (config.json && config.json_out.is_none())
        || !profile_backed_views_enabled(config)
    {
        return;
    }

    let json::JsonTraceRecord::SessionStart {
        glibc_profile_selection: Some(selection),
        ..
    } = record
    else {
        return;
    };

    if selection.confidence == GlibcProfileConfidence::Low {
        println!("[heapify] warning: {}", low_confidence_profile_warning());
    }
}

fn low_confidence_profile_warning() -> &'static str {
    "glibc profile confidence is low; profile-backed arena/bin views may be inaccurate"
}

fn profile_backed_views_enabled(config: &RenderConfig) -> bool {
    config.show_main_arena_candidate
        || config.show_main_arena_top_candidate
        || config.show_fastbin_experiment
        || config.show_unsorted_experiment
        || config.show_bin_experiment
        || config.show_unsorted_bin
        || config.show_fastbins
        || config.show_regular_bins
        || config.show_smallbins
        || config.show_largebins
        || config.allocator_views_preset == AllocatorViewsPreset::Full
}

pub fn parse_env_assignment(s: &str) -> Result<(String, String)> {
    let Some((key, value)) = s.split_once('=') else {
        bail!("invalid environment assignment '{s}': expected KEY=VALUE");
    };
    if key.is_empty() {
        bail!("invalid environment assignment '{s}': key must not be empty");
    }
    if key.contains('=') {
        bail!("invalid environment assignment '{s}': key must not contain '='");
    }
    Ok((key.to_string(), value.to_string()))
}

fn resolve_glibc_profile(name: &str) -> Result<GlibcProfile> {
    glibc_profile_by_name(name).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown glibc profile `{name}`\n\navailable profiles:\n{}",
            format_available_glibc_profiles()
        )
    })
}

pub fn format_available_glibc_profiles() -> String {
    std::iter::once("  auto".to_string())
        .chain(
            available_glibc_profiles()
                .iter()
                .map(|profile| format!("  {}", profile.name)),
        )
        .collect::<Vec<_>>()
        .join("\n")
}

fn resolve_trace_mode(
    trace_mode: Option<TraceModeArg>,
    libc_symbols: bool,
) -> Result<AllocationTraceMode> {
    match (trace_mode, libc_symbols) {
        (None, false) | (Some(TraceModeArg::Plt), false) => Ok(AllocationTraceMode::TargetPlt),
        (None, true) | (Some(TraceModeArg::Libc), _) => Ok(AllocationTraceMode::LibcSymbols),
        (Some(TraceModeArg::Plt), true) => bail!(
            "--trace-mode plt conflicts with --libc-symbols; use --trace-mode libc or remove --libc-symbols"
        ),
    }
}

fn select_main_arena_top_offset(
    explicit_offset: Option<u64>,
    requested_profile_offset: bool,
    profile: GlibcProfile,
) -> SelectedMainArenaTopOffset {
    if let Some(offset) = explicit_offset {
        return SelectedMainArenaTopOffset::User { offset };
    }

    if requested_profile_offset {
        if let Some(offset) = profile.main_arena_top_offset {
            return SelectedMainArenaTopOffset::Profile {
                offset,
                profile_name: profile.name.to_string(),
            };
        }
    }

    SelectedMainArenaTopOffset::Unavailable
}

fn json_trace_features(
    config: &RenderConfig,
    trace_mode: AllocationTraceMode,
) -> json::JsonTraceFeatures {
    json::JsonTraceFeatures {
        layout: config.show_layout,
        tcache_candidates: config.show_tcache_candidates,
        tcache_struct: config.show_tcache_struct_candidate,
        libc_symbols: matches!(trace_mode, AllocationTraceMode::LibcSymbols),
    }
}

fn json_libc_metadata(metadata: heapify_debugger::LibcMetadata) -> json::JsonLibcMetadata {
    json::JsonLibcMetadata {
        path: Some(metadata.path),
        supplied_path: metadata.supplied_path,
        paths_match: metadata.paths_match,
        version: metadata.version,
    }
}

fn json_launch_metadata(plan: &heapify_debugger::ExecPlan) -> json::JsonLaunchMetadata {
    let user_set_env_keys = user_launch_env_set_keys(plan);
    json::JsonLaunchMetadata {
        mode: plan.launch_mode.as_str().to_string(),
        loader: plan
            .loader_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        library_path: plan
            .effective_library_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        preload: plan
            .preload_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        cwd: plan
            .cwd
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        clear_env: plan.clear_env,
        set_env: user_set_env_keys,
        unset_env: plan.env_unsets.clone(),
        stdin: json_stdin_metadata(&plan.stdin),
    }
}

fn json_stdin_metadata(stdin: &StdinConfig) -> json::JsonStdinMetadata {
    match stdin {
        StdinConfig::Inherit => json::JsonStdinMetadata::default(),
        StdinConfig::File(path) => json::JsonStdinMetadata {
            kind: "file".to_string(),
            path: Some(path.to_string_lossy().into_owned()),
            bytes: None,
        },
        StdinConfig::Text(text) => json::JsonStdinMetadata {
            kind: "text".to_string(),
            path: None,
            bytes: Some(text.len()),
        },
    }
}

fn user_launch_env_set_keys(plan: &heapify_debugger::ExecPlan) -> Vec<String> {
    let auto_preload_count = usize::from(plan.preload_path.is_some());
    let user_len = plan.env_overrides.len().saturating_sub(auto_preload_count);
    plan.env_overrides
        .iter()
        .take(user_len)
        .map(|(key, _)| key.clone())
        .collect()
}

fn parse_replay_args(args: Vec<String>) -> Result<(ReplayConfig, PathBuf)> {
    let mut config = ReplayConfig::default();
    let mut trace_file = None;
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--events-only" => {
                config.events_only = true;
            }
            "--no-chunks" => {
                config.show_chunks = false;
            }
            "--tui" => {
                config.tui = true;
            }
            _ if arg.starts_with('-') => {
                bail!("unknown replay option: {arg}");
            }
            _ => {
                trace_file = Some(PathBuf::from(arg));
                if let Some(extra) = iter.next() {
                    bail!("unexpected replay argument: {extra}");
                }
                break;
            }
        }
    }

    let Some(trace_file) = trace_file else {
        usage();
        bail!("missing trace file");
    };

    Ok((config, trace_file))
}

fn replay_trace_file(path: &Path, config: &ReplayConfig) -> Result<()> {
    let records = load_replay_records(path)?;
    let session = ReplaySession::from_records(records);

    if let Some(record) = &session.session_start {
        print_replay_text(format_replay_record(record, config));
    }
    for record in &session.records {
        render_replay_record(record, config);
    }
    if let Some(record) = &session.session_end {
        print_replay_text(format_replay_record(record, config));
    }

    Ok(())
}

fn load_replay_records(path: &Path) -> Result<Vec<json::JsonTraceRecord>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open trace file {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.with_context(|| {
            format!(
                "failed to read trace file {} line {}",
                path.display(),
                line_number
            )
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let record: json::JsonTraceRecord = serde_json::from_str(trimmed).with_context(|| {
            format!(
                "failed to parse JSON trace record at {}:{}",
                path.display(),
                line_number
            )
        })?;
        records.push(record);
    }

    Ok(records)
}

fn replay_trace_file_tui(path: &Path, config: &ReplayConfig) -> Result<()> {
    let records = load_replay_records(path)?;
    let session = ReplaySession::from_records(records);
    if session.event_count() == 0 {
        println!("no events found in trace");
        return Ok(());
    }

    run_replay_tui(&session, config)
}

fn render_replay_record(record: &json::JsonTraceRecord, config: &ReplayConfig) {
    match record {
        json::JsonTraceRecord::SessionStart { .. } | json::JsonTraceRecord::SessionEnd { .. } => {}
        json::JsonTraceRecord::Event { event } => render_replay_event(event, config),
        json::JsonTraceRecord::HeapLayout {
            heap_start,
            heap_end,
            chunks,
            truncated,
            chunks_omitted,
            ..
        } => render_replay_heap_layout(
            heap_start,
            heap_end,
            chunks,
            *truncated,
            *chunks_omitted,
            config,
        ),
        json::JsonTraceRecord::ObservedTcacheChains { chains, .. } => {
            render_replay_observed_tcache_chains(chains, config)
        }
        json::JsonTraceRecord::TcacheStructCandidate {
            candidate,
            snapshot,
            ..
        } => render_replay_tcache_struct_candidate(candidate, snapshot.as_ref(), config),
        json::JsonTraceRecord::MainArenaCandidate { candidate, .. } => {
            render_replay_main_arena_candidate(candidate, config)
        }
        json::JsonTraceRecord::MainArenaExperiment {
            arena_addr,
            candidates,
            ..
        } => render_replay_main_arena_experiment(arena_addr, candidates, config),
        json::JsonTraceRecord::MainArenaTopCandidate {
            arena_addr,
            field_offset,
            top_addr,
            chunk_size,
            status,
            source,
            profile,
            ..
        } => render_replay_main_arena_top_candidate(
            arena_addr,
            field_offset,
            top_addr,
            chunk_size.as_deref(),
            status,
            source,
            profile.as_deref(),
            config,
        ),
        json::JsonTraceRecord::MainArenaView { arena, top, .. } => {
            render_replay_main_arena_view(arena, top.as_ref(), config)
        }
        json::JsonTraceRecord::FastbinExperiment {
            arena_addr,
            candidates,
            ..
        } => render_replay_fastbin_experiment(arena_addr, candidates, config),
        json::JsonTraceRecord::UnsortedBinExperiment {
            arena_addr,
            candidates,
            ..
        } => render_replay_unsorted_bin_experiment(arena_addr, candidates, config),
        json::JsonTraceRecord::BinExperiment {
            arena_addr,
            candidates,
            ..
        } => render_replay_bin_experiment(arena_addr, candidates, config),
        json::JsonTraceRecord::UnsortedBin {
            arena_addr,
            field_offset,
            fd,
            bk,
            fd_points_into_heap,
            bk_points_into_heap,
            fd_known_freed,
            bk_known_freed,
            chain,
            ..
        } => render_replay_unsorted_bin(
            arena_addr,
            field_offset,
            fd,
            bk,
            *fd_points_into_heap,
            *bk_points_into_heap,
            *fd_known_freed,
            *bk_known_freed,
            chain.as_ref(),
            config,
        ),
        json::JsonTraceRecord::UnsortedBinValidation { validation, .. } => {
            render_replay_unsorted_bin_validation(validation, config)
        }
        json::JsonTraceRecord::Fastbins {
            arena_addr,
            heads,
            chains,
            ..
        } => render_replay_fastbins(arena_addr, heads, chains, config),
        json::JsonTraceRecord::RegularBins {
            arena_addr,
            bins_offset,
            heads,
            ..
        } => render_replay_regular_bins(arena_addr, bins_offset, heads, config),
        json::JsonTraceRecord::Smallbins {
            arena_addr,
            bins_offset,
            chains,
            ..
        } => render_replay_smallbins(arena_addr, bins_offset, chains, config),
        json::JsonTraceRecord::SmallbinValidation { validations, .. } => {
            render_replay_smallbin_validation(validations, config)
        }
        json::JsonTraceRecord::Largebins {
            arena_addr,
            bins_offset,
            chains,
            ..
        } => render_replay_largebins(arena_addr, bins_offset, chains, config),
        json::JsonTraceRecord::LargebinValidation { validations, .. } => {
            render_replay_largebin_validation(validations, config)
        }
        json::JsonTraceRecord::FastbinValidation { validations, .. } => {
            render_replay_fastbin_validation(validations, config)
        }
        json::JsonTraceRecord::TcacheComparison { comparisons, .. } => {
            render_replay_tcache_comparison(comparisons, config)
        }
        json::JsonTraceRecord::TcacheValidation { validations, .. } => {
            render_replay_tcache_validation(validations, config)
        }
        json::JsonTraceRecord::AllocatorWarnings { warnings, .. } => {
            render_replay_allocator_warnings(warnings, config)
        }
        json::JsonTraceRecord::AllocatorSourceSummary {
            tcache_candidate_chunks,
            fastbin_chunks,
            unsorted_chunks,
            smallbin_chunks,
            largebin_chunks,
            total_free_list_chunks,
            warning_count,
            ..
        } => render_replay_allocator_source_summary(
            *tcache_candidate_chunks,
            *fastbin_chunks,
            *unsorted_chunks,
            *smallbin_chunks,
            *largebin_chunks,
            *total_free_list_chunks,
            *warning_count,
            config,
        ),
        json::JsonTraceRecord::AllocatorSourceDelta {
            tcache_candidate_chunks_delta,
            fastbin_chunks_delta,
            unsorted_chunks_delta,
            smallbin_chunks_delta,
            largebin_chunks_delta,
            total_free_list_chunks_delta,
            warning_count_delta,
            ..
        } => render_replay_allocator_source_delta(
            *tcache_candidate_chunks_delta,
            *fastbin_chunks_delta,
            *unsorted_chunks_delta,
            *smallbin_chunks_delta,
            *largebin_chunks_delta,
            *total_free_list_chunks_delta,
            *warning_count_delta,
            config,
        ),
        json::JsonTraceRecord::HeapScan { report, .. } => {
            print_replay_text(format_replay_heap_scan(report, config))
        }
    }
}

fn format_replay_record(record: &json::JsonTraceRecord, config: &ReplayConfig) -> String {
    match record {
        json::JsonTraceRecord::SessionStart {
            heapify_version,
            program,
            trace_mode,
            glibc_profile,
            suggested_glibc_profile,
            glibc_profile_selection,
            libc,
            launch,
            allocator_views_preset,
            features,
            ..
        } => format_replay_session_start(
            heapify_version,
            program,
            trace_mode,
            glibc_profile,
            suggested_glibc_profile.as_deref(),
            glibc_profile_selection.as_ref(),
            libc.as_ref(),
            launch.as_ref(),
            allocator_views_preset,
            features,
            !config.events_only,
        ),
        json::JsonTraceRecord::SessionEnd {
            exit_status,
            event_count,
        } => format_replay_session_end(exit_status, *event_count),
        json::JsonTraceRecord::Event { event } => format_replay_event(event, config),
        json::JsonTraceRecord::HeapLayout {
            chunks,
            truncated,
            chunks_omitted,
            ..
        } => format_replay_heap_layout(chunks, *truncated, *chunks_omitted, config),
        json::JsonTraceRecord::ObservedTcacheChains { chains, .. } => {
            format_replay_observed_tcache_chains(chains, config)
        }
        json::JsonTraceRecord::TcacheStructCandidate {
            candidate,
            snapshot,
            ..
        } => format_replay_tcache_struct_candidate(candidate, snapshot.as_ref(), config),
        json::JsonTraceRecord::MainArenaCandidate { candidate, .. } => {
            format_replay_main_arena_candidate(candidate, config)
        }
        json::JsonTraceRecord::MainArenaExperiment {
            arena_addr,
            candidates,
            ..
        } => format_replay_main_arena_experiment(arena_addr, candidates, config),
        json::JsonTraceRecord::MainArenaTopCandidate {
            arena_addr,
            field_offset,
            top_addr,
            chunk_size,
            status,
            source,
            profile,
            ..
        } => format_replay_main_arena_top_candidate(
            arena_addr,
            field_offset,
            top_addr,
            chunk_size.as_deref(),
            status,
            source,
            profile.as_deref(),
            config,
        ),
        json::JsonTraceRecord::MainArenaView { arena, top, .. } => {
            format_replay_main_arena_view(arena, top.as_ref(), config)
        }
        json::JsonTraceRecord::FastbinExperiment {
            arena_addr,
            candidates,
            ..
        } => format_replay_fastbin_experiment(arena_addr, candidates, config),
        json::JsonTraceRecord::UnsortedBinExperiment {
            arena_addr,
            candidates,
            ..
        } => format_replay_unsorted_bin_experiment(arena_addr, candidates, config),
        json::JsonTraceRecord::BinExperiment {
            arena_addr,
            candidates,
            ..
        } => format_replay_bin_experiment(arena_addr, candidates, config),
        json::JsonTraceRecord::UnsortedBin {
            arena_addr,
            field_offset,
            fd,
            bk,
            fd_points_into_heap,
            bk_points_into_heap,
            fd_known_freed,
            bk_known_freed,
            chain,
            ..
        } => format_replay_unsorted_bin(
            arena_addr,
            field_offset,
            fd,
            bk,
            *fd_points_into_heap,
            *bk_points_into_heap,
            *fd_known_freed,
            *bk_known_freed,
            chain.as_ref(),
            config,
        ),
        json::JsonTraceRecord::UnsortedBinValidation { validation, .. } => {
            format_replay_unsorted_bin_validation(validation, config)
        }
        json::JsonTraceRecord::Fastbins {
            arena_addr,
            heads,
            chains,
            ..
        } => format_replay_fastbins(arena_addr, heads, chains, config),
        json::JsonTraceRecord::RegularBins {
            arena_addr,
            bins_offset,
            heads,
            ..
        } => format_replay_regular_bins(arena_addr, bins_offset, heads, config),
        json::JsonTraceRecord::Smallbins {
            arena_addr,
            bins_offset,
            chains,
            ..
        } => format_replay_smallbins(arena_addr, bins_offset, chains, config),
        json::JsonTraceRecord::SmallbinValidation { validations, .. } => {
            format_replay_smallbin_validation(validations, config)
        }
        json::JsonTraceRecord::Largebins {
            arena_addr,
            bins_offset,
            chains,
            ..
        } => format_replay_largebins(arena_addr, bins_offset, chains, config),
        json::JsonTraceRecord::LargebinValidation { validations, .. } => {
            format_replay_largebin_validation(validations, config)
        }
        json::JsonTraceRecord::FastbinValidation { validations, .. } => {
            format_replay_fastbin_validation(validations, config)
        }
        json::JsonTraceRecord::TcacheComparison { comparisons, .. } => {
            format_replay_tcache_comparison(comparisons, config)
        }
        json::JsonTraceRecord::TcacheValidation { validations, .. } => {
            format_replay_tcache_validation(validations, config)
        }
        json::JsonTraceRecord::AllocatorWarnings { warnings, .. } => {
            format_replay_allocator_warnings(warnings, config)
        }
        json::JsonTraceRecord::AllocatorSourceSummary {
            tcache_candidate_chunks,
            fastbin_chunks,
            unsorted_chunks,
            smallbin_chunks,
            largebin_chunks,
            total_free_list_chunks,
            warning_count,
            ..
        } => format_replay_allocator_source_summary(
            *tcache_candidate_chunks,
            *fastbin_chunks,
            *unsorted_chunks,
            *smallbin_chunks,
            *largebin_chunks,
            *total_free_list_chunks,
            *warning_count,
            config,
        ),
        json::JsonTraceRecord::AllocatorSourceDelta {
            tcache_candidate_chunks_delta,
            fastbin_chunks_delta,
            unsorted_chunks_delta,
            smallbin_chunks_delta,
            largebin_chunks_delta,
            total_free_list_chunks_delta,
            warning_count_delta,
            ..
        } => format_replay_allocator_source_delta(
            *tcache_candidate_chunks_delta,
            *fastbin_chunks_delta,
            *unsorted_chunks_delta,
            *smallbin_chunks_delta,
            *largebin_chunks_delta,
            *total_free_list_chunks_delta,
            *warning_count_delta,
            config,
        ),
        json::JsonTraceRecord::HeapScan { report, .. } => format_replay_heap_scan(report, config),
    }
}

fn render_replay_event(event: &json::JsonHeapEvent, config: &ReplayConfig) {
    print_replay_text(format_replay_event(event, config));
}

fn format_replay_event(event: &json::JsonHeapEvent, config: &ReplayConfig) -> String {
    let mut lines = Vec::new();

    match event {
        json::JsonHeapEvent::Malloc {
            event_id,
            requested_size,
            returned_ptr,
            chunk,
            caller_addr,
            caller_symbol,
            tracker_note,
            tracker_explanation,
        } => {
            lines.push(format!(
                "#{event_id} malloc({requested_size}) = {returned_ptr}"
            ));
            if !config.events_only {
                maybe_push_replay_caller(
                    &mut lines,
                    caller_addr.as_deref(),
                    caller_symbol.as_ref(),
                );
            }
            if config.show_chunks {
                if let Some(chunk) = chunk {
                    lines.extend(format_replay_chunk("chunk", chunk, 4));
                } else if returned_ptr != "0x0" {
                    lines.push("    chunk: unavailable".to_string());
                }
            }
            lines.extend(format_replay_tracker(tracker_note, tracker_explanation));
        }
        json::JsonHeapEvent::Free {
            event_id,
            ptr,
            chunk,
            tcache_entry,
            caller_addr,
            caller_symbol,
            tracker_note,
            tracker_explanation,
        } => {
            lines.push(format!("#{event_id} free({ptr})"));
            if !config.events_only {
                maybe_push_replay_caller(
                    &mut lines,
                    caller_addr.as_deref(),
                    caller_symbol.as_ref(),
                );
            }
            if config.show_chunks {
                if let Some(chunk) = chunk {
                    lines.extend(format_replay_chunk("chunk", chunk, 4));
                } else if ptr != "0x0" {
                    lines.push("    chunk: unavailable".to_string());
                }
                if let Some(tcache_entry) = tcache_entry {
                    lines.extend(format_replay_tcache_entry(tcache_entry));
                }
            }
            lines.extend(format_replay_tracker(tracker_note, tracker_explanation));
        }
        json::JsonHeapEvent::Calloc {
            event_id,
            nmemb,
            size,
            returned_ptr,
            chunk,
            caller_addr,
            caller_symbol,
            tracker_note,
            tracker_explanation,
        } => {
            lines.push(format!(
                "#{event_id} calloc({nmemb}, {size}) = {returned_ptr}"
            ));
            if !config.events_only {
                maybe_push_replay_caller(
                    &mut lines,
                    caller_addr.as_deref(),
                    caller_symbol.as_ref(),
                );
            }
            if config.show_chunks {
                if let Some(chunk) = chunk {
                    lines.extend(format_replay_chunk("chunk", chunk, 4));
                } else if returned_ptr != "0x0" {
                    lines.push("    chunk: unavailable".to_string());
                }
            }
            lines.extend(format_replay_tracker(tracker_note, tracker_explanation));
        }
        json::JsonHeapEvent::Realloc {
            event_id,
            old_ptr,
            new_size,
            returned_ptr,
            old_chunk,
            new_chunk,
            caller_addr,
            caller_symbol,
            tracker_note,
            tracker_explanation,
        } => {
            lines.push(format!(
                "#{event_id} realloc({old_ptr}, {new_size}) = {returned_ptr}"
            ));
            if !config.events_only {
                maybe_push_replay_caller(
                    &mut lines,
                    caller_addr.as_deref(),
                    caller_symbol.as_ref(),
                );
            }
            if config.show_chunks {
                if let Some(old_chunk) = old_chunk {
                    lines.extend(format_replay_chunk("old chunk", old_chunk, 4));
                }
                if let Some(new_chunk) = new_chunk {
                    lines.extend(format_replay_chunk("new chunk", new_chunk, 4));
                } else if returned_ptr != "0x0" {
                    lines.push("    new chunk: unavailable".to_string());
                }
            }
            lines.extend(format_replay_tracker(tracker_note, tracker_explanation));
        }
    }

    lines.join("\n")
}

fn maybe_push_replay_caller(
    lines: &mut Vec<String>,
    caller_addr: Option<&str>,
    caller_symbol: Option<&json::JsonCallerSymbol>,
) {
    if let Some(caller_symbol) = caller_symbol {
        lines.push(format!(
            "    caller:     {}",
            format_json_caller_symbol(caller_symbol, caller_addr)
        ));
        maybe_push_json_source_line(lines, caller_symbol.source.as_ref());
    } else if let Some(caller_addr) = caller_addr {
        lines.push(format!("    caller:     {caller_addr}"));
    }
}

fn format_json_caller_symbol(
    caller_symbol: &json::JsonCallerSymbol,
    caller_addr: Option<&str>,
) -> String {
    let addr = caller_addr.unwrap_or(caller_symbol.symbol_addr.as_str());
    let symbol = if let Some(object) = caller_symbol.object.as_deref() {
        format!("{object}!{}", caller_symbol.symbol)
    } else {
        caller_symbol.symbol.clone()
    };
    if caller_symbol.offset == "0x0" {
        format!("{symbol} ({addr})")
    } else {
        format!("{symbol}+{} ({addr})", caller_symbol.offset)
    }
}

fn maybe_push_json_source_line(lines: &mut Vec<String>, source: Option<&json::JsonSourceLocation>) {
    if let Some(source) = source.and_then(format_json_source_location) {
        lines.push(format!("    at          {source}"));
    }
}

fn format_json_source_location(source: &json::JsonSourceLocation) -> Option<String> {
    format_source_location_parts(source.file.as_deref(), source.line, source.column)
}

fn render_replay_heap_layout(
    _heap_start: &str,
    _heap_end: &str,
    chunks: &[json::JsonLayoutChunk],
    truncated: bool,
    chunks_omitted: usize,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_heap_layout(
        chunks,
        truncated,
        chunks_omitted,
        config,
    ));
}

fn format_replay_heap_layout(
    chunks: &[json::JsonLayoutChunk],
    truncated: bool,
    chunks_omitted: usize,
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec!["heap layout:".to_string()];
    for chunk in chunks {
        let allocator_annotation = format_replay_layout_allocator_annotation(chunk);
        lines.push(format!(
            "    {} user={} size={} flags={} state={}{}",
            chunk.chunk_addr,
            chunk.user_addr,
            chunk.size,
            format_replay_flags(&chunk.flags),
            chunk.state,
            allocator_annotation
        ));
    }

    if chunks_omitted > 0 {
        lines.push(format!("    ... {chunks_omitted} more chunks not shown"));
    }
    if truncated {
        lines.push("    ... heap walk truncated".to_string());
    }

    lines.join("\n")
}

fn format_replay_layout_allocator_annotation(chunk: &json::JsonLayoutChunk) -> String {
    if let Some(source) = &chunk.allocator_source {
        if source.kind == "fastbin" {
            return format!(
                " source=fastbin[{}] index={}",
                source.chunk_size, source.index
            );
        }
        if source.kind == "tcache_candidate" {
            return format!(
                " tcache_candidate=size[{}] index={}",
                source.chunk_size, source.index
            );
        }
    }

    chunk
        .tcache_candidate
        .as_ref()
        .map(|membership| {
            format!(
                " tcache_candidate=size[{}] index={}",
                membership.chunk_size, membership.index
            )
        })
        .unwrap_or_default()
}

fn render_replay_observed_tcache_chains(
    chains: &[json::JsonObservedTcacheChain],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_observed_tcache_chains(chains, config));
}

fn format_replay_observed_tcache_chains(
    chains: &[json::JsonObservedTcacheChain],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks || chains.is_empty() {
        return String::new();
    }

    let mut lines = vec!["observed tcache candidates:".to_string()];
    for chain in chains {
        lines.push(format!(
            "    {}",
            format_replay_observed_tcache_chain(chain)
        ));
    }

    lines.join("\n")
}

fn render_replay_tcache_struct_candidate(
    candidate: &json::JsonTcacheStructCandidate,
    snapshot: Option<&json::JsonTcacheSnapshotCandidate>,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_tcache_struct_candidate(
        candidate, snapshot, config,
    ));
}

fn format_replay_tcache_struct_candidate(
    candidate: &json::JsonTcacheStructCandidate,
    snapshot: Option<&json::JsonTcacheSnapshotCandidate>,
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec![
        "tcache struct candidate:".to_string(),
        format!("    chunk:  {}", candidate.chunk_addr),
        format!("    user:   {}", candidate.user_addr),
        format!("    size:   {}", candidate.size),
        format!("    reason: {}", candidate.reason),
    ];

    if let Some(snapshot) = snapshot {
        if !snapshot.bins.is_empty() {
            lines.push("tcache snapshot candidate:".to_string());
            for bin in &snapshot.bins {
                lines.push(format!(
                    "    bin[{}] size={} count={} head={}",
                    bin.index, bin.chunk_size, bin.count, bin.head
                ));
            }
        }
    }

    lines.join("\n")
}

fn render_replay_main_arena_candidate(
    candidate: &json::JsonMainArenaCandidate,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_main_arena_candidate(candidate, config));
}

fn format_replay_main_arena_candidate(
    candidate: &json::JsonMainArenaCandidate,
    config: &ReplayConfig,
) -> String {
    if config.events_only {
        return String::new();
    }

    let mut lines = vec![
        "main_arena candidate:".to_string(),
        format!("    libc:   {}", candidate.libc_path),
        format!("    symbol: {}", candidate.symbol_name),
        format!("    addr:   {}", candidate.runtime_addr),
        format!("    source: {}", candidate.source),
    ];
    if let Some(offset) = &candidate.offset {
        lines.push(format!("    offset: {offset}"));
    }

    lines.join("\n")
}

fn render_replay_main_arena_experiment(
    arena_addr: &str,
    candidates: &[json::JsonMainArenaPointerCandidate],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_main_arena_experiment(
        arena_addr, candidates, config,
    ));
}

fn format_replay_main_arena_experiment(
    arena_addr: &str,
    candidates: &[json::JsonMainArenaPointerCandidate],
    config: &ReplayConfig,
) -> String {
    if config.events_only {
        return String::new();
    }

    let mut lines = vec![
        "main_arena experiment:".to_string(),
        format!("    arena: {arena_addr}"),
    ];
    if candidates.is_empty() {
        lines.push("    heap pointer candidates: none".to_string());
    } else {
        lines.push("    heap pointer candidates:".to_string());
        for candidate in candidates {
            lines.push(format!(
                "        offset={} value={} role={} matched_chunk_size={}",
                candidate.field_offset,
                candidate.value,
                candidate.role_hint,
                candidate.matched_chunk_size.as_deref().unwrap_or("none")
            ));
        }
    }

    lines.join("\n")
}

fn render_replay_main_arena_top_candidate(
    arena_addr: &str,
    field_offset: &str,
    top_addr: &str,
    chunk_size: Option<&str>,
    status: &str,
    source: &str,
    profile: Option<&str>,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_main_arena_top_candidate(
        arena_addr,
        field_offset,
        top_addr,
        chunk_size,
        status,
        source,
        profile,
        config,
    ));
}

fn format_replay_main_arena_top_candidate(
    arena_addr: &str,
    field_offset: &str,
    top_addr: &str,
    chunk_size: Option<&str>,
    status: &str,
    source: &str,
    profile: Option<&str>,
    config: &ReplayConfig,
) -> String {
    if config.events_only {
        return String::new();
    }

    let mut lines = vec![
        "main_arena top candidate:".to_string(),
        format!("    arena:       {arena_addr}"),
        format!("    field:       {field_offset}"),
        format!("    top:         {top_addr}"),
        format!("    source:      {source}"),
        format!("    chunk size:  {}", chunk_size.unwrap_or("unknown")),
        format!(
            "    status:      {}",
            format_replay_main_arena_top_status(status)
        ),
    ];
    if let Some(profile) = profile {
        lines.insert(5, format!("    profile:     {profile}"));
    }

    lines.join("\n")
}

fn render_replay_main_arena_view(
    arena: &json::JsonMainArenaViewArena,
    top: Option<&json::JsonMainArenaViewTop>,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_main_arena_view(arena, top, config));
}

fn format_replay_main_arena_view(
    arena: &json::JsonMainArenaViewArena,
    top: Option<&json::JsonMainArenaViewTop>,
    config: &ReplayConfig,
) -> String {
    if config.events_only {
        return String::new();
    }

    let mut lines = vec![
        "main_arena:".to_string(),
        format!("    addr:        {}", arena.addr),
        format!("    source:      {}", arena.source),
    ];
    if let Some(offset) = &arena.offset {
        lines.push(format!("    offset:      {offset}"));
    }
    if let Some(top) = top {
        lines.push(String::new());
        lines.push("    top:".to_string());
        lines.push(format!("        field:   {}", top.field_offset));
        lines.push(format!("        value:   {}", top.value));
        lines.push(format!(
            "        size:    {}",
            top.size.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!("        source:  {}", top.source));
        if let Some(profile) = &top.profile {
            lines.push(format!("        profile: {profile}"));
        }
        lines.push(format!("        status:  {}", top.status));
    }

    lines.join("\n")
}

fn render_replay_fastbin_experiment(
    arena_addr: &str,
    candidates: &[json::JsonFastbinPointerCandidate],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_fastbin_experiment(
        arena_addr, candidates, config,
    ));
}

fn format_replay_fastbin_experiment(
    arena_addr: &str,
    candidates: &[json::JsonFastbinPointerCandidate],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec![
        "fastbin experiment:".to_string(),
        format!("    arena: {arena_addr}"),
    ];
    if candidates.is_empty() {
        lines.push("    candidates: none".to_string());
    } else {
        lines.push("    candidates:".to_string());
        for candidate in candidates {
            lines.push(format!(
                "        offset={} value={} chunk_size={} known_freed={}",
                candidate.field_offset,
                candidate.value,
                candidate
                    .possible_chunk_size
                    .as_deref()
                    .unwrap_or("unknown"),
                replay_fastbin_known_freed(candidate.known_freed)
            ));
        }
    }

    lines.join("\n")
}

fn replay_fastbin_known_freed(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn render_replay_unsorted_bin_experiment(
    arena_addr: &str,
    candidates: &[json::JsonUnsortedBinPointerCandidate],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_unsorted_bin_experiment(
        arena_addr, candidates, config,
    ));
}

fn format_replay_unsorted_bin_experiment(
    arena_addr: &str,
    candidates: &[json::JsonUnsortedBinPointerCandidate],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec![
        "unsorted bin experiment:".to_string(),
        format!("    arena: {arena_addr}"),
    ];
    if candidates.is_empty() {
        lines.push("    candidates: none".to_string());
    } else {
        lines.push("    candidates:".to_string());
        for candidate in candidates {
            lines.push(format!(
                "        offset={} fd={} fd_in_heap={} fd_known_freed={} bk={} bk_in_heap={} bk_known_freed={} role={}",
                candidate.field_offset,
                candidate.fd,
                format_yes_no(candidate.fd_points_into_heap),
                replay_fastbin_known_freed(candidate.fd_known_freed),
                candidate.bk,
                format_yes_no(candidate.bk_points_into_heap),
                replay_fastbin_known_freed(candidate.bk_known_freed),
                candidate.role
            ));
        }
    }

    lines.join("\n")
}

fn render_replay_bin_experiment(
    arena_addr: &str,
    candidates: &[json::JsonBinPointerCandidate],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_bin_experiment(arena_addr, candidates, config));
}

fn format_replay_bin_experiment(
    arena_addr: &str,
    candidates: &[json::JsonBinPointerCandidate],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec![
        "bin experiment:".to_string(),
        format!("    arena: {arena_addr}"),
    ];
    if candidates.is_empty() {
        lines.push("    candidates: none".to_string());
    } else {
        lines.push("    candidates:".to_string());
        for candidate in candidates {
            lines.push(format!(
                "        offset={} fd={} fd_in_heap={} fd_in_arena={} fd_known_freed={} bk={} bk_in_heap={} bk_in_arena={} bk_known_freed={} role={}",
                candidate.field_offset,
                candidate.fd,
                format_yes_no(candidate.fd_points_into_heap),
                format_yes_no(candidate.fd_points_into_arena),
                replay_fastbin_known_freed(candidate.fd_known_freed),
                candidate.bk,
                format_yes_no(candidate.bk_points_into_heap),
                format_yes_no(candidate.bk_points_into_arena),
                replay_fastbin_known_freed(candidate.bk_known_freed),
                candidate.role
            ));
        }
    }

    lines.join("\n")
}

#[allow(clippy::too_many_arguments)]
fn render_replay_unsorted_bin(
    arena_addr: &str,
    field_offset: &str,
    fd: &str,
    bk: &str,
    fd_points_into_heap: bool,
    bk_points_into_heap: bool,
    fd_known_freed: Option<bool>,
    bk_known_freed: Option<bool>,
    chain: Option<&json::JsonUnsortedBinChain>,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_unsorted_bin(
        arena_addr,
        field_offset,
        fd,
        bk,
        fd_points_into_heap,
        bk_points_into_heap,
        fd_known_freed,
        bk_known_freed,
        chain,
        config,
    ));
}

#[allow(clippy::too_many_arguments)]
fn format_replay_unsorted_bin(
    arena_addr: &str,
    field_offset: &str,
    fd: &str,
    bk: &str,
    fd_points_into_heap: bool,
    bk_points_into_heap: bool,
    fd_known_freed: Option<bool>,
    bk_known_freed: Option<bool>,
    chain: Option<&json::JsonUnsortedBinChain>,
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec![
        "unsorted bin:".to_string(),
        format!("    arena: {arena_addr}"),
        format!("    offset: {field_offset}"),
        format!("    fd: {fd}"),
        format!("    bk: {bk}"),
        format!("    fd_in_heap: {}", format_yes_no(fd_points_into_heap)),
        format!("    bk_in_heap: {}", format_yes_no(bk_points_into_heap)),
        format!(
            "    fd_known_freed: {}",
            replay_fastbin_known_freed(fd_known_freed)
        ),
        format!(
            "    bk_known_freed: {}",
            replay_fastbin_known_freed(bk_known_freed)
        ),
    ];
    if let Some(chain) = chain {
        if chain.empty {
            lines.push("    chain: empty".to_string());
        } else {
            lines.push("    chain:".to_string());
            for node in &chain.nodes {
                lines.push(format!(
                    "        {} size={} fd={} bk={} known_freed={}",
                    node.chunk_addr,
                    node.chunk_size.as_deref().unwrap_or("unknown"),
                    node.fd,
                    node.bk,
                    replay_fastbin_known_freed(node.known_freed)
                ));
            }
        }
    }

    lines.join("\n")
}

fn render_replay_unsorted_bin_validation(
    validation: &json::JsonUnsortedBinValidation,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_unsorted_bin_validation(validation, config));
}

fn format_replay_unsorted_bin_validation(
    validation: &json::JsonUnsortedBinValidation,
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    [
        "unsorted bin validation:".to_string(),
        format!("    head_in_heap: {}", validation.head_in_heap),
        format!("    fd_bk_consistent: {}", validation.fd_bk_consistent),
        format!("    nodes_known_freed: {}", validation.nodes_known_freed),
        format!("    chain_complete: {}", validation.chain_complete),
        format!("    status: {}", validation.status),
    ]
    .join("\n")
}

fn render_replay_fastbins(
    arena_addr: &str,
    heads: &[json::JsonFastbinHead],
    chains: &[json::JsonFastbinChain],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_fastbins(arena_addr, heads, chains, config));
}

fn format_replay_fastbins(
    arena_addr: &str,
    heads: &[json::JsonFastbinHead],
    chains: &[json::JsonFastbinChain],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec!["fastbins:".to_string(), format!("    arena: {arena_addr}")];
    for head in heads {
        if head.head == "0x0" {
            lines.push(format!(
                "    bin[{}] size={} head=0x0",
                head.index, head.chunk_size
            ));
        } else {
            lines.push(format!(
                "    bin[{}] size={} head={} in_heap={} known_freed={}",
                head.index,
                head.chunk_size,
                head.head,
                format_replay_bool_yes_no(head.points_into_heap),
                replay_fastbin_known_freed(head.known_freed)
            ));
            if let Some(chain) = chains.iter().find(|chain| chain.index == head.index) {
                lines.push(format!(
                    "        chain: {}",
                    format_json_fastbin_chain(chain)
                ));
            }
        }
    }

    lines.join("\n")
}

fn render_replay_regular_bins(
    arena_addr: &str,
    bins_offset: &str,
    heads: &[json::JsonRegularBinHead],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_regular_bins(
        arena_addr,
        bins_offset,
        heads,
        config,
    ));
}

fn format_replay_regular_bins(
    arena_addr: &str,
    bins_offset: &str,
    heads: &[json::JsonRegularBinHead],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec![
        "regular bins:".to_string(),
        format!("    arena: {arena_addr}"),
        format!("    bins_offset: {bins_offset}"),
    ];
    for head in heads {
        let chunk_size = head
            .chunk_size
            .as_ref()
            .map(|size| format!(" chunk_size={size}"))
            .unwrap_or_default();
        lines.push(format!(
            "    bin[{}] glibc_bin_index={} role={}{} fd={} bk={} empty={} fd_in_heap={} bk_in_heap={}",
            head.index,
            head.glibc_bin_index,
            head.role,
            chunk_size,
            head.fd,
            head.bk,
            format_yes_no(head.empty),
            format_yes_no(head.fd_points_into_heap),
            format_yes_no(head.bk_points_into_heap)
        ));
    }

    lines.join("\n")
}

fn render_replay_smallbins(
    arena_addr: &str,
    bins_offset: &str,
    chains: &[json::JsonSmallbinChain],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_smallbins(
        arena_addr,
        bins_offset,
        chains,
        config,
    ));
}

fn format_replay_smallbins(
    arena_addr: &str,
    bins_offset: &str,
    chains: &[json::JsonSmallbinChain],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let non_empty = chains
        .iter()
        .filter(|chain| !chain.empty)
        .collect::<Vec<_>>();
    let mut lines = vec![
        "smallbins:".to_string(),
        format!("    arena: {arena_addr}"),
        format!("    bins_offset: {bins_offset}"),
    ];
    if non_empty.is_empty() {
        lines.push("    all smallbins empty".to_string());
        return lines.join("\n");
    }

    for chain in non_empty {
        lines.push(format!(
            "    bin[{}] size={}:",
            chain.glibc_bin_index, chain.expected_chunk_size
        ));
        lines.push("        chain:".to_string());
        for node in &chain.nodes {
            lines.push(format!(
                "            {} size={} fd={} bk={} known_freed={}",
                node.chunk_addr,
                node.chunk_size.as_deref().unwrap_or("unknown"),
                node.fd,
                node.bk,
                replay_fastbin_known_freed(node.known_freed)
            ));
        }
    }

    lines.join("\n")
}

fn render_replay_smallbin_validation(
    validations: &[json::JsonSmallbinBinValidation],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_smallbin_validation(validations, config));
}

fn format_replay_smallbin_validation(
    validations: &[json::JsonSmallbinBinValidation],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks || validations.is_empty() {
        return String::new();
    }

    let mut lines = vec!["smallbin validation:".to_string()];
    for validation in validations {
        lines.push(format!(
            "    bin[{}] size={}:",
            validation.glibc_bin_index, validation.expected_chunk_size
        ));
        lines.push(format!("        head_in_heap: {}", validation.head_in_heap));
        lines.push(format!(
            "        nodes_same_size: {}",
            validation.nodes_same_size
        ));
        lines.push(format!(
            "        fd_bk_consistent: {}",
            validation.fd_bk_consistent
        ));
        lines.push(format!(
            "        nodes_known_freed: {}",
            validation.nodes_known_freed
        ));
        lines.push(format!(
            "        chain_complete: {}",
            validation.chain_complete
        ));
        lines.push(format!("        status: {}", validation.status));
    }

    lines.join("\n")
}

fn render_replay_largebins(
    arena_addr: &str,
    bins_offset: &str,
    chains: &[json::JsonLargebinChain],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_largebins(
        arena_addr,
        bins_offset,
        chains,
        config,
    ));
}

fn format_replay_largebins(
    arena_addr: &str,
    bins_offset: &str,
    chains: &[json::JsonLargebinChain],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let non_empty = chains
        .iter()
        .filter(|chain| !chain.empty)
        .collect::<Vec<_>>();
    let mut lines = vec![
        "largebins:".to_string(),
        format!("    arena: {arena_addr}"),
        format!("    bins_offset: {bins_offset}"),
    ];
    if non_empty.is_empty() {
        lines.push("    all largebins empty".to_string());
        return lines.join("\n");
    }

    for chain in non_empty {
        lines.push(format!("    bin[{}]:", chain.glibc_bin_index));
        lines.push("        chain:".to_string());
        for node in &chain.nodes {
            lines.push(format!(
                "            {} size={} fd={} bk={} fd_nextsize={} bk_nextsize={} known_freed={}",
                node.chunk_addr,
                node.chunk_size.as_deref().unwrap_or("unknown"),
                node.fd,
                node.bk,
                node.fd_nextsize,
                node.bk_nextsize,
                replay_fastbin_known_freed(node.known_freed)
            ));
        }
    }

    lines.join("\n")
}

fn render_replay_largebin_validation(
    validations: &[json::JsonLargebinBinValidation],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_largebin_validation(validations, config));
}

fn format_replay_largebin_validation(
    validations: &[json::JsonLargebinBinValidation],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks || validations.is_empty() {
        return String::new();
    }

    let mut lines = vec!["largebin validation:".to_string()];
    for validation in validations {
        lines.push(format!("    bin[{}]:", validation.glibc_bin_index));
        lines.push(format!("        head_in_heap: {}", validation.head_in_heap));
        lines.push(format!(
            "        fd_bk_consistent: {}",
            validation.fd_bk_consistent
        ));
        lines.push(format!(
            "        nodes_known_freed: {}",
            validation.nodes_known_freed
        ));
        lines.push(format!(
            "        chain_complete: {}",
            validation.chain_complete
        ));
        lines.push(format!("        status: {}", validation.status));
    }

    lines.join("\n")
}

fn format_json_fastbin_chain(chain: &json::JsonFastbinChain) -> String {
    let entries = chain
        .nodes
        .iter()
        .map(|node| node.chunk_addr.as_str())
        .collect::<Vec<_>>();
    format_fastbin_chain_entries(
        &entries,
        chain.truncated,
        chain.stopped_on_unknown_next,
        chain.cycle_detected,
    )
}

fn format_fastbin_chain_entries(
    entries: &[&str],
    truncated: bool,
    stopped_on_unknown_next: bool,
    cycle_detected: bool,
) -> String {
    let mut parts = entries
        .iter()
        .map(|entry| (*entry).to_string())
        .collect::<Vec<_>>();
    if cycle_detected {
        parts.push("... cycle".to_string());
    } else if truncated {
        parts.push("... truncated".to_string());
    } else if stopped_on_unknown_next {
        parts.push("?".to_string());
    } else {
        parts.push("NULL".to_string());
    }

    parts.join(" -> ")
}

fn render_replay_fastbin_validation(
    validations: &[json::JsonFastbinBinValidation],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_fastbin_validation(validations, config));
}

fn format_replay_fastbin_validation(
    validations: &[json::JsonFastbinBinValidation],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    let mut lines = vec!["fastbin validation:".to_string()];
    for validation in validations {
        lines.push(format!(
            "    bin[{}] size={}:",
            validation.index, validation.chunk_size
        ));
        lines.push(format!("        head_in_heap: {}", validation.head_in_heap));
        lines.push(format!(
            "        nodes_same_size: {}",
            validation.nodes_same_size
        ));
        lines.push(format!(
            "        nodes_known_freed: {}",
            validation.nodes_known_freed
        ));
        lines.push(format!(
            "        chain_complete: {}",
            validation.chain_complete
        ));
        lines.push(format!("        status: {}", validation.status));
    }

    lines.join("\n")
}

fn format_replay_bool_yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_replay_main_arena_top_status(status: &str) -> &str {
    match status {
        "matches_walked_chunk" => "points into heap and matches walked chunk",
        "points_into_heap" => "points into heap but does not match walked chunk",
        "outside_heap" => "outside heap",
        "unavailable" => "unavailable",
        other => other,
    }
}

fn render_replay_tcache_comparison(
    comparisons: &[json::JsonTcacheBinComparison],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_tcache_comparison(comparisons, config));
}

fn render_replay_tcache_validation(
    validations: &[json::JsonTcacheBinValidation],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_tcache_validation(validations, config));
}

fn format_replay_tcache_comparison(
    comparisons: &[json::JsonTcacheBinComparison],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks || comparisons.is_empty() {
        return String::new();
    }

    let mut lines = vec!["tcache comparison candidate:".to_string()];
    for comparison in comparisons {
        lines.push(format!("    size {}:", comparison.chunk_size));
        lines.push(format!("        struct count: {}", comparison.struct_count));
        lines.push(format!("        struct head:  {}", comparison.struct_head));
        lines.push(format!(
            "        observed:     {}",
            format_replay_tcache_comparison_observed(comparison)
        ));
        lines.push(format!("        status:       {}", comparison.status));
    }

    lines.join("\n")
}

fn format_replay_tcache_validation(
    validations: &[json::JsonTcacheBinValidation],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks || validations.is_empty() {
        return String::new();
    }

    let mut lines = vec!["tcache validation candidate:".to_string()];
    for validation in validations {
        lines.push(format!("    size {}:", validation.chunk_size));
        lines.push(format!("        head_in_heap: {}", validation.head_in_heap));
        lines.push(format!(
            "        head_known_freed: {}",
            validation.head_known_freed
        ));
        lines.push(format!(
            "        observed_nodes_same_size: {}",
            validation.observed_nodes_same_size
        ));
        lines.push(format!(
            "        count_matches_observed: {}",
            validation.count_matches_observed
        ));
        lines.push(format!("        status: {}", validation.status));
    }

    lines.join("\n")
}

fn render_replay_allocator_warnings(
    warnings: &[json::JsonAllocatorWarning],
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_allocator_warnings(warnings, config));
}

fn render_replay_allocator_source_summary(
    tcache_candidate_chunks: usize,
    fastbin_chunks: usize,
    unsorted_chunks: usize,
    smallbin_chunks: usize,
    largebin_chunks: usize,
    total_free_list_chunks: usize,
    warning_count: usize,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_allocator_source_summary(
        tcache_candidate_chunks,
        fastbin_chunks,
        unsorted_chunks,
        smallbin_chunks,
        largebin_chunks,
        total_free_list_chunks,
        warning_count,
        config,
    ));
}

fn format_replay_allocator_source_summary(
    tcache_candidate_chunks: usize,
    fastbin_chunks: usize,
    unsorted_chunks: usize,
    smallbin_chunks: usize,
    largebin_chunks: usize,
    total_free_list_chunks: usize,
    warning_count: usize,
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    format!(
        "allocator source summary:\n    tcache candidates: {tcache_candidate_chunks} chunks\n    fastbins:          {fastbin_chunks} chunks\n    unsorted bin:      {unsorted_chunks} chunks\n    smallbins:         {smallbin_chunks} chunks\n    largebins:         {largebin_chunks} chunks\n    total free-list:   {total_free_list_chunks} chunks\n    warnings:          {warning_count}"
    )
}

fn render_replay_allocator_source_delta(
    tcache_candidate_chunks_delta: isize,
    fastbin_chunks_delta: isize,
    unsorted_chunks_delta: isize,
    smallbin_chunks_delta: isize,
    largebin_chunks_delta: isize,
    total_free_list_chunks_delta: isize,
    warning_count_delta: isize,
    config: &ReplayConfig,
) {
    print_replay_text(format_replay_allocator_source_delta(
        tcache_candidate_chunks_delta,
        fastbin_chunks_delta,
        unsorted_chunks_delta,
        smallbin_chunks_delta,
        largebin_chunks_delta,
        total_free_list_chunks_delta,
        warning_count_delta,
        config,
    ));
}

fn format_replay_allocator_source_delta(
    tcache_candidate_chunks_delta: isize,
    fastbin_chunks_delta: isize,
    unsorted_chunks_delta: isize,
    smallbin_chunks_delta: isize,
    largebin_chunks_delta: isize,
    total_free_list_chunks_delta: isize,
    warning_count_delta: isize,
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks {
        return String::new();
    }

    format!(
        "allocator delta:\n    tcache candidates: {}\n    fastbins:          {}\n    unsorted bin:      {}\n    smallbins:         {}\n    largebins:         {}\n    total free-list:   {}\n    warnings:          {}",
        format_allocator_source_delta(tcache_candidate_chunks_delta),
        format_allocator_source_delta(fastbin_chunks_delta),
        format_allocator_source_delta(unsorted_chunks_delta),
        format_allocator_source_delta(smallbin_chunks_delta),
        format_allocator_source_delta(largebin_chunks_delta),
        format_allocator_source_delta(total_free_list_chunks_delta),
        format_allocator_source_delta(warning_count_delta),
    )
}

fn format_replay_heap_scan(report: &json::JsonHeapScanReport, config: &ReplayConfig) -> String {
    if config.events_only {
        return String::new();
    }

    let snapshot_status = if report
        .findings
        .iter()
        .any(|finding| finding.kind == "heap_snapshot_unavailable")
    {
        "unavailable"
    } else if report.heap_snapshot_truncated {
        "truncated"
    } else {
        "complete"
    };
    let top_status = match report.top_validated {
        Some(true) => "validated",
        Some(false) => "not_validated",
        None => "unknown",
    };
    let mut lines = vec![
        "heap scan:".to_string(),
        format!("    chunks walked:          {}", report.chunks_walked),
        format!("    allocated observed:     {}", report.allocated_observed),
        format!("    freed observed:         {}", report.freed_observed),
        format!("    unknown observed:       {}", report.unknown_observed),
        format!(
            "    allocator sources:      {} chunks",
            report.allocator_source_chunks
        ),
        format!("    allocator warnings:     {}", report.warning_count),
        format!("    suspicious findings:    {}", report.suspicious_count),
        format!("    top chunk:              {top_status}"),
        format!("    heap snapshot:          {snapshot_status}"),
        format!("    status:                 {}", report.status),
    ];

    if !report.findings.is_empty() {
        lines.push("heap scan findings:".to_string());
        for finding in &report.findings {
            let chunk = finding
                .chunk_addr
                .as_ref()
                .map(|addr| format!(" chunk={addr}"))
                .unwrap_or_default();
            let user = finding
                .user_addr
                .as_ref()
                .map(|addr| format!(" user={addr}"))
                .unwrap_or_default();
            lines.push(format!(
                "    [{}] {}{}{}: {}",
                finding.severity, finding.kind, chunk, user, finding.message
            ));
            lines.extend(
                explain_heap_scan_finding(finding)
                    .into_iter()
                    .take(2)
                    .map(|line| format!("        {line}")),
            );
        }
    }

    lines.join("\n")
}

fn format_replay_allocator_warnings(
    warnings: &[json::JsonAllocatorWarning],
    config: &ReplayConfig,
) -> String {
    if config.events_only || !config.show_chunks || warnings.is_empty() {
        return String::new();
    }

    let mut lines = vec!["allocator warnings:".to_string()];
    for warning in warnings {
        lines.push(format!(
            "    [{}] chunk={} user={} sources={} message={}",
            warning.kind,
            warning.chunk_addr,
            warning.user_addr,
            format_json_allocator_warning_sources(&warning.sources),
            warning.message
        ));
    }

    lines.join("\n")
}

fn format_json_allocator_warning_sources(
    sources: &[json::JsonAllocatorSourceMembership],
) -> String {
    sources
        .iter()
        .map(|source| {
            let size = source
                .chunk_size
                .as_deref()
                .map(|size| format!("[{size}]"))
                .unwrap_or_else(|| "[unknown]".to_string());
            let index = source
                .index
                .map(|index| format!("#{index}"))
                .unwrap_or_default();

            format!("{}{}{}", source.kind, size, index)
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn format_replay_chunk(label: &str, chunk: &json::JsonChunk, spaces: usize) -> Vec<String> {
    let indent = " ".repeat(spaces);
    vec![
        format!("{indent}{label}:"),
        format!("{indent}    chunk:      {}", chunk.chunk_addr),
        format!("{indent}    user:       {}", chunk.user_addr),
        format!("{indent}    prev_size:  {}", chunk.prev_size),
        format!("{indent}    size_raw:   {}", chunk.size_raw),
        format!("{indent}    size:       {}", chunk.size),
        format!(
            "{indent}    flags:      {}",
            format_replay_flags(&chunk.flags)
        ),
    ]
}

fn format_replay_tcache_entry(candidate: &json::JsonTcacheEntry) -> Vec<String> {
    vec![
        "    tcache candidate:".to_string(),
        format!("        storage:      {}", candidate.storage_addr),
        format!("        encoded_next: {}", candidate.encoded_next),
        format!("        decoded_next: {}", candidate.decoded_next),
    ]
}

fn format_replay_tracker(tracker_note: &str, tracker_explanation: &Option<String>) -> Vec<String> {
    let mut lines = vec![format!("    tracker: {tracker_note}")];
    if let Some(explanation) = tracker_explanation {
        lines.push(format!("    explanation: {explanation}"));
    }
    lines
}

fn print_replay_text(text: String) {
    if !text.is_empty() {
        println!("{text}");
    }
}

fn format_replay_session_start(
    heapify_version: &str,
    program: &str,
    trace_mode: &str,
    glibc_profile: &str,
    suggested_glibc_profile: Option<&str>,
    glibc_profile_selection: Option<&heapify_core::glibc::GlibcProfileSelection>,
    libc: Option<&json::JsonLibcMetadata>,
    launch: Option<&json::JsonLaunchMetadata>,
    allocator_views_preset: &str,
    features: &json::JsonTraceFeatures,
    show_profile_details: bool,
) -> String {
    let (libc_path, glibc_version) = libc
        .map(|libc| {
            (
                libc.path.as_deref().unwrap_or("unknown"),
                libc.version.as_deref().unwrap_or("unknown"),
            )
        })
        .unwrap_or(("unknown", "unknown"));
    let glibc_profile = if glibc_profile.is_empty() {
        "unknown"
    } else {
        glibc_profile
    };
    let mut lines = vec![
        "session:".to_string(),
        format!("    program: {program}"),
        format!("    mode: {trace_mode}"),
        format!("    heapify: {heapify_version}"),
        format!("    libc: {libc_path}"),
        format!("    glibc version: {glibc_version}"),
        format!("    glibc profile: {glibc_profile}"),
    ];
    if let Some(supplied_path) = libc.and_then(|libc| libc.supplied_path.as_deref()) {
        lines.push(format!("    supplied libc: {supplied_path}"));
    }
    if libc.and_then(|libc| libc.paths_match) == Some(false) {
        lines.push(
            "    warning: supplied libc differs from loaded libc; symbol offsets may be wrong"
                .to_string(),
        );
    }
    if let Some(launch) = launch {
        lines.push(format!("    launch mode: {}", launch.mode));
        if let Some(cwd) = launch.cwd.as_deref() {
            lines.push(format!("    cwd: {cwd}"));
        }
        if let Some(loader) = launch.loader.as_deref() {
            lines.push(format!("    loader: {loader}"));
        }
        if let Some(library_path) = launch.library_path.as_deref() {
            lines.push(format!("    library path: {library_path}"));
        }
        if let Some(preload) = launch.preload.as_deref() {
            lines.push(format!("    preload: {preload}"));
        }
        match launch.stdin.kind.as_str() {
            "inherit" => {}
            "file" => {
                let path = launch.stdin.path.as_deref().unwrap_or("unknown");
                lines.push(format!("    stdin: file {path}"));
            }
            "text" => {
                let bytes = launch.stdin.bytes.unwrap_or(0);
                lines.push(format!("    stdin: text {bytes} bytes"));
            }
            other => lines.push(format!("    stdin: {other}")),
        }
        if launch.clear_env || !launch.set_env.is_empty() || !launch.unset_env.is_empty() {
            lines.push(format!(
                "    env: clear={} set={} unset={}",
                launch.clear_env,
                launch.set_env.len(),
                launch.unset_env.len()
            ));
            if !launch.set_env.is_empty() {
                lines.push(format!("    env set: {}", launch.set_env.join(", ")));
            }
            if !launch.unset_env.is_empty() {
                lines.push(format!("    env unset: {}", launch.unset_env.join(", ")));
            }
        }
    }
    if let Some(suggested_glibc_profile) = suggested_glibc_profile {
        lines.push(format!(
            "    suggested glibc profile: {suggested_glibc_profile}"
        ));
    }
    if show_profile_details {
        if let Some(selection) = glibc_profile_selection {
            lines.push("    glibc profile selection:".to_string());
            lines.push(format!("        requested: {}", selection.requested));
            lines.push(format!("        selected: {}", selection.selected));
            if let Some(version) = selection.detected_version.as_deref() {
                lines.push(format!("        detected version: {version}"));
            }
            if let Some(path) = selection.detected_libc_path.as_deref() {
                lines.push(format!("        detected libc: {path}"));
            }
            if let Some(path) = selection.supplied_libc_path.as_deref() {
                lines.push(format!("        supplied libc: {path}"));
            }
            lines.push(format!(
                "        confidence: {}",
                format_glibc_profile_confidence(selection.confidence)
            ));
            lines.push(format!("        reason: {}", selection.reason));
            for warning in &selection.warnings {
                lines.push(format!("        warning: {warning}"));
            }
            if selection.confidence == GlibcProfileConfidence::Low
                && allocator_views_preset == "full"
            {
                lines.push(format!(
                    "        warning: {}",
                    low_confidence_profile_warning()
                ));
            }
        }
    }
    if allocator_views_preset != "none" {
        lines.push(format!(
            "    allocator views preset: {allocator_views_preset}"
        ));
    }
    lines.push(format!(
        "    features: {}",
        format_replay_features(features)
    ));
    lines.join("\n")
}

fn format_glibc_profile_confidence(confidence: GlibcProfileConfidence) -> &'static str {
    match confidence {
        GlibcProfileConfidence::High => "high",
        GlibcProfileConfidence::Medium => "medium",
        GlibcProfileConfidence::Low => "low",
    }
}

fn format_replay_session_end(exit_status: &str, event_count: usize) -> String {
    format!("session end:\n    exit_status: {exit_status}\n    event_count: {event_count}")
}

fn format_replay_features(features: &json::JsonTraceFeatures) -> String {
    let mut enabled = Vec::new();
    if features.layout {
        enabled.push("layout");
    }
    if features.tcache_candidates {
        enabled.push("tcache_candidates");
    }
    if features.tcache_struct {
        enabled.push("tcache_struct");
    }
    if features.libc_symbols {
        enabled.push("libc_symbols");
    }

    if enabled.is_empty() {
        "none".to_string()
    } else {
        enabled.join(",")
    }
}

fn format_replay_flags(flags: &[String]) -> String {
    if flags.is_empty() {
        "none".to_string()
    } else {
        flags.join(" | ")
    }
}

fn format_replay_observed_tcache_chain(chain: &json::JsonObservedTcacheChain) -> String {
    let mut parts = chain.entries.clone();

    if chain.truncated {
        parts.push("... truncated".to_string());
    } else if chain.stopped_on_unknown_next {
        parts.push("?".to_string());
    } else {
        parts.push("NULL".to_string());
    }

    format!("size {}: {}", chain.chunk_size, parts.join(" -> "))
}

fn format_replay_tcache_comparison_observed(comparison: &json::JsonTcacheBinComparison) -> String {
    if comparison.observed_entries.is_empty() {
        return "<none>".to_string();
    }

    let mut parts = comparison.observed_entries.clone();

    if comparison.observed_truncated {
        parts.push("... truncated".to_string());
    } else if comparison.observed_stopped_on_unknown_next {
        parts.push("?".to_string());
    } else {
        parts.push("NULL".to_string());
    }

    parts.join(" -> ")
}

fn run_replay_tui(session: &ReplaySession, config: &ReplayConfig) -> Result<()> {
    let _guard = TerminalModeGuard::enter()?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal")?;
    let mut state = ReplayTuiState {
        selected_event_index: 0,
        scroll_details: 0,
    };

    terminal.clear().context("failed to clear terminal")?;
    loop {
        terminal
            .draw(|frame| draw_replay_tui(frame, session, config, &state))
            .context("failed to draw replay TUI")?;

        if event::poll(Duration::from_millis(250)).context("failed to poll terminal events")? {
            let Event::Key(key) = event::read().context("failed to read terminal event")? else {
                continue;
            };

            if handle_replay_tui_key(key.code, session, &mut state) {
                break;
            }
        }
    }

    Ok(())
}

fn draw_replay_tui(
    frame: &mut ratatui::Frame<'_>,
    session: &ReplaySession,
    config: &ReplayConfig,
    state: &ReplayTuiState,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ])
        .split(frame.size());

    let timeline_block = Block::default()
        .title("Event Timeline")
        .borders(Borders::ALL);
    let timeline_inner_height = chunks[0].height.saturating_sub(2) as usize;
    let timeline_offset = visible_timeline_offset(
        state.selected_event_index,
        timeline_inner_height,
        session.event_count(),
    );
    let timeline_items = session
        .events
        .iter()
        .skip(timeline_offset)
        .take(timeline_inner_height.max(1))
        .filter_map(|entry| match session.records.get(entry.record_index) {
            Some(json::JsonTraceRecord::Event { event }) => {
                Some(ListItem::new(format_timeline_event_summary(
                    event,
                    session.allocator_states_by_event_id.get(&entry.event_id),
                )))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut list_state = ListState::default();
    list_state.select(Some(
        state.selected_event_index.saturating_sub(timeline_offset),
    ));
    let timeline = List::new(timeline_items)
        .block(timeline_block)
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(timeline, chunks[0], &mut list_state);

    let selected_record = session.event_record(state.selected_event_index);
    let details_text = selected_record
        .map(|record| format_replay_record(record, config))
        .unwrap_or_else(|| "no event selected".to_string());
    let details = Paragraph::new(text_from_string(&details_text))
        .block(
            Block::default()
                .title("Selected Event Details")
                .borders(Borders::ALL),
        )
        .scroll((state.scroll_details, 0));
    frame.render_widget(details, chunks[1]);

    let related_text = selected_record
        .and_then(replay_record_event_id)
        .map(|event_id| format_related_replay_records(session, event_id, config))
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "no related records".to_string());
    let related = Paragraph::new(text_from_string(&related_text)).block(
        Block::default()
            .title("Related Records")
            .borders(Borders::ALL),
    );
    frame.render_widget(related, chunks[2]);
}

fn handle_replay_tui_key(
    key: KeyCode,
    session: &ReplaySession,
    state: &mut ReplayTuiState,
) -> bool {
    let last_index = session.event_count().saturating_sub(1);

    match key {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        KeyCode::Down | KeyCode::Char('j') => {
            state.selected_event_index = (state.selected_event_index + 1).min(last_index);
            state.scroll_details = 0;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.selected_event_index = state.selected_event_index.saturating_sub(1);
            state.scroll_details = 0;
        }
        KeyCode::PageDown => {
            state.selected_event_index = (state.selected_event_index + 10).min(last_index);
            state.scroll_details = 0;
        }
        KeyCode::PageUp => {
            state.selected_event_index = state.selected_event_index.saturating_sub(10);
            state.scroll_details = 0;
        }
        KeyCode::Home => {
            state.selected_event_index = 0;
            state.scroll_details = 0;
        }
        KeyCode::End => {
            state.selected_event_index = last_index;
            state.scroll_details = 0;
        }
        _ => {}
    }

    false
}

fn visible_timeline_offset(
    selected_event_index: usize,
    visible_rows: usize,
    event_count: usize,
) -> usize {
    if visible_rows == 0 || event_count <= visible_rows {
        return 0;
    }

    let max_offset = event_count.saturating_sub(visible_rows);
    selected_event_index
        .saturating_sub(visible_rows.saturating_sub(1))
        .min(max_offset)
}

fn format_related_replay_records(
    session: &ReplaySession,
    event_id: usize,
    config: &ReplayConfig,
) -> String {
    session
        .records_for_event(event_id)
        .into_iter()
        .filter(|record| !matches!(record, json::JsonTraceRecord::Event { .. }))
        .map(|record| format_replay_record(record, config))
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn text_from_string(text: &str) -> Text<'static> {
    Text::from(
        text.lines()
            .map(|line| Line::from(line.to_string()))
            .collect::<Vec<_>>(),
    )
}

fn format_replay_event_summary(event: &json::JsonHeapEvent) -> String {
    match event {
        json::JsonHeapEvent::Malloc {
            event_id,
            requested_size,
            returned_ptr,
            ..
        } => format!("#{event_id} malloc({requested_size}) = {returned_ptr}"),
        json::JsonHeapEvent::Free { event_id, ptr, .. } => {
            format!("#{event_id} free({ptr})")
        }
        json::JsonHeapEvent::Calloc {
            event_id,
            nmemb,
            size,
            returned_ptr,
            ..
        } => format!("#{event_id} calloc({nmemb}, {size}) = {returned_ptr}"),
        json::JsonHeapEvent::Realloc {
            event_id,
            old_ptr,
            new_size,
            returned_ptr,
            ..
        } => format!("#{event_id} realloc({old_ptr}, {new_size}) = {returned_ptr}"),
    }
}

fn format_timeline_event_summary(
    event: &json::JsonHeapEvent,
    state: Option<&ReplayEventAllocatorState>,
) -> String {
    let event_summary = format_replay_event_summary(event);
    let allocator_counts = format_timeline_allocator_counts(state);
    if allocator_counts.is_empty() {
        event_summary
    } else {
        format!("{event_summary}    {allocator_counts}")
    }
}

fn format_timeline_allocator_counts(state: Option<&ReplayEventAllocatorState>) -> String {
    state
        .map(|state| {
            format!(
                "tc={} fb={} ub={} sb={} lb={} warn={}",
                state.tcache_candidate_chunks,
                state.fastbin_chunks,
                state.unsorted_chunks,
                state.smallbin_chunks,
                state.largebin_chunks,
                state.warning_count
            )
        })
        .unwrap_or_default()
}

fn replay_event_id(event: &json::JsonHeapEvent) -> usize {
    match event {
        json::JsonHeapEvent::Malloc { event_id, .. }
        | json::JsonHeapEvent::Free { event_id, .. }
        | json::JsonHeapEvent::Calloc { event_id, .. }
        | json::JsonHeapEvent::Realloc { event_id, .. } => *event_id,
    }
}

fn replay_record_event_id(record: &json::JsonTraceRecord) -> Option<usize> {
    match record {
        json::JsonTraceRecord::SessionStart { .. } | json::JsonTraceRecord::SessionEnd { .. } => {
            None
        }
        json::JsonTraceRecord::Event { event } => Some(replay_event_id(event)),
        json::JsonTraceRecord::HeapLayout { event_id, .. }
        | json::JsonTraceRecord::ObservedTcacheChains { event_id, .. }
        | json::JsonTraceRecord::TcacheStructCandidate { event_id, .. }
        | json::JsonTraceRecord::MainArenaCandidate { event_id, .. }
        | json::JsonTraceRecord::MainArenaExperiment { event_id, .. }
        | json::JsonTraceRecord::MainArenaTopCandidate { event_id, .. }
        | json::JsonTraceRecord::MainArenaView { event_id, .. }
        | json::JsonTraceRecord::FastbinExperiment { event_id, .. }
        | json::JsonTraceRecord::UnsortedBinExperiment { event_id, .. }
        | json::JsonTraceRecord::BinExperiment { event_id, .. }
        | json::JsonTraceRecord::UnsortedBin { event_id, .. }
        | json::JsonTraceRecord::UnsortedBinValidation { event_id, .. }
        | json::JsonTraceRecord::Fastbins { event_id, .. }
        | json::JsonTraceRecord::RegularBins { event_id, .. }
        | json::JsonTraceRecord::Smallbins { event_id, .. }
        | json::JsonTraceRecord::SmallbinValidation { event_id, .. }
        | json::JsonTraceRecord::Largebins { event_id, .. }
        | json::JsonTraceRecord::LargebinValidation { event_id, .. }
        | json::JsonTraceRecord::FastbinValidation { event_id, .. }
        | json::JsonTraceRecord::TcacheComparison { event_id, .. }
        | json::JsonTraceRecord::TcacheValidation { event_id, .. }
        | json::JsonTraceRecord::AllocatorWarnings { event_id, .. }
        | json::JsonTraceRecord::AllocatorSourceSummary { event_id, .. }
        | json::JsonTraceRecord::AllocatorSourceDelta { event_id, .. }
        | json::JsonTraceRecord::HeapScan { event_id, .. } => Some(*event_id),
    }
}

struct TerminalModeGuard;

impl TerminalModeGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("failed to enable raw mode")?;
        if let Err(err) = execute!(std::io::stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(err).context("failed to enter alternate screen");
        }
        Ok(Self)
    }
}

impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

fn emit_live_trace_records(
    sink: &mut dyn LiveTraceSink,
    event: &HeapTraceEvent,
    note: HeapTrackerNote,
    explanation: HeapTrackerExplanation,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    tcache_tracker: &mut ObservedTcacheTracker,
    config: &RenderConfig,
    cached_tcache_struct_candidate: &mut Option<TcacheStructCandidate>,
    printed_tcache_struct_candidate_block: &mut bool,
    cached_main_arena_candidate: &mut Option<MainArenaCandidate>,
    printed_main_arena_candidate_block: &mut bool,
    printed_main_arena_experiment_block: &mut bool,
    printed_fastbin_experiment_block: &mut bool,
    printed_unsorted_experiment_block: &mut bool,
    printed_bin_experiment_block: &mut bool,
    printed_unsorted_bin_block: &mut bool,
    printed_fastbins_block: &mut bool,
    printed_regular_bins_block: &mut bool,
    printed_smallbins_block: &mut bool,
    printed_largebins_block: &mut bool,
    cached_fastbins_snapshot: &mut Option<FastbinsSnapshot>,
    cached_unsorted_bin_snapshot: &mut Option<UnsortedBinSnapshot>,
    cached_regular_bins_snapshot: &mut Option<RegularBinsSnapshot>,
    cached_smallbins_snapshot: &mut Option<SmallbinsSnapshot>,
    cached_largebins_snapshot: &mut Option<LargebinsSnapshot>,
    printed_main_arena_top_candidate_block: &mut bool,
    previous_allocator_source_summary: &mut Option<AllocatorSourceSummary>,
    caller_symbol: Option<SymbolizedAddress>,
) -> Result<Vec<json::JsonTraceRecord>> {
    let mut effective_config = config.clone();
    effective_config.glibc_profile = context.glibc_profile;
    let config = &effective_config;
    let mut sink = RecordingRelatedSink {
        inner: sink,
        related_records: Vec::new(),
    };
    let event_id = heap_event_id(event);
    sink.on_update(&LiveTraceUpdate::Event {
        event_id,
        event: event.clone(),
        note,
        explanation,
        caller_symbol,
    })?;
    tcache_tracker.observe_event(event);

    maybe_emit_main_arena_top_candidate_record(
        &mut sink,
        event_id,
        context,
        config,
        cached_main_arena_candidate,
        printed_main_arena_candidate_block,
        printed_main_arena_top_candidate_block,
    )?;
    maybe_emit_main_arena_candidate_record(
        &mut sink,
        event_id,
        context,
        config,
        cached_main_arena_candidate,
        printed_main_arena_candidate_block,
    )?;
    maybe_emit_main_arena_experiment_record(
        &mut sink,
        event_id,
        context,
        config,
        cached_main_arena_candidate.as_ref(),
        printed_main_arena_experiment_block,
    )?;
    if config.events_only() {
        return Ok(sink.related_records);
    }

    if config.show_chunks {
        maybe_emit_fastbin_experiment_record(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_main_arena_candidate.as_ref(),
            printed_fastbin_experiment_block,
        )?;
        maybe_emit_fastbins_record(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_main_arena_candidate.as_ref(),
            printed_fastbins_block,
            cached_fastbins_snapshot,
        )?;
        maybe_emit_unsorted_bin_record(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_main_arena_candidate.as_ref(),
            printed_unsorted_bin_block,
            cached_unsorted_bin_snapshot,
        )?;
        maybe_emit_regular_bins_record(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_main_arena_candidate.as_ref(),
            printed_regular_bins_block,
            cached_regular_bins_snapshot,
        )?;
        maybe_emit_smallbins_record(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_main_arena_candidate.as_ref(),
            printed_regular_bins_block,
            printed_smallbins_block,
            cached_regular_bins_snapshot,
            cached_smallbins_snapshot,
        )?;
        maybe_emit_largebins_record(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_main_arena_candidate.as_ref(),
            printed_regular_bins_block,
            printed_largebins_block,
            cached_regular_bins_snapshot,
            cached_largebins_snapshot,
        )?;
        maybe_emit_unsorted_bin_experiment_record(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_main_arena_candidate.as_ref(),
            printed_unsorted_experiment_block,
        )?;
        maybe_emit_bin_experiment_record(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_main_arena_candidate.as_ref(),
            printed_bin_experiment_block,
        )?;
    }

    if config.show_layout && config.show_chunks {
        if let Some(mapping) = &context.heap_mapping {
            if let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
                context.pid,
                mapping.start,
                mapping.end,
                config.glibc_profile,
            ) {
                let layout_tcache_tracker = if config.show_tcache_candidates {
                    Some(&*tcache_tracker)
                } else {
                    None
                };
                emit_related_trace_record(
                    &mut sink,
                    event_id,
                    json::json_layout_record(
                        event_id,
                        &snapshot,
                        tracker,
                        layout_tcache_tracker,
                        cached_fastbins_snapshot.as_ref(),
                        cached_unsorted_bin_snapshot.as_ref(),
                        cached_smallbins_snapshot.as_ref(),
                        cached_largebins_snapshot.as_ref(),
                        config.glibc_profile,
                        config.max_layout_chunks,
                        config.max_tcache_chain,
                    ),
                )?;
            }
        }
    }

    if config.show_tcache_candidates && config.show_chunks {
        emit_related_trace_record(
            &mut sink,
            event_id,
            json::json_observed_tcache_chains_record(
                event_id,
                tcache_tracker,
                config.max_tcache_chain,
            ),
        )?;
    }

    maybe_emit_allocator_warnings_record(
        &mut sink,
        event_id,
        tracker,
        tcache_tracker,
        cached_fastbins_snapshot.as_ref(),
        cached_unsorted_bin_snapshot.as_ref(),
        cached_smallbins_snapshot.as_ref(),
        cached_largebins_snapshot.as_ref(),
        config,
        previous_allocator_source_summary,
    )?;

    maybe_emit_heap_scan_record(
        &mut sink,
        event_id,
        context,
        tracker,
        tcache_tracker,
        cached_fastbins_snapshot.as_ref(),
        cached_unsorted_bin_snapshot.as_ref(),
        cached_smallbins_snapshot.as_ref(),
        cached_largebins_snapshot.as_ref(),
        config,
        cached_main_arena_candidate.as_ref(),
    )?;

    if config.show_chunks {
        maybe_emit_tcache_struct_records(
            &mut sink,
            event_id,
            context,
            tracker,
            config,
            cached_tcache_struct_candidate,
            printed_tcache_struct_candidate_block,
            tcache_tracker,
        )?;
    }

    Ok(sink.related_records)
}

fn emit_related_trace_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    record: json::JsonTraceRecord,
) -> Result<()> {
    sink.on_update(&LiveTraceUpdate::RelatedRecord { event_id, record })
}

fn maybe_emit_allocator_warnings_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    tracker: &HeapTracker,
    tcache_tracker: &ObservedTcacheTracker,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    config: &RenderConfig,
    previous_allocator_source_summary: &mut Option<AllocatorSourceSummary>,
) -> Result<()> {
    if !allocator_warnings_enabled(config) {
        return Ok(());
    }

    let tcache = config.show_tcache_candidates.then_some(tcache_tracker);
    let warnings = collect_allocator_warnings(
        tracker,
        tcache,
        fastbins,
        unsorted_bin,
        smallbins,
        largebins,
        config.glibc_profile,
        config.max_tcache_chain,
    );
    let summary = collect_allocator_source_summary(
        tcache,
        fastbins,
        unsorted_bin,
        smallbins,
        largebins,
        &warnings,
        config.glibc_profile,
        config.max_tcache_chain,
    );
    emit_related_trace_record(
        sink,
        event_id,
        json::json_allocator_source_summary_record(event_id, &summary),
    )?;
    let delta = diff_allocator_source_summary(previous_allocator_source_summary.as_ref(), &summary);
    emit_related_trace_record(
        sink,
        event_id,
        json::json_allocator_source_delta_record(event_id, &delta),
    )?;
    *previous_allocator_source_summary = Some(summary);
    if warnings.is_empty() {
        return Ok(());
    }

    emit_related_trace_record(
        sink,
        event_id,
        json::json_allocator_warnings_record(event_id, &warnings),
    )
}

fn maybe_emit_heap_scan_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    tcache_tracker: &ObservedTcacheTracker,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
) -> Result<()> {
    let Some(report) = build_heap_scan_report_for_context(
        context,
        tracker,
        tcache_tracker,
        fastbins,
        unsorted_bin,
        smallbins,
        largebins,
        config,
        main_arena_candidate,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_heap_scan_record(event_id, &report),
    )
}

fn maybe_emit_main_arena_candidate_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    config: &RenderConfig,
    cached_candidate: &mut Option<MainArenaCandidate>,
    printed_candidate_block: &mut bool,
) -> Result<()> {
    if !config.show_main_arena_candidate || *printed_candidate_block {
        return Ok(());
    }

    if cached_candidate.is_none() {
        *cached_candidate = heapify_debugger::resolve_main_arena_candidate_with_offset(
            context.pid,
            config.main_arena_offset,
            config.supplied_libc_path.as_deref(),
        )
        .ok()
        .flatten();
    }

    let Some(candidate) = cached_candidate.as_ref() else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_main_arena_candidate_record(event_id, candidate),
    )?;
    *printed_candidate_block = true;
    Ok(())
}

fn maybe_emit_main_arena_experiment_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: &mut bool,
) -> Result<()> {
    if !config.show_arena_experiment || *printed_experiment_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    let Ok(experiment) = heapify_debugger::read_main_arena_experiment(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_main_arena_experiment_record(event_id, &experiment),
    )?;
    *printed_experiment_block = true;
    Ok(())
}

fn maybe_emit_fastbin_experiment_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: &mut bool,
) -> Result<()> {
    if !config.show_fastbin_experiment || *printed_experiment_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    let Ok(experiment) = heapify_debugger::read_fastbin_experiment(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_fastbin_experiment_record(event_id, &experiment),
    )?;
    *printed_experiment_block = true;
    Ok(())
}

fn maybe_emit_fastbins_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_fastbins_block: &mut bool,
    cached_fastbins_snapshot: &mut Option<FastbinsSnapshot>,
) -> Result<()> {
    if !config.show_fastbins || *printed_fastbins_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    let Ok(Some(fastbins)) = heapify_debugger::read_fastbins_snapshot(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_fastbin_chain,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_fastbins_record(event_id, &fastbins),
    )?;
    let validations = validate_fastbins_snapshot(&fastbins);
    if !validations.is_empty() {
        emit_related_trace_record(
            sink,
            event_id,
            json::json_fastbin_validation_record(event_id, &fastbins),
        )?;
    }
    *cached_fastbins_snapshot = Some(fastbins);
    *printed_fastbins_block = true;
    Ok(())
}

fn maybe_emit_unsorted_bin_experiment_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: &mut bool,
) -> Result<()> {
    if !config.show_unsorted_experiment || *printed_experiment_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    let Ok(experiment) = heapify_debugger::read_unsorted_bin_experiment(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_unsorted_bin_experiment_record(event_id, &experiment),
    )?;
    *printed_experiment_block = true;
    Ok(())
}

fn maybe_emit_bin_experiment_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: &mut bool,
) -> Result<()> {
    if !config.show_bin_experiment || *printed_experiment_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    let Ok(experiment) = heapify_debugger::read_bin_experiment(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_bin_experiment_record(event_id, &experiment),
    )?;
    *printed_experiment_block = true;
    Ok(())
}

fn maybe_emit_unsorted_bin_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_unsorted_bin_block: &mut bool,
    cached_unsorted_bin_snapshot: &mut Option<UnsortedBinSnapshot>,
) -> Result<()> {
    if !config.show_unsorted_bin || *printed_unsorted_bin_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    let Ok(Some(unsorted_bin)) = heapify_debugger::read_unsorted_bin_snapshot(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_unsorted_chain,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_unsorted_bin_record(event_id, &unsorted_bin),
    )?;
    if let Some(validation) = validate_unsorted_bin_snapshot(&unsorted_bin) {
        emit_related_trace_record(
            sink,
            event_id,
            json::json_unsorted_bin_validation_record(event_id, &validation),
        )?;
    }
    *cached_unsorted_bin_snapshot = Some(unsorted_bin);
    *printed_unsorted_bin_block = true;
    Ok(())
}

fn maybe_emit_regular_bins_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_regular_bins_block: &mut bool,
    cached_regular_bins_snapshot: &mut Option<RegularBinsSnapshot>,
) -> Result<()> {
    if !config.show_regular_bins || *printed_regular_bins_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    let Ok(Some(regular_bins)) = heapify_debugger::read_regular_bins_snapshot(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_regular_bins,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_regular_bins_record(event_id, &regular_bins),
    )?;
    *cached_regular_bins_snapshot = Some(regular_bins);
    *printed_regular_bins_block = true;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn maybe_emit_smallbins_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_regular_bins_block: &mut bool,
    printed_smallbins_block: &mut bool,
    cached_regular_bins_snapshot: &mut Option<RegularBinsSnapshot>,
    cached_smallbins_snapshot: &mut Option<SmallbinsSnapshot>,
) -> Result<()> {
    if !config.show_smallbins || *printed_smallbins_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    if cached_regular_bins_snapshot.is_none() {
        let Ok(Some(regular_bins)) = heapify_debugger::read_regular_bins_snapshot(
            context.pid,
            candidate.runtime_addr,
            &snapshot,
            tracker,
            config.glibc_profile,
            config.max_regular_bins,
        ) else {
            return Ok(());
        };
        if config.show_regular_bins && !*printed_regular_bins_block {
            emit_related_trace_record(
                sink,
                event_id,
                json::json_regular_bins_record(event_id, &regular_bins),
            )?;
            *printed_regular_bins_block = true;
        }
        *cached_regular_bins_snapshot = Some(regular_bins);
    }
    let Some(regular_bins) = cached_regular_bins_snapshot.as_ref() else {
        return Ok(());
    };
    let Ok(smallbins) = heapify_debugger::read_smallbins_snapshot(
        context.pid,
        candidate.runtime_addr,
        regular_bins,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_smallbin_chain,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_smallbins_record(event_id, &smallbins),
    )?;
    let validations = validate_smallbins_snapshot(&smallbins);
    if !validations.is_empty() {
        emit_related_trace_record(
            sink,
            event_id,
            json::json_smallbin_validation_record(event_id, &smallbins),
        )?;
    }
    *cached_smallbins_snapshot = Some(smallbins);
    *printed_smallbins_block = true;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn maybe_emit_largebins_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_regular_bins_block: &mut bool,
    printed_largebins_block: &mut bool,
    cached_regular_bins_snapshot: &mut Option<RegularBinsSnapshot>,
    cached_largebins_snapshot: &mut Option<LargebinsSnapshot>,
) -> Result<()> {
    if !config.show_largebins || *printed_largebins_block {
        return Ok(());
    }

    let Some(candidate) = main_arena_candidate else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    if cached_regular_bins_snapshot.is_none() {
        let Ok(Some(regular_bins)) = heapify_debugger::read_regular_bins_snapshot(
            context.pid,
            candidate.runtime_addr,
            &snapshot,
            tracker,
            config.glibc_profile,
            config.max_regular_bins,
        ) else {
            return Ok(());
        };
        if config.show_regular_bins && !*printed_regular_bins_block {
            emit_related_trace_record(
                sink,
                event_id,
                json::json_regular_bins_record(event_id, &regular_bins),
            )?;
            *printed_regular_bins_block = true;
        }
        *cached_regular_bins_snapshot = Some(regular_bins);
    }
    let Some(regular_bins) = cached_regular_bins_snapshot.as_ref() else {
        return Ok(());
    };
    let Ok(largebins) = heapify_debugger::read_largebins_snapshot(
        context.pid,
        candidate.runtime_addr,
        regular_bins,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_largebin_chain,
    ) else {
        return Ok(());
    };

    emit_related_trace_record(
        sink,
        event_id,
        json::json_largebins_record(event_id, &largebins),
    )?;
    let validations = validate_largebins_snapshot(&largebins);
    if !validations.is_empty() {
        emit_related_trace_record(
            sink,
            event_id,
            json::json_largebin_validation_record(event_id, &largebins),
        )?;
    }
    *cached_largebins_snapshot = Some(largebins);
    *printed_largebins_block = true;
    Ok(())
}

fn maybe_emit_main_arena_top_candidate_record(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    config: &RenderConfig,
    cached_candidate: &mut Option<MainArenaCandidate>,
    printed_main_arena_candidate_block: &mut bool,
    printed_candidate_block: &mut bool,
) -> Result<()> {
    if !config.show_main_arena_top_candidate || *printed_candidate_block {
        return Ok(());
    }
    let selected_offset = select_main_arena_top_offset(
        config.main_arena_top_offset,
        config.show_main_arena_top_candidate,
        config.glibc_profile,
    );
    let (top_offset, source, profile_name) = match selected_offset {
        SelectedMainArenaTopOffset::User { offset } => {
            (offset, MainArenaFieldSource::UserOffset, None)
        }
        SelectedMainArenaTopOffset::Profile {
            offset,
            profile_name,
        } => (
            offset,
            MainArenaFieldSource::GlibcProfile,
            Some(profile_name),
        ),
        SelectedMainArenaTopOffset::Unavailable => return Ok(()),
    };

    if cached_candidate.is_none() {
        *cached_candidate = heapify_debugger::resolve_main_arena_candidate_with_offset(
            context.pid,
            config.main_arena_offset,
            config.supplied_libc_path.as_deref(),
        )
        .ok()
        .flatten();
    }

    let Some(candidate) = cached_candidate.as_ref() else {
        return Ok(());
    };
    let Some(mapping) = &context.heap_mapping else {
        return Ok(());
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return Ok(());
    };
    let Ok(mut top_candidate) = heapify_debugger::read_main_arena_top_candidate(
        context.pid,
        candidate.runtime_addr,
        top_offset,
        &snapshot,
    ) else {
        return Ok(());
    };
    top_candidate.source = source;
    top_candidate.profile_name = profile_name;

    if is_clean_main_arena_view(&top_candidate) {
        emit_related_trace_record(
            sink,
            event_id,
            json::json_main_arena_view_record(event_id, candidate, Some(&top_candidate)),
        )?;
        *printed_main_arena_candidate_block = true;
    } else {
        emit_related_trace_record(
            sink,
            event_id,
            json::json_main_arena_top_candidate_record(event_id, &top_candidate),
        )?;
    }
    *printed_candidate_block = true;
    Ok(())
}

fn maybe_emit_tcache_struct_records(
    sink: &mut dyn LiveTraceSink,
    event_id: usize,
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    cached_candidate: &mut Option<TcacheStructCandidate>,
    printed_candidate_block: &mut bool,
    tcache_tracker: &ObservedTcacheTracker,
) -> Result<()> {
    if !config.show_tcache_struct_candidate {
        return Ok(());
    }

    if cached_candidate.is_none() {
        let Some(mapping) = &context.heap_mapping else {
            return Ok(());
        };

        let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
            context.pid,
            mapping.start,
            mapping.end,
            config.glibc_profile,
        ) else {
            return Ok(());
        };

        let observed = tracker.observed_user_addr_set();
        *cached_candidate =
            find_tcache_struct_candidate_with_profile(&snapshot, &observed, config.glibc_profile);
    }

    let Some(candidate) = cached_candidate.as_ref() else {
        return Ok(());
    };

    let snapshot = heapify_debugger::read_tcache_snapshot_candidate_with_profile(
        context.pid,
        candidate,
        config.glibc_profile,
    )
    .ok();
    if !*printed_candidate_block {
        emit_related_trace_record(
            sink,
            event_id,
            json::json_tcache_struct_candidate_record(event_id, candidate, snapshot.as_ref()),
        )?;
        *printed_candidate_block = true;
    }

    if config.show_tcache_candidates {
        if let Some(snapshot) = snapshot.as_ref() {
            emit_related_trace_record(
                sink,
                event_id,
                json::json_tcache_comparison_record(
                    event_id,
                    snapshot,
                    tcache_tracker,
                    config.max_tcache_chain,
                ),
            )?;
            emit_related_trace_record(
                sink,
                event_id,
                json::json_tcache_validation_record(
                    event_id,
                    snapshot,
                    tcache_tracker,
                    tracker,
                    context
                        .heap_mapping
                        .as_ref()
                        .map(|mapping| (mapping.start, mapping.end)),
                    config.max_tcache_chain,
                ),
            )?;
        }
    }
    Ok(())
}

fn heap_event_id(event: &HeapTraceEvent) -> usize {
    match event {
        HeapTraceEvent::Malloc { event_id, .. }
        | HeapTraceEvent::Free { event_id, .. }
        | HeapTraceEvent::Calloc { event_id, .. }
        | HeapTraceEvent::Realloc { event_id, .. } => *event_id,
    }
}

fn heap_event_caller_addr(event: &HeapTraceEvent) -> Option<u64> {
    match event {
        HeapTraceEvent::Malloc { caller_addr, .. }
        | HeapTraceEvent::Free { caller_addr, .. }
        | HeapTraceEvent::Calloc { caller_addr, .. }
        | HeapTraceEvent::Realloc { caller_addr, .. } => *caller_addr,
    }
}

fn symbolize_event_caller(
    event: &HeapTraceEvent,
    symbolizer: Option<&ProcessSymbolizer>,
    source_mapper: Option<&TargetSourceMapper>,
) -> Option<SymbolizedAddress> {
    let caller_addr = heap_event_caller_addr(event)?;
    let mut symbol = symbolizer?.symbolize(caller_addr)?;
    if let Some(source_mapper) = source_mapper {
        symbol.source = source_mapper.lookup(caller_addr);
    }
    Some(symbol)
}

fn print_heap_event(
    event: &HeapTraceEvent,
    caller_symbol: Option<&SymbolizedAddress>,
    note: HeapTrackerNote,
    config: &RenderConfig,
) {
    match event {
        HeapTraceEvent::Malloc {
            event_id,
            requested_size,
            returned_ptr,
            chunk,
            caller_addr,
        } => {
            println!("#{event_id} malloc(0x{requested_size:x}) = 0x{returned_ptr:x}");
            if config.show_tracker_notes {
                print_caller_addr(*caller_addr, caller_symbol);
            }
            if config.show_chunks {
                if let Some(chunk) = chunk {
                    print_chunk_header(chunk);
                } else if *returned_ptr != 0 {
                    print_chunk_unavailable();
                }
            }
            if config.show_tracker_notes {
                print_tracker_note(note);
            }
        }
        HeapTraceEvent::Free {
            event_id,
            ptr,
            chunk,
            tcache_entry,
            caller_addr,
        } => {
            println!("#{event_id} free(0x{ptr:x})");
            if config.show_tracker_notes {
                print_caller_addr(*caller_addr, caller_symbol);
            }
            if config.show_chunks {
                if let Some(chunk) = chunk {
                    print_chunk_header(chunk);
                } else if *ptr != 0 {
                    print_chunk_unavailable();
                }
                if let Some(tcache_entry) = tcache_entry {
                    print_tcache_entry_candidate(tcache_entry);
                }
            }
            if config.show_tracker_notes {
                print_tracker_note(note);
            }
        }
        HeapTraceEvent::Calloc {
            event_id,
            nmemb,
            size,
            returned_ptr,
            chunk,
            caller_addr,
        } => {
            println!("#{event_id} calloc(0x{nmemb:x}, 0x{size:x}) = 0x{returned_ptr:x}");
            if config.show_tracker_notes {
                print_caller_addr(*caller_addr, caller_symbol);
            }
            if config.show_chunks {
                if let Some(chunk) = chunk {
                    print_chunk_header(chunk);
                } else if *returned_ptr != 0 {
                    print_chunk_unavailable();
                }
            }
            if config.show_tracker_notes {
                print_tracker_note(note);
            }
        }
        HeapTraceEvent::Realloc {
            event_id,
            old_ptr,
            new_size,
            returned_ptr,
            old_chunk,
            new_chunk,
            caller_addr,
        } => {
            println!("#{event_id} realloc(0x{old_ptr:x}, 0x{new_size:x}) = 0x{returned_ptr:x}");
            if config.show_tracker_notes {
                print_caller_addr(*caller_addr, caller_symbol);
            }
            if config.show_chunks {
                if let Some(old_chunk) = old_chunk {
                    print_old_chunk_header(old_chunk);
                }
                if let Some(new_chunk) = new_chunk {
                    print_new_chunk_header(new_chunk);
                } else if *returned_ptr != 0 {
                    print_new_chunk_unavailable();
                }
            }
            if config.show_tracker_notes {
                print_tracker_note(note);
            }
        }
    }
}

fn print_caller_addr(caller_addr: Option<u64>, caller_symbol: Option<&SymbolizedAddress>) {
    if let Some(caller_symbol) = caller_symbol {
        println!(
            "    caller:     {}",
            format_symbolized_caller(caller_symbol)
        );
        maybe_print_source_location(caller_symbol.source.as_ref());
    } else if let Some(caller_addr) = caller_addr {
        println!("    caller:     0x{caller_addr:x}");
    }
}

fn format_symbolized_caller(caller_symbol: &SymbolizedAddress) -> String {
    let symbol = if let Some(object_name) = caller_symbol.object_name.as_deref() {
        format!("{object_name}!{}", caller_symbol.symbol)
    } else {
        caller_symbol.symbol.clone()
    };
    if caller_symbol.offset == 0 {
        format!("{symbol} (0x{:x})", caller_symbol.addr)
    } else {
        format!(
            "{symbol}+0x{:x} (0x{:x})",
            caller_symbol.offset, caller_symbol.addr
        )
    }
}

fn maybe_print_source_location(source: Option<&SourceLocation>) {
    if let Some(source) = source.and_then(format_printable_source_location) {
        println!("    at          {source}");
    }
}

fn format_printable_source_location(source: &SourceLocation) -> Option<String> {
    format_source_location_parts(source.file.as_deref(), source.line, source.column)
}

fn format_source_location_parts(
    file: Option<&str>,
    line: Option<u32>,
    column: Option<u32>,
) -> Option<String> {
    let file = file?;
    match (line, column) {
        (Some(line), Some(column)) => Some(format!("{file}:{line}:{column}")),
        (Some(line), None) => Some(format!("{file}:{line}")),
        (None, Some(column)) => Some(format!("{file}:?:{column}")),
        (None, None) => Some(file.to_string()),
    }
}

fn print_chunk_header(chunk: &GlibcChunkHeader) {
    println!("    chunk:      0x{:x}", chunk.chunk_addr);
    println!("    user:       0x{:x}", chunk.user_addr);
    println!("    prev_size:  0x{:x}", chunk.prev_size);
    println!("    size_raw:   0x{:x}", chunk.size_raw);
    println!("    size:       0x{:x}", chunk.size);
    println!("    flags:      {}", format_chunk_flags(chunk));
}

fn print_chunk_unavailable() {
    println!("    chunk: unavailable");
}

fn print_tcache_entry_candidate(candidate: &TcacheEntryCandidate) {
    println!("    tcache candidate:");
    println!("        storage:      0x{:x}", candidate.storage_addr);
    println!("        encoded_next: 0x{:x}", candidate.encoded_next);
    println!("        decoded_next: 0x{:x}", candidate.decoded_next);
}

fn print_old_chunk_header(chunk: &GlibcChunkHeader) {
    println!("    old chunk:");
    print_indented_chunk_header(chunk, 8);
}

fn print_new_chunk_header(chunk: &GlibcChunkHeader) {
    println!("    new chunk:");
    print_indented_chunk_header(chunk, 8);
}

fn print_new_chunk_unavailable() {
    println!("    new chunk: unavailable");
}

fn print_indented_chunk_header(chunk: &GlibcChunkHeader, spaces: usize) {
    let indent = " ".repeat(spaces);
    println!("{indent}chunk:      0x{:x}", chunk.chunk_addr);
    println!("{indent}user:       0x{:x}", chunk.user_addr);
    println!("{indent}prev_size:  0x{:x}", chunk.prev_size);
    println!("{indent}size_raw:   0x{:x}", chunk.size_raw);
    println!("{indent}size:       0x{:x}", chunk.size);
    println!("{indent}flags:      {}", format_chunk_flags(chunk));
}

fn format_chunk_flags(chunk: &GlibcChunkHeader) -> String {
    let labels = chunk.flags.labels();
    if labels.is_empty() {
        "none".to_string()
    } else {
        labels.join(" | ")
    }
}

fn print_tracker_note(note: HeapTrackerNote) {
    println!("    {}", format_tracker_note(note));
}

fn print_heap_explanation(explanation: HeapTrackerExplanation) {
    match explanation {
        HeapTrackerExplanation::LikelyTcacheOrFastbinReuse { chunk_size } => {
            println!("    note: chunk size 0x{chunk_size:x} is likely tcache/fastbin-sized");
        }
        HeapTrackerExplanation::NoExtraExplanation => {}
    }
}

fn print_heap_layout(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    tcache_tracker: Option<&ObservedTcacheTracker>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    config: &RenderConfig,
) {
    let Some(mapping) = &context.heap_mapping else {
        println!("heap layout unavailable: heap mapping not found");
        return;
    };

    match heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) {
        Ok(snapshot) => print_heap_snapshot(
            &snapshot,
            tracker,
            tcache_tracker,
            fastbins,
            unsorted_bin,
            smallbins,
            largebins,
            config.glibc_profile,
            config.max_layout_chunks,
            config.max_tcache_chain,
        ),
        Err(err) => println!("heap layout unavailable: {err:#}"),
    }
}

fn print_heap_snapshot(
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
) {
    println!("heap layout:");
    if max_chunks == 0 {
        println!("    0 chunks shown");
    }

    for chunk in snapshot.chunks.iter().take(max_chunks) {
        let allocator_annotation = format_layout_allocator_annotation(
            chunk,
            tcache_tracker,
            fastbins,
            unsorted_bin,
            smallbins,
            largebins,
            profile,
            max_tcache_chain,
        );

        println!(
            "    0x{:x} user=0x{:x} size=0x{:x} flags={} state={}{}",
            chunk.chunk_addr,
            chunk.user_addr,
            chunk.size,
            format_chunk_flags(chunk),
            format_observed_state(tracker.state_for_user_addr(chunk.user_addr)),
            allocator_annotation
        );
    }

    if snapshot.chunks.len() > max_chunks {
        println!(
            "    ... {} more chunks not shown",
            snapshot.chunks.len() - max_chunks
        );
    }

    if snapshot.truncated {
        println!("    ... heap walk truncated");
    }
}

fn format_layout_allocator_annotation(
    chunk: &GlibcChunkHeader,
    tcache_tracker: Option<&ObservedTcacheTracker>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    profile: GlibcProfile,
    max_tcache_chain: usize,
) -> String {
    if let Some(membership) =
        largebins.and_then(|largebins| largebins.membership_for_user_addr(chunk.user_addr, profile))
    {
        return format!(
            " source=largebin[{}] index={}",
            membership
                .chunk_size
                .map(|size| format!("0x{size:x}"))
                .unwrap_or_else(|| "unknown".to_string()),
            membership.node_index
        );
    }

    if let Some(membership) =
        smallbins.and_then(|smallbins| smallbins.membership_for_user_addr(chunk.user_addr, profile))
    {
        return format!(
            " source=smallbin[0x{:x}] index={}",
            membership.chunk_size, membership.node_index
        );
    }

    if let Some(membership) = unsorted_bin
        .and_then(|unsorted_bin| unsorted_bin.membership_for_user_addr(chunk.user_addr, profile))
    {
        return format!(" source=unsorted index={}", membership.node_index);
    }

    if let Some(membership) =
        fastbins.and_then(|fastbins| fastbins.membership_for_user_addr(chunk.user_addr, profile))
    {
        return format!(
            " source=fastbin[0x{:x}] index={}",
            membership.chunk_size, membership.chain_index
        );
    }

    tcache_tracker
        .and_then(|tracker| tracker.membership_for_ptr(chunk.user_addr, max_tcache_chain))
        .map(|membership| {
            format!(
                " tcache_candidate=size[0x{:x}] index={}",
                membership.chunk_size, membership.index
            )
        })
        .unwrap_or_default()
}

fn read_heap_scan_snapshot(
    context: &TraceHeapContext,
    config: &RenderConfig,
) -> Option<GlibcHeapSnapshot> {
    if config.events_only() || !config.show_heap_scan || !config.show_chunks {
        return None;
    }

    let mapping = context.heap_mapping.as_ref()?;
    heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    )
    .ok()
}

fn build_heap_scan_report_for_context(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    tcache_tracker: &ObservedTcacheTracker,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
) -> Option<HeapScanReport> {
    if config.events_only() || !config.show_heap_scan {
        return None;
    }

    let heap_snapshot = read_heap_scan_snapshot(context, config);
    let tcache = config.show_tcache_candidates.then_some(tcache_tracker);
    let warnings = collect_allocator_warnings(
        tracker,
        tcache,
        fastbins,
        unsorted_bin,
        smallbins,
        largebins,
        config.glibc_profile,
        config.max_tcache_chain,
    );
    let summary = collect_allocator_source_summary(
        tcache,
        fastbins,
        unsorted_bin,
        smallbins,
        largebins,
        &warnings,
        config.glibc_profile,
        config.max_tcache_chain,
    );
    let fastbin_validations = fastbins.map(validate_fastbins_snapshot).unwrap_or_default();
    let unsorted_validation = unsorted_bin.and_then(validate_unsorted_bin_snapshot);
    let smallbin_validations = smallbins
        .map(validate_smallbins_snapshot)
        .unwrap_or_default();
    let largebin_validations = largebins
        .map(validate_largebins_snapshot)
        .unwrap_or_default();
    let main_arena_top_validated = heap_snapshot.as_ref().and_then(|snapshot| {
        read_main_arena_top_validated_for_scan(context, config, main_arena_candidate, snapshot)
    });

    Some(build_heap_scan_report(HeapScanInputs {
        heap_snapshot: heap_snapshot.as_ref(),
        heap_tracker: tracker,
        allocator_summary: Some(&summary),
        allocator_warnings: &warnings,
        main_arena_top_validated,
        profile: config.glibc_profile,
        tcache,
        fastbins,
        unsorted: unsorted_bin,
        smallbins,
        largebins,
        max_tcache_chain: config.max_tcache_chain,
        fastbin_validation_statuses: &fastbin_validations,
        unsorted_validation_status: unsorted_validation.as_ref(),
        smallbin_validation_statuses: &smallbin_validations,
        largebin_validation_statuses: &largebin_validations,
    }))
}

fn read_main_arena_top_validated_for_scan(
    context: &TraceHeapContext,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    snapshot: &GlibcHeapSnapshot,
) -> Option<bool> {
    if !config.show_main_arena_top_candidate {
        return None;
    }

    let (SelectedMainArenaTopOffset::User { offset }
    | SelectedMainArenaTopOffset::Profile { offset, .. }) = select_main_arena_top_offset(
        config.main_arena_top_offset,
        config.show_main_arena_top_candidate,
        config.glibc_profile,
    )
    else {
        return None;
    };
    let candidate = main_arena_candidate?;
    let top_candidate = heapify_debugger::read_main_arena_top_candidate(
        context.pid,
        candidate.runtime_addr,
        offset,
        snapshot,
    )
    .ok()?;

    Some(top_candidate.status == heapify_debugger::MainArenaTopStatus::MatchesWalkedChunk)
}

fn maybe_print_heap_scan(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    tcache_tracker: &ObservedTcacheTracker,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
) {
    let Some(report) = build_heap_scan_report_for_context(
        context,
        tracker,
        tcache_tracker,
        fastbins,
        unsorted_bin,
        smallbins,
        largebins,
        config,
        main_arena_candidate,
    ) else {
        return;
    };

    print_heap_scan_report(&report);
}

fn print_heap_scan_report(report: &HeapScanReport) {
    println!("heap scan:");
    println!("    chunks walked:          {}", report.chunks_walked);
    println!("    allocated observed:     {}", report.allocated_observed);
    println!("    freed observed:         {}", report.freed_observed);
    println!("    unknown observed:       {}", report.unknown_observed);
    println!(
        "    allocator sources:      {} chunks",
        report.allocator_source_chunks
    );
    println!("    allocator warnings:     {}", report.warning_count);
    println!("    suspicious findings:    {}", report.suspicious_count);
    println!(
        "    top chunk:              {}",
        format_heap_scan_top_validated(report.top_validated)
    );
    println!(
        "    heap snapshot:          {}",
        format_heap_scan_snapshot_status(report)
    );
    println!(
        "    status:                 {}",
        heap_scan_status_str(report.status)
    );

    if !report.findings.is_empty() {
        println!("heap scan findings:");
        for finding in &report.findings {
            println!(
                "    [{}] {}{}{}: {}",
                heap_scan_finding_severity_str(finding.severity),
                finding.kind,
                finding
                    .chunk_addr
                    .map(|addr| format!(" chunk=0x{addr:x}"))
                    .unwrap_or_default(),
                finding
                    .user_addr
                    .map(|addr| format!(" user=0x{addr:x}"))
                    .unwrap_or_default(),
                finding.message
            );
        }
    }
}

fn format_heap_scan_top_validated(top_validated: Option<bool>) -> &'static str {
    match top_validated {
        Some(true) => "validated",
        Some(false) => "not_validated",
        None => "unknown",
    }
}

fn format_heap_scan_snapshot_status(report: &HeapScanReport) -> &'static str {
    if report
        .findings
        .iter()
        .any(|finding| finding.kind == "heap_snapshot_unavailable")
    {
        "unavailable"
    } else if report.heap_snapshot_truncated {
        "truncated"
    } else {
        "complete"
    }
}

fn maybe_print_allocator_warnings(
    tracker: &HeapTracker,
    tcache_tracker: &ObservedTcacheTracker,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted_bin: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    config: &RenderConfig,
    previous_allocator_source_summary: &mut Option<AllocatorSourceSummary>,
) {
    if !allocator_warnings_enabled(config) {
        return;
    }

    let tcache = config.show_tcache_candidates.then_some(tcache_tracker);
    let warnings = collect_allocator_warnings(
        tracker,
        tcache,
        fastbins,
        unsorted_bin,
        smallbins,
        largebins,
        config.glibc_profile,
        config.max_tcache_chain,
    );
    let summary = collect_allocator_source_summary(
        tcache,
        fastbins,
        unsorted_bin,
        smallbins,
        largebins,
        &warnings,
        config.glibc_profile,
        config.max_tcache_chain,
    );
    print_allocator_source_summary(&summary);
    let delta = diff_allocator_source_summary(previous_allocator_source_summary.as_ref(), &summary);
    print_allocator_source_delta(&delta);
    *previous_allocator_source_summary = Some(summary);
    if warnings.is_empty() {
        return;
    }

    print_allocator_warnings(&warnings);
}

fn allocator_warnings_enabled(config: &RenderConfig) -> bool {
    !config.events_only()
        && (config.show_tcache_candidates
            || config.show_fastbins
            || config.show_unsorted_bin
            || config.show_smallbins
            || config.show_largebins)
}

fn print_allocator_warnings(warnings: &[AllocatorWarning]) {
    println!("allocator warnings:");
    for warning in warnings {
        println!(
            "    [{}] chunk=0x{:x} user=0x{:x} sources={} message={}",
            allocator_warning_kind_str(warning.kind),
            warning.chunk_addr,
            warning.user_addr,
            format_allocator_warning_sources(&warning.sources),
            warning.message
        );
    }
}

fn print_allocator_source_summary(summary: &AllocatorSourceSummary) {
    println!("allocator source summary:");
    println!(
        "    tcache candidates: {} chunks",
        summary.tcache_candidate_chunks
    );
    println!("    fastbins:          {} chunks", summary.fastbin_chunks);
    println!("    unsorted bin:      {} chunks", summary.unsorted_chunks);
    println!("    smallbins:         {} chunks", summary.smallbin_chunks);
    println!("    largebins:         {} chunks", summary.largebin_chunks);
    println!(
        "    total free-list:   {} chunks",
        summary.total_free_list_chunks
    );
    println!("    warnings:          {}", summary.warning_count);
}

fn print_allocator_source_delta(delta: &AllocatorSourceDelta) {
    println!("allocator delta:");
    println!(
        "    tcache candidates: {}",
        format_allocator_source_delta(delta.tcache_candidate_chunks_delta)
    );
    println!(
        "    fastbins:          {}",
        format_allocator_source_delta(delta.fastbin_chunks_delta)
    );
    println!(
        "    unsorted bin:      {}",
        format_allocator_source_delta(delta.unsorted_chunks_delta)
    );
    println!(
        "    smallbins:         {}",
        format_allocator_source_delta(delta.smallbin_chunks_delta)
    );
    println!(
        "    largebins:         {}",
        format_allocator_source_delta(delta.largebin_chunks_delta)
    );
    println!(
        "    total free-list:   {}",
        format_allocator_source_delta(delta.total_free_list_chunks_delta)
    );
    println!(
        "    warnings:          {}",
        format_allocator_source_delta(delta.warning_count_delta)
    );
}

fn format_allocator_source_delta(delta: isize) -> String {
    match delta {
        0 => "unchanged".to_string(),
        delta if delta > 0 => format!("+{delta}"),
        delta => delta.to_string(),
    }
}

fn format_allocator_warning_sources(sources: &[AllocatorSourceMembership]) -> String {
    sources
        .iter()
        .map(format_allocator_source_membership)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_allocator_source_membership(source: &AllocatorSourceMembership) -> String {
    let size = source
        .chunk_size
        .map(|size| format!("[0x{size:x}]"))
        .unwrap_or_else(|| "[unknown]".to_string());
    let index = source
        .index
        .map(|index| format!("#{index}"))
        .unwrap_or_default();

    format!(
        "{}{}{}",
        allocator_source_kind_str(source.kind),
        size,
        index
    )
}

fn maybe_print_tcache_struct_candidate(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    cached_candidate: &mut Option<TcacheStructCandidate>,
    printed_candidate_block: &mut bool,
    tcache_tracker: &ObservedTcacheTracker,
) {
    if !config.show_tcache_struct_candidate || !config.show_chunks || config.events_only() {
        return;
    }

    if cached_candidate.is_none() {
        let Some(mapping) = &context.heap_mapping else {
            return;
        };

        let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
            context.pid,
            mapping.start,
            mapping.end,
            config.glibc_profile,
        ) else {
            return;
        };

        let observed = tracker.observed_user_addr_set();
        *cached_candidate =
            find_tcache_struct_candidate_with_profile(&snapshot, &observed, config.glibc_profile);
    }

    let Some(candidate) = cached_candidate.as_ref() else {
        return;
    };

    if !*printed_candidate_block {
        print_tcache_struct_candidate(candidate);
        *printed_candidate_block = true;
    }
    let snapshot = print_tcache_snapshot_candidate(context, candidate, config.glibc_profile);
    if config.show_tcache_candidates {
        if let Some(snapshot) = snapshot {
            print_tcache_comparison_candidate(&snapshot, tcache_tracker, config.max_tcache_chain);
            print_tcache_validation_candidate(
                &snapshot,
                tcache_tracker,
                tracker,
                context
                    .heap_mapping
                    .as_ref()
                    .map(|mapping| (mapping.start, mapping.end)),
                config.max_tcache_chain,
            );
        }
    }
}

fn print_tcache_struct_candidate(candidate: &TcacheStructCandidate) {
    println!("tcache struct candidate:");
    println!("    chunk:  0x{:x}", candidate.chunk_addr);
    println!("    user:   0x{:x}", candidate.user_addr);
    println!("    size:   0x{:x}", candidate.size);
    println!("    reason: {}", candidate.reason);
}

fn maybe_print_main_arena_candidate(
    context: &TraceHeapContext,
    config: &RenderConfig,
    cached_candidate: &mut Option<MainArenaCandidate>,
    printed_candidate_block: &mut bool,
) {
    if !config.show_main_arena_candidate || config.events_only() || *printed_candidate_block {
        return;
    }

    if cached_candidate.is_none() {
        *cached_candidate = heapify_debugger::resolve_main_arena_candidate_with_offset(
            context.pid,
            config.main_arena_offset,
            config.supplied_libc_path.as_deref(),
        )
        .ok()
        .flatten();
    }

    let Some(candidate) = cached_candidate.as_ref() else {
        return;
    };

    print_main_arena_candidate(candidate);
    *printed_candidate_block = true;
}

fn maybe_print_unavailable_main_arena_candidate(
    config: &RenderConfig,
    json_enabled: bool,
    candidate: Option<&MainArenaCandidate>,
    printed_candidate_block: bool,
) {
    if !config.show_main_arena_candidate
        || config.events_only()
        || json_enabled
        || candidate.is_some()
        || printed_candidate_block
    {
        return;
    }

    println!("main_arena candidate: unavailable");
    println!("    reason: symbol main_arena not found in loaded libc");
}

fn maybe_print_main_arena_experiment(
    context: &TraceHeapContext,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: &mut bool,
) {
    if !config.show_arena_experiment || config.events_only() || *printed_experiment_block {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    let Ok(experiment) = heapify_debugger::read_main_arena_experiment(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
    ) else {
        return;
    };

    print_main_arena_experiment(&experiment);
    *printed_experiment_block = true;
}

fn maybe_print_unavailable_main_arena_experiment(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: bool,
) {
    if !config.show_arena_experiment
        || config.events_only()
        || json_enabled
        || printed_experiment_block
    {
        return;
    }

    println!("main_arena experiment: unavailable");
    if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_fastbin_experiment(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: &mut bool,
) {
    if !config.show_fastbin_experiment
        || config.events_only()
        || !config.show_chunks
        || *printed_experiment_block
    {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    let Ok(experiment) = heapify_debugger::read_fastbin_experiment(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
    ) else {
        return;
    };

    print_fastbin_experiment(&experiment);
    *printed_experiment_block = true;
}

fn maybe_print_fastbins(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_fastbins_block: &mut bool,
    cached_fastbins_snapshot: &mut Option<FastbinsSnapshot>,
) {
    if !config.show_fastbins
        || config.events_only()
        || !config.show_chunks
        || *printed_fastbins_block
    {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    let Ok(Some(fastbins)) = heapify_debugger::read_fastbins_snapshot(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_fastbin_chain,
    ) else {
        return;
    };

    print_fastbins(&fastbins);
    let validations = validate_fastbins_snapshot(&fastbins);
    if !validations.is_empty() {
        print_fastbin_validation(&validations);
    }
    *cached_fastbins_snapshot = Some(fastbins);
    *printed_fastbins_block = true;
}

fn maybe_print_unsorted_bin_experiment(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: &mut bool,
) {
    if !config.show_unsorted_experiment
        || config.events_only()
        || !config.show_chunks
        || *printed_experiment_block
    {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    let Ok(experiment) = heapify_debugger::read_unsorted_bin_experiment(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
    ) else {
        return;
    };

    print_unsorted_bin_experiment(&experiment);
    *printed_experiment_block = true;
}

fn maybe_print_bin_experiment(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: &mut bool,
) {
    if !config.show_bin_experiment
        || config.events_only()
        || !config.show_chunks
        || *printed_experiment_block
    {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    let Ok(experiment) = heapify_debugger::read_bin_experiment(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
    ) else {
        return;
    };

    print_bin_experiment(&experiment);
    *printed_experiment_block = true;
}

fn maybe_print_unsorted_bin(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_unsorted_bin_block: &mut bool,
    cached_unsorted_bin_snapshot: &mut Option<UnsortedBinSnapshot>,
) {
    if !config.show_unsorted_bin
        || config.events_only()
        || !config.show_chunks
        || *printed_unsorted_bin_block
    {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    let Ok(Some(unsorted_bin)) = heapify_debugger::read_unsorted_bin_snapshot(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_unsorted_chain,
    ) else {
        return;
    };

    print_unsorted_bin(&unsorted_bin);
    if let Some(validation) = validate_unsorted_bin_snapshot(&unsorted_bin) {
        print_unsorted_bin_validation(&validation);
    }
    *cached_unsorted_bin_snapshot = Some(unsorted_bin);
    *printed_unsorted_bin_block = true;
}

fn maybe_print_regular_bins(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_regular_bins_block: &mut bool,
    cached_regular_bins_snapshot: &mut Option<RegularBinsSnapshot>,
) {
    if !config.show_regular_bins
        || config.events_only()
        || !config.show_chunks
        || *printed_regular_bins_block
    {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    let Ok(Some(regular_bins)) = heapify_debugger::read_regular_bins_snapshot(
        context.pid,
        candidate.runtime_addr,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_regular_bins,
    ) else {
        return;
    };

    print_regular_bins(&regular_bins);
    *cached_regular_bins_snapshot = Some(regular_bins);
    *printed_regular_bins_block = true;
}

#[allow(clippy::too_many_arguments)]
fn maybe_print_smallbins(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_regular_bins_block: &mut bool,
    printed_smallbins_block: &mut bool,
    cached_regular_bins_snapshot: &mut Option<RegularBinsSnapshot>,
    cached_smallbins_snapshot: &mut Option<SmallbinsSnapshot>,
) {
    if !config.show_smallbins
        || config.events_only()
        || !config.show_chunks
        || *printed_smallbins_block
    {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    if cached_regular_bins_snapshot.is_none() {
        let Ok(Some(regular_bins)) = heapify_debugger::read_regular_bins_snapshot(
            context.pid,
            candidate.runtime_addr,
            &snapshot,
            tracker,
            config.glibc_profile,
            config.max_regular_bins,
        ) else {
            return;
        };
        if config.show_regular_bins && !*printed_regular_bins_block {
            print_regular_bins(&regular_bins);
            *printed_regular_bins_block = true;
        }
        *cached_regular_bins_snapshot = Some(regular_bins);
    }
    let Some(regular_bins) = cached_regular_bins_snapshot.as_ref() else {
        return;
    };
    let Ok(smallbins) = heapify_debugger::read_smallbins_snapshot(
        context.pid,
        candidate.runtime_addr,
        regular_bins,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_smallbin_chain,
    ) else {
        return;
    };

    print_smallbins(&smallbins);
    let validations = validate_smallbins_snapshot(&smallbins);
    if !validations.is_empty() {
        print_smallbin_validation(&validations);
    }
    *cached_smallbins_snapshot = Some(smallbins);
    *printed_smallbins_block = true;
}

#[allow(clippy::too_many_arguments)]
fn maybe_print_largebins(
    context: &TraceHeapContext,
    tracker: &HeapTracker,
    config: &RenderConfig,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_regular_bins_block: &mut bool,
    printed_largebins_block: &mut bool,
    cached_regular_bins_snapshot: &mut Option<RegularBinsSnapshot>,
    cached_largebins_snapshot: &mut Option<LargebinsSnapshot>,
) {
    if !config.show_largebins
        || config.events_only()
        || !config.show_chunks
        || *printed_largebins_block
    {
        return;
    }

    let Some(candidate) = main_arena_candidate else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    if cached_regular_bins_snapshot.is_none() {
        let Ok(Some(regular_bins)) = heapify_debugger::read_regular_bins_snapshot(
            context.pid,
            candidate.runtime_addr,
            &snapshot,
            tracker,
            config.glibc_profile,
            config.max_regular_bins,
        ) else {
            return;
        };
        if config.show_regular_bins && !*printed_regular_bins_block {
            print_regular_bins(&regular_bins);
            *printed_regular_bins_block = true;
        }
        *cached_regular_bins_snapshot = Some(regular_bins);
    }
    let Some(regular_bins) = cached_regular_bins_snapshot.as_ref() else {
        return;
    };
    let Ok(largebins) = heapify_debugger::read_largebins_snapshot(
        context.pid,
        candidate.runtime_addr,
        regular_bins,
        &snapshot,
        tracker,
        config.glibc_profile,
        config.max_largebin_chain,
    ) else {
        return;
    };

    print_largebins(&largebins);
    let validations = validate_largebins_snapshot(&largebins);
    if !validations.is_empty() {
        print_largebin_validation(&validations);
    }
    *cached_largebins_snapshot = Some(largebins);
    *printed_largebins_block = true;
}

fn maybe_print_unavailable_fastbin_experiment(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: bool,
) {
    if !config.show_fastbin_experiment
        || config.events_only()
        || !config.show_chunks
        || json_enabled
        || printed_experiment_block
    {
        return;
    }

    println!("fastbin experiment: unavailable");
    if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_unavailable_unsorted_bin_experiment(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: bool,
) {
    if !config.show_unsorted_experiment
        || config.events_only()
        || !config.show_chunks
        || json_enabled
        || printed_experiment_block
    {
        return;
    }

    println!("unsorted bin experiment: unavailable");
    if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_unavailable_bin_experiment(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_experiment_block: bool,
) {
    if !config.show_bin_experiment
        || config.events_only()
        || !config.show_chunks
        || json_enabled
        || printed_experiment_block
    {
        return;
    }

    println!("bin experiment: unavailable");
    if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_unavailable_unsorted_bin(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_unsorted_bin_block: bool,
) {
    if !config.show_unsorted_bin
        || config.events_only()
        || !config.show_chunks
        || json_enabled
        || printed_unsorted_bin_block
    {
        return;
    }

    println!("unsorted bin: unavailable");
    if config
        .glibc_profile
        .main_arena_unsorted_bin_offset
        .is_none()
    {
        println!("    reason: active glibc profile does not define unsorted bin offset");
    } else if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_unavailable_fastbins(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_fastbins_block: bool,
) {
    if !config.show_fastbins
        || config.events_only()
        || !config.show_chunks
        || json_enabled
        || printed_fastbins_block
    {
        return;
    }

    println!("fastbins: unavailable");
    if config.glibc_profile.main_arena_fastbins_offset.is_none()
        || config.glibc_profile.main_arena_fastbin_count.is_none()
    {
        println!("    reason: active glibc profile does not define fastbin offsets");
    } else if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_unavailable_regular_bins(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_regular_bins_block: bool,
) {
    if !config.show_regular_bins
        || config.events_only()
        || !config.show_chunks
        || json_enabled
        || printed_regular_bins_block
    {
        return;
    }

    println!("regular bins: unavailable");
    if config.glibc_profile.main_arena_bins_offset.is_none()
        || config.glibc_profile.main_arena_bin_count.is_none()
    {
        println!("    reason: active glibc profile does not define regular bin metadata");
    } else if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_unavailable_smallbins(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_smallbins_block: bool,
) {
    if !config.show_smallbins
        || config.events_only()
        || !config.show_chunks
        || json_enabled
        || printed_smallbins_block
    {
        return;
    }

    println!("smallbins: unavailable");
    if config.glibc_profile.main_arena_bins_offset.is_none()
        || config.glibc_profile.main_arena_bin_count.is_none()
    {
        println!("    reason: active glibc profile does not define regular bin metadata");
    } else if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_unavailable_largebins(
    config: &RenderConfig,
    json_enabled: bool,
    main_arena_candidate: Option<&MainArenaCandidate>,
    printed_largebins_block: bool,
) {
    if !config.show_largebins
        || config.events_only()
        || !config.show_chunks
        || json_enabled
        || printed_largebins_block
    {
        return;
    }

    println!("largebins: unavailable");
    if config.glibc_profile.main_arena_bins_offset.is_none()
        || config.glibc_profile.main_arena_bin_count.is_none()
    {
        println!("    reason: active glibc profile does not define regular bin metadata");
    } else if main_arena_candidate.is_none() {
        println!("    reason: main_arena candidate unavailable");
    } else {
        println!("    reason: heap snapshot unavailable");
    }
}

fn maybe_print_unavailable_main_arena_top_candidate(
    config: &RenderConfig,
    json_enabled: bool,
    printed_candidate_block: bool,
) {
    if !config.show_main_arena_top_candidate
        || config.events_only()
        || json_enabled
        || printed_candidate_block
    {
        return;
    }

    if matches!(
        select_main_arena_top_offset(
            config.main_arena_top_offset,
            config.show_main_arena_top_candidate,
            config.glibc_profile,
        ),
        SelectedMainArenaTopOffset::Unavailable
    ) {
        print_unavailable_main_arena_top_candidate(
            "active glibc profile does not define main_arena top offset",
        );
    }
}

fn maybe_print_main_arena_top_candidate(
    context: &TraceHeapContext,
    config: &RenderConfig,
    cached_candidate: &mut Option<MainArenaCandidate>,
    printed_main_arena_candidate_block: &mut bool,
    printed_candidate_block: &mut bool,
) {
    if !config.show_main_arena_top_candidate || config.events_only() || *printed_candidate_block {
        return;
    }
    let selected_offset = select_main_arena_top_offset(
        config.main_arena_top_offset,
        config.show_main_arena_top_candidate,
        config.glibc_profile,
    );
    let (top_offset, source, profile_name) = match selected_offset {
        SelectedMainArenaTopOffset::User { offset } => {
            (offset, MainArenaFieldSource::UserOffset, None)
        }
        SelectedMainArenaTopOffset::Profile {
            offset,
            profile_name,
        } => (
            offset,
            MainArenaFieldSource::GlibcProfile,
            Some(profile_name),
        ),
        SelectedMainArenaTopOffset::Unavailable => {
            print_unavailable_main_arena_top_candidate(
                "active glibc profile does not define main_arena top offset",
            );
            *printed_candidate_block = true;
            return;
        }
    };

    if cached_candidate.is_none() {
        *cached_candidate = heapify_debugger::resolve_main_arena_candidate_with_offset(
            context.pid,
            config.main_arena_offset,
            config.supplied_libc_path.as_deref(),
        )
        .ok()
        .flatten();
    }

    let Some(candidate) = cached_candidate.as_ref() else {
        return;
    };
    let Some(mapping) = &context.heap_mapping else {
        return;
    };
    let Ok(snapshot) = heapify_debugger::read_glibc_heap_snapshot_with_profile(
        context.pid,
        mapping.start,
        mapping.end,
        config.glibc_profile,
    ) else {
        return;
    };
    let Ok(mut top_candidate) = heapify_debugger::read_main_arena_top_candidate(
        context.pid,
        candidate.runtime_addr,
        top_offset,
        &snapshot,
    ) else {
        return;
    };
    top_candidate.source = source;
    top_candidate.profile_name = profile_name;

    if is_clean_main_arena_view(&top_candidate) {
        print_main_arena_view(candidate, Some(&top_candidate));
        *printed_main_arena_candidate_block = true;
    } else {
        if !*printed_main_arena_candidate_block {
            print_main_arena_candidate(candidate);
            *printed_main_arena_candidate_block = true;
        }
        print_main_arena_top_candidate(&top_candidate);
    }
    *printed_candidate_block = true;
}

fn print_main_arena_candidate(candidate: &MainArenaCandidate) {
    println!("main_arena candidate:");
    println!("    libc:   {}", candidate.libc_path);
    println!("    symbol: {}", candidate.symbol_name);
    println!("    addr:   0x{:x}", candidate.runtime_addr);
    println!("    source: {}", format_main_arena_source(candidate.source));
    if let Some(offset) = candidate.offset {
        println!("    offset: 0x{offset:x}");
    }
}

fn is_clean_main_arena_view(candidate: &heapify_debugger::MainArenaTopCandidate) -> bool {
    candidate.source == MainArenaFieldSource::GlibcProfile
        && candidate.status == heapify_debugger::MainArenaTopStatus::MatchesWalkedChunk
}

fn print_main_arena_view(
    arena: &MainArenaCandidate,
    top: Option<&heapify_debugger::MainArenaTopCandidate>,
) {
    println!("main_arena:");
    println!("    addr:        0x{:x}", arena.runtime_addr);
    println!(
        "    source:      {}",
        format_main_arena_source(arena.source)
    );
    if let Some(offset) = arena.offset {
        println!("    offset:      0x{offset:x}");
    }
    if let Some(top) = top {
        println!();
        println!("    top:");
        println!("        field:   0x{:x}", top.field_offset);
        println!("        value:   0x{:x}", top.top_addr);
        println!(
            "        size:    {}",
            top.chunk_size
                .map(|size| format!("0x{size:x}"))
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!(
            "        source:  {}",
            format_main_arena_field_source(top.source)
        );
        if let Some(profile_name) = &top.profile_name {
            println!("        profile: {profile_name}");
        }
        println!(
            "        status:  {}",
            format_main_arena_view_status(main_arena_view_status_from_top_status(top.status))
        );
    }
}

fn print_main_arena_top_candidate(candidate: &heapify_debugger::MainArenaTopCandidate) {
    println!("main_arena top candidate:");
    println!("    arena:       0x{:x}", candidate.arena_addr);
    println!("    field:       0x{:x}", candidate.field_offset);
    println!("    top:         0x{:x}", candidate.top_addr);
    println!(
        "    source:      {}",
        format_main_arena_field_source(candidate.source)
    );
    if let Some(profile_name) = &candidate.profile_name {
        println!("    profile:     {profile_name}");
    }
    println!(
        "    chunk size:  {}",
        candidate
            .chunk_size
            .map(|size| format!("0x{size:x}"))
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "    status:      {}",
        format_main_arena_top_status(candidate.status)
    );
}

fn format_main_arena_view_status(status: MainArenaViewStatus) -> &'static str {
    match status {
        MainArenaViewStatus::Validated => "validated",
        MainArenaViewStatus::PointsIntoHeap => "points_into_heap",
        MainArenaViewStatus::OutsideHeap => "outside_heap",
        MainArenaViewStatus::Unavailable => "unavailable",
    }
}

fn print_unavailable_main_arena_top_candidate(reason: &str) {
    println!("main_arena top candidate: unavailable");
    println!("    reason: {reason}");
}

fn print_main_arena_experiment(experiment: &heapify_debugger::MainArenaExperiment) {
    println!("main_arena experiment:");
    println!("    arena: 0x{:x}", experiment.arena_addr);
    if experiment.candidates.is_empty() {
        println!("    heap pointer candidates: none");
        return;
    }

    println!("    heap pointer candidates:");
    for candidate in &experiment.candidates {
        println!(
            "        offset=0x{:x} value=0x{:x} role={} matched_chunk_size={}",
            candidate.field_offset,
            candidate.value,
            format_main_arena_role_hint(&candidate.role_hint),
            candidate
                .matched_chunk_size
                .map(|size| format!("0x{size:x}"))
                .unwrap_or_else(|| "none".to_string())
        );
    }
}

fn print_fastbin_experiment(experiment: &FastbinExperiment) {
    println!("fastbin experiment:");
    println!("    arena: 0x{:x}", experiment.arena_addr);
    if experiment.candidates.is_empty() {
        println!("    candidates: none");
        return;
    }

    println!("    candidates:");
    for candidate in &experiment.candidates {
        println!(
            "        offset=0x{:x} value=0x{:x} chunk_size={} known_freed={}",
            candidate.field_offset,
            candidate.value,
            candidate
                .possible_chunk_size
                .map(|size| format!("0x{size:x}"))
                .unwrap_or_else(|| "unknown".to_string()),
            format_fastbin_known_freed(candidate.known_freed)
        );
    }
}

fn print_unsorted_bin_experiment(experiment: &UnsortedBinExperiment) {
    println!("unsorted bin experiment:");
    println!("    arena: 0x{:x}", experiment.arena_addr);
    if experiment.candidates.is_empty() {
        println!("    candidates: none");
        return;
    }

    println!("    candidates:");
    for candidate in &experiment.candidates {
        println!(
            "        offset=0x{:x} fd=0x{:x} fd_in_heap={} fd_known_freed={} bk=0x{:x} bk_in_heap={} bk_known_freed={} role={}",
            candidate.field_offset,
            candidate.fd,
            format_yes_no(candidate.fd_points_into_heap),
            format_fastbin_known_freed(candidate.fd_known_freed),
            candidate.bk,
            format_yes_no(candidate.bk_points_into_heap),
            format_fastbin_known_freed(candidate.bk_known_freed),
            json::json_unsorted_experiment_role(candidate.role)
        );
    }
}

fn print_bin_experiment(experiment: &BinExperiment) {
    println!("bin experiment:");
    println!("    arena: 0x{:x}", experiment.arena_addr);
    if experiment.candidates.is_empty() {
        println!("    candidates: none");
        return;
    }

    println!("    candidates:");
    for candidate in &experiment.candidates {
        println!(
            "        offset=0x{:x} fd=0x{:x} fd_in_heap={} fd_in_arena={} fd_known_freed={} bk=0x{:x} bk_in_heap={} bk_in_arena={} bk_known_freed={} role={}",
            candidate.field_offset,
            candidate.fd,
            format_yes_no(candidate.fd_points_into_heap),
            format_yes_no(candidate.fd_points_into_arena),
            format_fastbin_known_freed(candidate.fd_known_freed),
            candidate.bk,
            format_yes_no(candidate.bk_points_into_heap),
            format_yes_no(candidate.bk_points_into_arena),
            format_fastbin_known_freed(candidate.bk_known_freed),
            json::json_bin_experiment_role(candidate.role)
        );
    }
}

fn print_unsorted_bin(snapshot: &UnsortedBinSnapshot) {
    println!("unsorted bin:");
    println!("    arena: 0x{:x}", snapshot.arena_addr);
    println!("    offset: 0x{:x}", snapshot.field_offset);
    println!("    fd: 0x{:x}", snapshot.fd);
    println!("    bk: 0x{:x}", snapshot.bk);
    println!(
        "    fd_in_heap: {}",
        format_yes_no(snapshot.fd_points_into_heap)
    );
    println!(
        "    bk_in_heap: {}",
        format_yes_no(snapshot.bk_points_into_heap)
    );
    println!(
        "    fd_known_freed: {}",
        format_fastbin_known_freed(snapshot.fd_known_freed)
    );
    println!(
        "    bk_known_freed: {}",
        format_fastbin_known_freed(snapshot.bk_known_freed)
    );
    if let Some(chain) = &snapshot.chain {
        if chain.empty {
            println!("    chain: empty");
        } else {
            println!("    chain:");
            for node in &chain.nodes {
                println!(
                    "        0x{:x} size={} fd=0x{:x} bk=0x{:x} known_freed={}",
                    node.chunk_addr,
                    node.chunk_size
                        .map(|size| format!("0x{size:x}"))
                        .unwrap_or_else(|| "unknown".to_string()),
                    node.fd,
                    node.bk,
                    format_fastbin_known_freed(node.known_freed)
                );
            }
        }
    }
}

fn print_unsorted_bin_validation(validation: &UnsortedBinValidation) {
    println!("unsorted bin validation:");
    println!(
        "    head_in_heap: {}",
        format_unsorted_bin_validation_value(validation.head_in_heap)
    );
    println!(
        "    fd_bk_consistent: {}",
        format_unsorted_bin_validation_value(validation.fd_bk_consistent)
    );
    println!(
        "    nodes_known_freed: {}",
        format_unsorted_bin_validation_value(validation.nodes_known_freed)
    );
    println!(
        "    chain_complete: {}",
        format_unsorted_bin_validation_value(validation.chain_complete)
    );
    println!(
        "    status: {}",
        format_unsorted_bin_validation_status(validation.status)
    );
}

fn format_unsorted_bin_validation_value(value: UnsortedBinValidationValue) -> &'static str {
    match value {
        UnsortedBinValidationValue::Yes => "yes",
        UnsortedBinValidationValue::No => "no",
        UnsortedBinValidationValue::Unknown => "unknown",
    }
}

fn format_unsorted_bin_validation_status(status: UnsortedBinValidationStatus) -> &'static str {
    match status {
        UnsortedBinValidationStatus::Plausible => "plausible",
        UnsortedBinValidationStatus::Incomplete => "incomplete",
        UnsortedBinValidationStatus::Suspicious => "suspicious",
    }
}

fn print_fastbins(snapshot: &FastbinsSnapshot) {
    println!("fastbins:");
    println!("    arena: 0x{:x}", snapshot.arena_addr);
    for head in &snapshot.heads {
        if head.head == 0 {
            println!(
                "    bin[{}] size=0x{:x} head=0x0",
                head.index, head.chunk_size
            );
        } else {
            println!(
                "    bin[{}] size=0x{:x} head=0x{:x} in_heap={} known_freed={}",
                head.index,
                head.chunk_size,
                head.head,
                format_yes_no(head.points_into_heap),
                format_fastbin_known_freed(head.known_freed)
            );
            if let Some(chain) = snapshot
                .chains
                .iter()
                .find(|chain| chain.index == head.index)
            {
                println!("        chain: {}", format_fastbin_chain(chain));
            }
        }
    }
}

fn print_regular_bins(snapshot: &RegularBinsSnapshot) {
    println!("regular bins:");
    println!("    arena: 0x{:x}", snapshot.arena_addr);
    println!("    bins_offset: 0x{:x}", snapshot.bins_offset);
    for head in &snapshot.heads {
        let chunk_size = head
            .chunk_size
            .map(|size| format!(" chunk_size=0x{size:x}"))
            .unwrap_or_default();
        println!(
            "    bin[{}] glibc_bin_index={} role={}{} fd=0x{:x} bk=0x{:x} empty={} fd_in_heap={} bk_in_heap={}",
            head.index,
            head.glibc_bin_index,
            regular_bin_role_label(head),
            chunk_size,
            head.fd,
            head.bk,
            format_yes_no(head.empty),
            format_yes_no(head.fd_points_into_heap),
            format_yes_no(head.bk_points_into_heap)
        );
    }
}

fn regular_bin_role_label(head: &RegularBinHead) -> &'static str {
    match head.role {
        heapify_core::glibc::RegularBinRole::Unsorted => "unsorted",
        heapify_core::glibc::RegularBinRole::Smallbin => "smallbin",
        heapify_core::glibc::RegularBinRole::Largebin => "largebin",
    }
}

fn print_smallbins(snapshot: &SmallbinsSnapshot) {
    println!("smallbins:");
    let non_empty = snapshot
        .chains
        .iter()
        .filter(|chain| !chain.empty)
        .collect::<Vec<_>>();
    if non_empty.is_empty() {
        println!("    all smallbins empty");
        return;
    }

    println!("    arena: 0x{:x}", snapshot.arena_addr);
    for chain in non_empty {
        println!(
            "    bin[{}] size=0x{:x}:",
            chain.glibc_bin_index, chain.expected_chunk_size
        );
        println!("        chain:");
        for node in &chain.nodes {
            println!(
                "            0x{:x} size={} fd=0x{:x} bk=0x{:x} known_freed={}",
                node.chunk_addr,
                node.chunk_size
                    .map(|size| format!("0x{size:x}"))
                    .unwrap_or_else(|| "unknown".to_string()),
                node.fd,
                node.bk,
                format_fastbin_known_freed(node.known_freed)
            );
        }
    }
}

fn print_smallbin_validation(validations: &[SmallbinBinValidation]) {
    println!("smallbin validation:");
    for validation in validations {
        println!(
            "    bin[{}] size=0x{:x}:",
            validation.glibc_bin_index, validation.expected_chunk_size
        );
        println!(
            "        head_in_heap: {}",
            format_smallbin_validation_value(validation.head_in_heap)
        );
        println!(
            "        nodes_same_size: {}",
            format_smallbin_validation_value(validation.nodes_same_size)
        );
        println!(
            "        fd_bk_consistent: {}",
            format_smallbin_validation_value(validation.fd_bk_consistent)
        );
        println!(
            "        nodes_known_freed: {}",
            format_smallbin_validation_value(validation.nodes_known_freed)
        );
        println!(
            "        chain_complete: {}",
            format_smallbin_validation_value(validation.chain_complete)
        );
        println!(
            "        status: {}",
            format_smallbin_validation_status(validation.status)
        );
    }
}

fn format_smallbin_validation_value(value: SmallbinValidationValue) -> &'static str {
    match value {
        SmallbinValidationValue::Yes => "yes",
        SmallbinValidationValue::No => "no",
        SmallbinValidationValue::Unknown => "unknown",
    }
}

fn format_smallbin_validation_status(status: SmallbinValidationStatus) -> &'static str {
    match status {
        SmallbinValidationStatus::Plausible => "plausible",
        SmallbinValidationStatus::Incomplete => "incomplete",
        SmallbinValidationStatus::Suspicious => "suspicious",
    }
}

fn print_largebins(snapshot: &LargebinsSnapshot) {
    println!("largebins:");
    let non_empty = snapshot
        .chains
        .iter()
        .filter(|chain| !chain.empty)
        .collect::<Vec<_>>();
    if non_empty.is_empty() {
        println!("    all largebins empty");
        return;
    }

    println!("    arena: 0x{:x}", snapshot.arena_addr);
    for chain in non_empty {
        println!("    bin[{}]:", chain.glibc_bin_index);
        println!("        chain:");
        for node in &chain.nodes {
            println!(
                "            0x{:x} size={} fd=0x{:x} bk=0x{:x} fd_nextsize=0x{:x} bk_nextsize=0x{:x} known_freed={}",
                node.chunk_addr,
                node.chunk_size
                    .map(|size| format!("0x{size:x}"))
                    .unwrap_or_else(|| "unknown".to_string()),
                node.fd,
                node.bk,
                node.fd_nextsize,
                node.bk_nextsize,
                format_fastbin_known_freed(node.known_freed)
            );
        }
    }
}

fn print_largebin_validation(validations: &[LargebinBinValidation]) {
    println!("largebin validation:");
    for validation in validations {
        println!("    bin[{}]:", validation.glibc_bin_index);
        println!(
            "        head_in_heap: {}",
            format_largebin_validation_value(validation.head_in_heap)
        );
        println!(
            "        fd_bk_consistent: {}",
            format_largebin_validation_value(validation.fd_bk_consistent)
        );
        println!(
            "        nodes_known_freed: {}",
            format_largebin_validation_value(validation.nodes_known_freed)
        );
        println!(
            "        chain_complete: {}",
            format_largebin_validation_value(validation.chain_complete)
        );
        println!(
            "        status: {}",
            format_largebin_validation_status(validation.status)
        );
    }
}

fn format_largebin_validation_value(value: LargebinValidationValue) -> &'static str {
    match value {
        LargebinValidationValue::Yes => "yes",
        LargebinValidationValue::No => "no",
        LargebinValidationValue::Unknown => "unknown",
    }
}

fn format_largebin_validation_status(status: LargebinValidationStatus) -> &'static str {
    match status {
        LargebinValidationStatus::Plausible => "plausible",
        LargebinValidationStatus::Incomplete => "incomplete",
        LargebinValidationStatus::Suspicious => "suspicious",
    }
}

fn print_fastbin_validation(validations: &[FastbinBinValidation]) {
    println!("fastbin validation:");
    for validation in validations {
        println!(
            "    bin[{}] size=0x{:x}:",
            validation.index, validation.chunk_size
        );
        println!(
            "        head_in_heap: {}",
            format_fastbin_validation_value(validation.head_in_heap)
        );
        println!(
            "        nodes_same_size: {}",
            format_fastbin_validation_value(validation.nodes_same_size)
        );
        println!(
            "        nodes_known_freed: {}",
            format_fastbin_validation_value(validation.nodes_known_freed)
        );
        println!(
            "        chain_complete: {}",
            format_fastbin_validation_value(validation.chain_complete)
        );
        println!(
            "        status: {}",
            format_fastbin_validation_status(validation.status)
        );
    }
}

fn format_fastbin_chain(chain: &FastbinChain) -> String {
    let entries = chain
        .nodes
        .iter()
        .map(|node| format!("0x{:x}", node.chunk_addr))
        .collect::<Vec<_>>();
    let entry_refs = entries.iter().map(String::as_str).collect::<Vec<_>>();
    format_fastbin_chain_entries(
        &entry_refs,
        chain.truncated,
        chain.stopped_on_unknown_next,
        chain.cycle_detected,
    )
}

fn format_fastbin_validation_value(
    value: heapify_core::glibc::FastbinValidationValue,
) -> &'static str {
    match value {
        heapify_core::glibc::FastbinValidationValue::Yes => "yes",
        heapify_core::glibc::FastbinValidationValue::No => "no",
        heapify_core::glibc::FastbinValidationValue::Unknown => "unknown",
    }
}

fn format_fastbin_validation_status(
    status: heapify_core::glibc::FastbinValidationStatus,
) -> &'static str {
    match status {
        heapify_core::glibc::FastbinValidationStatus::Plausible => "plausible",
        heapify_core::glibc::FastbinValidationStatus::Incomplete => "incomplete",
        heapify_core::glibc::FastbinValidationStatus::Suspicious => "suspicious",
    }
}

fn format_yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_fastbin_known_freed(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn format_main_arena_top_status(status: heapify_debugger::MainArenaTopStatus) -> &'static str {
    match status {
        heapify_debugger::MainArenaTopStatus::MatchesWalkedChunk => {
            "points into heap and matches walked chunk"
        }
        heapify_debugger::MainArenaTopStatus::PointsIntoHeap => {
            "points into heap but does not match walked chunk"
        }
        heapify_debugger::MainArenaTopStatus::OutsideHeap => "outside heap",
        heapify_debugger::MainArenaTopStatus::Unavailable => "unavailable",
    }
}

fn format_main_arena_field_source(source: MainArenaFieldSource) -> &'static str {
    match source {
        MainArenaFieldSource::UserOffset => "user_offset",
        MainArenaFieldSource::GlibcProfile => "glibc_profile",
    }
}

fn format_main_arena_source(source: MainArenaSource) -> &'static str {
    match source {
        MainArenaSource::LibcSymbol => "libc_symbol",
        MainArenaSource::UserOffset => "user_offset",
    }
}

fn format_main_arena_role_hint(role_hint: &heapify_debugger::MainArenaRoleHint) -> &'static str {
    match role_hint {
        heapify_debugger::MainArenaRoleHint::CandidateTop => "candidate_top",
        heapify_debugger::MainArenaRoleHint::HeapPointer => "heap_pointer",
    }
}

fn print_tcache_snapshot_candidate(
    context: &TraceHeapContext,
    candidate: &TcacheStructCandidate,
    profile: GlibcProfile,
) -> Option<TcacheSnapshotCandidate> {
    match heapify_debugger::read_tcache_snapshot_candidate_with_profile(
        context.pid,
        candidate,
        profile,
    ) {
        Ok(snapshot) => {
            print_tcache_snapshot_candidate_bins(&snapshot);
            Some(snapshot)
        }
        Err(err) => {
            println!("tcache snapshot candidate: unavailable: {err:#}");
            None
        }
    }
}

fn print_tcache_snapshot_candidate_bins(snapshot: &TcacheSnapshotCandidate) {
    if snapshot.bins.is_empty() {
        return;
    }

    println!("tcache snapshot candidate:");
    for bin in &snapshot.bins {
        println!(
            "    bin[{}] size=0x{:x} count={} head=0x{:x}",
            bin.index, bin.chunk_size, bin.count, bin.head
        );
    }
}

fn print_tcache_comparison_candidate(
    snapshot: &TcacheSnapshotCandidate,
    tcache_tracker: &ObservedTcacheTracker,
    max_tcache_chain: usize,
) {
    let comparisons =
        compare_tcache_snapshot_with_observed(snapshot, tcache_tracker, max_tcache_chain);
    if comparisons.is_empty() {
        return;
    }

    println!("tcache comparison candidate:");
    for comparison in comparisons {
        println!("    size 0x{:x}:", comparison.chunk_size);
        println!("        struct count: {}", comparison.struct_count);
        println!("        struct head:  0x{:x}", comparison.struct_head);
        println!(
            "        observed:     {}",
            format_tcache_comparison_observed(&comparison)
        );
        println!(
            "        status:       {}",
            format_tcache_comparison_status(comparison.status)
        );
    }
}

fn print_tcache_validation_candidate(
    snapshot: &TcacheSnapshotCandidate,
    tcache_tracker: &ObservedTcacheTracker,
    heap_tracker: &HeapTracker,
    heap_range: Option<(u64, u64)>,
    max_tcache_chain: usize,
) {
    let validations = validate_tcache_snapshot_candidate(
        snapshot,
        tcache_tracker,
        heap_tracker,
        heap_range,
        max_tcache_chain,
    );
    if validations.is_empty() {
        return;
    }

    println!("tcache validation candidate:");
    for validation in validations {
        println!("    size 0x{:x}:", validation.chunk_size);
        println!(
            "        head_in_heap: {}",
            format_tcache_validation_value(validation.head_in_heap)
        );
        println!(
            "        head_known_freed: {}",
            format_tcache_validation_value(validation.head_known_freed)
        );
        println!(
            "        observed_nodes_same_size: {}",
            format_tcache_validation_value(validation.observed_nodes_same_size)
        );
        println!(
            "        count_matches_observed: {}",
            format_tcache_validation_value(validation.count_matches_observed)
        );
        println!(
            "        status: {}",
            format_tcache_validation_status(validation.status)
        );
    }
}

fn format_tcache_comparison_observed(comparison: &TcacheBinComparison) -> String {
    if comparison.observed_entries.is_empty() {
        return "<none>".to_string();
    }

    let mut parts = comparison
        .observed_entries
        .iter()
        .map(|entry| format!("0x{entry:x}"))
        .collect::<Vec<_>>();

    if comparison.observed_truncated {
        parts.push("... truncated".to_string());
    } else if comparison.observed_stopped_on_unknown_next {
        parts.push("?".to_string());
    } else {
        parts.push("NULL".to_string());
    }

    parts.join(" -> ")
}

fn format_tcache_comparison_status(status: TcacheComparisonStatus) -> &'static str {
    match status {
        TcacheComparisonStatus::MatchesObservedHeadAndCount => "matches observed head and count",
        TcacheComparisonStatus::HeadMatchesCountDiffers => "head matches, count differs",
        TcacheComparisonStatus::HeadMatchesObservedChainIncomplete => {
            "head matches, observed chain incomplete"
        }
        TcacheComparisonStatus::HeadDiffers => "struct head differs from observed head",
        TcacheComparisonStatus::MissingObservedChain => "no observed chain for this size",
    }
}

fn format_tcache_validation_value(value: TcacheValidationValue) -> &'static str {
    match value {
        TcacheValidationValue::Yes => "yes",
        TcacheValidationValue::No => "no",
        TcacheValidationValue::Unknown => "unknown",
    }
}

fn format_tcache_validation_status(status: TcacheValidationStatus) -> &'static str {
    match status {
        TcacheValidationStatus::Plausible => "plausible",
        TcacheValidationStatus::Incomplete => "incomplete",
        TcacheValidationStatus::Suspicious => "suspicious",
    }
}

fn print_observed_tcache_chains(tracker: &ObservedTcacheTracker, config: &RenderConfig) {
    let chains = tracker.chains(config.max_tcache_chain);
    if chains.is_empty() {
        return;
    }

    println!("observed tcache candidates:");
    for chain in chains {
        println!("    {}", format_observed_tcache_chain(&chain));
    }
}

fn format_observed_tcache_chain(chain: &ObservedTcacheChain) -> String {
    let mut parts = Vec::new();

    for entry in &chain.entries {
        parts.push(format!("0x{entry:x}"));
    }

    if chain.truncated {
        parts.push("... truncated".to_string());
    } else if chain.stopped_on_unknown_next {
        parts.push("?".to_string());
    } else {
        parts.push("NULL".to_string());
    }

    format!("size 0x{:x}: {}", chain.chunk_size, parts.join(" -> "))
}

fn format_observed_state(state: Option<ObservedChunkState>) -> &'static str {
    match state {
        Some(ObservedChunkState::Allocated) => "allocated",
        Some(ObservedChunkState::Freed) => "freed",
        None => "unknown",
    }
}

fn format_tracker_note(note: HeapTrackerNote) -> &'static str {
    match note {
        HeapTrackerNote::NewAllocation => "state: allocated new chunk",
        HeapTrackerNote::ReusedFreedChunk => "state: reused previously freed chunk",
        HeapTrackerNote::FreedKnownChunk => "state: freed known chunk",
        HeapTrackerNote::DoubleFree => "warning: possible double free",
        HeapTrackerNote::FreeUnknownPointer => "warning: freeing pointer not seen by Heapify",
        HeapTrackerNote::NullMalloc => "state: malloc returned NULL",
        HeapTrackerNote::NullFree => "state: free(NULL)",
        HeapTrackerNote::AllocatedPointerReturnedAgain => {
            "warning: malloc returned pointer already marked allocated"
        }
        HeapTrackerNote::NullCalloc => "state: calloc returned NULL",
        HeapTrackerNote::ReallocNullActsLikeMalloc => "state: realloc(NULL, size) allocated chunk",
        HeapTrackerNote::ReallocInPlace => "state: realloc kept allocation in place",
        HeapTrackerNote::ReallocMovedAllocation => "state: realloc moved allocation",
        HeapTrackerNote::ReallocFailedKeepsOldPointer => {
            "state: realloc failed; old pointer remains allocated"
        }
        HeapTrackerNote::ReallocPtrZeroFreedOldPointer => {
            "state: realloc(ptr, 0) freed old pointer"
        }
        HeapTrackerNote::ReallocUnknownOldPointer => {
            "warning: realloc old pointer not seen by Heapify"
        }
    }
}

fn parse_addr(addr: &str) -> Result<u64> {
    parse_u64_auto_radix(addr).with_context(|| format!("invalid address: {addr}"))
}

fn parse_u64_auto_radix(value: &str) -> Result<u64> {
    if value.is_empty() {
        bail!("empty integer");
    }

    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() {
            bail!("empty hex integer");
        }
        return u64::from_str_radix(hex, 16).context("invalid hex integer");
    }

    value.parse().context("invalid decimal integer")
}

fn usage() {
    eprintln!("Usage:");
    eprintln!("  heapify run <program> [args...]");
    eprintln!("  heapify break <program> <addr> [args...]");
    eprintln!("  heapify break-symbol <program> <symbol> [args...]");
    eprintln!("  heapify trace-heap [options] <program> [args...]");
    eprintln!("  heapify replay [--tui] [--events-only] [--no-chunks] <trace_file>");
    eprintln!();
    eprintln!("Common trace-heap options:");
    eprintln!("  --allocator-views none|basic|full   Enable grouped heap/allocator views");
    eprintln!("  --live-tui                          Inspect the trace while the target runs");
    eprintln!("  --glibc-profile auto|NAME           Select glibc metadata assumptions");
    eprintln!("  --json-out PATH                     Write replayable NDJSON trace to a file");
    eprintln!("  --events-only                       Print only allocator event lines");
    eprintln!("  --no-chunks                         Hide per-event chunk header details");
    eprintln!("  --break-on suspicious|double-free   Pause live TUI on allocator diagnostics");
    eprintln!("  --break-on-free PTR                 Pause live TUI when free(PTR) is observed");
    eprintln!("  --break-on-alloc-size SIZE          Pause live TUI on allocation request size");
    eprintln!();
    eprintln!("Launch scripting options:");
    eprintln!("  --stdin-file PATH                   Feed target stdin from a file");
    eprintln!("  --stdin-text TEXT                   Feed target stdin from a literal string");
    eprintln!("  --cwd PATH                          Run target from PATH");
    eprintln!("  --set-env KEY=VALUE                 Set a target environment variable");
    eprintln!("  --unset-env KEY                     Remove a target environment variable");
    eprintln!("  --clear-env                         Start target with an empty environment");
    eprintln!("  --ld PATH                           Run target through a custom dynamic loader");
    eprintln!("  --library-path PATH                 Library search path for the custom loader");
    eprintln!("  --preload PATH                      Set LD_PRELOAD for the target");
    eprintln!(
        "  --libc PATH                         Use libc ELF metadata for symbols/profile hints"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        format_allocator_source_delta, format_available_glibc_profiles,
        format_fastbin_chain_entries, format_observed_tcache_chain, format_replay_event_summary,
        format_replay_record, format_replay_regular_bins, format_symbolized_caller,
        format_timeline_allocator_counts, format_timeline_event_summary, is_clean_main_arena_view,
        json_launch_metadata, parse_env_assignment, parse_replay_args, parse_trace_heap_args,
        parse_u64_auto_radix, replay_trace_file, resolve_allocator_views_preset,
        resolve_glibc_profile, resolve_trace_mode, select_main_arena_top_offset,
        AllocatorViewsPreset, AllocatorViewsPresetArg, LiveTraceSink, ReplayConfig,
        ReplayEventAllocatorState, ReplaySession, SelectedMainArenaTopOffset, TraceModeArg,
    };
    use heapify_core::glibc::{
        MainArenaFieldSource, MainArenaTopStatus, GLIBC_2_35_X86_64, GLIBC_X86_64_MODERN,
    };
    use heapify_core::tcache::ObservedTcacheChain;
    use heapify_debugger::{
        AllocationTraceMode, ProcessMapEntry, ProcessMapsSnapshot, RegisterArch, RegisterRole,
        RegisterSnapshot, RegisterValue, SourceLocation, StackSnapshot, StackWord, StdinConfig,
        SymbolizedAddress,
    };
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    #[test]
    fn default_trace_config_preserves_verbose_output() {
        let (config, program, target_args) =
            parse_trace_heap_args(vec!["./target".into(), "arg".into()]).unwrap();

        assert_eq!(program, "./target");
        assert_eq!(target_args, vec!["arg"]);
        assert!(config.show_chunks);
        assert!(config.show_tracker_notes);
        assert!(config.show_explanations);
        assert!(!config.show_layout);
        assert_eq!(config.max_layout_chunks, 32);
        assert!(!config.show_tcache_candidates);
        assert_eq!(config.max_tcache_chain, 32);
        assert_eq!(config.max_fastbin_chain, 32);
        assert_eq!(config.max_unsorted_chain, 32);
        assert!(!config.show_tcache_struct_candidate);
        assert!(!config.show_main_arena_candidate);
        assert_eq!(config.main_arena_offset, None);
        assert!(!config.show_arena_experiment);
        assert!(!config.show_fastbin_experiment);
        assert!(!config.show_unsorted_experiment);
        assert!(!config.show_bin_experiment);
        assert!(!config.show_unsorted_bin);
        assert!(!config.show_fastbins);
        assert!(!config.show_heap_scan);
        assert_eq!(config.main_arena_top_offset, None);
        assert_eq!(config.trace_mode, None);
        assert!(!config.libc_symbols);
        assert!(config.supplied_libc_path.is_none());
        assert_eq!(config.glibc_profile, GLIBC_X86_64_MODERN);
        assert_eq!(config.allocator_views_preset, AllocatorViewsPreset::None);
        assert!(!config.json);
        assert!(config.json_out.is_none());
        assert!(!config.json_enabled());
    }

    #[test]
    fn parse_env_assignment_accepts_value() {
        assert_eq!(
            parse_env_assignment("FOO=bar").unwrap(),
            ("FOO".to_string(), "bar".to_string())
        );
    }

    #[test]
    fn parse_env_assignment_accepts_empty_value() {
        assert_eq!(
            parse_env_assignment("EMPTY=").unwrap(),
            ("EMPTY".to_string(), "".to_string())
        );
    }

    #[test]
    fn parse_env_assignment_rejects_missing_equals() {
        assert!(parse_env_assignment("FOO").is_err());
    }

    #[test]
    fn parse_env_assignment_rejects_empty_key() {
        assert!(parse_env_assignment("=bar").is_err());
    }

    #[test]
    fn trace_config_parses_cwd_and_env_controls() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--cwd".into(),
            "./challenge".into(),
            "--clear-env".into(),
            "--set-env".into(),
            "FOO=bar".into(),
            "--set-env".into(),
            "EMPTY=".into(),
            "--unset-env".into(),
            "LD_DEBUG".into(),
            "./chall".into(),
            "arg".into(),
        ])
        .unwrap();

        assert_eq!(program, "./chall");
        assert_eq!(args, vec!["arg"]);
        assert_eq!(config.cwd, Some(PathBuf::from("./challenge")));
        assert!(config.clear_env);
        assert_eq!(
            config.set_env,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("EMPTY".to_string(), "".to_string())
            ]
        );
        assert_eq!(config.unset_env, vec!["LD_DEBUG".to_string()]);
    }

    #[test]
    fn trace_config_parses_stdin_file() {
        let (config, program, _) = parse_trace_heap_args(vec![
            "--stdin-file".into(),
            "script.txt".into(),
            "./chall".into(),
        ])
        .unwrap();

        assert_eq!(program, "./chall");
        assert_eq!(config.stdin, StdinConfig::File(PathBuf::from("script.txt")));
    }

    #[test]
    fn trace_config_parses_stdin_text() {
        let (config, program, _) = parse_trace_heap_args(vec![
            "--stdin-text".into(),
            "1\n2\n".into(),
            "./chall".into(),
        ])
        .unwrap();

        assert_eq!(program, "./chall");
        assert_eq!(config.stdin, StdinConfig::Text("1\n2\n".to_string()));
    }

    #[test]
    fn trace_config_rejects_multiple_stdin_sources() {
        assert!(parse_trace_heap_args(vec![
            "--stdin-file".into(),
            "script.txt".into(),
            "--stdin-text".into(),
            "1\n".into(),
            "./chall".into(),
        ])
        .is_err());
    }

    #[test]
    fn allocator_views_preset_resolves_default_to_none() {
        assert_eq!(
            resolve_allocator_views_preset(None, false).unwrap(),
            AllocatorViewsPreset::None
        );
        assert_eq!(
            resolve_allocator_views_preset(Some(AllocatorViewsPresetArg::Basic), false).unwrap(),
            AllocatorViewsPreset::Basic
        );
    }

    #[test]
    fn allocator_views_basic_enables_expected_views() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--allocator-views".into(),
            "basic".into(),
            "./target".into(),
        ])
        .unwrap();

        assert_eq!(config.allocator_views_preset, AllocatorViewsPreset::Basic);
        assert!(config.show_layout);
        assert!(config.show_tcache_candidates);
        assert!(config.show_heap_scan);
        assert!(!config.show_fastbins);
    }

    #[test]
    fn allocator_views_full_enables_expected_views() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--allocator-views".into(),
            "full".into(),
            "./target".into(),
        ])
        .unwrap();

        assert_eq!(config.allocator_views_preset, AllocatorViewsPreset::Full);
        assert!(config.show_layout);
        assert!(config.show_tcache_candidates);
        assert!(config.show_main_arena_candidate);
        assert!(config.show_main_arena_top_candidate);
        assert!(config.show_fastbins);
        assert!(config.show_unsorted_bin);
        assert!(config.show_regular_bins);
        assert!(config.show_smallbins);
        assert!(config.show_largebins);
        assert!(config.show_heap_scan);
    }

    #[test]
    fn all_allocator_views_resolves_to_full() {
        let (config, _, _) =
            parse_trace_heap_args(vec!["--all-allocator-views".into(), "./target".into()]).unwrap();

        assert_eq!(config.allocator_views_preset, AllocatorViewsPreset::Full);
        assert!(config.show_largebins);
        assert_eq!(
            resolve_allocator_views_preset(None, true).unwrap(),
            AllocatorViewsPreset::Full
        );
    }

    #[test]
    fn allocator_views_flags_conflict() {
        let err = parse_trace_heap_args(vec![
            "--allocator-views".into(),
            "full".into(),
            "--all-allocator-views".into(),
            "./target".into(),
        ])
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("--all-allocator-views conflicts with --allocator-views"));
    }

    #[test]
    fn allocator_views_preset_is_additive_with_explicit_flags() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--allocator-views".into(),
            "basic".into(),
            "--fastbins".into(),
            "./target".into(),
        ])
        .unwrap();

        assert_eq!(config.allocator_views_preset, AllocatorViewsPreset::Basic);
        assert!(config.show_layout);
        assert!(config.show_tcache_candidates);
        assert!(config.show_heap_scan);
        assert!(config.show_fastbins);
        assert!(config.show_main_arena_candidate);
    }

    #[test]
    fn json_launch_metadata_records_env_keys_not_values() {
        let plan = heapify_debugger::build_exec_plan(&heapify_debugger::LaunchConfig {
            target_program: PathBuf::from("./chall"),
            target_args: Vec::new(),
            loader_path: None,
            library_path: None,
            preload_path: None,
            supplied_libc_path: None,
            cwd: Some(PathBuf::from("./challenge")),
            clear_env: true,
            set_env: vec![("SECRET".to_string(), "hidden-value".to_string())],
            unset_env: vec!["LD_DEBUG".to_string()],
            stdin: StdinConfig::Inherit,
        })
        .unwrap();

        let value = serde_json::to_value(json_launch_metadata(&plan)).unwrap();

        assert_eq!(value["cwd"], "./challenge");
        assert_eq!(value["clear_env"], true);
        assert_eq!(value["set_env"], serde_json::json!(["SECRET"]));
        assert_eq!(value["unset_env"], serde_json::json!(["LD_DEBUG"]));
        assert!(!value.to_string().contains("hidden-value"));
    }

    #[test]
    fn json_launch_metadata_text_stdin_records_byte_count_not_contents() {
        let plan = heapify_debugger::build_exec_plan(&heapify_debugger::LaunchConfig {
            target_program: PathBuf::from("./chall"),
            target_args: Vec::new(),
            loader_path: None,
            library_path: None,
            preload_path: None,
            supplied_libc_path: None,
            cwd: None,
            clear_env: false,
            set_env: Vec::new(),
            unset_env: Vec::new(),
            stdin: StdinConfig::Text("secret menu input\n".to_string()),
        })
        .unwrap();

        let value = serde_json::to_value(json_launch_metadata(&plan)).unwrap();

        assert_eq!(value["stdin"]["kind"], "text");
        assert_eq!(value["stdin"]["bytes"], 18);
        assert!(!value.to_string().contains("secret menu input"));
    }

    #[test]
    fn json_launch_metadata_file_stdin_records_path() {
        let plan = heapify_debugger::build_exec_plan(&heapify_debugger::LaunchConfig {
            target_program: PathBuf::from("./chall"),
            target_args: Vec::new(),
            loader_path: None,
            library_path: None,
            preload_path: None,
            supplied_libc_path: None,
            cwd: None,
            clear_env: false,
            set_env: Vec::new(),
            unset_env: Vec::new(),
            stdin: StdinConfig::File(PathBuf::from("script.txt")),
        })
        .unwrap();

        let value = serde_json::to_value(json_launch_metadata(&plan)).unwrap();

        assert_eq!(value["stdin"]["kind"], "file");
        assert_eq!(value["stdin"]["path"], "script.txt");
    }

    #[test]
    fn events_only_hides_extra_rendering_and_layout() {
        let (config, program, _) = parse_trace_heap_args(vec![
            "--events-only".into(),
            "--layout".into(),
            "./target".into(),
        ])
        .unwrap();

        assert_eq!(program, "./target");
        assert!(!config.show_chunks);
        assert!(!config.show_tracker_notes);
        assert!(!config.show_explanations);
        assert!(!config.show_layout);
        assert!(!config.show_tcache_candidates);
        assert!(!config.show_tcache_struct_candidate);
        assert!(!config.show_main_arena_candidate);
        assert!(!config.show_arena_experiment);
        assert!(!config.show_fastbin_experiment);
        assert!(!config.show_unsorted_experiment);
        assert!(!config.show_unsorted_bin);
        assert!(!config.show_fastbins);
        assert!(!config.show_heap_scan);
        assert!(!config.show_regular_bins);
    }

    #[test]
    fn max_layout_chunks_is_configurable() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--layout".into(),
            "--max-layout-chunks".into(),
            "8".into(),
            "./target".into(),
        ])
        .unwrap();

        assert!(config.show_layout);
        assert_eq!(config.max_layout_chunks, 8);
    }

    #[test]
    fn heap_scan_is_configurable_and_events_only_suppresses_it() {
        let (config, _, _) =
            parse_trace_heap_args(vec!["--heap-scan".into(), "./target".into()]).unwrap();
        assert!(config.show_heap_scan);

        let (config, _, _) = parse_trace_heap_args(vec![
            "--events-only".into(),
            "--heap-scan".into(),
            "./target".into(),
        ])
        .unwrap();
        assert!(!config.show_heap_scan);
    }

    #[test]
    fn tcache_candidates_are_configurable() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--tcache-candidates".into(),
            "--max-tcache-chain".into(),
            "4".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_tcache_candidates);
        assert_eq!(config.max_tcache_chain, 4);
    }

    #[test]
    fn max_fastbin_chain_is_configurable() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--max-fastbin-chain".into(),
            "4".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert_eq!(config.max_fastbin_chain, 4);
    }

    #[test]
    fn max_unsorted_chain_is_configurable() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--max-unsorted-chain".into(),
            "4".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert_eq!(config.max_unsorted_chain, 4);
    }

    #[test]
    fn regular_bins_are_configurable_and_imply_main_arena() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--regular-bins".into(),
            "--max-regular-bins".into(),
            "126".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_regular_bins);
        assert!(config.show_main_arena_candidate);
        assert_eq!(config.max_regular_bins, 126);
    }

    #[test]
    fn libc_symbols_mode_is_configurable() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--libc-symbols".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert_eq!(config.trace_mode, None);
        assert!(config.libc_symbols);
    }

    #[test]
    fn supplied_libc_path_is_configurable() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--libc".into(), "./libc.so.6".into(), "prog".into()])
                .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert_eq!(
            config.supplied_libc_path.as_deref(),
            Some(std::path::Path::new("./libc.so.6"))
        );
    }

    #[test]
    fn custom_loader_launch_options_are_configurable() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--ld".into(),
            "./ld-linux-x86-64.so.2".into(),
            "--library-path".into(),
            ".".into(),
            "--preload".into(),
            "./libc.so.6".into(),
            "prog".into(),
            "arg".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert_eq!(args, vec!["arg"]);
        assert_eq!(
            config.loader_path.as_deref(),
            Some(std::path::Path::new("./ld-linux-x86-64.so.2"))
        );
        assert_eq!(
            config.library_path.as_deref(),
            Some(std::path::Path::new("."))
        );
        assert_eq!(
            config.preload_path.as_deref(),
            Some(std::path::Path::new("./libc.so.6"))
        );
    }

    #[test]
    fn trace_mode_is_configurable() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--trace-mode".into(), "libc".into(), "prog".into()])
                .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert_eq!(config.trace_mode, Some(TraceModeArg::Libc));
        assert!(!config.libc_symbols);
    }

    #[test]
    fn glibc_profile_is_configurable() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--glibc-profile".into(),
            "glibc-2.35-x86_64".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert_eq!(config.glibc_profile, GLIBC_2_35_X86_64);
    }

    #[test]
    fn glibc_profile_auto_is_configurable() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--glibc-profile".into(), "auto".into(), "prog".into()])
                .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert_eq!(config.glibc_profile_request, "auto");
        assert_eq!(config.glibc_profile, GLIBC_X86_64_MODERN);
    }

    #[test]
    fn resolves_known_glibc_profile_name() {
        assert_eq!(
            resolve_glibc_profile("glibc-2.35-x86_64").unwrap(),
            GLIBC_2_35_X86_64
        );
    }

    #[test]
    fn unknown_glibc_profile_error_lists_available_profiles() {
        let err = resolve_glibc_profile("does-not-exist").unwrap_err();
        let message = format!("{err:#}");

        assert!(message.contains("unknown glibc profile `does-not-exist`"));
        assert!(message.contains("available profiles:"));
        assert!(message.contains("  auto"));
        assert!(message.contains("  glibc-x86_64-modern"));
        assert!(message.contains("  glibc-2.35-x86_64"));
        assert!(format_available_glibc_profiles().contains("glibc-2.35-x86_64"));
    }

    #[test]
    fn resolve_trace_mode_defaults_to_target_plt() {
        assert_eq!(
            resolve_trace_mode(None, false).unwrap(),
            AllocationTraceMode::TargetPlt
        );
    }

    #[test]
    fn resolve_trace_mode_accepts_legacy_libc_symbols() {
        assert_eq!(
            resolve_trace_mode(None, true).unwrap(),
            AllocationTraceMode::LibcSymbols
        );
    }

    #[test]
    fn resolve_trace_mode_accepts_explicit_plt() {
        assert_eq!(
            resolve_trace_mode(Some(TraceModeArg::Plt), false).unwrap(),
            AllocationTraceMode::TargetPlt
        );
    }

    #[test]
    fn resolve_trace_mode_accepts_explicit_libc() {
        assert_eq!(
            resolve_trace_mode(Some(TraceModeArg::Libc), false).unwrap(),
            AllocationTraceMode::LibcSymbols
        );
    }

    #[test]
    fn resolve_trace_mode_allows_libc_with_legacy_alias() {
        assert_eq!(
            resolve_trace_mode(Some(TraceModeArg::Libc), true).unwrap(),
            AllocationTraceMode::LibcSymbols
        );
    }

    #[test]
    fn resolve_trace_mode_rejects_plt_with_legacy_alias() {
        assert!(resolve_trace_mode(Some(TraceModeArg::Plt), true).is_err());
    }

    #[test]
    fn parse_u64_auto_radix_accepts_decimal() {
        assert_eq!(parse_u64_auto_radix("123").unwrap(), 123);
    }

    #[test]
    fn parse_u64_auto_radix_accepts_lowercase_hex() {
        assert_eq!(parse_u64_auto_radix("0x10").unwrap(), 16);
    }

    #[test]
    fn parse_u64_auto_radix_accepts_uppercase_hex() {
        assert_eq!(parse_u64_auto_radix("0X10").unwrap(), 16);
    }

    #[test]
    fn parse_u64_auto_radix_rejects_invalid_string() {
        assert!(parse_u64_auto_radix("not-a-number").is_err());
        assert!(parse_u64_auto_radix("").is_err());
        assert!(parse_u64_auto_radix("0x").is_err());
    }

    #[test]
    fn tcache_struct_candidate_is_configurable() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--tcache-struct".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_tcache_struct_candidate);
    }

    #[test]
    fn main_arena_candidate_is_configurable() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--main-arena".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
    }

    #[test]
    fn main_arena_offset_implies_main_arena_candidate() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--main-arena-offset".into(),
            "0x1d3c60".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert_eq!(config.main_arena_offset, Some(0x1d3c60));
    }

    #[test]
    fn arena_experiment_implies_main_arena_candidate() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--arena-experiment".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert!(config.show_arena_experiment);
    }

    #[test]
    fn fastbin_experiment_implies_main_arena_candidate() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--fastbin-experiment".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert!(config.show_fastbin_experiment);
    }

    #[test]
    fn unsorted_experiment_implies_main_arena_candidate() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--unsorted-experiment".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert!(config.show_unsorted_experiment);
    }

    #[test]
    fn bin_experiment_implies_main_arena_candidate() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--bin-experiment".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert!(config.show_bin_experiment);
    }

    #[test]
    fn unsorted_bin_implies_main_arena_candidate() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--unsorted-bin".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert!(config.show_unsorted_bin);
    }

    #[test]
    fn fastbins_implies_main_arena_candidate() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--fastbins".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert!(config.show_fastbins);
    }

    #[test]
    fn largebins_are_configurable_and_imply_regular_bins_and_main_arena() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--largebins".into(),
            "--max-largebin-chain".into(),
            "4".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_largebins);
        assert!(config.show_regular_bins);
        assert!(config.show_main_arena_candidate);
        assert_eq!(config.max_largebin_chain, 4);
    }

    #[test]
    fn fastbin_chain_formatting_ends_with_null() {
        assert_eq!(
            format_fastbin_chain_entries(&["0x1000", "0x2000"], false, false, false),
            "0x1000 -> 0x2000 -> NULL"
        );
    }

    #[test]
    fn fastbin_chain_formatting_ends_with_unknown_next() {
        assert_eq!(
            format_fastbin_chain_entries(&["0x1000"], false, true, false),
            "0x1000 -> ?"
        );
    }

    #[test]
    fn fastbin_chain_formatting_ends_with_truncated() {
        assert_eq!(
            format_fastbin_chain_entries(&["0x1000"], true, false, false),
            "0x1000 -> ... truncated"
        );
    }

    #[test]
    fn fastbin_chain_formatting_ends_with_cycle() {
        assert_eq!(
            format_fastbin_chain_entries(&["0x1000"], true, false, true),
            "0x1000 -> ... cycle"
        );
    }

    #[test]
    fn main_arena_top_offset_implies_main_arena_candidate() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--main-arena-top-offset".into(),
            "0x60".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert_eq!(config.main_arena_top_offset, Some(0x60));
    }

    #[test]
    fn main_arena_top_implies_main_arena_candidate() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--main-arena-top".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.show_main_arena_candidate);
        assert!(config.show_main_arena_top_candidate);
        assert_eq!(config.main_arena_top_offset, None);
    }

    #[test]
    fn main_arena_top_with_glibc_2_35_uses_profile_offset() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--glibc-profile".into(),
            "glibc-2.35-x86_64".into(),
            "--main-arena-top".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(
            select_main_arena_top_offset(
                config.main_arena_top_offset,
                config.show_main_arena_top_candidate,
                config.glibc_profile,
            ),
            SelectedMainArenaTopOffset::Profile {
                offset: 0x60,
                profile_name: "glibc-2.35-x86_64".to_string()
            }
        );
    }

    #[test]
    fn explicit_main_arena_top_offset_overrides_selected_profile_offset() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--glibc-profile".into(),
            "glibc-2.35-x86_64".into(),
            "--main-arena-top-offset".into(),
            "0x70".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(
            select_main_arena_top_offset(
                config.main_arena_top_offset,
                config.show_main_arena_top_candidate,
                config.glibc_profile,
            ),
            SelectedMainArenaTopOffset::User { offset: 0x70 }
        );
    }

    #[test]
    fn main_arena_top_uses_profile_offset_when_available() {
        let profile = heapify_core::glibc::GlibcProfile {
            main_arena_top_offset: Some(0x60),
            ..GLIBC_X86_64_MODERN
        };

        assert_eq!(
            select_main_arena_top_offset(None, true, profile),
            SelectedMainArenaTopOffset::Profile {
                offset: 0x60,
                profile_name: "glibc-x86_64-modern".to_string()
            }
        );
    }

    #[test]
    fn main_arena_top_offset_overrides_profile_offset() {
        let profile = heapify_core::glibc::GlibcProfile {
            main_arena_top_offset: Some(0x60),
            ..GLIBC_X86_64_MODERN
        };

        assert_eq!(
            select_main_arena_top_offset(Some(0x70), true, profile),
            SelectedMainArenaTopOffset::User { offset: 0x70 }
        );
    }

    #[test]
    fn clean_main_arena_view_requires_profile_validated_top() {
        let top = heapify_debugger::MainArenaTopCandidate {
            arena_addr: 0x7000,
            field_offset: 0x60,
            top_addr: 0x2000,
            points_into_heap: true,
            matches_heap_chunk: true,
            chunk_size: Some(0x21000),
            status: MainArenaTopStatus::MatchesWalkedChunk,
            source: MainArenaFieldSource::GlibcProfile,
            profile_name: Some("glibc-2.35-x86_64".to_string()),
        };

        assert!(is_clean_main_arena_view(&top));
    }

    #[test]
    fn candidate_rendering_remains_for_user_offset_top_source() {
        let top = heapify_debugger::MainArenaTopCandidate {
            arena_addr: 0x7000,
            field_offset: 0x60,
            top_addr: 0x2000,
            points_into_heap: true,
            matches_heap_chunk: true,
            chunk_size: Some(0x21000),
            status: MainArenaTopStatus::MatchesWalkedChunk,
            source: MainArenaFieldSource::UserOffset,
            profile_name: None,
        };

        assert!(!is_clean_main_arena_view(&top));
    }

    #[test]
    fn main_arena_top_without_profile_offset_is_unavailable() {
        assert_eq!(
            select_main_arena_top_offset(None, true, GLIBC_X86_64_MODERN),
            SelectedMainArenaTopOffset::Unavailable
        );
    }

    #[test]
    fn json_mode_is_configurable() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--json".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.json);
        assert!(config.json_enabled());
    }

    #[test]
    fn json_out_sets_output_path_and_enables_json() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--json-out".into(),
            "trace.ndjson".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert_eq!(
            config.json_out.as_deref(),
            Some(std::path::Path::new("trace.ndjson"))
        );
        assert!(config.json_enabled());
    }

    #[test]
    fn live_tui_is_configurable() {
        let (config, program, args) =
            parse_trace_heap_args(vec!["--live-tui".into(), "prog".into()]).unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.live_tui);
    }

    #[test]
    fn live_tui_conflicts_with_json_stdout_mode() {
        let err = parse_trace_heap_args(vec!["--live-tui".into(), "--json".into(), "prog".into()])
            .unwrap_err();

        assert!(err.to_string().contains("--live-tui conflicts with --json"));
    }

    #[test]
    fn live_tui_conflicts_with_events_only() {
        let err = parse_trace_heap_args(vec![
            "--live-tui".into(),
            "--events-only".into(),
            "prog".into(),
        ])
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("--live-tui conflicts with --events-only"));
    }

    #[test]
    fn live_tui_accepts_json_out() {
        let (config, program, args) = parse_trace_heap_args(vec![
            "--live-tui".into(),
            "--json-out".into(),
            "trace.ndjson".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(program, "prog");
        assert!(args.is_empty());
        assert!(config.live_tui);
        assert_eq!(
            config.json_out.as_deref(),
            Some(std::path::Path::new("trace.ndjson"))
        );
    }

    #[test]
    fn json_writer_writes_record_with_newline_to_file() {
        let path = std::env::temp_dir().join(format!(
            "heapify-json-writer-{}-{}.ndjson",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        {
            let mut writer = super::JsonWriter::file(&path).unwrap();
            writer
                .write_record(&serde_json::json!({"type": "event"}))
                .unwrap();
            writer.flush().unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(contents, "{\"type\":\"event\"}\n");
    }

    #[test]
    fn replay_config_parses_events_only_and_no_chunks() {
        let (config, path) = parse_replay_args(vec![
            "--events-only".into(),
            "--no-chunks".into(),
            "trace.ndjson".into(),
        ])
        .unwrap();

        assert!(config.events_only);
        assert!(!config.show_chunks);
        assert!(!config.tui);
        assert_eq!(path, std::path::Path::new("trace.ndjson"));
    }

    #[test]
    fn replay_config_parses_tui() {
        let (config, path) =
            parse_replay_args(vec!["--tui".into(), "trace.ndjson".into()]).unwrap();

        assert!(config.tui);
        assert_eq!(path, std::path::Path::new("trace.ndjson"));
    }

    #[test]
    fn replay_session_extracts_event_records_and_counts_them() {
        let records = vec![
            session_start_record(),
            malloc_record(1),
            layout_record(1),
            free_record(2),
            tcache_record(2),
            session_end_record(2),
        ];

        let session = ReplaySession::from_records(records);

        assert_eq!(session.event_count(), 2);
        assert_eq!(session.events[0].event_id, 1);
        assert_eq!(session.events[0].record_index, 1);
        assert_eq!(session.events[1].event_id, 2);
        assert_eq!(session.events[1].record_index, 3);
        assert!(session.session_start.is_some());
        assert!(session.session_end.is_some());
    }

    #[test]
    fn replay_session_metadata_parses_suggested_glibc_profile() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "session_start",
            "heapify_version": "0.1.0",
            "program": "./prog",
            "args": [],
            "trace_mode": "target_plt",
            "arch": "x86_64",
            "os": "linux",
            "glibc_profile": "glibc-x86_64-modern",
            "suggested_glibc_profile": "glibc-2.35-x86_64",
            "libc": {
                "path": "/lib/libc.so.6",
                "version": "2.35"
            },
            "features": {
                "layout": false,
                "tcache_candidates": false,
                "tcache_struct": false,
                "libc_symbols": false
            }
        }))
        .unwrap();

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    suggested glibc profile: glibc-2.35-x86_64"));
        assert!(!formatted.contains("allocator views preset"));
        match record {
            super::json::JsonTraceRecord::SessionStart {
                allocator_views_preset,
                ..
            } => assert_eq!(allocator_views_preset, "none"),
            _ => panic!("expected session_start"),
        }
    }

    #[test]
    fn replay_parses_old_session_start_without_glibc_profile_selection() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "session_start",
            "heapify_version": "0.1.0",
            "program": "./prog",
            "args": [],
            "trace_mode": "target_plt",
            "arch": "x86_64",
            "os": "linux",
            "glibc_profile": "glibc-x86_64-modern",
            "features": {
                "layout": false,
                "tcache_candidates": false,
                "tcache_struct": false,
                "libc_symbols": false
            }
        }))
        .unwrap();

        match record {
            super::json::JsonTraceRecord::SessionStart {
                glibc_profile_selection,
                ..
            } => assert!(glibc_profile_selection.is_none()),
            _ => panic!("expected session_start"),
        }
    }

    #[test]
    fn replay_session_metadata_renders_glibc_profile_selection() {
        let record = glibc_profile_selection_session_start_record("low", "full");

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    glibc profile selection:"));
        assert!(formatted.contains("        requested: auto"));
        assert!(formatted.contains("        selected: glibc-x86_64-modern"));
        assert!(formatted.contains("        confidence: low"));
        assert!(formatted.contains(super::low_confidence_profile_warning()));
    }

    #[test]
    fn events_only_suppresses_glibc_profile_selection_rendering() {
        let record = glibc_profile_selection_session_start_record("low", "full");
        let config = ReplayConfig {
            events_only: true,
            ..ReplayConfig::default()
        };

        let formatted = format_replay_record(&record, &config);

        assert!(!formatted.contains("glibc profile selection"));
        assert!(!formatted.contains(super::low_confidence_profile_warning()));
    }

    #[test]
    fn replay_session_metadata_renders_allocator_views_preset_when_present() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "session_start",
            "heapify_version": "0.1.0",
            "program": "./prog",
            "args": [],
            "trace_mode": "target_plt",
            "arch": "x86_64",
            "os": "linux",
            "glibc_profile": "glibc-x86_64-modern",
            "allocator_views_preset": "full",
            "features": {
                "layout": true,
                "tcache_candidates": true,
                "tcache_struct": false,
                "libc_symbols": false
            }
        }))
        .unwrap();

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    allocator views preset: full"));
    }

    #[test]
    fn replay_session_metadata_parses_libc_with_and_without_supplied_path() {
        let old_record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "session_start",
            "heapify_version": "0.1.0",
            "program": "./prog",
            "args": [],
            "trace_mode": "target_plt",
            "arch": "x86_64",
            "os": "linux",
            "glibc_profile": "glibc-x86_64-modern",
            "libc": {
                "path": "/lib/libc.so.6",
                "version": "2.35"
            },
            "features": {
                "layout": false,
                "tcache_candidates": false,
                "tcache_struct": false,
                "libc_symbols": false
            }
        }))
        .unwrap();
        let new_record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "session_start",
            "heapify_version": "0.1.0",
            "program": "./prog",
            "args": [],
            "trace_mode": "libc_symbols",
            "arch": "x86_64",
            "os": "linux",
            "glibc_profile": "glibc-x86_64-modern",
            "libc": {
                "path": "/usr/lib/libc.so.6",
                "supplied_path": "./libc.so.6",
                "paths_match": false,
                "version": "2.35"
            },
            "features": {
                "layout": false,
                "tcache_candidates": false,
                "tcache_struct": false,
                "libc_symbols": true
            }
        }))
        .unwrap();

        let old_formatted = format_replay_record(&old_record, &ReplayConfig::default());
        let new_formatted = format_replay_record(&new_record, &ReplayConfig::default());

        assert!(old_formatted.contains("    libc: /lib/libc.so.6"));
        assert!(new_formatted.contains("    supplied libc: ./libc.so.6"));
        assert!(new_formatted.contains(
            "    warning: supplied libc differs from loaded libc; symbol offsets may be wrong"
        ));
    }

    #[test]
    fn replay_session_metadata_parses_launch_metadata() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "session_start",
            "heapify_version": "0.1.0",
            "program": "./chall",
            "args": [],
            "trace_mode": "libc_symbols",
            "arch": "x86_64",
            "os": "linux",
            "glibc_profile": "glibc-x86_64-modern",
            "launch": {
                "mode": "custom_loader_with_preload",
                "loader": "./ld-linux-x86-64.so.2",
                "library_path": ".",
                "preload": "./libc.so.6",
                "cwd": "./challenge",
                "clear_env": true,
                "set_env": ["PATH", "GLIBC_TUNABLES"],
                "unset_env": ["LD_DEBUG"],
                "stdin": {
                    "kind": "file",
                    "path": "examples/menu_script.txt"
                }
            },
            "features": {
                "layout": false,
                "tcache_candidates": false,
                "tcache_struct": false,
                "libc_symbols": true
            }
        }))
        .unwrap();

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    launch mode: custom_loader_with_preload"));
        assert!(formatted.contains("    loader: ./ld-linux-x86-64.so.2"));
        assert!(formatted.contains("    library path: ."));
        assert!(formatted.contains("    preload: ./libc.so.6"));
        assert!(formatted.contains("    cwd: ./challenge"));
        assert!(formatted.contains("    stdin: file examples/menu_script.txt"));
        assert!(formatted.contains("    env: clear=true set=2 unset=1"));
        assert!(formatted.contains("    env set: PATH, GLIBC_TUNABLES"));
        assert!(formatted.contains("    env unset: LD_DEBUG"));
    }

    #[test]
    fn replay_session_records_for_event_returns_matching_related_records() {
        let session = ReplaySession::from_records(vec![
            session_start_record(),
            malloc_record(1),
            layout_record(1),
            tcache_record(2),
            session_end_record(1),
        ]);

        let records = session.records_for_event(1);

        assert_eq!(records.len(), 2);
        assert!(matches!(
            records[0],
            super::json::JsonTraceRecord::Event { .. }
        ));
        assert!(matches!(
            records[1],
            super::json::JsonTraceRecord::HeapLayout { .. }
        ));
    }

    #[test]
    fn replay_session_indexes_allocator_source_summary_by_event_id() {
        let session = ReplaySession::from_records(vec![allocator_source_summary_record(9)]);

        assert_eq!(
            session.allocator_states_by_event_id.get(&9),
            Some(&ReplayEventAllocatorState {
                event_id: 9,
                tcache_candidate_chunks: 7,
                fastbin_chunks: 1,
                unsorted_chunks: 0,
                smallbin_chunks: 0,
                largebin_chunks: 0,
                total_free_list_chunks: 8,
                warning_count: 0,
            })
        );
    }

    #[test]
    fn replay_session_indexes_allocator_source_delta_by_event_id() {
        let session = ReplaySession::from_records(vec![allocator_source_delta_record(9)]);
        let delta = session.allocator_deltas_by_event_id.get(&9).unwrap();

        assert_eq!(delta.event_id, 9);
        assert_eq!(delta.tcache_candidate_chunks_delta, 0);
        assert_eq!(delta.fastbin_chunks_delta, 1);
        assert_eq!(delta.unsorted_chunks_delta, 0);
        assert_eq!(delta.smallbin_chunks_delta, 0);
        assert_eq!(delta.largebin_chunks_delta, 0);
        assert_eq!(delta.total_free_list_chunks_delta, 1);
        assert_eq!(delta.warning_count_delta, 0);
    }

    #[test]
    fn timeline_allocator_counts_are_empty_when_summary_is_missing() {
        assert_eq!(format_timeline_allocator_counts(None), "");
    }

    #[test]
    fn timeline_allocator_counts_are_compact() {
        let state = ReplayEventAllocatorState {
            event_id: 9,
            tcache_candidate_chunks: 7,
            fastbin_chunks: 1,
            unsorted_chunks: 0,
            smallbin_chunks: 0,
            largebin_chunks: 0,
            total_free_list_chunks: 8,
            warning_count: 0,
        };

        assert_eq!(
            format_timeline_allocator_counts(Some(&state)),
            "tc=7 fb=1 ub=0 sb=0 lb=0 warn=0"
        );
    }

    #[test]
    fn timeline_event_summary_includes_allocator_counts_when_present() {
        let event = event_from_record(free_record(9));
        let state = ReplayEventAllocatorState {
            event_id: 9,
            tcache_candidate_chunks: 7,
            fastbin_chunks: 1,
            unsorted_chunks: 0,
            smallbin_chunks: 0,
            largebin_chunks: 0,
            total_free_list_chunks: 8,
            warning_count: 0,
        };

        assert_eq!(
            format_timeline_event_summary(&event, Some(&state)),
            "#9 free(0x1000)    tc=7 fb=1 ub=0 sb=0 lb=0 warn=0"
        );
    }

    #[test]
    fn timeline_event_summary_omits_allocator_counts_when_missing() {
        let event = event_from_record(free_record(9));

        assert_eq!(
            format_timeline_event_summary(&event, None),
            "#9 free(0x1000)"
        );
    }

    #[test]
    fn replay_session_event_record_handles_out_of_range_selection() {
        let session = ReplaySession::from_records(vec![malloc_record(1)]);

        assert!(session.event_record(0).is_some());
        assert!(session.event_record(1).is_none());
    }

    #[test]
    fn replay_event_summary_formats_allocator_calls() {
        assert_eq!(
            summary_for_event(serde_json::json!({
                "type": "malloc",
                "event_id": 1,
                "requested_size": "0x20",
                "returned_ptr": "0x1000",
                "chunk": null,
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            })),
            "#1 malloc(0x20) = 0x1000"
        );
        assert_eq!(
            summary_for_event(serde_json::json!({
                "type": "free",
                "event_id": 2,
                "ptr": "0x1000",
                "chunk": null,
                "tcache_entry": null,
                "tracker_note": "FreedKnownChunk",
                "tracker_explanation": null
            })),
            "#2 free(0x1000)"
        );
        assert_eq!(
            summary_for_event(serde_json::json!({
                "type": "calloc",
                "event_id": 3,
                "nmemb": "0x4",
                "size": "0x10",
                "returned_ptr": "0x2000",
                "chunk": null,
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            })),
            "#3 calloc(0x4, 0x10) = 0x2000"
        );
        assert_eq!(
            summary_for_event(serde_json::json!({
                "type": "realloc",
                "event_id": 4,
                "old_ptr": "0x2000",
                "new_size": "0x80",
                "returned_ptr": "0x3000",
                "old_chunk": null,
                "new_chunk": null,
                "tracker_note": "ReallocMovedAllocation",
                "tracker_explanation": null
            })),
            "#4 realloc(0x2000, 0x80) = 0x3000"
        );
    }

    #[test]
    fn replay_renders_caller_addr_when_present() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "malloc",
                "event_id": 1,
                "requested_size": "0x20",
                "returned_ptr": "0x1000",
                "chunk": null,
                "caller_addr": "0x5555555551b4",
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap();

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    caller:     0x5555555551b4"));
    }

    #[test]
    fn symbolized_caller_format_omits_zero_offset() {
        let caller = SymbolizedAddress {
            addr: 0x555555555180,
            object_name: None,
            symbol: "main".to_string(),
            symbol_addr: 0x555555555180,
            offset: 0,
            source: None,
        };

        assert_eq!(format_symbolized_caller(&caller), "main (0x555555555180)");
    }

    #[test]
    fn symbolized_caller_format_includes_nonzero_offset() {
        let caller = SymbolizedAddress {
            addr: 0x5555555551b8,
            object_name: None,
            symbol: "main".to_string(),
            symbol_addr: 0x555555555180,
            offset: 0x38,
            source: None,
        };

        assert_eq!(
            format_symbolized_caller(&caller),
            "main+0x38 (0x5555555551b8)"
        );
    }

    #[test]
    fn symbolized_shared_library_caller_format_includes_object_prefix() {
        let caller = SymbolizedAddress {
            addr: 0x7ffff7e00110,
            object_name: Some("libc.so.6".to_string()),
            symbol: "__libc_malloc".to_string(),
            symbol_addr: 0x7ffff7e00100,
            offset: 0x10,
            source: None,
        };

        assert_eq!(
            format_symbolized_caller(&caller),
            "libc.so.6!__libc_malloc+0x10 (0x7ffff7e00110)"
        );
    }

    #[test]
    fn replay_renders_symbolized_caller_when_present() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "malloc",
                "event_id": 1,
                "requested_size": "0x20",
                "returned_ptr": "0x1000",
                "chunk": null,
                "caller_addr": "0x5555555551b8",
                "caller_symbol": {
                    "symbol": "allocate_from_main",
                    "symbol_addr": "0x555555555180",
                    "offset": "0x38"
                },
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap();

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    caller:     allocate_from_main+0x38 (0x5555555551b8)"));
    }

    #[test]
    fn replay_renders_caller_source_line_when_present() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "malloc",
                "event_id": 1,
                "requested_size": "0x20",
                "returned_ptr": "0x1000",
                "chunk": null,
                "caller_addr": "0x5555555551b8",
                "caller_symbol": {
                    "symbol": "allocate_from_main",
                    "symbol_addr": "0x555555555180",
                    "offset": "0x38",
                    "source": {
                        "file": "examples/simple_malloc.c",
                        "line": 12
                    }
                },
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap();

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    caller:     allocate_from_main+0x38 (0x5555555551b8)"));
        assert!(formatted.contains("    at          examples/simple_malloc.c:12"));
    }

    #[test]
    fn replay_renders_caller_source_column_when_present() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "malloc",
                "event_id": 1,
                "requested_size": "0x20",
                "returned_ptr": "0x1000",
                "chunk": null,
                "caller_addr": "0x5555555551b8",
                "caller_symbol": {
                    "symbol": "allocate_from_main",
                    "symbol_addr": "0x555555555180",
                    "offset": "0x38",
                    "source": {
                        "file": "examples/simple_malloc.c",
                        "line": 12,
                        "column": 7
                    }
                },
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap();

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    at          examples/simple_malloc.c:12:7"));
    }

    #[test]
    fn replay_renders_object_aware_caller_symbol_when_present() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "malloc",
                "event_id": 1,
                "requested_size": "0x20",
                "returned_ptr": "0x1000",
                "chunk": null,
                "caller_addr": "0x7ffff7e00110",
                "caller_symbol": {
                    "object": "libc.so.6",
                    "symbol": "__libc_malloc",
                    "symbol_addr": "0x7ffff7e00100",
                    "offset": "0x10"
                },
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap();

        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("    caller:     libc.so.6!__libc_malloc+0x10 (0x7ffff7e00110)"));
    }

    #[test]
    fn replay_events_only_suppresses_caller_addr() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "free",
                "event_id": 2,
                "ptr": "0x1000",
                "chunk": null,
                "tcache_entry": null,
                "caller_addr": "0x5555555551f0",
                "tracker_note": "FreedKnownChunk",
                "tracker_explanation": null
            }
        }))
        .unwrap();
        let config = ReplayConfig {
            events_only: true,
            show_chunks: false,
            tui: false,
        };

        let formatted = format_replay_record(&record, &config);

        assert!(!formatted.contains("caller:"));
    }

    #[test]
    fn replay_parses_one_line_event_ndjson_file() {
        let path = unique_temp_path("heapify-replay-one-line");
        std::fs::write(
            &path,
            r#"{"type":"event","event":{"type":"malloc","event_id":1,"requested_size":"0x20","returned_ptr":"0x1000","chunk":null,"tracker_note":"NewAllocation","tracker_explanation":null}}"#,
        )
        .unwrap();

        let result = replay_trace_file(&path, &super::ReplayConfig::default());
        std::fs::remove_file(&path).unwrap();

        assert!(result.is_ok());
    }

    #[test]
    fn replay_parses_and_formats_main_arena_candidate_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "main_arena_candidate",
            "event_id": 1,
            "candidate": {
                "libc_path": "/lib/libc.so.6",
                "symbol_name": "main_arena",
                "runtime_addr": "0x7ffff7dd1b80",
                "source": "user_offset",
                "offset": "0x1d3c60"
            }
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(1));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("main_arena candidate:"));
        assert!(formatted.contains("    symbol: main_arena"));
        assert!(formatted.contains("    addr:   0x7ffff7dd1b80"));
        assert!(formatted.contains("    source: user_offset"));
        assert!(formatted.contains("    offset: 0x1d3c60"));
    }

    #[test]
    fn replay_parses_and_formats_main_arena_experiment_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "main_arena_experiment",
            "event_id": 1,
            "arena_addr": "0x7ffff7bd3c60",
            "candidates": [{
                "field_offset": "0x60",
                "value": "0x55555555a000",
                "points_into_heap": true,
                "matches_heap_chunk": true,
                "matched_chunk_size": "0x21000",
                "role_hint": "candidate_top"
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(1));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("main_arena experiment:"));
        assert!(formatted.contains("    arena: 0x7ffff7bd3c60"));
        assert!(formatted.contains(
            "        offset=0x60 value=0x55555555a000 role=candidate_top matched_chunk_size=0x21000"
        ));
    }

    #[test]
    fn replay_parses_and_formats_main_arena_top_candidate_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "main_arena_top_candidate",
            "event_id": 1,
            "arena_addr": "0x7ffff7bd3c60",
            "field_offset": "0x60",
            "top_addr": "0x55555555a000",
            "points_into_heap": true,
            "matches_heap_chunk": true,
            "chunk_size": "0x21000",
            "status": "matches_walked_chunk",
            "source": "glibc_profile",
            "profile": "glibc-test"
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(1));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("main_arena top candidate:"));
        assert!(formatted.contains("    arena:       0x7ffff7bd3c60"));
        assert!(formatted.contains("    field:       0x60"));
        assert!(formatted.contains("    top:         0x55555555a000"));
        assert!(formatted.contains("    source:      glibc_profile"));
        assert!(formatted.contains("    profile:     glibc-test"));
        assert!(formatted.contains("    chunk size:  0x21000"));
        assert!(formatted.contains("    status:      points into heap and matches walked chunk"));
    }

    #[test]
    fn replay_parses_and_formats_main_arena_view_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "main_arena_view",
            "event_id": 1,
            "arena": {
                "addr": "0x7ffff7bd3c60",
                "source": "user_offset",
                "offset": "0x1d3c60",
                "libc_path": "/lib/libc.so.6"
            },
            "top": {
                "field_offset": "0x60",
                "value": "0x55555555a000",
                "size": "0x21000",
                "source": "glibc_profile",
                "profile": "glibc-2.35-x86_64",
                "status": "validated"
            }
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(1));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("main_arena:"));
        assert!(formatted.contains("    addr:        0x7ffff7bd3c60"));
        assert!(formatted.contains("        value:   0x55555555a000"));
        assert!(formatted.contains("        status:  validated"));
    }

    #[test]
    fn replay_parses_and_formats_fastbin_experiment_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "fastbin_experiment",
            "event_id": 7,
            "arena_addr": "0x7ffff7bd3c60",
            "candidates": [{
                "field_offset": "0x20",
                "value": "0x55555555a000",
                "possible_chunk_size": "0x30",
                "points_into_heap": true,
                "matches_heap_chunk": true,
                "known_freed": true,
                "role": "fastbin_candidate"
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(7));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("fastbin experiment:"));
        assert!(formatted
            .contains("        offset=0x20 value=0x55555555a000 chunk_size=0x30 known_freed=yes"));
    }

    #[test]
    fn replay_parses_and_formats_unsorted_bin_experiment_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "unsorted_bin_experiment",
            "event_id": 7,
            "arena_addr": "0x7ffff7bd3c60",
            "candidates": [{
                "field_offset": "0x70",
                "fd": "0x55555555a000",
                "bk": "0x55555555b000",
                "fd_points_into_heap": true,
                "bk_points_into_heap": true,
                "fd_matches_heap_chunk": true,
                "bk_matches_heap_chunk": false,
                "fd_known_freed": true,
                "bk_known_freed": false,
                "role": "unsorted_candidate"
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(7));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("unsorted bin experiment:"));
        assert!(formatted.contains("offset=0x70 fd=0x55555555a000 fd_in_heap=yes fd_known_freed=yes bk=0x55555555b000 bk_in_heap=yes bk_known_freed=no role=unsorted_candidate"));
    }

    #[test]
    fn replay_parses_and_formats_bin_experiment_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "bin_experiment",
            "event_id": 7,
            "arena_addr": "0x7ffff7bd3c60",
            "candidates": [{
                "field_offset": "0x90",
                "fd": "0x55555555a000",
                "bk": "0x7ffff7bd3cf0",
                "fd_points_into_heap": true,
                "bk_points_into_heap": false,
                "fd_points_into_arena": false,
                "bk_points_into_arena": true,
                "fd_matches_heap_chunk": true,
                "bk_matches_heap_chunk": false,
                "fd_known_freed": true,
                "bk_known_freed": null,
                "role": "bin_sentinel_candidate"
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(7));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("bin experiment:"));
        assert!(formatted.contains("offset=0x90 fd=0x55555555a000 fd_in_heap=yes fd_in_arena=no fd_known_freed=yes bk=0x7ffff7bd3cf0 bk_in_heap=no bk_in_arena=yes bk_known_freed=unknown role=bin_sentinel_candidate"));
    }

    #[test]
    fn replay_parses_and_formats_unsorted_bin_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "unsorted_bin",
            "event_id": 7,
            "arena_addr": "0x7ffff7bd3c60",
            "field_offset": "0x70",
            "fd": "0x55555555a000",
            "bk": "0x55555555b000",
            "fd_points_into_heap": true,
            "bk_points_into_heap": true,
            "fd_matches_heap_chunk": true,
            "bk_matches_heap_chunk": false,
            "fd_known_freed": true,
            "bk_known_freed": false
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(7));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("unsorted bin:"));
        assert!(formatted.contains("    offset: 0x70"));
        assert!(formatted.contains("    fd_known_freed: yes"));
        assert!(formatted.contains("    bk_known_freed: no"));
    }

    #[test]
    fn replay_parses_and_formats_unsorted_bin_validation_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "unsorted_bin_validation",
            "event_id": 7,
            "validation": {
                "head_in_heap": "yes",
                "fd_bk_consistent": "yes",
                "nodes_known_freed": "yes",
                "chain_complete": "yes",
                "status": "plausible"
            }
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(7));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("unsorted bin validation:"));
        assert!(formatted.contains("    status: plausible"));
    }

    #[test]
    fn replay_parses_and_formats_allocator_warnings_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "allocator_warnings",
            "event_id": 9,
            "warnings": [{
                "kind": "conflicting_allocator_sources",
                "chunk_addr": "0x1000",
                "user_addr": "0x1010",
                "sources": [{
                    "kind": "tcache_candidate",
                    "chunk_size": "0x30",
                    "index": 7,
                    "chunk_addr": "0x1000",
                    "user_addr": "0x1010"
                }, {
                    "kind": "fastbin",
                    "chunk_size": "0x30",
                    "index": 0,
                    "chunk_addr": "0x1000",
                    "user_addr": "0x1010"
                }],
                "message": "chunk appears in multiple allocator sources"
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(9));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("allocator warnings:"));
        assert!(formatted.contains("[conflicting_allocator_sources]"));
        assert!(formatted.contains("sources=tcache_candidate[0x30]#7,fastbin[0x30]#0"));
    }

    #[test]
    fn replay_parses_and_formats_heap_scan_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "heap_scan",
            "event_id": 9,
            "report": {
                "chunks_walked": 2,
                "allocated_observed": 1,
                "freed_observed": 1,
                "unknown_observed": 0,
                "allocator_source_chunks": 1,
                "warning_count": 1,
                "suspicious_count": 1,
                "top_validated": false,
                "heap_snapshot_truncated": false,
                "status": "suspicious",
                "findings": [{
                    "severity": "suspicious",
                    "kind": "free_list_size_mismatch",
                    "chunk_addr": "0x1000",
                    "user_addr": "0x1010",
                    "message": "fastbin[0x30] expected size 0x30 but chunk has size 0x40"
                }]
            }
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(9));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("heap scan:"));
        assert!(formatted.contains("    chunks walked:          2"));
        assert!(formatted.contains("    top chunk:              not_validated"));
        assert!(formatted.contains("[suspicious] free_list_size_mismatch chunk=0x1000 user=0x1010"));
    }

    #[test]
    fn replay_parses_and_formats_allocator_source_summary_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "allocator_source_summary",
            "event_id": 9,
            "tcache_candidate_chunks": 1,
            "fastbin_chunks": 2,
            "unsorted_chunks": 3,
            "smallbin_chunks": 4,
            "total_free_list_chunks": 4,
            "warning_count": 5
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(9));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("allocator source summary:"));
        assert!(formatted.contains("    tcache candidates: 1 chunks"));
        assert!(formatted.contains("    smallbins:         4 chunks"));
        assert!(formatted.contains("    total free-list:   4 chunks"));
        assert!(formatted.contains("    warnings:          5"));
    }

    #[test]
    fn allocator_source_delta_formatting_renders_positive_negative_and_unchanged() {
        assert_eq!(format_allocator_source_delta(2), "+2");
        assert_eq!(format_allocator_source_delta(-3), "-3");
        assert_eq!(format_allocator_source_delta(0), "unchanged");
    }

    #[test]
    fn replay_parses_and_formats_allocator_source_delta_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "allocator_source_delta",
            "event_id": 9,
            "tcache_candidate_chunks_delta": 1,
            "fastbin_chunks_delta": -2,
            "unsorted_chunks_delta": 0,
            "smallbin_chunks_delta": 2,
            "total_free_list_chunks_delta": 3,
            "warning_count_delta": 0
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(9));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("allocator delta:"));
        assert!(formatted.contains("    tcache candidates: +1"));
        assert!(formatted.contains("    fastbins:          -2"));
        assert!(formatted.contains("    unsorted bin:      unchanged"));
        assert!(formatted.contains("    smallbins:         +2"));
        assert!(formatted.contains("    total free-list:   +3"));
        assert!(formatted.contains("    warnings:          unchanged"));
    }

    #[test]
    fn replay_parses_and_formats_fastbins_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "fastbins",
            "event_id": 8,
            "arena_addr": "0x7ffff7bd3c60",
            "heads": [{
                "index": 1,
                "chunk_size": "0x30",
                "field_offset": "0x18",
                "head": "0x55555555a000",
                "points_into_heap": true,
                "matches_heap_chunk": true,
                "known_freed": true
            }],
            "chains": [{
                "index": 1,
                "chunk_size": "0x30",
                "head": "0x55555555a000",
                "nodes": [{
                    "chunk_addr": "0x55555555a000",
                    "user_addr": "0x55555555a010",
                    "encoded_next": "0x0",
                    "decoded_next": "0x0",
                    "chunk_size": "0x30",
                    "matches_heap_chunk": true,
                    "known_freed": true
                }],
                "truncated": false,
                "stopped_on_unknown_next": false,
                "cycle_detected": false
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(8));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("fastbins:"));
        assert!(formatted
            .contains("    bin[1] size=0x30 head=0x55555555a000 in_heap=yes known_freed=yes"));
        assert!(formatted.contains("        chain: 0x55555555a000 -> NULL"));
    }

    #[test]
    fn replay_parses_and_formats_regular_bins_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "regular_bins",
            "event_id": 8,
            "arena_addr": "0x7ffff7bd3c60",
            "bins_offset": "0x70",
            "heads": [{
                "index": 0,
                "glibc_bin_index": 1,
                "role": "unsorted",
                "chunk_size": null,
                "field_offset": "0x70",
                "fd": "0x7ffff7bd3cd0",
                "bk": "0x7ffff7bd3cd0",
                "empty": true,
                "fd_points_into_heap": false,
                "bk_points_into_heap": false,
                "fd_points_into_arena": true,
                "bk_points_into_arena": true,
                "fd_matches_heap_chunk": false,
                "bk_matches_heap_chunk": false,
                "fd_known_freed": null,
                "bk_known_freed": null
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(8));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("regular bins:"));
        assert!(formatted.contains("    bins_offset: 0x70"));
        assert!(formatted
            .contains("    bin[0] glibc_bin_index=1 role=unsorted fd=0x7ffff7bd3cd0 bk=0x7ffff7bd3cd0 empty=yes"));
        assert_eq!(
            format_replay_regular_bins(
                "0x1",
                "0x70",
                &[],
                &ReplayConfig {
                    events_only: true,
                    show_chunks: false,
                    tui: false,
                },
            ),
            ""
        );
    }

    #[test]
    fn replay_parses_and_formats_smallbins_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "smallbins",
            "event_id": 8,
            "arena_addr": "0x7ffff7bd3c60",
            "bins_offset": "0x70",
            "chains": [{
                "regular_index": 31,
                "glibc_bin_index": 32,
                "expected_chunk_size": "0x200",
                "sentinel_addr": "0x7ffff7bd3ec0",
                "head": "0x55555555a000",
                "tail": "0x55555555a000",
                "nodes": [{
                    "chunk_addr": "0x55555555a000",
                    "user_addr": "0x55555555a010",
                    "fd": "0x7ffff7bd3ec0",
                    "bk": "0x7ffff7bd3ec0",
                    "chunk_size": "0x200",
                    "matches_heap_chunk": true,
                    "known_freed": true,
                    "fd_points_to_sentinel": true,
                    "bk_points_to_sentinel": true
                }],
                "empty": false,
                "truncated": false,
                "stopped_on_unknown_next": false,
                "cycle_detected": false,
                "fd_bk_consistent": true
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(8));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("smallbins:"));
        assert!(formatted.contains("    bin[32] size=0x200:"));
        assert!(formatted.contains(
            "            0x55555555a000 size=0x200 fd=0x7ffff7bd3ec0 bk=0x7ffff7bd3ec0 known_freed=yes"
        ));
    }

    #[test]
    fn replay_parses_and_formats_fastbin_validation_record() {
        let record: super::json::JsonTraceRecord = serde_json::from_value(serde_json::json!({
            "type": "fastbin_validation",
            "event_id": 8,
            "validations": [{
                "index": 1,
                "chunk_size": "0x30",
                "head": "0x55555555a000",
                "head_in_heap": "yes",
                "nodes_same_size": "yes",
                "nodes_known_freed": "yes",
                "chain_complete": "yes",
                "status": "plausible"
            }]
        }))
        .unwrap();

        assert_eq!(super::replay_record_event_id(&record), Some(8));
        let formatted = format_replay_record(&record, &ReplayConfig::default());

        assert!(formatted.contains("fastbin validation:"));
        assert!(formatted.contains("    bin[1] size=0x30:"));
        assert!(formatted.contains("        status: plausible"));
    }

    #[test]
    fn replay_invalid_json_reports_line_number() {
        let path = unique_temp_path("heapify-replay-invalid");
        std::fs::write(
            &path,
            "\n{\"type\":\"event\",\"event\":{\"type\":\"malloc\",\"event_id\":1,\"requested_size\":\"0x20\",\"returned_ptr\":\"0x1000\",\"chunk\":null,\"tracker_note\":\"NewAllocation\",\"tracker_explanation\":null}}\nnot json\n",
        )
        .unwrap();

        let err = replay_trace_file(&path, &super::ReplayConfig::default()).unwrap_err();
        std::fs::remove_file(&path).unwrap();

        let message = format!("{err:#}");
        assert!(message.contains(path.to_string_lossy().as_ref()));
        assert!(message.contains(":3") || message.contains("line 3"));
    }

    #[test]
    fn replay_ignores_empty_lines() {
        let path = unique_temp_path("heapify-replay-empty-lines");
        std::fs::write(
            &path,
            "\n  \n{\"type\":\"event\",\"event\":{\"type\":\"free\",\"event_id\":2,\"ptr\":\"0x1000\",\"chunk\":null,\"tcache_entry\":null,\"tracker_note\":\"FreedKnownChunk\",\"tracker_explanation\":null}}\n",
        )
        .unwrap();

        let result = replay_trace_file(&path, &super::ReplayConfig::default());
        std::fs::remove_file(&path).unwrap();

        assert!(result.is_ok());
    }

    fn malloc_live_update(event_id: usize) -> super::LiveTraceUpdate {
        super::LiveTraceUpdate::Event {
            event_id,
            event: heapify_core::HeapTraceEvent::Malloc {
                event_id,
                requested_size: 0x20,
                returned_ptr: 0x1000 + event_id as u64,
                chunk: None,
                caller_addr: None,
            },
            note: heapify_core::tracker::HeapTrackerNote::NewAllocation,
            explanation: heapify_core::tracker::HeapTrackerExplanation::NoExtraExplanation,
            caller_symbol: None,
        }
    }

    fn test_register_snapshot(rax: u64) -> RegisterSnapshot {
        RegisterSnapshot {
            arch: RegisterArch::X86_64,
            instruction_pointer: 0x4011a5,
            stack_pointer: 0x7fffffffdc30,
            frame_pointer: 0x7fffffffdc80,
            registers: vec![
                RegisterValue {
                    name: "rip".to_string(),
                    value: 0x4011a5,
                    role: Some(RegisterRole::InstructionPointer),
                },
                RegisterValue {
                    name: "rsp".to_string(),
                    value: 0x7fffffffdc30,
                    role: Some(RegisterRole::StackPointer),
                },
                RegisterValue {
                    name: "rbp".to_string(),
                    value: 0x7fffffffdc80,
                    role: Some(RegisterRole::FramePointer),
                },
                RegisterValue {
                    name: "rax".to_string(),
                    value: rax,
                    role: Some(RegisterRole::ReturnValue),
                },
            ],
        }
    }

    fn test_register_value(name: &str, value: u64, role: RegisterRole) -> RegisterValue {
        RegisterValue {
            name: name.to_string(),
            value,
            role: Some(role),
        }
    }

    fn test_code_context(rip: u64) -> super::CodeContext {
        super::CodeContext {
            instruction_pointer: rip,
            symbol: Some("main".to_string()),
            symbol_addr: Some(0x401000),
            symbol_offset: Some(rip.saturating_sub(0x401000)),
            object: Some("target".to_string()),
            source: Some(SourceLocation {
                file: Some("src/main.c".to_string()),
                line: Some(42),
                column: Some(7),
            }),
            disassembly: Some(super::DisassemblySnapshot {
                instruction_pointer: rip,
                start_address: rip,
                end_address: rip + 1,
                lines: vec![super::DisassemblyLine {
                    address: rip,
                    bytes: vec![0x90],
                    mnemonic: "nop".to_string(),
                    operands: String::new(),
                    text: "nop".to_string(),
                    is_current: true,
                    flow_control: None,
                    target: None,
                    target_annotation: None,
                }],
                truncated_before: false,
                truncated_after: false,
                read_error: None,
            }),
        }
    }

    fn test_stack_snapshot(values: &[u64]) -> StackSnapshot {
        StackSnapshot {
            stack_pointer: 0x7fffffffdc30,
            word_size: 8,
            words: values
                .iter()
                .enumerate()
                .map(|(index, value)| StackWord {
                    offset_from_sp: (index as i64) * 8,
                    address: 0x7fffffffdc30 + (index as u64) * 8,
                    value: *value,
                    annotation: None,
                })
                .collect(),
            truncated: false,
            read_error: None,
        }
    }

    fn test_process_maps() -> ProcessMapsSnapshot {
        ProcessMapsSnapshot {
            entries: vec![
                ProcessMapEntry {
                    start: 0x555555554000,
                    end: 0x555555556000,
                    permissions: "r-xp".to_string(),
                    offset: 0,
                    device: Some("08:20".to_string()),
                    inode: Some(11),
                    pathname: Some("/tmp/heapify-target".to_string()),
                },
                ProcessMapEntry {
                    start: 0x555555559000,
                    end: 0x55555557a000,
                    permissions: "rw-p".to_string(),
                    offset: 0,
                    device: Some("00:00".to_string()),
                    inode: Some(0),
                    pathname: Some("[heap]".to_string()),
                },
                ProcessMapEntry {
                    start: 0x7ffff7dd5000,
                    end: 0x7ffff7f9d000,
                    permissions: "r-xp".to_string(),
                    offset: 0x26000,
                    device: Some("08:20".to_string()),
                    inode: Some(12),
                    pathname: Some("/usr/lib/x86_64-linux-gnu/libc.so.6".to_string()),
                },
                ProcessMapEntry {
                    start: 0x7ffff7fc0000,
                    end: 0x7ffff7ffb000,
                    permissions: "r-xp".to_string(),
                    offset: 0,
                    device: Some("08:20".to_string()),
                    inode: Some(13),
                    pathname: Some("/usr/lib64/ld-linux-x86-64.so.2".to_string()),
                },
                ProcessMapEntry {
                    start: 0x7ffffffde000,
                    end: 0x7ffffffff000,
                    permissions: "rw-p".to_string(),
                    offset: 0,
                    device: Some("00:00".to_string()),
                    inode: Some(0),
                    pathname: Some("[stack]".to_string()),
                },
                ProcessMapEntry {
                    start: 0x7ffff7ffe000,
                    end: 0x7ffff7fff000,
                    permissions: "r-xp".to_string(),
                    offset: 0,
                    device: Some("00:00".to_string()),
                    inode: Some(0),
                    pathname: Some("[vdso]".to_string()),
                },
                ProcessMapEntry {
                    start: 0x7ffff7ffc000,
                    end: 0x7ffff7ffd000,
                    permissions: "r--p".to_string(),
                    offset: 0,
                    device: Some("00:00".to_string()),
                    inode: Some(0),
                    pathname: Some("[vvar]".to_string()),
                },
            ],
        }
    }

    #[test]
    fn live_tui_app_session_start_stores_metadata() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::SessionStart(
            super::JsonSessionStart {
                record: session_start_record(),
            },
        ));

        assert!(app.session_start.is_some());
        assert_eq!(app.status_line, "tracing...");
    }

    #[test]
    fn live_tui_app_event_appends_and_follow_tail_selects_newest() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(malloc_live_update(1));
        app.apply_update(malloc_live_update(2));

        assert_eq!(app.events.len(), 2);
        assert_eq!(app.selected_index, 1);
        assert!(app.follow_tail);
    }

    #[test]
    fn live_tui_app_stores_latest_register_snapshot() {
        let mut app = super::LiveTuiApp::default();
        let snapshot = test_register_snapshot(0xd972a0);

        app.apply_update(super::LiveTraceUpdate::RegisterSnapshot {
            event_id: None,
            snapshot: snapshot.clone(),
        });

        assert_eq!(app.latest_register_snapshot, Some(snapshot));
        assert!(app.register_snapshots_by_event_id.is_empty());
        assert!(app.previous_register_snapshot.is_none());
        assert!(app.changed_registers.is_empty());
    }

    #[test]
    fn live_tui_app_stores_event_specific_register_snapshot() {
        let mut app = super::LiveTuiApp::default();
        let snapshot = test_register_snapshot(0xd972a0);

        app.apply_update(super::LiveTraceUpdate::RegisterSnapshot {
            event_id: Some(7),
            snapshot: snapshot.clone(),
        });

        assert_eq!(app.latest_register_snapshot, Some(snapshot.clone()));
        assert_eq!(app.register_snapshots_by_event_id.get(&7), Some(&snapshot));
    }

    #[test]
    fn build_minimal_code_context_sets_rip() {
        let context = super::build_minimal_code_context(0x4011a5);

        assert_eq!(context.instruction_pointer, 0x4011a5);
        assert_eq!(context.symbol, None);
        assert_eq!(context.object, None);
    }

    #[test]
    fn format_code_context_lines_renders_rip() {
        let context = test_code_context(0x4011a5);

        let rendered = super::format_code_context_lines(&context).join("\n");

        assert!(rendered.contains("RIP:     0x00000000004011a5"));
    }

    #[test]
    fn format_code_context_lines_renders_unavailable_fields() {
        let context = super::build_minimal_code_context(0x4011a5);

        let rendered = super::format_code_context_lines(&context).join("\n");

        assert!(rendered.contains("Symbol:  unavailable"));
        assert!(rendered.contains("Source:  unavailable"));
        assert!(rendered.contains("Object:  unavailable"));
    }

    #[test]
    fn format_code_context_lines_renders_disassembly_placeholder() {
        let context = super::build_minimal_code_context(0x4011a5);

        let rendered = super::format_code_context_lines(&context).join("\n");

        assert!(rendered.contains("Disassembly:"));
        assert!(rendered.contains("> 0x00000000004011a5  <disassembly unavailable>"));
    }

    #[test]
    fn code_context_retains_metadata_when_disassembly_capture_fails() {
        let context = super::build_code_context(super::Pid::from_raw(-1), 0x4011a5, None, None);

        assert_eq!(context.instruction_pointer, 0x4011a5);
        assert_eq!(context.symbol, None);
        let disassembly = context.disassembly.unwrap();
        assert!(disassembly.lines.is_empty());
        assert!(disassembly.read_error.is_some());
    }

    #[test]
    fn live_tui_app_stores_latest_code_context() {
        let mut app = super::LiveTuiApp::default();
        let context = test_code_context(0x4011a5);

        app.apply_update(super::LiveTraceUpdate::CodeContext {
            event_id: None,
            context: context.clone(),
        });

        assert_eq!(app.latest_code_context, Some(context));
        assert!(app.code_context_by_event_id.is_empty());
    }

    #[test]
    fn live_tui_app_stores_event_specific_code_context() {
        let mut app = super::LiveTuiApp::default();
        let context = test_code_context(0x4011a5);

        app.apply_update(super::LiveTraceUpdate::CodeContext {
            event_id: Some(7),
            context: context.clone(),
        });

        assert_eq!(app.latest_code_context, Some(context.clone()));
        assert_eq!(app.code_context_by_event_id.get(&7), Some(&context));
    }

    #[test]
    fn format_stack_snapshot_lines_renders_rsp() {
        let snapshot = test_stack_snapshot(&[0x4011a5]);

        let rendered = super::format_stack_snapshot_lines(&snapshot).join("\n");

        assert!(rendered.contains("RSP:       0x00007fffffffdc30"));
    }

    #[test]
    fn format_stack_snapshot_lines_renders_stack_rows() {
        let snapshot = test_stack_snapshot(&[0x4011a5, 0xd972a0]);

        let rendered = super::format_stack_snapshot_lines(&snapshot).join("\n");

        assert!(rendered.contains("+0x000  0x00007fffffffdc30  0x00000000004011a5"));
        assert!(rendered.contains("+0x008  0x00007fffffffdc38  0x0000000000d972a0"));
    }

    #[test]
    fn format_stack_snapshot_lines_renders_truncated_warning() {
        let mut snapshot = test_stack_snapshot(&[0x4011a5]);
        snapshot.truncated = true;
        snapshot.read_error = Some("failed to read word".to_string());

        let rendered = super::format_stack_snapshot_lines(&snapshot).join("\n");

        assert!(rendered.contains("truncated: failed to read word"));
    }

    #[test]
    fn stack_annotation_marks_heap_user_pointer() {
        let layout = layout_record_with_chunks(1, &[(0x1000, 0x1010)]);

        let annotation = super::annotate_stack_value(0x1010, None, Some(&layout), None);

        assert_eq!(annotation.as_deref(), Some("heap user"));
    }

    #[test]
    fn stack_annotation_marks_interior_heap_pointer() {
        let layout = layout_record_with_chunks(1, &[(0x1000, 0x1010)]);

        let annotation = super::annotate_stack_value(0x1020, None, Some(&layout), None);

        assert_eq!(annotation.as_deref(), Some("heap"));
    }

    #[test]
    fn stack_annotation_marks_current_rip() {
        let annotation = super::annotate_stack_value(0x4011a5, None, None, Some(0x4011a5));

        assert_eq!(annotation.as_deref(), Some("rip"));
    }

    #[test]
    fn stack_annotation_uses_classifier_for_code_and_stack_maps() {
        let maps = test_process_maps();

        let code = super::annotate_stack_value(0x555555555000, Some(&maps), None, None);
        let stack = super::annotate_stack_value(0x7fffffffe000, Some(&maps), None, None);

        assert_eq!(code.as_deref(), Some("code"));
        assert_eq!(stack.as_deref(), Some("stack"));
    }

    #[test]
    fn live_tui_app_stores_latest_stack_snapshot() {
        let mut app = super::LiveTuiApp::default();
        let snapshot = test_stack_snapshot(&[0x4011a5]);

        app.apply_update(super::LiveTraceUpdate::StackSnapshot {
            event_id: None,
            snapshot: snapshot.clone(),
        });

        assert_eq!(app.latest_stack_snapshot, Some(snapshot));
        assert!(app.stack_snapshots_by_event_id.is_empty());
    }

    #[test]
    fn live_tui_app_stores_event_specific_stack_snapshot() {
        let mut app = super::LiveTuiApp::default();
        let snapshot = test_stack_snapshot(&[0x4011a5]);

        app.apply_update(super::LiveTraceUpdate::StackSnapshot {
            event_id: Some(7),
            snapshot: snapshot.clone(),
        });

        assert_eq!(app.latest_stack_snapshot, Some(snapshot.clone()));
        assert_eq!(app.stack_snapshots_by_event_id.get(&7), Some(&snapshot));
    }

    #[test]
    fn classify_address_finds_heap_user_pointer() {
        let layout = layout_record_with_chunks(1, &[(0x1000, 0x1010)]);

        let classification = super::classify_address(0x1010, None, Some(&layout));

        assert_eq!(classification.kind, super::AddressRegionKind::Heap);
        assert_eq!(classification.label, "heap user");
        assert!(matches!(
            classification.heap_detail,
            Some(super::HeapAddressDetail::UserPointer { .. })
        ));
    }

    #[test]
    fn classify_address_finds_heap_chunk_header() {
        let layout = layout_record_with_chunks(1, &[(0x1000, 0x1010)]);

        let classification = super::classify_address(0x1000, None, Some(&layout));

        assert_eq!(classification.kind, super::AddressRegionKind::Heap);
        assert_eq!(classification.label, "heap chunk");
        assert!(matches!(
            classification.heap_detail,
            Some(super::HeapAddressDetail::ChunkHeader { .. })
        ));
    }

    #[test]
    fn classify_address_finds_heap_interior_pointer() {
        let layout = layout_record_with_chunks(1, &[(0x1000, 0x1010)]);

        let classification = super::classify_address(0x1020, None, Some(&layout));

        assert_eq!(classification.kind, super::AddressRegionKind::Heap);
        assert_eq!(classification.label, "heap+0x10");
        assert!(matches!(
            classification.heap_detail,
            Some(super::HeapAddressDetail::Interior { offset: 0x10, .. })
        ));
    }

    #[test]
    fn classify_address_finds_heap_map() {
        let maps = test_process_maps();

        let classification = super::classify_address(0x55555555a000, Some(&maps), None);

        assert_eq!(classification.kind, super::AddressRegionKind::Heap);
        assert_eq!(classification.label, "heap");
    }

    #[test]
    fn classify_address_finds_stack_map() {
        let maps = test_process_maps();

        let classification = super::classify_address(0x7fffffffe000, Some(&maps), None);

        assert_eq!(classification.kind, super::AddressRegionKind::Stack);
        assert_eq!(classification.label, "stack");
    }

    #[test]
    fn classify_address_classifies_libc_pathname() {
        let maps = test_process_maps();

        let classification = super::classify_address(0x7ffff7de0000, Some(&maps), None);

        assert_eq!(classification.kind, super::AddressRegionKind::Libc);
        assert_eq!(classification.label, "libc");
    }

    #[test]
    fn classify_address_classifies_ld_linux_pathname() {
        let maps = test_process_maps();

        let classification = super::classify_address(0x7ffff7fc1000, Some(&maps), None);

        assert_eq!(classification.kind, super::AddressRegionKind::Loader);
        assert_eq!(classification.label, "loader");
    }

    #[test]
    fn classify_address_classifies_vdso_and_vvar() {
        let maps = test_process_maps();

        let vdso = super::classify_address(0x7ffff7ffe010, Some(&maps), None);
        let vvar = super::classify_address(0x7ffff7ffc010, Some(&maps), None);

        assert_eq!(vdso.kind, super::AddressRegionKind::Vdso);
        assert_eq!(vdso.label, "vdso");
        assert_eq!(vvar.kind, super::AddressRegionKind::Vvar);
        assert_eq!(vvar.label, "vvar");
    }

    #[test]
    fn classify_address_returns_unknown_for_unmapped_address() {
        let maps = test_process_maps();

        let classification = super::classify_address(0xdeadbeef, Some(&maps), None);

        assert_eq!(classification.kind, super::AddressRegionKind::Unknown);
        assert_eq!(classification.label, "unmapped");
    }

    #[test]
    fn format_process_map_entry_renders_range_permissions_and_path() {
        let entry = &test_process_maps().entries[0];

        let rendered = super::format_process_map_entry(entry);

        assert!(rendered.contains("0000555555554000-0000555555556000"));
        assert!(rendered.contains("r-xp"));
        assert!(rendered.contains("/tmp/heapify-target"));
    }

    #[test]
    fn live_tui_app_stores_latest_process_maps() {
        let mut app = super::LiveTuiApp::default();
        let snapshot = test_process_maps();

        app.apply_update(super::LiveTraceUpdate::ProcessMaps {
            snapshot: snapshot.clone(),
        });

        assert_eq!(app.latest_process_maps, Some(snapshot));
    }

    #[test]
    fn maps_tab_renders_unavailable_without_maps() {
        let app = super::LiveTuiApp::default();

        assert_eq!(
            super::format_live_maps_tab(&app),
            "process maps unavailable"
        );
    }

    #[test]
    fn maps_tab_renders_formatted_map_lines() {
        let mut app = super::LiveTuiApp::default();
        app.latest_process_maps = Some(test_process_maps());

        let rendered = super::format_live_maps_tab(&app);

        assert!(rendered.contains("Start-End"));
        assert!(rendered.contains("[stack]"));
        assert!(rendered.contains("libc.so.6"));
    }

    #[test]
    fn live_tui_scrolls_maps_tab() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        app.focused_debugger_pane = super::LiveDebuggerPane::RightTab;
        app.active_right_tab = super::LiveRightTab::Maps;
        app.latest_process_maps = Some(ProcessMapsSnapshot {
            entries: (0..20)
                .map(|index| ProcessMapEntry {
                    start: 0x1000 + index * 0x1000,
                    end: 0x2000 + index * 0x1000,
                    permissions: "r--p".to_string(),
                    offset: 0,
                    device: Some("00:00".to_string()),
                    inode: Some(index),
                    pathname: Some(format!("/tmp/map-{index}")),
                })
                .collect(),
        });
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::PageDown,
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);

        assert_eq!(app.maps_tab_scroll, 10);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_stack_tab_renders_unavailable_without_snapshot() {
        let app = super::LiveTuiApp::default();

        assert_eq!(
            super::format_live_stack_tab(&app),
            "stack snapshot unavailable"
        );
    }

    #[test]
    fn live_stack_tab_renders_rows_with_snapshot() {
        let mut app = super::LiveTuiApp::default();
        app.latest_stack_snapshot = Some(test_stack_snapshot(&[0x4011a5]));

        let rendered = super::format_live_stack_tab(&app);

        assert!(rendered.contains("RSP:       0x00007fffffffdc30"));
        assert!(rendered.contains("+0x000  0x00007fffffffdc30  0x00000000004011a5"));
    }

    #[test]
    fn live_tui_scrolls_stack_tab() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        app.focused_debugger_pane = super::LiveDebuggerPane::RightTab;
        app.active_right_tab = super::LiveRightTab::Stack;
        app.latest_stack_snapshot = Some(test_stack_snapshot(&(0..20).collect::<Vec<_>>()));
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::PageDown,
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);

        assert_eq!(app.stack_tab_scroll, 10);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_code_pane_renders_unavailable_without_context() {
        let app = super::LiveTuiApp::default();

        assert_eq!(
            super::format_live_code_context(&app),
            "code context unavailable"
        );
    }

    #[test]
    fn live_code_pane_renders_context_with_rip_symbol_source() {
        let mut app = super::LiveTuiApp::default();
        app.latest_code_context = Some(test_code_context(0x4011a5));

        let rendered = super::format_live_code_context(&app);

        assert!(rendered.contains("RIP:     0x00000000004011a5"));
        assert!(rendered.contains("Symbol:  main+0x1a5 (target)"));
        assert!(rendered.contains("Source:  src/main.c:42:7"));
    }

    #[test]
    fn live_tui_scrolls_code_pane() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        app.focused_debugger_pane = super::LiveDebuggerPane::Code;
        let mut context = test_code_context(0x401000);
        context.disassembly = Some(super::DisassemblySnapshot {
            instruction_pointer: 0x401000,
            start_address: 0x401000,
            end_address: 0x401014,
            lines: (0..20)
                .map(|index| super::DisassemblyLine {
                    address: 0x401000 + index,
                    bytes: vec![0x90],
                    mnemonic: "nop".to_string(),
                    operands: String::new(),
                    text: format!("line {index}"),
                    is_current: index == 0,
                    flow_control: None,
                    target: None,
                    target_annotation: None,
                })
                .collect(),
            truncated_before: false,
            truncated_after: false,
            read_error: None,
        });
        app.latest_code_context = Some(context);
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::PageDown,
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);

        assert_eq!(app.code_pane_scroll, 10);
        assert!(!app.code_follow_rip);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn code_follow_rip_is_enabled_initially() {
        let app = super::LiveTuiApp::default();

        assert!(app.code_follow_rip);
    }

    #[test]
    fn live_tui_d_recenters_code_pane_and_enables_follow() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        app.focused_debugger_pane = super::LiveDebuggerPane::Code;
        app.code_follow_rip = false;
        app.code_pane_scroll = 99;
        app.latest_code_context = Some(test_code_context(0x4011a5));
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('d'),
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(app.code_follow_rip);
        assert!(app.code_pane_scroll < 99);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn parse_console_command_disassemble_aliases() {
        for input in ["disas", "disassemble"] {
            assert_eq!(
                super::parse_console_command(input),
                super::ConsoleCommand::Disassemble
            );
        }
    }

    #[test]
    fn console_disas_focuses_code_and_recenters() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        app.code_follow_rip = false;
        app.code_pane_scroll = 42;
        app.latest_code_context = Some(test_code_context(0x4011a5));

        let should_exit = super::execute_console_command(
            &mut app,
            super::ConsoleCommand::Disassemble,
            "disas",
            false,
            &sender,
        );

        assert!(!should_exit);
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::Code);
        assert!(app.code_follow_rip);
        assert!(app.code_pane_scroll < 42);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn format_code_context_lines_renders_bytes_and_target_annotation() {
        let mut context = test_code_context(0x4011a5);
        let disassembly = context.disassembly.as_mut().unwrap();
        disassembly.lines[0].bytes = vec![0xe8, 0x8a, 0xfe, 0xff, 0xff];
        disassembly.lines[0].mnemonic = "call".to_string();
        disassembly.lines[0].operands = "0x401030".to_string();
        disassembly.lines[0].text = "call 0x401030".to_string();
        disassembly.lines[0].flow_control = Some(super::DisassemblyFlowControl::Call);
        disassembly.lines[0].target = Some(0x401030);
        disassembly.lines[0].target_annotation = Some("malloc@plt".to_string());

        let rendered = super::format_code_context_lines(&context).join("\n");

        assert!(rendered.contains("e8 8a fe ff ff"));
        assert!(rendered.contains("call"));
        assert!(rendered.contains("0x401030"));
        assert!(rendered.contains("<malloc@plt>"));
    }

    #[test]
    fn diff_register_snapshots_without_previous_returns_empty() {
        let current = test_register_snapshot(0xd972a0);

        assert!(super::diff_register_snapshots(None, &current).is_empty());
    }

    #[test]
    fn diff_register_snapshots_detects_changed_rax() {
        let previous = test_register_snapshot(0x1);
        let current = test_register_snapshot(0x2);

        let changed = super::diff_register_snapshots(Some(&previous), &current);

        assert!(changed.contains("rax"));
        assert!(!changed.contains("rip"));
    }

    #[test]
    fn diff_register_snapshots_detects_new_register() {
        let previous = test_register_snapshot(0x1);
        let mut current = test_register_snapshot(0x1);
        current
            .registers
            .push(test_register_value("R10", 0x10, RegisterRole::General));

        let changed = super::diff_register_snapshots(Some(&previous), &current);

        assert!(changed.contains("r10"));
    }

    #[test]
    fn register_rendering_uses_stable_order() {
        let snapshot = RegisterSnapshot {
            arch: RegisterArch::X86_64,
            instruction_pointer: 0x4011a5,
            stack_pointer: 0x7fffffffdc30,
            frame_pointer: 0x7fffffffdc80,
            registers: vec![
                test_register_value("rax", 0x1, RegisterRole::ReturnValue),
                test_register_value("rip", 0x2, RegisterRole::InstructionPointer),
                test_register_value("r9", 0x3, RegisterRole::Argument),
                test_register_value("rsp", 0x4, RegisterRole::StackPointer),
            ],
        };

        let lines = super::render_register_lines(&snapshot, &BTreeSet::new(), None, None, None);
        let names = lines
            .iter()
            .map(|line| line.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["RIP", "RSP", "RAX", "R9"]);
    }

    #[test]
    fn register_rendering_marks_changed_registers() {
        let snapshot = test_register_snapshot(0xd972a0);
        let changed = BTreeSet::from(["rax".to_string()]);

        let lines = super::render_register_lines(&snapshot, &changed, None, None, None);

        assert!(lines.iter().any(|line| line.name == "RAX" && line.changed));
        assert!(lines.iter().any(|line| line.name == "RIP" && !line.changed));
    }

    #[test]
    fn register_rendering_annotates_exact_heap_user_pointer() {
        let snapshot = test_register_snapshot(0x1010);
        let layout = layout_record_with_chunks(1, &[(0x1000, 0x1010)]);

        let lines =
            super::render_register_lines(&snapshot, &BTreeSet::new(), None, Some(&layout), None);

        assert_eq!(
            lines
                .iter()
                .find(|line| line.name == "RAX")
                .and_then(|line| line.annotation.as_deref()),
            Some("heap user")
        );
    }

    #[test]
    fn register_rendering_annotates_interior_heap_pointer() {
        let snapshot = test_register_snapshot(0x1020);
        let layout = layout_record_with_chunks(1, &[(0x1000, 0x1010)]);

        let lines =
            super::render_register_lines(&snapshot, &BTreeSet::new(), None, Some(&layout), None);

        assert_eq!(
            lines
                .iter()
                .find(|line| line.name == "RAX")
                .and_then(|line| line.annotation.as_deref()),
            Some("heap")
        );
    }

    #[test]
    fn register_rendering_uses_classifier_for_stack_and_libc_maps() {
        let mut snapshot = test_register_snapshot(0x7fffffffe000);
        snapshot.registers.push(test_register_value(
            "r10",
            0x7ffff7de0000,
            RegisterRole::General,
        ));
        let maps = test_process_maps();

        let lines =
            super::render_register_lines(&snapshot, &BTreeSet::new(), Some(&maps), None, None);

        assert_eq!(
            lines
                .iter()
                .find(|line| line.name == "RAX")
                .and_then(|line| line.annotation.as_deref()),
            Some("stack")
        );
        assert_eq!(
            lines
                .iter()
                .find(|line| line.name == "R10")
                .and_then(|line| line.annotation.as_deref()),
            Some("libc")
        );
    }

    #[test]
    fn live_tui_app_register_update_tracks_previous_and_changed() {
        let mut app = super::LiveTuiApp::default();
        let first = test_register_snapshot(0x1);
        let second = test_register_snapshot(0x2);

        app.apply_update(super::LiveTraceUpdate::RegisterSnapshot {
            event_id: None,
            snapshot: first.clone(),
        });
        app.apply_update(super::LiveTraceUpdate::RegisterSnapshot {
            event_id: None,
            snapshot: second.clone(),
        });

        assert_eq!(app.previous_register_snapshot, Some(first));
        assert_eq!(app.latest_register_snapshot, Some(second));
        assert_eq!(app.changed_registers, BTreeSet::from(["rax".to_string()]));
    }

    #[test]
    fn live_registers_pane_renders_unavailable_without_snapshot() {
        let app = super::LiveTuiApp::default();

        assert_eq!(
            super::format_live_registers_pane(&app),
            "registers unavailable"
        );
    }

    #[test]
    fn live_registers_pane_renders_summary_with_snapshot() {
        let mut app = super::LiveTuiApp::default();
        app.latest_register_snapshot = Some(test_register_snapshot(0xd972a0));

        let rendered = super::format_live_registers_pane(&app);

        assert!(rendered.contains("RIP     0x00000000004011a5"));
        assert!(rendered.contains("RAX     0x0000000000d972a0"));
    }

    #[test]
    fn live_tui_log_buffer_is_bounded() {
        let mut app = super::LiveTuiApp::default();

        for index in 0..250 {
            app.push_log_line(format!("line {index}"));
        }

        assert_eq!(app.logs.len(), 200);
        assert_eq!(app.logs.front().map(String::as_str), Some("line 50"));
        assert_eq!(app.logs.back().map(String::as_str), Some("line 249"));
    }

    #[test]
    fn live_tui_command_status_appends_log_line() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::CommandStatus {
            command_id: Some(super::LiveCommandId(7)),
            command: Some(super::LiveCommand::Pause),
            status: super::LiveCommandStatus::Completed,
            target_status: super::LiveTargetStatus::Paused,
            message: "target paused; inspect panes or resume".to_string(),
        });

        assert!(app
            .logs
            .back()
            .unwrap()
            .contains("pause: target paused; inspect panes or resume (completed)"));
    }

    #[test]
    fn live_tui_break_matched_appends_log_line() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::BreakMatched(
            super::AllocatorBreakMatch {
                condition: super::AllocatorBreakCondition::DoubleFree,
                event_id: 9,
                user_addr: None,
                message: "possible double free".to_string(),
            },
        ));

        assert!(app
            .logs
            .back()
            .unwrap()
            .contains("break condition matched: possible double free after event #9"));
    }

    #[test]
    fn live_tui_focus_next_cycles_debugger_panes() {
        let mut app = super::LiveTuiApp::default();

        app.focus_next_pane();
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::Console);
        app.focus_next_pane();
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::RightTab);
        app.focus_next_pane();
        assert_eq!(
            app.focused_debugger_pane,
            super::LiveDebuggerPane::Registers
        );
        app.focus_next_pane();
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::Code);
        app.focus_next_pane();
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::Trace);
    }

    #[test]
    fn live_tui_number_keys_switch_right_tabs() {
        let mut app = super::LiveTuiApp::default();
        let (sender, _) = std::sync::mpsc::channel();

        for (key, expected) in [
            ('2', super::LiveRightTab::Stack),
            ('3', super::LiveRightTab::Logs),
            ('4', super::LiveRightTab::Maps),
            ('1', super::LiveRightTab::Heap),
        ] {
            let key = crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char(key),
                crossterm::event::KeyModifiers::NONE,
            );
            super::handle_live_tui_key(key, &mut app, false, &sender);
            assert_eq!(app.active_right_tab, expected);
            assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::RightTab);
        }
    }

    #[test]
    fn live_tui_brackets_switch_right_tabs() {
        let mut app = super::LiveTuiApp::default();
        let (sender, _) = std::sync::mpsc::channel();
        let next = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(']'),
            crossterm::event::KeyModifiers::NONE,
        );
        let previous = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('['),
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(next, &mut app, false, &sender);
        assert_eq!(app.active_right_tab, super::LiveRightTab::Stack);

        super::handle_live_tui_key(previous, &mut app, false, &sender);
        assert_eq!(app.active_right_tab, super::LiveRightTab::Heap);
    }

    #[test]
    fn clamp_scroll_handles_short_content() {
        assert_eq!(super::clamp_scroll(20, 3, 10), 0);
        assert_eq!(super::clamp_scroll(20, 30, 10), 20);
        assert_eq!(super::clamp_scroll(25, 30, 10), 20);
    }

    #[test]
    fn live_tui_app_manual_selection_disables_follow_tail() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(malloc_live_update(1));
        app.apply_update(malloc_live_update(2));

        app.select_previous();

        assert_eq!(app.selected_index, 0);
        assert!(!app.follow_tail);
    }

    #[test]
    fn live_tui_event_navigation_down_keeps_follow_tail_disabled() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(malloc_live_update(1));
        app.apply_update(malloc_live_update(2));
        app.select_first();

        app.select_next();

        assert_eq!(app.selected_index, 1);
        assert!(!app.follow_tail);
    }

    #[test]
    fn live_tui_event_navigation_end_enables_follow_tail() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(malloc_live_update(1));
        app.apply_update(malloc_live_update(2));
        app.select_first();

        app.select_latest();

        assert_eq!(app.selected_index, 1);
        assert!(app.follow_tail);
    }

    #[test]
    fn live_tui_app_related_record_groups_by_event_id() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 7,
            record: layout_record(7),
        });

        assert_eq!(app.related_by_event_id.get(&7).unwrap().len(), 1);
    }

    #[test]
    fn live_tui_app_related_record_stores_latest_heap_layout() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 7,
            record: layout_record(7),
        });

        assert!(matches!(
            app.latest_heap_layout,
            Some(super::json::JsonTraceRecord::HeapLayout { event_id: 7, .. })
        ));
    }

    #[test]
    fn live_tui_app_related_record_stores_latest_allocator_summary() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 7,
            record: allocator_source_summary_record(7),
        });

        assert!(matches!(
            app.latest_allocator_summary,
            Some(super::json::JsonTraceRecord::AllocatorSourceSummary { event_id: 7, .. })
        ));
    }

    #[test]
    fn live_tui_app_related_record_stores_latest_allocator_delta() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 7,
            record: allocator_source_delta_record(7),
        });

        assert!(matches!(
            app.latest_allocator_delta,
            Some(super::json::JsonTraceRecord::AllocatorSourceDelta { event_id: 7, .. })
        ));
    }

    #[test]
    fn live_tui_app_related_record_stores_latest_heap_scan() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 7,
            record: heap_scan_record(7),
        });

        assert!(matches!(
            app.latest_heap_scan,
            Some(super::json::JsonTraceRecord::HeapScan { event_id: 7, .. })
        ));
    }

    #[test]
    fn live_tui_apply_update_clamps_scroll_when_content_changes() {
        let mut app = super::LiveTuiApp::default();
        app.heap_layout_scroll = 99;

        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 7,
            record: layout_record(7),
        });

        assert_eq!(app.heap_layout_scroll, 0);
    }

    #[test]
    fn live_tui_app_session_end_stores_status() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::SessionEnd(super::JsonSessionEnd {
            record: session_end_record(3),
        }));

        assert!(app.session_end.is_some());
        assert!(app
            .status_line
            .contains("target exited: unknown; 3 events; press q to quit"));
        assert_eq!(
            app.latest_stop_reason,
            Some(super::DebuggerStopReason::ProcessExit {
                status: "unknown".to_string()
            })
        );
    }

    #[test]
    fn live_tui_app_status_update_sets_message_and_state() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::Status {
            message: "target paused".to_string(),
        });

        assert_eq!(app.status_line, "target paused");
        assert_eq!(app.target_status, super::LiveTargetStatus::Running);
    }

    #[test]
    fn live_tui_command_status_update_sets_state_and_message() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::CommandStatus {
            command_id: Some(super::LiveCommandId(7)),
            command: Some(super::LiveCommand::Pause),
            status: super::LiveCommandStatus::Completed,
            target_status: super::LiveTargetStatus::Paused,
            message: "target paused; inspect panes or resume".to_string(),
        });

        assert_eq!(app.target_status, super::LiveTargetStatus::Paused);
        assert!(app.inspection_mode());
        assert_eq!(app.last_command, Some(super::LiveCommand::Pause));
        assert_eq!(
            app.last_command_status,
            Some(super::LiveCommandStatus::Completed)
        );
        assert_eq!(
            app.status_line,
            "target paused; inspect panes or resume".to_string()
        );
        assert_eq!(
            app.latest_stop_reason,
            Some(super::DebuggerStopReason::UserPause)
        );
    }

    #[test]
    fn live_command_validation_rules_are_stable() {
        assert!(super::validate_live_command(
            super::LiveTargetStatus::Running,
            super::LiveCommand::Pause
        )
        .is_ok());
        assert!(super::validate_live_command(
            super::LiveTargetStatus::Paused,
            super::LiveCommand::Resume
        )
        .is_ok());
        assert!(super::validate_live_command(
            super::LiveTargetStatus::Paused,
            super::LiveCommand::Continue
        )
        .is_ok());
        assert!(super::validate_live_command(
            super::LiveTargetStatus::Paused,
            super::LiveCommand::StepAllocatorEvent
        )
        .is_ok());
        assert!(super::validate_live_command(
            super::LiveTargetStatus::Paused,
            super::LiveCommand::StepInstruction
        )
        .is_ok());
        assert!(super::validate_live_command(
            super::LiveTargetStatus::Paused,
            super::LiveCommand::StepInstructionOver
        )
        .is_ok());
        for status in [
            super::LiveTargetStatus::NotStarted,
            super::LiveTargetStatus::Running,
            super::LiveTargetStatus::SteppingToNextAllocatorEvent,
            super::LiveTargetStatus::SteppingInstruction,
            super::LiveTargetStatus::SteppingInstructionOver,
            super::LiveTargetStatus::Stopping,
            super::LiveTargetStatus::Exited,
        ] {
            assert!(
                super::validate_live_command(status, super::LiveCommand::StepInstruction).is_err()
            );
            assert!(
                super::validate_live_command(status, super::LiveCommand::StepInstructionOver)
                    .is_err()
            );
        }
        assert!(super::validate_live_command(
            super::LiveTargetStatus::Exited,
            super::LiveCommand::Stop
        )
        .is_err());
        assert!(super::validate_live_command(
            super::LiveTargetStatus::Running,
            super::LiveCommand::StepAllocatorEvent
        )
        .is_err());
    }

    #[test]
    fn live_tui_prepare_command_assigns_increasing_ids() {
        let mut app = super::LiveTuiApp::default();

        let first = app.prepare_command(super::LiveCommand::Pause).unwrap();
        let second = app.prepare_command(super::LiveCommand::Stop).unwrap();

        assert_eq!(first.id, super::LiveCommandId(1));
        assert_eq!(second.id, super::LiveCommandId(2));
        assert_eq!(first.command, super::LiveCommand::Pause);
        assert_eq!(second.command, super::LiveCommand::Stop);
    }

    #[test]
    fn live_tui_prepare_command_rejects_step_while_running() {
        let mut app = super::LiveTuiApp::default();

        let result = app.prepare_command(super::LiveCommand::StepAllocatorEvent);

        assert!(result.is_err());
        assert_eq!(
            app.last_command,
            Some(super::LiveCommand::StepAllocatorEvent)
        );
        assert_eq!(
            app.last_command_status,
            Some(super::LiveCommandStatus::Rejected)
        );
        assert!(app.status_line.contains("not allowed"));
    }

    #[test]
    fn parse_console_command_help_aliases() {
        assert_eq!(
            super::parse_console_command("help"),
            super::ConsoleCommand::Help
        );
        assert_eq!(
            super::parse_console_command("h"),
            super::ConsoleCommand::Help
        );
        assert_eq!(
            super::parse_console_command("?"),
            super::ConsoleCommand::Help
        );
    }

    #[test]
    fn parse_console_command_continue_aliases() {
        assert_eq!(
            super::parse_console_command("continue"),
            super::ConsoleCommand::Continue
        );
        assert_eq!(
            super::parse_console_command("c"),
            super::ConsoleCommand::Continue
        );
        assert_eq!(
            super::parse_console_command("run"),
            super::ConsoleCommand::Continue
        );
    }

    #[test]
    fn parse_console_command_next_allocator_aliases() {
        for input in ["next", "n", "next-alloc", "next_allocator_event"] {
            assert_eq!(
                super::parse_console_command(input),
                super::ConsoleCommand::NextAllocatorEvent
            );
        }
    }

    #[test]
    fn parse_console_command_step_instruction_aliases() {
        for input in ["stepi", "si", "step"] {
            assert_eq!(
                super::parse_console_command(input),
                super::ConsoleCommand::StepInstruction
            );
        }
    }

    #[test]
    fn parse_console_command_step_instruction_over_aliases() {
        for input in ["nexti", "ni"] {
            assert_eq!(
                super::parse_console_command(input),
                super::ConsoleCommand::StepInstructionOver
            );
        }
    }

    #[test]
    fn parse_console_command_heap_and_jump_queries() {
        assert_eq!(
            super::parse_console_command("heap 0x1010"),
            super::ConsoleCommand::HeapJump(super::HeapSearchQuery::AnyAddress(0x1010))
        );
        assert_eq!(
            super::parse_console_command("jump u 0x1010"),
            super::ConsoleCommand::HeapJump(super::HeapSearchQuery::UserAddress(0x1010))
        );
        assert_eq!(
            super::parse_console_command("jump c 0x1000"),
            super::ConsoleCommand::HeapJump(super::HeapSearchQuery::ChunkAddress(0x1000))
        );
        assert_eq!(
            super::parse_console_command("jump s 0x30"),
            super::ConsoleCommand::HeapJump(super::HeapSearchQuery::Size(0x30))
        );
    }

    #[test]
    fn parse_console_command_tabs() {
        assert_eq!(
            super::parse_console_command("tab heap"),
            super::ConsoleCommand::SelectRightTab(super::LiveRightTab::Heap)
        );
        assert_eq!(
            super::parse_console_command("tab stack"),
            super::ConsoleCommand::SelectRightTab(super::LiveRightTab::Stack)
        );
        assert_eq!(
            super::parse_console_command("tab logs"),
            super::ConsoleCommand::SelectRightTab(super::LiveRightTab::Logs)
        );
        assert_eq!(
            super::parse_console_command("tab maps"),
            super::ConsoleCommand::SelectRightTab(super::LiveRightTab::Maps)
        );
    }

    #[test]
    fn parse_console_command_unknown() {
        assert_eq!(
            super::parse_console_command("wat"),
            super::ConsoleCommand::Unknown("wat".to_string())
        );
    }

    #[test]
    fn live_tui_colon_starts_console_input() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(':'),
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(app.console_input_active);
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::Console);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_tui_active_console_input_captures_printable_keys() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        app.console_input_active = true;

        for ch in ['h', 'e', 'l', 'p'] {
            let key = crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char(ch),
                crossterm::event::KeyModifiers::NONE,
            );
            super::handle_live_tui_key(key, &mut app, false, &sender);
        }

        assert_eq!(app.console_input, "help");
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_tui_esc_cancels_console_input() {
        let mut app = super::LiveTuiApp::default();
        let (sender, _) = std::sync::mpsc::channel();
        app.console_input_active = true;
        app.console_input = "help".to_string();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Esc,
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!app.console_input_active);
        assert!(app.console_input.is_empty());
    }

    #[test]
    fn live_tui_enter_submits_console_input_and_appends_history() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        app.console_input_active = true;
        app.console_input = "help".to_string();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Enter,
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!app.console_input_active);
        assert_eq!(app.console_history, vec!["help".to_string()]);
        assert!(app.logs.iter().any(|line| line.contains("commands: help")));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_tui_console_history_up_down() {
        let mut app = super::LiveTuiApp::default();
        app.console_input_active = true;
        app.console_history = vec!["help".to_string(), "regs".to_string()];

        app.history_previous();
        assert_eq!(app.console_input, "regs");
        app.history_previous();
        assert_eq!(app.console_input, "help");
        app.history_next();
        assert_eq!(app.console_input, "regs");
        app.history_next();
        assert!(app.console_input.is_empty());
    }

    #[test]
    fn console_help_command_writes_command_list() {
        let mut app = super::LiveTuiApp::default();
        let (sender, _) = std::sync::mpsc::channel();

        super::execute_console_command(
            &mut app,
            super::ConsoleCommand::Help,
            "help",
            false,
            &sender,
        );

        assert!(app.logs.iter().any(|line| line.contains("commands: help")));
    }

    #[test]
    fn console_regs_command_focuses_registers() {
        let mut app = super::LiveTuiApp::default();
        let (sender, _) = std::sync::mpsc::channel();

        super::execute_console_command(
            &mut app,
            super::ConsoleCommand::Registers,
            "regs",
            false,
            &sender,
        );

        assert_eq!(
            app.focused_debugger_pane,
            super::LiveDebuggerPane::Registers
        );
    }

    #[test]
    fn console_stack_and_maps_commands_select_tabs() {
        let mut app = super::LiveTuiApp::default();
        let (sender, _) = std::sync::mpsc::channel();

        super::execute_console_command(
            &mut app,
            super::ConsoleCommand::Stack,
            "stack",
            false,
            &sender,
        );
        assert_eq!(app.active_right_tab, super::LiveRightTab::Stack);
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::RightTab);

        super::execute_console_command(
            &mut app,
            super::ConsoleCommand::Maps,
            "maps",
            false,
            &sender,
        );
        assert_eq!(app.active_right_tab, super::LiveRightTab::Maps);
    }

    #[test]
    fn console_heap_command_uses_jump_logic_on_success() {
        let mut app = super::LiveTuiApp::default();
        let (sender, _) = std::sync::mpsc::channel();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010)]),
        });

        super::execute_console_command(
            &mut app,
            super::ConsoleCommand::HeapJump(super::HeapSearchQuery::UserAddress(0x1010)),
            "jump u 0x1010",
            false,
            &sender,
        );

        assert_eq!(app.active_right_tab, super::LiveRightTab::Heap);
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::RightTab);
        assert!(app.show_chunk_inspector);
        assert_eq!(app.selected_chunk_user_addr, Some(0x1010));
    }

    #[test]
    fn console_live_command_sends_existing_command_message() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();

        super::execute_console_command(
            &mut app,
            super::ConsoleCommand::Pause,
            "pause",
            false,
            &sender,
        );

        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::Pause
        );
        assert_eq!(app.status_line, "pause requested...");
    }

    #[test]
    fn live_tui_q_before_session_end_sends_stop_without_exiting() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('q'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        let message = receiver.try_recv().unwrap();
        assert_eq!(message.command, super::LiveCommand::Stop);
        assert_eq!(message.id, super::LiveCommandId(1));
        assert_eq!(app.target_status, super::LiveTargetStatus::Stopping);
        assert_eq!(app.status_line, "stopping target...");
    }

    #[test]
    fn live_tui_ctrl_c_before_session_end_sends_stop_without_exiting() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('c'),
            crossterm::event::KeyModifiers::CONTROL,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::Stop
        );
    }

    #[test]
    fn live_tui_q_after_session_end_exits() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        app.apply_update(super::LiveTraceUpdate::SessionEnd(super::JsonSessionEnd {
            record: session_end_record(1),
        }));
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('q'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(should_exit);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_tui_p_sends_pause_when_running() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('p'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::Pause
        );
        assert_eq!(app.target_status, super::LiveTargetStatus::Running);
        assert_eq!(app.follow_tail_before_pause, Some(true));
        assert!(!app.follow_tail);
        assert_eq!(app.status_line, "pause requested...");
    }

    #[test]
    fn live_tui_r_sends_resume_when_paused() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::Paused;
        app.follow_tail_before_pause = Some(true);
        app.follow_tail = false;
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('r'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::Resume
        );
        assert_eq!(app.status_line, "resume requested...");
        assert_eq!(app.target_status, super::LiveTargetStatus::Paused);
        assert!(app.follow_tail);
        assert_eq!(app.follow_tail_before_pause, None);
    }

    #[test]
    fn live_tui_resume_keeps_follow_tail_false_when_false_before_pause() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::Paused;
        app.follow_tail_before_pause = Some(false);
        app.follow_tail = false;
        let (sender, _receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('r'),
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);

        assert_eq!(app.target_status, super::LiveTargetStatus::Paused);
        assert!(!app.follow_tail);
        assert_eq!(app.follow_tail_before_pause, None);
    }

    #[test]
    fn live_tui_space_toggles_running_to_pause_and_paused_to_resume() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(' '),
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::Pause
        );
        assert_eq!(app.target_status, super::LiveTargetStatus::Running);

        app.target_status = super::LiveTargetStatus::Paused;
        super::handle_live_tui_key(key, &mut app, false, &sender);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::Resume
        );
        assert_eq!(app.target_status, super::LiveTargetStatus::Paused);
    }

    #[test]
    fn live_tui_event_updates_do_not_auto_select_newest_while_paused() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(malloc_live_update(1));
        app.apply_update(super::LiveTraceUpdate::CommandStatus {
            command_id: None,
            command: Some(super::LiveCommand::Pause),
            status: super::LiveCommandStatus::Completed,
            target_status: super::LiveTargetStatus::Paused,
            message: "target paused; inspect panes or resume".to_string(),
        });

        app.apply_update(malloc_live_update(2));

        assert_eq!(app.events.len(), 2);
        assert_eq!(app.selected_index, 0);
        assert!(!app.follow_tail);
    }

    #[test]
    fn live_tui_n_while_paused_sends_step_allocator_event() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::Paused;
        app.follow_tail = false;
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('n'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::StepAllocatorEvent
        );
        assert_eq!(
            app.target_status,
            super::LiveTargetStatus::SteppingToNextAllocatorEvent
        );
        assert!(app.follow_tail);
        assert_eq!(app.status_line, "stepping to next allocator event...");
    }

    #[test]
    fn live_tui_n_while_running_does_not_send_step_allocator_event() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('n'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert!(receiver.try_recv().is_err());
        assert!(app.status_line.contains("not allowed"));
    }

    #[test]
    fn live_tui_dot_while_paused_sends_step_instruction() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::Paused;
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('.'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::StepInstruction
        );
        assert_eq!(
            app.target_status,
            super::LiveTargetStatus::SteppingInstruction
        );
        assert_eq!(app.status_line, "waiting for next stop...");
    }

    #[test]
    fn live_tui_dot_while_running_does_not_send_step_instruction() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('.'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert!(receiver.try_recv().is_err());
        assert!(app.status_line.contains("not allowed"));
    }

    #[test]
    fn live_tui_comma_while_paused_sends_step_instruction_over() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::Paused;
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(','),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::StepInstructionOver
        );
        assert_eq!(
            app.target_status,
            super::LiveTargetStatus::SteppingInstructionOver
        );
        assert_eq!(app.status_line, "waiting for next stop...");
    }

    #[test]
    fn live_tui_instruction_step_completion_keeps_target_paused() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::SteppingInstruction;

        app.apply_update(super::LiveTraceUpdate::CommandStatus {
            command_id: Some(super::LiveCommandId(1)),
            command: Some(super::LiveCommand::StepInstruction),
            status: super::LiveCommandStatus::Completed,
            target_status: super::LiveTargetStatus::Paused,
            message: "stepped instruction: 0x401000 -> 0x401001".to_string(),
        });

        assert_eq!(app.target_status, super::LiveTargetStatus::Paused);
        assert_eq!(app.events.len(), 0);
        assert_eq!(app.status_line, "stepped instruction: 0x401000 -> 0x401001");
        assert_eq!(
            app.latest_stop_reason,
            Some(super::DebuggerStopReason::InstructionStep {
                from_rip: 0x401000,
                to_rip: 0x401001
            })
        );
    }

    #[test]
    fn live_tui_nexti_completion_keeps_target_paused_and_stores_stop_reason() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::SteppingInstructionOver;

        app.apply_update(super::LiveTraceUpdate::CommandStatus {
            command_id: Some(super::LiveCommandId(1)),
            command: Some(super::LiveCommand::StepInstructionOver),
            status: super::LiveCommandStatus::Completed,
            target_status: super::LiveTargetStatus::Paused,
            message: "nexti completed: 0x401000 -> 0x401005".to_string(),
        });

        assert_eq!(app.target_status, super::LiveTargetStatus::Paused);
        assert_eq!(app.events.len(), 0);
        assert_eq!(
            app.latest_stop_reason,
            Some(super::DebuggerStopReason::InstructionStepOver {
                from_rip: 0x401000,
                to_rip: 0x401005
            })
        );
    }

    #[test]
    fn live_tui_instruction_step_updates_refresh_debugger_context_without_event() {
        let mut app = super::LiveTuiApp::default();

        app.apply_update(super::LiveTraceUpdate::RegisterSnapshot {
            event_id: None,
            snapshot: test_register_snapshot(0x1),
        });
        app.apply_update(super::LiveTraceUpdate::CodeContext {
            event_id: None,
            context: test_code_context(0x401001),
        });
        app.apply_update(super::LiveTraceUpdate::StackSnapshot {
            event_id: None,
            snapshot: test_stack_snapshot(&[0x401001]),
        });

        assert!(app.latest_register_snapshot.is_some());
        assert!(app.latest_code_context.is_some());
        assert!(app.latest_stack_snapshot.is_some());
        assert!(app.register_snapshots_by_event_id.is_empty());
        assert!(app.code_context_by_event_id.is_empty());
        assert!(app.stack_snapshots_by_event_id.is_empty());
        assert!(app.events.is_empty());
    }

    #[test]
    fn live_tui_c_while_paused_sends_continue_and_follows_tail() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::Paused;
        app.follow_tail = false;
        app.apply_update(malloc_live_update(1));
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('c'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert_eq!(
            receiver.try_recv().unwrap().command,
            super::LiveCommand::Continue
        );
        assert_eq!(app.target_status, super::LiveTargetStatus::Running);
        assert!(app.follow_tail);
        assert_eq!(app.status_line, "running");
    }

    #[test]
    fn live_tui_stepping_mode_selects_next_event_when_it_arrives() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(malloc_live_update(1));
        app.apply_update(super::LiveTraceUpdate::CommandStatus {
            command_id: None,
            command: Some(super::LiveCommand::StepAllocatorEvent),
            status: super::LiveCommandStatus::Accepted,
            target_status: super::LiveTargetStatus::SteppingToNextAllocatorEvent,
            message: "stepping to next allocator event...".to_string(),
        });
        app.follow_tail = true;

        app.apply_update(malloc_live_update(2));

        assert_eq!(app.events.len(), 2);
        assert_eq!(app.selected_index, 1);
    }

    #[test]
    fn live_tui_target_state_paused_after_stepping_disables_follow_tail() {
        let mut app = super::LiveTuiApp::default();
        app.target_status = super::LiveTargetStatus::SteppingToNextAllocatorEvent;
        app.follow_tail = true;

        app.apply_update(super::LiveTraceUpdate::CommandStatus {
            command_id: None,
            command: Some(super::LiveCommand::StepAllocatorEvent),
            status: super::LiveCommandStatus::Completed,
            target_status: super::LiveTargetStatus::Paused,
            message: "paused after allocator event #2".to_string(),
        });

        assert_eq!(app.target_status, super::LiveTargetStatus::Paused);
        assert!(!app.follow_tail);
        assert_eq!(app.status_line, "paused after allocator event #2");
    }

    #[test]
    fn live_tui_scrolls_focused_non_event_pane() {
        let mut app = super::LiveTuiApp::default();
        app.focused_debugger_pane = super::LiveDebuggerPane::RightTab;
        app.active_right_tab = super::LiveRightTab::Heap;

        app.scroll_focused(3);

        assert_eq!(app.heap_layout_scroll, 3);
        assert_eq!(app.event_details_scroll, 0);
        assert_eq!(app.allocator_scan_scroll, 0);
        assert_eq!(app.related_records_scroll, 0);
    }

    #[test]
    fn live_tui_h_toggles_heap_pane() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('h'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert!(!app.show_heap_pane);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_tui_s_toggles_scan_pane() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('s'),
            crossterm::event::KeyModifiers::NONE,
        );

        let should_exit = super::handle_live_tui_key(key, &mut app, false, &sender);

        assert!(!should_exit);
        assert!(!app.show_scan_pane);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_tui_tab_and_backtab_change_focus() {
        let mut app = super::LiveTuiApp::default();
        let (sender, _) = std::sync::mpsc::channel();
        let tab = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Tab,
            crossterm::event::KeyModifiers::NONE,
        );
        let backtab = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::BackTab,
            crossterm::event::KeyModifiers::SHIFT,
        );

        super::handle_live_tui_key(tab, &mut app, false, &sender);
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::Console);
        super::handle_live_tui_key(backtab, &mut app, false, &sender);
        assert_eq!(app.focused_debugger_pane, super::LiveDebuggerPane::Trace);
    }

    #[test]
    fn live_allocator_summary_compact_line_formats_counts() {
        let formatted =
            super::format_live_allocator_summary_compact(&allocator_source_summary_record(9));

        assert_eq!(
            formatted,
            "event #9 allocator: tc=7 fb=1 ub=0 sb=0 lb=0 total=8 warn=0"
        );
    }

    #[test]
    fn live_heap_scan_compact_line_formats_status_and_findings() {
        let formatted = super::format_live_heap_scan_compact(&heap_scan_record(9));

        assert!(formatted.contains("event #9 heap scan: status=suspicious chunks=3 suspicious=1"));
        assert!(formatted.contains("suspicious allocator_source_allocated"));
        assert!(formatted.contains("Allocator metadata references a chunk"));
    }

    #[test]
    fn heap_scan_explanations_cover_stable_finding_kinds() {
        for kind in [
            "heap_snapshot_unavailable",
            "heap_snapshot_truncated",
            "allocator_source_conflict",
            "allocator_source_allocated",
            "free_list_size_mismatch",
            "free_list_node_outside_heap",
            "free_list_cycle",
            "main_arena_top_not_validated",
            "bin_validation_suspicious",
            "bin_validation_incomplete",
        ] {
            let finding = json_heap_scan_finding(kind, "message");
            assert!(
                !super::explain_heap_scan_finding(&finding).is_empty(),
                "missing explanation for {kind}"
            );
        }
    }

    #[test]
    fn allocator_source_conflict_explanation_mentions_multiple_sources() {
        let finding = json_heap_scan_finding("allocator_source_conflict", "message");
        let explanation = super::explain_heap_scan_finding(&finding).join(" ");

        assert!(explanation.contains("multiple allocator sources"));
    }

    #[test]
    fn free_list_size_mismatch_explanation_mentions_size_metadata() {
        let finding = json_heap_scan_finding("free_list_size_mismatch", "message");
        let explanation = super::explain_heap_scan_finding(&finding).join(" ");

        assert!(explanation.contains("chunk size metadata"));
        assert!(explanation.contains("expected bin size"));
    }

    #[test]
    fn free_list_node_outside_heap_explanation_mentions_pointer_outside_heap() {
        let finding = json_heap_scan_finding("free_list_node_outside_heap", "message");
        let explanation = super::explain_heap_scan_finding(&finding).join(" ");

        assert!(explanation.contains("pointer"));
        assert!(explanation.contains("outside the walked heap"));
    }

    #[test]
    fn human_heap_scan_rendering_includes_explanation_lines() {
        let formatted =
            super::format_replay_record(&heap_scan_record(9), &super::ReplayConfig::default());

        assert!(formatted.contains("heap scan findings:"));
        assert!(formatted.contains("Allocator metadata references a chunk"));
    }

    #[test]
    fn live_chunk_finding_rendering_includes_explanation_lines() {
        let findings = super::collect_heap_scan_findings_for_chunk(
            Some(&heap_scan_record(9)),
            Some(0x1000),
            Some(0x1010),
        );
        let formatted = findings.join("\n");

        assert!(formatted.contains("allocator_source_allocated"));
        assert!(formatted.contains("Allocator metadata references a chunk"));
    }

    #[test]
    fn live_related_records_render_with_headings() {
        let records = vec![layout_record(9), allocator_source_summary_record(9)];

        let formatted = super::format_live_related_records_with_headings(
            &records,
            &super::ReplayConfig::default(),
        );

        assert!(formatted.contains("== heap_layout =="));
        assert!(formatted.contains("== allocator_source_summary =="));
    }

    #[test]
    fn trace_config_parses_break_on_suspicious() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--break-on".into(),
            "suspicious".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(
            config.break_conditions,
            vec![super::AllocatorBreakCondition::Suspicious]
        );
    }

    #[test]
    fn trace_config_parses_break_on_double_free() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--break-on".into(),
            "double-free".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(
            config.break_conditions,
            vec![super::AllocatorBreakCondition::DoubleFree]
        );
    }

    #[test]
    fn trace_config_parses_break_on_free_pointer() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--break-on-free".into(),
            "0xd972a0".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(
            config.break_conditions,
            vec![super::AllocatorBreakCondition::FreePtr(0xd972a0)]
        );
    }

    #[test]
    fn trace_config_parses_break_on_alloc_size() {
        let (config, _, _) = parse_trace_heap_args(vec![
            "--break-on-alloc-size".into(),
            "0x80".into(),
            "prog".into(),
        ])
        .unwrap();

        assert_eq!(
            config.break_conditions,
            vec![super::AllocatorBreakCondition::AllocSize(0x80)]
        );
    }

    #[test]
    fn trace_config_rejects_unknown_break_on_value() {
        let error =
            parse_trace_heap_args(vec!["--break-on".into(), "unknown".into(), "prog".into()])
                .unwrap_err()
                .to_string();

        assert!(error.contains("invalid --break-on value"));
    }

    #[test]
    fn allocator_break_evaluates_alloc_size_for_malloc() {
        let event = heapify_core::HeapTraceEvent::Malloc {
            event_id: 7,
            requested_size: 0x80,
            returned_ptr: 0x2000,
            chunk: None,
            caller_addr: None,
        };

        let matched = super::evaluate_allocator_break_conditions(
            &[super::AllocatorBreakCondition::AllocSize(0x80)],
            &event,
            heapify_core::tracker::HeapTrackerNote::NewAllocation,
            &[],
        )
        .unwrap();

        assert_eq!(matched.event_id, 7);
        assert_eq!(matched.user_addr, Some(0x2000));
    }

    #[test]
    fn allocator_break_evaluates_alloc_size_for_calloc_checked_product() {
        let event = heapify_core::HeapTraceEvent::Calloc {
            event_id: 8,
            nmemb: 4,
            size: 0x20,
            returned_ptr: 0x3000,
            chunk: None,
            caller_addr: None,
        };

        let matched = super::evaluate_allocator_break_conditions(
            &[super::AllocatorBreakCondition::AllocSize(0x80)],
            &event,
            heapify_core::tracker::HeapTrackerNote::NewAllocation,
            &[],
        )
        .unwrap();

        assert_eq!(matched.event_id, 8);
        assert_eq!(matched.user_addr, Some(0x3000));
    }

    #[test]
    fn allocator_break_evaluates_alloc_size_for_realloc() {
        let event = heapify_core::HeapTraceEvent::Realloc {
            event_id: 9,
            old_ptr: 0x2000,
            new_size: 0x80,
            returned_ptr: 0x4000,
            old_chunk: None,
            new_chunk: None,
            caller_addr: None,
        };

        let matched = super::evaluate_allocator_break_conditions(
            &[super::AllocatorBreakCondition::AllocSize(0x80)],
            &event,
            heapify_core::tracker::HeapTrackerNote::ReallocMovedAllocation,
            &[],
        )
        .unwrap();

        assert_eq!(matched.event_id, 9);
        assert_eq!(matched.user_addr, Some(0x4000));
    }

    #[test]
    fn allocator_break_evaluates_free_pointer() {
        let event = heapify_core::HeapTraceEvent::Free {
            event_id: 10,
            ptr: 0xd972a0,
            chunk: None,
            tcache_entry: None,
            caller_addr: None,
        };

        let matched = super::evaluate_allocator_break_conditions(
            &[super::AllocatorBreakCondition::FreePtr(0xd972a0)],
            &event,
            heapify_core::tracker::HeapTrackerNote::FreedKnownChunk,
            &[],
        )
        .unwrap();

        assert_eq!(matched.user_addr, Some(0xd972a0));
    }

    #[test]
    fn allocator_break_evaluates_suspicious_heap_scan_record() {
        let event = heapify_core::HeapTraceEvent::Malloc {
            event_id: 9,
            requested_size: 0x20,
            returned_ptr: 0x1010,
            chunk: None,
            caller_addr: None,
        };

        let matched = super::evaluate_allocator_break_conditions(
            &[super::AllocatorBreakCondition::Suspicious],
            &event,
            heapify_core::tracker::HeapTrackerNote::NewAllocation,
            &[heap_scan_record(9)],
        )
        .unwrap();

        assert_eq!(
            matched.condition,
            super::AllocatorBreakCondition::Suspicious
        );
        assert!(matched.message.contains("allocator_source_allocated"));
    }

    #[test]
    fn allocator_break_evaluates_double_free_note() {
        let event = heapify_core::HeapTraceEvent::Free {
            event_id: 11,
            ptr: 0x5000,
            chunk: None,
            tcache_entry: None,
            caller_addr: None,
        };

        let matched = super::evaluate_allocator_break_conditions(
            &[super::AllocatorBreakCondition::DoubleFree],
            &event,
            heapify_core::tracker::HeapTrackerNote::DoubleFree,
            &[],
        )
        .unwrap();

        assert_eq!(matched.user_addr, Some(0x5000));
    }

    #[test]
    fn heap_search_parse_empty_input_errors() {
        assert!(super::parse_heap_search_query("").is_err());
        assert!(super::parse_heap_search_query("   ").is_err());
    }

    #[test]
    fn heap_search_parse_bare_address_defaults_to_any_address() {
        assert_eq!(
            super::parse_heap_search_query("0xd972a0").unwrap(),
            super::HeapSearchQuery::AnyAddress(0xd972a0)
        );
    }

    #[test]
    fn heap_search_parse_user_address_mode() {
        assert_eq!(
            super::parse_heap_search_query("u 0xd972a0").unwrap(),
            super::HeapSearchQuery::UserAddress(0xd972a0)
        );
    }

    #[test]
    fn heap_search_parse_chunk_address_mode() {
        assert_eq!(
            super::parse_heap_search_query("c 0xd97290").unwrap(),
            super::HeapSearchQuery::ChunkAddress(0xd97290)
        );
    }

    #[test]
    fn heap_search_parse_size_mode() {
        assert_eq!(
            super::parse_heap_search_query("s 0x30").unwrap(),
            super::HeapSearchQuery::Size(0x30)
        );
    }

    #[test]
    fn heap_search_parse_bad_mode_errors() {
        let error = super::parse_heap_search_query("bad 0x30")
            .unwrap_err()
            .to_string();

        assert!(error.contains("bad heap jump mode"));
    }

    #[test]
    fn heap_search_find_any_address_inside_chunk_range() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });

        assert_eq!(
            app.find_chunk_in_latest_layout(super::HeapSearchQuery::AnyAddress(0x1050)),
            Some(1)
        );
    }

    #[test]
    fn heap_search_find_user_address_exact() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });

        assert_eq!(
            app.find_chunk_in_latest_layout(super::HeapSearchQuery::UserAddress(0x1040)),
            Some(1)
        );
    }

    #[test]
    fn heap_search_find_chunk_address_exact() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });

        assert_eq!(
            app.find_chunk_in_latest_layout(super::HeapSearchQuery::ChunkAddress(0x1030)),
            Some(1)
        );
    }

    #[test]
    fn heap_search_find_size_returns_first_match() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });

        assert_eq!(
            app.find_chunk_in_latest_layout(super::HeapSearchQuery::Size(0x30)),
            Some(0)
        );
    }

    #[test]
    fn heap_search_success_updates_selection_and_enables_inspector() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });
        app.search_prompt_active = true;
        app.search_prompt_input = "u 0x1040".to_string();

        app.execute_heap_search();

        assert!(!app.search_prompt_active);
        assert_eq!(app.selected_chunk_index, Some(1));
        assert_eq!(app.selected_chunk_addr, Some(0x1030));
        assert_eq!(app.selected_chunk_user_addr, Some(0x1040));
        assert_eq!(app.focused_pane, super::LiveTuiPane::HeapLayout);
        assert!(app.show_heap_pane);
        assert!(app.show_chunk_inspector);
        assert_eq!(app.heap_layout_scroll, 0);
        assert!(app
            .search_status
            .as_deref()
            .unwrap()
            .contains("selected chunk 0x1030 user 0x1040"));
    }

    #[test]
    fn heap_search_failure_leaves_selection_unchanged_and_sets_status() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });
        app.select_next_chunk();
        app.search_prompt_active = true;
        app.search_prompt_input = "u 0xffff".to_string();

        app.execute_heap_search();

        assert!(!app.search_prompt_active);
        assert_eq!(app.selected_chunk_index, Some(0));
        assert_eq!(app.selected_chunk_addr, Some(0x1000));
        assert!(app
            .search_status
            .as_deref()
            .unwrap()
            .contains("no heap chunk with user address 0xffff"));
    }

    #[test]
    fn heap_search_prompt_input_handles_char_backspace_and_cancel() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let g = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('g'),
            crossterm::event::KeyModifiers::NONE,
        );
        let one = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('1'),
            crossterm::event::KeyModifiers::NONE,
        );
        let two = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('2'),
            crossterm::event::KeyModifiers::NONE,
        );
        let backspace = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Backspace,
            crossterm::event::KeyModifiers::NONE,
        );
        let esc = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Esc,
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(g, &mut app, false, &sender);
        super::handle_live_tui_key(one, &mut app, false, &sender);
        super::handle_live_tui_key(two, &mut app, false, &sender);
        assert_eq!(app.search_prompt_input, "12");

        super::handle_live_tui_key(backspace, &mut app, false, &sender);
        assert_eq!(app.search_prompt_input, "1");

        super::handle_live_tui_key(esc, &mut app, false, &sender);
        assert!(!app.search_prompt_active);
        assert!(app.search_prompt_input.is_empty());
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_tui_selecting_next_previous_chunk_updates_selection() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });

        app.select_next_chunk();
        assert_eq!(app.selected_chunk_index, Some(0));
        assert_eq!(app.selected_chunk_addr, Some(0x1000));
        assert_eq!(app.selected_chunk_user_addr, Some(0x1010));

        app.select_next_chunk();
        assert_eq!(app.selected_chunk_index, Some(1));
        assert_eq!(app.selected_chunk_addr, Some(0x1030));
        assert_eq!(app.selected_chunk_user_addr, Some(0x1040));

        app.select_previous_chunk();
        assert_eq!(app.selected_chunk_index, Some(0));
        assert_eq!(app.selected_chunk_addr, Some(0x1000));
        assert_eq!(app.selected_chunk_user_addr, Some(0x1010));
    }

    #[test]
    fn live_tui_chunk_selection_is_preserved_by_user_addr_after_layout_update() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });
        app.select_next_chunk();
        app.select_next_chunk();

        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 2,
            record: layout_record_with_chunks(2, &[(0x2000, 0x2010), (0x3000, 0x1040)]),
        });

        assert_eq!(app.selected_chunk_index, Some(1));
        assert_eq!(app.selected_chunk_addr, Some(0x3000));
        assert_eq!(app.selected_chunk_user_addr, Some(0x1040));
    }

    #[test]
    fn live_tui_chunk_selection_clamps_when_selected_chunk_disappears() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(
                1,
                &[(0x1000, 0x1010), (0x1030, 0x1040), (0x1060, 0x1070)],
            ),
        });
        app.select_next_chunk();
        app.select_next_chunk();
        app.select_next_chunk();

        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 2,
            record: layout_record_with_chunks(2, &[(0x1000, 0x1010)]),
        });

        assert_eq!(app.selected_chunk_index, Some(0));
        assert_eq!(app.selected_chunk_addr, Some(0x1000));
        assert_eq!(app.selected_chunk_user_addr, Some(0x1010));
    }

    #[test]
    fn live_tui_i_toggles_chunk_inspector() {
        let mut app = super::LiveTuiApp::default();
        let (sender, receiver) = std::sync::mpsc::channel();
        let key = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('i'),
            crossterm::event::KeyModifiers::NONE,
        );

        super::handle_live_tui_key(key, &mut app, false, &sender);
        assert!(app.show_chunk_inspector);
        super::handle_live_tui_key(key, &mut app, false, &sender);
        assert!(!app.show_chunk_inspector);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn live_chunk_inspector_renders_no_selection_message() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010)]),
        });

        assert_eq!(super::live_chunk_inspector_text(&app), "no chunk selected");
    }

    #[test]
    fn live_chunk_inspector_renders_selected_chunk_fields() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_annotated_chunk(1),
        });
        app.select_next_chunk();

        let formatted = super::live_chunk_inspector_text(&app);

        assert!(formatted.contains("chunk addr: 0x1000"));
        assert!(formatted.contains("user addr:  0x1010"));
        assert!(formatted.contains("size:       0x30"));
        assert!(formatted.contains("flags:      PREV_INUSE"));
        assert!(formatted.contains("tracker:    freed"));
        assert!(formatted.contains("allocator:  tcache_candidate size=0x30 index=0"));
    }

    #[test]
    fn live_event_history_matches_allocator_events_by_user_pointer() {
        let events = vec![
            malloc_event_record(1, 0x1010),
            calloc_event_record(2, 0x1010),
            free_event_record(3, 0x1010),
            realloc_event_record(4, 0x1010, 0x2020),
            realloc_event_record(5, 0x3030, 0x1010),
            malloc_event_record(6, 0x4040),
        ];

        let history = super::collect_event_history_for_user_addr(&events, 0x1010);

        assert_eq!(history.len(), 5);
        assert!(history[0].contains("#1 malloc"));
        assert!(history[1].contains("#2 calloc"));
        assert!(history[2].contains("#3 free"));
        assert!(history[3].contains("#4 realloc"));
        assert!(history[4].contains("#5 realloc"));
    }

    #[test]
    fn live_heap_scan_findings_filter_by_selected_chunk_or_user_addr() {
        let findings = super::collect_heap_scan_findings_for_chunk(
            Some(&heap_scan_record_with_findings(1)),
            Some(0x1000),
            Some(0x2020),
        );

        assert_eq!(findings.len(), 2);
        assert!(findings[0].contains("chunk=0x1000"));
        assert!(findings[1].contains("user=0x2020"));
    }

    #[test]
    fn live_tui_app_selects_matched_event_on_break_matched() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(malloc_live_update(1));
        app.apply_update(malloc_live_update(2));

        app.apply_update(super::LiveTraceUpdate::BreakMatched(
            super::AllocatorBreakMatch {
                condition: super::AllocatorBreakCondition::AllocSize(0x20),
                event_id: 1,
                user_addr: None,
                message: "allocation size 0x20".to_string(),
            },
        ));

        assert_eq!(app.target_status, super::LiveTargetStatus::Paused);
        assert_eq!(app.selected_index, 0);
        assert!(!app.follow_tail);
        assert!(app
            .status_line
            .contains("break condition matched: allocation size 0x20 after event #1"));
    }

    #[test]
    fn live_tui_app_opens_chunk_inspector_for_break_user_addr() {
        let mut app = super::LiveTuiApp::default();
        app.apply_update(malloc_live_update(1));
        app.apply_update(super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record_with_chunks(1, &[(0x1000, 0x1010), (0x1030, 0x1040)]),
        });

        app.apply_update(super::LiveTraceUpdate::BreakMatched(
            super::AllocatorBreakMatch {
                condition: super::AllocatorBreakCondition::FreePtr(0x1040),
                event_id: 1,
                user_addr: Some(0x1040),
                message: "free pointer 0x1040".to_string(),
            },
        ));

        assert_eq!(app.focused_pane, super::LiveTuiPane::HeapLayout);
        assert!(app.show_chunk_inspector);
        assert_eq!(app.selected_chunk_index, Some(1));
        assert_eq!(app.selected_chunk_user_addr, Some(0x1040));
    }

    #[test]
    fn live_command_status_labels_are_stable() {
        assert_eq!(super::LiveCommand::Stop.as_str(), "stop");
        assert_eq!(super::LiveCommand::Pause.as_str(), "pause");
        assert_eq!(super::LiveCommand::Resume.as_str(), "resume");
        assert_eq!(super::LiveCommand::Continue.as_str(), "continue");
        assert_eq!(
            super::LiveCommand::StepAllocatorEvent.as_str(),
            "step_allocator_event"
        );
        assert_eq!(
            super::LiveCommand::StepInstruction.as_str(),
            "step_instruction"
        );
        assert_eq!(
            super::LiveCommand::StepInstructionOver.as_str(),
            "step_instruction_over"
        );
        assert_eq!(super::LiveTargetStatus::NotStarted.as_str(), "not_started");
        assert_eq!(super::LiveTargetStatus::Running.as_str(), "running");
        assert_eq!(super::LiveTargetStatus::Paused.as_str(), "paused");
        assert_eq!(
            super::LiveTargetStatus::SteppingToNextAllocatorEvent.as_str(),
            "stepping_to_next_allocator_event"
        );
        assert_eq!(
            super::LiveTargetStatus::SteppingInstruction.as_str(),
            "stepping_instruction"
        );
        assert_eq!(
            super::LiveTargetStatus::SteppingInstructionOver.as_str(),
            "stepping_instruction_over"
        );
        assert_eq!(super::LiveTargetStatus::Stopping.as_str(), "stopping");
        assert_eq!(super::LiveTargetStatus::Exited.as_str(), "exited");
        assert_eq!(super::LiveCommandStatus::Accepted.as_str(), "accepted");
        assert_eq!(super::LiveCommandStatus::Rejected.as_str(), "rejected");
        assert_eq!(super::LiveCommandStatus::Completed.as_str(), "completed");
        assert_eq!(super::LiveCommandStatus::Failed.as_str(), "failed");
    }

    #[derive(Default)]
    struct CollectingLiveTraceSink {
        updates: Vec<super::LiveTraceUpdate>,
    }

    impl super::LiveTraceSink for CollectingLiveTraceSink {
        fn on_update(&mut self, update: &super::LiveTraceUpdate) -> anyhow::Result<()> {
            self.updates.push(update.clone());
            Ok(())
        }
    }

    #[test]
    fn live_trace_sink_collects_expected_update_order() {
        let mut sink = CollectingLiveTraceSink::default();
        let event = heapify_core::HeapTraceEvent::Malloc {
            event_id: 1,
            requested_size: 0x20,
            returned_ptr: 0x1000,
            chunk: None,
            caller_addr: None,
        };

        sink.on_update(&super::LiveTraceUpdate::SessionStart(
            super::JsonSessionStart {
                record: session_start_record(),
            },
        ))
        .unwrap();
        sink.on_update(&super::LiveTraceUpdate::Event {
            event_id: 1,
            event,
            note: heapify_core::tracker::HeapTrackerNote::NewAllocation,
            explanation: heapify_core::tracker::HeapTrackerExplanation::NoExtraExplanation,
            caller_symbol: None,
        })
        .unwrap();
        sink.on_update(&super::LiveTraceUpdate::RelatedRecord {
            event_id: 1,
            record: layout_record(1),
        })
        .unwrap();
        sink.on_update(&super::LiveTraceUpdate::SessionEnd(super::JsonSessionEnd {
            record: session_end_record(1),
        }))
        .unwrap();

        let kinds: Vec<&str> = sink
            .updates
            .iter()
            .map(|update| match update {
                super::LiveTraceUpdate::SessionStart(_) => "session_start",
                super::LiveTraceUpdate::Event { .. } => "event",
                super::LiveTraceUpdate::RelatedRecord { .. } => "related_record",
                super::LiveTraceUpdate::Status { .. } => "status",
                super::LiveTraceUpdate::CommandStatus { .. } => "command_status",
                super::LiveTraceUpdate::ProcessMaps { .. } => "process_maps",
                super::LiveTraceUpdate::RegisterSnapshot { .. } => "register_snapshot",
                super::LiveTraceUpdate::StackSnapshot { .. } => "stack_snapshot",
                super::LiveTraceUpdate::CodeContext { .. } => "code_context",
                super::LiveTraceUpdate::BreakMatched(_) => "break_matched",
                super::LiveTraceUpdate::SessionEnd(_) => "session_end",
            })
            .collect();

        assert_eq!(
            kinds,
            vec!["session_start", "event", "related_record", "session_end"]
        );
    }

    #[test]
    fn current_output_sink_writes_event_and_related_json_records() {
        let path = unique_temp_path("heapify-live-sink-json");
        let mut writer = super::JsonWriter::file(&path).unwrap();
        let mut config = super::RenderConfig::default();
        config.json = true;
        let event = heapify_core::HeapTraceEvent::Malloc {
            event_id: 1,
            requested_size: 0x20,
            returned_ptr: 0x1000,
            chunk: None,
            caller_addr: None,
        };

        {
            let mut sink = super::CurrentOutputSink {
                config: &config,
                json_writer: Some(&mut writer),
            };
            sink.on_update(&super::LiveTraceUpdate::Event {
                event_id: 1,
                event,
                note: heapify_core::tracker::HeapTrackerNote::NewAllocation,
                explanation: heapify_core::tracker::HeapTrackerExplanation::NoExtraExplanation,
                caller_symbol: None,
            })
            .unwrap();
            sink.on_update(&super::LiveTraceUpdate::RelatedRecord {
                event_id: 1,
                record: layout_record(1),
            })
            .unwrap();
        }
        writer.flush().unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let records: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["type"], "event");
        assert_eq!(records[0]["event"]["type"], "malloc");
        assert_eq!(records[1]["type"], "heap_layout");
        assert_eq!(records[1]["event_id"], 1);
    }

    #[test]
    fn live_tui_sink_does_not_write_command_status_to_json() {
        let path = unique_temp_path("heapify-live-command-status-json");
        let mut writer = super::JsonWriter::file(&path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();

        {
            let mut sink = super::LiveTuiSink {
                sender,
                json_writer: Some(&mut writer),
            };
            sink.on_update(&super::LiveTraceUpdate::CommandStatus {
                command_id: Some(super::LiveCommandId(1)),
                command: Some(super::LiveCommand::Pause),
                status: super::LiveCommandStatus::Accepted,
                target_status: super::LiveTargetStatus::Running,
                message: "pause requested...".to_string(),
            })
            .unwrap();
        }
        writer.flush().unwrap();

        assert!(matches!(
            receiver.try_recv().unwrap(),
            super::LiveTraceUpdate::CommandStatus {
                command: Some(super::LiveCommand::Pause),
                ..
            }
        ));
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[test]
    fn live_tui_sink_does_not_write_process_maps_to_json() {
        let path = unique_temp_path("heapify-live-process-maps-json");
        let mut writer = super::JsonWriter::file(&path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let snapshot = test_process_maps();

        {
            let mut sink = super::LiveTuiSink {
                sender,
                json_writer: Some(&mut writer),
            };
            sink.on_update(&super::LiveTraceUpdate::ProcessMaps { snapshot })
                .unwrap();
        }
        writer.flush().unwrap();

        assert!(matches!(
            receiver.try_recv().unwrap(),
            super::LiveTraceUpdate::ProcessMaps { .. }
        ));
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[test]
    fn live_tui_sink_does_not_write_register_snapshot_to_json() {
        let path = unique_temp_path("heapify-live-register-snapshot-json");
        let mut writer = super::JsonWriter::file(&path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let snapshot = test_register_snapshot(0xd972a0);

        {
            let mut sink = super::LiveTuiSink {
                sender,
                json_writer: Some(&mut writer),
            };
            sink.on_update(&super::LiveTraceUpdate::RegisterSnapshot {
                event_id: Some(1),
                snapshot,
            })
            .unwrap();
        }
        writer.flush().unwrap();

        assert!(matches!(
            receiver.try_recv().unwrap(),
            super::LiveTraceUpdate::RegisterSnapshot {
                event_id: Some(1),
                ..
            }
        ));
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[test]
    fn live_tui_sink_does_not_write_stack_snapshot_to_json() {
        let path = unique_temp_path("heapify-live-stack-snapshot-json");
        let mut writer = super::JsonWriter::file(&path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let snapshot = test_stack_snapshot(&[0x4011a5]);

        {
            let mut sink = super::LiveTuiSink {
                sender,
                json_writer: Some(&mut writer),
            };
            sink.on_update(&super::LiveTraceUpdate::StackSnapshot {
                event_id: Some(1),
                snapshot,
            })
            .unwrap();
        }
        writer.flush().unwrap();

        assert!(matches!(
            receiver.try_recv().unwrap(),
            super::LiveTraceUpdate::StackSnapshot {
                event_id: Some(1),
                ..
            }
        ));
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[test]
    fn live_tui_sink_does_not_write_code_context_to_json() {
        let path = unique_temp_path("heapify-live-code-context-json");
        let mut writer = super::JsonWriter::file(&path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let context = test_code_context(0x4011a5);

        {
            let mut sink = super::LiveTuiSink {
                sender,
                json_writer: Some(&mut writer),
            };
            sink.on_update(&super::LiveTraceUpdate::CodeContext {
                event_id: Some(1),
                context,
            })
            .unwrap();
        }
        writer.flush().unwrap();

        assert!(matches!(
            receiver.try_recv().unwrap(),
            super::LiveTraceUpdate::CodeContext {
                event_id: Some(1),
                ..
            }
        ));
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[test]
    fn instruction_step_live_only_updates_are_ignored_by_json_sink() {
        let path = unique_temp_path("heapify-instruction-step-live-only-json");
        let mut writer = super::JsonWriter::file(&path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();

        {
            let mut sink = super::LiveTuiSink {
                sender,
                json_writer: Some(&mut writer),
            };
            sink.on_update(&super::LiveTraceUpdate::CommandStatus {
                command_id: Some(super::LiveCommandId(1)),
                command: Some(super::LiveCommand::StepInstruction),
                status: super::LiveCommandStatus::Completed,
                target_status: super::LiveTargetStatus::Paused,
                message: "stepped instruction: 0x401000 -> 0x401001".to_string(),
            })
            .unwrap();
            sink.on_update(&super::LiveTraceUpdate::CommandStatus {
                command_id: Some(super::LiveCommandId(2)),
                command: Some(super::LiveCommand::StepInstructionOver),
                status: super::LiveCommandStatus::Completed,
                target_status: super::LiveTargetStatus::Paused,
                message: "nexti completed: 0x401001 -> 0x401006".to_string(),
            })
            .unwrap();
            sink.on_update(&super::LiveTraceUpdate::RegisterSnapshot {
                event_id: None,
                snapshot: test_register_snapshot(0x1),
            })
            .unwrap();
            sink.on_update(&super::LiveTraceUpdate::StackSnapshot {
                event_id: None,
                snapshot: test_stack_snapshot(&[0x401001]),
            })
            .unwrap();
            sink.on_update(&super::LiveTraceUpdate::CodeContext {
                event_id: None,
                context: test_code_context(0x401001),
            })
            .unwrap();
        }
        writer.flush().unwrap();

        assert_eq!(receiver.try_iter().count(), 5);
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[test]
    fn live_tui_sink_does_not_write_break_matched_to_json() {
        let path = unique_temp_path("heapify-live-break-matched-json");
        let mut writer = super::JsonWriter::file(&path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();

        {
            let mut sink = super::LiveTuiSink {
                sender,
                json_writer: Some(&mut writer),
            };
            sink.on_update(&super::LiveTraceUpdate::BreakMatched(
                super::AllocatorBreakMatch {
                    condition: super::AllocatorBreakCondition::Suspicious,
                    event_id: 9,
                    user_addr: Some(0x1010),
                    message: "suspicious heap scan".to_string(),
                },
            ))
            .unwrap();
        }
        writer.flush().unwrap();

        assert!(matches!(
            receiver.try_recv().unwrap(),
            super::LiveTraceUpdate::BreakMatched(super::AllocatorBreakMatch { event_id: 9, .. })
        ));
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[test]
    fn formats_observed_tcache_chain() {
        let chain = ObservedTcacheChain {
            chunk_size: 0x30,
            head: Some(0x2000),
            entries: vec![0x2000, 0x1000],
            truncated: false,
            stopped_on_unknown_next: false,
        };

        assert_eq!(
            format_observed_tcache_chain(&chain),
            "size 0x30: 0x2000 -> 0x1000 -> NULL"
        );
    }

    #[test]
    fn formats_unknown_observed_tcache_chain() {
        let chain = ObservedTcacheChain {
            chunk_size: 0x30,
            head: Some(0x2000),
            entries: vec![0x2000, 0x41414141],
            truncated: false,
            stopped_on_unknown_next: true,
        };

        assert_eq!(
            format_observed_tcache_chain(&chain),
            "size 0x30: 0x2000 -> 0x41414141 -> ?"
        );
    }

    #[test]
    fn formats_truncated_observed_tcache_chain() {
        let chain = ObservedTcacheChain {
            chunk_size: 0x30,
            head: Some(0x3000),
            entries: vec![0x3000, 0x2000],
            truncated: true,
            stopped_on_unknown_next: false,
        };

        assert_eq!(
            format_observed_tcache_chain(&chain),
            "size 0x30: 0x3000 -> 0x2000 -> ... truncated"
        );
    }

    fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}.ndjson",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn session_start_record() -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "session_start",
            "heapify_version": "0.1.0",
            "program": "./prog",
            "args": ["arg"],
            "trace_mode": "target_plt",
            "arch": "x86_64",
            "os": "linux",
            "glibc_profile": "glibc-x86_64-modern",
            "libc": {
                "path": "/lib/libc.so.6",
                "version": "2.39"
            },
            "features": {
                "layout": true,
                "tcache_candidates": false,
                "tcache_struct": false,
                "libc_symbols": false
            }
        }))
        .unwrap()
    }

    fn glibc_profile_selection_session_start_record(
        confidence: &str,
        allocator_views_preset: &str,
    ) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "session_start",
            "heapify_version": "0.1.0",
            "program": "./prog",
            "args": [],
            "trace_mode": "target_plt",
            "arch": "x86_64",
            "os": "linux",
            "glibc_profile": "glibc-x86_64-modern",
            "glibc_profile_selection": {
                "requested": "auto",
                "selected": "glibc-x86_64-modern",
                "detected_version": "2.39",
                "detected_libc_path": "/lib/libc.so.6",
                "supplied_libc_path": null,
                "confidence": confidence,
                "reason": "detected glibc 2.39 has no exact profile; using generic modern profile",
                "warnings": ["no exact glibc profile for detected version 2.39"]
            },
            "allocator_views_preset": allocator_views_preset,
            "features": {
                "layout": true,
                "tcache_candidates": true,
                "tcache_struct": false,
                "libc_symbols": false
            }
        }))
        .unwrap()
    }

    fn session_end_record(event_count: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "session_end",
            "exit_status": "unknown",
            "event_count": event_count
        }))
        .unwrap()
    }

    fn malloc_record(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "malloc",
                "event_id": event_id,
                "requested_size": "0x20",
                "returned_ptr": "0x1000",
                "chunk": null,
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap()
    }

    fn malloc_event_record(event_id: usize, returned_ptr: u64) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "malloc",
                "event_id": event_id,
                "requested_size": "0x20",
                "returned_ptr": format!("0x{returned_ptr:x}"),
                "chunk": null,
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap()
    }

    fn calloc_event_record(event_id: usize, returned_ptr: u64) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "calloc",
                "event_id": event_id,
                "nmemb": "0x2",
                "size": "0x10",
                "returned_ptr": format!("0x{returned_ptr:x}"),
                "chunk": null,
                "tracker_note": "NewAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap()
    }

    fn free_event_record(event_id: usize, ptr: u64) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "free",
                "event_id": event_id,
                "ptr": format!("0x{ptr:x}"),
                "chunk": null,
                "tcache_entry": null,
                "tracker_note": "FreedKnownChunk",
                "tracker_explanation": null
            }
        }))
        .unwrap()
    }

    fn realloc_event_record(
        event_id: usize,
        old_ptr: u64,
        returned_ptr: u64,
    ) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "realloc",
                "event_id": event_id,
                "old_ptr": format!("0x{old_ptr:x}"),
                "new_size": "0x40",
                "returned_ptr": format!("0x{returned_ptr:x}"),
                "old_chunk": null,
                "new_chunk": null,
                "tracker_note": "ReallocMovedKnownAllocation",
                "tracker_explanation": null
            }
        }))
        .unwrap()
    }

    fn free_record(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "event",
            "event": {
                "type": "free",
                "event_id": event_id,
                "ptr": "0x1000",
                "chunk": null,
                "tcache_entry": null,
                "tracker_note": "FreedKnownChunk",
                "tracker_explanation": null
            }
        }))
        .unwrap()
    }

    fn layout_record(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "heap_layout",
            "event_id": event_id,
            "heap_start": "0x1000",
            "heap_end": "0x2000",
            "chunks": [],
            "truncated": false,
            "chunks_omitted": 0
        }))
        .unwrap()
    }

    fn layout_record_with_chunks(
        event_id: usize,
        chunks: &[(u64, u64)],
    ) -> super::json::JsonTraceRecord {
        let chunks = chunks
            .iter()
            .map(|(chunk_addr, user_addr)| {
                serde_json::json!({
                    "chunk_addr": format!("0x{chunk_addr:x}"),
                    "user_addr": format!("0x{user_addr:x}"),
                    "prev_size": "0x0",
                    "size_raw": "0x31",
                    "size": "0x30",
                    "flags": ["PREV_INUSE"],
                    "state": "allocated",
                    "tcache_candidate": null,
                    "allocator_source": null
                })
            })
            .collect::<Vec<_>>();

        serde_json::from_value(serde_json::json!({
            "type": "heap_layout",
            "event_id": event_id,
            "heap_start": "0x1000",
            "heap_end": "0x3000",
            "chunks": chunks,
            "truncated": false,
            "chunks_omitted": 0
        }))
        .unwrap()
    }

    fn layout_record_with_annotated_chunk(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "heap_layout",
            "event_id": event_id,
            "heap_start": "0x1000",
            "heap_end": "0x2000",
            "chunks": [{
                "chunk_addr": "0x1000",
                "user_addr": "0x1010",
                "prev_size": "0x0",
                "size_raw": "0x31",
                "size": "0x30",
                "flags": ["PREV_INUSE"],
                "state": "freed",
                "tcache_candidate": {
                    "chunk_size": "0x30",
                    "index": 0
                },
                "allocator_source": {
                    "kind": "tcache_candidate",
                    "chunk_size": "0x30",
                    "index": 0
                }
            }],
            "truncated": false,
            "chunks_omitted": 0
        }))
        .unwrap()
    }

    fn tcache_record(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "observed_tcache_chains",
            "event_id": event_id,
            "chains": []
        }))
        .unwrap()
    }

    fn allocator_source_summary_record(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "allocator_source_summary",
            "event_id": event_id,
            "tcache_candidate_chunks": 7,
            "fastbin_chunks": 1,
            "unsorted_chunks": 0,
            "smallbin_chunks": 0,
            "largebin_chunks": 0,
            "total_free_list_chunks": 8,
            "warning_count": 0
        }))
        .unwrap()
    }

    fn allocator_source_delta_record(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "allocator_source_delta",
            "event_id": event_id,
            "tcache_candidate_chunks_delta": 0,
            "fastbin_chunks_delta": 1,
            "unsorted_chunks_delta": 0,
            "smallbin_chunks_delta": 0,
            "largebin_chunks_delta": 0,
            "total_free_list_chunks_delta": 1,
            "warning_count_delta": 0
        }))
        .unwrap()
    }

    fn heap_scan_record_with_findings(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "heap_scan",
            "event_id": event_id,
            "report": {
                "chunks_walked": 4,
                "allocated_observed": 1,
                "freed_observed": 1,
                "unknown_observed": 2,
                "allocator_source_chunks": 2,
                "warning_count": 2,
                "suspicious_count": 2,
                "top_validated": false,
                "heap_snapshot_truncated": false,
                "status": "suspicious",
                "findings": [{
                    "severity": "suspicious",
                    "kind": "allocator_source_allocated",
                    "chunk_addr": "0x1000",
                    "user_addr": "0x1010",
                    "message": "chunk match"
                }, {
                    "severity": "suspicious",
                    "kind": "allocator_source_allocated",
                    "chunk_addr": "0x2000",
                    "user_addr": "0x2020",
                    "message": "user match"
                }, {
                    "severity": "suspicious",
                    "kind": "allocator_source_allocated",
                    "chunk_addr": "0x3000",
                    "user_addr": "0x3030",
                    "message": "unrelated"
                }]
            }
        }))
        .unwrap()
    }

    fn heap_scan_record(event_id: usize) -> super::json::JsonTraceRecord {
        serde_json::from_value(serde_json::json!({
            "type": "heap_scan",
            "event_id": event_id,
            "report": {
                "chunks_walked": 3,
                "allocated_observed": 1,
                "freed_observed": 1,
                "unknown_observed": 1,
                "allocator_source_chunks": 2,
                "warning_count": 1,
                "suspicious_count": 1,
                "top_validated": false,
                "heap_snapshot_truncated": false,
                "status": "suspicious",
                "findings": [{
                    "severity": "suspicious",
                    "kind": "allocator_source_allocated",
                    "chunk_addr": "0x1000",
                    "user_addr": "0x1010",
                    "message": "allocator source disagrees with tracker"
                }]
            }
        }))
        .unwrap()
    }

    fn json_heap_scan_finding(kind: &str, message: &str) -> super::json::JsonHeapScanFinding {
        serde_json::from_value(serde_json::json!({
            "severity": "suspicious",
            "kind": kind,
            "chunk_addr": "0x1000",
            "user_addr": "0x1010",
            "message": message
        }))
        .unwrap()
    }

    fn event_from_record(record: super::json::JsonTraceRecord) -> super::json::JsonHeapEvent {
        let super::json::JsonTraceRecord::Event { event } = record else {
            panic!("expected event record");
        };
        event
    }

    fn summary_for_event(value: serde_json::Value) -> String {
        let event = serde_json::from_value(value).unwrap();
        format_replay_event_summary(&event)
    }
}
