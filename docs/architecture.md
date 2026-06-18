# Heapify Architecture

Heapify is split into small crates so tracing, heap interpretation, ELF lookup,
and command-line rendering can evolve independently.

## Crate Responsibilities

`heapify-cli`

- Owns command parsing, human output, JSON output, replay, replay TUI, and live
  TUI rendering.
- Converts trace updates into text, NDJSON records, and TUI state.
- Holds the user-facing workflow presets such as `--allocator-views basic` and
  `--allocator-views full`.

`heapify-core`

- Owns allocator event tracking and best-effort heap interpretation.
- Provides chunk header parsing, heap scan diagnostics, tcache observation,
  allocator source summaries, and glibc profile-backed metadata helpers.
- Keeps evidence categories explicit so observed events, candidate metadata,
  and profile-backed reads can be presented without overclaiming.

`heapify-debugger`

- Owns ptrace process control, target launch planning, breakpoints used for
  allocator tracing, symbolization hooks, process maps, and live control
  commands.
- Emits structured allocator trace updates to the CLI layer.
- Applies launch controls such as custom loader, library path, preload, cwd,
  environment overrides, and scripted stdin.

`heapify-elf`

- Owns ELF symbol and metadata lookup used by the debugger and CLI.
- Supports target symbol resolution and libc metadata discovery used by glibc
  profile selection.

## Trace Lifecycle

1. `heapify-cli` parses `trace-heap` arguments into a render configuration and
   target launch configuration.
2. `heapify-debugger` launches the target under ptrace and installs allocator
   tracing breakpoints according to the selected trace mode.
3. Allocator calls and returns become observed `HeapTraceEvent` values.
4. `heapify-core` updates tracker state and derives optional heap layouts,
   tcache candidates, allocator source summaries, profile-backed bin views, and
   heap scan findings.
5. `heapify-cli` renders updates as human text, writes NDJSON, feeds the live
   TUI, or all applicable outputs.

The observed allocator event stream is the most direct evidence. Any memory
walk, allocator-list traversal, or scan result is best-effort evidence layered
on top of that stream.

## Live TUI Update and Control Flow

The trace worker emits `LiveTraceUpdate` values. The live TUI consumes those
updates through a channel and keeps an in-memory timeline of events plus related
records such as heap layouts, allocator summaries, allocator deltas, and heap
scan reports.

User controls flow in the opposite direction:

1. The TUI translates keys such as pause, resume, next allocator event,
   instruction step, continue, or stop into live commands.
2. Commands are sent to the debugger control loop.
3. The debugger validates target state, applies ptrace control, and emits
   command status updates.
4. Command status updates are displayed in the TUI but are not serialized into
   NDJSON.

Live inspection is read-only. Heap jumps, pane focus, scrolling, and the chunk
inspector affect TUI state, not target memory.

Instruction stepping is Linux x86-64 ptrace-based. `stepi` steps one machine
instruction while the target is paused. `nexti` decodes the current x86-64
instruction, plants a temporary user-owned breakpoint at a call fall-through
address when needed, and otherwise behaves like a single instruction step.
Both refresh live register, code, and stack panes without adding allocator
events or JSON replay records. Allocator events can still be recorded while
`nexti` runs, and heap break conditions can interrupt it.

The live Code pane reads a best-effort x86-64 byte window around RIP and uses
iced-x86 to render a read-only disassembly listing. Pre-RIP instructions are
shown only when a candidate decode sequence lands exactly on RIP; uncertain
boundaries are omitted. Direct branch and call targets are annotated from
symbol metadata when available. `d` recenters the pane at RIP, and `:disas`
focuses the Code pane and recenters. Source stepping, a source-file viewer,
memory editing, and interactive breakpoint management remain future work.

v0.81 adds live register snapshot plumbing for Linux x86-64 stops. Snapshots are
captured as structured data and attached to live TUI state, but there is not yet
a dedicated register pane or instruction stepping.

## JSON and Replay Flow

When JSON output is enabled, `heapify-cli` serializes the same trace records
used by text rendering:

1. A `session_start` record captures target, launch, platform, profile, and
   feature metadata.
2. Each allocator event is serialized as an `event` record.
3. Optional related records are serialized when their views are enabled.
4. A `session_end` record captures final event count and exit status.

Replay reads NDJSON records back into `heapify-cli` and renders only what the
trace contains. Replay does not rerun the target and does not synthesize missing
heap snapshots, allocator lists, or scan records.

Live-only updates, including target command acknowledgements and break-match UI
notifications, are intentionally kept out of the trace file.

## glibc Profile System

glibc profiles describe layout assumptions Heapify can use for x86-64 glibc
metadata. Profiles may include chunk layout rules, tcache assumptions, and
profile-backed `main_arena` field offsets.

`--glibc-profile auto` uses detected libc metadata when available. Exact matches
are high confidence. Broad or unknown matches are medium confidence. Conflicts
or fallback to `glibc-x86_64-modern` are low confidence.

Profile selection affects allocator metadata interpretation. It does not make
unavailable offsets available, recover stripped debug data, or prove allocator
ownership.

## Trust Boundaries

Heapify reports different categories of evidence:

- Observed events: allocator calls and returns seen through ptrace.
- Best-effort metadata: heap walks, candidate tcache structures, scans, and
  pointer-shape heuristics read from target memory.
- Profile-backed evidence: allocator metadata decoded using selected glibc
  profile offsets and assumptions.

Allocator source membership is evidence, not definitive truth. Disagreement
between sources can be caused by real corruption, missed events, target-specific
allocator behavior, hardening, bad offsets, weak profile confidence, or false
positive candidates.
