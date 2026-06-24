# Heapify

Heapify is a Linux x86-64 glibc heap debugger and visualizer. It is a
ptrace-based allocator tracer that records allocator events, renders
best-effort heap and allocator metadata, and can replay saved traces.

Heapify is useful for understanding malloc/free behavior, glibc heap layouts,
tcache and bin state, allocator warnings, and small corruption fixtures. It is
not yet a full GDB replacement.

## What Heapify Is

Heapify traces allocator calls in a target process and correlates those
observed events with optional heap snapshots and allocator metadata views.

The core model is deliberately conservative:

- Observed allocator events are the strongest evidence.
- Heap walking and allocator metadata are best-effort process memory reads.
- Profile-backed allocator views depend on the selected glibc profile and its
  confidence.
- Allocator source membership is evidence, not definitive truth.

## Quick Start

Build Heapify:

```sh
cargo build --workspace
```

Build the bundled C examples:

```sh
./scripts/build-examples.sh
```

Trace a simple target:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/simple_malloc
```

Open the live TUI:

```sh
cargo run -p heapify-cli -- trace-heap --live-tui --allocator-views basic ./examples/simple_malloc
```

Save and replay a trace:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views basic --json-out trace.ndjson ./examples/simple_malloc
cargo run -p heapify-cli -- replay --tui trace.ndjson
```

## Core Workflows

Recommended starting points:

```sh
heapify trace-heap --allocator-views basic ./target
heapify trace-heap --live-tui --allocator-views basic ./target
heapify trace-heap --live-tui --allocator-views full --glibc-profile auto ./target
heapify trace-heap --allocator-views basic --json-out trace.ndjson ./target
heapify replay --tui trace.ndjson
```

During development from the workspace, prefix those commands with:

```sh
cargo run -p heapify-cli --
```

For menu-driven programs, script stdin:

```sh
cargo run -p heapify-cli -- trace-heap \
  --stdin-file examples/menu_script.txt \
  --allocator-views basic \
  ./examples/menu_heap
```

Launch controls for challenge-style setups:

```sh
cargo run -p heapify-cli -- trace-heap --cwd ./challenge ./chall
cargo run -p heapify-cli -- trace-heap --set-env GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./chall
cargo run -p heapify-cli -- trace-heap --clear-env --set-env PATH=/usr/bin ./chall
cargo run -p heapify-cli -- trace-heap --ld ./ld-linux-x86-64.so.2 --libc ./libc.so.6 ./chall
cargo run -p heapify-cli -- trace-heap --libc ./libc.so.6 --preload ./libc.so.6 ./chall
```

`--libc` supplies metadata for symbol and version lookup. It does not force the
target to load that libc; use `--preload` or `--ld` when you need launch-time
library control.

## Live TUI

Run:

```sh
cargo run -p heapify-cli -- trace-heap --live-tui --allocator-views basic ./examples/simple_malloc
```

Useful keys:

- `q` or `Esc`: stop the running target, or quit after it exits.
- `Space`: pause or resume.
- `p`: pause.
- `r`: resume.
- `n`: continue to the next allocator event and pause again.
- `S`: step into the next target source location.
- `N`: step over calls to the next target source location.
- `.`: step one machine instruction while paused.
- `,`: step over one machine instruction while paused.
- `c`: continue normally.
- `Tab`: cycle focus.
- `:`: open the command console.
- `j`/`k` or arrows: move or scroll the focused pane.
- `d`: recenter the code pane at RIP and resume follow-RIP mode.
- `g`: jump in the heap pane.
- `6`: open the memory tab.
- `i`: toggle chunk inspector.
- `h`: toggle heap pane.
- `s`: toggle allocator/scan pane.

The live TUI is read-only over target memory. `n` is allocator-event stepping.
`.` is Linux x86-64 ptrace-based machine-instruction stepping. `,` performs
instruction step-over: calls run until their fall-through instruction, while
non-call instructions behave like a single instruction step. Heapify may still
record allocator events while `nexti` runs; heap break conditions can interrupt
it. Source stepping requires target-executable DWARF source information and is
target-executable only in v0.94. Shared-library stepping and stack-aware frame
stepping remain future work.

The live TUI uses a debugger-style shell layout. The left column contains
registers, code context, allocator trace, and a console/status pane. The right
column has tabs for heap, stack, logs, maps, breakpoints, and memory. Use
`1`/`2`/`3`/`4`/`5`/`6` to switch right tabs, or `[` and `]` to move between them.
The heap tab contains the
existing heap layout, allocator/scan summary, related records, and chunk
inspector. The registers pane shows the latest register snapshot, marks changed
registers after each stop/event, and adds best-effort address classifications
for values that look like heap, stack, code, libc, loader, or mapped-file
pointers. The code pane shows the current RIP, best-effort symbol/source/object
context, and a read-only x86-64 disassembly window around RIP. When DWARF source
metadata points at a local source file, the Code pane can also show a read-only
source preview around the current line. Press `v` while the Code pane is focused
to toggle between disassembly and source mode. The current instruction/source
line is marked, raw instruction bytes are shown in disassembly mode, and direct
branch/call targets are annotated from symbols when available. The stack tab
shows a read-only memory snapshot around RSP and uses the same best-effort
address classification. The maps tab shows `/proc/<pid>/maps`-style memory
mappings. Address classification is evidence for inspection, not proof that a
value is a valid pointer.
The memory tab is a read-only mapped-memory browser. Use `:mem ADDR`,
`:inspect ADDR`, `:x/16gx ADDR`, or `:x/64xb ADDR`. `$rip`, `$rsp`, `$rbp`,
and `$rax` through `$r15` are supported as basic register aliases. Pointer
annotations are best-effort labels, not proof that an integer is a valid
pointer.

The breakpoints tab lists persistent user breakpoints with ID, enabled state,
resolved address, best-effort symbol/source metadata, and hit count. With the
breakpoints tab focused, `j`/`k` or arrows select rows, `Enter` inspects the
selected breakpoint address in the Code pane, `Space` toggles enable/disable,
and `x` deletes the selected breakpoint. Enter on a source breakpoint opens the
Code pane in source mode when source metadata is available. The Code pane marks
the current RIP with `>`, enabled breakpoint addresses with `B`, and the current
instruction at an enabled breakpoint with `*>`. Press `d` to return the Code
pane to RIP-follow mode without changing the source/disassembly mode.

The command console starts with a small command set that maps to existing live
TUI actions: `help`, `continue`, `pause`, `resume`, `source-step`, `ss`,
`source-next`, `sn`, `next`, `stepi`, `si`, `nexti`, `ni`, `break *ADDR`, `break SYMBOL`, `break FILE:LINE`,
`info breaks`, `disable ID`, `enable ID`, `delete ID`, `mem ADDR`,
`inspect ADDR`, `x/16gx ADDR`, `x/64xb ADDR`, `disas`, `disassemble`,
`source`, `list`, `stop`, `regs`, `stack`, `maps`, `heap ADDR`, `jump ADDR`,
and `tab NAME`. `:tab breaks` or `:tab breakpoints` opens the breakpoints tab.
`:source-step` and `:ss` step into the next target source location.
`:source-next` and `:sn` step over calls to the next target source location.
`:stepi` and `:si` step one machine instruction while paused. `:nexti` and
`:ni` perform instruction step-over. `:next` and `:n` step to the next allocator
event. `:break *0x4011a5` sets a persistent absolute-address
breakpoint; `:break main` sets a persistent symbol breakpoint with PIE rebasing
when applicable. `:break examples/simple_malloc.c:12` and `:b src/main.c:42`
set persistent source-line breakpoints. Source breakpoints resolve only in the
main target executable and require DWARF line info; source files must still be
available locally for text preview. Breakpoint add/delete/enable/disable
commands require the target to be paused. `:info breaks` lists breakpoints,
`:disable ID` and `:enable ID` toggle them, and `:delete ID` removes them.
`:disas` and `:disassemble` focus the Code pane and recenter at RIP. `:source`
and `:list` focus the Code pane in source mode. `n`/`:next` remains
allocator-event stepping. Shared-library source breakpoints, conditional
breakpoints, watchpoints, breakpoint command/actions, expression evaluation,
expression arithmetic, memory editing, register editing, source editing,
automatic source downloading, and a full source-file browser are not
implemented.

## Allocator Views

Allocator view presets keep common commands short:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/simple_malloc
cargo run -p heapify-cli -- trace-heap --allocator-views full --glibc-profile auto ./examples/simple_malloc
```

`--allocator-views basic` enables heap layout, observed tcache candidates, and
heap scan output.

`--allocator-views full` enables the profile-backed allocator views Heapify can
currently render, including tcache candidates, fastbins, unsorted bins,
smallbins, largebins, main arena metadata, and heap scan output. Full views work
best when Heapify has a confident glibc profile and any required arena offsets.

Allocator warnings and source summaries are evidence from enabled views. They
can indicate corruption, missed events, incompatible profile assumptions, or
candidate false positives.

## Break Conditions

Allocator-event break conditions pause the live TUI after matching allocator
events:

```sh
cargo run -p heapify-cli -- trace-heap --live-tui --allocator-views basic --break-on suspicious ./target
cargo run -p heapify-cli -- trace-heap --live-tui --break-on double-free ./target
cargo run -p heapify-cli -- trace-heap --live-tui --break-on-free 0x5555555592a0 ./target
cargo run -p heapify-cli -- trace-heap --live-tui --break-on-alloc-size 0x80 ./target
```

Supported conditions:

- `--break-on suspicious`: pause when heap scan or allocator diagnostics mark
  the event suspicious.
- `--break-on double-free`: pause when the event tracker sees a repeated free.
- `--break-on-free PTR`: pause when `free(PTR)` is observed.
- `--break-on-alloc-size SIZE`: pause on an allocation request size.

These are allocator-event break conditions, not source breakpoints.

## Replay

Replay renders saved NDJSON traces without running the target:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views basic --json-out trace.ndjson ./examples/simple_malloc
cargo run -p heapify-cli -- replay trace.ndjson
cargo run -p heapify-cli -- replay --events-only trace.ndjson
cargo run -p heapify-cli -- replay --no-chunks trace.ndjson
cargo run -p heapify-cli -- replay --tui trace.ndjson
```

Replay only shows records present in the trace file. It does not reconstruct
heap snapshots or allocator metadata that were not serialized during tracing.

See [docs/json-trace.md](docs/json-trace.md) for trace format notes.

## glibc Profiles

Heapify uses glibc profiles to interpret chunk headers and profile-backed
allocator metadata:

```sh
cargo run -p heapify-cli -- trace-heap --glibc-profile auto --allocator-views full ./target
cargo run -p heapify-cli -- trace-heap --glibc-profile glibc-2.35-x86_64 --allocator-views full ./target
```

`--glibc-profile auto` selects a profile from detected libc metadata when it
can. It reports confidence:

- `high`: exact detected version match.
- `medium`: version is unknown or the selected profile is a broad match.
- `low`: detection conflicts or auto falls back.

Unknown or unavailable versions fall back to `glibc-x86_64-modern`.
Auto-selection does not yet recover missing `main_arena` offsets, download debug
symbols, or infer unavailable profile fields.

## Corruption Examples

Educational corruption fixtures live under `examples/corruption/`:

```sh
./scripts/build-examples.sh
cargo run -p heapify-cli -- trace-heap --live-tui --allocator-views basic --break-on double-free ./examples/corruption/double_free
cargo run -p heapify-cli -- trace-heap --live-tui --allocator-views full --break-on suspicious ./examples/corruption/tcache_poison_shape
```

These fixtures demonstrate suspicious allocator shapes and diagnostics. Exact
behavior depends on glibc version and hardening settings.

## JSON Output

Write newline-delimited JSON:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views basic --json-out trace.ndjson ./examples/simple_malloc
head -n 1 trace.ndjson
cargo run -p heapify-cli -- replay trace.ndjson
```

`--json` writes NDJSON to stdout. `--json-out PATH` writes the same records to a
file and can be combined with `--live-tui`.

The JSON trace format is alpha and not yet a stable public API. See
[docs/json-trace.md](docs/json-trace.md).

## Limitations

- Linux x86-64 only.
- glibc-focused.
- Dynamically linked targets are the practical path.
- Allocator metadata is best-effort.
- Profile-backed views depend on profile confidence.
- No stack unwinding or backtrace yet.
- Source-level stepping is not implemented.
- Source breakpoints are limited to the main target executable with DWARF line
  info; shared-library source breakpoints are not implemented.
- No memory editing.
- No expression evaluator.
- No watchpoints.
- No conditional breakpoints.
- No breakpoint command/actions.
- No non-glibc allocator support yet.

## Current Debugger Capabilities

Heapify currently supports allocator tracing, live pause/resume/continue,
allocator-event stepping, `stepi`, `nexti`, read-only register/code/stack/maps
snapshots, read-only disassembly/source preview around RIP, command-console
control, break conditions on allocator diagnostics, persistent address, symbol,
main-executable source-line breakpoints, initial target-executable source
stepping, read-only memory browsing, NDJSON traces, and replay.

Shared-library source breakpoints, conditional breakpoints, breakpoint
command/actions, shared-library source stepping, stack-aware frame stepping,
stack unwinding/backtraces, watchpoints, memory editing, expression arithmetic,
pointer-chain following, and typed C structure parsing remain future work.

## Development / Tests

Common checks:

```sh
cargo fmt --all --check
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
cargo test --workspace
./scripts/build-examples.sh
./scripts/smoke.sh
```

Fast local commands:

```sh
cargo check -p heapify-cli
cargo test -p heapify-core
cargo test -p heapify-debugger
cargo test --workspace --lib
cargo test --workspace -- --ignored
```

`cargo-nextest` is useful optional developer tooling for faster local test
runs, but it is not required by the project.

Project notes:

- [docs/architecture.md](docs/architecture.md)
- [docs/json-trace.md](docs/json-trace.md)
- [examples/README.md](examples/README.md)

## Roadmap

v0.80 is the first usable alpha cleanup: documentation, CLI clarity, examples,
smoke scripts, and project organization.

v0.81 introduces register snapshot plumbing for live debugger stops.

v0.82 and v0.83 add the live debugger shell layout and register pane. v0.84
adds code-context plumbing and a code pane with RIP, symbol/source/object
fields.

v0.85 adds read-only stack snapshot plumbing and a stack tab around RSP, with
best-effort heap/code pointer annotations. Stack unwinding, backtraces, memory
editing, watchpoints, and general memory browsing remain future work.

v0.86 adds a read-only maps tab and centralizes best-effort address
classification for registers and stack values.

v0.87 through v0.90 add allocator break conditions, live command-console
control, `stepi`, `nexti`, read-only x86-64 disassembly around RIP, and
register/code/stack refreshes after debugger stops. v0.91 adds persistent
absolute-address and symbol breakpoints managed from the live console. v0.92
adds a live Breakpoints tab with enable/disable/delete controls, breakpoint
hit counts, code inspection, and breakpoint markers in disassembly. v0.93 adds
main-executable DWARF source-line breakpoints and Code pane source preview
navigation. v0.94 adds initial target-executable source-step/source-next.
v0.95 adds a read-only memory browser and typed address inspection.

Near-term work is expected to focus on reliability of existing heap and
allocator views, trace compatibility, diagnostics quality, and UI clarity. Full
debugger features such as shared-library source breakpoints, conditional
breakpoints, breakpoint command/actions, source stepping, stack
unwinding/backtraces, watchpoints, memory editing, and expression evaluation are
future work, not part of this milestone.
