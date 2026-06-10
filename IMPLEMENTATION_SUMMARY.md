# Heapify Implementation Summary

Heapify is a Rust, Linux x86-64, debugger-assisted glibc heap tracer and
visualizer. It launches a target under `ptrace`, sets allocator breakpoints,
emits allocator events after calls return, decodes best-effort glibc heap
metadata, tracks observed allocation state, records allocator caller addresses,
symbolizes process executable mappings when possible, enriches target callers
with DWARF source locations when available, emits structured live trace updates,
and renders the result as human output, NDJSON, plain replay, or a read-only
replay TUI.

The project is intentionally incremental. It currently focuses on allocator
call tracing, chunk snapshots, observed free-list evidence, profile-backed
glibc structure reads, target-executable source lookup, launch scripting,
profile-backed fastbin/unsorted/smallbin/largebin traversal, and replayable
diagnostics. It does not yet implement definitive full glibc bin ownership
analysis.

## Workspace

- `heapify-cli`: command parsing, render configuration, live trace update
  emission, output sinks for human/JSON behavior, JSON DTOs, JSON writing,
  replay parsing/rendering, replay session indexing, replay TUI, and
  orchestration of tracker/tcache/arena/bin views.
- `heapify-core`: allocator event model, glibc profiles, chunk/header decoding,
  heap snapshot data model, tcache candidate tracking, allocator-source
  summaries/warnings, heap scan reports/findings, and observed allocation state
  tracking.
- `heapify-debugger`: target launch/control via `ptrace`, software
  breakpoints, register/memory reads, process-map parsing, allocator symbol
  resolution, runtime caller symbolization, libc metadata detection, heap
  snapshot reads, and best-effort arena/bin readers for fastbins, unsorted
  bins, regular-bin sentinels, smallbins, and largebins.
- `heapify-elf`: ELF type detection, entry-point lookup, symbol lookup, symbol
  listing, prefix/versioned symbol matching, and x86-64 PLT fallback lookup.

Main dependencies:

- `anyhow` for error context.
- `nix` with `process` and `ptrace` features for process control.
- `object` for ELF parsing.
- `addr2line` and `gimli` for in-process target-executable DWARF/source-line
  lookup.
- `libc` for low-level stdin redirection helpers.
- `serde` and `serde_json` for trace DTOs.
- `ratatui` and `crossterm` for replay TUI rendering.
- `clap` for trace-mode and allocator-view preset value enums.

## Commands

```sh
heapify run <program> [args...]
heapify break <program> <addr> [args...]
heapify break-symbol <program> <symbol> [args...]
heapify trace-heap [options] <program> [args...]
heapify replay [--events-only] [--no-chunks] [--tui] <trace_file>
```

- `run`: launches the program under `ptrace` and continues it until exit.
- `break`: launches the program and sets one software breakpoint at a runtime
  address.
- `break-symbol`: resolves a symbol from the target ELF and uses the
  one-breakpoint flow. This command is simple and does not have the full
  PIE/runtime-symbol handling of `trace-heap`.
- `trace-heap`: traces `malloc`, `free`, `calloc`, and `realloc`.
- `replay`: reads saved NDJSON traces and renders only the records present in
  the file. `--tui` opens a read-only terminal UI.

## Live Trace Update Stream

`trace-heap` now routes session start, allocator events, related allocator-view
records, and session end through `LiveTraceUpdate` values consumed by a
`LiveTraceSink`. `CurrentOutputSink` implements the existing behavior: it
renders human output when enabled and writes the same NDJSON trace records when
JSON output is enabled.

The trace loop still uses the existing debugger, tracker, tcache, arena, bin,
allocator warning, and heap scan logic. The refactor moves output ownership
behind a sink boundary so a future live TUI can subscribe to the same update
stream without changing debugger semantics or the saved trace format.

## trace-heap Options

- `--events-only`: event lines/records only. Suppresses status lines, chunks,
  tracker notes, explanations, layouts, tcache views, arena views, bin views,
  caller metadata in human/replay output, and allocator-source summaries.
- `--no-chunks`: hides chunk/detail records while keeping event lines, tracker
  notes, explanations, and caller metadata. Also suppresses layout/bin detail
  output that depends on chunk snapshots.
- `--layout`: prints compact heap layout snapshots.
- `--max-layout-chunks N`: maximum rendered layout rows, default `32`.
- `--allocator-views none|basic|full`: additive convenience preset. `none`
  enables no extra views. `basic` enables layout, tcache candidates, and heap
  scan. `full` enables all profile-backed allocator views plus heap scan.
- `--all-allocator-views`: alias for the `full` preset. It conflicts with
  `--allocator-views`.
- `--tcache-candidates`: prints observed tcache candidate chains and enables
  layout annotations from observed tcache membership.
- `--max-tcache-chain N`: observed tcache chain traversal limit, default `32`.
- `--tcache-struct`: prints one heuristic `tcache_perthread_struct` candidate
  and decoded non-empty bins.
- `--main-arena`: locates `main_arena` through loaded libc symbols when
  available.
- `--main-arena-offset OFFSET`: computes `main_arena` as
  `libc_load_base + OFFSET` and implies `--main-arena`.
- `--main-arena-top`: reads `main_arena.top` using the active profile offset
  when available and implies `--main-arena`.
- `--main-arena-top-offset OFFSET`: reads `main_arena.top` at an explicit field
  offset, overrides profile offsets, and implies `--main-arena`.
- `--arena-experiment`: scans early `main_arena` fields for heap-pointer and
  top-like candidates. Implies `--main-arena`.
- `--fastbin-experiment`: scans early `main_arena` pointer fields before `top`
  for heap pointers that may be fastbin heads. Implies `--main-arena`.
- `--fastbins`: reads profile-backed fastbin head fields from `main_arena` and
  traverses safe-linked chains. Implies `--main-arena`.
- `--max-fastbin-chain N`: fastbin traversal limit, default `32`.
- `--unsorted-experiment`: scans arena field pairs for possible unsorted-bin
  `fd`/`bk` candidates. Implies `--main-arena`.
- `--bin-experiment`: experimental regular-bin sentinel-like `fd`/`bk` scan
  after the unsorted-bin region. Implies `--main-arena`.
- `--unsorted-bin`: reads a profile-backed unsorted-bin sentinel and best-effort
  chain. Implies `--main-arena`.
- `--max-unsorted-chain N`: unsorted-bin traversal limit, default `32`.
- `--regular-bins`: reads profile-backed regular-bin sentinel `fd`/`bk` pairs
  from `main_arena`. Implies `--main-arena`.
- `--max-regular-bins N`: regular-bin sentinel output limit, default `16`.
- `--smallbins`: reads and traverses profile-backed smallbin chains. Implies
  `--regular-bins` and `--main-arena`.
- `--max-smallbin-chain N`: smallbin traversal limit, default `32`.
- `--largebins`: reads and traverses profile-backed largebin chains. Implies
  `--regular-bins` and `--main-arena`.
- `--max-largebin-chain N`: largebin traversal limit, default `32`.
- `--heap-scan`: prints a compact best-effort consistency report built from
  heap snapshots, tracker state, allocator-source summaries/warnings, parsed
  allocator views, validation statuses, and optional `main_arena.top`
  validation.
- `--trace-mode plt|libc`: `plt` is the default and traces target executable
  PLT entries; `libc` traces allocator symbols in loaded libc.
- `--libc-symbols`: legacy alias for `--trace-mode libc`.
- `--libc PATH`: supplies a libc ELF file for libc symbol offsets and version
  metadata. This does not preload libc or change the loader; runtime rebasing
  still uses the libc mapping loaded in the target process.
- `--ld PATH`: runs the target through a custom dynamic loader.
- `--library-path PATH`: passes `--library-path PATH` to the custom loader.
- `--preload PATH`: sets `LD_PRELOAD=PATH` in the traced child before exec.
- `--cwd PATH`: changes the traced child's working directory before exec.
- `--set-env KEY=VALUE`: repeatable environment override for the traced child.
  Values are applied to the child but are not stored in trace metadata.
- `--unset-env KEY`: repeatable environment removal for the traced child.
- `--clear-env`: clears the traced child's environment before explicit unsets
  and sets are applied.
- `--stdin-file PATH`: redirects traced-child stdin from a script file.
- `--stdin-text TEXT`: feeds traced-child stdin from an in-memory text script.
  Mutually exclusive with `--stdin-file`.
- `--glibc-profile NAME`: selects allocator layout assumptions. Available
  profiles are `glibc-x86_64-modern` and `glibc-2.35-x86_64`.
- `--json`: writes NDJSON to stdout and suppresses human/status output.
- `--json-out PATH`: writes NDJSON to a file and prints a completion message
  unless `--events-only` suppresses it.

Preset behavior:

- Presets are applied after individual flags are parsed and are additive with
  explicit flags. For example, `--allocator-views basic --fastbins` enables the
  basic preset plus fastbins and the existing fastbin `main_arena` implication.
- Existing implications still apply: fastbins, unsorted bins, regular bins, and
  `main_arena.top` imply `--main-arena`; smallbins and largebins imply
  regular bins.
- Non-`none` presets print `[heapify] allocator views preset: <preset>` in
  human mode. This status line is suppressed by `--events-only` and by JSON
  stdout mode.

## Debugger Lifecycle

Heapify launches the target with `fork`/`execvp` and traces the child with
`ptrace`.

For software breakpoints:

- Breakpoints patch the target word's low byte with `0xcc`.
- On hit, Heapify computes `hit_addr = RIP - 1`, rewinds `RIP`, disables the
  breakpoint, single-steps the original instruction, and re-enables persistent
  breakpoints.
- Temporary return breakpoints are removed after handling.

For allocator tracing:

- Heapify builds an `ExecPlan` from `LaunchConfig` before forking.
- Normal launch execs the target directly with argv `[target, args...]`.
- Preload launch keeps direct exec but sets `LD_PRELOAD`.
- Custom-loader launch execs the loader with argv
  `[loader, --library-path <path>, target, args...]` when a library path is
  available.
- With `--ld --libc` and no explicit `--library-path`, the effective library
  path defaults to the supplied libc's parent directory.
- Launch plans also carry optional cwd, environment clear/unset/set controls,
  and stdin scripting configuration.
- In the child, after `ptrace::traceme` and before `execvp`, Heapify applies:
  cwd change, environment clear/unsets/sets, and stdin redirection.
- User `--set-env` assignments are applied before automatic `LD_PRELOAD`, so
  explicit `--preload` wins over a user-provided `LD_PRELOAD` key.
- `--stdin-file` opens the file in the child and `dup2`s it onto stdin.
- `--stdin-text` creates a pipe before fork; the child reads from the pipe and
  the parent writes the scripted bytes then closes the write end. This is
  scripted input only, not interactive terminal passthrough or prompt matching.
- Target executable symbol resolution and main-target caller formatting still
  use the original target path, not the loader.
- Entry breakpoints read x86-64 call arguments from registers:
  `rdi`, `rsi`, and return value `rax` at return breakpoints.
- At allocator entry, Heapify reads the caller return address from target memory
  at `RSP`. This raw address is stored as `caller_addr` when available.
- Caller-address capture is best-effort and non-fatal. A failed stack read does
  not abort tracing.
- Return breakpoint state carries allocator arguments, `event_id`, prior chunk
  data where needed, and `caller_addr`.
- `malloc`, `calloc`, and `realloc` emit after return so returned pointers are
  known.
- `free` emits after return so freed user data can be inspected for tcache
  candidate decoding.
- Chunk reads, tcache reads, heap snapshots, arena reads, bin reads, and caller
  symbolization are all best-effort and non-fatal.

Managed breakpoint variants:

- Entry: `MallocEntry`, `FreeEntry`, `CallocEntry`, `ReallocEntry`.
- Return: `MallocReturn`, `FreeReturn`, `CallocReturn`, `ReallocReturn`.

## Symbol and Map Resolution

Trace modes:

- Target mode resolves target executable PLT symbols for allocator calls.
- Non-PIE target addresses are used unchanged.
- PIE target addresses are rebased with
  `load_base = executable_mapping.start - executable_mapping.offset`.
- Libc mode finds the executable libc mapping, computes the same load base, and
  resolves allocator symbols such as `__libc_malloc`/`malloc`,
  `__libc_free`/`free`, `__libc_calloc`/`calloc`, and
  `__libc_realloc`/`realloc`.
- Target PLT and libc modes are mutually exclusive.

Process map support:

- `/proc/<pid>/maps` parsing exposes start/end, permissions, offset, dev,
  inode, and pathname.
- Heapify locates `[heap]`, target executable mappings, and executable libc
  mappings.
- Libc path matching is tolerant of common libc/glibc path names.
- `mapping_load_base` checks for underflow.
- In libc trace mode, `--libc PATH` changes the symbol-offset file but not the
  runtime base. Heapify still finds the loaded libc mapping in the target and
  computes runtime addresses as `loaded_libc_base + supplied_symbol_offset`.
- `main_arena` symbol lookup also uses the supplied libc file when present,
  while `--main-arena-offset` remains relative to the loaded libc base.

Libc metadata:

- Heapify detects libc path and a best-effort version string.
- Metadata keeps the loaded libc path for compatibility and can also include a
  supplied libc path plus a best-effort path-match result.
- If `--libc` is supplied, version detection uses the supplied file; otherwise
  it uses the loaded libc file.
- Heapify warns when the supplied libc differs from the loaded libc because
  symbol offsets may be wrong unless the target is actually running that libc.
- Version detection scans libc bytes for printable `GNU C Library` release text
  and falls back to the highest `GLIBC_2.xx` symbol-version string.
- Trace session metadata records selected glibc profile, optional libc
  metadata, and optional suggested profile.
- Suggested profiles are metadata-only; Heapify never auto-switches behavior.

## Caller Attribution and Symbolization

Allocator events carry `caller_addr: Option<u64>`, the raw allocator return
address captured from the target stack at allocator entry. This address usually
points to the instruction immediately after the call into the allocator.

`heapify-debugger` provides:

- `RuntimeSymbol { object_path, object_name, name, runtime_addr, size }`
- `SourceLocation { file, line, column }`
- `SymbolizedAddress { addr, object_name, symbol, symbol_addr, offset,
  source }`
- `ProcessSymbolizer`
- `TargetSymbolizer` as a main-executable compatibility wrapper
- `TargetSourceMapper` for target-executable DWARF/source-line lookup

`ProcessSymbolizer::from_process(pid, program_path)`:

- Reads `/proc/<pid>/maps`.
- Selects executable file mappings with absolute pathnames.
- Skips anonymous mappings and bracketed special mappings such as `[vdso]`.
- Deduplicates runtime objects by canonical path plus load base.
- Calls `heapify_elf::list_symbols(path)` for each object and skips objects
  that cannot be parsed.
- Rebases each symbol by that object's mapping load base.
- Includes the main executable through the existing main-target fallback if map
  matching is tricky.
- Sorts all runtime symbols by address.
- Fails best-effort; tracing continues without symbolization if construction
  fails.

`ProcessSymbolizer::symbolize(addr)`:

- Finds the nearest previous runtime symbol across all loaded executable
  objects.
- Computes `offset = addr - symbol.runtime_addr`.
- Accepts `offset <= size` for sized symbols, including `offset == size` to
  tolerate return addresses just after a call/instruction.
- Accepts zero-size symbols only within a bounded maximum offset.
- Returns `None` when no plausible symbol exists.

Rendering:

- Main-executable callers show `caller: symbol+0xoffset (0xaddr)`.
- Shared-library callers show `caller: object!symbol+0xoffset (0xaddr)`.
- Offset zero omits `+0x0`.
- If source location is available, the next indented line is
  `at <file>:<line>` or `at <file>:<line>:<column>`.
- If symbolization is unavailable but `caller_addr` exists, output falls back
  to `caller: 0xaddr`.
- `--events-only` suppresses caller lines.
- `--no-chunks` still shows caller lines.

Source lookup:

- Main executable and shared-library symbols from executable file mappings.
- Source-line lookup is target-executable only.
- `TargetSourceMapper::from_process(pid, program_path)` reads the target ELF,
  builds an `addr2line`/`gimli` context, detects PIE with `heapify_elf::is_pie`,
  and stores the target load base from the executable mapping when needed.
- `TargetSourceMapper::lookup(runtime_addr)` converts runtime address to a
  target-relative address and applies `saturating_sub(1)` because
  `caller_addr` is a return address.
- Lookup is best-effort and non-fatal. If source information is missing or
  unavailable, existing symbol-only caller output is preserved.
- Shared-library source lookup and external debug-file discovery are not
  implemented.

## ELF Support

`heapify-elf` provides:

- `ElfFileType::{Executable, PositionIndependentExecutable, SharedObject, Other}`
- `ElfSymbol { name, addr, size }`
- `elf_file_type(path)`
- `is_pie(path)`
- `entry_point(path)`
- `find_symbol(path, name)`
- `find_symbol_by_prefix(path, prefix)`
- `list_symbols(path)`

`ET_EXEC` is treated as executable. `ET_DYN` is treated as PIE for the current
target use case. Symbol lookup checks regular symbols and dynamic symbols.
Prefix lookup also has an x86-64 `.plt`/`.plt.sec` fallback through
`.rela.plt`, `.dynsym`, and `.dynstr`, so imported names such as `malloc@plt`
can be resolved.

`list_symbols` includes named symbols with non-zero addresses from regular and
dynamic symbol tables, records sizes when available, sorts by address, and
deduplicates repeated name/address pairs.

## Core Events

`HeapTraceEvent` variants:

- `Malloc { event_id, requested_size, returned_ptr, chunk, caller_addr }`
- `Free { event_id, ptr, chunk, tcache_entry, caller_addr }`
- `Calloc { event_id, nmemb, size, returned_ptr, chunk, caller_addr }`
- `Realloc { event_id, old_ptr, new_size, returned_ptr, old_chunk, new_chunk,
  caller_addr }`

Events carry parsed chunk metadata when available. `Realloc` can carry both old
and new chunk metadata. The event model stores raw caller addresses only;
symbolized caller data is produced at render/JSON time and persisted in JSON as
separate DTO fields.

## glibc Profiles and Chunk Decoding

`GlibcProfile` captures:

- pointer size
- malloc alignment
- chunk header size
- minimum chunk size
- tcache counts/entries offsets
- tcache count size
- tcache-struct candidate size range and scan count
- optional `main_arena.top` offset
- optional fastbin head offset/count
- optional unsorted-bin sentinel offset
- optional regular-bin sentinel offset/count

Profiles:

- `glibc-x86_64-modern`: conservative default x86-64 profile. Pointer size
  `8`, alignment `0x10`, header `0x10`, minimum chunk `0x20`, 64 tcache bins,
  counts at `0x0`, entries at `0x80`, `u16` counts, tcache struct candidate
  size `0x280..=0x2a0`, first 8 heap chunks scanned, and no known arena/bin
  offsets.
- `glibc-2.35-x86_64`: same core assumptions plus
  `main_arena_top_offset = 0x60`, fastbins offset `0x10`, 10 fastbin heads, and
  unsorted-bin/regular-bin offset `0x70` with 126 regular-bin heads.

Profile helpers include registry lookup, profile listing, version-based
suggestion, size masking, chunk-size normalization, alignment checks, tcache
chunk-size calculation, and fastbin chunk-size calculation.

Chunk decoding:

- `chunk_addr = user_addr - profile.chunk_header_size`
- `prev_size` is read from `chunk_addr`
- `size_raw` is read from `chunk_addr + profile.pointer_size`
- `size = profile.normalize_chunk_size(size_raw)`
- flags: `PREV_INUSE` (`0x1`), `IS_MMAPPED` (`0x2`), and `NON_MAIN_ARENA`
  (`0x4`)

Heap snapshots walk the `[heap]` mapping with profile min-size/alignment rules.
Walking stops and marks the snapshot truncated on invalid size, misalignment,
overflow, passing heap end, exceeding the hard chunk limit, or read failure
after some chunks. Observed allocation state comes from Heapify events, not
glibc chunk flags.

## Allocation Tracker

`HeapTracker` tracks observed user-pointer state as `Allocated` or `Freed`.

Tracker notes cover:

- new allocations
- reused freed chunks
- freed known chunks
- possible double frees
- frees of unknown pointers
- null malloc/free/calloc
- calloc as allocation
- realloc null-as-malloc
- realloc in-place
- realloc moved
- realloc failed and old pointer remains allocated
- realloc pointer with zero size freeing old pointer
- realloc of unknown old pointer

Tracker explanations are intentionally lightweight. For example, a reused freed
chunk with parsed `chunk.size <= 0x80` is described as likely tcache/fastbin
sized, but this is not a definitive allocator-source classification.

## Tcache Candidate Features

Free events decode the first word of freed user data as a safe-linked next
pointer candidate:

```text
decoded_next = encoded_next ^ (storage_addr >> 12)
```

This is candidate evidence only and does not prove tcache membership.

`ObservedTcacheTracker`:

- Observes `Free` events with non-null pointer, parsed chunk, and tcache entry
  candidate.
- Reconstructs observed candidate chains by chunk size.
- Treats latest free per size as the observed head.
- Follows decoded next pointers through observed entries.
- Stops on `NULL`.
- Includes unknown non-zero next pointers as `?`.
- Truncates on max entries or cycles.
- Provides membership lookup by user pointer.

`--tcache-struct` heuristic:

- Scans only the first profile-configured heap chunks.
- Ignores chunks whose user pointers are already known to the tracker.
- Picks the first unobserved chunk in the profile tcache-struct size range.
- Records reason
  `early heap chunk with plausible tcache_perthread_struct size`.
- Decodes 64 counts and 64 entry heads using profile offsets/count sizes.
- Renders only non-empty bins.

When `--tcache-struct` and `--tcache-candidates` are both enabled:

- `compare_tcache_snapshot_with_observed` compares decoded tcache heads/counts
  with observed chains.
- Comparison statuses include matching head/count, head match with count
  difference, head match with incomplete observed chain, head difference, and
  missing observed chain.
- `validate_tcache_snapshot_candidate` checks `head_in_heap`,
  `head_known_freed`, `observed_nodes_same_size`, and
  `count_matches_observed`.
- Validation values are `yes`, `no`, or `unknown`.
- Aggregate status is `plausible`, `incomplete`, or `suspicious`.

## main_arena Features

Heapify can locate or inspect `main_arena` in several ways:

- `--main-arena` resolves the libc symbol when available.
- `--main-arena-offset` computes the arena from libc load base plus a manual
  offset.
- `--arena-experiment` scans early pointer-sized fields for heap pointers and
  role hints such as `candidate_top` and `heap_pointer`.
- `--main-arena-top` reads the top pointer through the active profile offset
  when known.
- `--main-arena-top-offset` reads the top pointer from a manual field offset.

Top statuses:

- `MatchesWalkedChunk`
- `PointsIntoHeap`
- `OutsideHeap`
- `Unavailable`

View statuses:

- `validated`
- `points_into_heap`
- `outside_heap`
- `unavailable`

If the top source is profile-backed and the value matches a walked heap chunk,
Heapify emits a clean `main_arena_view`. Manual offsets, weak validation, or
unavailable data keep the output in candidate/diagnostic form.

## Fastbin Features

Heapify has two fastbin-oriented features. Both are best-effort.

### Fastbin Experiment

`--fastbin-experiment` scans pointer-sized arena fields from `0x0` up to the
profile `main_arena_top_offset` when available, otherwise `0x0..0x80`.

It:

- skips nulls and individual read failures
- includes values inside the heap
- checks whether each value equals a walked chunk address
- records possible chunk size when matched
- maps `value + profile.chunk_header_size` through the tracker for
  `known_freed = yes|no|unknown`
- returns an empty candidate list if no heap pointers are found
- returns an error only when all reads fail

### Profile-Backed Fastbins

`--fastbins` reads fastbin head fields from `main_arena` using the selected
profile.

Data model:

- `FastbinHead { index, chunk_size, field_offset, head, points_into_heap,
  matches_heap_chunk, known_freed }`
- `FastbinNode { chunk_addr, user_addr, encoded_next, decoded_next, chunk_size,
  matches_heap_chunk, known_freed }`
- `FastbinChain { index, chunk_size, head, nodes, truncated,
  stopped_on_unknown_next, cycle_detected }`
- `FastbinsSnapshot { arena_addr, heads, chains }`

Traversal:

- Reads every configured head, including `head = 0`.
- For each non-null head, reads the encoded `fd` from the chunk user area.
- Decodes safe-linked next pointers with the storage address.
- Follows plausible heap-aligned chunk addresses.
- Stops on `NULL`, unknown next, cycle, or `--max-fastbin-chain`.

Validation checks:

- head in heap
- nodes same size
- nodes known freed
- chain complete

Statuses are `plausible`, `incomplete`, or `suspicious`.

Fastbin membership is used by heap-layout allocator-source annotations and is
preferred over observed tcache candidate membership when both match.

## Unsorted-Bin Features

Heapify has experimental and profile-backed unsorted-bin views.

### Unsorted Experiment

`--unsorted-experiment` scans arena field pairs for possible unsorted-bin
`fd`/`bk` pointers.

It records:

- field offset
- `fd` and `bk`
- whether each pointer points into the heap
- whether each matches a walked chunk
- whether each is known freed according to the tracker
- role string `unsorted_candidate`

### Profile-Backed Unsorted Bin

`--unsorted-bin` reads the unsorted-bin sentinel at the profile offset when
available and follows the chain best-effort.

Data model:

- `UnsortedBinSnapshot { arena_addr, field_offset, fd, bk, fd_points_into_heap,
  bk_points_into_heap, fd_matches_heap_chunk, bk_matches_heap_chunk,
  fd_known_freed, bk_known_freed, chain }`
- `UnsortedBinChain { sentinel_addr, head, tail, nodes, empty, truncated,
  stopped_on_unknown_next, cycle_detected, fd_bk_consistent }`
- `UnsortedBinNode { chunk_addr, user_addr, fd, bk, chunk_size,
  matches_heap_chunk, known_freed, fd_points_to_sentinel,
  bk_points_to_sentinel }`

Validation checks:

- head in heap
- `fd`/`bk` consistency
- nodes known freed
- chain complete

Statuses are `plausible`, `incomplete`, or `suspicious`.

Unsorted membership is included in allocator-source annotations and summary
counts when available.

## Regular, Small, and Large Bin Features

Heapify has both an experimental regular-bin sentinel scan and profile-backed
regular/small/large bin readers. These views remain best-effort and
profile-dependent; they do not prove definitive bin ownership.

### Regular-Bin Experiment

`--bin-experiment` is experimental groundwork for regular-bin discovery. It
scans for sentinel-like `fd`/`bk` pairs after the unsorted-bin region and does
not annotate heap layout rows by itself.

`read_bin_experiment(pid, arena_addr, heap_snapshot, heap_tracker, profile)`:

- Starts scanning at `profile.main_arena_unsorted_bin_offset.unwrap_or(0x70)`.
- Scans through `scan_start + 0x800` in `0x10`-byte steps.
- Reads an `fd` word at `arena_addr + offset` and a `bk` word at
  `arena_addr + offset + profile.pointer_size`.
- Skips individual read failures and returns an error only if every read fails.
- Includes a candidate when either pointer points into the heap or into
  `arena_addr..arena_addr+0x1000`.
- Records whether `fd`/`bk` match walked heap chunk addresses.
- Maps heap pointers through `ptr + profile.chunk_header_size` to query the
  allocation tracker for known freed/allocated state.
- Uses role string `bin_sentinel_candidate`.

Human and replay rendering show:

- `bin experiment:`
- arena address
- either `candidates: none` or candidate rows with `offset`, `fd`, `bk`,
  heap/arena flags, known-freed status, and role

### Profile-Backed Regular Bins

`--regular-bins` reads sentinel `fd`/`bk` pairs from `main_arena` using
profile-provided `bins` offset and bin count metadata.

Data model:

- `RegularBinHead { index, glibc_bin_index, role, chunk_size, field_offset,
  fd, bk, empty, fd_points_into_heap, bk_points_into_heap,
  fd_points_into_arena, bk_points_into_arena, fd_matches_heap_chunk,
  bk_matches_heap_chunk, fd_known_freed, bk_known_freed }`
- `RegularBinsSnapshot { arena_addr, bins_offset, heads }`

Roles classify heads as unsorted, smallbin, largebin, or unknown according to
profile bin geometry. `--max-regular-bins` limits rendered heads and defaults
to `16`.

### Profile-Backed Smallbins

`--smallbins` implies `--regular-bins`, selects regular-bin heads classified as
smallbins, computes their sentinel addresses, and follows `fd` chains
best-effort.

Data model:

- `SmallbinChain { regular_index, glibc_bin_index, expected_chunk_size,
  sentinel_addr, head, tail, nodes, empty, truncated,
  stopped_on_unknown_next, cycle_detected, fd_bk_consistent }`
- `SmallbinNode { chunk_addr, user_addr, fd, bk, chunk_size,
  matches_heap_chunk, known_freed, fd_points_to_sentinel,
  bk_points_to_sentinel }`
- `SmallbinsSnapshot { arena_addr, bins_offset, chains }`

Validation checks:

- head in heap
- nodes same size
- `fd`/`bk` consistency
- nodes known freed
- chain complete

Statuses are `plausible`, `incomplete`, or `suspicious`.

### Profile-Backed Largebins

`--largebins` implies `--regular-bins`, selects regular-bin heads classified as
largebins, computes their sentinel addresses, and follows `fd` chains
best-effort.

Data model:

- `LargebinChain { regular_index, glibc_bin_index, sentinel_addr, head, tail,
  nodes, empty, truncated, stopped_on_unknown_next, cycle_detected,
  fd_bk_consistent }`
- `LargebinNode { chunk_addr, user_addr, fd, bk, fd_nextsize, bk_nextsize,
  chunk_size, matches_heap_chunk, known_freed, fd_points_to_sentinel,
  bk_points_to_sentinel, fd_nextsize_points_into_heap,
  bk_nextsize_points_into_heap, fd_nextsize_points_into_arena,
  bk_nextsize_points_into_arena }`
- `LargebinsSnapshot { arena_addr, bins_offset, chains }`

Validation checks:

- head in heap
- `fd`/`bk` consistency
- nodes known freed
- chain complete

Statuses are `plausible`, `incomplete`, or `suspicious`. Largebin nodes record
`fd_nextsize`/`bk_nextsize` evidence, but nextsize ordering validation is not
implemented.

Smallbin and largebin membership is included in allocator-source annotations
and summary counts when available.

## Allocator Source Summaries and Warnings

Heapify combines evidence from observed tcache candidates, parsed fastbins,
parsed unsorted-bin chains, parsed smallbin chains, and parsed largebin chains
into allocator-source annotations.

Allocator-source features:

- Layout rows can show allocator source membership.
- Fastbin membership is preferred over tcache candidate membership when both
  apply.
- Summaries count tcache candidate chunks, fastbin chunks, unsorted chunks,
  smallbin chunks, largebin chunks, unique total free-list chunks, and warning
  count.
- Deltas show changes since the previous emitted summary.
- Warnings report conflicting or suspicious allocator-source evidence, such as
  overlapping source membership or a free-list source pointing to a tracker
  state that looks allocated.

These records are evidence summaries, not definitive allocator truth.

## Heap Scan Reports

`--heap-scan` is a unified evidence aggregation layer. It does not add new
allocator parsing and does not claim definitive heap ownership.

Core model:

- `HeapScanFindingSeverity::{Info, Warning, Suspicious}`
- `HeapScanStatus::{Plausible, Incomplete, Suspicious}`
- `HeapScanFinding { severity, kind, chunk_addr, user_addr, message }`
- `HeapScanReport { chunks_walked, allocated_observed, freed_observed,
  unknown_observed, allocator_source_chunks, warning_count, suspicious_count,
  top_validated, heap_snapshot_truncated, status, findings }`
- `HeapScanInputs` aggregates optional heap snapshot, `HeapTracker`,
  allocator summary/warnings, optional allocator source snapshots, validation
  statuses, `main_arena.top` validation, profile, and tcache chain limit.

`collect_heap_scan_source_nodes` normalizes allocator evidence from observed
tcache candidates, fastbins, unsorted bins, smallbins, and largebins into
`HeapScanSourceNode { source_kind, source_label, chunk_addr, user_addr,
expected_size, actual_size, chain_index }`.

Scan counters:

- `chunks_walked` comes from the heap snapshot length when available.
- `allocated_observed` and `freed_observed` count walked snapshot chunks whose
  user pointers match tracker state.
- `unknown_observed` is walked chunks minus observed allocated/freed chunks.
- `allocator_source_chunks` comes from allocator-source summary total
  free-list chunks when available.
- `warning_count` remains the allocator-warning count.
- `suspicious_count` counts suspicious heap-scan findings.

Finding kinds are stable strings:

- `heap_snapshot_unavailable`
- `heap_snapshot_truncated`
- `allocator_source_conflict`
- `allocator_source_allocated`
- `free_list_size_mismatch`
- `free_list_node_outside_heap`
- `free_list_cycle`
- `main_arena_top_not_validated`
- `bin_validation_suspicious`
- `bin_validation_incomplete`

Consistency checks:

- Converts conflicting allocator-source warnings to suspicious
  `allocator_source_conflict` findings.
- Converts free-list/tracker allocated warnings to suspicious
  `allocator_source_allocated` findings.
- Directly checks normalized source nodes against `HeapTracker` for allocated
  state.
- Checks expected-vs-actual source-node sizes for tcache candidates, fastbins,
  and smallbins.
- Checks largebin node sizes for minimum size and alignment.
- Reports stopped unknown next pointers or heads outside the heap as
  `free_list_node_outside_heap` evidence.
- Reports fastbin, unsorted, smallbin, and largebin chain cycles as
  `free_list_cycle`.
- Reports `main_arena.top` validation failure as
  `main_arena_top_not_validated`.
- Converts validation statuses into `bin_validation_suspicious` or
  `bin_validation_incomplete`.
- Deduplicates findings by `(kind, chunk_addr, user_addr, message)` and avoids
  duplicated direct `allocator_source_allocated` findings when an allocator
  warning already supplied the same identity.

Report status is suspicious when any suspicious finding exists, incomplete
when there are warning findings or unavailable/truncated snapshots but no
suspicious findings, and plausible otherwise.

## Human Rendering

Default event output includes:

- event id
- allocator call details
- returned pointer when applicable
- caller line and optional source line when available and not in
  `--events-only`
- chunk headers when available
- `chunk: unavailable` for non-null pointers with unreadable chunks
- tracker note
- optional tracker explanation

Additional human blocks:

- tcache entry candidate for frees
- observed tcache candidate chains
- tcache struct candidate and decoded bins
- tcache comparison and validation results
- heap layout with tracker state and allocator-source annotations
- `main_arena` candidate/experiment/top/view records
- fastbin experiment candidates
- profile-backed fastbin heads/chains/validation
- unsorted-bin experiment candidates
- profile-backed unsorted-bin snapshot/chain/validation
- regular-bin experiment candidates
- profile-backed regular-bin heads
- profile-backed smallbin chains/validation
- profile-backed largebin chains/validation
- allocator warnings, summary, and delta
- heap scan summary and findings
- allocator view preset status line when a non-`none` preset is active

`--events-only` suppresses all non-event metadata and caller lines.
`--no-chunks` hides chunk/bin/layout details but still keeps tracker notes,
explanations, and caller lines.

## JSON Records

`--json` and `--json-out` emit newline-delimited JSON. Addresses and sizes are
lower-case hex strings.

Current record types:

- `session_start`: Heapify version, program, args, trace mode, arch, OS,
  feature flags, selected glibc profile, allocator-view preset, optional
  suggested profile, and optional libc metadata. Libc metadata includes loaded
  `path`, optional `supplied_path`, optional `paths_match`, and version.
- `session_start.launch`: optional launch metadata with mode, loader,
  effective library path, preload path, cwd, environment-control metadata, and
  stdin metadata. Modes are `normal`, `ld_preload`, `custom_loader`, and
  `custom_loader_with_preload`.
- `session_start.launch.set_env` and `unset_env` store environment keys only,
  not environment values.
- `session_start.launch.stdin` stores kind `inherit`, `file`, or `text`; file
  stdin stores the path, text stdin stores only byte count.
- `session_end`: exit status string and event count.
- `event`: allocator event with arguments/returns, optional chunk(s), optional
  tcache entry candidate, `caller_addr`, optional `caller_symbol`, tracker
  note, and optional tracker explanation.
- `heap_layout`: compact heap snapshot with row states, tcache membership, and
  allocator-source annotations.
- `observed_tcache_chains`: reconstructed observed tcache candidate chains.
- `tcache_struct_candidate`: heuristic tcache struct candidate and optional
  decoded snapshot.
- `tcache_comparison`: decoded tcache snapshot compared with observed chains.
- `tcache_validation`: best-effort tcache validation checks.
- `main_arena_candidate`: located arena candidate.
- `main_arena_experiment`: early arena heap-pointer scan results.
- `main_arena_top_candidate`: top field read and classification.
- `main_arena_view`: clean profile-backed arena/top view.
- `fastbin_experiment`: experimental fastbin pointer candidates.
- `fastbins`: profile-backed fastbin heads plus chains and nodes.
- `fastbin_validation`: validation checks for parsed fastbin chains.
- `unsorted_bin_experiment`: experimental unsorted-bin pointer candidates.
- `bin_experiment`: experimental regular-bin sentinel-like pointer candidates.
- `unsorted_bin`: profile-backed unsorted-bin sentinel and optional chain.
- `unsorted_bin_validation`: validation checks for parsed unsorted-bin chains.
- `regular_bins`: profile-backed regular-bin sentinel heads.
- `smallbins`: profile-backed smallbin chains and nodes.
- `smallbin_validation`: validation checks for parsed smallbin chains.
- `largebins`: profile-backed largebin chains and nodes, including nextsize
  pointers.
- `largebin_validation`: validation checks for parsed largebin chains.
- `allocator_warnings`: allocator-source warning records.
- `allocator_source_summary`: tcache/fastbin/unsorted/smallbin/largebin/total/
  warning counts.
- `allocator_source_delta`: count changes since the previous summary.
- `heap_scan`: compact heap scan report and enriched findings. Optional
  `chunk_addr`/`user_addr` fields are hex strings when present.

`JsonCallerSymbol` contains:

- `symbol`
- `symbol_addr`
- `offset`
- optional `object`
- optional `source { file, line, column }`

Older traces without newer optional fields continue to parse through serde
defaults where supported. Missing `allocator_views_preset` defaults to `none`.

## Replay

Replay behavior:

- Reads NDJSON line by line.
- Ignores empty lines.
- Reports parse errors with path and line number.
- Renders only records present in the trace file.
- Does not reconstruct missing layout, tcache, arena, fastbin, unsorted,
  regular-bin, smallbin, largebin, or allocator-source data.
- Prints session header/footer when session records exist.
- `--events-only` renders only event records and suppresses caller lines.
- `--no-chunks` hides chunk/detail records while preserving event/caller
  metadata.
- Symbolized callers are rendered from `caller_symbol` when present; otherwise
  replay falls back to `caller_addr`.
- Caller source lines are rendered from persisted `caller_symbol.source` when
  present. Replay does not perform source lookup itself.
- Launch cwd/env/stdin metadata is parsed and rendered in the session header.
- Non-`none` allocator-view presets are parsed and rendered in the session
  header.
- `bin_experiment`, `regular_bins`, `smallbins`, `smallbin_validation`,
  `largebins`, `largebin_validation`, and `heap_scan` records are parsed,
  rendered, and included in related-record lookup by `event_id`.

`ReplaySession`:

- Stores all parsed records.
- Indexes `type=event` records for the timeline.
- Tracks event count, session start/end metadata, allocator-source summaries,
  and allocator-source deltas.
- Selects related records by matching `event_id`.

Replay TUI:

- Read-only.
- Uses `ratatui` and `crossterm`.
- Shows event timeline, selected event details, and related records.
- Selected event details use the same replay formatting, including symbolized
  callers and persisted source lines.
- Timeline rows include compact allocator-source counts when available.
- Navigation: `j`/Down, `k`/Up, PageUp/PageDown, Home/End, `q`/Esc.
- Empty traces with no events print `no events found in trace` and do not enter
  the TUI.

## Examples

Example sources currently include:

- `simple_malloc.c`
- `simple_calloc.c`
- `simple_realloc.c`
- `marker.c`
- `free_null.c`
- `free_unknown.c`
- `double_free.c`
- `tcache_candidate.c`
- `tcache_chain.c`
- `fastbin_candidate.c`
- `fastbin_chain.c`
- `unsorted_candidate.c`
- `bin_candidate.c`
- `smallbin_candidate.c`
- `largebin_candidate.c`
- `menu_heap.c`
- `menu_script.txt`

Representative commands:

```sh
gcc -g -O0 -no-pie -o examples/simple_malloc examples/simple_malloc.c
cargo run -p heapify-cli -- trace-heap ./examples/simple_malloc
cargo run -p heapify-cli -- trace-heap --trace-mode libc ./examples/simple_malloc
cargo run -p heapify-cli -- trace-heap --layout ./examples/simple_malloc
cargo run -p heapify-cli -- trace-heap --json-out trace.ndjson ./examples/simple_malloc
cargo run -p heapify-cli -- replay trace.ndjson
cargo run -p heapify-cli -- replay --tui trace.ndjson

gcc -g -O0 -fPIE -pie -o examples/simple_malloc_pie examples/simple_malloc.c
cargo run -p heapify-cli -- trace-heap ./examples/simple_malloc_pie

gcc -g -O0 -no-pie -o examples/tcache_chain examples/tcache_chain.c
cargo run -p heapify-cli -- trace-heap --tcache-candidates ./examples/tcache_chain
cargo run -p heapify-cli -- trace-heap --layout --tcache-candidates ./examples/tcache_chain
cargo run -p heapify-cli -- trace-heap --tcache-struct --tcache-candidates ./examples/tcache_chain

gcc -g -O0 -no-pie -o examples/fastbin_candidate examples/fastbin_candidate.c
cargo run -p heapify-cli -- trace-heap \
  --glibc-profile glibc-2.35-x86_64 \
  --main-arena-offset 0x21ac80 \
  --fastbins \
  ./examples/fastbin_candidate

gcc -g -O0 -no-pie -o examples/unsorted_candidate examples/unsorted_candidate.c
cargo run -p heapify-cli -- trace-heap \
  --glibc-profile glibc-2.35-x86_64 \
  --main-arena-offset 0x21ac80 \
  --unsorted-bin \
  ./examples/unsorted_candidate

gcc -g -O0 -no-pie -o examples/bin_candidate examples/bin_candidate.c
cargo run -p heapify-cli -- trace-heap \
  --glibc-profile glibc-2.35-x86_64 \
  --main-arena-offset 0x21ac80 \
  --bin-experiment \
  ./examples/bin_candidate

cargo run -p heapify-cli -- trace-heap \
  --glibc-profile glibc-2.35-x86_64 \
  --main-arena-offset 0x21ac80 \
  --regular-bins \
  ./examples/bin_candidate

gcc -g -O0 -no-pie -o examples/smallbin_candidate examples/smallbin_candidate.c
cargo run -p heapify-cli -- trace-heap \
  --glibc-profile glibc-2.35-x86_64 \
  --main-arena-offset 0x21ac80 \
  --smallbins \
  ./examples/smallbin_candidate

gcc -g -O0 -no-pie -o examples/largebin_candidate examples/largebin_candidate.c
cargo run -p heapify-cli -- trace-heap \
  --glibc-profile glibc-2.35-x86_64 \
  --main-arena-offset 0x21ac80 \
  --largebins \
  ./examples/largebin_candidate

gcc -g -O0 -no-pie -o examples/menu_heap examples/menu_heap.c
cargo run -p heapify-cli -- trace-heap \
  --stdin-file examples/menu_script.txt \
  --layout \
  --tcache-candidates \
  ./examples/menu_heap

cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/menu_heap

cargo run -p heapify-cli -- trace-heap \
  --glibc-profile glibc-2.35-x86_64 \
  --main-arena-offset 0x21ac80 \
  --allocator-views full \
  ./examples/menu_heap

cargo run -p heapify-cli -- trace-heap \
  --glibc-profile glibc-2.35-x86_64 \
  --main-arena-offset 0x21ac80 \
  --all-allocator-views \
  ./examples/menu_heap
```

## Verification

Required checks:

```sh
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

Current test coverage includes:

- ELF type detection, symbol sorting/deduping, symbol lookup behavior, and PLT
  fallback behavior.
- Process maps parsing, load-base calculation, executable/libc mapping
  matching, and libc version metadata.
- Runtime symbol rebasing and caller symbolizer nearest-symbol lookup.
- Target-executable source lookup address adjustment and source DTO
  serialization.
- Breakpoint-adjacent helper behavior, including non-fatal caller capture
  failure.
- glibc profile defaults, lookup, suggestions, chunk-size helpers, chunk flag
  decoding, and heap snapshot walking.
- Safe-link decoding.
- Allocation tracker notes, state transitions, and explanations.
- Tcache candidate chains, membership, comparison, and validation.
- Tcache struct candidate heuristics.
- main_arena lookup, top reads, view classification, JSON, and replay.
- Fastbin experiment scan ranges, profile-backed fastbin chains, validation,
  JSON, and replay.
- Unsorted-bin experiment/snapshot/validation, JSON, and replay.
- Regular-bin experiment classifier behavior, profile-backed regular-bin
  sentinels, smallbin chains, largebin chains, validation, JSON, and replay.
- Allocator-source warnings, summaries, and deltas.
- Heap scan source-node normalization, enriched consistency findings, status
  calculation, deduplication, JSON, and replay.
- Launch planning for loader/preload/cwd/env/stdin controls.
- JSON DTO hex/status serialization, caller address/source serialization,
  launch metadata serialization, allocator-view preset metadata, and caller
  symbol serialization.
- Replay parsing, session indexing, event formatting, caller formatting, and
  TUI-related formatting helpers.
- CLI option parsing, allocator-view preset resolution/application/conflicts,
  and configuration implications.

## Current Limits

- Linux x86-64 only.
- Dynamically linked glibc targets are the practical target.
- Target PLT tracing is default; loaded libc allocator tracing is opt-in.
- `trace-heap` has PIE/ASLR support for target executable symbols; simple
  `break-symbol` does not have the same full runtime-symbol path.
- Caller symbolization uses executable mappings from `/proc/<pid>/maps`, but
  only when ELF symbols are available.
- DWARF/source-line lookup is target-executable only; shared-library source
  lookup and external debug-file discovery are not implemented.
- No full `tcache_perthread_struct` parsing.
- No definitive tcache/bin membership claims.
- Fastbin, unsorted-bin, regular-bin, smallbin, and largebin parsing are
  profile-backed and best-effort.
- Largebin nextsize pointers are captured as evidence, but nextsize ordering
  validation is not implemented.
- Stdin scripting supports file/text input only; no interactive terminal
  passthrough or expect-style prompt matching is implemented.
- No full heap ownership analysis beyond walked chunks, observed events, and
  best-effort source evidence.
- glibc profile selection is manual; suggestions do not auto-switch behavior.
- glibc version detection is best-effort and metadata-only.
- Replay TUI is read-only and works on saved NDJSON traces only.
- Live TUI tracing is not implemented.
