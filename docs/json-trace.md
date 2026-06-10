# JSON Trace Format

Heapify JSON traces are newline-delimited JSON files. Each line is one complete
record object. This format is convenient for streaming traces while the target
runs and for replaying traces later.

The JSON format is alpha and is not yet a stable public API.

## NDJSON Overview

Create a trace:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views basic --json-out trace.ndjson ./examples/simple_malloc
```

Replay it:

```sh
cargo run -p heapify-cli -- replay trace.ndjson
cargo run -p heapify-cli -- replay --tui trace.ndjson
```

Addresses and sizes are encoded as hex strings. Consumers should ignore record
types and fields they do not understand.

## Session Records

`session_start` is the first record written by current Heapify versions. It
contains target metadata such as:

- Heapify version.
- Program and arguments.
- Trace mode.
- Architecture and operating system.
- Launch metadata, when applicable.
- libc metadata, when available.
- Requested and selected glibc profile metadata.
- Allocator view preset and enabled features.

`session_end` is written after tracing completes. It contains the final event
count and target exit status metadata.

Older traces may not contain all session metadata. Replay keeps compatibility
with older records where practical.

## Event Records

`event` records contain observed allocator events such as `malloc`, `calloc`,
`realloc`, and `free`. They include the allocator arguments and return values
Heapify observed, tracker notes, explanations, and caller symbol metadata when
available.

Observed event records are the core replay timeline.

## Related Records

Optional records are emitted only when the corresponding views are enabled.
Examples include:

- `heap_layout`
- `observed_tcache_chains`
- `tcache_struct_candidate`
- `tcache_comparison`
- `main_arena_candidate`
- `main_arena_top_candidate`
- `main_arena_view`
- `fastbins`
- `unsorted_bin`
- `regular_bins`
- `smallbins`
- `largebins`
- `allocator_source_summary`
- `allocator_source_delta`
- `heap_scan`

Related records usually include an `event_id` so replay and the TUI can attach
them to the allocator event that produced the evidence.

Allocator source membership in these records is evidence, not definitive truth.
It can depend on target memory reads, profile confidence, and enabled views.

## Live-Only Updates

Live TUI control messages are not serialized. This includes pause/resume/step
command acknowledgements, target status updates, and UI break-match
notifications.

If `--live-tui` and `--json-out PATH` are used together, the saved trace remains
a replayable allocator trace rather than a recording of every TUI interaction.

## Replay Compatibility

Replay expects valid NDJSON and renders only records present in the file. It
does not rerun the target, rewalk heap memory, or reconstruct missing related
records.

Compatibility expectations for the alpha format:

- New Heapify versions should keep reading recent traces where practical.
- Consumers should tolerate unknown fields and unknown record types.
- Field names and record shapes may still change before a stable public trace
  API is declared.
