# Heapify Examples

Build all documented C examples:

```sh
../scripts/build-examples.sh
```

From the repository root, use:

```sh
./scripts/build-examples.sh
```

## Basic malloc/calloc/realloc

Files:

- `simple_malloc.c`
- `simple_calloc.c`
- `simple_realloc.c`

Commands:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/simple_malloc
cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/simple_calloc
cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/simple_realloc
```

These show basic allocation, free, reuse, calloc, and realloc tracking.

## tcache

Files:

- `tcache_candidate.c`
- `tcache_chain.c`

Commands:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/tcache_candidate
cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/tcache_chain
cargo run -p heapify-cli -- trace-heap --tcache-struct --tcache-candidates ./examples/tcache_chain
```

These demonstrate observed tcache candidate chains and best-effort decoded
tcache structure candidates.

## fastbin

Files:

- `fastbin_candidate.c`
- `fastbin_chain.c`

Commands:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views full --glibc-profile auto ./examples/fastbin_candidate
cargo run -p heapify-cli -- trace-heap --allocator-views full --glibc-profile auto ./examples/fastbin_chain
```

These are intended for fastbin-shape experiments. Depending on glibc behavior,
you may need a profile and arena offset for richer profile-backed fastbin
views.

## unsorted, smallbin, and largebin

Files:

- `unsorted_candidate.c`
- `smallbin_candidate.c`
- `largebin_candidate.c`
- `bin_candidate.c`

Commands:

```sh
cargo run -p heapify-cli -- trace-heap --allocator-views full --glibc-profile auto ./examples/unsorted_candidate
cargo run -p heapify-cli -- trace-heap --allocator-views full --glibc-profile auto ./examples/smallbin_candidate
cargo run -p heapify-cli -- trace-heap --allocator-views full --glibc-profile auto ./examples/largebin_candidate
cargo run -p heapify-cli -- trace-heap --bin-experiment --glibc-profile auto ./examples/bin_candidate
```

These demonstrate larger freed chunks and regular-bin pointer shapes. The
profile-backed views are best-effort and depend on glibc profile confidence and
available arena metadata.

## menu_heap

Files:

- `menu_heap.c`
- `menu_script.txt`

Command:

```sh
cargo run -p heapify-cli -- trace-heap --stdin-file examples/menu_script.txt --allocator-views basic ./examples/menu_heap
```

This demonstrates tracing an interactive target with scripted stdin.

## Corruption

Files:

- `corruption/double_free.c`
- `corruption/tcache_poison_shape.c`
- `corruption/fastbin_dup_shape.c`
- `corruption/unsorted_fd_bk_shape.c`

Commands:

```sh
cargo run -p heapify-cli -- trace-heap --live-tui --allocator-views basic --break-on double-free ./examples/corruption/double_free
cargo run -p heapify-cli -- trace-heap --live-tui --allocator-views full --break-on suspicious ./examples/corruption/tcache_poison_shape
cargo run -p heapify-cli -- trace-heap --allocator-views full --glibc-profile auto ./examples/corruption/unsorted_fd_bk_shape
```

These are educational fixtures for diagnostics. They are not exploitation
payloads. Exact behavior depends on glibc version and hardening settings.
