# `arinsal-bits` (OTP 29.1.1)

The crate root documents the instruction-to-API mapping. A caller resolves BEAM
register operands into `Term` values, calls `create_bin_size` before GC, then
calls `create_bin` with the same segments. `start_match(source, heap)` returns a
mutable `SUB_BITS` term. Import `MatchOps` for matching instructions; failed
get operations leave the term's position unchanged. Register copies of that
term share the same cursor.

## Installed BEAM corpus census

`target/debug/arinsal disasm <file.beam> --format erl` was run on all 1,934
`.beam` files under the installed OTP 29.1.1 and Elixir 1.20.4-otp-29 roots.
The count includes top-level instructions only, excluding nested operand terms
and functions whose names begin with `bs_`. No files failed disassembly.

| Opcode | Count | API |
| --- | ---: | --- |
| `bs_create_bin` | 4,726 | `create_bin_size`, `create_bin` |
| `bs_match` | 11,875 | `MatchOps` methods on the context term |
| `bs_start_match4` | 2,139 | `start_match(source, heap)` |
| `bs_get_tail` | 4,165 | `MatchOps::get_tail` |
| `bs_get_position` | 2,998 | `get_position` (small integer, bignum at large offsets) |
| `bs_set_position` | 4,756 | `set_position_term` |
| `bs_init_writable` | 209 | `init_writable` |

Legacy `bs_get_integer2`, `bs_get_binary2`, `bs_get_float2`, `bs_get_utf*`,
`bs_skip_utf*`, `bs_skip_bits2`, `bs_test_tail2`, and `bs_test_unit` did not occur
in this corpus. Their semantics map to the corresponding `MatchOps` methods.

An initial `append` or `private_append` segment of `bs_create_bin` grows a
writable off-heap owner when it remains the unique writer. The direct
`append` and `private_append` APIs accept suffix bytes and a significant bit
length. Taking a sub-binary, matching, copying to another heap, or explicitly
calling `writable_finalize` pins the owner. A later append then copies into a
new growable owner. `private_append` requires the caller to keep the source as
the sole observable handle, matching the compiler's private append contract.

## Validation and performance

`cargo test -p arinsal-bits` compares 100,000 deterministic pseudo-random
constructions and 100,000 matches to OTP, plus widths 1..128, endianness,
floats, UTF, bignums, binary slices, and error cases.

`cargo run -p arinsal-bits --release --example binary_parse` performs the
1024-byte frame parse from `bench/bench.erl` through this API. On the Apple M1
Pro, 10,000 frames over 20 rounds measured 42.6 ns/frame in a release run after
the term-backed context change. That figure excludes
BEAM dispatch, GC, and list construction.

## GC integration

`SUB_BITS` word one reserves bit 0 for MUTABLE and bit 1 for VOLATILE. A match
context has flags `1`; the active writable handle has flags `3`. The original
term is in word four. A moved match context must retain its start and end,
trace and rewrite its original term, and update its base if the original is a
moved on-heap bitstring. A writable BinRef has kind bit `1` in word two and
points to a retained `WritableBinary` owner; bits 1–2 record the initial byte
displacement used to keep the flags separate from a possibly unaligned data
pointer. The collector must retain that owner exactly once per live BinRef,
release unreachable owners, and finalize a writable binary before exposing it
to another process. Call `writable_gc_visit` once per live BinRef during a
stopped process collection: active writers keep capacity, while inactive
writers may shrink. `is_match_context`, `sub_bits_flags`, and
`writable_finalize` expose the other required state; `copy_term` retains
owners through the same protocol.

Errors return `BadArg` or `SystemLimit` with the one-based segment index. OTP
also attaches an `error_info` map containing the segment, type, failing field,
and value; that metadata is not yet produced by this API.
