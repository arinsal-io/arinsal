# `arinsal-maps` (OTP 29.1.1 / ERTS 17.1)

This crate stores maps in OTP's tagged heap layout. A flatmap has a three-word header (`MAP`, size, key tuple) followed by parallel values. The key tuple has one arity word and one word per key; OTP's empty tuple is static. At key 33 the map becomes a HAMT. Its root is a bitmap or 16-slot array with an untagged size, inner nodes are bitmap nodes, hash collisions are tuples, and key/value leaves are cons cells. Removing key 33 from a 33-key map converts it back to a flatmap.

## Ordering evidence

- `erts/emulator/beam/erl_utils.h:267` (`erts_cmp_flatmap_keys`) compares *two atom keys* by tagged atom-table index and other keys with exact term comparison. Exact number order places all integers before all floats; float order distinguishes signed zero. The term crate's flatmap builder and this crate use this rule.
- `erl -noshell -eval 'A=list_to_atom("zzzz_new"),B=list_to_atom("aaaa_new"),io:format("~p~n",[maps:to_list(#{A=>1,B=>2})]),halt().'` prints `[{zzzz_new,1},{aaaa_new,2}]`. Thus text order is observably wrong for dynamically interned atoms. The `predefined_atom_indices_match_otp_hashes` differential test compares the internal hashes of `false`, `true`, `error`, and `undefined` with OTP. The hash is a permutation of the immediate tagged word, so matching hashes establish matching indices for these samples. Arinsal loads the same 762-entry `atom.names` list, while `erl -noshell -eval 'io:format("~B~n",[erlang:system_info(atom_count)]),halt().'` reported 10,562 atoms after OTP boot. A new user atom's absolute index will differ until the VM reproduces OTP's startup and module loading intern sequence; matching relative intern order suffices for flatmap order among newly created atoms, but HAMT hashes require the absolute index.
- `erts/emulator/beam/erl_term_hashing.c:2301-2318` (`erts_internal_hash`, `erts_map_hash`) uses the unsalted internal hash in normal builds. `erl_map.h:78-85` consumes four low bits per HAMT level. `erl_map.c:2337-2378` visits child positions in ascending order. Two independent OTP 29.1.1 runs on the same 100-key integer map returned the same `maps:keys/1` sequence (starting `[54,18,96,94,84,4,72,68,...]`). No per-run salt affected this order.
- `erl_map.c:2975-3025` converts a HAMT back to a flatmap when a removal leaves 32 keys. In OTP, a 33-key integer map has `erts_debug:flat_size/1 = 123`; after removing its 33rd key, the size is 68. The differential suite checks sizes 0, 1, 2, 16, 32, 33, 34, 100, 1,000, and 2,000, sixteen seeded random sizes in 0..2,000, random operation sequences, generated compound keys from `arinsal-difftest`, and mixed-key HAMTs.
- `external.c:3745-3822` writes ordinary ETF map pairs from a LIFO traversal stack. For HAMTs this is the reverse of `maps:to_list/1`; flatmaps retain their stored order. `term_to_binary_pairs` exposes that order to the serializer. Byte-for-byte differential tests pass for integer maps of sizes 0, 32, 33, and 100 and for a mixed 46-key HAMT.

## Ported source paths

| OTP source | Arinsal operation |
| --- | --- |
| `erl_utils.h:267-273` | Flatmap atom-index comparison |
| `erl_map.h:178-205` | HAMT header, bitmap, array, collision-node layout |
| `erl_map.c:857-1158` | Build HAMT from unique entries |
| `erl_map.c:2190-2250` | Flatmap put and transition at 33 |
| `erl_map.c:2337-2378` | HAMT iteration |
| `erl_map.c:2520-2794` | Persistent HAMT insertion and replacement |
| `erl_map.c:2900-3190` | HAMT removal and transition back to flatmap |
| `erl_map.c:3636-4140` and `lib/stdlib/src/maps.erl:996-1116` | Iterator term shape and `maps:next/1` protocol |
| `external.c:3745-3822` | Ordinary ETF map pair order |

## Performance

Existing-key updates remain persistent. The flatmap path copies the header and
value slots while reusing the immutable key tuple; it does not rebuild or sort
the key list. The HAMT path finds the leaf without allocating temporary child
vectors, then copies that leaf and its ancestors in one heap reservation.
Lookup also walks bitmap nodes directly without a temporary vector. The VM's
single-pair `put_map_assoc` handler reads its two operands directly. The
benchmark's `maps:put/3` source call compiles to this opcode in OTP 29.1.1, so
BIF dispatch is not on its hot path.

### Why in-place update is disabled

Overwriting the destination register proves only that this particular register
will no longer hold the old map. It does not prove that another X/Y register,
tuple, closure, process message, ETS value, persistent term, or literal cannot
still reach it. The benchmark's `put_map_assoc` reads and writes X3, but this
instruction shape alone is insufficient. Its live-count operand specifies GC
roots; it is not an ownership certificate. Type metadata describes term kinds,
not aliases. A young-heap allocation watermark can exclude old or escaped
roots, but cannot establish uniqueness of a HAMT child: persistent updates
share untouched child nodes with earlier maps, and those children may predate
the most recent root. A flatmap also shares its key tuple. Checking only the
root pointer or its age would therefore permit a stale alias to observe a
changed value. This crate makes no in-place writes to an existing map.

An in-place path needs both (1) a last-use certificate for every live root and
escape edge, invalidated on capture, send, term construction, table insertion,
and literal loading, and (2) exclusive ownership of every node on the edited
path. One possible representation is a process-private transient map with an
owner token and separately owned slots. The runtime would freeze or copy it
before any alias or escape; GC must preserve and update the token, and shared
HAMT children must be copied before mutation. Integrating that representation
crosses the term heap, interpreter/JIT, process messaging, ETS, and GC. Until
those invariants are enforced and differentially tested, persistent copying is
the sound fallback.

On this worktree's Apple M1 Pro, with 200,000 existing-key updates (five consecutive release-example runs):

| Implementation | Keys | Median time | ns/update |
| --- | ---: | ---: | ---: |
| Previous Arinsal release example | 1,000 | 186.8 ms | 934.2 |
| Persistent path after this change | 1,000 | 22.785 ms | 113.9 |
| Persistent path after this change | 32 | 15.072 ms | 75.4 |

The Rust example uses `VecHeap` without garbage collection and retains previous
persistent versions until exit. Each HAMT update copies only the edited path;
the 1,000-key example used 8,528,112 words in total, including the initial
map. The previous figure is from this README's earlier three-run measurement,
so its ratio is indicative, not a paired benchmark.

The full VM gate uses four million updates. In the five-run comparison on
2026-09-25, Arinsal took 2,091.9 ms kernel / 7.2 MiB RSS at 1,000 keys and
1,070.7 ms / 6.3 MiB at 32 keys. The same run measured Go at 34.2 ms / 3.7 MiB
and 21.9 ms / 3.7 MiB, respectively. Machine load was high and wall-time
variation exceeded 5% for several cases; the gap is still orders of magnitude
larger than the noise. The supplied stable Go gates are 25.4 and 21.9 ms,
with RSS below 3.6 and 3.5 MiB. Persistent copying does not meet them.

`erts_debug:flat_size/1` includes the representation of each key and value. The mixed-key size test uses `binary:copy(<<1>>)` on OTP to compare against Arinsal's heap bitstring; the OTP binary literal is a reference/sub-binary object (8 words), while its copied byte uses a heap bitstring (3 words).

## Current integration boundaries

The term crate's `cmp`, `internal_hash`, `size_object`, and `copy_term` still reject HAMT map *terms*. A HAMT used anywhere inside a map key returns `MapError::UnsupportedKey`. Comparing or hashing whole HAMT maps outside this crate needs term-crate work by the supervisor. `iterator_term` supports native and `ordered` traversal; `iterator_term_reversed` supports `reversed`. `next_term` reproduces the initial iterator terms and flatmap tuple chain; HAMT `maps:next/1` emits one pair per call because OTP's batch length depends on the calling process's remaining reduction budget, which this API does not receive.
