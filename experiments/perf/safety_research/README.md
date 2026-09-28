# Safety API cost probes

Question: can a scoped view of a real moving term heap, a checked register file, and a safe byte cursor replace three common unsafe patterns without missing the performance target?

This standalone package has its own empty `[workspace]` and depends on the unchanged `arinsal-term` crate by path. Its test also uses `arinsal-etf` to check the term after relocation. `heap_current` uses the public `ProcessHeap`, `TermBuilder::tuple`, `TermBuilder::cons`, and `collect` APIs directly. `heap_scoped` uses the same allocator and collector behind a root slot and an immutable `TermView<'h>`; `collect(&mut self)` invalidates a live view. Both allocate one tuple and one cons per iteration, with collection between the two every 64th iteration and whenever capacity requires it. The previous result is replaced each iteration, keeping the live graph shallow. The register loops model specialized X-register dispatch over 256 and 1024 slots. The full-size `RegisterFile` exposes only safe methods to dispatch and keeps one audited unchecked access inside the core. The byte loop models aligned 8-bit binary reads over a slice. These are microbenchmarks, not end-to-end VM or JIT timings.

```sh
cargo test --manifest-path experiments/perf/safety_research/Cargo.toml
cargo check --manifest-path experiments/perf/safety_research/Cargo.toml --features borrow-fail  # must fail with E0502
cargo build --manifest-path experiments/perf/safety_research/Cargo.toml --release
for i in $(seq 1 21); do timeout 30 experiments/perf/safety_research/target/release/safety-research; done
xcrun llvm-objdump --disassemble --demangle experiments/perf/safety_research/target/release/safety-research
```

Apple Silicon arm64, Rust 1.98.1 `--release`, 21 independent processes, each with one warmup and eight timed repetitions. Medians below are medians of the 21 per-process medians; range is across processes. One operation is one tuple-plus-cons pair, one register update, or one byte. The heap workloads use 8,000 operations; register and byte workloads use 1,638,400 and 3,276,800 operations per timed repetition respectively. Other agents were active on the shared machine; interpret differences smaller than the process range cautiously.

| Case | Median ns/op | Process range ns/op | Statically counted steady-loop instructions/op |
| --- | ---: | ---: | ---: |
| Real heap, current API | 16.589 | 16.266–18.487 | N/A: allocator and GC paths vary |
| Real heap, scoped root/view API | 16.508 | 16.294–18.000 | N/A: allocator and GC paths vary |
| 256 X, unchecked dynamic slice | 0.280 | 0.279–0.288 | 5.5 |
| 256 X, checked dynamic slice | 0.364 | 0.363–0.374 | 8 |
| 256 X, fixed array + `u8` | 0.278 | 0.277–0.286 | 4.375 |
| 1024 X, unchecked dynamic slice | 0.331 | 0.330–0.334 | 6 |
| 1024 X, safe four-bank array | 0.416 | 0.402–0.419 | 9 |
| 1024 X, safe masked index | 0.358 | 0.346–0.368 | 7 |
| 1024 X, safe API + audited register core | 0.331 | 0.330–0.334 | 6 |
| Bytes, raw pointer | 0.0204 | 0.0203–0.0207 | 0.3125 |
| Bytes, checked slice | 0.0203 | 0.0203–0.0207 | 0.3125 |
| Bytes, slice iterator | 0.0204 | 0.0203–0.0210 | 0.3125 |

Instruction figures are counts along the disassembled ARM64 steady loop: the checked 256-register loop executes eight instructions per update including a bounds comparison and conditional branch; unchecked unrolls two updates in 11 instructions; fixed unrolls eight in 35. The wide baseline and typed core each execute six instructions per update; the redundant safe mask adds one, and banked storage adds three. The byte loops vectorize 64 bytes into 20 instructions. These are **not hardware retired-instruction counts**. `xcrun xctrace` could not start in this sandbox because Instruments was denied access to its cache directory, and no other hardware counter tool is available here. `xcrun llvm-objdump` shows a `panic_bounds_check` edge in the dynamic checked register function; the fixed-array, masked, banked, and typed-core loops have no per-access bounds check. The three byte loops have the same 64-byte vectorized inner loop. The root wrapper's GC and allocation remain inlined through the actual term crate, so a static instruction count per allocating operation would be misleading.

The root design's difference is inside timing noise; it is evidence that a thin root/view API can be cheap on this shallow-live workload, not evidence that a full moving-heap conversion is free. A fully safe 1024-slot per-access design costs about 8% with a masked validated index and 26% with four banks. A validated `TypedXReg` passed to a safe `RegisterFile::bump` interface matches the raw path, but the file retains one audited unsafe access. The byte test does not cover unaligned bit extraction or owner lifetime. Repeat against `trees`, binary matching, interpreter and JIT before accepting an implementation change.
