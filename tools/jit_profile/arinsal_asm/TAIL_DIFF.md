# `tail_loop/2`: BeamAsm instruction diff

The comparison uses the steady-state iteration with `N > 0`, both operands tagged small integers, no arithmetic overflow, and reductions remaining. Counts follow the taken/not-taken paths in `kernels.asm` and `erts_asm/kernels.asm`; assembler metadata, cold fallback paths, and the base-case return are excluded.

| BEAM operation | erts hot-path instructions | Arinsal hot-path instructions | Difference |
| --- | ---: | ---: | ---: |
| `i_breakpoint_trampoline` | 2 (`str; b`) | 1 (`str`) | -1 |
| `i_test_yield` | 3 (`adr; subs; b.le`) | 2 (`subs; b.gt`) | -1 |
| `is_eq_exact` (`N == 0`) | 2 (`cmp; b.ne`) | 2 (`cmp; b.ne`) | 0 |
| `i_minus` (`N - 1`) | 6 (incl. constant and result moves) | 5 (incl. result move) | -1 |
| `i_plus` (`Sum + 1`) | 6 (incl. constant and result moves) | 5 (incl. result move) | -1 |
| `i_call_only` | 2 (`ldr; b`) | 3 (`ldr; subs; b.pl`) | +1 |
| **Total per iteration** | **21** | **18** | **-3** |

Both immediate arithmetic hot paths now match OTP's `adds/subs`, tag check, `ccmp` overflow check and conditional branch shape. OTP also materializes its tagged constant on the hot path; Arinsal uses the tagged constant only in the cold helper path. Both listings move the result into the mapped X register.

## Implementation evidence

- Exact equality and inequality against a tagged small integer or atom immediate emit a direct compare and failure branch without entering the Rust guard helper. The implementation is in `crates/beamasm/src/guard.rs`; OTP's exact-comparison immediate path is `ref/otp-29/erts/emulator/beam/jit/arm/instr_common.cpp:1844-1856`.
- Relative `is_lt` and `is_ge` guards compare directly when one operand is a small-integer immediate and the other is a small at runtime; non-small terms use the shared guard helper. OTP's corresponding immediate comparison path is in `ref/otp-29/erts/emulator/beam/jit/arm/instr_common.cpp:2179-2355`.
- Immediate `i_plus`, `i_minus` and `i_increment` compute directly on tagged values. `ccmp` selects the fast path only when the source is a small integer and the signed operation did not overflow. Non-small operands and overflow enter the existing arithmetic helper. The implementation is in `crates/beamasm/src/arith.rs`; OTP's implementation is in `ref/otp-29/erts/emulator/beam/jit/arm/instr_arith.cpp:145-204,334-392`.
- `tools/jit_profile/arinsal_asm/kernels.asm` was regenerated with `ARINSAL_BEAMASM_DUMP` using OTP 29.1.1's gate `kernels.erl`.

## Remaining difference

`i_call_only` executes one additional conditional reduction branch in Arinsal. OTP pops the Erlang frame and branches directly to `tail_loop/2`; Arinsal decrements reductions and checks for yielding there even though the callee checks reductions at entry. This emitter is in `crates/beamasm/src/module.rs`, outside this task's ownership. OTP source: `ref/otp-29/erts/emulator/beam/jit/arm/instr_call.cpp:117-121`.
