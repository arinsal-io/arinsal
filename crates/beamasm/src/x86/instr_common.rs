//! Port of erts/emulator/beam/jit/x86/instr_common.cpp, OTP-29.1.1: the move, trim and jump
//! instructions of box I1 so far. Every `emit_*` here is one erts `BeamModuleAssembler::emit_*`.

use arinsal_x64::enc::{self, Xmm};

use super::beam_asm::register::{ARG1, ARG2};
use super::beam_asm::{
    AsmError, BeamAssembler, CpuFeature, get_arg_ref, get_y_ref, process, process_ref,
};
use super::beam_asm_module::{BeamModuleAssembler, arg_label, arg_word};
use crate::common::args::ArgVal;
use crate::common::args::{Relation, memory_relation};

impl BeamModuleAssembler {
    /// `i_move Src Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:654-661 (emit_i_move), OTP-29.1.1.
    pub fn emit_i_move(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let spill = self.alloc_temp_reg();
        self.mov_arg(dst, src, spill)
    }

    /// `init_yregs Size Ys`: stores NIL in every listed Y register, using `stosq` for runs
    /// of consecutive ones.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:569-648 (emit_init_yregs),
    // OTP-29.1.1.
    pub fn emit_init_yregs(&mut self, size: ArgVal, args: &[ArgVal]) -> Result<(), AsmError> {
        const NIL: u64 = 0x3b;
        let ys = args
            .iter()
            .map(|arg| match arg {
                ArgVal::Y(y) => Ok(*y),
                _ => Err(AsmError::Operand("init_yregs takes Y registers")),
            })
            .collect::<Result<Vec<u32>, AsmError>>()?;
        if arg_word(size)? != ys.len() as u64 {
            return Err(AsmError::Operand("init_yregs size"));
        }
        let ys = ys.as_slice();
        if let [y] = ys {
            return self.mov_arg_word(ArgVal::Y(*y), NIL, ARG1);
        }
        let mut i = 0;
        let mut y_ptr: i64 = -1;
        self.asm.mov_imm(enc::RAX, NIL)?;
        while i < ys.len() {
            let first_y = ys[i];
            let mut slots = 1;
            while i + slots < ys.len() && first_y + slots as u32 == ys[i + slots] {
                slots += 1;
            }
            let a = &mut self.asm;
            if slots == 1 {
                a.emit(|e| e.mov_mr(get_y_ref(first_y, 8), enc::RAX))?;
            } else {
                if first_y == 0 {
                    // With NATIVE_ERLANG_STACK, `mov` is two bytes shorter than `lea`.
                    a.emit(|e| e.mov_rr(enc::RDI, super::beam_asm::register::E))?;
                    y_ptr = 0;
                } else if y_ptr < 0 {
                    y_ptr = i64::from(first_y);
                    a.emit(|e| e.lea(enc::RDI, get_y_ref(first_y, 8)))?;
                } else {
                    let offset = (i64::from(first_y) - y_ptr) * 8;
                    a.emit(|e| e.add_ri(enc::RDI, offset))?;
                    y_ptr = i64::from(first_y);
                }
                if slots <= 4 {
                    for _ in 0..slots {
                        a.emit(|e| e.stosq())?;
                    }
                } else {
                    a.mov_imm(enc::RCX, slots as u64)?;
                    a.emit(|e| e.rep_stosq())?;
                }
                y_ptr += slots as i64;
            }
            i += slots;
        }
        Ok(())
    }

    /// `move_two_words Src1 Dst1 Src2 Dst2`: two adjacent words to adjacent destinations.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:663-707 (emit_move_two_words),
    // OTP-29.1.1.
    pub fn emit_move_two_words(
        &mut self,
        src1: ArgVal,
        dst1: ArgVal,
        src2: ArgVal,
        dst2: ArgVal,
    ) -> Result<(), AsmError> {
        let reg = |arg| get_arg_ref(arg, 8).ok_or(AsmError::Operand("BEAM register operand"));
        let src_ptr = reg(src1)?.with_size(16);
        if memory_relation(src1, src2) != Relation::Consecutive {
            return Err(AsmError::Operand("move_two_words sources not consecutive"));
        }
        let (d1, d2) = (reg(dst1)?, reg(dst2)?);
        match memory_relation(dst1, dst2) {
            Relation::Consecutive => {
                let dst_ptr = d1.with_size(16);
                self.preserve_cache(&[], &[d1, d2], |m| {
                    m.asm.vmovups_xm(Xmm(0), src_ptr)?;
                    m.asm.vmovups_mx(dst_ptr, Xmm(0))
                })
            }
            Relation::ReverseConsecutive => {
                let dst_ptr = d2.with_size(16);
                if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
                    // "(moving and swapping)": load and swap.
                    self.preserve_cache(&[], &[d1, d2], |m| {
                        m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), src_ptr, 1))?;
                        m.asm.emit(|e| e.vmovups_mx(dst_ptr, Xmm(0)))
                    })
                } else {
                    self.mov_arg_to_reg(ARG1, src1)?;
                    self.mov_arg_to_reg(ARG2, src2)?;
                    self.mov_arg_from_reg(dst1, ARG1)?;
                    self.mov_arg_from_reg(dst2, ARG2)
                }
            }
            Relation::None => Err(AsmError::Operand(
                "move_two_words destinations not adjacent",
            )),
        }
    }

    /// `swap R1 R2`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:709-748 (emit_swap), OTP-29.1.1.
    pub fn emit_swap(&mut self, r1: ArgVal, r2: ArgVal) -> Result<(), AsmError> {
        let reg = |arg| get_arg_ref(arg, 8).ok_or(AsmError::Operand("BEAM register operand"));
        let (m1, m2) = (reg(r1)?, reg(r2)?);
        let relation = if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            memory_relation(r1, r2)
        } else {
            Relation::None
        };
        let ptr = match relation {
            Relation::Consecutive => m1.with_size(16),
            Relation::ReverseConsecutive => m2.with_size(16),
            Relation::None => {
                self.mov_arg_to_reg(ARG1, r1)?;
                self.mov_arg_to_reg(ARG2, r2)?;
                self.mov_arg_from_reg(r2, ARG1)?;
                return self.mov_arg_from_reg(r1, ARG2);
            }
        };
        // "(swapping using AVX)": load and swap, then store back.
        self.preserve_cache(&[], &[m1, m2], |m| {
            m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), ptr, 1))?;
            m.asm.emit(|e| e.vmovups_mx(ptr, Xmm(0)))
        })
    }

    /// `i_trim Words`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:650-652 (emit_i_trim), OTP-29.1.1.
    pub fn emit_i_trim(&mut self, words: ArgVal) -> Result<(), AsmError> {
        let words =
            u32::try_from(arg_word(words)?).map_err(|_| AsmError::Operand("i_trim word count"))?;
        self.trim_preserve_cache(words)
    }

    /// `self Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:914-924 (emit_self), OTP-29.1.1.
    pub fn emit_self(&mut self, dst: ArgVal) -> Result<(), AsmError> {
        let reg = self.alloc_temp_reg();
        self.preserve_cache(&[reg], &[], |m| {
            m.asm
                .emit(|e| e.mov_rm(reg, process_ref(process::SELF_PID, 8)))
        })?;
        self.mov_arg_from_reg(dst, reg)
    }

    /// `jump Fail`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:1140-1142 (emit_jump), OTP-29.1.1.
    pub fn emit_jump(&mut self, fail: ArgVal) -> Result<(), AsmError> {
        let label = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("jump to an unknown label"))?;
        self.asm.jmp(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::jdump::{beam_register, erts_dump, gnu_as, op_blocks};
    use arinsal_x64::buf::Section;

    /// Modules whose dumps the I1 tests compare against.
    const MODULES: [&str; 4] = ["lists", "gen_server", "proc_lib", "application_controller"];

    /// The `i_move_sd` operands of an erts block emitted with a fresh register cache: one
    /// store of an immediate, or a load into the first temporary (`TMP1`, r10) and its store.
    fn i_move_operands(block: &[String]) -> Option<(ArgVal, ArgVal)> {
        match block {
            [store] => {
                let (dst, imm) = store.strip_prefix("mov ")?.split_once(", ")?;
                Some((
                    ArgVal::Immediate(imm.parse::<i64>().ok()? as u64),
                    beam_register(dst)?,
                ))
            }
            [load, store] => {
                let (reg, src) = load.strip_prefix("mov ")?.split_once(", ")?;
                let (dst, reg2) = store.strip_prefix("mov ")?.split_once(", ")?;
                (reg == "r10" && reg2 == "r10").then_some(())?;
                Some((beam_register(src)?, beam_register(dst)?))
            }
            _ => None,
        }
    }

    fn emitted(f: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>) -> Vec<u8> {
        let mut m = BeamModuleAssembler::new(1);
        f(&mut m).unwrap();
        m.asm.a.bytes(Section::Code).to_vec()
    }

    // Differential check against erts: every `i_move_sd` and `i_trim_t` erts emitted for real
    // modules, whose operands can be read back from its text, encodes to the same bytes here.
    #[test]
    fn moves_and_trims_match_erts_dump() {
        let Some(dumps) = MODULES
            .iter()
            .map(|m| erts_dump(m))
            .collect::<Option<Vec<_>>>()
        else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let (mut moves, mut trims) = (0, 0);
        for dump in &dumps {
            for block in op_blocks(dump, "i_move_sd") {
                let Some((src, dst)) = i_move_operands(&block) else {
                    continue;
                };
                let Some(expected) = gnu_as(&block) else {
                    eprintln!("skipping: GNU binutils unavailable");
                    return;
                };
                assert_eq!(emitted(|m| m.emit_i_move(src, dst)), expected, "{block:?}");
                moves += 1;
            }
            for block in op_blocks(dump, "i_trim_t") {
                let [add] = block.as_slice() else { continue };
                let words = add
                    .strip_prefix("add rsp, ")
                    .unwrap()
                    .parse::<u32>()
                    .unwrap()
                    / 8;
                let expected = gnu_as(&block).unwrap();
                assert_eq!(
                    emitted(|m| m.emit_i_trim(ArgVal::Immediate(u64::from(words)))),
                    expected,
                    "{block:?}"
                );
                trims += 1;
            }
        }
        eprintln!("compared {moves} i_move_sd and {trims} i_trim_t blocks");
        assert!(
            moves > 1000 && trims > 50,
            "compared {moves} moves, {trims} trims"
        );
    }

    // erts' `self_d`: `common.id` is at offset 0 of erts' Process, `self_pid` in Arinsal's
    // `ProcessHeader`.
    #[test]
    fn self_matches_erts_dump() {
        let Some(dump) = erts_dump("lists").or_else(|| erts_dump("gen_server")) else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let mut compared = 0;
        for module in ["gen_server", "proc_lib", "gen", "application_master"] {
            let dump = erts_dump(module).unwrap_or_else(|| dump.clone());
            for block in op_blocks(&dump, "self_d") {
                let [load, store] = block.as_slice() else {
                    continue;
                };
                if load != "mov r10, qword ptr [r13]" {
                    continue;
                }
                let dst = beam_register(
                    store
                        .strip_prefix("mov ")
                        .unwrap()
                        .split_once(", ")
                        .unwrap()
                        .0,
                )
                .unwrap();
                let ours = [
                    format!("mov r10, qword ptr [r13+{}]", process::SELF_PID),
                    store.clone(),
                ];
                let Some(expected) = gnu_as(&ours) else {
                    return;
                };
                assert_eq!(emitted(|m| m.emit_self(dst)), expected, "{block:?}");
                compared += 1;
            }
        }
        assert!(compared > 0);
    }

    // erts' register cache: a store leaves the value cached, so a following load of the same
    // slot reuses the register ("skipped fetching of BEAM register").
    #[test]
    fn move_reuses_cached_register() {
        let bytes = emitted(|m| {
            m.emit_i_move(ArgVal::X(1), ArgVal::Y(0))?;
            m.emit_i_move(ArgVal::Y(0), ArgVal::X(2))
        });
        let expected = gnu_as(&[
            "mov r10, qword ptr [rbx+8]".into(),
            "mov qword ptr [rsp], r10".into(),
            "mov qword ptr [rbx+16], r10".into(),
        ]);
        if let Some(expected) = expected {
            assert_eq!(bytes, expected);
        }
    }

    fn dump_blocks(op: &str) -> Option<Vec<Vec<String>>> {
        let dumps = MODULES
            .iter()
            .map(|m| erts_dump(m))
            .collect::<Option<Vec<_>>>()?;
        Some(dumps.iter().flat_map(|d| op_blocks(d, op)).collect())
    }

    fn mem_operand(text: &str) -> Option<ArgVal> {
        beam_register(&text.replace("xmmword ptr", "qword ptr"))
    }

    fn assert_matches(block: &[String], ours: Vec<u8>) {
        let text: Vec<String> = block
            .iter()
            .map(|l| {
                l.replace("rep stos qword ptr [rdi], rax", "rep stosq")
                    .replace("stos qword ptr [rdi], rax", "stosq")
            })
            .collect();
        if let Some(expected) = gnu_as(&text) {
            assert_eq!(ours, expected, "{block:?}");
        }
    }

    // init_yregs: the Y registers are read back by replaying erts' stores (`rdi` tracking).
    #[test]
    fn init_yregs_matches_erts_dump() {
        let Some(blocks) = dump_blocks("init_yregs_I") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let mut compared = 0;
        for block in blocks {
            let mut ys = Vec::new();
            let mut rdi = 0u32;
            let mut count = 0u32;
            for line in &block {
                if let Some(rest) = line.strip_prefix("mov qword ptr ") {
                    ys.push(
                        beam_register(&format!("qword ptr {}", rest.split_once(", ").unwrap().0))
                            .unwrap(),
                    );
                } else if line == "mov rdi, rsp" {
                    rdi = 0;
                } else if let Some(mem) = line.strip_prefix("lea rdi, ") {
                    let ArgVal::Y(y) = beam_register(mem).unwrap() else {
                        panic!()
                    };
                    rdi = y;
                } else if let Some(n) = line.strip_prefix("add rdi, ") {
                    rdi += n.parse::<u32>().unwrap() / 8;
                } else if let Some(n) = line.strip_prefix("mov ecx, ") {
                    count = n.parse().unwrap();
                } else if line.starts_with("rep stos") {
                    ys.extend((rdi..rdi + count).map(ArgVal::Y));
                    rdi += count;
                } else if line.starts_with("stos") {
                    ys.push(ArgVal::Y(rdi));
                    rdi += 1;
                }
            }
            let ys: Vec<u32> = ys
                .into_iter()
                .map(|y| match y {
                    ArgVal::Y(y) => y,
                    _ => panic!(),
                })
                .collect();
            let args: Vec<ArgVal> = ys.iter().map(|y| ArgVal::Y(*y)).collect();
            let size = ArgVal::Immediate(args.len() as u64);
            assert_matches(&block, emitted(|m| m.emit_init_yregs(size, &args)));
            compared += 1;
        }
        assert!(compared > 50, "compared {compared}");
    }

    // move_two_words and swap on an AVX host: one `vmovups`/`vpermilpd` load and one store.
    #[test]
    fn move_two_words_and_swap_match_erts_dump() {
        let (Some(moves), Some(swaps)) =
            (dump_blocks("move_two_words_sdsd"), dump_blocks("swap_dd"))
        else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        if !BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            return;
        }
        let next = |arg: ArgVal| match arg {
            ArgVal::X(i) => ArgVal::X(i + 1),
            ArgVal::Y(i) => ArgVal::Y(i + 1),
            other => other,
        };
        let mut compared = 0;
        for block in moves {
            let [load, store] = block.as_slice() else {
                continue;
            };
            let src = load
                .split_once(", ")
                .and_then(|(_, m)| mem_operand(m.trim_end_matches(", 1")));
            let dst = store
                .strip_prefix("vmovups ")
                .and_then(|rest| mem_operand(rest.split_once(", ")?.0));
            let (Some(src), Some(dst)) = (src, dst) else {
                continue;
            };
            let ours = if load.starts_with("vpermilpd") {
                emitted(|m| m.emit_move_two_words(src, next(dst), next(src), dst))
            } else {
                emitted(|m| m.emit_move_two_words(src, dst, next(src), next(dst)))
            };
            assert_matches(&block, ours);
            compared += 1;
        }
        for block in swaps {
            let operands = match block.as_slice() {
                [load, _] if load.starts_with("vpermilpd ") => {
                    let r = load
                        .split_once(", ")
                        .and_then(|(_, m)| mem_operand(m.trim_end_matches(", 1")));
                    r.map(|r| (r, next(r)))
                }
                [l1, l2, _, _] => l1
                    .strip_prefix("mov rdi, ")
                    .and_then(beam_register)
                    .zip(l2.strip_prefix("mov rsi, ").and_then(beam_register)),
                _ => None,
            };
            let Some((r1, r2)) = operands else { continue };
            assert_matches(&block, emitted(|m| m.emit_swap(r1, r2)));
            compared += 1;
        }
        assert!(compared > 100, "compared {compared}");
    }
}
