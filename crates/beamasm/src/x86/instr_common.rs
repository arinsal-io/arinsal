//! Port of erts/emulator/beam/jit/x86/instr_common.cpp, OTP-29.1.1: the move, trim and jump
//! instructions of box I1 so far. Every `emit_*` here is one erts `BeamModuleAssembler::emit_*`.

use super::beam_asm::{AsmError, process, process_ref};
use super::beam_asm_module::BeamModuleAssembler;
use crate::common::args::ArgVal;

impl BeamModuleAssembler {
    /// `i_move Src Dst`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:654-661 (emit_i_move), OTP-29.1.1.
    pub fn emit_i_move(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let spill = self.alloc_temp_reg();
        self.mov_arg(dst, src, spill)
    }

    /// `i_trim Words`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:650-652 (emit_i_trim), OTP-29.1.1.
    pub fn emit_i_trim(&mut self, words: u32) -> Result<(), AsmError> {
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
    pub fn emit_jump(&mut self, fail: u32) -> Result<(), AsmError> {
        let label = self
            .resolve_beam_label(fail)
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
                assert_eq!(emitted(|m| m.emit_i_trim(words)), expected, "{block:?}");
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
}
