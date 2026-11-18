//! Port of erts/emulator/beam/jit/x86/instr_bif.cpp, OTP-29.1.1: so far the light-BIF call,
//! `call_light_bif` and its global fragment `call_light_bif_shared`.

use arinsal_x64::enc::{CondCode, Mem, byte_ptr, dword_ptr, qword_ptr};

use super::beam_asm::register::{
    ACTIVE_CODE_IX, ARG1, ARG2, ARG2D, ARG3, ARG4, ARG5, ARG5D, C_P, E, FCALLS, HTOP, RET,
};
use super::beam_asm::{
    AsmError, ERTS_SAVE_CALLS_CODE_IX, Update, get_x_ref, process, process_ref, tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::BeamModuleAssembler;
pub use super::rt::erts_gc_after_bif_call_lhf;
use crate::common::args::ArgVal;

/// `offsetof(Export, is_bif_traced)`.
// Port of erts/emulator/beam/export.h:57-58 (Export.is_bif_traced), OTP-29.1.1.
const EXPORT_IS_BIF_TRACED: i32 =
    core::mem::offset_of!(arinsal_term::ExportEntry, is_bif_traced) as i32;
/// `offsetof(Export, info.mfa)`.
const EXPORT_MFA: i32 = arinsal_term::EXPORT_MFA_OFFSET as i32;
/// `offsetof(Export, info.mfa.arity)`.
const EXPORT_MFA_ARITY: i32 =
    EXPORT_MFA + core::mem::offset_of!(arinsal_term::ErtsCodeMfa, arity) as i32;

/// `F_FORCE_GC | F_DISABLE_GC` of `c_p->flags`.
// Port of erts/emulator/beam/erl_process.h (F_FORCE_GC, F_DISABLE_GC), OTP-29.1.1.
const F_FORCE_OR_DISABLE_GC: i64 =
    (arinsal_term::pflags::F_FORCE_GC | arinsal_term::pflags::F_DISABLE_GC) as i64;

impl BeamGlobalAssembler {
    /// Calls a light BIF through its `(c_p, reg, I)` function: `ARG3` is the entry address
    /// of the call site, `ARG4` the `Export`, `RET` the BIF function. Traced BIFs and
    /// `save_calls` go through the export entry instead; a desired collection after the
    /// call runs `erts_gc_after_bif_call_lhf`.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:420-671 (emit_call_light_bif_shared),
    // OTP-29.1.1. Release build: no `debug_call_light_bif`, no `ERTS_CCONV_DEBUG`
    // trampoline, no `ERTS_MSACC_EXTENDED_STATES`.
    pub(crate) fn emit_call_light_bif_shared(&mut self) -> Result<(), AsmError> {
        let (entry_mem, export_mem, mbuf_mem) = (tmp_mem_q(0), tmp_mem_q(1), tmp_mem_q(2));
        let context_switch_simplified = self.label(GlobalLabels::ContextSwitchSimplified);
        let raise_exception_shared = self.label(GlobalLabels::RaiseExceptionShared);
        let a = &mut self.asm;
        let trace = a.new_label();
        let r#yield = a.new_label();

        a.emit_enter_frame()?;

        // Spill everything we may need on the error and GC paths.
        a.emit(|e| e.mov_rm(ARG1, process_ref(process::MBUF, 8)))?;
        a.emit(|e| e.mov_mr(entry_mem, ARG3))?;
        a.emit(|e| e.mov_mr(export_mem, ARG4))?;
        a.emit(|e| e.mov_mr(mbuf_mem, ARG1))?;

        // Check if we should trace this bif call or handle save_calls. Both variants dispatch
        // through the export entry.
        a.emit(|e| e.cmp_mi(dword_ptr(ARG4, EXPORT_IS_BIF_TRACED), 0))?;
        a.jcc(CondCode::NE, trace)?;
        a.emit(|e| e.cmp_ri(ACTIVE_CODE_IX, i64::from(ERTS_SAVE_CALLS_CODE_IX)))?;
        a.jcc(CondCode::E, trace)?;

        a.emit(|e| e.dec_r(FCALLS))?;
        a.jcc(CondCode::LE, r#yield)?;

        {
            let check_bif_return = a.new_label();
            let gc_after_bif_call = a.new_label();
            let spec = Update::REDUCTIONS.union(Update::STACK).union(Update::HEAP);

            a.emit_enter_runtime(spec)?;

            // Call the BIF proper. ARG3 and RET have been set earlier.
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.load_x_reg_array(ARG2)?;
            a.emit(|e| e.mov_rr(ARG4, RET))?;
            a.dynamic_runtime_call(ARG4)?;

            // The active code index is updated in case another process has loaded new code:
            // the result of this BIF may be observable on both ends.
            a.emit_leave_runtime(spec.union(Update::CODE_INDEX))?;

            // ERTS_IS_GC_DESIRED_INTERNAL
            {
                // Test whether GC is forced.
                a.emit(|e| e.test_mi(process_ref(process::FLAGS, 4), F_FORCE_OR_DISABLE_GC))?;
                a.jcc(CondCode::NE, gc_after_bif_call)?;

                // Test if binary heap size should trigger GC.
                a.emit(|e| e.mov_rm(ARG1, process_ref(process::BIN_VHEAP_SZ, 8)))?;
                a.emit(|e| e.cmp_mr(process_ref(process::OFF_HEAP_OVERHEAD, 8), ARG1))?;
                a.jcc(CondCode::A, gc_after_bif_call)?;

                // Test if heap fragment size is larger than remaining heap size. erts writes
                // `x86::qword_ptr(HTOP, ARG2, 0, 3)`: asmjit's operands are (base, index,
                // shift, offset), so this is shift 0 and displacement 3, as erts emits it.
                a.emit(|e| e.mov_rm(ARG2, process_ref(process::MBUF_SZ, 8)))?;
                a.emit(|e| e.lea(ARG1, Mem::base_index(HTOP, ARG2, 0, 3, 8)))?;
                a.emit(|e| e.cmp_rr(E, ARG1))?;
                a.jcc(CondCode::L, gc_after_bif_call)?;
            }

            // ! FALL THROUGH !
            a.bind(check_bif_return)?;
            {
                let trap = a.new_label();
                let error = a.new_label();

                a.emit_test_the_non_value(RET)?;
                a.short_jcc(CondCode::E, trap)?;

                a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;

                a.emit_leave_frame()?;
                a.emit(|e| e.ret())?;

                a.bind(trap)?;
                {
                    a.emit(|e| {
                        e.cmp_mi(
                            process_ref(process::FREASON, 8),
                            arinsal_term::exc::TRAP as i64,
                        )
                    })?;
                    a.short_jcc(CondCode::NE, error)?;

                    // Trap out, our return address is on the Erlang stack. The BIF_TRAP
                    // macros all set up c_p->arity and c_p->current, so we can use a
                    // simplified context switch.
                    a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
                    a.jmp(context_switch_simplified)?;
                }

                a.bind(error)?;
                {
                    a.emit(|e| e.mov_rm(ARG2, entry_mem))?;
                    a.emit(|e| e.mov_rm(ARG4, export_mem))?;
                    a.emit(|e| e.add_ri(ARG4, i64::from(EXPORT_MFA)))?;

                    // Overwrite the return address with the entry address to ensure that only
                    // the entry address ends up in the stack trace.
                    const {
                        assert!(matches!(
                            super::beam_asm::FRAME_LAYOUT,
                            super::beam_asm::FrameLayout::Ra
                        ))
                    };
                    a.emit(|e| e.mov_mr(qword_ptr(E, 0), ARG2))?;

                    a.jmp(raise_exception_shared)?;
                }
            }

            a.bind(gc_after_bif_call)?;
            {
                a.emit(|e| e.mov_rm(ARG2, mbuf_mem))?;
                a.emit(|e| e.mov_rm(ARG5, export_mem))?;
                a.emit(|e| e.movzx_rm(ARG5D, byte_ptr(ARG5, EXPORT_MFA_ARITY)))?;

                a.emit_enter_runtime(spec)?;

                a.emit(|e| e.mov_rr(ARG1, C_P))?;
                a.emit(|e| e.mov_rr(ARG3, RET))?;
                a.load_x_reg_array(ARG4)?;
                a.runtime_call(erts_gc_after_bif_call_lhf as *const () as usize)?;

                a.emit_leave_runtime(spec)?;

                a.jmp(check_bif_return)?;
            }
        }

        a.bind(trace)?;
        {
            // Tail call the export entry instead of the BIF. With the native stack as the
            // Erlang stack our return address is already on the Erlang stack.
            a.emit_leave_frame()?;
            let destination = a.emit_setup_dispatchable_call_active(ARG4)?;
            a.emit(|e| e.jmp_m(destination))?;
        }

        a.bind(r#yield)?;
        {
            a.emit(|e| e.movzx_rm(ARG2D, byte_ptr(ARG4, EXPORT_MFA_ARITY)))?;
            a.emit(|e| e.lea(ARG4, qword_ptr(ARG4, EXPORT_MFA)))?;
            a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG2.r8()))?;
            a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG4))?;

            // We'll find our way back through ARG3 (entry address).
            a.emit_unwind_frame()?;

            a.jmp(context_switch_simplified)
        }
    }
}

impl BeamModuleAssembler {
    /// `call_light_bif(Bif, Exp)`: `Bif` is the address of the BIF's `(c_p, reg, I)` function,
    /// `Exp` its import.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:673-689 (emit_call_light_bif),
    // OTP-29.1.1.
    pub fn emit_call_light_bif(&mut self, bif: ArgVal, exp: ArgVal) -> Result<(), AsmError> {
        let ArgVal::Word(bif) = bif else {
            return Err(AsmError::Operand("call_light_bif: Bif must be a word"));
        };
        if !matches!(exp, ArgVal::Export(_)) {
            return Err(AsmError::Operand("call_light_bif: Exp must be an export"));
        }
        let entry = self.asm.new_label();

        self.asm.align_erlang_cp()?;
        self.asm.bind(entry)?;

        self.mov_arg_to_reg(ARG4, exp)?;
        self.asm.emit(|e| e.mov_ri(RET, bif as i64))?;
        self.asm
            .a
            .emit_rip_label(entry, |e| e.lea(ARG3, Mem::rip(0, 8)))?;

        let fragment = self.ga_get(GlobalLabels::CallLightBifShared)?;
        self.asm.fragment_call_abs(fragment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::beam_asm_global::GLOBAL_LABELS;
    use crate::x86::jdump::{erts_dump, gnu_as};
    use arinsal_x64::buf::Section;

    /// The lines of each `call_light_bif_be` block from the entry label to the fragment call,
    /// with the absolute call written as `fill` bytes (`call imm` through the address table).
    fn blocks(dump: &str, fill: u8) -> Vec<(u64, Vec<String>)> {
        let lines: Vec<&str> = dump.lines().map(str::trim).collect();
        let mut out = Vec::new();
        for (i, _) in lines
            .iter()
            .enumerate()
            .filter(|(_, l)| **l == "# call_light_bif_be")
        {
            let entry = lines[i + 2].trim_end_matches(':');
            let mut text = vec!["Lentry:".to_string()];
            let mut bif = None;
            for line in &lines[i + 3..] {
                if line.starts_with('#') || line.ends_with(':') {
                    continue;
                }
                if let Some(target) = line.strip_prefix("call ") {
                    assert!(target.parse::<u64>().is_ok(), "{line}");
                    text.push(format!(".byte 0x40, 0xe8, {fill}, {fill}, {fill}, {fill}"));
                    break;
                }
                if let Some(value) = line.strip_prefix("mov rax, ") {
                    bif = value.parse::<u64>().ok();
                }
                text.push(if *line == format!("lea rdx, qword ptr [{entry}]") {
                    "lea rdx, [rip+Lentry]".to_string()
                } else {
                    crate::x86::jdump::erts_to_arinsal(line)
                });
            }
            out.push((bif.expect("BIF address"), text));
        }
        out
    }

    // Differential check against erts: every `call_light_bif` site of a few boot modules
    // encodes the same instructions (the import patch, the BIF address, the entry address, the
    // padding that makes the return address a CP and the fragment call).
    #[test]
    fn call_light_bif_matches_erts_dump() {
        let dumps: Vec<String> = ["lists", "erlang", "gen_server", "code_server"]
            .iter()
            .filter_map(|m| erts_dump(m))
            .collect();
        if dumps.is_empty() || gnu_as(&[]).is_none() {
            eprintln!("skipping: `erl +JDdump true` or GNU binutils unavailable");
            return;
        }
        let mut compared = 0;
        for dump in &dumps {
            for ((bif, zeros), (_, ones)) in blocks(dump, 0).into_iter().zip(blocks(dump, 255)) {
                let (zeros, ones) = (gnu_as(&zeros).unwrap(), gnu_as(&ones).unwrap());
                let addresses = (0..GLOBAL_LABELS.len())
                    .map(|i| Some(0x7000_0000 + 64 * i))
                    .collect();
                let mut m = BeamModuleAssembler::with_fragment_addresses(16, addresses);
                m.emit_call_light_bif(ArgVal::Word(bif), ArgVal::Export(0))
                    .unwrap();
                let ours = m.asm.a.bytes(Section::Code);
                assert_eq!(ours.len(), zeros.len(), "{bif:#x}");
                assert!(
                    ours.iter()
                        .zip(zeros.iter().zip(&ones))
                        .all(|(o, (z, f))| z != f || o == z),
                    "{bif:#x}: {ours:02x?} vs {zeros:02x?}"
                );
                compared += 1;
            }
        }
        eprintln!("compared {compared} call_light_bif blocks");
        assert!(compared >= 100, "compared {compared}");
    }
}
