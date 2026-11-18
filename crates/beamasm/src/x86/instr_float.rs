//! Port of erts/emulator/beam/jit/x86/instr_float.cpp, OTP-29.1.1.
//!
//! The float registers live in the scheduler register block. `ArgVal::FReg` carries the
//! loader's byte offset (`register number * sizeof(FloatDef)`).

use arinsal_x64::enc::{self, CondCode, Mem, Xmm};

use super::beam_asm::{
    AsmError, BeamAssembler, CpuFeature, Distance, Update, emit_boxed_val, get_f_ref, process,
    process_ref, tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::BeamModuleAssembler;
pub use super::rt::big_to_double;
use crate::common::args::ArgVal;
use crate::common::types::{BeamModuleAssemblerCommon, type_id};
use crate::exc::EXC_BADARITH;

const TAG_PRIMARY_BOXED: i64 = 2;
const HEADER_FLONUM: i64 = 0x58;
const FLOAT_SIZE_OBJECT_WORDS: i64 = 2;
const TAG_IMMED1_SIZE: i64 = 4;
const HEADER_POS_BIG: i64 = 0x08;

fn fregister(arg: ArgVal) -> Result<Mem, AsmError> {
    match arg {
        ArgVal::FReg(byte_offset) if byte_offset.is_multiple_of(8) => {
            let index = byte_offset / 8;
            Ok(get_f_ref(index, 8))
        }
        ArgVal::FReg(_) => Err(AsmError::Operand("float register byte offset")),
        _ => Err(AsmError::Operand("float register operand")),
    }
}

impl BeamGlobalAssembler {
    /// Checks that the computed float is finite and raises `badarith` otherwise.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:36-64 (emit_check_float_error),
    // OTP-29.1.1.
    pub fn emit_check_float_error(&mut self) -> Result<(), AsmError> {
        let error = self.asm.new_label();
        let float_max = self.asm.new_label();
        let float_sign_mask = self.asm.new_label();

        self.asm
            .a
            .emit_rip_label(float_max, |e| e.vmovsd_xm(Xmm(1), Mem::rip(0, 8)))?;
        if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            self.asm.a.emit_rip_label(float_sign_mask, |e| {
                e.vandpd_xxm(Xmm(2), Xmm(0), Mem::rip(0, 16))
            })?;
        } else {
            self.asm.emit(|e| e.movq_xx(Xmm(2), Xmm(0)))?;
            self.asm
                .a
                .emit_rip_label(float_sign_mask, |e| e.andpd_xm(Xmm(2), Mem::rip(0, 16)))?;
        }
        self.asm.emit(|e| e.vucomisd_xx(Xmm(1), Xmm(2)))?;
        self.asm.short_jcc(CondCode::B, error)?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(error)?;
        self.asm
            .emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADARITH as i64))?;
        self.asm.emit(|e| {
            e.sub_rr(
                super::beam_asm::register::ARG4,
                super::beam_asm::register::ARG4,
            )
        })?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))?;

        self.asm.align_code(16)?;
        self.asm.bind(float_sign_mask)?;
        self.asm.a.embed_u64(0x7fff_ffff_ffff_ffff)?;
        self.asm.bind(float_max)?;
        self.asm.a.embed_f64(f64::MAX)?;
        Ok(())
    }
}

impl BeamModuleAssembler {
    /// Loads a boxed float term into a BEAM float register.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:83-92 (emit_fload), OTP-29.1.1.
    pub fn emit_fload(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let dst = fregister(dst)?;
        self.mov_arg_to_reg(super::beam_asm::register::ARG1, src)?;
        let boxed_ptr = self.asm.emit_ptr_val(
            super::beam_asm::register::ARG1,
            super::beam_asm::register::ARG1,
        );
        self.asm
            .emit(|e| e.vmovsd_xm(Xmm(0), emit_boxed_val(boxed_ptr, 8, 8)))?;
        self.asm.emit(|e| e.vmovsd_mx(dst, Xmm(0)))?;
        Ok(())
    }

    /// Allocates a boxed float from a BEAM float register and stores its term in Dst.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:94-111 (emit_fstore), OTP-29.1.1.
    pub fn emit_fstore(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let src = fregister(src)?;
        self.asm.emit(|e| e.vmovsd_xm(Xmm(0), src))?;

        self.asm.emit(|e| {
            e.mov_mi(
                enc::qword_ptr(super::beam_asm::register::HTOP, 0),
                HEADER_FLONUM,
            )
        })?;
        self.asm
            .emit(|e| e.vmovsd_mx(enc::qword_ptr(super::beam_asm::register::HTOP, 8), Xmm(0)))?;
        self.asm.emit(|e| {
            e.lea(
                super::beam_asm::register::ARG1,
                enc::qword_ptr(super::beam_asm::register::HTOP, TAG_PRIMARY_BOXED as i32),
            )
        })?;
        self.mov_arg_from_reg(dst, super::beam_asm::register::ARG1)?;
        self.preserve_cache(&[super::beam_asm::register::HTOP], &[], |m| {
            m.asm
                .emit(|e| e.add_ri(super::beam_asm::register::HTOP, FLOAT_SIZE_OBJECT_WORDS * 8))
        })?;
        Ok(())
    }

    /// Emits a floating point operation and raises `badarith` when the result is not finite.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:66-81 (emit_float_instr), OTP-29.1.1.
    fn emit_float_instr(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        dst: ArgVal,
        sse: impl FnOnce(
            &mut arinsal_x64::enc::Emitter,
            Xmm,
            Xmm,
        ) -> Result<(), arinsal_x64::enc::EncodeError>,
        avx: impl FnOnce(
            &mut arinsal_x64::enc::Emitter,
            Xmm,
            Xmm,
            Xmm,
        ) -> Result<(), arinsal_x64::enc::EncodeError>,
    ) -> Result<(), AsmError> {
        let (lhs, rhs, dst) = (fregister(lhs)?, fregister(rhs)?, fregister(dst)?);
        let (xmm0, xmm1) = (Xmm(0), Xmm(1));
        self.asm.emit(|e| e.vmovsd_xm(xmm0, lhs))?;
        self.asm.emit(|e| e.vmovsd_xm(xmm1, rhs))?;
        if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            self.asm.emit(|e| avx(e, xmm0, xmm0, xmm1))?;
        } else {
            self.asm.emit(|e| sse(e, xmm0, xmm1))?;
        }
        let check = self.ga_get(GlobalLabels::CheckFloatError)?;
        self.safe_fragment_call(check)?;
        self.asm.emit(|e| e.vmovsd_mx(dst, xmm0))?;
        Ok(())
    }

    /// Converts a BEAM integer or float term into a float register.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:152-211 (emit_fconv), OTP-29.1.1.
    pub fn emit_fconv(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let dst = fregister(dst)?;
        if self.always_small(src) {
            self.mov_arg_to_reg(super::beam_asm::register::ARG2, src)?;
            self.asm
                .emit(|e| e.sar_ri(super::beam_asm::register::ARG2, TAG_IMMED1_SIZE))?;
            if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
                self.asm
                    .emit(|e| e.vcvtsi2sd_xxr(Xmm(0), Xmm(0), super::beam_asm::register::ARG2))?;
            } else {
                self.asm
                    .emit(|e| e.cvtsi2sd_xr(Xmm(0), super::beam_asm::register::ARG2))?;
            }
            self.asm.emit(|e| e.vmovsd_mx(dst, Xmm(0)))?;
            return Ok(());
        }

        let next = self.asm.new_label();
        let not_small = self.asm.new_label();
        let fallback = self.asm.new_label();
        let arg2 = super::beam_asm::register::ARG2;
        self.mov_arg_to_reg(arg2, src)?;
        self.emit_is_small(not_small, src, arg2)?;
        self.asm.emit(|e| e.sar_ri(arg2, TAG_IMMED1_SIZE))?;
        if BeamAssembler::has_cpu_feature(CpuFeature::Avx) {
            self.asm.emit(|e| e.vcvtsi2sd_xxr(Xmm(0), Xmm(0), arg2))?;
        } else {
            self.asm.emit(|e| e.cvtsi2sd_xr(Xmm(0), arg2))?;
        }
        self.asm.short_jmp(next)?;

        self.asm.bind(not_small)?;
        if self.never_one_of(src, type_id::FLOAT) {
            // The compiler type excludes floats; the shared path handles bignums and errors.
        } else {
            if !self.always_one_of(src, type_id::NUMBER) {
                self.emit_is_boxed_source(fallback, src, arg2, Distance::Short)?;
            }
            let boxed_ptr = self.asm.emit_ptr_val(super::beam_asm::register::ARG1, arg2);
            self.asm
                .emit(|e| e.vmovsd_xm(Xmm(0), emit_boxed_val(boxed_ptr, 8, 8)))?;
            self.asm
                .emit(|e| e.cmp_mi(emit_boxed_val(boxed_ptr, 0, 8), HEADER_FLONUM))?;
            self.asm.short_jcc(CondCode::E, next)?;
        }

        self.asm.bind(fallback)?;
        let fragment = self.ga_get(GlobalLabels::FconvShared)?;
        self.safe_fragment_call(fragment)?;

        self.asm.bind(next)?;
        self.asm.emit(|e| e.vmovsd_mx(dst, Xmm(0)))?;
        Ok(())
    }

    /// Adds two float registers.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:213-218 (emit_i_fadd), OTP-29.1.1.
    pub fn emit_i_fadd(&mut self, lhs: ArgVal, rhs: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        self.emit_float_instr(
            lhs,
            rhs,
            dst,
            |e, d, s| e.addpd_xx(d, s),
            |e, d, a, b| e.vaddpd_xxx(d, a, b),
        )
    }

    /// Subtracts the right float register from the left one.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:219-224 (emit_i_fsub), OTP-29.1.1.
    pub fn emit_i_fsub(&mut self, lhs: ArgVal, rhs: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        self.emit_float_instr(
            lhs,
            rhs,
            dst,
            |e, d, s| e.subpd_xx(d, s),
            |e, d, a, b| e.vsubpd_xxx(d, a, b),
        )
    }

    /// Multiplies two float registers.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:225-230 (emit_i_fmul), OTP-29.1.1.
    pub fn emit_i_fmul(&mut self, lhs: ArgVal, rhs: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        self.emit_float_instr(
            lhs,
            rhs,
            dst,
            |e, d, s| e.mulpd_xx(d, s),
            |e, d, a, b| e.vmulpd_xxx(d, a, b),
        )
    }

    /// Divides the left float register by the right one.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:231-236 (emit_i_fdiv), OTP-29.1.1.
    pub fn emit_i_fdiv(&mut self, lhs: ArgVal, rhs: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        self.emit_float_instr(
            lhs,
            rhs,
            dst,
            |e, d, s| e.divpd_xx(d, s),
            |e, d, a, b| e.vdivpd_xxx(d, a, b),
        )
    }

    /// Negates a float by toggling its sign bit.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:237-247 (emit_i_fnegate), OTP-29.1.1.
    pub fn emit_i_fnegate(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), AsmError> {
        let src_mem = fregister(src)?;
        let dst_mem = fregister(dst)?;
        if src != dst {
            self.asm
                .emit(|e| e.mov_rm(super::beam_asm::register::RET, src_mem))?;
            self.asm
                .emit(|e| e.btc_ri(super::beam_asm::register::RET, 63))?;
            self.asm
                .emit(|e| e.mov_mr(dst_mem, super::beam_asm::register::RET))?;
        } else {
            self.asm.emit(|e| e.btc_mi(dst_mem, 63))?;
        }
        Ok(())
    }
}

impl BeamGlobalAssembler {
    /// Converts a boxed bignum to double, or raises `badarith` on failure.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:113-150 (emit_fconv_shared),
    // OTP-29.1.1.
    pub fn emit_fconv_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.new_label();
        let arg1 = super::beam_asm::register::ARG1;
        let arg2 = super::beam_asm::register::ARG2;
        let ret = super::beam_asm::register::RET;
        self.asm.emit(|e| e.mov_rr(arg1, arg2))?;
        self.asm.emit_is_boxed(error, arg2, Distance::Short)?;
        let boxed_ptr = self.asm.emit_ptr_val(arg2, arg2);
        self.asm
            .emit(|e| e.mov_rm(arg2, emit_boxed_val(boxed_ptr, 0, 8)))?;
        self.asm.emit(|e| e.and_ri(arg2, 0x3b))?;
        self.asm.emit(|e| e.cmp_ri(arg2, HEADER_POS_BIG))?;
        self.asm.short_jcc(CondCode::NE, error)?;
        self.asm.emit_enter_frame()?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.lea(arg2, tmp_mem_q(0)))?;
        self.asm.runtime_call(big_to_double as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.test_rr(ret.r32(), ret.r32()))?;
        self.asm.short_jcc(CondCode::S, error)?;
        self.asm.emit(|e| e.vmovsd_xm(Xmm(0), tmp_mem_q(0)))?;
        self.asm.emit(|e| e.ret())?;

        self.asm.bind(error)?;
        self.asm
            .emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADARITH as i64))?;
        self.asm.emit(|e| {
            e.sub_rr(
                super::beam_asm::register::ARG4,
                super::beam_asm::register::ARG4,
            )
        })?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::args::ArgVal;
    use crate::common::types::{ArgType, type_id};
    use crate::x86::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
    use crate::x86::beam_asm_module::BeamModuleAssembler;
    use crate::x86::jdump::{
        erts_dump, erts_to_arinsal, gnu_as, matches_with_global_jumps, op_blocks,
    };
    use arinsal_x64::buf::Section;
    use similar_asserts::assert_eq;

    fn first_block(module: &str, op: &str) -> Vec<String> {
        let dump = erts_dump(module).expect("OTP 29.1.1 jdump for boot module");
        op_blocks(&dump, op)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("no {op} block in {module}"))
    }

    fn first_complete_block(module: &str, op: &str) -> Vec<String> {
        let dump = erts_dump(module).expect("OTP 29.1.1 jdump for boot module");
        let is_header = |line: &str| {
            line.strip_prefix("# ").is_some_and(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        };
        let mut current: Option<Vec<String>> = None;
        for line in dump.lines() {
            if is_header(line) {
                if let Some(block) = current.take() {
                    return block;
                }
                if line == format!("# {op}") {
                    current = Some(Vec::new());
                }
            } else if let Some(block) = current.as_mut()
                && !line.starts_with('#')
            {
                block.push(line.trim().to_string());
            }
        }
        current.unwrap_or_else(|| panic!("no {op} block in {module}"))
    }

    fn fragment_module() -> BeamModuleAssembler {
        BeamModuleAssembler::with_fragment_addresses(
            8,
            vec![Some(0x100000); crate::x86::beam_asm_global::GLOBAL_LABELS.len()],
        )
    }

    fn module_block(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                let line = erts_to_arinsal(line);
                if line.starts_with("call L") {
                    ".byte 0xe8, 0, 0, 0, 0".to_string()
                } else {
                    line
                }
            })
            .collect()
    }

    fn global_lines(dump: &str, name: &str) -> Vec<String> {
        let head = format!("global::{name}:");
        let mut found = false;
        let mut lines = Vec::new();
        for line in dump.lines() {
            if line.starts_with("global::") {
                if found {
                    break;
                }
                found = line == head;
                continue;
            }
            if found {
                let line = line.trim();
                if line == "align 16" {
                    lines.push(".balign 16".to_string());
                } else if !line.is_empty() && !line.starts_with("align ") && !line.starts_with('#')
                {
                    lines.push(
                        erts_to_arinsal(line)
                            .replace(".dq ", ".quad ")
                            .replace("[L", "[rip + L"),
                    );
                }
            }
        }
        lines
    }

    #[test]
    fn check_float_error_matches_erts_global_fragment() {
        let dump = erts_dump("beam_asm_global").expect("OTP 29.1.1 global jdump");
        let mut lines = global_lines(&dump, "check_float_error");
        for line in &mut lines {
            if line == "jmp global::raise_exception" {
                *line = ".byte 0xe9, 0, 0, 0, 0".to_string();
            }
        }
        let nops = [
            "0x90",
            "0x66, 0x90",
            "0x0f, 0x1f, 0x00",
            "0x0f, 0x1f, 0x40, 0x00",
            "0x0f, 0x1f, 0x44, 0x00, 0x00",
            "0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00",
            "0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00",
            "0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00",
            "0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00",
        ];
        let mut expected_lines = Vec::new();
        for line in lines {
            if line == ".balign 16" {
                let offset = gnu_as(&expected_lines).expect("GNU as prefix").len();
                let mut padding = (16 - offset % 16) % 16;
                while padding > 0 {
                    let length = padding.min(nops.len());
                    expected_lines.push(format!(".byte {}", nops[length - 1]));
                    padding -= length;
                }
            } else {
                expected_lines.push(line);
            }
        }
        let mut global = BeamGlobalAssembler::declare_labels(
            crate::common::process_offsets::ProcessOffsets::ERTS_X86_64,
        );
        let label = global.label(GlobalLabels::CheckFloatError);
        global.asm.bind(label).unwrap();
        global.emit_check_float_error().unwrap();
        let actual = global.asm.a.bytes(Section::Code);
        let expected = gnu_as(&expected_lines).expect("GNU as");
        assert_eq!(actual, expected, "{expected_lines:?}");
    }

    #[test]
    fn float_register_offsets_are_loader_byte_offsets() {
        assert_eq!(
            fregister(ArgVal::FReg(0)).unwrap().disp,
            super::super::beam_asm::f_ref_disp(0)
        );
        assert_eq!(
            fregister(ArgVal::FReg(8)).unwrap().disp,
            super::super::beam_asm::f_ref_disp(1)
        );
        assert!(fregister(ArgVal::FReg(1)).is_err());
    }

    #[test]
    fn fload_matches_erts_dump() {
        let lines = first_block("erl_scan", "fload_Sl");
        let expected = gnu_as(
            &lines
                .iter()
                .map(|line| erts_to_arinsal(line))
                .collect::<Vec<_>>(),
        )
        .expect("GNU as");
        let mut module = BeamModuleAssembler::new(0);
        module.emit_fload(ArgVal::X(0), ArgVal::FReg(128)).unwrap();
        assert_eq!(module.asm.a.bytes(Section::Code), expected);
    }

    #[test]
    fn fstore_matches_erts_dump() {
        let lines = first_block("erl_scan", "fstore_ld");
        let expected = gnu_as(
            &lines
                .iter()
                .map(|line| erts_to_arinsal(line))
                .collect::<Vec<_>>(),
        )
        .expect("GNU as");
        let mut module = BeamModuleAssembler::new(0);
        module.emit_fstore(ArgVal::FReg(64), ArgVal::X(7)).unwrap();
        assert_eq!(module.asm.a.bytes(Section::Code), expected);
    }

    #[test]
    fn float_arithmetic_conversion_and_negation_match_erts_dump() {
        for (module_name, op, emit, lhs, rhs) in [
            (
                "rand",
                "i_fadd_lll",
                BeamModuleAssembler::emit_i_fadd
                    as fn(&mut BeamModuleAssembler, ArgVal, ArgVal, ArgVal) -> Result<(), AsmError>,
                128,
                64,
            ),
            (
                "erl_scan",
                "i_fmul_lll",
                BeamModuleAssembler::emit_i_fmul,
                64,
                128,
            ),
            (
                "beam_lib",
                "i_fdiv_lll",
                BeamModuleAssembler::emit_i_fdiv,
                64,
                128,
            ),
            (
                "rand",
                "i_fsub_lll",
                BeamModuleAssembler::emit_i_fsub,
                64,
                128,
            ),
        ] {
            let lines = first_block(module_name, op);
            let mut module = fragment_module();
            emit(
                &mut module,
                ArgVal::FReg(lhs),
                ArgVal::FReg(rhs),
                ArgVal::FReg(64),
            )
            .unwrap();
            let actual = module.asm.a.bytes(Section::Code);
            let expected = module_block(&lines);
            assert_eq!(
                matches_with_global_jumps(&expected, actual, &[]),
                Some(true),
                "{module_name}:{op}: {expected:?} vs {actual:02x?}"
            );
        }

        let lines = first_complete_block("erl_scan", "fconv_sl");
        let mut module = fragment_module();
        let source = ArgVal::typed_y(0, 1);
        module.beam_types.push(ArgType {
            union_bits: type_id::INTEGER,
            min: None,
            max: None,
            unit: 1,
        });
        module.emit_fconv(source, ArgVal::FReg(64)).unwrap();
        let actual = module.asm.a.bytes(Section::Code);
        let expected = module_block(&lines);
        assert_eq!(
            matches_with_global_jumps(&expected, actual, &[]),
            Some(true),
            "fconv: {expected:?} vs {actual:02x?}"
        );

        let lines = first_block("rand", "i_fnegate_ll");
        let mut module = fragment_module();
        module
            .emit_i_fnegate(ArgVal::FReg(64), ArgVal::FReg(64))
            .unwrap();
        let expected = gnu_as(&module_block(&lines)).expect("GNU as");
        assert_eq!(module.asm.a.bytes(Section::Code), expected);
    }
}
