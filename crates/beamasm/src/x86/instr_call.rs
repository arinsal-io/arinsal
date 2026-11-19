//! Port of erts/emulator/beam/jit/x86/instr_call.cpp, OTP-29.1.1.

use arinsal_term::{ErtsCodeMfa, Term, atoms};
use arinsal_x64::buf::Label;
use arinsal_x64::enc::{CondCode, Mem, dword_ptr, qword_ptr};

use super::beam_asm::register::{ARG1, ARG1D, ARG2, ARG3, ARG4, ARG5, C_P, E, FCALLS, RET};
use super::beam_asm::{AsmError, Update, process, process_ref, tmp_mem_q};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, arg_label};
pub use super::rt::{apply, fixed_apply, save_calls};
use crate::common::args::ArgVal;

// Port of the `apply3_mfa` initializer in instr_call.cpp:145, OTP-29.1.1.
const fn mfa(function: arinsal_term::Atom, arity: usize) -> ErtsCodeMfa {
    ErtsCodeMfa {
        module: Term::atom(atoms::ERLANG).word(),
        function: Term::atom(function).word(),
        arity,
    }
}

/// `apply/3`, used when variable apply cannot resolve an export.
// Port of erts/emulator/beam/jit/x86/instr_call.cpp:145-145 (apply3_mfa), OTP-29.1.1.
pub(crate) static APPLY3_MFA: ErtsCodeMfa = mfa(atoms::APPLY, 3);

impl BeamGlobalAssembler {
    /// Schedules out at a return; `ARG3` receives the return address from the Erlang stack.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:30-41 (emit_dispatch_return),
    // OTP-29.1.1.
    pub(crate) fn emit_dispatch_return(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.pop_r(ARG3))?;
        a.emit(|e| e.mov_mi(process_ref(process::CURRENT, 8), 0))?;
        a.emit(|e| e.mov_mi(process_ref(process::ARITY, 1), 1))?;
        let context_switch = self.label(GlobalLabels::ContextSwitchSimplified);
        self.asm.jmp(context_switch)
    }

    /// Records an export call for `save_calls` and continues with the active code index.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:98-118
    // (emit_dispatch_save_calls_export), OTP-29.1.1.
    pub(crate) fn emit_dispatch_save_calls_export(&mut self) -> Result<(), AsmError> {
        let active = &raw const super::rt::the_active_code_index as i64;
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), RET))?;
        a.emit_enter_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| e.mov_rr(ARG2, RET))?;
        a.runtime_call(save_calls as *const () as usize)?;
        a.emit_leave_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rm(RET, tmp_mem_q(0)))?;
        a.emit(|e| e.mov_ri(ARG1, active))?;
        a.emit(|e| e.mov_rm(ARG1D, dword_ptr(ARG1, 0)))?;
        let target = a.emit_setup_dispatchable_call(RET, ARG1)?;
        a.emit(|e| e.jmp_m(target))
    }
}

impl BeamModuleAssembler {
    /// `return`: leaves the current frame, checks reductions, and returns to its CP.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:43-45 (emit_return), OTP-29.1.1.
    pub fn emit_return(&mut self) -> Result<(), AsmError> {
        self.emit_return_do(false)
    }

    /// `emit_return_do(set_I)`: the reduction test stays in module code as in erts.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:47-80 (emit_return_do), OTP-29.1.1.
    pub fn emit_return_do(&mut self, set_i: bool) -> Result<(), AsmError> {
        self.asm.emit_leave_frame()?;
        if set_i {
            self.asm.emit(|e| e.mov_rm(ARG3, qword_ptr(E, 0)))?;
            self.asm
                .emit(|e| e.mov_mr(process_ref(process::I, 8), ARG3))?;
        }
        self.asm.emit(|e| e.dec_r(FCALLS))?;
        let dispatch_return = self.ga_get(GlobalLabels::DispatchReturn)?;
        let target = self.resolve_fragment(dispatch_return);
        self.asm.jcc(CondCode::L, target)?;
        self.asm.emit(|e| e.ret())
    }

    /// `i_call CallDest`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:80-82 (emit_i_call), OTP-29.1.1.
    pub fn emit_i_call(&mut self, call_dest: ArgVal) -> Result<(), AsmError> {
        let target = self.call_label(call_dest)?;
        self.asm.erlang_call(target)
    }

    /// `i_call_last CallDest Deallocate`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:84-88 (emit_i_call_last), OTP-29.1.1.
    pub fn emit_i_call_last(
        &mut self,
        call_dest: ArgVal,
        deallocate: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_deallocate(deallocate)?;
        self.emit_i_call_only(call_dest)
    }

    /// `i_call_only CallDest`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:90-94 (emit_i_call_only), OTP-29.1.1.
    pub fn emit_i_call_only(&mut self, call_dest: ArgVal) -> Result<(), AsmError> {
        self.asm.emit_leave_frame()?;
        let target = self.call_label(call_dest)?;
        self.asm.jmp(target)
    }

    /// `i_call_ext Exp`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:120-124 (emit_i_call_ext), OTP-29.1.1.
    pub fn emit_i_call_ext(&mut self, export: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(RET, export)?;
        let target = self.asm.emit_setup_dispatchable_call_active(RET)?;
        self.asm.erlang_call_m(target)
    }

    /// `i_call_ext_only Exp`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:126-132
    // (emit_i_call_ext_only), OTP-29.1.1.
    pub fn emit_i_call_ext_only(&mut self, export: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(RET, export)?;
        let target = self.asm.emit_setup_dispatchable_call_active(RET)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.jmp_m(target))
    }

    /// `i_call_ext_last Exp Deallocate`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:134-145
    // (emit_i_call_ext_last), OTP-29.1.1.
    pub fn emit_i_call_ext_last(
        &mut self,
        export: ArgVal,
        deallocate: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_deallocate(deallocate)?;
        self.mov_arg_to_reg(RET, export)?;
        let target = self.asm.emit_setup_dispatchable_call_active(RET)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.jmp_m(target))
    }

    /// Builds the variable-arity `apply/3` dispatch before its caller invokes the export.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:147-177 (emit_variable_apply),
    // OTP-29.1.1.
    fn emit_variable_apply(&mut self, include_i: bool) -> Result<Mem, AsmError> {
        let dispatch = self.asm.new_label();
        let entry = self.asm.new_label();

        self.asm.align_erlang_cp()?;
        self.asm.bind(entry)?;
        let update = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        self.asm.emit_enter_runtime(update)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        if include_i {
            self.asm
                .a
                .emit_rip_label(entry, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
        } else {
            self.asm.mov_imm(ARG3, 0)?;
        }
        self.asm.mov_imm(ARG4, 0)?;
        self.asm.runtime_call(apply as *const () as usize)?;
        self.asm.emit_leave_runtime(update)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.short_jcc(CondCode::NE, dispatch)?;
        self.emit_raise_exception_label(entry, Some(&APPLY3_MFA))?;
        self.asm.bind(dispatch)?;
        self.asm.emit_setup_dispatchable_call_active(RET)
    }

    /// `i_apply`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:179-182 (emit_i_apply), OTP-29.1.1.
    pub fn emit_i_apply(&mut self) -> Result<(), AsmError> {
        let target = self.emit_variable_apply(false)?;
        self.asm.erlang_call_m(target)
    }

    /// `i_apply_last Deallocate`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:184-187 (emit_i_apply_last), OTP-29.1.1.
    pub fn emit_i_apply_last(&mut self, deallocate: ArgVal) -> Result<(), AsmError> {
        self.emit_deallocate(deallocate)?;
        self.emit_i_apply_only()
    }

    /// `i_apply_only`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:189-194 (emit_i_apply_only), OTP-29.1.1.
    pub fn emit_i_apply_only(&mut self) -> Result<(), AsmError> {
        let target = self.emit_variable_apply(true)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.jmp_m(target))
    }

    /// Builds the fixed-arity `apply/3` dispatch before its caller invokes the export.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:196-228 (emit_fixed_apply),
    // OTP-29.1.1.
    fn emit_fixed_apply(&mut self, arity: ArgVal, include_i: bool) -> Result<Mem, AsmError> {
        let dispatch = self.asm.new_label();
        let entry = self.asm.new_label();

        self.asm.align_erlang_cp()?;
        self.asm.bind(entry)?;
        self.mov_arg_to_reg(ARG3, arity)?;
        let update = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        self.asm.emit_enter_runtime(update)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        if include_i {
            self.asm
                .a
                .emit_rip_label(entry, |e| e.lea(ARG4, Mem::rip(0, 8)))?;
        } else {
            self.asm.mov_imm(ARG4, 0)?;
        }
        self.asm.mov_imm(ARG5, 0)?;
        self.asm.runtime_call(fixed_apply as *const () as usize)?;
        self.asm.emit_leave_runtime(update)?;
        self.asm.emit(|e| e.test_rr(RET, RET))?;
        self.asm.short_jcc(CondCode::NE, dispatch)?;
        self.emit_raise_exception_label(entry, Some(&APPLY3_MFA))?;
        self.asm.bind(dispatch)?;
        self.asm.emit_setup_dispatchable_call_active(RET)
    }

    /// `apply Arity`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:231-234 (emit_apply), OTP-29.1.1.
    pub fn emit_apply(&mut self, arity: ArgVal) -> Result<(), AsmError> {
        let target = self.emit_fixed_apply(arity, false)?;
        self.asm.erlang_call_m(target)
    }

    /// `apply_last Arity Deallocate`.
    // Port of erts/emulator/beam/jit/x86/instr_call.cpp:236-246 (emit_apply_last), OTP-29.1.1.
    pub fn emit_apply_last(&mut self, arity: ArgVal, deallocate: ArgVal) -> Result<(), AsmError> {
        self.emit_deallocate(deallocate)?;
        let target = self.emit_fixed_apply(arity, true)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.jmp_m(target))
    }

    fn call_label(&self, call_dest: ArgVal) -> Result<Label, AsmError> {
        self.resolve_beam_label(arg_label(call_dest)?)
            .ok_or(AsmError::Operand("call to an unknown label"))
    }
}

#[cfg(test)]
pub(crate) mod differential_tests {
    use super::*;
    use crate::x86::beam_asm_global::GLOBAL_LABELS;
    use crate::x86::beam_asm_module::LambdaPatch;
    use crate::x86::jdump::{erts_dump, erts_to_arinsal, gnu_as, matches_with_global_jumps};
    use arinsal_x64::buf::Section;

    const FAR_LABEL_PADDING: usize = 200;

    #[derive(Clone, Copy)]
    pub(crate) enum Target {
        Beam(u32),
        Fragment(GlobalLabels),
        Lambda(u32),
    }

    pub(crate) struct TargetRewrite {
        pub(crate) source: &'static str,
        pub(crate) target: Target,
    }

    fn full_op_blocks(dump: &str, op: &str) -> Vec<Vec<String>> {
        let is_header = |line: &str| {
            line.strip_prefix("# ").is_some_and(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        };
        let mut blocks = Vec::new();
        let mut current: Option<Vec<String>> = None;
        for line in dump.lines() {
            if is_header(line) {
                if let Some(block) = current.take() {
                    blocks.push(block);
                }
                if line == format!("# {op}") {
                    current = Some(Vec::new());
                }
            } else if let Some(block) = current.as_mut()
                && !line.starts_with('#')
            {
                block.push(line.trim().to_owned());
            }
        }
        blocks.extend(current);
        blocks
    }

    fn rewrite_expected(
        block: &[String],
        rewrites: &[(String, String)],
        pointer_rewrites: &[(&str, u64)],
    ) -> Vec<String> {
        let mut lines = Vec::new();
        for line in block {
            let is_branch =
                line.starts_with("short ") || line.starts_with("long ") || line.starts_with('j');
            let mut line = if is_branch {
                line.clone()
            } else {
                erts_to_arinsal(line)
            };
            if let Some(alignment) = line.strip_prefix("align ") {
                line = format!(".balign {alignment}");
            }
            if line.starts_with("lea ")
                && let Some((before, label)) = line.split_once("ptr [L")
            {
                line = format!("{before}ptr [rip + L{label}");
            }
            for (from, to) in rewrites {
                line = line.replace(from, to);
            }
            for (register, address) in pointer_rewrites {
                let prefix = format!("mov {register}, ");
                if let Some(value) = line.strip_prefix(&prefix)
                    && value.parse::<u64>().is_ok()
                {
                    line = format!("{prefix}{address}");
                }
            }
            lines.push(line);
        }
        lines
    }

    fn explicit_branch(line: &str) -> Option<[String; 2]> {
        let (short, mnemonic, target) = if let Some(rest) = line.strip_prefix("short ") {
            let (mnemonic, target) = rest.split_once(' ')?;
            (true, mnemonic, target)
        } else if let Some(rest) = line.strip_prefix("long ") {
            let (mnemonic, target) = rest.split_once(' ')?;
            (false, mnemonic, target)
        } else {
            let (mnemonic, target) = line.split_once(' ')?;
            (false, mnemonic, target)
        };
        if target.contains(' ') || target.starts_with('r') || target.starts_with('e') {
            return None;
        }
        let opcode = match mnemonic {
            "jmp" => 0xe9,
            "jo" => 0x80,
            "jno" => 0x81,
            "jb" | "jc" | "jnae" => 0x82,
            "jae" | "jnb" | "jnc" => 0x83,
            "je" | "jz" => 0x84,
            "jne" | "jnz" => 0x85,
            "jbe" | "jna" => 0x86,
            "ja" | "jnbe" => 0x87,
            "js" => 0x88,
            "jns" => 0x89,
            "jp" | "jpe" => 0x8a,
            "jnp" | "jpo" => 0x8b,
            "jl" | "jnge" => 0x8c,
            "jge" | "jnl" => 0x8d,
            "jle" | "jng" => 0x8e,
            "jg" | "jnle" => 0x8f,
            _ => return None,
        };
        if mnemonic == "jmp" {
            if short {
                Some([".byte 0xeb".to_owned(), format!(".byte {target} - . - 1")])
            } else {
                Some([".byte 0xe9".to_owned(), format!(".long {target} - . - 4")])
            }
        } else if short {
            Some([
                format!(".byte {:#04x}", 0x70 + (opcode - 0x80)),
                format!(".byte {target} - . - 1"),
            ])
        } else {
            Some([
                format!(".byte 0x0f, {opcode:#04x}"),
                format!(".long {target} - . - 4"),
            ])
        }
    }

    fn global_branch_bytes(line: &str) -> Option<String> {
        let (op, _) = line.split_once(" global::")?;
        if op == "call" {
            return Some(".byte 0xe8, 0, 0, 0, 0".to_owned());
        }
        let short = op.starts_with("short ");
        let mnemonic = op.strip_prefix("short ").unwrap_or(op);
        let condition = match mnemonic {
            "jo" => 0x80,
            "jno" => 0x81,
            "jb" | "jc" | "jnae" => 0x82,
            "jae" | "jnb" | "jnc" => 0x83,
            "je" | "jz" => 0x84,
            "jne" | "jnz" => 0x85,
            "jbe" | "jna" => 0x86,
            "ja" | "jnbe" => 0x87,
            "js" => 0x88,
            "jns" => 0x89,
            "jp" | "jpe" => 0x8a,
            "jnp" | "jpo" => 0x8b,
            "jl" | "jnge" => 0x8c,
            "jge" | "jnl" => 0x8d,
            "jle" | "jng" => 0x8e,
            "jg" | "jnle" => 0x8f,
            "jmp" => 0,
            _ => return None,
        };
        let opcode = if mnemonic == "jmp" {
            if short { vec![0xeb] } else { vec![0xe9] }
        } else if short {
            vec![0x70 + (condition - 0x80)]
        } else {
            vec![0x0f, condition]
        };
        let displacement_len = if short { 1 } else { 4 };
        Some(format!(
            ".byte {}",
            opcode
                .into_iter()
                .chain(std::iter::repeat_n(0, displacement_len))
                .map(|byte| format!("{byte:#04x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    /// Reconstructs the CP padding hidden at a labeled call boundary in +JDdump.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:400-439 (aligned_call), OTP-29.1.1.
    fn align_reference_call(lines: &mut Vec<String>, target_labels: &[String]) {
        let Some(index) = lines.iter().rposition(|line| {
            line.strip_prefix("call ").is_some_and(|target| {
                !target.contains("global::") && target.parse::<u64>().is_err()
            })
        }) else {
            return;
        };
        let mut prefix = lines[..index]
            .iter()
            .map(|line| global_branch_bytes(line).unwrap_or_else(|| line.clone()))
            .collect::<Vec<_>>();
        prefix.extend(target_labels.iter().cloned());
        let offset = gnu_as(&prefix)
            .expect("assemble +JDdump prefix for aligned call")
            .len();
        let target = lines[index].strip_prefix("call ").unwrap();
        let call_size = if target.starts_with('L') || target.starts_with("__target_") {
            5
        } else {
            gnu_as(&[lines[index].clone()])
                .expect("assemble +JDdump aligned call")
                .len()
        };
        let padding = (4 - (offset + call_size) % 4) % 4;
        let nop = match padding {
            0 => return,
            1 => ".byte 0x90",
            2 => ".byte 0x66, 0x90",
            3 => ".byte 0x0f, 0x1f, 0x00",
            _ => unreachable!(),
        };
        lines.insert(index, nop.to_owned());
    }

    fn get_target(
        module: &mut BeamModuleAssembler,
        index: usize,
        rewrite: TargetRewrite,
    ) -> Result<(String, Label), AsmError> {
        let label = match rewrite.target {
            Target::Beam(index) => module
                .resolve_beam_label(index)
                .ok_or(AsmError::Operand("differential BEAM label"))?,
            Target::Fragment(fragment) => {
                let address = module.ga_get(fragment)?;
                module.resolve_fragment(address)
            }
            Target::Lambda(index) => module.lambda_trampoline(index)?,
        };
        Ok((format!("__target_{index}"), label))
    }

    pub(crate) fn assert_matches(
        dump: &str,
        op: &str,
        choose: impl Fn(&[String]) -> bool,
        emit: impl Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>,
        rewrites: &[TargetRewrite],
        pointers: impl Fn(&BeamModuleAssembler) -> Vec<(&'static str, u64)>,
        lambdas: &[u32],
    ) {
        let mut block = full_op_blocks(dump, op)
            .into_iter()
            .find(|block| choose(block))
            .unwrap_or_else(|| panic!("no {op} block in +JDdump"));
        // +JDdump includes the following opcode's CP landing instruction for a few calls.
        // Keep the first instruction and its return-address alignment in this opcode's range.
        if let Some((first, _)) = block.iter().enumerate().find_map(|(index, line)| {
            if !line.starts_with("call ") && !line.starts_with("jmp ") {
                return None;
            }
            block
                .iter()
                .skip(index + 1)
                .rposition(|later| later == line)
                .map(|later| (index, later + index + 1))
        }) && block[first + 1..]
            .iter()
            .any(|line| line.starts_with("call ") || line.starts_with("jmp "))
        {
            block.truncate(first + 1);
        }
        let label_rewrites = rewrites
            .iter()
            .enumerate()
            .map(|(index, rewrite)| {
                let target = match rewrite.target {
                    Target::Fragment(fragment) => format!("global::{}", fragment.name()),
                    Target::Beam(_) | Target::Lambda(_) => format!("__target_{index}"),
                };
                (rewrite.source.to_owned(), target)
            })
            .collect::<Vec<_>>();
        let (ga, global_code) = {
            let mut ga = BeamGlobalAssembler::new(
                crate::common::process_offsets::ProcessOffsets::ERTS_X86_64,
            )
            .unwrap();
            for label in GLOBAL_LABELS {
                let target = ga.label(label);
                if ga.asm.a.label_location(target).is_none() {
                    ga.asm.align_code(8).unwrap();
                    ga.asm.bind(target).unwrap();
                    ga.asm.emit(|e| e.ud2()).unwrap();
                }
            }
            let code = ga.codegen().unwrap();
            (ga, code)
        };
        let addresses = ga.ptrs().to_vec();
        let mut matched = false;
        for prefix in 0..4 {
            let mut module = BeamModuleAssembler::with_fragment_addresses(16, addresses.clone());
            for index in lambdas {
                let trampoline = module.asm.new_label();
                module.lambdas.insert(
                    *index,
                    LambdaPatch {
                        patches: Vec::new(),
                        trampoline,
                    },
                );
            }
            for _ in 0..prefix {
                module.asm.emit(|e| e.nop()).unwrap();
            }
            emit(&mut module).unwrap_or_else(|error| panic!("{op} emission failed: {error:?}"));

            let pointer_rewrites = pointers(&module);
            let targets = rewrites
                .iter()
                .enumerate()
                .map(|(index, rewrite)| {
                    get_target(
                        &mut module,
                        index,
                        TargetRewrite {
                            source: rewrite.source,
                            target: rewrite.target,
                        },
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            for _ in 0..FAR_LABEL_PADDING {
                module.asm.emit(|e| e.nop()).unwrap();
            }
            for (_, label) in &targets {
                module.asm.bind(*label).unwrap();
            }
            let actual = module.asm.a.bytes(Section::Code).to_vec();

            let mut expected = Vec::new();
            expected.extend(std::iter::repeat_n("nop".to_owned(), prefix));
            let block_lines = rewrite_expected(&block, &label_rewrites, &pointer_rewrites);
            for line in block_lines {
                if line.contains("global::") {
                    expected.push(line.strip_prefix("long ").unwrap_or(&line).to_owned());
                } else if let Some(branch) = explicit_branch(&line) {
                    expected.extend(branch);
                } else if let Some(target) = line.strip_prefix("call ")
                    && target.parse::<u64>().is_ok()
                {
                    expected.push(".byte 0x40, 0xe8, 0, 0, 0, 0".to_owned());
                } else {
                    expected.push(line);
                }
            }
            expected.extend(std::iter::repeat_n("nop".to_owned(), FAR_LABEL_PADDING));
            expected.extend(
                targets
                    .iter()
                    .zip(rewrites)
                    .filter(|(_, rewrite)| !matches!(rewrite.target, Target::Fragment(_)))
                    .map(|((name, _), _)| format!("{name}:")),
            );
            let target_labels = targets
                .iter()
                .zip(rewrites)
                .filter(|(_, rewrite)| !matches!(rewrite.target, Target::Fragment(_)))
                .map(|((name, _), _)| format!("{name}:"))
                .collect::<Vec<_>>();
            align_reference_call(&mut expected, &target_labels);

            if matches_with_global_jumps(&expected, &actual, &[]) == Some(true) {
                matched = true;
                break;
            }
        }
        assert!(matched, "{op} bytes differ from +JDdump block: {block:#?}");
        let _ = global_code;
    }

    #[test]
    fn call_and_apply_emitters_match_erts_dump() {
        let calls = erts_dump("erl_internal").expect("erl_internal +JDdump");
        let c = erts_dump("c").expect("c +JDdump");
        let raw_file_io = erts_dump("raw_file_io").expect("raw_file_io +JDdump");
        let peer = erts_dump("peer").expect("peer +JDdump");
        let net_kernel = erts_dump("net_kernel").expect("net_kernel +JDdump");
        let file = erts_dump("file").expect("file +JDdump");
        let ordsets = erts_dump("ordsets").expect("ordsets +JDdump");
        let otp_internal = erts_dump("otp_internal").expect("otp_internal +JDdump");

        let no_targets = &[];
        let no_pointers = |_: &BeamModuleAssembler| Vec::new();
        assert_matches(
            &otp_internal,
            "return",
            |_| true,
            |m| m.emit_return(),
            &[TargetRewrite {
                source: "L195",
                target: Target::Fragment(GlobalLabels::DispatchReturn),
            }],
            no_pointers,
            &[],
        );
        assert_matches(
            &calls,
            "i_call_f",
            |_| true,
            |m| m.emit_i_call(ArgVal::Label(1)),
            &[TargetRewrite {
                source: "new_type_test/2",
                target: Target::Beam(1),
            }],
            no_pointers,
            &[],
        );
        assert_matches(
            &calls,
            "i_call_last_ft",
            |_| true,
            |m| m.emit_i_call_last(ArgVal::Label(1), ArgVal::Word(2)),
            &[TargetRewrite {
                source: "old_type_test/2",
                target: Target::Beam(1),
            }],
            no_pointers,
            &[],
        );
        assert_matches(
            &calls,
            "i_call_only_f",
            |_| true,
            |m| m.emit_i_call_only(ArgVal::Label(1)),
            &[TargetRewrite {
                source: "new_type_test/2",
                target: Target::Beam(1),
            }],
            no_pointers,
            &[],
        );
        assert_matches(
            &calls,
            "i_call_ext_e",
            |_| true,
            |m| m.emit_i_call_ext(ArgVal::Export(0)),
            no_targets,
            no_pointers,
            &[],
        );
        assert_matches(
            &ordsets,
            "i_call_ext_only_e",
            |_| true,
            |m| m.emit_i_call_ext_only(ArgVal::Export(0)),
            no_targets,
            no_pointers,
            &[],
        );
        assert_matches(
            &calls,
            "i_call_ext_last_et",
            |_| true,
            |m| m.emit_i_call_ext_last(ArgVal::Export(0), ArgVal::Word(0)),
            no_targets,
            no_pointers,
            &[],
        );

        let apply_mfa =
            |_: &BeamModuleAssembler| vec![("rcx", core::ptr::from_ref(&APPLY3_MFA) as u64)];
        assert_matches(
            &file,
            "apply_t",
            |block| block.iter().any(|line| line == "mov edx, 1"),
            |m| m.emit_apply(ArgVal::Word(1)),
            &[TargetRewrite {
                source: "L481",
                target: Target::Fragment(GlobalLabels::RaiseExceptionShared),
            }],
            apply_mfa,
            &[],
        );
        assert_matches(
            &raw_file_io,
            "apply_last_tt",
            |_| true,
            |m| m.emit_apply_last(ArgVal::Word(3), ArgVal::Word(2)),
            &[TargetRewrite {
                source: "L52",
                target: Target::Fragment(GlobalLabels::RaiseExceptionShared),
            }],
            apply_mfa,
            &[],
        );
        assert_matches(
            &c,
            "i_apply",
            |_| true,
            |m| m.emit_i_apply(),
            &[TargetRewrite {
                source: "L1059",
                target: Target::Fragment(GlobalLabels::RaiseExceptionShared),
            }],
            apply_mfa,
            &[],
        );
        assert_matches(
            &net_kernel,
            "i_apply_last_t",
            |_| true,
            |m| m.emit_i_apply_last(ArgVal::Word(3)),
            &[TargetRewrite {
                source: "L925",
                target: Target::Fragment(GlobalLabels::RaiseExceptionShared),
            }],
            apply_mfa,
            &[],
        );
        assert_matches(
            &peer,
            "i_apply_only",
            |_| true,
            |m| m.emit_i_apply_only(),
            &[TargetRewrite {
                source: "L715",
                target: Target::Fragment(GlobalLabels::RaiseExceptionShared),
            }],
            apply_mfa,
            &[],
        );
    }
}
