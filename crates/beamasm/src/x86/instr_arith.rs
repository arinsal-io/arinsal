//! Non-runtime arithmetic tag-test helpers from erts/emulator/beam/jit/x86/instr_arith.cpp.
//! The arithmetic entry points that need shared runtime fragments remain unported as whole functions.

use arinsal_x64::buf::Label;
use arinsal_x64::enc::Gp;

use super::beam_asm::AsmError;
use super::beam_asm::register::{ARG1, ARG1D, RET, RETB, RETD};
use super::beam_asm_module::BeamModuleAssembler;
use crate::common::types::{TypedArg, type_id};

const TAG_PRIMARY_LIST: i64 = 1;
const TAG_IMMED1_MASK: i64 = 0x0f;
const TAG_IMMED1_SMALL: i64 = 0x0f;

impl BeamModuleAssembler {
    /// Emits the small-integer test used by arithmetic fast paths.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:39-60 (emit_is_small), OTP-29.1.1.
    pub fn emit_is_small(&mut self, fail: Label, arg: TypedArg, reg: Gp) -> Result<(), AsmError> {
        assert_ne!(ARG1, reg);

        if arg.always_small() {
            // The type range proves the check.
        } else if arg.always_one_of(type_id::NUMBER) {
            self.asm.emit(|e| e.test_ri(reg.r8(), TAG_PRIMARY_LIST))?;
            self.asm.short_jcc(arinsal_x64::enc::CondCode::E, fail)?;
        } else {
            self.asm.emit(|e| e.mov_rr(ARG1D, reg.r32()))?;
            self.asm.emit(|e| e.and_ri(ARG1D, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(ARG1D, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
        }
        Ok(())
    }

    /// Emits a single small-integer test for two arithmetic operands.
    // Port of erts/emulator/beam/jit/x86/instr_arith.cpp:62-121
    // (emit_are_both_small), OTP-29.1.1.
    pub fn emit_are_both_small(
        &mut self,
        fail: Label,
        lhs: TypedArg,
        a: Gp,
        rhs: TypedArg,
        b: Gp,
    ) -> Result<(), AsmError> {
        assert_ne!(ARG1, a);
        assert_ne!(ARG1, b);

        if lhs.always_small() && rhs.always_small() {
            return Ok(());
        }

        if lhs.always_one_of(type_id::NUMBER) && rhs.always_one_of(type_id::NUMBER) {
            if rhs.always_small() {
                self.asm.emit(|e| e.test_ri(a.r8(), TAG_PRIMARY_LIST))?;
            } else if lhs.always_small() {
                self.asm.emit(|e| e.test_ri(b.r8(), TAG_PRIMARY_LIST))?;
            } else if a != RET && b != RET {
                self.asm.emit(|e| e.mov_rr(RETD, a.r32()))?;
                self.asm.emit(|e| e.and_rr(RETD, b.r32()))?;
                self.asm.emit(|e| e.test_ri(RETB, TAG_PRIMARY_LIST))?;
            } else {
                self.asm.emit(|e| e.mov_rr(ARG1D, a.r32()))?;
                self.asm.emit(|e| e.and_rr(ARG1D, b.r32()))?;
                self.asm.emit(|e| e.test_ri(ARG1.r8(), TAG_PRIMARY_LIST))?;
            }
            self.asm.short_jcc(arinsal_x64::enc::CondCode::E, fail)?;
        } else if lhs.always_small() {
            if a == RET || b == RET {
                self.emit_is_small(fail, rhs, b)?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, b.r32()))?;
                self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
            }
        } else if rhs.always_small() {
            if a == RET || b == RET {
                self.emit_is_small(fail, lhs, a)?;
            } else {
                self.asm.emit(|e| e.mov_rr(RETD, a.r32()))?;
                self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
                self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
                self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
            }
        } else if a != RET && b != RET {
            self.asm.emit(|e| e.mov_rr(RETD, a.r32()))?;
            self.asm.emit(|e| e.and_rr(RETD, b.r32()))?;
            self.asm.emit(|e| e.and_ri(RETB, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(RETB, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
        } else {
            self.asm.emit(|e| e.mov_rr(ARG1D, a.r32()))?;
            self.asm.emit(|e| e.and_rr(ARG1D, b.r32()))?;
            self.asm.emit(|e| e.and_ri(ARG1D, TAG_IMMED1_MASK))?;
            self.asm.emit(|e| e.cmp_ri(ARG1D, TAG_IMMED1_SMALL))?;
            self.asm.short_jcc(arinsal_x64::enc::CondCode::NE, fail)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_x64::buf::Section;

    use crate::common::types::ArgType;
    use crate::x86::beam_asm::register::{ARG2, ARG3};
    use crate::x86::jdump::{erts_dump, gnu_as};

    const MODULES: [&str; 5] = ["edlin", "erl_prim_loader", "ets", "file", "inet_parse"];

    fn internal_label(line: &str) -> bool {
        let Some(name) = line.strip_suffix(':').and_then(|s| s.strip_prefix('L')) else {
            return false;
        };
        !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
    }

    fn blocks_with_internal_labels(dump: &str, op: &str) -> Vec<Vec<String>> {
        let mut blocks = Vec::new();
        let mut current: Option<Vec<String>> = None;
        for line in dump.lines() {
            if let Some(header) = line.strip_prefix("# ")
                && !header.is_empty()
                && header
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                blocks.extend(current.take());
                if header == op {
                    current = Some(Vec::new());
                }
                continue;
            }
            let Some(block) = current.as_mut() else {
                continue;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() || line.starts_with('#') {
                continue;
            }
            if internal_label(trimmed) || line.starts_with([' ', '\t']) {
                block.push(trimmed.to_owned());
            } else {
                blocks.extend(current.take());
            }
        }
        blocks.extend(current);
        blocks
    }

    fn branch_target(line: &str) -> Option<&str> {
        let line = line.strip_prefix("short ").unwrap_or(line);
        let (instruction, target) = line.split_once(' ')?;
        instruction.starts_with('j').then_some(target.trim())
    }

    fn call_target(line: &str) -> Option<&str> {
        line.strip_prefix("call ").map(str::trim)
    }

    fn branch_code(line: &str) -> Option<(bool, u8, &str)> {
        let (short, line) = match line.strip_prefix("short ") {
            Some(line) => (true, line),
            None => (false, line),
        };
        let (instruction, target) = line.split_once(' ')?;
        let code = match instruction {
            "jo" => 0,
            "jno" => 1,
            "jb" | "jc" | "jnae" => 2,
            "jae" | "jnb" | "jnc" => 3,
            "je" | "jz" => 4,
            "jne" | "jnz" => 5,
            "jbe" | "jna" => 6,
            "ja" | "jnbe" => 7,
            "js" => 8,
            "jns" => 9,
            "jp" | "jpe" => 10,
            "jnp" | "jpo" => 11,
            "jl" | "jnge" => 12,
            "jge" | "jnl" => 13,
            "jle" | "jng" => 14,
            "jg" | "jnle" => 15,
            "jmp" => 0xff,
            _ => return None,
        };
        Some((short, code, target.trim()))
    }

    fn asm_lines(block: &[String]) -> Vec<String> {
        let mut lines = Vec::with_capacity(block.len());
        for line in block {
            if let Some((short, code, target)) = branch_code(line) {
                match (code, short) {
                    (0xff, true) => {
                        lines.push(".byte 0xeb".to_owned());
                        lines.push(format!(".byte {target} - . - 1"));
                    }
                    (0xff, false) => {
                        lines.push(".byte 0xe9".to_owned());
                        lines.push(format!(".long {target} - . - 4"));
                    }
                    (code, true) => {
                        lines.push(format!(".byte 0x{:02x}", 0x70 + code));
                        lines.push(format!(".byte {target} - . - 1"));
                    }
                    (code, false) => {
                        lines.push(format!(".byte 0x0f, 0x{:02x}", 0x80 + code));
                        lines.push(format!(".long {target} - . - 4"));
                    }
                }
            } else if let Some(target) = call_target(line) {
                lines.push(".byte 0xe8".to_owned());
                lines.push(format!(".long {target} - . - 4"));
            } else {
                lines.push(line.clone());
            }
        }
        lines
    }

    fn verify_helper_prefix(
        block: &[String],
        helper_start: usize,
        emit: impl FnOnce(&mut BeamModuleAssembler, Label) -> Result<(), AsmError>,
    ) -> bool {
        let Some(branch) = block.get(helper_start..).and_then(|tail| {
            tail.iter()
                .position(|line| branch_target(line).is_some())
                .map(|offset| helper_start + offset)
        }) else {
            return false;
        };
        let Some(target) = branch_target(&block[branch]) else {
            return false;
        };
        let Some(label_offset) = block.iter().position(|line| line == &format!("{target}:")) else {
            return false;
        };
        let target_block = &block[..=label_offset];
        let Some(prefix_bytes) = gnu_as(&asm_lines(&block[..helper_start])) else {
            return false;
        };
        let mut expected_lines = asm_lines(target_block);
        let mut external_labels = std::collections::BTreeSet::new();
        for line in target_block {
            let Some(target) = call_target(line).or_else(|| branch_target(line)) else {
                continue;
            };
            if !target_block
                .iter()
                .any(|line| line == &format!("{target}:"))
            {
                external_labels.insert(target);
            }
        }
        expected_lines.extend(
            external_labels
                .into_iter()
                .map(|target| format!("{target}:")),
        );
        let Some(expected) = gnu_as(&expected_lines) else {
            return false;
        };

        let mut assembler = BeamModuleAssembler::new(1);
        let fail = assembler.asm.new_label();
        if emit(&mut assembler, fail).is_err() {
            return false;
        }
        let helper_len = assembler.asm.a.offset();
        let displacement = expected[prefix_bytes.len() + helper_len - 1] as i8 as isize;
        let target_offset = helper_len as isize + displacement;
        if target_offset < helper_len as isize {
            return false;
        }
        for _ in 0..(target_offset as usize - helper_len) {
            if assembler.asm.emit(|e| e.nop()).is_err() {
                return false;
            }
        }
        if assembler.asm.bind(fail).is_err() {
            return false;
        }

        assembler.asm.a.bytes(Section::Code)[..helper_len]
            == expected[prefix_bytes.len()..prefix_bytes.len() + helper_len]
    }

    fn any_arg() -> TypedArg {
        TypedArg::new(
            crate::common::args::ArgVal::X(0),
            ArgType {
                union_bits: type_id::ANY,
                min: None,
                max: None,
            },
        )
    }

    fn number_arg() -> TypedArg {
        TypedArg::new(
            crate::common::args::ArgVal::X(0),
            ArgType {
                union_bits: type_id::NUMBER,
                min: None,
                max: None,
            },
        )
    }

    #[test]
    fn is_small_matches_erts_i_bsr_blocks() {
        let Some(dumps) = MODULES
            .iter()
            .map(|module| erts_dump(module))
            .collect::<Option<Vec<_>>>()
        else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let mut compared = 0;
        for dump in &dumps {
            for block in blocks_with_internal_labels(dump, "i_bsr_ssjd") {
                let Some(start) = block
                    .windows(3)
                    .position(|window| window == ["mov edi, esi", "and edi, 15", "cmp edi, 15"])
                else {
                    continue;
                };
                if !verify_helper_prefix(&block, start, |assembler, fail| {
                    assembler.emit_is_small(fail, any_arg(), ARG2)
                }) {
                    panic!("i_bsr small test differs: {block:#?}");
                }
                compared += 1;
            }
        }
        assert!(compared > 0, "no generic small-tag checks compared");
    }

    #[test]
    fn are_both_small_matches_erts_i_plus_blocks() {
        let Some(dumps) = MODULES
            .iter()
            .map(|module| erts_dump(module))
            .collect::<Option<Vec<_>>>()
        else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let mut compared = 0;
        for dump in &dumps {
            for block in blocks_with_internal_labels(dump, "i_plus_ssjd") {
                let Some(start) = block
                    .windows(3)
                    .position(|window| window == ["mov eax, esi", "and eax, edx", "test al, 1"])
                else {
                    continue;
                };
                if !verify_helper_prefix(&block, start, |assembler, fail| {
                    assembler.emit_are_both_small(fail, number_arg(), ARG2, number_arg(), ARG3)
                }) {
                    panic!("i_plus pair small test differs: {block:#?}");
                }
                compared += 1;
            }
        }
        assert!(compared > 0, "no pair small-tag checks compared");
    }
}
