//! Port of erts/emulator/beam/jit/x86/instr_select.cpp, OTP-29.1.1.

use arinsal_term::Term;
use arinsal_x64::buf::Label;
use arinsal_x64::enc::{CondCode, Mem};

use super::beam_asm::{
    AsmError, Distance, emit_boxed_val,
    register::{ARG1, ARG2, ARG2D, RET},
};
use super::beam_asm_module::{BeamModuleAssembler, arg_label, arg_word};
use crate::common::args::ArgVal;
use crate::common::types::{BeamModuleAssemblerCommon, type_id};

const TAG_HEADER_MASK: i64 = 0x3f;
const TAG_IMMED1_MASK: i64 = 0x0f;
const TAG_IMMED1_SMALL: i64 = 0x0f;
const TAG_IMMED1_SIZE: u32 = 4;

impl BeamModuleAssembler {
    /// Emits `i_select_tuple_arity` over a tuple header and the arity/label pairs.
    // Port of erts/emulator/beam/jit/x86/instr_select.cpp:58-92 (emit_i_select_tuple_arity),
    // OTP-29.1.1.
    pub fn emit_i_select_tuple_arity(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let fail = arg_label(fail)?;
        let size = arg_word(size)? as usize;
        validate_size(size, args)?;
        let fail = self
            .resolve_beam_label(fail)
            .ok_or(AsmError::Operand("tuple arity select fail label"))?;

        self.mov_arg_to_reg(ARG2, src)?;
        if !self.always_one_of(src, type_id::ALWAYS_BOXED) {
            self.emit_is_boxed(fail, ARG2, Distance::Long)?;
        }

        let boxed_ptr = self.asm.emit_ptr_val(ARG2, ARG2);
        self.asm
            .emit(|e| e.mov_rm(ARG2D, emit_boxed_val(boxed_ptr, 0, 4)))?;

        if self.masked_types(src, type_id::MAYBE_BOXED) != type_id::TUPLE {
            self.asm.emit(|e| e.test_ri(ARG2.r8(), TAG_HEADER_MASK))?;
            self.asm.jcc(CondCode::NE, fail)?;
        }

        let count = args.len() / 2;
        for index in 0..count {
            let value = args[index];
            let label = self.resolve_arg_label(args[index + count])?;
            let ArgVal::Immediate(value) = value else {
                return Err(AsmError::Operand("tuple arity select value"));
            };
            self.asm.emit(|e| e.cmp_ri(ARG2D, value as i64))?;
            self.asm.jcc(CondCode::E, label)?;
        }
        self.asm.jcc(CondCode::NE, fail)
    }

    /// Emits `i_select_val_lins` and its shared linear search.
    // Port of erts/emulator/beam/jit/x86/instr_select.cpp:20-55, 94-104
    // (emit_linear_search, emit_i_select_val_lins), OTP-29.1.1.
    pub fn emit_i_select_val_lins(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let size = arg_word(size)? as usize;
        validate_size(size, args)?;
        self.mov_arg_to_reg(ARG2, src)?;
        let fail = self.resolve_optional_fail(fail)?;
        self.emit_linear_search(ARG2, fail, args)
    }

    /// Emits `i_select_val_bins` and its recursive binary-search tree.
    // Port of erts/emulator/beam/jit/x86/instr_select.cpp:106-197
    // (emit_i_select_val_bins, emit_binsearch_nodes), OTP-29.1.1.
    pub fn emit_i_select_val_bins(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let size = arg_word(size)? as usize;
        validate_size(size, args)?;
        let count = args.len() / 2;
        if count == 0 {
            return Err(AsmError::Operand("binary select needs at least one value"));
        }

        let (fail, fail_is_label) = match fail {
            ArgVal::Label(index) => (
                self.resolve_beam_label(index)
                    .ok_or(AsmError::Operand("binary select fail label"))?,
                true,
            ),
            ArgVal::Immediate(value) if value == Term::NIL.word() => (self.asm.new_label(), false),
            _ => return Err(AsmError::Operand("select fail must be label or nil")),
        };

        self.mov_arg_to_reg(ARG2, src)?;
        self.emit_binsearch_nodes(0, count - 1, fail, fail_is_label, args)?;
        if !fail_is_label {
            self.asm.bind(fail)?;
        }
        Ok(())
    }

    /// Emits an indexed jump through the label table of `i_jump_on_val`.
    // Port of erts/emulator/beam/jit/x86/instr_select.cpp:199-255 (emit_i_jump_on_val),
    // OTP-29.1.1.
    pub fn emit_i_jump_on_val(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        base: ArgVal,
        size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let base = arg_word(base)?;
        let size = arg_word(size)? as usize;
        if size != args.len() {
            return Err(AsmError::Operand("jump table size does not match labels"));
        }

        self.mov_arg_to_reg(ARG1, src)?;
        self.asm.emit(|e| e.mov_rr(RET.r32(), ARG1.r32()))?;
        self.asm.emit(|e| e.and_ri(RET.r8(), TAG_IMMED1_MASK))?;
        self.asm.emit(|e| e.cmp_ri(RET.r8(), TAG_IMMED1_SMALL))?;

        let fail_label = match fail {
            ArgVal::Label(index) => Some(
                self.resolve_beam_label(index)
                    .ok_or(AsmError::Operand("jump table fail label"))?,
            ),
            ArgVal::Immediate(value) if value == Term::NIL.word() => None,
            _ => return Err(AsmError::Operand("jump table fail must be label or nil")),
        };
        let fallthrough = fail_label.is_none().then(|| self.asm.new_label());
        if let Some(label) = fail_label {
            self.asm.jcc(CondCode::NE, label)?;
        } else if let Some(label) = fallthrough {
            self.asm.short_jcc(CondCode::NE, label)?;
        }

        self.asm
            .emit(|e| e.sar_ri(ARG1, i64::from(TAG_IMMED1_SIZE)))?;
        if base != 0 {
            if fits_i32(base as i64) {
                self.asm.emit(|e| e.sub_ri(ARG1, base as i64))?;
            } else {
                self.asm.mov_imm(ARG2, base)?;
                self.asm.emit(|e| e.sub_rr(ARG1, ARG2))?;
            }
        }

        self.asm.emit(|e| e.cmp_ri(ARG1, args.len() as i64))?;
        if let Some(label) = fail_label {
            self.asm.jcc(CondCode::AE, label)?;
        } else if let Some(label) = fallthrough {
            self.asm.short_jcc(CondCode::AE, label)?;
        }

        self.embed_vararg_rodata(args, RET, 0)?;
        self.asm
            .emit(|e| e.jmp_m(Mem::base_index(RET, ARG1, 3, 0, 8)))?;

        if let Some(label) = fallthrough {
            self.asm.bind(label)?;
        }
        Ok(())
    }

    // Port of erts/emulator/beam/jit/x86/instr_select.cpp:20-55, OTP-29.1.1.
    fn emit_linear_search(
        &mut self,
        comparand: arinsal_x64::enc::Gp,
        fail: Option<Label>,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let count = args.len() / 2;
        let mut index = 0;
        while index < count {
            let value = args[index];
            let label_value = args[index + count];

            if index < count - 1 && label_value == args[index + count + 1] {
                let destructive = index == count - 2;
                if self.emit_optimized_two_way_select(
                    destructive,
                    value,
                    args[index + 1],
                    label_value,
                )? {
                    index += 2;
                    continue;
                }
            }

            let label = self.resolve_arg_label(label_value)?;
            self.cmp_arg_reg(comparand, value, ARG1)?;
            self.asm.jcc(CondCode::E, label)?;
            index += 1;
        }

        self.emit_fail_branch(fail)
    }

    fn emit_fail_branch(&mut self, fail: Option<Label>) -> Result<(), AsmError> {
        if let Some(fail) = fail {
            self.asm.jmp(fail)
        } else {
            Ok(())
        }
    }

    // Port of erts/emulator/beam/jit/x86/instr_select.cpp:257-300, OTP-29.1.1.
    fn emit_optimized_two_way_select(
        &mut self,
        destructive: bool,
        value1: ArgVal,
        value2: ArgVal,
        label: ArgVal,
    ) -> Result<bool, AsmError> {
        let (ArgVal::Immediate(x), ArgVal::Immediate(y)) = (value1, value2) else {
            return Ok(false);
        };
        let combined = x | y;
        let diff = x ^ y;
        if diff & diff.wrapping_sub(1) != 0 {
            return Ok(false);
        }

        let target = self.resolve_arg_label(label)?;
        if destructive && fits_i32(diff as i64) {
            self.asm.emit(|e| e.or_ri(ARG2, diff as i64))?;
            self.cmp_arg_reg(ARG2, ArgVal::Immediate(combined), RET)?;
        } else {
            self.asm.mov_imm(RET, diff)?;
            self.asm.emit(|e| e.or_rr(RET, ARG2))?;
            self.cmp_arg_reg(RET, ArgVal::Immediate(combined), ARG1)?;
        }
        self.asm.jcc(CondCode::E, target)?;
        Ok(true)
    }

    // Port of erts/emulator/beam/jit/x86/instr_select.cpp:135-197, OTP-29.1.1.
    fn emit_binsearch_nodes(
        &mut self,
        left: usize,
        right: usize,
        fail: Label,
        fail_is_label: bool,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let count = args.len() / 2;
        if left > right || right >= count {
            return Err(AsmError::Operand("binary select interval"));
        }

        let mid = (left + right) >> 1;
        let mid_value = args[mid];
        let remaining = right - left + 1;

        if remaining <= 10 {
            let mut shrunk = Vec::with_capacity(remaining * 2);
            shrunk.extend_from_slice(&args[left..left + remaining]);
            shrunk.extend_from_slice(&args[count + left..count + left + remaining]);
            self.emit_linear_search(ARG2, fail_is_label.then_some(fail), &shrunk)?;
            return Ok(());
        }

        self.cmp_arg_reg(ARG2, mid_value, ARG1)?;
        if left == right {
            let label = self.resolve_arg_label(args[mid + count])?;
            self.asm.jcc(CondCode::E, label)?;
            self.asm.jmp(fail)?;
            return Ok(());
        }

        let equal = self.resolve_arg_label(args[mid + count])?;
        self.asm.jcc(CondCode::E, equal)?;

        if left == mid {
            self.asm.jcc(CondCode::B, fail)?;
        } else {
            let right_tree = self.asm.new_label();
            self.asm.jcc(CondCode::A, right_tree)?;
            self.emit_binsearch_nodes(left, mid - 1, fail, fail_is_label, args)?;
            self.asm.bind(right_tree)?;
        }

        self.emit_binsearch_nodes(mid + 1, right, fail, fail_is_label, args)
    }

    fn resolve_arg_label(&self, value: ArgVal) -> Result<Label, AsmError> {
        let ArgVal::Label(index) = value else {
            return Err(AsmError::Operand("select destination must be a label"));
        };
        self.resolve_beam_label(index)
            .ok_or(AsmError::Operand("unknown select destination label"))
    }

    fn resolve_optional_fail(&self, fail: ArgVal) -> Result<Option<Label>, AsmError> {
        match fail {
            ArgVal::Label(index) => self
                .resolve_beam_label(index)
                .map(Some)
                .ok_or(AsmError::Operand("select fail label")),
            ArgVal::Immediate(value) if value == Term::NIL.word() => Ok(None),
            _ => Err(AsmError::Operand("select fail must be label or nil")),
        }
    }
}

fn validate_size(size: usize, args: &[ArgVal]) -> Result<(), AsmError> {
    if size == args.len() && args.len().is_multiple_of(2) {
        Ok(())
    } else {
        Err(AsmError::Operand("select size does not match pair table"))
    }
}

fn fits_i32(value: i64) -> bool {
    value as i32 as i64 == value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::ArgType;
    use crate::x86::jdump::{beam_register, erts_dump, gnu_as, op_blocks};
    use arinsal_x64::buf::{RelocationKind, RelocationTarget, Section};

    const MODULES: [&str; 6] = [
        "edlin",
        "erl_scan",
        "edlin_key",
        "application",
        "file",
        "prim_inet",
    ];
    const FAR_LABEL_PADDING: usize = 200;

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
            if internal_label(trimmed) || line.starts_with(' ') || line.starts_with('\t') {
                block.push(trimmed.to_owned());
            } else {
                blocks.extend(current.take());
            }
        }
        blocks.extend(current);
        blocks
    }

    fn first_source(block: &[String]) -> Option<ArgVal> {
        let instruction = block.first()?;
        let (_, source) = instruction.strip_prefix("mov ")?.split_once(", ")?;
        beam_register(source)
    }

    fn parse_branch(line: &str) -> Option<(bool, &'static str, &str)> {
        let mut instruction = line;
        let short = if let Some(rest) = instruction.strip_prefix("short ") {
            instruction = rest;
            true
        } else {
            false
        };
        let (mnemonic, target) = instruction.split_once(' ')?;
        if !mnemonic.starts_with('j') {
            return None;
        }
        let code = match mnemonic {
            "jmp" => "jmp",
            "je" | "jz" => "e",
            "jne" | "jnz" => "ne",
            "jb" | "jc" | "jnae" => "b",
            "jae" | "jnb" | "jnc" => "ae",
            "ja" | "jnbe" => "a",
            _ => return None,
        };
        Some((short, code, target.trim()))
    }

    fn branch_directive(short: bool, code: &str, target: &str) -> [String; 2] {
        if code == "jmp" {
            if short {
                [".byte 0xeb".to_owned(), format!(".byte {target} - . - 1")]
            } else {
                [".byte 0xe9".to_owned(), format!(".long {target} - . - 4")]
            }
        } else {
            let nibble = match code {
                "b" => 2,
                "ae" => 3,
                "e" => 4,
                "ne" => 5,
                "a" => 7,
                _ => unreachable!(),
            };
            if short {
                [
                    format!(".byte 0x{:02x}", 0x70 + nibble),
                    format!(".byte {target} - . - 1"),
                ]
            } else {
                [
                    format!(".byte 0x0f, 0x{:02x}", 0x80 + nibble),
                    format!(".long {target} - . - 4"),
                ]
            }
        }
    }

    fn external_labels(lines: &[String]) -> Vec<u32> {
        let mut labels = std::collections::BTreeSet::new();
        for line in lines {
            if let Some((_, _, target)) = parse_branch(line)
                && let Some(index) = target
                    .strip_prefix("label_")
                    .and_then(|value| value.parse().ok())
            {
                labels.insert(index);
            }
        }
        labels.into_iter().collect()
    }

    fn expected_lines(block: &[String], targets: &[u32]) -> Vec<String> {
        let mut lines = Vec::with_capacity(block.len() + FAR_LABEL_PADDING + targets.len());
        for line in block {
            if let Some((short, code, target)) = parse_branch(line) {
                lines.extend(branch_directive(short, code, target));
            } else {
                lines.push(line.clone());
            }
        }
        lines.extend(std::iter::repeat_n("nop".to_owned(), FAR_LABEL_PADDING));
        lines.extend(targets.iter().map(|index| format!("label_{index}:")));
        lines
    }

    fn assemble_ours(
        emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>,
        target_ids: &[u32],
    ) -> Vec<u8> {
        let num_labels = target_ids.iter().copied().max().unwrap_or(0) + 1;
        let mut assembler = BeamModuleAssembler::new(num_labels.max(1));
        emit(&mut assembler).unwrap();
        for _ in 0..FAR_LABEL_PADDING {
            assembler.asm.emit(|e| e.nop()).unwrap();
        }
        for index in target_ids {
            let label = assembler.resolve_beam_label(*index).unwrap();
            assembler.asm.bind(label).unwrap();
        }
        assembler.asm.a.bytes(Section::Code).to_vec()
    }

    fn assert_block_matches_erts(
        block: &[String],
        emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), AsmError>,
    ) -> usize {
        let targets = external_labels(block);
        let expected = gnu_as(&expected_lines(block, &targets)).unwrap();
        assert_eq!(
            assemble_ours(emit, &targets),
            expected,
            "erts block: {block:#?}"
        );
        block.len()
    }

    fn parse_linear(block: &[String]) -> Option<(ArgVal, ArgVal, Vec<ArgVal>)> {
        let source = first_source(block)?;
        let mut pairs = Vec::new();
        let mut fail = ArgVal::Immediate(Term::NIL.word());
        let mut index = 1;
        while index < block.len() {
            if let Some(cmp) = block[index].strip_prefix("cmp ") {
                let (_, value) = cmp.split_once(", ")?;
                let value = value.parse::<u64>().ok()?;
                let (short, code, target) = parse_branch(block.get(index + 1)?)?;
                if code != "e" || short {
                    return None;
                }
                let label = target.strip_prefix("label_")?.parse::<u32>().ok()?;
                pairs.push((ArgVal::Immediate(value), ArgVal::Label(label)));
                index += 2;
            } else if let Some((short, code, target)) = parse_branch(&block[index]) {
                if short || code != "jmp" || index + 1 != block.len() {
                    return None;
                }
                fail = ArgVal::Label(target.strip_prefix("label_")?.parse().ok()?);
                index += 1;
            } else {
                return None;
            }
        }
        if pairs.is_empty() {
            return None;
        }
        let args = pairs
            .iter()
            .map(|(value, _)| *value)
            .chain(pairs.iter().map(|(_, label)| *label))
            .collect();
        Some((source, fail, args))
    }

    fn parse_binsearch(block: &[String]) -> Option<(ArgVal, ArgVal, Vec<ArgVal>)> {
        let source = first_source(block)?;
        let mut pairs = Vec::new();
        for index in 0..block.len().saturating_sub(1) {
            let Some(cmp) = block[index].strip_prefix("cmp ") else {
                continue;
            };
            let (_, value) = cmp.split_once(", ")?;
            let value = value.parse::<u64>().ok()?;
            let (_, code, target) = parse_branch(&block[index + 1])?;
            if code != "e" {
                return None;
            }
            let label = target.strip_prefix("label_")?.parse::<u32>().ok()?;

            let destructive_diff = index
                .checked_sub(1)
                .and_then(|at| block[at].strip_prefix("or rsi, "))
                .and_then(|diff| diff.parse::<u64>().ok());
            let register_diff = index
                .checked_sub(2)
                .and_then(|at| block[at].strip_prefix("mov eax, "))
                .and_then(|diff| diff.parse::<u64>().ok())
                .filter(|_| {
                    block
                        .get(index - 1)
                        .is_some_and(|line| line == "or rax, rsi")
                });
            if let Some(diff) = destructive_diff.or(register_diff) {
                pairs.push((value, label));
                pairs.push((value ^ diff, label));
            } else {
                pairs.push((value, label));
            }
        }
        pairs.sort_unstable_by_key(|(value, _)| *value);
        pairs.dedup_by_key(|(value, _)| *value);
        if pairs.len() < 11 {
            return None;
        }

        let destinations: std::collections::BTreeSet<u32> =
            pairs.iter().map(|(_, label)| *label).collect();
        let fail = block
            .iter()
            .filter_map(|line| parse_branch(line))
            .filter(|(_, code, target)| *code != "e" && !target.starts_with('L'))
            .find_map(|(_, _, target)| {
                let label = target.strip_prefix("label_")?.parse::<u32>().ok()?;
                (!destinations.contains(&label)).then_some(ArgVal::Label(label))
            })
            .unwrap_or(ArgVal::Immediate(Term::NIL.word()));

        let args = pairs
            .iter()
            .map(|(value, _)| ArgVal::Immediate(*value))
            .chain(pairs.iter().map(|(_, label)| ArgVal::Label(*label)))
            .collect();
        Some((source, fail, args))
    }

    fn parse_tuple(block: &[String]) -> Option<((ArgVal, ArgType), u32, Vec<ArgVal>)> {
        let source = first_source(block)?;
        let has_header_test = block.iter().any(|line| {
            line.trim_start_matches("rex ").starts_with("test ") && line.ends_with(", 63")
        });
        let has_box_test = block.iter().any(|line| {
            line.trim_start_matches("rex ").starts_with("test ") && line.ends_with(", 1")
        });
        let union = if !has_header_test {
            type_id::TUPLE
        } else if !has_box_test {
            type_id::ALWAYS_BOXED
        } else {
            type_id::ANY
        };
        let src = (
            source,
            ArgType {
                union_bits: union,
                ..ArgType::ANY
            },
        );

        let mut pairs = Vec::new();
        let mut fail = None;
        for index in 0..block.len().saturating_sub(1) {
            if let Some(cmp) = block[index].strip_prefix("cmp ") {
                let (_, value) = cmp.split_once(", ")?;
                let value = value.parse::<u64>().ok()?;
                let (_, code, target) = parse_branch(&block[index + 1])?;
                if code == "e" {
                    let label = target.strip_prefix("label_")?.parse::<u32>().ok()?;
                    pairs.push((ArgVal::Immediate(value), ArgVal::Label(label)));
                }
            }
            if let Some((_, code, target)) = parse_branch(&block[index])
                && code == "ne"
            {
                fail = Some(target.strip_prefix("label_")?.parse::<u32>().ok()?);
            }
        }
        Some((
            src,
            fail?,
            pairs
                .iter()
                .map(|(value, _)| *value)
                .chain(pairs.iter().map(|(_, label)| *label))
                .collect(),
        ))
    }

    fn parse_jump_table(
        dump: &str,
        block: &[String],
    ) -> Option<(ArgVal, u32, u64, usize, Vec<ArgVal>, String)> {
        if block
            .iter()
            .filter_map(|line| parse_branch(line))
            .any(|(short, _, _)| short)
        {
            return None;
        }
        let source = first_source(block)?;
        let fail = block
            .iter()
            .filter_map(|line| parse_branch(line))
            .find(|(_, code, _)| *code != "jmp")?
            .2
            .strip_prefix("label_")?
            .parse::<u32>()
            .ok()?;
        let base = if let Some(line) = block.iter().find(|line| line.starts_with("sub rdi, ")) {
            let rhs = line.strip_prefix("sub rdi, ")?;
            if let Ok(value) = rhs.parse::<u64>() {
                value
            } else {
                let register = rhs;
                block
                    .iter()
                    .take_while(|candidate| *candidate != line)
                    .find_map(|candidate| {
                        candidate
                            .strip_prefix(&format!("mov {register}, "))?
                            .parse::<u64>()
                            .ok()
                    })?
            }
        } else {
            0
        };
        let size = block
            .iter()
            .find_map(|line| line.strip_prefix("cmp rdi, "))?
            .parse::<usize>()
            .ok()?;
        let table = block
            .iter()
            .find_map(|line| line.strip_prefix("lea rax, qword ptr ["))?
            .strip_suffix(']')?
            .to_owned();
        let table_line = dump
            .lines()
            .position(|line| line.trim() == format!("{table}:"))?;
        let mut args = Vec::new();
        for line in dump.lines().skip(table_line + 1) {
            let line = line.trim();
            if line.starts_with(".section ") || line.starts_with('L') && line.ends_with(':') {
                break;
            }
            if let Some(label) = line.strip_prefix(".dq label_") {
                args.push(ArgVal::Label(label.parse().ok()?));
            }
        }
        (args.len() == size).then_some((source, fail, base, size, args, table))
    }

    fn expected_jump_lines(block: &[String], fail: u32, table: &str) -> Vec<String> {
        let mut lines = Vec::with_capacity(block.len() + FAR_LABEL_PADDING + 3);
        for line in block {
            if let Some((short, code, target)) = parse_branch(line) {
                lines.extend(branch_directive(short, code, target));
            } else if line.contains(&format!("[{table}]")) {
                lines.push(line.replace(&format!("[{table}]"), "[rip + jump_table]"));
            } else {
                lines.push(line.clone());
            }
        }
        lines.push("jmp qword ptr [rax+rdi*8]".to_owned());
        lines.extend(std::iter::repeat_n("nop".to_owned(), FAR_LABEL_PADDING));
        lines.push(format!("label_{fail}:"));
        lines.push(".balign 8".to_owned());
        lines.push("jump_table:".to_owned());
        lines
    }

    #[test]
    fn select_val_linear_blocks_match_erts_dumps() {
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
            for block in op_blocks(dump, "i_select_val_lins_sfI") {
                let Some((source, fail, args)) = parse_linear(&block) else {
                    continue;
                };
                compared += assert_block_matches_erts(&block, |m| {
                    m.emit_i_select_val_lins(source, fail, ArgVal::Word(args.len() as u64), &args)
                });
            }
        }
        eprintln!("compared {compared} linear-select dump lines");
        assert!(compared > 100, "compared only {compared} lines");
    }

    #[test]
    fn select_val_binary_blocks_match_erts_dumps() {
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
            for block in blocks_with_internal_labels(dump, "i_select_val_bins_sfI") {
                let Some((source, fail, args)) = parse_binsearch(&block) else {
                    continue;
                };
                compared += assert_block_matches_erts(&block, |m| {
                    m.emit_i_select_val_bins(source, fail, ArgVal::Word(args.len() as u64), &args)
                });
            }
        }
        eprintln!("compared {compared} binary-select dump lines");
        assert!(compared > 100, "compared only {compared} lines");
    }

    #[test]
    fn select_tuple_arity_blocks_match_erts_dumps() {
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
            for block in op_blocks(dump, "i_select_tuple_arity_SfI") {
                // `BeamAssembler::jcc` has no post-bind relaxation; keep byte comparisons to
                // the erts near-branch form represented by unprefixed label branches.
                if block.iter().any(|line| line.starts_with("short ")) {
                    continue;
                }
                let Some((source, fail, args)) = parse_tuple(&block) else {
                    continue;
                };
                compared += assert_block_matches_erts(&block, |m| {
                    let source = m.typed_arg(source.0, source.1);
                    m.emit_i_select_tuple_arity(
                        source,
                        ArgVal::Label(fail),
                        ArgVal::Word(args.len() as u64),
                        &args,
                    )
                });
            }
        }
        eprintln!("compared {compared} tuple-arity-select dump lines");
        assert!(compared > 100, "compared only {compared} lines");
    }

    #[test]
    fn jump_on_val_blocks_match_erts_dump() {
        const JUMP_MODULES: [&str; 7] = [
            "erl_scan",
            "erl_parse",
            "unicode",
            "erl_eval",
            "logger_formatter",
            "prim_inet",
            "rand",
        ];
        let dumps = JUMP_MODULES
            .iter()
            .map(|module| erts_dump(module))
            .collect::<Option<Vec<_>>>();
        let Some(dumps) = dumps else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let (mut compared, mut covered_nonzero_base) = (0, false);
        for dump in &dumps {
            for block in op_blocks(dump, "i_jump_on_val_sfWI") {
                let Some((source, fail, base, size, args, table)) = parse_jump_table(dump, &block)
                else {
                    continue;
                };
                let target_ids: Vec<u32> = args
                    .iter()
                    .map(|arg| match arg {
                        ArgVal::Label(index) => *index,
                        _ => unreachable!("table entry must be a label"),
                    })
                    .collect();
                let label_count = target_ids.iter().copied().chain([fail]).max().unwrap_or(0) + 1;
                let mut assembler = BeamModuleAssembler::new(label_count);
                assembler
                    .emit_i_jump_on_val(
                        source,
                        ArgVal::Label(fail),
                        ArgVal::Word(base),
                        ArgVal::Word(size as u64),
                        &args,
                    )
                    .unwrap();
                for _ in 0..FAR_LABEL_PADDING {
                    assembler.asm.emit(|e| e.nop()).unwrap();
                }
                let mut bound = std::collections::BTreeSet::new();
                bound.insert(fail);
                bound.extend(target_ids.iter().copied());
                for target in bound {
                    let label = assembler.resolve_beam_label(target).unwrap();
                    if assembler.asm.a.label_location(label).is_none() {
                        assembler.asm.bind(label).unwrap();
                    }
                }
                let finalized = assembler.asm.a.clone().finish().unwrap();
                let expected = gnu_as(&expected_jump_lines(&block, fail, &table)).unwrap();
                assert_eq!(
                    &finalized.code,
                    &expected[..finalized.code.len()],
                    "erts block: {block:#?}"
                );
                assert_eq!(finalized.data, vec![0; args.len() * 8]);
                let relocation_targets: Vec<_> = finalized
                    .relocations
                    .iter()
                    .filter_map(|relocation| match relocation.kind {
                        RelocationKind::Absolute64 {
                            target: RelocationTarget::Label(label),
                            ..
                        } => Some(label),
                        _ => None,
                    })
                    .collect();
                let expected_targets: Vec<_> = target_ids
                    .iter()
                    .map(|target| assembler.resolve_beam_label(*target).unwrap())
                    .collect();
                assert_eq!(relocation_targets, expected_targets);
                compared += 1;
                covered_nonzero_base |= base != 0;
            }
        }
        assert!(compared >= 4, "compared only {compared} jump-table blocks");
        assert!(covered_nonzero_base, "no nonzero table base compared");
    }
}
