//! Inline BeamAsm select instructions and indexed branch tables.

use arinsal_a64::{
    buf::Label,
    enc::{Cond, Gpr, Shift},
};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::types::{TypedArg, type_id};

const TMP0: Gpr = Gpr::x(8);
const TMP1: Gpr = Gpr::x(9);
const TMP2: Gpr = Gpr::x(10);
const TMP3: Gpr = Gpr::x(11);
const ARG1: Gpr = Gpr::x(0);
/// Whether `i_select_val_bins` untags and rebases its values, as erts does
/// (instr_select.cpp `emit_i_select_val_bins`).
const BINS_UNTAG: bool = true;
const SMALL_TAG: u64 = 0x0f;
const SMALL_MASK: u64 = 0x0f;
const SMALL_SHIFT: u8 = 4;

impl BeamModuleAssembler {
    fn emit_compare(&mut self, reg: Gpr, value: ArgVal) -> Result<(), ModuleError> {
        match value {
            ArgVal::Immediate(value) | ArgVal::Literal(value) => {
                if value <= 4095 {
                    self.code.emit(|e| e.cmp_imm(reg, value as u16, false))?;
                } else if value.wrapping_neg() <= 4095 {
                    // Rebased values below the base wrap around; `cmn` keeps the unsigned
                    // `hs`/`lo` meaning of `cmp`.
                    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp (cmp_arg/cmp), OTP-29.1.1.
                    self.code
                        .emit(|e| e.cmn_imm(reg, value.wrapping_neg() as u16, false))?;
                } else {
                    self.code.emit(|e| e.mov_const(TMP3, value))?;
                    self.code.emit(|e| e.cmp_reg(reg, TMP3, Shift::Lsl, 0))?;
                }
            }
            _ => {
                let rhs = self.source_reg(value)?;
                self.code.emit(|e| e.cmp_reg(reg, rhs, Shift::Lsl, 0))?;
            }
        }
        Ok(())
    }

    fn branch_cond(&mut self, cond: Cond, id: u32) -> Result<(), ModuleError> {
        let target = self.label(id);
        self.code.b_cond(cond, target)?;
        Ok(())
    }

    fn branch_fail(&mut self, fail: ArgVal, fallthrough: Label) -> Result<(), ModuleError> {
        match fail {
            ArgVal::Label(id) => {
                let target = self.label(id);
                self.code.b(target)?;
            }
            ArgVal::Immediate(0 | 0x3b) | ArgVal::Literal(0 | 0x3b) => self.code.b(fallthrough)?,
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "select fail must be label or nil",
                ));
            }
        }
        Ok(())
    }

    fn validate_pairs(size: usize, args: &[ArgVal]) -> Result<usize, ModuleError> {
        if !size.is_multiple_of(2) || size != args.len() {
            return Err(ModuleError::InvalidOperand(
                "select size does not match pair table",
            ));
        }
        Ok(size / 2)
    }

    /// Emits BeamAsm's linear search, including its contiguous run and two-way shortcuts.
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp (emit_i_select_val_lins), OTP-29.1.1
    pub fn emit_i_select_val_lins(
        &mut self,
        src: impl Into<TypedArg>,
        fail: ArgVal,
        size: usize,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        let src = src.into();
        let count = Self::validate_pairs(size, args)?;
        if count >= 128 {
            return Err(ModuleError::InvalidOperand(
                "linear select has 128 or more values",
            ));
        }
        // With a nil fail the search falls through; `next` follows the search so the tag
        // test of the untagged form can skip it.
        let (fail_label, next) = match fail {
            ArgVal::Label(id) => {
                let label = self.label(id);
                (Some(label), label)
            }
            _ => {
                let label = self.code.new_label();
                self.branch_fail_check(fail)?;
                (None, label)
            }
        };
        let reg = self.source_reg_into(src.val, ARG1)?;
        let (base, shift) = plan_untag(&select_values(&args[..count]));
        if base == 0 && shift == 0 {
            self.emit_linear_search(reg, fail_label, args)?;
        } else {
            let untagged =
                self.emit_select_untag(reg, &src, &args[..count], args, next, base, shift)?;
            self.emit_linear_search(ARG1, fail_label, &untagged)?;
        }
        if fail_label.is_none() {
            self.code.bind(next)?;
        }
        Ok(())
    }

    fn branch_fail_check(&self, fail: ArgVal) -> Result<(), ModuleError> {
        if is_nil(fail) {
            Ok(())
        } else {
            Err(ModuleError::InvalidOperand(
                "select fail must be label or nil",
            ))
        }
    }

    /// Emits the type test and rebasing of `emit_select_untag` and returns the rewritten
    /// value and label vector (values sorted again when a base is applied).
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp (emit_select_untag), OTP-29.1.1
    #[allow(clippy::too_many_arguments)]
    fn emit_select_untag(
        &mut self,
        comparand: Gpr,
        src: &TypedArg,
        values: &[ArgVal],
        args: &[ArgVal],
        fail: Label,
        base: u64,
        shift: u32,
    ) -> Result<Vec<ArgVal>, ModuleError> {
        let count = values.len();
        let first = select_values(values)[0];
        let (mask, tag) = if first & 0xf == 0xf {
            (0xfu64, 0xfu16)
        } else {
            (0x3f, 0xb)
        };
        // The compiler's type for the source can prove the tag already.
        let known = if tag == 0xf {
            src.always_small()
        } else {
            src.exact_type(type_id::ATOM)
        };
        if !known {
            self.code.emit(|e| e.and_imm(TMP1, comparand, mask))?;
            self.code.emit(|e| e.cmp_imm(TMP1, tag, false))?;
            self.code.b_cond(Cond::Ne, fail)?;
        }
        let mut comparand = comparand;
        let mut base = base;
        if shift != 0 {
            self.code
                .emit(|e| e.lsr_imm(ARG1, comparand, shift as u8))?;
            base >>= shift;
            comparand = ARG1;
        }
        let raw = select_values(values);
        let mut entries: Vec<(u64, ArgVal)> = (0..count)
            .map(|i| ((raw[i] >> shift).wrapping_sub(base), args[i + count]))
            .collect();
        if base != 0 {
            if base <= 4095 {
                self.code
                    .emit(|e| e.sub_imm(ARG1, comparand, base as u16, false))?;
            } else if base < (1 << 24) {
                // erts' `sub(ARG1, comparand, base)`: two immediate subtractions.
                let (low, high) = ((base & 0xfff) as u16, (base >> 12) as u16);
                let mut from = comparand;
                if low != 0 {
                    self.code.emit(|e| e.sub_imm(ARG1, from, low, false))?;
                    from = ARG1;
                }
                self.code.emit(|e| e.sub_imm(ARG1, from, high, true))?;
            } else {
                self.code.emit(|e| e.mov_const(TMP0, base))?;
                self.code
                    .emit(|e| e.sub_reg(ARG1, comparand, TMP0, Shift::Lsl, 0))?;
            }
            // The order changes after rebasing: values below the base wrap to large words.
            entries.sort_by_key(|(value, _)| *value);
        }
        let mut result = Vec::with_capacity(count * 2);
        result.extend(entries.iter().map(|(value, _)| ArgVal::Immediate(*value)));
        result.extend(entries.iter().map(|(_, label)| *label));
        Ok(result)
    }

    /// Linear search over `args` (values then labels). `fail` is the branch after the
    /// last test; `None` falls through.
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp (emit_linear_search), OTP-29.1.1
    fn emit_linear_search(
        &mut self,
        reg: Gpr,
        fail: Option<Label>,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_select.cpp:199-205 (emit_linear_search),
        // OTP-29.1.1: keep the branch stubs in range before emitting the search.
        self.check_pending_stubs()?;
        let count = args.len() / 2;
        let mut i = 0;
        while i < count {
            let value = args[i];
            let target = args[i + count];
            let ArgVal::Label(target_id) = target else {
                return Err(ModuleError::InvalidOperand(
                    "select destinations must be labels",
                ));
            };
            let mut end = i + 1;
            while end < count && args[end + count] == target {
                end += 1;
            }
            let mut run = 1;
            while i + run < end {
                let previous = match args[i + run - 1] {
                    ArgVal::Immediate(v) | ArgVal::Literal(v) => v,
                    _ => break,
                };
                let current = match args[i + run] {
                    ArgVal::Immediate(v) | ArgVal::Literal(v) => v,
                    _ => break,
                };
                if previous.checked_add(1) != Some(current) {
                    break;
                }
                run += 1;
            }
            if run > 2 {
                let first = match value {
                    ArgVal::Immediate(v) | ArgVal::Literal(v) => v,
                    _ => {
                        return Err(ModuleError::InvalidOperand(
                            "contiguous select values must be words",
                        ));
                    }
                };
                if first == 0 {
                    self.code.emit(|e| e.cmp_imm(reg, run as u16, false))?;
                } else {
                    self.code.emit(|e| e.mov_const(TMP0, first))?;
                    self.code
                        .emit(|e| e.sub_reg(TMP0, reg, TMP0, Shift::Lsl, 0))?;
                    self.code.emit(|e| e.cmp_imm(TMP0, run as u16, false))?;
                }
                self.branch_cond(Cond::Cc, target_id)?;
                i += run;
            } else if end - i >= 2 {
                self.emit_two_way(reg, value, args[i + 1], target_id)?;
                i += 2;
            } else {
                self.emit_compare(reg, value)?;
                self.branch_cond(Cond::Eq, target_id)?;
                i += 1;
            }
        }
        if let Some(fail) = fail {
            self.code.b(fail)?;
        }
        Ok(())
    }

    fn emit_two_way(
        &mut self,
        reg: Gpr,
        first: ArgVal,
        second: ArgVal,
        target: u32,
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_select.cpp:533-582, OTP-29.1.1
        let x = match first {
            ArgVal::Immediate(v) | ArgVal::Literal(v) => v,
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "two-value select needs constants",
                ));
            }
        };
        let y = match second {
            ArgVal::Immediate(v) | ArgVal::Literal(v) => v,
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "two-value select needs constants",
                ));
            }
        };
        let diff = x ^ y;
        if x.checked_add(1) == Some(y) {
            if x == 0 {
                self.code.emit(|e| e.cmp_imm(reg, 2, false))?;
            } else {
                self.code.emit(|e| e.mov_const(TMP0, x))?;
                self.code
                    .emit(|e| e.sub_reg(TMP0, reg, TMP0, Shift::Lsl, 0))?;
                self.code.emit(|e| e.cmp_imm(TMP0, 2, false))?;
            }
            self.branch_cond(Cond::Cc, target)
        } else if diff != 0 && diff & (diff - 1) == 0 {
            self.code.emit(|e| e.mov_const(TMP0, diff))?;
            self.code.emit(|e| {
                e.orr_reg(
                    TMP0,
                    reg,
                    arinsal_a64::enc::Shifted {
                        reg: TMP0,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?;
            self.emit_compare(TMP0, ArgVal::Immediate(x | y))?;
            self.branch_cond(Cond::Eq, target)
        } else {
            if x < 32 {
                self.emit_compare(reg, second)?;
                self.code.emit(|e| e.ccmp_imm(reg, x as u8, 4, Cond::Ne))?;
            } else if y.wrapping_neg() < 32 {
                self.emit_compare(reg, first)?;
                self.code
                    .emit(|e| e.ccmn_imm(reg, y.wrapping_neg() as u8, 4, Cond::Ne))?;
            } else {
                self.emit_compare(reg, first)?;
                self.code.emit(|e| e.mov_const(TMP0, y))?;
                self.code.emit(|e| e.ccmp_reg(reg, TMP0, 4, Cond::Ne))?;
            }
            self.branch_cond(Cond::Eq, target)
        }
    }

    /// Emits the binary search tree, switching to linear search at ten entries.
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp (emit_i_select_val_bins,
    // emit_binsearch_nodes), OTP-29.1.1
    pub fn emit_i_select_val_bins(
        &mut self,
        src: impl Into<TypedArg>,
        fail: ArgVal,
        size: usize,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.select_val_bins(src.into(), fail, size, args, BINS_UNTAG)
    }

    /// [`Self::emit_i_select_val_bins`] with the untag + rebase plan forced on.
    pub fn emit_i_select_val_bins_untagged(
        &mut self,
        src: impl Into<TypedArg>,
        fail: ArgVal,
        size: usize,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.select_val_bins(src.into(), fail, size, args, true)
    }

    fn select_val_bins(
        &mut self,
        src: TypedArg,
        fail: ArgVal,
        size: usize,
        args: &[ArgVal],
        untag: bool,
    ) -> Result<(), ModuleError> {
        let count = Self::validate_pairs(size, args)?;
        if count == 0 {
            let done = self.code.new_label();
            self.branch_fail(fail, done)?;
            self.code.bind(done)?;
            return Ok(());
        }
        let reg = self.source_reg_into(src.val, ARG1)?;
        let fail_label = self.fail_label(fail)?;
        let sorted = sorted_select_pairs(count, args)?;
        let (base, shift) = if untag {
            plan_untag(&select_values(&sorted[..count]))
        } else {
            (0, 0)
        };
        if base == 0 && shift == 0 {
            self.binsearch(reg, 0, count, &sorted, fail_label)?;
        } else {
            let untagged = self.emit_select_untag(
                reg,
                &src,
                &sorted[..count],
                &sorted,
                fail_label,
                base,
                shift,
            )?;
            self.binsearch(ARG1, 0, count, &untagged, fail_label)?;
        }
        if is_nil(fail) {
            self.code.bind(fail_label)?;
        }
        Ok(())
    }

    fn fail_label(&mut self, fail: ArgVal) -> Result<Label, ModuleError> {
        match fail {
            ArgVal::Label(id) => Ok(self.label(id)),
            ArgVal::Immediate(0 | 0x3b) | ArgVal::Literal(0 | 0x3b) => Ok(self.code.new_label()),
            _ => Err(ModuleError::InvalidOperand(
                "select fail must be label or nil",
            )),
        }
    }

    fn binsearch(
        &mut self,
        reg: Gpr,
        left: usize,
        right: usize,
        args: &[ArgVal],
        fail: Label,
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_select.cpp (emit_binsearch_nodes), OTP-29.1.1
        let count = args.len() / 2;
        let remaining = right - left;
        if remaining <= 10 {
            // The leaf is a linear search with the run and two-way shortcuts.
            let mut shrunk = Vec::with_capacity(remaining * 2);
            shrunk.extend_from_slice(&args[left..right]);
            shrunk.extend_from_slice(&args[left + count..right + count]);
            return self.emit_linear_search(reg, Some(fail), &shrunk);
        }
        // Port of erts/emulator/beam/jit/arm/instr_select.cpp:386-425 (emit_binsearch_nodes),
        // OTP-29.1.1: flush veneers before emitting another subtree's branches.
        self.check_pending_stubs()?;
        let mid = (left + right) / 2;
        let ArgVal::Label(target) = args[mid + count] else {
            return Err(ModuleError::InvalidOperand(
                "select destinations must be labels",
            ));
        };
        self.emit_compare(reg, args[mid])?;
        self.branch_cond(Cond::Eq, target)?;
        let right_tree = self.code.new_label();
        self.code.b_cond(Cond::Cs, right_tree)?;
        self.binsearch(reg, left, mid, args, fail)?;
        self.code.bind(right_tree)?;
        self.binsearch(reg, mid + 1, right, args, fail)
    }

    /// Emits the specialized two-value select with optional fail fallthrough.
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp:533-582, OTP-29.1.1
    pub fn emit_i_select_val2(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        first: ArgVal,
        first_label: ArgVal,
        second: ArgVal,
        second_label: ArgVal,
    ) -> Result<(), ModuleError> {
        let reg = self.source_reg(src)?;
        let ArgVal::Label(first_id) = first_label else {
            return Err(ModuleError::InvalidOperand(
                "select destination must be label",
            ));
        };
        let ArgVal::Label(second_id) = second_label else {
            return Err(ModuleError::InvalidOperand(
                "select destination must be label",
            ));
        };
        if first_label == second_label {
            self.emit_two_way(reg, first, second, first_id)?;
        } else {
            self.emit_compare(reg, first)?;
            self.branch_cond(Cond::Eq, first_id)?;
            self.emit_compare(reg, second)?;
            self.branch_cond(Cond::Eq, second_id)?;
        }
        let done = self.code.new_label();
        self.branch_fail(fail, done)?;
        self.code.bind(done)?;
        Ok(())
    }

    /// Emits tuple validation followed by the sorted arity search.
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp:258-281, OTP-29.1.1
    pub fn emit_i_select_tuple_arity(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        size: usize,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.emit_tuple_arity(src, fail, size, args)
    }

    /// Emits the two-entry tuple-arity specialization.
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp:258-281, OTP-29.1.1
    pub fn emit_i_select_tuple_arity2(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        first: ArgVal,
        first_label: ArgVal,
        second: ArgVal,
        second_label: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_tuple_arity(src, fail, 4, &[first, second, first_label, second_label])
    }

    fn emit_tuple_arity(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        size: usize,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_select.cpp:258-281, OTP-29.1.1
        let count = Self::validate_pairs(size, args)?;
        let fallthrough = is_nil(fail);
        let fail = self.fail_label(fail)?;
        let reg = self.source_reg(src)?;
        self.code.emit(|e| e.and_imm(TMP0, reg, 3))?;
        self.code.emit(|e| e.cmp_imm(TMP0, 2, false))?;
        self.code.b_cond(Cond::Ne, fail)?;
        self.code.emit(|e| e.and_imm(TMP0, reg, !7))?;
        self.code.emit(|e| e.ldr_uoff(TMP1, TMP0, 0))?;
        self.code.emit(|e| e.and_imm(TMP2, TMP1, 0x3f))?;
        self.code.emit(|e| e.cmp_imm(TMP2, 0, false))?;
        self.code.b_cond(Cond::Ne, fail)?;
        self.code.emit(|e| e.lsr_imm(TMP1, TMP1, 6))?;
        let pairs = [args[..count].to_vec(), args[count..].to_vec()].concat();
        for (value, label) in pairs[..count].iter().zip(&pairs[count..]) {
            let ArgVal::Label(id) = label else {
                return Err(ModuleError::InvalidOperand(
                    "tuple arity destinations must be labels",
                ));
            };
            self.emit_compare(TMP1, *value)?;
            self.branch_cond(Cond::Eq, *id)?;
        }
        self.code.b(fail)?;
        if fallthrough {
            self.code.bind(fail)?;
        }
        Ok(())
    }

    /// Emits a table indexed by an untagged small integer with a nonzero base.
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp:448-518, OTP-29.1.1
    pub fn emit_i_jump_on_val(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        base: u64,
        size: usize,
        targets: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.emit_jump_table(src, fail, base, size, targets)
    }

    /// Emits a zero-based table indexed by an untagged small integer.
    // Port of erts/emulator/beam/jit/arm/instr_select.cpp:448-518, OTP-29.1.1
    pub fn emit_i_jump_on_val_zero(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        size: usize,
        targets: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.emit_jump_table(src, fail, 0, size, targets)
    }

    fn emit_jump_table(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        base: u64,
        size: usize,
        targets: &[ArgVal],
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_select.cpp:448-518, OTP-29.1.1
        if size == 0 || targets.len() != size {
            return Err(ModuleError::InvalidOperand(
                "jump table size does not match destinations",
            ));
        }
        let reg = self.source_reg(src)?;
        let fallthrough = is_nil(fail);
        let fail = self.fail_label(fail)?;
        self.code.emit(|e| e.and_imm(TMP0, reg, SMALL_MASK))?;
        self.code
            .emit(|e| e.cmp_imm(TMP0, SMALL_TAG as u16, false))?;
        self.code.b_cond(Cond::Ne, fail)?;
        self.code.emit(|e| e.asr_imm(TMP1, reg, SMALL_SHIFT))?;
        if base != 0 {
            self.code.emit(|e| e.mov_const(TMP2, base))?;
            self.code
                .emit(|e| e.sub_reg(TMP1, TMP1, TMP2, Shift::Lsl, 0))?;
        }
        if size <= 4095 {
            self.code.emit(|e| e.cmp_imm(TMP1, size as u16, false))?;
        } else {
            self.code.emit(|e| e.mov_const(TMP2, size as u64))?;
            self.code.emit(|e| e.cmp_reg(TMP1, TMP2, Shift::Lsl, 0))?;
        }
        self.code.b_cond(Cond::Cs, fail)?;
        let table = self.code.new_label();
        self.code.adr(TMP2, table)?;
        self.code
            .emit(|e| e.add_reg(TMP2, TMP2, TMP1, Shift::Lsl, 2))?;
        self.code.emit(|e| e.br(TMP2))?;
        self.code.bind(table)?;
        for target in targets {
            let ArgVal::Label(id) = target else {
                return Err(ModuleError::InvalidOperand(
                    "jump table destinations must be labels",
                ));
            };
            let label = self.label(*id);
            self.code.b(label)?;
        }
        if fallthrough {
            self.code.bind(fail)?;
        }
        Ok(())
    }
}

/// Raw words of a value vector; non-word operands map to a value that disables untagging.
fn select_values(values: &[ArgVal]) -> Vec<u64> {
    values
        .iter()
        .map(|value| match value {
            ArgVal::Immediate(v) | ArgVal::Literal(v) => *v,
            _ => 0,
        })
        .collect()
}

/// `isInt13`: fits the 12-bit immediate of `cmp` or, negated, of `cmn`.
fn is_int13(value: u64) -> bool {
    value < 4096 || (value as i64).wrapping_neg() as u64 <= 4095
}

/// Finds the base and shift that let the most comparisons use immediate operands, or
/// `(0, 0)` when untagging does not pay off.
// Port of erts/emulator/beam/jit/arm/instr_select.cpp (plan_untag), OTP-29.1.1
fn plan_untag(values: &[u64]) -> (u64, u32) {
    let count = values.len();
    if count == 0 {
        return (0, 0);
    }
    let shift = if values[0] & 0xf == 0xf {
        4
    } else if values[0] & 0x3f == 0xb {
        6
    } else {
        return (0, 0);
    };
    let tag_ok = |v: u64| {
        if shift == 4 {
            v & 0xf == 0xf
        } else {
            v & 0x3f == 0xb
        }
    };
    if !values.iter().all(|v| tag_ok(*v)) {
        return (0, 0);
    }
    let (mut left, mut right) = (0usize, 0usize);
    let (mut best_left, mut best_right) = (0usize, 0usize);
    while right < count {
        let distance = right - left;
        let left_value = values[left] >> shift;
        let mid_value = values[left + distance / 2] >> shift;
        let right_value = values[right] >> shift;
        if is_int13(left_value.wrapping_sub(mid_value))
            && is_int13(right_value.wrapping_sub(mid_value))
        {
            if distance > best_right - best_left {
                best_right = right;
                best_left = left;
            }
            right += 1;
        } else {
            left += 1;
        }
    }
    let distance = best_right - best_left;
    // A short run does not pay for the untagging.
    if distance <= 6 {
        return (0, 0);
    }
    if is_int13(values[best_left]) && is_int13(values[best_right]) {
        return (0, 0);
    }
    if is_int13(values[best_left] >> shift) && is_int13(values[best_right] >> shift) {
        return (0, shift);
    }
    (values[best_left + distance / 2], shift)
}

fn sorted_select_pairs(count: usize, args: &[ArgVal]) -> Result<Vec<ArgVal>, ModuleError> {
    let mut pairs = (0..count)
        .map(|index| {
            let raw = match args[index] {
                ArgVal::Immediate(value) | ArgVal::Literal(value) => value,
                _ => {
                    return Err(ModuleError::InvalidOperand(
                        "binary select values must be constants",
                    ));
                }
            };
            Ok((raw, args[index], args[index + count]))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Port of erts/emulator/beam/beam_transform_helpers.c:135-155
    // (beam_load_sort_select_vals/oparg_compare), OTP-29.1.1.
    pairs.sort_by_key(|(raw, _, _)| *raw);
    let mut sorted = Vec::with_capacity(args.len());
    sorted.extend(pairs.iter().map(|(_, value, _)| *value));
    sorted.extend(pairs.iter().map(|(_, _, target)| *target));
    Ok(sorted)
}

fn is_nil(value: ArgVal) -> bool {
    matches!(
        value,
        ArgVal::Immediate(0 | 0x3b) | ArgVal::Literal(0 | 0x3b)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_term::{Term, global_atoms};

    #[test]
    fn binary_select_orders_atoms_by_raw_term_word() {
        let atoms = global_atoms();
        let zzz = Term::atom(atoms.intern("zzx2a_select_crash").unwrap()).tagged_word();
        let aaa = Term::atom(atoms.intern("aax2a_select_crash").unwrap()).tagged_word();
        assert!(zzz < aaa, "fixture must reverse atom literal order");

        let args = [
            ArgVal::Literal(aaa),
            ArgVal::Literal(zzz),
            ArgVal::Label(10),
            ArgVal::Label(20),
        ];
        assert_eq!(
            sorted_select_pairs(2, &args).unwrap(),
            [
                ArgVal::Literal(zzz),
                ArgVal::Literal(aaa),
                ArgVal::Label(20),
                ArgVal::Label(10),
            ]
        );
    }
}
