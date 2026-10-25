//! Relational and loose-equality guard tests: the fast path stays inline, everything else is a
//! call to the process-wide `arith_compare_shared` fragment, which leaves the relation in the
//! flags.

use arinsal_a64::{
    buf::Label,
    enc::{Cond, Gpr, Shift, Shifted},
};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::types::{TypedArg, type_id};

const ARG1: Gpr = Gpr::x(0);
const ARG2: Gpr = Gpr::x(1);
const TMP1: Gpr = Gpr::x(8);
const TMP2: Gpr = Gpr::x(9);
const SUPER_TMP: Gpr = Gpr::x(17);
const TAG_IMMED1_MASK: u64 = 0xf;
const TAG_IMMED1_SMALL: u16 = 0xf;
const TAG_PRIMARY_MASK: u64 = 0x3;
const TAG_HEADER_MASK: u64 = 0x3c;
const TAG_HEADER_POS_BIG: u16 = 0x08;
const NEG_BIG_BIT: u8 = 2;

impl BeamModuleAssembler {
    /// Whether the process-wide `arith_compare_shared` fragment is installed.
    pub(crate) fn has_arith_compare_shared(&self) -> bool {
        self.arith_compare_shared != 0
    }

    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp (emit_is_boxed), OTP-29.1.1:
    // branches when the value is not boxed.
    fn emit_is_boxed(&mut self, label: Label, reg: Gpr) -> Result<(), ModuleError> {
        self.preserve_cache(&[], |this| Ok(this.code.tbnz(reg, 0, label)?))
    }

    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp (emit_is_not_boxed), OTP-29.1.1:
    // branches when the value is boxed.
    fn emit_is_not_boxed(&mut self, label: Label, reg: Gpr) -> Result<(), ModuleError> {
        self.preserve_cache(&[], |this| Ok(this.code.tbz(reg, 0, label)?))
    }

    fn mov_var(&mut self, dst: Gpr, src: Gpr) -> Result<(), ModuleError> {
        if dst != src {
            self.code.emit(|e| e.mov_reg(dst, src))?;
        }
        Ok(())
    }

    fn cmp_regs(&mut self, lhs: Gpr, rhs: Gpr) -> Result<(), ModuleError> {
        self.code.emit(|e| e.cmp_reg(lhs, rhs, Shift::Lsl, 0))?;
        Ok(())
    }

    fn call_arith_compare(&mut self, lhs: Gpr, rhs: Gpr) -> Result<(), ModuleError> {
        self.mov_var(ARG1, lhs)?;
        self.mov_var(ARG2, rhs)?;
        let target = self.arith_compare_shared;
        self.fragment_call(target)
    }

    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp (emit_are_both_immediate),
    // OTP-29.1.1: sets Z when both registers hold immediates.
    fn emit_are_both_immediate(
        &mut self,
        lhs: &TypedArg,
        lhs_reg: Gpr,
        rhs: &TypedArg,
        rhs_reg: Gpr,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            if lhs.always_immediate() {
                e.and_imm(SUPER_TMP, rhs_reg, TAG_PRIMARY_MASK)?;
            } else if rhs.always_immediate() {
                e.and_imm(SUPER_TMP, lhs_reg, TAG_PRIMARY_MASK)?;
            } else {
                e.and_reg(
                    SUPER_TMP,
                    lhs_reg,
                    Shifted {
                        reg: rhs_reg,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )?;
                e.and_imm(SUPER_TMP, SUPER_TMP, TAG_PRIMARY_MASK)?;
            }
            e.cmp_imm(SUPER_TMP, TAG_PRIMARY_MASK as u16, false)
        })?;
        Ok(())
    }

    fn cons_or_boxed(arg: &TypedArg) -> bool {
        arg.always_one_of(type_id::CONS | type_id::ALWAYS_BOXED)
    }

    /// Emits `is_eq` (`==`).
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_eq), OTP-29.1.1.
    pub(crate) fn emit_is_eq_shared(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_loose_equality(lhs, rhs, fail, false)
    }

    /// Emits `is_ne` (`/=`).
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_ne), OTP-29.1.1.
    pub(crate) fn emit_is_ne_shared(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_loose_equality(lhs, rhs, fail, true)
    }

    fn emit_loose_equality(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        fail: u32,
        fail_on_equal: bool,
    ) -> Result<(), ModuleError> {
        let next = self.code.new_label();
        let fail_label = self.label(fail);
        let (x, y) = self.load_two_sources(lhs.val, ARG1, rhs.val, ARG2)?;
        self.cmp_regs(x, y)?;
        self.code
            .b_cond(Cond::Eq, if fail_on_equal { fail_label } else { next })?;
        if !Self::cons_or_boxed(&lhs) {
            self.emit_are_both_immediate(&lhs, x, &rhs, y)?;
            self.code
                .b_cond(Cond::Eq, if fail_on_equal { next } else { fail_label })?;
        }
        self.call_arith_compare(x, y)?;
        self.code
            .b_cond(if fail_on_equal { Cond::Eq } else { Cond::Ne }, fail_label)?;
        self.code.bind(next)?;
        Ok(())
    }

    /// Emits `is_lt`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_lt), OTP-29.1.1.
    pub(crate) fn emit_is_lt_shared(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        let (l, r) = self.load_two_sources(lhs.val, ARG1, rhs.val, ARG2)?;
        let integer = type_id::INTEGER;
        let int_or_boxed = type_id::INTEGER | type_id::ALWAYS_BOXED;
        if lhs.always_small() && rhs.always_small() {
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Ge, fail_label)?;
        } else if lhs.always_small() && rhs.exact_type(integer) && rhs.ty.min.is_some() {
            let next = self.code.new_label();
            self.emit_is_not_boxed(next, r)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Ge, fail_label)?;
            self.code.bind(next)?;
        } else if lhs.always_small() && rhs.exact_type(integer) && rhs.ty.max.is_some() {
            self.emit_is_not_boxed(fail_label, r)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Ge, fail_label)?;
        } else if lhs.exact_type(integer) && lhs.ty.min.is_some() && rhs.always_small() {
            self.emit_is_not_boxed(fail_label, l)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Ge, fail_label)?;
        } else if lhs.exact_type(integer) && lhs.ty.max.is_some() && rhs.always_small() {
            let next = self.code.new_label();
            self.emit_is_not_boxed(next, l)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Ge, fail_label)?;
            self.code.bind(next)?;
        } else if lhs.is_literal() || rhs.is_literal() {
            let next = self.code.new_label();
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Eq, next)?;
            self.call_arith_compare(l, r)?;
            self.code.bind(next)?;
            self.code.b_cond(Cond::Ge, fail_label)?;
        } else if lhs.always_one_of(int_or_boxed) && rhs.always_one_of(int_or_boxed) {
            self.emit_small_or_shared(&lhs, l, &rhs, r)?;
            self.code.b_cond(Cond::Ge, fail_label)?;
        } else {
            self.emit_small_or_generic(&lhs, l, &rhs, r)?;
            self.code.b_cond(Cond::Ge, fail_label)?;
        }
        Ok(())
    }

    // The "all other types are boxed" branch shared by is_lt and is_ge: the flags come from
    // the inline compare or from the shared fragment.
    fn emit_small_or_shared(
        &mut self,
        lhs: &TypedArg,
        l: Gpr,
        rhs: &TypedArg,
        r: Gpr,
    ) -> Result<(), ModuleError> {
        let branch_compare = self.code.new_label();
        self.cmp_regs(l, r)?;
        if lhs.always_small() {
            self.emit_is_boxed(branch_compare, r)?;
        } else if rhs.always_small() {
            self.emit_is_boxed(branch_compare, l)?;
        } else {
            self.code.emit(|e| {
                e.and_reg(
                    TMP1,
                    l,
                    Shifted {
                        reg: r,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )
            })?;
            self.emit_is_boxed(branch_compare, TMP1)?;
        }
        self.call_arith_compare(l, r)?;
        self.code.bind(branch_compare)?;
        Ok(())
    }

    // The final branch of is_lt and is_ge: small operands are compared inline, the rest goes
    // to the shared fragment. The flags are left for the caller's conditional branch.
    fn emit_small_or_generic(
        &mut self,
        lhs: &TypedArg,
        l: Gpr,
        rhs: &TypedArg,
        r: Gpr,
    ) -> Result<(), ModuleError> {
        let generic = self.code.new_label();
        let next = self.code.new_label();
        if rhs.always_small() {
            self.code.emit(|e| e.and_imm(TMP1, l, TAG_IMMED1_MASK))?;
        } else if lhs.always_small() {
            self.code.emit(|e| e.and_imm(TMP1, r, TAG_IMMED1_MASK))?;
        } else {
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Eq, next)?;
            self.code.emit(|e| {
                e.and_reg(
                    TMP1,
                    l,
                    Shifted {
                        reg: r,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                )?;
                e.and_imm(TMP1, TMP1, TAG_IMMED1_MASK)
            })?;
        }
        self.code
            .emit(|e| e.cmp_imm(TMP1, TAG_IMMED1_SMALL, false))?;
        self.code.b_cond(Cond::Ne, generic)?;
        self.cmp_regs(l, r)?;
        self.code.b(next)?;
        self.code.bind(generic)?;
        self.call_arith_compare(l, r)?;
        self.code.bind(next)?;
        Ok(())
    }

    /// Emits `is_ge`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_ge), OTP-29.1.1.
    pub(crate) fn emit_is_ge_shared(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        if lhs.always_small() && rhs.is_small() && rhs.is_immed() {
            let l = self.source_reg_into(lhs.val, ARG1)?;
            self.cmp_arg(l, rhs.val)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
            return Ok(());
        } else if lhs.is_small() && lhs.is_immed() && rhs.always_small() {
            let r = self.source_reg_into(rhs.val, ARG1)?;
            self.cmp_arg(r, lhs.val)?;
            self.code.b_cond(Cond::Gt, fail_label)?;
            return Ok(());
        }
        let (l, r) = self.load_two_sources(lhs.val, ARG1, rhs.val, ARG2)?;
        let integer = type_id::INTEGER;
        let int_or_boxed = type_id::INTEGER | type_id::ALWAYS_BOXED;
        if lhs.always_small() && rhs.always_small() {
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
        } else if lhs.always_small() && rhs.exact_type(integer) && rhs.ty.min.is_some() {
            self.emit_is_not_boxed(fail_label, r)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
        } else if lhs.always_small() && rhs.exact_type(integer) && rhs.ty.max.is_some() {
            let next = self.code.new_label();
            self.emit_is_not_boxed(next, r)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
            self.code.bind(next)?;
        } else if lhs.exact_type(integer) && lhs.ty.max.is_some() && rhs.always_small() {
            self.emit_is_not_boxed(fail_label, l)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
        } else if lhs.exact_type(integer) && lhs.ty.min.is_some() && rhs.always_small() {
            let next = self.code.new_label();
            self.emit_is_not_boxed(next, l)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
            self.code.bind(next)?;
        } else if lhs.exact_type(integer) && rhs.always_small() {
            let big = self.code.new_label();
            let next = self.code.new_label();
            self.emit_is_not_boxed(big, l)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Ge, next)?;
            self.code.b(fail_label)?;
            self.code.bind(big)?;
            self.code.emit(|e| e.ldur(TMP1, l, -2))?;
            self.code.tbnz(TMP1, NEG_BIG_BIT, fail_label)?;
            self.code.bind(next)?;
        } else if lhs.always_small() && rhs.exact_type(integer) {
            let big = self.code.new_label();
            let next = self.code.new_label();
            self.emit_is_not_boxed(big, r)?;
            self.cmp_regs(l, r)?;
            self.code.b_cond(Cond::Ge, next)?;
            self.code.b(fail_label)?;
            self.code.bind(big)?;
            self.code.emit(|e| e.ldur(TMP1, r, -2))?;
            self.code.tbz(TMP1, NEG_BIG_BIT, fail_label)?;
            self.code.bind(next)?;
        } else if lhs.is_literal() || rhs.is_literal() {
            self.call_arith_compare(l, r)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
        } else if lhs.always_one_of(int_or_boxed) && rhs.always_one_of(int_or_boxed) {
            self.emit_small_or_shared(&lhs, l, &rhs, r)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
        } else {
            self.emit_small_or_generic(&lhs, l, &rhs, r)?;
            self.code.b_cond(Cond::Lt, fail_label)?;
        }
        Ok(())
    }

    /// Emits `is_int_ge`: fails unless the source is an integer not below `min`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_int_ge),
    // OTP-29.1.1.
    pub(crate) fn emit_is_int_ge_shared(
        &mut self,
        src: TypedArg,
        min: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        let source = self.source_reg_into(src.val, ARG1)?;
        let small = self.code.new_label();
        let next = self.code.new_label();
        if src.always_one_of(type_id::INTEGER | type_id::ALWAYS_BOXED) {
            if !src.always_boxed() {
                self.emit_is_boxed(small, source)?;
            }
        } else {
            self.preserve_cache(&[TMP2], |this| {
                this.code.emit(|e| {
                    e.and_imm(TMP2, source, TAG_IMMED1_MASK)?;
                    e.cmp_imm(TMP2, TAG_IMMED1_SMALL, false)
                })?;
                this.code.b_cond(Cond::Eq, small)?;
                Ok(())
            })?;
            if !src.always_boxed() {
                self.emit_is_boxed(fail_label, TMP2)?;
            }
        }
        self.preserve_cache(&[TMP1], |this| {
            this.code.emit(|e| {
                e.ldur(TMP1, source, -2)?;
                e.and_imm(TMP1, TMP1, TAG_HEADER_MASK)?;
                e.cmp_imm(TMP1, TAG_HEADER_POS_BIG, false)
            })?;
            this.code.b_cond(Cond::Ne, fail_label)?;
            this.code.b(next)?;
            this.code.bind(small)?;
            this.cmp_arg(source, min)?;
            this.code.b_cond(Cond::Lt, fail_label)?;
            this.code.bind(next)?;
            Ok(())
        })
    }

    /// Emits `is_int_in_range`: fails unless the source is a small integer in `min..=max`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_int_in_range), OTP-29.1.1.
    pub(crate) fn emit_is_int_in_range_shared(
        &mut self,
        src: TypedArg,
        min: ArgVal,
        max: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let (ArgVal::Immediate(min), ArgVal::Immediate(max)) = (min, max) else {
            return Err(ModuleError::InvalidOperand(
                "range bounds must be immediates",
            ));
        };
        let fail_label = self.label(fail);
        let source = self.source_reg_into(src.val, ARG1)?;
        self.preserve_cache(&[TMP1], |this| {
            this.sub_signed(TMP1, source, min as i64)?;
            this.code.emit(|e| e.tst_imm(TMP1, TAG_IMMED1_MASK))?;
            this.code.b_cond(Cond::Ne, fail_label)?;
            this.cmp_signed(TMP1, max.wrapping_sub(min) as i64)?;
            this.code.b_cond(Cond::Hi, fail_label)?;
            Ok(())
        })
    }

    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp (sub), OTP-29.1.1.
    fn sub_signed(&mut self, dst: Gpr, src: Gpr, value: i64) -> Result<(), ModuleError> {
        if (0..=4095).contains(&value) {
            self.code
                .emit(|e| e.sub_imm(dst, src, value as u16, false))?;
        } else if (-4095..0).contains(&value) {
            self.code
                .emit(|e| e.add_imm(dst, src, (-value) as u16, false))?;
        } else {
            self.mov_value(SUPER_TMP, false, value as u64)?;
            self.code
                .emit(|e| e.sub_reg(dst, src, SUPER_TMP, Shift::Lsl, 0))?;
        }
        Ok(())
    }

    // The module's shared `element/2` error raisers: `from_guard` first restores the arguments
    // the guard fragment copied to x2 and x3.
    fn element_error_labels(&mut self) -> (Label, Label) {
        if let Some(labels) = self.element_error {
            return labels;
        }
        let labels = (self.code.new_label(), self.code.new_label());
        self.element_error = Some(labels);
        labels
    }

    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_handle_element_error_shared),
    // OTP-29.1.1: raises `badarg` with erlang:element/2 as the top frame and the position and
    // tuple as the arguments. The return address of the calling `bl` names the source line.
    pub(crate) fn emit_element_error_stubs(
        &mut self,
        from_guard: Label,
        direct: Label,
    ) -> Result<(), ModuleError> {
        let badarg = arinsal_term::Term::atom(
            arinsal_term::global_atoms()
                .intern("badarg")
                .map_err(|_| ModuleError::InvalidOperand("badarg atom"))?,
        )
        .tagged_word();
        self.code.bind(from_guard)?;
        self.code.emit(|e| {
            e.mov_reg(ARG1, Gpr::x(2))?;
            e.mov_reg(ARG2, Gpr::x(3))
        })?;
        self.code.bind(direct)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(25), ARG1)?;
            e.mov_reg(Gpr::x(26), ARG2)
        })?;
        self.set_badarg_mfa(0)?;
        self.code.emit(|e| {
            e.mov_const(TMP2, crate::exc::EXC_BADARG)?;
            e.str_uoff(TMP2, Gpr::x(21), 40)?;
            e.mov_const(TMP2, badarg)?;
            e.str_uoff(TMP2, Gpr::x(21), 48)
        })?;
        self.branch_error_from_lr()
    }

    /// Emits `element/2` with the position test and tuple walk in the shared guard fragment.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_bif_element), OTP-29.1.1.
    pub(crate) fn emit_bif_element_shared(
        &mut self,
        fail: u32,
        pos: TypedArg,
        tuple: TypedArg,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        let (from_guard, direct) = self.element_error_labels();
        let max_arity = (1_i64 << 58) - 1;
        let const_position =
            pos.is_small() && pos.small_value() > 0 && pos.small_value() <= max_arity;
        if const_position {
            let position = pos.small_value() as u64;
            let tuple_reg = self.source_reg_into(tuple.val, ARG2)?;
            let output = self.guard_destination(destination)?;
            let local_fail = self.code.new_label();
            let good = self.code.new_label();
            if tuple.exact_type(type_id::TUPLE) {
                self.code.emit(|e| e.ldur(TMP2, tuple_reg, -2))?;
                self.cmp_signed(TMP2, (position << 6) as i64)?;
            } else {
                if fail != 0 {
                    let fail_label = self.label(fail);
                    self.emit_is_boxed(fail_label, tuple_reg)?;
                } else {
                    self.emit_is_boxed(local_fail, tuple_reg)?;
                }
                self.code.emit(|e| {
                    e.ldur(TMP2, tuple_reg, -2)?;
                    e.mov_const(Gpr::x(10), position << 6)?;
                    e.tst_imm(TMP2, 0x3f)?;
                    e.ccmp_reg(TMP2, Gpr::x(10), 0, Cond::Eq)
                })?;
            }
            if fail != 0 {
                let fail_label = self.label(fail);
                self.code.b_cond(Cond::Cc, fail_label)?;
                self.code.bind(local_fail)?;
            } else {
                self.code.b_cond(Cond::Cs, good)?;
                self.code.bind(local_fail)?;
                self.mov_arg_to_reg(ARG1, pos.val)?;
                self.mov_var(ARG2, tuple_reg)?;
                self.code.bl(direct)?;
                self.code.bind(good)?;
            }
            let offset = (position << 3) as i64 - 2;
            if (-256..256).contains(&offset) {
                self.code
                    .emit(|e| e.ldur(output, tuple_reg, offset as i16))?;
            } else {
                self.code.emit(|e| {
                    e.mov_const(SUPER_TMP, offset as u64)?;
                    e.ldr_regoff(output, tuple_reg, SUPER_TMP, 0)
                })?;
            }
            return self.store_guard_result(destination, output);
        }
        if tuple.exact_type(type_id::TUPLE) && fail == 0 {
            let (p, t) = self.load_two_sources(pos.val, ARG1, tuple.val, ARG2)?;
            let output = self.guard_destination(destination)?;
            let bad = self.code.new_label();
            let good = self.code.new_label();
            self.code.emit(|e| {
                e.sub_imm(TMP1, t, 2, false)?;
                e.ldr_uoff(TMP2, TMP1, 0)
            })?;
            if pos.always_one_of(type_id::INTEGER | type_id::ALWAYS_BOXED) {
                self.code.emit(|e| {
                    e.tst_imm(p, 1)?;
                    e.ccmp_imm(p, 0xf, 0b0100, Cond::Ne)
                })?;
            } else {
                self.code.emit(|e| {
                    e.and_imm(Gpr::x(10), p, TAG_IMMED1_MASK)?;
                    e.cmp_imm(Gpr::x(10), TAG_IMMED1_SMALL, false)?;
                    e.ccmp_imm(p, 0xf, 0b0100, Cond::Eq)
                })?;
            }
            self.code.b_cond(Cond::Eq, bad)?;
            self.code.emit(|e| {
                e.asr_imm(Gpr::x(10), p, 4)?;
                e.cmp_reg(Gpr::x(10), TMP2, Shift::Lsr, 6)
            })?;
            self.code.b_cond(Cond::Ls, good)?;
            self.code.bind(bad)?;
            self.mov_var(ARG1, p)?;
            self.mov_var(ARG2, t)?;
            self.code.bl(direct)?;
            self.code.bind(good)?;
            self.code
                .emit(|e| e.ldr_regoff(output, TMP1, Gpr::x(10), 3))?;
            return self.store_guard_result(destination, output);
        }
        let (p, t) = self.load_two_sources(pos.val, ARG1, tuple.val, ARG2)?;
        self.mov_var(ARG1, p)?;
        self.mov_var(ARG2, t)?;
        let target = self.element_guard_shared;
        self.fragment_call(target)?;
        if fail != 0 {
            let fail_label = self.label(fail);
            self.code.cbz(ARG1, fail_label)?;
        } else {
            self.code.cbz(ARG1, from_guard)?;
        }
        self.store_guard_result(destination, ARG1)
    }
}
