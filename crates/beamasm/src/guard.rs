//! AArch64 emitters for Erlang guard tests, comparisons, and guard BIFs.

use arinsal_a64::{
    buf::Label,
    enc::{Cond, Gpr},
};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::{Update, emit_enter_runtime, emit_leave_runtime};

/// Runtime hook used for guards that need term-aware runtime behavior.
pub type GuardHelper = unsafe extern "C" fn(
    process: *mut crate::ProcessHeader,
    op: u32,
    first: u64,
    second: u64,
) -> u64;
/// Runtime hook carrying three term operands, used for tagged tuple checks.
pub type GuardHelper3 = unsafe extern "C" fn(
    process: *mut crate::ProcessHeader,
    op: u32,
    first: u64,
    second: u64,
    third: u64,
) -> u64;

/// Target mode accepted by the function arity guard adapter.
pub enum Function2TestTarget {
    /// Branch to a BEAM failure label when the test does not match.
    FailLabel(u32),
    /// Preserve the older boolean result used by the fun module adapter.
    LegacyBoolean,
}

impl From<u32> for Function2TestTarget {
    fn from(value: u32) -> Self {
        Self::FailLabel(value)
    }
}

impl From<GuardHelper> for Function2TestTarget {
    fn from(_: GuardHelper) -> Self {
        Self::LegacyBoolean
    }
}

#[derive(Clone, Copy)]
enum InlineType {
    Integer,
    Atom,
    List,
    NonemptyList,
    Nil,
    Tuple,
    Arity,
    TaggedTuple,
    Boolean,
    Binary,
    Bitstring,
    Float,
    Number,
    Pid,
    Port,
    Reference,
    Map,
    Function,
    Function2,
}

#[derive(Clone, Copy)]
enum RelativeComparison {
    Less,
    GreaterEqual,
}

impl BeamModuleAssembler {
    fn emit_boolean_result(
        &mut self,
        yes: Label,
        no: Label,
        fail: Label,
    ) -> Result<(), ModuleError> {
        let done = self.code.new_label();
        self.code.bind(yes)?;
        self.code.b(done)?;
        self.code.bind(no)?;
        self.code.b(fail)?;
        self.code.bind(done)?;
        Ok(())
    }

    fn emit_inline_type(
        &mut self,
        op: InlineType,
        src: ArgVal,
        second: Option<ArgVal>,
        third: Option<ArgVal>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let fail = self.label(fail);
        self.emit_inline_type_to_label(op, src, second, third, fail)
    }

    fn emit_inline_type_to_label(
        &mut self,
        op: InlineType,
        src: ArgVal,
        second: Option<ArgVal>,
        third: Option<ArgVal>,
        fail: Label,
    ) -> Result<(), ModuleError> {
        let yes = self.code.new_label();
        let no = self.code.new_label();
        let value = self.source_reg(src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(11), value))?;
        if matches!(
            op,
            InlineType::Arity | InlineType::TaggedTuple | InlineType::Function2
        ) {
            let arity_reg = self
                .source_reg(second.ok_or(ModuleError::InvalidOperand("arity operand required"))?)?;
            self.code.emit(|e| e.mov_reg(Gpr::x(13), arity_reg))?;
        }
        if matches!(op, InlineType::TaggedTuple) {
            let tag_reg =
                self.source_reg(third.ok_or(ModuleError::InvalidOperand("tag operand required"))?)?;
            self.code.emit(|e| e.mov_reg(Gpr::x(14), tag_reg))?;
        }
        self.code.emit(|e| match op {
            InlineType::Integer | InlineType::Number | InlineType::Pid | InlineType::Port => {
                e.ands_imm(Gpr::x(8), Gpr::x(11), 15)?;
                e.cmp_imm(
                    Gpr::x(8),
                    match op {
                        InlineType::Pid => 3,
                        InlineType::Port => 7,
                        _ => 15,
                    },
                    false,
                )
            }
            InlineType::Atom => {
                e.ands_imm(Gpr::x(8), Gpr::x(11), 63)?;
                e.cmp_imm(Gpr::x(8), 11, false)
            }
            InlineType::List | InlineType::NonemptyList => {
                e.ands_imm(Gpr::x(8), Gpr::x(11), 3)?;
                e.cmp_imm(Gpr::x(8), 1, false)
            }
            InlineType::Nil => e.cmp_imm(Gpr::x(11), 0x3b, false),
            InlineType::Tuple
            | InlineType::Arity
            | InlineType::TaggedTuple
            | InlineType::Binary
            | InlineType::Bitstring
            | InlineType::Float
            | InlineType::Reference
            | InlineType::Map
            | InlineType::Function
            | InlineType::Function2 => {
                e.ands_imm(Gpr::x(8), Gpr::x(11), 3)?;
                e.cmp_imm(Gpr::x(8), 2, false)
            }
            InlineType::Boolean => {
                e.and_imm(Gpr::x(8), Gpr::x(11), !(1 << 6))?;
                e.cmp_imm(Gpr::x(8), 11, false)
            }
        })?;
        match op {
            InlineType::Integer => {
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.emit(|e| {
                    e.ands_imm(Gpr::x(8), Gpr::x(11), 3)?;
                    e.cmp_imm(Gpr::x(8), 2, false)
                })?;
                self.code.b_cond(Cond::Ne, no)?;
                self.load_boxed_header(Gpr::x(11), Gpr::x(10))?;
                self.code
                    .emit(|e| e.and_imm(Gpr::x(10), Gpr::x(10), 0x38))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(10), 8, false))?;
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            InlineType::Number => {
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.emit(|e| {
                    e.ands_imm(Gpr::x(8), Gpr::x(11), 3)?;
                    e.cmp_imm(Gpr::x(8), 2, false)
                })?;
                self.code.b_cond(Cond::Ne, no)?;
                self.emit_inline_type_tail(op, yes, no)?;
            }
            InlineType::Pid | InlineType::Port => {
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.emit(|e| {
                    e.ands_imm(Gpr::x(8), Gpr::x(11), 3)?;
                    e.cmp_imm(Gpr::x(8), 2, false)
                })?;
                self.code.b_cond(Cond::Ne, no)?;
                self.emit_inline_type_tail(op, yes, no)?;
            }
            InlineType::Atom | InlineType::NonemptyList | InlineType::Nil | InlineType::Boolean => {
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            InlineType::List => {
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(11), 0x3b, false))?;
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            _ => {
                self.code.b_cond(Cond::Ne, no)?;
                self.emit_inline_type_tail(op, yes, no)?;
            }
        }
        self.emit_boolean_result(yes, no, fail)
    }

    fn load_boxed_header(&mut self, tagged: Gpr, out: Gpr) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.and_imm(Gpr::x(17), tagged, !7)?;
            e.ldur(out, Gpr::x(17), 0)
        })?;
        Ok(())
    }

    fn emit_inline_type_tail(
        &mut self,
        op: InlineType,
        yes: Label,
        no: Label,
    ) -> Result<(), ModuleError> {
        self.load_boxed_header(Gpr::x(11), Gpr::x(10))?;
        match op {
            InlineType::Tuple => {
                self.code.emit(|e| e.ands_imm(Gpr::x(10), Gpr::x(10), 63))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0, false))?;
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            InlineType::Arity | InlineType::TaggedTuple => {
                self.code.emit(|e| e.mov_reg(Gpr::x(12), Gpr::x(10)))?;
                self.code.emit(|e| e.and_imm(Gpr::x(12), Gpr::x(12), 63))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(12), 0, false))?;
                self.code.b_cond(Cond::Ne, no)?;
                self.code.emit(|e| e.lsr_imm(Gpr::x(12), Gpr::x(10), 6))?;
                self.code.emit(|e| e.asr_imm(Gpr::x(13), Gpr::x(13), 4))?;
                self.code
                    .emit(|e| e.cmp_reg(Gpr::x(12), Gpr::x(13), arinsal_a64::enc::Shift::Lsl, 0))?;
                self.code.b_cond(Cond::Ne, no)?;
                if matches!(op, InlineType::TaggedTuple) {
                    self.code.emit(|e| {
                        e.ldur(Gpr::x(12), Gpr::x(17), 8)?;
                        e.cmp_reg(Gpr::x(12), Gpr::x(14), arinsal_a64::enc::Shift::Lsl, 0)
                    })?;
                    self.code.b_cond(Cond::Eq, yes)?;
                    self.code.b(no)?;
                } else {
                    self.code.b(yes)?;
                }
            }
            InlineType::Boolean => unreachable!(),
            InlineType::Binary | InlineType::Bitstring => {
                self.code.emit(|e| e.and_imm(Gpr::x(12), Gpr::x(10), 63))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(12), 0x20, false))?;
                let heap_bits = self.code.new_label();
                let sub_bits = self.code.new_label();
                self.code.b_cond(Cond::Eq, heap_bits)?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(12), 0x24, false))?;
                self.code.b_cond(Cond::Eq, sub_bits)?;
                self.code.b(no)?;
                self.code.bind(heap_bits)?;
                if matches!(op, InlineType::Bitstring) {
                    self.code.b(yes)?;
                } else {
                    self.code.emit(|e| e.ldur(Gpr::x(12), Gpr::x(17), 8))?;
                    self.code.emit(|e| e.tst_imm(Gpr::x(12), 7))?;
                    self.code.b_cond(Cond::Eq, yes)?;
                    self.code.b(no)?;
                }
                self.code.bind(sub_bits)?;
                if matches!(op, InlineType::Bitstring) {
                    self.code.b(yes)?;
                } else {
                    self.code.emit(|e| {
                        e.ldur(Gpr::x(12), Gpr::x(17), 24)?;
                        e.ldur(Gpr::x(9), Gpr::x(17), 16)?;
                        e.sub_reg(
                            Gpr::x(12),
                            Gpr::x(12),
                            Gpr::x(9),
                            arinsal_a64::enc::Shift::Lsl,
                            0,
                        )?;
                        e.tst_imm(Gpr::x(12), 7)
                    })?;
                    self.code.b_cond(Cond::Eq, yes)?;
                    self.code.b(no)?;
                }
            }
            InlineType::Float | InlineType::Map | InlineType::Function => {
                let expected = match op {
                    InlineType::Float => 0x18,
                    InlineType::Map => 0x2c,
                    InlineType::Function => 0x14,
                    _ => unreachable!(),
                };
                self.code.emit(|e| e.and_imm(Gpr::x(10), Gpr::x(10), 63))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(10), expected, false))?;
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            InlineType::Number => {
                self.code
                    .emit(|e| e.and_imm(Gpr::x(12), Gpr::x(10), 0x38))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(12), 8, false))?;
                let not_integer = self.code.new_label();
                self.code.b_cond(Cond::Ne, not_integer)?;
                self.code.b(yes)?;
                self.code.bind(not_integer)?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(12), 0x18, false))?;
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            InlineType::Pid | InlineType::Port => {
                let header = if matches!(op, InlineType::Pid) {
                    0x30
                } else {
                    0x34
                };
                self.code.emit(|e| e.and_imm(Gpr::x(10), Gpr::x(10), 63))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(10), header, false))?;
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            InlineType::Reference => {
                self.code.emit(|e| e.and_imm(Gpr::x(10), Gpr::x(10), 63))?;
                for header in [0x10, 0x38, 0x3c] {
                    self.code.emit(|e| e.cmp_imm(Gpr::x(10), header, false))?;
                    self.code.b_cond(Cond::Eq, yes)?;
                }
                self.code.b(no)?;
            }
            InlineType::Function2 => {
                self.code.emit(|e| e.and_imm(Gpr::x(12), Gpr::x(10), 63))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(12), 0x14, false))?;
                self.code.b_cond(Cond::Ne, no)?;
                self.code.emit(|e| e.ubfx(Gpr::x(12), Gpr::x(10), 8, 8))?;
                self.code.emit(|e| e.asr_imm(Gpr::x(13), Gpr::x(13), 4))?;
                self.code
                    .emit(|e| e.cmp_reg(Gpr::x(12), Gpr::x(13), arinsal_a64::enc::Shift::Lsl, 0))?;
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            InlineType::Integer
            | InlineType::Atom
            | InlineType::List
            | InlineType::NonemptyList
            | InlineType::Nil => unreachable!(),
        }
        Ok(())
    }

    fn emit_guard_helper(
        &mut self,
        op: u32,
        first: ArgVal,
        second: ArgVal,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let lhs = self.source_reg(first)?;
        let rhs = self.source_reg(second)?;
        self.code.emit(|e| e.mov_const(Gpr::x(8), u64::from(op)))?;
        self.emit_guard_runtime_call(helper as usize, &[Gpr::x(8), lhs, rhs])?;
        let fail = self.label(fail);
        self.code.cbz(Gpr::x(0), fail)?;
        Ok(())
    }

    fn emit_guard_value_helper(
        &mut self,
        op: u32,
        first: ArgVal,
        second: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let lhs = self.source_reg(first)?;
        let rhs = self.source_reg(second)?;
        self.code.emit(|e| e.mov_const(Gpr::x(8), u64::from(op)))?;
        self.emit_guard_runtime_call(helper as usize, &[Gpr::x(8), lhs, rhs])?;
        self.store_guard_result(destination, Gpr::x(0))
    }

    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:78-84,818-820,911-913, OTP-29.1.1
    fn emit_guard_runtime_call(&mut self, target: usize, args: &[Gpr]) -> Result<(), ModuleError> {
        let update = Update::NONE;
        emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::x(21))?;
            for (index, arg) in args.iter().copied().enumerate() {
                e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
            }
            e.mov_const(Gpr::x(17), target as u64)?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
        })?;
        self.code.cbnz(Gpr::x(9), self.error_label)?;
        Ok(())
    }

    fn guard_destination(&mut self, destination: ArgVal) -> Result<Gpr, ModuleError> {
        match destination {
            ArgVal::X(index) if index < 6 => Ok([
                Gpr::x(25),
                Gpr::x(26),
                Gpr::x(27),
                Gpr::x(28),
                Gpr::x(10 + 5),
                Gpr::x(10 + 6),
            ][index as usize]),
            ArgVal::Y(_) => Ok(Gpr::x(17)),
            _ => Err(ModuleError::InvalidOperand(
                "guard BIF destination must be X or Y",
            )),
        }
    }

    fn store_guard_result(&mut self, destination: ArgVal, result: Gpr) -> Result<(), ModuleError> {
        match destination {
            ArgVal::X(index) if index < 6 => {
                let target = self.guard_destination(destination)?;
                if target != result {
                    self.code.emit(|e| e.mov_reg(target, result))?;
                }
            }
            ArgVal::Y(index) => {
                let offset = index
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.str_uoff(result, Gpr::x(20), offset))?;
            }
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "guard BIF destination must be X or Y",
                ));
            }
        }
        Ok(())
    }

    fn emit_comparison(
        &mut self,
        op: u32,
        equal_result: bool,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: u32,
        runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(11), left))?;
        let right = self.source_reg(rhs)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(12), right))?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(11), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        let slow = self.code.new_label();
        let done = self.code.new_label();
        if equal_result {
            self.code.b_cond(Cond::Ne, slow)?;
            self.code.b(done)?;
        } else {
            let fail_label = self.label(fail);
            self.code.b_cond(Cond::Eq, fail_label)?;
            self.code.b(slow)?;
        }
        self.code.bind(slow)?;
        self.emit_guard_helper(op, lhs, rhs, fail, runtime)?;
        self.code.bind(done)?;
        Ok(())
    }

    fn emit_cmp_immediate_or_register(&mut self, left: Gpr, value: u64) -> Result<(), ModuleError> {
        if value <= 4095 {
            self.code.emit(|e| e.cmp_imm(left, value as u16, false))?;
        } else {
            self.code.emit(|e| e.mov_const(Gpr::x(12), value))?;
            self.code
                .emit(|e| e.cmp_reg(left, Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        }
        Ok(())
    }

    fn emit_small_immediate_comparison(
        &mut self,
        other: ArgVal,
        immediate: u64,
        immediate_is_lhs: bool,
        comparison: RelativeComparison,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let term = self.source_reg(other)?;
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), term, 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.emit_cmp_immediate_or_register(term, immediate)?;
        let (op, fail_cond) = match (comparison, immediate_is_lhs) {
            (RelativeComparison::Less, false) => (23, Cond::Ge),
            (RelativeComparison::Less, true) => (23, Cond::Le),
            (RelativeComparison::GreaterEqual, false) => (24, Cond::Lt),
            (RelativeComparison::GreaterEqual, true) => (24, Cond::Gt),
        };
        let fail_label = self.label(fail);
        self.code.b_cond(fail_cond, fail_label)?;
        self.code.b(done)?;
        self.code.bind(slow)?;
        let (lhs, rhs) = if immediate_is_lhs {
            (ArgVal::Immediate(immediate), other)
        } else {
            (other, ArgVal::Immediate(immediate))
        };
        self.emit_guard_helper(op, lhs, rhs, fail, helper)?;
        self.code.bind(done)?;
        Ok(())
    }

    fn emit_small_compare(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        cond: Cond,
        op: u32,
        fail: u32,
        runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(11), left))?;
        let right = self.source_reg(rhs)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(12), right))?;
        let generic = self.code.new_label();
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(11), 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, generic)?;
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(12), 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, generic)?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(11), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        let done = self.code.new_label();
        let opposite = match cond {
            Cond::Lt => Cond::Ge,
            Cond::Ge => Cond::Lt,
            _ => return Err(ModuleError::InvalidOperand("unsupported small comparison")),
        };
        let fail_label = self.label(fail);
        self.code.b_cond(opposite, fail_label)?;
        self.code.b(done)?;
        self.code.bind(generic)?;
        self.emit_guard_helper(op, lhs, rhs, fail, runtime)?;
        self.code.bind(done)?;
        Ok(())
    }

    fn emit_min_max(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        cond: Cond,
        op: u32,
        destination: ArgVal,
        runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), left, 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), right, 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.csel(output, right, left, cond)
        })?;
        self.store_guard_result(destination, output)?;
        self.code.b(done)?;
        self.code.bind(slow)?;
        self.emit_guard_value_helper(op, lhs, rhs, destination, runtime)?;
        self.code.bind(done)?;
        Ok(())
    }

    /// Emits an integer type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1308-1357, OTP-29.1.1
    pub fn emit_is_integer(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Integer, src, None, None, fail)
    }

    /// Emits an atom type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1132-1143, OTP-29.1.1
    pub fn emit_is_atom(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Atom, src, None, None, fail)
    }

    /// Emits a list-or-nil type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1359-1364, OTP-29.1.1
    pub fn emit_is_list(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::List, src, None, None, fail)
    }

    /// Emits a nonempty-list type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1121-1129, OTP-29.1.1
    pub fn emit_is_nonempty_list(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::NonemptyList, src, None, None, fail)
    }

    /// Emits an empty-list test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1389-1401, OTP-29.1.1
    pub fn emit_is_nil(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Nil, src, None, None, fail)
    }

    /// Emits a tuple type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1590-1609, OTP-29.1.1
    pub fn emit_is_tuple(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Tuple, src, None, None, fail)
    }

    /// Emits an exact tuple arity test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1655-1664, OTP-29.1.1
    pub fn emit_test_arity(
        &mut self,
        src: ArgVal,
        arity: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Arity, src, Some(arity), None, fail)
    }

    /// Emits an exact tuple arity and tag test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1529-1551, OTP-29.1.1
    pub fn emit_is_tagged_tuple(
        &mut self,
        src: ArgVal,
        arity: ArgVal,
        tag: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::TaggedTuple, src, Some(arity), Some(tag), fail)
    }

    /// Emits a boolean atom test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1145-1156, OTP-29.1.1
    pub fn emit_is_boolean(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Boolean, src, None, None, fail)
    }

    /// Emits a byte-aligned bitstring test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1186-1227, OTP-29.1.1
    pub fn emit_is_binary(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Binary, src, None, None, fail)
    }

    /// Emits a bitstring test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1158-1184, OTP-29.1.1
    pub fn emit_is_bitstring(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Bitstring, src, None, None, fail)
    }

    /// Emits a float type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1229-1244, OTP-29.1.1
    pub fn emit_is_float(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Float, src, None, None, fail)
    }

    /// Emits a number type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1403-1444, OTP-29.1.1
    pub fn emit_is_number(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Number, src, None, None, fail)
    }

    /// Emits a process identifier type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1446-1474, OTP-29.1.1
    pub fn emit_is_pid(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Pid, src, None, None, fail)
    }

    /// Emits a port type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1476-1504, OTP-29.1.1
    pub fn emit_is_port(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Port, src, None, None, fail)
    }

    /// Emits a reference type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1506-1527, OTP-29.1.1
    pub fn emit_is_reference(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Reference, src, None, None, fail)
    }

    /// Emits a map type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1366-1387, OTP-29.1.1
    pub fn emit_is_map(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Map, src, None, None, fail)
    }

    /// Emits a function type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1246-1261, OTP-29.1.1
    pub fn emit_is_function(&mut self, src: ArgVal, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Function, src, None, None, fail)
    }

    /// Emits a function type and arity test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1263-1306, OTP-29.1.1
    pub fn emit_is_function2_guard(
        &mut self,
        src: ArgVal,
        arity: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Function2, src, Some(arity), None, fail)
    }

    /// Emits a function arity guard or the older boolean form used by the fun adapter.
    pub fn emit_is_function2(
        &mut self,
        src: ArgVal,
        arity: ArgVal,
        fail: impl Into<Function2TestTarget>,
    ) -> Result<(), ModuleError> {
        match fail.into() {
            Function2TestTarget::FailLabel(label) => {
                self.emit_is_function2_guard(src, arity, label)
            }
            Function2TestTarget::LegacyBoolean => {
                let no = self.code.new_label();
                let done = self.code.new_label();
                self.emit_inline_type_to_label(InlineType::Function2, src, Some(arity), None, no)?;
                self.code.emit(|e| e.mov_const(Gpr::x(25), 1))?;
                self.code.b(done)?;
                self.code.bind(no)?;
                self.code.emit(|e| e.mov_const(Gpr::x(25), 0))?;
                self.code.bind(done)?;
                Ok(())
            }
        }
    }

    /// Emits an exact equality guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1751-1898, OTP-29.1.1
    pub fn emit_is_eq_exact(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1844-1856, OTP-29.1.1.
        if let Some((term, value)) = exact_immediate_operand(lhs, rhs) {
            let left = self.source_reg(term)?;
            self.emit_cmp_immediate_or_register(left, value)?;
            let fail = self.label(fail);
            self.code.b_cond(Cond::Ne, fail)?;
            return Ok(());
        }
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_comparison(19, true, lhs, rhs, fail, helper)
    }

    /// Emits an exact inequality guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1900-2053, OTP-29.1.1
    pub fn emit_is_ne_exact(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2001-2013, OTP-29.1.1.
        if let Some((term, value)) = exact_immediate_operand(lhs, rhs) {
            let left = self.source_reg(term)?;
            self.emit_cmp_immediate_or_register(left, value)?;
            let fail = self.label(fail);
            self.code.b_cond(Cond::Eq, fail)?;
            return Ok(());
        }
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_comparison(20, false, lhs, rhs, fail, helper)
    }

    /// Emits a loose equality guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2055-2079, OTP-29.1.1
    pub fn emit_is_eq(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_comparison(21, true, lhs, rhs, fail, helper)
    }

    /// Emits a loose inequality guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2081-2177, OTP-29.1.1
    pub fn emit_is_ne(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_comparison(22, false, lhs, rhs, fail, helper)
    }

    /// Emits a less-than guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2179-2291, OTP-29.1.1
    pub fn emit_is_lt(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        if let Some((other, immediate, immediate_is_lhs)) = small_comparison_immediate(lhs, rhs) {
            return self.emit_small_immediate_comparison(
                other,
                immediate,
                immediate_is_lhs,
                RelativeComparison::Less,
                fail,
                helper,
            );
        }
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_small_compare(lhs, rhs, Cond::Lt, 23, fail, helper)
    }

    /// Emits a greater-or-equal guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2293-2355, OTP-29.1.1
    pub fn emit_is_ge(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        if let Some((other, immediate, immediate_is_lhs)) = small_comparison_immediate(lhs, rhs) {
            return self.emit_small_immediate_comparison(
                other,
                immediate,
                immediate_is_lhs,
                RelativeComparison::GreaterEqual,
                fail,
                helper,
            );
        }
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_small_compare(lhs, rhs, Cond::Ge, 24, fail, helper)
    }

    /// Emits a value-producing comparison BIF into its decoded destination.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1751-2355, OTP-29.1.1
    pub fn emit_bif_compare(
        &mut self,
        op: u32,
        lhs: ArgVal,
        rhs: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_guard_value_helper(op, lhs, rhs, destination, helper)
    }

    /// Emits the `element/2` guard BIF through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:579-767, OTP-29.1.1
    pub fn emit_bif_element(
        &mut self,
        index: ArgVal,
        tuple: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let index = self.source_reg(index)?;
        let tuple = self.source_reg(tuple)?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(12), index, 4)?;
            e.sub_imm(Gpr::x(12), Gpr::x(12), 1, false)?;
            e.and_imm(Gpr::x(10), tuple, !7)?;
            e.add_imm(Gpr::x(10), Gpr::x(10), 8, false)?;
            e.ldr_regoff(output, Gpr::x(10), Gpr::x(12), 3)
        })?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `hd/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:773-797, OTP-29.1.1
    pub fn emit_bif_hd(
        &mut self,
        list: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let list = self.source_reg(list)?;
        self.code.emit(|e| {
            e.tst_imm(list, 3)?;
            e.and_imm(Gpr::x(10), list, !7)?;
            e.ldur(output, Gpr::x(10), 0)
        })?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `tl/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1266-1290, OTP-29.1.1
    pub fn emit_bif_tl(
        &mut self,
        list: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let list = self.source_reg(list)?;
        self.code.emit(|e| {
            e.tst_imm(list, 3)?;
            e.and_imm(Gpr::x(10), list, !7)?;
            e.ldur(output, Gpr::x(10), 8)
        })?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `tuple_size/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1335-1364, OTP-29.1.1
    pub fn emit_bif_tuple_size(
        &mut self,
        tuple: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let tuple = self.source_reg(tuple)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), tuple, !7)?;
            e.ldur(Gpr::x(12), Gpr::x(10), 0)?;
            e.lsr_imm(output, Gpr::x(12), 2)?;
            e.orr_imm(output, output, 15)
        })?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `map_size/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:947-997, OTP-29.1.1
    pub fn emit_bif_map_size(
        &mut self,
        map: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let map = self.source_reg(map)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), map, !7)?;
            e.ldur(Gpr::x(12), Gpr::x(10), 8)?;
            e.lsl_imm(output, Gpr::x(12), 4)?;
            e.orr_imm(output, output, 15)
        })?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `is_map_key/2` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:799-830, OTP-29.1.1
    pub fn emit_bif_is_map_key(
        &mut self,
        key: ArgVal,
        map: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let key_reg = self.source_reg(key)?;
        let map_reg = self.source_reg(map)?;
        self.code.emit(|e| {
            e.cmp_reg(key_reg, map_reg, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.ldr_uoff(Gpr::x(8), map_reg, 8)
        })?;
        self.emit_guard_value_helper(30, key, map, destination, helper)
    }

    /// Emits `map_get/2` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:854-936, OTP-29.1.1
    pub fn emit_bif_map_get(
        &mut self,
        key: ArgVal,
        map: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let key_reg = self.source_reg(key)?;
        let map_reg = self.source_reg(map)?;
        self.code.emit(|e| {
            e.cmp_reg(key_reg, map_reg, arinsal_a64::enc::Shift::Lsl, 0)?;
            e.ldr_uoff(Gpr::x(8), map_reg, 8)
        })?;
        self.emit_guard_value_helper(31, key, map, destination, helper)
    }

    /// Emits `byte_size/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:458-520, OTP-29.1.1
    pub fn emit_bif_byte_size(
        &mut self,
        term: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let term = self.source_reg(term)?;
        let sub = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), term, !7)?;
            e.ldur(Gpr::x(12), Gpr::x(10), 0)?;
            e.and_imm(Gpr::x(13), Gpr::x(12), 63)?;
            e.cmp_imm(Gpr::x(13), 0x24, false)
        })?;
        self.code.b_cond(Cond::Eq, sub)?;
        self.code.emit(|e| e.ldur(output, Gpr::x(10), 8))?;
        self.code.b(done)?;
        self.code.bind(sub)?;
        self.code.emit(|e| {
            e.ldur(Gpr::x(12), Gpr::x(10), 24)?;
            e.ldur(Gpr::x(13), Gpr::x(10), 16)?;
            e.sub_reg(
                output,
                Gpr::x(12),
                Gpr::x(13),
                arinsal_a64::enc::Shift::Lsl,
                0,
            )
        })?;
        self.code.bind(done)?;
        self.code.emit(|e| {
            e.lsr_imm(output, output, 3)?;
            e.lsl_imm(output, output, 4)?;
            e.orr_imm(output, output, 15)
        })?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `bit_size/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:382-436, OTP-29.1.1
    pub fn emit_bif_bit_size(
        &mut self,
        term: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let term = self.source_reg(term)?;
        let sub = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), term, !7)?;
            e.ldur(Gpr::x(12), Gpr::x(10), 0)?;
            e.and_imm(Gpr::x(13), Gpr::x(12), 63)?;
            e.cmp_imm(Gpr::x(13), 0x24, false)
        })?;
        self.code.b_cond(Cond::Eq, sub)?;
        self.code.emit(|e| e.ldur(output, Gpr::x(10), 8))?;
        self.code.b(done)?;
        self.code.bind(sub)?;
        self.code.emit(|e| {
            e.ldur(Gpr::x(12), Gpr::x(10), 24)?;
            e.ldur(Gpr::x(13), Gpr::x(10), 16)?;
            e.sub_reg(
                output,
                Gpr::x(12),
                Gpr::x(13),
                arinsal_a64::enc::Shift::Lsl,
                0,
            )
        })?;
        self.code.bind(done)?;
        self.code.emit(|e| {
            e.lsl_imm(output, output, 4)?;
            e.orr_imm(output, output, 15)
        })?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `self/0` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:844-857, OTP-29.1.1
    pub fn emit_bif_self(
        &mut self,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        self.code.emit(|e| e.ldr_uoff(output, Gpr::x(21), 104))?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `node/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1089-1170, OTP-29.1.1
    pub fn emit_bif_node(
        &mut self,
        term: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_guard_value_helper(39, term, ArgVal::Immediate(0), destination, helper)
    }

    /// Emits `length/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:320-335, OTP-29.1.1
    pub fn emit_bif_length(
        &mut self,
        list: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let list_reg = self.source_reg(list)?;
        let loop_label = self.code.new_label();
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(11), list_reg)?;
            e.mov_const(Gpr::x(12), 0)
        })?;
        self.code.bind(loop_label)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(11), 0x3b, false))?;
        self.code.b_cond(Cond::Eq, done)?;
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(11), 3)?;
            e.cmp_imm(Gpr::x(8), 1, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), Gpr::x(11), !7)?;
            e.ldur(Gpr::x(11), Gpr::x(10), 8)?;
            e.add_imm(Gpr::x(12), Gpr::x(12), 1, false)
        })?;
        self.code.b(loop_label)?;
        self.code.bind(done)?;
        self.code.emit(|e| {
            e.lsl_imm(output, Gpr::x(12), 4)?;
            e.orr_imm(output, output, 15)
        })?;
        self.store_guard_result(destination, output)?;
        let finished = self.code.new_label();
        self.code.b(finished)?;
        self.code.bind(slow)?;
        self.emit_guard_value_helper(35, list, ArgVal::Immediate(0), destination, helper)?;
        self.code.bind(finished)?;
        Ok(())
    }

    /// Emits `min/2` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:999-1065, OTP-29.1.1
    pub fn emit_bif_min(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_min_max(lhs, rhs, Cond::Gt, 36, destination, helper)
    }

    /// Emits `max/2` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:999-1065, OTP-29.1.1
    pub fn emit_bif_max(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg(lhs)?;
        let right = self.source_reg(rhs)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_min_max(lhs, rhs, Cond::Lt, 37, destination, helper)
    }

    /// Emits `abs/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:246-333, OTP-29.1.1
    pub fn emit_bif_abs(
        &mut self,
        value: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let value_reg = self.source_reg(value)?;
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), value_reg, 15)?;
            e.cmp_imm(Gpr::x(8), 15, false)
        })?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(8), 0x8000_0000_0000_000f))?;
        self.code
            .emit(|e| e.cmp_reg(value_reg, Gpr::x(8), arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Eq, slow)?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(8), value_reg, 4)?;
            e.cmp_imm(Gpr::x(8), 0, false)?;
            e.neg(Gpr::x(9), Gpr::x(8))?;
            e.csel(Gpr::x(8), Gpr::x(9), Gpr::x(8), Cond::Mi)?;
            e.lsl_imm(output, Gpr::x(8), 4)?;
            e.orr_imm(output, output, 15)
        })?;
        self.store_guard_result(destination, output)?;
        self.code.b(done)?;
        self.code.bind(slow)?;
        self.emit_guard_value_helper(38, value, ArgVal::Immediate(0), destination, helper)?;
        self.code.bind(done)?;
        Ok(())
    }
}

fn exact_immediate(value: ArgVal) -> Option<u64> {
    match value {
        ArgVal::Immediate(word) | ArgVal::Literal(word)
            if word & 15 == 15 || word & 63 == 11 || word == 0x3b =>
        {
            Some(word)
        }
        _ => None,
    }
}

fn exact_immediate_operand(lhs: ArgVal, rhs: ArgVal) -> Option<(ArgVal, u64)> {
    exact_immediate(rhs)
        .map(|word| (lhs, word))
        .or_else(|| exact_immediate(lhs).map(|word| (rhs, word)))
}

fn small_comparison_immediate(lhs: ArgVal, rhs: ArgVal) -> Option<(ArgVal, u64, bool)> {
    match (lhs, rhs) {
        (ArgVal::X(_) | ArgVal::Y(_), ArgVal::Immediate(word)) if word & 15 == 15 => {
            Some((lhs, word, false))
        }
        (ArgVal::Immediate(word), ArgVal::X(_) | ArgVal::Y(_)) if word & 15 == 15 => {
            Some((rhs, word, true))
        }
        _ => None,
    }
}
