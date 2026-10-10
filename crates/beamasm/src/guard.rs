//! AArch64 emitters for Erlang guard tests, comparisons, and guard BIFs.

use arinsal_a64::{
    buf::Label,
    enc::{Cond, Gpr},
};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::types::{ArgType, TypedArg, type_id};
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

/// BIFs whose inline guard code raises `badarg` with the BIF itself as the top stack frame.
/// `SchedulerRegisters::tmp_mem[7]` holds `index + 1` of the raising BIF; its arguments are in
/// X0.. (erts passes the `ErtsCodeMFA` to `raise_exception` the same way).
pub const BADARG_MFAS: [(&str, &str, u8); 7] = [
    ("erlang", "element", 2),
    ("erlang", "hd", 1),
    ("erlang", "tl", 1),
    ("erlang", "bit_size", 1),
    ("erlang", "byte_size", 1),
    ("erlang", "map_size", 1),
    ("erlang", "tuple_size", 1),
];
/// `freason` of an inline `map_size/1` failure: `{badmap, Value}` (erts `EXC_BADMAP`).
pub const EXC_BADMAP: u64 = (18 << 10) | 0x50;
const BADARG_MFA_SLOT: u32 = 16_440;

/// Target mode accepted by the function arity guard adapter.
pub enum Function2TestTarget {
    /// Branch to a BEAM failure label when the test does not match.
    FailLabel(u32),
    /// Preserve the older boolean result used by the fun module adapter.
    LegacyBoolean(GuardHelper),
}

impl From<u32> for Function2TestTarget {
    fn from(value: u32) -> Self {
        Self::FailLabel(value)
    }
}

impl From<GuardHelper> for Function2TestTarget {
    fn from(helper: GuardHelper) -> Self {
        Self::LegacyBoolean(helper)
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
    Function,
    Function2,
    Map,
}

#[derive(Clone, Copy)]
enum RelativeComparison {
    Less,
    GreaterEqual,
}

/// Guard helper op flag for an instruction with a failure label (see the VM guard hook).
const QUIET_GUARD: u32 = 0x100;

fn small_operand(value: ArgVal) -> Result<i64, ModuleError> {
    let operand = TypedArg::new(value, ArgType::ANY);
    if operand.is_small() {
        Ok(operand.small_value())
    } else {
        Err(ModuleError::InvalidOperand(
            "arity operand must be an immediate small",
        ))
    }
}

fn arity_word(arity: i64) -> u64 {
    (arity as u64).wrapping_shl(6)
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
            | InlineType::Map
            | InlineType::Reference
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

    /// Emits erts' type tests directly to the failure label instead of materializing a Boolean.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1121-1403, 1529-1664, OTP-29.1.1.
    fn emit_inline_type(
        &mut self,
        op: InlineType,
        source: TypedArg,
        second: Option<ArgVal>,
        third: Option<ArgVal>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let fail = self.label(fail);
        let src = self.source_reg_into(source.val, Gpr::x(11))?;
        let tmp1 = Gpr::x(8);
        let tmp2 = Gpr::x(9);
        let tmp3 = Gpr::x(10);

        match op {
            InlineType::Integer => {
                if source.always_immediate() {
                    self.code.emit(|e| e.and_imm(tmp2, src, 15))?;
                    self.code.emit(|e| e.cmp_imm(tmp2, 15, false))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                } else {
                    let next = self.code.new_label();
                    if source.always_one_of(type_id::INTEGER | type_id::ALWAYS_BOXED) {
                        if !source.always_boxed() {
                            self.code.tbnz(src, 0, next)?;
                        }
                    } else {
                        self.code.emit(|e| e.and_imm(tmp2, src, 15))?;
                        self.code.emit(|e| e.cmp_imm(tmp2, 15, false))?;
                        self.code.b_cond(Cond::Eq, next)?;
                        self.emit_boxed_check(source, tmp2, fail)?;
                    }
                    if source.masked_types(type_id::MAYBE_BOXED) != type_id::INTEGER {
                        self.code.emit(|e| e.ldur(tmp1, src, -2))?;
                        self.code.emit(|e| e.and_imm(tmp1, tmp1, 0x38))?;
                        self.code.emit(|e| e.cmp_imm(tmp1, 8, false))?;
                        self.code.b_cond(Cond::Ne, fail)?;
                    }
                    self.code.bind(next)?;
                }
            }
            InlineType::Atom => {
                self.code.emit(|e| e.and_imm(tmp1, src, 63))?;
                self.code.emit(|e| e.cmp_imm(tmp1, 11, false))?;
                self.code.b_cond(Cond::Ne, fail)?;
            }
            InlineType::List => {
                self.code.emit(|e| e.tst_imm(src, 2))?;
                self.code.emit(|e| e.mov_const(Gpr::x(14), 0x3b))?;
                self.code
                    .emit(|e| e.ccmp_reg(src, Gpr::x(14), 4, Cond::Ne))?;
                self.code.b_cond(Cond::Ne, fail)?;
            }
            InlineType::NonemptyList => self.code.tbnz(src, 1, fail)?,
            InlineType::Nil => {
                if source.always_one_of(type_id::CONS | type_id::NIL) {
                    self.code.tbz(src, 1, fail)?;
                } else {
                    self.code.emit(|e| e.cmp_imm(src, 0x3b, false))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
            }
            InlineType::Tuple => {
                self.emit_boxed_check(source, src, fail)?;
                self.code.emit(|e| e.and_imm(Gpr::x(0), src, !7))?;
                if source.masked_types(type_id::MAYBE_BOXED) != type_id::TUPLE {
                    self.code.emit(|e| e.ldr_uoff(tmp1, Gpr::x(0), 0))?;
                    self.code.emit(|e| e.tst_imm(tmp1, 63))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
            }
            InlineType::Arity => {
                let arity = small_operand(second.ok_or(ModuleError::InvalidOperand(
                    "arity operand must be an immediate small",
                ))?)?;
                let arity_word = arity_word(arity);
                self.code.emit(|e| e.and_imm(Gpr::x(0), src, !7))?;
                self.code.emit(|e| e.ldr_uoff(tmp1, Gpr::x(0), 0))?;
                self.emit_cmp_constant(tmp1, arity_word, Gpr::x(14))?;
                self.code.b_cond(Cond::Ne, fail)?;
            }
            InlineType::TaggedTuple => {
                let arity = small_operand(second.ok_or(ModuleError::InvalidOperand(
                    "arity operand must be an immediate small",
                ))?)?;
                let arity_word = arity_word(arity);
                let tag = third.ok_or(ModuleError::InvalidOperand("tag operand required"))?;
                self.emit_boxed_check(source, src, fail)?;
                self.code.emit(|e| e.and_imm(Gpr::x(0), src, !7))?;
                self.code.emit(|e| e.ldp(tmp1, tmp2, Gpr::x(0), 0))?;
                let tag_reg = self.source_reg_into(tag, Gpr::x(14))?;
                self.code
                    .emit(|e| e.cmp_reg(tmp2, tag_reg, arinsal_a64::enc::Shift::Lsl, 0))?;
                self.code.emit(|e| e.mov_const(tmp3, arity_word))?;
                self.code.emit(|e| e.ccmp_reg(tmp1, tmp3, 0, Cond::Eq))?;
                self.code.b_cond(Cond::Ne, fail)?;
            }
            InlineType::Boolean => {
                self.code.emit(|e| e.and_imm(tmp1, src, !(1 << 6)))?;
                self.code.emit(|e| e.cmp_imm(tmp1, 11, false))?;
                self.code.b_cond(Cond::Ne, fail)?;
            }
            InlineType::Binary => {
                self.emit_boxed_check(source, src, fail)?;
                self.code.emit(|e| e.and_imm(Gpr::x(0), src, !7))?;
                self.code.emit(|e| e.ldp(tmp1, tmp2, Gpr::x(0), 0))?;
                let not_sub_bits = self.code.new_label();
                self.code.emit(|e| e.cmp_imm(tmp1, 0x24, false))?;
                self.code.b_cond(Cond::Ne, not_sub_bits)?;
                self.code.emit(|e| e.ldp(tmp2, tmp3, Gpr::x(0), 16))?;
                self.code
                    .emit(|e| e.sub_reg(tmp2, tmp3, tmp2, arinsal_a64::enc::Shift::Lsl, 0))?;
                self.code.bind(not_sub_bits)?;
                if source.masked_types(type_id::MAYBE_BOXED) == type_id::BITSTRING {
                    self.code.emit(|e| e.tst_imm(tmp2, 7))?;
                } else {
                    self.code.emit(|e| e.and_imm(tmp1, tmp1, 56))?;
                    self.code.emit(|e| {
                        e.orr_reg(
                            tmp1,
                            tmp1,
                            arinsal_a64::enc::Shifted {
                                reg: tmp2,
                                shift: arinsal_a64::enc::Shift::Lsl,
                                amount: 61,
                            },
                        )
                    })?;
                    self.code.emit(|e| e.cmp_imm(tmp1, 0x20, false))?;
                }
                self.code.b_cond(Cond::Ne, fail)?;
            }
            InlineType::Bitstring => {
                self.emit_boxed_check(source, src, fail)?;
                if source.masked_types(type_id::MAYBE_BOXED) != type_id::BITSTRING {
                    self.code.emit(|e| e.ldur(tmp1, src, -2))?;
                    self.code.emit(|e| e.and_imm(tmp1, tmp1, 56))?;
                    self.code.emit(|e| e.cmp_imm(tmp1, 0x20, false))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
            }
            InlineType::Float => {
                self.emit_boxed_check(source, src, fail)?;
                if source.masked_types(type_id::MAYBE_BOXED) != type_id::FLOAT {
                    self.code.emit(|e| e.ldur(tmp1, src, -2))?;
                    self.code.emit(|e| e.cmp_imm(tmp1, 0x58, false))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
            }
            InlineType::Map => {
                self.emit_boxed_check(source, src, fail)?;
                if source.masked_types(type_id::MAYBE_BOXED) != type_id::MAP {
                    self.code.emit(|e| e.ldur(tmp3, src, -2))?;
                    self.code.emit(|e| e.and_imm(tmp3, tmp3, 63))?;
                    self.code.emit(|e| e.cmp_imm(tmp3, 0x2c, false))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
            }
            InlineType::Function => {
                self.emit_boxed_check(source, src, fail)?;
                if source.masked_types(type_id::MAYBE_BOXED) != type_id::FUN {
                    self.code.emit(|e| e.ldurb(Gpr::w(8), src, -2))?;
                    self.code.emit(|e| e.cmp_imm(tmp1, 0x14, false))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
            }
            InlineType::Number => {
                let next = self.code.new_label();
                if source.always_one_of(type_id::INTEGER | type_id::ALWAYS_BOXED) {
                    if !source.always_boxed() {
                        self.code.tbnz(src, 0, next)?;
                    }
                } else {
                    self.code.emit(|e| e.and_imm(tmp2, src, 15))?;
                    self.code.emit(|e| e.cmp_imm(tmp2, 15, false))?;
                    self.code.b_cond(Cond::Eq, next)?;
                    self.emit_boxed_check(source, src, fail)?;
                }
                if source.masked_types(type_id::MAYBE_BOXED) != type_id::NUMBER {
                    self.code.emit(|e| e.ldur(tmp1, src, -2))?;
                    self.code.emit(|e| e.and_imm(tmp2, tmp1, 0x38))?;
                    self.code.emit(|e| e.cmp_imm(tmp2, 8, false))?;
                    self.code.emit(|e| e.mov_const(tmp3, 0x58))?;
                    self.code.emit(|e| e.ccmp_reg(tmp1, tmp3, 4, Cond::Ne))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
                self.code.bind(next)?;
            }
            InlineType::Pid | InlineType::Port => {
                let (immediate_tag, boxed_header) = if matches!(op, InlineType::Pid) {
                    (3, 0x30)
                } else {
                    (7, 0x34)
                };
                let immediate_type = if matches!(op, InlineType::Pid) {
                    type_id::PID
                } else {
                    type_id::PORT
                };
                let next = self.code.new_label();
                if source.always_one_of(immediate_type | type_id::ALWAYS_BOXED) {
                    if !source.always_boxed() {
                        self.code.tbnz(src, 0, next)?;
                    }
                } else {
                    self.code.emit(|e| e.and_imm(tmp2, src, 15))?;
                    self.code.emit(|e| e.cmp_imm(tmp2, immediate_tag, false))?;
                    self.code.b_cond(Cond::Eq, next)?;
                    self.emit_boxed_check(source, tmp2, fail)?;
                }
                if source.masked_types(type_id::MAYBE_BOXED) != immediate_type {
                    self.code.emit(|e| e.ldur(tmp2, src, -2))?;
                    self.code.emit(|e| e.and_imm(tmp2, tmp2, 63))?;
                    self.code.emit(|e| e.cmp_imm(tmp2, boxed_header, false))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
                self.code.bind(next)?;
            }
            InlineType::Reference => {
                self.emit_boxed_check(source, src, fail)?;
                if source.masked_types(type_id::MAYBE_BOXED) != type_id::REFERENCE {
                    self.code.emit(|e| e.ldur(tmp1, src, -2))?;
                    self.code.emit(|e| e.and_imm(tmp1, tmp1, 63))?;
                    self.code.emit(|e| e.cmp_imm(tmp1, 0x38, false))?;
                    self.code.emit(|e| e.ccmp_imm(tmp1, 0x10, 4, Cond::Ne))?;
                    self.code.b_cond(Cond::Ne, fail)?;
                }
            }
            InlineType::Function2 => {
                let arity = small_operand(second.ok_or(ModuleError::InvalidOperand(
                    "arity operand must be an immediate small",
                ))?)?;
                if !(0..=255).contains(&arity) {
                    self.code.b(fail)?;
                    return Ok(());
                }
                self.emit_boxed_check(source, src, fail)?;
                self.code.emit(|e| e.ldurh(Gpr::w(9), src, -2))?;
                self.emit_cmp_constant(Gpr::x(9), ((arity as u64) << 8) | 0x14, Gpr::x(14))?;
                self.code.b_cond(Cond::Ne, fail)?;
            }
        }
        Ok(())
    }

    fn emit_boxed_check(
        &mut self,
        source: TypedArg,
        reg: Gpr,
        fail: Label,
    ) -> Result<(), ModuleError> {
        if !source.always_boxed() {
            self.code.tbnz(reg, 0, fail)?;
        }
        Ok(())
    }

    fn emit_cmp_constant(&mut self, reg: Gpr, value: u64, scratch: Gpr) -> Result<(), ModuleError> {
        if value <= 4095 {
            self.code.emit(|e| e.cmp_imm(reg, value as u16, false))?;
        } else {
            self.code.emit(|e| e.mov_const(scratch, value))?;
            self.code
                .emit(|e| e.cmp_reg(reg, scratch, arinsal_a64::enc::Shift::Lsl, 0))?;
        }
        Ok(())
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
            InlineType::Float | InlineType::Function => {
                let expected = match op {
                    InlineType::Float => 0x18,
                    InlineType::Function => 0x14,
                    _ => unreachable!(),
                };
                self.code.emit(|e| e.and_imm(Gpr::x(10), Gpr::x(10), 63))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(10), expected, false))?;
                self.code.b_cond(Cond::Eq, yes)?;
                self.code.b(no)?;
            }
            InlineType::Map => {
                self.code.emit(|e| e.and_imm(Gpr::x(10), Gpr::x(10), 63))?;
                self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0x2c, false))?;
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
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1517-1521 (is_ref), OTP-29.1.1.
                for header in [0x10, 0x38] {
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
        let rhs = self.source_reg_into(second, Gpr::x(17))?;
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
        let rhs = self.source_reg_into(second, Gpr::x(17))?;
        self.code.emit(|e| e.mov_const(Gpr::x(8), u64::from(op)))?;
        self.emit_guard_runtime_call(helper as usize, &[Gpr::x(8), lhs, rhs])?;
        self.store_guard_result(destination, Gpr::x(0))
    }

    /// Like `emit_guard_value_helper`, but a failure branches to `fail` instead of raising when
    /// the instruction has a failure label.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (guard BIFs with a Fail label:
    // THE_NON_VALUE branches to Fail), OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    fn emit_guard_value_helper_fail(
        &mut self,
        fail: u32,
        boolean: bool,
        op: u32,
        first: ArgVal,
        second: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        if fail == 0 && boolean {
            return self.emit_guard_boolean_value_helper(op, first, second, destination, helper);
        }
        if fail == 0 {
            return self.emit_guard_value_helper(op, first, second, destination, helper);
        }
        let lhs = self.source_reg(first)?;
        let rhs = self.source_reg_into(second, Gpr::x(17))?;
        // The runtime records no BIF frame for a failure that branches to the label.
        self.code
            .emit(|e| e.mov_const(Gpr::x(8), u64::from(op | QUIET_GUARD)))?;
        let update = Update::HEAP_ALLOC;
        emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::x(21))?;
            e.mov_reg(Gpr::x(1), Gpr::x(8))?;
            e.mov_reg(Gpr::x(2), lhs)?;
            e.mov_reg(Gpr::x(3), rhs)?;
            e.mov_const(Gpr::x(17), helper as usize as u64)?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(&mut self.code, 6, update)?;
        let ok = self.code.new_label();
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
        })?;
        self.code.cbz(Gpr::x(9), ok)?;
        self.code.emit(|e| e.str_uoff(Gpr::xzr(), Gpr::x(21), 40))?;
        let fail = self.label(fail);
        self.code.b(fail)?;
        self.code.bind(ok)?;
        if boolean {
            self.code.emit(|e| {
                e.cmp_imm(Gpr::x(0), 0, false)?;
                e.mov_const(Gpr::x(10), 0x0b)?;
                e.mov_const(Gpr::x(11), 0x4b)?;
                e.csel(Gpr::x(0), Gpr::x(11), Gpr::x(10), Cond::Ne)
            })?;
        }
        self.store_guard_result(destination, Gpr::x(0))
    }

    fn emit_guard_boolean_value_helper(
        &mut self,
        op: u32,
        first: ArgVal,
        second: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let lhs = self.source_reg(first)?;
        let rhs = self.source_reg_into(second, Gpr::x(17))?;
        self.code.emit(|e| e.mov_const(Gpr::x(8), u64::from(op)))?;
        self.emit_guard_runtime_call(helper as usize, &[Gpr::x(8), lhs, rhs])?;
        self.code.emit(|e| {
            e.cmp_imm(Gpr::x(0), 0, false)?;
            e.mov_const(Gpr::x(10), 0x0b)?;
            e.mov_const(Gpr::x(11), 0x4b)?;
            e.csel(Gpr::x(0), Gpr::x(11), Gpr::x(10), Cond::Ne)
        })?;
        self.store_guard_result(destination, Gpr::x(0))
    }

    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:78-84,818-820,911-913, OTP-29.1.1
    pub(super) fn emit_guard_runtime_call(
        &mut self,
        target: usize,
        args: &[Gpr],
    ) -> Result<(), ModuleError> {
        let update = Update::HEAP_ALLOC;
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
        self.error_if_nonzero(Gpr::x(9))?;
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
            ArgVal::Y(_) | ArgVal::XMemory(_) => Ok(Gpr::x(17)),
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
            ArgVal::Y(_) | ArgVal::XMemory(_) => self.store_operand(destination, result)?,
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
    pub fn emit_is_integer(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Integer, src.into(), None, None, fail)
    }

    /// Emits an atom type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1132-1143, OTP-29.1.1
    pub fn emit_is_atom(&mut self, src: impl Into<TypedArg>, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Atom, src.into(), None, None, fail)
    }

    /// Emits a list-or-nil type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1359-1364, OTP-29.1.1
    pub fn emit_is_list(&mut self, src: impl Into<TypedArg>, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::List, src.into(), None, None, fail)
    }

    /// Emits a nonempty-list type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1121-1129, OTP-29.1.1
    pub fn emit_is_nonempty_list(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::NonemptyList, src.into(), None, None, fail)
    }

    /// Emits an empty-list test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1389-1401, OTP-29.1.1
    pub fn emit_is_nil(&mut self, src: impl Into<TypedArg>, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Nil, src.into(), None, None, fail)
    }

    /// Emits a tuple type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1590-1609, OTP-29.1.1
    pub fn emit_is_tuple(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Tuple, src.into(), None, None, fail)
    }

    /// Emits an exact tuple arity test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1655-1664, OTP-29.1.1
    pub fn emit_test_arity(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Arity, src.into(), Some(arity), None, fail)
    }

    /// Emits the fused `is_tuple` + `test_arity` test: one boxed check and one header load,
    /// failing to `not_tuple` or, when the tuple has another arity, to `bad_arity`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1611-1653 (emit_i_is_tuple_of_arity,
    // emit_i_is_tuple_of_arity_ff), OTP-29.1.1. The arity operand is the loader's small
    // integer; the header compare is against its `make_arityval`.
    pub fn emit_is_tuple_of_arity(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        not_tuple: u32,
        bad_arity: u32,
    ) -> Result<(), ModuleError> {
        let source = src.into();
        let arity = small_operand(arity)?;
        let header = arity_word(arity);
        let not_tuple = self.label(not_tuple);
        let bad_arity = self.label(bad_arity);
        let value = self.source_reg_into(source.val, Gpr::x(11))?;
        self.emit_boxed_check(source, value, not_tuple)?;
        self.code.emit(|e| e.and_imm(Gpr::x(0), value, !7))?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(8), Gpr::x(0), 0))?;
        if not_tuple != bad_arity && source.masked_types(type_id::MAYBE_BOXED) != type_id::TUPLE {
            self.code.emit(|e| e.tst_imm(Gpr::x(8), 63))?;
            self.code.b_cond(Cond::Ne, not_tuple)?;
        }
        self.emit_cmp_constant(Gpr::x(8), header, Gpr::x(14))?;
        self.code.b_cond(Cond::Ne, bad_arity)?;
        Ok(())
    }

    /// Emits an exact tuple arity and tag test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1529-1551, OTP-29.1.1
    pub fn emit_is_tagged_tuple(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        tag: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(
            InlineType::TaggedTuple,
            src.into(),
            Some(arity),
            Some(tag),
            fail,
        )
    }

    /// Emits the tagged tuple test with separate non-tuple and record failures.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1554-1587, OTP-29.1.1.
    pub fn emit_is_tagged_tuple_ff(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        tag: ArgVal,
        not_tuple: u32,
        not_record: u32,
    ) -> Result<(), ModuleError> {
        let source = src.into();
        let src_reg = self.source_reg_into(source.val, Gpr::x(11))?;
        let not_tuple = self.label(not_tuple);
        let not_record = self.label(not_record);
        let arity = small_operand(arity)?;
        let arity_word = arity_word(arity);
        self.emit_boxed_check(source, src_reg, not_tuple)?;
        self.code.emit(|e| e.and_imm(Gpr::x(0), src_reg, !7))?;
        self.code
            .emit(|e| e.ldp(Gpr::x(8), Gpr::x(9), Gpr::x(0), 0))?;
        let correct_arity = self.code.new_label();
        self.emit_cmp_constant(Gpr::x(8), arity_word, Gpr::x(14))?;
        self.code.b_cond(Cond::Eq, correct_arity)?;
        self.code.emit(|e| e.tst_imm(Gpr::x(8), 63))?;
        self.code.b_cond(Cond::Eq, not_record)?;
        self.code.b(not_tuple)?;
        self.code.bind(correct_arity)?;
        let tag_reg = self.source_reg_into(tag, Gpr::x(14))?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(9), tag_reg, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Ne, not_record)?;
        Ok(())
    }

    /// Emits a boolean atom test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1145-1156, OTP-29.1.1
    pub fn emit_is_boolean(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Boolean, src.into(), None, None, fail)
    }

    /// Emits a byte-aligned bitstring test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1186-1227, OTP-29.1.1
    pub fn emit_is_binary(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Binary, src.into(), None, None, fail)
    }

    /// Emits a bitstring test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1158-1184, OTP-29.1.1
    pub fn emit_is_bitstring(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Bitstring, src.into(), None, None, fail)
    }

    /// Emits a float type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1229-1244, OTP-29.1.1
    pub fn emit_is_float(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Float, src.into(), None, None, fail)
    }

    /// Emits a number type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1403-1444, OTP-29.1.1
    pub fn emit_is_number(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Number, src.into(), None, None, fail)
    }

    /// Emits a process identifier type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1446-1474, OTP-29.1.1
    pub fn emit_is_pid(&mut self, src: impl Into<TypedArg>, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Pid, src.into(), None, None, fail)
    }

    /// Emits a port type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1476-1504, OTP-29.1.1
    pub fn emit_is_port(&mut self, src: impl Into<TypedArg>, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Port, src.into(), None, None, fail)
    }

    /// Emits a reference type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1506-1527, OTP-29.1.1
    pub fn emit_is_reference(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Reference, src.into(), None, None, fail)
    }

    /// Emits a map type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1366-1387, OTP-29.1.1
    pub fn emit_is_map(&mut self, src: impl Into<TypedArg>, fail: u32) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Map, src.into(), None, None, fail)
    }

    /// Emits a function type test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1246-1261, OTP-29.1.1
    pub fn emit_is_function(
        &mut self,
        src: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Function, src.into(), None, None, fail)
    }

    /// Emits a function type and arity test.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1263-1306, OTP-29.1.1
    pub fn emit_is_function2_guard(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_inline_type(InlineType::Function2, src.into(), Some(arity), None, fail)
    }

    /// Emits the function arity guard, using OTP's runtime path for a non-small arity operand.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1263-1306, OTP-29.1.1.
    pub fn emit_is_function2_guard_with_helper(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        fail: u32,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        if TypedArg::from(arity).is_small() {
            self.emit_is_function2_guard(src, arity, fail)
        } else {
            self.emit_guard_helper(43, src.into().val, arity, fail, helper)
        }
    }

    /// Emits a function arity guard or the older boolean form used by the fun adapter.
    pub fn emit_is_function2(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        fail: impl Into<Function2TestTarget>,
    ) -> Result<(), ModuleError> {
        let src = src.into();
        match fail.into() {
            Function2TestTarget::FailLabel(label) => {
                self.emit_is_function2_guard(src, arity, label)
            }
            Function2TestTarget::LegacyBoolean(helper) => {
                if !TypedArg::from(arity).is_small() {
                    let source = self.source_reg(src.val)?;
                    let arity = self.source_reg_into(arity, Gpr::x(17))?;
                    self.code.emit(|e| e.mov_const(Gpr::x(8), 43))?;
                    self.emit_guard_runtime_call(helper as usize, &[Gpr::x(8), source, arity])?;
                    self.code.emit(|e| e.mov_reg(Gpr::x(25), Gpr::x(0)))?;
                    return Ok(());
                }
                let no = self.code.new_label();
                let done = self.code.new_label();
                self.emit_inline_type_to_label(
                    InlineType::Function2,
                    src.val,
                    Some(arity),
                    None,
                    no,
                )?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        // OTP's comparison BIFs produce tagged atoms even though this VM hook
        // returns a native boolean condition for branch-oriented guard tests.
        self.emit_guard_boolean_value_helper(op, lhs, rhs, destination, helper)
    }

    /// Emits the `element/2` guard BIF.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:522-543 (emit_bif_element_helper)
    // and 579-767 (emit_bif_element), OTP-29.1.1: a non-tuple, a non-small or non-positive
    // position, or a position past the arity fails (branch to `fail`, or badarg).
    pub fn emit_bif_element(
        &mut self,
        fail: u32,
        index: ArgVal,
        tuple: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let index = self.source_reg(index)?;
        let tuple = self.source_reg_into(tuple, Gpr::x(17))?;
        let bad = self.code.new_label();
        let ok = self.code.new_label();
        self.code.emit(|e| {
            e.and_imm(Gpr::x(12), tuple, 3)?;
            e.cmp_imm(Gpr::x(12), 2, false)
        })?;
        self.code.b_cond(Cond::Ne, bad)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), tuple, !7)?;
            e.ldur(Gpr::x(13), Gpr::x(10), 0)?;
            e.tst_imm(Gpr::x(13), 0x3f)
        })?;
        self.code.b_cond(Cond::Ne, bad)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(12), index, 0xf)?;
            e.cmp_imm(Gpr::x(12), 0xf, false)
        })?;
        self.code.b_cond(Cond::Ne, bad)?;
        self.code.emit(|e| {
            e.asr_imm(Gpr::x(12), index, 4)?;
            e.cmp_imm(Gpr::x(12), 0, false)
        })?;
        self.code.b_cond(Cond::Le, bad)?;
        self.code.emit(|e| {
            e.lsr_imm(Gpr::x(14), Gpr::x(13), 6)?;
            e.cmp_reg(Gpr::x(12), Gpr::x(14), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Hi, bad)?;
        self.code
            .emit(|e| e.ldr_regoff(output, Gpr::x(10), Gpr::x(12), 3))?;
        self.code.b(ok)?;
        self.code.bind(bad)?;
        if fail == 0 {
            // Port of instr_guard_bifs.cpp:572-577 (emit_handle_element_error_shared).
            self.code.emit(|e| {
                e.mov_reg(Gpr::x(12), index)?;
                e.mov_reg(Gpr::x(13), tuple)?;
                e.mov_reg(Gpr::x(25), Gpr::x(12))?;
                e.mov_reg(Gpr::x(26), Gpr::x(13))
            })?;
            self.set_badarg_mfa(0)?;
        }
        self.emit_guard_fail(fail)?;
        self.code.bind(ok)?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    fn set_badarg_mfa(&mut self, index: u64) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.mov_const(Gpr::x(9), index + 1)?;
            e.str_uoff(Gpr::x(9), Gpr::x(19), BADARG_MFA_SLOT)
        })?;
        Ok(())
    }

    /// Emits `hd/1`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:768-797, OTP-29.1.1: anything
    // but a cons cell raises badarg.
    pub fn emit_bif_hd(
        &mut self,
        list: ArgVal,
        destination: ArgVal,
        runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_cons_field(list, destination, 0, runtime)
    }

    /// Emits `tl/1`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1261-1290, OTP-29.1.1.
    pub fn emit_bif_tl(
        &mut self,
        list: ArgVal,
        destination: ArgVal,
        runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_cons_field(list, destination, 8, runtime)
    }

    fn emit_cons_field(
        &mut self,
        list: ArgVal,
        destination: ArgVal,
        offset: i16,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let list = self.source_reg(list)?;
        let good = self.code.new_label();
        // A cons cell has primary tag 0b01; boxed, immediate and header words all have bit 1 set.
        self.code.tbz(list, 1, good)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(25), list))?;
        self.set_badarg_mfa(if offset == 0 { 1 } else { 2 })?;
        self.emit_guard_fail(0)?;
        self.code.bind(good)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), list, !7)?;
            e.ldur(output, Gpr::x(10), offset)
        })?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `tuple_size/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1335-1364, OTP-29.1.1
    pub fn emit_bif_tuple_size(
        &mut self,
        fail: u32,
        tuple: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let tuple = self.source_reg(tuple)?;
        let bad = self.code.new_label();
        let ok = self.code.new_label();
        // The argument may be any term: only a boxed tuple has a size.
        self.code.emit(|e| {
            e.and_imm(Gpr::x(12), tuple, 3)?;
            e.cmp_imm(Gpr::x(12), 2, false)
        })?;
        self.code.b_cond(Cond::Ne, bad)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), tuple, !7)?;
            e.ldur(Gpr::x(12), Gpr::x(10), 0)?;
            e.tst_imm(Gpr::x(12), 0x3f)
        })?;
        self.code.b_cond(Cond::Ne, bad)?;
        self.code.emit(|e| {
            e.lsr_imm(output, Gpr::x(12), 2)?;
            e.orr_imm(output, output, 15)
        })?;
        self.code.b(ok)?;
        self.code.bind(bad)?;
        if fail == 0 {
            // Port of instr_guard_bifs.cpp:1310-1321 (emit_bif_tuple_size_body): badarg with
            // erlang:tuple_size/1 as the top frame.
            self.code.emit(|e| e.mov_reg(Gpr::x(25), tuple))?;
            self.set_badarg_mfa(6)?;
        }
        self.emit_guard_fail(fail)?;
        self.code.bind(ok)?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `map_size/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:947-997, OTP-29.1.1
    pub fn emit_bif_map_size(
        &mut self,
        fail: u32,
        map: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bif_map_size_typed(
            fail,
            TypedArg::new(map, ArgType::ANY),
            destination,
            _runtime,
        )
    }

    /// Emits `map_size/1`, eliding checks proven redundant by the `Type` chunk.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:947-997, OTP-29.1.1.
    pub fn emit_bif_map_size_typed(
        &mut self,
        fail: u32,
        map: TypedArg,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let map_reg = self.source_reg(map.val)?;
        let needs_map_check = map.masked_types(type_id::MAYBE_BOXED) != type_id::MAP;
        let needs_box_check = !map.always_one_of(type_id::ALWAYS_BOXED);
        let bad = (needs_map_check || needs_box_check).then(|| self.code.new_label());
        if needs_box_check {
            self.code.tbnz(map_reg, 0, bad.expect("check label"))?;
        }
        if needs_map_check {
            self.code.emit(|e| {
                e.ldur(Gpr::x(12), map_reg, -2)?;
                e.and_imm(Gpr::x(12), Gpr::x(12), 0x3f)?;
                e.cmp_imm(Gpr::x(12), 0x2c, false)
            })?;
            self.code.b_cond(Cond::Ne, bad.expect("check label"))?;
        }
        self.code.emit(|e| {
            e.ldur(Gpr::x(12), map_reg, 6)?;
            e.mov_const(output, 15)?;
            e.bfi(output, Gpr::x(12), 4, 60)
        })?;
        if let Some(bad) = bad {
            let ok = self.code.new_label();
            self.code.b(ok)?;
            self.code.bind(bad)?;
            if fail == 0 {
                // Port of instr_guard_bifs.cpp:938-945 (emit_handle_map_size_error): BADMAP
                // with the map in `fvalue` and erlang:map_size/1 as the top frame.
                self.code.emit(|e| {
                    e.mov_reg(Gpr::x(25), map_reg)?;
                    e.mov_const(Gpr::x(9), EXC_BADMAP)?;
                    e.str_uoff(Gpr::x(9), Gpr::x(21), 40)?;
                    e.str_uoff(Gpr::x(25), Gpr::x(21), 48)
                })?;
                self.set_badarg_mfa(5)?;
                self.branch_error()?;
            } else {
                self.emit_guard_fail(fail)?;
            }
            self.code.bind(ok)?;
        }
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits the body fast path of `is_map_key/2` through the shared map lookup fragment.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:799-830, OTP-29.1.1
    #[allow(clippy::too_many_arguments)]
    pub fn emit_bif_is_map_key(
        &mut self,
        fail: u32,
        key: ArgVal,
        map: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
        exact_map: bool,
        key_maybe_immediate: bool,
        map_runtime: crate::map::MapRuntime,
    ) -> Result<(), ModuleError> {
        if !exact_map {
            let slow = self.code.new_label();
            let done = self.code.new_label();
            self.emit_map_is_key_fast(
                map,
                key,
                destination,
                false,
                key_maybe_immediate,
                Some(slow),
                map_runtime,
            )?;
            self.code.b(done)?;
            self.code.bind(slow)?;
            self.emit_guard_value_helper_fail(fail, true, 30, key, map, destination, helper)?;
            self.code.bind(done)?;
            return Ok(());
        }
        self.emit_map_is_key_fast(
            map,
            key,
            destination,
            true,
            key_maybe_immediate,
            None,
            map_runtime,
        )
    }

    /// Emits `is_map_key/2`, using map and key types to select the shared lookup fragment.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:799-830, OTP-29.1.1.
    pub fn emit_bif_is_map_key_typed(
        &mut self,
        fail: u32,
        key: TypedArg,
        map: TypedArg,
        destination: ArgVal,
        helper: GuardHelper,
        map_runtime: crate::map::MapRuntime,
    ) -> Result<(), ModuleError> {
        if !map.exact_type(type_id::MAP) {
            return self.emit_bif_is_map_key(
                fail,
                key.val,
                map.val,
                destination,
                helper,
                false,
                key.maybe_one_of(type_id::MAYBE_IMMEDIATE),
                map_runtime,
            );
        }

        let output = self.guard_destination(destination)?;
        let map_reg = self.source_reg(map.val)?;
        let key_reg = self.source_reg_into(key.val, Gpr::x(17))?;
        if key.maybe_one_of(type_id::MAYBE_IMMEDIATE) {
            self.code.emit(|e| {
                e.mov_reg(Gpr::x(0), map_reg)?;
                e.mov_reg(Gpr::x(1), key_reg)
            })?;
            self.code
                .emit(|e| e.mov_const(Gpr::x(17), map_runtime.get_element_shared as u64))?;
            self.code.emit(|e| e.blr(Gpr::x(17)))?;
            self.code.emit(|e| {
                e.mov_const(Gpr::x(10), 0x4b)?;
                e.mov_const(Gpr::x(11), 0x0b)?;
                e.csel(output, Gpr::x(10), Gpr::x(11), Cond::Eq)
            })?;
            return self.store_guard_result(destination, output);
        }

        // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:811-819, OTP-29.1.1: the
        // sources go to their own argument registers; x0 is rewritten with `c_p` first.
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(8), map_reg)?;
            e.mov_reg(Gpr::x(9), key_reg)?;
            e.mov_reg(Gpr::x(10), Gpr::xzr())
        })?;
        self.emit_guard_runtime_call(
            map_runtime.get as usize,
            &[Gpr::x(8), Gpr::x(9), Gpr::x(10)],
        )?;
        self.code.emit(|e| {
            e.cmp_imm(Gpr::x(0), 0, false)?;
            e.mov_const(Gpr::x(10), 0x4b)?;
            e.mov_const(Gpr::x(11), 0x0b)?;
            e.csel(output, Gpr::x(10), Gpr::x(11), Cond::Ne)
        })?;
        self.store_guard_result(destination, output)
    }

    /// Emits `map_get/2`: shared-fragment lookup, the runtime hook for a miss or non-map.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:854-936, OTP-29.1.1
    #[allow(clippy::too_many_arguments)]
    pub fn emit_bif_map_get(
        &mut self,
        fail: u32,
        key: ArgVal,
        map: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
        exact_map: bool,
        key_maybe_immediate: bool,
        map_runtime: crate::map::MapRuntime,
    ) -> Result<(), ModuleError> {
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.emit_map_get_fast(
            map,
            key,
            destination,
            slow,
            exact_map,
            key_maybe_immediate,
            map_runtime,
        )?;
        self.code.b(done)?;
        self.code.bind(slow)?;
        self.emit_guard_value_helper_fail(fail, false, 31, key, map, destination, helper)?;
        self.code.bind(done)?;
        Ok(())
    }

    /// Emits `byte_size/1`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:438-520 (emit_bif_byte_size),
    // OTP-29.1.1: the bit size is rounded up to whole bytes.
    pub fn emit_bif_byte_size(
        &mut self,
        fail: u32,
        term: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bitstring_size(fail, term, destination, true)
    }

    /// Emits `bit_size/1`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:382-436 (emit_bif_bit_size),
    // OTP-29.1.1.
    pub fn emit_bif_bit_size(
        &mut self,
        fail: u32,
        term: ArgVal,
        destination: ArgVal,
        _runtime: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_bitstring_size(fail, term, destination, false)
    }

    fn emit_bitstring_size(
        &mut self,
        fail: u32,
        term: ArgVal,
        destination: ArgVal,
        bytes: bool,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let term = self.source_reg(term)?;
        let bad = self.code.new_label();
        let sub = self.code.new_label();
        let size = self.code.new_label();
        let ok = self.code.new_label();
        self.code.emit(|e| {
            e.and_imm(Gpr::x(12), term, 3)?;
            e.cmp_imm(Gpr::x(12), 2, false)
        })?;
        self.code.b_cond(Cond::Ne, bad)?;
        // Heap bits keep their bit size after the header; sub bits keep start and end offsets.
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), term, !7)?;
            e.ldur(Gpr::x(12), Gpr::x(10), 0)?;
            e.and_imm(Gpr::x(13), Gpr::x(12), 63)?;
            e.cmp_imm(Gpr::x(13), 0x24, false)
        })?;
        self.code.b_cond(Cond::Eq, sub)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(13), 0x20, false))?;
        self.code.b_cond(Cond::Ne, bad)?;
        self.code.emit(|e| e.ldur(Gpr::x(14), Gpr::x(10), 8))?;
        self.code.b(size)?;
        self.code.bind(sub)?;
        self.code.emit(|e| {
            e.ldur(Gpr::x(12), Gpr::x(10), 16)?;
            e.ldur(Gpr::x(13), Gpr::x(10), 24)?;
            e.sub_reg(
                Gpr::x(14),
                Gpr::x(13),
                Gpr::x(12),
                arinsal_a64::enc::Shift::Lsl,
                0,
            )
        })?;
        self.code.bind(size)?;
        self.code.emit(|e| {
            if bytes {
                e.add_imm(Gpr::x(14), Gpr::x(14), 7, false)?;
                e.lsr_imm(Gpr::x(14), Gpr::x(14), 3)?;
            }
            e.lsl_imm(Gpr::x(14), Gpr::x(14), 4)?;
            e.orr_imm(output, Gpr::x(14), 15)
        })?;
        self.code.b(ok)?;
        self.code.bind(bad)?;
        if fail == 0 {
            self.code.emit(|e| e.mov_reg(Gpr::x(25), term))?;
            self.set_badarg_mfa(if bytes { 4 } else { 3 })?;
        }
        self.emit_guard_fail(fail)?;
        self.code.bind(ok)?;
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
        fail: u32,
        term: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        self.emit_guard_value_helper_fail(
            fail,
            false,
            39,
            term,
            ArgVal::Immediate(0),
            destination,
            helper,
        )
    }

    /// Emits `length/1` through the runtime hook.
    ///
    /// The `i_length` entry calls `erts_trapping_length_1`. This inlines that
    /// walk for lists that stay under the reduction budget (the trap itself is
    /// a later task): one `is_list` test, then `CDR` at tagged+7.
    // Port of erts/emulator/beam/erl_bif_guard.c:293-296 (erts_trapping_length_1), OTP-29.1.1.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:320-335 (emit_i_length), OTP-29.1.1.
    pub fn emit_bif_length(
        &mut self,
        fail: u32,
        list: ArgVal,
        destination: ArgVal,
        helper: GuardHelper,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let list_reg = self.source_reg(list)?;
        let loop_label = self.code.new_label();
        let not_list = self.code.new_label();
        let slow = self.code.new_label();
        let done = self.code.new_label();
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(11), list_reg)?;
            e.mov_const(Gpr::x(12), 0)
        })?;
        self.code.bind(loop_label)?;
        self.code.emit(|e| {
            e.ands_imm(Gpr::x(8), Gpr::x(11), 3)?;
            e.cmp_imm(Gpr::x(8), 1, false)
        })?;
        self.code.b_cond(Cond::Ne, not_list)?;
        // CDR(list_val(list)): a list tag of 1 puts the tail word at tagged+7.
        self.code.emit(|e| {
            e.ldur(Gpr::x(11), Gpr::x(11), 7)?;
            e.add_imm(Gpr::x(12), Gpr::x(12), 1, false)
        })?;
        self.code.b(loop_label)?;
        self.code.bind(not_list)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(11), 0x3b, false))?;
        self.code.b_cond(Cond::Ne, slow)?;
        self.code.bind(done)?;
        self.code.emit(|e| {
            e.lsl_imm(output, Gpr::x(12), 4)?;
            e.orr_imm(output, output, 15)
        })?;
        self.store_guard_result(destination, output)?;
        let finished = self.code.new_label();
        self.code.b(finished)?;
        self.code.bind(slow)?;
        self.emit_guard_value_helper_fail(
            fail,
            false,
            35,
            list,
            ArgVal::Immediate(0),
            destination,
            helper,
        )?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
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
        let right = self.source_reg_into(rhs, Gpr::x(17))?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.emit_min_max(lhs, rhs, Cond::Lt, 37, destination, helper)
    }

    /// Emits `abs/1` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:246-333, OTP-29.1.1
    pub fn emit_bif_abs(
        &mut self,
        fail: u32,
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
        self.emit_guard_value_helper_fail(
            fail,
            false,
            38,
            value,
            ArgVal::Immediate(0),
            destination,
            helper,
        )?;
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
        (ArgVal::X(_) | ArgVal::XMemory(_) | ArgVal::Y(_), ArgVal::Immediate(word))
            if word & 15 == 15 =>
        {
            Some((lhs, word, false))
        }
        (ArgVal::Immediate(word), ArgVal::X(_) | ArgVal::XMemory(_) | ArgVal::Y(_))
            if word & 15 == 15 =>
        {
            Some((rhs, word, true))
        }
        _ => None,
    }
}
