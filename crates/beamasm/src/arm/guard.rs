//! AArch64 emitters for Erlang guard tests, comparisons, and guard BIFs.

use arinsal_a64::{
    buf::Label,
    enc::{Cond, Gpr, Shifted},
};
use arinsal_term::{
    Term, TermKind,
    raw::{Cons, Tuple, bitstring_extent, term_from_bits},
};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::rt::addr;
use crate::types::{ArgType, TypedArg, type_id};
use crate::{Update, emit_enter_runtime, emit_leave_runtime};

/// Addresses of the process-wide comparison fragments.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompareShared {
    /// `bif_is_eq_exact_shared`: terms in x0/x1, `true` or `false` in x0.
    pub eq_exact: usize,
    /// `bif_is_ne_exact_shared`: terms in x0/x1, `true` or `false` in x0.
    pub ne_exact: usize,
    /// `arith_compare_shared`: terms in x0/x1, the relation in the flags.
    pub arith: usize,
    /// `bif_element_guard_shared`: position in x0, tuple in x1, the element or `THE_NON_VALUE`
    /// in x0.
    pub element_guard: usize,
    /// `is_eq_exact_list_shared`: terms in x0/x1, equality in the Z flag.
    pub eq_exact_list: usize,
    /// C `eq(Eterm, Eterm) -> int` (erts `eq`, utils.c:1125). Non-zero means equal; the general
    /// path of `=:=` / `=/=` calls it directly, so it must be set before emitting those ops.
    pub eq: usize,
}

/// Compile-time shape erts reads from the module's literal word for exact comparisons.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EqLiteral {
    /// No inline shape: the general path decides, as erts does for literals it cannot inline.
    Generic,
    /// A proper list of immediates. `words[i]` is the head of cell `i`; the tail is nil.
    ListOfImmediates(Vec<u64>),
    /// A tuple whose elements are all immediates: its header word, then the element words.
    ShallowTuple { header: u64, elements: Vec<u64> },
    /// `<<>>`.
    EmptyBinary,
    /// `#{}`.
    EmptyMap,
}

/// Classifies the loaded term exactly where erts uses `beamfile_get_literal`.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1366-1392 (beam_jit_is_list_of_immediates,
// beam_jit_is_shallow_boxed), OTP-29.1.1.
fn classify_eq_literal(term: Term) -> EqLiteral {
    let mut current = term;
    let mut words = Vec::new();
    while current != Term::NIL {
        let Ok(cell) = Cons::try_from(current) else {
            words.clear();
            break;
        };
        let head = cell.head();
        if !head.is_immed() {
            words.clear();
            break;
        }
        words.push(head.word());
        current = cell.tail();
    }
    if current == Term::NIL && !words.is_empty() {
        return EqLiteral::ListOfImmediates(words);
    }

    if let Ok(tuple) = Tuple::try_from(term)
        && tuple.arity() <= 4000
    {
        let elements = tuple.elements().collect::<Vec<_>>();
        if elements.iter().all(|value| value.is_immed()) {
            return EqLiteral::ShallowTuple {
                header: (tuple.arity() as u64) << 6,
                elements: elements.into_iter().map(Term::word).collect(),
            };
        }
    }

    if bitstring_extent(term).is_some_and(|(_, bits)| bits == 0) {
        return EqLiteral::EmptyBinary;
    }

    if term.classify() == TermKind::Map
        && term.is_flatmap()
        && term
            .flatmap_keys_tuple()
            .and_then(|keys| Tuple::try_from(keys).ok())
            .is_some_and(|keys| keys.arity() == 0)
    {
        return EqLiteral::EmptyMap;
    }

    EqLiteral::Generic
}

/// Heap bitstring header tags (crates/term/src/lib.rs:120-121, erts `_TAG_HEADER_HEAP_BITS` and
/// `HEADER_SUB_BITS`).
const HEAP_BITS_HEADER: u64 = 0x20;
const SUB_BITS_HEADER: u64 = 0x24;
/// `MAP_HEADER_FLATMAP` (crates/term/src/lib.rs:126, erts `erl_map.h:185`).
const MAP_HEADER_FLATMAP: u64 = 0x12c;
/// The empty list / `[]` immediate word.
const NIL_WORD: u64 = 0x3b;

/// Index of `erlang:map_size/1` in the guard BIF MFA table.
pub const MAP_SIZE_MFA_INDEX: u8 = 5;
/// Index of `erlang:map_get/2` in the guard BIF MFA table.
pub const MAP_GET_MFA_INDEX: u8 = 7;
/// Index of `erlang:length/1` in the guard BIF MFA table.
pub const LENGTH_MFA_INDEX: u8 = 8;
/// `freason` of a missing key in exact map update: `{badkey, Key}` (erts `EXC_BADKEY`).
// Port of erts/emulator/beam/error.h:168, OTP-29.1.1.
pub use crate::exc::EXC_BADKEY;
/// `freason` of an inline `map_size/1` failure: `{badmap, Value}` (erts `EXC_BADMAP`).
pub use crate::exc::EXC_BADMAP;

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

fn arity_header(value: ArgVal) -> Result<u64, ModuleError> {
    match value {
        ArgVal::Immediate(header) => Ok(header),
        _ => Err(ModuleError::InvalidOperand(
            "tuple arity must be a make_arityval immediate",
        )),
    }
}

impl BeamModuleAssembler {
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
        let src = if matches!(op, InlineType::NonemptyList | InlineType::Nil) {
            self.load_source_any(source.val, Gpr::x(8), &[])?
        } else {
            self.source_reg_into(source.val, Gpr::x(11))?
        };
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
            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1121-1129 and beam_asm.hpp:1163-1167
            // (emit_is_nonempty_list, emit_is_cons: preserve_cache), OTP-29.1.1.
            InlineType::NonemptyList => {
                self.preserve_cache(&[], |this| Ok(this.code.tbnz(src, 1, fail)?))?
            }
            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1389-1401 (emit_is_nil),
            // OTP-29.1.1.
            InlineType::Nil => {
                if source.always_one_of(type_id::CONS | type_id::NIL) {
                    self.preserve_cache(&[], |this| Ok(this.code.tbz(src, 1, fail)?))?;
                } else {
                    self.preserve_cache(&[], |this| {
                        this.code.emit(|e| e.cmp_imm(src, 0x3b, false))?;
                        this.code.b_cond(Cond::Ne, fail)?;
                        Ok(())
                    })?;
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
                let header = arity_header(
                    second.ok_or(ModuleError::InvalidOperand("arity operand required"))?,
                )?;
                self.code.emit(|e| e.and_imm(Gpr::x(0), src, !7))?;
                self.code.emit(|e| e.ldr_uoff(tmp1, Gpr::x(0), 0))?;
                self.emit_cmp_constant(tmp1, header, Gpr::x(14))?;
                self.code.b_cond(Cond::Ne, fail)?;
            }
            InlineType::TaggedTuple => {
                let header = arity_header(
                    second.ok_or(ModuleError::InvalidOperand("arity operand required"))?,
                )?;
                let tag = third.ok_or(ModuleError::InvalidOperand("tag operand required"))?;
                self.emit_boxed_check(source, src, fail)?;
                self.code.emit(|e| e.and_imm(Gpr::x(0), src, !7))?;
                self.code.emit(|e| e.ldp(tmp1, tmp2, Gpr::x(0), 0))?;
                let tag_reg = self.source_reg_into(tag, Gpr::x(14))?;
                self.code
                    .emit(|e| e.cmp_reg(tmp2, tag_reg, arinsal_a64::enc::Shift::Lsl, 0))?;
                self.code.emit(|e| e.mov_const(tmp3, header))?;
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
                // HEADER_SUB_BITS = _make_header(ERL_SUB_BITS_SIZE-1, _TAG_HEADER_SUB_BITS).
                // The bare subtag 0x24 never matches a live sub-binary (header 0x124), so the
                // size would be taken from base_flags and a byte-aligned slice would fail.
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1196-1204, OTP-29.1.1.
                self.code.emit(|e| e.cmp_imm(tmp1, 0x124, false))?;
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
        // The caller tests the result (`cmp ARG1, am_true` / THE_NON_VALUE), as each erts
        // emitter does after `runtime_call`.
        self.code.emit(|e| e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72))?;
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

    pub(super) fn guard_destination(&mut self, destination: ArgVal) -> Result<Gpr, ModuleError> {
        match destination {
            ArgVal::X(index) if index < 6 => Ok([
                Gpr::x(25),
                Gpr::x(26),
                Gpr::x(27),
                Gpr::x(28),
                Gpr::x(10 + 5),
                Gpr::x(10 + 6),
            ][index as usize]),
            ArgVal::Y(_) | ArgVal::X(_) => Ok(Gpr::x(17)),
            _ => Err(ModuleError::InvalidOperand(
                "guard BIF destination must be X or Y",
            )),
        }
    }

    pub(super) fn store_guard_result(
        &mut self,
        destination: ArgVal,
        result: Gpr,
    ) -> Result<(), ModuleError> {
        match destination {
            ArgVal::X(index) if index < 6 => {
                let target = self.guard_destination(destination)?;
                if target != result {
                    self.code.emit(|e| e.mov_reg(target, result))?;
                }
            }
            ArgVal::Y(_) | ArgVal::X(_) => self.store_operand(destination, result)?,
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "guard BIF destination must be X or Y",
                ));
            }
        }
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
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1611-1664 (emit_i_is_tuple_of_arity,
    // emit_i_is_tuple_of_arity_ff), OTP-29.1.1. The arity operand is the loader's small
    // integer transformed to `make_arityval`; compare the header word directly.
    pub fn emit_is_tuple_of_arity(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        not_tuple: u32,
        bad_arity: u32,
    ) -> Result<(), ModuleError> {
        let source = src.into();
        let header = arity_header(arity)?;
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
        let header = arity_header(arity)?;
        self.emit_boxed_check(source, src_reg, not_tuple)?;
        self.code.emit(|e| e.and_imm(Gpr::x(0), src_reg, !7))?;
        self.code
            .emit(|e| e.ldp(Gpr::x(8), Gpr::x(9), Gpr::x(0), 0))?;
        let correct_arity = self.code.new_label();
        self.emit_cmp_constant(Gpr::x(8), header, Gpr::x(14))?;
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

    /// Emits `is_function2` with a non-literal arity: `erl_is_function` decides.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1263-1283 (emit_is_function2,
    // `!Arity.isSmall()`), OTP-29.1.1.
    pub fn emit_is_function2_dynamic(
        &mut self,
        src: impl Into<TypedArg>,
        arity: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        let src = src.into();
        if TypedArg::from(arity).is_small() {
            return self.emit_is_function2_guard(src, arity, fail);
        }
        let source = self.source_reg(src.val)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(8), source))?;
        let arity = self.source_reg_into(arity, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(9), arity))?;
        self.emit_guard_runtime_call(
            addr(crate::rt::erl_is_function as *const ()),
            &[Gpr::x(8), Gpr::x(9)],
        )?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0x4b, false))?;
        let fail = self.label(fail);
        self.code.b_cond(Cond::Ne, fail)?;
        Ok(())
    }

    /// Emits an exact equality guard; `eq` is the C `eq` helper (`CompareShared::eq`).
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1751-1898 (emit_is_eq_exact),
    // OTP-29.1.1.
    pub fn emit_is_eq_exact(
        &mut self,
        lhs: impl Into<TypedArg>,
        rhs: impl Into<TypedArg>,
        fail: u32,
        eq: usize,
    ) -> Result<(), ModuleError> {
        self.emit_exact_eq(lhs.into(), rhs.into(), fail, eq, false)
    }

    /// Emits an exact inequality guard; see [`Self::emit_is_eq_exact`].
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1900-2053 (emit_is_ne_exact),
    // OTP-29.1.1.
    pub fn emit_is_ne_exact(
        &mut self,
        lhs: impl Into<TypedArg>,
        rhs: impl Into<TypedArg>,
        fail: u32,
        eq: usize,
    ) -> Result<(), ModuleError> {
        self.emit_exact_eq(lhs.into(), rhs.into(), fail, eq, true)
    }

    /// Shared body of `=:=` (`fail_on_equal == false`) and `=/=`.
    fn emit_exact_eq(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        fail: u32,
        eq: usize,
        fail_on_equal: bool,
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1844-1856 and 2001-2013
        // (always_immediate cmp_arg), OTP-29.1.1.
        if lhs.always_immediate() || rhs.always_immediate() {
            return self.emit_exact_immediate_guard(lhs, rhs, fail, fail_on_equal);
        }
        if let Some((term, value)) = self.exact_immediate_operand(lhs.val, rhs.val) {
            let word = TypedArg {
                val: ArgVal::Immediate(value),
                ..rhs
            };
            let term = TypedArg { val: term, ..lhs };
            return self.emit_exact_immediate_guard(term, word, fail, fail_on_equal);
        }
        if let ArgVal::Literal(index) = rhs.val {
            let literal = classify_eq_literal(term_from_bits(self.beamfile_get_literal(index)));
            if literal != EqLiteral::Generic {
                return self.emit_literal_exact_eq(lhs.val, rhs.val, &literal, fail, fail_on_equal);
            }
        }
        // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1857-1897 (general path of
        // emit_is_eq_exact), OTP-29.1.1: compare the words, then call `eq` for the rest.
        let left = self.source_reg(lhs.val)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(11), left))?;
        let right = self.source_reg_into(rhs.val, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(12), right))?;
        self.code
            .emit(|e| e.cmp_reg(Gpr::x(11), Gpr::x(12), arinsal_a64::enc::Shift::Lsl, 0))?;
        let done = self.code.new_label();
        let fail_label = self.label(fail);
        // Same word: `=:=` holds and `=/=` fails.
        self.code
            .b_cond(Cond::Eq, if fail_on_equal { fail_label } else { done })?;
        // Port of erts/emulator/beam/jit/beam_asm.hpp:1941-1955 (emit_are_both_immediate),
        // OTP-29.1.1. Two different immediates are never exactly equal.
        let both = Shifted {
            reg: Gpr::x(12),
            shift: arinsal_a64::enc::Shift::Lsl,
            amount: 0,
        };
        self.code.emit(|e| {
            e.and_reg(Gpr::x(8), Gpr::x(11), both)?;
            e.and_imm(Gpr::x(8), Gpr::x(8), 3)?;
            e.cmp_imm(Gpr::x(8), 3, false)
        })?;
        self.code
            .b_cond(Cond::Eq, if fail_on_equal { done } else { fail_label })?;
        self.emit_exact_eq_call(eq)?;
        // `eq` returns non-zero when the terms are equal.
        if fail_on_equal {
            self.code.cbnz(Gpr::x(0), fail_label)?;
        } else {
            self.code.cbz(Gpr::x(0), fail_label)?;
        }
        self.code.bind(done)?;
        Ok(())
    }

    /// Calls the C `eq(Eterm, Eterm)` on x11/x12 and leaves its result in x0 (zero extended).
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1866-1875 (emit_enter_runtime,
    // runtime_call<eq>, emit_leave_runtime), OTP-29.1.1. No process state is published, as in
    // erts, but the caller's live X registers are not known here, so X4 and X5 are kept like
    // erts does with its default live count of six.
    fn emit_exact_eq_call(&mut self, eq: usize) -> Result<(), ModuleError> {
        if eq == 0 {
            return Err(ModuleError::InvalidOperand(
                "the eq helper is not installed for exact comparisons",
            ));
        }
        emit_enter_runtime(&mut self.code, 6, Update::NONE)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::x(11))?;
            e.mov_reg(Gpr::x(1), Gpr::x(12))?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.mov_const(Gpr::x(17), eq as u64)?;
            e.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(&mut self.code, 6, Update::NONE)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            // `eq` returns a C int: only the low word of x0 is defined.
            e.and_imm(Gpr::x(0), Gpr::x(0), 0xffff_ffff)
        })?;
        Ok(())
    }

    /// Inline match of a literal shape against `lhs`. The mismatch branch goes to `fail` for
    /// `=:=`; for `=/=` a full match jumps to `fail` and a mismatch falls through.
    fn emit_literal_exact_eq(
        &mut self,
        lhs: ArgVal,
        rhs: ArgVal,
        literal: &EqLiteral,
        fail: u32,
        fail_on_equal: bool,
    ) -> Result<(), ModuleError> {
        let fail_label = self.label(fail);
        let mismatch = if fail_on_equal {
            self.code.new_label()
        } else {
            fail_label
        };
        let value = self.source_reg(lhs)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(11), value))?;
        match literal {
            EqLiteral::Generic => {
                return Err(ModuleError::InvalidOperand(
                    "a generic literal has no inline shape",
                ));
            }
            EqLiteral::ListOfImmediates(words) => {
                if words.is_empty() {
                    return Err(ModuleError::InvalidOperand(
                        "an empty list literal is nil, not a list shape",
                    ));
                }
                if words.len() > 1 && self.eq_exact_list_shared != 0 {
                    let right = self.source_reg_into(rhs, Gpr::x(17))?;
                    self.code.emit(|e| {
                        e.mov_reg(Gpr::x(0), value)?;
                        e.mov_reg(Gpr::x(1), right)
                    })?;
                    self.fragment_call(self.eq_exact_list_shared)?;
                    self.code
                        .b_cond(if fail_on_equal { Cond::Eq } else { Cond::Ne }, fail_label)?;
                    return Ok(());
                }
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1756-1770 (inlined list
                // test), OTP-29.1.1: the one-element list test compares its head and nil tail.
                self.emit_tag_check_and_untag(1, mismatch)?;
                for (index, word) in words.iter().enumerate() {
                    self.code.emit(|e| e.ldr_uoff(Gpr::x(13), Gpr::x(12), 0))?;
                    self.emit_word_match(*word, mismatch)?;
                    self.code.emit(|e| e.ldr_uoff(Gpr::x(13), Gpr::x(12), 8))?;
                    if index + 1 < words.len() {
                        self.emit_tag_check_on_x13(1, mismatch)?;
                    } else {
                        self.emit_word_match(NIL_WORD, mismatch)?;
                    }
                }
            }
            EqLiteral::ShallowTuple { header, elements } => {
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1772-1790 and
                // is_eq_exact_shallow_boxed_shared, OTP-29.1.1: the boxed header and every
                // element word must match.
                self.emit_tag_check_and_untag(2, mismatch)?;
                let header_and_elements = std::iter::once(*header).chain(elements.iter().copied());
                for (index, word) in header_and_elements.enumerate() {
                    let offset = (index * 8) as u32;
                    self.code
                        .emit(|e| e.ldr_uoff(Gpr::x(13), Gpr::x(12), offset))?;
                    self.emit_word_match(word, mismatch)?;
                }
            }
            EqLiteral::EmptyBinary => {
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1792-1827 (empty binary
                // test), OTP-29.1.1: a heap bitstring has size 0 in word 1, a sub-bitstring
                // has start == end in words 2 and 3.
                self.emit_tag_check_and_untag(2, mismatch)?;
                let sub_bits = self.code.new_label();
                let done = self.code.new_label();
                self.code.emit(|e| e.ldr_uoff(Gpr::x(13), Gpr::x(12), 0))?;
                self.code.emit(|e| e.and_imm(Gpr::x(13), Gpr::x(13), 63))?;
                self.code
                    .emit(|e| e.cmp_imm(Gpr::x(13), SUB_BITS_HEADER as u16, false))?;
                self.code.b_cond(Cond::Eq, sub_bits)?;
                self.code
                    .emit(|e| e.cmp_imm(Gpr::x(13), HEAP_BITS_HEADER as u16, false))?;
                self.code.b_cond(Cond::Ne, mismatch)?;
                self.code.emit(|e| e.ldr_uoff(Gpr::x(13), Gpr::x(12), 8))?;
                self.code.cbnz(Gpr::x(13), mismatch)?;
                self.code.b(done)?;
                self.code.bind(sub_bits)?;
                self.code.emit(|e| e.ldr_uoff(Gpr::x(13), Gpr::x(12), 16))?;
                self.code.emit(|e| e.ldr_uoff(Gpr::x(14), Gpr::x(12), 24))?;
                self.code
                    .emit(|e| e.cmp_reg(Gpr::x(13), Gpr::x(14), arinsal_a64::enc::Shift::Lsl, 0))?;
                self.code.b_cond(Cond::Ne, mismatch)?;
                self.code.bind(done)?;
            }
            EqLiteral::EmptyMap => {
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1828-1846 (empty map
                // test), OTP-29.1.1: a flatmap header with a zero size word.
                self.emit_tag_check_and_untag(2, mismatch)?;
                self.code.emit(|e| e.ldr_uoff(Gpr::x(13), Gpr::x(12), 0))?;
                self.emit_word_match(MAP_HEADER_FLATMAP, mismatch)?;
                self.code.emit(|e| e.ldr_uoff(Gpr::x(13), Gpr::x(12), 8))?;
                self.code.cbnz(Gpr::x(13), mismatch)?;
            }
        }
        if fail_on_equal {
            self.code.b(fail_label)?;
            self.code.bind(mismatch)?;
        }
        Ok(())
    }

    /// Checks the primary tag of x11 and untags it into x12.
    fn emit_tag_check_and_untag(&mut self, tag: u16, mismatch: Label) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.and_imm(Gpr::x(8), Gpr::x(11), 3)?;
            e.cmp_imm(Gpr::x(8), tag, false)
        })?;
        self.code.b_cond(Cond::Ne, mismatch)?;
        self.code
            .emit(|e| e.and_imm(Gpr::x(12), Gpr::x(11), !7_u64))?;
        Ok(())
    }

    /// Checks the primary tag of x13 (the next cell) and untags it into x12.
    fn emit_tag_check_on_x13(&mut self, tag: u16, mismatch: Label) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.and_imm(Gpr::x(8), Gpr::x(13), 3)?;
            e.cmp_imm(Gpr::x(8), tag, false)
        })?;
        self.code.b_cond(Cond::Ne, mismatch)?;
        self.code
            .emit(|e| e.and_imm(Gpr::x(12), Gpr::x(13), !7_u64))?;
        Ok(())
    }

    /// Branches to `mismatch` unless x13 holds `word`.
    fn emit_word_match(&mut self, word: u64, mismatch: Label) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.mov_const(Gpr::x(14), word)?;
            e.cmp_reg(Gpr::x(13), Gpr::x(14), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Ne, mismatch)?;
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1844-1856 and 2001-2013
    // (always_immediate cmp_arg), OTP-29.1.1. `fail_on_equal` selects `=/=`.
    fn emit_exact_immediate_guard(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        fail: u32,
        fail_on_equal: bool,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg_into(lhs.val, Gpr::x(0))?;
        let fail = self.label(fail);
        self.preserve_cache(&[], |this| {
            this.cmp_arg(left, rhs.val)?;
            this.code
                .b_cond(if fail_on_equal { Cond::Eq } else { Cond::Ne }, fail)?;
            Ok(())
        })
    }

    /// Compares a register with a signed constant: `cmp` or `cmn` with a 12-bit immediate,
    /// otherwise through the super temporary.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:795-806 (cmp), OTP-29.1.1.
    pub(super) fn cmp_signed(&mut self, reg: Gpr, value: i64) -> Result<(), ModuleError> {
        if (0..=4095).contains(&value) {
            self.code.emit(|e| e.cmp_imm(reg, value as u16, false))?;
        } else if (-4095..0).contains(&value) {
            self.code.emit(|e| e.cmn_imm(reg, (-value) as u16, false))?;
        } else {
            self.mov_value(Gpr::x(17), value as u64)?;
            self.code
                .emit(|e| e.cmp_reg(reg, Gpr::x(17), arinsal_a64::enc::Shift::Lsl, 0))?;
        }
        Ok(())
    }

    /// Compares a register with an immediate or with any other source operand.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1777-1790 (cmp_arg), OTP-29.1.1.
    pub(super) fn cmp_arg(&mut self, reg: Gpr, arg: ArgVal) -> Result<(), ModuleError> {
        if let ArgVal::Immediate(word) = arg {
            return self.cmp_signed(reg, word as i64);
        }
        let other = self.source_reg_into(arg, Gpr::x(17))?;
        self.code
            .emit(|e| e.cmp_reg(reg, other, arinsal_a64::enc::Shift::Lsl, 0))?;
        Ok(())
    }

    /// Emits a loose equality guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_eq), OTP-29.1.1.
    pub fn emit_is_eq(
        &mut self,
        lhs: impl Into<TypedArg>,
        rhs: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_is_eq_shared(lhs.into(), rhs.into(), fail)
    }

    /// Emits a loose inequality guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_ne), OTP-29.1.1.
    pub fn emit_is_ne(
        &mut self,
        lhs: impl Into<TypedArg>,
        rhs: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_is_ne_shared(lhs.into(), rhs.into(), fail)
    }

    /// Emits a less-than guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_lt), OTP-29.1.1.
    pub fn emit_is_lt(
        &mut self,
        lhs: impl Into<TypedArg>,
        rhs: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_is_lt_shared(lhs.into(), rhs.into(), fail)
    }

    /// Emits a greater-or-equal guard.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_ge), OTP-29.1.1.
    pub fn emit_is_ge(
        &mut self,
        lhs: impl Into<TypedArg>,
        rhs: impl Into<TypedArg>,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_is_ge_shared(lhs.into(), rhs.into(), fail)
    }

    /// Emits `is_int_ge`: fails unless the source is an integer not below `min`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_int_ge), OTP-29.1.1.
    pub fn emit_is_int_ge(
        &mut self,
        src: TypedArg,
        min: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_is_int_ge_shared(src, min, fail)
    }

    /// Emits `is_int_in_range`: fails unless the source is a small integer in `min..=max`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_int_in_range), OTP-29.1.1.
    pub fn emit_is_int_in_range(
        &mut self,
        src: TypedArg,
        min: ArgVal,
        max: ArgVal,
        fail: u32,
    ) -> Result<(), ModuleError> {
        self.emit_is_int_in_range_shared(src, min, max, fail)
    }

    /// Emits a value-producing comparison BIF (`bif_is_eq_exact`, `bif_is_ne_exact`,
    /// `bif_is_lt`, `bif_is_ge`; `op` is the runtime helper's operation code 19, 20, 23 or 24)
    /// into its decoded destination.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:157-262 (emit_bif_is_eq_exact,
    // emit_bif_is_ne_exact, emit_bif_is_ge_lt, emit_bif_is_ge, emit_bif_is_lt), OTP-29.1.1.
    pub fn emit_bif_compare(
        &mut self,
        op: u32,
        lhs: TypedArg,
        rhs: TypedArg,
        destination: ArgVal,
        shared: CompareShared,
    ) -> Result<(), ModuleError> {
        match op {
            19 | 20 => {
                let cc = if op == 19 { Cond::Eq } else { Cond::Ne };
                if lhs.always_immediate() || rhs.always_immediate() {
                    return self.emit_cmp_immed_to_bool(cc, lhs, rhs, destination);
                }
                // Port of instr_guard_bifs.cpp:165-174 and 185-194, OTP-29.1.1.
                let fragment = if op == 19 {
                    shared.eq_exact
                } else {
                    shared.ne_exact
                };
                let left = self.source_reg_into(lhs.val, Gpr::x(11))?;
                let right = self.source_reg_into(rhs.val, Gpr::x(12))?;
                self.code.emit(|e| {
                    e.mov_reg(Gpr::x(0), left)?;
                    e.mov_reg(Gpr::x(1), right)
                })?;
                self.fragment_call(fragment)?;
                let dst = self.guard_destination(destination)?;
                self.code.emit(|e| e.mov_reg(dst, Gpr::x(0)))?;
                self.store_guard_result(destination, dst)
            }
            24 => {
                // Port of instr_guard_bifs.cpp:238-256 (emit_bif_is_ge).
                if lhs.always_small() && rhs.is_small() {
                    let left = self.source_reg_into(lhs.val, Gpr::x(11))?;
                    self.emit_cmp_immediate_or_register(left, rhs.word())?;
                    return self.emit_cond_to_bool(Cond::Ge, destination);
                } else if lhs.is_small() && rhs.always_small() {
                    let right = self.source_reg_into(rhs.val, Gpr::x(11))?;
                    self.emit_cmp_immediate_or_register(right, lhs.word())?;
                    return self.emit_cond_to_bool(Cond::Le, destination);
                }
                self.emit_bif_is_ge_lt(Cond::Ge, lhs, rhs, destination, shared.arith)
            }
            23 => self.emit_bif_is_ge_lt(Cond::Lt, lhs, rhs, destination, shared.arith),
            _ => Err(ModuleError::InvalidOperand("unknown comparison BIF")),
        }
    }

    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:135-142 (emit_cond_to_bool),
    // OTP-29.1.1.
    fn emit_cond_to_bool(&mut self, cc: Cond, destination: ArgVal) -> Result<(), ModuleError> {
        let dst = self.guard_destination(destination)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(10), 0x4b)?;
            e.mov_const(Gpr::x(11), 0x0b)?;
            e.csel(dst, Gpr::x(10), Gpr::x(11), cc)
        })?;
        self.store_guard_result(destination, dst)
    }

    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:144-155
    // (emit_cmp_immed_to_bool), OTP-29.1.1.
    fn emit_cmp_immed_to_bool(
        &mut self,
        cc: Cond,
        lhs: TypedArg,
        rhs: TypedArg,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        if rhs.is_immed() {
            let left = self.source_reg_into(lhs.val, Gpr::x(11))?;
            self.emit_cmp_immediate_or_register(left, rhs.word())?;
        } else {
            let left = self.source_reg_into(lhs.val, Gpr::x(11))?;
            let right = self.source_reg_into(rhs.val, Gpr::x(12))?;
            self.code
                .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        }
        self.emit_cond_to_bool(cc, destination)
    }

    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:196-236 (emit_bif_is_ge_lt),
    // OTP-29.1.1. The generic path calls `arith_compare_shared`, which leaves the relation
    // in the flags for `emit_cond_to_bool`.
    fn emit_bif_is_ge_lt(
        &mut self,
        cc: Cond,
        lhs: TypedArg,
        rhs: TypedArg,
        destination: ArgVal,
        arith_compare_shared: usize,
    ) -> Result<(), ModuleError> {
        let left = self.source_reg_into(lhs.val, Gpr::x(11))?;
        let right = self.source_reg_into(rhs.val, Gpr::x(12))?;
        let generic = self.code.new_label();
        let next = self.code.new_label();
        let int_or_boxed = type_id::INTEGER | type_id::ALWAYS_BOXED;
        let both = Shifted {
            reg: right,
            shift: arinsal_a64::enc::Shift::Lsl,
            amount: 0,
        };
        if lhs.always_one_of(int_or_boxed) && rhs.always_one_of(int_or_boxed) {
            // The only possible immediate is a small, so testing for boxed tests for small.
            if lhs.always_small() {
                self.code.tbz(right, 0, generic)?;
            } else if rhs.always_small() {
                self.code.tbz(left, 0, generic)?;
            } else {
                self.code.emit(|e| e.and_reg(Gpr::x(8), left, both))?;
                self.code.tbz(Gpr::x(8), 0, generic)?;
            }
        } else {
            if rhs.always_small() {
                self.code.emit(|e| e.and_imm(Gpr::x(8), left, 15))?;
            } else if lhs.always_small() {
                self.code.emit(|e| e.and_imm(Gpr::x(8), right, 15))?;
            } else {
                self.code.emit(|e| {
                    e.and_reg(Gpr::x(8), left, both)?;
                    e.and_imm(Gpr::x(8), Gpr::x(8), 15)
                })?;
            }
            self.code.emit(|e| e.cmp_imm(Gpr::x(8), 15, false))?;
            self.code.b_cond(Cond::Ne, generic)?;
        }
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b(next)?;
        self.code.bind(generic)?;
        self.code
            .emit(|e| e.cmp_reg(left, right, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Eq, next)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), left)?;
            e.mov_reg(Gpr::x(1), right)
        })?;
        self.fragment_call(arith_compare_shared)?;
        self.code.bind(next)?;
        self.emit_cond_to_bool(cc, destination)
    }

    /// Emits the `element/2` BIF.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_bif_element), OTP-29.1.1.
    // Without the process-wide `bif_element_guard_shared` fragment the whole test stays inline.
    pub fn emit_bif_element(
        &mut self,
        fail: u32,
        index: impl Into<TypedArg>,
        tuple: impl Into<TypedArg>,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        let (index, tuple) = (index.into(), tuple.into());
        if self.element_guard_shared != 0 {
            return self.emit_bif_element_shared(fail, index, tuple, destination);
        }
        self.emit_bif_element_inline(fail, index.val, tuple.val, destination)
    }

    /// Emits `element/2` without the shared fragment (assemblers without a VM).
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:522-543 (emit_bif_element_helper)
    // and 579-767 (emit_bif_element), OTP-29.1.1: a non-tuple, a non-small or non-positive
    // position, or a position past the arity fails (branch to `fail`, or badarg).
    fn emit_bif_element_inline(
        &mut self,
        fail: u32,
        index: ArgVal,
        tuple: ArgVal,
        destination: ArgVal,
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
        }
        let mfa = if fail == 0 { self.guard_mfa(0)? } else { 0 };
        self.emit_guard_fail(fail, mfa)?;
        self.code.bind(ok)?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// `emit_raise_badarg(&mfa)` of a guard BIF without a failure label: the operands go to X0
    /// (and X1), `freason = BADARG`, and `handle_error` names `mfa` with those registers.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp (emit_raise_badarg) and
    // instr_guard_bifs.cpp (emit_bif_not, emit_bif_and, emit_bif_or), OTP-29.1.1.
    pub(super) fn emit_raise_badarg(
        &mut self,
        mfa_index: u64,
        operands: &[Gpr],
    ) -> Result<(), ModuleError> {
        let mfa = crate::bif::guard_bif_mfa(mfa_index as usize)
            .ok_or(ModuleError::InvalidOperand("guard BIF MFA index"))?;
        let x_regs = [Gpr::x(25), Gpr::x(26)];
        if operands.len() > x_regs.len() {
            return Err(ModuleError::InvalidOperand("guard BIF arity"));
        }
        self.code.emit(|e| {
            // X1 first: a second operand may live in X0's machine register.
            for (target, source) in x_regs.iter().zip(operands).rev() {
                if target != source {
                    e.mov_reg(*target, *source)?;
                }
            }
            e.mov_const(Gpr::x(9), crate::exc::EXC_BADARG)?;
            e.str_uoff(Gpr::x(9), Gpr::x(21), 40)
        })?;
        self.branch_error_with_mfa(mfa)
    }

    /// The `ErtsCodeMFA` of guard BIF `index`, embedded as erts' `emit_raise_exception(&mfa)`
    /// constant.
    pub(super) fn guard_mfa(&self, index: u64) -> Result<usize, ModuleError> {
        let index = usize::try_from(index)
            .map_err(|_| ModuleError::InvalidOperand("guard BIF MFA index"))?;
        crate::bif::guard_bif_mfa(index).ok_or(ModuleError::InvalidOperand("guard BIF MFA index"))
    }

    /// Emits `hd/1`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:768-797, OTP-29.1.1: anything
    // but a cons cell raises badarg.
    pub fn emit_bif_hd(&mut self, list: ArgVal, destination: ArgVal) -> Result<(), ModuleError> {
        self.emit_cons_field(list, destination, 0)
    }

    /// Emits `tl/1`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1261-1290, OTP-29.1.1.
    pub fn emit_bif_tl(&mut self, list: ArgVal, destination: ArgVal) -> Result<(), ModuleError> {
        self.emit_cons_field(list, destination, 8)
    }

    fn emit_cons_field(
        &mut self,
        list: ArgVal,
        destination: ArgVal,
        offset: i16,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let list = self.source_reg(list)?;
        let good = self.code.new_label();
        // A cons cell has primary tag 0b01; boxed, immediate and header words all have bit 1 set.
        self.code.tbz(list, 1, good)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(25), list))?;
        let mfa = self.guard_mfa(if offset == 0 { 1 } else { 2 })?;
        self.emit_guard_fail(0, mfa)?;
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
        }
        let mfa = if fail == 0 { self.guard_mfa(6)? } else { 0 };
        self.emit_guard_fail(fail, mfa)?;
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
    ) -> Result<(), ModuleError> {
        self.emit_bif_map_size_typed(fail, TypedArg::new(map, ArgType::ANY), destination)
    }

    /// Emits `map_size/1`, eliding checks proven redundant by the `Type` chunk.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:947-997, OTP-29.1.1.
    pub fn emit_bif_map_size_typed(
        &mut self,
        fail: u32,
        map: TypedArg,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        let map_reg = self.source_reg(map.val)?;
        let needs_map_check = map.masked_types(type_id::MAYBE_BOXED) != type_id::MAP;
        let needs_box_check = !map.always_one_of(type_id::ALWAYS_BOXED);
        if (needs_map_check || needs_box_check)
            && let Some((_, _, size_error)) = self.map_error_fragments
        {
            // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_bif_map_size), OTP-29.1.1: a
            // failing guard branches to its label from the tests, the error path is a call of
            // `handle_map_size_error` with the argument in XREG0.
            let good = self.code.new_label();
            let bad = if fail != 0 {
                self.label(fail)
            } else {
                self.code.new_label()
            };
            if needs_box_check {
                if !needs_map_check && fail == 0 {
                    self.code.tbz(map_reg, 0, good)?;
                } else {
                    self.code.tbnz(map_reg, 0, bad)?;
                }
            }
            if needs_map_check {
                self.code.emit(|e| {
                    e.ldur(Gpr::x(12), map_reg, -2)?;
                    e.and_imm(Gpr::x(12), Gpr::x(12), 0x3f)?;
                    e.cmp_imm(Gpr::x(12), 0x2c, false)
                })?;
                self.code.b_cond(
                    if fail == 0 { Cond::Eq } else { Cond::Ne },
                    if fail == 0 { good } else { bad },
                )?;
            }
            if fail == 0 {
                self.code.bind(bad)?;
                if map_reg != Gpr::x(25) {
                    self.code.emit(|e| e.mov_reg(Gpr::x(25), map_reg))?;
                }
                self.fragment_call(size_error)?;
            }
            self.code.bind(good)?;
            self.code.emit(|e| {
                e.ldur(Gpr::x(12), map_reg, 6)?;
                e.mov_const(output, 15)?;
                e.bfi(output, Gpr::x(12), 4, 60)
            })?;
            return self.store_guard_result(destination, output);
        }
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
                let mfa = self.guard_mfa(5)?;
                self.branch_error_with_mfa(mfa)?;
            } else {
                self.emit_guard_fail(fail, 0)?;
            }
            self.code.bind(ok)?;
        }
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits the inlined `is_map_key/2` for a source known to be a map. Any other source is
    /// the `i_bif2` call of the loader (`emit_bif_by_identity`).
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:799-825 (emit_bif_is_map_key),
    // OTP-29.1.1.
    pub fn emit_bif_is_map_key_typed(
        &mut self,
        key: TypedArg,
        map: TypedArg,
        destination: ArgVal,
        map_runtime: crate::map::MapRuntime,
    ) -> Result<(), ModuleError> {
        if !map.exact_type(type_id::MAP) {
            return Err(ModuleError::InvalidOperand(
                "is_map_key/2 on a source not known to be a map is an i_bif2 call",
            ));
        }
        let output = self.guard_destination(destination)?;
        let map_reg = self.source_reg(map.val)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(0), map_reg))?;
        let key_reg = self.source_reg_into(key.val, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), key_reg))?;
        if key.maybe_one_of(type_id::MAYBE_IMMEDIATE) {
            self.fragment_call(map_runtime.get_element_shared)?;
            self.code.emit(|e| {
                e.mov_const(Gpr::x(10), 0x4b)?;
                e.mov_const(Gpr::x(11), 0x0b)?;
                e.csel(output, Gpr::x(10), Gpr::x(11), Cond::Eq)
            })?;
            return self.store_guard_result(destination, output);
        }
        self.emit_get_map_element_call(addr(crate::rt::get_map_element as *const ()))?;
        self.code.emit(|e| {
            e.cmp_imm(Gpr::x(0), 0, false)?;
            e.mov_const(Gpr::x(10), 0x4b)?;
            e.mov_const(Gpr::x(11), 0x0b)?;
            e.csel(output, Gpr::x(10), Gpr::x(11), Cond::Ne)
        })?;
        self.store_guard_result(destination, output)
    }

    /// Emits `map_get/2`: a failing guard branches to its label, a failing body call raises
    /// through the process-wide `handle_map_get_badmap` / `handle_map_get_badkey` fragments.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:854-936 (emit_bif_map_get),
    // OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_bif_map_get(
        &mut self,
        fail: u32,
        key: ArgVal,
        map: ArgVal,
        destination: ArgVal,
        exact_map: bool,
        key_maybe_immediate: bool,
        map_runtime: crate::map::MapRuntime,
    ) -> Result<(), ModuleError> {
        let (badmap, badkey, _) = self.map_error_fragments.ok_or(ModuleError::InvalidOperand(
            "map_get/2 needs the map error fragments",
        ))?;
        self.emit_bif_map_get_fragments(
            fail,
            (key, map, destination),
            (exact_map, key_maybe_immediate),
            map_runtime,
            (badmap, badkey),
        )
    }

    /// `map_get/2` with the process-wide `handle_map_get_badmap` and `handle_map_get_badkey`
    /// fragments: a failing guard branches to its label, a failing body call raises through
    /// the fragments.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_bif_map_get), OTP-29.1.1.
    fn emit_bif_map_get_fragments(
        &mut self,
        fail: u32,
        (key, map, destination): (ArgVal, ArgVal, ArgVal),
        (exact_map, key_maybe_immediate): (bool, bool),
        runtime: crate::map::MapRuntime,
        (badmap, badkey): (usize, usize),
    ) -> Result<(), ModuleError> {
        let map_reg = self.source_reg_into(map, Gpr::x(0))?;
        if map_reg != Gpr::x(0) {
            self.code.emit(|e| e.mov_reg(Gpr::x(0), map_reg))?;
        }
        let key_reg = self.source_reg_into(key, Gpr::x(1))?;
        if key_reg != Gpr::x(1) {
            self.code.emit(|e| e.mov_reg(Gpr::x(1), key_reg))?;
        }
        let good_key = self.code.new_label();
        let fail_label = (fail != 0).then(|| self.label(fail));
        if !exact_map {
            let good_map = self.code.new_label();
            let bad_map = fail_label.unwrap_or_else(|| self.code.new_label());
            self.code.tbnz(Gpr::x(0), 0, bad_map)?;
            self.code.emit(|e| {
                e.ldur(Gpr::x(8), Gpr::x(0), -2)?;
                e.and_imm(Gpr::x(8), Gpr::x(8), 0x3f)?;
                e.cmp_imm(Gpr::x(8), 0x2c, false)
            })?;
            match fail_label {
                Some(label) => self.code.b_cond(Cond::Ne, label)?,
                None => {
                    self.code.b_cond(Cond::Eq, good_map)?;
                    self.code.bind(bad_map)?;
                    self.fragment_call(badmap)?;
                }
            }
            self.code.bind(good_map)?;
        }
        if key_maybe_immediate {
            self.fragment_call(runtime.get_element_shared)?;
            match fail_label {
                Some(label) => self.code.b_cond(Cond::Ne, label)?,
                None => self.code.b_cond(Cond::Eq, good_key)?,
            }
        } else {
            self.emit_map_get_runtime(Gpr::x(1), Gpr::x(0), runtime)?;
            match fail_label {
                Some(label) => self.code.cbz(Gpr::x(0), label)?,
                None => self.code.cbnz(Gpr::x(0), good_key)?,
            }
        }
        if fail == 0 {
            let map_reg = self.source_reg_into(map, Gpr::x(0))?;
            if map_reg != Gpr::x(0) {
                self.code.emit(|e| e.mov_reg(Gpr::x(0), map_reg))?;
            }
            let key_reg = self.source_reg_into(key, Gpr::x(1))?;
            if key_reg != Gpr::x(1) {
                self.code.emit(|e| e.mov_reg(Gpr::x(1), key_reg))?;
            }
            self.fragment_call(badkey)?;
        }
        self.code.bind(good_key)?;
        self.store_map_result(destination, Gpr::x(0))
    }

    /// Emits `byte_size/1`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:438-520 (emit_bif_byte_size),
    // OTP-29.1.1: the bit size is rounded up to whole bytes.
    pub fn emit_bif_byte_size(
        &mut self,
        fail: u32,
        term: ArgVal,
        destination: ArgVal,
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
        }
        let mfa = if fail == 0 {
            self.guard_mfa(if bytes { 4 } else { 3 })?
        } else {
            0
        };
        self.emit_guard_fail(fail, mfa)?;
        self.code.bind(ok)?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `self/0` through the runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:844-857, OTP-29.1.1
    pub fn emit_bif_self(&mut self, destination: ArgVal) -> Result<(), ModuleError> {
        let output = self.guard_destination(destination)?;
        self.code.emit(|e| e.ldr_uoff(output, Gpr::x(21), 104))?;
        self.store_guard_result(destination, output)?;
        Ok(())
    }

    /// Emits `node/1`: the node of an internal identifier is `erts_this_node`, of an
    /// external one the `ExternalThing`'s `node`; anything else fails or raises badarg.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1084-1170 (emit_handle_node_error,
    // emit_bif_node), OTP-29.1.1.
    pub fn emit_bif_node(
        &mut self,
        fail: u32,
        term: ArgVal,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        const TAG_HEADER_MASK: u64 = 0x3f;
        const TAG_HEADER_REF: u16 = 0x10;
        const TAG_HEADER_EXTERNAL_PID: u16 = 0x30;
        const TAG_HEADER_EXTERNAL_REF: u16 = 0x38;
        const TAG_IMMED1_MASK: u64 = 0xf;
        const TAG_IMMED1_PID: u16 = 0x3;
        const TAG_IMMED1_PORT: u16 = 0x7;
        let output = self.guard_destination(destination)?;
        let src = self.source_reg_into(term, Gpr::x(1))?;
        if src != Gpr::x(1) {
            self.code.emit(|e| e.mov_reg(Gpr::x(1), src))?;
        }
        let src = Gpr::x(1);
        let test_internal = self.code.new_label();
        let internal = self.code.new_label();
        let next = self.code.new_label();
        let external = self.code.new_label();
        let fail_label = if fail != 0 {
            self.label(fail)
        } else {
            self.code.new_label()
        };
        // emit_is_boxed: an immediate goes to the internal pid/port test.
        self.code.tbnz(src, 0, test_internal)?;
        self.code.emit(|e| {
            e.ldur(Gpr::x(11), src, -2)?;
            e.and_imm(Gpr::x(11), Gpr::x(11), TAG_HEADER_MASK)?;
            e.cmp_imm(Gpr::x(11), TAG_HEADER_REF, false)
        })?;
        self.code.b_cond(Cond::Eq, internal)?;
        self.code.emit(|e| {
            e.sub_imm(Gpr::x(12), Gpr::x(11), TAG_HEADER_EXTERNAL_PID, false)?;
            e.cmp_imm(
                Gpr::x(12),
                TAG_HEADER_EXTERNAL_REF - TAG_HEADER_EXTERNAL_PID,
                false,
            )
        })?;
        if fail != 0 {
            self.code.b_cond(Cond::Hi, fail_label)?;
        } else {
            self.code.b_cond(Cond::Ls, external)?;
            self.code.bind(fail_label)?;
            // `mov_var(XREG0, src); fragment_call(ga->get_handle_node_error())`.
            self.code.emit(|e| e.mov_reg(Gpr::x(25), Gpr::x(1)))?;
            self.cache_invalidate_reg(Gpr::x(25));
            let mfa = self.guard_mfa(13)?;
            self.emit_guard_fail(0, mfa)?;
        }
        self.code.bind(external)?;
        // `ExternalThing.node`, the word after the header.
        self.code.emit(|e| e.ldur(Gpr::x(10), src, 6))?;
        self.code.b(next)?;
        self.code.bind(test_internal)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(10), src, TAG_IMMED1_MASK)?;
            e.cmp_imm(Gpr::x(10), TAG_IMMED1_PID, false)
        })?;
        self.code.b_cond(Cond::Eq, internal)?;
        self.code
            .emit(|e| e.cmp_imm(Gpr::x(10), TAG_IMMED1_PORT, false))?;
        self.code.b_cond(Cond::Ne, fail_label)?;
        self.code.bind(internal)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(10), arinsal_term::erts_this_node_addr() as u64)?;
            e.ldr_uoff(Gpr::x(10), Gpr::x(10), 0)
        })?;
        self.code.bind(next)?;
        self.code.emit(|e| {
            e.ldr_uoff(
                output,
                Gpr::x(10),
                arinsal_term::ERL_NODE_SYSNAME_OFFSET as u32,
            )
        })?;
        self.store_guard_result(destination, output)
    }

    /// Emits the trap state `i_length` walks: the list, the length so far and, outside
    /// guards, the original argument for an error.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:198-228 (emit_i_length_setup), OTP-29.1.1.
    pub fn emit_i_length_setup(
        &mut self,
        fail: u32,
        live: u32,
        source: ArgVal,
    ) -> Result<(), ModuleError> {
        let reg = self.source_reg(source)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(10), reg)?;
            e.mov_const(Gpr::x(8), 15)
        })?;
        if fail == 0 {
            self.store_operand(x_slot(live + 2)?, Gpr::x(10))?;
        }
        self.store_operand(x_slot(live + 1)?, Gpr::x(8))?;
        self.store_operand(x_slot(live)?, Gpr::x(10))
    }

    /// Emits `length/1`: the `i_length_{body,guard}_shared` fragment calls
    /// `erts_trapping_length_1`, which walks the trap state above the live registers; on TRAP
    /// it yields through `context_switch_simplified` and the instruction runs again at `entry`.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:323-339 (emit_i_length), OTP-29.1.1.
    pub fn emit_bif_length(
        &mut self,
        fail: u32,
        live: u32,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        let (body_shared, guard_shared) = (
            self.bif_fragments.i_length_body,
            self.bif_fragments.i_length_guard,
        );
        if body_shared == 0 || guard_shared == 0 {
            return Err(ModuleError::InvalidOperand(
                "length/1 without the i_length_*_shared fragments",
            ));
        }
        let entry = self.code.new_label();
        self.code.bind(entry)?;
        // ARG2 = live registers, ARG3 = entry address; the result comes back in ARG1.
        self.code
            .emit(|e| e.mov_const(Gpr::x(1), u64::from(live)))?;
        self.code.adr(Gpr::x(2), entry)?;
        if fail != 0 {
            self.fragment_call(guard_shared)?;
            let fail_label = self.label(fail);
            self.code.cbz(Gpr::x(0), fail_label)?;
        } else {
            self.fragment_call(body_shared)?;
        }
        self.store_guard_result(destination, Gpr::x(0))
    }

    /// Emits `min/2`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1073-1077 (emit_bif_min),
    // OTP-29.1.1.
    pub fn emit_bif_min(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_min_max(Cond::Gt, lhs, rhs, destination)
    }

    /// Emits `max/2`.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:1067-1071 (emit_bif_max),
    // OTP-29.1.1.
    pub fn emit_bif_max(
        &mut self,
        lhs: TypedArg,
        rhs: TypedArg,
        destination: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_min_max(Cond::Lt, lhs, rhs, destination)
    }
}

impl BeamModuleAssembler {
    fn exact_immediate(&self, value: ArgVal) -> Option<u64> {
        let word = self.constant_word(value)?;
        (word & 15 == 15 || word & 63 == 11 || word == 0x3b).then_some(word)
    }

    fn exact_immediate_operand(&self, lhs: ArgVal, rhs: ArgVal) -> Option<(ArgVal, u64)> {
        self.exact_immediate(rhs)
            .map(|word| (lhs, word))
            .or_else(|| self.exact_immediate(lhs).map(|word| (rhs, word)))
    }
}

/// The X register `index`, within the scheduler register array.
fn x_slot(index: u32) -> Result<ArgVal, ModuleError> {
    match index {
        0..1024 => Ok(ArgVal::X(index)),
        _ => Err(ModuleError::InvalidOperand(
            "X register index exceeds scheduler register array",
        )),
    }
}
