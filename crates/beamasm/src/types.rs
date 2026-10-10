//! Compiler type information for instruction operands.
//!
//! Port of the helpers in erts/emulator/beam/jit/beam_jit_common.hpp:253-415 and
//! erts/emulator/beam/jit/beam_jit_types.hpp (BeamTypeId, BeamArgType), OTP-29.1.1.

use crate::module::ArgVal;

/// Type-union bits, the `BEAM_TYPE_*` values of erts/emulator/beam/beam_types.h.
pub mod type_id {
    /// No type.
    pub const NONE: u16 = 0;
    /// Atom.
    pub const ATOM: u16 = 1 << 0;
    /// Bitstring.
    pub const BITSTRING: u16 = 1 << 1;
    /// Cons cell.
    pub const CONS: u16 = 1 << 2;
    /// Float.
    pub const FLOAT: u16 = 1 << 3;
    /// Fun.
    pub const FUN: u16 = 1 << 4;
    /// Integer (small or big).
    pub const INTEGER: u16 = 1 << 5;
    /// Map.
    pub const MAP: u16 = 1 << 6;
    /// Nil.
    pub const NIL: u16 = 1 << 7;
    /// Pid.
    pub const PID: u16 = 1 << 8;
    /// Port.
    pub const PORT: u16 = 1 << 9;
    /// Reference.
    pub const REFERENCE: u16 = 1 << 10;
    /// Tuple.
    pub const TUPLE: u16 = 1 << 11;
    /// Record.
    pub const RECORD: u16 = 1 << 12;
    /// Any term.
    pub const ANY: u16 = (1 << 13) - 1;
    /// Float or integer.
    pub const NUMBER: u16 = FLOAT | INTEGER;
    /// Types that can be boxed, including those that may also be immediates.
    pub const MAYBE_BOXED: u16 =
        BITSTRING | FLOAT | FUN | INTEGER | MAP | PID | PORT | REFERENCE | TUPLE | RECORD;
    /// Types that can be immediates, including those that may also be boxed.
    pub const MAYBE_IMMEDIATE: u16 = ATOM | INTEGER | NIL | PID | PORT;
    /// Types that are always boxed.
    pub const ALWAYS_BOXED: u16 = MAYBE_BOXED & !(CONS | MAYBE_IMMEDIATE);
}

/// Smallest and largest small integers (erts MIN_SMALL / MAX_SMALL, 60-bit smalls).
const MAX_SMALL: i64 = (1 << 59) - 1;
const MIN_SMALL: i64 = -(1 << 59);

fn is_ssmall(value: i64) -> bool {
    (MIN_SMALL..=MAX_SMALL).contains(&value)
}

/// One entry of the `Type` chunk: a type union and optional integer bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgType {
    /// `BEAM_TYPE_*` union bits.
    pub union_bits: u16,
    /// Inclusive lower bound, when the type chunk records one.
    pub min: Option<i64>,
    /// Inclusive upper bound, when the type chunk records one.
    pub max: Option<i64>,
}

impl ArgType {
    /// The entry every untyped operand uses (type index zero).
    pub const ANY: ArgType = ArgType {
        union_bits: type_id::ANY,
        min: None,
        max: None,
    };
}

impl Default for ArgType {
    fn default() -> Self {
        Self::ANY
    }
}

/// An operand together with its compiler type (erts' `ArgSource` with a type index).
#[derive(Clone, Copy, Debug)]
pub struct TypedArg {
    /// The operand.
    pub val: ArgVal,
    /// Its type; only meaningful for registers and literals.
    pub ty: ArgType,
}

impl TypedArg {
    /// Pairs an operand with its type.
    pub fn new(val: ArgVal, ty: ArgType) -> Self {
        Self { val, ty }
    }

    /// `ArgSource::isSmall`: an immediate small integer.
    pub fn is_small(&self) -> bool {
        matches!(self.val, ArgVal::Immediate(word) if word & 15 == 15)
    }

    /// The operand's machine word (`ArgSmall::get` for a small: the tagged value).
    pub fn word(&self) -> u64 {
        match self.val {
            ArgVal::Immediate(word) | ArgVal::Literal(word) => word,
            _ => 0,
        }
    }

    /// `ArgSmall::getSigned`: the untagged value of a small immediate.
    pub fn small_value(&self) -> i64 {
        match self.val {
            ArgVal::Immediate(word) => (word as i64) >> 4,
            _ => 0,
        }
    }

    /// `ArgSource::isLiteral`: a boxed literal (never a small).
    pub fn is_literal(&self) -> bool {
        matches!(self.val, ArgVal::Literal(_))
    }

    /// `ArgSource::isImmed`.
    pub fn is_immed(&self) -> bool {
        matches!(self.val, ArgVal::Immediate(_))
    }

    /// `ArgSource::isRegister`.
    pub fn is_register(&self) -> bool {
        matches!(self.val, ArgVal::X(_) | ArgVal::XMemory(_) | ArgVal::Y(_))
    }

    /// `getTypeUnion`.
    pub fn type_union(&self) -> u16 {
        match self.val {
            ArgVal::Immediate(word) => match word & 0x3f {
                _ if word & 15 == 15 => type_id::INTEGER,
                0x0b => type_id::ATOM,
                0x3b => type_id::NIL,
                _ => type_id::ANY,
            },
            _ => self.ty.union_bits,
        }
    }

    /// `getClampedRange`.
    pub fn clamped_range(&self) -> (i64, i64) {
        if self.is_small() {
            let value = self.small_value();
            (value, value)
        } else {
            (
                self.ty.min.unwrap_or(MIN_SMALL),
                self.ty.max.unwrap_or(MAX_SMALL),
            )
        }
    }

    /// `always_one_of<Types...>`.
    pub fn always_one_of(&self, types: u16) -> bool {
        let union = self.type_union();
        union == union & types
    }

    /// `exact_type<Type>`.
    pub fn exact_type(&self, ty: u16) -> bool {
        let union = self.type_union();
        union == union & ty
    }

    /// `always_small`.
    pub fn always_small(&self) -> bool {
        if self.is_small() {
            return true;
        }
        if !self.exact_type(type_id::INTEGER) {
            return false;
        }
        match (self.ty.min, self.ty.max) {
            (Some(min), Some(max)) => is_ssmall(min) && is_ssmall(max),
            _ => false,
        }
    }
}

/// `is_sum_small_if_args_are_small`.
pub fn is_sum_small_if_args_are_small(lhs: &TypedArg, rhs: &TypedArg) -> bool {
    let (min1, max1) = lhs.clamped_range();
    let (min2, max2) = rhs.clamped_range();
    is_ssmall(min1 + min2) && is_ssmall(max1 + max2)
}

/// `is_diff_small_if_args_are_small`.
pub fn is_diff_small_if_args_are_small(lhs: &TypedArg, rhs: &TypedArg) -> bool {
    let (min1, max1) = lhs.clamped_range();
    let (min2, max2) = rhs.clamped_range();
    is_ssmall(min1 - max2) && is_ssmall(max1 - min2)
}

/// `is_bsl_small`.
pub fn is_bsl_small(lhs: &TypedArg, rhs: &TypedArg) -> bool {
    if !(lhs.always_small() && rhs.always_small()) {
        return false;
    }
    let (min1, max1) = lhs.clamped_range();
    let (min2, max2) = rhs.clamped_range();
    if min1 < 0 || max1 == 0 || min2 < 0 {
        return false;
    }
    // _TAG_IMMED1_SIZE is 4.
    max2 < i64::from(max1.leading_zeros()) - 4
}
