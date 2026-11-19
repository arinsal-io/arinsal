//! Compiler type information for instruction operands.
//!
//! Port of the helpers in erts/emulator/beam/jit/beam_jit_common.hpp:253-415 and
//! erts/emulator/beam/jit/beam_jit_types.hpp (BeamTypeId, BeamArgType), OTP-29.1.1.

use crate::common::args::ArgVal;
use arinsal_term::{Term, TermKind, raw::term_from_bits};

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
    /// Types that are always immediate.
    pub const ALWAYS_IMMEDIATE: u16 = MAYBE_IMMEDIATE & !(CONS | MAYBE_BOXED);
}

/// Smallest and largest small integers (erts MIN_SMALL / MAX_SMALL, 60-bit smalls).
const MAX_SMALL: i64 = (1 << 59) - 1;
const MIN_SMALL: i64 = -(1 << 59);

fn is_ssmall(value: i64) -> bool {
    (MIN_SMALL..=MAX_SMALL).contains(&value)
}

/// One entry of the module's type table (`BeamArgType`, `beam->types.entries[i]`): a type
/// union, optional integer bounds and the size unit of a bitstring.
// Port of erts/emulator/beam/jit/beam_jit_types.hpp:119-150 (BeamArgType), OTP-29.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgType {
    /// `BEAM_TYPE_*` union bits.
    pub union_bits: u16,
    /// Inclusive lower bound, when the type chunk records one (`hasLowerBound`).
    pub min: Option<i64>,
    /// Inclusive upper bound, when the type chunk records one (`hasUpperBound`).
    pub max: Option<i64>,
    /// `size_unit`: 1 unless the type chunk records a unit (`hasUnit`).
    pub unit: u16,
}

impl ArgType {
    /// The entry of `init_fallback_type_table`, the only entry of a module without a type
    /// chunk, and the type of every untyped operand.
    // Port of erts/emulator/beam/beam_file.c:607-623 (init_fallback_type_table), OTP-29.1.1.
    pub const ANY: ArgType = ArgType {
        union_bits: type_id::ANY,
        min: None,
        max: None,
        unit: 1,
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

    /// The operand's immediate machine word (`ArgSmall::get` for a small: the tagged value).
    pub fn word(&self) -> u64 {
        match self.val {
            ArgVal::Immediate(word) => word,
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
        matches!(self.val, ArgVal::X(_) | ArgVal::Y(_))
    }

    /// `getTypeUnion`.
    pub fn type_union(&self) -> u16 {
        match self.val {
            ArgVal::Immediate(word) => match word & 0x3f {
                _ if word & 15 == 15 => type_id::INTEGER,
                0x0b => type_id::ATOM,
                0x3b => type_id::NIL,
                _ if word & 15 == 3 => type_id::PID,
                _ if word & 15 == 7 => type_id::PORT,
                _ if word & 7 == 1 => type_id::CONS,
                _ => type_id::ANY,
            },
            _ => self.ty.union_bits,
        }
    }

    /// `masked_types<Type>`.
    pub fn masked_types(&self, types: u16) -> u16 {
        self.type_union() & types
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

    /// `maybe_one_of<Types...>`.
    pub fn maybe_one_of(&self, types: u16) -> bool {
        self.type_union() & types != 0
    }

    /// `always_immediate` for values whose type cannot be boxed.
    // Port of erts/emulator/beam/jit/beam_jit_common.hpp:283-286, OTP-29.1.1.
    pub fn always_immediate(&self) -> bool {
        self.always_one_of(type_id::ALWAYS_IMMEDIATE) || self.always_small()
    }

    /// `always_one_of<AlwaysBoxed>`.
    // Port of erts/emulator/beam/jit/beam_jit_common.hpp:316-329, OTP-29.1.1.
    pub fn always_boxed(&self) -> bool {
        self.always_one_of(type_id::ALWAYS_BOXED)
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

/// The type union of a constant operand (`getTypeUnion` on an `ArgImmed` or an `ArgLiteral`):
/// the `BeamTypeId` of the term's `tag_val_def`.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:208-249 (getTypeUnion, constants),
// OTP-29.1.1.
fn constant_type_union(constant: Term) -> u16 {
    match constant.classify() {
        TermKind::Atom => type_id::ATOM,
        TermKind::Bitstring => type_id::BITSTRING,
        TermKind::Number if constant.float_value().is_some() => type_id::FLOAT,
        TermKind::Number => type_id::INTEGER,
        TermKind::Fun => type_id::FUN,
        TermKind::List => type_id::CONS,
        TermKind::Map => type_id::MAP,
        TermKind::Nil => type_id::NIL,
        TermKind::Pid => type_id::PID,
        TermKind::Port => type_id::PORT,
        TermKind::Ref => type_id::REFERENCE,
        TermKind::Tuple => type_id::TUPLE,
        // `ERTS_ASSERT(!"tag_val_def error")`.
        other => panic!("getTypeUnion: no type for a {other:?} constant"),
    }
}

/// The type helpers of `BeamModuleAssemblerCommon`, which every architecture's
/// `BeamModuleAssembler` inherits: they read an operand's type through the type index its
/// `ArgVal` carries, from the module's type table (`beam->types`).
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:199-430 (BeamModuleAssemblerCommon,
// getTypeEntry .. hasUpperBound), OTP-29.1.1.
pub trait BeamModuleAssemblerCommon {
    /// `beam->types.entries`.
    fn beam_types(&self) -> &[ArgType];

    /// `beamfile_get_literal(beam, index)`.
    fn beamfile_get_literal(&self, index: i64) -> u64;

    /// A constant term word as read by `getTypeUnion`.
    fn constant_word(&self, arg: ArgVal) -> Option<u64> {
        match arg {
            ArgVal::Immediate(word) => Some(word),
            ArgVal::Literal(index) => Some(self.beamfile_get_literal(index)),
            _ => None,
        }
    }

    /// `getTypeEntry`: entry 0 for a constant.
    fn get_type_entry(&self, arg: ArgVal) -> ArgType {
        let type_index = if arg.is_register() {
            arg.type_index()
        } else {
            0
        };
        // `ASSERT(typeIndex < beam->types.count)`: the loader only packs indices of the table.
        self.beam_types()[type_index as usize]
    }

    /// `getTypeUnion`.
    fn get_type_union(&self, arg: ArgVal) -> u16 {
        match arg {
            // `beamfile_get_literal`: the loader resolved the literal to its term in the
            // module's literal area, live for as long as the module.
            ArgVal::Immediate(term) => constant_type_union(term_from_bits(term)),
            ArgVal::Literal(index) => {
                constant_type_union(term_from_bits(self.beamfile_get_literal(index)))
            }
            _ => self.get_type_entry(arg).union_bits,
        }
    }

    /// `getClampedRange`.
    fn get_clamped_range(&self, arg: ArgVal) -> (i64, i64) {
        if let Some(value) = arg.small_signed() {
            (value, value)
        } else {
            let entry = self.get_type_entry(arg);
            (
                entry.min.unwrap_or(MIN_SMALL),
                entry.max.unwrap_or(MAX_SMALL),
            )
        }
    }

    /// `always_small`.
    fn always_small(&self, arg: ArgVal) -> bool {
        if arg.is_small() {
            return true;
        } else if !self.exact_type(arg, type_id::INTEGER) {
            return false;
        }
        let entry = self.get_type_entry(arg);
        match (entry.min, entry.max) {
            (Some(min), Some(max)) => is_ssmall(min) && is_ssmall(max),
            _ => false,
        }
    }

    /// `always_immediate`.
    fn always_immediate(&self, arg: ArgVal) -> bool {
        self.always_one_of(arg, type_id::ALWAYS_IMMEDIATE) || self.always_small(arg)
    }

    /// `always_same_types`.
    fn always_same_types(&self, lhs: ArgVal, rhs: ArgVal) -> bool {
        let lhs_types = self.get_type_union(lhs);
        let rhs_types = self.get_type_union(rhs);
        // Only certain to be the same when there is one possible type: a number and an
        // integer could differ if the former is a float.
        if lhs_types & lhs_types.wrapping_sub(1) == 0 {
            return lhs_types == rhs_types;
        }
        false
    }

    /// `never_one_of<Types...>`.
    fn never_one_of(&self, arg: ArgVal, types: u16) -> bool {
        self.get_type_union(arg) & types == type_id::NONE
    }

    /// `maybe_one_of<Types...>`.
    fn maybe_one_of(&self, arg: ArgVal, types: u16) -> bool {
        !self.never_one_of(arg, types)
    }

    /// `always_one_of<Types...>`.
    fn always_one_of(&self, arg: ArgVal, types: u16) -> bool {
        let type_union = self.get_type_union(arg);
        type_union == type_union & types
    }

    /// `exact_type<Type>`.
    fn exact_type(&self, arg: ArgVal, ty: u16) -> bool {
        let type_union = self.get_type_union(arg);
        type_union == type_union & ty
    }

    /// `masked_types<Mask>`.
    fn masked_types(&self, arg: ArgVal, mask: u16) -> u16 {
        self.get_type_union(arg) & mask
    }

    /// `is_sum_small_if_args_are_small`.
    fn is_sum_small_if_args_are_small(&self, lhs: ArgVal, rhs: ArgVal) -> bool {
        let (min1, max1) = self.get_clamped_range(lhs);
        let (min2, max2) = self.get_clamped_range(rhs);
        is_ssmall(min1 + min2) && is_ssmall(max1 + max2)
    }

    /// `is_diff_small_if_args_are_small`.
    fn is_diff_small_if_args_are_small(&self, lhs: ArgVal, rhs: ArgVal) -> bool {
        let (min1, max1) = self.get_clamped_range(lhs);
        let (min2, max2) = self.get_clamped_range(rhs);
        is_ssmall(min1 - max2) && is_ssmall(max1 - min2)
    }

    /// `is_product_small_if_args_are_small`.
    fn is_product_small_if_args_are_small(&self, lhs: ArgVal, rhs: ArgVal) -> bool {
        let (min1, max1) = self.get_clamped_range(lhs);
        let (min2, max2) = self.get_clamped_range(rhs);
        let mag1 = min1.abs().max(max1.abs());
        let mag2 = min2.abs().max(max2.abs());
        // mag1 * mag2 <= MAX_SMALL, i.e. mag1 <= MAX_SMALL / mag2 when mag2 != 0.
        mag2 == 0 || mag1 <= MAX_SMALL / mag2
    }

    /// `is_bsl_small`.
    fn is_bsl_small(&self, lhs: ArgVal, rhs: ArgVal) -> bool {
        if !(self.always_small(lhs) && self.always_small(rhs)) {
            return false;
        }
        let (min1, max1) = self.get_clamped_range(lhs);
        let (min2, max2) = self.get_clamped_range(rhs);
        if min1 < 0 || max1 == 0 || min2 < 0 {
            return false;
        }
        // _TAG_IMMED1_SIZE is 4.
        max2 < i64::from(max1.leading_zeros()) - 4
    }

    /// `getSizeUnit`.
    fn get_size_unit(&self, arg: ArgVal) -> u16 {
        self.get_type_entry(arg).unit
    }

    /// `hasLowerBound`.
    fn has_lower_bound(&self, arg: ArgVal) -> bool {
        self.get_type_entry(arg).min.is_some()
    }

    /// `hasUpperBound`.
    fn has_upper_bound(&self, arg: ArgVal) -> bool {
        self.get_type_entry(arg).max.is_some()
    }
}

impl From<ArgVal> for TypedArg {
    fn from(val: ArgVal) -> Self {
        Self::new(val, ArgType::ANY)
    }
}

/// `is_product_small_if_args_are_small`.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:388-401, OTP-29.1.1.
pub fn is_product_small_if_args_are_small(lhs: &TypedArg, rhs: &TypedArg) -> bool {
    let (min1, max1) = lhs.clamped_range();
    let (min2, max2) = rhs.clamped_range();
    let mag1 = min1.abs().max(max1.abs());
    let mag2 = min2.abs().max(max2.abs());
    // mag1 * mag2 <= MAX_SMALL, i.e. mag1 <= MAX_SMALL / mag2 when mag2 != 0.
    // MAX_SMALL < -MIN_SMALL, so a zero factor always fits.
    mag2 == 0 || mag1 <= MAX_SMALL / mag2
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

#[cfg(test)]
mod tests {
    use super::{ArgType, BeamModuleAssemblerCommon, MAX_SMALL, type_id};
    use crate::common::args::ArgVal;

    /// A module's type table, as the assemblers hold it.
    struct Types(Vec<ArgType>);

    impl BeamModuleAssemblerCommon for Types {
        fn beam_types(&self) -> &[ArgType] {
            &self.0
        }

        fn beamfile_get_literal(&self, _index: i64) -> u64 {
            unreachable!("type tests do not read literal operands")
        }
    }

    fn entry(union_bits: u16) -> ArgType {
        ArgType {
            union_bits,
            ..ArgType::ANY
        }
    }

    #[test]
    fn immediate_and_boxed_elisions_match_beam_type_unions() {
        let types = Types(vec![
            ArgType::ANY,
            entry(type_id::ATOM),
            entry(type_id::NIL),
            entry(type_id::CONS),
            entry(type_id::TUPLE),
            entry(type_id::MAP),
            entry(type_id::INTEGER),
            ArgType {
                union_bits: type_id::INTEGER,
                min: Some(MAX_SMALL + 1),
                ..ArgType::ANY
            },
        ]);
        let reg = |type_index| ArgVal::typed_x(3, type_index);
        assert_eq!(types.get_type_union(ArgVal::Immediate(0x03)), type_id::PID);
        assert_eq!(types.get_type_union(ArgVal::Immediate(0x07)), type_id::PORT);
        assert_eq!(types.get_type_union(ArgVal::Immediate(0x3b)), type_id::NIL);
        assert_eq!(
            types.get_type_union(ArgVal::Immediate(0x1f)),
            type_id::INTEGER
        );
        assert_eq!(types.get_type_union(ArgVal::X(3)), type_id::ANY);
        assert!(types.always_immediate(reg(1)));
        assert!(types.always_immediate(reg(2)));
        assert!(!types.always_immediate(reg(3)));
        assert!(types.always_one_of(reg(4), type_id::ALWAYS_BOXED));
        assert!(types.always_one_of(reg(5), type_id::ALWAYS_BOXED));
        assert!(!types.always_one_of(reg(6), type_id::ALWAYS_BOXED));
        assert!(!types.always_one_of(reg(7), type_id::ALWAYS_BOXED));
        assert!(!types.always_small(reg(7)));
        assert_eq!(types.get_clamped_range(reg(7)), (MAX_SMALL + 1, MAX_SMALL));
    }

    #[test]
    fn register_operands_carry_the_type_index_above_reg_mask() {
        let arg = ArgVal::typed_y(5, 9);
        assert_eq!(arg, ArgVal::Y(5 | (9 << 10)));
        assert_eq!((arg.reg(), arg.type_index()), (Some(5), 9));
        // `ArgRegister::trimmed` drops the type index of a Y register.
        assert_eq!(arg.trimmed(2), Some(ArgVal::Y(3)));
        assert_eq!(arg.copy(1), Some(ArgVal::typed_y(1, 9)));
        assert_eq!(
            crate::common::args::memory_relation(ArgVal::typed_x(1, 4), ArgVal::X(2)),
            crate::common::args::Relation::Consecutive
        );
    }
}
