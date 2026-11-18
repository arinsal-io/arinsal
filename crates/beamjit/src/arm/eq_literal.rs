//! Compile-time classification of literals compared with `=:=` and `=/=`.

use arinsal_beamasm::guard::EqLiteral;
use arinsal_etf::OwnedTerm;

/// Largest tuple matched inline: its element loads use 12-bit scaled offsets.
const MAX_INLINE_TUPLE_ARITY: usize = 4000;
/// Smallest and largest exclusive bounds of small integers (60-bit payload).
const SMALL_LIMIT: i64 = 1 << 59;
/// `make_small(v)` tag for the immediate form of small integers.
const SMALL_TAG: u64 = 0xf;
/// The nil immediate word.
const NIL_WORD: u64 = 0x3b;

/// Classifies a literal by the shape erts's `is_eq_exact` checks.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1366-1392 (beam_jit_is_list_of_immediates,
// beam_jit_is_shallow_boxed), OTP-29.1.1. Anything else takes the general path.
pub fn classify_eq_literal(term: &OwnedTerm, atom_word: &dyn Fn(&str) -> Option<u64>) -> EqLiteral {
    match term {
        OwnedTerm::List { elems, tail } if matches!(**tail, OwnedTerm::Nil) => {
            immediate_words(elems, atom_word)
                .map_or(EqLiteral::Generic, EqLiteral::ListOfImmediates)
        }
        OwnedTerm::Tuple(elems) if elems.len() <= MAX_INLINE_TUPLE_ARITY => {
            immediate_words(elems, atom_word).map_or(EqLiteral::Generic, |elements| {
                EqLiteral::ShallowTuple {
                    header: (elems.len() as u64) << 6,
                    elements,
                }
            })
        }
        OwnedTerm::Binary(bytes) if bytes.is_empty() => EqLiteral::EmptyBinary,
        OwnedTerm::Map(entries) if entries.is_empty() => EqLiteral::EmptyMap,
        _ => EqLiteral::Generic,
    }
}

/// The words of all elements when each is an immediate, otherwise `None`.
fn immediate_words(
    terms: &[OwnedTerm],
    atom_word: &dyn Fn(&str) -> Option<u64>,
) -> Option<Vec<u64>> {
    terms
        .iter()
        .map(|term| immediate_word(term, atom_word))
        .collect()
}

/// The term word of an immediate literal (small integer, atom, nil), using the same encodings as
/// the operand lowering in `arg`.
fn immediate_word(term: &OwnedTerm, atom_word: &dyn Fn(&str) -> Option<u64>) -> Option<u64> {
    match term {
        OwnedTerm::Int(value) if (-SMALL_LIMIT..SMALL_LIMIT).contains(value) => {
            Some((*value as u64).wrapping_shl(4) | SMALL_TAG)
        }
        OwnedTerm::Nil => Some(NIL_WORD),
        OwnedTerm::Atom(name) => atom_word(name),
        _ => None,
    }
}
