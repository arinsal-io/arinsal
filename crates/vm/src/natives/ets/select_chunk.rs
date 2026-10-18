//! The continuations of `ets:select/3`, `match/3`, `match_object/3`, `select_reverse/3` and
//! their `select/1` family: decoding a continuation the caller hands in, building the one a
//! call returns and the results of a chunk.
//!
//! Port of erts/emulator/beam/erl_db_hash.c (db_select_continue_hash,
//! select_chunk_on_loop_ended, select_chunk_continue_on_loop_ended) and erl_db_tree.c
//! (db_select_continue_tree_common, db_select_chunk_tree_common, ets_select_reverse),
//! OTP-29.1.1.

use super::{atom, badarg, list, tuple_items};
use crate::VmError;
use arinsal_ets::match_spec::MatchProgram;
use arinsal_ets::{SavedKey, SavedMatches, ScanPosition, Tid};
use arinsal_term::{HeapAlloc, Term, TermBuilder, VecHeap, copy_term};
use std::sync::Arc;

/// Reductions of `ets:reverse/3` per `CONTEXT_REDS` worth of list cells (it charges one per ten).
const REVERSE_CELLS: usize = 40_000;

/// What a call starts from: a continuation the caller handed in.
pub(super) struct Run {
    pub(super) program: Arc<MatchProgram>,
    pub(super) chunk: usize,
    pub(super) backwards: bool,
    pub(super) position: ScanPosition,
    pub(super) saved: SavedMatches,
}

fn small(term: Term) -> Option<i64> {
    term.as_small()
}

/// The results a continuation holds, newest first, as a list of terms.
fn held(list_term: Term) -> Option<Vec<Term>> {
    list(list_term)
}

/// Decode the continuation of a hash table: a 6-tuple, or a 7-tuple trap continuation.
// Port of erts/emulator/beam/erl_db_hash.c, db_select_continue_hash, OTP-29.1.1.
pub(super) fn decode_hash(
    registry: &arinsal_ets::Registry,
    items: &[Term],
) -> Result<Run, VmError> {
    let arity = items.len();
    if !(arity == 6 || (arity == 7 && small(items[6]).is_some())) {
        return Err(badarg());
    }
    let slot = small(items[1]).ok_or_else(badarg)?;
    let chunk = small(items[2]).ok_or_else(badarg)?;
    let rest = held(items[4]).ok_or_else(badarg)?;
    let got = small(items[5]).ok_or_else(badarg)?;
    if chunk < 0 || got < 0 || rest.len() != got as usize {
        return Err(badarg());
    }
    let program = registry
        .match_program(items[3])
        .or_else(|| super::compiled_match_program(items[3]))
        .ok_or_else(badarg)?;
    let mut saved = SavedMatches::new();
    let oldest_first: Vec<Term> = rest.into_iter().rev().collect();
    saved.extend(&oldest_first).map_err(super::err)?;
    Ok(Run {
        program,
        chunk: chunk as usize,
        backwards: false,
        position: ScanPosition::Slot(if slot < 0 { usize::MAX } else { slot as usize }),
        saved,
    })
}

/// Decode the continuation of an ordered table: an 8-tuple.
// Port of erts/emulator/beam/erl_db_tree.c, db_select_continue_tree_common, OTP-29.1.1.
pub(super) fn decode_tree(
    registry: &arinsal_ets::Registry,
    items: &[Term],
) -> Result<Run, VmError> {
    if items.len() != 8 {
        return Err(badarg());
    }
    let chunk = small(items[3]).ok_or_else(badarg)?;
    let accum = held(items[5]).ok_or_else(badarg)?;
    let reverse = small(items[6]).ok_or_else(badarg)?;
    let got = small(items[7]).ok_or_else(badarg)?;
    let program = registry
        .match_program(items[4])
        .or_else(|| super::compiled_match_program(items[4]))
        .ok_or_else(badarg)?;
    if chunk <= 0 || got < 0 || accum.len() != got as usize {
        return Err(badarg());
    }
    let key = SavedKey::new(items[1]).map_err(super::err)?;
    let mut saved = SavedMatches::new();
    let oldest_first: Vec<Term> = accum.into_iter().rev().collect();
    saved.extend(&oldest_first).map_err(super::err)?;
    Ok(Run {
        program,
        chunk: chunk as usize,
        backwards: reverse != 0,
        position: ScanPosition::After(key),
        saved,
    })
}

/// The elements of the continuation argument of `select/1`.
pub(super) fn continuation_items(term: Term) -> Result<Vec<Term>, VmError> {
    let items = tuple_items(term).ok_or_else(badarg)?;
    if items.is_empty() {
        return Err(badarg());
    }
    Ok(items)
}

/// The result of a hash traversal whose buckets are exhausted or whose chunk filled.
///
/// `held` are the results in visit order, `slot` the next bucket (`None` at the end of the
/// table) and `continued` whether a continuation was resumed. The result is the list or the
/// pair with the new continuation and whether a continuation was made.
// Port of erts/emulator/beam/erl_db_hash.c, select_chunk_on_loop_ended and
// select_chunk_continue_on_loop_ended, OTP-29.1.1.
pub(super) fn hash_loop_ended<H: HeapAlloc>(
    heap: &mut H,
    tid: Tid,
    program: &MatchProgram,
    chunk: usize,
    mut held: Vec<Term>,
    slot: Option<usize>,
    continued: bool,
) -> Result<(Term, bool), VmError> {
    let got = held.len();
    let (rest, rest_size) = if got > chunk {
        let extra = held.split_off(chunk);
        let rest: Vec<Term> = if continued {
            extra
        } else {
            extra.into_iter().rev().collect()
        };
        (rest, got - chunk)
    } else {
        (Vec::new(), 0)
    };
    let kept = !held.is_empty();
    let matches = TermBuilder::new(heap)
        .list_from_iter(held.into_iter().rev())
        .map_err(|_| badarg())?;
    if !rest.is_empty() || slot.is_some() {
        let tid = tid.to_term(heap).map_err(|_| badarg())?;
        let reference = program.reference(heap).map_err(super::err)?;
        let rest = TermBuilder::new(heap)
            .list_from_iter(rest)
            .map_err(|_| badarg())?;
        let slot = slot.map_or(-1, |slot| slot as i64);
        let continuation = TermBuilder::new(heap)
            .tuple(&[
                tid,
                Term::small(slot).ok_or_else(badarg)?,
                Term::small(chunk as i64).ok_or_else(badarg)?,
                reference,
                rest,
                Term::small(rest_size as i64).ok_or_else(badarg)?,
            ])
            .map_err(|_| badarg())?;
        let pair = TermBuilder::new(heap)
            .tuple(&[matches, continuation])
            .map_err(|_| badarg())?;
        return Ok((pair, true));
    }
    if kept {
        let pair = TermBuilder::new(heap)
            .tuple(&[matches, atom("$end_of_table")])
            .map_err(|_| badarg())?;
        return Ok((pair, false));
    }
    Ok((atom("$end_of_table"), false))
}

/// The continuation an ordered table's chunk returns once `ets:reverse/3` has its results.
// Port of erts/emulator/beam/erl_db_tree.c, db_select_chunk_tree_common, OTP-29.1.1.
pub(super) fn tree_continuation<H: HeapAlloc>(
    heap: &mut H,
    tid: Tid,
    program: &MatchProgram,
    chunk: usize,
    reverse: bool,
    key: &SavedKey,
    end: Option<&SavedKey>,
) -> Result<Term, VmError> {
    let tid = tid.to_term(heap).map_err(|_| badarg())?;
    let key = copy_term(key.term(), heap).map_err(|_| badarg())?;
    let end = match end {
        Some(end) => copy_term(end.term(), heap).map_err(|_| badarg())?,
        None => Term::NIL,
    };
    let reference = program.reference(heap).map_err(super::err)?;
    TermBuilder::new(heap)
        .tuple(&[
            tid,
            key,
            end,
            Term::small(chunk as i64).ok_or_else(badarg)?,
            reference,
            Term::NIL,
            Term::small(i64::from(reverse)).ok_or_else(badarg)?,
            Term::small(0).ok_or_else(badarg)?,
        ])
        .map_err(|_| badarg())
}

/// Where `ets:reverse/3` stands: the cells it takes another trap for, or the cells it
/// reverses in its last pass and what that costs.
pub(super) enum ReversePass {
    /// This pass reverses `cells` and traps again.
    Trap { cells: usize },
    /// This pass reverses the last `cells` and returns, for `reds` reductions.
    Done { reds: isize },
}

/// How `ets:reverse/3` treats a list with `left` cells to go.
// Port of erts/emulator/beam/erl_db_tree.c, ets_select_reverse, OTP-29.1.1.
pub(super) fn reverse_pass(left: usize) -> ReversePass {
    if left >= REVERSE_CELLS {
        ReversePass::Trap {
            cells: REVERSE_CELLS - 1,
        }
    } else {
        ReversePass::Done {
            reds: left.div_ceil(10) as isize,
        }
    }
}

/// An empty scratch heap for a reference that only names a program.
pub(super) fn program_reference(program: &MatchProgram) -> Result<(VecHeap, Term), VmError> {
    let mut heap = VecHeap::new();
    let reference = program.reference(&mut heap).map_err(super::err)?;
    Ok((heap, reference))
}
