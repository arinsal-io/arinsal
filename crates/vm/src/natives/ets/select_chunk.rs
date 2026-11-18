//! The continuations of `ets:select/3`, `match/3`, `match_object/3`, `select_reverse/3` and
//! their `select/1` family: decoding a continuation the caller hands in, building the one a
//! call returns and the results of a chunk.
//!
//! Port of erts/emulator/beam/erl_db_hash.c (db_select_continue_hash,
//! select_chunk_on_loop_ended, select_chunk_continue_on_loop_ended) and erl_db_tree.c
//! (db_select_continue_tree_common, db_select_chunk_tree_common, ets_select_reverse),
//! OTP-29.1.1.

use super::{badarg, list, tuple_items};
use crate::VmError;
use arinsal_ets::match_spec::MatchProgram;
use arinsal_ets::{IterSafety, SavedKey, ScanPosition};
use arinsal_term::{HeapAlloc, MagicBin, Term, TermBuilder, copy_term};
use std::sync::Arc;

/// What a call starts from: a continuation the caller handed in.
pub(super) struct Run {
    /// `select_count/2` continuation.
    pub(super) count: bool,
    /// Objects counted so far (`select_count/2`).
    pub(super) got: usize,
    /// The iteration safety a trap continuation carries; a chunk continuation has none.
    pub(super) safety: Option<IterSafety>,
    pub(super) program: Arc<MatchProgram>,
    pub(super) program_owner: MagicBin,
    pub(super) chunk: usize,
    pub(super) backwards: bool,
    pub(super) position: ScanPosition,
    /// The results so far, newest first, and how many: the list of the continuation, which
    /// grows without being rebuilt.
    pub(super) accum: (Term, usize),
}

fn small(term: Term) -> Option<i64> {
    term.as_small()
}

/// The results a continuation holds, oldest first, from their list (newest first).
pub(super) fn expand(list_term: Term) -> Result<Vec<Term>, VmError> {
    let mut items = list(list_term).ok_or_else(badarg)?;
    items.reverse();
    Ok(items)
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
    let got = small(items[5]).ok_or_else(badarg)?;
    if chunk < 0 || got < 0 {
        return Err(badarg());
    }
    let accum = accumulator(items[4], got as usize)?;
    let program = registry
        .match_program(items[3])
        .or_else(|| super::compiled_match_program(items[3]))
        .ok_or_else(badarg)?;
    let program_owner = match_program_owner(items[3], &program);
    let safety = match items.get(6) {
        Some(&safety) => Some(decode_safety(safety)?),
        None => None,
    };
    Ok(Run {
        count: false,
        got: 0,
        safety,
        program,
        program_owner,
        chunk: chunk as usize,
        backwards: false,
        position: ScanPosition::Slot(if slot < 0 { usize::MAX } else { slot as usize }),
        accum,
    })
}

fn accumulator(list: Term, got: usize) -> Result<(Term, usize), VmError> {
    if list != Term::NIL && list.classify() != arinsal_term::TermKind::List {
        return Err(badarg());
    }
    Ok((list, got))
}

/// `make_small(ctx->safety)` of a trap continuation.
fn decode_safety(term: Term) -> Result<IterSafety, VmError> {
    match small(term) {
        Some(0) => Ok(IterSafety::Unsafe),
        Some(1) => Ok(IterSafety::SafeLocked),
        Some(2) => Ok(IterSafety::Safe),
        _ => Err(badarg()),
    }
}

fn encode_safety(safety: IterSafety) -> i64 {
    match safety {
        IterSafety::Unsafe => 0,
        IterSafety::SafeLocked => 1,
        IterSafety::Safe => 2,
    }
}

/// Decode the continuation `ets:count_trap/1` receives: `{Tid, Slot|Key, MatchProgram, Got,
/// Safety}`.
// Port of erts/emulator/beam/erl_db_hash.c (unpack_simple_continuation), OTP-29.1.1.
pub(super) fn decode_count(
    registry: &arinsal_ets::Registry,
    hash: bool,
    items: &[Term],
) -> Result<Run, VmError> {
    if items.len() != 5 {
        return Err(badarg());
    }
    let got = small(items[3]).ok_or_else(badarg)?;
    if got < 0 {
        return Err(badarg());
    }
    let safety = decode_safety(items[4])?;
    let program = registry
        .match_program(items[2])
        .or_else(|| super::compiled_match_program(items[2]))
        .ok_or_else(badarg)?;
    let program_owner = match_program_owner(items[2], &program);
    let position = if hash {
        let slot = small(items[1]).ok_or_else(badarg)?;
        ScanPosition::Slot(if slot < 0 { usize::MAX } else { slot as usize })
    } else {
        ScanPosition::After(SavedKey::new(items[1]).map_err(super::err)?)
    };
    Ok(Run {
        count: true,
        got: got as usize,
        safety: Some(safety),
        program,
        program_owner,
        chunk: 0,
        backwards: false,
        position,
        accum: (Term::NIL, 0),
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
    let reverse = small(items[6]).ok_or_else(badarg)?;
    let got = small(items[7]).ok_or_else(badarg)?;
    let program = registry
        .match_program(items[4])
        .or_else(|| super::compiled_match_program(items[4]))
        .ok_or_else(badarg)?;
    let program_owner = match_program_owner(items[4], &program);
    if chunk < 0 || got < 0 {
        return Err(badarg());
    }
    let key = SavedKey::new(items[1]).map_err(super::err)?;
    let accum = accumulator(items[5], got as usize)?;
    Ok(Run {
        count: false,
        got: 0,
        safety: None,
        program,
        program_owner,
        chunk: chunk as usize,
        backwards: reverse != 0,
        position: ScanPosition::After(key),
        accum,
    })
}

/// The elements of the continuation argument of `select/1`.
pub(super) fn continuation_items(term: Term) -> Result<Vec<Term>, VmError> {
    let items = tuple_items(term).ok_or_else(badarg)?;
    if items.is_empty() {
        return Err(badarg());
    }
    Ok(items.into_vec())
}

/// The result of a hash traversal whose buckets are exhausted or whose chunk filled.
///
/// `held` are the results in visit order, `slot` the next bucket (`None` at the end of the
/// table) and `continued` whether a continuation was resumed. The result is the list or the
/// pair with the new continuation.
// Port of erts/emulator/beam/erl_db_hash.c, select_chunk_on_loop_ended and
// select_chunk_continue_on_loop_ended, OTP-29.1.1.
pub(super) fn hash_loop_ended<H: HeapAlloc>(
    heap: &mut H,
    tid: Term,
    program_owner: &MagicBin,
    chunk: usize,
    mut held: Vec<Term>,
    slot: Option<usize>,
    continued: bool,
) -> Result<Term, VmError> {
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
        let reference = match_program_reference(heap, program_owner)?;
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
        return Ok(pair);
    }
    if kept {
        let pair = TermBuilder::new(heap)
            .tuple(&[matches, Term::atom(arinsal_term::atoms::EOT)])
            .map_err(|_| badarg())?;
        return Ok(pair);
    }
    Ok(Term::atom(arinsal_term::atoms::EOT))
}

/// The continuation an ordered table's chunk returns once `ets:reverse/3` has its results.
// Port of erts/emulator/beam/erl_db_tree.c, db_select_chunk_tree_common, OTP-29.1.1.
pub(super) fn tree_continuation<H: HeapAlloc>(
    heap: &mut H,
    tid: Term,
    program_owner: &MagicBin,
    chunk: usize,
    reverse: bool,
    key: &SavedKey,
    end: Option<&SavedKey>,
) -> Result<Term, VmError> {
    let key = copy_term(key.term(), heap).map_err(|_| badarg())?;
    let end = match end {
        Some(end) => copy_term(end.term(), heap).map_err(|_| badarg())?,
        None => Term::NIL,
    };
    let reference = match_program_reference(heap, program_owner)?;
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

/// The data of a compiled match specification's magic binary.
pub(crate) struct MatchProgRef(pub(crate) Arc<MatchProgram>);
// erl_db_util.c: erts_db_match_prog_destructor.
arinsal_term::magic_payload!(MatchProgRef => erts_db_match_prog_destructor);

/// Keep the match program alive through every continuation term that names it.
// Port of erts/emulator/beam/erl_db_util.h (erts_db_make_match_prog_ref), OTP-29.1.1.
fn match_program_owner(reference: Term, program: &Arc<MatchProgram>) -> MagicBin {
    reference
        .magic_owner()
        .filter(|owner| owner.downcast_ref::<MatchProgRef>().is_some())
        .unwrap_or_else(|| new_match_program_owner(program))
}

/// Create the binary owner used by the first continuation for a match program.
pub(super) fn new_match_program_owner(program: &Arc<MatchProgram>) -> MagicBin {
    MagicBin::with_erts_payload_size_and_refn(
        MatchProgRef(Arc::clone(program)),
        program.erts_magic_payload_size(),
        arinsal_sched::unique::next_ref_words(),
    )
}

/// Build a continuation reference with the same identity as its predecessor.
// Port of erts/emulator/beam/erl_db_hash.c (select_chunk_on_loop_ended), OTP-29.1.1.
fn match_program_reference<H: HeapAlloc>(heap: &mut H, owner: &MagicBin) -> Result<Term, VmError> {
    TermBuilder::new(heap)
        .magic_ref(MagicBin::clone(owner))
        .map_err(|_| badarg())
}

/// The continuation a trapped hash traversal passes to `ets:select_trap/1`: `{Tid, Slot,
/// Chunk, MatchProgram, MatchList, Got, Safety}`, the list newest first.
// Port of erts/emulator/beam/erl_db_hash.c (select_chunk_on_trap), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
pub(super) fn hash_trap_continuation<H: HeapAlloc>(
    heap: &mut H,
    tid: Term,
    program_owner: &MagicBin,
    slot: usize,
    chunk: usize,
    (list, got): (Term, usize),
    safety: IterSafety,
) -> Result<Term, VmError> {
    let reference = match_program_reference(heap, program_owner)?;
    TermBuilder::new(heap)
        .tuple(&[
            tid,
            Term::small(if slot == usize::MAX { -1 } else { slot as i64 }).ok_or_else(badarg)?,
            Term::small(chunk as i64).ok_or_else(badarg)?,
            reference,
            list,
            Term::small(got as i64).ok_or_else(badarg)?,
            Term::small(encode_safety(safety)).ok_or_else(badarg)?,
        ])
        .map_err(|_| badarg())
}

/// The continuation an ordered table's traversal passes to `ets:select/1`: `{Tid, Key, End,
/// Chunk, MatchProgram, Accum, Reverse, Got}`, the accumulator newest first.
// Port of erts/emulator/beam/erl_db_tree.c (db_select_chunk_tree_common, db_select_tree_common),
// OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
pub(super) fn tree_trap_continuation<H: HeapAlloc>(
    heap: &mut H,
    tid: Term,
    program_owner: &MagicBin,
    chunk: usize,
    reverse: bool,
    key: &SavedKey,
    (list, got): (Term, usize),
) -> Result<Term, VmError> {
    let key = copy_term(key.term(), heap).map_err(|_| badarg())?;
    let reference = match_program_reference(heap, program_owner)?;
    TermBuilder::new(heap)
        .tuple(&[
            tid,
            key,
            Term::NIL,
            Term::small(chunk as i64).ok_or_else(badarg)?,
            reference,
            list,
            Term::small(i64::from(reverse)).ok_or_else(badarg)?,
            Term::small(got as i64).ok_or_else(badarg)?,
        ])
        .map_err(|_| badarg())
}

/// The continuation of a trapped `select_count`: `{Tid, Slot|Key, MatchProgram, Got, Safety}`.
// Port of erts/emulator/beam/erl_db_hash.c (on_simple_trap), OTP-29.1.1.
pub(super) fn count_trap_continuation<H: HeapAlloc>(
    heap: &mut H,
    tid: Term,
    program_owner: &MagicBin,
    position: &ScanPosition,
    got: usize,
    safety: IterSafety,
) -> Result<Term, VmError> {
    let position = match position {
        ScanPosition::Slot(slot) => Term::small(if *slot == usize::MAX {
            -1
        } else {
            *slot as i64
        })
        .ok_or_else(badarg)?,
        ScanPosition::After(key) => copy_term(key.term(), heap).map_err(|_| badarg())?,
    };
    let reference = match_program_reference(heap, program_owner)?;
    let got = TermBuilder::new(heap)
        .int_from_i128(got as i128)
        .map_err(|_| badarg())?;
    TermBuilder::new(heap)
        .tuple(&[
            tid,
            position,
            reference,
            got,
            Term::small(encode_safety(safety)).ok_or_else(badarg)?,
        ])
        .map_err(|_| badarg())
}
