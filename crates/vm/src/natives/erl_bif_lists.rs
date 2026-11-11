//! The list BIFs of erl_bif_lists.c.
//!
//! Port of erts/emulator/beam/erl_bif_lists.c (append, ebif_plusplus_2, append_2, subtract,
//! ebif_minusminus_2, subtract_2, lists_member_2, lists_reverse_2, lists_keymember_3,
//! lists_keysearch_3, lists_keyfind_3), OTP-29.1.1. Each BIF is `bif_table[].f` with
//! `(c_p, reg, I)`. Work is charged with `BUMP_REDS` on `c_p->fcalls` only; `BIF_TRAP*` goes
//! to the BIF's own export with the arguments erts passes (the remaining list, or a magic
//! reference to the `ErtsAppendContext` / `ErtsSubtractContext` for `++` and `--`).

use crate::VmError;
use crate::natives::bif::{badarg, bif_ret};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{
    AppendCont, AppendStep, BifCall, Ctx, KeyOp, KeyOutcome, MemberStep, ProcessHeapHandle,
    ReverseStep, SubtractWalk,
};
use arinsal_term::{MagicRef, Term, TermBuilder, atoms};
use std::sync::{Arc, Mutex};

/// `sizeof(ErtsAppendContext)` on a 64-bit build: the magic binary's `orig_size`.
// Port of erts/emulator/beam/erl_bif_lists.c (ErtsAppendContext), OTP-29.1.1.
const ERTS_APPEND_CONTEXT_SIZE: usize = 40;
/// `sizeof(ErtsSubtractContext)` on a 64-bit build.
// Port of erts/emulator/beam/erl_bif_lists.c (ErtsSubtractContext), OTP-29.1.1.
const ERTS_SUBTRACT_CONTEXT_SIZE: usize = 192;

/// `is_list(term)`: the list primary tag.
#[inline(always)]
fn is_list(term: Term) -> bool {
    term.tagged_word() & 3 == 1
}

/// `ERTS_BIF_REDS_LEFT(c_p)`.
// Port of erts/emulator/beam/bif.h (ERTS_BIF_REDS_LEFT), OTP-29.1.1.
#[inline(always)]
fn bif_reds_left(process: &crate::Process) -> usize {
    process.heap.abi.fcalls.max(0) as usize
}

/// `BIF_TRAPn(BIF_TRAP_EXPORT(bif), c_p, args...)`.
#[cold]
#[inline(never)]
fn bif_trap(process: &mut crate::Process, export: &'static str, args: Vec<Term>) -> VmError {
    VmError::TrapExport(crate::ExportTrap::new(process, export, args))
}

/// `true` / `false`.
#[inline(always)]
fn boolean(value: bool) -> u64 {
    crate::native_hooks::raw(Term::atom(if value { atoms::TRUE } else { atoms::FALSE }))
}

/// `erlang:'++'/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (ebif_plusplus_2), OTP-29.1.1.
pub(crate) extern "C" fn ebif_plusplus_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    append(c_p, i, "erlang:++/2")
}

/// `erlang:append/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (append_2), OTP-29.1.1.
pub(crate) extern "C" fn append_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    append(c_p, i, "erlang:append/2")
}

/// `append(bif_entry, BIF_ALIST_2)`: `[] ++ Rhs` is Rhs, and a left list that fits the young
/// heap and the reduction budget is copied by `lists_append_onheap` with the context on the
/// stack. Everything else is [`append_general`].
// Port of erts/emulator/beam/erl_bif_lists.c (append, append_start, lists_append_onheap),
// OTP-29.1.1.
#[inline(always)]
fn append(c_p: *mut ProcessHeader, i: u64, bif_entry: &'static str) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (lhs, rhs) = (process.x[0], process.x[1]);
    // `[] ++ 'not_a_list'` has always been 'not_a_list'.
    if let Some(value) = arinsal_bifs::append_onheap_direct(&mut process.heap, lhs, rhs) {
        return crate::native_hooks::raw(value);
    }
    append_general(c_p, i, process, lhs, rhs, bif_entry)
}

/// The rest of `append`: a list that needs `append_empty_rhs` or `lists_append_alloc` or
/// traps, a resumed trap state, or `BIF_ERROR`.
// Port of erts/emulator/beam/erl_bif_lists.c (append), OTP-29.1.1.
#[cold]
#[inline(never)]
fn append_general(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    lhs: Term,
    rhs: Term,
    bif_entry: &'static str,
) -> u64 {
    if is_list(lhs) {
        return append_start(c_p, i, process, lhs, rhs, bif_entry);
    }
    let resumed = lhs.with_magic_payload::<Mutex<AppendCont>, _>(|context| {
        std::mem::replace(
            &mut *context.lock().expect("append context"),
            AppendCont::start(Term::NIL, Term::NIL),
        )
    });
    let Some(context) = resumed else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    // ASSERT(BIF_P->flags & F_DISABLE_GC); ASSERT(rhs == NIL);
    let (lhs_original, rhs_original) = (context.lhs_original(), context.rhs());
    match append_continue(process, context) {
        Ok(AppendStep::Done(value)) => {
            process.set_gc_enabled(true);
            crate::native_hooks::raw(value)
        }
        Ok(AppendStep::More(next)) => {
            let _ = lhs.with_magic_payload::<Mutex<AppendCont>, _>(|context| {
                *context.lock().expect("append context") = next;
            });
            let trap = bif_trap(process, bif_entry, vec![lhs, Term::NIL]);
            bif_ret(c_p, i, Err(trap))
        }
        Err(_) => {
            process.set_gc_enabled(true);
            // ERTS_BIF_ERROR_TRAPPED2: the error names the original arguments.
            process.x[0] = lhs_original;
            process.x[1] = rhs_original;
            bif_ret(c_p, i, Err(badarg()))
        }
    }
}

/// `append_start` and the first `BIF_TRAP2` with a new trap state.
#[inline(always)]
fn append_start(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    lhs: Term,
    rhs: Term,
    bif_entry: &'static str,
) -> u64 {
    match append_continue(process, AppendCont::start(lhs, rhs)) {
        Ok(AppendStep::Done(value)) => crate::native_hooks::raw(value),
        Ok(AppendStep::More(context)) => {
            // append_create_trap_state, then erts_set_gc_state(BIF_P, 0): the context points
            // into the unfinished result on the heap.
            let state_mref = match create_trap_state(process, context, ERTS_APPEND_CONTEXT_SIZE) {
                Ok(state_mref) => state_mref,
                Err(error) => return bif_ret(c_p, i, Err(error)),
            };
            process.set_gc_enabled(false);
            let trap = bif_trap(process, bif_entry, vec![state_mref, Term::NIL]);
            bif_ret(c_p, i, Err(trap))
        }
        Err(_) => bif_ret(c_p, i, Err(badarg())),
    }
}

/// `append_continue`: `append_empty_rhs`, `lists_append_onheap` or `lists_append_alloc`, each
/// sized by `ERTS_BIF_REDS_LEFT` and charging `BUMP_REDS`.
// Port of erts/emulator/beam/erl_bif_lists.c (append_continue), OTP-29.1.1.
fn append_continue(
    process: &mut crate::Process,
    context: AppendCont,
) -> Result<AppendStep, arinsal_bifs::BifError> {
    let reds = bif_reds_left(process);
    let (onheap, alloc) = if context.rhs() == Term::NIL {
        (reds.saturating_mul(arinsal_bifs::APPEND_EMPTY_PER_RED), 0)
    } else {
        (
            reds.saturating_mul(arinsal_bifs::APPEND_ONHEAP_PER_RED),
            reds.saturating_mul(arinsal_bifs::APPEND_ALLOC_PER_RED),
        )
    };
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    arinsal_bifs::lists_append(&mut ctx, context, onheap, alloc)
}

/// `erts_create_magic_binary` + `erts_mk_magic_ref` of a trap context.
// Port of erts/emulator/beam/erl_bif_lists.c (append_create_trap_state,
// subtract_create_trap_state), OTP-29.1.1.
fn create_trap_state<T: std::any::Any + Send>(
    process: &mut crate::Process,
    context: T,
    c_size: usize,
) -> Result<Term, VmError> {
    let state: Arc<MagicRef> = MagicRef::with_erts_payload_size_and_refn(
        Mutex::new(context),
        c_size,
        arinsal_bifs::next_ref_words(),
    );
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap).magic_ref(state).map_err(|_| {
        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            atoms::SYSTEM_LIMIT,
        )))
    })
}

/// `erlang:'--'/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (ebif_minusminus_2), OTP-29.1.1.
pub(crate) extern "C" fn ebif_minusminus_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    subtract(c_p, i, "erlang:--/2")
}

/// `erlang:subtract/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (subtract_2), OTP-29.1.1.
pub(crate) extern "C" fn subtract_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    subtract(c_p, i, "erlang:subtract/2")
}

/// `subtract(bif_entry, BIF_ALIST_2)`: two lists start the stages with the context on the
/// stack; a call that finishes in this slice returns at once.
// Port of erts/emulator/beam/erl_bif_lists.c (subtract, subtract_start), OTP-29.1.1.
#[inline(always)]
fn subtract(c_p: *mut ProcessHeader, i: u64, bif_entry: &'static str) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (lhs, rhs) = (process.x[0], process.x[1]);
    if (is_list(lhs) || lhs == Term::NIL) && (is_list(rhs) || rhs == Term::NIL) {
        let Ok(mut context) = SubtractWalk::new(lhs, rhs) else {
            return bif_ret(c_p, i, Err(badarg()));
        };
        let result = subtract_continue(process, &mut context);
        if let Ok(Some(value)) = result {
            return crate::native_hooks::raw(value);
        }
        return subtract_first_slice_end(c_p, i, process, context, result.is_ok(), bif_entry);
    }
    subtract_resume(c_p, i, process, lhs, bif_entry)
}

/// The first call ran out of reductions (`subtract_create_trap_state`, then
/// `BIF_TRAP2(bif_entry, state_mref, NIL)` with collection disabled) or failed.
#[cold]
#[inline(never)]
fn subtract_first_slice_end(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    context: SubtractWalk,
    trapped: bool,
    bif_entry: &'static str,
) -> u64 {
    if !trapped {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let state_mref = match create_trap_state(process, context, ERTS_SUBTRACT_CONTEXT_SIZE) {
        Ok(state_mref) => state_mref,
        Err(error) => return bif_ret(c_p, i, Err(error)),
    };
    process.set_gc_enabled(false);
    let trap = bif_trap(process, bif_entry, vec![state_mref, Term::NIL]);
    bif_ret(c_p, i, Err(trap))
}

/// `subtract` called with its trap state: the next stages, or `BIF_ERROR` for any other
/// argument.
// Port of erts/emulator/beam/erl_bif_lists.c (subtract: the is_internal_magic_ref arm),
// OTP-29.1.1.
#[cold]
#[inline(never)]
fn subtract_resume(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    lhs: Term,
    bif_entry: &'static str,
) -> u64 {
    let resumed = lhs.with_magic_payload::<Mutex<SubtractWalk>, _>(|context| {
        let mut context = context.lock().expect("subtract context");
        let originals = context.originals();
        (subtract_continue(process, &mut context), originals)
    });
    let Some((result, (lhs_original, rhs_original))) = resumed else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    match result {
        Ok(None) => {
            let trap = bif_trap(process, bif_entry, vec![lhs, Term::NIL]);
            bif_ret(c_p, i, Err(trap))
        }
        Ok(Some(value)) => {
            process.set_gc_enabled(true);
            crate::native_hooks::raw(value)
        }
        Err(_) => {
            process.set_gc_enabled(true);
            // ERTS_BIF_ERROR_TRAPPED2: the error names the original arguments.
            process.x[0] = lhs_original;
            process.x[1] = rhs_original;
            bif_ret(c_p, i, Err(badarg()))
        }
    }
}

/// `subtract_continue`: the next stages, each sized by `ERTS_BIF_REDS_LEFT`.
// Port of erts/emulator/beam/erl_bif_lists.c (subtract_continue), OTP-29.1.1.
#[inline(always)]
fn subtract_continue(
    process: &mut crate::Process,
    context: &mut SubtractWalk,
) -> Result<Option<Term>, arinsal_bifs::BifError> {
    let reds = bif_reds_left(process);
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    context.step(&mut ctx, reds)
}

/// `lists:member/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_member_2), OTP-29.1.1.
pub(crate) extern "C" fn lists_member_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (term, list) = (process.x[0], process.x[1]);
    let max_iter = bif_reds_left(process).saturating_mul(arinsal_bifs::MEMBER_PER_RED);
    let step = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut call = BifCall::default();
        let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
        arinsal_bifs::lists_member(&mut ctx, term, list, max_iter)
    };
    match step {
        Ok(MemberStep::Done(found)) => boolean(found),
        Ok(MemberStep::More(cont)) => {
            // BUMP_ALL_REDS was charged by the scan.
            let trap = bif_trap(process, "lists:member/2", vec![cont.term(), cont.list()]);
            bif_ret(c_p, i, Err(trap))
        }
        Err(_) => bif_ret(c_p, i, Err(badarg())),
    }
}

/// `lists:reverse/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_reverse_2, lists_reverse_onheap,
// lists_reverse_alloc), OTP-29.1.1.
pub(crate) extern "C" fn lists_reverse_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (list, tail) = (process.x[0], process.x[1]);
    // `[]` returns the tail; lists_reverse_onheap when the whole reversal fits the young heap
    // and the budget.
    if let Some(value) = arinsal_bifs::reverse_onheap_direct(&mut process.heap, list, tail) {
        return crate::native_hooks::raw(value);
    }
    lists_reverse_slice(c_p, i, process, list, tail)
}

/// The rest of `lists_reverse_2`: on-heap then alloc fill, `BIF_TRAP2` with the remaining list
/// and the reversed prefix, or `BIF_ERROR`.
#[cold]
#[inline(never)]
fn lists_reverse_slice(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    list: Term,
    tail: Term,
) -> u64 {
    if !is_list(list) {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let step = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut call = BifCall::default();
        let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
        arinsal_bifs::lists_reverse(&mut ctx, list, tail, usize::MAX)
    };
    match step {
        Ok(ReverseStep::Done(value)) => crate::native_hooks::raw(value),
        Ok(ReverseStep::Trap(cont)) => {
            let trap = bif_trap(process, "lists:reverse/2", vec![cont.list(), cont.tail()]);
            bif_ret(c_p, i, Err(trap))
        }
        Err(_) => bif_ret(c_p, i, Err(badarg())),
    }
}

/// `lists:keymember/3`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_keymember_3), OTP-29.1.1.
pub(crate) extern "C" fn lists_keymember_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    keyfind(c_p, i, KeyOp::Member, "lists:keymember/3")
}

/// `lists:keysearch/3`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_keysearch_3), OTP-29.1.1.
pub(crate) extern "C" fn lists_keysearch_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    keyfind(c_p, i, KeyOp::Search, "lists:keysearch/3")
}

/// `lists:keyfind/3`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_keyfind_3), OTP-29.1.1.
pub(crate) extern "C" fn lists_keyfind_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    keyfind(c_p, i, KeyOp::Find, "lists:keyfind/3")
}

/// `keyfind(Bif, p, Key, Pos, List)` and the result wrapping of its three callers. The loop
/// counts `10 * CONTEXT_REDS` elements, independent of the reductions left.
// Port of erts/emulator/beam/erl_bif_lists.c (keyfind), OTP-29.1.1.
#[inline(always)]
fn keyfind(c_p: *mut ProcessHeader, i: u64, op: KeyOp, bif: &'static str) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (key, pos, list) = (process.x[0], process.x[1], process.x[2]);
    let outcome = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut call = BifCall::default();
        let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
        let outcome =
            arinsal_bifs::lists_key(&mut ctx, op, key, pos, list, arinsal_bifs::KEYFIND_MAX_ITER);
        if matches!(outcome, Ok(KeyOutcome::More(_))) {
            // BUMP_ALL_REDS(p) before BIF_TRAP3.
            ctx.bump_all_reds();
        }
        outcome
    };
    match outcome {
        Ok(KeyOutcome::Done(value)) => crate::native_hooks::raw(value),
        Ok(KeyOutcome::More(cont)) => {
            let trap = bif_trap(process, bif, vec![cont.key(), cont.pos(), cont.list()]);
            bif_ret(c_p, i, Err(trap))
        }
        Err(_) => bif_ret(c_p, i, Err(badarg())),
    }
}
