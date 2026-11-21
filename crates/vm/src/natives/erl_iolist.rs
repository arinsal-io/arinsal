//! The iolist BIFs of erl_iolist.c.
//!
//! Port of erts/emulator/beam/erl_iolist.c (iolist_size_1, iolist_size_continue,
//! iolist_size_dispatch, list_to_bitstring_bif, list_to_bitstring_engine,
//! list_to_bitstring_dispatch, list_to_bitstring_continue, iolist_to_iovec_1,
//! iolist_to_iovec_engine, iolist_to_iovec_dispatch, iolist_to_iovec_continue), OTP-29.1.1.
//! Each BIF is `bif_table[].f` with `(c_p, reg, I)`; the passes are `generic_iolist_size` and
//! `generic_iolist_copy` of `erl_iolist_generic.rs`. A walk that runs out of reductions keeps its
//! state in a magic binary, disables collection and `BIF_TRAP1`s to the hidden
//! `erts_internal:*_continue/1` export (installed by `erts_init_trap_export`) with the magic
//! reference in X0.

use crate::bif_traps::TrapContext;
use crate::natives::bif::bif_ret;
use crate::natives::erl_iolist_generic::{
    CopyState, IolistAction, IolistState, NO_VEC, generic_iolist_copy, generic_iolist_size,
};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, BifError, Ctx, ProcessHeapHandle};
use arinsal_term::raw::{BinRef, Cons, UninitBitstring};
use arinsal_term::{MagicBin, Term, TermBuilder};

/// `CONTEXT_REDS`.
const CONTEXT_REDS: usize = 4000;
/// `IOL2B_MIN_EXEC_REDS` and `IOL2B_RESCHED_REDS`.
const IOL2B_MIN_EXEC_REDS: usize = CONTEXT_REDS / 4;
const IOL2B_RESCHED_REDS: usize = CONTEXT_REDS / 40;
/// `IOLIST_SIZE_MAX_BIGNUM_ARITY`.
const IOLIST_SIZE_MAX_BIGNUM_ARITY: usize = 64;

/// `sizeof(IOListSizeState)`, `sizeof(ErtsL2BState)` and `sizeof(ErtsIOList2VecState)` on a
/// 64-bit build: the magic binaries' `orig_size`.
// Port of erts/emulator/beam/erl_iolist.c (IOListSizeState, ErtsL2BState, ErtsIOList2VecState),
// OTP-29.1.1.
const ERTS_IOLIST_SIZE_STATE_SIZE: usize = 88;
const ERTS_L2B_STATE_SIZE: usize = 88;
const ERTS_IOLIST_TO_IOVEC_STATE_SIZE: usize = 152;

/// `IOL2V_COPY_THRESHOLD`: `ERL_ONHEAP_BITS_LIMIT * 8` bits.
const IOL2V_COPY_THRESHOLD: usize = 64 * 8 * 8;

const LIST_TO_BITSTRING_CONTINUE: &str = "erts_internal:list_to_bitstring_continue/1";
const IOLIST_TO_IOVEC_CONTINUE: &str = "erts_internal:iolist_to_iovec_continue/1";

/// `IOListSizeState`.
struct SizeState {
    iolist: IolistState,
    accumulator: Option<Term>,
    arg: Term,
}

type SizeHolder = TrapContext<Option<SizeState>>;

/// `ErtsL2BState`.
struct L2bState {
    copy: CopyState,
    result: Term,
    arg: Term,
    bif: &'static str,
    /// 8 for `list_to_binary` and friends, 1 for `list_to_bitstring`: selects the
    /// `iolist_to_buf_size` and `iolist_to_buf` pair.
    unit: usize,
}

type L2bHolder = TrapContext<Option<L2bState>>;

/// `ErtsIOList2VecState`.
struct VecState {
    copy: CopyState,
    result: Term,
    arg: Term,
}

type VecHolder = TrapContext<Option<VecState>>;

/// `BUMP_REDS(c_p, reds)`.
pub(crate) fn charge(process: &mut crate::Process, reds: usize) {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    ctx.charge_reductions(reds);
}

/// `erts_set_gc_state(c_p, 1)`: whether delayed GC tasks were moved back to the system queue.
pub(crate) fn gc_enable(process: &mut crate::Process) -> bool {
    process.erts_set_gc_state_enable()
}

/// The magic reference of a new trap state: `erts_create_magic_binary` + `erts_mk_magic_ref`,
/// then `erts_set_gc_state(c_p, 0)`.
pub(crate) fn create_holder<T: arinsal_term::MagicPayload>(
    process: &mut crate::Process,
    holder: T,
    c_size: usize,
) -> Option<Term> {
    let state: MagicBin = MagicBin::with_erts_payload_size_and_refn(
        holder,
        c_size,
        arinsal_sched::unique::next_ref_words(),
    );
    let mref = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        TermBuilder::new(&mut heap).magic_ref(state).ok()?
    };
    process.set_gc_enabled(false);
    Some(mref)
}

/// `ERTS_BIF_ERROR_TRAPPED1(c_p, reason, bif, arg)` after `erts_set_gc_state(c_p, 1)` of a
/// parked call (`ERTS_VBUMP_ALL_REDS` when that moved delayed GC tasks).
#[allow(clippy::too_many_arguments)]
fn fail(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    bif: &'static str,
    arg: Term,
    error: BifError,
    gc_disabled: bool,
) -> u64 {
    if gc_disabled && gc_enable(process) {
        crate::bif_traps::vbump_all_reds(process);
    }
    crate::bif_table::set_bif_arg(reg, 0, arg);
    let (module, rest) = bif.split_once(':').unwrap_or(("erlang", bif));
    let function = rest.split_once('/').map_or(rest, |(function, _)| function);
    let error = crate::exceptions::bif_error(process, module, function, &[arg], error);
    bif_ret(c_p, i, Err(error))
}

/// `BIF_TRAP1(&<continue>_export, c_p, mref)`.
fn trap_continue(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    mref: Term,
) -> u64 {
    let trap = crate::natives::erl_bif_lists::bif_trap(process, export, vec![mref]);
    bif_ret(c_p, i, Err(trap))
}

/// `erlang:iolist_size/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_size_1), OTP-29.1.1.
pub(crate) extern "C" fn iolist_size_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [arg] = crate::bif_table::bif_args::<1>(reg);
    let mut state = SizeState {
        iolist: IolistState::new(arg),
        accumulator: None,
        arg,
    };
    state.iolist.set_reds_left(process);
    iolist_size_dispatch(c_p, reg, i, process, state, None)
}

/// `erts_internal:iolist_size_continue/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_size_continue), OTP-29.1.1.
pub(crate) extern "C" fn iolist_size_continue_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [mref] = crate::bif_table::bif_args::<1>(reg);
    let state = mref
        .with_magic_payload_mut::<SizeHolder, _>(|holder| holder.0.take())
        .flatten();
    match state {
        Some(mut state) => {
            state.iolist.set_reds_left(process);
            iolist_size_dispatch(c_p, reg, i, process, state, Some(mref))
        }
        None => crate::natives::bif::bif_badarg(c_p),
    }
}

/// `iolist_size_accumulate`: adds the bytes counted so far to the accumulator integer, which
/// becomes a bignum only after an overflow of the word-sized count.
// Port of erts/emulator/beam/erl_iolist.c (iolist_size_accumulate), OTP-29.1.1.
fn iolist_size_accumulate(
    process: &mut crate::Process,
    state: &mut SizeState,
    size_in_bytes: usize,
) -> Result<(), BifError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let size = u64::try_from(size_in_bytes).map_err(|_| BifError::SystemLimit)?;
    let accumulated = match state.accumulator {
        None => builder.int_from_u64(size),
        Some(acc) if acc.as_small().is_some() => {
            let total = size
                .checked_add(acc.as_small().map_or(0, |small| small as u64))
                .ok_or(BifError::SystemLimit)?;
            builder.int_from_u64(total)
        }
        Some(acc) => {
            let guessed = acc.bignum_digit_count().map_or(0, |digits| digits + 2);
            if guessed > IOLIST_SIZE_MAX_BIGNUM_ARITY {
                return Err(BifError::SystemLimit);
            }
            let small = builder
                .int_from_u64(size)
                .map_err(|_| BifError::SystemLimit)?;
            state.accumulator =
                Some(arinsal_arith::add(acc, small, &mut heap).map_err(|_| BifError::SystemLimit)?);
            return Ok(());
        }
    };
    state.accumulator = Some(accumulated.map_err(|_| BifError::SystemLimit)?);
    Ok(())
}

/// `iolist_size_dispatch`: the size, `BIF_TRAP1` to `iolist_size_continue_export`, or
/// `iolist_size_dispatch`: the size, `BIF_TRAP1` to `iolist_size_continue_export`, or
/// `ERTS_BIF_ERROR_TRAPPED1` naming `iolist_size/1` with the original argument.
// Port of erts/emulator/beam/erl_iolist.c (iolist_size_dispatch), OTP-29.1.1.
fn iolist_size_dispatch(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    mut state: SizeState,
    mref: Option<Term>,
) -> u64 {
    const BIF: &str = "erlang:iolist_size/1";
    let gc_disabled = mref.is_some();
    let error = loop {
        match generic_iolist_size::<8>(&mut state.iolist, process, NO_VEC) {
            IolistAction::Yield => {
                let arg = state.arg;
                let mref = match mref {
                    Some(mref) => {
                        let _ = mref.with_magic_payload_mut::<SizeHolder, _>(|holder| {
                            holder.0 = Some(state);
                        });
                        mref
                    }
                    None => {
                        match create_holder(
                            process,
                            SizeHolder::new(Some(state)),
                            ERTS_IOLIST_SIZE_STATE_SIZE,
                        ) {
                            Some(mref) => mref,
                            None => {
                                return fail(
                                    c_p,
                                    reg,
                                    i,
                                    process,
                                    BIF,
                                    arg,
                                    BifError::SystemLimit,
                                    false,
                                );
                            }
                        }
                    }
                };
                return trap_continue(
                    c_p,
                    i,
                    process,
                    "erts_internal:iolist_size_continue/1",
                    mref,
                );
            }
            IolistAction::Ok => {
                let bytes = std::mem::take(&mut state.iolist.size) / 8;
                match iolist_size_accumulate(process, &mut state, bytes) {
                    Ok(()) => {
                        if gc_disabled {
                            process.set_gc_enabled(true);
                        }
                        return crate::native_hooks::raw(
                            state.accumulator.expect("the accumulator was just set"),
                        );
                    }
                    Err(error) => break error,
                }
            }
            IolistAction::Overflow => {
                // Result too large to fit into the size: accumulate the current size in an
                // integer term and start over where the walk stopped.
                let bytes = std::mem::take(&mut state.iolist.size) / 8;
                if let Err(error) = iolist_size_accumulate(process, &mut state, bytes) {
                    break error;
                }
            }
            IolistAction::Type => break BifError::BADARG,
        }
    };
    fail(c_p, reg, i, process, BIF, state.arg, error, gc_disabled)
}

// ---- list_to_bitstring family ------------------------------------------------------------

/// `binary:list_to_bin/1`.
// Port of erts/emulator/beam/erl_iolist.c (binary_list_to_bin_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_list_to_bin_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    list_to_bitstring_bif(c_p, reg, i, "binary:list_to_bin/1", 8, false)
}

/// `erlang:list_to_binary/1`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_binary_1), OTP-29.1.1.
pub(crate) extern "C" fn list_to_binary_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    list_to_bitstring_bif(c_p, reg, i, "erlang:list_to_binary/1", 8, false)
}

/// `erlang:iolist_to_binary/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_binary_1), OTP-29.1.1.
pub(crate) extern "C" fn iolist_to_binary_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    list_to_bitstring_bif(c_p, reg, i, "erlang:iolist_to_binary/1", 8, true)
}

/// `erlang:list_to_bitstring/1`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_bitstring_1), OTP-29.1.1.
pub(crate) extern "C" fn list_to_bitstring_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    list_to_bitstring_bif(c_p, reg, i, "erlang:list_to_bitstring/1", 1, false)
}

/// `list_to_bitstring_bif`, with the `is_bitstring` head of `iolist_to_binary_1`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_bitstring_bif, iolist_to_binary_1),
// OTP-29.1.1.
fn list_to_bitstring_bif(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    bif: &'static str,
    unit: usize,
    iolist_to_binary: bool,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [arg] = crate::bif_table::bif_args::<1>(reg);
    if iolist_to_binary && let Ok(view) = BinRef::try_from(arg) {
        return if view.bit_len() % 8 == 0 {
            crate::native_hooks::raw(arg)
        } else {
            crate::natives::bif::bif_badarg(c_p)
        };
    }
    let mut reds_left = i64::from(process.heap.abi.fcalls);
    if reds_left < IOL2B_MIN_EXEC_REDS as i64 {
        if reds_left <= IOL2B_RESCHED_REDS as i64 {
            // ERTS_BIF_YIELD1(bif, c_p, arg): ERTS_VBUMP_ALL_REDS, then BIF_TRAP1 to itself.
            crate::bif_traps::vbump_all_reds(process);
            let trap = crate::natives::erl_bif_lists::bif_trap(process, bif, vec![arg]);
            return bif_ret(c_p, i, Err(trap));
        }
        // Allow a bit more reductions...
        reds_left = IOL2B_MIN_EXEC_REDS as i64;
    }
    if arg == Term::NIL {
        let built = {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            TermBuilder::new(&mut heap).bitstring(&[], 0)
        };
        return match built {
            Ok(value) => crate::native_hooks::raw(value),
            Err(_) => fail(c_p, reg, i, process, bif, arg, BifError::SystemLimit, false),
        };
    }
    let Ok(cons) = Cons::try_from(arg) else {
        return crate::natives::bif::bif_badarg(c_p);
    };
    // Check for the `[bitstring()]` case.
    let (head, tail) = cons.pair();
    if let Ok(view) = BinRef::try_from(head)
        && tail == Term::NIL
        && view.bit_len() % unit == 0
    {
        return crate::native_hooks::raw(head);
    }
    let mut state = L2bState {
        copy: CopyState::new(arg),
        result: Term::NIL,
        arg,
        bif,
        unit,
    };
    state.copy.iolist.reds_left = reds_left;
    list_to_bitstring_dispatch(c_p, reg, i, process, state, None)
}

/// `erts_internal:list_to_bitstring_continue/1`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_bitstring_continue), OTP-29.1.1.
pub(crate) extern "C" fn list_to_bitstring_continue_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [mref] = crate::bif_table::bif_args::<1>(reg);
    let state = mref
        .with_magic_payload_mut::<L2bHolder, _>(|holder| holder.0.take())
        .flatten();
    match state {
        Some(mut state) => {
            state.copy.iolist.set_reds_left(process);
            list_to_bitstring_dispatch(c_p, reg, i, process, state, Some(mref))
        }
        None => crate::natives::bif::bif_badarg(c_p),
    }
}

/// `list_to_bitstring_engine`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_bitstring_engine), OTP-29.1.1.
fn list_to_bitstring_engine(sp: &mut L2bState, process: &mut crate::Process) -> IolistAction {
    // have_size == 0 until iolist_to_buf_size finishes.
    if !sp.copy.iolist.have_size {
        let action = if sp.unit == 8 {
            generic_iolist_size::<8>(&mut sp.copy.iolist, process, NO_VEC)
        } else {
            generic_iolist_size::<1>(&mut sp.copy.iolist, process, NO_VEC)
        };
        if action != IolistAction::Ok {
            return action;
        }
        let output = UninitBitstring::allocate_bits(
            &mut ProcessHeapHandle(&mut process.heap),
            sp.copy.iolist.size,
        )
        .expect("HAlloc");
        sp.result = output.term();
        if sp.copy.iolist.size == 0 {
            return IolistAction::Ok;
        }
        sp.copy.to_base = Some(output);
        sp.copy.iolist.obj = sp.arg;
        if sp.copy.iolist.reds_left <= 0 {
            process.heap.abi.fcalls = 0;
            return IolistAction::Yield;
        }
    }
    if sp.unit == 8 {
        generic_iolist_copy::<8>(&mut sp.copy, process, NO_VEC)
    } else {
        generic_iolist_copy::<1>(&mut sp.copy, process, NO_VEC)
    }
}

/// `list_to_bitstring_dispatch`: the result, `BIF_TRAP1` to `list_to_bitstring_continue_export`,
/// or `ERTS_BIF_ERROR_TRAPPED1` naming the BIF that was called.
// Port of erts/emulator/beam/erl_iolist.c (list_to_bitstring_dispatch), OTP-29.1.1.
fn list_to_bitstring_dispatch(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    mut state: L2bState,
    mref: Option<Term>,
) -> u64 {
    let gc_disabled = mref.is_some();
    let (bif, arg) = (state.bif, state.arg);
    match list_to_bitstring_engine(&mut state, process) {
        IolistAction::Ok => {
            if gc_disabled {
                process.set_gc_enabled(true);
            }
            crate::native_hooks::raw(state.result)
        }
        IolistAction::Yield => {
            let mref = match mref {
                Some(mref) => {
                    let _ = mref.with_magic_payload_mut::<L2bHolder, _>(|holder| {
                        holder.0 = Some(state);
                    });
                    mref
                }
                None => {
                    match create_holder(process, L2bHolder::new(Some(state)), ERTS_L2B_STATE_SIZE) {
                        Some(mref) => mref,
                        None => {
                            return fail(
                                c_p,
                                reg,
                                i,
                                process,
                                bif,
                                arg,
                                BifError::SystemLimit,
                                false,
                            );
                        }
                    }
                }
            };
            trap_continue(c_p, i, process, LIST_TO_BITSTRING_CONTINUE, mref)
        }
        action => {
            let error = if action == IolistAction::Overflow {
                BifError::SystemLimit
            } else {
                BifError::BADARG
            };
            fail(c_p, reg, i, process, bif, arg, error, gc_disabled)
        }
    }
}

// ---- iolist_to_iovec ---------------------------------------------------------------------

/// `erlang:iolist_to_iovec/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_1), OTP-29.1.1.
pub(crate) extern "C" fn iolist_to_iovec_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    const BIF: &str = "erlang:iolist_to_iovec/1";
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [arg] = crate::bif_table::bif_args::<1>(reg);
    let badarg = || crate::natives::bif::bif_badarg(c_p);
    // `[]`, `Bin` and `[Bin]` need no traversal.
    let single = if arg == Term::NIL {
        return crate::native_hooks::raw(Term::NIL);
    } else if let Ok(view) = BinRef::try_from(arg) {
        (view.bit_len(), arg, false)
    } else if let Ok(cons) = Cons::try_from(arg) {
        let (head, tail) = cons.pair();
        match BinRef::try_from(head) {
            Ok(view) if tail == Term::NIL => (view.bit_len(), head, true),
            _ => (0, Term::NIL, false),
        }
    } else {
        return badarg();
    };
    if single.1 != Term::NIL {
        let (bits, bin, listed) = single;
        if bits % 8 != 0 {
            return badarg();
        }
        if bits == 0 {
            return crate::native_hooks::raw(Term::NIL);
        }
        if listed {
            return crate::native_hooks::raw(arg);
        }
        let cell =
            TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap)).list_from_iter([bin]);
        return match cell {
            Ok(value) => crate::native_hooks::raw(value),
            Err(_) => fail(c_p, reg, i, process, BIF, arg, BifError::SystemLimit, false),
        };
    }
    let mut state = VecState {
        copy: CopyState::new(arg),
        result: Term::NIL,
        arg,
    };
    state.copy.iolist.set_reds_left(process);
    iolist_to_iovec_dispatch(c_p, reg, i, process, state, None)
}

/// `erts_internal:iolist_to_iovec_continue/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_continue), OTP-29.1.1.
pub(crate) extern "C" fn iolist_to_iovec_continue_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [mref] = crate::bif_table::bif_args::<1>(reg);
    let state = mref
        .with_magic_payload_mut::<VecHolder, _>(|holder| holder.0.take())
        .flatten();
    match state {
        Some(mut state) => {
            state.copy.iolist.set_reds_left(process);
            iolist_to_iovec_dispatch(c_p, reg, i, process, state, Some(mref))
        }
        None => crate::natives::bif::bif_badarg(c_p),
    }
}

/// `iolist_to_iovec_engine`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_engine), OTP-29.1.1.
fn iolist_to_iovec_engine(state: &mut VecState, process: &mut crate::Process) -> IolistAction {
    // have_size == 0 until iolist_to_iovec_size finishes.
    if !state.copy.iolist.have_size {
        let action =
            generic_iolist_size::<8>(&mut state.copy.iolist, process, IOL2V_COPY_THRESHOLD);
        if action != IolistAction::Ok {
            return action;
        }
        state.result = Term::NIL;
        state.copy.start_vec_result();
        // We cannot fail from here on. Allocate a common off-heap binary for all copied
        // components if need be.
        if state.copy.iolist.size > 0 {
            let output = UninitBitstring::allocate(
                &mut ProcessHeapHandle(&mut process.heap),
                state.copy.iolist.size / 8,
            )
            .expect("HAlloc");
            state.copy.set_vec_output(output);
        }
        state.copy.iolist.obj = state.arg;
        if state.copy.iolist.reds_left <= 0 {
            process.heap.abi.fcalls = 0;
            return IolistAction::Yield;
        }
    }
    let action = generic_iolist_copy::<8>(&mut state.copy, process, IOL2V_COPY_THRESHOLD);
    if action == IolistAction::Ok {
        state.result = state.copy.take_vec_result();
    }
    action
}

/// `iolist_to_iovec_dispatch`: run the engine, then return the result, `BIF_TRAP1` to
/// `iolist_to_iovec_continue_export` with the state in a magic binary, or
/// `ERTS_BIF_ERROR_TRAPPED1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_dispatch), OTP-29.1.1.
fn iolist_to_iovec_dispatch(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    mut state: VecState,
    mref: Option<Term>,
) -> u64 {
    const BIF: &str = "erlang:iolist_to_iovec/1";
    let gc_disabled = mref.is_some();
    let arg = state.arg;
    match iolist_to_iovec_engine(&mut state, process) {
        IolistAction::Ok => {
            if gc_disabled {
                process.set_gc_enabled(true);
            }
            crate::native_hooks::raw(state.result)
        }
        IolistAction::Yield => {
            let mref = match mref {
                Some(mref) => {
                    let _ = mref.with_magic_payload_mut::<VecHolder, _>(|holder| {
                        holder.0 = Some(state);
                    });
                    mref
                }
                None => {
                    match create_holder(
                        process,
                        VecHolder::new(Some(state)),
                        ERTS_IOLIST_TO_IOVEC_STATE_SIZE,
                    ) {
                        Some(mref) => mref,
                        None => {
                            return fail(
                                c_p,
                                reg,
                                i,
                                process,
                                BIF,
                                arg,
                                BifError::SystemLimit,
                                false,
                            );
                        }
                    }
                }
            };
            trap_continue(c_p, i, process, IOLIST_TO_IOVEC_CONTINUE, mref)
        }
        action => {
            let error = if action == IolistAction::Overflow {
                BifError::SystemLimit
            } else {
                BifError::BADARG
            };
            fail(c_p, reg, i, process, BIF, arg, error, gc_disabled)
        }
    }
}

arinsal_term::magic_payload!(
    SizeHolder => iolist_size_destructor,
    L2bHolder => list_to_bitstring_destructor,
    VecHolder => iolist_to_iovec_destructor,
);
