//! The iolist BIFs of erl_iolist.c.
//!
//! Port of erts/emulator/beam/erl_iolist.c (iolist_size_1, iolist_size_continue,
//! iolist_size_dispatch, list_to_bitstring_bif, list_to_bitstring_dispatch,
//! list_to_bitstring_continue, iolist_to_iovec_1, iolist_to_iovec_continue and their engines),
//! OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`. A walk that runs out of
//! reductions keeps its state in a magic binary, disables collection and `BIF_TRAP1`s to the
//! hidden `erts_internal:*_continue/1` export (installed by `erts_init_trap_export`) with the
//! magic reference in X0.

use crate::Process;
use crate::natives::bif::bif_ret;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, BifError, Ctx, IolistSizeWalk, IolistVecWalk, ProcessHeapHandle};
use arinsal_term::{MagicRef, Term, TermBuilder, TermKind};
use std::sync::{Arc, Mutex};

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

/// Yield counts of `generic_iolist_size` per reduction left.
const SIZE_YIELDS_PER_RED: usize = 8;

const LIST_TO_BITSTRING_CONTINUE: &str = "erts_internal:list_to_bitstring_continue/1";
const IOLIST_TO_IOVEC_CONTINUE: &str = "erts_internal:iolist_to_iovec_continue/1";

/// `iolist_size_dispatch`'s state: `IOListSizeState{iolist, accumulator, arg}`.
struct SizeState {
    walk: IolistSizeWalk,
    accumulator: Option<Term>,
    arg: Term,
}

type SizeHolder = Mutex<Option<SizeState>>;

/// `ErtsL2BState`: the phase, the list being converted and the BIF that is blamed on error.
struct L2bState {
    phase: ErtsL2BState,
    root: Term,
    bif: &'static str,
}

type L2bHolder = Mutex<Option<L2bState>>;

/// `ErtsIOList2VecState`.
struct VecState {
    walk: IolistVecWalk,
    arg: Term,
}

type VecHolder = Mutex<Option<VecState>>;

/// `BUMP_REDS(c_p, reds)`.
pub(crate) fn charge(process: &mut crate::Process, reds: usize) {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    ctx.charge_reductions(reds);
}

/// `erts_set_gc_state(c_p, 1)`: whether delayed GC tasks were moved back to the system queue.
pub(crate) fn gc_enable(process: &mut crate::Process) -> bool {
    process.set_gc_enabled(true);
    process.delayed_gc_due()
}

/// The magic reference of a new trap state: `erts_create_magic_binary` + `erts_mk_magic_ref`,
/// then `erts_set_gc_state(c_p, 0)`.
pub(crate) fn create_holder<T: std::any::Any + Send + Sync>(
    process: &mut crate::Process,
    holder: T,
    c_size: usize,
) -> Option<Term> {
    let state: Arc<MagicRef> =
        MagicRef::with_erts_payload_size_and_refn(holder, c_size, arinsal_bifs::next_ref_words());
    let mref = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        TermBuilder::new(&mut heap).magic_ref(state).ok()?
    };
    process.set_gc_enabled(false);
    Some(mref)
}

/// `ERTS_BIF_ERROR_TRAPPED1(c_p, reason, bif, arg)` after `erts_set_gc_state(c_p, 1)` of a
/// parked call (`ERTS_VBUMP_ALL_REDS` when that moved delayed GC tasks).
fn fail(
    c_p: *mut ProcessHeader,
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
    process.x[0] = arg;
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
pub(crate) extern "C" fn iolist_size_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let arg = process.x[0];
    let state = SizeState {
        walk: IolistSizeWalk::new(arg),
        accumulator: None,
        arg,
    };
    iolist_size_dispatch(c_p, i, process, state, None)
}

/// `erts_internal:iolist_size_continue/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_size_continue), OTP-29.1.1.
pub(crate) extern "C" fn iolist_size_continue_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mref = process.x[0];
    let state = mref
        .with_magic_payload::<SizeHolder, _>(|holder| holder.lock().ok()?.take())
        .flatten();
    match state {
        Some(state) => iolist_size_dispatch(c_p, i, process, state, Some(mref)),
        None => bif_ret(c_p, i, Err(crate::natives::bif::badarg())),
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
/// `ERTS_BIF_ERROR_TRAPPED1` naming `iolist_size/1` with the original argument.
fn iolist_size_dispatch(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mut state: SizeState,
    mref: Option<Term>,
) -> u64 {
    const BIF: &str = "erlang:iolist_size/1";
    let gc_disabled = mref.is_some();
    loop {
        let budget = (process.heap.abi.fcalls.max(0) as usize).saturating_mul(SIZE_YIELDS_PER_RED);
        let step = state.walk.step(budget);
        let work = match step {
            Ok((_, work)) | Err((_, work)) => work,
        };
        // generic_iolist_size's BUMP_REDS of the yield counts used.
        charge(process, arinsal_bifs::iolist_yield_reductions(work));
        match step {
            Ok((false, _)) => {
                let mref = match mref {
                    Some(mref) => {
                        let _ = mref.with_magic_payload::<SizeHolder, _>(|holder| {
                            *holder.lock().expect("iolist size state") = Some(state);
                        });
                        mref
                    }
                    None => {
                        let arg = state.arg;
                        match create_holder(
                            process,
                            SizeHolder::new(Some(state)),
                            ERTS_IOLIST_SIZE_STATE_SIZE,
                        ) {
                            Some(mref) => mref,
                            None => {
                                return fail(
                                    c_p,
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
            Ok((true, _)) => {
                let size = state.walk.take_size();
                if let Err(error) = iolist_size_accumulate(process, &mut state, size) {
                    return fail(c_p, i, process, BIF, state.arg, error, gc_disabled);
                }
                if gc_disabled {
                    process.set_gc_enabled(true);
                }
                return crate::native_hooks::raw(
                    state.accumulator.expect("the accumulator was just set"),
                );
            }
            Err((BifError::SystemLimit, _)) => {
                // ERTS_IOLIST_OVERFLOW: accumulate and start over where the walk stopped.
                if let Some(bytes) = state.walk.take_overflow() {
                    match iolist_size_accumulate(process, &mut state, bytes) {
                        Ok(()) => continue,
                        Err(error) => {
                            return fail(c_p, i, process, BIF, state.arg, error, gc_disabled);
                        }
                    }
                }
                return fail(
                    c_p,
                    i,
                    process,
                    BIF,
                    state.arg,
                    BifError::SystemLimit,
                    gc_disabled,
                );
            }
            Err((error, _)) => {
                return fail(c_p, i, process, BIF, state.arg, error, gc_disabled);
            }
        }
    }
}

// ---- list_to_bitstring family ------------------------------------------------------------

/// `binary:list_to_bin/1`.
// Port of erts/emulator/beam/erl_iolist.c (binary_list_to_bin_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_list_to_bin_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    list_to_bitstring_bif(c_p, i, "binary:list_to_bin/1", 8, false)
}

/// `erlang:list_to_binary/1`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_binary_1), OTP-29.1.1.
pub(crate) extern "C" fn list_to_binary_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    list_to_bitstring_bif(c_p, i, "erlang:list_to_binary/1", 8, false)
}

/// `erlang:iolist_to_binary/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_binary_1), OTP-29.1.1.
pub(crate) extern "C" fn iolist_to_binary_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    list_to_bitstring_bif(c_p, i, "erlang:iolist_to_binary/1", 8, true)
}

/// `erlang:list_to_bitstring/1`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_bitstring_1), OTP-29.1.1.
pub(crate) extern "C" fn list_to_bitstring_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    list_to_bitstring_bif(c_p, i, "erlang:list_to_bitstring/1", 1, false)
}

/// `list_to_bitstring_bif`, with the `is_bitstring` head of `iolist_to_binary_1`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_bitstring_bif, iolist_to_binary_1),
// OTP-29.1.1.
fn list_to_bitstring_bif(
    c_p: *mut ProcessHeader,
    i: u64,
    bif: &'static str,
    unit: usize,
    iolist_to_binary: bool,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let arg = process.x[0];
    if iolist_to_binary && arg.classify() == TermKind::Bitstring {
        return match arinsal_bifs::bitstring_bit_len(arg) {
            Ok(bits) if bits % 8 == 0 => crate::native_hooks::raw(arg),
            _ => bif_ret(c_p, i, Err(crate::natives::bif::badarg())),
        };
    }
    let mut reds_left = process.heap.abi.fcalls.max(0) as usize;
    if reds_left < IOL2B_MIN_EXEC_REDS {
        if reds_left <= IOL2B_RESCHED_REDS {
            // ERTS_BIF_YIELD1(bif, c_p, arg): ERTS_VBUMP_ALL_REDS, then BIF_TRAP1 to itself.
            crate::bif_traps::vbump_all_reds(process);
            let trap = crate::natives::erl_bif_lists::bif_trap(process, bif, vec![arg]);
            return bif_ret(c_p, i, Err(trap));
        }
        reds_left = IOL2B_MIN_EXEC_REDS;
    }
    if arg == Term::NIL {
        let built = {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            TermBuilder::new(&mut heap).bitstring(&[], 0)
        };
        return match built {
            Ok(value) => crate::native_hooks::raw(value),
            Err(_) => fail(c_p, i, process, bif, arg, BifError::SystemLimit, false),
        };
    }
    if arg.classify() != TermKind::List {
        return bif_ret(c_p, i, Err(crate::natives::bif::badarg()));
    }
    // The `[bitstring()]` case.
    match arinsal_bifs::singleton_bitstring(arg, unit) {
        Ok(Some(head)) => return crate::native_hooks::raw(head),
        Ok(None) => {}
        Err(error) => return fail(c_p, i, process, bif, arg, error, false),
    }
    let walk = if unit == 8 {
        IolistSizeWalk::new(arg)
    } else {
        IolistSizeWalk::new_bits(arg)
    };
    let state = L2bState {
        phase: ErtsL2BState::Size(walk),
        root: arg,
        bif,
    };
    list_to_bitstring_dispatch(c_p, i, process, state, None, reds_left)
}

/// `erts_internal:list_to_bitstring_continue/1`.
// Port of erts/emulator/beam/erl_iolist.c (list_to_bitstring_continue), OTP-29.1.1.
pub(crate) extern "C" fn list_to_bitstring_continue_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mref = process.x[0];
    let state = mref
        .with_magic_payload::<L2bHolder, _>(|holder| holder.lock().ok()?.take())
        .flatten();
    let reds_left = process.heap.abi.fcalls.max(0) as usize;
    match state {
        Some(state) => list_to_bitstring_dispatch(c_p, i, process, state, Some(mref), reds_left),
        None => bif_ret(c_p, i, Err(crate::natives::bif::badarg())),
    }
}

/// `list_to_bitstring_dispatch`: the result, `BIF_TRAP1` to `list_to_bitstring_continue_export`,
/// or `ERTS_BIF_ERROR_TRAPPED1` naming the BIF that was called.
fn list_to_bitstring_dispatch(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mut state: L2bState,
    mref: Option<Term>,
    reds_left: usize,
) -> u64 {
    let gc_disabled = mref.is_some();
    let (bif, arg) = (state.bif, state.root);
    let step = iolist_binary_step(process, state.root, &mut state.phase, reds_left);
    match step {
        Ok(IolistStep::Done(value, reds)) => {
            charge(process, reds as usize);
            if gc_disabled {
                process.set_gc_enabled(true);
            }
            crate::native_hooks::raw(value)
        }
        Ok(IolistStep::Yield(reds)) => {
            charge(process, reds as usize);
            let mref = match mref {
                Some(mref) => {
                    let _ = mref.with_magic_payload::<L2bHolder, _>(|holder| {
                        *holder.lock().expect("l2b state") = Some(state);
                    });
                    mref
                }
                None => {
                    match create_holder(process, L2bHolder::new(Some(state)), ERTS_L2B_STATE_SIZE) {
                        Some(mref) => mref,
                        None => {
                            return fail(c_p, i, process, bif, arg, BifError::SystemLimit, false);
                        }
                    }
                }
            };
            trap_continue(c_p, i, process, LIST_TO_BITSTRING_CONTINUE, mref)
        }
        Ok(IolistStep::Fail(error, reds)) => {
            charge(process, reds as usize);
            fail(c_p, i, process, bif, arg, error, gc_disabled)
        }
        Err(error) => fail(c_p, i, process, bif, arg, error, gc_disabled),
    }
}

enum ErtsL2BState {
    Size(arinsal_bifs::IolistSizeWalk),
    Copy {
        output: IolistOutput,
        bit_len: usize,
        bitstring: bool,
        walk: arinsal_bifs::IolistCopyWalk,
    },
    Done,
}

/// Output staging for `erts_new_bitstring`: up to 64 bytes stay on heap after the walk completes.
// Port of erts/emulator/beam/erl_bits.c:2841-2858 (erts_new_bitstring_refc), OTP-29.1.1.
enum IolistOutput {
    Small(arinsal_term::HeapBinaryWriter),
    Bitstring(Vec<u8>),
    Writable(Term),
}

impl IolistOutput {
    fn finish_writer(&self) {
        if let Self::Writable(term) = self {
            arinsal_bifs::finish_iolist_binary_output(*term);
        }
    }
}

struct IolistCopySetup {
    empty: Option<Term>,
    ready: Option<(IolistOutput, usize, arinsal_bifs::IolistCopyWalk)>,
}

/// Allocate the result after the size pass of `list_to_binary/1` and friends (`bitstring` false)
/// or `list_to_bitstring/1`.
// Port of erts/emulator/beam/erl_iolist.c (`list_to_bitstring_dispatch`), OTP-29.1.1.
fn iolist_copy_setup(
    process: &mut Process,
    size: &mut arinsal_bifs::IolistSizeWalk,
    root: Term,
) -> Result<IolistCopySetup, BifError> {
    if size.is_bits() {
        let bit_len = size.take_bits();
        if bit_len == 0 {
            let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .bitstring(&[], 0)
                .map_err(|_| BifError::SystemLimit)?;
            return Ok(IolistCopySetup {
                empty: Some(value),
                ready: None,
            });
        }
        return Ok(IolistCopySetup {
            empty: None,
            ready: Some((
                IolistOutput::Bitstring(vec![0; bit_len.div_ceil(8)]),
                bit_len,
                arinsal_bifs::IolistCopyWalk::new_bits(root),
            )),
        });
    }
    let byte_len = size.take_size();
    if byte_len == 0 {
        let value = arinsal_bifs::allocate_iolist_binary(
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            0,
        )?;
        return Ok(IolistCopySetup {
            empty: Some(value),
            ready: None,
        });
    }
    if byte_len <= 64 {
        let output = match arinsal_term::HeapBinaryWriter::new(&mut process.heap, byte_len) {
            Ok(output) => output,
            Err(_) => return Err(BifError::SystemLimit),
        };
        return Ok(IolistCopySetup {
            empty: None,
            ready: Some((
                IolistOutput::Small(output),
                byte_len * 8,
                arinsal_bifs::IolistCopyWalk::new(root),
            )),
        });
    }
    let output = IolistOutput::Writable(arinsal_bifs::allocate_iolist_binary(
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        byte_len,
    )?);
    Ok(IolistCopySetup {
        empty: None,
        ready: Some((
            output,
            byte_len * 8,
            arinsal_bifs::IolistCopyWalk::new(root),
        )),
    })
}

enum IolistStep {
    Done(Term, u32),
    Fail(BifError, u32),
    Yield(u32),
}

fn iolist_binary_step(
    process: &mut Process,
    root: Term,
    phase: &mut ErtsL2BState,
    reds_left: usize,
) -> Result<IolistStep, BifError> {
    let mut available_reductions = reds_left;
    let mut size_reductions = 0_usize;

    match phase {
        ErtsL2BState::Size(walk) => {
            let initial_yield_count = available_reductions.saturating_mul(SIZE_YIELDS_PER_RED);
            let (done, work) = match walk.step(initial_yield_count) {
                Ok(progress) => progress,
                Err((error, work)) => {
                    let reductions = work.div_ceil(SIZE_YIELDS_PER_RED) as u32;
                    return Ok(IolistStep::Fail(error, reductions));
                }
            };
            size_reductions = work.div_ceil(SIZE_YIELDS_PER_RED);
            if !done {
                return Ok(IolistStep::Yield(size_reductions as u32));
            }
            let bitstring = walk.is_bits();
            let setup = iolist_copy_setup(process, walk, root)?;
            if let Some(value) = setup.empty {
                *phase = ErtsL2BState::Done;
                return Ok(IolistStep::Done(value, size_reductions as u32));
            }
            let (output, bit_len, walk) = setup
                .ready
                .expect("nonempty iolist output has a copy state");
            *phase = ErtsL2BState::Copy {
                output,
                bit_len,
                bitstring,
                walk,
            };
            available_reductions = available_reductions.saturating_sub(size_reductions);
            if available_reductions == 0 {
                return Ok(IolistStep::Yield(size_reductions as u32));
            }
        }
        ErtsL2BState::Copy { .. } => {}
        ErtsL2BState::Done => return Err(BifError::BADARG),
    }

    let ErtsL2BState::Copy {
        output,
        bit_len,
        bitstring,
        walk,
    } = &mut *phase
    else {
        unreachable!("the size phase transitions to copy or returns above")
    };
    let yield_count = available_reductions.saturating_mul(SIZE_YIELDS_PER_RED);
    let stepped = match output {
        IolistOutput::Small(writer) => {
            walk.step_to_heap_binary(&mut process.heap, writer, yield_count)
        }
        IolistOutput::Bitstring(bytes) => walk.step(bytes, yield_count),
        IolistOutput::Writable(term) => arinsal_bifs::with_iolist_binary_output(*term, |bytes| {
            Ok(walk.step(bytes, yield_count))
        })?,
    };
    let (done, work) = match stepped {
        Ok(progress) => progress,
        Err((error, work)) => {
            let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
            if let IolistOutput::Small(writer) = output {
                writer.cancel(&mut process.heap);
            } else {
                output.finish_writer();
            }
            return Ok(IolistStep::Fail(error, reductions));
        }
    };
    let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
    if !done {
        return Ok(IolistStep::Yield(reductions));
    }
    if walk.written_bits() != *bit_len {
        if let IolistOutput::Small(writer) = output {
            writer.cancel(&mut process.heap);
        } else {
            output.finish_writer();
        }
        return Ok(IolistStep::Fail(BifError::SystemLimit, reductions));
    }
    let (bit_len, bitstring) = (*bit_len, *bitstring);
    let value = match output {
        IolistOutput::Small(writer) => writer
            .finish(&mut process.heap)
            .map_err(|_| BifError::SystemLimit)?,
        IolistOutput::Bitstring(bytes) => {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let mut builder = TermBuilder::new(&mut heap);
            if bitstring {
                builder.bitstring(bytes, bit_len)
            } else {
                builder.binary(bytes)
            }
            .map_err(|_| BifError::SystemLimit)?
        }
        IolistOutput::Writable(term) => {
            arinsal_bifs::finish_iolist_binary_output(*term);
            *term
        }
    };
    *phase = ErtsL2BState::Done;
    Ok(IolistStep::Done(value, reductions))
}

// ---- iolist_to_iovec ---------------------------------------------------------------------

/// `erlang:iolist_to_iovec/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_1), OTP-29.1.1.
pub(crate) extern "C" fn iolist_to_iovec_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    const BIF: &str = "erlang:iolist_to_iovec/1";
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let arg = process.x[0];
    let shortcut = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_bifs::iolist_to_iovec_shortcut(&mut heap, arg)
    };
    match shortcut {
        Ok(Some(value)) => return crate::native_hooks::raw(value),
        Ok(None) => {}
        Err(error) => return fail(c_p, i, process, BIF, arg, error, false),
    }
    let state = VecState {
        walk: IolistVecWalk::new(arg),
        arg,
    };
    iolist_to_iovec_dispatch(c_p, i, process, state, None)
}

/// `erts_internal:iolist_to_iovec_continue/1`.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_continue), OTP-29.1.1.
pub(crate) extern "C" fn iolist_to_iovec_continue_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mref = process.x[0];
    let state = mref
        .with_magic_payload::<VecHolder, _>(|holder| holder.lock().ok()?.take())
        .flatten();
    match state {
        Some(state) => iolist_to_iovec_dispatch(c_p, i, process, state, Some(mref)),
        None => bif_ret(c_p, i, Err(crate::natives::bif::badarg())),
    }
}

/// `iolist_to_iovec_dispatch`: size pass, then copy pass, each for the reductions left.
// Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_engine, iolist_to_iovec_dispatch),
// OTP-29.1.1.
fn iolist_to_iovec_dispatch(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mut state: VecState,
    mref: Option<Term>,
) -> u64 {
    const BIF: &str = "erlang:iolist_to_iovec/1";
    let gc_disabled = mref.is_some();
    let arg = state.arg;
    let entry_reds = process.heap.abi.fcalls.max(0) as usize;
    let mut spent = 0_usize;
    let mut reds_left = entry_reds;
    // Outcome: Ok(Some(value)) done, Ok(None) yield with the reductions to charge.
    let outcome: Result<(Option<Term>, usize), (BifError, usize)> = (|| {
        if !state.walk.sized() {
            if reds_left == 0 {
                return Ok((None, 0));
            }
            match state
                .walk
                .size_step(reds_left.saturating_mul(SIZE_YIELDS_PER_RED))
            {
                Err((error, used)) => {
                    return Err((error, arinsal_bifs::iolist_yield_reductions(used)));
                }
                Ok((false, _)) => return Ok((None, entry_reds)),
                Ok((true, used)) => {
                    let reds = arinsal_bifs::iolist_yield_reductions(used);
                    spent += reds;
                    reds_left = reds_left.saturating_sub(reds);
                }
            }
            if reds_left == 0 {
                return Ok((None, entry_reds));
            }
        }
        if reds_left == 0 {
            return Ok((None, 0));
        }
        match state
            .walk
            .copy_step(reds_left.saturating_mul(SIZE_YIELDS_PER_RED))
        {
            Err((error, used)) => Err((error, spent + arinsal_bifs::iolist_yield_reductions(used))),
            Ok((false, _)) => Ok((None, entry_reds)),
            Ok((true, used)) => {
                let reds = spent + arinsal_bifs::iolist_yield_reductions(used);
                let finished = {
                    let mut heap = ProcessHeapHandle(&mut process.heap);
                    state.walk.finish(&mut heap)
                };
                match finished {
                    Ok(value) => Ok((Some(value), reds)),
                    Err(error) => Err((error, reds)),
                }
            }
        }
    })();
    match outcome {
        Ok((Some(value), reds)) => {
            charge(process, reds);
            if gc_disabled {
                process.set_gc_enabled(true);
            }
            crate::native_hooks::raw(value)
        }
        Ok((None, reds)) => {
            charge(process, reds);
            let mref = match mref {
                Some(mref) => {
                    let _ = mref.with_magic_payload::<VecHolder, _>(|holder| {
                        *holder.lock().expect("iovec state") = Some(state);
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
                            return fail(c_p, i, process, BIF, arg, BifError::SystemLimit, false);
                        }
                    }
                }
            };
            trap_continue(c_p, i, process, IOLIST_TO_IOVEC_CONTINUE, mref)
        }
        Err((error, reds)) => {
            charge(process, reds);
            fail(c_p, i, process, BIF, arg, error, gc_disabled)
        }
    }
}
