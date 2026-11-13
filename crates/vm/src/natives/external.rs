//! The BIFs of external.c.
//!
//! Port of erts/emulator/beam/external.c (term_to_binary_1/2, term_to_iovec_1/2,
//! term_to_binary_trap_1, erts_term_to_binary_int, external_size_1/2, binary_to_term_1/2,
//! binary_to_term_trap_1, binary_to_term_int), OTP-29.1.1. Each BIF is
//! `bif_table[].f` with `(c_p, reg, I)`. `erts_term_to_binary_int` runs the TTBContext through
//! TTBSize / TTBEncode / TTBCompress on the stack; only a pass that runs out of reductions
//! exports the context into a magic binary (`EXPORT_CONTEXT`), disables collection and
//! `BIF_TRAP1`s to the hidden `erts_internal:term_to_binary_trap/1` with
//! `{Term, Opts, MagicRef, BifIx}` (`RETURN_STATE`).

use crate::Process;
use crate::natives::bif::{badarg, bif_ret};
use crate::natives::erl_bif_lists::bif_trap;
use crate::natives::erl_iolist::{charge, create_holder, gc_enable};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifError, DecodeWalk, EncodeWalk, ProcessHeapHandle};
use arinsal_term::{RefcBinary, Term, TermBuilder, atoms};
use std::sync::Mutex;

/// `TERM_TO_BINARY_LOOP_FACTOR`.
const TERM_TO_BINARY_LOOP_FACTOR: usize = 32;

/// `sizeof(TTBContext)` on a 64-bit build (its encode union is the largest member): the magic
/// binary's `orig_size`.
// Port of erts/emulator/beam/dist.h (TTBContext), OTP-29.1.1.
const ERTS_TTB_CONTEXT_SIZE: usize = 296;

const TERM_TO_BINARY_TRAP: &str = "erts_internal:term_to_binary_trap/1";

/// The four BIFs that share `erts_term_to_binary_int`, indexed by the `bif_ix` of the trap
/// tuple: name, arity, `iovec`.
// Port of erts/emulator/beam/external.c (BIF_term_to_binary_1 ... BIF_term_to_iovec_2),
// OTP-29.1.1: erts stores the BIF's number in `bif_table`; the table here is local.
const TTB_BIFS: [(&str, usize, bool); 4] = [
    ("term_to_binary", 1, false),
    ("term_to_binary", 2, false),
    ("term_to_iovec", 1, true),
    ("term_to_iovec", 2, true),
];

/// `TTBContext.state` with the members of its union.
enum TtbState {
    /// `TTBSize`: the walk is sizing the term.
    Size,
    /// `TTBEncode` into `s.ec.result_bin`, a refc binary of the sized length.
    Encode(Option<RefcBinary>),
    /// `TTBEncode` of a result that is compressed next: the plain encoding is staged in a
    /// writable binary.
    EncodeStaged(Term),
    /// `TTBEncode` of `term_to_iovec`, whose parts are cut from the encoded bytes.
    Iovec,
    /// `TTBCompress`: `s.cc.result_bin` (the plain encoding) and `s.cc.destination_bin`.
    Compress { source: Term, destination: Term },
}

/// `TTBContext`.
struct TtbContext {
    state: TtbState,
    walk: EncodeWalk,
}

type TtbHolder = Mutex<Option<TtbContext>>;

/// What one pass of `erts_term_to_binary_int` produced.
enum TtbStep {
    /// The result and the reductions to bump (`BUMP_REDS`).
    Done(Term, usize),
    /// The context ran out of reductions and must be exported.
    Yield,
    /// `THE_NON_VALUE` (SYSTEM_LIMIT or an encode error), with the work done.
    Failed(BifError, usize),
}

/// Node name and creation for locally tagged pids, ports and references; read only when the
/// term being encoded holds one (erts reads `erts_this_node` in `enc_internal_pid`).
fn local_node_source() -> (arinsal_term::Atom, u32) {
    // `erts_this_node` is read without any lock.
    arinsal_term::this_node()
}

/// The reductions `term_to_binary` charges for `work` units: one for an encoding that fits an
/// on-heap binary, `work / TERM_TO_BINARY_LOOP_FACTOR` otherwise.
fn charge_for(walk: &EncodeWalk, work: usize) -> usize {
    if walk.finishes_simple() {
        1
    } else {
        work / TERM_TO_BINARY_LOOP_FACTOR
    }
}

/// `erlang:term_to_binary/1`.
// Port of erts/emulator/beam/external.c (term_to_binary_1), OTP-29.1.1.
pub(crate) extern "C" fn term_to_binary_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    term_to_binary_start(c_p, i, 0)
}

/// `erlang:term_to_binary/2`.
// Port of erts/emulator/beam/external.c (term_to_binary_2), OTP-29.1.1.
pub(crate) extern "C" fn term_to_binary_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    term_to_binary_start(c_p, i, 1)
}

/// `erlang:term_to_iovec/1`.
// Port of erts/emulator/beam/external.c (term_to_iovec_1), OTP-29.1.1.
pub(crate) extern "C" fn term_to_iovec_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    term_to_binary_start(c_p, i, 2)
}

/// `erlang:term_to_iovec/2`.
// Port of erts/emulator/beam/external.c (term_to_iovec_2), OTP-29.1.1.
pub(crate) extern "C" fn term_to_iovec_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    term_to_binary_start(c_p, i, 3)
}

/// The shared first call of `term_to_binary_1/2` and `term_to_iovec_1/2`: the option parse,
/// then `erts_term_to_binary_int` with a context on the stack.
fn term_to_binary_start(c_p: *mut ProcessHeader, i: u64, bif_ix: usize) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (name, arity, iovec) = TTB_BIFS[bif_ix];
    let args = [process.x[0], process.x[1]];
    let term = args[0];
    let opts = if arity == 2 {
        args[1]
    } else {
        Term::atom(atoms::UNDEFINED)
    };
    // parse_t2b_opts: an option that is not understood is BADARG.
    let walk = match EncodeWalk::new(&args[..arity]) {
        Ok(walk) => walk,
        Err(error) => {
            let error =
                crate::exceptions::bif_error(process, "erlang", name, &args[..arity], error);
            return bif_ret(c_p, i, Err(error));
        }
    };
    let mut walk = walk;
    walk.set_local_node_source(local_node_source);
    if iovec {
        walk.set_iovec(true);
    }
    let context = TtbContext {
        state: if iovec {
            TtbState::Iovec
        } else {
            TtbState::Size
        },
        walk,
    };
    erts_term_to_binary_int(c_p, i, process, bif_ix, (term, opts), context, None)
}

/// `erts_internal:term_to_binary_trap/1`.
// Port of erts/emulator/beam/external.c (term_to_binary_trap_1), OTP-29.1.1.
pub(crate) extern "C" fn term_to_binary_trap_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let state = process.x[0];
    let (Ok(term), Ok(opts), Ok(mref), Ok(bix)) = (
        arinsal_bifs::tuple_element(state, 0),
        arinsal_bifs::tuple_element(state, 1),
        arinsal_bifs::tuple_element(state, 2),
        arinsal_bifs::tuple_element(state, 3),
    ) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let Some(bif_ix) = bix.as_small().and_then(|n| usize::try_from(n).ok()) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    if bif_ix >= TTB_BIFS.len() {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let context = mref
        .with_magic_payload::<TtbHolder, _>(|holder| holder.lock().ok()?.take())
        .flatten();
    let Some(context) = context else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    erts_term_to_binary_int(c_p, i, process, bif_ix, (term, opts), context, Some(mref))
}

/// `erts_term_to_binary_int` and the BIF tail that follows it in `term_to_binary_N` (first
/// call, `mref` is `None`) or `term_to_binary_trap_1` (`mref` is the context's magic ref).
// Port of erts/emulator/beam/external.c (erts_term_to_binary_int, term_to_binary_1/2,
// term_to_iovec_1/2, term_to_binary_trap_1), OTP-29.1.1.
fn erts_term_to_binary_int(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    bif_ix: usize,
    (term, opts): (Term, Term),
    context: TtbContext,
    mref: Option<Term>,
) -> u64 {
    let (name, arity, _) = TTB_BIFS[bif_ix];
    match ttb_outcome(process, bif_ix, (term, opts), context, mref) {
        TtbOutcome::Value(value) => crate::native_hooks::raw(value),
        TtbOutcome::Trap(trap) => bif_ret(c_p, i, Err(trap)),
        TtbOutcome::Failed(error) => {
            // ERTS_BIF_ERROR_TRAPPED1/2 name the original BIF and arguments.
            let args = [term, opts];
            process.x[0] = term;
            process.x[1] = opts;
            let error =
                crate::exceptions::bif_error(process, "erlang", name, &args[..arity], error);
            bif_ret(c_p, i, Err(error))
        }
    }
}

/// What the tail of a `term_to_binary` family BIF returns.
enum TtbOutcome {
    /// The BIF's value.
    Value(Term),
    /// `BIF_TRAP1`, `ERTS_BIF_YIELD_RETURN`.
    Trap(crate::VmError),
    /// `THE_NON_VALUE`: the BIF fails with this reason.
    Failed(BifError),
}

/// `erts_term_to_binary_int` and what the callers do with its result, up to the exception.
// Port of erts/emulator/beam/external.c (erts_term_to_binary_int, term_to_binary_1/2,
// term_to_iovec_1/2, term_to_binary_trap_1, erts_debug_term_to_binary), OTP-29.1.1.
fn ttb_outcome(
    process: &mut Process,
    bif_ix: usize,
    (term, opts): (Term, Term),
    mut context: TtbContext,
    mref: Option<Term>,
) -> TtbOutcome {
    let reds = process.heap.abi.fcalls.max(0) as usize;
    let chunk = reds.saturating_mul(TERM_TO_BINARY_LOOP_FACTOR);
    let trapped = mref.is_some();
    match ttb_pass(process, &mut context, chunk) {
        TtbStep::Failed(error, work) => {
            abandon(&mut context);
            charge(process, work / TERM_TO_BINARY_LOOP_FACTOR);
            if trapped && (gc_enable(process) || process.heap.bin_vheap_gc_due()) {
                crate::bif_traps::vbump_all_reds(process);
            }
            TtbOutcome::Failed(error)
        }
        TtbStep::Done(value, bump) => {
            charge(process, bump);
            if trapped && (gc_enable(process) || process.heap.bin_vheap_gc_due()) {
                // ERTS_BIF_YIELD_RETURN: ERTS_VBUMP_ALL_REDS, then bif_return_trap.
                crate::bif_traps::vbump_all_reds(process);
                let undefined = Term::atom(atoms::UNDEFINED);
                let trap = bif_trap(process, "erlang:bif_return_trap/2", vec![value, undefined]);
                return TtbOutcome::Trap(trap);
            }
            TtbOutcome::Value(value)
        }
        TtbStep::Yield => {
            // EXPORT_CONTEXT, then RETURN_STATE.
            let mref = match mref {
                Some(mref) => {
                    let _ = mref.with_magic_payload::<TtbHolder, _>(|holder| {
                        *holder.lock().expect("term_to_binary context") = Some(context);
                    });
                    mref
                }
                None => {
                    let Some(mref) = create_holder(
                        process,
                        TtbHolder::new(Some(context)),
                        ERTS_TTB_CONTEXT_SIZE,
                    ) else {
                        return TtbOutcome::Failed(BifError::SystemLimit);
                    };
                    mref
                }
            };
            let bix = Term::small(bif_ix as i64).expect("bif index fits a small");
            let tuple = {
                let mut heap = ProcessHeapHandle(&mut process.heap);
                TermBuilder::new(&mut heap).tuple(&[term, opts, mref, bix])
            };
            // BUMP_ALL_REDS(p).
            process.heap.abi.fcalls = 0;
            match tuple {
                Ok(state) => TtbOutcome::Trap(bif_trap(process, TERM_TO_BINARY_TRAP, vec![state])),
                Err(_) => TtbOutcome::Failed(BifError::SystemLimit),
            }
        }
    }
}

/// `erts_debug:get_internal_state({term_to_binary, Term, Opts})`: the `term_to_binary/2` engine
/// with its failures reported as `system_limit` and its trap as a plain `BIF_TRAP1`.
// Port of erts/emulator/beam/external.c (erts_debug_term_to_binary), OTP-29.1.1.
pub(crate) fn erts_debug_term_to_binary(
    process: &mut Process,
    term: Term,
    opts: Term,
) -> Result<Term, crate::VmError> {
    let mut walk = EncodeWalk::new(&[term, opts]).map_err(|_| badarg())?;
    walk.set_local_node_source(local_node_source);
    let context = TtbContext {
        state: TtbState::Size,
        walk,
    };
    match ttb_outcome(process, 1, (term, opts), context, None) {
        TtbOutcome::Value(value) => Ok(value),
        TtbOutcome::Trap(trap) => Err(trap),
        TtbOutcome::Failed(_) => Err(crate::VmError::Trap(crate::exceptions::Trap::error(
            Term::atom(atoms::SYSTEM_LIMIT),
        ))),
    }
}

/// Releases the writable staging binaries of a context that failed.
fn abandon(context: &mut TtbContext) {
    match &context.state {
        TtbState::EncodeStaged(output) => arinsal_bifs::finish_iolist_binary_output(*output),
        TtbState::Compress {
            source,
            destination,
        } => {
            arinsal_bifs::finish_iolist_binary_output(*source);
            arinsal_bifs::finish_iolist_binary_output(*destination);
        }
        _ => {}
    }
}

/// The `for (;;) switch (context->state)` loop of `erts_term_to_binary_int`.
fn ttb_pass(process: &mut Process, context: &mut TtbContext, chunk: usize) -> TtbStep {
    let mut work = 0usize;
    macro_rules! tri {
        ($e:expr) => {
            match $e {
                Ok(value) => value,
                Err(error) => return TtbStep::Failed(error, work),
            }
        };
    }
    loop {
        match &mut context.state {
            TtbState::Size => {
                let (sized, size_work) = tri!(context.walk.step_size(chunk.saturating_sub(work)));
                work += size_work;
                if !sized {
                    return TtbStep::Yield;
                }
                if context.walk.finishes_simple() {
                    // erts_term_to_binary_simple: finish in one go, BUMP_REDS(p, 1).
                    let mut heap = ProcessHeapHandle(&mut process.heap);
                    let value = tri!(context.walk.encode_simple_binary(&mut heap));
                    return TtbStep::Done(value, 1);
                }
                let size = tri!(context.walk.encoded_size().ok_or(BifError::SystemLimit));
                if context.walk.uses_compression() {
                    let mut heap = ProcessHeapHandle(&mut process.heap);
                    let output = tri!(arinsal_bifs::allocate_iolist_binary(&mut heap, size));
                    context.state = TtbState::EncodeStaged(output);
                } else {
                    // erts_bin_nrml_alloc(size): the result binary the pass fills in place.
                    let binary =
                        tri!(RefcBinary::new_zeroed(size).map_err(|_| BifError::SystemLimit));
                    context.state = TtbState::Encode(Some(binary));
                }
            }
            TtbState::Encode(binary) => {
                let size = tri!(context.walk.encoded_size().ok_or(BifError::SystemLimit));
                let budget = chunk.saturating_sub(work);
                let bytes = tri!(
                    binary
                        .as_mut()
                        .and_then(RefcBinary::bytes_mut_unique)
                        .ok_or(BifError::SystemLimit)
                );
                let (done, encode_work) = tri!(context.walk.step_into(bytes, budget));
                work += encode_work;
                if !done {
                    return TtbStep::Yield;
                }
                let binary = binary.take().expect("the result binary");
                let mut heap = ProcessHeapHandle(&mut process.heap);
                let value = tri!(arinsal_bifs::install_refc_binary(&mut heap, binary, size));
                return TtbStep::Done(value, charge_for(&context.walk, work));
            }
            TtbState::EncodeStaged(output) => {
                let output = *output;
                let budget = chunk.saturating_sub(work);
                let encoded = arinsal_bifs::with_iolist_binary_output(output, |bytes| {
                    context.walk.step_into(bytes, budget)
                });
                let (done, encode_work) = tri!(encoded);
                work += encode_work;
                if !done {
                    return TtbStep::Yield;
                }
                arinsal_bifs::finish_iolist_binary_output(output);
                // The deflate stream starts: the destination holds the 6-byte header.
                let size = tri!(context.walk.encoded_size().ok_or(BifError::SystemLimit));
                let mut heap = ProcessHeapHandle(&mut process.heap);
                let destination = tri!(arinsal_bifs::allocate_iolist_binary(&mut heap, size));
                tri!(arinsal_bifs::with_iolist_binary_output(
                    destination,
                    |bytes| {
                        bytes[..6].copy_from_slice(&[131, 80, 0, 0, 0, 0]);
                        bytes[2..6].copy_from_slice(&((size - 1) as u32).to_be_bytes());
                        Ok(())
                    }
                ));
                context.state = TtbState::Compress {
                    source: output,
                    destination,
                };
            }
            TtbState::Iovec => {
                let (done, step_work) = tri!(context.walk.step(chunk.saturating_sub(work)));
                work += step_work;
                if !done {
                    return TtbStep::Yield;
                }
                let bump = charge_for(&context.walk, work);
                let walk = std::mem::replace(&mut context.walk, EncodeWalk::completed());
                let value = tri!(finish_iovec(process, walk));
                return TtbStep::Done(value, bump);
            }
            TtbState::Compress {
                source,
                destination,
            } => {
                let (source, destination) = (*source, *destination);
                let size = tri!(context.walk.encoded_size().ok_or(BifError::SystemLimit));
                let walk = &mut context.walk;
                if !walk.compression_output_full() {
                    let budget = chunk.saturating_sub(work).max(1);
                    let progress = tri!(
                        arinsal_bifs::with_binary_bytes(source, |view| {
                            arinsal_bifs::with_iolist_binary_output(destination, |bytes| {
                                walk.compress_into(&view.bytes()[1..], &mut bytes[6..], budget)
                            })
                        })
                        .and_then(|result| result)
                    );
                    work += progress.1;
                    if !progress.0 && !walk.compression_output_full() {
                        return TtbStep::Yield;
                    }
                }
                if walk.compression_is_useful() {
                    let payload = tri!(walk.compressed_payload_len().ok_or(BifError::SystemLimit));
                    let final_size = tri!(6usize.checked_add(payload).ok_or(BifError::SystemLimit));
                    tri!(
                        final_size
                            .checked_mul(8)
                            .ok_or(BifError::SystemLimit)
                            .and_then(|bits| arinsal_term::writable_resize_private(
                                destination,
                                bits
                            )
                            .map_err(|_| BifError::SystemLimit))
                    );
                    arinsal_bifs::finish_iolist_binary_output(destination);
                    return TtbStep::Done(destination, charge_for(walk, work));
                }
                if walk.compression_output_full() || walk.compression_finished() {
                    // Compression did not pay: the plain encoding is the result.
                    arinsal_bifs::finish_iolist_binary_output(destination);
                    let _ = size;
                    return TtbStep::Done(source, charge_for(walk, work));
                }
                return TtbStep::Yield;
            }
        }
    }
}

/// The `iovec` branch of `return_normal`: the parts of the encoding as a list of binaries, or
/// the one compressed binary.
// Port of erts/emulator/beam/external.c (erts_term_to_binary_int, return_normal), OTP-29.1.1.
fn finish_iovec(process: &mut Process, walk: EncodeWalk) -> Result<Term, BifError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let (parts, compressed) = walk.finish_iovec()?;
    let terms = parts
        .iter()
        .map(|bytes| builder.binary(bytes).map_err(|_| BifError::SystemLimit))
        .collect::<Result<Vec<_>, _>>()?;
    if compressed {
        Ok(terms[0])
    } else {
        builder
            .list_from_iter(terms)
            .map_err(|_| BifError::SystemLimit)
    }
}

/// `erlang:external_size/1`.
// Port of erts/emulator/beam/external.c (external_size_1), OTP-29.1.1.
pub(crate) extern "C" fn external_size_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    external_size(c_p, i, 1)
}

/// `erlang:external_size/2`.
// Port of erts/emulator/beam/external.c (external_size_2), OTP-29.1.1.
pub(crate) extern "C" fn external_size_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    external_size(c_p, i, 2)
}

/// `erts_encode_ext_size[_2]` with an unbounded budget, then `make_small` or `uint_to_big`.
// Port of erts/emulator/beam/external.c (external_size_1, external_size_2,
// erts_encode_ext_size_2), OTP-29.1.1.
fn external_size(c_p: *mut ProcessHeader, i: u64, arity: usize) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = [process.x[0], process.x[1]];
    let result = (|| {
        let mut walk = EncodeWalk::new_external_size(&args[..arity])?;
        walk.set_local_node_source(local_node_source);
        walk.step_size(usize::MAX)?;
        let size = walk.encoded_size().ok_or(BifError::SystemLimit)?;
        let size = u64::try_from(size).map_err(|_| BifError::SystemLimit)?;
        TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .int_from_u64(size)
            .map_err(|_| BifError::SystemLimit)
    })();
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => {
            let error = crate::exceptions::bif_error(
                process,
                "erlang",
                "external_size",
                &args[..arity],
                error,
            );
            bif_ret(c_p, i, Err(error))
        }
    }
}

/// `B2T_BYTES_PER_REDUCTION`.
const B2T_BYTES_PER_REDUCTION: i64 = 128;

/// `B2T_MEMCPY_FACTOR`.
const B2T_MEMCPY_FACTOR: i64 = 8;

/// `sizeof(B2TContext)` on a 64-bit build (its decode union is the largest member): the magic
/// binary's `orig_size`.
// Port of erts/emulator/beam/external.c (B2TContext), OTP-29.1.1.
const ERTS_B2T_CONTEXT_SIZE: usize = 296;

const BINARY_TO_TERM_TRAP: &str = "erts_internal:binary_to_term_trap/1";

/// `B2TState` of external.c without `B2TDecodeFail` and `B2TBadArg`, which are `B2tExit::Fail`;
/// the order matters: `state >= B2TDone` keeps the loop running.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum B2tState {
    Prepare,
    UncompressChunk,
    SizeInit,
    Size,
    DecodeInit,
    Decode,
    Done,
}

/// `B2TContext`: the state, the decode (`b2ts` and the `u.uc`/`u.sc`/`u.dc` union live in the
/// walk), the reductions left, `trap_bin` once exported, and `bif` and `arg[]`, the original
/// call's number of arguments and arguments, which a failure reports.
// Port of erts/emulator/beam/external.c (B2TContext), OTP-29.1.1.
struct B2tContext<'a> {
    state: B2tState,
    walk: DecodeWalk<'a>,
    reds: i64,
    initial_reds: i64,
    heap_size: usize,
    result: Term,
    trap_bin: Option<Term>,
    arity: usize,
    arg: [Term; 2],
}

type B2tHolder = Mutex<Option<B2tContext<'static>>>;

/// Why `b2t_run` left the loop.
enum B2tExit {
    /// `B2TDone`.
    Done,
    /// `B2TBadArg` / `B2TDecodeFail`, with the error the phase reported.
    Fail(BifError),
    /// `ctx->reds <= 0` before `B2TDone`.
    Yield,
    /// `b2t_export_context` is wanted (`B2TPrepare` of compressed input, `B2TDecodeInit` that
    /// will probably trap).
    Export,
}

/// `erlang:binary_to_term/1`.
// Port of erts/emulator/beam/external.c (binary_to_term_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_term_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    binary_to_term_start(c_p, i, 1)
}

/// `erlang:binary_to_term/2`.
// Port of erts/emulator/beam/external.c (binary_to_term_2), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_term_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    binary_to_term_start(c_p, i, 2)
}

/// The BADARG of `binary_to_term_N` / `binary_to_term_int` with the reductions done so far
/// (`BUMP_REDS`); `trapped` is `ERTS_BIF_PREP_ERROR_TRAPPED*` after `erts_set_gc_state(p, 1)`.
fn b2t_error(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    args: &[Term],
    error: BifError,
    consumed: i64,
) -> u64 {
    charge(
        process,
        (consumed / B2T_BYTES_PER_REDUCTION).max(0) as usize,
    );
    // A decoder that cannot read the input is the input's fault.
    let error = match error {
        BifError::Unsupported(_) => BifError::BADARG,
        other => other,
    };
    process.x[0] = args[0];
    if args.len() > 1 {
        process.x[1] = args[1];
    }
    let error = crate::exceptions::bif_error(process, "erlang", "binary_to_term", args, error);
    bif_ret(c_p, i, Err(error))
}

/// `binary_to_term_1/2`: the context on the stack, then `binary_to_term_int`.
// Port of erts/emulator/beam/external.c (binary_to_term_1, binary_to_term_2), OTP-29.1.1.
fn binary_to_term_start(c_p: *mut ProcessHeader, i: u64, arity: usize) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let call_args = [process.x[0], process.x[1]];
    let args = &call_args[..arity];
    let walk = match DecodeWalk::new(args) {
        Ok(mut walk) => {
            // `dec_is_this_node`.
            let local_node = arinsal_term::this_node();
            walk.set_local_node(local_node.0, local_node.1);
            walk
        }
        Err(error) => return b2t_error(c_p, i, process, args, error, 0),
    };
    let mut arg = [Term::NIL; 2];
    arg[..arity].copy_from_slice(args);
    let ctx = B2tContext {
        state: B2tState::Prepare,
        walk,
        reds: 0,
        initial_reds: 0,
        heap_size: 0,
        result: Term::NIL,
        trap_bin: None,
        arity,
        arg,
    };
    binary_to_term_int(c_p, i, process, ctx)
}

/// `erts_internal:binary_to_term_trap/1`.
// Port of erts/emulator/beam/external.c (binary_to_term_trap_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_term_trap_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let mref = process.x[0];
    let context = mref
        .with_magic_payload::<B2tHolder, _>(|holder| holder.lock().ok()?.take())
        .flatten();
    let Some(ctx) = context else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    binary_to_term_int(c_p, i, process, ctx)
}

/// `binary_to_term_int`: the B2T state machine with `ERTS_BIF_REDS_LEFT * 128` bytes of
/// budget; it traps through `erts_internal:binary_to_term_trap/1` when that runs out.
// Port of erts/emulator/beam/external.c (binary_to_term_int), OTP-29.1.1.
fn binary_to_term_int(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    mut ctx: B2tContext<'_>,
) -> u64 {
    // ERTS_BIF_REDS_LEFT(p) * B2T_BYTES_PER_REDUCTION.
    ctx.initial_reds = process.heap.abi.fcalls.max(0) as i64 * B2T_BYTES_PER_REDUCTION;
    ctx.reds = ctx.initial_reds;
    match b2t_run(process, &mut ctx) {
        B2tExit::Export => {
            // `b2t_export_context`: the rest of the call runs on the exported context.
            let mut owned = match b2t_export_context(process, ctx) {
                Ok(owned) => owned,
                Err((args, error)) => return b2t_error(c_p, i, process, &args, error, 0),
            };
            let exit = b2t_run(process, &mut owned);
            b2t_exit(c_p, i, process, owned, exit)
        }
        exit => b2t_exit(c_p, i, process, ctx, exit),
    }
}

/// What `binary_to_term_int` does after its loop: the result, the BADARG or the trap.
fn b2t_exit(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    mut ctx: B2tContext<'_>,
    exit: B2tExit,
) -> u64 {
    match exit {
        B2tExit::Done => {
            // erts_set_gc_state(p, 1) when a magic binary disabled it; BUMP_REDS.
            if ctx.trap_bin.is_some() {
                gc_enable(process);
            }
            charge(
                process,
                ((ctx.initial_reds - ctx.reds) / B2T_BYTES_PER_REDUCTION).max(0) as usize,
            );
            crate::native_hooks::raw(ctx.result)
        }
        B2tExit::Fail(error) => {
            ctx.walk.undo_factory(&mut process.heap);
            if ctx.trap_bin.is_some() {
                gc_enable(process);
            }
            let consumed = ctx.initial_reds - ctx.reds;
            let (arity, arg) = (ctx.arity, ctx.arg);
            b2t_error(c_p, i, process, &arg[..arity], error, consumed)
        }
        B2tExit::Yield | B2tExit::Export => {
            // The context is in a magic binary by now (`B2TDecode*`) or is exported here
            // (`ASSERT(ctx->state < B2TDecode)`), then BUMP_ALL_REDS and BIF_TRAP1.
            let ctx = match b2t_export_context(process, ctx) {
                Ok(owned) => owned,
                Err((args, error)) => return b2t_error(c_p, i, process, &args, error, 0),
            };
            let mref = ctx.trap_bin.expect("exported context has a trap_bin");
            let _ = mref.with_magic_payload::<B2tHolder, _>(|holder| {
                *holder.lock().expect("binary_to_term context") = Some(ctx);
            });
            process.heap.abi.fcalls = 0;
            let trap = bif_trap(process, BINARY_TO_TERM_TRAP, vec![mref]);
            bif_ret(c_p, i, Err(trap))
        }
    }
}

/// `b2t_export_context`: the context moves into a new magic binary (owned input, so nothing
/// borrows the caller's argument) and `trap_bin` names it; a context that has one keeps it.
// Port of erts/emulator/beam/external.c (b2t_export_context), OTP-29.1.1.
#[allow(clippy::result_large_err)]
fn b2t_export_context(
    process: &mut Process,
    ctx: B2tContext<'_>,
) -> Result<B2tContext<'static>, ([Term; 2], BifError)> {
    let B2tContext {
        state,
        walk,
        reds,
        initial_reds,
        heap_size,
        result,
        trap_bin,
        arity,
        arg,
    } = ctx;
    let walk = walk.into_owned().map_err(|error| (arg, error))?;
    let trap_bin = match trap_bin {
        Some(trap_bin) => trap_bin,
        None => create_holder(process, B2tHolder::new(None), ERTS_B2T_CONTEXT_SIZE)
            .ok_or((arg, BifError::SystemLimit))?,
    };
    Ok(B2tContext {
        state,
        walk,
        reds,
        initial_reds,
        heap_size,
        result,
        trap_bin: Some(trap_bin),
        arity,
        arg,
    })
}

/// The `do { switch (ctx->state) ... } while (ctx->reds > 0 || ctx->state >= B2TDone)` loop.
// Port of erts/emulator/beam/external.c (binary_to_term_int), OTP-29.1.1.
fn b2t_run(process: &mut Process, ctx: &mut B2tContext<'_>) -> B2tExit {
    loop {
        match ctx.state {
            B2tState::Prepare => {
                // binary2term_prepare: compressed input exports the context first.
                ctx.reds -= ctx.walk.prepare_reds_charge() as i64;
                if ctx.walk.is_compressed() {
                    ctx.state = B2tState::UncompressChunk;
                    if ctx.trap_bin.is_none() {
                        return B2tExit::Export;
                    }
                } else {
                    ctx.state = B2tState::SizeInit;
                }
            }
            B2tState::UncompressChunk => {
                match ctx.walk.uncompress_chunk(ctx.reds.max(1) as usize) {
                    Ok((done, consumed)) => {
                        ctx.reds -= consumed as i64;
                        if done {
                            ctx.state = B2tState::SizeInit;
                        } else {
                            ctx.reds = 0;
                        }
                    }
                    Err((error, consumed)) => {
                        ctx.reds -= consumed as i64;
                        return B2tExit::Fail(error);
                    }
                }
            }
            B2tState::SizeInit | B2tState::Size => {
                ctx.state = B2tState::Size;
                match ctx.walk.size_chunk(ctx.reds.max(1) as usize) {
                    Ok((Some(words), consumed)) => {
                        ctx.reds -= consumed as i64;
                        ctx.heap_size = words;
                        ctx.state = B2tState::DecodeInit;
                    }
                    Ok((None, consumed)) => {
                        ctx.reds -= consumed as i64;
                        ctx.reds = 0;
                    }
                    Err((error, consumed)) => {
                        ctx.reds -= consumed as i64;
                        return B2tExit::Fail(error);
                    }
                }
            }
            B2tState::DecodeInit => {
                if ctx.trap_bin.is_none() {
                    if ctx.walk.extsize() as i64 > ctx.reds {
                        // dec_term will maybe trap: the magic binary is allocated before the
                        // factory so the result term can be trimmed with HRelease.
                        return B2tExit::Export;
                    }
                    // We will probably not trap: artificially increase the available
                    // reductions (GH-11404).
                    let consumed = ctx.initial_reds - ctx.reds;
                    ctx.reds = i32::MAX as i64 / B2T_MEMCPY_FACTOR;
                    ctx.initial_reds = ctx.reds + consumed;
                }
                ctx.state = B2tState::Decode;
            }
            B2tState::Decode => {
                let mut heap = ProcessHeapHandle(&mut process.heap);
                let mut bif_state = arinsal_bifs::BifState::default();
                let mut dctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
                match ctx.walk.decode_chunk(ctx.reds.max(1) as usize, &mut dctx) {
                    Ok((Some(value), consumed)) => {
                        ctx.reds -= consumed as i64;
                        ctx.result = value;
                        ctx.state = B2tState::Done;
                    }
                    Ok((None, consumed)) => {
                        ctx.reds -= consumed as i64;
                        ctx.reds = 0;
                    }
                    Err((error, consumed)) => {
                        ctx.reds -= consumed as i64;
                        return B2tExit::Fail(error);
                    }
                }
            }
            B2tState::Done => return B2tExit::Done,
        }
        if !(ctx.reds > 0 || ctx.state >= B2tState::Done) {
            return B2tExit::Yield;
        }
    }
}
