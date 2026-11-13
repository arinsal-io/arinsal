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
const B2T_BYTES_PER_REDUCTION: usize = 128;

/// `sizeof(B2TContext)` on a 64-bit build (its decode union is the largest member): the magic
/// binary's `orig_size`.
// Port of erts/emulator/beam/external.c (B2TContext), OTP-29.1.1.
const ERTS_B2T_CONTEXT_SIZE: usize = 296;

const BINARY_TO_TERM_TRAP: &str = "erts_internal:binary_to_term_trap/1";

/// `B2TContext` of a trapped call: the decode (its `B2TUncompressChunk`..`B2TDecode*` state, the
/// reserved heap block and the `PSTACK` of maps) plus `bif` and `arg[]`, the original call's
/// number of arguments and arguments, which a failure reports.
struct B2tContext {
    walk: DecodeWalk<'static>,
    arity: usize,
    arg: [Term; 2],
}

type B2tHolder = Mutex<Option<B2tContext>>;

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
    consumed: usize,
) -> u64 {
    charge(process, consumed / B2T_BYTES_PER_REDUCTION);
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

/// The first call of `binary_to_term/1,2`: `binary_to_term_int` with a context on the stack,
/// exported to a magic binary only when the decode traps.
// Port of erts/emulator/beam/external.c (binary_to_term_1, binary_to_term_2,
// binary_to_term_int), OTP-29.1.1.
fn binary_to_term_start(c_p: *mut ProcessHeader, i: u64, arity: usize) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let call_args = [process.x[0], process.x[1]];
    let args = &call_args[..arity];
    // `ERTS_BIF_REDS_LEFT(p) * B2T_BYTES_PER_REDUCTION`.
    let reds = process.heap.abi.fcalls.max(0) as usize;
    let initial_reds = reds.saturating_mul(B2T_BYTES_PER_REDUCTION);
    let local_node = arinsal_term::this_node();
    let mut prepared = None;
    match DecodeWalk::decode_small(
        args,
        &mut process.heap,
        Some(local_node),
        initial_reds,
        &mut prepared,
    ) {
        Ok(Some((value, consumed))) => {
            charge(process, consumed / B2T_BYTES_PER_REDUCTION);
            return crate::native_hooks::raw(value);
        }
        Ok(None) => {}
        Err((error, consumed)) => return b2t_error(c_p, i, process, args, error, consumed),
    }
    let mut walk = match prepared {
        Some(walk) => walk,
        None => match DecodeWalk::new(args) {
            Ok(mut walk) => {
                // `dec_is_this_node`.
                walk.set_local_node(local_node.0, local_node.1);
                walk
            }
            Err(error) => return b2t_error(c_p, i, process, args, error, 0),
        },
    };
    match b2t_step(process, &mut walk, initial_reds) {
        Ok((None, _)) => {
            // `b2t_export_context`, then `erts_set_gc_state(p, 0)`.
            let walk = match walk.into_owned() {
                Ok(walk) => walk,
                Err(error) => return b2t_error(c_p, i, process, args, error, 0),
            };
            let mut arg = [Term::NIL; 2];
            arg[..arity].copy_from_slice(args);
            let context = B2tContext { walk, arity, arg };
            let Some(mref) = create_holder(
                process,
                B2tHolder::new(Some(context)),
                ERTS_B2T_CONTEXT_SIZE,
            ) else {
                return b2t_error(c_p, i, process, args, BifError::SystemLimit, 0);
            };
            // BUMP_ALL_REDS(p), then BIF_TRAP1(&binary_to_term_trap_export, p, trap_bin).
            process.heap.abi.fcalls = 0;
            let trap = bif_trap(process, BINARY_TO_TERM_TRAP, vec![mref]);
            bif_ret(c_p, i, Err(trap))
        }
        Ok((Some(value), consumed)) => {
            charge(process, consumed / B2T_BYTES_PER_REDUCTION);
            crate::native_hooks::raw(value)
        }
        Err((error, consumed)) => b2t_error(c_p, i, process, args, error, consumed),
    }
}

/// `erts_internal:binary_to_term_trap/1`.
// Port of erts/emulator/beam/external.c (binary_to_term_trap_1, binary_to_term_int with a
// B2TContext taken from the magic binary), OTP-29.1.1.
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
    let Some(mut context) = context else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let initial_reds =
        (process.heap.abi.fcalls.max(0) as usize).saturating_mul(B2T_BYTES_PER_REDUCTION);
    match b2t_step(process, &mut context.walk, initial_reds) {
        Ok((None, _)) => {
            // The context stays in its magic binary: BUMP_ALL_REDS, BIF_TRAP1 with the same ref.
            let _ = mref.with_magic_payload::<B2tHolder, _>(|holder| {
                *holder.lock().expect("binary_to_term context") = Some(context);
            });
            process.heap.abi.fcalls = 0;
            let trap = bif_trap(process, BINARY_TO_TERM_TRAP, vec![mref]);
            bif_ret(c_p, i, Err(trap))
        }
        Ok((Some(value), consumed)) => {
            // erts_set_gc_state(p, 1), BUMP_REDS.
            gc_enable(process);
            charge(process, consumed / B2T_BYTES_PER_REDUCTION);
            crate::native_hooks::raw(value)
        }
        Err((error, consumed)) => {
            gc_enable(process);
            let args = context.arg;
            b2t_error(c_p, i, process, &args[..context.arity], error, consumed)
        }
    }
}

/// One `dec_term` slice of `binary_to_term_int` with `reds` bytes of budget.
fn b2t_step(
    process: &mut Process,
    walk: &mut DecodeWalk<'_>,
    reds: usize,
) -> Result<(Option<Term>, usize), (BifError, usize)> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifState::default();
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    walk.step_into(reds, &mut ctx)
}
