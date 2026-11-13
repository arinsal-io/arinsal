//! The checksum BIFs of erl_bif_chksum.c.
//!
//! Port of erts/emulator/beam/erl_bif_chksum.c (crc32_1, crc32_2, crc32_combine_3, adler32_1,
//! adler32_2, adler32_combine_3, md5_1, md5_2, md5_init_0, md5_update_2, md5_final_1),
//! OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`. `crc32` and `adler32` trap to
//! their own `/2` export with `(Sum, Rest)`, `md5_update/2` to itself with `(Context, Rest)`,
//! and `md5/1` to the hidden `erlang:md5_trap/2` (`chksum_md5_2_exp`).

use super::bif::{badarg, bif_ret};
use super::erl_bif_lists::{bif_reds_left, bif_trap};
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, BifError, Chksum, Ctx, Md5State, ProcessHeapHandle};
use arinsal_term::{Term, atoms};

/// `erlang:md5_trap/2`, `chksum_md5_2_exp`.
// Port of erts/emulator/beam/erl_bif_chksum.c (erts_init_bif_chksum), OTP-29.1.1.
const MD5_TRAP: &str = "erlang:md5_trap/2";

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        atoms::SYSTEM_LIMIT,
    )))
}

/// Runs `f` with the process heap and `c_p->fcalls`, which `BUMP_REDS` and `BUMP_ALL_REDS` write.
fn with_ctx<R>(process: &mut Process, f: impl FnOnce(&mut Ctx<'_>) -> R) -> R {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut call = BifCall::default();
    let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
    f(&mut ctx)
}

/// `BUMP_REDS(c_p, reds)`.
fn bump_reds(process: &mut Process, reds: usize) {
    with_ctx(process, |ctx| ctx.charge_reductions(reds));
}

/// `BUMP_ALL_REDS(c_p)`.
pub(crate) fn bump_all_reds(process: &mut Process) {
    with_ctx(process, |ctx| ctx.bump_all_reds());
}

/// `erts_make_integer` of a 32-bit sum: a small on a 64-bit build.
fn sum_term(sum: u32) -> Term {
    Term::small(i64::from(sum)).expect("a 32-bit sum is a small integer")
}

fn binary(process: &mut Process, bytes: &[u8]) -> Result<Term, VmError> {
    with_ctx(process, |ctx| arinsal_bifs::chksum_new_binary(ctx, bytes)).map_err(
        |error| match error {
            BifError::SystemLimit => system_limit(),
            _ => badarg(),
        },
    )
}

/// The shared tail of `crc32_1/2` and `adler32_1/2`.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_1, crc32_2, adler32_1, adler32_2),
// OTP-29.1.1.
fn zlib_sum(
    process: &mut Process,
    adler: bool,
    seed: u32,
    data: Term,
    bif: &'static str,
) -> Result<Term, VmError> {
    let mut sum = seed;
    let Chksum { rest, failed, .. } = with_ctx(process, |ctx| {
        let out = arinsal_bifs::do_chksum_zlib(
            ctx,
            adler,
            &mut sum,
            data,
            arinsal_bifs::CHUNK_PER_SCHEDULE,
        );
        ctx.charge_reductions(out.consumed / arinsal_bifs::BYTES_PER_REDUCTION);
        out
    });
    if failed {
        return Err(badarg());
    }
    let res_sum = sum_term(sum);
    if rest != Term::NIL {
        bump_all_reds(process);
        return Err(bif_trap(process, bif, vec![res_sum, rest]));
    }
    Ok(res_sum)
}

fn zlib_1(process: &mut Process, adler: bool, bif: &'static str) -> Result<Term, VmError> {
    let data = process.x[0];
    zlib_sum(process, adler, arinsal_bifs::zlib_initial(adler), data, bif)
}

fn zlib_2(process: &mut Process, adler: bool, bif: &'static str) -> Result<Term, VmError> {
    let (seed, data) = (process.x[0], process.x[1]);
    let seed = arinsal_bifs::term_to_u32(seed).map_err(|_| badarg())?;
    zlib_sum(process, adler, seed, data, bif)
}

/// `erlang:crc32/1`.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_1), OTP-29.1.1.
pub(crate) extern "C" fn crc32_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = zlib_1(process, false, "erlang:crc32/2");
    bif_ret(c_p, i, result)
}

/// `erlang:crc32/2`.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_2), OTP-29.1.1.
pub(crate) extern "C" fn crc32_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = zlib_2(process, false, "erlang:crc32/2");
    bif_ret(c_p, i, result)
}

/// `erlang:adler32/1`.
// Port of erts/emulator/beam/erl_bif_chksum.c (adler32_1), OTP-29.1.1.
pub(crate) extern "C" fn adler32_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = zlib_1(process, true, "erlang:adler32/2");
    bif_ret(c_p, i, result)
}

/// `erlang:adler32/2`.
// Port of erts/emulator/beam/erl_bif_chksum.c (adler32_2), OTP-29.1.1.
pub(crate) extern "C" fn adler32_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = zlib_2(process, true, "erlang:adler32/2");
    bif_ret(c_p, i, result)
}

fn combine(process: &Process, adler: bool) -> Result<Term, VmError> {
    let arg = |index: usize| arinsal_bifs::term_to_u32(process.x[index]).map_err(|_| badarg());
    let (a, b, length) = (arg(0)?, arg(1)?, arg(2)?);
    Ok(sum_term(arinsal_bifs::chksum_combine(adler, a, b, length)))
}

/// `erlang:crc32_combine/3`.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_combine_3), OTP-29.1.1.
pub(crate) extern "C" fn crc32_combine_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = combine(process, false);
    bif_ret(c_p, i, result)
}

/// `erlang:adler32_combine/3`.
// Port of erts/emulator/beam/erl_bif_chksum.c (adler32_combine_3), OTP-29.1.1.
pub(crate) extern "C" fn adler32_combine_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = combine(process, true);
    bif_ret(c_p, i, result)
}

/// `(4 * ERTS_BIF_REDS_LEFT(c_p)) & ~0x3f`: each reduction does one round of MD5 (4 bytes),
/// rounded down to whole 64 byte blocks.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_1), OTP-29.1.1.
fn md5_reds(process: &Process) -> usize {
    bif_reds_left(process).saturating_mul(4) & !0x3f
}

/// The tail shared by `md5_1` and `md5_2`: `BIF_TRAP2(chksum_md5_2_exp, bin, rest)` with the
/// state so far, or the digest.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_1, md5_2), OTP-29.1.1.
fn md5_run(process: &mut Process, mut context: Md5State, data: Term) -> Result<Term, VmError> {
    let left = md5_reds(process);
    let Chksum {
        rest,
        consumed,
        failed,
    } = with_ctx(process, |ctx| {
        arinsal_bifs::do_chksum_md5(ctx, &mut context, data, left)
    });
    if failed {
        bump_reds(process, consumed);
        return Err(badarg());
    }
    if rest != Term::NIL {
        bump_all_reds(process);
        let bin = binary(process, &context.bytes())?;
        return Err(bif_trap(process, MD5_TRAP, vec![bin, rest]));
    }
    bump_reds(process, consumed);
    binary(process, &context.final_digest())
}

/// `erlang:md5/1`.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_1), OTP-29.1.1.
pub(crate) extern "C" fn md5_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let data = process.x[0];
    let result = md5_run(process, Md5State::new(), data);
    bif_ret(c_p, i, result)
}

/// `erlang:md5_trap/2`, the hidden trap target of `md5_1`, installed by `erts_init_trap_export`
/// (`bif_table::trap_function`). The context is always a binary of `sizeof(erts_md5_state)`
/// bytes because only `md5_1` and this function trap to it.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_2), OTP-29.1.1.
pub(crate) extern "C" fn md5_trap_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (context, data) = (process.x[0], process.x[1]);
    let result = arinsal_bifs::md5_state_arg(context)
        .map_err(|_| badarg())
        .and_then(|state| md5_run(process, state, data));
    bif_ret(c_p, i, result)
}

/// `erlang:md5_init/0`.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_init_0), OTP-29.1.1.
pub(crate) extern "C" fn md5_init_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = binary(process, &Md5State::new().bytes());
    bif_ret(c_p, i, result)
}

/// `erlang:md5_update/2`.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_update_2), OTP-29.1.1.
pub(crate) extern "C" fn md5_update_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (context, data) = (process.x[0], process.x[1]);
    let result = md5_update(process, context, data);
    bif_ret(c_p, i, result)
}

fn md5_update(process: &mut Process, context: Term, data: Term) -> Result<Term, VmError> {
    let mut context = arinsal_bifs::md5_state_arg(context).map_err(|_| badarg())?;
    let left = md5_reds(process);
    let Chksum {
        rest,
        consumed,
        failed,
    } = with_ctx(process, |ctx| {
        arinsal_bifs::do_chksum_md5(ctx, &mut context, data, left)
    });
    if failed {
        bump_reds(process, consumed);
        return Err(badarg());
    }
    let bin = binary(process, &context.bytes())?;
    if rest != Term::NIL {
        bump_all_reds(process);
        return Err(bif_trap(process, "erlang:md5_update/2", vec![bin, rest]));
    }
    bump_reds(process, consumed);
    Ok(bin)
}

/// `erlang:md5_final/1`.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_final_1), OTP-29.1.1.
pub(crate) extern "C" fn md5_final_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let context = process.x[0];
    let result = arinsal_bifs::md5_state_arg(context)
        .map_err(|_| badarg())
        .and_then(|state| binary(process, &state.final_digest()));
    bif_ret(c_p, i, result)
}
