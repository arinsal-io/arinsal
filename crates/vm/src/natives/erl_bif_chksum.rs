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
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::{Term, TermBuilder, TermKind, atoms};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

mod raw;

/// `erlang:md5_trap/2`, `chksum_md5_2_exp`.
// Port of erts/emulator/beam/erl_bif_chksum.c (erts_init_bif_chksum), OTP-29.1.1.
const MD5_TRAP: &str = "erlang:md5_trap/2";

/// Bytes of a checksum charged as one reduction.
// Port of BYTES_PER_REDUCTION in erts/emulator/beam/erl_bif_chksum.c, OTP-29.1.1.
const BYTES_PER_REDUCTION: usize = 10;
/// The `CONTEXT_REDS`-sized zlib chunk.
// Port of CHUNK_PER_SCHEDULE in erts/emulator/beam/erl_bif_chksum.c, OTP-29.1.1.
const CHUNK_PER_SCHEDULE: usize = BYTES_PER_REDUCTION * crate::process::CONTEXT_REDS as usize;

struct Chksum {
    rest: Term,
    consumed: usize,
    failed: bool,
}

enum WalkError {
    Invalid(usize),
    SystemLimit,
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        atoms::SYSTEM_LIMIT,
    )))
}

/// `BUMP_REDS(c_p, reds)`.
fn bump_reds(process: &mut Process, reds: usize) {
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
        .saturating_sub(i32::try_from(reds).unwrap_or(i32::MAX))
        .max(0);
}

/// `BUMP_ALL_REDS(c_p)`.
pub(crate) fn bump_all_reds(process: &mut Process) {
    process.heap.abi.fcalls = 0;
}

/// `erts_make_integer` of a 32-bit sum: a small on a 64-bit build.
fn sum_term(sum: u32) -> Term {
    Term::small(i64::from(sum)).expect("a 32-bit sum is a small integer")
}

fn binary(process: &mut Process, bytes: &[u8]) -> Result<Term, VmError> {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .binary(bytes)
        .map_err(|_| system_limit())
}

fn integer(term: Term) -> Option<BigInt> {
    term.as_small()
        .map(BigInt::from)
        .or_else(|| arinsal_term::raw::big_value(term))
}

fn term_to_u32(term: Term) -> Result<u32, VmError> {
    integer(term)
        .and_then(|value| value.to_u32())
        .ok_or_else(badarg)
}

fn md5_state_arg(term: Term) -> Result<Md5State, VmError> {
    let bytes = arinsal_bifs::binary_bytes(term).map_err(|_| badarg())?;
    Md5State::from_bytes(&bytes).map_err(|_| badarg())
}

fn is_bitstring(term: Term) -> bool {
    term.classify() == TermKind::Bitstring
}

fn is_byte(term: Term) -> bool {
    term.as_small()
        .is_some_and(|value| (0..=255).contains(&value))
}

/// Feed an aligned byte range directly, copying only a byte-aligned view with an unaligned base.
fn binary_prefix(term: Term, count: usize, sum: &mut dyn FnMut(&[u8])) -> Result<(), WalkError> {
    let direct = arinsal_bifs::with_binary_bytes(term, |view| {
        if view.start_bit().is_multiple_of(8) {
            let start = view.start_bit() / 8;
            let end = start.saturating_add(count);
            if let Some(bytes) = view.bytes().get(start..end) {
                sum(bytes);
                return true;
            }
        }
        false
    })
    .unwrap_or(false);
    if direct {
        return Ok(());
    }
    let mut bytes = vec![0_u8; count];
    arinsal_bifs::copy_binary_range(term, 0, &mut bytes).map_err(|_| WalkError::Invalid(0))?;
    sum(&bytes);
    Ok(())
}

/// `do_chksum`: walk an iolist and return its unconsumed tail after at most `left` bytes.
// Port of erts/emulator/beam/erl_bif_chksum.c (do_chksum), OTP-29.1.1.
fn do_chksum(
    process: &mut Process,
    sum: &mut dyn FnMut(&[u8]),
    mut ioterm: Term,
    mut left: usize,
) -> Result<(Term, usize), WalkError> {
    if left == 0 || ioterm == Term::NIL {
        return Ok((ioterm, 0));
    }
    if is_bitstring(ioterm) {
        let bits = arinsal_bifs::bitstring_bit_len(ioterm).map_err(|_| WalkError::Invalid(0))?;
        if !bits.is_multiple_of(8) {
            return Err(WalkError::Invalid(0));
        }
        let mut size = bits / 8;
        let mut rest = Term::NIL;
        if size > left {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            rest = TermBuilder::new(&mut heap)
                .sub_binary(ioterm, left * 8, (size - left) * 8)
                .map_err(|_| WalkError::SystemLimit)?;
            size = left;
        }
        binary_prefix(ioterm, size, sum)?;
        return Ok((rest, size));
    }
    if raw::cons_cell(ioterm).is_none() {
        return Err(WalkError::Invalid(0));
    }
    let mut consumed = 0_usize;
    let mut stack = vec![ioterm];
    while !stack.is_empty() && left != 0 {
        ioterm = stack.pop().unwrap();
        if ioterm == Term::NIL {
            continue;
        }
        if let Some((mut object, mut tail)) = raw::cons_cell(ioterm) {
            loop {
                if is_byte(object) {
                    let mut buffer = Vec::new();
                    loop {
                        buffer.push(object.as_small().unwrap() as u8);
                        left -= 1;
                        ioterm = tail;
                        let Some((head, next)) = raw::cons_cell(ioterm) else {
                            break;
                        };
                        object = head;
                        tail = next;
                        if !is_byte(object) || left == 0 {
                            break;
                        }
                    }
                    sum(&buffer);
                    consumed += buffer.len();
                } else if object == Term::NIL {
                    ioterm = tail;
                    let Some((head, next)) = raw::cons_cell(ioterm) else {
                        break;
                    };
                    object = head;
                    tail = next;
                } else if let Some((head, next)) = raw::cons_cell(object) {
                    stack.push(tail);
                    object = head;
                    tail = next;
                    continue;
                } else if is_bitstring(object) {
                    match do_chksum(process, sum, object, left) {
                        Err(WalkError::Invalid(n)) => {
                            return Err(WalkError::Invalid(consumed + n));
                        }
                        Err(WalkError::SystemLimit) => return Err(WalkError::SystemLimit),
                        Ok((rest, size)) => {
                            consumed += size;
                            left -= size;
                            if rest != Term::NIL {
                                let mut heap = ProcessHeapHandle(&mut process.heap);
                                ioterm = TermBuilder::new(&mut heap)
                                    .cons(rest, tail)
                                    .map_err(|_| WalkError::SystemLimit)?;
                                left = 0;
                                break;
                            }
                            ioterm = tail;
                            if let Some((head, next)) = raw::cons_cell(ioterm) {
                                object = head;
                                tail = next;
                            }
                        }
                    }
                } else {
                    return Err(WalkError::Invalid(consumed));
                }
                if left == 0 || ioterm == Term::NIL || raw::cons_cell(ioterm).is_none() {
                    break;
                }
            }
        }
        if left != 0 && raw::cons_cell(ioterm).is_none() && ioterm != Term::NIL {
            if is_bitstring(ioterm) {
                match do_chksum(process, sum, ioterm, left) {
                    Err(WalkError::Invalid(n)) => {
                        return Err(WalkError::Invalid(consumed + n));
                    }
                    Err(WalkError::SystemLimit) => return Err(WalkError::SystemLimit),
                    Ok((rest, size)) => {
                        ioterm = rest;
                        consumed += size;
                        left -= size;
                    }
                }
            } else {
                return Err(WalkError::Invalid(consumed));
            }
        }
    }
    while let Some(entry) = stack.pop() {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        ioterm = TermBuilder::new(&mut heap)
            .cons(ioterm, entry)
            .map_err(|_| WalkError::SystemLimit)?;
    }
    Ok((ioterm, consumed))
}

fn run(
    process: &mut Process,
    sum: &mut dyn FnMut(&[u8]),
    input: Term,
    left: usize,
) -> Result<Chksum, VmError> {
    match do_chksum(process, sum, input, left) {
        Ok((rest, consumed)) => Ok(Chksum {
            rest,
            consumed,
            failed: false,
        }),
        Err(WalkError::Invalid(consumed)) => Ok(Chksum {
            rest: Term::NIL,
            consumed,
            failed: true,
        }),
        Err(WalkError::SystemLimit) => Err(system_limit()),
    }
}

fn do_chksum_zlib(
    process: &mut Process,
    adler: bool,
    sum: &mut u32,
    input: Term,
    left: usize,
) -> Result<Chksum, VmError> {
    let mut value = std::ffi::c_ulong::from(*sum);
    let outcome = {
        let mut feed = |bytes: &[u8]| value = raw::zlib_sum(adler, value, bytes);
        run(process, &mut feed, input, left)?
    };
    *sum = value as u32;
    Ok(outcome)
}

fn do_chksum_md5(
    process: &mut Process,
    state: &mut Md5State,
    input: Term,
    left: usize,
) -> Result<Chksum, VmError> {
    let mut feed = |bytes: &[u8]| state.update(bytes);
    run(process, &mut feed, input, left)
}

fn zlib_initial(adler: bool) -> u32 {
    if adler { 1 } else { 0 }
}

fn combine_sum(adler: bool, a: u32, b: u32, length: u32) -> u32 {
    raw::zlib_combine(adler, a, b, length) as u32
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
    let Chksum {
        rest,
        consumed,
        failed,
    } = do_chksum_zlib(process, adler, &mut sum, data, CHUNK_PER_SCHEDULE)?;
    bump_reds(process, consumed / BYTES_PER_REDUCTION);
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

fn zlib_1(
    process: &mut Process,
    reg: *mut u64,
    adler: bool,
    bif: &'static str,
) -> Result<Term, VmError> {
    let [data] = crate::bif_table::bif_args::<1>(reg);
    zlib_sum(process, adler, zlib_initial(adler), data, bif)
}

fn zlib_2(
    process: &mut Process,
    reg: *mut u64,
    adler: bool,
    bif: &'static str,
) -> Result<Term, VmError> {
    let [seed, data] = crate::bif_table::bif_args::<2>(reg);
    let seed = term_to_u32(seed)?;
    zlib_sum(process, adler, seed, data, bif)
}

/// `erlang:crc32/1`.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_1), OTP-29.1.1.
pub(crate) extern "C" fn crc32_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = zlib_1(process, reg, false, "erlang:crc32/2");
    bif_ret(c_p, i, result)
}

/// `erlang:crc32/2`.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_2), OTP-29.1.1.
pub(crate) extern "C" fn crc32_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = zlib_2(process, reg, false, "erlang:crc32/2");
    bif_ret(c_p, i, result)
}

/// `erlang:adler32/1`.
// Port of erts/emulator/beam/erl_bif_chksum.c (adler32_1), OTP-29.1.1.
pub(crate) extern "C" fn adler32_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = zlib_1(process, reg, true, "erlang:adler32/2");
    bif_ret(c_p, i, result)
}

/// `erlang:adler32/2`.
// Port of erts/emulator/beam/erl_bif_chksum.c (adler32_2), OTP-29.1.1.
pub(crate) extern "C" fn adler32_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = zlib_2(process, reg, true, "erlang:adler32/2");
    bif_ret(c_p, i, result)
}

fn combine(reg: *mut u64, adler: bool) -> Result<Term, VmError> {
    let args = crate::bif_table::bif_args::<3>(reg);
    let arg = |index: usize| term_to_u32(args[index]);
    let (a, b, length) = (arg(0)?, arg(1)?, arg(2)?);
    Ok(sum_term(combine_sum(adler, a, b, length)))
}

/// `erlang:crc32_combine/3`.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_combine_3), OTP-29.1.1.
pub(crate) extern "C" fn crc32_combine_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = combine(reg, false);
    bif_ret(c_p, i, result)
}

/// `erlang:adler32_combine/3`.
// Port of erts/emulator/beam/erl_bif_chksum.c (adler32_combine_3), OTP-29.1.1.
pub(crate) extern "C" fn adler32_combine_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let result = combine(reg, true);
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
    } = do_chksum_md5(process, &mut context, data, left)?;
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
pub(crate) extern "C" fn md5_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [data] = crate::bif_table::bif_args::<1>(reg);
    let result = md5_run(process, Md5State::new(), data);
    bif_ret(c_p, i, result)
}

/// `erlang:md5_trap/2`, the hidden trap target of `md5_1`, installed by `erts_init_trap_export`
/// (`bif_table::trap_function`). The context is always a binary of `sizeof(erts_md5_state)`
/// bytes because only `md5_1` and this function trap to it.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_2), OTP-29.1.1.
pub(crate) extern "C" fn md5_trap_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [context, data] = crate::bif_table::bif_args::<2>(reg);
    let result = md5_state_arg(context)
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
pub(crate) extern "C" fn md5_update_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [context, data] = crate::bif_table::bif_args::<2>(reg);
    let result = md5_update(process, context, data);
    bif_ret(c_p, i, result)
}

fn md5_update(process: &mut Process, context: Term, data: Term) -> Result<Term, VmError> {
    let mut context = md5_state_arg(context)?;
    let left = md5_reds(process);
    let Chksum {
        rest,
        consumed,
        failed,
    } = do_chksum_md5(process, &mut context, data, left)?;
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
pub(crate) extern "C" fn md5_final_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [context] = crate::bif_table::bif_args::<1>(reg);
    let result = md5_state_arg(context)
        .map_err(|_| badarg())
        .and_then(|state| binary(process, &state.final_digest()));
    bif_ret(c_p, i, result)
}

/// The 96-byte `erts_md5_state` copied between `md5_update/2` trap entries.
// Port of erts/emulator/beam/erl_md5.h (erts_md5_state), OTP-29.1.1.
#[derive(Clone)]
struct Md5State {
    words: [u32; 4],
    processed: u64,
    len: usize,
    buffer: [u8; 64],
}

impl Md5State {
    /// `erts_md5_init`.
    // Port of erts/emulator/beam/erl_md5.c (erts_md5_init), OTP-29.1.1.
    fn new() -> Self {
        Self {
            words: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            processed: 0,
            len: 0,
            buffer: [0; 64],
        }
    }

    /// Reconstruct `erts_md5_state` from its native binary representation.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() != 96 {
            return Err(());
        }
        let mut words = [0; 4];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_ne_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
        }
        let processed = u64::from_ne_bytes(bytes[16..24].try_into().unwrap());
        let len = u64::from_ne_bytes(bytes[24..32].try_into().unwrap()) as usize;
        if len > 64 {
            return Err(());
        }
        let mut buffer = [0; 64];
        buffer.copy_from_slice(&bytes[32..96]);
        Ok(Self {
            words,
            processed,
            len,
            buffer,
        })
    }

    /// Copy the state to the binary representation used by `erts_new_binary_from_data`.
    fn bytes(&self) -> [u8; 96] {
        let mut out = [0; 96];
        for (index, word) in self.words.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        out[16..24].copy_from_slice(&self.processed.to_ne_bytes());
        out[24..32].copy_from_slice(&(self.len as u64).to_ne_bytes());
        out[32..96].copy_from_slice(&self.buffer);
        out
    }

    /// `erts_md5_update`.
    // Port of erts/emulator/beam/erl_md5.c:92-125 (erts_md5_update), OTP-29.1.1.
    fn update(&mut self, mut data: &[u8]) {
        if self.len > 0 {
            let count = 64 - self.len;
            if count < data.len() {
                self.buffer[self.len..64].copy_from_slice(&data[..count]);
                data = &data[count..];
                compress(&mut self.words, &self.buffer);
                self.len = 0;
                self.processed += 64;
            } else {
                self.buffer[self.len..self.len + data.len()].copy_from_slice(data);
                self.len += data.len();
                return;
            }
        }
        while data.len() >= 64 {
            compress(&mut self.words, &data[..64]);
            data = &data[64..];
            self.processed += 64;
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.len = data.len();
        }
    }

    /// `erts_md5_finish`.
    // Port of erts/emulator/beam/erl_md5.c (erts_md5_finish), OTP-29.1.1.
    fn final_digest(mut self) -> [u8; 16] {
        let bit_len = (self.processed + self.len as u64).wrapping_mul(8);
        let mut pad = self.buffer[..self.len].to_vec();
        pad.push(0x80);
        pad.resize((pad.len() + 8).div_ceil(64) * 64 - 8, 0);
        pad.extend_from_slice(&bit_len.to_le_bytes());
        for chunk in pad.as_chunks::<64>().0 {
            compress(&mut self.words, chunk);
        }
        let mut out = [0; 16];
        for (index, word) in self.words.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

const MD5_SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_CONSTANTS: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// `hash_part`: the four rounds of MD5's 64-word compression block.
// Port of erts/emulator/beam/erl_md5.c:151-223 (hash_part), OTP-29.1.1.
fn compress(words: &mut [u32; 4], block: &[u8]) {
    let [mut a, mut b, mut c, mut d] = *words;
    for index in 0..64 {
        let (function, word_index) = match index {
            0..=15 => (d ^ (b & (c ^ d)), index),
            16..=31 => (c ^ (d & (b ^ c)), (5 * index + 1) & 15),
            32..=47 => (b ^ c ^ d, (3 * index + 5) & 15),
            _ => (c ^ (b | !d), (7 * index) & 15),
        };
        let message = u32::from_le_bytes(
            block[word_index * 4..word_index * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let next = b.wrapping_add(
            a.wrapping_add(function)
                .wrapping_add(MD5_CONSTANTS[index])
                .wrapping_add(message)
                .rotate_left(MD5_SHIFTS[index]),
        );
        a = d;
        d = c;
        c = b;
        b = next;
    }
    for (word, value) in words.iter_mut().zip([a, b, c, d]) {
        *word = word.wrapping_add(value);
    }
}
