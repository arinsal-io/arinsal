//! zlib-compatible checksum BIFs.

use arinsal_term::{Term, TermBuilder, TermKind};
use num_traits::ToPrimitive;

use crate::lists::{DeferredTrap, cons_cell};
use crate::pure::{Heap, bigint, binary_bytes, copy_binary_range, with_binary_bytes};
use crate::{BifError, Ctx};

/// Bytes of a checksum charged as one reduction.
// Port of `BYTES_PER_REDUCTION` in erts/emulator/beam/erl_bif_chksum.c, OTP-29.1.1.
pub const BYTES_PER_REDUCTION: usize = 10;

/// Reductions in one scheduler slice, as `CONTEXT_REDS`.
const CONTEXT_REDS: usize = 4000;

/// Bytes `erlang:crc32/1,2` and `adler32/1,2` consume before they trap.
// Port of `CHUNK_PER_SCHEDULE` in erts/emulator/beam/erl_bif_chksum.c, OTP-29.1.1.
pub const CHUNK_PER_SCHEDULE: usize = BYTES_PER_REDUCTION * CONTEXT_REDS;

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let f = match (module, name, arity) {
        ("erlang", "crc32", 1 | 2) => v.entry::<word_bodies::crc32>(),
        ("erlang", "adler32", 1 | 2) => v.entry::<word_bodies::adler32>(),
        ("erlang", "crc32_combine", 3) => v.entry::<word_bodies::crc32_combine>(),
        ("erlang", "adler32_combine", 3) => v.entry::<word_bodies::adler32_combine>(),
        ("erlang", "md5", 1) => v.entry::<word_bodies::md5>(),
        ("erlang", "md5_init", 0) => v.entry::<word_bodies::md5_init>(),
        ("erlang", "md5_update", 2) => v.entry::<word_bodies::md5_update>(),
        ("erlang", "md5_final", 1) => v.entry::<word_bodies::md5_final>(),
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

fn u32_arg(term: Term) -> Result<u32, BifError> {
    bigint(term)?.to_u32().ok_or(BifError::BADARG)
}
fn result(value: u32) -> Term {
    Term::small(value as i64).expect("checksum fits small integer")
}
/// Which checksum a continuation computes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChksumKind {
    /// `erlang:crc32/1,2`.
    Crc32,
    /// `erlang:adler32/1,2`.
    Adler32,
    /// `erlang:md5/1`.
    Md5,
    /// `erlang:md5_update/2` and its continuation.
    Md5Update,
}

#[derive(Clone, Copy)]
enum ChksumTarget {
    Checksum,
    Md5Update,
}

#[derive(Clone)]
enum ChksumSum {
    Zlib(std::ffi::c_ulong),
    Md5(Md5State),
}

/// Resume state of `erlang:crc32/2`, `adler32/2` and the hidden `md5` trap target.
///
/// Port of the arguments `BIF_TRAP2` passes in erts/emulator/beam/erl_bif_chksum.c
/// (the sum so far and the rest of the input), OTP-29.1.1.
#[derive(Clone)]
pub struct ChksumCont {
    kind: ChksumKind,
    target: ChksumTarget,
    sum: ChksumSum,
    rest: Term,
}

impl ChksumCont {
    /// The continuation export this state belongs to.
    pub fn continuation(&self) -> &'static str {
        match self.kind {
            ChksumKind::Crc32 => "erlang:crc32/2",
            ChksumKind::Adler32 => "erlang:adler32/2",
            ChksumKind::Md5 | ChksumKind::Md5Update => match self.target {
                ChksumTarget::Checksum => "erlang:md5_trap/2",
                ChksumTarget::Md5Update => "erlang:md5_update/2",
            },
        }
    }

    /// The input not yet consumed.
    pub fn rest(&self) -> Term {
        self.rest
    }
}

/// One slice of a checksum.
pub enum ChksumStep {
    /// The finished value.
    Done(Term),
    /// `BIF_TRAP2` with the sum so far and the rest of the input.
    More(ChksumCont),
}

fn is_bitstring(term: Term) -> bool {
    term.classify() == TermKind::Bitstring
}

fn is_byte(term: Term) -> bool {
    term.as_small().is_some_and(|n| (0..=255).contains(&n))
}

/// Feed the first `count` bytes of a byte-aligned binary to `sum`, or `None` for a bitstring
/// that is not a whole number of bytes.
fn binary_prefix(term: Term, count: usize, sum: &mut dyn FnMut(&[u8])) {
    let done = with_binary_bytes(term, |view| {
        if view.start_bit().is_multiple_of(8) {
            let start = view.start_bit() / 8;
            sum(&view.bytes()[start..start + count]);
            true
        } else {
            false
        }
    });
    if done == Ok(true) {
        return;
    }
    let mut bytes = vec![0u8; count];
    let _ = copy_binary_range(term, 0, &mut bytes);
    sum(&bytes);
}

/// Sum up to `left` bytes of an iolist. Returns the unconsumed rest (`[]` when everything was
/// consumed), the bytes consumed, and whether the input is not an iolist.
// Port of erts/emulator/beam/erl_bif_chksum.c (do_chksum), OTP-29.1.1.
fn do_chksum(
    ctx: &mut Ctx<'_>,
    sum: &mut dyn FnMut(&[u8]),
    mut ioterm: Term,
    mut left: usize,
) -> Result<(Term, usize), usize> {
    if left == 0 || ioterm == Term::NIL {
        return Ok((ioterm, 0));
    }
    if is_bitstring(ioterm) {
        let bits = crate::pure::bitstring_bit_len(ioterm).map_err(|_| 0usize)?;
        if !bits.is_multiple_of(8) {
            return Err(0);
        }
        let mut size = bits / 8;
        let mut rest = Term::NIL;
        if size > left {
            rest = TermBuilder::new(&mut Heap(&mut ctx.heap))
                .sub_binary(ioterm, left * 8, (size - left) * 8)
                .map_err(|_| 0usize)?;
            size = left;
        }
        binary_prefix(ioterm, size, sum);
        return Ok((rest, size));
    }
    if cons_cell(ioterm).is_none() {
        return Err(0);
    }
    let mut res = 0usize;
    let mut stack: Vec<Term> = vec![ioterm];
    while !stack.is_empty() && left != 0 {
        ioterm = stack.pop().unwrap();
        if ioterm == Term::NIL {
            continue;
        }
        if let Some((mut obj, mut tail)) = cons_cell(ioterm) {
            loop {
                if is_byte(obj) {
                    let mut buffer: Vec<u8> = Vec::new();
                    loop {
                        buffer.push(obj.as_small().unwrap() as u8);
                        left -= 1;
                        ioterm = tail;
                        let Some((head, next)) = cons_cell(ioterm) else {
                            break;
                        };
                        obj = head;
                        tail = next;
                        if !is_byte(obj) {
                            break;
                        }
                        if left == 0 {
                            break;
                        }
                    }
                    sum(&buffer);
                    res += buffer.len();
                } else if obj == Term::NIL {
                    ioterm = tail;
                    let Some((head, next)) = cons_cell(ioterm) else {
                        break;
                    };
                    obj = head;
                    tail = next;
                } else if let Some((head, next)) = cons_cell(obj) {
                    stack.push(tail);
                    obj = head;
                    tail = next;
                    continue;
                } else if is_bitstring(obj) {
                    match do_chksum(ctx, sum, obj, left) {
                        Err(sres) => return Err(res + sres),
                        Ok((rest_term, sres)) => {
                            res += sres;
                            left -= sres;
                            if rest_term != Term::NIL {
                                ioterm = TermBuilder::new(&mut Heap(&mut ctx.heap))
                                    .cons(rest_term, tail)
                                    .map_err(|_| res)?;
                                left = 0;
                                break;
                            }
                            ioterm = tail;
                            if let Some((head, next)) = cons_cell(ioterm) {
                                obj = head;
                                tail = next;
                            }
                        }
                    }
                } else {
                    return Err(res);
                }
                if left == 0 || ioterm == Term::NIL || cons_cell(ioterm).is_none() {
                    break;
                }
            }
        }
        if left != 0 && cons_cell(ioterm).is_none() && ioterm != Term::NIL {
            if is_bitstring(ioterm) {
                match do_chksum(ctx, sum, ioterm, left) {
                    Err(sres) => return Err(res + sres),
                    Ok((rest_term, sres)) => {
                        ioterm = rest_term;
                        res += sres;
                        left -= sres;
                    }
                }
            } else {
                return Err(res);
            }
        }
    }
    while let Some(entry) = stack.pop() {
        ioterm = TermBuilder::new(&mut Heap(&mut ctx.heap))
            .cons(ioterm, entry)
            .map_err(|_| res)?;
    }
    Ok((ioterm, res))
}

fn chksum_left(ctx: &Ctx<'_>, kind: ChksumKind) -> usize {
    let budget = ctx.reduction_budget();
    if budget == usize::MAX {
        return usize::MAX;
    }
    match kind {
        // Calibrated so that each reduction does one round of MD5 (4 bytes), rounded down to
        // whole 64 byte blocks.
        ChksumKind::Md5 | ChksumKind::Md5Update => budget.saturating_mul(4) & !0x3f,
        _ => CHUNK_PER_SCHEDULE,
    }
}

/// Run one slice of a checksum over `input`.
///
/// Port of `crc32_1`, `crc32_2`, `adler32_1`, `adler32_2`, `md5_1` and the hidden `md5_2` in
/// erts/emulator/beam/erl_bif_chksum.c, OTP-29.1.1: the sums consume a bounded number of
/// bytes, charge per byte and trap with the sum so far and the rest of the input.
fn chksum_slice(
    ctx: &mut Ctx<'_>,
    kind: ChksumKind,
    target: ChksumTarget,
    mut sum: ChksumSum,
    input: Term,
) -> Result<ChksumStep, BifError> {
    let left = chksum_left(ctx, kind);
    let outcome = {
        let mut feed = |bytes: &[u8]| match &mut sum {
            ChksumSum::Zlib(value) => {
                for chunk in bytes.chunks(u32::MAX as usize) {
                    // SAFETY: the chunk pointer stays valid for the duration of this zlib call.
                    *value = unsafe {
                        if kind == ChksumKind::Adler32 {
                            libz_sys::adler32(*value, chunk.as_ptr(), chunk.len() as u32)
                        } else {
                            libz_sys::crc32(*value, chunk.as_ptr(), chunk.len() as u32)
                        }
                    };
                }
            }
            ChksumSum::Md5(state) => state.update(bytes),
        };
        do_chksum(ctx, &mut feed, input, left)
    };
    let (rest, res) = match outcome {
        Ok(done) => done,
        Err(res) => {
            ctx.charge_reductions(match kind {
                ChksumKind::Md5 | ChksumKind::Md5Update => res,
                _ => res / BYTES_PER_REDUCTION,
            });
            return Err(BifError::BADARG);
        }
    };
    match kind {
        ChksumKind::Crc32 | ChksumKind::Adler32 => {
            ctx.charge_reductions(res / BYTES_PER_REDUCTION);
            let ChksumSum::Zlib(value) = sum else {
                unreachable!("zlib kinds carry a zlib sum")
            };
            if rest != Term::NIL && ctx.reduction_budget() != usize::MAX {
                ctx.bump_all_reds();
                return Ok(ChksumStep::More(ChksumCont {
                    kind,
                    target,
                    sum: ChksumSum::Zlib(value),
                    rest,
                }));
            }
            Ok(ChksumStep::Done(result(value as u32)))
        }
        ChksumKind::Md5 | ChksumKind::Md5Update => {
            if rest != Term::NIL && ctx.reduction_budget() != usize::MAX {
                ctx.bump_all_reds();
                return Ok(ChksumStep::More(ChksumCont {
                    kind,
                    target,
                    sum,
                    rest,
                }));
            }
            ctx.charge_reductions(res);
            let ChksumSum::Md5(state) = sum else {
                unreachable!("md5 carries an md5 state")
            };
            let bytes = match target {
                ChksumTarget::Checksum => state.final_digest().to_vec(),
                ChksumTarget::Md5Update => state.bytes().to_vec(),
            };
            Ok(ChksumStep::Done(binary(ctx, &bytes)?))
        }
    }
}

/// The first slice of `crc32/1,2`, `adler32/1,2` or `md5/1`, or of `crc32/2` and `adler32/2`
/// called directly. `Md5Update` starts from the supplied serialized context.
pub fn chksum_start(
    ctx: &mut Ctx<'_>,
    kind: ChksumKind,
    args: &[Term],
) -> Result<ChksumStep, BifError> {
    let (data, sum, target) = if kind == ChksumKind::Md5Update {
        (
            args[1],
            ChksumSum::Md5(Md5State::from_bytes(&binary_bytes(args[0])?)?),
            ChksumTarget::Md5Update,
        )
    } else {
        let (seed, data) = if args.len() == 1 {
            (if kind == ChksumKind::Adler32 { 1 } else { 0 }, args[0])
        } else {
            (u32_arg(args[0])?, args[1])
        };
        let sum = if kind == ChksumKind::Md5 {
            ChksumSum::Md5(Md5State::new())
        } else {
            ChksumSum::Zlib(seed as std::ffi::c_ulong)
        };
        (data, sum, ChksumTarget::Checksum)
    };
    chksum_slice(ctx, kind, target, sum, data)
}

/// Run the slice that follows a trap.
pub fn chksum_resume(ctx: &mut Ctx<'_>, cont: &ChksumCont) -> Result<ChksumStep, BifError> {
    chksum_slice(ctx, cont.kind, cont.target, cont.sum.clone(), cont.rest)
}

fn run_chksum(ctx: &mut Ctx<'_>, kind: ChksumKind, args: &[Term]) -> Term {
    match chksum_start(ctx, kind, args) {
        Ok(ChksumStep::Done(value)) => value,
        Ok(ChksumStep::More(cont)) => ctx.trap(DeferredTrap::Chksum(cont)),
        Err(error) => ctx.fail(error),
    }
}
fn crc32(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    run_chksum(ctx, ChksumKind::Crc32, args)
}
fn adler32(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    run_chksum(ctx, ChksumKind::Adler32, args)
}
fn combine(args: &[Term], adler: bool) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_bif_chksum.c:340-455, OTP-29.1.1.
    let a = u32_arg(args[0])?;
    let b = u32_arg(args[1])?;
    let length = u32_arg(args[2])?;
    if adler && length == 0 {
        return Ok(result(a));
    }
    // SAFETY: zlib takes integer values only and retains no pointers.
    let value = unsafe {
        if adler {
            libz_sys::adler32_combine(a.into(), b.into(), length.into())
        } else {
            libz_sys::crc32_combine(a.into(), b.into(), length.into())
        }
    };
    Ok(result(value as u32))
}
fn crc32_combine_result(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    combine(args, false)
}
fn adler32_combine_result(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    combine(args, true)
}

fn binary(ctx: &mut Ctx<'_>, bytes: &[u8]) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .binary(bytes)
        .map_err(|_| BifError::SystemLimit)
}
fn md5(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    run_chksum(ctx, ChksumKind::Md5, args)
}

#[derive(Clone)]
pub(crate) struct Md5State {
    words: [u32; 4],
    processed: u64,
    len: usize,
    buffer: [u8; 64],
}
impl Md5State {
    fn new() -> Self {
        Self {
            words: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            processed: 0,
            len: 0,
            buffer: [0; 64],
        }
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self, BifError> {
        if bytes.len() != 96 {
            return Err(BifError::BADARG);
        }
        let mut words = [0; 4];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_ne_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
        }
        let processed = u64::from_ne_bytes(bytes[16..24].try_into().unwrap());
        let len = u64::from_ne_bytes(bytes[24..32].try_into().unwrap()) as usize;
        if len > 64 {
            return Err(BifError::BADARG);
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
    fn update(&mut self, mut data: &[u8]) {
        // Port of erts/emulator/beam/erl_md5.c:92-125 (erts_md5_update), OTP-29.1.1.
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

const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const CONSTANTS: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];
fn compress(words: &mut [u32; 4], block: &[u8]) {
    // Port of erts/emulator/beam/erl_md5.c:151-223 (hash_part), OTP-29.1.1.
    let [mut a, mut b, mut c, mut d] = *words;
    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => (d ^ (b & (c ^ d)), i),
            16..=31 => (c ^ (d & (b ^ c)), (5 * i + 1) & 15),
            32..=47 => (b ^ c ^ d, (3 * i + 5) & 15),
            _ => (c ^ (b | !d), (7 * i) & 15),
        };
        let m = u32::from_le_bytes(block[g * 4..g * 4 + 4].try_into().unwrap());
        let next = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(CONSTANTS[i])
                .wrapping_add(m)
                .rotate_left(SHIFTS[i]),
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
fn md5_init_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    binary(ctx, &Md5State::new().bytes())
}
fn md5_update(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match chksum_start(ctx, ChksumKind::Md5Update, args) {
        Ok(ChksumStep::Done(value)) => value,
        Ok(ChksumStep::More(cont)) => ctx.trap(DeferredTrap::Chksum(cont)),
        Err(error) => ctx.fail(error),
    }
}
fn md5_final_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let state = Md5State::from_bytes(&binary_bytes(args[0])?)?;
    binary(ctx, &state.final_digest())
}

macro_rules! word_adapters {
    ($($word:ident => $body:ident),+ $(,)?) => {
        $(#[inline(always)]
        fn $word(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
            match $body(ctx, args) { Ok(value) => value, Err(error) => ctx.fail(error) }
        })+
    };
}
word_adapters!(crc32_combine => crc32_combine_result, adler32_combine => adler32_combine_result,
    md5_init => md5_init_result, md5_final => md5_final_result);
crate::word_bif_bodies_in!(word_bodies; crc32, adler32, crc32_combine, adler32_combine, md5,
    md5_init, md5_update, md5_final);
