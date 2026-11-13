//! The checksum helpers of erl_bif_chksum.c: `do_chksum`, the zlib sums and `erts_md5_state`.
//!
//! Port of erts/emulator/beam/erl_bif_chksum.c (do_chksum, crc32_wrap, adler32_wrap, md5_wrap)
//! and erl_md5.c, OTP-29.1.1. The BIF bodies (`crc32_1` ... `md5_final_1`) are in the VM crate,
//! where they are `bif_table[].f` with `(c_p, reg, I)`.

use arinsal_term::{Term, TermBuilder, TermKind};
use num_traits::ToPrimitive;

use crate::lists::cons_cell;
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

/// `term_to_Uint(term, &u) && ((u >> 16) >> 16) == 0`.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_2, adler32_2, *_combine_3), OTP-29.1.1.
pub fn term_to_u32(term: Term) -> Result<u32, BifError> {
    bigint(term)?.to_u32().ok_or(BifError::BADARG)
}

/// What `do_chksum` returned: `rest`, `*res` and `*err`.
pub struct Chksum {
    /// The input not consumed (`NIL` when all of it was).
    pub rest: Term,
    /// Bytes fed to the sum (`*res`).
    pub consumed: usize,
    /// The input is not an iolist (`*err`).
    pub failed: bool,
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

fn run(ctx: &mut Ctx<'_>, sum: &mut dyn FnMut(&[u8]), input: Term, left: usize) -> Chksum {
    match do_chksum(ctx, sum, input, left) {
        Ok((rest, consumed)) => Chksum {
            rest,
            consumed,
            failed: false,
        },
        Err(consumed) => Chksum {
            rest: Term::NIL,
            consumed,
            failed: true,
        },
    }
}

/// `do_chksum(&crc32_wrap | &adler32_wrap, ...)`.
// Port of erts/emulator/beam/erl_bif_chksum.c (do_chksum, crc32_wrap, adler32_wrap), OTP-29.1.1.
pub fn do_chksum_zlib(
    ctx: &mut Ctx<'_>,
    adler: bool,
    sum: &mut u32,
    input: Term,
    left: usize,
) -> Chksum {
    let mut value = std::ffi::c_ulong::from(*sum);
    let outcome = {
        let mut feed = |bytes: &[u8]| {
            for chunk in bytes.chunks(u32::MAX as usize) {
                // SAFETY: the chunk pointer stays valid for the duration of this zlib call.
                value = unsafe {
                    if adler {
                        libz_sys::adler32(value, chunk.as_ptr(), chunk.len() as u32)
                    } else {
                        libz_sys::crc32(value, chunk.as_ptr(), chunk.len() as u32)
                    }
                };
            }
        };
        run(ctx, &mut feed, input, left)
    };
    *sum = value as u32;
    outcome
}

/// `adler32(0, NULL, 0)` is 1, `crc32(0, NULL, 0)` is 0.
pub fn zlib_initial(adler: bool) -> u32 {
    if adler { 1 } else { 0 }
}

/// `do_chksum(&md5_wrap, ...)`.
// Port of erts/emulator/beam/erl_bif_chksum.c (do_chksum, md5_wrap), OTP-29.1.1.
pub fn do_chksum_md5(ctx: &mut Ctx<'_>, state: &mut Md5State, input: Term, left: usize) -> Chksum {
    let mut feed = |bytes: &[u8]| state.update(bytes);
    run(ctx, &mut feed, input, left)
}

/// `crc32_combine` / `adler32_combine` of the `_3` BIFs.
// Port of erts/emulator/beam/erl_bif_chksum.c (crc32_combine_3, adler32_combine_3), OTP-29.1.1.
pub fn combine(adler: bool, a: u32, b: u32, length: u32) -> u32 {
    if adler && length == 0 {
        // Workaround for unexpected behaviour in zlib.
        return a;
    }
    // SAFETY: zlib takes integer values only and retains no pointers.
    let value = unsafe {
        if adler {
            libz_sys::adler32_combine(a.into(), b.into(), length.into())
        } else {
            libz_sys::crc32_combine(a.into(), b.into(), length.into())
        }
    };
    value as u32
}

/// `md5_update_2` / `md5_final_1`: the context argument, which must be a binary of exactly
/// `sizeof(erts_md5_state)` bytes.
// Port of erts/emulator/beam/erl_bif_chksum.c (md5_update_2, md5_final_1:
// erts_get_aligned_binary_bytes), OTP-29.1.1.
pub fn md5_state_arg(term: Term) -> Result<Md5State, BifError> {
    Md5State::from_bytes(&binary_bytes(term)?)
}

/// A binary of `bytes`, as `erts_new_binary_from_data`.
pub fn new_binary(ctx: &mut Ctx<'_>, bytes: &[u8]) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .binary(bytes)
        .map_err(|_| BifError::SystemLimit)
}

/// `erts_md5_state` (`sizeof` 96 on a 64-bit build).
// Port of erts/emulator/beam/erl_md5.h (erts_md5_state), OTP-29.1.1.
#[derive(Clone)]
pub struct Md5State {
    words: [u32; 4],
    processed: u64,
    len: usize,
    buffer: [u8; 64],
}
impl Default for Md5State {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5State {
    /// `erts_md5_init`.
    pub fn new() -> Self {
        Self {
            words: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            processed: 0,
            len: 0,
            buffer: [0; 64],
        }
    }
    /// The state from its in-memory form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BifError> {
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
    /// The in-memory form, as copied into a binary.
    pub fn bytes(&self) -> [u8; 96] {
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
    /// `erts_md5_finish`.
    pub fn final_digest(mut self) -> [u8; 16] {
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
