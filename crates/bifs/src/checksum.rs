//! zlib-compatible checksum BIFs.

use arinsal_term::{Term, TermBuilder};
use md5::{Digest, Md5};
use num_traits::ToPrimitive;

use crate::pure::{Heap, bigint, binary_bytes, iolist_bytes};
use crate::{BifError, BifFn, Ctx};

pub(super) fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    let f: BifFn = match (module, name, arity) {
        ("erlang", "crc32", 1 | 2) => crc32,
        ("erlang", "adler32", 1 | 2) => adler32,
        ("erlang", "crc32_combine", 3) => crc32_combine,
        ("erlang", "adler32_combine", 3) => adler32_combine,
        ("erlang", "md5", 1) => md5,
        ("erlang", "md5_init", 0) => md5_init,
        ("erlang", "md5_update", 2) => md5_update,
        ("erlang", "md5_final", 1) => md5_final,
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
fn checksum(args: &[Term], adler: bool) -> Result<Term, BifError> {
    let (seed, data) = if args.len() == 1 {
        (if adler { 1 } else { 0 }, args[0])
    } else {
        (u32_arg(args[0])?, args[1])
    };
    let bytes = iolist_bytes(data)?;
    let mut sum = seed as std::ffi::c_ulong;
    for chunk in bytes.chunks(u32::MAX as usize) {
        // SAFETY: the chunk pointer stays valid for the duration of this zlib call.
        sum = unsafe {
            if adler {
                libz_sys::adler32(sum, chunk.as_ptr(), chunk.len() as u32)
            } else {
                libz_sys::crc32(sum, chunk.as_ptr(), chunk.len() as u32)
            }
        };
    }
    Ok(result(sum as u32))
}
fn crc32(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    checksum(args, false)
}
fn adler32(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    checksum(args, true)
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
fn crc32_combine(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    combine(args, false)
}
fn adler32_combine(_: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    combine(args, true)
}

fn binary(ctx: &mut Ctx<'_>, bytes: &[u8]) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(ctx.heap))
        .binary(bytes)
        .map_err(|_| BifError::SystemLimit)
}
fn md5(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let bytes = iolist_bytes(args[0])?;
    binary(ctx, &Md5::digest(bytes))
}

#[derive(Clone)]
struct Md5State {
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
fn md5_init(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    binary(ctx, &Md5State::new().bytes())
}
fn md5_update(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut state = Md5State::from_bytes(&binary_bytes(args[0])?)?;
    state.update(&iolist_bytes(args[1])?);
    binary(ctx, &state.bytes())
}
fn md5_final(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let state = Md5State::from_bytes(&binary_bytes(args[0])?)?;
    binary(ctx, &state.final_digest())
}
