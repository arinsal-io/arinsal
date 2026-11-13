//! `dec_term` of `binary_to_term`: one function over the factory block, the work list being
//! the `next` chain threaded through the heap words not yet filled.
//!
//! Port of erts/emulator/beam/external.c (`dec_term`, `dec_pid`, `dec_sysname`,
//! `B2TDecodeContext`), OTP-29.1.1.

use super::external_dec::{B2T_MEMCPY_FACTOR, B2tState};
use arinsal_bifs::BifError;
use arinsal_term::raw::{HeapSlotPtr, copy_to_binary_payload, term_from_bits};
use arinsal_term::{
    Atom, AtomEncoding, FunEntry, HeapAlloc, HeapFactory, HeapReservation, HxNode, Node,
    ProcessHeap, RefcBinary, Term, TermBuilder, TermKind, global_atoms,
    hashmap_from_unsorted_array, hashmap_key_hash,
};
use num_bigint::{BigInt, Sign};
use smallvec::SmallVec;
use std::sync::Arc;

pub(super) struct Reader<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) at: usize,
}
impl Reader<'_> {
    pub(super) fn take(&mut self, n: usize) -> Result<&[u8], BifError> {
        let end = self.at.checked_add(n).ok_or(BifError::BADARG)?;
        let part = self
            .bytes
            .get(self.at..end)
            .ok_or(BifError::Unsupported("incomplete ETF input"))?;
        self.at = end;
        Ok(part)
    }
    pub(super) fn u8(&mut self) -> Result<u8, BifError> {
        Ok(self.take(1)?[0])
    }
    pub(super) fn u16(&mut self) -> Result<u16, BifError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub(super) fn u32(&mut self) -> Result<u32, BifError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub(super) fn u64(&mut self) -> Result<u64, BifError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub(super) fn atom(
        &mut self,
        safe: bool,
        has_heap: bool,
    ) -> Result<(Term, Option<String>), BifError> {
        let tag = self.u8()?;
        let (len, utf8) = match tag {
            100 => (self.u16()? as usize, false),
            115 => (self.u8()? as usize, false),
            118 => (self.u16()? as usize, true),
            119 => (self.u8()? as usize, true),
            _ => return Err(BifError::BADARG),
        };
        let raw = self.take(len)?;
        let encoding = if utf8 {
            AtomEncoding::Utf8
        } else {
            AtomEncoding::Latin1
        };
        let atoms = global_atoms();
        let found = atoms.existing(raw, encoding);
        if safe && found.is_none() {
            return Err(BifError::BADARG);
        }
        let (atom, unknown) = if let Some(atom) = found {
            (atom, None)
        } else if has_heap {
            let atom = atoms
                .put(raw, encoding, false)
                .map_err(|error| match error {
                    arinsal_term::AtomError::SystemLimit => BifError::SystemLimit,
                    arinsal_term::AtomError::TooLong | arinsal_term::AtomError::BadEncoding => {
                        BifError::BADARG
                    }
                })?;
            (atom, None)
        } else {
            let name = match encoding {
                AtomEncoding::Ascii | AtomEncoding::Utf8 => std::str::from_utf8(raw)
                    .map_err(|_| BifError::BADARG)?
                    .to_owned(),
                AtomEncoding::Latin1 => {
                    raw.iter().map(|byte| char::from(*byte)).collect::<String>()
                }
            };
            if name.chars().count() > 255 {
                return Err(BifError::BADARG);
            }
            (arinsal_term::atoms::NONAME, Some(name))
        };
        Ok((Term::atom(atom), unknown))
    }
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8], at: usize) -> Self {
        Self { bytes, at }
    }
}

/// `struct dec_term_map`: a map whose keys and values are filled by the `next` chain and that
/// is finished (sorted / hashed) after the whole term was decoded.
// Port of erts/emulator/beam/external.c (struct dec_term_map), OTP-29.1.1.
pub(crate) struct DecTermMap {
    /// `objp` of a hashmap (where the built HAMT goes); `None` for a flatmap.
    objp: Option<HeapSlotPtr>,
    size: usize,
    /// `u.flatmap` or `u.leaf_array`.
    ptr: HeapSlotPtr,
}

/// `B2TDecodeContext` (`ctx->u.dc`).
// Port of erts/emulator/beam/external.c (B2TDecodeContext), OTP-29.1.1.
#[derive(Default)]
pub(crate) struct B2tDecodeContext {
    pub(crate) ep: usize,
    /// `res`: the root word; `next` starts at its address, so the context must not move while
    /// a decode is in progress (it lives in the trap's magic binary, as in erts).
    pub(crate) res: u64,
    pub(crate) next: Option<HeapSlotPtr>,
    pub(crate) factory: Option<HeapFactory>,
    pub(crate) remaining_n: usize,
    pub(crate) remaining_bytes: usize,
    /// `map_array` saved across a yield (`PSTACK_SAVE`).
    pub(crate) map_array: SmallVec<[DecTermMap; 10]>,
}

/// `flags` of `dec_term`: `ERTS_DIST_EXT_BTT_SAFE`, `ERTS_DIST_EXT_INTERNAL_NC`, and this node
/// for `dec_is_this_node`.
pub(crate) struct DecFlags {
    pub(crate) safe: bool,
    pub(crate) internal_nc: bool,
    pub(crate) this_node: (Atom, u32),
}

/// The parts of `B2TContext` that `dec_term` uses when it is resumable.
pub(crate) struct DecCtx<'c> {
    pub(crate) state: &'c mut B2tState,
    pub(crate) reds: &'c mut i64,
    pub(crate) dc: &'c mut B2tDecodeContext,
}

pub(super) fn map_term_build_error(error: arinsal_term::TermError) -> BifError {
    match error {
        arinsal_term::TermError::SystemLimit => BifError::SystemLimit,
        _ => BifError::BADARG,
    }
}

// Port of erl_term.h (make_list, make_tuple / make_boxed), OTP-29.1.1.
#[inline(always)]
fn make_list(p: HeapSlotPtr) -> u64 {
    p.address() | 1
}
#[inline(always)]
fn make_boxed(p: HeapSlotPtr) -> u64 {
    p.address() | 2
}
#[inline(always)]
fn link(next: Option<HeapSlotPtr>) -> u64 {
    next.map_or(0, HeapSlotPtr::address)
}

/// `hp += words` on the factory (`erts_produce_heap` once the block is used up).
#[inline(always)]
fn produce(
    fac: &mut HeapReservation<'_, ProcessHeap>,
    words: usize,
) -> Result<HeapSlotPtr, BifError> {
    fac.alloc(words)
        .and_then(HeapSlotPtr::from_ptr)
        .ok_or(BifError::SystemLimit)
}

/// `dec_sysname`: a node name atom, or `NIL_EXT` for this node under `LOCAL_EXT`.
// Port of erts/emulator/beam/external.c (dec_sysname), OTP-29.1.1.
fn dec_sysname(r: &mut Reader<'_>, flags: &DecFlags) -> Result<(Atom, bool), BifError> {
    if flags.internal_nc && r.bytes.get(r.at) == Some(&106) {
        r.at += 1;
        return Ok((flags.this_node.0, true));
    }
    let node = r
        .atom(flags.safe, true)?
        .0
        .as_atom()
        .ok_or(BifError::BADARG)?;
    Ok((node, false))
}

/// `dec_is_this_node`.
// Port of erts/emulator/beam/external.c (dec_is_this_node), OTP-29.1.1.
#[inline]
fn dec_is_this_node(flags: &DecFlags, sysname: (Atom, bool), creation: u32) -> bool {
    sysname.1 || (sysname.0 == flags.this_node.0 && creation == flags.this_node.1)
}

/// `dec_pid`.
// Port of erts/emulator/beam/external.c (dec_pid), OTP-29.1.1.
fn dec_pid(
    r: &mut Reader<'_>,
    fac: &mut HeapReservation<'_, ProcessHeap>,
    tag: u8,
    flags: &DecFlags,
) -> Result<Term, BifError> {
    let sysname = dec_sysname(r, flags)?;
    let num = r.u32()?;
    let ser = r.u32()?;
    let cre = if tag == 103 {
        let cre = r.u8()? as u32;
        if cre > 3 {
            return Err(BifError::BADARG);
        }
        cre
    } else {
        r.u32()?
    };
    if dec_is_this_node(flags, sysname, cre) {
        Term::pid(num, ser).ok_or(BifError::BADARG)
    } else {
        TermBuilder::new(fac)
            .external_pid(Node::new(sysname.0, cre), num, ser)
            .map_err(map_term_build_error)
    }
}

/// `dec_term(edep, factory, ep, objp, ctx, flags)`: decode one term into `*objp` (or resume
/// `ctx`). `Ok(Some(ep))` when done, `Ok(None)` when `ctx` yielded (`ctx->reds = 0`); on an
/// error the caller undoes the factory (`erts_factory_undo`).
// Port of erts/emulator/beam/external.c (dec_term), OTP-29.1.1.
pub(crate) fn dec_term(
    fac: &mut HeapReservation<'_, ProcessHeap>,
    bytes: &[u8],
    ep: usize,
    objp: Option<HeapSlotPtr>,
    ctx: Option<DecCtx<'_>>,
    flags: &mut DecFlags,
) -> Result<Option<usize>, BifError> {
    match ctx {
        Some(mut ctx) => {
            let mut reds = *ctx.reds;
            let result = dec_term_body(fac, bytes, ep, None, Some(&mut ctx), flags, &mut reds);
            *ctx.reds = reds;
            result
        }
        None => {
            let mut reds = i64::MAX;
            dec_term_body(fac, bytes, ep, objp, None, flags, &mut reds)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dec_term_body(
    fac: &mut HeapReservation<'_, ProcessHeap>,
    bytes: &[u8],
    ep: usize,
    objp: Option<HeapSlotPtr>,
    mut ctx: Option<&mut DecCtx<'_>>,
    flags: &mut DecFlags,
    reds: &mut i64,
) -> Result<Option<usize>, BifError> {
    let mut r = Reader::new(bytes, ep);
    let mut next: Option<HeapSlotPtr>;
    let mut map_array: SmallVec<[DecTermMap; 10]>;
    if let Some(c) = ctx.as_deref_mut() {
        next = c.dc.next;
        r.at = c.dc.ep;
        if *c.state != B2tState::Decode {
            let mut n_limit = *reds;
            let mut n = c.dc.remaining_n as i64;
            if *c.state == B2tState::DecodeBinary {
                n_limit *= B2T_MEMCPY_FACTOR as i64;
                *reds -= n / B2T_MEMCPY_FACTOR as i64;
            } else {
                *reds -= n;
            }
            if n > n_limit {
                c.dc.remaining_n -= n_limit as usize;
                n = n_limit;
                *reds = 0;
            } else {
                c.dc.remaining_n = 0;
            }
            match *c.state {
                B2tState::DecodeList => {
                    let mut o = next.ok_or(BifError::BADARG)?.back(2);
                    while n > 0 {
                        o.store(link(next));
                        o.offset(1).store(make_list(next.ok_or(BifError::BADARG)?));
                        next = Some(o);
                        o = o.back(2);
                        n -= 1;
                    }
                }
                B2tState::DecodeTuple => {
                    let mut o = next.ok_or(BifError::BADARG)?.back(1);
                    while n > 0 {
                        o.store(link(next));
                        next = Some(o);
                        o = o.back(1);
                        n -= 1;
                    }
                }
                B2tState::DecodeString => {
                    if n > 0 {
                        let src = r.take(n as usize)?;
                        let hp = produce(fac, 2 * n as usize)?;
                        // Overwrite the premature NIL of the previous chunk.
                        hp.back(1).store(make_list(hp));
                        for (i, byte) in src.iter().enumerate() {
                            hp.offset(2 * i)
                                .store(Term::small(i64::from(*byte)).unwrap().word());
                            hp.offset(2 * i + 1).store(make_list(hp.offset(2 * i + 2)));
                        }
                        hp.offset(2 * n as usize - 1).store(Term::NIL.word());
                    }
                }
                B2tState::DecodeBinary => {
                    let src = r.take(n as usize)?;
                    copy_to_binary_payload(c.dc.remaining_bytes, src);
                    c.dc.remaining_bytes += n as usize;
                }
                _ => return Err(BifError::BADARG),
            }
            if c.dc.remaining_n == 0 {
                *c.state = B2tState::Decode;
            }
            if *reds <= 0 {
                c.dc.next = next;
                c.dc.ep = r.at;
                *reds = 0;
                return Ok(None);
            }
        }
        map_array = std::mem::take(&mut c.dc.map_array);
    } else {
        next = objp;
        if let Some(root) = objp {
            root.store(0);
        }
        map_array = SmallVec::new();
    }

    while let Some(current) = next {
        let objp = current;
        next = HeapSlotPtr::from_ptr(objp.load() as *mut u64);
        // `continue_this_obj`: LOCAL_EXT decodes the next tag into the same `objp`.
        loop {
            let tag = r.u8()?;
            match tag {
                98 => objp.store(Term::small(i64::from(r.u32()? as i32)).unwrap().word()),
                97 => objp.store(Term::small(i64::from(r.u8()?)).unwrap().word()),
                110 | 111 => {
                    let n = if tag == 110 {
                        r.u8()? as usize
                    } else {
                        r.u32()? as usize
                    };
                    let neg = r.u8()?;
                    let digits = r.take(n)?;
                    // Strip away leading zeroes to avoid creating illegal bignums.
                    let len = digits
                        .iter()
                        .rposition(|byte| *byte != 0)
                        .map_or(0, |i| i + 1);
                    let big = if len == 0 {
                        Term::small(0).unwrap()
                    } else {
                        let value = BigInt::from_bytes_le(
                            if neg == 0 { Sign::Plus } else { Sign::Minus },
                            &digits[..len],
                        );
                        TermBuilder::new(&mut *fac)
                            .int_from_bigint(&value)
                            .map_err(map_term_build_error)?
                    };
                    objp.store(big.word());
                }
                100 | 115 | 118 | 119 => {
                    r.at -= 1;
                    objp.store(r.atom(flags.safe, true)?.0.word());
                }
                104 | 105 => {
                    let mut n = if tag == 104 {
                        r.u8()? as i64
                    } else {
                        r.u32()? as i64
                    };
                    if n == 0 {
                        objp.store(arinsal_term::global_empty_tuple().word());
                    } else {
                        let hp = produce(fac, n as usize + 1)?;
                        objp.store(make_boxed(hp));
                        hp.store((n as u64) << 6);
                        let mut o = hp.offset(n as usize);
                        if let Some(c) = ctx.as_deref_mut() {
                            if *reds < n {
                                *c.state = B2tState::DecodeTuple;
                                c.dc.remaining_n = (n - *reds) as usize;
                                n = *reds;
                            }
                            *reds -= n;
                        }
                        while n > 0 {
                            o.store(link(next));
                            next = Some(o);
                            o = o.back(1);
                            n -= 1;
                        }
                    }
                }
                106 => objp.store(Term::NIL.word()),
                108 => {
                    let mut nu = r.u32()? as i64;
                    if nu == 0 {
                        next = Some(objp);
                    } else {
                        let hp = produce(fac, 2 * nu as usize)?;
                        objp.store(make_list(hp));
                        let mut o = hp.offset(2 * nu as usize - 2);
                        o.store(o.offset(1).address());
                        o.offset(1).store(link(next));
                        next = Some(o);
                        o = o.back(2);
                        nu -= 1;
                        if let Some(c) = ctx.as_deref_mut() {
                            if *reds < nu {
                                *c.state = B2tState::DecodeList;
                                c.dc.remaining_n = (nu - *reds) as usize;
                                nu = *reds;
                            }
                            *reds -= nu;
                        }
                        while nu > 0 {
                            let n = next.ok_or(BifError::BADARG)?;
                            o.store(n.address());
                            o.offset(1).store(make_list(n));
                            next = Some(o);
                            o = o.back(2);
                            nu -= 1;
                        }
                    }
                }
                107 => {
                    let mut n = r.u16()? as i64;
                    if n == 0 {
                        objp.store(Term::NIL.word());
                    } else {
                        if let Some(c) = ctx.as_deref_mut() {
                            if *reds < n {
                                *c.state = B2tState::DecodeString;
                                c.dc.remaining_n = (n - *reds) as usize;
                                n = *reds;
                            }
                            *reds -= n;
                        }
                        let src = r.take(n as usize)?;
                        let hp = produce(fac, 2 * n as usize)?;
                        objp.store(make_list(hp));
                        for (i, byte) in src.iter().enumerate() {
                            hp.offset(2 * i)
                                .store(Term::small(i64::from(*byte)).unwrap().word());
                            hp.offset(2 * i + 1).store(make_list(hp.offset(2 * i + 2)));
                        }
                        hp.offset(2 * n as usize - 1).store(Term::NIL.word());
                    }
                }
                99 | 70 => {
                    let value = if tag == 70 {
                        let value = f64::from_bits(r.u64()?);
                        if !value.is_finite() {
                            return Err(BifError::BADARG);
                        }
                        value
                    } else {
                        // sys_chars_to_double
                        let raw = r.take(31)?;
                        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(31);
                        let value = std::str::from_utf8(&raw[..end])
                            .map_err(|_| BifError::BADARG)?
                            .trim()
                            .parse::<f64>()
                            .map_err(|_| BifError::BADARG)?;
                        if !value.is_finite() {
                            return Err(BifError::BADARG);
                        }
                        value
                    };
                    objp.store(
                        TermBuilder::new(&mut *fac)
                            .float(value)
                            .map_err(map_term_build_error)?
                            .word(),
                    );
                }
                103 | 88 => {
                    objp.store(Term::NIL.word());
                    objp.store(dec_pid(&mut r, fac, tag, flags)?.word());
                }
                102 | 89 | 120 | 101 | 114 | 90 => {
                    objp.store(dec_port_or_ref(&mut r, fac, tag, flags)?.word());
                }
                109 | 77 => {
                    let mut nu = r.u32()? as usize;
                    let mut size_in_bits = nu.checked_mul(8).ok_or(BifError::BADARG)?;
                    if tag == 77 {
                        let trailing_bits = r.u8()? as usize;
                        if !(1..=8).contains(&trailing_bits) || size_in_bits < 8 {
                            return Err(BifError::BADARG);
                        }
                        size_in_bits -= 8 - trailing_bits;
                    }
                    if size_in_bits <= ERL_ONHEAP_BITS_LIMIT {
                        if ctx.is_some() {
                            // Count reductions but don't bother trying to trap in the
                            // middle, it's short enough not to matter.
                            *reds -= (*reds).min((nu / B2T_MEMCPY_FACTOR) as i64);
                        }
                        let src = r.take(nu)?;
                        let words = 2 + nu.div_ceil(8);
                        let hb = produce(fac, words)?;
                        hb.store((((words - 1) as u64) << 6) | HEAP_BITS);
                        hb.offset(1).store(size_in_bits as u64);
                        for (index, chunk) in src.chunks(8).enumerate() {
                            let mut word = [0; 8];
                            word[..chunk.len()].copy_from_slice(chunk);
                            if index + 1 == words - 2 && !size_in_bits.is_multiple_of(8) {
                                word[chunk.len() - 1] &= 0xff << (8 - size_in_bits % 8);
                            }
                            hb.offset(2 + index).store(u64::from_ne_bytes(word));
                        }
                        objp.store(make_boxed(hb));
                    } else {
                        let mut binary = RefcBinary::new_zeroed(size_in_bits.div_ceil(8))
                            .map_err(map_term_build_error)?;
                        let data = binary.bytes_mut_unique().ok_or(BifError::BADARG)?;
                        let data_addr = data.as_mut_ptr() as usize;
                        if let Some(c) = ctx.as_deref_mut() {
                            let n_limit = (*reds).max(0) as usize * B2T_MEMCPY_FACTOR;
                            if nu > n_limit {
                                *c.state = B2tState::DecodeBinary;
                                c.dc.remaining_n = nu - n_limit;
                                c.dc.remaining_bytes = data_addr + n_limit;
                                nu = n_limit;
                                *reds = 0;
                            } else {
                                *reds -= (nu / B2T_MEMCPY_FACTOR) as i64;
                            }
                        }
                        data[..nu].copy_from_slice(r.take(nu)?);
                        let term = TermBuilder::new(&mut *fac)
                            .refc_binary(binary, size_in_bits)
                            .map_err(map_term_build_error)?;
                        objp.store(term.word());
                    }
                }
                113 => {
                    let module = r
                        .atom(flags.safe, true)?
                        .0
                        .as_atom()
                        .ok_or(BifError::BADARG)?;
                    let name = r
                        .atom(flags.safe, true)?
                        .0
                        .as_atom()
                        .ok_or(BifError::BADARG)?;
                    let temp = dec_sub_term(fac, &mut r, flags)?;
                    let arity = temp.as_small().ok_or(BifError::BADARG)?;
                    if arity < 0 {
                        return Err(BifError::BADARG);
                    }
                    let arity = u8::try_from(arity).map_err(|_| BifError::BADARG)?;
                    let mfa = (module, name, arity);
                    if flags.safe && crate::export::active_export_entry(mfa).is_none() {
                        return Err(BifError::BADARG);
                    }
                    let export =
                        crate::export::export_get_or_make_stub(mfa).ok_or(BifError::SystemLimit)?;
                    objp.store(
                        TermBuilder::new(&mut *fac)
                            .export_fun(export)
                            .map_err(map_term_build_error)?
                            .word(),
                    );
                }
                116 => {
                    let size = r.u32()? as usize;
                    if size <= MAP_SMALL_MAP_LIMIT {
                        let keys;
                        let mut kptr = None;
                        if size == 0 {
                            keys = arinsal_term::global_empty_tuple().word();
                        } else {
                            let hp = produce(fac, size + 1)?;
                            hp.store((size as u64) << 6);
                            keys = make_boxed(hp);
                            kptr = Some(hp.offset(size));
                        }
                        let mp = produce(fac, MAP_HEADER_FLATMAP_SZ + size)?;
                        mp.store(MAP_HEADER_FLATMAP);
                        mp.offset(1).store(size as u64);
                        mp.offset(2).store(keys);
                        objp.store(make_boxed(mp));
                        if let Some(mut kptr) = kptr {
                            let mut vptr = mp.offset(MAP_HEADER_FLATMAP_SZ + size - 1);
                            for _ in 0..size {
                                vptr.store(link(next));
                                kptr.store(vptr.address());
                                next = Some(kptr);
                                vptr = vptr.back(1);
                                kptr = kptr.back(1);
                            }
                        }
                        map_array.push(DecTermMap {
                            objp: None,
                            size,
                            ptr: mp,
                        });
                    } else {
                        let leaf_array = produce(fac, 2 * size)?;
                        map_array.push(DecTermMap {
                            objp: Some(objp),
                            size,
                            ptr: leaf_array,
                        });
                        let mut hp = leaf_array;
                        for _ in 0..size {
                            hp.offset(1).store(link(next));
                            hp.store(hp.offset(1).address());
                            next = Some(hp);
                            hp = hp.offset(2);
                        }
                    }
                }
                112 => {
                    r.take(4)?; // Skip total size in bytes
                    let arity = r.u8()?;
                    let uniq: [u8; 16] = r.take(16)?.try_into().map_err(|_| BifError::BADARG)?;
                    let index = r.u32()?;
                    let num_free = r.u32()? as usize;
                    let funp = produce(fac, ERL_FUN_SIZE + num_free)?;
                    let module = r
                        .atom(flags.safe, true)?
                        .0
                        .as_atom()
                        .ok_or(BifError::BADARG)?;
                    let old_index = dec_sub_term(fac, &mut r, flags)?
                        .as_small()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or(BifError::BADARG)?;
                    let old_uniq = dec_sub_term(fac, &mut r, flags)?
                        .as_small()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or(BifError::BADARG)?;
                    let pid = dec_sub_term(fac, &mut r, flags)?;
                    if pid.classify() != TermKind::Pid {
                        return Err(BifError::BADARG);
                    }
                    let entry = Arc::new(FunEntry {
                        dispatch_target: Default::default(),
                        pend_purge_address: Default::default(),
                        module,
                        arity,
                        index,
                        uniq,
                        old_index,
                        old_uniq,
                        pid,
                        dispatch: Default::default(),
                        dispatch_epoch: Default::default(),
                    });
                    let fun = TermBuilder::<HeapReservation<'_, ProcessHeap>>::init_decoded_fun(
                        funp, entry, num_free,
                    )
                    .map_err(map_term_build_error)?;
                    objp.store(fun.word());
                    for i in (0..num_free).rev() {
                        let env = funp.offset(ERL_FUN_SIZE + i);
                        env.store(link(next));
                        next = Some(env);
                    }
                }
                73 | 75 => {
                    let n = if tag == 73 {
                        r.u16()? as u32
                    } else {
                        let b = r.take(3)?;
                        u32::from_be_bytes([0, b[0], b[1], b[2]])
                    };
                    let atom = Atom(n);
                    if global_atoms().text(atom).is_none() {
                        return Err(BifError::BADARG);
                    }
                    objp.store(Term::atom(atom).word());
                }
                121 => {
                    flags.internal_nc = true;
                    r.take(4)?; // 32-bit hash (verified in decoded_size())
                    continue;
                }
                67 => {
                    let num_fields = r.u32()? as usize;
                    let exported = match r.u8()? {
                        0 => false,
                        1 => true,
                        // The other bits in this byte are reserved and must be zero.
                        _ => return Err(BifError::BADARG),
                    };
                    let module = r
                        .atom(flags.safe, true)?
                        .0
                        .as_atom()
                        .ok_or(BifError::BADARG)?;
                    let name = r
                        .atom(flags.safe, true)?
                        .0
                        .as_atom()
                        .ok_or(BifError::BADARG)?;
                    let mut keys = SmallVec::<[Atom; 8]>::new();
                    for _ in 0..num_fields {
                        keys.push(
                            r.atom(flags.safe, true)?
                                .0
                                .as_atom()
                                .ok_or(BifError::BADARG)?,
                        );
                    }
                    let (instance, values) = TermBuilder::new(&mut *fac)
                        .decoded_native_record(module, name, exported, &keys)
                        .map_err(map_term_build_error)?;
                    for value in values.iter().rev() {
                        value.store(link(next));
                        next = Some(*value);
                    }
                    objp.store(instance.word());
                }
                _ => return Err(BifError::BADARG),
            }
            break;
        }

        *reds -= 1;
        if *reds <= 0 {
            if let Some(c) = ctx.as_deref_mut() {
                if next.is_some() || *c.state != B2tState::Decode {
                    c.dc.ep = r.at;
                    c.dc.next = next;
                    c.dc.map_array = map_array;
                    *reds = 0;
                    return Ok(None);
                }
            } else {
                *reds = i64::MAX;
            }
        }
    }

    // Iterate through all the maps bottom-up: hash the keys and build the inner HAMT nodes of
    // hashmaps, check for duplicate keys and sort the keys of flatmaps. From here the factory
    // may produce heap fragments.
    while let Some(map) = map_array.last() {
        match map.objp {
            Some(objp) => {
                let mut hxns = Vec::with_capacity(map.size);
                for i in 0..map.size {
                    let leaf = map.ptr.offset(2 * i);
                    let key = term_from_bits(leaf.load());
                    hxns.push(HxNode {
                        hx: hashmap_key_hash(key),
                        skip: 1,
                        i,
                        val: term_from_bits(make_list(leaf)),
                    });
                }
                let built = hashmap_from_unsorted_array(&mut hxns, true, &mut *fac)
                    .map_err(map_term_build_error)?
                    .ok_or(BifError::BADARG)?;
                objp.store(built.word());
            }
            None => {
                if !arinsal_term::raw::validate_and_sort_flatmap(term_from_bits(make_boxed(
                    map.ptr,
                ))) {
                    return Err(BifError::BADARG);
                }
            }
        }
        map_array.pop();
    }

    if let Some(c) = ctx {
        *c.state = B2tState::Done;
        c.dc.ep = r.at;
    }
    Ok(Some(r.at))
}

/// `dec_term(edep, factory, ep, &temp, NULL, flags)`: a nested decode into a local word.
fn dec_sub_term(
    fac: &mut HeapReservation<'_, ProcessHeap>,
    r: &mut Reader<'_>,
    flags: &mut DecFlags,
) -> Result<Term, BifError> {
    let mut temp: u64 = 0;
    let slot = HeapSlotPtr::from_ptr(&mut temp).ok_or(BifError::BADARG)?;
    r.at = dec_term(fac, r.bytes, r.at, Some(slot), None, flags)?.ok_or(BifError::BADARG)?;
    Ok(term_from_bits(temp))
}

/// `ERL_ONHEAP_BITS_LIMIT`.
// Port of erts/emulator/beam/erl_bits.h, OTP-29.1.1.
const ERL_ONHEAP_BITS_LIMIT: usize = 64 * 8;
/// `HEAP_BITS_SUBTAG` header bits.
const HEAP_BITS: u64 = 0x20;
/// `MAP_SMALL_MAP_LIMIT`.
const MAP_SMALL_MAP_LIMIT: usize = 32;
/// `MAP_HEADER_FLATMAP` and `MAP_HEADER_FLATMAP_SZ`.
// Port of erts/emulator/beam/erl_map.h, OTP-29.1.1.
const MAP_HEADER_FLATMAP: u64 = 0x12c;
const MAP_HEADER_FLATMAP_SZ: usize = 3;
/// `ERL_FUN_SIZE`: header and entry words of a local fun.
const ERL_FUN_SIZE: usize = 2;

/// `PORT_EXT`/`NEW_PORT_EXT`/`V4_PORT_EXT` and `REFERENCE_EXT`/`NEW_REFERENCE_EXT`/
/// `NEWER_REFERENCE_EXT` of `dec_term`.
// Port of erts/emulator/beam/external.c (dec_term, PORT_EXT .. NEWER_REFERENCE_EXT),
// OTP-29.1.1.
fn dec_port_or_ref(
    r: &mut Reader<'_>,
    fac: &mut HeapReservation<'_, ProcessHeap>,
    tag: u8,
    flags: &DecFlags,
) -> Result<Term, BifError> {
    if matches!(tag, 102 | 89 | 120) {
        let sysname = dec_sysname(r, flags)?;
        let num = if tag == 120 {
            r.u64()?
        } else {
            r.u32()? as u64
        };
        let cre = if tag == 102 {
            let cre = r.u8()? as u32;
            if cre > 3 {
                return Err(BifError::BADARG);
            }
            cre
        } else {
            r.u32()?
        };
        return if dec_is_this_node(flags, sysname, cre) {
            Term::port(num).ok_or(BifError::BADARG)
        } else {
            TermBuilder::new(fac)
                .external_port(Node::new(sysname.0, cre), num)
                .map_err(map_term_build_error)
        };
    }
    let (sysname, cre, ref_words, r0) = match tag {
        101 => {
            let sysname = dec_sysname(r, flags)?;
            let r0 = r.u32()?;
            if r0 >= MAX_REFERENCE {
                return Err(BifError::BADARG);
            }
            let cre = r.u8()? as u32;
            if cre > 3 {
                return Err(BifError::BADARG);
            }
            (sysname, cre, 1, r0)
        }
        114 => {
            let ref_words = r.u16()? as usize;
            let sysname = dec_sysname(r, flags)?;
            let cre = r.u8()? as u32;
            if cre > 3 {
                return Err(BifError::BADARG);
            }
            let r0 = r.u32()?;
            if r0 >= MAX_REFERENCE {
                return Err(BifError::BADARG);
            }
            (sysname, cre, ref_words, r0)
        }
        _ => {
            let ref_words = r.u16()? as usize;
            let sysname = dec_sysname(r, flags)?;
            let cre = r.u32()?;
            let r0 = r.u32()?;
            (sysname, cre, ref_words, r0)
        }
    };
    if ref_words > ERTS_MAX_REF_NUMBERS {
        return Err(BifError::BADARG);
    }
    let mut ref_num = [0u32; ERTS_MAX_REF_NUMBERS];
    ref_num[0] = r0;
    for slot in ref_num.iter_mut().take(ref_words).skip(1) {
        *slot = r.u32()?;
    }
    if !dec_is_this_node(flags, sysname, cre) {
        return TermBuilder::new(fac)
            .external_ref(Node::new(sysname.0, cre), &ref_num[..ref_words])
            .map_err(map_term_build_error);
    }
    if r0 >= MAX_REFERENCE {
        // Local refs with more than 18 bits in the first word are rejected: the magic ref
        // table relies on it.
        return Err(BifError::BADARG);
    }
    let mut local_ids = [0; 3];
    local_ids.copy_from_slice(&ref_num[..3]);
    if ref_words == 5 && ref_num[1] & (1 << 16) != 0 {
        TermBuilder::new(fac)
            .local_pid_ref_from_words(local_ids, ref_num[3], ref_num[4])
            .map_err(map_term_build_error)
    } else {
        let saved = (local_ids[1] & (1 << 17) != 0)
            .then(|| arinsal_term::MagicRef::lookup_saved_numbers(local_ids))
            .flatten();
        match saved {
            Some(owner) => TermBuilder::new(fac)
                .magic_ref(owner)
                .map_err(map_term_build_error),
            None => TermBuilder::new(fac)
                .local_ref(local_ids)
                .map_err(map_term_build_error),
        }
    }
}

/// `MAX_REFERENCE` and `ERTS_MAX_REF_NUMBERS`.
// Port of erts/emulator/beam/erl_node_tables.h / erl_term.h, OTP-29.1.1.
const MAX_REFERENCE: u32 = 1 << 18;
const ERTS_MAX_REF_NUMBERS: usize = 5;
