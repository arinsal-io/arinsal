//! The distribution encoder: the atom cache map of one signal, the dist header and the
//! encoding of the control message and payload from heap terms.
//!
//! Port of erts/emulator/beam/external.c (erts_init_atom_cache_map, insert_acache_map,
//! get_iix_acache_map, erts_finalize_atom_cache_map, erts_encode_dist_ext_size,
//! erts_encode_dist_ext, erts_encode_ext_dist_header_setup,
//! erts_encode_ext_dist_header_finalize, erts_encode_ext_dist_header_fragment) and the
//! `ErtsAtomCache` of erts/emulator/beam/dist.h, OTP-29.1.1.

use std::cell::Cell;

use arinsal_term::{Atom, Term, global_atoms};

use crate::{ByteOutput, EncodeError, EncodeOpts, TtbContext, raw};

/// `ERTS_ATOM_CACHE_SIZE`.
pub const ERTS_ATOM_CACHE_SIZE: usize = 2048;
/// `ERTS_USE_ATOM_CACHE_SIZE`: the slots `atom2cix` maps to.
const ERTS_USE_ATOM_CACHE_SIZE: u32 = 2039;
/// `ERTS_MAX_INTERNAL_ATOM_CACHE_ENTRIES`.
const ERTS_MAX_INTERNAL_ATOM_CACHE_ENTRIES: usize = 255;
/// `ERTS_DIST_FRAGMENT_SIZE`.
pub const ERTS_DIST_FRAGMENT_SIZE: usize = 64 * 1024;

const DFLAG_DIST_HDR_ATOM_CACHE: u64 = 0x2000;
const DFLAG_FRAGMENTS: u64 = 0x80_0000;

const VERSION_MAGIC: u8 = 131;
const DIST_HEADER: u8 = 68;
const DIST_FRAG_HEADER: u8 = 69;
const DIST_FRAG_CONT: u8 = 70;
const PASS_THROUGH: u8 = 112;
const ERTS_DIST_HDR_LONG_ATOMS_FLG: u8 = 1;

/// `atom2cix`.
fn atom2cix(atom: Atom) -> usize {
    (atom.0 % ERTS_USE_ATOM_CACHE_SIZE) as usize
}

/// `ErtsAtomCache` (dist.h): the output half, `out_arr`, of a connection's atom cache.
#[derive(Clone, Debug)]
pub struct ErtsAtomCache {
    out_arr: Box<[Option<Atom>]>,
}

impl Default for ErtsAtomCache {
    fn default() -> Self {
        Self {
            out_arr: vec![None; ERTS_ATOM_CACHE_SIZE].into_boxed_slice(),
        }
    }
}

impl ErtsAtomCache {
    /// `out_arr[cix]`.
    pub fn out(&self, cix: usize) -> Option<Atom> {
        self.out_arr.get(cix).copied().flatten()
    }
}

/// `ErtsAtomCacheMap`: the atoms of one signal that go through the connection's atom cache,
/// collected by the size pass and turned into `ATOM_CACHE_REF`s by the encode pass. The size
/// pass inserts through a shared reference, so the fields are cells.
#[derive(Clone)]
pub struct ErtsAtomCacheMap {
    /// `cache[cix].iix`, -1 when unused.
    iix: Box<[Cell<i16>]>,
    /// `cache[cix].atom`.
    atom: Box<[Cell<u32>]>,
    /// `cix[iix]`.
    cix: [Cell<u16>; ERTS_MAX_INTERNAL_ATOM_CACHE_ENTRIES],
    /// `sz`.
    sz: Cell<usize>,
    /// `long_atoms`.
    long_atoms: Cell<bool>,
    /// `hdr_sz`: set by `erts_finalize_atom_cache_map`.
    hdr_sz: Cell<usize>,
}

impl Default for ErtsAtomCacheMap {
    /// `erts_init_atom_cache_map`.
    fn default() -> Self {
        Self {
            iix: (0..ERTS_ATOM_CACHE_SIZE).map(|_| Cell::new(-1)).collect(),
            atom: (0..ERTS_ATOM_CACHE_SIZE).map(|_| Cell::new(0)).collect(),
            cix: std::array::from_fn(|_| Cell::new(0)),
            sz: Cell::new(0),
            long_atoms: Cell::new(false),
            hdr_sz: Cell::new(0),
        }
    }
}

impl std::fmt::Debug for ErtsAtomCacheMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErtsAtomCacheMap")
            .field("sz", &self.sz.get())
            .finish()
    }
}

impl ErtsAtomCacheMap {
    /// `erts_reset_atom_cache_map`.
    pub fn reset(&self) {
        self.long_atoms.set(false);
        for i in 0..self.sz.get() {
            self.iix[self.cix[i].get() as usize].set(-1);
        }
        self.sz.set(0);
    }

    /// `insert_acache_map`.
    pub(crate) fn insert(&self, atom: Atom) {
        let sz = self.sz.get();
        if sz < ERTS_MAX_INTERNAL_ATOM_CACHE_ENTRIES {
            let ix = atom2cix(atom);
            if self.iix[ix].get() < 0 {
                self.iix[ix].set(sz as i16);
                self.cix[sz].set(ix as u16);
                self.sz.set(sz + 1);
                self.atom[ix].set(atom.0);
            }
        }
    }

    /// `get_iix_acache_map`.
    pub(crate) fn get_iix(&self, atom: Atom) -> Option<u8> {
        let ix = atom2cix(atom);
        let iix = self.iix[ix].get();
        (iix >= 0 && self.atom[ix].get() == atom.0).then_some(iix as u8)
    }

    /// `erts_finalize_atom_cache_map`: whether any atom needs a 2-byte length, and
    /// `hdr_sz`, the room the header needs when every atom is a new cache entry.
    fn finalize(&self) {
        let table = global_atoms();
        let sz = self.sz.get();
        let mut long_atoms = false;
        let mut hdr_sz = 0;
        // Make sure cache update instructions fit.
        let min_sz = (2 + 4) * sz;
        for i in 0..sz {
            let atom = Atom(self.atom[self.cix[i].get() as usize].get());
            let len = table.text(atom).map_or(0, str::len);
            if len > 255 {
                long_atoms = true;
            }
            // Enough for a new atom cache value.
            hdr_sz += 1 + 1 + len;
        }
        if long_atoms {
            // 2 bytes per atom for the length.
            hdr_sz += sz;
        }
        hdr_sz += erts_dist_hdr_atom_cache_flag_bytes(sz);
        self.long_atoms.set(long_atoms);
        self.hdr_sz.set(hdr_sz.max(min_sz));
    }
}

/// `ERTS_DIST_HDR_ATOM_CACHE_FLAG_BYTES`.
fn erts_dist_hdr_atom_cache_flag_bytes(no_atoms: usize) -> usize {
    no_atoms / 2 + 1
}

/// The encoder options of a dist encode: the mandatory OTP 29 dflags (`UTF8_ATOMS`,
/// `NEW_FLOATS`, `V4_NC`, ...) are those of `minor_version` 2.
fn dist_opts() -> EncodeOpts {
    EncodeOpts {
        minor: 2,
        dist: true,
        ..EncodeOpts::default()
    }
}

/// `ErtsExtSzRes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErtsExtSzRes {
    /// `ERTS_EXT_SZ_OK`.
    Ok,
    /// `ERTS_EXT_SZ_YIELD`.
    Yield,
    /// `ERTS_EXT_SZ_SYSTEM_LIMIT`.
    SystemLimit,
}

/// `TTBSizeContext` of a dist encode: what the size pass keeps across the terms of one
/// signal (`vlen`, `fragment_size`, `extra_size`) and the saved walk of the current term
/// (`wstack`, here the term's size context).
// Port of erts/emulator/beam/dist.h (TTBSizeContext, ERTS_INIT_TTBSizeContext), OTP-29.1.1.
struct TtbDistSizeContext {
    dflags: u64,
    fragment_size: usize,
    /// `last_result`, `extra_size` and `vlen`, which the walk updates for referenced binaries.
    iov: TtbIovSize,
    /// `wstack.wstart != NULL`: the walk of the term being sized.
    walk: Option<Box<TtbContext>>,
    /// Where the walk reads this node's name and creation (`erts_this_node`).
    node_source: fn() -> (Atom, u32),
}

impl TtbDistSizeContext {
    /// `ERTS_INIT_TTBSizeContext`.
    fn new(dflags: u64, node_source: fn() -> (Atom, u32)) -> Self {
        Self {
            dflags,
            fragment_size: usize::MAX,
            iov: TtbIovSize {
                last_result: 0,
                extra_size: 0,
                vlen: -1,
            },
            walk: None,
            node_source,
        }
    }
}

/// The I/O vector part of a dist `TTBSizeContext`: binaries the encode will reference
/// instead of copying count in `extra_size` (they are not in the signal's buffer) and in
/// `vlen`. `last_result` is the size where the previous referenced binary ended; here it is
/// relative to the walk of the current term.
// Port of erts/emulator/beam/dist.h (TTBSizeContext: last_result, extra_size, vlen),
// OTP-29.1.1.
pub(crate) struct TtbIovSize {
    pub(crate) last_result: usize,
    pub(crate) extra_size: usize,
    pub(crate) vlen: isize,
}

/// `erts_encode_dist_ext_size`: the budgeted size pass of one term of a signal, which also
/// enters the term's atoms in the atom cache map. `szp` accumulates the data size of the
/// signal's terms; on `Ok`, `fragmentsp` and `vlenp` give the fragments and I/O vector
/// length the signal needs.
// Port of erts/emulator/beam/external.c (erts_encode_dist_ext_size), OTP-29.1.1.
fn erts_encode_dist_ext_size(
    term: Term,
    acmp: Option<&ErtsAtomCacheMap>,
    ctx: &mut TtbDistSizeContext,
    szp: &mut usize,
    redsp: &mut i64,
    vlenp: &mut isize,
    fragmentsp: &mut usize,
) -> ErtsExtSzRes {
    let mut sz = *szp;
    if ctx.walk.is_none() {
        // First call for this term; `ctx` holds what the previous terms of the signal need.
        if ctx.iov.vlen < 0 {
            // First term as well.
            ctx.iov.vlen = 0;
            if ctx.dflags & DFLAG_FRAGMENTS != 0 {
                ctx.fragment_size = ERTS_DIST_FRAGMENT_SIZE;
            }
        }
        if ctx.dflags & (DFLAG_DIST_HDR_ATOM_CACHE | DFLAG_FRAGMENTS) == 0 {
            sz += 1; // VERSION_MAGIC
        }
        ctx.walk = Some(Box::new(TtbContext::start(term, dist_opts())));
        ctx.iov.last_result = 0;
    }
    let walk = ctx.walk.as_mut().expect("size walk started above");
    walk.set_local_node_source(ctx.node_source);
    // encode_size_struct_int handles at least one object per call (`--r <= 0`).
    let budget = (*redsp).max(1) as usize;
    let (done, consumed) = match walk.step_size_acmp(acmp, Some(&mut ctx.iov), budget) {
        Ok(step) => step,
        Err(_) => {
            ctx.walk = None;
            return ErtsExtSzRes::SystemLimit;
        }
    };
    *redsp -= consumed as i64;
    if !done {
        return ErtsExtSzRes::Yield;
    }
    let output = walk.output_size().expect("size pass done");
    // The bytes after the last referenced binary are one more element of the I/O vector.
    // Port of erts/emulator/beam/external.c (encode_size_struct_int, the end of the walk:
    // `vlen += csz/MAX_SYSIOVEC_IOVLEN + 1`), OTP-29.1.1.
    let csz = output - ctx.iov.last_result;
    if csz != 0 {
        ctx.iov.vlen += (csz / crate::MAX_SYSIOVEC_IOVLEN + 1) as isize;
    }
    // The walk counts the VERSION_MAGIC of a term_to_binary; the dist encode counted its own.
    sz += output - 1;
    ctx.walk = None;
    // Each fragment uses one element for the driver header, one for the fragment header
    // and (at least) one for data.
    let total_size = sz + ctx.iov.extra_size;
    let fragments = (total_size.max(1) - 1) / ctx.fragment_size + 1;
    *szp = sz;
    *fragmentsp = fragments;
    *vlenp = ctx.iov.vlen + 3 * fragments as isize;
    ErtsExtSzRes::Ok
}

/// Byte sizes of the records `alloc_dist_obufs` places in front of the data of a signal's
/// driver Binary (64-bit layout of the C structs).
// Port of erts/emulator/beam/erl_node_tables.h (ErtsDistOutputBuf), erl_driver.h (SysIOVec,
// ErlIOVec, ErlDrvBinary *), OTP-29.1.1.
const OBUF_SZ: usize = 8; // ErtsDistOutputBuf: eiov (`next`/`bin` are the queue and the handle)
use raw::{BINV_SZ, SYSIOVEC_SZ};
const ERLIOVEC_PTR_SZ: usize = 8; // ErlIOVec *
const ERLIOVEC_SZ: usize = 32; // ErlIOVec: vsize, size, iov, binv

/// `erts_ttb_iov_size(0, vlen, fragments)`.
// Port of erts/emulator/beam/external.c (erts_ttb_iov_size), OTP-29.1.1.
fn erts_ttb_iov_size(vlen: usize, fragments: usize) -> usize {
    debug_assert!(vlen > 0 && fragments > 0);
    SYSIOVEC_SZ * vlen + BINV_SZ * vlen + ERLIOVEC_PTR_SZ * fragments + ERLIOVEC_SZ * fragments
}

/// Field offsets inside an `ErlIOVec` record.
const EIOV_VSIZE: usize = 0;
const EIOV_SIZE: usize = 8;
const EIOV_IOV: usize = 16;
const EIOV_BINV: usize = 24;

/// `TTBEncodeContext` of a dist encode. The I/O vector (`iov`, `binv`) and the fragments'
/// `ErlIOVec`s are records in the signal's driver Binary in front of the data
/// (`erts_ttb_iov_init` on the memory `alloc_dist_obufs` allocated); the context keeps
/// their offsets and the address of the data.
// Port of erts/emulator/beam/dist.h (TTBEncodeContext, ERTS_INIT_TTBEncodeContext,
// erts_ttb_iov_init), OTP-29.1.1.
pub(crate) struct TtbDistEncodeContext {
    /// `wstack.wstart != NULL`: the walk of the term being encoded.
    walk: Option<Box<TtbContext>>,
    /// `cptr`: the start of the bytes not yet stored in the I/O vector (a data offset).
    cptr: usize,
    /// `vlen`: I/O vector elements used so far.
    vlen: usize,
    /// `frag_ix`, -1 before the first fragment.
    frag_ix: isize,
    fragment_size: usize,
    /// `debug_vlen`: the elements the arrays have room for (the size pass's `vlen`).
    debug_vlen: usize,
    /// `ctx->iov`, `ctx->binv`, `ctx->fragment_eiovs`: payload offsets of the arrays.
    iov: usize,
    binv: usize,
    fragment_eiovs: usize,
    /// The address of the first data byte (data offsets are relative to it).
    data_base: usize,
    /// `payload_ixp` of a pending-connection encode.
    payload_ixp: Option<usize>,
    node_source: fn() -> (Atom, u32),
}

/// The I/O vector records of a dist encode as the encoder reaches them: the context and the
/// part of the Binary in front of the data (`meta`).
pub(crate) struct DistIovSink<'a> {
    pub(crate) ctx: &'a mut TtbDistEncodeContext,
    pub(crate) meta: raw::ObufMeta<'a>,
}

impl DistIovSink<'_> {
    /// `store_in_vec` at the encoder's position `ep`.
    pub(crate) fn store_in_vec(
        &mut self,
        ep: usize,
        refc_binary: Option<(arinsal_alloc::raw::OwnedBinaryRef, usize, usize)>,
    ) {
        self.ctx.store_in_vec(&mut self.meta, ep, refc_binary);
    }
}

impl TtbDistEncodeContext {
    /// `ERTS_INIT_TTBEncodeContext` + `erts_ttb_iov_init` at payload offset `ptr`.
    fn new(
        ptr: usize,
        vlen: usize,
        fragment_size: usize,
        data_base: usize,
        node_source: fn() -> (Atom, u32),
    ) -> Self {
        let iov = ptr;
        let binv = iov + SYSIOVEC_SZ * vlen;
        // `sizeof(ErlIOVec *) * fragments` of erts_ttb_iov_size stays unused here, as in erts.
        let fragment_eiovs = binv + BINV_SZ * vlen;
        Self {
            node_source,
            walk: None,
            cptr: 0,
            vlen: 0,
            frag_ix: -1,
            fragment_size,
            debug_vlen: vlen,
            iov,
            binv,
            fragment_eiovs,
            data_base,
            payload_ixp: None,
        }
    }

    /// `store_in_vec`: the bytes of the signal's buffer from `cptr` up to `ep`, then the
    /// referenced binary `refc_binary` (`len` bytes at `offset`), go into the fragments' I/O
    /// vectors.
    // Port of erts/emulator/beam/external.c (store_in_vec), OTP-29.1.1.
    fn store_in_vec(
        &mut self,
        meta: &mut raw::ObufMeta<'_>,
        ep: usize,
        refc_binary: Option<(arinsal_alloc::raw::OwnedBinaryRef, usize, usize)>,
    ) {
        let cp = self.cptr;
        if cp != ep {
            // Save data in the common binary.
            self.store_in_vec_aux(meta, None, self.data_base + cp, ep - cp);
            self.cptr = ep;
        }
        if let Some((bin, offset, len)) = refc_binary {
            // Save the off-heap binary.
            let base = bin.payload_ptr() as usize + offset;
            self.store_in_vec_aux(meta, Some(&bin), base, len);
        }
    }

    /// `store_in_vec_aux`: `len` bytes at address `ptr` of `bin` (`None`: the signal's
    /// buffer) go into the current fragment, a new fragment starting whenever one reaches
    /// `fragment_size`; each element is at most `MAX_SYSIOVEC_IOVLEN` long and holds its own
    /// reference to its binary (`erts_refc_inc`). The references to the signal's own buffer
    /// are taken in `FIN`, when the buffer is complete (their `binv` slot is null until
    /// then).
    // Port of erts/emulator/beam/external.c (store_in_vec_aux), OTP-29.1.1.
    fn store_in_vec_aux(
        &mut self,
        meta: &mut raw::ObufMeta<'_>,
        bin: Option<&arinsal_alloc::raw::OwnedBinaryRef>,
        mut ptr: usize,
        mut len: usize,
    ) {
        let mut iov_len;
        if self.frag_ix >= 0 {
            let feiovp = self.fragment_eiovs + ERLIOVEC_SZ * self.frag_ix as usize;
            let size = meta.word(feiovp + EIOV_SIZE);
            debug_assert!(0 < size && size <= self.fragment_size);
            if size != self.fragment_size {
                // Current fragment not full yet.
                iov_len = (self.fragment_size - size).min(len);
                self.store_iov_data(meta, bin, &mut ptr, &mut len, iov_len);
            }
        }
        while len != 0 {
            // Start a new fragment.
            self.frag_ix += 1;
            let feiovp = self.fragment_eiovs + ERLIOVEC_SZ * self.frag_ix as usize;
            meta.set_word(feiovp + EIOV_VSIZE, 2);
            meta.set_word(feiovp + EIOV_SIZE, 0);
            meta.set_word(feiovp + EIOV_IOV, self.iov + SYSIOVEC_SZ * self.vlen);
            meta.set_word(feiovp + EIOV_BINV, self.binv + BINV_SZ * self.vlen);
            // Entries for the driver header and the dist header.
            for _ in 0..2 {
                debug_assert!(self.vlen < self.debug_vlen);
                meta.set_own(self.vlen, 0, 0);
                self.vlen += 1;
            }
            iov_len = len.min(self.fragment_size);
            self.store_iov_data(meta, bin, &mut ptr, &mut len, iov_len);
        }
    }

    fn store_iov_data(
        &mut self,
        meta: &mut raw::ObufMeta<'_>,
        bin: Option<&arinsal_alloc::raw::OwnedBinaryRef>,
        ptr: &mut usize,
        len: &mut usize,
        mut iov_len: usize,
    ) {
        let feiovp = self.fragment_eiovs + ERLIOVEC_SZ * self.frag_ix as usize;
        loop {
            let iov_len_left = iov_len.saturating_sub(crate::MAX_SYSIOVEC_IOVLEN);
            iov_len -= iov_len_left;
            debug_assert!(self.vlen < self.debug_vlen);
            match bin {
                None => meta.set_own(self.vlen, *ptr, iov_len),
                // The slot keeps the count (released by free_dist_obuf).
                Some(bin) => {
                    meta.set_ref(self.vlen, bin, *ptr - bin.payload_ptr() as usize, iov_len)
                }
            }
            let vsize = meta.word(feiovp + EIOV_VSIZE);
            meta.set_word(feiovp + EIOV_VSIZE, vsize + 1);
            let size = meta.word(feiovp + EIOV_SIZE);
            meta.set_word(feiovp + EIOV_SIZE, size + iov_len);
            self.vlen += 1;
            *ptr += iov_len;
            *len -= iov_len;
            iov_len = iov_len_left;
            if iov_len == 0 {
                break;
            }
        }
    }
}

/// `erts_encode_dist_ext`: the budgeted encode of one term of a signal into `buf` at
/// `*ext`, stored in the fragments' I/O vectors when done. Returns whether the term is
/// done; `fragmentsp` gets the fragments used so far.
// Port of erts/emulator/beam/external.c (erts_encode_dist_ext), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn erts_encode_dist_ext(
    term: Term,
    meta: &mut raw::ObufMeta<'_>,
    buf: &mut [u8],
    ext: &mut usize,
    flags: u64,
    acmp: Option<&ErtsAtomCacheMap>,
    ctx: &mut TtbDistEncodeContext,
    fragmentsp: &mut usize,
    reds: &mut i64,
) -> Result<bool, EncodeError> {
    if ctx.walk.is_none() {
        ctx.cptr = *ext;
        if flags & (DFLAG_DIST_HDR_ATOM_CACHE | DFLAG_PENDING_CONNECT | DFLAG_FRAGMENTS) == 0 {
            buf[*ext] = VERSION_MAGIC;
            *ext += 1;
        }
        if flags & DFLAG_PENDING_CONNECT != 0 {
            let payload_ix = ctx.vlen;
            if payload_ix != 0 {
                // We potentially need a version magic on the payload: the byte stays out of
                // the I/O vector until transcode_dist_obuf prepends it.
                *ext += 1;
                ctx.cptr = *ext;
                let at = ctx.payload_ixp.expect("pending header set up");
                buf[at..at + 4].copy_from_slice(&(payload_ix as u32).to_be_bytes());
            }
        }
        let mut walk = Box::new(TtbContext::start(term, dist_opts()));
        // The size pass ran in erts_encode_dist_ext_size.
        walk.size.done = true;
        // `use_iov = !!ctx->iov`: a dist encode has an I/O vector, so a large byte-aligned
        // binary is not a budgeted ENC_BIN_COPY (`copy_payload == 0`). erts references the
        // binary in the I/O vector; here its bytes go into the buffer at once.
        walk.iovec = true;
        ctx.walk = Some(walk);
    }
    let mut walk = ctx.walk.take().expect("encode walk started above");
    walk.set_local_node_source(ctx.node_source);
    let budget = (*reds).max(1) as usize;
    let mut out = crate::OutputSlice::new(buf, *ext);
    out.iov = Some(DistIovSink {
        ctx: &mut *ctx,
        meta: meta.reborrow(),
    });
    let (done, consumed) = crate::enc_term_int(&mut walk, acmp, budget, &mut out, 0)?;
    if out.failed() {
        return Err(EncodeError::SystemLimit);
    }
    *ext = out.len();
    *reds -= consumed as i64;
    if done {
        ctx.store_in_vec(meta, *ext, None);
    } else {
        ctx.walk = Some(walk);
    }
    *fragmentsp = if done {
        (ctx.frag_ix + 1) as usize
    } else {
        ctx.frag_ix.max(0) as usize
    };
    Ok(done)
}

/// `erts_encode_ext_dist_header_size`.
// Port of erts/emulator/beam/external.c (erts_encode_ext_dist_header_size), OTP-29.1.1.
fn erts_encode_ext_dist_header_size(
    dflags: u64,
    acmp: Option<&ErtsAtomCacheMap>,
    fragments: usize,
) -> usize {
    if dflags & DFLAG_PENDING_CONNECT != 0 {
        // HOPEFUL_DATA + hopeful flags + hopeful ix + payload ix.
        HOPEFUL_HDR_SZ
    } else if acmp.is_none() && dflags & DFLAG_FRAGMENTS == 0 {
        1 // PASS_THROUGH
    } else {
        // VERSION_MAGIC, DIST_HEADER, dist header flags, number of internal cache entries.
        let mut fix_sz = 1 + 1 + 1 + 1;
        if fragments > 1 {
            fix_sz += 8 + 8; // sequence id, number of fragments
        }
        if let Some(acmp) = acmp {
            fix_sz += acmp.hdr_sz.get();
        }
        fix_sz
    }
}

/// `erts_encode_ext_dist_header_setup`: the internal dist header, written backwards just
/// before the control message at `ctl_ext`; returns where it starts. With an atom cache the
/// cache update instructions are internal (`cix`, atom index) and are rewritten for the wire
/// by [`erts_encode_ext_dist_header_finalize`] against the connection's cache.
// Port of erts/emulator/beam/external.c (erts_encode_ext_dist_header_setup), OTP-29.1.1.
fn erts_encode_ext_dist_header_setup(
    dflags: u64,
    buf: &mut [u8],
    ctl_ext: usize,
    acmp: Option<&ErtsAtomCacheMap>,
    fragments: usize,
    from: u64,
    ec: &mut TtbDistEncodeContext,
) -> usize {
    let mut ep = ctl_ext;
    if dflags & DFLAG_PENDING_CONNECT != 0 {
        ep -= 4;
        ec.payload_ixp = Some(ep);
        buf[ep..ep + 4].copy_from_slice(&0u32.to_be_bytes());
        ep -= 4;
        buf[ep..ep + 4].copy_from_slice(&ERTS_NO_HIX.to_be_bytes());
        ep -= 8;
        // The hopeful flags: no hopeful encodings are recorded.
        buf[ep..ep + 8].copy_from_slice(&0u64.to_be_bytes());
        ep -= 1;
        buf[ep] = HOPEFUL_DATA;
        return ep;
    }
    if acmp.is_none() && dflags & DFLAG_FRAGMENTS == 0 {
        ep -= 1;
        buf[ep] = PASS_THROUGH;
        return ep;
    }
    let dist_hdr_flags = if acmp.is_some_and(|acmp| acmp.long_atoms.get()) {
        ERTS_DIST_HDR_LONG_ATOMS_FLG
    } else {
        0
    };
    match acmp {
        Some(acmp) => {
            for i in (0..acmp.sz.get()).rev() {
                let cix = acmp.cix[i].get();
                let aval = acmp.atom[cix as usize].get();
                ep -= 4;
                buf[ep..ep + 4].copy_from_slice(&aval.to_be_bytes());
                ep -= 2;
                buf[ep..ep + 2].copy_from_slice(&cix.to_be_bytes());
            }
            ep -= 1;
            buf[ep] = acmp.sz.get() as u8;
        }
        None => {
            // A dist header without an atom cache: 0 in the atom cache size slot.
            ep -= 1;
            buf[ep] = 0;
        }
    }
    ep -= 1;
    buf[ep] = dist_hdr_flags;
    if fragments > 1 {
        ep -= 8;
        buf[ep..ep + 8].copy_from_slice(&(fragments as u64).to_be_bytes());
        ep -= 8;
        buf[ep..ep + 8].copy_from_slice(&from.to_be_bytes());
        ep -= 1;
        buf[ep] = DIST_FRAG_HEADER;
    } else {
        ep -= 1;
        buf[ep] = DIST_HEADER;
    }
    ep -= 1;
    buf[ep] = VERSION_MAGIC;
    ep
}

/// `erts_encode_ext_dist_header_fragment`: the header of a continuation fragment at `*hdrp`.
// Port of erts/emulator/beam/external.c (erts_encode_ext_dist_header_fragment), OTP-29.1.1.
fn erts_encode_ext_dist_header_fragment(
    buf: &mut [u8],
    hdrp: &mut usize,
    fragment: u64,
    from: u64,
) -> usize {
    let start = *hdrp;
    buf[start] = VERSION_MAGIC;
    buf[start + 1] = DIST_FRAG_CONT;
    buf[start + 2..start + 10].copy_from_slice(&from.to_be_bytes());
    buf[start + 10..start + 18].copy_from_slice(&fragment.to_be_bytes());
    *hdrp = start + ERTS_DIST_FRAGMENT_HEADER_SIZE;
    start
}

/// `ERTS_DIST_FRAGMENT_HEADER_SIZE`: magic, header, sequence id, fragment id.
const ERTS_DIST_FRAGMENT_HEADER_SIZE: usize = 1 + 1 + 8 + 8;

/// `HOPEFUL_DATA` (external.h): the first byte of a signal encoded toward a pending connection.
const HOPEFUL_DATA: u8 = b'H';
/// `ERTS_NO_HIX` (external.h).
const ERTS_NO_HIX: u32 = u32::MAX;
/// `1 + 8 + 4 + 4`: HOPEFUL_DATA, hopeful flags, hopeful ix, payload ix
/// (erts_encode_ext_dist_header_size with `DFLAG_PENDING_CONNECT`).
const HOPEFUL_HDR_SZ: usize = 1 + 8 + 4 + 4;

/// `DFLAG_PENDING_CONNECT` (dist.h): internal flag of a signal encoded before the connection is
/// set up.
pub const DFLAG_PENDING_CONNECT: u64 = 0x20_0000;
const DFLAG_DIST_MONITOR: u64 = 0x08;
const DFLAG_DIST_MONITOR_NAME: u64 = 0x20;
const DFLAG_SEND_SENDER: u64 = 0x8_0000;
const DFLAG_EXIT_PAYLOAD: u64 = 0x40_0000;
const DFLAG_SPAWN: u64 = 1 << 32;
const DFLAG_ALIAS: u64 = 0x8 << 32;
const DFLAG_ALTACT_SIG: u64 = 0x20 << 32;
const DFLAG_NATIVE_RECORDS: u64 = 0x40 << 32;
/// `DFLAG_DIST_HOPEFULLY` (dist.h): the optimistic flags a signal toward a pending connection
/// is encoded with; `transcode_dist_obuf` repairs the signal when the peer lacks them.
pub const DFLAG_DIST_HOPEFULLY: u64 = DFLAG_DIST_MONITOR
    | DFLAG_DIST_MONITOR_NAME
    | DFLAG_SPAWN
    | DFLAG_ALTACT_SIG
    | DFLAG_ALIAS
    | DFLAG_NATIVE_RECORDS;

const SMALL_INTEGER_EXT: u8 = 97;
const SMALL_TUPLE_EXT: u8 = 104;
const LARGE_TUPLE_EXT: u8 = 105;
const NEW_PID_EXT: u8 = 88;
const ATOM_UTF8_EXT: u8 = 118;
const SMALL_ATOM_UTF8_EXT: u8 = 119;

const DOP_SEND: u8 = 2;
const DOP_REG_SEND: u8 = 6;
const DOP_EXIT2: u8 = 8;
const DOP_SEND_TT: u8 = 12;
const DOP_REG_SEND_TT: u8 = 16;
const DOP_EXIT2_TT: u8 = 18;
const DOP_MONITOR_P: u8 = 19;
const DOP_DEMONITOR_P: u8 = 20;
const DOP_MONITOR_P_EXIT: u8 = 21;
const DOP_SEND_SENDER: u8 = 22;
const DOP_SEND_SENDER_TT: u8 = 23;
const DOP_PAYLOAD_EXIT2: u8 = 26;
const DOP_PAYLOAD_EXIT2_TT: u8 = 27;
const DOP_SPAWN_REQUEST: u8 = 29;
const DOP_SPAWN_REQUEST_TT: u8 = 30;
const DOP_ALIAS_SEND: u8 = 33;
const DOP_ALIAS_SEND_TT: u8 = 34;
const DOP_ALTACT_SIG_SEND: u8 = 37;

const ERTS_DOP_ALTACT_SIG_FLG_TOKEN: u8 = 1 << 1;
const ERTS_DOP_ALTACT_SIG_FLG_ALIAS: u8 = 1 << 2;
const ERTS_DOP_ALTACT_SIG_FLG_NAME: u8 = 1 << 3;
const ERTS_DOP_ALTACT_SIG_FLG_EXIT: u8 = 1 << 4;

/// One element of an output buffer's I/O vector taken out of it, `iov[i]` with its
/// `binv[i]`: `range` of the payload of a Binary this element holds one reference to (the
/// signal's own buffer or a refc binary of the encoded term).
// Port of erts/emulator/beam/erl_driver.h (ErlIOVec iov/binv), OTP-29.1.1.
pub struct DistIov {
    bin: arinsal_alloc::raw::OwnedBinaryRef,
    range: std::ops::Range<usize>,
}

impl DistIov {
    /// The bytes of the element.
    pub fn bytes(&self) -> &[u8] {
        self.bin
            .payload(self.range.start, self.range.len())
            .expect("an I/O vector element lies inside its Binary")
    }

    /// The Binary reference, the offset and the length of the element.
    pub fn into_parts(self) -> (arinsal_alloc::raw::OwnedBinaryRef, usize, usize) {
        (self.bin, self.range.start, self.range.len())
    }
}

impl std::fmt::Debug for DistIov {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DistIov").field(&self.range).finish()
    }
}

/// `ErtsDistOutputBuf`: one fragment of an encoded signal in a distribution output queue.
/// The buffer record, its `ErlIOVec` and the `iov`/`binv` arrays are in the signal's driver
/// Binary (`alloc_dist_obufs`), which every fragment holds one reference to (`obuf->bin`);
/// this handle is that reference and the record's offset. `eiov->iov[0]` is reserved for the
/// driver, `iov[1]` is the dist header and `iov[2..vsize]` the data; every element with a
/// `binv` slot holds a reference to its Binary.
// Port of erts/emulator/beam/erl_node_tables.h (ErtsDistOutputBuf), OTP-29.1.1.
pub struct ErtsDistOutputBuf {
    bin: raw::ObufBin,
    obuf: usize,
}

impl std::fmt::Debug for ErtsDistOutputBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErtsDistOutputBuf")
            .field("size", &self.size())
            .finish()
    }
}

impl ErtsDistOutputBuf {
    fn record(&self, at: usize) -> usize {
        self.bin.word(at)
    }

    fn set_record(&mut self, at: usize, value: usize) {
        self.bin.set_word(at, value);
    }

    /// `obuf->eiov`: the payload offset of the buffer's `ErlIOVec`.
    fn eiov(&self) -> usize {
        self.record(self.obuf)
    }

    fn vsize(&self) -> usize {
        self.record(self.eiov() + EIOV_VSIZE)
    }

    /// The index in the signal's `iov`/`binv` arrays of `eiov->iov[ix]`.
    fn slot(&self, ix: usize) -> usize {
        (self.record(self.eiov() + EIOV_IOV) - self.bin.iov_offset()) / SYSIOVEC_SZ + ix
    }

    /// The bytes of `eiov->iov[ix]`.
    fn iov(&self, ix: usize) -> &[u8] {
        self.bin.iov_bytes(self.slot(ix))
    }

    /// `eiov->iov[ix]` with the reference `binv[ix]` holds, taken out of the slot.
    fn take_binv(
        &mut self,
        ix: usize,
    ) -> Option<(arinsal_alloc::raw::OwnedBinaryRef, usize, usize)> {
        let slot = self.slot(ix);
        self.bin.take_ref(slot)
    }

    /// The signal dropped by `transcode_dist_obuf`: the `binv` references of `iov[1..]`
    /// released, the buffer a tick (`vsize = 1`, `size = 0`).
    fn free_to_tick(&mut self) {
        for ix in 1..self.vsize() {
            drop(self.take_binv(ix));
        }
        let eiov = self.eiov();
        self.set_record(eiov + EIOV_VSIZE, 1);
        self.set_record(eiov + EIOV_SIZE, 0);
    }

    /// `size_obuf`: the bytes this buffer puts on the wire (`eiov->size`).
    pub fn size(&self) -> usize {
        self.record(self.eiov() + EIOV_SIZE)
    }

    /// The I/O vector the buffer is output as (`eiov->iov[1..vsize]`): the header, then the
    /// data. An empty vector is a tick (a signal transcoded away).
    pub fn iovec(&self) -> Vec<&[u8]> {
        (1..self.vsize())
            .map(|ix| self.iov(ix))
            .filter(|part| !part.is_empty())
            .collect()
    }

    /// The I/O vector for output, `eiov->iov[1..vsize]` with the references of `binv`
    /// handed over to the elements (dist_port_commandv / dist_ctrl_get_data, then
    /// `free_dist_obuf(obuf, 0)`). An empty vector is a tick.
    pub fn into_iov(mut self) -> Vec<DistIov> {
        let mut iov = Vec::with_capacity(self.vsize());
        for ix in 1..self.vsize() {
            if let Some((bin, start, len)) = self.take_binv(ix)
                && len != 0
            {
                iov.push(DistIov {
                    bin,
                    range: start..start + len,
                });
            }
        }
        iov
    }

    /// The bytes of [`Self::iovec`] in one buffer.
    pub fn to_vec(&self) -> Vec<u8> {
        self.iovec().concat()
    }

    /// The data elements (`iov[2..vsize]`): the Binary each references (header address),
    /// the payload offset in it and the length.
    #[cfg(test)]
    fn data_elements(&self) -> Vec<(usize, std::ops::Range<usize>)> {
        (2..self.vsize())
            .map(|ix| self.bin.slot_parts(self.slot(ix)))
            .collect()
    }
}

impl Drop for ErtsDistOutputBuf {
    /// `free_dist_obuf(obuf, !0)`: the `binv` references, then `erts_bin_release(obuf->bin)`.
    // Port of erts/emulator/beam/dist.c (free_dist_obuf), OTP-29.1.1.
    fn drop(&mut self) {
        for ix in 0..self.vsize() {
            drop(self.take_binv(ix));
        }
    }
}

/// What `erts_encode_ext_dist_header_finalize` left for its caller.
#[derive(Debug, Eq, PartialEq)]
pub enum DistHeaderFinalize {
    /// The buffer is ready for output; an empty buffer is a tick.
    Done,
    /// A `DOP_SPAWN_REQUEST[_TT]` toward a peer without `DFLAG_SPAWN` was turned into a tick;
    /// the caller decodes this control message (`transcode_decode_ctl_msg`) and answers the
    /// spawning process with `notsup` (`erts_proc_sig_send_dist_spawn_reply`).
    SpawnNotSupported(Vec<u8>),
}

/// Finalize an output buffer for the connection when it is taken for output: a signal
/// encoded toward a pending connection is transcoded for the connection's `dflags`; the
/// internal atom cache instructions of a dist header are rewritten in place as the wire
/// header (`iov[1]` grows backwards into the room the encode reserved), updating the
/// connection's output atom `cache`. `reds` is decremented by the reductions used.
// Port of erts/emulator/beam/external.c (erts_encode_ext_dist_header_finalize), OTP-29.1.1.
pub fn erts_encode_ext_dist_header_finalize(
    ob: &mut ErtsDistOutputBuf,
    cache: &mut ErtsAtomCache,
    dflags: u64,
    reds: &mut i64,
) -> DistHeaderFinalize {
    let ep = ob.iov(1);
    let hdr_len = ep.len();
    let hdr_base = ep.as_ptr() as usize;
    if ep.is_empty() {
        return DistHeaderFinalize::Done;
    }
    if ep[0] == HOPEFUL_DATA {
        return transcode_dist_obuf(ob, dflags, reds);
    }
    if ep[0] == PASS_THROUGH {
        debug_assert_eq!(hdr_len, 1);
        return DistHeaderFinalize::Done;
    }
    if ep[1] == DIST_FRAG_CONT {
        debug_assert_eq!(ep[0], VERSION_MAGIC);
        debug_assert_eq!(hdr_len, ERTS_DIST_FRAGMENT_HEADER_SIZE);
        return DistHeaderFinalize::Done;
    }
    let mut ip = 2;
    let mut frag = None;
    if ep[1] == DIST_FRAG_HEADER {
        // Skip the seq id and frag id.
        frag = Some((get_int64(&ep[2..10]), get_int64(&ep[10..18])));
        ip += 16;
    }
    let dist_hdr_flags = ep[ip];
    let long_atoms = dist_hdr_flags & ERTS_DIST_HDR_LONG_ATOMS_FLG != 0;
    let ci = ep[ip + 1] as usize;
    ip += 2;
    // `instr_buf`: the cache update instructions, copied before the header is rewritten
    // over them.
    let mut instr_buf = [0u8; (2 + 4) * ERTS_MAX_INTERNAL_ATOM_CACHE_ENTRIES];
    let sz = (2 + 4) * ci;
    instr_buf[..sz].copy_from_slice(&ep[ip..ip + sz]);
    debug_assert_eq!(ip + sz, hdr_len);
    // The header is written backwards, ending where the internal header ends: the encode
    // reserved `erts_encode_ext_dist_header_size` bytes (every atom a new entry) in front.
    let end = ob.bin.data_offset(hdr_base) + hdr_len;
    let mut wire_len = 1 + 1 + 1 + if frag.is_some() { 16 } else { 0 };
    let table = global_atoms();
    if ci > 0 {
        wire_len += erts_dist_hdr_atom_cache_flag_bytes(ci);
        for iix in 0..ci {
            let instr = &instr_buf[6 * iix..6 * iix + 6];
            let cix = u16::from_be_bytes([instr[0], instr[1]]) as usize;
            let atom = Atom(u32::from_be_bytes([instr[2], instr[3], instr[4], instr[5]]));
            wire_len += 1;
            if cache.out_arr[cix] != Some(atom) {
                let len = table.text(atom).map_or(0, str::len);
                wire_len += if long_atoms { 2 } else { 1 } + len;
            }
        }
    }
    let start = end - wire_len;
    let wire = ob.bin.bytes_mut(start, wire_len);
    let mut ep = wire_len;
    if ci > 0 {
        let flgs_bytes = erts_dist_hdr_atom_cache_flag_bytes(ci);
        let mut flags = vec![0u8; flgs_bytes];
        for iix in (0..ci).rev() {
            let instr = &instr_buf[6 * iix..6 * iix + 6];
            let cix = u16::from_be_bytes([instr[0], instr[1]]) as usize;
            let atom = Atom(u32::from_be_bytes([instr[2], instr[3], instr[4], instr[5]]));
            let new = cache.out_arr[cix] != Some(atom);
            if new {
                cache.out_arr[cix] = Some(atom);
                let name = table.text(atom).unwrap_or_default();
                ep -= name.len();
                wire[ep..ep + name.len()].copy_from_slice(name.as_bytes());
                if long_atoms {
                    ep -= 2;
                    wire[ep..ep + 2].copy_from_slice(&(name.len() as u16).to_be_bytes());
                } else {
                    ep -= 1;
                    wire[ep] = name.len() as u8;
                }
            }
            ep -= 1;
            wire[ep] = cix as u8;
            let nibble = (u8::from(new) << 3) | ((cix >> 8) as u8 & 7);
            flags[iix / 2] |= nibble << ((iix % 2) * 4);
        }
        flags[ci / 2] |= dist_hdr_flags << ((ci % 2) * 4);
        ep -= flgs_bytes;
        wire[ep..ep + flgs_bytes].copy_from_slice(&flags);
        // Was ERTS_PORT_REDS_DIST_CMD_FINALIZE.
        *reds -= 3;
    }
    ep -= 1;
    wire[ep] = ci as u8;
    match frag {
        Some((seq_id, frag_id)) => {
            ep -= 8;
            wire[ep..ep + 8].copy_from_slice(&frag_id.to_be_bytes());
            ep -= 8;
            wire[ep..ep + 8].copy_from_slice(&seq_id.to_be_bytes());
            ep -= 1;
            wire[ep] = DIST_FRAG_HEADER;
        }
        None => {
            ep -= 1;
            wire[ep] = DIST_HEADER;
        }
    }
    ep -= 1;
    wire[ep] = VERSION_MAGIC;
    debug_assert_eq!(ep, 0);
    let eiov = ob.eiov();
    let size = ob.size();
    ob.set_record(eiov + EIOV_SIZE, size - hdr_len + wire_len);
    let slot = ob.slot(1);
    ob.bin.set_own(slot, start, wire_len);
    *reds = (*reds).max(0);
    DistHeaderFinalize::Done
}

fn get_int64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("8 bytes"))
}

/// `ERTS_TRANSCODE_REDS_FACT` (external.c).
const ERTS_TRANSCODE_REDS_FACT: i64 = 4;

/// Rewrite, in place, a signal encoded toward a pending connection for the flags the
/// connection got: drop what the peer cannot take (the buffer becomes a tick), rewrite
/// `DOP_ALTACT_SIG_SEND` as the plain operation inside `iov[2]`, prepend the version magic
/// on the payload (`iov[payload_ix]`) and replace the hopeful header in `iov[1]` by the real
/// one. `reds` is decremented by the reductions used.
// Port of erts/emulator/beam/external.c (transcode_dist_obuf), OTP-29.1.1.
fn transcode_dist_obuf(
    ob: &mut ErtsDistOutputBuf,
    dflags: u64,
    reds: &mut i64,
) -> DistHeaderFinalize {
    if *reds < 0 {
        return DistHeaderFinalize::Done;
    }
    // HOPEFUL_DATA header always present in io vector element 1:
    // 'H', hopeful flags (8), hopeful ix (4), payload ix (4).
    let hdr = ob.iov(1);
    debug_assert_eq!(hdr[0], HOPEFUL_DATA);
    debug_assert_eq!(hdr.len(), HOPEFUL_HDR_SZ);
    // Currently, the hopeful flags and IX are not used.
    let payload_ix = u32::from_be_bytes(hdr[13..17].try_into().expect("4 bytes")) as usize;
    // Control message always begins in vector element 2.
    let ep = ob.iov(2);
    let b = |i: usize| ep.get(i).copied().unwrap_or(0);
    debug_assert!(b(0) == SMALL_TUPLE_EXT || b(0) == LARGE_TUPLE_EXT);
    let op = (b(0) == SMALL_TUPLE_EXT && b(2) == SMALL_INTEGER_EXT).then(|| (b(1), b(3)));
    let drop_monitor = !dflags & (DFLAG_DIST_MONITOR | DFLAG_DIST_MONITOR_NAME) != 0
        && matches!(
            op,
            Some((4, DOP_MONITOR_P | DOP_MONITOR_P_EXIT | DOP_DEMONITOR_P))
        );
    let drop_alias = dflags & DFLAG_ALIAS == 0
        && matches!(op, Some((3 | 4, DOP_ALIAS_SEND | DOP_ALIAS_SEND_TT)));
    if drop_monitor || drop_alias {
        // Drop the packet by converting it to an empty (tick) packet.
        ob.free_to_tick();
        return DistHeaderFinalize::Done;
    }
    if dflags & DFLAG_SPAWN == 0
        && matches!(
            op,
            Some((6, DOP_SPAWN_REQUEST)) | Some((8, DOP_SPAWN_REQUEST_TT))
        )
    {
        // The receiver does not support distributed spawn: a tick, and the spawning process
        // is told `notsup` by the caller, which decodes the control message
        // (transcode_decode_ctl_msg: iov[2..payload_ix]).
        debug_assert!(payload_ix >= 3);
        let ctl: Vec<u8> = (2..payload_ix).flat_map(|ix| ob.iov(ix).to_vec()).collect();
        ob.free_to_tick();
        *reds = (*reds - 4).max(0);
        return DistHeaderFinalize::SpawnNotSupported(ctl);
    }
    let mut payload_moved_to_control = false;
    if dflags & DFLAG_ALTACT_SIG == 0
        && let Some((tuple_size @ (4 | 5), DOP_ALTACT_SIG_SEND)) = op
    {
        let mut tuple_size = tuple_size;
        // The flags were encoded as a SMALL_INTEGER_EXT.
        assert_eq!(b(4), SMALL_INTEGER_EXT, "Invalid altact msg flags");
        let flags = b(5);
        let token = flags & ERTS_DOP_ALTACT_SIG_FLG_TOKEN != 0;
        let pick = |tt: u8, plain: u8| if token { tt } else { plain };
        let dist_op = if flags & ERTS_DOP_ALTACT_SIG_FLG_EXIT != 0 {
            if flags & ERTS_DOP_ALTACT_SIG_FLG_ALIAS != 0 {
                0
            } else if dflags & DFLAG_EXIT_PAYLOAD != 0 {
                pick(DOP_PAYLOAD_EXIT2_TT, DOP_PAYLOAD_EXIT2)
            } else {
                pick(DOP_EXIT2_TT, DOP_EXIT2)
            }
        } else if flags & ERTS_DOP_ALTACT_SIG_FLG_ALIAS != 0 {
            if dflags & DFLAG_ALIAS == 0 {
                0
            } else {
                pick(DOP_ALIAS_SEND_TT, DOP_ALIAS_SEND)
            }
        } else if flags & ERTS_DOP_ALTACT_SIG_FLG_NAME != 0 {
            pick(DOP_REG_SEND_TT, DOP_REG_SEND)
        } else if dflags & DFLAG_SEND_SENDER != 0 {
            pick(DOP_SEND_SENDER_TT, DOP_SEND_SENDER)
        } else {
            pick(DOP_SEND_TT, DOP_SEND)
        };
        if dist_op == 0 {
            // Drop the signal and send a tick instead.
            ob.free_to_tick();
            *reds = (*reds - 1).max(0);
            return DistHeaderFinalize::Done;
        }
        let ep_len = ep.len();
        let slot2 = ob.slot(2);
        let ep_off = ob.bin.data_offset(ep.as_ptr() as usize);
        let ctl = ob.bin.bytes_mut(ep_off, ep_len);
        // `ptr`: the last byte before SenderPid.
        let mut ptr = 5;
        match dist_op {
            // Drop the flags element, write the new operation, one element less.
            DOP_ALIAS_SEND | DOP_ALIAS_SEND_TT | DOP_SEND_SENDER | DOP_SEND_SENDER_TT
            | DOP_PAYLOAD_EXIT2 | DOP_PAYLOAD_EXIT2_TT => tuple_size -= 1,
            // Reason follows the control message as its last element: same tuple size, and
            // no version magic before it.
            DOP_EXIT2 | DOP_EXIT2_TT => payload_moved_to_control = true,
            DOP_REG_SEND | DOP_REG_SEND_TT | DOP_SEND | DOP_SEND_TT => {
                ptr += 1;
                let sender_start = ptr;
                assert_eq!(ctl[sender_start], NEW_PID_EXT, "Unexpected pid encoding");
                ptr += 1;
                let tag = ctl[ptr];
                ptr += 1;
                let n = match tag {
                    ATOM_UTF8_EXT => {
                        let n = u16::from_be_bytes([ctl[ptr], ctl[ptr + 1]]) as usize;
                        ptr += 2;
                        n
                    }
                    SMALL_ATOM_UTF8_EXT => {
                        let n = ctl[ptr] as usize;
                        ptr += 1;
                        n
                    }
                    _ => panic!("Unexpected pid encoding"),
                };
                ptr += n + 4 /* ID */ + 4 /* serial */ + 4 /* creation */;
                // `ptr` is the first byte of ToPid / ToName.
                if dist_op == DOP_SEND || dist_op == DOP_SEND_TT {
                    // Write the empty atom over the end of SenderPid.
                    ptr -= 1;
                    ctl[ptr] = 0;
                    ptr -= 1;
                    ctl[ptr] = SMALL_ATOM_UTF8_EXT;
                    tuple_size -= 1;
                    ptr -= 1;
                    *reds -= 1;
                } else {
                    // Move SenderPid two bytes earlier to make room for the empty atom
                    // between it and ToName.
                    let new_sender_start = sender_start - 2;
                    ctl.copy_within(sender_start..ptr, new_sender_start);
                    ptr -= 1;
                    ctl[ptr] = 0;
                    ptr -= 1;
                    ctl[ptr] = SMALL_ATOM_UTF8_EXT;
                    ptr = new_sender_start - 1;
                    *reds -= 2;
                }
            }
            _ => panic!("Unexpected fallback dist operation"),
        }
        // altact_sig_fallback_common: write the operation and tuple header backwards.
        ctl[ptr] = dist_op;
        ctl[ptr - 1] = SMALL_INTEGER_EXT;
        ctl[ptr - 2] = tuple_size;
        ptr -= 3;
        ctl[ptr] = SMALL_TUPLE_EXT;
        *reds -= 1;
        ob.bin.set_own(slot2, ep_off + ptr, ep_len - ptr);
        let eiov = ob.eiov();
        let size = ob.size();
        ob.set_record(eiov + EIOV_SIZE, size - ptr);
    }
    let start_r = *reds * ERTS_TRANSCODE_REDS_FACT;
    let mut r = start_r;
    // Replace the hopeful data header with the actual header.
    let eiov = ob.eiov();
    let hdr = ob.iov(1);
    let hdr_off = ob.bin.data_offset(hdr.as_ptr() as usize);
    let mut size = ob.size() - hdr.len();
    let header: &[u8] = if dflags & (DFLAG_DIST_HDR_ATOM_CACHE | DFLAG_FRAGMENTS) != 0 {
        // Encoded without atom caching but the receiver expects a dist header: an empty
        // one is prepended.
        &[VERSION_MAGIC, DIST_HEADER, 0]
    } else {
        if payload_ix != 0 && !payload_moved_to_control {
            debug_assert!(0 < payload_ix && payload_ix < ob.vsize());
            // Prepend version magic on payload: the encode left the byte before it free.
            let payload = ob.iov(payload_ix);
            let len = payload.len();
            let off = ob.bin.data_offset(payload.as_ptr() as usize) - 1;
            ob.bin.bytes_mut(off, 1)[0] = VERSION_MAGIC;
            let slot = ob.slot(payload_ix);
            ob.bin.set_own(slot, off, len + 1);
            size += 1;
            r -= 1;
        }
        &[PASS_THROUGH, VERSION_MAGIC]
    };
    ob.bin
        .bytes_mut(hdr_off, header.len())
        .copy_from_slice(header);
    let slot1 = ob.slot(1);
    ob.bin.set_own(slot1, hdr_off, header.len());
    size += header.len();
    ob.set_record(eiov + EIOV_SIZE, size);
    r -= 1;
    *reds = (*reds - ((start_r - r) / ERTS_TRANSCODE_REDS_FACT + 1)).max(0);
    DistHeaderFinalize::Done
}
/// `enum erts_dsig_send_phase` up to `ERTS_DSIG_SEND_PHASE_FIN`: the encode part of
/// `erts_dsig_send`. `ERTS_DSIG_SEND_PHASE_SEND` is the caller's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DsigSendPhase {
    /// `ERTS_DSIG_SEND_PHASE_INIT`: the control message size.
    Init,
    /// `ERTS_DSIG_SEND_PHASE_MSG_SIZE`.
    MsgSize,
    /// `ERTS_DSIG_SEND_PHASE_ALLOC`: buffer, header and the control message encode.
    Alloc,
    /// `ERTS_DSIG_SEND_PHASE_MSG_ENCODE`.
    MsgEncode,
    /// `ERTS_DSIG_SEND_PHASE_FIN`: fragment headers.
    Fin,
    /// `ERTS_DSIG_SEND_PHASE_SEND`: the output buffers are ready.
    Send,
}

/// The result of [`DsigEncode::step`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DsigEncodeResult {
    /// The phase is `Send`: the output buffers are ready ([`DsigEncode::take_obufs`]).
    Send,
    /// `ERTS_DSIG_SEND_CONTINUE`: out of reductions in `MSG_SIZE`, `MSG_ENCODE` or after
    /// `FIN`.
    Continue,
    /// `ERTS_DSIG_SEND_TOO_LRG`.
    TooLarge,
}

/// The encode part of `ErtsDSigSendContext`: the phase, the control message and payload,
/// the size and encode contexts and the output buffers being built.
// Port of erts/emulator/beam/dist.h (ErtsDSigSendContext: phase, ctl, msg, data_size,
// dhdr_ext_size, dhdrp, extp, acmp, obuf, alloced_fragments, fragments, vlen, dflags, u.sc,
// u.ec), OTP-29.1.1.
pub struct DsigEncode {
    phase: DsigSendPhase,
    ctl: Term,
    /// `ctl_heap`: the control message's own copy once the send is exported.
    ctl_heap: Option<arinsal_term::VecHeap>,
    msg: Option<Term>,
    dflags: u64,
    /// `ctx->from`: names the fragments of the signal.
    from: u64,
    /// The exported copy of the atom cache map (`exported_ctx.acm`). Only `&mut self`
    /// reaches it (`Mutex::get_mut`); the mutex makes the context `Sync` for the magic
    /// binary that holds it without ever locking.
    acm: Option<Box<std::sync::Mutex<ErtsAtomCacheMap>>>,
    data_size: usize,
    dhdr_ext_size: usize,
    dhdrp: usize,
    extp: usize,
    /// The payload offset of the data: the output buffers and their I/O vectors come first.
    data_off: usize,
    alloced_fragments: usize,
    fragments: usize,
    vlen: isize,
    sc: TtbDistSizeContext,
    ec: Option<TtbDistEncodeContext>,
    /// `ctx->obuf->bin`: the signal's buffer, uniquely owned until `FIN`.
    bin: Option<raw::ObufBlock>,
    obufs: Vec<ErtsDistOutputBuf>,
    node_source: fn() -> (Atom, u32),
}

impl std::fmt::Debug for DsigEncode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsigEncode")
            .field("phase", &self.phase)
            .field("fragments", &self.fragments)
            .finish()
    }
}

/// `CONTEXT_REDS` (erl_vm.h): the loop units of a phase run that does not trap.
const CONTEXT_REDS: i64 = 4000;

impl DsigEncode {
    /// A context in `ERTS_DSIG_SEND_PHASE_INIT` for `ctl` and `msg` with the connection's
    /// `dflags`; `from` names the fragments of the signal. `node_source` gives this node's
    /// name and creation (`erts_this_node`) when a local pid, port or reference is encoded.
    pub fn new(
        ctl: Term,
        msg: Option<Term>,
        dflags: u64,
        from: u64,
        node_source: fn() -> (Atom, u32),
    ) -> Self {
        Self {
            phase: DsigSendPhase::Init,
            ctl,
            ctl_heap: None,
            msg,
            dflags,
            from,
            acm: None,
            data_size: 0,
            dhdr_ext_size: 0,
            dhdrp: 0,
            extp: 0,
            data_off: 0,
            alloced_fragments: 0,
            fragments: 0,
            vlen: 0,
            sc: TtbDistSizeContext::new(dflags, node_source),
            ec: None,
            bin: None,
            obufs: Vec::new(),
            node_source,
        }
    }

    /// `ctx->phase`.
    pub fn phase(&self) -> DsigSendPhase {
        self.phase
    }

    /// `erts_dsend_export_trap_context`: the control message is copied into the context's
    /// own heap and the atom cache map in use into the context's own map, so that the send
    /// can resume on another scheduler and after other sends reused the shared map.
    // Port of erts/emulator/beam/dist.c (erts_dsend_export_trap_context), OTP-29.1.1.
    pub fn export(&mut self, acmp: Option<&ErtsAtomCacheMap>) {
        if self.ctl_heap.is_none() {
            let size = arinsal_term::size_object(self.ctl);
            let mut heap = arinsal_term::VecHeap::with_initial_chunk_words(size.max(1));
            // erts HAlloc into a heap sized by size_object never fails.
            self.ctl = arinsal_term::copy_struct(self.ctl, &mut heap, size)
                .expect("control heap sized by size_object");
            self.ctl_heap = Some(heap);
        }
        if self.acm.is_none()
            && self.dflags & DFLAG_DIST_HDR_ATOM_CACHE != 0
            && let Some(acmp) = acmp
        {
            self.acm = Some(Box::new(std::sync::Mutex::new(acmp.clone())));
        }
    }

    /// The output buffers of a context in `ERTS_DSIG_SEND_PHASE_SEND`.
    pub fn take_obufs(&mut self) -> Vec<ErtsDistOutputBuf> {
        std::mem::take(&mut self.obufs)
    }

    /// Run the encode phases of `erts_dsig_send` from the current phase. `shared_acmp` is
    /// the atom cache map of a context that was not exported (`erts_get_atom_cache_map`).
    /// `reds` is `ctx->reds` in loop units; with `no_trap` the `MSG_*` phases run to the end
    /// on `CONTEXT_REDS` slices, still charging `reds`.
    // Port of erts/emulator/beam/dist.c (erts_dsig_send, ERTS_DSIG_SEND_PHASE_INIT ..
    // ERTS_DSIG_SEND_PHASE_FIN), OTP-29.1.1.
    pub fn step(
        &mut self,
        shared_acmp: Option<&ErtsAtomCacheMap>,
        reds: &mut i64,
        no_trap: bool,
    ) -> Result<DsigEncodeResult, EncodeError> {
        let mut acm = self.acm.take();
        let exported = acm
            .as_mut()
            .map(|acm| &*acm.get_mut().unwrap_or_else(|poison| poison.into_inner()));
        let acmp = (self.dflags & DFLAG_DIST_HDR_ATOM_CACHE != 0)
            .then(|| exported.or(shared_acmp))
            .flatten();
        let result = self.run(acmp, reds, no_trap);
        self.acm = acm;
        result
    }

    fn run(
        &mut self,
        acmp: Option<&ErtsAtomCacheMap>,
        ctx_reds: &mut i64,
        no_trap: bool,
    ) -> Result<DsigEncodeResult, EncodeError> {
        loop {
            match self.phase {
                DsigSendPhase::Init => {
                    self.data_size = 0;
                    if let Some(acmp) = acmp {
                        acmp.reset();
                    }
                    self.sc = TtbDistSizeContext::new(self.dflags, self.node_source);
                    loop {
                        let mut reds = CONTEXT_REDS;
                        let res = erts_encode_dist_ext_size(
                            self.ctl,
                            acmp,
                            &mut self.sc,
                            &mut self.data_size,
                            &mut reds,
                            &mut self.vlen,
                            &mut self.fragments,
                        );
                        *ctx_reds -= CONTEXT_REDS - reds;
                        match res {
                            ErtsExtSzRes::Ok => break,
                            ErtsExtSzRes::SystemLimit => return Ok(DsigEncodeResult::TooLarge),
                            ErtsExtSzRes::Yield => {}
                        }
                    }
                    self.phase = if self.msg.is_none() {
                        DsigSendPhase::Alloc
                    } else {
                        DsigSendPhase::MsgSize
                    };
                }
                DsigSendPhase::MsgSize => {
                    let msg = self.msg.expect("MSG_SIZE has a payload");
                    loop {
                        let mut local = CONTEXT_REDS;
                        let redsp = if no_trap { &mut local } else { &mut *ctx_reds };
                        let res = erts_encode_dist_ext_size(
                            msg,
                            acmp,
                            &mut self.sc,
                            &mut self.data_size,
                            redsp,
                            &mut self.vlen,
                            &mut self.fragments,
                        );
                        if no_trap {
                            *ctx_reds -= CONTEXT_REDS - local;
                            if res == ErtsExtSzRes::Yield {
                                continue;
                            }
                        }
                        match res {
                            ErtsExtSzRes::Ok => break,
                            ErtsExtSzRes::SystemLimit => return Ok(DsigEncodeResult::TooLarge),
                            ErtsExtSzRes::Yield => return Ok(DsigEncodeResult::Continue),
                        }
                    }
                    self.phase = DsigSendPhase::Alloc;
                }
                DsigSendPhase::Alloc => {
                    if let Some(acmp) = acmp {
                        acmp.finalize();
                    }
                    self.dhdr_ext_size =
                        erts_encode_ext_dist_header_size(self.dflags, acmp, self.fragments);
                    // alloc_dist_obufs: one driver Binary of the exact size for the output
                    // buffers of every fragment, their I/O vectors and the data.
                    let data_size = self.dhdr_ext_size
                        + self.data_size
                        + (self.fragments - 1) * ERTS_DIST_FRAGMENT_HEADER_SIZE;
                    let vlen = usize::try_from(self.vlen).expect("the size pass set vlen");
                    let obsz = OBUF_SZ * self.fragments;
                    let iov_sz = erts_ttb_iov_size(vlen, self.fragments);
                    let size = obsz + iov_sz + data_size;
                    self.data_off = obsz + iov_sz;
                    let mut block = raw::ObufBlock::alloc(size, obsz, vlen, self.data_off);
                    let (mut meta, bin) = block.split();
                    let fragment_size = if self.fragments > 1 {
                        ERTS_DIST_FRAGMENT_SIZE
                    } else {
                        usize::MAX
                    };
                    let data_base = meta.data_base();
                    let mut ec = TtbDistEncodeContext::new(
                        obsz,
                        vlen,
                        fragment_size,
                        data_base,
                        self.node_source,
                    );
                    for ix in 0..self.fragments {
                        // obuf[ix].eiov = &ctx->fragment_eiovs[ix].
                        meta.set_word(OBUF_SZ * ix, ec.fragment_eiovs + ERLIOVEC_SZ * ix);
                    }
                    self.alloced_fragments = self.fragments;
                    // Encode the internal version of the dist header.
                    self.extp = self.dhdr_ext_size;
                    self.dhdrp = erts_encode_ext_dist_header_setup(
                        self.dflags,
                        bin,
                        self.extp,
                        acmp,
                        self.fragments,
                        self.from,
                        &mut ec,
                    );
                    self.dhdr_ext_size = self.extp - self.dhdrp;
                    loop {
                        let mut reds = CONTEXT_REDS;
                        // Encode the control message.
                        let done = match erts_encode_dist_ext(
                            self.ctl,
                            &mut meta,
                            &mut *bin,
                            &mut self.extp,
                            self.dflags,
                            acmp,
                            &mut ec,
                            &mut self.fragments,
                            &mut reds,
                        ) {
                            Ok(done) => done,
                            Err(error) => {
                                // The references stored so far go with the buffer
                                // (erts_dsend_context_dtor).
                                meta.release_slots();
                                return Err(error);
                            }
                        };
                        *ctx_reds -= CONTEXT_REDS - reds;
                        if done {
                            break;
                        }
                    }
                    self.bin = Some(block);
                    self.ec = Some(ec);
                    self.phase = if self.msg.is_none() {
                        DsigSendPhase::Fin
                    } else {
                        DsigSendPhase::MsgEncode
                    };
                }
                DsigSendPhase::MsgEncode => {
                    let msg = self.msg.expect("MSG_ENCODE has a payload");
                    let (mut meta, bin) = self
                        .bin
                        .as_mut()
                        .expect("buffer allocated in ALLOC")
                        .split();
                    let ec = self.ec.as_mut().expect("encode context set up in ALLOC");
                    loop {
                        let mut local = CONTEXT_REDS;
                        let redsp = if no_trap { &mut local } else { &mut *ctx_reds };
                        let done = erts_encode_dist_ext(
                            msg,
                            &mut meta,
                            &mut *bin,
                            &mut self.extp,
                            self.dflags,
                            acmp,
                            ec,
                            &mut self.fragments,
                            redsp,
                        )?;
                        if !no_trap {
                            if done {
                                break;
                            }
                            return Ok(DsigEncodeResult::Continue);
                        }
                        *ctx_reds -= CONTEXT_REDS - local;
                        if done {
                            break;
                        }
                    }
                    self.phase = DsigSendPhase::Fin;
                }
                DsigSendPhase::Fin => {
                    self.fin();
                    self.phase = DsigSendPhase::Send;
                    if *ctx_reds <= 0 && !no_trap {
                        return Ok(DsigEncodeResult::Continue);
                    }
                }
                DsigSendPhase::Send => return Ok(DsigEncodeResult::Send),
            }
        }
    }

    /// `ERTS_DSIG_SEND_PHASE_FIN`: the fragment count in the `DIST_FRAG_HEADER`, the
    /// `DIST_FRAG_CONT` headers after the data in `iov[1]` of each fragment's `ErlIOVec`,
    /// and the references the elements of the signal's own buffer hold (`binv`), taken now
    /// that the buffer is complete. One output buffer per fragment, each holding a
    /// reference to the Binary.
    // Port of erts/emulator/beam/dist.c (erts_dsig_send, ERTS_DSIG_SEND_PHASE_FIN), OTP-29.1.1.
    fn fin(&mut self) {
        let mut block = self.bin.take().expect("buffer allocated in ALLOC");
        let ec = self.ec.take().expect("encode context set up in ALLOC");
        let (mut meta, bin) = block.split();
        let data_base = meta.data_base();
        let mut fid = self.fragments as u64;
        debug_assert!(fid >= 1);
        debug_assert!(self.alloced_fragments >= self.fragments);
        if self.alloced_fragments > 1 {
            // Update the frag_id in the DIST_FRAG_HEADER.
            let at = self.dhdrp + 1 + 1 + 8;
            bin[at..at + 8].copy_from_slice(&(self.fragments as u64).to_be_bytes());
        }
        for fix in 0..self.fragments {
            let (hdr, sz) = if fix == 0 {
                (self.dhdrp, self.dhdr_ext_size)
            } else {
                fid -= 1;
                let hdr = erts_encode_ext_dist_header_fragment(bin, &mut self.extp, fid, self.from);
                (hdr, self.extp - hdr)
            };
            let eiov = ec.fragment_eiovs + ERLIOVEC_SZ * fix;
            debug_assert!(meta.word(eiov + EIOV_VSIZE) >= 3);
            let size = meta.word(eiov + EIOV_SIZE);
            meta.set_word(eiov + EIOV_SIZE, size + sz);
            let slot = (meta.word(eiov + EIOV_IOV) - ec.iov) / SYSIOVEC_SZ + 1;
            debug_assert_eq!(meta.iov_len(slot), 0);
            meta.set_own(slot, data_base + hdr, sz);
        }
        debug_assert!(fid == 1);
        // binv[1] and the data elements of the signal's own buffer get their references
        // now that the buffer is complete.
        let bin = block.into_shared();
        // A size pass that over-counted leaves allocated fragments unused; they are dropped
        // (free_dist_obuf(&ctx->obuf[fix], 0)).
        let mut bin = Some(bin);
        self.obufs = (0..self.fragments)
            .map(|fix| {
                let bin = if fix + 1 == self.fragments {
                    bin.take().expect("one reference per fragment")
                } else {
                    bin.as_ref()
                        .and_then(|bin| bin.try_clone())
                        .expect("the signal's buffer is live while referenced")
                };
                ErtsDistOutputBuf {
                    bin,
                    obuf: OBUF_SZ * fix,
                }
            })
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_term::{TermBuilder, VecHeap};

    const DFLAGS: u64 = DFLAG_DIST_HDR_ATOM_CACHE | DFLAG_FRAGMENTS;

    fn node() -> (Atom, u32) {
        (global_atoms().intern("n@h").unwrap(), 7)
    }

    /// Encode a signal to the end and finalize its buffers against `cache`, as the output
    /// path does.
    fn encode_signal(
        ctl: Term,
        msg: Option<Term>,
        dflags: u64,
        cache: &mut ErtsAtomCache,
        map: &ErtsAtomCacheMap,
        from: u64,
    ) -> Vec<Vec<u8>> {
        let mut enc = DsigEncode::new(ctl, msg, dflags, from, node);
        let mut reds = CONTEXT_REDS;
        assert_eq!(
            enc.step(Some(map), &mut reds, true).unwrap(),
            DsigEncodeResult::Send
        );
        enc.take_obufs()
            .into_iter()
            .map(|mut ob| {
                assert_eq!(
                    erts_encode_ext_dist_header_finalize(&mut ob, cache, dflags, &mut 0),
                    DistHeaderFinalize::Done
                );
                ob.to_vec()
            })
            .collect()
    }

    /// A signal encoded toward a pending connection: its one output buffer.
    fn pending(ctl: Term, msg: Option<Term>) -> ErtsDistOutputBuf {
        let mut enc = DsigEncode::new(ctl, msg, DFLAG_PENDING_CONNECT, 1, node);
        let mut reds = CONTEXT_REDS;
        assert_eq!(
            enc.step(None, &mut reds, true).unwrap(),
            DsigEncodeResult::Send
        );
        let mut obufs = enc.take_obufs();
        assert_eq!(obufs.len(), 1);
        obufs.pop().unwrap()
    }

    fn ctl(heap: &mut VecHeap, atom: &str) -> Term {
        let atom = Term::atom(global_atoms().intern(atom).unwrap());
        TermBuilder::new(heap)
            .tuple(&[Term::small(2).unwrap(), atom])
            .unwrap()
    }

    #[test]
    fn atoms_go_through_the_connection_cache() {
        let mut heap = VecHeap::new();
        let ctl = ctl(&mut heap, "dist_enc_test_atom");
        let atom = global_atoms().intern("dist_enc_test_atom").unwrap();
        let cix = atom2cix(atom);
        let mut cache = ErtsAtomCache::default();
        let map = ErtsAtomCacheMap::default();
        let first = encode_signal(ctl, None, DFLAGS, &mut cache, &map, 1);
        let name = b"dist_enc_test_atom";
        let mut expected = vec![131, 68, 1, 8 | ((cix >> 8) as u8 & 7), cix as u8];
        expected.push(name.len() as u8);
        expected.extend_from_slice(name);
        expected.extend_from_slice(&[104, 2, 97, 2, 82, 0]);
        assert_eq!(first, vec![expected]);
        assert_eq!(cache.out(cix), Some(atom));
        // The second signal names the cached atom only.
        let again = encode_signal(ctl, None, DFLAGS, &mut cache, &map, 2);
        assert_eq!(
            again,
            vec![vec![
                131,
                68,
                1,
                (cix >> 8) as u8 & 7,
                cix as u8,
                104,
                2,
                97,
                2,
                82,
                0
            ]]
        );
    }

    #[test]
    fn internal_pids_are_named_by_this_node() {
        let mut heap = VecHeap::new();
        let pid = Term::pid_from_data((1 << arinsal_term::ptab::PID_NUM_SIZE) | 5);
        let ctl = TermBuilder::new(&mut heap)
            .tuple(&[Term::small(1).unwrap(), pid])
            .unwrap();
        let mut cache = ErtsAtomCache::default();
        let map = ErtsAtomCacheMap::default();
        let out = encode_signal(ctl, None, 0, &mut cache, &map, 1);
        assert_eq!(
            out,
            vec![vec![
                112, 131, 104, 2, 97, 1, 88, 119, 3, b'n', b'@', b'h', 0, 0, 0, 5, 0, 0, 0, 1, 0,
                0, 0, 7
            ]]
        );
    }

    fn tuple(heap: &mut VecHeap, elems: &[Term]) -> Term {
        TermBuilder::new(heap).tuple(elems).unwrap()
    }

    fn small(n: i64) -> Term {
        Term::small(n).unwrap()
    }

    fn atom(name: &str) -> Term {
        Term::atom(global_atoms().intern(name).unwrap())
    }

    /// A pending signal finalized for `dflags`.
    fn transcoded(ctl: Term, msg: Option<Term>, dflags: u64) -> (Vec<u8>, DistHeaderFinalize) {
        let mut ob = pending(ctl, msg);
        assert_eq!(ob.to_vec()[0], HOPEFUL_DATA);
        let result = erts_encode_ext_dist_header_finalize(
            &mut ob,
            &mut ErtsAtomCache::default(),
            dflags,
            &mut 0,
        );
        (ob.to_vec(), result)
    }

    /// The same signal encoded directly for a connected peer with `dflags`.
    fn direct(ctl: Term, msg: Option<Term>, dflags: u64) -> Vec<u8> {
        let mut cache = ErtsAtomCache::default();
        let map = ErtsAtomCacheMap::default();
        let mut out = encode_signal(ctl, msg, dflags, &mut cache, &map, 1);
        assert_eq!(out.len(), 1);
        out.pop().unwrap()
    }

    #[test]
    fn pending_signals_are_finalized_with_the_connection_flags() {
        let mut heap = VecHeap::new();
        let ctl = ctl(&mut heap, "a");
        let body = [104, 2, 97, 2, 119, 1, b'a'];
        let mut header = vec![131, 68, 0];
        header.extend_from_slice(&body);
        header.extend_from_slice(&body);
        assert_eq!(
            transcoded(ctl, Some(ctl), DFLAGS),
            (header, DistHeaderFinalize::Done)
        );
        let mut pass = vec![112, 131];
        pass.extend_from_slice(&body);
        pass.push(131);
        pass.extend_from_slice(&body);
        assert_eq!(
            transcoded(ctl, Some(ctl), 0),
            (pass, DistHeaderFinalize::Done)
        );
        // Signals encoded for a connected peer without a dist header are left alone.
        let mut enc = DsigEncode::new(ctl, None, 0, 1, node);
        let mut reds = CONTEXT_REDS;
        enc.step(None, &mut reds, true).unwrap();
        let mut ob = enc.take_obufs().pop().unwrap();
        let before = ob.to_vec();
        assert_eq!(
            erts_encode_ext_dist_header_finalize(
                &mut ob,
                &mut ErtsAtomCache::default(),
                DFLAGS,
                &mut 0
            ),
            DistHeaderFinalize::Done
        );
        assert_eq!(ob.to_vec(), before);
    }

    #[test]
    fn altact_signals_are_rewritten_for_peers_without_altact_sig() {
        let mut heap = VecHeap::new();
        let me = Term::pid_from_data((1 << arinsal_term::ptab::PID_NUM_SIZE) | 5);
        let to = Term::pid_from_data((2 << arinsal_term::ptab::PID_NUM_SIZE) | 9);
        let msg = atom("hello");
        let name = atom("server");
        let flg_name = i64::from(ERTS_DOP_ALTACT_SIG_FLG_NAME);
        let flg_exit = i64::from(ERTS_DOP_ALTACT_SIG_FLG_EXIT);
        let flg_alias = i64::from(ERTS_DOP_ALTACT_SIG_FLG_ALIAS);
        let cases = [
            // {DOP_ALTACT_SIG_SEND, PRIO, Me, To} -> {DOP_SEND, '', To}
            (
                tuple(&mut heap, &[small(37), small(1), me, to]),
                tuple(&mut heap, &[small(2), atom(""), to]),
                0,
                true,
            ),
            // ... -> {DOP_SEND_SENDER, Me, To}
            (
                tuple(&mut heap, &[small(37), small(1), me, to]),
                tuple(&mut heap, &[small(22), me, to]),
                DFLAG_SEND_SENDER,
                true,
            ),
            // NAME -> {DOP_REG_SEND, Me, '', Name}
            (
                tuple(&mut heap, &[small(37), small(1 | flg_name), me, name]),
                tuple(&mut heap, &[small(6), me, atom(""), name]),
                DFLAG_FRAGMENTS,
                true,
            ),
            // NAME + token -> {DOP_REG_SEND_TT, Me, '', Name, Token}
            (
                tuple(
                    &mut heap,
                    &[small(37), small(3 | flg_name), me, name, small(7)],
                ),
                tuple(&mut heap, &[small(16), me, atom(""), name, small(7)]),
                0,
                true,
            ),
            // EXIT with payload -> {DOP_PAYLOAD_EXIT2, Me, To}
            (
                tuple(&mut heap, &[small(37), small(1 | flg_exit), me, to]),
                tuple(&mut heap, &[small(26), me, to]),
                DFLAG_EXIT_PAYLOAD,
                true,
            ),
        ];
        for (altact, plain, dflags, with_msg) in cases {
            let msg = with_msg.then_some(msg);
            assert_eq!(
                transcoded(altact, msg, dflags),
                (direct(plain, msg, dflags), DistHeaderFinalize::Done)
            );
        }
        // EXIT without DFLAG_EXIT_PAYLOAD: the reason moves into the control message,
        // {DOP_EXIT2, Me, To, Reason}.
        let altact = tuple(&mut heap, &[small(37), small(1 | flg_exit), me, to]);
        let plain = tuple(&mut heap, &[small(8), me, to, msg]);
        assert_eq!(transcoded(altact, Some(msg), 0).0, direct(plain, None, 0));
        // An alias exit and an alias message to a peer without DFLAG_ALIAS are ticks.
        let alias_exit = tuple(&mut heap, &[small(37), small(flg_exit | flg_alias), me, to]);
        assert_eq!(transcoded(alias_exit, Some(msg), 0).0, Vec::<u8>::new());
        let alias_send = tuple(&mut heap, &[small(37), small(flg_alias), me, to]);
        assert_eq!(transcoded(alias_send, Some(msg), 0).0, Vec::<u8>::new());
        // With DFLAG_ALIAS the alias message is a DOP_ALIAS_SEND.
        let plain = tuple(&mut heap, &[small(33), me, to]);
        assert_eq!(
            transcoded(alias_send, Some(msg), DFLAG_ALIAS).0,
            direct(plain, Some(msg), DFLAG_ALIAS)
        );
        // A peer with DFLAG_ALTACT_SIG gets the signal as encoded.
        let altact = tuple(&mut heap, &[small(37), small(1), me, to]);
        assert_eq!(
            transcoded(altact, Some(msg), DFLAG_ALTACT_SIG).0,
            direct(altact, Some(msg), DFLAG_ALTACT_SIG)
        );
    }

    #[test]
    fn pending_signals_are_transcoded_in_place() {
        // transcode_dist_obuf rewrites the buffer's own I/O vector: the data elements keep
        // referencing the signal's Binary and the refc binary of the payload, and the
        // payload gets its version magic in the byte the encode left in front of it.
        let mut heap = VecHeap::new();
        let data: Vec<u8> = (0..4096).map(|i| (i * 3) as u8).collect();
        let mut builder = TermBuilder::new(&mut heap);
        let bin = builder.binary(&data).unwrap();
        let msg = builder.tuple(&[bin, Term::small(5).unwrap()]).unwrap();
        let (owner, _) = crate::raw::refc_payload(bin).expect("a refc binary");
        let refs = owner.ref_count().unwrap();
        let me = Term::pid_from_data((1 << arinsal_term::ptab::PID_NUM_SIZE) | 5);
        let to = Term::pid_from_data((2 << arinsal_term::ptab::PID_NUM_SIZE) | 9);
        let altact = tuple(&mut heap, &[small(37), small(1), me, to]);
        let mut ob = pending(altact, Some(msg));
        let before: Vec<usize> = ob.data_elements().iter().map(|(h, _)| *h).collect();
        assert!(before.contains(&(owner.header_ptr() as usize)));
        let result =
            erts_encode_ext_dist_header_finalize(&mut ob, &mut ErtsAtomCache::default(), 0, &mut 0);
        assert_eq!(result, DistHeaderFinalize::Done);
        let after: Vec<usize> = ob.data_elements().iter().map(|(h, _)| *h).collect();
        assert_eq!(before, after);
        let plain = tuple(&mut heap, &[small(2), atom(""), to]);
        assert_eq!(ob.to_vec(), direct(plain, Some(msg), 0));
        assert_eq!(ob.size(), ob.to_vec().len());
        drop(ob);
        assert_eq!(owner.ref_count().unwrap(), refs);
    }

    #[test]
    fn unsupported_signals_become_ticks() {
        let mut heap = VecHeap::new();
        let me = Term::pid_from_data((1 << arinsal_term::ptab::PID_NUM_SIZE) | 5);
        let monitor = tuple(&mut heap, &[small(19), me, atom("x"), small(1)]);
        assert_eq!(transcoded(monitor, None, 0).0, Vec::<u8>::new());
        assert_eq!(
            transcoded(monitor, None, DFLAG_DIST_MONITOR | DFLAG_DIST_MONITOR_NAME).0,
            direct(monitor, None, 0)
        );
        let spawn = tuple(
            &mut heap,
            &[small(29), small(1), me, me, atom("mfa"), Term::NIL],
        );
        let (ob, result) = transcoded(spawn, Some(Term::NIL), 0);
        assert!(ob.is_empty());
        let mut ctl = direct(spawn, None, 0);
        ctl.drain(..2);
        assert_eq!(result, DistHeaderFinalize::SpawnNotSupported(ctl));
    }

    #[test]
    fn large_signals_are_fragmented() {
        // A binary of two fragments and a bit inside a list: the fragments cut the encoded
        // stream at ERTS_DIST_FRAGMENT_SIZE and concatenate to the plain encoding.
        let mut heap = VecHeap::new();
        let data: Vec<u8> = (0..(ERTS_DIST_FRAGMENT_SIZE * 2 + 10))
            .map(|i| i as u8)
            .collect();
        let mut builder = TermBuilder::new(&mut heap);
        let bin = builder.binary(&data).unwrap();
        let msg = builder
            .list_from_slice(&[bin, Term::small(1).unwrap()])
            .unwrap();
        let ctl = ctl(&mut heap, "a");
        let mut cache = ErtsAtomCache::default();
        let map = ErtsAtomCacheMap::default();
        let out = encode_signal(ctl, Some(msg), DFLAGS, &mut cache, &map, 9);
        assert_eq!(out.len(), 3);
        assert_eq!(&out[0][..2], &[131, 69]);
        assert_eq!(&out[0][2..10], &9u64.to_be_bytes());
        assert_eq!(&out[0][10..18], &3u64.to_be_bytes());
        assert_eq!(&out[1][..2], &[131, 70]);
        assert_eq!(&out[1][10..18], &2u64.to_be_bytes());
        assert_eq!(&out[2][..2], &[131, 70]);
        assert_eq!(&out[2][10..18], &1u64.to_be_bytes());
        // Header: magic, 'E', seq, frag, 1 atom ('a', new) with its flags byte.
        let first_hdr = 18 + 1 + 1 + 1 + 1 + 1;
        assert_eq!(out[0].len() - first_hdr, ERTS_DIST_FRAGMENT_SIZE);
        assert_eq!(out[1].len() - 18, ERTS_DIST_FRAGMENT_SIZE);
        let mut stream = out[0][first_hdr..].to_vec();
        stream.extend_from_slice(&out[1][18..]);
        stream.extend_from_slice(&out[2][18..]);
        let plain = crate::encode_term_to_binary(msg).unwrap();
        // The control message {2, a} as an ATOM_CACHE_REF, then the payload.
        assert_eq!(&stream[..6], &[104, 2, 97, 2, 82, 0]);
        assert_eq!(&stream[6..], &plain[1..]);
    }

    #[test]
    fn large_binaries_are_referenced_in_the_iovec() {
        // A refc binary over ERL_ONHEAP_BITS_LIMIT is referenced by the output buffers, not
        // copied into the signal's buffer; the wire bytes are the plain encoding.
        let mut heap = VecHeap::new();
        let data: Vec<u8> = (0..(ERTS_DIST_FRAGMENT_SIZE + 1000))
            .map(|i| (i * 7) as u8)
            .collect();
        let mut builder = TermBuilder::new(&mut heap);
        let bin = builder.binary(&data).unwrap();
        let msg = builder.tuple(&[bin, Term::small(5).unwrap()]).unwrap();
        let (owner, offset) = crate::raw::refc_payload(bin).expect("a refc binary");
        let refs = owner.ref_count().unwrap();
        let ctl = ctl(&mut heap, "a");
        let map = ErtsAtomCacheMap::default();
        let mut enc = DsigEncode::new(ctl, Some(msg), DFLAGS, 3, node);
        let mut reds = CONTEXT_REDS;
        assert_eq!(
            enc.step(Some(&map), &mut reds, true).unwrap(),
            DsigEncodeResult::Send
        );
        let mut obufs = enc.take_obufs();
        assert_eq!(obufs.len(), 2);
        let referenced: usize = obufs
            .iter()
            .flat_map(|ob| ob.data_elements())
            .filter(|(header, _)| *header == owner.header_ptr() as usize)
            .map(|(_, range)| {
                assert!(range.start >= offset);
                range.len()
            })
            .sum();
        assert_eq!(referenced, data.len());
        // One reference per element that points into the binary.
        assert!(owner.ref_count().unwrap() > refs);
        let mut cache = ErtsAtomCache::default();
        let mut stream = Vec::new();
        for (i, ob) in obufs.iter_mut().enumerate() {
            erts_encode_ext_dist_header_finalize(ob, &mut cache, DFLAGS, &mut 0);
            let bytes = ob.to_vec();
            let hdr = if i == 0 { 18 + 5 } else { 18 };
            stream.extend_from_slice(&bytes[hdr..]);
        }
        let plain = crate::encode_term_to_binary(msg).unwrap();
        assert_eq!(&stream[6..], &plain[1..]);
        drop(obufs);
        assert_eq!(owner.ref_count().unwrap(), refs);
    }

    #[test]
    fn writable_binaries_are_pinned_and_referenced() {
        // ERTS_PIN_BITSTRING: a writable binary (a private-append target) is pinned by the
        // encode, then referenced in the I/O vector like any refc binary.
        let mut heap = VecHeap::new();
        let data: Vec<u8> = (0..4000).map(|i| (i * 11) as u8).collect();
        let bin = TermBuilder::new(&mut heap)
            .writable_binary(&data, data.len() * 8, 8192)
            .unwrap();
        assert!(
            crate::raw::refc_payload(bin).is_none(),
            "writable before the encode"
        );
        let ctl = ctl(&mut heap, "a");
        let map = ErtsAtomCacheMap::default();
        let mut enc = DsigEncode::new(ctl, Some(bin), DFLAGS, 3, node);
        let mut reds = CONTEXT_REDS;
        assert_eq!(
            enc.step(Some(&map), &mut reds, true).unwrap(),
            DsigEncodeResult::Send
        );
        let mut obufs = enc.take_obufs();
        assert_eq!(obufs.len(), 1);
        assert!(
            crate::raw::refc_payload(bin).is_some(),
            "pinned by the encode"
        );
        // The control message and binary header, then the binary itself.
        let elements = obufs[0].data_elements();
        assert_eq!(elements.len(), 3);
        assert_eq!(elements[2].1.len(), data.len());
        let mut cache = ErtsAtomCache::default();
        erts_encode_ext_dist_header_finalize(&mut obufs[0], &mut cache, DFLAGS, &mut 0);
        let bytes = obufs[0].to_vec();
        let plain = crate::encode_term_to_binary(bin).unwrap();
        assert_eq!(&bytes[7 + 6..], &plain[1..]);
    }

    #[test]
    fn referenced_bitstrings_copy_their_trailing_bits() {
        let mut heap = VecHeap::new();
        let data: Vec<u8> = (0..1001).map(|i| (i * 13) as u8).collect();
        let bits = 1000 * 8 + 3;
        let msg = TermBuilder::new(&mut heap).bitstring(&data, bits).unwrap();
        let referenced = crate::raw::refc_payload(msg).is_some();
        let ctl = ctl(&mut heap, "a");
        let map = ErtsAtomCacheMap::default();
        let mut enc = DsigEncode::new(ctl, Some(msg), DFLAGS, 3, node);
        let mut reds = CONTEXT_REDS;
        assert_eq!(
            enc.step(Some(&map), &mut reds, true).unwrap(),
            DsigEncodeResult::Send
        );
        let mut obufs = enc.take_obufs();
        assert_eq!(obufs.len(), 1);
        if referenced {
            // The control message, the payload up to the trailing-bits byte, the binary,
            // then that byte.
            let elements = obufs[0].data_elements();
            assert_eq!(elements.len(), 4);
            assert_eq!(elements[2].1.len(), 1000);
            assert_eq!(elements[3].1.len(), 1);
        }
        let mut cache = ErtsAtomCache::default();
        erts_encode_ext_dist_header_finalize(&mut obufs[0], &mut cache, DFLAGS, &mut 0);
        let bytes = obufs[0].to_vec();
        let plain = crate::encode_term_to_binary(msg).unwrap();
        // Header with one new atom (7 bytes), the control message {2, a} (6 bytes).
        assert_eq!(&bytes[7 + 6..], &plain[1..]);
    }

    #[test]
    fn a_trapping_encode_yields_and_resumes() {
        let mut heap = VecHeap::new();
        let elems: Vec<Term> = (0..20_000).map(|i| Term::small(i).unwrap()).collect();
        let msg = TermBuilder::new(&mut heap).list_from_slice(&elems).unwrap();
        let ctl = ctl(&mut heap, "a");
        let map = ErtsAtomCacheMap::default();
        let mut enc = DsigEncode::new(ctl, Some(msg), DFLAGS, 1, node);
        let mut continues = 0;
        loop {
            let mut reds = 1000;
            match enc.step(Some(&map), &mut reds, false).unwrap() {
                DsigEncodeResult::Send => break,
                DsigEncodeResult::Continue => {
                    continues += 1;
                    enc.export(Some(&map));
                    // Another signal reuses the shared map meanwhile.
                    map.reset();
                }
                DsigEncodeResult::TooLarge => panic!("too large"),
            }
        }
        assert!(continues > 2, "{continues}");
        let mut cache = ErtsAtomCache::default();
        let trapped: Vec<Vec<u8>> = enc
            .take_obufs()
            .into_iter()
            .map(|mut ob| {
                erts_encode_ext_dist_header_finalize(&mut ob, &mut cache, DFLAGS, &mut 0);
                ob.to_vec()
            })
            .collect();
        assert_eq!(trapped.len(), 2);
        let mut cache2 = ErtsAtomCache::default();
        let direct = encode_signal(ctl, Some(msg), DFLAGS, &mut cache2, &map, 1);
        assert_eq!(trapped, direct);
    }
}
