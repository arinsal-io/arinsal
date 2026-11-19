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

use crate::{ByteOutput, EncodeError, EncodeOpts, TtbContext};

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
    // The walk counts the VERSION_MAGIC of a term_to_binary; the dist encode counted its own.
    sz += walk.output_size().expect("size pass done") - 1;
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

/// One data element of a fragment's I/O vector while the signal is encoded: a range of the
/// signal's own buffer (`ctx->result_bin`, referenced once the buffer is complete) or a
/// range of a referenced binary.
enum EncIov {
    Common(std::ops::Range<usize>),
    Binary(DistIov),
}

/// One `fragment_eiovs[ix]`: the data the fragment carries (`iov[2..]`; `iov[0]` and
/// `iov[1]` are the driver and dist headers).
#[derive(Default)]
struct FragmentEiov {
    size: usize,
    iov: Vec<EncIov>,
}

/// `TTBEncodeContext` of a dist encode.
// Port of erts/emulator/beam/dist.h (TTBEncodeContext, ERTS_INIT_TTBEncodeContext,
// erts_ttb_iov_init), OTP-29.1.1.
pub(crate) struct TtbDistEncodeContext {
    /// `wstack.wstart != NULL`: the walk of the term being encoded.
    walk: Option<Box<TtbContext>>,
    /// `cptr`: the start of the bytes not yet stored in the I/O vector.
    cptr: usize,
    /// `vlen`: I/O vector elements used so far.
    vlen: usize,
    /// `frag_ix`, -1 before the first fragment.
    frag_ix: isize,
    fragment_size: usize,
    fragment_eiovs: Vec<FragmentEiov>,
    /// `payload_ixp` of a pending-connection encode.
    payload_ixp: Option<usize>,
    /// Where the flattened output buffer starts (`dhdrp`): the payload ix of a
    /// pending-connection encode is the payload's offset from there.
    dhdrp: usize,
    /// Bytes of referenced binaries stored so far: the flattened buffer holds them too.
    referenced: usize,
    node_source: fn() -> (Atom, u32),
}

impl TtbDistEncodeContext {
    /// `ERTS_INIT_TTBEncodeContext` + `erts_ttb_iov_init`.
    fn new(fragments: usize, fragment_size: usize, node_source: fn() -> (Atom, u32)) -> Self {
        Self {
            node_source,
            walk: None,
            cptr: 0,
            vlen: 0,
            frag_ix: -1,
            fragment_size,
            fragment_eiovs: (0..fragments).map(|_| FragmentEiov::default()).collect(),
            payload_ixp: None,
            dhdrp: 0,
            referenced: 0,
        }
    }

    /// `store_in_vec`: the bytes of the signal's buffer from `cptr` up to `ep`, then the
    /// referenced binary `refc_binary` (`len` bytes at `offset`), go into the fragments' I/O
    /// vectors.
    // Port of erts/emulator/beam/external.c (store_in_vec), OTP-29.1.1.
    pub(crate) fn store_in_vec(
        &mut self,
        ep: usize,
        refc_binary: Option<(arinsal_alloc::raw::OwnedBinaryRef, usize, usize)>,
    ) {
        let cp = self.cptr;
        if cp != ep {
            // Save data in the common binary.
            self.store_in_vec_aux(None, cp, ep - cp);
            self.cptr = ep;
        }
        if let Some((bin, offset, len)) = refc_binary {
            // Save the off-heap binary.
            self.referenced += len;
            self.store_in_vec_aux(Some(&bin), offset, len);
        }
    }

    /// `store_in_vec_aux`: `len` bytes at `ptr` of `bin` (`None`: the signal's buffer) go
    /// into the current fragment, a new fragment starting whenever one reaches
    /// `fragment_size`; each element is at most `MAX_SYSIOVEC_IOVLEN` long and holds its own
    /// reference to its binary (`erts_refc_inc`).
    // Port of erts/emulator/beam/external.c (store_in_vec_aux), OTP-29.1.1.
    fn store_in_vec_aux(
        &mut self,
        bin: Option<&arinsal_alloc::raw::OwnedBinaryRef>,
        mut ptr: usize,
        mut len: usize,
    ) {
        let mut iov_len;
        if self.frag_ix >= 0 {
            let feiov = &self.fragment_eiovs[self.frag_ix as usize];
            if feiov.size != self.fragment_size {
                // Current fragment not full yet.
                iov_len = (self.fragment_size - feiov.size).min(len);
                self.store_iov_data(bin, &mut ptr, &mut len, iov_len);
            }
        }
        while len != 0 {
            // Start a new fragment: entries for the driver and dist headers.
            self.frag_ix += 1;
            self.vlen += 2;
            iov_len = len.min(self.fragment_size);
            self.store_iov_data(bin, &mut ptr, &mut len, iov_len);
        }
    }

    fn store_iov_data(
        &mut self,
        bin: Option<&arinsal_alloc::raw::OwnedBinaryRef>,
        ptr: &mut usize,
        len: &mut usize,
        mut iov_len: usize,
    ) {
        let feiov = &mut self.fragment_eiovs[self.frag_ix as usize];
        loop {
            let iov_len_left = iov_len.saturating_sub(crate::MAX_SYSIOVEC_IOVLEN);
            iov_len -= iov_len_left;
            let range = *ptr..*ptr + iov_len;
            feiov.iov.push(match bin {
                None => EncIov::Common(range),
                Some(bin) => EncIov::Binary(DistIov {
                    bin: bin
                        .try_clone()
                        .expect("a referenced Binary is live while it is referenced"),
                    range,
                }),
            });
            feiov.size += iov_len;
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
        if flags & DFLAG_PENDING_CONNECT != 0 && ctx.vlen != 0 {
            // We potentially need a version magic on the payload... erts leaves the byte out
            // of the I/O vector (`cptr` moves past it); the flattened buffer of the transcode
            // keeps it, so the payload ix is the payload's offset in that buffer.
            *ext += 1;
            let payload_ix = (*ext - ctx.dhdrp + ctx.referenced) as u32;
            let at = ctx.payload_ixp.expect("pending header set up");
            buf[at..at + 4].copy_from_slice(&payload_ix.to_be_bytes());
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
    out.iov = Some(&mut *ctx);
    let (done, consumed) = crate::enc_term_int(&mut walk, acmp, budget, &mut out, 0)?;
    if out.failed() {
        return Err(EncodeError::SystemLimit);
    }
    *ext = out.len();
    *reds -= consumed as i64;
    if done {
        ctx.store_in_vec(*ext, None);
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

/// One element of an output buffer's I/O vector, `iov[i]` with its `binv[i]`: `range` of
/// the payload of a Binary this element holds one reference to (the signal's own buffer or
/// a refc binary of the encoded term).
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
/// All fragments of a signal reference the signal's buffer (the `erts_bin_drv_alloc` of
/// `alloc_dist_obufs`); `hdr` is `eiov->iov[1]`, the dist header, and `iov` the data
/// (`eiov->iov[2..]`), which also references the refc binaries of the encoded term.
// Port of erts/emulator/beam/dist.h (ErtsDistOutputBuf), OTP-29.1.1.
#[derive(Debug)]
pub struct ErtsDistOutputBuf {
    hdr: DistIov,
    /// The header as `erts_encode_ext_dist_header_finalize` rewrote it for the wire. The
    /// shared buffer is immutable, so the rewritten header is kept here instead of in place.
    wire_hdr: Option<Vec<u8>>,
    iov: Vec<DistIov>,
}

impl ErtsDistOutputBuf {
    /// `size_obuf`: the bytes this buffer puts on the wire.
    pub fn size(&self) -> usize {
        self.header().len() + self.iov.iter().map(|iov| iov.range.len()).sum::<usize>()
    }

    fn header(&self) -> &[u8] {
        match &self.wire_hdr {
            Some(hdr) => hdr,
            None => self.hdr.bytes(),
        }
    }

    /// The I/O vector the buffer is output as (`eiov->iov[1..]`): the header, then the data.
    /// An empty vector is a tick (a signal transcoded away).
    pub fn iovec(&self) -> Vec<&[u8]> {
        let header = self.header();
        std::iter::once(header)
            .chain(self.iov.iter().map(DistIov::bytes))
            .filter(|part| !part.is_empty())
            .collect()
    }

    /// The I/O vector for output: the wire header and the data elements, each holding its
    /// Binary reference. An empty header and no data is a tick.
    pub fn into_iov(self) -> (Vec<u8>, Vec<DistIov>) {
        let header = match self.wire_hdr {
            Some(hdr) => hdr,
            None => self.hdr.bytes().to_vec(),
        };
        (header, self.iov)
    }

    /// The bytes of [`Self::iovec`] in one buffer.
    pub fn to_vec(&self) -> Vec<u8> {
        self.iovec().concat()
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
/// internal atom cache instructions of a dist header are turned into the wire header,
/// updating the connection's output atom `cache`. `reds` is decremented by the reductions
/// the transcoding uses.
// Port of erts/emulator/beam/external.c (erts_encode_ext_dist_header_finalize), OTP-29.1.1.
pub fn erts_encode_ext_dist_header_finalize(
    ob: &mut ErtsDistOutputBuf,
    cache: &mut ErtsAtomCache,
    dflags: u64,
    reds: &mut i64,
) -> DistHeaderFinalize {
    let ep = ob.hdr.bytes();
    if ob.wire_hdr.is_some() || ep.is_empty() {
        return DistHeaderFinalize::Done;
    }
    if ep[0] == HOPEFUL_DATA {
        let mut flat = ob.to_vec();
        let result = transcode_dist_obuf(&mut flat, dflags, reds);
        ob.wire_hdr = Some(flat);
        ob.iov.clear();
        return result;
    }
    if ep[0] == PASS_THROUGH || ep[1] == DIST_FRAG_CONT {
        return DistHeaderFinalize::Done;
    }
    let mut ip = 2;
    let frag = (ep[1] == DIST_FRAG_HEADER).then(|| {
        let ids = (&ep[2..10], &ep[10..18]);
        ip += 16;
        ids
    });
    let dist_hdr_flags = ep[ip];
    let long_atoms = dist_hdr_flags & ERTS_DIST_HDR_LONG_ATOMS_FLG != 0;
    let ci = ep[ip + 1] as usize;
    ip += 2;
    let table = global_atoms();
    let mut wire = Vec::with_capacity(ob.hdr.range.len());
    wire.push(VERSION_MAGIC);
    match frag {
        Some((seq_id, frag_id)) => {
            wire.push(DIST_FRAG_HEADER);
            wire.extend_from_slice(seq_id);
            wire.extend_from_slice(frag_id);
        }
        None => wire.push(DIST_HEADER),
    }
    wire.push(ci as u8);
    if ci > 0 {
        let flags_at = wire.len();
        wire.resize(flags_at + erts_dist_hdr_atom_cache_flag_bytes(ci), 0);
        let mut refs = Vec::with_capacity(ci * 2);
        for iix in 0..ci {
            let instr = &ep[ip + 6 * iix..ip + 6 * iix + 6];
            let cix = u16::from_be_bytes([instr[0], instr[1]]) as usize;
            let atom = Atom(u32::from_be_bytes([instr[2], instr[3], instr[4], instr[5]]));
            let new = cache.out_arr[cix] != Some(atom);
            refs.push(cix as u8);
            if new {
                cache.out_arr[cix] = Some(atom);
                let name = table.text(atom).unwrap_or_default();
                if long_atoms {
                    refs.extend_from_slice(&(name.len() as u16).to_be_bytes());
                } else {
                    refs.push(name.len() as u8);
                }
                refs.extend_from_slice(name.as_bytes());
            }
            let nibble = (u8::from(new) << 3) | ((cix >> 8) as u8 & 7);
            wire[flags_at + iix / 2] |= nibble << ((iix % 2) * 4);
        }
        wire[flags_at + ci / 2] |= dist_hdr_flags << ((ci % 2) * 4);
        wire.extend_from_slice(&refs);
    }
    ob.wire_hdr = Some(wire);
    DistHeaderFinalize::Done
}

/// Rewrite a signal encoded toward a pending connection for the flags the connection got:
/// drop what the peer cannot take, rewrite `DOP_ALTACT_SIG_SEND` as the plain operation, and
/// replace the hopeful header by the real one. `ob` is the flattened buffer; its payload ix
/// is the payload's offset in it (erts: the payload's I/O vector index).
// Port of erts/emulator/beam/external.c (transcode_dist_obuf), OTP-29.1.1.
fn transcode_dist_obuf(ob: &mut Vec<u8>, dflags: u64, reds: &mut i64) -> DistHeaderFinalize {
    debug_assert!(ob.len() > HOPEFUL_HDR_SZ);
    let payload_ix = u32::from_be_bytes(ob[13..HOPEFUL_HDR_SZ].try_into().unwrap()) as usize;
    // Control message always begins after the hopeful header.
    let mut ep = HOPEFUL_HDR_SZ;
    let ctl_end = if payload_ix != 0 {
        payload_ix - 1
    } else {
        ob.len()
    };
    let b = |ob: &Vec<u8>, i: usize| ob.get(ep + i).copied().unwrap_or(0);
    debug_assert!(b(ob, 0) == SMALL_TUPLE_EXT || b(ob, 0) == LARGE_TUPLE_EXT);
    let small_op = |ob: &Vec<u8>| {
        (b(ob, 0) == SMALL_TUPLE_EXT && b(ob, 2) == SMALL_INTEGER_EXT).then(|| (b(ob, 1), b(ob, 3)))
    };
    let op = small_op(ob);
    let drop_monitor = !dflags & (DFLAG_DIST_MONITOR | DFLAG_DIST_MONITOR_NAME) != 0
        && matches!(
            op,
            Some((4, DOP_MONITOR_P | DOP_MONITOR_P_EXIT | DOP_DEMONITOR_P))
        );
    let drop_alias = dflags & DFLAG_ALIAS == 0
        && matches!(op, Some((3 | 4, DOP_ALIAS_SEND | DOP_ALIAS_SEND_TT)));
    if drop_monitor || drop_alias {
        // Drop the packet by converting it to an empty (tick) packet.
        ob.clear();
        return DistHeaderFinalize::Done;
    }
    if dflags & DFLAG_SPAWN == 0
        && matches!(
            op,
            Some((6, DOP_SPAWN_REQUEST)) | Some((8, DOP_SPAWN_REQUEST_TT))
        )
    {
        // The receiver does not support distributed spawn: a tick, and the spawning process
        // is told `notsup`.
        let ctl = ob[ep..ctl_end].to_vec();
        ob.clear();
        *reds -= 4;
        return DistHeaderFinalize::SpawnNotSupported(ctl);
    }
    let mut payload_moved_to_control = false;
    if dflags & DFLAG_ALTACT_SIG == 0
        && let Some((tuple_size @ (4 | 5), DOP_ALTACT_SIG_SEND)) = op
    {
        let mut tuple_size = tuple_size;
        // The flags were encoded as a SMALL_INTEGER_EXT; `ptr` is the last byte before
        // SenderPid.
        assert_eq!(b(ob, 4), SMALL_INTEGER_EXT, "Invalid altact msg flags");
        let flags = b(ob, 5);
        let mut ptr = ep + 5;
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
        match dist_op {
            // Drop the signal and send a tick instead.
            0 => {
                ob.clear();
                return DistHeaderFinalize::Done;
            }
            // Drop the flags element, write the new operation, one element less.
            DOP_ALIAS_SEND | DOP_ALIAS_SEND_TT | DOP_SEND_SENDER | DOP_SEND_SENDER_TT
            | DOP_PAYLOAD_EXIT2 | DOP_PAYLOAD_EXIT2_TT => tuple_size -= 1,
            // Reason follows the control message as its last element: same tuple size, and
            // no VERSION_MAGIC before it.
            DOP_EXIT2 | DOP_EXIT2_TT => payload_moved_to_control = true,
            DOP_REG_SEND | DOP_REG_SEND_TT | DOP_SEND | DOP_SEND_TT => {
                ptr += 1;
                let sender_start = ptr;
                assert_eq!(ob[sender_start], NEW_PID_EXT, "Unexpected pid encoding");
                ptr += 1;
                let tag = ob[ptr];
                ptr += 1;
                let n = match tag {
                    ATOM_UTF8_EXT => {
                        let n = u16::from_be_bytes([ob[ptr], ob[ptr + 1]]) as usize;
                        ptr += 2;
                        n
                    }
                    SMALL_ATOM_UTF8_EXT => {
                        let n = ob[ptr] as usize;
                        ptr += 1;
                        n
                    }
                    _ => panic!("Unexpected pid encoding"),
                };
                ptr += n + 4 /* ID */ + 4 /* serial */ + 4 /* creation */;
                // `ptr` is the first byte of ToPid / ToName.
                if dist_op == DOP_SEND || dist_op == DOP_SEND_TT {
                    // Replace SenderPid by the empty atom.
                    ob[ptr - 1] = 0;
                    ob[ptr - 2] = SMALL_ATOM_UTF8_EXT;
                    tuple_size -= 1;
                    ptr -= 3;
                } else {
                    // Move SenderPid two bytes earlier and put the empty atom between it and
                    // ToName.
                    let new_sender_start = sender_start - 2;
                    ob.copy_within(sender_start..ptr, new_sender_start);
                    ob[ptr - 1] = 0;
                    ob[ptr - 2] = SMALL_ATOM_UTF8_EXT;
                    ptr = new_sender_start - 1;
                }
            }
            _ => panic!("Unexpected fallback dist operation"),
        }
        // altact_sig_fallback_common: write the operation and tuple header backwards.
        ob[ptr] = dist_op;
        ob[ptr - 1] = SMALL_INTEGER_EXT;
        ob[ptr - 2] = tuple_size;
        ob[ptr - 3] = SMALL_TUPLE_EXT;
        *reds -= 1;
        ptr -= 3;
        debug_assert!(ptr >= ep);
        ep = ptr;
    }
    // Replace the hopeful data header with the actual header.
    let mut out = Vec::with_capacity(ob.len());
    if dflags & (DFLAG_DIST_HDR_ATOM_CACHE | DFLAG_FRAGMENTS) != 0 {
        // Encoded without atom caching but the receiver expects a dist header: an empty one.
        out.extend_from_slice(&[VERSION_MAGIC, DIST_HEADER, 0]);
        out.extend_from_slice(&ob[ep..ctl_end]);
        if payload_ix != 0 {
            out.extend_from_slice(&ob[payload_ix..]);
        }
    } else {
        out.extend_from_slice(&[PASS_THROUGH, VERSION_MAGIC]);
        out.extend_from_slice(&ob[ep..ctl_end]);
        if payload_ix != 0 {
            if !payload_moved_to_control {
                // Prepend version magic on payload.
                out.push(VERSION_MAGIC);
            }
            out.extend_from_slice(&ob[payload_ix..]);
        }
    }
    *ob = out;
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
    alloced_fragments: usize,
    fragments: usize,
    vlen: isize,
    sc: TtbDistSizeContext,
    ec: Option<TtbDistEncodeContext>,
    /// `ctx->obuf->bin`: the signal's buffer, uniquely owned until `FIN`.
    bin: Option<arinsal_alloc::typed::BinaryBlock>,
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
                    // alloc_dist_obufs: one buffer of the exact size for every fragment.
                    let size = self.dhdr_ext_size
                        + self.data_size
                        + (self.fragments - 1) * ERTS_DIST_FRAGMENT_HEADER_SIZE;
                    // erts_bin_drv_alloc never fails (it aborts on out of memory).
                    let mut block = arinsal_alloc::typed::BinaryBlock::new(size, 0, size)
                        .expect("dist output buffer allocation");
                    let bin = block.bytes_mut_unique().expect("a fresh Binary is unique");
                    let fragment_size = if self.fragments > 1 {
                        ERTS_DIST_FRAGMENT_SIZE
                    } else {
                        usize::MAX
                    };
                    let mut ec =
                        TtbDistEncodeContext::new(self.fragments, fragment_size, self.node_source);
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
                    ec.dhdrp = self.dhdrp;
                    self.dhdr_ext_size = self.extp - self.dhdrp;
                    loop {
                        let mut reds = CONTEXT_REDS;
                        // Encode the control message.
                        let done = erts_encode_dist_ext(
                            self.ctl,
                            bin,
                            &mut self.extp,
                            self.dflags,
                            acmp,
                            &mut ec,
                            &mut self.fragments,
                            &mut reds,
                        )?;
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
                    let bin = self
                        .bin
                        .as_mut()
                        .and_then(|block| block.bytes_mut_unique())
                        .expect("buffer allocated in ALLOC and unique until FIN");
                    let ec = self.ec.as_mut().expect("encode context set up in ALLOC");
                    loop {
                        let mut local = CONTEXT_REDS;
                        let redsp = if no_trap { &mut local } else { &mut *ctx_reds };
                        let done = erts_encode_dist_ext(
                            msg,
                            bin,
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
    /// `DIST_FRAG_CONT` headers after the data, and one output buffer per fragment.
    fn fin(&mut self) {
        let mut block = self.bin.take().expect("buffer allocated in ALLOC");
        let bin = block.bytes_mut_unique().expect("buffer unique until FIN");
        let ec = self.ec.take().expect("encode context set up in ALLOC");
        let mut fid = self.fragments as u64;
        debug_assert!(fid >= 1);
        debug_assert!(self.alloced_fragments >= self.fragments);
        if self.alloced_fragments > 1 {
            // Update the frag_id in the DIST_FRAG_HEADER.
            let at = self.dhdrp + 1 + 1 + 8;
            bin[at..at + 8].copy_from_slice(&(self.fragments as u64).to_be_bytes());
        }
        let mut headers = Vec::with_capacity(self.fragments);
        headers.push(self.dhdrp..self.dhdrp + self.dhdr_ext_size);
        for _ in 1..self.fragments {
            fid -= 1;
            let hdr = erts_encode_ext_dist_header_fragment(bin, &mut self.extp, fid, self.from);
            headers.push(hdr..self.extp);
        }
        debug_assert!(fid == 1);
        let bin = block.into_reference();
        let common = |range| DistIov {
            bin: bin
                .try_clone()
                .expect("the signal's buffer is live while referenced"),
            range,
        };
        // A size pass that over-counted leaves allocated fragments unused; they are dropped.
        self.obufs = headers
            .into_iter()
            .zip(ec.fragment_eiovs)
            .map(|(hdr, feiov)| ErtsDistOutputBuf {
                hdr: common(hdr),
                wire_hdr: None,
                iov: feiov
                    .iov
                    .into_iter()
                    .map(|iov| match iov {
                        EncIov::Common(range) => common(range),
                        EncIov::Binary(iov) => iov,
                    })
                    .collect(),
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
            .flat_map(|ob| ob.iov.iter())
            .filter(|iov| iov.bin.header_ptr() == owner.header_ptr())
            .map(|iov| {
                assert!(iov.range.start >= offset);
                iov.range.len()
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
        assert_eq!(obufs[0].iov.len(), 3);
        assert_eq!(obufs[0].iov[2].range.len(), data.len());
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
            assert_eq!(obufs[0].iov.len(), 4);
            assert_eq!(obufs[0].iov[2].range.len(), 1000);
            assert_eq!(obufs[0].iov[3].range.len(), 1);
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
