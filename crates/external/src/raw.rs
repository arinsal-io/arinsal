//! Pointer writes for the final, pre-sized ETF output buffer, and the Binary behind a
//! referenced dist payload.
//!
//! Port of erts/emulator/beam/external.c (`enc_term_int`), OTP-29.1.1. The size pass computed
//! the required output length before `enc_term_int` writes through its byte pointer.

#[inline(always)]
pub(crate) fn write_byte_validated(output: &mut [u8], at: usize, value: u8) {
    debug_assert!(at < output.len());
    // SAFETY: the encode-size pass reserved the full output and the encoder cursor stays in it.
    unsafe { output.as_mut_ptr().add(at).write(value) }
}

#[inline(always)]
pub(crate) fn write_validated(output: &mut [u8], at: usize, bytes: &[u8]) {
    debug_assert!(at <= output.len() && bytes.len() <= output.len() - at);
    // SAFETY: the encode-size pass reserved this range; immutable source bytes cannot alias the
    // exclusively borrowed destination slice.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output.as_mut_ptr().add(at), bytes.len())
    }
}

#[inline(always)]
pub(crate) fn zero_validated(output: &mut [u8], at: usize, len: usize) {
    debug_assert!(at <= output.len() && len <= output.len() - at);
    // SAFETY: the encode-size pass reserved this range in the final output buffer.
    unsafe { std::ptr::write_bytes(output.as_mut_ptr().add(at), 0, len) }
}

#[inline(always)]
pub(crate) fn mask_validated(output: &mut [u8], at: usize, mask: u8) {
    debug_assert!(at < output.len());
    // SAFETY: the encoder masks the final byte it has just written inside the reserved output.
    unsafe {
        let byte = output.as_mut_ptr().add(at);
        byte.write(byte.read() & mask);
    }
}

/// The refc Binary that holds the payload of a byte-aligned off-heap bitstring and the
/// payload's byte offset in it, with one reference taken (`erts_refc_inc` of
/// `store_in_vec_aux`). `None` when the payload is not referenceable: on heap, not
/// byte-aligned, a NIF resource binary, or a binary still writable. The encoder pins the
/// term's writable binary first (`ERTS_PIN_BITSTRING`), so only a binary whose writer is not
/// this term stays writable.
// Port of erts/emulator/beam/external.c (enc_term_int, BITSTRING_DEF: ERTS_PIN_BITSTRING
// and `store_in_vec(ctx, ep, br->val, obj, base, BYTE_SIZE(size))`), OTP-29.1.1.
pub(crate) fn refc_payload(
    term: arinsal_term::Term,
) -> Option<(arinsal_alloc::raw::OwnedBinaryRef, usize)> {
    let arinsal_term::BinaryOwner::Binary(owner) = arinsal_term::binary_owner(term)? else {
        return None;
    };
    if owner.is_writable() {
        return None;
    }
    // SAFETY: the encoded term and its BinRef are live for the encode; the view does not
    // escape this function.
    let view = unsafe { term.binary_ref() }?;
    if !view.is_off_heap() || !view.start_bit().is_multiple_of(8) {
        return None;
    }
    let base = view.bytes().as_ptr() as usize + view.start_bit() / 8;
    let offset = base.checked_sub(owner.payload_ptr() as usize)?;
    Some((owner, offset))
}

/// `SysIOVec` (erl_driver.h): `iov_base`, `iov_len`.
pub(crate) const SYSIOVEC_SZ: usize = 16;
/// `ErlDrvBinary *` (erl_driver.h): one `binv` slot.
pub(crate) const BINV_SZ: usize = 8;

/// Where the `iov[vlen]` and `binv[vlen]` arrays lie among the records in front of the data
/// of a signal's driver Binary (`erts_ttb_iov_init` on the memory of `alloc_dist_obufs`).
/// The slots are written only through [`ObufMeta`] and [`ObufBin`], which keep the slot
/// invariant: `iov_len == 0`, or `iov_base .. iov_base + iov_len` lies inside the payload
/// of a live Binary — the signal's own (whose `binv` slot is null until
/// [`ObufBlock::into_shared`]) or the one whose counted reference the `binv` slot holds.
#[derive(Clone, Copy, Debug)]
struct IovArrays {
    iov: usize,
    vlen: usize,
}

impl IovArrays {
    fn binv(self) -> usize {
        self.iov + SYSIOVEC_SZ * self.vlen
    }

    fn end(self) -> usize {
        self.binv() + BINV_SZ * self.vlen
    }

    /// Panics when `at .. at + len` touches the arrays: they are written only through the
    /// typed slot operations.
    fn check_outside(self, at: usize, len: usize) {
        assert!(
            len == 0 || at + len <= self.iov || self.end() <= at,
            "a record write stays outside the iov/binv arrays"
        );
    }

    /// The payload offsets of `iov[ix].iov_base`, `iov[ix].iov_len` and `binv[ix]`.
    fn slot(self, ix: usize) -> (usize, usize, usize) {
        assert!(ix < self.vlen, "the size pass counted the I/O vector");
        let at = self.iov + SYSIOVEC_SZ * ix;
        (at, at + 8, self.binv() + BINV_SZ * ix)
    }
}

fn get_word(bytes: &[u8], at: usize) -> usize {
    u64::from_ne_bytes(bytes[at..at + 8].try_into().expect("8 bytes")) as usize
}

fn put_word(bytes: &mut [u8], at: usize, value: usize) {
    bytes[at..at + 8].copy_from_slice(&(value as u64).to_ne_bytes());
}

/// Takes back the counted reference a `binv` slot holds (no refcount change).
///
/// # Safety
/// `header` was stored in a `binv` slot by this module from a reference whose count the
/// slot kept (`std::mem::forget` of a clone), and the slot is cleared before the count is
/// used, so the Binary is live and the count is taken back once.
// Port of erts/emulator/beam/dist.c (free_dist_obuf: `driver_free_binary(binv[i])`, and the
// transfer of `binv` to the port in dist_port_commandv), OTP-29.1.1.
unsafe fn binv_reclaim(header: usize) -> arinsal_alloc::raw::OwnedBinaryRef {
    debug_assert!(header != 0 && header.is_multiple_of(8));
    // SAFETY: by the contract `header` is the header of a live Binary; four words cover the
    // header to read the capacity.
    let prefix = unsafe { arinsal_alloc::raw::BinaryView::from_header(header as *const u64, 4) };
    let capacity = prefix.capacity().expect("a binv Binary has a header");
    let words = 4 + capacity.div_ceil(8);
    // SAFETY: as above; `words` covers the header and the payload allocation.
    let view = unsafe { arinsal_alloc::raw::BinaryView::from_header(header as *const u64, words) };
    arinsal_alloc::typed::BinaryBlock::borrow_from_view(view)
        .expect("a binv Binary has allocator metadata")
        .into_reference()
}

/// The counted reference `binv[ix]` holds, as a slot value (the clone's count is kept by the
/// slot).
fn binv_count(bin: &arinsal_alloc::raw::OwnedBinaryRef) -> usize {
    let owned = bin
        .try_clone()
        .expect("a referenced Binary is live while it is referenced");
    let header = owned.header_ptr() as usize;
    std::mem::forget(owned);
    header
}

/// Releases every counted reference of the slots in `meta` and clears them.
fn release_slots(meta: &mut [u8], arrays: IovArrays) {
    for ix in 0..arrays.vlen {
        let (base, len, binv) = arrays.slot(ix);
        let header = get_word(meta, binv);
        put_word(meta, base, 0);
        put_word(meta, len, 0);
        put_word(meta, binv, 0);
        if header != 0 {
            // SAFETY: a non-null slot was set by binv_count / ObufBin::set_ref (slot
            // invariant) and is cleared above.
            drop(unsafe { binv_reclaim(header) });
        }
    }
}

/// The driver Binary of a signal's output buffers from `alloc_dist_obufs` until `FIN`, owned
/// by the encode (refcount 1): the records (`obuf[]`, `iov[]`, `binv[]`, the fragments'
/// `ErlIOVec`s) at `0..data_off`, the data after. Dropped before `FIN`, it releases the
/// references its slots took (erts_dsend_context_dtor's free_dist_obuf).
// Port of erts/emulator/beam/dist.c (alloc_dist_obufs), external.c (erts_ttb_iov_init),
// OTP-29.1.1.
pub(crate) struct ObufBlock {
    block: Option<arinsal_alloc::typed::BinaryBlock>,
    arrays: IovArrays,
    data_off: usize,
}

impl ObufBlock {
    /// `erts_bin_drv_alloc(size)` with the arrays of `vlen` slots at payload offset `iov`,
    /// cleared, and the data from `data_off`.
    pub(crate) fn alloc(size: usize, iov: usize, vlen: usize, data_off: usize) -> Self {
        let arrays = IovArrays { iov, vlen };
        assert!(arrays.end() <= data_off && data_off <= size);
        // erts_bin_drv_alloc never fails (it aborts on out of memory).
        let mut block = arinsal_alloc::typed::BinaryBlock::new(size, 0, size)
            .expect("dist output buffer allocation");
        block.bytes_mut_unique().expect("a fresh Binary is unique")[iov..arrays.end()].fill(0);
        Self {
            block: Some(block),
            arrays,
            data_off,
        }
    }

    /// The records and the data, borrowed for one phase of the encode.
    pub(crate) fn split(&mut self) -> (ObufMeta<'_>, &mut [u8]) {
        let payload = self
            .block
            .as_mut()
            .and_then(|block| block.bytes_mut_unique())
            .expect("the buffer is unique until FIN");
        let base = payload.as_ptr() as usize;
        let data = base + self.data_off..base + payload.len();
        let (meta, bin) = payload.split_at_mut(self.data_off);
        (
            ObufMeta {
                meta,
                arrays: self.arrays,
                data,
            },
            bin,
        )
    }

    /// `FIN`: every element of the signal's own buffer gets its `binv` reference
    /// (`binv[i] = bin` with `erts_refc_inc`), and the Binary becomes shared by the output
    /// buffers; the returned reference is the first one.
    pub(crate) fn into_shared(mut self) -> ObufBin {
        let mut block = self.block.take().expect("the buffer is owned until FIN");
        let header = block.view().header_ptr() as usize;
        let payload = block
            .bytes_mut_unique()
            .expect("the buffer is unique until FIN");
        let base = payload.as_ptr() as usize;
        let data = self.data_off..payload.len();
        let mut refs = 0;
        for ix in 0..self.arrays.vlen {
            let (_, len, binv) = self.arrays.slot(ix);
            if get_word(payload, binv) == 0 && get_word(payload, len) != 0 {
                put_word(payload, binv, header);
                refs += 1;
            }
        }
        let bin = block.into_reference();
        debug_assert_eq!(bin.payload_ptr() as usize, base);
        for _ in 0..refs {
            // erts_refc_inc for each slot set above; the slot keeps the count.
            std::mem::forget(
                bin.try_clone()
                    .expect("the signal's buffer is live while referenced"),
            );
        }
        ObufBin {
            bin,
            arrays: self.arrays,
            data,
        }
    }
}

impl Drop for ObufBlock {
    fn drop(&mut self) {
        if let Some(payload) = self
            .block
            .as_mut()
            .and_then(|block| block.bytes_mut_unique())
        {
            release_slots(&mut payload[..self.data_off], self.arrays);
        }
    }
}

/// The records of an [`ObufBlock`] during one phase of the encode: the `obuf`/`ErlIOVec`
/// words freely, the `iov`/`binv` slots only as elements whose range is checked.
// Port of erts/emulator/beam/external.c (store_in_vec_aux writes into ctx->iov/binv),
// OTP-29.1.1.
pub(crate) struct ObufMeta<'a> {
    meta: &'a mut [u8],
    arrays: IovArrays,
    /// The addresses of the data of the signal's own buffer.
    data: std::ops::Range<usize>,
}

impl ObufMeta<'_> {
    /// The same records for a shorter borrow.
    pub(crate) fn reborrow(&mut self) -> ObufMeta<'_> {
        ObufMeta {
            meta: self.meta,
            arrays: self.arrays,
            data: self.data.clone(),
        }
    }

    /// A record word at payload offset `at`.
    pub(crate) fn word(&self, at: usize) -> usize {
        get_word(self.meta, at)
    }

    /// Writes a record word outside the arrays.
    pub(crate) fn set_word(&mut self, at: usize, value: usize) {
        self.arrays.check_outside(at, 8);
        put_word(self.meta, at, value);
    }

    /// The address of the first data byte.
    pub(crate) fn data_base(&self) -> usize {
        self.data.start
    }

    /// `iov[ix].iov_len`.
    pub(crate) fn iov_len(&self, ix: usize) -> usize {
        get_word(self.meta, self.arrays.slot(ix).1)
    }

    /// `iov[ix]` = `len` bytes at address `base` of the signal's own data, `binv[ix]` null
    /// until FIN (the reference is taken by [`ObufBlock::into_shared`]).
    pub(crate) fn set_own(&mut self, ix: usize, base: usize, len: usize) {
        let (b, l, binv) = self.arrays.slot(ix);
        assert_eq!(
            get_word(self.meta, binv),
            0,
            "an own element holds no count"
        );
        assert!(
            len == 0 || (self.data.start <= base && base + len <= self.data.end),
            "an own element lies in the signal's data"
        );
        put_word(self.meta, b, base);
        put_word(self.meta, l, len);
    }

    /// `iov[ix]` = `len` bytes at `offset` of `bin`, `binv[ix]` = `bin` with
    /// `erts_refc_inc`.
    pub(crate) fn set_ref(
        &mut self,
        ix: usize,
        bin: &arinsal_alloc::raw::OwnedBinaryRef,
        offset: usize,
        len: usize,
    ) {
        assert!(
            bin.payload(offset, len).is_some(),
            "a referenced element lies inside its Binary"
        );
        let (b, l, binv) = self.arrays.slot(ix);
        assert_eq!(get_word(self.meta, binv), 0, "the slot is free");
        put_word(self.meta, b, bin.payload_ptr() as usize + offset);
        put_word(self.meta, l, len);
        put_word(self.meta, binv, binv_count(bin));
    }

    /// Releases the references the slots hold (an encode that failed).
    pub(crate) fn release_slots(&mut self) {
        release_slots(self.meta, self.arrays);
    }
}

/// One reference to the driver Binary of a signal's output buffers after `FIN`
/// (`obuf->bin`), shared by every fragment. Every non-empty slot holds a counted `binv`
/// reference.
// Port of erts/emulator/beam/erl_node_tables.h (ErtsDistOutputBuf.bin), dist.c
// (free_dist_obuf), OTP-29.1.1.
pub(crate) struct ObufBin {
    bin: arinsal_alloc::raw::OwnedBinaryRef,
    arrays: IovArrays,
    /// The payload offsets of the data.
    data: std::ops::Range<usize>,
}

impl ObufBin {
    /// Another reference for the next fragment (`erts_refc_inc`).
    pub(crate) fn try_clone(&self) -> Option<Self> {
        Some(Self {
            bin: self.bin.try_clone()?,
            arrays: self.arrays,
            data: self.data.clone(),
        })
    }

    /// The payload offset of `iov[0]` (`ctx->iov`).
    pub(crate) fn iov_offset(&self) -> usize {
        self.arrays.iov
    }

    /// The payload offset of an address in the data.
    pub(crate) fn data_offset(&self, addr: usize) -> usize {
        let offset = addr - self.bin.payload_ptr() as usize;
        assert!(self.data.contains(&offset) || offset == self.data.end);
        offset
    }

    /// A record word at payload offset `at`.
    pub(crate) fn word(&self, at: usize) -> usize {
        get_word(
            self.bin
                .payload(at, 8)
                .expect("an output buffer record lies inside its Binary"),
            0,
        )
    }

    /// Writes a record word outside the arrays.
    pub(crate) fn set_word(&mut self, at: usize, value: usize) {
        self.arrays.check_outside(at, 8);
        put_word(self.bytes_mut(at, 8), 0, value);
    }

    /// `len` bytes at payload offset `offset` written by the holder of one output buffer:
    /// `erts_encode_ext_dist_header_finalize` rewrites the buffer's dist header and its
    /// `ErlIOVec` in place although every fragment references the same Binary. Panics when
    /// the range lies outside the payload or touches the arrays.
    // Port of erts/emulator/beam/external.c (erts_encode_ext_dist_header_finalize: the header
    // is written backwards into `ob->eiov->iov[1]`), OTP-29.1.1.
    pub(crate) fn bytes_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        self.arrays.check_outside(offset, len);
        self.payload_mut(offset, len)
    }

    /// `len` bytes at payload offset `offset`, records or slots of the buffer the caller
    /// holds.
    fn payload_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        assert!(
            self.bin.payload(offset, len).is_some(),
            "an output buffer record lies inside its Binary"
        );
        let ptr = self.bin.payload_ptr().cast_mut();
        // SAFETY: the range is inside the live payload (checked above, the held reference
        // keeps it allocated). The Binary is a driver Binary, never writable, so it does not
        // move. Each range written belongs to one output buffer (its header, its ErlIOVec
        // record and its iov/binv slots); the caller holds that buffer exclusively (`&mut`),
        // and the other fragments of the signal only read and write their own disjoint
        // ranges.
        unsafe { std::slice::from_raw_parts_mut(ptr.add(offset), len) }
    }

    /// The bytes of `iov[ix]`, borrowed for as long as this reference (which keeps the
    /// slot's `binv` count, released only through `&mut self`).
    pub(crate) fn iov_bytes(&self, ix: usize) -> &[u8] {
        let (b, l, _) = self.arrays.slot(ix);
        let len = self.word(l);
        if len == 0 {
            return &[];
        }
        let base = self.word(b);
        // SAFETY: slot invariant: a non-empty slot was written by this module with a range
        // checked inside the payload of the Binary its `binv` slot holds a counted reference
        // to (or of this Binary, which `self` keeps). The count is released only by
        // `take_ref` through `&mut self`, so the bytes stay allocated for the borrow; a
        // driver or pinned refc Binary is not written in the referenced range.
        unsafe { std::slice::from_raw_parts(base as *const u8, len) }
    }

    /// `iov[ix]` with the reference `binv[ix]` holds, taken out of the slot (the slot is
    /// cleared): the Binary, the payload offset and the length.
    pub(crate) fn take_ref(
        &mut self,
        ix: usize,
    ) -> Option<(arinsal_alloc::raw::OwnedBinaryRef, usize, usize)> {
        let (b, l, binv) = self.arrays.slot(ix);
        let header = self.word(binv);
        let base = self.word(b);
        let len = self.word(l);
        self.payload_mut(b, SYSIOVEC_SZ).fill(0);
        self.payload_mut(binv, BINV_SZ).fill(0);
        if header == 0 {
            debug_assert_eq!(len, 0);
            return None;
        }
        // SAFETY: a non-null slot holds a count set by this module (slot invariant); it was
        // cleared above.
        let bin = unsafe { binv_reclaim(header) };
        let offset = base - bin.payload_ptr() as usize;
        Some((bin, offset, len))
    }

    /// `iov[ix]` = `len` bytes at payload offset `offset` of this Binary; the slot already
    /// holds its reference to this Binary (the header of `iov[1]` moved by finalize).
    pub(crate) fn set_own(&mut self, ix: usize, offset: usize, len: usize) {
        let (b, l, binv) = self.arrays.slot(ix);
        assert_eq!(
            self.word(binv),
            self.bin.header_ptr() as usize,
            "the slot holds its reference to this Binary"
        );
        assert!(len != 0 && self.data.start <= offset && offset + len <= self.data.end);
        let base = self.bin.payload_ptr() as usize + offset;
        put_word(self.payload_mut(b, 8), 0, base);
        put_word(self.payload_mut(l, 8), 0, len);
    }

    /// The Binary `binv[ix]` references (header address) and the element's payload range in
    /// it.
    #[cfg(test)]
    pub(crate) fn slot_parts(&self, ix: usize) -> (usize, std::ops::Range<usize>) {
        let (b, l, binv) = self.arrays.slot(ix);
        let header = self.word(binv);
        let start = self.word(b) - (header + 4 * 8);
        (header, start..start + self.word(l))
    }
}
