//! The `B2TContext` of `binary_to_term` and `binary2term_prepare` / `B2TUncompressChunk`; the
//! `dec_term` and `decoded_size` functions live in `external_dec_term.rs` and
//! `external_dec_size.rs`.
//!
//! Port of erts/emulator/beam/external.c (`B2TContext`, `binary2term_prepare`,
//! `B2TUncompressChunk`, `decoded_size`, `dec_term`, `erts_factory_*` as used by
//! `binary_to_term_int`), OTP-29.1.1. The heap words of the decoded term are written through
//! a `HeapReservation` (the preallocated factory) and the `next` pointer chain of
//! [`arinsal_term::raw::HeapSlotPtr`]; every length is checked against the end of the data by
//! `decoded_size` and by the [`Reader`].

use super::external_dec_size::{B2tSizeState, decoded_size};
use super::external_dec_term::{
    DecodeMap, DecodePending, Reader, decode_direct_step, finish_decode_maps, map_term_build_error,
};
use arinsal_bifs::{BifError, ProcessHeapHandle};
use arinsal_term::{
    BinaryOwner, BinaryRef, HeapReservation, HeapReservationState, OwnedBinaryRef, ProcessHeap,
    Term, TermBuilder, binary_owner, global_atoms,
};
use flate2::{Decompress, FlushDecompress, Status};
use smallvec::SmallVec;

/// `B2T_MAX_DIRECT_UNCOMPRESSED_SIZE`.
// Port of erts/emulator/beam/external.c:1768-1769, OTP-29.1.1.
const B2T_MAX_DIRECT_UNCOMPRESSED_SIZE: usize = 32 * 1024 * 1024;
/// `B2T_MEMCPY_FACTOR`.
// Port of erts/emulator/beam/external.c:1916, OTP-29.1.1.
pub(super) const B2T_MEMCPY_FACTOR: usize = 8;

fn atom_text(term: Term) -> Option<&'static str> {
    global_atoms().text(term.as_atom()?)
}

fn bit_bytes(term: Term) -> Result<(SmallVec<[u8; 64]>, usize), BifError> {
    // SAFETY: the process owns the binary; no writable append occurs in this BIF.
    let view = unsafe { term.binary_ref() }.ok_or(BifError::BADARG)?;
    let mut bytes = SmallVec::new();
    bytes.resize(view.bit_len().div_ceil(8), 0);
    if view.start_bit().is_multiple_of(8) {
        let start = view.start_bit() / 8;
        let len = bytes.len();
        bytes.copy_from_slice(&view.bytes()[start..start + len]);
    } else {
        for (i, byte) in bytes.iter_mut().enumerate() {
            let at = view.start_bit() + i * 8;
            let first = view.bytes()[at / 8];
            let next = view.bytes().get(at / 8 + 1).copied().unwrap_or(0);
            *byte = (first << (at % 8)) | (next >> (8 - at % 8));
        }
    }
    if view.bit_len() % 8 != 0 {
        let mask = 0xff << (8 - view.bit_len() % 8);
        *bytes.last_mut().unwrap() &= mask;
    }
    Ok((bytes, view.bit_len()))
}

/// `B2TState` of external.c without `B2TDecodeFail` and `B2TBadArg`, which are `B2tExit::Fail`;
/// the order matters: `state >= B2TDone` keeps the loop running.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum B2tState {
    Prepare,
    UncompressChunk,
    SizeInit,
    Size,
    DecodeInit,
    Decode,
    Done,
}

#[derive(Default)]
struct DecodeOpts {
    safe: bool,
    used: bool,
}

fn decode_options(term: Option<Term>) -> Result<DecodeOpts, BifError> {
    let mut opts = DecodeOpts::default();
    let Some(mut tail) = term else {
        return Ok(opts);
    };
    while tail != Term::NIL {
        // SAFETY: the option list remains live and stable during the BIF.
        let (head, next) = unsafe { tail.cons_ref() }.ok_or_else(badopt)?;
        tail = next;
        match atom_text(head) {
            Some("safe") => opts.safe = true,
            Some("used") => opts.used = true,
            _ => return Err(badopt()),
        }
    }
    Ok(opts)
}

fn badopt() -> BifError {
    BifError::Badarg {
        cause: Some(Term::atom(arinsal_term::atoms::BADOPT)),
    }
}

enum DecodeInput<'a> {
    Inline(Box<[u8]>),
    Borrowed {
        bytes: &'a [u8],
        term: Term,
        offset: usize,
        len: usize,
    },
    Refc {
        owner: OwnedBinaryRef,
        offset: usize,
        len: usize,
    },
}

fn decode_binary_view(args: &[Term]) -> Result<(Term, BinaryRef<'_>), BifError> {
    let term = *args.first().ok_or(BifError::BADARG)?;
    // SAFETY: the input binary owner is live and stable during the BIF call.
    let view = unsafe { term.binary_ref() }.ok_or(BifError::BADARG)?;
    Ok((term, view))
}

impl DecodeInput<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Inline(bytes) => bytes,
            Self::Borrowed { bytes, .. } => bytes,
            Self::Refc { owner, offset, len } => owner
                .payload(*offset, *len)
                .expect("retained ETF bytes remain within the Binary allocation"),
        }
    }
}

fn decode_input(args: &[Term]) -> Result<DecodeInput<'_>, BifError> {
    let (term, view) = decode_binary_view(args)?;
    if !view.bit_len().is_multiple_of(8) {
        return Err(BifError::BADARG);
    }
    let can_borrow = view.is_refc()
        && view.start_bit().is_multiple_of(8)
        && !arinsal_term::is_writable_binary(term);
    if can_borrow {
        let offset = view.start_bit() / 8;
        let len = view.bit_len() / 8;
        Ok(DecodeInput::Borrowed {
            bytes: &view.bytes()[offset..offset + len],
            term,
            offset,
            len,
        })
    } else {
        Ok(DecodeInput::Inline(
            bit_bytes(term)?.0.into_vec().into_boxed_slice(),
        ))
    }
}

/// `B2TContext`: the state, the reductions left, `trap_bin` once exported, `bif` and `arg[]` (the
/// original call's number of arguments and arguments, which a failure reports) and `b2ts`,
/// `u.uc`, `u.sc`, `u.dc`: the input and its inflate state, the `decoded_size` state and the
/// `dec_term` state (the `next` chain, the `PSTACK` of maps, the factory).
// Port of erts/emulator/beam/external.c (B2TContext), OTP-29.1.1.
pub(crate) struct B2tContext<'a> {
    // B2TContext.
    pub(crate) state: B2tState,
    pub(crate) reds: i64,
    pub(crate) initial_reds: i64,
    pub(crate) size: B2tSizeState,
    pub(crate) result: Term,
    pub(crate) trap_bin: Option<Term>,
    pub(crate) arity: usize,
    pub(crate) arg: [Term; 2],
    // b2ts, u.uc and u.dc of B2TContext.
    input: DecodeInput<'a>,
    plain: Option<SmallVec<[u8; 128]>>,
    decode_at: usize,
    decode_next: Option<arinsal_term::raw::HeapSlotPtr>,
    decode_root: Term,
    decode_root_started: bool,
    // Port of `PSTACK_DECLARE(map_array, 10)` in external.c:4316, OTP-29.1.1.
    decode_maps: SmallVec<[DecodeMap; 10]>,
    pending: Option<DecodePending>,
    internal_nc: bool,
    safe: bool,
    local_node: Option<(arinsal_term::Atom, u32)>,
    used: bool,
    compressed: bool,
    used_prefix: usize,
    input_size: usize,
    input_offset: usize,
    expected_plain: usize,
    decompressor: Option<Decompress>,
    inflate_done: bool,
    heap_words: Option<usize>,
    prepare_charge: usize,
    reservation: Option<HeapReservationState>,
    /// Allocation state before the first decode slice, to undo a failed decode.
    factory_mark: Option<arinsal_term::HeapFactoryMark>,
}

impl<'a> B2tContext<'a> {
    /// Start decoding an ETF binary while borrowing a reference-counted input payload.
    pub(crate) fn new(args: &'a [Term], arity: usize) -> Result<Self, BifError> {
        let opts = decode_options(args.get(1).copied())?;
        let input = decode_input(args)?;
        let bytes = input.bytes();
        if bytes.first() != Some(&131) {
            return Err(BifError::BADARG);
        }
        let (used_prefix, compressed, expected_plain, decompressor) = if bytes.get(1) == Some(&80) {
            if bytes.len() < 6 {
                return Err(BifError::BADARG);
            }
            let size = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
            // Port of erts/emulator/beam/external.c:1770-1779 (binary2term_prepare),
            // OTP-29.1.1. ERTS validates oversized length claims by counting output in
            // 64 KiB chunks before allocating the uncompressed external term.
            if size > B2T_MAX_DIRECT_UNCOMPRESSED_SIZE
                && compressed_uncompressed_size(&bytes[6..])? != size
            {
                return Err(BifError::BADARG);
            }
            (6, true, size, Some(Decompress::new(true)))
        } else {
            (1, false, 0, None)
        };
        let input_size = bytes.len();
        let mut arg = [Term::NIL; 2];
        arg[..arity].copy_from_slice(&args[..arity]);
        Ok(Self {
            state: B2tState::Prepare,
            reds: 0,
            initial_reds: 0,
            size: B2tSizeState::default(),
            result: Term::NIL,
            trap_bin: None,
            arity,
            arg,
            input,
            // Port of the compressed-input arm of B2TContext.u (binary_to_term_int),
            // erts/emulator/beam/external.c, OTP-29.1.1: uncompressed input does not carry
            // or initialize an inflation buffer.
            plain: compressed.then(SmallVec::new),
            decode_at: 0,
            decode_next: None,
            decode_root: Term::NIL,
            decode_root_started: false,
            decode_maps: SmallVec::new(),
            pending: None,
            internal_nc: false,
            safe: opts.safe,
            local_node: None,
            used: opts.used,
            compressed,
            used_prefix,
            input_size,
            input_offset: 0,
            expected_plain,
            decompressor,
            inflate_done: !compressed,
            heap_words: None,
            prepare_charge: if compressed && expected_plain > B2T_MAX_DIRECT_UNCOMPRESSED_SIZE {
                expected_plain
            } else {
                0
            },
            reservation: None,
            factory_mark: None,
        })
    }

    /// `B2TSize`: one `decoded_size` slice over the external term data.
    pub(crate) fn decoded_size(&mut self) -> Result<Option<usize>, BifError> {
        let bytes = if self.compressed {
            self.plain
                .as_deref()
                .expect("compressed input has an inflate buffer")
        } else {
            &self.input.bytes()[1..]
        };
        decoded_size(bytes, &mut self.size, &mut self.reds)
    }

    /// Configure this node's identity for external pid, port, and reference terms.
    pub fn set_local_node(&mut self, node: arinsal_term::Atom, creation: u32) {
        self.local_node = Some((node, creation));
    }

    /// Retain the refc input only when the decoder is moved into a trap context.
    pub(crate) fn into_owned(self) -> Result<B2tContext<'static>, BifError> {
        let Self {
            state,
            reds,
            initial_reds,
            size,
            result,
            trap_bin,
            arity,
            arg,
            input,
            plain,
            decode_at,
            decode_next,
            decode_root,
            decode_root_started,
            decode_maps,
            pending,
            internal_nc,
            safe,
            local_node,
            used,
            compressed,
            used_prefix,
            input_size,
            input_offset,
            expected_plain,
            decompressor,
            inflate_done,
            heap_words,
            prepare_charge,
            reservation,
            factory_mark,
        } = self;
        let input = match input {
            DecodeInput::Inline(bytes) => DecodeInput::Inline(bytes),
            DecodeInput::Refc { owner, offset, len } => DecodeInput::Refc { owner, offset, len },
            DecodeInput::Borrowed {
                term, offset, len, ..
            } => match binary_owner(term) {
                // `new` excluded active writable handles. The process can still expose an
                // immutable bitstring backed by a writable owner; pin it like the BIF argument
                // root held by erts across a trap.
                Some(BinaryOwner::Binary(owner)) => DecodeInput::Refc { owner, offset, len },
                _ => return Err(BifError::BADARG),
            },
        };
        Ok(B2tContext {
            state,
            reds,
            initial_reds,
            size,
            result,
            trap_bin,
            arity,
            arg,
            input,
            plain,
            decode_at,
            decode_next,
            decode_root,
            decode_root_started,
            decode_maps,
            pending,
            internal_nc,
            safe,
            local_node,
            used,
            compressed,
            used_prefix,
            input_size,
            input_offset,
            expected_plain,
            decompressor,
            inflate_done,
            heap_words,
            prepare_charge,
            reservation,
            factory_mark,
        })
    }

    fn inflate_more(&mut self, output_budget: usize) -> Result<usize, BifError> {
        if self.inflate_done {
            return Ok(0);
        }
        let plain_len = self.plain.as_ref().ok_or(BifError::BADARG)?.len();
        let remaining = self.expected_plain.saturating_sub(plain_len);
        let capacity = output_budget.max(1).min(remaining.saturating_add(1));
        let mut output = SmallVec::<[u8; 128]>::new();
        output.resize(capacity, 0);
        let input = &self.input.bytes()[6 + self.input_offset..];
        let flush = if input.is_empty() {
            FlushDecompress::Finish
        } else {
            FlushDecompress::None
        };
        let inflater = self.decompressor.as_mut().ok_or(BifError::BADARG)?;
        let before_in = inflater.total_in();
        let before_out = inflater.total_out();
        let status = inflater
            .decompress(input, &mut output, flush)
            .map_err(|_| BifError::BADARG)?;
        let consumed =
            usize::try_from(inflater.total_in() - before_in).map_err(|_| BifError::BADARG)?;
        let produced =
            usize::try_from(inflater.total_out() - before_out).map_err(|_| BifError::BADARG)?;
        self.input_offset = self.input_offset.saturating_add(consumed);
        if plain_len.saturating_add(produced) > self.expected_plain {
            return Err(BifError::BADARG);
        }
        self.plain
            .as_mut()
            .ok_or(BifError::BADARG)?
            .extend_from_slice(&output[..produced]);
        if status == Status::StreamEnd {
            self.inflate_done = true;
            self.used_prefix = 6 + self.input_offset;
            if self.plain.as_ref().ok_or(BifError::BADARG)?.len() != self.expected_plain {
                return Err(BifError::BADARG);
            }
        } else if consumed == 0 && produced == 0 {
            return Err(BifError::BADARG);
        }
        Ok(produced)
    }

    /// The external term data after the version byte (`b2ts.extp`).
    pub fn plain_bytes(&self) -> &[u8] {
        if self.compressed {
            self.plain
                .as_deref()
                .expect("compressed input has an inflate buffer")
        } else {
            &self.input.bytes()[1..]
        }
    }

    /// `b2ts.extsize`: the decoded external term data's size in bytes.
    // Port of erts/emulator/beam/external.c (ErtsBinary2TermState.extsize), OTP-29.1.1.
    pub fn extsize(&self) -> usize {
        if self.compressed {
            self.expected_plain
        } else {
            self.input_size - 1
        }
    }

    /// Whether the input is compressed: `binary2term_prepare` starts in `B2TUncompressChunk`,
    /// else in `B2TSizeInit`.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// The `ctx->reds -= dest_len` of `binary2term_prepare` after it validated an oversized
    /// length claim by inflating the data once.
    pub fn prepare_reds_charge(&self) -> usize {
        self.prepare_charge
    }

    /// `B2TUncompressChunk`: inflate at most `budget` bytes; `true` when the stream ended.
    // Port of erts/emulator/beam/external.c (binary_to_term_int, B2TUncompressChunk),
    // OTP-29.1.1.
    pub fn uncompress_chunk(&mut self, budget: usize) -> Result<(bool, usize), (BifError, usize)> {
        let mut consumed = 0;
        while !self.inflate_done && consumed < budget {
            let produced = self
                .inflate_more(budget - consumed)
                .map_err(|error| (error, consumed))?;
            consumed += produced.max(1);
            if produced == 0 && !self.inflate_done {
                return Err((BifError::BADARG, consumed));
            }
        }
        Ok((self.inflate_done, consumed))
    }

    /// The end of `decoded_size`: the heap size in words that `B2TDecodeInit` reserves. For
    /// inflated input the walk must have covered exactly the data the header announced.
    pub fn set_heap_words(&mut self, words: usize) {
        self.heap_words = Some(words);
    }

    /// Undo what the decode built, as `erts_factory_undo` does when `binary_to_term_int`
    /// fails; a no-op before the first decode slice.
    // Port of erts/emulator/beam/external.c (binary_to_term_int failure path), OTP-29.1.1.
    pub fn undo_factory(&mut self, heap: &mut ProcessHeap) {
        self.reservation = None;
        if let Some(mark) = self.factory_mark.take() {
            heap.factory_undo(mark);
        }
    }

    /// `B2TDecode`: `dec_term` with `budget` bytes of reductions into the process heap; the
    /// result once the whole term was decoded.
    // Port of erts/emulator/beam/external.c (binary_to_term_int, B2TDecodeInit..B2TDecode,
    // dec_term), OTP-29.1.1.
    pub fn decode_chunk(
        &mut self,
        byte_budget: usize,
        process_heap: &mut ProcessHeap,
    ) -> Result<(Option<Term>, usize), (BifError, usize)> {
        let consumed = 0;
        let Some(heap_words) = self.heap_words else {
            return Err((BifError::BADARG, consumed));
        };
        let mut reservation = match self.reservation.take() {
            Some(state) => HeapReservation::resume(process_heap, state),
            None => {
                self.factory_mark = Some(process_heap.factory_mark());
                HeapReservation::new(process_heap, heap_words)
                    .map_err(|error| (map_term_build_error(error), consumed))?
            }
        };
        let budget = byte_budget.max(1);
        let before = self.decode_at;
        let (parsed, after) = reservation
            .with_words(|reserved_words| {
                let bytes = if self.compressed {
                    self.plain
                        .as_deref()
                        .expect("compressed input has an inflate buffer")
                } else {
                    &self.input.bytes()[1..]
                };
                let mut reader = Reader::new(bytes, before);
                let parsed = decode_direct_step(
                    &mut reader,
                    &mut self.decode_next,
                    &mut self.decode_root,
                    &mut self.decode_root_started,
                    &mut self.decode_maps,
                    &mut self.pending,
                    &mut self.internal_nc,
                    self.safe,
                    self.local_node,
                    &mut *reserved_words,
                    budget,
                );
                let after = reader.at;
                debug_assert_eq!(reserved_words.as_mut_words().len(), heap_words);
                (parsed, after)
            })
            .map_err(|error| (map_term_build_error(error), consumed))?;
        self.decode_at = after;
        let decoded = self.decode_at - before;
        match parsed {
            Ok((Some((_term, checked)), decode_work)) => {
                if self.compressed && checked != self.plain_bytes().len() {
                    drop(reservation);
                    return Err((BifError::BADARG, consumed + decoded));
                }
                finish_decode_maps(
                    &mut reservation,
                    &mut self.decode_maps,
                    &mut self.decode_root,
                )
                .map_err(|error| (error, consumed + decode_work))?;
                let term = self.decode_root;
                drop(reservation);
                let value = self
                    .wrap_used(process_heap, term, checked)
                    .map_err(|error| (error, consumed + decode_work))?;
                Ok((Some(value), consumed + decode_work))
            }
            Ok((None, decode_work)) => {
                self.reservation = Some(reservation.suspend());
                Ok((None, consumed + decode_work))
            }
            Err(error) => {
                drop(reservation);
                let error = match error {
                    BifError::Unsupported("incomplete ETF input") => BifError::BADARG,
                    error => error,
                };
                Err((error, consumed + decoded))
            }
        }
    }

    fn wrap_used(
        &self,
        heap: &mut ProcessHeap,
        term: Term,
        checked: usize,
    ) -> Result<Term, BifError> {
        if self.used {
            let used = if self.compressed {
                self.used_prefix
            } else {
                self.used_prefix + checked
            };
            let mut handle = ProcessHeapHandle(heap);
            let mut builder = TermBuilder::new(&mut handle);
            let size = builder
                .int_from_u64(used as u64)
                .map_err(map_term_build_error)?;
            builder.tuple(&[term, size]).map_err(map_term_build_error)
        } else {
            Ok(term)
        }
    }
}

// Port of erts/emulator/beam/external.c:1719-1741 (binary2term_uncomp_size), OTP-29.1.1.
fn compressed_uncompressed_size(input: &[u8]) -> Result<usize, BifError> {
    let mut decompressor = Decompress::new(true);
    let mut output = [0; 64 * 1024];
    loop {
        let consumed = usize::try_from(decompressor.total_in()).map_err(|_| BifError::BADARG)?;
        let before_out = decompressor.total_out();
        let status = decompressor
            .decompress(
                input.get(consumed..).ok_or(BifError::BADARG)?,
                &mut output,
                FlushDecompress::Finish,
            )
            .map_err(|_| BifError::BADARG)?;
        if status == Status::StreamEnd {
            return usize::try_from(decompressor.total_out()).map_err(|_| BifError::BADARG);
        }
        if decompressor.total_in() == consumed as u64 && decompressor.total_out() == before_out {
            return Err(BifError::BADARG);
        }
    }
}
