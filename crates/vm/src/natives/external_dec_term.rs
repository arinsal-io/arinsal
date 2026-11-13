//! `dec_term` of `binary_to_term`: the decoder over the `next` pointer chain.
//!
//! Port of erts/emulator/beam/external.c (`dec_term`), OTP-29.1.1.

use super::external_dec::B2T_MEMCPY_FACTOR;
use arinsal_bifs::BifError;
use arinsal_term::{
    Atom, AtomEncoding, ConsListBuilder, ExportEntry, FunEntry, HeapAlloc, HeapBlockBuilder,
    HeapReservation, HeapReservationWords, HeapTermSlot, HxNode, Node, ProcessHeap, RefcBinary,
    Term, TermBuilder, TermKind, atoms, flat_key_cmp, global_atoms, hashmap_from_unsorted_array,
    hashmap_key_hash,
};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use smallvec::SmallVec;
use std::cmp::Ordering;
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

#[derive(Clone, Copy)]
pub(super) enum DecodeTarget {
    Root,
    Heap(arinsal_term::raw::HeapSlotPtr),
}

pub(super) enum DecodeMap {
    Flatmap {
        keys: HeapTermSlot,
        values: HeapTermSlot,
        size: usize,
    },
    Hashmap {
        target: DecodeTarget,
        pairs: HeapTermSlot,
        size: usize,
    },
}

pub(super) enum DecodePending {
    Tuple {
        block: HeapBlockBuilder,
        arity: usize,
        next_index: usize,
        continuation: Option<arinsal_term::raw::HeapSlotPtr>,
    },
    List {
        block: HeapBlockBuilder,
        size: usize,
        next_index: usize,
        chain: Option<arinsal_term::raw::HeapSlotPtr>,
        continuation: Option<arinsal_term::raw::HeapSlotPtr>,
    },
    String {
        target: DecodeTarget,
        continuation: Option<arinsal_term::raw::HeapSlotPtr>,
        builder: ConsListBuilder,
        source_at: usize,
        size: usize,
        written: usize,
    },
    Binary {
        target: DecodeTarget,
        continuation: Option<arinsal_term::raw::HeapSlotPtr>,
        binary: RefcBinary,
        remaining: usize,
        bit_len: usize,
    },
}

pub(super) fn map_term_build_error(error: arinsal_term::TermError) -> BifError {
    match error {
        arinsal_term::TermError::SystemLimit => BifError::SystemLimit,
        _ => BifError::BADARG,
    }
}

fn write_decode_target(target: DecodeTarget, root: &mut Term, term: Term) -> Result<(), BifError> {
    match target {
        DecodeTarget::Root => *root = term,
        DecodeTarget::Heap(slot) => slot.store(term.word()),
    }
    Ok(())
}

#[inline(always)]
fn decode_slot_ptr(
    heap: &mut HeapReservationWords<'_>,
    slot: HeapTermSlot,
) -> Result<arinsal_term::raw::HeapSlotPtr, BifError> {
    let index = slot.word_index().ok_or(BifError::BADARG)?;
    let (words, _) = heap.words_and_cursor();
    arinsal_term::raw::HeapSlotPtr::at(words, index).ok_or(BifError::BADARG)
}

#[inline(always)]
fn decode_heap_slot(
    heap: &mut HeapReservationWords<'_>,
    slot: arinsal_term::raw::HeapSlotPtr,
) -> Result<HeapTermSlot, BifError> {
    let (words, _) = heap.words_and_cursor();
    let index = arinsal_term::raw::slot_index(words.as_ptr() as usize, words.len(), slot)
        .ok_or(BifError::BADARG)?;
    Ok(HeapTermSlot::from_index(index))
}

#[inline(always)]
fn decode_slot_ptrs(
    heap: &mut HeapReservationWords<'_>,
    slots: Option<HeapTermSlot>,
) -> Result<Option<arinsal_term::raw::HeapSlotPtr>, BifError> {
    slots.map(|slot| decode_slot_ptr(heap, slot)).transpose()
}

// Port of erts/emulator/beam/external.c:5425-5460 (dec_term map_array post-pass), OTP-29.1.1.
pub(super) fn finish_decode_maps(
    reservation: &mut HeapReservation<'_, ProcessHeap>,
    maps: &mut SmallVec<[DecodeMap; 10]>,
    root: &mut Term,
) -> Result<(), BifError> {
    while let Some(map) = maps.pop() {
        match map {
            DecodeMap::Flatmap { keys, values, size } => {
                reservation
                    .with_words(|words| {
                        for index in 1..size {
                            let mut current = index;
                            while current > 0 {
                                let key_slot = words
                                    .offset_slot(keys, current)
                                    .map_err(map_term_build_error)?;
                                let prev_slot = words
                                    .offset_slot(keys, current - 1)
                                    .map_err(map_term_build_error)?;
                                let key = words
                                    .read_term_slot(key_slot)
                                    .map_err(map_term_build_error)?;
                                let prev = words
                                    .read_term_slot(prev_slot)
                                    .map_err(map_term_build_error)?;
                                match flat_key_cmp(key, prev) {
                                    Ordering::Greater => break,
                                    Ordering::Equal => return Err(BifError::BADARG),
                                    Ordering::Less => {
                                        let value_slot = words
                                            .offset_slot(values, current)
                                            .map_err(map_term_build_error)?;
                                        let prev_value_slot = words
                                            .offset_slot(values, current - 1)
                                            .map_err(map_term_build_error)?;
                                        words
                                            .swap_term_slots(key_slot, prev_slot)
                                            .map_err(map_term_build_error)?;
                                        words
                                            .swap_term_slots(value_slot, prev_value_slot)
                                            .map_err(map_term_build_error)?;
                                        current -= 1;
                                    }
                                }
                            }
                        }
                        Ok(())
                    })
                    .map_err(map_term_build_error)??;
            }
            DecodeMap::Hashmap {
                target,
                pairs,
                size,
            } => {
                let mut hxns = reservation
                    .with_words(|words| {
                        let mut hxns = Vec::with_capacity(size);
                        for index in 0..size {
                            let key_slot = words
                                .offset_slot(pairs, index * 2)
                                .map_err(map_term_build_error)?;
                            let key = words
                                .read_term_slot(key_slot)
                                .map_err(map_term_build_error)?;
                            let leaf =
                                words.list_term_at(key_slot).map_err(map_term_build_error)?;
                            hxns.push(HxNode {
                                hx: hashmap_key_hash(key),
                                skip: 1,
                                i: index,
                                val: leaf,
                            });
                        }
                        Ok(hxns)
                    })
                    .map_err(map_term_build_error)??;
                let map = hashmap_from_unsorted_array(&mut hxns, true, reservation)
                    .map_err(map_term_build_error)?
                    .ok_or(BifError::BADARG)?;
                reservation
                    .with_words(|_| {
                        match target {
                            DecodeTarget::Root => *root = map,
                            DecodeTarget::Heap(slot) => slot.store(map.word()),
                        }
                        Ok(())
                    })
                    .map_err(map_term_build_error)??;
            }
        }
    }
    Ok(())
}

// Port of erts/emulator/beam/external.c:4325-5445 (`dec_term`), OTP-29.1.1.
fn read_small_integer(r: &mut Reader<'_>) -> Result<i64, BifError> {
    let tag = r.u8()?;
    let number = match tag {
        97 => r.u8()? as i64,
        98 => r.u32()? as i32 as i64,
        110 | 111 => {
            let length = if tag == 110 {
                r.u8()? as usize
            } else {
                r.u32()? as usize
            };
            let sign = r.u8()?;
            BigInt::from_bytes_le(
                if sign == 0 { Sign::Plus } else { Sign::Minus },
                r.take(length)?,
            )
            .to_i64()
            .ok_or(BifError::BADARG)?
        }
        _ => return Err(BifError::BADARG),
    };
    if Term::small(number).is_none() {
        return Err(BifError::BADARG);
    }
    Ok(number)
}

// Port of erts/emulator/beam/external.c:4640-4694 (PID_EXT/NEW_PID_EXT), OTP-29.1.1.
fn read_pid_term<H: HeapAlloc>(
    r: &mut Reader<'_>,
    safe: bool,
    local_node: Option<(Atom, u32)>,
    heap: &mut H,
) -> Result<Term, BifError> {
    let tag = r.u8()?;
    if tag != 103 && tag != 88 {
        return Err(BifError::BADARG);
    }
    let (node_term, _) = r.atom(safe, true)?;
    let node = node_term.as_atom().ok_or(BifError::BADARG)?;
    let id = r.u32()?;
    let serial = r.u32()?;
    let creation = if tag == 103 { r.u8()? as u32 } else { r.u32()? };
    if tag == 103 && creation > 3 {
        return Err(BifError::BADARG);
    }
    if node == atoms::NONAME && creation == 0
        || local_node.is_some_and(|(name, current)| node == name && creation == current)
    {
        Term::pid(id, serial).ok_or(BifError::BADARG)
    } else {
        TermBuilder::new(&mut *heap)
            .external_pid(Node::new(node, creation), id, serial)
            .map_err(map_term_build_error)
    }
}

// Port of erts/emulator/beam/external.c:4325-5445 (`dec_term`, in-place `next` walk), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
pub(super) fn decode_direct_step(
    r: &mut Reader<'_>,
    next: &mut Option<arinsal_term::raw::HeapSlotPtr>,
    root: &mut Term,
    root_started: &mut bool,
    maps: &mut SmallVec<[DecodeMap; 10]>,
    pending: &mut Option<DecodePending>,
    internal_nc: &mut bool,
    safe: bool,
    local_node: Option<(Atom, u32)>,
    heap: &mut HeapReservationWords<'_>,
    budget: usize,
) -> Result<(Option<(Term, usize)>, usize), BifError> {
    let mut work = 0;
    if pending.is_some() {
        if pending
            .as_ref()
            .is_some_and(|item| matches!(item, DecodePending::Tuple { .. }))
        {
            let Some(DecodePending::Tuple {
                block,
                arity,
                mut next_index,
                continuation,
            }) = pending.take()
            else {
                unreachable!();
            };
            let count = next_index.min(budget.saturating_sub(work));
            if count > 0 {
                let first = next_index - count + 1;
                let terminal = if next_index == arity {
                    continuation
                        .map(|slot| decode_heap_slot(heap, slot))
                        .transpose()?
                } else {
                    Some(
                        block
                            .term_slot(next_index + 1)
                            .map_err(map_term_build_error)?,
                    )
                };
                block
                    .write_next_chain(first, count, terminal)
                    .map_err(map_term_build_error)?;
                next_index -= count;
            }
            work += count;
            if next_index != 0 {
                *pending = Some(DecodePending::Tuple {
                    block,
                    arity,
                    next_index,
                    continuation,
                });
                return Ok((None, work));
            }
            *next = Some(decode_slot_ptr(
                heap,
                block.term_slot(1).map_err(map_term_build_error)?,
            )?);
        }
        if pending
            .as_ref()
            .is_some_and(|item| matches!(item, DecodePending::List { .. }))
        {
            let Some(DecodePending::List {
                block,
                size,
                mut next_index,
                mut chain,
                continuation,
            }) = pending.take()
            else {
                unreachable!();
            };
            let count = next_index.min(budget.saturating_sub(work));
            if count > 0 {
                let first = block
                    .write_list_chain(
                        next_index - count,
                        count,
                        decode_heap_slot(heap, chain.ok_or(BifError::BADARG)?)?,
                    )
                    .map_err(map_term_build_error)?;
                chain = Some(decode_slot_ptr(heap, first)?);
                next_index -= count;
            }
            work += count;
            if next_index != 0 {
                *pending = Some(DecodePending::List {
                    block,
                    size,
                    next_index,
                    chain,
                    continuation,
                });
                return Ok((None, work));
            }
            *next = chain;
        }
        if pending
            .as_ref()
            .is_some_and(|item| matches!(item, DecodePending::String { .. }))
        {
            let Some(DecodePending::String {
                target,
                continuation,
                mut builder,
                source_at,
                size,
                mut written,
            }) = pending.take()
            else {
                unreachable!();
            };
            let count = (size - written).min(budget.saturating_sub(work));
            let source = r
                .bytes
                .get(source_at + written..source_at + written + count)
                .ok_or(BifError::BADARG)?;
            for byte in source {
                builder
                    .append(Term::small(i64::from(*byte)).ok_or(BifError::BADARG)?)
                    .map_err(map_term_build_error)?;
            }
            written += count;
            work += count;
            if written != size {
                *pending = Some(DecodePending::String {
                    target,
                    continuation,
                    builder,
                    source_at,
                    size,
                    written,
                });
                return Ok((None, work));
            }
            let term = builder.finish(Term::NIL).map_err(map_term_build_error)?;
            write_decode_target(target, root, term)?;
            *root_started = true;
            *next = continuation;
        }
        if pending
            .as_ref()
            .is_some_and(|item| matches!(item, DecodePending::Binary { .. }))
        {
            let Some(DecodePending::Binary {
                target,
                continuation,
                mut binary,
                mut remaining,
                bit_len,
            }) = pending.take()
            else {
                unreachable!();
            };
            let copy_limit = budget
                .saturating_sub(work)
                .saturating_mul(B2T_MEMCPY_FACTOR);
            let copy_len = remaining.min(copy_limit);
            let source = r.take(copy_len)?;
            let destination_at = binary
                .len()
                .checked_sub(remaining)
                .ok_or(BifError::BADARG)?;
            let destination = binary.bytes_mut_unique().ok_or(BifError::BADARG)?;
            let destination_end = destination_at
                .checked_add(copy_len)
                .ok_or(BifError::BADARG)?;
            destination
                .get_mut(destination_at..destination_end)
                .ok_or(BifError::BADARG)?
                .copy_from_slice(source);
            remaining -= copy_len;
            if remaining != 0 {
                *pending = Some(DecodePending::Binary {
                    target,
                    continuation,
                    binary,
                    remaining,
                    bit_len,
                });
                return Ok((None, work + copy_len / B2T_MEMCPY_FACTOR));
            }
            let term = TermBuilder::new(&mut *heap)
                .refc_binary(binary, bit_len)
                .map_err(map_term_build_error)?;
            write_decode_target(target, root, term)?;
            *root_started = true;
            *next = continuation;
            work += copy_len / B2T_MEMCPY_FACTOR;
        }
    }
    if work >= budget {
        if *root_started && next.is_none() {
            return Ok((Some((*root, r.at)), work));
        }
        return Ok((None, work));
    }
    let mut hp = {
        let (_, cursor) = heap.words_and_cursor();
        *cursor
    };
    let mut cur = *next;
    loop {
        let target = match cur {
            Some(slot) => DecodeTarget::Heap(slot),
            None if !*root_started => DecodeTarget::Root,
            None => {
                *next = None;
                return Ok((Some((*root, r.at)), work));
            }
        };
        let mut next_was_set = false;
        let mut defer_output = false;
        let mut reprocess_target = false;
        let mut yield_after_write = false;
        let (tag, continuation, direct, cursor_hp) = {
            let (words, cursor) = heap.words_and_cursor();
            *cursor = hp;
            let len = words.len();
            let base = words.as_ptr() as usize as u64;
            let slot_ptr = match target {
                DecodeTarget::Root => None,
                DecodeTarget::Heap(slot) => Some(slot),
            };
            let continuation = slot_ptr.and_then(arinsal_term::raw::HeapSlotPtr::take_next);
            let tag = r.u8()?;
            let payload_at = r.at;
            let mut root_term = None;
            let mut root_block = None;
            let mut direct_next = continuation;
            let direct_work = match tag {
                97 => {
                    let term = Term::small(i64::from(r.u8()?)).ok_or(BifError::BADARG)?;
                    if let Some(slot) = slot_ptr {
                        slot.store(term.word());
                    } else {
                        root_term = Some(term);
                    }
                    Some(1)
                }
                98 => {
                    let term = Term::small(i64::from(r.u32()? as i32)).ok_or(BifError::BADARG)?;
                    if let Some(slot) = slot_ptr {
                        slot.store(term.word());
                    } else {
                        root_term = Some(term);
                    }
                    Some(1)
                }
                106 => {
                    if let Some(slot) = slot_ptr {
                        slot.store(Term::NIL.word());
                    } else {
                        root_term = Some(Term::NIL);
                    }
                    Some(1)
                }
                100 | 115 | 118 | 119 => {
                    r.at = payload_at - 1;
                    let (term, _) = r.atom(safe, true)?;
                    if let Some(slot) = slot_ptr {
                        slot.store(term.word());
                    } else {
                        root_term = Some(term);
                    }
                    Some(1)
                }
                104 | 105 => {
                    let arity = if tag == 104 {
                        r.u8()? as usize
                    } else {
                        r.u32()? as usize
                    };
                    let end = hp.checked_add(arity + 1).ok_or(BifError::BADARG)?;
                    if arity == 0 {
                        if let Some(slot) = slot_ptr {
                            slot.store(arinsal_term::global_empty_tuple().word());
                        } else {
                            root_term = Some(arinsal_term::global_empty_tuple());
                        }
                        Some(1)
                    } else if arity < (1 << 24)
                        && arity <= budget.saturating_sub(work + 1)
                        && end <= len
                    {
                        let block = words.get_mut(hp..end).ok_or(BifError::BADARG)?;
                        block[0] = (arity as u64) << 6;
                        for (offset, word) in block[1..arity].iter_mut().enumerate() {
                            *word = arinsal_term::raw::slot_address(base as usize, hp + offset + 2);
                        }
                        block[arity] =
                            continuation.map_or(0, arinsal_term::raw::HeapSlotPtr::address);
                        let term_word = base.wrapping_add((hp * 8) as u64) | 2;
                        if let Some(slot) = slot_ptr {
                            slot.store(term_word);
                        } else {
                            root_block = Some((hp, 2));
                        }
                        *cursor = end;
                        direct_next = Some(
                            arinsal_term::raw::HeapSlotPtr::at(words, hp + 1)
                                .ok_or(BifError::BADARG)?,
                        );
                        let extra = arity + 1;
                        hp = end;
                        Some(extra)
                    } else {
                        r.at = payload_at;
                        None
                    }
                }
                107 => {
                    let size = r.u16()? as usize;
                    let bytes_at = r.at;
                    let Some(bytes) = r.bytes.get(bytes_at..bytes_at.saturating_add(size)) else {
                        return Err(BifError::BADARG);
                    };
                    if size == 0 {
                        if let Some(slot) = slot_ptr {
                            slot.store(Term::NIL.word());
                        } else {
                            root_term = Some(Term::NIL);
                        }
                        r.at += size;
                        Some(1)
                    } else if size <= budget.saturating_sub(work + 1)
                        && hp
                            .checked_add(size.checked_mul(2).ok_or(BifError::BADARG)?)
                            .is_some_and(|end| end <= len)
                    {
                        let end = hp + size * 2;
                        for (index, byte) in bytes.iter().copied().enumerate() {
                            let car = hp + index * 2;
                            words[car] =
                                Term::small(i64::from(byte)).ok_or(BifError::BADARG)?.word();
                            words[car + 1] = if index + 1 == size {
                                Term::NIL.word()
                            } else {
                                base.wrapping_add(((car + 2) * 8) as u64) | 1
                            };
                        }
                        let term_word = base.wrapping_add((hp * 8) as u64) | 1;
                        if let Some(slot) = slot_ptr {
                            slot.store(term_word);
                        } else {
                            root_block = Some((hp, 1));
                        }
                        r.at += size;
                        *cursor = end;
                        hp = end;
                        Some(size + 1)
                    } else {
                        r.at = payload_at;
                        None
                    }
                }
                108 => {
                    let size = r.u32()? as usize;
                    if size == 0 {
                        r.at = payload_at;
                        None
                    } else if size - 1 <= budget.saturating_sub(work + 1)
                        && hp
                            .checked_add(size.checked_mul(2).ok_or(BifError::BADARG)?)
                            .is_some_and(|end| end <= len)
                    {
                        let end = hp + size * 2;
                        let tail = continuation.map_or(0, arinsal_term::raw::HeapSlotPtr::address);
                        for index in 0..size {
                            let car = hp + index * 2;
                            words[car] = if index + 1 == size {
                                arinsal_term::raw::slot_address(base as usize, car + 1)
                            } else {
                                arinsal_term::raw::slot_address(base as usize, car + 2)
                            };
                            words[car + 1] = if index + 1 == size {
                                tail
                            } else {
                                base.wrapping_add(((car + 2) * 8) as u64) | 1
                            };
                        }
                        let term_word = base.wrapping_add((hp * 8) as u64) | 1;
                        if let Some(slot) = slot_ptr {
                            slot.store(term_word);
                        } else {
                            root_block = Some((hp, 1));
                        }
                        *cursor = end;
                        direct_next = Some(
                            arinsal_term::raw::HeapSlotPtr::at(words, hp)
                                .ok_or(BifError::BADARG)?,
                        );
                        hp = end;
                        Some(size)
                    } else {
                        r.at = payload_at;
                        None
                    }
                }
                109 | 77 => {
                    let size = r.u32()? as usize;
                    let bits = if tag == 77 { r.u8()? as usize } else { 8 };
                    if tag == 77 && (size == 0 || !(1..=8).contains(&bits)) {
                        return Err(BifError::BADARG);
                    }
                    if size > 64 {
                        r.at = payload_at;
                        None
                    } else {
                        let bit_len = if tag == 109 {
                            size.checked_mul(8)
                        } else {
                            size.checked_sub(1)
                                .and_then(|n| n.checked_mul(8))
                                .and_then(|n| n.checked_add(bits))
                        }
                        .ok_or(BifError::BADARG)?;
                        let bytes = r.take(size)?;
                        let payload_words = size.div_ceil(8);
                        let words_needed = 2 + payload_words;
                        let end = hp.checked_add(words_needed).ok_or(BifError::BADARG)?;
                        if end > len {
                            return Err(BifError::BADARG);
                        }
                        words[hp] = (((words_needed - 1) as u64) << 6) | 0x20;
                        words[hp + 1] = bit_len as u64;
                        for (index, chunk) in bytes.chunks(8).enumerate() {
                            let mut word = [0; 8];
                            word[..chunk.len()].copy_from_slice(chunk);
                            if index + 1 == payload_words && !bit_len.is_multiple_of(8) {
                                let used = bit_len % 8;
                                word[chunk.len() - 1] &= 0xff << (8 - used);
                            }
                            words[hp + 2 + index] = u64::from_ne_bytes(word);
                        }
                        let term_word = base.wrapping_add((hp * 8) as u64) | 2;
                        if let Some(slot) = slot_ptr {
                            slot.store(term_word);
                        } else {
                            root_block = Some((hp, 2));
                        }
                        *cursor = end;
                        hp = end;
                        Some(1 + (budget.saturating_sub(work).min(size / B2T_MEMCPY_FACTOR)))
                    }
                }
                121 => {
                    // Port of external.c:5250-5255 (`dec_term`, LOCAL_EXT), OTP-29.1.1.
                    r.take(4)?;
                    *internal_nc = true;
                    None
                }
                _ => None,
            };
            if direct_work.is_none()
                && tag == 121
                && let Some(slot) = slot_ptr
            {
                slot.store(continuation.map_or(0, arinsal_term::raw::HeapSlotPtr::address));
            }
            let direct = direct_work.map(|amount| (root_term, root_block, direct_next, amount));
            (tag, continuation, direct, *cursor)
        };
        if let Some((root_term, root_block, direct_next, direct_work)) = direct {
            if let Some(term) = root_term {
                *root = term;
            } else if let Some((index, tag)) = root_block {
                *root = if tag == 1 {
                    heap.list_term_at(HeapTermSlot::from_index(index))
                        .map_err(map_term_build_error)?
                } else {
                    heap.boxed_term_at(HeapTermSlot::from_index(index))
                        .map_err(map_term_build_error)?
                };
            }
            *root_started = true;
            cur = direct_next;
            hp = cursor_hp;
            work += direct_work;
            if work >= budget && cur.is_some() {
                *next = cur;
                return Ok((None, work));
            }
            continue;
        }
        *next = None;
        let term = match tag {
            97 | 98 | 106 => unreachable!("hot immediate tags are decoded in the loop"),
            121 => {
                if let DecodeTarget::Heap(slot) = target {
                    *next = Some(slot);
                    next_was_set = true;
                }
                reprocess_target = true;
                None
            }
            110 | 111 => {
                let length = if tag == 110 {
                    r.u8()? as usize
                } else {
                    r.u32()? as usize
                };
                let sign = r.u8()?;
                let number = BigInt::from_bytes_le(
                    if sign == 0 { Sign::Plus } else { Sign::Minus },
                    r.take(length)?,
                );
                Some(
                    TermBuilder::new(&mut *heap)
                        .int_from_bigint(&number)
                        .map_err(map_term_build_error)?,
                )
            }
            70 | 99 => {
                let value = if tag == 70 {
                    f64::from_bits(r.u64()?)
                } else {
                    let raw = r.take(31)?;
                    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(31);
                    std::str::from_utf8(&raw[..end])
                        .map_err(|_| BifError::BADARG)?
                        .parse::<f64>()
                        .map_err(|_| BifError::BADARG)?
                };
                if !value.is_finite() {
                    return Err(BifError::BADARG);
                }
                Some(
                    TermBuilder::new(&mut *heap)
                        .float(value)
                        .map_err(map_term_build_error)?,
                )
            }
            100 | 115 | 118 | 119 => {
                r.at -= 1;
                Some(r.atom(safe, true)?.0)
            }
            73 | 75 => {
                let index = if tag == 73 {
                    r.u16()? as u32
                } else {
                    let bytes = r.take(3)?;
                    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
                };
                let atom = Atom(index);
                if global_atoms().text(atom).is_none() {
                    return Err(BifError::BADARG);
                }
                Some(Term::atom(atom))
            }
            104 | 105 => {
                let arity = if tag == 104 {
                    r.u8()? as usize
                } else {
                    r.u32()? as usize
                };
                if arity == 0 {
                    Some(
                        TermBuilder::new(&mut *heap)
                            .tuple(&[])
                            .map_err(map_term_build_error)?,
                    )
                } else {
                    let block = TermBuilder::new(&mut *heap)
                        .reserve_tuple_block(arity)
                        .map_err(map_term_build_error)?;
                    let term = block.term_at(0).map_err(map_term_build_error)?;
                    *pending = Some(DecodePending::Tuple {
                        block,
                        arity,
                        next_index: arity,
                        continuation,
                    });
                    next_was_set = true;
                    yield_after_write = true;
                    Some(term)
                }
            }
            107 => {
                let size = r.u16()? as usize;
                let source_at = r.at;
                r.take(size)?;
                if size == 0 {
                    Some(Term::NIL)
                } else {
                    let builder = TermBuilder::new(&mut *heap)
                        .reserve_cons_list(size)
                        .map_err(map_term_build_error)?;
                    *pending = Some(DecodePending::String {
                        target,
                        continuation,
                        builder,
                        source_at,
                        size,
                        written: 0,
                    });
                    defer_output = true;
                    yield_after_write = true;
                    None
                }
            }
            108 => {
                let size = r.u32()? as usize;
                if size == 0 {
                    if let DecodeTarget::Heap(slot) = target {
                        slot.store(continuation.map_or(0, arinsal_term::raw::HeapSlotPtr::address));
                        *next = Some(slot);
                        next_was_set = true;
                    }
                    reprocess_target = true;
                    None
                } else {
                    let block = TermBuilder::new(&mut *heap)
                        .reserve_boxed_words(size * 2, 0)
                        .map_err(map_term_build_error)?;
                    let term = block.list_at(0).map_err(map_term_build_error)?;
                    let last_car = block
                        .write_list_tail(
                            continuation
                                .map(|slot| decode_heap_slot(heap, slot))
                                .transpose()?,
                        )
                        .map_err(map_term_build_error)?;
                    *pending = Some(DecodePending::List {
                        block,
                        size,
                        next_index: size - 1,
                        chain: Some(decode_slot_ptr(heap, last_car)?),
                        continuation,
                    });
                    next_was_set = true;
                    yield_after_write = true;
                    Some(term)
                }
            }
            116 => {
                let size = r.u32()? as usize;
                if size == 0 {
                    Some(arinsal_maps::from_pairs(&[], &mut *heap).map_err(|_| BifError::BADARG)?)
                } else if size <= 32 {
                    let words = size
                        .checked_mul(2)
                        .and_then(|n| n.checked_add(4))
                        .ok_or(BifError::BADARG)?;
                    let mut block = TermBuilder::new(&mut *heap)
                        .reserve_boxed_words(words, 0)
                        .map_err(map_term_build_error)?;
                    block
                        .write_header((size as u64) << 6)
                        .map_err(map_term_build_error)?;
                    for _ in 0..size {
                        block.write_term(Term::NIL).map_err(map_term_build_error)?;
                    }
                    let keys_term = block.term_at(0).map_err(map_term_build_error)?;
                    block
                        // Port of MAP_HEADER_FLATMAP (erl_map.h), OTP-29.1.1.
                        .write_header(0x12c)
                        .map_err(map_term_build_error)?;
                    block
                        .write_header(size as u64)
                        .map_err(map_term_build_error)?;
                    block.write_term(keys_term).map_err(map_term_build_error)?;
                    for _ in 0..size {
                        block.write_term(Term::NIL).map_err(map_term_build_error)?;
                    }
                    let term = block.term_at(size + 1).map_err(map_term_build_error)?;
                    let keys = block.term_slot(1).map_err(map_term_build_error)?;
                    let values = block.term_slot(size + 4).map_err(map_term_build_error)?;
                    let mut child = continuation
                        .map(|slot| decode_heap_slot(heap, slot))
                        .transpose()?;
                    for index in (0..size).rev() {
                        let key = heap
                            .offset_slot(keys, index)
                            .map_err(map_term_build_error)?;
                        let value = heap
                            .offset_slot(values, index)
                            .map_err(map_term_build_error)?;
                        heap.write_next_slot(value, child)
                            .map_err(map_term_build_error)?;
                        heap.write_next_slot(key, Some(value))
                            .map_err(map_term_build_error)?;
                        child = Some(key);
                    }
                    maps.push(DecodeMap::Flatmap { keys, values, size });
                    *next = decode_slot_ptrs(heap, child)?;
                    next_was_set = true;
                    Some(term)
                } else {
                    let block = TermBuilder::new(&mut *heap)
                        .reserve_boxed_words(size * 2, 0)
                        .map_err(map_term_build_error)?;
                    let pairs = block.term_slot(0).map_err(map_term_build_error)?;
                    let mut child = continuation
                        .map(|slot| decode_heap_slot(heap, slot))
                        .transpose()?;
                    for index in (0..size).rev() {
                        let key = block.term_slot(index * 2).map_err(map_term_build_error)?;
                        let value = block
                            .term_slot(index * 2 + 1)
                            .map_err(map_term_build_error)?;
                        heap.write_next_slot(value, child)
                            .map_err(map_term_build_error)?;
                        heap.write_next_slot(key, Some(value))
                            .map_err(map_term_build_error)?;
                        child = Some(key);
                    }
                    maps.push(DecodeMap::Hashmap {
                        target,
                        pairs,
                        size,
                    });
                    *next = decode_slot_ptrs(heap, child)?;
                    next_was_set = true;
                    defer_output = true;
                    None
                }
            }
            113 => {
                let module = r.atom(safe, true)?.0.as_atom().ok_or(BifError::BADARG)?;
                let function = r.atom(safe, true)?.0.as_atom().ok_or(BifError::BADARG)?;
                let arity_tag = r.u8()?;
                let arity = match arity_tag {
                    97 => r.u8()? as i64,
                    98 => r.u32()? as i32 as i64,
                    110 | 111 => {
                        let length = if arity_tag == 110 {
                            r.u8()? as usize
                        } else {
                            r.u32()? as usize
                        };
                        let sign = r.u8()?;
                        BigInt::from_bytes_le(
                            if sign == 0 { Sign::Plus } else { Sign::Minus },
                            r.take(length)?,
                        )
                        .to_i64()
                        .ok_or(BifError::BADARG)?
                    }
                    _ => return Err(BifError::BADARG),
                };
                let arity = u8::try_from(arity).map_err(|_| BifError::BADARG)?;
                Some(
                    TermBuilder::new(&mut *heap)
                        .export_fun(Arc::new(ExportEntry::new(module, function, arity)))
                        .map_err(map_term_build_error)?,
                )
            }
            112 => {
                r.u32()?;
                let arity = r.u8()?;
                let uniq: [u8; 16] = r.take(16)?.try_into().map_err(|_| BifError::BADARG)?;
                let index = r.u32()?;
                let free = r.u32()? as usize;
                let module = r.atom(safe, true)?.0.as_atom().ok_or(BifError::BADARG)?;
                let old_index =
                    u32::try_from(read_small_integer(r)?).map_err(|_| BifError::BADARG)?;
                let old_uniq =
                    u32::try_from(read_small_integer(r)?).map_err(|_| BifError::BADARG)?;
                let pid = read_pid_term(r, safe, local_node, heap)?;
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
                let (term, environment) = heap
                    .reserve_local_fun_stub(entry, free)
                    .map_err(map_term_build_error)?;
                if let Some(first) = environment {
                    let mut child = continuation
                        .map(|slot| decode_heap_slot(heap, slot))
                        .transpose()?;
                    for offset in (0..free).rev() {
                        let slot = heap
                            .offset_slot(first, offset)
                            .map_err(map_term_build_error)?;
                        heap.write_next_slot(slot, child)
                            .map_err(map_term_build_error)?;
                        child = Some(slot);
                    }
                    *next = decode_slot_ptrs(heap, child)?;
                    next_was_set = true;
                }
                Some(term)
            }
            103 | 88 | 102 | 89 | 120 | 101 | 114 | 90 => {
                let count = if tag == 101 {
                    1
                } else if tag == 114 || tag == 90 {
                    r.u16()? as usize
                } else {
                    0
                };
                if matches!(tag, 101 | 114 | 90) && !(1..=5).contains(&count) {
                    return Err(BifError::BADARG);
                }
                let (node_term, _) = if *internal_nc && r.bytes.get(r.at) == Some(&106) {
                    r.at += 1;
                    (Term::atom(atoms::NONAME), None)
                } else {
                    r.atom(safe, true)?
                };
                let node = node_term.as_atom().ok_or(BifError::BADARG)?;
                let mut ids = [0; 5];
                let (id, serial, creation, ids_len) = if tag == 103 || tag == 88 {
                    let id = r.u32()?;
                    let serial = r.u32()?;
                    let creation = if tag == 103 { r.u8()? as u32 } else { r.u32()? };
                    if tag == 103 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    (id as u64, serial, creation, 0)
                } else if matches!(tag, 102 | 89 | 120) {
                    let id = if tag == 120 {
                        r.u64()?
                    } else {
                        r.u32()? as u64
                    };
                    let creation = if tag == 102 { r.u8()? as u32 } else { r.u32()? };
                    if tag == 102 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    (id, 0, creation, 0)
                } else if tag == 101 {
                    let id = r.u32()?;
                    let creation = r.u8()? as u32;
                    if id >= (1 << 18) || creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    ids[0] = id;
                    (0, 0, creation, 1)
                } else {
                    let creation = if tag == 90 { r.u32()? } else { r.u8()? as u32 };
                    if tag != 90 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    for (index, slot) in ids.iter_mut().take(count).enumerate() {
                        let id = r.u32()?;
                        if index == 0 && tag != 90 && id >= (1 << 18) {
                            return Err(BifError::BADARG);
                        }
                        *slot = id;
                    }
                    (0, 0, creation, count)
                };
                let is_this_node =
                    local_node.is_some_and(|(name, current)| node == name && creation == current);
                let local = (node == atoms::NONAME && creation == 0) || is_this_node;
                let term = if tag == 103 || tag == 88 {
                    if local {
                        Term::pid(id as u32, serial).ok_or(BifError::BADARG)?
                    } else {
                        TermBuilder::new(&mut *heap)
                            .external_pid(Node::new(node, creation), id as u32, serial)
                            .map_err(map_term_build_error)?
                    }
                } else if matches!(tag, 102 | 89 | 120) {
                    if local {
                        Term::port(id).ok_or(BifError::BADARG)?
                    } else {
                        TermBuilder::new(&mut *heap)
                            .external_port(Node::new(node, creation), id)
                            .map_err(map_term_build_error)?
                    }
                } else if local {
                    let mut local_ids = [0; 3];
                    for (slot, value) in local_ids.iter_mut().zip(&ids[..ids_len]) {
                        *slot = *value;
                    }
                    if ids_len == 5 && ids[1] & (1 << 16) != 0 {
                        TermBuilder::new(&mut *heap)
                            .local_pid_ref_from_words(local_ids, ids[3], ids[4])
                            .map_err(map_term_build_error)?
                    } else {
                        let saved = (local_ids[1] & (1 << 17) != 0)
                            .then(|| arinsal_term::MagicRef::lookup_saved_numbers(local_ids))
                            .flatten();
                        match saved {
                            Some(owner) => TermBuilder::new(&mut *heap)
                                .magic_ref(owner)
                                .map_err(map_term_build_error)?,
                            None => TermBuilder::new(&mut *heap)
                                .local_ref(local_ids)
                                .map_err(map_term_build_error)?,
                        }
                    }
                } else {
                    TermBuilder::new(&mut *heap)
                        .external_ref(Node::new(node, creation), &ids[..ids_len])
                        .map_err(map_term_build_error)?
                };
                Some(term)
            }
            109 | 77 => {
                let size = r.u32()? as usize;
                let bits = if tag == 77 { r.u8()? as usize } else { 8 };
                if tag == 77 && (size == 0 || !(1..=8).contains(&bits)) {
                    return Err(BifError::BADARG);
                }
                let bit_len = if tag == 109 {
                    size.checked_mul(8)
                } else {
                    size.checked_sub(1)
                        .and_then(|n| n.checked_mul(8))
                        .and_then(|n| n.checked_add(bits))
                }
                .ok_or(BifError::BADARG)?;
                if size > 64 {
                    let copy_limit = budget
                        .saturating_sub(work)
                        .saturating_mul(B2T_MEMCPY_FACTOR);
                    let copy_len = size.min(copy_limit);
                    let source = r.take(copy_len)?;
                    let mut binary = RefcBinary::new_zeroed(size).map_err(map_term_build_error)?;
                    binary
                        .bytes_mut_unique()
                        .ok_or(BifError::BADARG)?
                        .get_mut(..copy_len)
                        .ok_or(BifError::BADARG)?
                        .copy_from_slice(source);
                    work += copy_len / B2T_MEMCPY_FACTOR;
                    if copy_len != size {
                        *pending = Some(DecodePending::Binary {
                            target,
                            continuation,
                            binary,
                            remaining: size - copy_len,
                            bit_len,
                        });
                        yield_after_write = true;
                        None
                    } else {
                        Some(
                            TermBuilder::new(&mut *heap)
                                .refc_binary(binary, bit_len)
                                .map_err(map_term_build_error)?,
                        )
                    }
                } else {
                    let bytes = r.take(size)?;
                    let start = {
                        let (words, cursor) = heap.words_and_cursor();
                        let start = hp;
                        let payload_words = size.div_ceil(8);
                        let words_needed = 2 + payload_words;
                        let end = start.checked_add(words_needed).ok_or(BifError::BADARG)?;
                        if end > words.len() {
                            return Err(BifError::BADARG);
                        }
                        words[start] = (((words_needed - 1) as u64) << 6) | 0x20;
                        words[start + 1] = bit_len as u64;
                        for (index, chunk) in bytes.chunks(8).enumerate() {
                            let mut word = [0; 8];
                            word[..chunk.len()].copy_from_slice(chunk);
                            if index + 1 == payload_words && !bit_len.is_multiple_of(8) {
                                let used = bit_len % 8;
                                word[chunk.len() - 1] &= 0xff << (8 - used);
                            }
                            words[start + 2 + index] = u64::from_ne_bytes(word);
                        }
                        *cursor = end;
                        start
                    };
                    hp += 2 + size.div_ceil(8);
                    work += budget.saturating_sub(work).min(size / B2T_MEMCPY_FACTOR);
                    Some(
                        heap.boxed_term_at(HeapTermSlot::from_index(start))
                            .map_err(map_term_build_error)?,
                    )
                }
            }
            67 => {
                // Port of erts/emulator/beam/external.c:5257-5385 (`dec_term`, RECORD_EXT),
                // OTP-29.1.1: the definition is read inline, the values are the next terms.
                let fields = r.u32()? as usize;
                let exported = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(BifError::BADARG),
                };
                let module = r.atom(safe, true)?.0.as_atom().ok_or(BifError::BADARG)?;
                let name = r.atom(safe, true)?.0.as_atom().ok_or(BifError::BADARG)?;
                let mut keys = SmallVec::<[Atom; 8]>::new();
                for _ in 0..fields {
                    keys.push(r.atom(safe, true)?.0.as_atom().ok_or(BifError::BADARG)?);
                }
                let (term, slots) = heap
                    .reserve_native_record(module, name, exported, &keys)
                    .map_err(map_term_build_error)?;
                if !slots.is_empty() {
                    let mut child = continuation
                        .map(|slot| decode_heap_slot(heap, slot))
                        .transpose()?;
                    for slot in slots.iter().rev() {
                        heap.write_next_slot(*slot, child)
                            .map_err(map_term_build_error)?;
                        child = Some(*slot);
                    }
                    *next = decode_slot_ptrs(heap, child)?;
                    next_was_set = true;
                }
                Some(term)
            }
            _ => return Err(BifError::BADARG),
        };
        if let Some(term) = term {
            if !defer_output {
                write_decode_target(target, root, term)?;
            }
            *root_started = true;
            if !next_was_set {
                *next = continuation;
            }
        } else if !reprocess_target && !*root_started {
            *root_started = true;
        }
        if tag != 121 {
            work += 1;
        }
        cur = *next;
        if !matches!(tag, 97 | 98 | 104 | 105 | 106 | 107 | 108) {
            let (_, cursor) = heap.words_and_cursor();
            hp = *cursor;
        }
        if yield_after_write {
            return Ok((None, work));
        }
        if work >= budget && cur.is_some() {
            // Publish `next` only when the reduction budget stops this invocation.
            *next = cur;
            return Ok((None, work));
        }
    }
}
