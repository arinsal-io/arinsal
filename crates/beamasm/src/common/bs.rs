//! Port of erts/emulator/beam/jit/beam_jit_bs.hpp and erts/emulator/beam/jit/beam_jit_bs.cpp
//! (`beam_jit_bsc_combine_segments`, `beam_jit_bsm_init`, `beam_jit_opt_bsm_segments`),
//! OTP-29.1.1: the architecture-neutral bit syntax segment planning both emitters use.

use crate::common::args::ArgVal;

/// `SMALL_BITS`: bits of a small integer on a 64-bit target.
pub(crate) const SMALL_BITS: u64 = 60;
pub(crate) const ERL_ONHEAP_BITS_LIMIT: u64 = 64 * 8;
/// Words of a sub-bitstring (erl_bits.h, ERL_SUB_BITS_SIZE).
pub(crate) const ERL_SUB_BITS_SIZE: u64 = 5;
/// `BUILD_SUB_BITSTRING_HEAP_NEED`: `MAX(ERL_SUB_BITS_SIZE, heap_bits_size(ERL_ONHEAP_BITS_LIMIT))`.
pub(crate) const BUILD_SUB_BITSTRING_HEAP_NEED: u64 = 2 + 64 / 8;

/// One command of a `bs_match` list, decoded from the loader operands.
#[derive(Clone, Copy, Debug)]
pub enum BsmCommand {
    /// `{ensure_at_least, Size, Unit}`.
    EnsureAtLeast { size: u64, unit: u64 },
    /// `{ensure_exactly, Size}`.
    EnsureExactly { size: u64 },
    /// `{integer, Live, Flags, Size, Unit, Dst}`; `live` is `None` for `nil`.
    Integer {
        live: Option<u32>,
        flags: u64,
        size: u64,
        unit: u64,
        dst: ArgVal,
    },
    /// `{binary, Live, Flags, Size, Unit, Dst}`.
    Binary {
        live: Option<u32>,
        flags: u64,
        size: u64,
        unit: u64,
        dst: ArgVal,
    },
    /// `{get_tail, Live, Unit, Dst}`.
    GetTail { live: Option<u32>, dst: ArgVal },
    /// `{skip, Size}`.
    Skip { size: u64 },
    /// `{'=:=', Live, Size, Value}`.
    Eq {
        live: Option<u32>,
        size: u64,
        value: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    EnsureAtLeast,
    EnsureExactly,
    Eq,
    TestHeap,
    Read,
    ExtractBitstring,
    ExtractInteger,
    ReadInteger,
    GetInteger,
    GetBitstring,
    GetTail,
    Skip,
    Drop,
}

/// `BsmSegment` (beam_jit_bs.hpp:73-98).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Segment {
    pub(crate) action: Action,
    pub(crate) live: Option<u32>,
    pub(crate) size: u64,
    pub(crate) unit: u64,
    pub(crate) flags: u64,
    pub(crate) dst: Option<ArgVal>,
}

impl Segment {
    pub(crate) fn new(action: Action) -> Self {
        Segment {
            action,
            live: None,
            size: 0,
            unit: 0,
            flags: 0,
            dst: None,
        }
    }
}

/// `erts_extracted_bitstring_size` (erl_bits.h:585-593) for fields the segments extract
/// inline (at most 64 bits, always a heap bitstring).
///
/// Wider fields go through `TermBuilder::sub_binary`, which allocates a BinRef plus a
/// SubBits (8 words) over a refc owner instead of erts' single SubBits, so the reservation
/// uses that builder's bound until the binary owner layout is the erts one.
fn extracted_bitstring_size(bits: u64) -> u64 {
    if bits <= 64 {
        heap_bits_size(bits)
    } else if bits <= ERL_ONHEAP_BITS_LIMIT {
        heap_bits_size(bits).max(8)
    } else {
        8.max(ERL_SUB_BITS_SIZE)
    }
}

/// The segments of the arm64 loader's decoded `bs_match` commands (`BsmCommand`); the
/// x86-64 emitter reads the loader's `ArgVal` list with [`beam_jit_bsm_init`] as erts does.
// Port of erts/emulator/beam/jit/beam_jit_bs.cpp:287-364 (beam_jit_bsm_init), OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
pub(crate) fn bsm_init(commands: &[BsmCommand]) -> Vec<Segment> {
    commands
        .iter()
        .map(|command| match *command {
            BsmCommand::EnsureAtLeast { size, unit } => Segment {
                size,
                unit,
                ..Segment::new(Action::EnsureAtLeast)
            },
            BsmCommand::EnsureExactly { size } => Segment {
                size,
                ..Segment::new(Action::EnsureExactly)
            },
            BsmCommand::Integer {
                live,
                flags,
                size,
                unit,
                dst,
            } => Segment {
                live,
                size: size * unit,
                unit,
                flags,
                dst: Some(dst),
                ..Segment::new(Action::GetInteger)
            },
            BsmCommand::Binary {
                live,
                flags,
                size,
                unit,
                dst,
            } => Segment {
                live,
                size: size * unit,
                unit,
                flags,
                dst: Some(dst),
                ..Segment::new(Action::GetBitstring)
            },
            BsmCommand::GetTail { live, dst } => Segment {
                live,
                dst: Some(dst),
                ..Segment::new(Action::GetTail)
            },
            BsmCommand::Skip { size } => Segment {
                size,
                ..Segment::new(Action::Skip)
            },
            BsmCommand::Eq { live, size, value } => Segment {
                live,
                size,
                unit: value,
                ..Segment::new(Action::Eq)
            },
        })
        .collect()
}

/// `bs_get_flags(beam, val)`: the flags of a `bs_match` segment, NIL, a flag list literal
/// or a word (from `bs_get_integer2`).
// Port of erts/emulator/beam/jit/beam_jit_bs.cpp:255-285 (bs_get_flags), OTP-29.1.1.
#[cfg(target_arch = "x86_64")]
fn bs_get_flags(val: ArgVal) -> Result<u64, &'static str> {
    if val.is_nil() {
        Ok(0)
    } else if let Some(word) = val.word() {
        Ok(word)
    } else if val.is_literal() {
        // Walking the flag list (`am_little`/`am_native` -> BSF_LITTLE, `am_signed` ->
        // BSF_SIGNED) needs a safe cons view in `arinsal_term::raw`, which it lacks.
        Err("bs_match flag list literal (no safe cons view in arinsal_term::raw)")
    } else {
        Err("bs_match flags")
    }
}

/// `seg.live = current[0]`: NIL or a word.
#[cfg(target_arch = "x86_64")]
fn bsm_live(val: ArgVal) -> Result<Option<u32>, &'static str> {
    if val.is_nil() {
        Ok(None)
    } else {
        val.word()
            .map(|live| Some(live as u32))
            .ok_or("bs_match live")
    }
}

/// `beam_jit_bsm_init(beam, List)`: the segments of an `i_bs_match` command list, as the
/// loader hands it to the emitter (`{atom, operands...}` flattened).
// Port of erts/emulator/beam/jit/beam_jit_bs.cpp:287-364 (beam_jit_bsm_init), OTP-29.1.1.
#[cfg(target_arch = "x86_64")]
pub(crate) fn beam_jit_bsm_init(list: &[ArgVal]) -> Result<Vec<Segment>, &'static str> {
    use arinsal_term::{Term, atoms};
    let atom = |a| Term::atom(a).word();
    let word = |val: ArgVal| val.word().ok_or("bs_match word operand");
    let mut segments = Vec::new();
    let mut current = 0;
    let arg = |index: usize| list.get(index).copied().ok_or("bs_match list too short");
    while current < list.len() {
        let cmd = arg(current)?.immed().ok_or("bs_match command")?;
        current += 1;
        let seg = if cmd == atom(atoms::ENSURE_AT_LEAST) {
            current += 2;
            Segment {
                size: word(arg(current - 2)?)?,
                unit: word(arg(current - 1)?)?,
                ..Segment::new(Action::EnsureAtLeast)
            }
        } else if cmd == atom(atoms::ENSURE_EXACTLY) {
            current += 1;
            Segment {
                size: word(arg(current - 1)?)?,
                ..Segment::new(Action::EnsureExactly)
            }
        } else if cmd == atom(atoms::BINARY) || cmd == atom(atoms::INTEGER) {
            let size = word(arg(current + 2)?)?;
            let unit = word(arg(current + 3)?)?;
            let action = if cmd == atom(atoms::INTEGER) {
                Action::GetInteger
            } else {
                Action::GetBitstring
            };
            let dst = arg(current + 4)?;
            if !dst.is_register() {
                return Err("bs_match destination");
            }
            let seg = Segment {
                live: bsm_live(arg(current)?)?,
                size: size * unit,
                unit,
                flags: bs_get_flags(arg(current + 1)?)?,
                dst: Some(dst),
                ..Segment::new(action)
            };
            current += 5;
            seg
        } else if cmd == atom(atoms::GET_TAIL) {
            let dst = arg(current + 2)?;
            if !dst.is_register() {
                return Err("bs_match destination");
            }
            let seg = Segment {
                live: Some(word(arg(current)?)? as u32),
                dst: Some(dst),
                ..Segment::new(Action::GetTail)
            };
            current += 3;
            seg
        } else if cmd == atom(atoms::SKIP) {
            current += 1;
            Segment {
                size: word(arg(current - 1)?)?,
                flags: 0,
                ..Segment::new(Action::Skip)
            }
        } else if cmd == atom(atoms::EQ) {
            let seg = Segment {
                live: bsm_live(arg(current)?)?,
                size: word(arg(current + 1)?)?,
                unit: word(arg(current + 2)?)?,
                ..Segment::new(Action::Eq)
            };
            current += 3;
            seg
        } else {
            // `abort()`.
            return Err("unknown bs_match command");
        };
        segments.push(seg);
    }
    Ok(segments)
}

/// `heap_bits_size` (erl_bits.h:155-161).
pub(crate) fn heap_bits_size(bits: u64) -> u64 {
    2 + bits.div_ceil(8).div_ceil(8)
}

/// Port of beam_jit_bs.cpp:366-528 (beam_jit_opt_bsm_segments).
pub(crate) fn opt_bsm_segments(segments: &[Segment], need: u64, live: u32) -> Vec<Segment> {
    let mut segs: Vec<Segment> = Vec::with_capacity(segments.len() * 2);
    let mut heap_need = need;

    for seg in segments {
        match seg.action {
            Action::GetInteger if seg.size >= SMALL_BITS => {
                // BIG_NEED_FOR_BITS
                heap_need += (seg.size - 1) / 64 + 1 + 1;
            }
            Action::GetBitstring => heap_need += extracted_bitstring_size(seg.size),
            Action::GetTail => heap_need += BUILD_SUB_BITSTRING_HEAP_NEED,
            _ => {}
        }
    }

    let mut read_action_pos: Option<usize> = None;
    let count = segments.len();

    for (i, original) in segments.iter().enumerate() {
        let mut seg = *original;
        if heap_need != 0 && seg.live.is_some() {
            let mut s = seg;
            read_action_pos = None;
            s.action = Action::TestHeap;
            s.size = heap_need;
            segs.push(s);
            heap_need = 0;
        }

        match seg.action {
            Action::GetInteger | Action::GetBitstring => {
                let is_common_size = matches!(seg.size, 8 | 16 | 32);
                if seg.size > 64 {
                    read_action_pos = None;
                } else if read_action_pos.is_none()
                    && seg.action == Action::GetInteger
                    && is_common_size
                    && i + 1 == count
                {
                    seg.action = Action::ReadInteger;
                    read_action_pos = None;
                } else {
                    match read_action_pos {
                        Some(pos) if seg.size + segs[pos].size <= 64 => {
                            segs[pos].size += seg.size;
                        }
                        _ => {
                            read_action_pos = Some(segs.len());
                            let mut s = Segment::new(Action::Read);
                            s.size = seg.size;
                            segs.push(s);
                        }
                    }
                    seg.action = match seg.action {
                        Action::GetInteger => Action::ExtractInteger,
                        _ => Action::ExtractBitstring,
                    };
                }
                segs.push(seg);
            }
            Action::Eq => {
                match read_action_pos {
                    Some(pos) if seg.size + segs[pos].size <= 64 => {
                        segs[pos].size += seg.size;
                    }
                    _ => {
                        read_action_pos = Some(segs.len());
                        let mut s = Segment::new(Action::Read);
                        s.size = seg.size;
                        segs.push(s);
                    }
                }
                let last = segs.last_mut().expect("a segment was just pushed");
                if last.action == Action::Eq && last.size + seg.size <= 64 {
                    // Coalesce with the previous EQ instruction.
                    last.size += seg.size;
                    last.unit = last.unit.checked_shl(seg.size as u32).unwrap_or(0) | seg.unit;
                } else {
                    segs.push(seg);
                }
            }
            Action::Skip => {
                match read_action_pos {
                    Some(pos) if seg.size + segs[pos].size <= 64 => {
                        segs[pos].size += seg.size;
                        seg.action = Action::Drop;
                    }
                    _ => read_action_pos = None,
                }
                segs.push(seg);
            }
            _ => {
                read_action_pos = None;
                segs.push(seg);
            }
        }
    }

    // A trailing test_heap (for i_bs_match_test_heap).
    if heap_need != 0 {
        let mut seg = Segment::new(Action::TestHeap);
        seg.size = heap_need;
        seg.live = Some(live);
        segs.push(seg);
    }
    segs
}

pub(crate) struct AccSeg {
    pub(crate) src: ArgVal,
    pub(crate) bits: u64,
    pub(crate) offset: u64,
}

pub(crate) struct Group {
    pub(crate) bits: u64,
    pub(crate) segs: Vec<AccSeg>,
}

/// Groups big-endian integer fields into 64-bit accumulator stores.
// Port of erts/emulator/beam/jit/beam_jit_bs.cpp:162-250 (beam_jit_bsc_combine_segments).
pub(crate) fn combine(segs: &[AccSeg]) -> Vec<Group> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut combined = 0u64;
    for (index, seg) in segs.iter().enumerate() {
        if index == start {
            combined = seg.bits;
            continue;
        }
        if combined + seg.bits <= 64 {
            combined += seg.bits;
            continue;
        }
        out.push(finish_group(segs, start, index, combined));
        start = index;
        combined = seg.bits;
    }
    if start < segs.len() {
        out.push(finish_group(segs, start, segs.len(), combined));
    }
    out
}

fn finish_group(segs: &[AccSeg], start: usize, end: usize, bits: u64) -> Group {
    let mut offset = 64 - bits;
    let mut grouped = Vec::with_capacity(end - start);
    for seg in segs[start..end].iter().rev() {
        grouped.push(AccSeg {
            src: seg.src,
            bits: seg.bits,
            offset,
        });
        offset += seg.bits;
    }
    grouped.reverse();
    Group {
        bits,
        segs: grouped,
    }
}
