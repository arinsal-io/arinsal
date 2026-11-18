//! Port of erts/emulator/beam/jit/beam_jit_bs.hpp and erts/emulator/beam/jit/beam_jit_bs.cpp
//! (`beam_jit_bsc_combine_segments`, `beam_jit_bsm_init`, `beam_jit_opt_bsm_segments`),
//! OTP-29.1.1: the architecture-neutral bit syntax segment planning both emitters use.

use crate::common::args::ArgVal;
use arinsal_term::{Term, atoms};

/// `BscSegment` (beam_jit_bs.hpp): one six-operand binary-construction segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BscSegment {
    pub(crate) type_: ArgVal,
    pub(crate) unit: u64,
    pub(crate) flags: u64,
    pub(crate) src: ArgVal,
    pub(crate) size: ArgVal,
    pub(crate) error_info: u64,
    pub(crate) offset_in_accumulator: u64,
    pub(crate) effective_size: i64,
    pub(crate) action: BscAction,
}

impl BscSegment {
    pub(crate) fn new() -> Self {
        Self {
            type_: ArgVal::Immediate(Term::atom(atoms::FALSE).word()),
            unit: 1,
            flags: 0,
            src: ArgVal::Immediate(Term::NIL.word()),
            size: ArgVal::Immediate(Term::NIL.word()),
            error_info: 0,
            offset_in_accumulator: 0,
            effective_size: -1,
            action: BscAction::Direct,
        }
    }
}

/// Sub-actions used to accumulate adjacent small integer segments into one word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BscAction {
    Direct,
    AccumulateFirst,
    Accumulate,
    Store,
}

/// Operation encoded in the packed `error_info` field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub(crate) enum BscOp {
    Bitstring = 0,
    Float = 1,
    Integer = 2,
    Utf8 = 3,
    Utf16 = 4,
    Utf32 = 5,
}

/// Failure class encoded in the packed `error_info` field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub(crate) enum BscReason {
    Badarg = 0,
    SystemLimit = 1,
    Depends = 2,
}

/// Failed operand encoded in the packed `error_info` field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub(crate) enum BscInfo {
    Fvalue = 0,
    Type = 1,
    Size = 2,
    Unit = 3,
    Depends = 4,
}

/// Value location encoded in the packed `error_info` field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub(crate) enum BscValue {
    Arg1 = 0,
    #[expect(
        dead_code,
        reason = "erts reserves this packed value source for segment errors"
    )]
    Arg3 = 1,
    Fvalue = 2,
}

/// Packs a segment index and its operation as `beam_jit_set_bsc_segment_op` does.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:466-475, OTP-29.1.1.
fn set_bsc_segment_op(segment: u64, op: BscOp) -> u64 {
    (segment << 10) | ((op as u64) << 7)
}

/// Adds failure details to an existing packed segment error value.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:478-483 (beam_jit_update_bsc_reason_info),
// OTP-29.1.1.
pub(crate) fn update_bsc_reason_info(
    packed_info: u64,
    reason: BscReason,
    info: BscInfo,
    value: BscValue,
) -> u64 {
    packed_info | ((value as u64) << 2) | ((info as u64) << 4) | reason as u64
}

fn atom_arg(atom: arinsal_term::Atom) -> ArgVal {
    ArgVal::Immediate(Term::atom(atom).word())
}

/// Reads the six typed operands for every `bs_create_bin` segment and packs its error origin.
// Port of erts/emulator/beam/jit/beam_jit_bs.cpp:35-85 (beam_jit_bsc_init), OTP-29.1.1.
pub(crate) fn beam_jit_bsc_init(args: &[ArgVal]) -> Vec<BscSegment> {
    let mut segments = Vec::new();
    for args in args.as_chunks::<6>().0 {
        let mut seg = BscSegment::new();
        seg.type_ = args[0];
        let segment = args[1].word().expect("bsc segment index is an ArgWord");
        seg.unit = args[2].word().expect("bsc unit is an ArgWord");
        seg.flags = args[3].word().expect("bsc flags are an ArgWord");
        seg.src = args[4];
        seg.size = args[5];

        let op = if seg.type_ == atom_arg(atoms::FLOAT) {
            BscOp::Float
        } else if seg.type_ == atom_arg(atoms::INTEGER) {
            BscOp::Integer
        } else if seg.type_ == atom_arg(atoms::UTF8) {
            BscOp::Utf8
        } else if seg.type_ == atom_arg(atoms::UTF16) {
            BscOp::Utf16
        } else if seg.type_ == atom_arg(atoms::UTF32) {
            BscOp::Utf32
        } else {
            BscOp::Bitstring
        };
        seg.error_info = set_bsc_segment_op(segment, op);
        segments.push(seg);
    }
    segments
}

/// Combines compatible integer segments using erts' accumulator actions and bit offsets.
// Port of erts/emulator/beam/jit/beam_jit_bs.cpp:89-250
// (fold_group, push_group, beam_jit_bsc_combine_segments), OTP-29.1.1.
pub(crate) fn beam_jit_bsc_combine_segments(segments: &[BscSegment]) -> Vec<BscSegment> {
    use core::iter::Rev;
    use core::slice::Iter;

    fn fold_group<I>(out: &mut Vec<BscSegment>, iter: I, first: BscSegment) -> i64
    where
        I: Iterator<Item = BscSegment>,
    {
        let mut head = first;
        head.action = BscAction::AccumulateFirst;
        let mut total = head.effective_size;
        out.push(head);
        for mut seg in iter {
            seg.action = BscAction::Accumulate;
            total += seg.effective_size;
            out.push(seg);
        }
        total
    }

    fn push_group(out: &mut Vec<BscSegment>, group: &[BscSegment], start: usize, end: usize) {
        if start >= end {
            return;
        }
        let first = group[start];
        let little = first.flags & 2 != 0;
        let total = if little {
            let mut rev: Rev<Iter<'_, BscSegment>> = group[start..end].iter().rev();
            let first = *rev.next().expect("non-empty integer group");
            fold_group(out, rev.copied(), first)
        } else {
            let mut iter = group[start..end].iter().copied();
            let first = iter.next().expect("non-empty integer group");
            fold_group(out, iter, first)
        };
        out.push(BscSegment {
            type_: atom_arg(atoms::INTEGER),
            action: BscAction::Store,
            effective_size: total,
            flags: first.flags,
            ..BscSegment::new()
        });
    }

    let mut out = Vec::new();
    let mut group_start = None;
    let mut combined_size = 0i64;

    for (index, seg) in segments.iter().copied().enumerate() {
        if seg.type_ == atom_arg(atoms::INTEGER) {
            if !(0 < seg.effective_size && seg.effective_size <= 64) {
                if let Some(start) = group_start.take() {
                    push_group(&mut out, segments, start, index);
                }
                out.push(seg);
                continue;
            }

            if group_start.is_none() {
                group_start = Some(index);
                combined_size = seg.effective_size;
                continue;
            }

            let start = group_start.expect("integer group has a start");
            let first = segments[start];
            let same_endian = (seg.flags & 2) == (first.flags & 2);
            let suitable_sizes = seg.flags & 2 == 0 || combined_size % 8 == 0;
            if same_endian && combined_size + seg.effective_size <= 64 && suitable_sizes {
                combined_size += seg.effective_size;
                continue;
            }

            push_group(&mut out, segments, start, index);
            group_start = Some(index);
            combined_size = seg.effective_size;
        } else {
            if let Some(start) = group_start.take() {
                push_group(&mut out, segments, start, index);
            }
            out.push(seg);
        }
    }

    if let Some(start) = group_start {
        push_group(&mut out, segments, start, segments.len());
    }

    let mut offset = 0u64;
    for seg in out.iter_mut().rev() {
        match seg.action {
            BscAction::Store => offset = 64 - seg.effective_size as u64,
            BscAction::AccumulateFirst | BscAction::Accumulate => {
                seg.offset_in_accumulator = offset;
                offset += seg.effective_size as u64;
            }
            BscAction::Direct => {}
        }
    }
    out
}

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
