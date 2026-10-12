//! `i_bs_match` / `i_bs_match_test_heap`: segment optimiser and emitter.
//!
//! Port of erts/emulator/beam/jit/beam_jit_bs.cpp:287-528 (`beam_jit_bsm_init`,
//! `beam_jit_opt_bsm_segments`) and erts/emulator/beam/jit/arm/instr_bs.cpp:2496-3210
//! (`emit_read_bits`, `emit_extract_integer`, `emit_extract_bitstring`,
//! `emit_i_bs_match_test_heap`), OTP-29.1.1.

use crate::bs_match::{BsMatchCmdHelper, BsMatchHelper};
use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::{Cond, Gpr, Shift, Shifted};

/// `BSF_LITTLE`, `BSF_SIGNED` (erts/emulator/beam/erl_bits.h).
const BSF_LITTLE: u64 = 2;
const BSF_SIGNED: u64 = 4;
/// `SMALL_BITS`: bits of a small integer on a 64-bit target.
const SMALL_BITS: u64 = 60;
/// Offset of `ErlSubBits` fields from the (untagged) pointer.
const BASE_FLAGS_OFFSET: u32 = 8;
const START_OFFSET: i16 = 16;
const END_OFFSET: i16 = 24;
/// `emit_boxed_val`: the box tag is subtracted from field displacements.
const BOXED_TAG: i16 = 2;
/// `ERL_SUB_BITS_FLAG_MASK`.
const SUB_BITS_FLAG_MASK: u64 = 3;
const ERL_ONHEAP_BITS_LIMIT: u64 = 64 * 8;
/// Words of a sub-bitstring (erl_bits.h, ERL_SUB_BITS_SIZE).
const ERL_SUB_BITS_SIZE: u64 = 5;
/// `BUILD_SUB_BITSTRING_HEAP_NEED`: `MAX(ERL_SUB_BITS_SIZE, heap_bits_size(ERL_ONHEAP_BITS_LIMIT))`.
const BUILD_SUB_BITSTRING_HEAP_NEED: u64 = 2 + 64 / 8;
const TAG_PRIMARY_BOXED: u16 = 2;
const TAG_IMMED1_SMALL: u64 = 0xf;
const TAG_IMMED1_SIZE: u8 = 4;
/// Subtags for heap bitstrings and one-word bignums (erl_term.h).
const HEAP_BITS_SUBTAG: u64 = 0x20;
const POS_BIG_SUBTAG: u64 = 0x08;
const NEG_BIG_SUBTAG: u64 = 0x0c;

// Register roles of the erts arm port (beam_asm.hpp:153-172), mapped one to one.
const ARG1: Gpr = Gpr::x(0);
const BIN_BASE: Gpr = Gpr::x(1);
const BIN_POSITION: Gpr = Gpr::x(2);
const BIN_SIZE: Gpr = Gpr::x(3);
const SMALL_TAG: Gpr = Gpr::x(4);
const BITDATA: Gpr = Gpr::x(7);
const TMP1: Gpr = Gpr::x(8);
const TMP2: Gpr = Gpr::x(9);
const TMP3: Gpr = Gpr::x(10);
const TMP4: Gpr = Gpr::x(11);
const TMP5: Gpr = Gpr::x(12);
const SUPER_TMP: Gpr = Gpr::x(14);
const HTOP: Gpr = Gpr::x(23);

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
enum Action {
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
struct Segment {
    action: Action,
    live: Option<u32>,
    size: u64,
    unit: u64,
    flags: u64,
    dst: Option<ArgVal>,
}

impl Segment {
    fn new(action: Action) -> Self {
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

/// Port of beam_jit_bs.cpp:287-364 (beam_jit_bsm_init).
fn bsm_init(commands: &[BsmCommand]) -> Vec<Segment> {
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

/// `heap_bits_size` (erl_bits.h:155-161).
fn heap_bits_size(bits: u64) -> u64 {
    2 + bits.div_ceil(8).div_ceil(8)
}

/// Port of beam_jit_bs.cpp:366-528 (beam_jit_opt_bsm_segments).
fn opt_bsm_segments(segments: &[Segment], need: u64, live: u32) -> Vec<Segment> {
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

impl BeamModuleAssembler {
    /// `ctx_reg = load_source(Ctx, scratch)`.
    fn bsm_load_ctx(&mut self, ctx: ArgVal, scratch: Gpr) -> Result<Gpr, ModuleError> {
        self.source_reg_into(ctx, scratch)
    }

    /// `cmp(reg, value)` with `SUPER_TMP` for constants that need materialising.
    fn bsm_cmp(&mut self, reg: Gpr, value: u64) -> Result<(), ModuleError> {
        if value <= 0xfff {
            self.code.emit(|e| e.cmp_imm(reg, value as u16, false))?;
        } else if value <= 0xfff_000 && value & 0xfff == 0 {
            self.code
                .emit(|e| e.cmp_imm(reg, (value >> 12) as u16, true))?;
        } else {
            let tmp = if reg.width == arinsal_a64::enc::Width::X64 {
                SUPER_TMP
            } else {
                Gpr::w(14)
            };
            self.code.emit(|e| {
                e.mov_const(tmp, value)?;
                e.cmp_reg(reg, tmp, Shift::Lsl, 0)
            })?;
        }
        Ok(())
    }

    /// `add(dst, src, value)` / `sub(dst, src, value)` as the erts `add`/`sub` helpers.
    fn bsm_add_sub(
        &mut self,
        dst: Gpr,
        src: Gpr,
        value: u64,
        sub: bool,
    ) -> Result<(), ModuleError> {
        if value == 0 {
            if dst != src {
                self.code.emit(|e| e.mov_reg(dst, src))?;
            }
        } else if value <= 0xfff {
            self.code.emit(|e| {
                if sub {
                    e.sub_imm(dst, src, value as u16, false)
                } else {
                    e.add_imm(dst, src, value as u16, false)
                }
            })?;
        } else if value <= 0xfff_000 && value & 0xfff == 0 {
            self.code.emit(|e| {
                if sub {
                    e.sub_imm(dst, src, (value >> 12) as u16, true)
                } else {
                    e.add_imm(dst, src, (value >> 12) as u16, true)
                }
            })?;
        } else {
            self.code.emit(|e| {
                e.mov_const(SUPER_TMP, value)?;
                if sub {
                    e.sub_reg(dst, src, SUPER_TMP, Shift::Lsl, 0)
                } else {
                    e.add_reg(dst, src, SUPER_TMP, Shift::Lsl, 0)
                }
            })?;
        }
        Ok(())
    }

    /// Port of instr_bs.cpp:2496-2748 (emit_read_bits).
    fn bsm_read_bits(&mut self, bits: u64) -> Result<(), ModuleError> {
        let handle_partial = self.code.new_label();
        let rev64 = self.code.new_label();
        let shift = self.code.new_label();
        let read_done = self.code.new_label();

        let mut need_rev64 = false;
        let mut need_shift = true;

        let ptr = TMP2;
        let bit_offset = TMP4;
        let tmp_w = Gpr::w(12);
        let bitdata_w = Gpr::w(7);
        let num_partial = (bits % 8) as u16;
        debug_assert!((1..=64).contains(&bits));

        self.code
            .emit(|e| e.add_reg(ptr, BIN_BASE, BIN_POSITION, Shift::Lsr, 3))?;

        if bits <= 8 {
            self.code
                .emit(|e| e.ands_imm(bit_offset, BIN_POSITION, 7))?;
            if num_partial == 0 {
                self.code.b_cond(Cond::Ne, handle_partial)?;
            } else if num_partial > 1 {
                self.code
                    .emit(|e| e.cmp_imm(bit_offset, 8 - num_partial, false))?;
                self.code.b_cond(Cond::Gt, handle_partial)?;
            }
            self.code.emit(|e| e.ldrb_uoff(bitdata_w, ptr, 0))?;
            if num_partial == 0 {
                self.code.emit(|e| e.rev64(BITDATA, BITDATA))?;
                self.code.b(read_done)?;
            } else if num_partial > 1 {
                self.code.b(rev64)?;
            }
            self.code.bind(handle_partial)?;
            if num_partial != 1 {
                self.code.emit(|e| e.ldrh_uoff(bitdata_w, ptr, 0))?;
            }
            need_rev64 = true;
        } else if bits <= 16 {
            self.code.emit(|e| {
                e.ands_imm(bit_offset, BIN_POSITION, 7)?;
                e.ldrh_uoff(bitdata_w, ptr, 0)?;
                e.rev64(BITDATA, BITDATA)
            })?;
            self.code.b_cond(Cond::Eq, read_done)?;
            self.code.bind(handle_partial)?;
            if num_partial > 1 {
                self.code
                    .emit(|e| e.cmp_imm(bit_offset, 8 - num_partial, false))?;
                self.code.b_cond(Cond::Le, shift)?;
            }
            if num_partial != 1 {
                self.code.emit(|e| {
                    e.ldrb_uoff(tmp_w, ptr, 2)?;
                    e.orr_reg(
                        BITDATA,
                        BITDATA,
                        Shifted {
                            reg: TMP5,
                            shift: Shift::Lsl,
                            amount: 40,
                        },
                    )
                })?;
            }
        } else if bits <= 24 {
            self.code
                .emit(|e| e.ands_imm(bit_offset, BIN_POSITION, 7))?;
            if num_partial == 0 {
                self.code.b_cond(Cond::Ne, handle_partial)?;
            } else if num_partial > 1 {
                self.code
                    .emit(|e| e.cmp_imm(bit_offset, 8 - num_partial, false))?;
                self.code.b_cond(Cond::Gt, handle_partial)?;
            }
            self.code.emit(|e| {
                e.ldrh_uoff(bitdata_w, ptr, 0)?;
                e.ldrb_uoff(tmp_w, ptr, 2)?;
                e.orr_reg(
                    BITDATA,
                    BITDATA,
                    Shifted {
                        reg: TMP5,
                        shift: Shift::Lsl,
                        amount: 16,
                    },
                )
            })?;
            if num_partial == 0 {
                self.code.emit(|e| e.rev64(BITDATA, BITDATA))?;
                self.code.b(read_done)?;
            } else if num_partial > 1 {
                self.code.b(rev64)?;
            }
            self.code.bind(handle_partial)?;
            if num_partial != 1 {
                self.code.emit(|e| e.ldr_uoff(bitdata_w, ptr, 0))?;
            }
            need_rev64 = true;
        } else if bits <= 32 {
            self.code.emit(|e| {
                e.ands_imm(bit_offset, BIN_POSITION, 7)?;
                e.ldr_uoff(bitdata_w, ptr, 0)?;
                e.rev64(BITDATA, BITDATA)
            })?;
            self.code.b_cond(Cond::Eq, read_done)?;
            self.code.bind(handle_partial)?;
            if num_partial > 0 {
                self.code
                    .emit(|e| e.cmp_imm(bit_offset, 8 - num_partial, false))?;
                self.code.b_cond(Cond::Le, shift)?;
            }
            if num_partial != 1 {
                self.code.emit(|e| {
                    e.ldrb_uoff(tmp_w, ptr, 4)?;
                    e.orr_reg(
                        BITDATA,
                        BITDATA,
                        Shifted {
                            reg: TMP5,
                            shift: Shift::Lsl,
                            amount: 24,
                        },
                    )
                })?;
            }
        } else if bits <= 40 {
            self.code.emit(|e| {
                e.ands_imm(bit_offset, BIN_POSITION, 7)?;
                e.ldr_uoff(bitdata_w, ptr, 0)?;
                e.rev64(BITDATA, BITDATA)
            })?;
            if num_partial == 0 {
                self.code.b_cond(Cond::Ne, handle_partial)?;
            } else if num_partial > 1 {
                self.code
                    .emit(|e| e.cmp_imm(bit_offset, 8 - num_partial, false))?;
                self.code.b_cond(Cond::Gt, handle_partial)?;
            }
            self.code.emit(|e| {
                e.ldrb_uoff(tmp_w, ptr, 4)?;
                e.orr_reg(
                    BITDATA,
                    BITDATA,
                    Shifted {
                        reg: TMP5,
                        shift: Shift::Lsl,
                        amount: 24,
                    },
                )
            })?;
            if num_partial == 0 {
                self.code.b(read_done)?;
            } else if num_partial > 1 {
                self.code.b(shift)?;
            }
            self.code.bind(handle_partial)?;
            if num_partial != 1 {
                self.code.emit(|e| {
                    e.ldrh_uoff(tmp_w, ptr, 4)?;
                    e.rev16(tmp_w, tmp_w)?;
                    e.orr_reg(
                        BITDATA,
                        BITDATA,
                        Shifted {
                            reg: TMP5,
                            shift: Shift::Lsl,
                            amount: 16,
                        },
                    )
                })?;
            }
        } else if bits <= 48 {
            self.code.emit(|e| {
                e.ands_imm(bit_offset, BIN_POSITION, 7)?;
                e.ldr_uoff(bitdata_w, ptr, 0)?;
                e.ldrh_uoff(tmp_w, ptr, 4)?;
                e.orr_reg(
                    BITDATA,
                    BITDATA,
                    Shifted {
                        reg: TMP5,
                        shift: Shift::Lsl,
                        amount: 32,
                    },
                )?;
                e.rev64(BITDATA, BITDATA)
            })?;
            self.code.b_cond(Cond::Eq, read_done)?;
            self.code.bind(handle_partial)?;
            if num_partial > 1 {
                self.code
                    .emit(|e| e.cmp_imm(bit_offset, 8 - num_partial, false))?;
                self.code.b_cond(Cond::Le, shift)?;
            }
            if num_partial != 1 {
                self.code.emit(|e| {
                    e.ldrb_uoff(tmp_w, ptr, 6)?;
                    e.orr_reg(
                        BITDATA,
                        BITDATA,
                        Shifted {
                            reg: TMP5,
                            shift: Shift::Lsl,
                            amount: 8,
                        },
                    )
                })?;
            }
        } else if bits <= 56 {
            self.code
                .emit(|e| e.ands_imm(bit_offset, BIN_POSITION, 7))?;
            if num_partial == 0 {
                self.code.b_cond(Cond::Ne, handle_partial)?;
            } else if num_partial > 1 {
                self.code
                    .emit(|e| e.cmp_imm(bit_offset, 8 - num_partial, false))?;
                self.code.b_cond(Cond::Gt, handle_partial)?;
            }
            self.code.emit(|e| {
                e.ldur(BITDATA, ptr, -1)?;
                e.lsr_imm(BITDATA, BITDATA, 8)
            })?;
            self.code.b(rev64)?;
            self.code.bind(handle_partial)?;
            if num_partial != 1 {
                self.code.emit(|e| e.ldr_uoff(BITDATA, ptr, 0))?;
            }
            need_rev64 = true;
        } else {
            self.code.emit(|e| {
                e.ands_imm(bit_offset, BIN_POSITION, 7)?;
                e.ldr_uoff(BITDATA, ptr, 0)?;
                e.rev64(BITDATA, BITDATA)
            })?;
            if num_partial == 0 {
                self.code.b_cond(Cond::Eq, read_done)?;
            } else if num_partial == 1 {
                self.code.b(shift)?;
            } else {
                self.code
                    .emit(|e| e.cmp_imm(bit_offset, 8 - num_partial, false))?;
                self.code.b_cond(Cond::Le, shift)?;
            }
            self.code.bind(handle_partial)?;
            if num_partial != 1 {
                self.code.emit(|e| {
                    e.ldrb_uoff(tmp_w, ptr, 8)?;
                    e.lsl_reg(BITDATA, BITDATA, bit_offset)?;
                    e.lsl_reg(TMP5, TMP5, bit_offset)?;
                    e.orr_reg(
                        BITDATA,
                        BITDATA,
                        Shifted {
                            reg: TMP5,
                            shift: Shift::Lsr,
                            amount: 8,
                        },
                    )
                })?;
                if bits == 64 {
                    // Simplified reading of a 64-bit word.
                    need_rev64 = false;
                    need_shift = false;
                } else {
                    self.code.b(read_done)?;
                }
            }
        }

        self.code.bind(rev64)?;
        if need_rev64 {
            self.code.emit(|e| e.rev64(BITDATA, BITDATA))?;
        }
        // Shift the read data into the most significant bits of the word.
        self.code.bind(shift)?;
        if need_shift {
            self.code
                .emit(|e| e.lsl_reg(BITDATA, BITDATA, bit_offset))?;
        }
        self.code.bind(read_done)?;
        Ok(())
    }

    /// Port of instr_bs.cpp:2750-2879 (emit_extract_integer).
    fn bsm_extract_integer(
        &mut self,
        flags: u64,
        position: u64,
        bits: u64,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let mut flags = flags;
        let dst_reg = self.init_destination(dst, TMP1);

        if bits <= 8 {
            // Endian does not matter for values that fit in a byte.
            flags &= !BSF_LITTLE;
        }

        // Optimize extraction of the first segment after a read.
        if bits > 0
            && bits < SMALL_BITS
            && position + bits == 64
            && flags & (BSF_LITTLE | BSF_SIGNED) == 0
        {
            let amount = (position - u64::from(TAG_IMMED1_SIZE)) as u8;
            self.code.emit(|e| {
                e.orr_reg(
                    dst_reg,
                    SMALL_TAG,
                    Shifted {
                        reg: BITDATA,
                        shift: Shift::Lsr,
                        amount,
                    },
                )
            })?;
            return self.store_register(dst, dst_reg);
        }

        let big = self.code.new_label();
        let done = self.code.new_label();
        let num_partial = (bits % 8) as u8;
        let num_complete = (8 * (bits / 8)) as u8;

        let mut data_reg = match bits {
            0 => Gpr::xzr(),
            64 => BITDATA,
            _ => {
                match flags & (BSF_SIGNED | BSF_LITTLE) {
                    BSF_SIGNED => self
                        .code
                        .emit(|e| e.sbfx(TMP2, BITDATA, position as u8, bits as u8))?,
                    _ => self
                        .code
                        .emit(|e| e.ubfx(TMP2, BITDATA, position as u8, bits as u8))?,
                }
                TMP2
            }
        };

        // If this segment is little-endian, reverse endianness.
        if flags & BSF_LITTLE != 0 {
            if bits == 16 {
                self.code.emit(|e| e.rev16(TMP2, data_reg))?;
            } else if bits == 32 {
                self.code.emit(|e| e.rev32(TMP2, data_reg))?;
            } else if num_partial == 0 {
                self.code.emit(|e| {
                    e.rev64(TMP2, data_reg)?;
                    e.lsr_imm(TMP2, TMP2, (64 - bits) as u8)
                })?;
            } else {
                self.code.emit(|e| {
                    e.ubfiz(TMP3, data_reg, num_complete, num_partial)?;
                    e.ubfx(TMP2, data_reg, num_partial, num_complete)?;
                    e.rev64(TMP2, TMP2)?;
                    e.orr_reg(
                        TMP2,
                        TMP3,
                        Shifted {
                            reg: TMP2,
                            shift: Shift::Lsr,
                            amount: 64 - num_complete,
                        },
                    )
                })?;
            }
            data_reg = TMP2;
        }

        // Sign-extend the number if the segment is signed and little-endian.
        if flags & (BSF_SIGNED | BSF_LITTLE) == (BSF_SIGNED | BSF_LITTLE) && 0 < bits && bits < 64 {
            self.code.emit(|e| e.sbfx(TMP2, data_reg, 0, bits as u8))?;
            data_reg = TMP2;
        }

        // Handle segments whose values might not fit in a small integer.
        if bits >= SMALL_BITS {
            if flags & BSF_SIGNED != 0 {
                self.code.emit(|e| {
                    e.adds_reg(
                        TMP3,
                        Gpr::xzr(),
                        data_reg,
                        Shift::Lsr,
                        (SMALL_BITS - 1) as u8,
                    )?;
                    // _TAG_IMMED1_MASK << 1 | 1, NZCV::kEqual
                    e.ccmp_imm(TMP3, 0x1f, 0b0100, Cond::Ne)
                })?;
                self.code.b_cond(Cond::Ne, big)?;
            } else {
                self.code
                    .emit(|e| e.lsr_imm(TMP3, data_reg, (SMALL_BITS - 1) as u8))?;
                self.code.cbnz(TMP3, big)?;
            }
        }

        // Tag and store the extracted small integer.
        self.code.emit(|e| {
            e.orr_reg(
                dst_reg,
                SMALL_TAG,
                Shifted {
                    reg: data_reg,
                    shift: Shift::Lsl,
                    amount: TAG_IMMED1_SIZE,
                },
            )
        })?;

        if bits >= SMALL_BITS {
            self.code.b(done)?;
            // Handle a bignum (up to 64 bits).
            self.code.bind(big)?;
            self.code
                .emit(|e| e.add_imm(dst_reg, HTOP, TAG_PRIMARY_BOXED, false))?;
            let pos_header = (1 << 6) | POS_BIG_SUBTAG;
            let neg_header = (1 << 6) | NEG_BIG_SUBTAG;
            self.code.emit(|e| e.mov_const(TMP3, pos_header))?;
            if flags & BSF_SIGNED == 0 {
                self.code.emit(|e| e.stp_post(TMP3, data_reg, HTOP, 16))?;
            } else {
                let store = self.code.new_label();
                self.code
                    .emit(|e| e.adds_reg(TMP2, data_reg, Gpr::xzr(), Shift::Lsl, 0))?;
                self.code.b_cond(Cond::Pl, store)?;
                self.code.emit(|e| {
                    e.mov_const(TMP3, neg_header)?;
                    e.neg(TMP2, TMP2)
                })?;
                self.code.bind(store)?;
                self.code.emit(|e| e.stp_post(TMP3, TMP2, HTOP, 16))?;
            }
        } else {
            self.code.bind(big)?;
        }
        self.code.bind(done)?;
        self.store_register(dst, dst_reg)
    }

    /// Port of instr_bs.cpp:2881-2908 (emit_extract_bitstring).
    fn bsm_extract_bitstring(
        &mut self,
        position: u64,
        bits: u64,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        let dst_reg = self.init_destination(dst, TMP1);
        match position {
            0 => self.code.emit(|e| e.mov_const(TMP4, 0))?,
            64 => self.code.emit(|e| e.mov_reg(TMP4, BITDATA))?,
            _ => self
                .code
                .emit(|e| e.ror_imm(TMP4, BITDATA, position as u8))?,
        }
        let header = ((heap_bits_size(bits) - 1) << 6) | HEAP_BITS_SUBTAG;
        self.code.emit(|e| {
            e.add_imm(dst_reg, HTOP, TAG_PRIMARY_BOXED, false)?;
            e.mov_const(TMP2, header)?;
            e.mov_const(TMP3, bits)?;
            e.stp_post(TMP2, TMP3, HTOP, 16)
        })?;
        if bits > 0 {
            self.code.emit(|e| {
                e.rev64(TMP4, TMP4)?;
                e.str_post(TMP4, HTOP, 8)
            })?;
        }
        self.store_register(dst, dst_reg)
    }

    /// Emits `i_bs_match` / `i_bs_match_test_heap`.
    ///
    /// `need`/`live` are the `Need` and `Live` operands of `i_bs_match_test_heap` (zero for
    /// plain `i_bs_match`).
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2910-3210
    // (emit_i_bs_match, emit_i_bs_match_test_heap), OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_i_bs_match_segments(
        &mut self,
        ctx: ArgVal,
        fail: u32,
        need: u64,
        live: u32,
        commands: &[BsmCommand],
        helper: BsMatchHelper,
        cmd_helper: BsMatchCmdHelper,
        gc_hook: crate::construct::GcHook,
    ) -> Result<(), ModuleError> {
        let segments = bsm_init(commands);
        let segments = opt_bsm_segments(&segments, need, live);

        let mut position_is_valid = false;
        let mut small_tag_valid = false;
        let mut offset_in_bitdata: u64 = 0;
        let fail_label = self.label(fail);

        for seg in segments {
            match seg.action {
                Action::EnsureAtLeast => {
                    let ctx_reg = self.bsm_load_ctx(ctx, TMP1)?;
                    let stride = seg.size;
                    let unit = seg.unit;
                    if unit == 0 {
                        return Err(ModuleError::InvalidOperand(
                            "bitstring match unit must be nonzero",
                        ));
                    }
                    self.code.emit(|e| {
                        e.ldur(BIN_POSITION, ctx_reg, START_OFFSET - BOXED_TAG)?;
                        e.ldur(BIN_SIZE, ctx_reg, END_OFFSET - BOXED_TAG)?;
                        e.sub_reg(TMP5, BIN_SIZE, BIN_POSITION, Shift::Lsl, 0)
                    })?;
                    if stride != 0 {
                        self.bsm_cmp(TMP5, stride)?;
                        self.code.b_cond(Cond::Cc, fail_label)?;
                    }
                    if unit != 1 {
                        if stride % unit != 0 {
                            self.bsm_add_sub(TMP5, TMP5, stride, true)?;
                        }
                        if !unit.is_power_of_two() {
                            self.code.emit(|e| {
                                e.mov_const(TMP4, unit)?;
                                e.udiv(TMP3, TMP5, TMP4)?;
                                e.msub(TMP5, TMP3, TMP4, TMP5)
                            })?;
                            self.code.cbnz(TMP5, fail_label)?;
                        } else {
                            self.code.emit(|e| e.tst_imm(TMP5, unit - 1))?;
                            self.code.b_cond(Cond::Ne, fail_label)?;
                        }
                    }
                    position_is_valid = true;
                }
                Action::EnsureExactly => {
                    let ctx_reg = self.bsm_load_ctx(ctx, TMP1)?;
                    let size = seg.size;
                    self.code.emit(|e| {
                        e.ldur(BIN_POSITION, ctx_reg, START_OFFSET - BOXED_TAG)?;
                        e.ldur(TMP3, ctx_reg, END_OFFSET - BOXED_TAG)
                    })?;
                    if size != 0 {
                        self.code
                            .emit(|e| e.sub_reg(TMP1, TMP3, BIN_POSITION, Shift::Lsl, 0))?;
                        self.bsm_cmp(TMP1, size)?;
                    } else {
                        self.code
                            .emit(|e| e.subs_reg(TMP1, TMP3, BIN_POSITION, Shift::Lsl, 0))?;
                    }
                    self.code.b_cond(Cond::Ne, fail_label)?;
                    position_is_valid = true;
                }
                Action::Eq => {
                    offset_in_bitdata -= seg.size;
                    let cmp_reg = if seg.size == 0 {
                        Gpr::xzr()
                    } else if seg.size == 64 {
                        BITDATA
                    } else {
                        self.code.emit(|e| {
                            e.ubfx(TMP1, BITDATA, offset_in_bitdata as u8, seg.size as u8)
                        })?;
                        TMP1
                    };
                    if seg.size == 32 {
                        let reg = Gpr::w(cmp_reg.number);
                        self.bsm_cmp(reg, seg.unit)?;
                    } else {
                        self.bsm_cmp(cmp_reg, seg.unit)?;
                    }
                    self.code.b_cond(Cond::Ne, fail_label)?;
                }
                Action::TestHeap => {
                    self.emit_test_heap(seg.size as u32, seg.live.unwrap_or(0), gc_hook)?;
                    position_is_valid = false;
                    small_tag_valid = false;
                }
                Action::Read => {
                    offset_in_bitdata = 64;
                    if seg.size != 0 {
                        let ctx_reg = self.bsm_load_ctx(ctx, ARG1)?;
                        self.bsm_read_with_ctx(ctx_reg, &mut position_is_valid, seg.size)?;
                    }
                }
                Action::ExtractBitstring => {
                    let bits = seg.size;
                    self.bsm_extract_bitstring(
                        offset_in_bitdata,
                        bits,
                        seg.dst.expect("extract has a destination"),
                    )?;
                    offset_in_bitdata -= bits;
                }
                Action::ExtractInteger => {
                    if !small_tag_valid {
                        small_tag_valid = true;
                        self.code
                            .emit(|e| e.mov_const(SMALL_TAG, TAG_IMMED1_SMALL))?;
                    }
                    offset_in_bitdata -= seg.size;
                    self.bsm_extract_integer(
                        seg.flags,
                        offset_in_bitdata,
                        seg.size,
                        seg.dst.expect("extract has a destination"),
                    )?;
                }
                Action::ReadInteger => {
                    if seg.size != 0 {
                        let ctx_reg = self.bsm_load_ctx(ctx, ARG1)?;
                        self.bsm_read_with_ctx(ctx_reg, &mut position_is_valid, seg.size)?;
                    }
                    offset_in_bitdata = 64 - seg.size;
                    self.code
                        .emit(|e| e.mov_const(SMALL_TAG, TAG_IMMED1_SMALL))?;
                    self.bsm_extract_integer(
                        seg.flags,
                        offset_in_bitdata,
                        seg.size,
                        seg.dst.expect("read integer has a destination"),
                    )?;
                }
                Action::GetInteger | Action::GetBitstring => {
                    // Integers wider than 64 bits and bitstrings that are not extracted
                    // inline run through the runtime (erts_bs_get_integer_2,
                    // erts_build_sub_bitstring).
                    let kind = u32::from(seg.action == Action::GetBitstring);
                    let tagged = |value: u64| ArgVal::Immediate((value << 4) | 0xf);
                    self.emit_bs_match_command(
                        kind,
                        seg.live.unwrap_or(0),
                        &[ctx, tagged(seg.flags), tagged(seg.size), tagged(1)],
                        fail,
                        seg.dst,
                        cmd_helper,
                    )?;
                    position_is_valid = false;
                    small_tag_valid = false;
                }
                Action::GetTail => {
                    // The heap test above reserved BUILD_SUB_BITSTRING_HEAP_NEED words.
                    self.emit_bs_helper(
                        10,
                        ctx,
                        ArgVal::Immediate(u64::from(seg.live.unwrap_or(0))),
                        0,
                        seg.dst,
                        None,
                        helper,
                    )?;
                    position_is_valid = false;
                    small_tag_valid = false;
                }
                Action::Skip => {
                    let ctx_reg = self.bsm_load_ctx(ctx, TMP1)?;
                    if !position_is_valid {
                        self.code
                            .emit(|e| e.ldur(BIN_POSITION, ctx_reg, START_OFFSET - BOXED_TAG))?;
                        position_is_valid = true;
                    }
                    self.bsm_add_sub(BIN_POSITION, BIN_POSITION, seg.size, false)?;
                    self.code
                        .emit(|e| e.stur(BIN_POSITION, ctx_reg, START_OFFSET - BOXED_TAG))?;
                }
                Action::Drop => {
                    offset_in_bitdata -= seg.size;
                }
            }
        }
        Ok(())
    }

    /// Shared part of READ and READ_INTEGER (instr_bs.cpp:3024-3041, 3073-3090).
    fn bsm_read_with_ctx(
        &mut self,
        ctx_reg: Gpr,
        position_is_valid: &mut bool,
        bits: u64,
    ) -> Result<(), ModuleError> {
        if !*position_is_valid {
            self.code
                .emit(|e| e.ldur(BIN_POSITION, ctx_reg, START_OFFSET - BOXED_TAG))?;
            *position_is_valid = true;
        }
        self.code.emit(|e| {
            e.ldur(BIN_BASE, ctx_reg, BASE_FLAGS_OFFSET as i16 - BOXED_TAG)?;
            e.and_imm(BIN_BASE, BIN_BASE, !SUB_BITS_FLAG_MASK)
        })?;
        self.bsm_read_bits(bits)?;
        self.bsm_add_sub(BIN_POSITION, BIN_POSITION, bits, false)?;
        self.code
            .emit(|e| e.stur(BIN_POSITION, ctx_reg, START_OFFSET - BOXED_TAG))?;
        Ok(())
    }
}
