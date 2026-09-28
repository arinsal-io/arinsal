//! AArch64 emitters for BEAM bit syntax construction.

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use arinsal_a64::enc::Gpr;

/// Runtime hook for one binary-construction segment.
pub type BsConstructHelper = extern "C" fn(*mut crate::ProcessHeader, u64, u64, u64, u64) -> u64;
/// Runtime hook used by the shared badarg path.
pub type BsConstructErrorHelper = extern "C" fn(*mut crate::ProcessHeader, u32, u64) -> u64;
/// Runtime hook used to initialize a writable bitstring.
pub type BsInitWritableHelper = extern "C" fn(*mut crate::ProcessHeader, u64) -> u64;

/// Construction segment kind understood by [`BeamModuleAssembler::emit_i_bs_create_bin`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BsSegmentKind {
    /// Fixed byte sequence or a bitstring segment.
    Binary = 0,
    /// Integer segment, using the supplied endianness flag.
    Integer = 1,
    /// Floating point segment.
    Float = 2,
    /// UTF-8 code point.
    Utf8 = 3,
    /// Append to a prior binary.
    Append = 4,
    /// Literal byte string.
    String = 5,
    /// Private append into the current writable binary.
    PrivateAppend = 6,
}

/// One typed segment passed to the construction emitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BsSegment {
    /// Segment operation.
    pub kind: BsSegmentKind,
    /// Value source, or literal payload for a string segment.
    pub src: ArgVal,
    /// Bit size, in BEAM tagged-small representation when dynamic.
    pub size: ArgVal,
    /// Size multiplier.
    pub unit: u32,
    /// Operation flags, including little-endian selection.
    pub flags: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct BinSizePlan {
    constant_bits: u64,
    estimated_bits: u64,
    effective_bits: Vec<Option<u64>>,
    contains_append: bool,
    requires_dynamic_size: bool,
    requires_error_path: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinAllocation {
    OnHeapBitstring,
    OffHeapBinary,
    Append,
    PrivateAppend,
}

impl BinAllocation {
    fn select(segments: &[BsSegment], plan: &BinSizePlan) -> Self {
        match segments.first().map(|segment| segment.kind) {
            Some(BsSegmentKind::Append) => Self::Append,
            Some(BsSegmentKind::PrivateAppend) => Self::PrivateAppend,
            _ if plan.can_use_heap_bitstring() => Self::OnHeapBitstring,
            _ => Self::OffHeapBinary,
        }
    }

    fn owns_heap_storage(self) -> bool {
        matches!(self, Self::OnHeapBitstring | Self::OffHeapBinary)
    }

    fn needs_append_state(self) -> bool {
        matches!(self, Self::Append | Self::PrivateAppend)
    }
}

impl BinSizePlan {
    const ON_HEAP_LIMIT_BITS: u64 = 64 * 1024;

    fn calculate(segments: &[BsSegment]) -> Result<Self, ModuleError> {
        let mut plan = Self::default();
        for segment in segments {
            let effective = BeamModuleAssembler::inline_static_bits(*segment);
            plan.effective_bits.push(effective);
            match segment.kind {
                BsSegmentKind::Append | BsSegmentKind::PrivateAppend => {
                    plan.contains_append = true;
                    plan.requires_error_path |= segment.kind == BsSegmentKind::Append;
                    plan.estimated_bits = plan
                        .estimated_bits
                        .saturating_add(Self::clamped_estimate(*segment));
                }
                BsSegmentKind::Utf8 if segment.unit == 0 => {
                    plan.estimated_bits = plan.estimated_bits.saturating_add(32);
                    plan.requires_error_path = true;
                }
                _ => {
                    if segment.unit == 0 {
                        plan.requires_error_path = true;
                        plan.estimated_bits = Self::ON_HEAP_LIMIT_BITS.saturating_add(8);
                        continue;
                    }
                    if let Some(bits) = effective {
                        plan.constant_bits = plan
                            .constant_bits
                            .checked_add(bits)
                            .ok_or(ModuleError::InvalidOperand("binary size overflow"))?;
                        plan.estimated_bits = plan.estimated_bits.saturating_add(bits);
                    } else {
                        plan.requires_dynamic_size = true;
                        plan.requires_error_path = true;
                        plan.estimated_bits = plan
                            .estimated_bits
                            .saturating_add(Self::clamped_estimate(*segment));
                    }
                }
            }
        }
        Ok(plan)
    }

    fn clamped_estimate(segment: BsSegment) -> u64 {
        match BeamModuleAssembler::inline_static_bits(segment) {
            Some(bits) => bits.min(Self::ON_HEAP_LIMIT_BITS.saturating_add(8)),
            None if segment.kind == BsSegmentKind::Utf8 => 32,
            None => Self::ON_HEAP_LIMIT_BITS.saturating_add(8),
        }
    }

    fn can_use_heap_bitstring(&self) -> bool {
        self.estimated_bits <= Self::ON_HEAP_LIMIT_BITS
            && !self.contains_append
            && !self.requires_dynamic_size
    }

    fn rounded_heap_bytes(&self) -> Result<u64, ModuleError> {
        self.constant_bits
            .checked_add(63)
            .map(|bits| (bits / 64) * 8)
            .ok_or(ModuleError::InvalidOperand(
                "binary allocation size overflow",
            ))
    }
}

const FAIL_VALUE: u64 = 0;
const OK_VALUE: u64 = 1;
const HTOP: Gpr = Gpr::x(23);
const C_P: Gpr = Gpr::x(21);
const BIT_STATE: Gpr = Gpr::x(19);
const BIN_OFFSET_SLOT: u32 = 16_392;
const CURRENT_BIN_SLOT: u32 = 16_384;

impl BeamModuleAssembler {
    fn emit_bs_construct_runtime_hook(
        &mut self,
        helper: usize,
        args: &[Gpr],
        live: usize,
        update: crate::Update,
    ) -> Result<(), ModuleError> {
        if args.len() > 5 {
            return Err(ModuleError::InvalidOperand(
                "runtime hook has too many arguments",
            ));
        }
        crate::emit_enter_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            for (index, arg) in args.iter().copied().enumerate() {
                e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
            }
            e.mov_const(Gpr::x(17), helper as u64)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            e.ldr_uoff(Gpr::x(9), C_P, 40)
        })?;
        self.code.cbnz(Gpr::x(9), self.error_label)?;
        Ok(())
    }

    /// Calls the runtime helper that initializes the current writable binary.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000, OTP-29.1.1.
    pub fn emit_bs_init_writable(
        &mut self,
        src: ArgVal,
        helper: BsInitWritableHelper,
    ) -> Result<(), ModuleError> {
        let src = self.source_reg(src)?;
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000, OTP-29.1.1.
        self.emit_bs_construct_runtime_hook(
            helper as usize,
            &[src],
            0,
            crate::Update::HEAP_ALLOC.union(crate::Update::REDUCTIONS),
        )?;
        self.code.emit(|e| e.mov_reg(Gpr::x(25), Gpr::x(0)))?;
        Ok(())
    }

    /// Emits the shared binary-construction error handler fragment.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1002-1019, OTP-29.1.1.
    pub fn emit_bs_create_bin_error_shared(
        &mut self,
        info: u32,
        value: ArgVal,
        helper: BsConstructErrorHelper,
    ) -> Result<(), ModuleError> {
        let value = self.source_reg(value)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(1), u64::from(info))?;
            e.mov_reg(Gpr::x(2), value)
        })?;
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1002-1019, OTP-29.1.1.
        self.emit_bs_construct_runtime_hook(
            helper as usize,
            &[Gpr::x(1), Gpr::x(2)],
            0,
            crate::Update::HEAP_ALLOC,
        )?;
        self.code.b(self.error_label)?;
        Ok(())
    }

    /// Emits construction of a bitstring from typed segments.
    ///
    /// Segment writes and allocation are delegated through typed runtime hooks so the process
    /// implementation can own its bitstring state and heap policy.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1442-2494, OTP-29.1.1.
    pub fn emit_i_bs_create_bin(
        &mut self,
        fail: Option<u32>,
        dst: ArgVal,
        segments: &[BsSegment],
        helper: BsConstructHelper,
        error_helper: BsConstructErrorHelper,
    ) -> Result<(), ModuleError> {
        Self::validate_segments(segments)?;
        let size_plan = BinSizePlan::calculate(segments)?;
        let allocation = BinAllocation::select(segments, &size_plan);
        if segments.len() == 1 && segments[0].kind == BsSegmentKind::Utf8 {
            self.emit_construct_utf8(segments[0].src, 0, true)?;
            self.move_(ArgVal::Immediate(OK_VALUE), dst)?;
            return Ok(());
        }
        if allocation == BinAllocation::OnHeapBitstring
            && let Some(total_bits) = Self::inline_segments_bits(segments)
        {
            let _allocation_bytes = size_plan.rounded_heap_bytes()?;
            self.emit_inline_segments(segments, total_bits)?;
            self.move_(ArgVal::Immediate(OK_VALUE), dst)?;
            return Ok(());
        }

        let _uses_owned_heap = allocation.owns_heap_storage();
        let _requires_append_state = allocation.needs_append_state();

        let failure = self.code.new_label();
        let done = self.code.new_label();
        for segment in segments {
            let src = self.source_reg(segment.src)?;
            self.code.emit(|e| e.mov_reg(Gpr::x(10), src))?;
            self.emit_validate_dynamic_size(segment.size, failure)?;
            self.emit_effective_segment_size(*segment)?;
            self.code.emit(|e| {
                let operation = (segment.kind as u64) | (u64::from(segment.flags) << 32);
                e.mov_const(Gpr::x(1), operation)?;
                e.mov_reg(Gpr::x(2), Gpr::x(10))?;
                e.mov_reg(Gpr::x(3), Gpr::x(12))?;
                e.mov_const(Gpr::x(4), 1)
            })?;
            // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:3125-3169, OTP-29.1.1.
            self.emit_bs_construct_runtime_hook(
                helper as usize,
                &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
                6,
                crate::Update::HEAP_ALLOC.union(crate::Update::X_REGS),
            )?;
            self.code.cbz(Gpr::x(0), failure)?;
        }
        self.move_(ArgVal::Immediate(OK_VALUE), dst)?;
        self.code.b(done)?;
        self.code.bind(failure)?;
        if let Some(label) = fail {
            let label = self.label(label);
            self.code.b(label)?;
        } else {
            self.emit_bs_create_bin_error_shared(0, ArgVal::Immediate(FAIL_VALUE), error_helper)?;
        }
        self.code.bind(done)?;
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2088-2143, OTP-29.1.1.
    fn validate_segments(segments: &[BsSegment]) -> Result<(), ModuleError> {
        for (index, segment) in segments.iter().enumerate() {
            if segment.unit == 0 && segment.kind != BsSegmentKind::Utf8 {
                return Err(ModuleError::InvalidOperand(
                    "binary segment unit must be nonzero",
                ));
            }
            if matches!(
                segment.kind,
                BsSegmentKind::Append | BsSegmentKind::PrivateAppend
            ) && index != 0
            {
                return Err(ModuleError::InvalidOperand(
                    "append must be the first segment",
                ));
            }
            if segment.kind == BsSegmentKind::Float
                && let Some(bits) = Self::inline_static_bits(*segment)
                && bits != 32
                && bits != 64
            {
                return Err(ModuleError::InvalidOperand(
                    "float segment size must be 32 or 64",
                ));
            }
        }
        Ok(())
    }

    /// Rejects non-small and negative dynamic size terms before size arithmetic.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1680-1742, OTP-29.1.1.
    fn emit_validate_dynamic_size(
        &mut self,
        size: ArgVal,
        fail: arinsal_a64::buf::Label,
    ) -> Result<(), ModuleError> {
        let (ArgVal::X(_) | ArgVal::Y(_)) = size else {
            return Ok(());
        };
        let source = self.source_reg(size)?;
        self.code.emit(|e| {
            e.and_imm(Gpr::x(11), source, 0x0f)?;
            e.cmp_imm(Gpr::x(11), 0x0f, false)
        })?;
        self.code.b_cond(arinsal_a64::enc::Cond::Ne, fail)?;
        self.code.tbnz(source, 63, fail)?;
        Ok(())
    }

    /// Calculates the effective segment size in bits before entering a runtime hook.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1680-1752, OTP-29.1.1.
    fn emit_effective_segment_size(&mut self, segment: BsSegment) -> Result<(), ModuleError> {
        if let Some(bits) = Self::inline_static_bits(segment) {
            self.code.emit(|e| e.mov_const(Gpr::x(12), bits))?;
            return Ok(());
        }

        match segment.size {
            ArgVal::X(_) | ArgVal::Y(_) => {
                let tagged = self.source_reg(segment.size)?;
                self.code.emit(|e| e.asr_imm(Gpr::x(12), tagged, 4))?;
            }
            ArgVal::Immediate(value) | ArgVal::Literal(value) => {
                self.code.emit(|e| e.mov_const(Gpr::x(12), value))?;
            }
            ArgVal::Label(_) | ArgVal::Export(_) => {
                return Err(ModuleError::InvalidOperand("invalid binary segment size"));
            }
        }
        if segment.unit > 1 {
            self.code.emit(|e| {
                e.mov_const(Gpr::x(11), u64::from(segment.unit))?;
                e.mul(Gpr::x(12), Gpr::x(12), Gpr::x(11))
            })?;
        }
        Ok(())
    }

    fn inline_static_bits(segment: BsSegment) -> Option<u64> {
        let (ArgVal::Immediate(size) | ArgVal::Literal(size)) = segment.size else {
            return None;
        };
        size.checked_mul(u64::from(segment.unit))
    }

    fn inline_segments_bits(segments: &[BsSegment]) -> Option<u64> {
        if segments.is_empty() {
            return None;
        }
        segments.iter().try_fold(0_u64, |total, segment| {
            let inline_source =
                matches!(segment.kind, BsSegmentKind::Integer | BsSegmentKind::String)
                    || (segment.kind == BsSegmentKind::Binary
                        && matches!(segment.src, ArgVal::Immediate(_)));
            if !inline_source {
                return None;
            }
            let bits = Self::inline_static_bits(*segment)?;
            let result = total.checked_add(bits)?;
            (bits > 0 && bits <= 64 && result <= 512).then_some(result)
        })
    }

    fn emit_inline_segments(
        &mut self,
        segments: &[BsSegment],
        total_bits: u64,
    ) -> Result<(), ModuleError> {
        let byte_count = u16::try_from(total_bits.div_ceil(8))
            .map_err(|_| ModuleError::InvalidOperand("inline construction is too large"))?;
        self.emit_heap_capacity_check(byte_count)?;
        for offset in 0..byte_count {
            self.code.emit(|e| e.strb_uoff(Gpr::wzr(), HTOP, offset))?;
        }
        let mut bit_offset = 0_u64;
        for segment in segments {
            let bits = Self::inline_static_bits(*segment).ok_or(ModuleError::InvalidOperand(
                "inline segment needs a fixed size",
            ))?;
            if segment.kind == BsSegmentKind::Integer
                && matches!(segment.src, ArgVal::Immediate(0) | ArgVal::Literal(0))
                && bit_offset.is_multiple_of(8)
                && bits % 8 == 0
            {
                self.code.emit(|e| {
                    e.mov_reg(Gpr::x(2), Gpr::xzr())?;
                    e.mov_const(Gpr::x(3), bits)?;
                    e.str_uoff(HTOP, BIT_STATE, CURRENT_BIN_SLOT)?;
                    e.str_uoff(Gpr::xzr(), BIT_STATE, BIN_OFFSET_SLOT)
                })?;
                self.set_zero(bits as i64)?;
            } else if bits % 8 == 0 && bit_offset.is_multiple_of(8) {
                self.emit_inline_fixed_segment(*segment, bits, bit_offset / 8)?;
            } else {
                self.emit_store_unaligned(*segment, bits, bit_offset)?;
            }
            bit_offset = bit_offset
                .checked_add(bits)
                .ok_or(ModuleError::InvalidOperand("binary size overflow"))?;
        }
        self.code
            .emit(|e| e.add_imm(HTOP, HTOP, byte_count, false))?;
        Ok(())
    }

    /// Branches to the native error exit if a fixed inline allocation exceeds the young heap.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1910-1950, OTP-29.1.1.
    fn emit_heap_capacity_check(&mut self, byte_count: u16) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.add_imm(Gpr::x(10), HTOP, byte_count, false)?;
            e.ldr_uoff(Gpr::x(11), C_P, 24)?;
            e.cmp_reg(Gpr::x(10), Gpr::x(11), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code
            .b_cond(arinsal_a64::enc::Cond::Hi, self.error_label)?;
        Ok(())
    }

    /// Emits stores for a fixed byte-aligned integer or packed binary literal.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2332-2360, OTP-29.1.1.
    fn emit_inline_fixed_segment(
        &mut self,
        segment: BsSegment,
        bits: u64,
        base_byte_offset: u64,
    ) -> Result<(), ModuleError> {
        let bytes = u16::try_from(bits / 8)
            .map_err(|_| ModuleError::InvalidOperand("inline binary segment is too large"))?;
        let source = self.source_reg(segment.src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(10), source))?;
        if !base_byte_offset.is_multiple_of(4) {
            for index in 0..bytes {
                let byte_index = if segment.kind == BsSegmentKind::Integer && segment.flags & 1 != 0
                {
                    index
                } else {
                    bytes - index - 1
                };
                let offset = u16::try_from(base_byte_offset + u64::from(index))
                    .map_err(|_| ModuleError::InvalidOperand("inline offset is too large"))?;
                self.code.emit(|e| {
                    e.lsr_imm(Gpr::x(12), Gpr::x(10), (byte_index * 8) as u8)?;
                    e.strb_uoff(Gpr::w(12), HTOP, offset)
                })?;
            }
            return Ok(());
        }
        self.emit_store_integer_bytes(
            bits,
            base_byte_offset,
            segment.kind == BsSegmentKind::Integer && segment.flags & 1 != 0,
        )
    }

    /// Converts a 64-bit accumulator into an exact-width byte sequence without an overstore.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2260-2330, OTP-29.1.1.
    fn emit_store_integer_bytes(
        &mut self,
        bits: u64,
        base_byte_offset: u64,
        little_endian: bool,
    ) -> Result<(), ModuleError> {
        let mut byte_count = u8::try_from(bits / 8)
            .map_err(|_| ModuleError::InvalidOperand("inline store exceeds eight bytes"))?;
        if byte_count == 0 || byte_count > 8 {
            return Err(ModuleError::InvalidOperand(
                "inline byte width is out of range",
            ));
        }
        if !little_endian {
            if bits < 64 {
                self.code
                    .emit(|e| e.lsl_imm(Gpr::x(10), Gpr::x(10), (64 - bits) as u8))?;
            }
            self.code.emit(|e| e.rev64(Gpr::x(10), Gpr::x(10)))?;
        }

        let mut offset = u32::try_from(base_byte_offset)
            .map_err(|_| ModuleError::InvalidOperand("inline byte offset is too large"))?;
        while byte_count >= 4 {
            self.code.emit(|e| e.str_uoff(Gpr::w(10), HTOP, offset))?;
            offset += 4;
            byte_count -= 4;
            if byte_count > 0 {
                self.code.emit(|e| e.lsr_imm(Gpr::x(10), Gpr::x(10), 32))?;
            }
        }
        if byte_count >= 2 {
            self.code
                .emit(|e| e.strh_uoff(Gpr::w(10), HTOP, offset as u16))?;
            offset += 2;
            byte_count -= 2;
            if byte_count > 0 {
                self.code.emit(|e| e.lsr_imm(Gpr::x(10), Gpr::x(10), 16))?;
            }
        }
        if byte_count == 1 {
            self.code
                .emit(|e| e.strb_uoff(Gpr::w(10), HTOP, offset as u16))?;
        }
        Ok(())
    }

    /// Stores a fixed segment at a non-byte-aligned bit offset.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1362-1439, OTP-29.1.1.
    fn emit_store_unaligned(
        &mut self,
        segment: BsSegment,
        bits: u64,
        destination_bit: u64,
    ) -> Result<(), ModuleError> {
        let bits = u8::try_from(bits)
            .map_err(|_| ModuleError::InvalidOperand("inline bit segment exceeds 64 bits"))?;
        let source = self.source_reg(segment.src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(10), source))?;
        for index in 0..bits {
            let source_lsb = if segment.kind == BsSegmentKind::Integer
                && segment.flags & 1 != 0
                && bits % 8 == 0
            {
                let source_byte = u64::from(index / 8);
                let bit_in_byte = u64::from(index % 8);
                (source_byte * 8 + 7 - bit_in_byte) as u8
            } else {
                bits - index - 1
            };
            let destination = destination_bit + u64::from(index);
            let byte_offset = u16::try_from(destination / 8)
                .map_err(|_| ModuleError::InvalidOperand("bit destination is too far"))?;
            let destination_lsb = 7 - (destination % 8) as u8;
            self.code.emit(|e| {
                e.ubfx(Gpr::x(12), Gpr::x(10), source_lsb, 1)?;
                if destination_lsb > 0 {
                    e.lsl_imm(Gpr::x(12), Gpr::x(12), destination_lsb)?;
                }
                e.ldrb_uoff(Gpr::x(11), HTOP, byte_offset)?;
                e.orr_reg(
                    Gpr::x(11),
                    Gpr::x(11),
                    arinsal_a64::enc::Shifted {
                        reg: Gpr::x(12),
                        shift: arinsal_a64::enc::Shift::Lsl,
                        amount: 0,
                    },
                )?;
                e.strb_uoff(Gpr::w(11), HTOP, byte_offset)
            })?;
        }
        Ok(())
    }

    /// Updates the cached binary pointer and bit offset used by inline stores.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1076-1123, OTP-29.1.1.
    fn update_bin_state(
        &mut self,
        bin_offset: Gpr,
        bit_offset: i64,
        size: i64,
        size_reg: Option<Gpr>,
    ) -> Result<(), ModuleError> {
        if bit_offset % 8 != 0 {
            self.code.emit(|e| {
                e.ldr_uoff(Gpr::x(10), BIT_STATE, CURRENT_BIN_SLOT)?;
                e.ldr_uoff(bin_offset, BIT_STATE, BIN_OFFSET_SLOT)?;
                if let Some(size_reg) = size_reg {
                    e.add_reg(
                        Gpr::x(11),
                        bin_offset,
                        size_reg,
                        arinsal_a64::enc::Shift::Lsl,
                        0,
                    )?;
                } else {
                    e.add_imm(Gpr::x(11), bin_offset, size as u16, false)?;
                }
                e.str_uoff(Gpr::x(11), BIT_STATE, BIN_OFFSET_SLOT)?;
                e.lsr_imm(Gpr::x(12), bin_offset, 3)?;
                e.add_reg(
                    Gpr::x(9),
                    Gpr::x(10),
                    Gpr::x(12),
                    arinsal_a64::enc::Shift::Lsl,
                    0,
                )
            })?;
        } else {
            self.code
                .emit(|e| e.ldr_uoff(Gpr::x(9), BIT_STATE, CURRENT_BIN_SLOT))?;
            let offset = bit_offset
                .checked_add(size)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(ModuleError::InvalidOperand("binary offset is out of range"))?;
            if let Some(size_reg) = size_reg {
                if bit_offset == 0 {
                    self.code
                        .emit(|e| e.str_uoff(size_reg, BIT_STATE, BIN_OFFSET_SLOT))?;
                } else {
                    self.code.emit(|e| {
                        e.add_imm(Gpr::x(10), size_reg, bit_offset as u16, false)?;
                        e.str_uoff(Gpr::x(10), BIT_STATE, BIN_OFFSET_SLOT)
                    })?;
                }
            } else {
                self.code.emit(|e| {
                    e.mov_const(Gpr::x(10), u64::from(offset))?;
                    e.str_uoff(Gpr::x(10), BIT_STATE, BIN_OFFSET_SLOT)
                })?;
            }
            if bit_offset != 0 {
                self.code
                    .emit(|e| e.add_imm(Gpr::x(9), Gpr::x(9), (bit_offset / 8) as u16, false))?;
            }
        }
        Ok(())
    }

    /// Fills a fixed-size or dynamic bit range with zero bytes.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1126-1210, OTP-29.1.1.
    fn set_zero(&mut self, effective_size: i64) -> Result<(), ModuleError> {
        self.update_bin_state(Gpr::x(2), -1, -1, Some(Gpr::x(3)))?;
        if effective_size < 0 {
            self.emit_zero_dynamic()?;
            return Ok(());
        }
        let byte_count = u16::try_from((effective_size + 7) / 8)
            .map_err(|_| ModuleError::InvalidOperand("zero segment is too large"))?;
        let mut offset = 0_u16;
        let mut remaining = byte_count;

        // On wide fixed segments, clear complete double words first. This is the
        // same word-at-a-time strategy used by set_zero in the reference emitter.
        while remaining >= 8 {
            self.code
                .emit(|e| e.str_uoff(Gpr::xzr(), Gpr::x(9), u32::from(offset)))?;
            offset += 8;
            remaining -= 8;
        }
        if remaining >= 4 {
            self.code
                .emit(|e| e.str_uoff(Gpr::wzr(), Gpr::x(9), u32::from(offset)))?;
            offset += 4;
            remaining -= 4;
        }
        if remaining >= 2 {
            self.code
                .emit(|e| e.strh_uoff(Gpr::wzr(), Gpr::x(9), offset))?;
            offset += 2;
            remaining -= 2;
        }
        if remaining == 1 {
            self.code
                .emit(|e| e.strb_uoff(Gpr::wzr(), Gpr::x(9), offset))?;
        }
        Ok(())
    }

    fn emit_zero_dynamic(&mut self) -> Result<(), ModuleError> {
        let done = self.code.new_label();
        let loop_label = self.code.new_label();
        self.code.cbz(Gpr::x(3), done)?;
        self.code.bind(loop_label)?;
        self.code.emit(|e| {
            e.strb_uoff(Gpr::wzr(), Gpr::x(9), 0)?;
            e.add_imm(Gpr::x(9), Gpr::x(9), 1, false)?;
            e.subs_imm(Gpr::x(3), Gpr::x(3), 8, false)
        })?;
        self.code.b_cond(arinsal_a64::enc::Cond::Gt, loop_label)?;
        self.code.bind(done)?;
        Ok(())
    }

    /// Emits UTF-8 bytes for a statically known code point.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1268-1358, OTP-29.1.1.
    fn emit_construct_utf8(
        &mut self,
        source: ArgVal,
        bit_offset: i64,
        is_byte_aligned: bool,
    ) -> Result<(), ModuleError> {
        if !is_byte_aligned && bit_offset % 8 != 0 {
            return Err(ModuleError::InvalidOperand(
                "unaligned UTF-8 needs the unaligned store path",
            ));
        }
        if let ArgVal::Immediate(raw) | ArgVal::Literal(raw) = source {
            let codepoint = u32::try_from(raw)
                .ok()
                .and_then(char::from_u32)
                .ok_or(ModuleError::InvalidOperand("invalid UTF-8 code point"))?;
            let mut buffer = [0; 4];
            let encoded = codepoint.encode_utf8(&mut buffer).as_bytes();
            let offset = u16::try_from(bit_offset.max(0) / 8)
                .map_err(|_| ModuleError::InvalidOperand("UTF-8 offset is out of range"))?;
            for (index, byte) in encoded.iter().enumerate() {
                self.code.emit(|e| {
                    e.mov_const(Gpr::x(12), u64::from(*byte))?;
                    e.strb_uoff(Gpr::w(12), HTOP, offset + index as u16)
                })?;
            }
            self.code
                .emit(|e| e.add_imm(HTOP, HTOP, encoded.len() as u16, false))?;
            return Ok(());
        }

        let value = self.source_reg(source)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(10), value))?;
        let one_byte = self.code.new_label();
        let two_bytes = self.code.new_label();
        let three_bytes = self.code.new_label();
        let four_bytes = self.code.new_label();
        let done = self.code.new_label();
        let fail = self.error_label;

        // UTF-8 width boundaries are ordered so the first successful comparison
        // selects the shortest representation of the code point.
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0x80, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Cc, one_byte)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0x800, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Cc, two_bytes)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0x10, true))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Cc, three_bytes)?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(11), 0x110000)?;
            e.cmp_reg(Gpr::x(10), Gpr::x(11), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(arinsal_a64::enc::Cond::Cs, fail)?;
        self.code.b(four_bytes)?;

        self.code.bind(one_byte)?;
        self.code.emit(|e| e.strb_uoff(Gpr::w(10), HTOP, 0))?;
        self.code.emit(|e| e.add_imm(HTOP, HTOP, 1, false))?;
        self.code.b(done)?;

        self.code.bind(two_bytes)?;
        self.emit_utf8_part(Gpr::x(10), 6, 5, 0xc0, 0)?;
        self.emit_utf8_part(Gpr::x(10), 0, 6, 0x80, 1)?;
        self.code.emit(|e| e.add_imm(HTOP, HTOP, 2, false))?;
        self.code.b(done)?;

        self.code.bind(three_bytes)?;
        let valid_three = self.code.new_label();
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0xd800, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Cc, valid_three)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(10), 0xe000, false))?;
        self.code.b_cond(arinsal_a64::enc::Cond::Cc, fail)?;
        self.code.bind(valid_three)?;
        self.emit_utf8_part(Gpr::x(10), 12, 4, 0xe0, 0)?;
        self.emit_utf8_part(Gpr::x(10), 6, 6, 0x80, 1)?;
        self.emit_utf8_part(Gpr::x(10), 0, 6, 0x80, 2)?;
        self.code.emit(|e| e.add_imm(HTOP, HTOP, 3, false))?;
        self.code.b(done)?;

        self.code.bind(four_bytes)?;
        self.emit_utf8_part(Gpr::x(10), 18, 3, 0xf0, 0)?;
        self.emit_utf8_part(Gpr::x(10), 12, 6, 0x80, 1)?;
        self.emit_utf8_part(Gpr::x(10), 6, 6, 0x80, 2)?;
        self.emit_utf8_part(Gpr::x(10), 0, 6, 0x80, 3)?;
        self.code.emit(|e| e.add_imm(HTOP, HTOP, 4, false))?;
        self.code.bind(done)?;
        Ok(())
    }

    fn emit_utf8_part(
        &mut self,
        value: Gpr,
        lsb: u8,
        width: u8,
        prefix: u64,
        output_offset: u16,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.ubfx(Gpr::x(12), value, lsb, width)?;
            e.orr_imm(Gpr::x(12), Gpr::x(12), prefix)?;
            e.strb_uoff(Gpr::w(12), HTOP, output_offset)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BeamModuleAssembler, BinAllocation, BinSizePlan, BsSegment, BsSegmentKind};
    use crate::module::ArgVal;

    fn segment(kind: BsSegmentKind, size: ArgVal, unit: u32) -> BsSegment {
        BsSegment {
            kind,
            src: ArgVal::Immediate(7),
            size,
            unit,
            flags: 0,
        }
    }

    #[test]
    fn fixed_size_segments_accumulate_effective_bits() {
        let segments = [
            segment(BsSegmentKind::Integer, ArgVal::Immediate(16), 1),
            segment(BsSegmentKind::Binary, ArgVal::Immediate(3), 8),
        ];
        let plan = BinSizePlan::calculate(&segments).unwrap();
        assert_eq!(plan.constant_bits, 40);
        assert_eq!(plan.effective_bits, [Some(16), Some(24)]);
        assert_eq!(plan.rounded_heap_bytes().unwrap(), 8);
        assert_eq!(
            BinAllocation::select(&segments, &plan),
            BinAllocation::OnHeapBitstring
        );
    }

    #[test]
    fn unknown_size_suppresses_fixed_heap_estimate() {
        let segments = [segment(BsSegmentKind::Binary, ArgVal::X(0), 8)];
        let plan = BinSizePlan::calculate(&segments).unwrap();
        assert!(plan.requires_dynamic_size);
        assert!(plan.requires_error_path);
        assert!(!plan.can_use_heap_bitstring());
        assert_eq!(plan.estimated_bits, BinSizePlan::ON_HEAP_LIMIT_BITS + 8);
    }

    #[test]
    fn append_segments_choose_their_own_allocation_path() {
        let append = [segment(BsSegmentKind::Append, ArgVal::Immediate(8), 1)];
        let private_append = [segment(
            BsSegmentKind::PrivateAppend,
            ArgVal::Immediate(8),
            1,
        )];
        let append_plan = BinSizePlan::calculate(&append).unwrap();
        let private_plan = BinSizePlan::calculate(&private_append).unwrap();
        assert_eq!(
            BinAllocation::select(&append, &append_plan),
            BinAllocation::Append
        );
        assert_eq!(
            BinAllocation::select(&private_append, &private_plan),
            BinAllocation::PrivateAppend
        );
        assert!(append_plan.contains_append);
        assert!(private_plan.contains_append);
    }

    #[test]
    fn dynamic_utf8_uses_a_bounded_size_estimate() {
        let utf8 = [segment(BsSegmentKind::Utf8, ArgVal::X(0), 0)];
        let plan = BinSizePlan::calculate(&utf8).unwrap();
        assert_eq!(plan.estimated_bits, 32);
        assert!(plan.requires_error_path);
    }

    #[test]
    fn append_segments_must_be_first_and_private_append_can_have_suffixes() {
        let later_append = [
            segment(BsSegmentKind::Integer, ArgVal::Immediate(8), 1),
            segment(BsSegmentKind::Append, ArgVal::Immediate(8), 1),
        ];
        let combined_private_append = [
            segment(BsSegmentKind::PrivateAppend, ArgVal::Immediate(8), 1),
            segment(BsSegmentKind::Integer, ArgVal::Immediate(8), 1),
        ];
        assert!(BeamModuleAssembler::validate_segments(&later_append).is_err());
        assert!(BeamModuleAssembler::validate_segments(&combined_private_append).is_ok());
    }

    #[test]
    fn float_segments_accept_only_otp_widths() {
        let valid = segment(BsSegmentKind::Float, ArgVal::Immediate(64), 1);
        let invalid = segment(BsSegmentKind::Float, ArgVal::Immediate(24), 1);
        assert!(BeamModuleAssembler::validate_segments(&[valid]).is_ok());
        assert!(BeamModuleAssembler::validate_segments(&[invalid]).is_err());
    }

    #[test]
    fn unit_scales_constant_sizes_before_the_heap_rounding_step() {
        let segments = [segment(BsSegmentKind::Binary, ArgVal::Immediate(9), 3)];
        let plan = BinSizePlan::calculate(&segments).unwrap();
        assert_eq!(plan.constant_bits, 27);
        assert_eq!(plan.rounded_heap_bytes().unwrap(), 8);
    }

    #[test]
    fn aggregate_size_overflow_is_reported() {
        let segments = [
            segment(BsSegmentKind::Integer, ArgVal::Immediate(u64::MAX), 1),
            segment(BsSegmentKind::Integer, ArgVal::Immediate(1), 1),
        ];
        assert!(BinSizePlan::calculate(&segments).is_err());
    }

    #[test]
    fn zero_units_are_only_valid_for_unitless_character_segments() {
        let invalid = segment(BsSegmentKind::Integer, ArgVal::Immediate(8), 0);
        let utf8 = segment(BsSegmentKind::Utf8, ArgVal::X(0), 0);
        assert!(BeamModuleAssembler::validate_segments(&[invalid]).is_err());
        assert!(BeamModuleAssembler::validate_segments(&[utf8]).is_ok());
    }

    #[test]
    fn large_unknown_sizes_are_clamped_to_the_off_heap_threshold() {
        let dynamic = segment(BsSegmentKind::Integer, ArgVal::Y(2), 1);
        assert_eq!(
            BinSizePlan::clamped_estimate(dynamic),
            BinSizePlan::ON_HEAP_LIMIT_BITS + 8
        );
    }

    #[test]
    fn invalid_segment_size_operand_is_not_a_static_size() {
        let segment = segment(BsSegmentKind::Integer, ArgVal::Export(3), 1);
        assert_eq!(BeamModuleAssembler::inline_static_bits(segment), None);
    }
}
