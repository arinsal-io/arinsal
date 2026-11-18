//! Shared x86_64 encoding machinery: legacy/REX/VEX prefixes, opcode maps, ModRM/SIB and
//! displacement selection, RIP-relative operands and immediates.
//!
//! Port of the emit tail of `x86::Assembler::_emit` in
//! `erts/emulator/asmjit/x86/x86assembler.cpp`, OTP-29.1.1 (`EmitX86Op`, `EmitX86OpReg`,
//! `EmitX86R`, `EmitX86M`, `EmitModSib`, `EmitVexEvexR`, `EmitVexEvexM`) for 64-bit mode and the
//! operands erts uses: no segment overrides, no 32-bit addressing, no EVEX. Every family file
//! builds an [`Opcode`] and calls one of these; nothing else writes instruction bytes.

use super::{Emitter, EncodeError, Gp, GpKind, Mem, MemBase, RipFixup};

/// Mandatory prefix (asmjit `Opcode::kPP_*`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Pp {
    #[default]
    None,
    P66,
    #[expect(
        dead_code,
        reason = "first used by the SSE scalar family (E22); remove then"
    )]
    PF3,
    #[expect(
        dead_code,
        reason = "first used by the SSE scalar family (E22); remove then"
    )]
    PF2,
}

impl Pp {
    /// The legacy prefix byte.
    const fn byte(self) -> Option<u8> {
        match self {
            Pp::None => None,
            Pp::P66 => Some(0x66),
            Pp::PF3 => Some(0xF3),
            Pp::PF2 => Some(0xF2),
        }
    }
    /// VEX `pp` field.
    const fn vex(self) -> u8 {
        match self {
            Pp::None => 0,
            Pp::P66 => 1,
            Pp::PF3 => 2,
            Pp::PF2 => 3,
        }
    }
}

/// Opcode map (asmjit `Opcode::kMM_*`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Map {
    #[default]
    Legacy,
    M0F,
    M0F38,
    #[expect(
        dead_code,
        reason = "first used by vpermilpd/vpinsrq (E25); remove then"
    )]
    M0F3A,
}

impl Map {
    /// VEX `mmmmm` field (legacy map is not VEX-encodable).
    const fn vex(self) -> u8 {
        match self {
            Map::Legacy => 0,
            Map::M0F => 1,
            Map::M0F38 => 2,
            Map::M0F3A => 3,
        }
    }
}

/// An opcode with its mandatory prefix, map and REX.W/VEX.W bit: the parts of asmjit's
/// packed `Opcode` value that 64-bit legacy and VEX encodings use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Opcode {
    pub pp: Pp,
    pub map: Map,
    pub byte: u8,
    pub w: bool,
}

impl Opcode {
    /// One-byte-map opcode.
    pub const fn legacy(byte: u8) -> Self {
        Self {
            pp: Pp::None,
            map: Map::Legacy,
            byte,
            w: false,
        }
    }
    /// `0F xx` opcode.
    pub const fn m0f(byte: u8) -> Self {
        Self {
            map: Map::M0F,
            ..Self::legacy(byte)
        }
    }
    /// `0F 38 xx` opcode.
    pub const fn m0f38(byte: u8) -> Self {
        Self {
            map: Map::M0F38,
            ..Self::legacy(byte)
        }
    }
    /// `0F 3A xx` opcode.
    #[expect(
        dead_code,
        reason = "first used by vpermilpd/vpinsrq (E25); remove then"
    )]
    pub const fn m0f3a(byte: u8) -> Self {
        Self {
            map: Map::M0F3A,
            ..Self::legacy(byte)
        }
    }
    /// With a mandatory prefix.
    pub const fn with_pp(mut self, pp: Pp) -> Self {
        self.pp = pp;
        self
    }
    /// With REX.W / VEX.W set to `w`.
    pub const fn with_w(mut self, w: bool) -> Self {
        self.w = w;
        self
    }
    /// asmjit `Opcode::add_prefix_by_size`: 66h for 16-bit, REX.W for 64-bit.
    pub const fn prefix_by_size(mut self, size: u8) -> Self {
        match size {
            2 => self.pp = Pp::P66,
            8 => self.w = true,
            _ => {}
        }
        self
    }
    /// asmjit `Opcode::add_arith_by_size`: `+1` for non-byte forms plus [`Self::prefix_by_size`].
    pub const fn arith_by_size(mut self, size: u8) -> Self {
        if size != 1 {
            self.byte += 1;
        }
        self.prefix_by_size(size)
    }
}

/// An immediate to append after the instruction: the low `size` bytes of `value`, little endian.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Imm {
    pub value: u64,
    pub size: u8,
}

impl Imm {
    pub const NONE: Self = Self { value: 0, size: 0 };

    pub const fn new(value: u64, size: u8) -> Self {
        Self { value, size }
    }
}

/// REX constraints from byte registers (asmjit `FIXUP_GPB`: `kX86_Rex` / `kX86_InvalidRex`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ByteRex {
    /// `spl`/`bpl`/`sil`/`dil`: a REX prefix is required even with no REX bits set.
    pub force: bool,
    /// `ah`/`ch`/`dh`/`bh`: any REX prefix makes the encoding invalid.
    pub invalid: bool,
}

/// The ModRM.rm operand.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Rm<'a> {
    /// Register id 0..=15 (byte registers already fixed up).
    Reg(u8),
    Mem(&'a Mem),
}

/// asmjit `is_int_n<N>`.
pub(crate) const fn is_int(value: i64, bits: u32) -> bool {
    let min = -(1i64 << (bits - 1));
    let max = (1i64 << (bits - 1)) - 1;
    value >= min && value <= max
}

/// asmjit `is_uint_n<N>`.
pub(crate) const fn is_uint(value: i64, bits: u32) -> bool {
    value >= 0 && (value as u64) < (1u64 << bits)
}

/// ModRM.rm target after validation.
enum Target {
    Reg(u8),
    Mem(MemEnc),
}

/// Encoded memory operand: REX.X/REX.B bits and the ModRM/SIB/displacement tail.
struct MemEnc {
    x: u8,
    b: u8,
    tail: [u8; 7],
    len: usize,
    /// Index of the RIP displacement in `tail`.
    rip_disp: Option<usize>,
}

impl MemEnc {
    fn push(&mut self, byte: u8) {
        self.tail[self.len] = byte;
        self.len += 1;
    }
    fn push32(&mut self, value: i32) {
        for byte in value.to_le_bytes() {
            self.push(byte);
        }
    }
}

const fn modrm(md: u8, reg: u8, rm: u8) -> u8 {
    (md << 6) | ((reg & 7) << 3) | (rm & 7)
}

const fn sib(shift: u8, index: u8, base: u8) -> u8 {
    (shift << 6) | ((index & 7) << 3) | (base & 7)
}

impl Emitter {
    /// Validates a general-purpose register operand and returns its ModRM id, applying asmjit's
    /// `FIXUP_GPB` byte-register rules (`ah`..`bh` encode as 4..7 and forbid REX; `spl`..`dil`
    /// need a REX prefix).
    pub(crate) fn gp_id(reg: Gp, rex: &mut ByteRex) -> Result<u8, EncodeError> {
        if reg.id > 15 {
            return Err(EncodeError::InvalidRegister(reg));
        }
        match reg.kind {
            GpKind::B8Hi => {
                if reg.id > 3 {
                    return Err(EncodeError::InvalidRegister(reg));
                }
                rex.invalid = true;
                Ok(reg.id + 4)
            }
            GpKind::B8Lo => {
                rex.force |= reg.id >= 4;
                Ok(reg.id)
            }
            _ => Ok(reg.id),
        }
    }

    /// Operation size of two register operands that must match (asmjit `kOperandSizeMismatch`).
    pub(crate) fn same_size(a: Gp, b: Gp) -> Result<u8, EncodeError> {
        if a.size() == b.size() {
            Ok(a.size())
        } else {
            Err(EncodeError::OperandSizeMismatch)
        }
    }

    /// Access size of a memory operand in a form without a register to size it.
    pub(crate) fn mem_size(mem: &Mem) -> Result<u8, EncodeError> {
        match mem.size {
            1 | 2 | 4 | 8 => Ok(mem.size),
            0 => Err(EncodeError::AmbiguousOperandSize),
            _ => Err(EncodeError::InvalidInstruction),
        }
    }

    /// Validates a vector register id (0..=15; EVEX registers 16..=31 are not used by erts).
    pub(crate) fn vec_id(id: u8) -> Result<u8, EncodeError> {
        if id > 15 {
            Err(EncodeError::InvalidVecRegister(id))
        } else {
            Ok(id)
        }
    }

    /// Port of asmjit `EmitModSib`/`EmitModVSib` (64-bit, non-VSIB): ModRM, SIB and displacement
    /// for `mem` with ModRM.reg = `reg`.
    fn encode_mem(mem: &Mem, reg: u8) -> Result<MemEnc, EncodeError> {
        let mut enc = MemEnc {
            x: 0,
            b: 0,
            tail: [0; 7],
            len: 0,
            rip_disp: None,
        };
        let disp = mem.disp;
        let index = match mem.index {
            Some(index) => {
                if index.kind != GpKind::Q64 || index.id > 15 || mem.shift > 3 {
                    return Err(EncodeError::InvalidAddressIndex);
                }
                // ESP|RSP can't be used as INDEX in pure SIB mode.
                if index.id == 4 {
                    return Err(EncodeError::InvalidAddressIndex);
                }
                enc.x = index.id >> 3;
                Some(index.id)
            }
            None => None,
        };
        match (mem.base, index) {
            (Some(MemBase::Gp(base)), None) => {
                if base.kind != GpKind::Q64 || base.id > 15 {
                    return Err(EncodeError::InvalidAddress);
                }
                enc.b = base.id >> 3;
                let rb = base.id & 7;
                if rb == 4 {
                    // [RSP|R12 (+ DISP8|DISP32)] needs a SIB byte.
                    if disp == 0 {
                        enc.push(modrm(0, reg, 4));
                        enc.push(sib(0, 4, rb));
                    } else if is_int(disp as i64, 8) {
                        enc.push(modrm(1, reg, 4));
                        enc.push(sib(0, 4, rb));
                        enc.push(disp as u8);
                    } else {
                        enc.push(modrm(2, reg, 4));
                        enc.push(sib(0, 4, rb));
                        enc.push32(disp);
                    }
                } else if rb != 5 && disp == 0 {
                    enc.push(modrm(0, reg, rb));
                } else if is_int(disp as i64, 8) {
                    enc.push(modrm(1, reg, rb));
                    enc.push(disp as u8);
                } else {
                    enc.push(modrm(2, reg, rb));
                    enc.push32(disp);
                }
            }
            (Some(MemBase::Gp(base)), Some(index)) => {
                if base.kind != GpKind::Q64 || base.id > 15 {
                    return Err(EncodeError::InvalidAddress);
                }
                enc.b = base.id >> 3;
                let rb = base.id & 7;
                let s = sib(mem.shift, index, rb);
                if disp == 0 && rb != 5 {
                    enc.push(modrm(0, reg, 4));
                    enc.push(s);
                } else if is_int(disp as i64, 8) {
                    enc.push(modrm(1, reg, 4));
                    enc.push(s);
                    enc.push(disp as u8);
                } else {
                    enc.push(modrm(2, reg, 4));
                    enc.push(s);
                    enc.push32(disp);
                }
            }
            (Some(MemBase::Rip), None) => {
                enc.push(modrm(0, reg, 5));
                enc.rip_disp = Some(enc.len);
                enc.push32(disp);
            }
            // [LABEL|RIP + INDEX] is not encodable in 64-bit mode.
            (Some(MemBase::Rip), Some(_)) => return Err(EncodeError::InvalidAddress),
            (None, Some(index)) => {
                enc.push(modrm(0, reg, 4));
                enc.push(sib(mem.shift, index, 5));
                enc.push32(disp);
            }
            (None, None) => {
                // Absolute [DISP32]: erts' CodeHolder has no base address, so asmjit picks the
                // sign-extended SIB form for a 32-bit address.
                enc.push(modrm(0, reg, 4));
                enc.push(sib(0, 4, 5));
                enc.push32(disp);
            }
        }
        Ok(enc)
    }

    fn rex_byte(
        w: bool,
        r: u8,
        x: u8,
        b: u8,
        byte_rex: ByteRex,
    ) -> Result<Option<u8>, EncodeError> {
        let bits = ((w as u8) << 3) | ((r & 1) << 2) | ((x & 1) << 1) | (b & 1);
        if bits == 0 && !byte_rex.force {
            return Ok(None);
        }
        if byte_rex.invalid {
            return Err(EncodeError::InvalidRexPrefix);
        }
        Ok(Some(0x40 | bits))
    }

    fn put_map_and_opcode(&mut self, opcode: Opcode) {
        match opcode.map {
            Map::Legacy => {}
            Map::M0F => self.bytes.push(0x0F),
            Map::M0F38 => self.bytes.extend_from_slice(&[0x0F, 0x38]),
            Map::M0F3A => self.bytes.extend_from_slice(&[0x0F, 0x3A]),
        }
        self.bytes.push(opcode.byte);
    }

    fn put_imm(&mut self, imm: Imm) {
        self.bytes
            .extend_from_slice(&imm.value.to_le_bytes()[..imm.size as usize]);
    }

    fn put_mem_tail(&mut self, enc: &MemEnc, imm: Imm) {
        let tail_start = self.bytes.len();
        self.bytes.extend_from_slice(&enc.tail[..enc.len]);
        self.put_imm(imm);
        self.last_rip = enc.rip_disp.map(|at| RipFixup {
            disp_at: tail_start + at,
            end: self.bytes.len(),
        });
    }

    /// asmjit `EmitX86Op`: `[pp] [REX] [map] opcode [imm]`, no ModRM.
    pub(crate) fn x86_op(&mut self, opcode: Opcode, imm: Imm) -> Result<(), EncodeError> {
        let rex = Self::rex_byte(opcode.w, 0, 0, 0, ByteRex::default())?;
        self.bytes.extend(opcode.pp.byte());
        self.bytes.extend(rex);
        self.put_map_and_opcode(opcode);
        self.put_imm(imm);
        self.last_rip = None;
        Ok(())
    }

    /// asmjit `EmitX86OpReg`: register in the low opcode bits (`B8+r`, `0F C8+r`), REX.B for r8+.
    pub(crate) fn x86_op_reg(
        &mut self,
        opcode: Opcode,
        reg: u8,
        byte_rex: ByteRex,
        imm: Imm,
    ) -> Result<(), EncodeError> {
        let rex = Self::rex_byte(opcode.w, 0, 0, reg >> 3, byte_rex)?;
        self.bytes.extend(opcode.pp.byte());
        self.bytes.extend(rex);
        self.put_map_and_opcode(Opcode {
            byte: opcode.byte + (reg & 7),
            ..opcode
        });
        self.put_imm(imm);
        self.last_rip = None;
        Ok(())
    }

    /// asmjit `EmitX86R` / `EmitX86M`: `[pp] [REX] [map] opcode ModRM [SIB] [disp] [imm]` with
    /// ModRM.reg = `reg` (a register id or an opcode extension `/n`).
    pub(crate) fn x86_rm(
        &mut self,
        opcode: Opcode,
        reg: u8,
        rm: Rm<'_>,
        byte_rex: ByteRex,
        imm: Imm,
    ) -> Result<(), EncodeError> {
        match rm {
            Rm::Reg(rb) => {
                let rex = Self::rex_byte(opcode.w, reg >> 3, 0, rb >> 3, byte_rex)?;
                self.bytes.extend(opcode.pp.byte());
                self.bytes.extend(rex);
                self.put_map_and_opcode(opcode);
                self.bytes.push(modrm(3, reg, rb));
                self.put_imm(imm);
                self.last_rip = None;
            }
            Rm::Mem(mem) => {
                let enc = Self::encode_mem(mem, reg)?;
                let rex = Self::rex_byte(opcode.w, reg >> 3, enc.x, enc.b, byte_rex)?;
                self.bytes.extend(opcode.pp.byte());
                self.bytes.extend(rex);
                self.put_map_and_opcode(opcode);
                self.put_mem_tail(&enc, imm);
            }
        }
        Ok(())
    }

    /// asmjit `EmitVexEvexR` / `EmitVexEvexM` (VEX only): `C5`/`C4` prefix, opcode, ModRM tail.
    ///
    /// `reg` is ModRM.reg, `vvvv` the extra source register (0 when unused), `l256` selects
    /// VEX.L. The two-byte `C5` form is used when W, X and B are clear and the map is `0F`.
    pub(crate) fn vex_rm(
        &mut self,
        opcode: Opcode,
        l256: bool,
        reg: u8,
        vvvv: u8,
        rm: Rm<'_>,
        imm: Imm,
    ) -> Result<(), EncodeError> {
        if opcode.map == Map::Legacy {
            return Err(EncodeError::InvalidInstruction);
        }
        let target = match rm {
            Rm::Reg(rb) => Target::Reg(rb),
            Rm::Mem(mem) => Target::Mem(Self::encode_mem(mem, reg)?),
        };
        let (x, b) = match &target {
            Target::Reg(rb) => (0, rb >> 3),
            Target::Mem(enc) => (enc.x, enc.b),
        };
        let r = (reg >> 3) & 1;
        let tail = ((!vvvv & 0xF) << 3) | ((l256 as u8) << 2) | opcode.pp.vex();
        if !opcode.w && x == 0 && b == 0 && opcode.map == Map::M0F {
            self.bytes.extend_from_slice(&[0xC5, ((r ^ 1) << 7) | tail]);
        } else {
            let rxb = ((r ^ 1) << 7) | (((x & 1) ^ 1) << 6) | (((b & 1) ^ 1) << 5);
            self.bytes.extend_from_slice(&[
                0xC4,
                rxb | opcode.map.vex(),
                ((opcode.w as u8) << 7) | tail,
            ]);
        }
        self.bytes.push(opcode.byte);
        match target {
            Target::Reg(rb) => {
                self.bytes.push(modrm(3, reg, rb));
                self.put_imm(imm);
                self.last_rip = None;
            }
            Target::Mem(enc) => self.put_mem_tail(&enc, imm),
        }
        Ok(())
    }
}
