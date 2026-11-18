//! Operand model of the x86_64 encoder.
//!
//! Port of the operand types erts' `jit/x86` code builds through asmjit
//! (`erts/emulator/asmjit/x86/x86operand.h`, OTP-29.1.1): `x86::Gp` with its
//! 8/16/32/64-bit views, `x86::Xmm`/`x86::Ymm`/`x86::Zmm`, and `x86::Mem`. Register ids are
//! asmjit's physical ids (`Gp::kIdAx` = 0 ... `kIdR15` = 15), which are also the
//! hardware encodings; `jit/x86/beam_asm.hpp` names its fixed registers with them
//! (`c_p` = r13, `HTOP` = r15, `registers` = rbx, `E` = rsp/rbp, ...).

/// Width and byte-half of a general-purpose register view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpKind {
    /// Low byte (`al`, `cl`, ..., `spl`, `sil`, `r8b`): asmjit `GpbLo`.
    B8Lo,
    /// High byte of ids 0..=3 (`ah`, `ch`, `dh`, `bh`): asmjit `GpbHi`; unencodable with a REX prefix.
    B8Hi,
    /// 16-bit view (`ax`, ..., `r15w`): asmjit `Gpw`.
    W16,
    /// 32-bit view (`eax`, ..., `r15d`): asmjit `Gpd`.
    D32,
    /// 64-bit register (`rax`, ..., `r15`): asmjit `Gpq`.
    Q64,
}

/// A general-purpose register view: asmjit `x86::Gp`.
///
/// Fields are public like `arinsal_a64::enc::Gpr`; encodings validate them (`id <= 15`,
/// `B8Hi` only for ids 0..=3) and return [`super::EncodeError::InvalidRegister`] otherwise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gp {
    /// Physical register id, 0..=15 (asmjit `Gp::kIdAx` .. `kIdR15`).
    pub id: u8,
    /// View width.
    pub kind: GpKind,
}

impl Gp {
    /// 64-bit view of register `id` (asmjit `x86::gpq(id)`).
    pub const fn q(id: u8) -> Self {
        Self {
            id,
            kind: GpKind::Q64,
        }
    }
    /// 32-bit view of register `id` (asmjit `x86::gpd(id)`).
    pub const fn d(id: u8) -> Self {
        Self {
            id,
            kind: GpKind::D32,
        }
    }
    /// 16-bit view of register `id` (asmjit `x86::gpw(id)`).
    pub const fn w(id: u8) -> Self {
        Self {
            id,
            kind: GpKind::W16,
        }
    }
    /// Low-byte view of register `id` (asmjit `x86::gpb_lo(id)`).
    pub const fn b(id: u8) -> Self {
        Self {
            id,
            kind: GpKind::B8Lo,
        }
    }
    /// High-byte view of register `id` (asmjit `x86::gpb_hi(id)`), valid for ids 0..=3.
    pub const fn b_hi(id: u8) -> Self {
        Self {
            id,
            kind: GpKind::B8Hi,
        }
    }

    /// asmjit `Gp::r64()`.
    pub const fn r64(self) -> Self {
        Self::q(self.id)
    }
    /// asmjit `Gp::r32()`.
    pub const fn r32(self) -> Self {
        Self::d(self.id)
    }
    /// asmjit `Gp::r16()`.
    pub const fn r16(self) -> Self {
        Self::w(self.id)
    }
    /// asmjit `Gp::r8()` (the low byte).
    pub const fn r8(self) -> Self {
        Self::b(self.id)
    }
    /// asmjit `Gp::r8_hi()`.
    pub const fn r8_hi(self) -> Self {
        Self::b_hi(self.id)
    }

    /// Operand size in bytes (asmjit `x86_rm_size()`).
    pub const fn size(self) -> u8 {
        match self.kind {
            GpKind::B8Lo | GpKind::B8Hi => 1,
            GpKind::W16 => 2,
            GpKind::D32 => 4,
            GpKind::Q64 => 8,
        }
    }
}

macro_rules! gp_consts {
    ($ctor:ident: $($name:ident = $id:expr),* $(,)?) => {
        $(
            #[doc = concat!("`", stringify!($name), "` (asmjit `x86::", stringify!($name), "`).")]
            pub const $name: Gp = Gp::$ctor($id);
        )*
    };
}

gp_consts!(q: RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    R8 = 8, R9 = 9, R10 = 10, R11 = 11, R12 = 12, R13 = 13, R14 = 14, R15 = 15);
gp_consts!(d: EAX = 0, ECX = 1, EDX = 2, EBX = 3, ESP = 4, EBP = 5, ESI = 6, EDI = 7,
    R8D = 8, R9D = 9, R10D = 10, R11D = 11, R12D = 12, R13D = 13, R14D = 14, R15D = 15);
gp_consts!(w: AX = 0, CX = 1, DX = 2, BX = 3, SP = 4, BP = 5, SI = 6, DI = 7,
    R8W = 8, R9W = 9, R10W = 10, R11W = 11, R12W = 12, R13W = 13, R14W = 14, R15W = 15);
gp_consts!(b: AL = 0, CL = 1, DL = 2, BL = 3, SPL = 4, BPL = 5, SIL = 6, DIL = 7,
    R8B = 8, R9B = 9, R10B = 10, R11B = 11, R12B = 12, R13B = 13, R14B = 14, R15B = 15);
gp_consts!(b_hi: AH = 0, CH = 1, DH = 2, BH = 3);

/// A 128-bit SSE/AVX register: asmjit `x86::Xmm`, ids 0..=15.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Xmm(pub u8);

/// A 256-bit AVX register: asmjit `x86::Ymm`, ids 0..=15.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ymm(pub u8);

/// A 512-bit AVX-512 register: asmjit `x86::Zmm`, ids 0..=31.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Zmm(pub u8);

impl Xmm {
    /// asmjit `Vec::ymm()`.
    pub const fn ymm(self) -> Ymm {
        Ymm(self.0)
    }
}

impl Ymm {
    /// asmjit `Vec::xmm()`.
    pub const fn xmm(self) -> Xmm {
        Xmm(self.0)
    }
}

/// Base of a memory operand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemBase {
    /// A 64-bit general-purpose base register.
    Gp(Gp),
    /// `[rip + disp32]`. asmjit's label-based memory (`x86::qword_ptr(label)`) encodes as this form;
    /// the label layer binds the displacement through [`super::Emitter::last_rip_fixup`].
    Rip,
}

/// A memory operand: asmjit `x86::Mem` restricted to the 64-bit addressing erts uses.
///
/// `size` is the access size in bytes (0 = unsized, 1, 2, 4, 8, 16, 32), as asmjit's
/// `byte_ptr`/`word_ptr`/`dword_ptr`/`qword_ptr`/`xmmword_ptr`/`ymmword_ptr`/`ptr`. Like asmjit,
/// forms with a register operand take the operation size from the register and ignore `size`;
/// forms without one (`Mem, Imm`, unary `Mem`) require it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mem {
    /// Base register, RIP, or none for `[index*scale + disp32]` / absolute `[disp32]`.
    pub base: Option<MemBase>,
    /// Index register (64-bit, not `rsp`).
    pub index: Option<Gp>,
    /// Index scale as a shift, 0..=3 (asmjit `Mem::shift()`).
    pub shift: u8,
    /// Signed 32-bit displacement.
    pub disp: i32,
    /// Access size in bytes; 0 when unsized.
    pub size: u8,
}

impl Mem {
    /// `[base + disp]` with the given access size (asmjit `x86::ptr(base, disp, size)`).
    pub const fn base_disp(base: Gp, disp: i32, size: u8) -> Self {
        Self {
            base: Some(MemBase::Gp(base)),
            index: None,
            shift: 0,
            disp,
            size,
        }
    }
    /// `[base + index << shift + disp]` with the given access size.
    pub const fn base_index(base: Gp, index: Gp, shift: u8, disp: i32, size: u8) -> Self {
        Self {
            base: Some(MemBase::Gp(base)),
            index: Some(index),
            shift,
            disp,
            size,
        }
    }
    /// `[rip + disp]` with the given access size.
    pub const fn rip(disp: i32, size: u8) -> Self {
        Self {
            base: Some(MemBase::Rip),
            index: None,
            shift: 0,
            disp,
            size,
        }
    }
    /// Absolute `[disp32]` (sign-extended 32-bit address, SIB no-base form).
    pub const fn abs(disp: i32, size: u8) -> Self {
        Self {
            base: None,
            index: None,
            shift: 0,
            disp,
            size,
        }
    }
    /// The same address with another access size (asmjit `Mem::clone_resized`-style retyping).
    pub const fn with_size(mut self, size: u8) -> Self {
        self.size = size;
        self
    }
    /// The same address moved by `delta` bytes (asmjit `Mem::clone_adjusted`).
    pub const fn adjusted(mut self, delta: i32) -> Self {
        self.disp = self.disp.wrapping_add(delta);
        self
    }
}

/// `byte ptr [base + disp]` (asmjit `x86::byte_ptr`).
pub const fn byte_ptr(base: Gp, disp: i32) -> Mem {
    Mem::base_disp(base, disp, 1)
}
/// `word ptr [base + disp]` (asmjit `x86::word_ptr`).
pub const fn word_ptr(base: Gp, disp: i32) -> Mem {
    Mem::base_disp(base, disp, 2)
}
/// `dword ptr [base + disp]` (asmjit `x86::dword_ptr`).
pub const fn dword_ptr(base: Gp, disp: i32) -> Mem {
    Mem::base_disp(base, disp, 4)
}
/// `qword ptr [base + disp]` (asmjit `x86::qword_ptr`).
pub const fn qword_ptr(base: Gp, disp: i32) -> Mem {
    Mem::base_disp(base, disp, 8)
}
/// `xmmword ptr [base + disp]` (asmjit `x86::xmmword_ptr`).
pub const fn xmmword_ptr(base: Gp, disp: i32) -> Mem {
    Mem::base_disp(base, disp, 16)
}
/// `ymmword ptr [base + disp]` (asmjit `x86::ymmword_ptr`).
pub const fn ymmword_ptr(base: Gp, disp: i32) -> Mem {
    Mem::base_disp(base, disp, 32)
}
/// Unsized `[base + disp]` (asmjit `x86::ptr`).
pub const fn ptr(base: Gp, disp: i32) -> Mem {
    Mem::base_disp(base, disp, 0)
}
