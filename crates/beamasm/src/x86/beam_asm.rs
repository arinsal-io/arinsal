//! Port of erts/emulator/beam/jit/x86/beam_asm.hpp (`struct BeamAssembler`: register
//! assignments, C ABI argument registers, `Update`, scheduler register and Erlang stack
//! addressing, frame transitions, tag tests) and the frame layout selection and layout checks
//! of erts/emulator/beam/jit/beam_jit_main.cpp (beamasm_init), OTP-29.1.1.
//!
//! [`BeamAssembler`] is the base both [`super::beam_asm_global::BeamGlobalAssembler`] and
//! [`super::beam_asm_module::BeamModuleAssembler`] build on, as in erts. Its `a` is the asmjit
//! `x86::Assembler` attached to the assembler's `CodeHolder`: here the `arinsal_x64`
//! [`CodeBuffer`], whose instructions are encoded by [`Emitter`] one asmjit call at a time.

use arinsal_x64::buf::{BufferError, CodeBuffer, FinalizedCode, Label};
use arinsal_x64::enc::{self, CondCode, Emitter, EncodeError, Gp, Mem};
use arinsal_x64::exec::CodeMemory;

use crate::common::args::{ArgVal, REG_MASK};
use crate::{
    F_REG_ARRAY_DISP, ProcessHeader, RUNTIME_STACK_DISP, SchedulerRegisters, X_REG_ARRAY_OFFSET,
    scheduler_reg_disp, tmp_mem_disp,
};

/// BeamAsm's pinned registers and C ABI registers on x86-64 (`BeamAssembler` members).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:103-181 (BeamAssembler), OTP-29.1.1.
pub mod register {
    use arinsal_x64::enc::{self, Gp};

    /// `registers`: points at `x_reg_array` inside the scheduler's `SchedulerRegisters`.
    pub const REGISTERS: Gp = enc::RBX;
    /// `E`: the Erlang stack pointer. erts defines `NATIVE_ERLANG_STACK` on every x86-64
    /// target but OpenBSD (configure.ac), so the Erlang stack is the native stack and `E` is
    /// `rsp`, invalid while running on the runtime stack.
    pub const E: Gp = enc::RSP;
    /// `E_saved`: holds `E` across a runtime call that does not publish the stack.
    pub const E_SAVED: Gp = enc::RBP;
    /// `frame_pointer` under `ERLANG_FRAME_POINTERS` (Linux), used by the `FP_RA` layout.
    #[cfg(target_os = "linux")]
    pub const FRAME_POINTER: Gp = enc::RBP;
    /// `c_p`: the current process.
    pub const C_P: Gp = enc::R13;
    /// `FCALLS`: remaining reductions, the 32-bit view `r14d`.
    pub const FCALLS: Gp = enc::R14D;
    /// `HTOP`: the young heap top.
    pub const HTOP: Gp = enc::R15;
    /// `active_code_ix`: local copy of the active code index (or `ERTS_SAVE_CALLS_CODE_IX`).
    pub const ACTIVE_CODE_IX: Gp = enc::R12;

    /// C argument registers, `ARG1`..`ARG6` (System V AMD64).
    #[cfg(not(windows))]
    pub const ARG: [Gp; 6] = [enc::RDI, enc::RSI, enc::RDX, enc::RCX, enc::R8, enc::R9];
    /// Caller-saved scratch registers `TMP1`, `TMP2` (System V AMD64).
    #[cfg(not(windows))]
    pub const TMP: [Gp; 2] = [enc::R10, enc::R11];

    /// C argument registers, `ARG1`..`ARG6` (`ERTS_JIT_ABI_WIN32`). The Win64 convention
    /// passes four arguments in registers; `runtime_call` pushes ARG5/ARG6 for the callee.
    #[cfg(windows)]
    pub const ARG: [Gp; 6] = [enc::RCX, enc::RDX, enc::R8, enc::R9, enc::R10, enc::R11];
    /// Caller-saved scratch registers `TMP1`, `TMP2` (`ERTS_JIT_ABI_WIN32`).
    #[cfg(windows)]
    pub const TMP: [Gp; 2] = [enc::RDI, enc::RSI];

    /// `ARG1`.
    pub const ARG1: Gp = ARG[0];
    /// `ARG2`.
    pub const ARG2: Gp = ARG[1];
    /// `ARG3`.
    pub const ARG3: Gp = ARG[2];
    /// `ARG4`.
    pub const ARG4: Gp = ARG[3];
    /// `ARG5`.
    pub const ARG5: Gp = ARG[4];
    /// `ARG6`.
    pub const ARG6: Gp = ARG[5];
    /// `ARG1d`.
    pub const ARG1D: Gp = ARG1.r32();
    /// `ARG2d`.
    pub const ARG2D: Gp = ARG2.r32();
    /// `ARG3d`.
    pub const ARG3D: Gp = ARG3.r32();
    /// `ARG4d`.
    pub const ARG4D: Gp = ARG4.r32();
    /// `ARG5d`.
    pub const ARG5D: Gp = ARG5.r32();
    /// `ARG6d`.
    pub const ARG6D: Gp = ARG6.r32();
    /// `TMP1`.
    pub const TMP1: Gp = TMP[0];
    /// `TMP2`.
    pub const TMP2: Gp = TMP[1];

    /// `RET`: C return value.
    pub const RET: Gp = enc::RAX;
    /// `RETd`.
    pub const RETD: Gp = enc::EAX;
    /// `RETb`.
    pub const RETB: Gp = enc::AL;
}

use register::{ACTIVE_CODE_IX, ARG1, ARG1D, ARG6, C_P, E, E_SAVED, FCALLS, HTOP, REGISTERS, RET};

/// Bytes `runtime_call` reserves below the arguments for the callee: Win64's shadow space.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:497-529 (runtime_call), OTP-29.1.1.
#[cfg(windows)]
pub const RUNTIME_CALL_SHADOW_SPACE: i32 = 4 * 8;
/// Bytes `runtime_call` reserves below the arguments for the callee: none on System V.
#[cfg(not(windows))]
pub const RUNTIME_CALL_SHADOW_SPACE: i32 = 0;

/// Erlang stack frame layout, erts `ErtsFrameLayout`.
// Port of erts/emulator/beam/erl_vm.h:70-86, OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameLayout {
    /// Each frame holds only its return address (`ERTS_FRAME_LAYOUT_RA`).
    Ra,
    /// Each frame holds a frame pointer and the return address (`ERTS_FRAME_LAYOUT_FP_RA`).
    FpRa,
}

/// The frame layout native code is emitted for.
///
/// erts hardcodes `ERTS_FRAME_LAYOUT_RA` without `ERLANG_FRAME_POINTERS` (every x86-64
/// target but Linux). On Linux `beamasm_init` picks `FP_RA` only for `+JPperf fp`; without it
/// the layout is `RA`, the only one this port emits.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:276-289 (beamasm_init), OTP-29.1.1.
pub const FRAME_LAYOUT: FrameLayout = FrameLayout::Ra;

/// Words a return address takes in an Erlang frame (`CP_SIZE` for the `RA` layout).
// Port of erts/emulator/beam/erl_vm.h:85 (CP_SIZE), OTP-29.1.1.
pub const CP_SIZE: usize = 1;

/// `_TAG_PRIMARY_MASK`.
// Port of erts/emulator/beam/erl_term.h:72-79, OTP-29.1.1.
pub const TAG_PRIMARY_MASK: u8 = 0x3;
/// `TAG_PRIMARY_LIST`.
pub const TAG_PRIMARY_LIST: u8 = 0x1;
/// `TAG_PRIMARY_BOXED`.
pub const TAG_PRIMARY_BOXED: u8 = 0x2;
/// `THE_NON_VALUE` in a release build.
// Port of erts/emulator/beam/erl_term.h:155, OTP-29.1.1.
pub const THE_NON_VALUE: u64 = 0;

/// Selects process fields synchronized at a native/runtime boundary (erts `Update`).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:655-667 (enum Update), OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Update(u8);

impl Update {
    /// No state synchronization.
    pub const NONE: Self = Self(0);
    /// `eStack`: publish/reload `E` through `c_p->stop`.
    pub const STACK: Self = Self(1 << 0);
    /// `eHeap`: publish/reload `HTOP` through `c_p->htop`.
    pub const HEAP: Self = Self(1 << 1);
    /// `eReductions`: publish/reload `FCALLS` through `c_p->fcalls`.
    pub const REDUCTIONS: Self = Self(1 << 2);
    /// `eCodeIndex`: reload `active_code_ix`, keeping save_calls.
    pub const CODE_INDEX: Self = Self(1 << 3);
    /// `eHeapAlloc`: runtime functions that allocate heap.
    pub const HEAP_ALLOC: Self = Self(Self::HEAP.0 | Self::STACK.0);
    /// `eHeapOnlyAlloc` in a release build.
    pub const HEAP_ONLY_ALLOC: Self = Self::HEAP;

    /// Combines synchronization flags.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every flag of `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Branch reach a tag test asks for (`BeamAssembler::Distance`).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:210, OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distance {
    /// `dShort`: `a.short_().jcc(label)`, rel8.
    Short,
    /// `dLong`: `a.jcc(label)`.
    Long,
}

/// Displacement from `registers` of X register `index` (`getXRef`).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:252-258 (getXRef), OTP-29.1.1.
pub const fn x_ref_disp(index: u32) -> i32 {
    assert!(index < 1024);
    scheduler_reg_disp(X_REG_ARRAY_OFFSET + index as usize * 8)
}

/// Displacement from `registers` of float register `index` (`getFRef`).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:244-250 (getFRef), OTP-29.1.1.
pub const fn f_ref_disp(index: u32) -> i32 {
    assert!(index < 1024);
    F_REG_ARRAY_DISP + index as i32 * 8
}

/// Displacement from `registers` of `TMP_MEM{index+1}q`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:183-207 (TMP_MEM1q..TMP_MEM5q), OTP-29.1.1.
pub const fn tmp_mem_q_disp(index: u32) -> i32 {
    assert!(index < 5);
    tmp_mem_disp(index as usize)
}

/// Displacement from `E` of Y register `index` (`getYRef`). With `NATIVE_ERLANG_STACK` the
/// return address sits above the Y registers, so Y0 is at `E` itself.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:260-268 (getYRef), OTP-29.1.1.
pub const fn y_ref_disp(index: u32) -> i32 {
    assert!(index < 1024);
    index as i32 * 8
}

/// `getSchedulerRegRef(offset, size)`: a field of `SchedulerRegisters` at `offset`, addressed
/// from `registers` (which points at `x_reg_array`).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:232-242 (getSchedulerRegRef), OTP-29.1.1.
pub const fn get_scheduler_reg_ref(offset: usize, size: u8) -> Mem {
    Mem::base_disp(REGISTERS, scheduler_reg_disp(offset), size)
}

/// `getRuntimeStackRef()`: `aux_regs.d.runtime_stack`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:212-216 (getRuntimeStackRef), OTP-29.1.1.
pub const fn get_runtime_stack_ref() -> Mem {
    Mem::base_disp(REGISTERS, RUNTIME_STACK_DISP, 8)
}

/// `getFRef(index, size)`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:244-250 (getFRef), OTP-29.1.1.
pub const fn get_f_ref(index: u32, size: u8) -> Mem {
    Mem::base_disp(REGISTERS, f_ref_disp(index), size)
}

/// `getXRef(index, size)`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:252-258 (getXRef), OTP-29.1.1.
pub const fn get_x_ref(index: u32, size: u8) -> Mem {
    Mem::base_disp(REGISTERS, x_ref_disp(index), size)
}

/// `getYRef(index, size)`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:260-268 (getYRef), OTP-29.1.1.
pub const fn get_y_ref(index: u32, size: u8) -> Mem {
    Mem::base_disp(E, y_ref_disp(index), size)
}

/// `getCARRef(Src, size)`: the head of the cons cell `src` points at.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:270-273 (getCARRef), OTP-29.1.1.
pub const fn get_car_ref(src: Gp, size: u8) -> Mem {
    Mem::base_disp(src, -(TAG_PRIMARY_LIST as i32), size)
}

/// `getCDRRef(Src, size)`: the tail of the cons cell `src` points at.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:275-278 (getCDRRef), OTP-29.1.1.
pub const fn get_cdr_ref(src: Gp, size: u8) -> Mem {
    Mem::base_disp(src, -(TAG_PRIMARY_LIST as i32) + 8, size)
}

/// `TMP_MEM{index+1}q`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:183-192, OTP-29.1.1.
pub const fn tmp_mem_q(index: u32) -> Mem {
    Mem::base_disp(REGISTERS, tmp_mem_q_disp(index), 8)
}

/// `TMP_MEM{index+1}d`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:194-208, OTP-29.1.1.
pub const fn tmp_mem_d(index: u32) -> Mem {
    Mem::base_disp(REGISTERS, tmp_mem_q_disp(index), 4)
}

/// `getArgRef(arg, size)`: the memory of an X or Y register operand. erts' remaining case
/// is the float register file, which [`ArgVal`] reaches through `getFRef` directly.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:561-570 (getArgRef), OTP-29.1.1.
pub const fn get_arg_ref(arg: ArgVal, size: u8) -> Option<Mem> {
    match arg {
        ArgVal::X(val) => Some(get_x_ref(val & REG_MASK, size)),
        ArgVal::Y(val) => Some(get_y_ref(val & REG_MASK, size)),
        _ => None,
    }
}

/// `emit_boxed_val(Src, bytes, size)`: the word at `bytes` into the boxed object `src`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:944-949 (emit_boxed_val), OTP-29.1.1.
pub const fn emit_boxed_val(src: Gp, bytes: i32, size: u8) -> Mem {
    assert!(bytes % 8 == 0);
    Mem::base_disp(src, bytes - TAG_PRIMARY_BOXED as i32, size)
}

pub use crate::common::process;

/// `x86::ptr(c_p, offsetof(Process, field), size)`.
pub const fn process_ref(offset: i32, size: u8) -> Mem {
    Mem::base_disp(C_P, offset, size)
}

/// An assembly failure: an operand asmjit would reject, or a label/layout error of the
/// code holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsmError {
    /// The encoder rejected an instruction.
    Encode(EncodeError),
    /// Label binding, fixup or layout failed.
    Buffer(BufferError),
    /// An operand the instruction does not take (erts `ASSERT`s it at load time).
    Operand(&'static str),
    /// The JIT allocator could not allocate or write the code (erts `ERTS_ASSERT`s "Failed
    /// to allocate module code").
    AllocCode,
}

impl From<EncodeError> for AsmError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

impl From<BufferError> for AsmError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

impl std::fmt::Display for AsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AsmError {}

/// erts `struct BeamAssembler`: the code holder and the helpers shared by the global and
/// module assemblers.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:84-1126 (struct BeamAssembler), OTP-29.1.1.
#[derive(Debug, Default)]
pub struct BeamAssembler {
    /// `a` attached to `code`: the code and read-only data sections, labels and fixups.
    pub a: CodeBuffer,
    /// `code` once flattened and relocated by [`Self::codegen`]: the label offsets from the
    /// base address and the text size, which `getCode` and `getOffset` read afterwards.
    code: Option<FinalizedCode>,
    /// `code.base_address()`: the executable address the code was relocated to.
    base_address: Option<usize>,
}

impl BeamAssembler {
    /// An empty assembler with the text section active.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emits one asmjit instruction call into the active section.
    pub fn emit(
        &mut self,
        f: impl FnOnce(&mut Emitter) -> Result<(), EncodeError>,
    ) -> Result<(), AsmError> {
        Ok(self.a.emit(f)?)
    }

    /// Flattens the code, resolves every label, allocates executable memory from the JIT
    /// allocator (dual-mapped: an RX and an RW view of the same pages), relocates the code to
    /// the RX address and copies it in through the RW view. The returned span owns both views
    /// (erts' `executable_ptr` / `writable_ptr`); the code stays inspectable through
    /// [`Self::get_code`] and [`Self::get_offset`].
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:87-140 (BeamAssemblerCommon::codegen),
    // OTP-29.1.1.
    pub fn codegen(&mut self) -> Result<CodeMemory, AsmError> {
        // `code.flatten()`, `code.resolve_cross_section_fixups()`; an unresolved label fails
        // here as erts' "Could not resolve all labels" assertion.
        let mut code = std::mem::take(&mut self.a).finish()?;
        // `allocator->alloc(out, code.code_size() + 16)`.
        let mut memory = CodeMemory::new(code.code_size() + 16).map_err(|_| AsmError::AllocCode)?;
        let base = memory.as_ptr() as usize;
        // `code.relocate_to_base(executable)`, `code.copy_flattened_data(writable, ...)`.
        code.relocate(base as u64)?;
        let image = code.image()?;
        memory.write(0, &image).map_err(|_| AsmError::AllocCode)?;
        self.code = Some(code);
        self.base_address = Some(base);
        Ok(memory)
    }

    /// `getBaseAddress()`: the address the code was relocated to; `None` before codegen.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:78-81 (getBaseAddress), OTP-29.1.1.
    pub fn get_base_address(&self) -> Option<usize> {
        self.base_address
    }

    /// `getCode(Label)`: the executable address of a bound label after codegen.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:142-145 (getCode), OTP-29.1.1.
    pub fn get_code(&self, label: Label) -> Option<usize> {
        let code = self.code.as_ref()?;
        Some(self.base_address? + code.label_offset_from_base(label)?)
    }

    /// `code.label_offset_from_base(label)` after codegen.
    pub fn label_offset_from_base(&self, label: Label) -> Option<usize> {
        self.code.as_ref()?.label_offset_from_base(label)
    }

    /// `getOffset()`: `a.offset()`, the offset in the text section; after codegen the size
    /// of the text section.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:83-85 (getOffset), OTP-29.1.1.
    pub fn get_offset(&self) -> usize {
        match &self.code {
            Some(code) => code.code.len(),
            None => self.a.offset(),
        }
    }

    /// `code.code_size()` after codegen: the size of the whole image.
    pub fn code_size(&self) -> Option<usize> {
        self.code.as_ref().map(FinalizedCode::code_size)
    }

    /// `embed_zeros(size)`.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:185-197 (embed_zeros), OTP-29.1.1.
    pub fn embed_zeros(&mut self, size: usize) -> Result<(), AsmError> {
        self.a.embed(&vec![0; size])?;
        Ok(())
    }

    /// `a.new_label()`.
    pub fn new_label(&mut self) -> Label {
        self.a.new_label()
    }

    /// `a.bind(label)`.
    pub fn bind(&mut self, label: Label) -> Result<(), AsmError> {
        Ok(self.a.bind(label)?)
    }

    /// `load_x_reg_array(reg)`: `registers` points at `x_reg_array` by definition.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:287-290 (load_x_reg_array), OTP-29.1.1.
    pub fn load_x_reg_array(&mut self, reg: Gp) -> Result<(), AsmError> {
        self.emit(|e| e.mov_rr(reg, REGISTERS))
    }

    /// `load_erl_bits_state(reg)`: the address of `aux_regs.d.erl_bits_state`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:292-297 (load_erl_bits_state),
    // OTP-29.1.1.
    pub fn load_erl_bits_state(&mut self, reg: Gp) -> Result<(), AsmError> {
        let offset = core::mem::offset_of!(SchedulerRegisters, erl_bits_state);
        self.emit(|e| e.lea(reg, get_scheduler_reg_ref(offset, 8)))
    }

    /// `emit_enter_frame()`. Under the `RA` layout ([`FRAME_LAYOUT`]) an Erlang frame is only
    /// its return address, pushed by the `call`, so nothing is emitted.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:669-680 (emit_enter_frame), OTP-29.1.1.
    pub fn emit_enter_frame(&mut self) -> Result<(), AsmError> {
        const { assert!(matches!(FRAME_LAYOUT, FrameLayout::Ra)) };
        Ok(())
    }

    /// `emit_leave_frame()`: nothing under the `RA` layout, see [`Self::emit_enter_frame`].
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:682-690 (emit_leave_frame), OTP-29.1.1.
    pub fn emit_leave_frame(&mut self) -> Result<(), AsmError> {
        const { assert!(matches!(FRAME_LAYOUT, FrameLayout::Ra)) };
        Ok(())
    }

    /// `emit_unwind_frame()`: leaves the frame and drops its return address.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:692-697 (emit_unwind_frame), OTP-29.1.1.
    pub fn emit_unwind_frame(&mut self) -> Result<(), AsmError> {
        self.emit_leave_frame()?;
        self.emit(|e| e.add_ri(enc::RSP, 8))
    }

    /// `emit_test(Src, mask)`: the shortest `test` of the low byte(s) of `src`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:870-879 (emit_test), OTP-29.1.1.
    pub fn emit_test(&mut self, src: Gp, mask: u8) -> Result<(), AsmError> {
        let src = src.r64();
        if src == enc::RAX
            || src == enc::RDI
            || src == enc::RSI
            || src == enc::RCX
            || src == enc::RDX
        {
            self.emit(|e| e.test_ri(src.r8(), i64::from(mask)))
        } else {
            self.emit(|e| e.test_ri(src.r32(), i64::from(mask)))
        }
    }

    /// `emit_test_cons(Src)`: ZF is set when `src` is a list cell.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:881-883 (emit_test_cons), OTP-29.1.1.
    pub fn emit_test_cons(&mut self, src: Gp) -> Result<(), AsmError> {
        self.emit_test(src, TAG_PRIMARY_MASK - TAG_PRIMARY_LIST)
    }

    /// `emit_test_boxed(Src)`: ZF is set when `src` is boxed.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:903-905 (emit_test_boxed), OTP-29.1.1.
    pub fn emit_test_boxed(&mut self, src: Gp) -> Result<(), AsmError> {
        self.emit_test(src, TAG_PRIMARY_MASK - TAG_PRIMARY_BOXED)
    }

    /// `emit_ptr_val(Dst, Src)`. x86-64 Linux reserves physical memory for literals
    /// (`ERTS_HAVE_OS_PHYSICAL_MEMORY_RESERVATION`), so a release build has no
    /// `TAG_LITERAL_PTR` and the pointer is `src` itself.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:925-942 (emit_ptr_val) and
    // erts/emulator/beam/erl_term.h:55-61 (TAG_LITERAL_PTR), OTP-29.1.1.
    pub fn emit_ptr_val(&mut self, _dst: Gp, src: Gp) -> Gp {
        src
    }

    /// `emit_test_the_non_value(Reg)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:951-957 (emit_test_the_non_value),
    // OTP-29.1.1.
    pub fn emit_test_the_non_value(&mut self, reg: Gp) -> Result<(), AsmError> {
        const { assert!(THE_NON_VALUE == 0) };
        self.emit(|e| e.test_rr(reg.r32(), reg.r32()))
    }

    /// `mov_imm(to, value)`: the shortest instruction setting `to`; may clear flags.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:963-995 (mov_imm), OTP-29.1.1.
    pub fn mov_imm(&mut self, to: Gp, value: u64) -> Result<(), AsmError> {
        if value != 0 {
            if u32::try_from(value).is_ok() {
                self.emit(|e| e.mov_ri(to.r32(), value as i64))
            } else {
                self.emit(|e| e.mov_ri(to, value as i64))
            }
        } else {
            self.emit(|e| e.xor_rr(to.r32(), to.r32()))
        }
    }

    /// `emit_setup_dispatchable_call(Src, CodeIndex)`: moves the `Export`/`ErlFunEntry` into
    /// `RET` (where the export trampoline, save_calls and tracing fragments expect it) and
    /// returns its dispatch address for `CodeIndex`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:578-595 (emit_setup_dispatchable_call),
    // OTP-29.1.1.
    pub fn emit_setup_dispatchable_call(
        &mut self,
        src: Gp,
        code_index: Gp,
    ) -> Result<Mem, AsmError> {
        if RET != src {
            self.emit(|e| e.mov_rr(RET, src))?;
        }
        // `dispatch` is the first field of both Export and ErlFunEntry, and
        // `ErtsDispatchable.addresses` is its first field.
        const {
            assert!(core::mem::offset_of!(arinsal_term::ExportEntry, dispatch) == 0);
        }
        Ok(Mem::base_index(RET, code_index, 3, 0, 8))
    }

    /// `emit_setup_dispatchable_call(Src)` with the local `active_code_ix`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:578-580, OTP-29.1.1.
    pub fn emit_setup_dispatchable_call_active(&mut self, src: Gp) -> Result<Mem, AsmError> {
        self.emit_setup_dispatchable_call(src, ACTIVE_CODE_IX)
    }

    /// `a.jmp(label)`: asmjit encodes a jump to a bound label within rel8 reach as
    /// `jmp rel8` and every other label jump as `jmp rel32`.
    // Port of erts/emulator/asmjit/x86/x86assembler.cpp (kEncodingX86Jmp, label target),
    // OTP-29.1.1.
    pub fn jmp(&mut self, label: Label) -> Result<(), AsmError> {
        Ok(self.a.jmp(label)?)
    }

    /// `a.short_().jmp(label)`.
    pub fn short_jmp(&mut self, label: Label) -> Result<(), AsmError> {
        Ok(self.a.jmp_short(label)?)
    }

    /// `a.j<cc>(label)`: `jcc rel8` to a bound label within reach, `jcc rel32` otherwise.
    // Port of erts/emulator/asmjit/x86/x86assembler.cpp (kEncodingX86Jcc, label target),
    // OTP-29.1.1.
    pub fn jcc(&mut self, cc: CondCode, label: Label) -> Result<(), AsmError> {
        Ok(self.a.jcc(cc as u8, label)?)
    }

    /// `a.short_().j<cc>(label)`.
    pub fn short_jcc(&mut self, cc: CondCode, label: Label) -> Result<(), AsmError> {
        Ok(self.a.jcc_short(cc as u8, label)?)
    }

    /// `j<cc>` with the reach a tag test asks for (`dShort` / `dLong`).
    pub fn jcc_dist(&mut self, cc: CondCode, label: Label, dist: Distance) -> Result<(), AsmError> {
        match dist {
            Distance::Short => self.short_jcc(cc, label),
            Distance::Long => self.jcc(cc, label),
        }
    }

    /// `hasCpuFeature(feature)`: the host CPU features asmjit's `CpuInfo` reports.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp (BeamAssemblerCommon::hasCpuFeature),
    // OTP-29.1.1.
    pub fn has_cpu_feature(feature: CpuFeature) -> bool {
        use arinsal_x64::enc::cpu;
        match feature {
            CpuFeature::Avx => cpu::has_avx(),
            CpuFeature::Avx2 => cpu::has_avx2(),
            CpuFeature::Bmi1 => cpu::has_bmi1(),
            CpuFeature::Bmi2 => cpu::has_bmi2(),
            CpuFeature::Lzcnt => cpu::has_lzcnt(),
            CpuFeature::Popcnt => cpu::has_popcnt(),
            CpuFeature::Movbe => cpu::has_movbe(),
            CpuFeature::Avx512Vl => cpu::has_avx512vl(),
            CpuFeature::Avx512F => cpu::has_avx512f(),
            CpuFeature::Sse => true,
        }
    }

    /// `a.align(AlignMode::kCode, alignment)`: asmjit's optimized NOP fill up to the next
    /// multiple of `alignment` of the section offset.
    pub fn align_code(&mut self, alignment: u32) -> Result<(), AsmError> {
        Ok(self.a.align(alignment as usize)?)
    }

    /// `align_erlang_cp()`: aligns so that the current address forms a valid CP.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:280-285 (align_erlang_cp), OTP-29.1.1.
    pub fn align_erlang_cp(&mut self) -> Result<(), AsmError> {
        self.align_code(4)
    }

    /// `vmovups(dst, src)` to memory: `vmovups` with AVX, `movups` otherwise.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1002-1009 (vmovups), OTP-29.1.1.
    pub fn vmovups_mx(&mut self, dst: Mem, src: enc::Xmm) -> Result<(), AsmError> {
        if Self::has_cpu_feature(CpuFeature::Avx) {
            self.emit(|e| e.vmovups_mx(dst, src))
        } else {
            self.emit(|e| e.movups_mx(dst, src))
        }
    }

    /// `vmovups(dst, src)` from memory.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1002-1009 (vmovups), OTP-29.1.1.
    pub fn vmovups_xm(&mut self, dst: enc::Xmm, src: Mem) -> Result<(), AsmError> {
        if Self::has_cpu_feature(CpuFeature::Avx) {
            self.emit(|e| e.vmovups_xm(dst, src))
        } else {
            self.emit(|e| e.movups_xm(dst, src))
        }
    }

    /// `emit_enter_runtime<Spec>()` for the `RA` frame layout with `NATIVE_ERLANG_STACK`:
    /// publishes what `Spec` names and switches to the runtime stack.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:699-816 (emit_enter_runtime),
    // OTP-29.1.1.
    pub fn emit_enter_runtime(&mut self, spec: Update) -> Result<(), AsmError> {
        const { assert!(matches!(FRAME_LAYOUT, FrameLayout::Ra)) };
        assert!(!spec.contains(Update::CODE_INDEX));
        let avx = Self::has_cpu_feature(CpuFeature::Avx);
        let (xmm0, xmm1) = (enc::Xmm(0), enc::Xmm(1));
        if spec.contains(Update::HEAP_ALLOC) {
            // Both heap and stack with one 16-byte store, as gcc -O3 does.
            let htop_stop = enc::xmmword_ptr(C_P, process::HTOP);
            if avx {
                self.emit(|e| e.vmovq_xr(xmm1, HTOP))?;
                self.emit(|e| e.vpinsrq_xxri(xmm0, xmm1, E, 1))?;
                self.emit(|e| e.vmovdqu_mx(htop_stop, xmm0))?;
            } else {
                self.emit(|e| e.movq_xr(xmm0, HTOP))?;
                self.emit(|e| e.movq_xr(xmm1, E))?;
                self.emit(|e| e.punpcklqdq_xx(xmm0, xmm1))?;
                self.emit(|e| e.movups_mx(htop_stop, xmm0))?;
            }
        } else {
            if spec.contains(Update::HEAP) {
                self.emit(|e| e.mov_mr(process_ref(process::HTOP, 8), HTOP))?;
            }
            if spec.contains(Update::STACK) {
                self.emit(|e| e.mov_mr(process_ref(process::STOP, 8), E))?;
            }
        }
        if !spec.contains(Update::STACK) {
            self.emit(|e| e.mov_rr(E_SAVED, E))?;
        }
        if spec.contains(Update::REDUCTIONS) {
            self.emit(|e| e.mov_mr(process_ref(process::FCALLS, 4), FCALLS))?;
        }
        self.emit(|e| e.lea(E, get_runtime_stack_ref()))?;
        // The emulator is not built with AVX, so clear the upper halves to avoid AVX/SSE
        // transition penalties.
        if avx {
            self.emit(|e| e.vzeroupper())?;
        }
        Ok(())
    }

    /// `aligned_call(target, size)`: pads with erts' canned NOPs so the return address of the
    /// `size`-byte call that follows forms a valid CP (4-byte aligned).
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:417-439 (aligned_call(target, size)) and
    // jit/x86/process_main.cpp:33-36 (nops), OTP-29.1.1.
    fn pad_for_call(&mut self, size: usize) -> Result<(), AsmError> {
        const NOPS: [&[u8]; 3] = [&[0x90], &[0x66, 0x90], &[0x0F, 0x1F, 0x00]];
        let next_address = self.a.offset() + size;
        if !next_address.is_multiple_of(4) {
            let nop_count = 4 - next_address % 4;
            self.a.embed(NOPS[nop_count - 1])?;
        }
        Ok(())
    }

    /// `aligned_call(Label)`: relative calls are always 5 bytes long.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:395-398, OTP-29.1.1.
    pub fn aligned_call_label(&mut self, target: Label) -> Result<(), AsmError> {
        self.pad_for_call(5)?;
        self.a.call(target)?;
        debug_assert!(self.a.offset().is_multiple_of(4));
        Ok(())
    }

    /// `aligned_call(OperandType)` for a register or memory target: measures the call, then
    /// pads and emits it.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:400-415, OTP-29.1.1.
    pub fn aligned_call_with(
        &mut self,
        call: impl Fn(&mut Emitter) -> Result<(), EncodeError>,
    ) -> Result<(), AsmError> {
        let mut probe = Emitter::new();
        call(&mut probe)?;
        self.pad_for_call(probe.len())?;
        self.emit(call)?;
        debug_assert!(self.a.offset().is_multiple_of(4));
        Ok(())
    }

    /// `fragment_call(Label)`: calls a shared fragment with a return address that is a CP.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:355-370 (fragment_call), OTP-29.1.1.
    pub fn fragment_call(&mut self, target: Label) -> Result<(), AsmError> {
        self.emit_assert_redzone_unused();
        self.aligned_call_label(target)
    }

    /// `fragment_call(FuncPtr)`: a fragment called by its absolute address (the module
    /// assembler's `fragment_call(ga->get_x())`, which `BeamAssembler::fragment_call` resolves
    /// to `aligned_call(FuncPtr *)`).
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:355-370 (fragment_call) and 388-393
    // (aligned_call(FuncPtr *)), OTP-29.1.1.
    pub fn fragment_call_abs(&mut self, target: usize) -> Result<(), AsmError> {
        self.emit_assert_redzone_unused();
        self.aligned_call_abs(target)
    }

    /// `erlang_call(Label, spill)`: with `NATIVE_ERLANG_STACK` an Erlang call is a native
    /// `call` whose return address is the CP.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:327-348 (erlang_call), OTP-29.1.1.
    pub fn erlang_call(&mut self, target: Label) -> Result<(), AsmError> {
        self.emit_assert_redzone_unused();
        self.aligned_call_label(target)
    }

    /// `erlang_call(Mem, spill)`, e.g. through `emit_setup_dispatchable_call`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:327-348 (erlang_call), OTP-29.1.1.
    pub fn erlang_call_m(&mut self, target: Mem) -> Result<(), AsmError> {
        self.emit_assert_redzone_unused();
        self.aligned_call_with(|e| e.call_m(target))
    }

    /// `runtime_call<Sig, Func>()` on the SysV ABI: `call imm(Func)`, which asmjit encodes
    /// as a 6-byte `REX call rel32`, relocated to a rel32 or to an address-table call. `func`
    /// is the address of an erts-named runtime function (`x86::rt`), taken with `f as usize`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:488-530 (runtime_call), OTP-29.1.1.
    pub fn runtime_call(&mut self, func: usize) -> Result<(), AsmError> {
        self.emit_assert_runtime_stack();
        self.a.call_external(func as u64)?;
        Ok(())
    }

    /// `dynamic_runtime_call<Arity>(func)`: a call through a register.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:532-546 (dynamic_runtime_call),
    // OTP-29.1.1.
    pub fn dynamic_runtime_call(&mut self, func: Gp) -> Result<(), AsmError> {
        self.emit_assert_runtime_stack();
        self.emit(|e| e.call_r(func))
    }

    /// `abs_jmp(addr)`: `jmp imm(addr)`, a 6-byte `REX jmp rel32` relocated like a runtime
    /// call.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:548-551 (abs_jmp), OTP-29.1.1.
    pub fn abs_jmp(&mut self, addr: usize) -> Result<(), AsmError> {
        self.a.jmp_external(addr as u64)?;
        Ok(())
    }

    /// `safe_fragment_call(Target)` of the global assembler: `call imm(Target)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:383-386 (safe_fragment_call),
    // OTP-29.1.1.
    pub fn safe_fragment_call_abs(&mut self, target: usize) -> Result<(), AsmError> {
        self.emit_assert_redzone_unused();
        self.a.call_external(target as u64)?;
        Ok(())
    }

    /// `aligned_call(FuncPtr *target)`: calls to absolute addresses (encoded through the
    /// address table) are always 6 bytes long.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:388-393, OTP-29.1.1.
    pub fn aligned_call_abs(&mut self, target: usize) -> Result<(), AsmError> {
        self.pad_for_call(6)?;
        self.a.call_external(target as u64)?;
        debug_assert!(self.a.offset().is_multiple_of(4));
        Ok(())
    }

    /// `emit_assert_runtime_stack()`: emits nothing outside `JIT_HARD_DEBUG`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp (emit_assert_runtime_stack), OTP-29.1.1.
    pub fn emit_assert_runtime_stack(&mut self) {}

    /// `emit_assert_redzone_unused()`: emits nothing outside `JIT_HARD_DEBUG`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:302-322, OTP-29.1.1.
    pub fn emit_assert_redzone_unused(&mut self) {}

    /// `pic_jmp(addr)`: a position-independent absolute jump through `ARG6`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:553-559 (pic_jmp), OTP-29.1.1.
    pub fn pic_jmp(&mut self, address: usize) -> Result<(), AsmError> {
        self.emit(|e| e.mov_ri(ARG6, address as i64))?;
        self.emit(|e| e.jmp_r(ARG6))
    }

    /// `emit_leave_runtime<Spec>()` for the `RA` frame layout with `NATIVE_ERLANG_STACK`:
    /// back to the Erlang stack and reload what `Spec` names.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:818-868 (emit_leave_runtime),
    // OTP-29.1.1.
    pub fn emit_leave_runtime(&mut self, spec: Update) -> Result<(), AsmError> {
        const { assert!(matches!(FRAME_LAYOUT, FrameLayout::Ra)) };
        if spec.contains(Update::STACK) {
            self.emit(|e| e.mov_rm(E, process_ref(process::STOP, 8)))?;
        } else {
            self.emit(|e| e.mov_rr(E, E_SAVED))?;
        }
        if spec.contains(Update::HEAP) {
            self.emit(|e| e.mov_rm(HTOP, process_ref(process::HTOP, 8)))?;
        }
        if spec.contains(Update::REDUCTIONS) {
            self.emit(|e| e.mov_rm(FCALLS, process_ref(process::FCALLS, 4)))?;
        }
        if spec.contains(Update::CODE_INDEX) {
            // Updates the local copy of the active code index, retaining save_calls.
            let active = &raw const super::rt::the_active_code_index as i64;
            self.emit(|e| e.mov_ri(ARG1, active))?;
            self.emit(|e| e.mov_rm(ARG1D, enc::dword_ptr(ARG1, 0)))?;
            self.emit(|e| e.cmp_ri(ACTIVE_CODE_IX, ERTS_SAVE_CALLS_CODE_IX as i64))?;
            self.emit(|e| e.cmovcc_rr(CondCode::NE, ACTIVE_CODE_IX, ARG1))?;
        }
        Ok(())
    }

    /// `emit_is_cons(Fail, Src, dist)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:885-892 (emit_is_cons), OTP-29.1.1.
    pub fn emit_is_cons(&mut self, fail: Label, src: Gp, dist: Distance) -> Result<(), AsmError> {
        self.emit_test_cons(src)?;
        self.jcc_dist(CondCode::NE, fail, dist)
    }

    /// `emit_is_not_cons(Fail, Src, dist)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:894-901 (emit_is_not_cons), OTP-29.1.1.
    pub fn emit_is_not_cons(
        &mut self,
        fail: Label,
        src: Gp,
        dist: Distance,
    ) -> Result<(), AsmError> {
        self.emit_test_cons(src)?;
        self.jcc_dist(CondCode::E, fail, dist)
    }

    /// `emit_is_boxed(Fail, Src, dist)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:907-914 (emit_is_boxed), OTP-29.1.1.
    pub fn emit_is_boxed(&mut self, fail: Label, src: Gp, dist: Distance) -> Result<(), AsmError> {
        self.emit_test_boxed(src)?;
        self.jcc_dist(CondCode::NE, fail, dist)
    }

    /// `emit_is_not_boxed(Fail, Src, dist)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:916-923 (emit_is_not_boxed), OTP-29.1.1.
    pub fn emit_is_not_boxed(
        &mut self,
        fail: Label,
        src: Gp,
        dist: Distance,
    ) -> Result<(), AsmError> {
        self.emit_test_boxed(src)?;
        self.jcc_dist(CondCode::E, fail, dist)
    }
}

/// The CPU features erts' x86 emitters test (`CpuFeatures::X86::k*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuFeature {
    /// `kAVX`.
    Avx,
    /// `kAVX2`.
    Avx2,
    /// `kBMI`.
    Bmi1,
    /// `kBMI2`.
    Bmi2,
    /// `kLZCNT`.
    Lzcnt,
    /// `kPOPCNT`.
    Popcnt,
    /// `kMOVBE`.
    Movbe,
    /// `kAVX512_VL`, used by `emit_copy_words`.
    Avx512Vl,
    /// `kAVX512_F`, used by `emit_copy_words`.
    Avx512F,
    /// `kSSE`, the x86-64 baseline feature.
    Sse,
}

/// `ERTS_SAVE_CALLS_CODE_IX`.
// Port of erts/emulator/beam/code_ix.h:72-95, OTP-29.1.1.
pub const ERTS_SAVE_CALLS_CODE_IX: u32 = arinsal_term::ERTS_SAVE_CALLS_CODE_IX as u32;

// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1032-1110 (emit_copy_words), OTP-29.1.1.
impl BeamAssembler {
    /// Copies words through erts' ordered vector feature choices, then its scalar tail.
    pub fn emit_copy_words(
        &mut self,
        mut from: Mem,
        mut to: Mem,
        mut count: i32,
        spill: Gp,
    ) -> Result<(), AsmError> {
        debug_assert!(from.index.is_none() && to.index.is_none());
        debug_assert!((0..(i32::MAX / 8)).contains(&count));
        debug_assert!(from.disp < i32::MAX - count * 8);
        debug_assert!(to.disp < i32::MAX - count * 8);

        from = from.with_size(0);
        to = to.with_size(0);

        // erts checks every row in this order; a narrower supported row copies any remainder.
        const VECTORS: [(CpuFeature, i32, bool); 5] = [
            (CpuFeature::Avx512Vl, 8, true),
            (CpuFeature::Avx512F, 8, true),
            (CpuFeature::Avx, 4, true),
            (CpuFeature::Avx, 2, true),
            (CpuFeature::Sse, 2, false),
        ];

        for (feature, vector_words, use_vmovups) in VECTORS {
            if !Self::has_cpu_feature(feature) {
                continue;
            }

            if count <= vector_words * 4 {
                while count >= vector_words {
                    self.emit_copy_words_vector(from, to, vector_words, use_vmovups)?;
                    let offset = vector_words * 8;
                    from = from.adjusted(offset);
                    to = to.adjusted(offset);
                    count -= vector_words;
                }
            } else {
                let loop_iterations = count / vector_words;
                let loop_size = loop_iterations * vector_words * 8;
                from = from.adjusted(loop_size);
                to = to.adjusted(loop_size);
                from.index = Some(spill.r64());
                to.index = Some(spill.r64());

                self.mov_imm(spill, (-i64::from(loop_size)) as u64)?;
                let copy_next = self.new_label();
                self.bind(copy_next)?;
                self.emit_copy_words_vector(from, to, vector_words, use_vmovups)?;
                self.emit(|e| e.add_ri(spill, i64::from(vector_words * 8)))?;
                self.short_jcc(CondCode::NE, copy_next)?;

                from.index = None;
                to.index = None;
                count %= vector_words;
            }
        }

        if count == 1 {
            self.emit(|e| e.mov_rm(spill, from))?;
            self.emit(|e| e.mov_mr(to, spill))?;
            count -= 1;
        }

        debug_assert_eq!(count, 0);
        Ok(())
    }

    fn emit_copy_words_vector(
        &mut self,
        from: Mem,
        to: Mem,
        vector_words: i32,
        use_vmovups: bool,
    ) -> Result<(), AsmError> {
        match (vector_words, use_vmovups) {
            (8, true) => {
                self.emit(|e| e.vmovups_zm(enc::Zmm(0), from))?;
                self.emit(|e| e.vmovups_mz(to, enc::Zmm(0)))?;
            }
            (4, true) => {
                self.emit(|e| e.vmovups_ym(enc::Ymm(0), from))?;
                self.emit(|e| e.vmovups_my(to, enc::Ymm(0)))?;
            }
            (2, true) => {
                self.emit(|e| e.vmovups_xm(enc::Xmm(0), from))?;
                self.emit(|e| e.vmovups_mx(to, enc::Xmm(0)))?;
            }
            (2, false) => {
                self.emit(|e| e.movups_xm(enc::Xmm(0), from))?;
                self.emit(|e| e.movups_mx(to, enc::Xmm(0)))?;
            }
            _ => unreachable!("emit_copy_words vector specification"),
        }
        Ok(())
    }
}

// Port of erts/emulator/beam/jit/beam_jit_main.cpp:291-305 (beamasm_init), OTP-29.1.1: the
// commonly used process fields must be reachable with an 8-bit displacement from `c_p`.
const _: () = {
    assert!(core::mem::offset_of!(ProcessHeader, htop) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, stop) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, fcalls) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, exc.freason) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, exc.fvalue) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, flags) < 128);
    // jit/x86/beam_asm.hpp:719-720 (emit_enter_runtime): `htop` and `stop` are stored together
    // with one 16-byte vector store.
    assert!(
        core::mem::offset_of!(ProcessHeader, stop) - core::mem::offset_of!(ProcessHeader, htop)
            == 8
    );
    // `registers` points at x_reg_array; the auxiliary registers before it take 8-bit
    // displacements (getSchedulerRegRef's ERTS_CT_ASSERT(x_reg_offset <= 128)).
    assert!(x_ref_disp(0) == 0);
    assert!(f_ref_disp(0) == 8192);
    assert!(tmp_mem_q_disp(4) >= -128 && tmp_mem_q_disp(4) < 0);
    assert!(RUNTIME_STACK_DISP >= -128);
};

#[cfg(test)]
mod tests {
    use super::register::*;
    use super::*;

    fn bytes(f: impl FnOnce(&mut BeamAssembler) -> Result<(), AsmError>) -> Vec<u8> {
        let mut asm = BeamAssembler::new();
        f(&mut asm).unwrap();
        asm.a.bytes(arinsal_x64::buf::Section::Code).to_vec()
    }

    #[test]
    fn pinned_registers_match_erts() {
        assert_eq!(REGISTERS, enc::RBX);
        assert_eq!(E, enc::RSP);
        assert_eq!(C_P, enc::R13);
        assert_eq!(FCALLS, enc::R14D);
        assert_eq!(HTOP, enc::R15);
        assert_eq!(ACTIVE_CODE_IX, enc::R12);
        assert_eq!(RET, enc::RAX);
    }

    #[cfg(not(windows))]
    #[test]
    fn sysv_argument_registers() {
        assert_eq!(
            ARG,
            [enc::RDI, enc::RSI, enc::RDX, enc::RCX, enc::R8, enc::R9]
        );
        assert_eq!(TMP, [enc::R10, enc::R11]);
        assert_eq!(ARG4D, enc::ECX);
    }

    #[test]
    fn update_sets() {
        assert!(Update::HEAP_ALLOC.contains(Update::STACK));
        assert!(Update::HEAP_ALLOC.contains(Update::HEAP));
        assert!(!Update::HEAP_ALLOC.contains(Update::REDUCTIONS));
        assert_eq!(Update::HEAP_ONLY_ALLOC, Update::HEAP);
    }

    #[test]
    fn stack_and_register_displacements() {
        assert_eq!(x_ref_disp(1023), 1023 * 8);
        assert_eq!(f_ref_disp(1), 8200);
        assert_eq!(tmp_mem_q_disp(4), -120 + 32);
        assert_eq!(y_ref_disp(3), 24);
        assert_eq!(get_runtime_stack_ref(), Mem::base_disp(enc::RBX, -128, 8));
        assert_eq!(get_y_ref(2, 8), Mem::base_disp(enc::RSP, 16, 8));
        assert_eq!(get_car_ref(enc::RAX, 8).disp, -1);
        assert_eq!(get_cdr_ref(enc::RAX, 8).disp, 7);
        assert_eq!(emit_boxed_val(enc::RAX, 8, 8).disp, 6);
        assert_eq!(tmp_mem_d(0).size, 4);
        assert_eq!(get_arg_ref(ArgVal::X(2), 8), Some(get_x_ref(2, 8)));
        assert_eq!(get_arg_ref(ArgVal::Label(2), 8), None);
    }

    // Expected bytes are the encodings of the instructions erts 29.1.1 emits for the same
    // calls (`erl +JDdump true` text, e.g. `mov rdx, rbx` in global::garbage_collect).
    #[test]
    fn helpers_emit_erts_sequences() {
        // load_x_reg_array(ARG3): mov rdx, rbx
        assert_eq!(bytes(|a| a.load_x_reg_array(ARG3)), [0x48, 0x89, 0xda]);
        // load_erl_bits_state(ARG1): lea rdi, [rbx-56]
        assert_eq!(
            bytes(|a| a.load_erl_bits_state(ARG1)),
            [0x48, 0x8d, 0x7b, 0xc8]
        );
        // emit_unwind_frame(): add rsp, 8
        assert_eq!(bytes(|a| a.emit_unwind_frame()), [0x48, 0x83, 0xc4, 0x08]);
        // emit_test_boxed(ARG1): test dil, 1
        assert_eq!(bytes(|a| a.emit_test_boxed(ARG1)), [0x40, 0xf6, 0xc7, 0x01]);
        // emit_test_cons(TMP1): test r10d, 2
        assert_eq!(
            bytes(|a| a.emit_test_cons(TMP1)),
            [0x41, 0xf7, 0xc2, 0x02, 0, 0, 0]
        );
        // emit_test_the_non_value(RET): test eax, eax
        assert_eq!(bytes(|a| a.emit_test_the_non_value(RET)), [0x85, 0xc0]);
        // mov_imm(ARG4, 0): xor ecx, ecx; mov_imm(ARG4, 15): mov ecx, 15
        assert_eq!(bytes(|a| a.mov_imm(ARG4, 0)), [0x31, 0xc9]);
        assert_eq!(bytes(|a| a.mov_imm(ARG4, 15)), [0xb9, 15, 0, 0, 0]);
        // mov_imm(ARG1, 1 << 40): movabs rdi, 0x10000000000
        assert_eq!(
            bytes(|a| a.mov_imm(ARG1, 1 << 40)),
            [0x48, 0xbf, 0, 0, 0, 0, 0, 1, 0, 0]
        );
        // emit_setup_dispatchable_call(ARG2) then `mov rdi, [rax + r12*8]`.
        assert_eq!(
            bytes(|a| {
                let target = a.emit_setup_dispatchable_call_active(ARG2)?;
                a.emit(|e| e.mov_rm(ARG1, target))
            }),
            [0x48, 0x89, 0xf0, 0x4a, 0x8b, 0x3c, 0xe0]
        );
    }

    fn as_bytes(lines: &[&str]) -> Option<Vec<u8>> {
        let lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        crate::x86::jdump::gnu_as(&lines)
    }

    #[test]
    fn leave_runtime_matches_erts_sequences() {
        let ours = bytes(|a| a.emit_leave_runtime(Update::HEAP_ALLOC.union(Update::REDUCTIONS)));
        let expected = as_bytes(&[
            &format!("mov rsp, qword ptr [r13+{}]", process::STOP),
            &format!("mov r15, qword ptr [r13+{}]", process::HTOP),
            &format!("mov r14d, dword ptr [r13+{}]", process::FCALLS),
        ]);
        if let Some(expected) = expected {
            assert_eq!(ours, expected);
        }
        // Without eStack, E comes back from E_saved.
        assert_eq!(
            bytes(|a| a.emit_leave_runtime(Update::NONE)),
            [0x48, 0x89, 0xec]
        );
        let active = &raw const crate::x86::rt::the_active_code_index as u64;
        let ours = bytes(|a| a.emit_leave_runtime(Update::CODE_INDEX));
        let mov = if active <= u64::from(u32::MAX) {
            format!("mov edi, {active}")
        } else {
            format!("movabs rdi, {active}")
        };
        let expected = as_bytes(&[
            "mov rsp, rbp",
            &mov,
            "mov edi, dword ptr [rdi]",
            &format!("cmp r12, {ERTS_SAVE_CALLS_CODE_IX}"),
            "cmovne r12, rdi",
        ]);
        if let Some(expected) = expected {
            assert_eq!(ours, expected);
        }
    }

    #[test]
    fn label_jumps_follow_asmjit_reach() {
        let mut asm = BeamAssembler::new();
        let back = asm.new_label();
        let forward = asm.new_label();
        asm.bind(back).unwrap();
        asm.jcc(CondCode::NE, back).unwrap(); // bound, in reach: rel8
        asm.jcc(CondCode::NE, forward).unwrap(); // unbound: rel32
        asm.jmp(back).unwrap(); // rel8
        asm.a.embed(&[0x90; 200]).unwrap();
        asm.jmp(back).unwrap(); // out of rel8 reach: rel32
        asm.bind(forward).unwrap();
        let code = asm.a.bytes(arinsal_x64::buf::Section::Code).to_vec();
        assert_eq!(&code[..2], &[0x75, 0xfe]);
        assert_eq!(&code[2..4], &[0x0f, 0x85]);
        assert_eq!(&code[8..10], &[0xeb, 0xf6]);
        assert_eq!(code[210], 0xe9);
        assert_eq!(code.len(), 215);
    }

    #[test]
    fn aligned_calls_return_to_a_cp() {
        let mut asm = BeamAssembler::new();
        let target = asm.new_label();
        asm.a.embed(&[0x90]).unwrap();
        // 1 + 5 = 6: two NOP bytes (`66 90`) put the return address at 8.
        asm.aligned_call_label(target).unwrap();
        asm.bind(target).unwrap();
        // `call [rax + r12*8]` is 4 bytes: at 8 its end is already 4-byte aligned, no padding.
        asm.aligned_call_with(|e| e.call_m(Mem::base_index(enc::RAX, enc::R12, 3, 0, 8)))
            .unwrap();
        let code = asm.a.bytes(arinsal_x64::buf::Section::Code).to_vec();
        assert_eq!(&code[1..4], &[0x66, 0x90, 0xe8]);
        assert_eq!(code.len(), 12);
    }

    // erts' emit_enter_runtime<eHeapAlloc | eReductions> opens global::process_exit and
    // <eStack | eHeap> sits in global::garbage_collect after its prologue.
    #[test]
    fn enter_runtime_matches_erts_dump() {
        let Some(dump) = crate::x86::jdump::erts_dump("beam_asm_global") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let fragment = |name: &str, skip: usize, take: usize| -> Vec<String> {
            dump.lines()
                .skip_while(|l| l.trim() != format!("global::{name}:"))
                .skip(1 + skip)
                .take(take)
                .map(|l| crate::x86::jdump::erts_to_arinsal(l.trim()))
                .collect()
        };
        let cases = [
            (
                Update::HEAP_ALLOC.union(Update::REDUCTIONS),
                fragment("process_exit", 0, 6),
            ),
            (Update::HEAP_ALLOC, fragment("garbage_collect", 5, 5)),
        ];
        for (spec, lines) in cases {
            let Some(expected) = crate::x86::jdump::gnu_as(&lines) else {
                return;
            };
            assert_eq!(bytes(|a| a.emit_enter_runtime(spec)), expected, "{lines:?}");
        }
    }
}
