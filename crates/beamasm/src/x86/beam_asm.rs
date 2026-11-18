//! Port of erts/emulator/beam/jit/x86/beam_asm.hpp (`struct BeamAssembler`: register
//! assignments, C ABI argument registers, `Update`, scheduler register and Erlang stack
//! addressing, frame transitions, tag tests) and the frame layout selection and layout checks
//! of erts/emulator/beam/jit/beam_jit_main.cpp (beamasm_init), OTP-29.1.1.
//!
//! [`BeamAssembler`] is the base both [`super::beam_asm_global::BeamGlobalAssembler`] and
//! [`super::beam_asm_module::BeamModuleAssembler`] build on, as in erts. Its `a` is the asmjit
//! `x86::Assembler` attached to the assembler's `CodeHolder`: here the `arinsal_x64`
//! [`CodeBuffer`], whose instructions are encoded by [`Emitter`] one asmjit call at a time.

use arinsal_x64::buf::{BufferError, CodeBuffer, Label};
use arinsal_x64::enc::{self, Emitter, EncodeError, Gp, Mem};

use crate::common::args::ArgVal;
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

use register::{ACTIVE_CODE_IX, C_P, E, REGISTERS, RET};

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
        ArgVal::X(index) => Some(get_x_ref(index, size)),
        ArgVal::Y(index) => Some(get_y_ref(index, size)),
        _ => None,
    }
}

/// `emit_boxed_val(Src, bytes, size)`: the word at `bytes` into the boxed object `src`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:944-949 (emit_boxed_val), OTP-29.1.1.
pub const fn emit_boxed_val(src: Gp, bytes: i32, size: u8) -> Mem {
    assert!(bytes % 8 == 0);
    Mem::base_disp(src, bytes - TAG_PRIMARY_BOXED as i32, size)
}

/// `offsetof(Process, field)` of the fields x86 native code addresses through `c_p`.
// Port of erts/emulator/beam/erl_process.h (struct process), OTP-29.1.1: Arinsal's
// `ProcessHeader` is the native prefix of the process.
pub mod process {
    use crate::ProcessHeader;
    use core::mem::offset_of;

    /// `offsetof(Process, htop)`.
    pub const HTOP: i32 = offset_of!(ProcessHeader, htop) as i32;
    /// `offsetof(Process, stop)`.
    pub const STOP: i32 = offset_of!(ProcessHeader, stop) as i32;
    /// `offsetof(Process, heap)`.
    pub const HEAP: i32 = offset_of!(ProcessHeader, heap) as i32;
    /// `offsetof(Process, hend)`.
    pub const HEND: i32 = offset_of!(ProcessHeader, hend) as i32;
    /// `offsetof(Process, fcalls)`.
    pub const FCALLS: i32 = offset_of!(ProcessHeader, fcalls) as i32;
    /// `offsetof(Process, freason)`.
    pub const FREASON: i32 = offset_of!(ProcessHeader, exc.freason) as i32;
    /// `offsetof(Process, fvalue)`.
    pub const FVALUE: i32 = offset_of!(ProcessHeader, exc.fvalue) as i32;
    /// `offsetof(Process, i)`.
    pub const I: i32 = offset_of!(ProcessHeader, i) as i32;
    /// `offsetof(Process, arity)`.
    pub const ARITY: i32 = offset_of!(ProcessHeader, arity) as i32;
    /// `offsetof(Process, current)`.
    pub const CURRENT: i32 = offset_of!(ProcessHeader, current) as i32;
    /// `offsetof(Process, flags)`.
    pub const FLAGS: i32 = offset_of!(ProcessHeader, flags) as i32;
}

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
        let mut e = Emitter::new();
        f(&mut e)?;
        self.a.append(&e.bytes);
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
}
