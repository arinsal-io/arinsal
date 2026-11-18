//! Audited native runtime transition core on x86-64: the C-to-Erlang entry bridge, its exit
//! fragment and the trace return addresses.
//!
//! Port of the process entry and exit of erts/emulator/beam/jit/x86/process_main.cpp
//! (emit_process_main: `schedule_next` hands a process to native code with
//! `emit_leave_runtime<eStack | eHeap>` and a jump to `c_p->i`; `context_switch*` /
//! `do_schedule` come back with `emit_enter_runtime<eStack | eHeap>`), OTP-29.1.1. erts runs
//! the scheduler loop on the runtime stack below `process_main`; here the Rust scheduler calls
//! the bridge once per slice, so the bridge is the native side of that loop.
//!
//! erts selects `NATIVE_ERLANG_STACK` on x86-64: `E` is `rsp`. Native code therefore leaves
//! the runtime (scheduler thread) stack on entry and returns to it before every runtime call;
//! the runtime stack position lives in `SchedulerRegisters::runtime_stack`, which the bridge
//! sets to its own frame.

use crate::{
    ACTIVE_CODE_IX_DISP, ENTRY_RETURN_DISP, ExitReason, ProcessHeader, RUNTIME_STACK_DISP,
    SchedulerRegisters, X_REG_ARRAY_OFFSET, tmp_mem_disp,
};
use core::ffi::c_void;

/// Per-call exit fragment result passed between the assembly bridge and Rust.
#[repr(C)]
#[derive(Default)]
struct NativeExit {
    kind: u64,
    target: usize,
    resume: usize,
}

/// Enters generated code by raw address through the process-wide pinned-register trampoline.
///
/// Native code returns to the exit fragment `arinsal_enter_native_return` (or jumps there
/// with `E` in `rsp`). A non-zero `tmp_mem[3]` marker is the exit kind: 2 hands the call at
/// `ARG2` (resume address `ARG3`) to the scheduler, any other non-zero value yields; zero is
/// a plain return.
///
/// # Safety
/// `code_ptr` must point into a live executable mapping at a function entry that follows the
/// x86-64 BeamAsm register contract (`register` in `beam_asm`) and leaves through the exit
/// fragment with `E` in `rsp`.
// Inlined so the scheduler's slice calls the trampoline directly, as on arm64.
#[inline(always)]
pub unsafe fn enter_native_raw(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    code_ptr: *const c_void,
) -> ExitReason {
    let mut exit = NativeExit::default();
    // SAFETY: The assembly bridge saves the System V callee-saved registers, loads the
    // documented ProcessHeader/SchedulerRegisters layout, switches to the Erlang stack, jumps to
    // code_ptr and comes back to this frame on the runtime stack through its exit fragment.
    unsafe { arinsal_enter_native(header, regs, code_ptr, &mut exit) };
    match exit.kind {
        2 => ExitReason::CallUnported {
            target_pc: exit.target,
            resume_pc: exit.resume,
        },
        0 => ExitReason::Returned,
        _ => ExitReason::Yield,
    }
}

// The pointer exposes the fixed C-layout prefix; trailing BIF bookkeeping is Rust-only.
#[allow(improper_ctypes)]
unsafe extern "C" {
    pub fn arinsal_enter_native_return();
    /// erts `beam_return_trace`: the return address of a return_trace frame.
    pub fn arinsal_return_trace();
    /// erts `beam_exception_trace`: the return address of an exception_trace frame.
    pub fn arinsal_exception_trace();
    /// erts `beam_return_to_trace`: the return address of a return_to frame.
    pub fn arinsal_return_to_trace();
    /// erts `beam_call_trace_return`: the return address of a call time/memory frame.
    pub fn arinsal_call_trace_return();
    fn arinsal_enter_native(
        header: *mut ProcessHeader,
        regs: *mut SchedulerRegisters,
        code: *const c_void,
        exit: *mut NativeExit,
    );
}

// Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:28-32 (`extern "C" { #include
// "bif.h" #include "beam_common.h" }`) and erl_gc.h, OTP-29.1.1: the runtime functions the
// fragments of this file call by address (`runtime_call`). They are defined with these erts
// names and C signatures by the VM (docs/design/jit_runtime_symbols.md); fragments take their
// address with `f as usize`. The declarations live in this raw module (`unsafe extern`);
// `beam_asm_global` re-exports them.
unsafe extern "C" {
    /// `ErtsCodePtr handle_error(Process *c_p, ErtsCodePtr pc, Eterm *reg,
    /// const ErtsCodeMFA *bif_mfa)` (beam_common.h): the handler to continue at, or null.
    pub safe fn handle_error(
        c_p: *mut crate::ProcessHeader,
        pc: usize,
        reg: *mut u64,
        bif_mfa: *const arinsal_term::ErtsCodeMfa,
    ) -> usize;
    /// `const Export *call_error_handler(Process *p, const ErtsCodeMFA *mfa, Eterm *reg,
    /// Eterm func)` (beam_common.h): the `Export` address, or null. `Export` is read only by
    /// native code, so it crosses as an address.
    pub safe fn call_error_handler(
        c_p: *mut crate::ProcessHeader,
        mfa: *const arinsal_term::ErtsCodeMfa,
        reg: *mut u64,
        func: u64,
    ) -> usize;
    /// `int erts_garbage_collect_nobump(Process *p, int need, Eterm *objv, int nobj,
    /// int fcalls)` (erl_gc.h): reductions spent.
    pub safe fn erts_garbage_collect_nobump(
        c_p: *mut crate::ProcessHeader,
        need: i32,
        objv: *mut u64,
        nobj: i32,
        fcalls: i32,
    ) -> i32;
}

/// Displacements (from `registers`) the bridge shares with native fragments and the VM, as on
/// arm64. `tmp_mem[0..2]`: the exit target and resume address a trace hook leaves.
const TMP_MEM0: i32 = tmp_mem_disp(0);
const TMP_MEM1: i32 = tmp_mem_disp(1);
/// `tmp_mem[3]`: the exit kind marker a fragment leaves before jumping to the exit fragment.
const EXIT_MARKER: i32 = tmp_mem_disp(3);
/// `tmp_mem[4]`: the exit fragment address, for runtime error fragments.
const EXIT_FRAGMENT: i32 = tmp_mem_disp(4);
/// `tmp_mem[5]`: the Rust trace return hook.
const TRACE_HOOK: i32 = tmp_mem_disp(5);

const HTOP: usize = core::mem::offset_of!(ProcessHeader, htop);
const STOP: usize = core::mem::offset_of!(ProcessHeader, stop);
const FCALLS: usize = core::mem::offset_of!(ProcessHeader, fcalls);

#[cfg(windows)]
compile_error!("the x86-64 BeamAsm entry bridge implements the System V ABI only");

// Mach-O prepends an underscore to C symbols; ELF does not.
#[cfg(target_vendor = "apple")]
macro_rules! asm_sym {
    ($name:literal) => {
        concat!("_", $name)
    };
}
#[cfg(not(target_vendor = "apple"))]
macro_rules! asm_sym {
    ($name:literal) => {
        $name
    };
}

core::arch::global_asm!(
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp:255-270 (the `erts_beamasm` trace
    // return addresses) and jit/x86/instr_trace.cpp (emit_return_trace,
    // emit_i_return_to_trace, emit_i_call_trace_return), OTP-29.1.1: one return address per
    // trace frame kind, each entered by a `ret` with `E` in rsp. Each passes its kind
    // (`TRACE_FRAME_*`) to the shared Rust hook in ARG2.
    concat!(".global ", asm_sym!("arinsal_return_trace")),
    concat!(asm_sym!("arinsal_return_trace"), ":"),
    "mov esi, 0",
    "jmp 2f",
    concat!(".global ", asm_sym!("arinsal_exception_trace")),
    concat!(asm_sym!("arinsal_exception_trace"), ":"),
    "mov esi, 1",
    "jmp 2f",
    concat!(".global ", asm_sym!("arinsal_return_to_trace")),
    concat!(asm_sym!("arinsal_return_to_trace"), ":"),
    "mov esi, 2",
    "jmp 2f",
    concat!(".global ", asm_sym!("arinsal_call_trace_return")),
    concat!(asm_sym!("arinsal_call_trace_return"), ":"),
    "mov esi, 3",
    "2:",
    // emit_enter_runtime<eStack | eHeap | eReductions> (jit/x86/beam_asm.hpp:700-800).
    "mov [r13 + {htop}], r15",
    "mov [r13 + {stop}], rsp",
    "mov [r13 + {fcalls}], r14d",
    "mov rsp, [rbx + {runtime_stack}]",
    "mov rdi, r13",
    // `reg`: the hook roots and reloads the X registers through it.
    "mov rdx, rbx",
    "call qword ptr [rbx + {trace_hook}]",
    // emit_leave_runtime<eStack | eHeap | eReductions> (jit/x86/beam_asm.hpp:803-850).
    "mov rsp, [r13 + {stop}]",
    "mov r15, [r13 + {htop}]",
    "mov r14d, [r13 + {fcalls}]",
    // A hook that hands the return to the scheduler leaves the exit target and resume
    // address in tmp_mem[0..2] and returns the exit fragment; ARG2/ARG3 are free at a return.
    "mov rsi, [rbx + {tmp_mem0}]",
    "mov rdx, [rbx + {tmp_mem1}]",
    "jmp rax",
    htop = const HTOP,
    stop = const STOP,
    fcalls = const FCALLS,
    runtime_stack = const RUNTIME_STACK_DISP,
    trace_hook = const TRACE_HOOK,
    tmp_mem0 = const TMP_MEM0,
    tmp_mem1 = const TMP_MEM1,
);

core::arch::global_asm!(
    concat!(".global ", asm_sym!("arinsal_enter_native")),
    concat!(asm_sym!("arinsal_enter_native"), ":"),
    // Port of erts/emulator/beam/jit/x86/process_main.cpp:53-110 and 270-293
    // (emit_process_main), OTP-29.1.1. Arguments (System V): rdi = c_p, rsi = registers,
    // rdx = code, rcx = exit record. Preserve the System V callee-saved registers; together
    // with the exit record pointer and the return address the frame is 64 bytes, so the
    // runtime stack stays 16-byte aligned for runtime calls.
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "push rcx",
    // `registers` points at x_reg_array (process_main.cpp:72-77); c_p is r13.
    "lea rbx, [rsi + {x_reg_array}]",
    "mov r13, rdi",
    // The runtime stack every emit_enter_runtime switches back to is this frame.
    "mov [rbx + {runtime_stack}], rsp",
    // Setup reduction counting and the active code index (process_main.cpp:252-286): the
    // runtime already resolved the process's code index (save_calls or the active one).
    "mov r14d, [r13 + {fcalls}]",
    "mov r12, [rbx + {active_code_ix}]",
    // Runtime error fragments find the exit fragment here after a runtime call.
    concat!("lea rax, [rip + ", asm_sym!("arinsal_enter_native_return"), "]"),
    "mov [rbx + {exit_fragment}], rax",
    // emit_leave_runtime<eStack | eHeap>: switch to the Erlang stack.
    "mov r15, [r13 + {htop}]",
    "mov rsp, [r13 + {stop}]",
    // A call entered from the scheduler returns to its caller's continuation: it is the
    // callee's CP, which on x86-64 is the word on top of the Erlang stack (`entry_return`).
    "mov rax, [rbx + {entry_return}]",
    "test rax, rax",
    "jz 2f",
    "mov qword ptr [rbx + {entry_return}], 0",
    "push rax",
    // Port of erts/emulator/beam/jit/x86/process_main.cpp:288-293, OTP-29.1.1: a scheduler
    // re-entry can target a BIF continuation, whose result is in RET.
    "mov rax, [rbx]",
    "jmp rdx",
    "2:",
    "mov rax, [rbx]",
    // The call pushes the exit fragment as the callee's CP, which must be 4-byte aligned
    // (`aligned_call`, jit/x86/beam_asm.hpp:420-440): pad so the 2-byte `call rdx` ends on a
    // 4-byte boundary. A call (not a jump) also keeps the return stack buffer balanced.
    ".p2align 2",
    ".byte 0x66, 0x90",
    "call rdx",
    // This label must directly follow the `call rdx` above: its return address is the exit
    // fragment. Arrives by a `ret` or a jump, with `E` in rsp either way.
    concat!(".global ", asm_sym!("arinsal_enter_native_return")),
    concat!(asm_sym!("arinsal_enter_native_return"), ":"),
    // The marker distinguishes a scheduler handoff without adding work to each BEAM return;
    // consume it so a later plain return is not taken for a handoff.
    "mov rcx, [rbx + {exit_marker}]",
    "mov qword ptr [rbx + {exit_marker}], 0",
    "mov rax, rcx",
    // emit_enter_runtime<eStack | eHeap | eReductions>: publish the cursors, back to the
    // runtime stack.
    "mov [r13 + {htop}], r15",
    "mov [r13 + {stop}], rsp",
    "mov [r13 + {fcalls}], r14d",
    "mov rsp, [rbx + {runtime_stack}]",
    "pop rcx",
    "mov [rcx], rax",
    "mov [rcx + 8], rsi",
    "mov [rcx + 16], rdx",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    htop = const HTOP,
    stop = const STOP,
    fcalls = const FCALLS,
    x_reg_array = const X_REG_ARRAY_OFFSET,
    runtime_stack = const RUNTIME_STACK_DISP,
    active_code_ix = const ACTIVE_CODE_IX_DISP,
    entry_return = const ENTRY_RETURN_DISP,
    exit_fragment = const EXIT_FRAGMENT,
    exit_marker = const EXIT_MARKER,
);

#[cfg(test)]
mod tests {
    use super::*;

    // Native functions following the x86-64 BeamAsm register contract, entered through the
    // bridge. `preserve` is a host-side caller that checks the bridge keeps every System V
    // callee-saved register.
    core::arch::global_asm!(
        concat!(asm_sym!("arinsal_x86_test_return"), ":"),
        // Clobber registers the host expects preserved; the bridge must restore them.
        "mov rbp, 0x1111",
        "mov r12, 0x2222",
        // RET holds XREG0 on entry.
        "mov [rbx + 8], rax",
        "add r15, 16",
        "sub r14d, 1",
        "ret",
        concat!(asm_sym!("arinsal_x86_test_handoff"), ":"),
        "mov qword ptr [rbx + {exit_marker}], 2",
        "mov esi, 0x1234",
        "mov edx, 0x5678",
        "ret",
        concat!(asm_sym!("arinsal_x86_test_runtime_call"), ":"),
        // emit_enter_runtime<eStack>, runtime_call, emit_leave_runtime<eStack>.
        "mov [r13 + {stop}], rsp",
        "mov rsp, [rbx + {runtime_stack}]",
        "mov rdi, r13",
        "call {hook}",
        "mov rsp, [r13 + {stop}]",
        "mov [rbx + 16], rax",
        "ret",
        concat!(asm_sym!("arinsal_x86_test_yield_jump"), ":"),
        // A fragment leaving by jump: E is rsp with no CP popped.
        "mov qword ptr [rbx + {exit_marker}], 1",
        "push 0",
        "pop rax",
        "jmp qword ptr [rbx + {exit_fragment}]",
        concat!(asm_sym!("arinsal_x86_test_exception_trace"), ":"),
        // Returns through an exception_trace frame.
        concat!("lea rax, [rip + ", asm_sym!("arinsal_exception_trace"), "]"),
        "push rax",
        "ret",
        concat!(asm_sym!("arinsal_x86_test_preserve"), ":"),
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "sub rsp, 8",
        "mov rbx, 0x0b0b",
        "mov rbp, 0x5005",
        "mov r12, 0x1212",
        "mov r13, 0x1313",
        "mov r14, 0x1414",
        "mov r15, 0x1515",
        concat!("call ", asm_sym!("arinsal_enter_native")),
        "xor eax, eax",
        "cmp rbx, 0x0b0b",
        "jne 4f",
        "cmp rbp, 0x5005",
        "jne 4f",
        "cmp r12, 0x1212",
        "jne 4f",
        "cmp r13, 0x1313",
        "jne 4f",
        "cmp r14, 0x1414",
        "jne 4f",
        "cmp r15, 0x1515",
        "jne 4f",
        "mov eax, 1",
        "4:",
        "add rsp, 8",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
        exit_marker = const EXIT_MARKER,
        exit_fragment = const EXIT_FRAGMENT,
        stop = const STOP,
        runtime_stack = const RUNTIME_STACK_DISP,
        hook = sym runtime_hook,
    );

    unsafe extern "C" {
        fn arinsal_x86_test_return();
        fn arinsal_x86_test_handoff();
        fn arinsal_x86_test_runtime_call();
        fn arinsal_x86_test_yield_jump();
        fn arinsal_x86_test_exception_trace();
        fn arinsal_x86_test_preserve(
            header: *mut ProcessHeader,
            regs: *mut SchedulerRegisters,
            code: *const c_void,
            exit: *mut NativeExit,
        ) -> u64;
    }

    /// A runtime function called from native code on the runtime stack. Heap allocation and
    /// formatting exercise the 16-byte stack alignment the C ABI requires.
    extern "C" fn runtime_hook(c_p: *mut ProcessHeader) -> u64 {
        let words: Vec<u64> = (0..64).collect();
        let text = format!("{:?}", &words[..4]);
        // SAFETY: the test bridge passes the live header it was entered with.
        let fcalls = unsafe { (*c_p).fcalls };
        fcalls as u64 + text.len() as u64
    }

    /// The Rust trace return hook: records its kind and continues at the exit fragment. Like
    /// the VM's `arinsal_beamasm_native_trace_return`, it gets `reg` (`x_reg_array`), not the
    /// start of the register file.
    extern "C" fn trace_hook(_c_p: *mut ProcessHeader, kind: u64, reg: *mut u64) -> usize {
        let registers = SchedulerRegisters::from_reg(reg);
        // SAFETY: the trace fragment passes the `reg` of the live register file it runs with.
        unsafe { (*registers).tmp_mem[7] = kind + 10 };
        arinsal_enter_native_return as *const () as usize
    }

    struct Fixture {
        header: ProcessHeader,
        regs: Box<SchedulerRegisters>,
        stack: Vec<u64>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut fixture = Self {
                header: ProcessHeader::default(),
                regs: Box::default(),
                stack: vec![0; 64],
            };
            let heap = fixture.stack.as_mut_ptr();
            fixture.header.htop = heap;
            // SAFETY: 32 is within the 64-word stack allocation.
            fixture.header.stop = unsafe { heap.add(32) };
            fixture.header.fcalls = 100;
            fixture.regs.x_reg_array[0] = arinsal_term::Term::NIL;
            fixture
        }

        fn enter(&mut self, code: unsafe extern "C" fn()) -> ExitReason {
            // SAFETY: the test functions above follow the bridge contract.
            unsafe { enter_native_raw(&mut self.header, &mut self.regs, code as *const c_void) }
        }

        fn stop_offset(&self) -> isize {
            // SAFETY: both pointers are into `stack`.
            unsafe { self.header.stop.offset_from(self.stack.as_ptr()) }
        }
    }

    #[test]
    fn plain_return_publishes_cursors() {
        let mut fixture = Fixture::new();
        let htop = fixture.header.htop;
        assert_eq!(fixture.enter(arinsal_x86_test_return), ExitReason::Returned);
        // SAFETY: 2 words stay within the stack allocation.
        assert_eq!(fixture.header.htop, unsafe { htop.add(2) });
        assert_eq!(fixture.header.fcalls, 99);
        assert_eq!(fixture.stop_offset(), 32);
        assert_eq!(
            fixture.regs.x_reg_array[1].tagged_word(),
            arinsal_term::Term::NIL.tagged_word()
        );
        // The bridge's CP was pushed just below `stop`, 4-byte aligned.
        let cp = fixture.stack[31];
        assert_eq!(cp, arinsal_enter_native_return as *const () as u64);
        assert_eq!(cp & 3, 0);
    }

    #[test]
    fn handoff_marker_selects_call_unported() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.enter(arinsal_x86_test_handoff),
            ExitReason::CallUnported {
                target_pc: 0x1234,
                resume_pc: 0x5678
            }
        );
        assert_eq!(fixture.regs.tmp_mem[3], 0);
        assert_eq!(
            fixture.regs.tmp_mem[4],
            arinsal_enter_native_return as *const () as u64
        );
    }

    #[test]
    fn entry_return_becomes_callee_cp() {
        let mut fixture = Fixture::new();
        fixture.regs.entry_return = arinsal_enter_native_return as *const () as u64;
        assert_eq!(fixture.enter(arinsal_x86_test_return), ExitReason::Returned);
        assert_eq!(fixture.regs.entry_return, 0);
        assert_eq!(fixture.stop_offset(), 32);
    }

    #[test]
    fn runtime_call_runs_on_runtime_stack() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.enter(arinsal_x86_test_runtime_call),
            ExitReason::Returned
        );
        assert_eq!(fixture.regs.x_reg_array[2].tagged_word(), 100 + 12);
        assert_eq!(fixture.stop_offset(), 32);
    }

    #[test]
    fn jump_to_exit_fragment_yields() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.enter(arinsal_x86_test_yield_jump),
            ExitReason::Yield
        );
        // A jump leaves the bridge's CP on the Erlang stack: `stop` is below it.
        assert_eq!(fixture.stop_offset(), 31);
    }

    #[test]
    fn trace_return_calls_hook_on_runtime_stack() {
        let mut fixture = Fixture::new();
        fixture.regs.tmp_mem[5] = trace_hook as *const () as u64;
        assert_eq!(
            fixture.enter(arinsal_x86_test_exception_trace),
            ExitReason::Returned
        );
        assert_eq!(fixture.regs.tmp_mem[7], 11);
        // The trace frame's address was popped; the hook's jump to the exit fragment leaves
        // the bridge's own CP below `stop`.
        assert_eq!(fixture.stop_offset(), 31);
    }

    #[test]
    fn bridge_preserves_callee_saved_registers() {
        let mut fixture = Fixture::new();
        let mut exit = NativeExit::default();
        // SAFETY: the test native function follows the bridge contract.
        let preserved = unsafe {
            arinsal_x86_test_preserve(
                &mut fixture.header,
                &mut *fixture.regs,
                arinsal_x86_test_return as *const c_void,
                &mut exit,
            )
        };
        assert_eq!(preserved, 1);
        assert_eq!(exit.kind, 0);
    }
}
