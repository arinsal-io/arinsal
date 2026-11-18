//! Port of erts/emulator/beam/jit/x86/instr_msg.cpp, OTP-29.1.1: the receive instructions
//! (`recv_marker_*`, `i_loop_rec`, `remove_message`, `loop_rec_end`, `wait*`, `timeout*`) and
//! the global fragment `i_loop_rec_shared`.

use arinsal_x64::enc::{CondCode, Mem, dword_ptr, qword_ptr};

use super::beam_asm::register::{
    ARG1, ARG2, ARG2D, ARG3, ARG4, ARG5, C_P, E, FCALLS, HTOP, RET, RETD,
};
use super::beam_asm::{
    AsmError, THE_NON_VALUE, Update, get_x_ref, process, process_ref, tmp_mem_d, tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, arg_label};
pub use super::rt::{
    beam_jit_decode_dist, beam_jit_remove_message, beam_jit_take_receive_lock, beam_jit_timeout,
    beam_jit_timeout_locked, beam_jit_wait_locked, beam_jit_wait_timeout, beam_jit_wait_unlocked,
    erts_msgq_recv_marker_bind, erts_msgq_recv_marker_clear, erts_msgq_recv_marker_insert,
    erts_msgq_recv_marker_set_save, erts_msgq_set_save_next, erts_proc_sig_receive_helper,
};
use crate::common::args::ArgVal;

/// `F_DELAY_GC` of `c_p->flags`.
// Port of erts/emulator/beam/erl_process.h (F_DELAY_GC), OTP-29.1.1.
const F_DELAY_GC: u32 = arinsal_term::pflags::F_DELAY_GC;

/// `enum beam_jit_tmo_ret`: `RET_wait`.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:574 (beam_jit_tmo_ret), OTP-29.1.1.
const RET_WAIT: i64 = 1;

/// `x86::dword_ptr(c_p, offsetof(Process, flags))`.
const fn flags_ref() -> Mem {
    dword_ptr(C_P, process::FLAGS)
}

impl BeamModuleAssembler {
    /// `resolve_beam_label(Label)` of a label operand.
    fn msg_label(&self, label: ArgVal) -> Result<arinsal_x64::buf::Label, AsmError> {
        self.resolve_beam_label(arg_label(label)?)
            .ok_or(AsmError::Operand("label number"))
    }

    /// `a.lea(reg, x86::qword_ptr(label))`.
    fn lea_label(
        &mut self,
        reg: arinsal_x64::enc::Gp,
        label: arinsal_x64::buf::Label,
    ) -> Result<(), AsmError> {
        Ok(self
            .asm
            .a
            .emit_rip_label(label, |e| e.lea(reg, Mem::rip(0, 8)))?)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:34-43 (emit_recv_marker_reserve),
    // OTP-29.1.1.
    pub fn emit_recv_marker_reserve(&mut self, dst: ArgVal) -> Result<(), AsmError> {
        self.asm.emit_enter_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_msgq_recv_marker_insert as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::HEAP_ALLOC)?;
        self.mov_arg_from_reg(dst, RET)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:45-56 (emit_recv_marker_bind),
    // OTP-29.1.1.
    pub fn emit_recv_marker_bind(
        &mut self,
        marker: ArgVal,
        reference: ArgVal,
    ) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG2, marker)?;
        self.mov_arg_to_reg(ARG3, reference)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_msgq_recv_marker_bind as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:58-66 (emit_recv_marker_clear),
    // OTP-29.1.1.
    pub fn emit_recv_marker_clear(&mut self, reference: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG2, reference)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_msgq_recv_marker_clear as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:68-76 (emit_recv_marker_use),
    // OTP-29.1.1.
    pub fn emit_recv_marker_use(&mut self, reference: ArgVal) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG2, reference)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_msgq_recv_marker_set_save as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:236-245 (emit_i_loop_rec), OTP-29.1.1.
    pub fn emit_i_loop_rec(&mut self, wait: ArgVal) -> Result<(), AsmError> {
        let entry = self.asm.new_label();
        self.asm.align_erlang_cp()?;
        self.asm.bind(entry)?;
        self.lea_label(ARG1, entry)?;
        let wait = self.msg_label(wait)?;
        self.lea_label(ARG2, wait)?;
        let fragment = self.ga_get(GlobalLabels::ILoopRecShared)?;
        let target = self.resolve_fragment(fragment);
        self.asm.fragment_call(target)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:247-263 (emit_remove_message),
    // OTP-29.1.1.
    pub fn emit_remove_message(&mut self) -> Result<(), AsmError> {
        use super::beam_asm::register::{ACTIVE_CODE_IX, ARG2D};
        // HTOP and E are passed explicitly and only read from, so they need no swap.
        self.asm.emit(|e| e.mov_rr(ARG3, HTOP))?;
        self.asm.emit(|e| e.mov_rr(ARG4, E))?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.emit(|e| e.mov_rr(ARG2D, FCALLS))?;
        self.asm.emit(|e| e.mov_rr(ARG5, ACTIVE_CODE_IX))?;
        self.asm
            .runtime_call(beam_jit_remove_message as *const () as usize)?;
        self.asm.emit(|e| e.mov_rr(FCALLS, RETD))?;
        self.asm.emit_leave_runtime(Update::NONE)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:265-275 (emit_loop_rec_end), OTP-29.1.1.
    pub fn emit_loop_rec_end(&mut self, dest: ArgVal) -> Result<(), AsmError> {
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_msgq_set_save_next as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| e.dec_r(FCALLS))?;
        let dest = self.msg_label(dest)?;
        self.asm.jmp(dest)
    }

    /// `emit_wait_unlocked` / `emit_wait_locked`: `wait` is the runtime function.
    fn emit_wait(&mut self, dest: ArgVal, wait: usize) -> Result<(), AsmError> {
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        let dest = self.msg_label(dest)?;
        self.lea_label(ARG2, dest)?;
        self.asm.runtime_call(wait)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        let fragment = self.ga_get(GlobalLabels::DoSchedule)?;
        let label = self.resolve_fragment(fragment);
        self.asm.jmp(label)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:277-288 (emit_wait_unlocked),
    // OTP-29.1.1.
    pub fn emit_wait_unlocked(&mut self, dest: ArgVal) -> Result<(), AsmError> {
        self.emit_wait(dest, beam_jit_wait_unlocked as *const () as usize)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:290-301 (emit_wait_locked), OTP-29.1.1.
    pub fn emit_wait_locked(&mut self, dest: ArgVal) -> Result<(), AsmError> {
        self.emit_wait(dest, beam_jit_wait_locked as *const () as usize)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:303-313 (emit_wait_timeout_unlocked),
    // OTP-29.1.1.
    pub fn emit_wait_timeout_unlocked(
        &mut self,
        src: ArgVal,
        dest: ArgVal,
    ) -> Result<(), AsmError> {
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(beam_jit_take_receive_lock as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.emit_wait_timeout_locked(src, dest)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:315-345 (emit_wait_timeout_locked),
    // OTP-29.1.1.
    pub fn emit_wait_timeout_locked(&mut self, src: ArgVal, dest: ArgVal) -> Result<(), AsmError> {
        let wait = self.asm.new_label();
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG2, src)?;
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.lea_label(ARG3, next)?;
        self.asm
            .runtime_call(beam_jit_wait_timeout as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        // RET_next < RET_wait < RET_badarg.
        self.asm.emit(|e| e.cmp_ri(RET, RET_WAIT))?;
        self.asm.short_jcc(CondCode::E, wait)?;
        self.asm.short_jcc(CondCode::L, next)?;
        let current = self
            .current_label()
            .ok_or(AsmError::Operand("wait_timeout outside a label"))?;
        self.emit_raise_exception_label(current, None)?;
        self.asm.bind(wait)?;
        self.emit_wait_locked(dest)?;
        self.asm.align_erlang_cp()?;
        self.asm.bind(next)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:347-355 (emit_timeout_locked),
    // OTP-29.1.1.
    pub fn emit_timeout_locked(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(beam_jit_timeout_locked as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)
    }

    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:357-365 (emit_timeout), OTP-29.1.1.
    pub fn emit_timeout(&mut self) -> Result<(), AsmError> {
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(beam_jit_timeout as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::NONE)
    }
}

impl BeamGlobalAssembler {
    /// `ARG1` = the `loop_rec`'s own address (the yield address), `ARG2` = the wait address:
    /// the next message's term in X0, or a jump to the wait (queue empty) or to `do_schedule`
    /// (out of reductions or an exit signal).
    // Port of erts/emulator/beam/jit/x86/instr_msg.cpp:100-234 (emit_i_loop_rec_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_i_loop_rec_shared(&mut self) -> Result<(), AsmError> {
        use super::beam_asm::register::ARG5;
        let sig_qs_save = qword_ptr(C_P, self.offsets.sig_qs_save as i32);
        let message_term = self.offsets.message_term as i32;
        let do_schedule = self.label(GlobalLabels::DoSchedule);
        let a = &mut self.asm;
        let restart = a.new_label();
        let peek_message = a.new_label();
        let schedule_out = a.new_label();
        let check_is_distributed = a.new_label();
        let done = a.new_label();
        let (await_addr, message_ptr, get_out) = (tmp_mem_q(0), tmp_mem_q(1), tmp_mem_d(2));

        a.emit_enter_frame()?;
        a.emit(|e| e.or_mi(flags_ref(), i64::from(F_DELAY_GC)))?;
        a.emit(|e| e.mov_mr(process_ref(process::I, 8), ARG1))?;
        a.emit(|e| e.mov_mr(await_addr, ARG2))?;

        a.bind(restart)?;
        a.emit(|e| e.test_rr(FCALLS, FCALLS))?;
        a.jcc(CondCode::LE, schedule_out)?;
        // !! FALL THROUGH !!

        // Peek next message.
        a.bind(peek_message)?;
        a.emit(|e| e.mov_rm(ARG1, sig_qs_save))?;
        a.emit(|e| e.mov_rm(ARG1, qword_ptr(ARG1, 0)))?;
        a.emit(|e| e.test_rr(ARG1, ARG1))?;
        a.jcc(CondCode::NE, check_is_distributed)?;

        // Inner queue empty, fetch more from the outer/middle queues.
        a.emit_enter_runtime(Update::REDUCTIONS.union(Update::HEAP_ALLOC))?;
        a.emit(|e| e.mov_mi(message_ptr, 0))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| e.mov_rr(ARG2D, FCALLS))?;
        a.mov_imm(ARG3, 0)?;
        a.emit(|e| e.lea(ARG4, message_ptr))?;
        a.emit(|e| e.lea(ARG5, get_out))?;
        a.runtime_call(erts_proc_sig_receive_helper as *const () as usize)?;
        // The helper merely inspects FCALLS. Another process may have loaded new code and
        // told us so, so the active code index is reloaded.
        a.emit_leave_runtime(Update::HEAP_ALLOC.union(Update::CODE_INDEX))?;
        a.emit(|e| e.sub_rr(FCALLS, RETD))?;
        // check_is_distributed reads the message from ARG1.
        a.emit(|e| e.mov_rm(ARG1, message_ptr))?;
        a.emit(|e| e.test_rr(ARG1, ARG1))?;
        a.jcc(CondCode::NE, check_is_distributed)?;
        // Did we receive a signal or run out of reductions?
        a.emit(|e| e.cmp_mi(get_out, 0))?;
        a.short_jcc(CondCode::NE, schedule_out)?;
        // The queue is empty and we neither yield nor exit: on to the wait/timeout
        // instruction, with the message queue lock still held.
        a.emit(|e| e.and_mi(flags_ref(), i64::from(!F_DELAY_GC as i32)))?;
        a.emit_unwind_frame()?;
        a.emit(|e| e.jmp_m(await_addr))?;

        a.bind(schedule_out)?;
        // Out of reductions or an exit signal: schedule out. The yield address (`c_p->i`) was
        // set on ingress.
        a.emit(|e| e.and_mi(flags_ref(), i64::from(!F_DELAY_GC as i32)))?;
        a.emit(|e| e.mov_mi(process_ref(process::ARITY, 1), 0))?;
        a.emit(|e| e.mov_mi(process_ref(process::CURRENT, 8), 0))?;
        a.emit_unwind_frame()?;
        a.jmp(do_schedule)?;

        // Check if the message is distributed: `ErtsSignal.common.tag` is `m[0]`.
        a.bind(check_is_distributed)?;
        a.emit(|e| e.cmp_mi(qword_ptr(ARG1, message_term), THE_NON_VALUE as i64))?;
        a.jcc(CondCode::NE, done)?;
        a.emit(|e| e.sub_ri(FCALLS, 10))?;
        a.emit_enter_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rr(ARG2, ARG1))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.runtime_call(beam_jit_decode_dist as *const () as usize)?;
        a.emit_leave_runtime(Update::NONE)?;
        a.emit(|e| e.test_rr(RET, RET))?;
        a.jcc(CondCode::E, restart)?;
        a.emit(|e| e.mov_rr(ARG1, RET))?;
        // !! FALL THROUGH !!

        a.bind(done)?;
        a.emit(|e| e.mov_rm(ARG1, qword_ptr(ARG1, message_term)))?;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG1))?;
        a.emit_leave_frame()?;
        a.emit(|e| e.ret())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::beam_asm_global::GLOBAL_LABELS;
    use crate::x86::jdump::{beam_register, erts_dump, erts_to_arinsal, gnu_as, op_blocks};
    use arinsal_x64::buf::Section;

    const MODULES: [&str; 8] = [
        "application_master",
        "application_controller",
        "code_server",
        "gen_server",
        "gen_event",
        "erl_prim_loader",
        "init",
        "net_kernel",
    ];

    /// One erts dump line with every displacement to code outside the block (labels, the
    /// module's fragment thunks, absolute runtime calls) written as `fill` bytes.
    fn masked(line: &str, fill: u8, relative_fragment_call: bool) -> String {
        let bytes = |opcode: &[u8], width: usize| {
            let all: Vec<String> = opcode
                .iter()
                .copied()
                .chain(std::iter::repeat_n(fill, width))
                .map(|b| format!("{b:#04x}"))
                .collect();
            format!(".byte {}", all.join(", "))
        };
        let is_label = |t: &str| t.starts_with('L') || t.starts_with("label_");
        if let Some(target) = line.strip_prefix("call ")
            && target.parse::<u64>().is_ok()
        {
            return if relative_fragment_call {
                bytes(&[0xe8], 4)
            } else {
                bytes(&[0x40, 0xe8], 4)
            };
        }
        if let Some((dst, target)) = line
            .strip_prefix("lea ")
            .and_then(|r| r.split_once(", qword ptr ["))
            && is_label(target.trim_end_matches(']'))
        {
            let disp = if fill == 0 { "rip+0" } else { "rip-1" };
            return format!("lea {dst}, [{disp}]");
        }
        let (op, target) = line.rsplit_once(' ').unwrap_or((line, ""));
        if is_label(target) {
            return match op {
                "jmp" => bytes(&[0xe9], 4),
                "short jz" => bytes(&[0x74], 1),
                "short jl" => bytes(&[0x7c], 1),
                other => panic!("unexpected jump `{other}`"),
            };
        }
        erts_to_arinsal(line)
    }

    /// Whether `emit` encodes `block` (after `pad` bytes of code) as erts does, ignoring the
    /// displacements [`masked`] hides.
    fn matches(
        block: &[String],
        emit: &dyn Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>,
        relative_fragment_call: bool,
    ) -> bool {
        let lines = |fill: u8| -> Vec<String> {
            const NOPS: [&str; 3] = ["0x90", "0x66, 0x90", "0x0f, 0x1f, 0x00"];
            let is_call_alignment_nop = |line: &str| {
                matches!(
                    line.to_ascii_lowercase().replace(' ', "").as_str(),
                    ".byte0x90" | ".byte0x66,0x90" | ".byte0x0f,0x1f,0x00"
                )
            };
            let mut output: Vec<String> = Vec::new();
            for line in block.iter().filter(|line| !line.starts_with("align ")) {
                if relative_fragment_call
                    && line
                        .strip_prefix("call ")
                        .is_some_and(|target| target.parse::<u64>().is_ok())
                {
                    while output
                        .last()
                        .is_some_and(|line| is_call_alignment_nop(line))
                    {
                        output.pop();
                    }
                    let prefix_len = gnu_as(&output).expect("GNU as for call prefix").len();
                    let padding = (4 - (prefix_len + 5) % 4) % 4;
                    if padding > 0 {
                        output.push(format!(".byte {}", NOPS[padding - 1]));
                    }
                    output.push(masked(line, fill, true));
                } else {
                    output.push(masked(line, fill, false));
                }
            }
            output
        };
        let (Some(zeros), Some(ones)) = (gnu_as(&lines(0)), gnu_as(&lines(0xff))) else {
            return false;
        };
        let addresses = (0..GLOBAL_LABELS.len())
            .map(|i| Some(0x7000_0000 + 64 * i))
            .collect();
        let mut m = BeamModuleAssembler::with_fragment_addresses(4096, addresses);
        m.emit_label(ArgVal::Label(4095)).unwrap();
        emit(&mut m).unwrap();
        let ours = m.asm.a.bytes(Section::Code);
        ours.len() >= zeros.len()
            && ours
                .iter()
                .zip(zeros.iter().zip(&ones))
                .all(|(o, (z, f))| z != f || o == z)
    }

    /// The label a `lea rsi, qword ptr [label_N]` / `jmp label_N` line names.
    fn beam_label(line: &str) -> Option<ArgVal> {
        let n = line.rsplit_once("label_")?.1.trim_end_matches(']');
        Some(ArgVal::Label(n.parse().ok()?))
    }

    /// The source operand `mov rsi, <src>` loads.
    fn source(line: &str) -> Option<ArgVal> {
        let src = line
            .strip_prefix("mov rsi, ")
            .or(line.strip_prefix("mov esi, "))?;
        beam_register(src).or_else(|| src.parse().ok().map(ArgVal::Immediate))
    }

    fn check(op: &str, min: usize, emit: &dyn Fn(&[String]) -> Option<Box<EmitFn>>) {
        let dumps: Vec<String> = MODULES.iter().filter_map(|m| erts_dump(m)).collect();
        if dumps.is_empty() || gnu_as(&[]).is_none() {
            eprintln!("skipping: `erl +JDdump true` or GNU binutils unavailable");
            return;
        }
        let mut compared = 0;
        for dump in &dumps {
            let blocks = if op == "i_loop_rec_f" {
                // `align_erlang_cp` and the entry label split the block: take the label and
                // the three instructions after it.
                let lines: Vec<&str> = dump.lines().collect();
                lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| **l == "# i_loop_rec_f")
                    .map(|(i, _)| {
                        lines[i + 2..i + 6]
                            .iter()
                            .map(|l| l.trim().to_string())
                            .collect()
                    })
                    .collect()
            } else {
                op_blocks(dump, op)
            };
            for block in blocks {
                let Some(f) = emit(&block) else { continue };
                assert!(
                    matches(&block, &*f, op == "i_loop_rec_f"),
                    "{op}: {block:?}"
                );
                compared += 1;
            }
        }
        eprintln!("compared {compared} {op} blocks");
        assert!(compared >= min, "{op}: compared {compared}");
    }

    type EmitFn = dyn Fn(&mut BeamModuleAssembler) -> Result<(), AsmError>;

    #[test]
    fn receive_instructions_match_erts_dump() {
        check("timeout", 3, &|_| Some(Box::new(|m| m.emit_timeout())));
        check("timeout_locked", 3, &|_| {
            Some(Box::new(|m| m.emit_timeout_locked()))
        });
        check("remove_message", 10, &|_| {
            Some(Box::new(|m| m.emit_remove_message()))
        });
        check("loop_rec_end_f", 5, &|b| {
            // A backward jump in rel8 reach depends on a layout this test does not rebuild.
            let jump = b.last()?;
            if jump.starts_with("short ") {
                return None;
            }
            let dest = beam_label(jump)?;
            Some(Box::new(move |m| m.emit_loop_rec_end(dest)))
        });
        check("wait_locked_f", 5, &|b| {
            let dest = beam_label(b.iter().find(|l| l.starts_with("lea rsi"))?)?;
            Some(Box::new(move |m| m.emit_wait_locked(dest)))
        });
        check("wait_unlocked_f", 1, &|b| {
            let dest = beam_label(b.iter().find(|l| l.starts_with("lea rsi"))?)?;
            Some(Box::new(move |m| m.emit_wait_unlocked(dest)))
        });
        check("i_loop_rec_f", 5, &|b| {
            let wait = beam_label(b.iter().find(|l| l.starts_with("lea rsi"))?)?;
            Some(Box::new(move |m| m.emit_i_loop_rec(wait)))
        });
        check("wait_timeout_locked_sf", 3, &|b| {
            let src = source(&b[0])?;
            let dest = ArgVal::Label(1);
            Some(Box::new(move |m| m.emit_wait_timeout_locked(src, dest)))
        });
        check("wait_timeout_unlocked_sf", 3, &|b| {
            let src = b.iter().find_map(|l| source(l))?;
            let dest = ArgVal::Label(1);
            Some(Box::new(move |m| m.emit_wait_timeout_unlocked(src, dest)))
        });
    }

    #[test]
    fn recv_markers_match_erts_dump() {
        check("recv_marker_reserve_S", 5, &|b| {
            let dst = beam_register(b.last()?.strip_prefix("mov ")?.split_once(", rax")?.0)?;
            Some(Box::new(move |m| m.emit_recv_marker_reserve(dst)))
        });
        check("recv_marker_clear_S", 5, &|b| {
            let r = source(&b[0])?;
            Some(Box::new(move |m| m.emit_recv_marker_clear(r)))
        });
        check("recv_marker_use_S", 5, &|b| {
            let r = source(&b[0])?;
            Some(Box::new(move |m| m.emit_recv_marker_use(r)))
        });
        check("recv_marker_bind_SS", 5, &|b| {
            let marker = source(&b[0])?;
            let reference = beam_register(b[1].strip_prefix("mov rdx, ")?)?;
            Some(Box::new(move |m| {
                m.emit_recv_marker_bind(marker, reference)
            }))
        });
    }
}
