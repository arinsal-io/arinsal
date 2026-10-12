//! Process-wide BeamAsm dispatch fragments.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::{Cond, Gpr, Shift, Shifted, VecReg},
    exec::{CodeMemory, ExecError},
};

use crate::{
    Update, emit_enter_runtime, emit_leave_runtime,
    rt::{arinsal_enter_native_return, arinsal_enter_native_yield},
};

const RUNTIME_UPDATE: Update = Update::HEAP_ALLOC
    .union(Update::STACK)
    .union(Update::REDUCTIONS)
    .union(Update::X_REGS);
const THE_NON_VALUE: u16 = 0;
pub(crate) const TRAP_REASON: u16 = 1 << 10;

/// Executable fragments shared by every compiled module in one VM process.
pub struct DispatchFragments {
    memory: CodeMemory,
    export_offset: usize,
    light_bif_offset: usize,
    /// Helper-ABI fragment for call breakpoints. `call_light_bif_shared` is not its entry:
    /// erts calls `erts_generic_breakpoint` from the trampoline itself.
    breakpoint_offset: usize,
    line_breakpoint_offset: usize,
    line_breakpoint_cleanup_offset: usize,
    send_offset: usize,
    call_fun_unported_offset: usize,
    apply_fixed_offset: usize,
    apply2_offset: usize,
    apply3_offset: usize,
    save_calls_export_offset: usize,
    apply_fun_offset: usize,
    unloaded_fun_offset: usize,
    save_calls_fun_offset: usize,
    bif_is_eq_exact_offset: usize,
    bif_is_ne_exact_offset: usize,
    arith_compare_offset: usize,
}

/// C functions called by the comparison fragments (`eq`, `erts_cmp_atoms`, `erts_cmp_compound`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CompareHelpers {
    /// `eq(Eterm, Eterm) -> int`. Non-zero means equal.
    pub eq: usize,
    /// `erts_cmp_atoms(Eterm, Eterm) -> int`.
    pub cmp_atoms: usize,
    /// `erts_cmp_compound(Eterm, Eterm, int, int) -> Sint`.
    pub cmp_compound: usize,
}

/// Runtime helpers used by the shared native line-breakpoint fragment.
#[derive(Clone, Copy, Debug, Default)]
pub struct LineBreakpointHelpers {
    /// Performs the heap check used before spilling live X registers.
    pub garbage_collect: usize,
    /// Resolves the current source location and returns `erts_internal:breakpoint/4`.
    pub prepare_call: usize,
    /// Restores the live X register prefix from the Erlang stack.
    pub cleanup: usize,
}

/// Byte offsets, from the process pointer, of the fields the light-BIF fragment's inline
/// collection test reads (`ERTS_IS_GC_DESIRED_INTERNAL`, instr_bif.cpp:488-523).
#[derive(Clone, Copy, Debug, Default)]
pub struct LightGcOffsets {
    /// `Process.heap.fragment_words` (`mbuf_sz`), a 32-bit count of words.
    pub fragment_words: u32,
    /// `Process.heap.bin_vheap` (`off_heap.overhead`).
    pub bin_vheap: u32,
    /// `Process.heap.bin_vheap_size` (`bin_vheap_sz`).
    pub bin_vheap_size: u32,
    /// `Process.gc_enabled` as a byte; clear means `F_DISABLE_GC`.
    pub gc_enabled: u32,
}

/// Runtime callbacks used by the shared export and instrumentation fragments.
#[derive(Clone, Copy, Debug, Default)]
pub struct DispatchRuntimeHelpers {
    /// Shared export-entry trampoline helper.
    pub export: usize,
    /// Shared light-BIF helper.
    pub light_bif: usize,
    /// Collection helper run when a light BIF's result leaves a collection desired
    /// (`erts_gc_after_bif_call_lhf`). Zero disables the inline GC-desired test.
    pub light_bif_gc: usize,
    /// Byte offsets of the live process fields the inline test reads, from `c_p`.
    pub light_gc: LightGcOffsets,
    /// Shared exception resolver.
    pub exception_resolver: usize,
    /// Process-saving-calls export helper.
    pub save_calls_export: usize,
    /// Unloaded-fun resolver.
    pub unloaded_fun: usize,
    /// Process-saving-calls fun helper.
    pub save_calls_fun: usize,
    /// Comparison-BIF helpers.
    pub compare: CompareHelpers,
    /// Native line-breakpoint helpers.
    pub line_breakpoint: LineBreakpointHelpers,
}

/// Sentinel `CallUnported.target_pc` for a fun call that must resume in the interpreter.
pub const CALL_FUN_UNPORTED: usize = usize::MAX - 0xF0;
/// Sentinel `CallUnported.target_pc` for `apply Arity`; the arity is in `c_p->arity`.
pub const APPLY_FIXED_UNPORTED: usize = usize::MAX - 0xF2;
/// Sentinel `CallUnported.target_pc` for `apply/2` (fun and argument list in X0/X1).
pub const APPLY2_UNPORTED: usize = usize::MAX - 0xF3;
/// Sentinel `CallUnported.target_pc` for `apply/3` (module, function, arguments in X0..X2).
pub const APPLY3_UNPORTED: usize = usize::MAX - 0xF4;
/// Identity sent through the light-BIF fragment to hand native `send` to the executor.
pub const SEND_DISPATCH_IDENTITY: usize = usize::MAX - 0xF1;
/// Identity sent through the light-BIF fragment to hand a native entry breakpoint to the
/// executor, which owns the VM and run context that tracer modules and meta tracing need.
pub const BREAKPOINT_DISPATCH_IDENTITY: usize = usize::MAX - 0xF5;

/// Top byte of the identity a native line-breakpoint site sends through the light-BIF
/// fragment; bits 32..48 hold the live X register count and bits 0..32 the source line.
const LINE_BREAKPOINT_TAG: usize = 0xF8 << 56;

/// Identity of an enabled `i_line_breakpoint_trampoline` hit at `line` with `live` X registers.
pub const fn line_breakpoint_identity(line: u32, live: u16) -> usize {
    LINE_BREAKPOINT_TAG | (live as usize) << 32 | line as usize
}

/// Decodes a legacy executor line-breakpoint identity into `(line, live)`.
pub const fn decode_line_breakpoint_identity(identity: usize) -> Option<(u32, u16)> {
    if identity >> 56 != 0xF8 {
        return None;
    }
    Some((identity as u32, (identity >> 32) as u16))
}

/// `target_pc` of the exit a traced native return takes so the executor can emit its
/// `return_to` event; `resume_pc` is the caller continuation.
pub const RETURN_TO_DISPATCH_IDENTITY: usize = usize::MAX - 0xF6;
/// `target_pc` of the exit a dirty NIF called on a normal scheduler takes, so the executor
/// can move the process to a dirty scheduler; `resume_pc` is the NIF body's return point.
pub const DIRTY_NIF_DISPATCH_IDENTITY: usize = usize::MAX - 0xF7;

impl DispatchFragments {
    /// Emits the export and light-BIF runtime fragments once for the VM.
    /// `save_calls_helper(c_p, export)` records a remote call of a process saving calls and
    /// returns the export's address in the active code index.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210 and
    // erts/emulator/beam/jit/arm/instr_bif.cpp:378-471, OTP-29.1.1.
    pub fn new(
        export_helper: usize,
        light_bif_helper: usize,
        exception_resolver: usize,
        save_calls_helper: usize,
    ) -> Result<Self, ExecError> {
        Self::with_fun_helpers(
            export_helper,
            light_bif_helper,
            exception_resolver,
            save_calls_helper,
            0,
            0,
        )
    }

    /// As [`DispatchFragments::new`], plus the fun dispatch fragments: `unloaded_fun_helper`
    /// is the `call_fun` resolver (`beam_jit_handle_unloaded_fun`) and
    /// `save_calls_fun_helper(c_p, fun)` returns the fun's address in its node's active code
    /// index.
    pub fn with_fun_helpers(
        export_helper: usize,
        light_bif_helper: usize,
        exception_resolver: usize,
        save_calls_helper: usize,
        unloaded_fun_helper: usize,
        save_calls_fun_helper: usize,
    ) -> Result<Self, ExecError> {
        Self::with_compare(
            export_helper,
            light_bif_helper,
            exception_resolver,
            save_calls_helper,
            unloaded_fun_helper,
            save_calls_fun_helper,
            CompareHelpers::default(),
        )
    }

    /// As [`DispatchFragments::with_fun_helpers`], plus the comparison fragments.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:67-131 and
    // instr_common.cpp:2113-2176, OTP-29.1.1.
    pub fn with_compare(
        export_helper: usize,
        light_bif_helper: usize,
        exception_resolver: usize,
        save_calls_helper: usize,
        unloaded_fun_helper: usize,
        save_calls_fun_helper: usize,
        compare: CompareHelpers,
    ) -> Result<Self, ExecError> {
        Self::with_line_breakpoint_helpers(DispatchRuntimeHelpers {
            export: export_helper,
            light_bif: light_bif_helper,
            // Without a collection helper the GC-desired test never fires: a test header
            // publishes zero fragment and binary sizes.
            light_bif_gc: 0,
            light_gc: LightGcOffsets::default(),
            exception_resolver,
            save_calls_export: save_calls_helper,
            unloaded_fun: unloaded_fun_helper,
            save_calls_fun: save_calls_fun_helper,
            compare,
            line_breakpoint: LineBreakpointHelpers::default(),
        })
    }

    /// As [`DispatchFragments::with_compare`], plus the line-breakpoint runtime helpers.
    pub fn with_line_breakpoint_helpers(
        helpers: DispatchRuntimeHelpers,
    ) -> Result<Self, ExecError> {
        let DispatchRuntimeHelpers {
            export: export_helper,
            light_bif: light_bif_helper,
            light_bif_gc: light_bif_gc_helper,
            light_gc: light_gc_offsets,
            exception_resolver,
            save_calls_export: save_calls_helper,
            unloaded_fun: unloaded_fun_helper,
            save_calls_fun: save_calls_fun_helper,
            compare,
            line_breakpoint: line_breakpoint_helpers,
        } = helpers;
        let mut code = CodeBuffer::new();
        let export = code.new_label();
        let light_bif = code.new_label();
        let breakpoint = code.new_label();
        let line_breakpoint = code.new_label();
        let send = code.new_label();
        let call_fun_unported = code.new_label();
        let raise_exception = code.new_label();
        let apply_fixed = code.new_label();
        let apply2 = code.new_label();
        let apply3 = code.new_label();
        let save_calls_export = code.new_label();
        let apply_fun = code.new_label();
        let unloaded_fun = code.new_label();
        let save_calls_fun = code.new_label();
        let bif_is_eq_exact = code.new_label();
        let bif_is_ne_exact = code.new_label();
        let arith_compare = code.new_label();
        code.bind(export)
            .map_err(|_error| ExecError::InvalidSize("dispatch fragment"))?;
        emit_export_fragment(&mut code, export_helper, raise_exception)
            .map_err(|_| ExecError::InvalidSize("export trampoline"))?;
        code.bind(light_bif)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_call_light_bif_shared(
            &mut code,
            light_bif_helper,
            light_bif_gc_helper,
            light_gc_offsets,
            exception_resolver,
        )
        .map_err(|_| ExecError::InvalidSize("light BIF fragment"))?;
        // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:231-250
        // (emit_i_breakpoint_trampoline), OTP-29.1.1: the trampoline passes (c_p, identity,
        // site) and a trap return. That is the helper ABI, not ARG3/ARG4 of call_light_bif_shared.
        code.bind(breakpoint)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_helper_fragment(&mut code, light_bif_helper, 6)
            .map_err(|_| ExecError::InvalidSize("breakpoint fragment"))?;
        code.bind(line_breakpoint)
            .map_err(|_error| ExecError::InvalidSize("dispatch fragment"))?;
        let line_breakpoint_cleanup =
            emit_line_breakpoint_shared(&mut code, line_breakpoint_helpers)
                .map_err(|_| ExecError::InvalidSize("line-breakpoint fragment"))?;
        code.bind(send)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_helper_fragment(&mut code, light_bif_helper, 2)
            .map_err(|_| ExecError::InvalidSize("send fragment"))?;
        code.bind(call_fun_unported)
            .map_err(|_error| ExecError::InvalidSize("dispatch fragment"))?;
        emit_unported_fragment(&mut code, CALL_FUN_UNPORTED)
            .map_err(|_| ExecError::InvalidSize("call_fun unported fragment"))?;
        for (label, sentinel) in [
            (apply_fixed, APPLY_FIXED_UNPORTED),
            (apply2, APPLY2_UNPORTED),
            (apply3, APPLY3_UNPORTED),
        ] {
            code.bind(label)
                .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
            emit_unported_fragment(&mut code, sentinel)
                .map_err(|_| ExecError::InvalidSize("apply unported fragment"))?;
        }
        code.bind(save_calls_export)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_save_calls_export_fragment(&mut code, save_calls_helper)
            .map_err(|_| ExecError::InvalidSize("save_calls export fragment"))?;
        code.bind(apply_fun)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_apply_fun_fragment(&mut code)
            .map_err(|_| ExecError::InvalidSize("apply/2 fragment"))?;
        code.bind(unloaded_fun)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_unloaded_fun_fragment(&mut code, unloaded_fun_helper, raise_exception)
            .map_err(|_| ExecError::InvalidSize("unloaded fun fragment"))?;
        code.bind(save_calls_fun)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_save_calls_fun_fragment(&mut code, save_calls_fun_helper)
            .map_err(|_| ExecError::InvalidSize("save_calls fun fragment"))?;
        code.bind(raise_exception)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_raise_exception_fragment(&mut code, exception_resolver)
            .map_err(|_| ExecError::InvalidSize("raise exception fragment"))?;
        code.bind(bif_is_eq_exact)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_bif_is_eq_exact_shared(&mut code, compare.eq)
            .map_err(|_| ExecError::InvalidSize("bif_is_eq_exact fragment"))?;
        code.bind(bif_is_ne_exact)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_bif_is_ne_exact_shared(&mut code, compare.eq)
            .map_err(|_| ExecError::InvalidSize("bif_is_ne_exact fragment"))?;
        code.bind(arith_compare)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_arith_compare_shared(&mut code, compare.cmp_atoms, compare.cmp_compound)
            .map_err(|_| ExecError::InvalidSize("arith_compare fragment"))?;
        let (words, labels) = code
            .finish_with_labels()
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let mut memory = CodeMemory::new(bytes.len().max(4))?;
        let offset = memory.alloc(bytes.len().max(4))?;
        memory.write_bytes(offset, &bytes)?;
        memory.flush_all()?;
        Ok(Self {
            memory,
            export_offset: labels[&export],
            light_bif_offset: labels[&light_bif],
            breakpoint_offset: labels[&breakpoint],
            line_breakpoint_offset: labels[&line_breakpoint],
            line_breakpoint_cleanup_offset: labels[&line_breakpoint_cleanup],
            send_offset: labels[&send],
            call_fun_unported_offset: labels[&call_fun_unported],
            apply_fixed_offset: labels[&apply_fixed],
            apply2_offset: labels[&apply2],
            apply3_offset: labels[&apply3],
            save_calls_export_offset: labels[&save_calls_export],
            apply_fun_offset: labels[&apply_fun],
            unloaded_fun_offset: labels[&unloaded_fun],
            save_calls_fun_offset: labels[&save_calls_fun],
            bif_is_eq_exact_offset: labels[&bif_is_eq_exact],
            bif_is_ne_exact_offset: labels[&bif_is_ne_exact],
            arith_compare_offset: labels[&arith_compare],
        })
    }

    /// Shared export-entry trampoline address.
    pub fn export_trampoline(&self) -> usize {
        self.memory.ptr_at(self.export_offset) as usize
    }

    /// Entry of every export in `ERTS_SAVE_CALLS_CODE_IX` (`beam_save_calls_export`).
    pub fn save_calls_export(&self) -> usize {
        self.memory.ptr_at(self.save_calls_export_offset) as usize
    }

    /// Shared light-BIF fragment address.
    pub fn call_light_bif(&self) -> usize {
        self.memory.ptr_at(self.light_bif_offset) as usize
    }

    /// Fragment the native call-breakpoint trampoline enters.
    ///
    /// The caller has already placed `c_p`, the breakpoint identity and the site in the
    /// argument registers. `call_light_bif_shared` does not read those.
    pub fn breakpoint(&self) -> usize {
        self.memory.ptr_at(self.breakpoint_offset) as usize
    }

    /// Fragment entered by the patchable `i_line_breakpoint_trampoline` call.
    pub fn line_breakpoint(&self) -> usize {
        self.memory.ptr_at(self.line_breakpoint_offset) as usize
    }

    /// Return address of the shared breakpoint-handler call's cleanup continuation.
    pub fn line_breakpoint_cleanup(&self) -> usize {
        self.memory.ptr_at(self.line_breakpoint_cleanup_offset) as usize
    }

    /// Shared `send/2` fragment with only its two live X registers saved.
    pub fn send(&self) -> usize {
        self.memory.ptr_at(self.send_offset) as usize
    }

    /// Entry that hands `apply Arity` to the interpreter (arity in `c_p->arity`).
    pub fn apply_fixed_unported(&self) -> usize {
        self.memory.ptr_at(self.apply_fixed_offset) as usize
    }

    /// Entry that hands `apply/2` to the interpreter.
    pub fn apply2_unported(&self) -> usize {
        self.memory.ptr_at(self.apply2_offset) as usize
    }

    /// Entry that hands `apply/3` to the interpreter.
    pub fn apply3_unported(&self) -> usize {
        self.memory.ptr_at(self.apply3_offset) as usize
    }

    /// `apply_fun_shared`: unpacks the `apply/2` argument list in X1 into the X registers.
    pub fn apply_fun_shared(&self) -> usize {
        self.memory.ptr_at(self.apply_fun_offset) as usize
    }

    /// Entry used when a fun has no native trampoline yet.
    pub fn call_fun_unported(&self) -> usize {
        self.memory.ptr_at(self.call_fun_unported_offset) as usize
    }

    /// Entry of every code index of a fun entry without loaded code (`beam_unloaded_fun`).
    pub fn unloaded_fun(&self) -> usize {
        self.memory.ptr_at(self.unloaded_fun_offset) as usize
    }

    /// Entry of every local fun in `ERTS_SAVE_CALLS_CODE_IX` (`beam_save_calls_fun`).
    pub fn save_calls_fun(&self) -> usize {
        self.memory.ptr_at(self.save_calls_fun_offset) as usize
    }

    /// `bif_is_eq_exact_shared`: terms in x0 and x1, `true` or `false` in x0.
    pub fn bif_is_eq_exact_shared(&self) -> usize {
        self.memory.ptr_at(self.bif_is_eq_exact_offset) as usize
    }

    /// `bif_is_ne_exact_shared`: terms in x0 and x1, `true` or `false` in x0.
    pub fn bif_is_ne_exact_shared(&self) -> usize {
        self.memory.ptr_at(self.bif_is_ne_exact_offset) as usize
    }

    /// `arith_compare_shared`: terms in x0 and x1, the relation left in the flags.
    pub fn arith_compare_shared(&self) -> usize {
        self.memory.ptr_at(self.arith_compare_offset) as usize
    }
}

/// Highest number of `apply/2` arguments: erts bails at MAX_REG - 1, as the highest X
/// register is reserved for the loader.
const APPLY_MAX_ARGS: u16 = 1024 - 1;

// Registers of the comparison fragments, named after erts' ARG*/TMP* (arm/beam_asm.hpp).
const ARG1: Gpr = Gpr::x(0);
const ARG2: Gpr = Gpr::x(1);
const TMP1: Gpr = Gpr::x(8);
const TMP2: Gpr = Gpr::x(9);
const TMP3: Gpr = Gpr::x(10);
const TMP4: Gpr = Gpr::x(11);
const TMP5: Gpr = Gpr::x(12);
/// `TAG_PRIMARY_IMMED1` / `_TAG_PRIMARY_MASK`.
const TAG_PRIMARY_IMMED1: u64 = 3;
/// `_TAG_IMMED2_MASK` and `_TAG_IMMED2_ATOM`.
const TAG_IMMED2_MASK: u64 = 0x3f;
const TAG_IMMED2_ATOM: u16 = 0x0b;
/// `HEADER_FLONUM` (`_make_header(1, _TAG_HEADER_FLOAT)`).
const HEADER_FLONUM: u64 = (1 << 6) | 0x18;
/// `am_false` / `am_true` (`make_atom(0)` / `make_atom(1)`).
const AM_FALSE: u64 = 0x0b;
const AM_TRUE: u64 = 0x4b;

// Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:67-99 (emit_bif_is_eq_exact_shared),
// OTP-29.1.1. ARG1 and ARG2 are the terms; the atom `true` or `false` is returned in ARG1.
fn emit_bif_is_eq_exact_shared(code: &mut CodeBuffer, eq: usize) -> Result<(), BufferError> {
    let succ = code.new_label();
    let fail = code.new_label();
    code.emit(|e| e.cmp_reg(ARG1, ARG2, Shift::Lsl, 0))?;
    code.b_cond(Cond::Eq, succ)?;
    emit_is_unequal_based_on_tags(code)?;
    code.b_cond(Cond::Eq, fail)?;
    emit_framed_call(code, eq, false)?;
    code.cbz(Gpr::w(0), fail)?;
    code.bind(succ)?;
    code.emit(|e| {
        e.mov_const(ARG1, AM_TRUE)?;
        e.ret(Gpr::x(30))
    })?;
    code.bind(fail)?;
    code.emit(|e| {
        e.mov_const(ARG1, AM_FALSE)?;
        e.ret(Gpr::x(30))
    })
}

// Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp:101-131 (emit_bif_is_ne_exact_shared),
// OTP-29.1.1.
fn emit_bif_is_ne_exact_shared(code: &mut CodeBuffer, eq: usize) -> Result<(), BufferError> {
    let succ = code.new_label();
    let fail = code.new_label();
    code.emit(|e| e.cmp_reg(ARG1, ARG2, Shift::Lsl, 0))?;
    code.b_cond(Cond::Eq, fail)?;
    emit_is_unequal_based_on_tags(code)?;
    code.b_cond(Cond::Eq, succ)?;
    emit_framed_call(code, eq, false)?;
    code.cbnz(Gpr::w(0), fail)?;
    code.bind(succ)?;
    code.emit(|e| {
        e.mov_const(ARG1, AM_TRUE)?;
        e.ret(Gpr::x(30))
    })?;
    code.bind(fail)?;
    code.emit(|e| {
        e.mov_const(ARG1, AM_FALSE)?;
        e.ret(Gpr::x(30))
    })
}

// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:698-711 (emit_is_unequal_based_on_tags),
// OTP-29.1.1. Z is set when the tags alone prove the terms differ.
fn emit_is_unequal_based_on_tags(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let super_tmp = Gpr::x(14);
    code.emit(|e| {
        e.orr_reg(
            super_tmp,
            ARG1,
            Shifted {
                reg: ARG2,
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.and_imm(super_tmp, super_tmp, TAG_PRIMARY_IMMED1)?;
        e.cmp_imm(super_tmp, TAG_PRIMARY_IMMED1 as u16, false)
    })
}

// Port of erts/emulator/beam/jit/arm/instr_common.cpp:2113-2176 (emit_arith_compare_shared),
// OTP-29.1.1. The relation is returned in the flags (the same codes `cmp` / `fcmpe` set).
fn emit_arith_compare_shared(
    code: &mut CodeBuffer,
    cmp_atoms: usize,
    cmp_compound: usize,
) -> Result<(), BufferError> {
    let atom_compare = code.new_label();
    let generic_compare = code.new_label();
    code.emit(|e| {
        e.orr_reg(
            TMP1,
            ARG1,
            Shifted {
                reg: ARG2,
                shift: Shift::Lsl,
                amount: 0,
            },
        )
    })?;
    // Not boxed: bit 0 of the primary tag is set (`emit_is_boxed`).
    code.tbnz(TMP1, 0, atom_compare)?;
    // `emit_ptr_val` is the identity when literals are not a distinct pointer tag, so the
    // header is at the tagged pointer minus `TAG_PRIMARY_BOXED`.
    code.emit(|e| {
        e.ldur(TMP3, ARG1, -2)?;
        e.ldur(TMP4, ARG2, -2)?;
        e.mov_const(TMP5, HEADER_FLONUM)?;
        e.cmp_reg(TMP3, TMP5, Shift::Lsl, 0)?;
        e.ccmp_reg(TMP4, TMP5, 0, Cond::Eq)
    })?;
    code.b_cond(Cond::Ne, generic_compare)?;
    code.emit(|e| {
        e.ldur_d(VecReg(0), ARG1, 6)?;
        e.ldur_d(VecReg(1), ARG2, 6)?;
        e.fcmpe(VecReg(0), VecReg(1))?;
        e.ret(Gpr::x(30))
    })?;

    code.bind(atom_compare)?;
    code.emit(|e| {
        e.and_imm(TMP1, ARG1, TAG_IMMED2_MASK)?;
        e.and_imm(TMP2, ARG2, TAG_IMMED2_MASK)?;
        e.sub_imm(TMP1, TMP1, TAG_IMMED2_ATOM, false)?;
        e.sub_imm(TMP2, TMP2, TAG_IMMED2_ATOM, false)?;
        e.orr_reg(
            TMP1,
            TMP1,
            Shifted {
                reg: TMP2,
                shift: Shift::Lsl,
                amount: 0,
            },
        )
    })?;
    code.cbnz(TMP1, generic_compare)?;
    emit_framed_call(code, cmp_atoms, false)?;
    code.emit(|e| {
        e.tst_reg(Gpr::w(0), Gpr::w(0), Shift::Lsl, 0)?;
        e.ret(Gpr::x(30))
    })?;

    code.bind(generic_compare)?;
    emit_framed_call(code, cmp_compound, true)?;
    code.emit(|e| {
        e.tst_reg(ARG1, ARG1, Shift::Lsl, 0)?;
        e.ret(Gpr::x(30))
    })
}

// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:437-445,459-536,539-601
// (emit_enter_runtime_frame / emit_enter_runtime<0> / emit_leave_runtime / emit_leave_runtime_frame),
// OTP-29.1.1. `zero_extra` loads the two trailing zeros of `erts_cmp_compound(X, Y, 0, 0)`.
fn emit_framed_call(
    code: &mut CodeBuffer,
    target: usize,
    zero_extra: bool,
) -> Result<(), BufferError> {
    code.emit(|e| {
        e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        e.mov_reg(Gpr::x(29), Gpr::sp())
    })?;
    emit_enter_runtime(code, 6, Update::NONE)?;
    code.emit(|e| {
        if zero_extra {
            e.mov_reg(Gpr::x(2), Gpr::xzr())?;
            e.mov_reg(Gpr::x(3), Gpr::xzr())?;
        }
        e.mov_const(Gpr::x(17), target as u64)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, Update::NONE)?;
    code.emit(|e| {
        e.mov_reg(Gpr::sp(), Gpr::x(29))?;
        e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)
    })
}

// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:253-328 (emit_apply_fun_shared), OTP-29.1.1:
// the fun (X0) goes to x4 and the arity to x2 for `call_fun`; x0 is zero once every argument is
// in the X registers. A malformed list or one with too many elements returns nonzero with X0
// and X1 untouched, and the caller hands the apply to the interpreter, which raises
// badarg/system_limit for erlang:apply/2 like erts' error path.
fn emit_apply_fun_fragment(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let unpack_next = code.new_label();
    let malformed_list = code.new_label();
    let finished = code.new_label();
    code.emit(|e| {
        e.mov_reg(Gpr::x(2), Gpr::xzr())?;
        e.mov_reg(Gpr::x(4), Gpr::x(25))?;
        e.mov_reg(Gpr::x(5), Gpr::x(26))
    })?;
    // No X register is live: the arguments are written straight to the X register array.
    emit_enter_runtime(code, 0, Update::X_REGS)?;
    code.emit(|e| {
        e.mov_reg(Gpr::x(9), Gpr::x(5))?;
        e.mov_reg(Gpr::x(10), Gpr::x(19))
    })?;
    code.bind(unpack_next)?;
    code.emit(|e| e.cmp_imm(Gpr::x(9), 0x3b, false))?;
    code.b_cond(Cond::Eq, finished)?;
    // _TAG_PRIMARY_MASK - TAG_PRIMARY_LIST == 1 << 1: anything but a cons has bit 1 set.
    code.tbnz(Gpr::x(9), 1, malformed_list)?;
    code.emit(|e| {
        e.sub_imm(Gpr::x(9), Gpr::x(9), 1, false)?;
        e.ldp(Gpr::x(11), Gpr::x(9), Gpr::x(9), 0)?;
        e.str_post(Gpr::x(11), Gpr::x(10), 8)?;
        e.add_imm(Gpr::x(2), Gpr::x(2), 1, false)?;
        e.cmp_imm(Gpr::x(2), APPLY_MAX_ARGS, false)
    })?;
    code.b_cond(Cond::Cc, unpack_next)?;
    code.bind(malformed_list)?;
    emit_leave_runtime(code, 0, Update::X_REGS)?;
    code.emit(|e| {
        e.mov_const(Gpr::x(0), 1)?;
        e.ret(Gpr::x(30))
    })?;
    code.bind(finished)?;
    emit_leave_runtime(code, 6, Update::X_REGS)?;
    code.emit(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
}

// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210, OTP-29.1.1.
fn emit_export_fragment(
    code: &mut CodeBuffer,
    helper: usize,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    let interpreted = code.new_label();
    code.emit(|encoder| {
        // Interpreted targets have no native prologue to save this continuation.
        encoder.str_pre(Gpr::x(30), Gpr::x(20), -8)?;
        encoder.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -32)?;
        encoder.mov_reg(Gpr::x(29), Gpr::sp())?;
        encoder.str_uoff(Gpr::x(1), Gpr::sp(), 16)?;
        // The caller supplies c_p in x0 and the export identity in x1.
        Ok(())
    })?;
    let helper_call = code.new_label();
    let direct_done = code.new_label();
    let direct_non_value = code.new_label();
    let return_term = code.new_label();
    code.emit(|encoder| {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:730-776 (call_bif_shared),
        // OTP-29.1.1: a BIF export calls `bif_table[].f` directly. The pointer is the
        // one published on the export; zero stays on the helper (ordinary remote calls).
        encoder.ldr_uoff(Gpr::x(8), Gpr::x(1), crate::bif::EXPORT_LIGHT_BIF_OFFSET)
    })?;
    code.cbz(Gpr::x(8), helper_call)?;
    code.emit(|encoder| {
        // A traced BIF still goes through the helper. Save-calls does not: that
        // code index already entered `save_calls_export` (beam_asm_global.cpp:164).
        // call_bif_shared itself has no trace check; the light fragment does
        // (instr_bif.cpp:388-397) and an export entry has not.
        encoder.ldr_uoff(
            Gpr::w(9),
            Gpr::x(1),
            crate::bif::EXPORT_IS_BIF_TRACED_OFFSET,
        )?;
        encoder.cmp_imm(Gpr::w(9), 0, false)?;
        Ok(())
    })?;
    code.b_cond(Cond::Ne, helper_call)?;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:723-725, OTP-29.1.1:
    // reductions are checked in module code, not in the BIF trampoline.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1.
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        // c_p->arity from the export, then (c_p, reg, I, Export.info). x4 stays
        // the Export* the call site loaded. `info` is the descriptor, the same
        // word the helper path loads; the BIF does not look the export up.
        encoder.ldrb_uoff(Gpr::w(9), Gpr::x(1), crate::bif::EXPORT_ARITY_OFFSET as u16)?;
        encoder.strb_uoff(Gpr::w(9), Gpr::x(21), 80)?;
        encoder.ldr_uoff(Gpr::x(3), Gpr::x(1), crate::bif::EXPORT_INFO_OFFSET)?;
        encoder.mov_reg(Gpr::x(4), Gpr::x(1))?;
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
        encoder.blr(Gpr::x(8))
    })?;
    code.b(direct_done)?;
    code.bind(helper_call)?;
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        // Port of erts/emulator/beam/beam_jit_common.cpp (beam_jit_bif trampolines read the
        // BIF from their own Export), OTP-29.1.1: x2 = the export's descriptor word.
        encoder.ldr_uoff(Gpr::x(2), Gpr::x(1), crate::bif::EXPORT_INFO_OFFSET)?;
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:539-601, OTP-29.1.1.
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| encoder.cmp_imm(Gpr::x(0), 0, false))?;
    code.b_cond(Cond::Eq, raise_exception)?;
    code.emit(|encoder| encoder.cmp_imm(Gpr::x(0), 1, false))?;
    code.b_cond(Cond::Eq, interpreted)?;
    code.b(return_term)?;
    code.bind(direct_done)?;
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.cbz(Gpr::x(0), direct_non_value)?;
    code.b(return_term)?;
    code.bind(direct_non_value)?;
    code.emit(|encoder| {
        // THE_NON_VALUE with freason == TRAP, or with no reason, is the executor
        // handoff (the helper's sentinel 1). Any other reason is the exception.
        encoder.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)?;
        encoder.cmp_imm(Gpr::x(9), TRAP_REASON, false)
    })?;
    code.b_cond(Cond::Eq, interpreted)?;
    code.emit(|encoder| encoder.cmp_imm(Gpr::x(9), 0, false))?;
    code.b_cond(Cond::Eq, interpreted)?;
    code.b(raise_exception)?;
    // A BIF returns its term in x0. The continuation pushed on entry stays on E.
    code.bind(return_term)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(25), Gpr::x(0))?;
        encoder.ldr_post(Gpr::x(9), Gpr::x(20), 8)?;
        encoder.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 32)?;
        encoder.ret(Gpr::x(30))
    })?;
    code.bind(interpreted)?;
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(17), Gpr::sp(), 16)?;
        encoder.add_imm(Gpr::sp(), Gpr::sp(), 32, false)?;
        encoder.mov_const(Gpr::x(0), 2)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(17))?;
        // The native call site is the CP pushed on entry; it names the calling module.
        encoder.ldr_uoff(Gpr::x(2), Gpr::x(20), 0)?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(())
}

/// Records a remote call of a process saving calls, then continues through the export's
/// address in the active code index. The export entry is in x1 and the return address in
/// x30; both are preserved since this runs between caller and callee.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:123-148 (emit_dispatch_save_calls_export),
// OTP-29.1.1.
fn emit_save_calls_export_fragment(
    code: &mut CodeBuffer,
    helper: usize,
) -> Result<(), BufferError> {
    code.emit(|encoder| encoder.stp_pre(Gpr::x(30), Gpr::x(1), Gpr::sp(), -16))?;
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.ldr_uoff(Gpr::x(2), Gpr::x(1), crate::bif::EXPORT_INFO_OFFSET)?;
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))?;
        encoder.mov_reg(Gpr::x(17), Gpr::x(0))
    })?;
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.ldp_post(Gpr::x(30), Gpr::x(1), Gpr::sp(), 16)?;
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.br(Gpr::x(17))
    })
}

/// Calls a fun whose entry has no code in the active code index. Entered from a `call_fun`
/// site between caller and callee: x2 = expected fun header bits, x4 = fun, x30 = the caller's continuation.
/// The helper either returns the address to continue with (the interpreter's fun call for an
/// unloaded fun, which runs the error handler) or zero with the exception set, raised with the
/// call site as the current pc.
// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:34-62 (emit_unloaded_fun), OTP-29.1.1.
fn emit_unloaded_fun_fragment(
    code: &mut CodeBuffer,
    helper: usize,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    let error = code.new_label();
    code.emit(|encoder| {
        // emit_enter_runtime_frame: only a native frame. E stays the caller's, so the runtime
        // sees the caller's stack like beam_jit_handle_unloaded_fun does in erts; the
        // continuation (erts keeps ARG5 in TMP_MEM1q) is saved in the native frame.
        encoder.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -32)?;
        encoder.mov_reg(Gpr::x(29), Gpr::sp())?;
        encoder.stp(Gpr::x(2), Gpr::x(4), Gpr::sp(), 16)
    })?;
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.ldp(Gpr::x(2), Gpr::x(1), Gpr::sp(), 16)?;
        encoder.lsr_imm(Gpr::x(2), Gpr::x(2), 8)?;
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))?;
        encoder.mov_reg(Gpr::x(17), Gpr::x(0))
    })?;
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.cbz(Gpr::x(17), error)?;
    code.emit(|encoder| {
        encoder.ldp(Gpr::x(2), Gpr::x(4), Gpr::sp(), 16)?;
        encoder.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 32)?;
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.br(Gpr::x(17))
    })?;
    code.bind(error)?;
    // erts raises with ARG2 = the saved call site; the shared raise fragment here reads the
    // exception pc from the top of E and pops the native frame itself.
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(9), Gpr::sp(), 8)?;
        encoder.str_pre(Gpr::x(9), Gpr::x(20), -8)
    })?;
    code.b(raise_exception)
}

/// Continues a local fun call of a process saving calls with its node's active code index.
/// x4 = fun and x30 = return address are preserved: this runs between caller and callee.
// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:139-149 (emit_dispatch_save_calls_fun),
// OTP-29.1.1. erts reads the one `the_active_code_index`; each node here has its own, which
// the helper reads.
fn emit_save_calls_fun_fragment(code: &mut CodeBuffer, helper: usize) -> Result<(), BufferError> {
    code.emit(|encoder| {
        encoder.stp_pre(Gpr::x(30), Gpr::x(4), Gpr::sp(), -32)?;
        encoder.stp(Gpr::x(1), Gpr::x(2), Gpr::sp(), 16)
    })?;
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.ldr_uoff(Gpr::x(1), Gpr::sp(), 8)?;
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))?;
        encoder.mov_reg(Gpr::x(17), Gpr::x(0))
    })?;
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.ldp(Gpr::x(1), Gpr::x(2), Gpr::sp(), 16)?;
        encoder.ldp_post(Gpr::x(30), Gpr::x(4), Gpr::sp(), 32)?;
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.br(Gpr::x(17))
    })
}

// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:220-286, OTP-29.1.1.
fn emit_raise_exception_fragment(
    code: &mut CodeBuffer,
    resolver: usize,
) -> Result<(), BufferError> {
    let exit = code.new_label();
    // The export trampoline's BEAM continuation remains on E as the current
    // exception PC; only its host ABI frame is removed here.
    code.emit(|encoder| {
        encoder.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 32)?;
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
        encoder.mov_reg(Gpr::x(2), Gpr::x(20))?;
        encoder.mov_const(Gpr::x(17), resolver as u64)?;
        encoder.blr(Gpr::x(17))
    })?;
    code.cbz(Gpr::x(0), exit)?;
    // handle_error wrote reg[0..3] (non-value, reason, raw trace, class) and
    // the catch frame's E. Reload them: the resolver is a runtime call, so the
    // X cache and the heap/stack cursors are stale.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:327-334
    // (leave_runtime then br to the handler) and beam_common.c:541-561, OTP-29.1.1.
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(25), Gpr::x(19), 0)?;
        encoder.ldr_uoff(Gpr::x(26), Gpr::x(19), 8)?;
        encoder.ldr_uoff(Gpr::x(27), Gpr::x(19), 16)?;
        encoder.ldr_uoff(Gpr::x(28), Gpr::x(19), 24)?;
        encoder.ldr_uoff(Gpr::x(20), Gpr::x(21), 8)?;
        encoder.ldr_uoff(Gpr::x(23), Gpr::x(21), 0)?;
        encoder.br(Gpr::x(0))
    })?;
    code.bind(exit)?;
    // The host frame was already popped above; only the exit bridge remains.
    code.emit(|encoder| {
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })
}

/// Shared body of every `call_light_bif`.
///
/// On entry ARG3 (`x3`) is the call's entry address and ARG4 (`x4`) is the export.
/// The fragment charges one reduction, calls the BIF helper, and either returns with
/// the result in XREG0 or leaves native code on a trap, an error or a yield.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-593 (emit_call_light_bif_shared),
// OTP-29.1.1.
fn emit_call_light_bif_shared(
    code: &mut CodeBuffer,
    helper: usize,
    gc_helper: usize,
    gc: LightGcOffsets,
    resolver: usize,
) -> Result<(), BufferError> {
    let trace = code.new_label();
    let yield_bif = code.new_label();
    let success = code.new_label();
    let store = code.new_label();
    let gc_after_bif = code.new_label();
    let not_value = code.new_label();
    let trap = code.new_label();
    let scheduler_error = code.new_label();
    // Host frame: x29, x30, the Export* (x4, reloaded by the GC path), and the result
    // (spilled only on the GC path). It is 32 bytes so the pops below use one offset.
    let frame_pointer_slot =
        std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32 + 2 * 8;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:384-387, OTP-29.1.1:
    // spill the entry before the trace check. The trace path never returns here, and
    // the scheduler names the caller from this slot (`native_error_pc` / `tmp_mem[6]`).
    code.emit(|encoder| encoder.str_uoff(Gpr::x(3), Gpr::x(19), 16_432))?;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:388-397, OTP-29.1.1:
    // a traced BIF, or a process saving calls, dispatches through the export entry.
    code.emit(|encoder| {
        encoder.ldr_uoff(
            Gpr::w(9),
            Gpr::x(4),
            crate::bif::EXPORT_IS_BIF_TRACED_OFFSET,
        )?;
        encoder.cmp_imm(Gpr::w(9), 0, false)?;
        encoder.ccmp_imm(
            Gpr::x(24),
            crate::bif::ERTS_SAVE_CALLS_CODE_IX as u8,
            4,
            Cond::Eq,
        )
    })?;
    code.b_cond(Cond::Eq, trace)?;
    code.emit(|encoder| encoder.subs_imm(Gpr::w(22), Gpr::w(22), 1, false))?;
    code.b_cond(Cond::Le, yield_bif)?;
    code.emit(|encoder| {
        encoder.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -32)?;
        encoder.str_uoff(Gpr::x(4), Gpr::sp(), 16)?;
        encoder.mov_reg(Gpr::x(29), Gpr::sp())?;
        Ok(())
    })?;
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    let helper_call = code.new_label();
    let after_bif = code.new_label();
    code.emit(|encoder| {
        // `emit_enter_runtime_frame` made x29 the host frame, and `emit_enter_runtime`
        // stored that into `tmp_mem[2]`. The Erlang frame pointer is the x29 saved at
        // `[sp]`; the light trap path reads `tmp_mem[2]` as that pointer.
        // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:437-440 (emit_enter_runtime_frame),
        // OTP-29.1.1, with the same repair as `emit_helper_fragment`.
        encoder.ldr_uoff(Gpr::x(9), Gpr::sp(), 0)?;
        encoder.str_uoff(Gpr::x(9), Gpr::x(19), frame_pointer_slot)?;
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:434-445, OTP-29.1.1:
        // `dynamic_runtime_call<3>(ARG8)` of the BIF itself. A zero pointer is a BIF
        // the helper still dispatches (traps, the executor, save_calls already branched).
        encoder.ldr_uoff(Gpr::x(8), Gpr::x(4), crate::bif::EXPORT_LIGHT_BIF_OFFSET)
    })?;
    code.cbz(Gpr::x(8), helper_call)?;
    code.emit(|encoder| {
        // (c_p, reg, I, Export.info). x19 is the register array; the entry pc was
        // spilled at the top. ARG4 stays the Export* the call site loaded
        // (instr_bif.cpp:434-445). `info` is the descriptor, the same word the
        // helper path loads; the BIF does not look the export up.
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
        encoder.ldr_uoff(Gpr::x(2), Gpr::x(19), 16_432)?;
        encoder.ldr_uoff(Gpr::x(3), Gpr::x(4), crate::bif::EXPORT_INFO_OFFSET)?;
        encoder.blr(Gpr::x(8))
    })?;
    code.b(after_bif)?;
    code.bind(helper_call)?;
    code.emit(|encoder| {
        // x0 = c_p, x1 = export, x2 = export (site; breakpoints use a real one),
        // x3 = the export's descriptor word.
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(4))?;
        encoder.mov_reg(Gpr::x(2), Gpr::x(4))?;
        encoder.ldr_uoff(Gpr::x(3), Gpr::x(4), crate::bif::EXPORT_INFO_OFFSET)?;
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))
    })?;
    code.bind(after_bif)?;
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| encoder.cmp_imm(Gpr::x(0), THE_NON_VALUE, false))?;
    code.b_cond(Cond::Ne, success)?;
    code.bind(not_value)?;
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)?;
        encoder.cmp_imm(Gpr::x(9), TRAP_REASON, false)
    })?;
    code.b_cond(Cond::Eq, trap)?;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:539-545 (`raise_exception_shared`),
    // OTP-29.1.1. A catch stays in this fragment. No catch, or a null resolver, returns
    // to the scheduler so `handle_error` keeps the BIF frame.
    code.emit(|encoder| {
        encoder.mov_const(Gpr::x(17), resolver as u64)?;
        encoder.ldr_uoff(Gpr::x(9), Gpr::x(21), 0x40)
    })?;
    code.cbz(Gpr::x(17), scheduler_error)?;
    code.cbz(Gpr::x(9), scheduler_error)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
        encoder.mov_reg(Gpr::x(2), Gpr::x(20))?;
        encoder.blr(Gpr::x(17))
    })?;
    code.cbz(Gpr::x(0), scheduler_error)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(17), Gpr::x(0))?;
        encoder.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 32)?;
        encoder.ldr_uoff(Gpr::x(25), Gpr::x(19), 0)?;
        encoder.ldr_uoff(Gpr::x(26), Gpr::x(19), 8)?;
        encoder.ldr_uoff(Gpr::x(27), Gpr::x(19), 16)?;
        encoder.ldr_uoff(Gpr::x(28), Gpr::x(19), 24)?;
        encoder.ldr_uoff(Gpr::x(20), Gpr::x(21), 8)?;
        encoder.ldr_uoff(Gpr::x(23), Gpr::x(21), 0)?;
        encoder.ldr_uoff(Gpr::w(22), Gpr::x(21), 32)?;
        encoder.br(Gpr::x(17))
    })?;
    code.bind(scheduler_error)?;
    // `emit_leave_runtime` reloaded x29 from `tmp_mem[2]` (the Erlang frame pointer).
    // Pop the host frame without restoring that saved x29: it is the entry-time
    // pointer, and a collection may have moved it.
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(30), Gpr::sp(), 8)?;
        encoder.add_imm(Gpr::sp(), Gpr::sp(), 32, false)?;
        encoder.ldr_uoff(Gpr::x(30), Gpr::x(19), 16_416)?;
        encoder.br(Gpr::x(30))
    })?;
    code.bind(success)?;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:488-523 (ERTS_IS_GC_DESIRED_INTERNAL),
    // OTP-29.1.1: the test reads the live process fields (`F_DISABLE_GC`, `mbuf_sz`,
    // `off_heap.overhead`, `bin_vheap_sz`) and the header's `htop`/`stop`, as erts does.
    // Without a collection helper no test is emitted (test fragments use zero sizes).
    if gc_helper != 0 {
        // Same shape as erts' ERTS_IS_GC_DESIRED_INTERNAL: Z is set when collection is
        // enabled, and each ccmp either compares or forces the flags that make `lt` true.
        // NZCV constants are erts' NZCV::kCF (C) and NZCV::kVF (V).
        const NZCV_CF: u8 = 0b0010;
        const NZCV_VF: u8 = 0b0001;
        code.emit(|encoder| {
            encoder.ldrb_uoff(Gpr::w(9), Gpr::x(21), gc.gc_enabled as u16)?;
            encoder.cmp_imm(Gpr::w(9), 1, false)?;
            encoder.ldr_uoff(Gpr::x(12), Gpr::x(21), gc.bin_vheap)?;
            encoder.ldr_uoff(Gpr::x(13), Gpr::x(21), gc.bin_vheap_size)?;
            // Enabled: overhead against bin_vheap_sz. Disabled: C is set, so the next
            // condition fails and collection is taken.
            encoder.ccmp_reg(Gpr::x(12), Gpr::x(13), NZCV_CF, Cond::Eq)?;
            encoder.ldr_uoff(Gpr::x(10), Gpr::x(21), 0)?;
            encoder.ldr_uoff(Gpr::x(9), Gpr::x(21), 8)?;
            encoder.sub_reg(Gpr::x(9), Gpr::x(9), Gpr::x(10), Shift::Lsl, 0)?;
            encoder.asr_imm(Gpr::x(9), Gpr::x(9), 3)?;
            encoder.ldr_uoff(Gpr::w(11), Gpr::x(21), gc.fragment_words)?;
            // Unless the binary test said "no collection" (LS), the flags force `lt`.
            encoder.ccmp_reg(Gpr::x(9), Gpr::x(11), NZCV_VF, Cond::Ls)
        })?;
        code.b_cond(Cond::Lt, gc_after_bif)?;
    }
    code.bind(store)?;
    code.emit(|encoder| {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:518-523, OTP-29.1.1.
        // x29 stays the Erlang frame pointer `emit_leave_runtime` reloaded.
        // FCALLS may be 0 (`ERTS_VBUMP_ALL_REDS`); the next checked instruction
        // yields. Returning here keeps the current code index, so the call that
        // follows `process_flag(save_calls, _)` is not itself recorded.
        encoder.mov_reg(Gpr::x(25), Gpr::x(0))?;
        encoder.ldr_uoff(Gpr::x(30), Gpr::sp(), 8)?;
        encoder.add_imm(Gpr::sp(), Gpr::sp(), 32, false)?;
        encoder.ret(Gpr::x(30))
    })?;
    if gc_helper != 0 {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:549-570 (gc_after_bif_call), OTP-29.1.1:
        // the result is spilled, the runtime is entered as for the BIF, and the collection
        // keeps the arguments live. A zero result is an error that `not_value` raises.
        code.bind(gc_after_bif)?;
        code.emit(|encoder| {
            encoder.str_uoff(Gpr::x(0), Gpr::sp(), 24)?;
            encoder.ldr_uoff(Gpr::x(9), Gpr::sp(), 0)?;
            encoder.str_uoff(Gpr::x(9), Gpr::x(19), frame_pointer_slot)
        })?;
        emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
        code.emit(|encoder| {
            encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
            encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
            encoder.ldr_uoff(Gpr::x(2), Gpr::sp(), 24)?;
            encoder.ldr_uoff(Gpr::x(9), Gpr::sp(), 16)?;
            encoder.ldr_uoff(Gpr::x(3), Gpr::x(9), crate::bif::EXPORT_INFO_OFFSET)?;
            encoder.mov_const(Gpr::x(17), gc_helper as u64)?;
            encoder.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
        code.emit(|encoder| encoder.cmp_imm(Gpr::x(0), THE_NON_VALUE, false))?;
        code.b_cond(Cond::Eq, not_value)?;
        code.b(store)?;
    }
    code.bind(trap)?;
    code.emit(|encoder| {
        // The bl that entered this fragment left the continuation in x30, saved in the
        // frame. That is the address a trapping BIF returns to, with the result in XREG0.
        encoder.ldr_uoff(Gpr::x(17), Gpr::sp(), 8)?;
        encoder.str_pre(Gpr::x(17), Gpr::x(20), -8)?;
        encoder.ldr_uoff(Gpr::x(1), Gpr::x(21), 72)?;
        encoder.mov_reg(Gpr::x(2), Gpr::x(17))?;
        encoder.mov_reg(Gpr::x(9), Gpr::xzr())?;
        encoder.str_uoff(Gpr::x(9), Gpr::x(21), 40)?;
        encoder.mov_const(Gpr::x(0), 2)
    })?;
    emit_restore_and_exit_frame(code, 32)?;
    code.bind(yield_bif)?;
    code.emit(|encoder| {
        // c_p->i = entry, c_p->arity = the export's arity, then the yield bridge.
        encoder.str_uoff(Gpr::x(3), Gpr::x(21), 72)?;
        encoder.ldrb_uoff(Gpr::w(8), Gpr::x(4), crate::bif::EXPORT_ARITY_OFFSET as u16)?;
        encoder.strb_uoff(Gpr::w(8), Gpr::x(21), 80)?;
        Ok(())
    })?;
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_const(Gpr::x(30), arinsal_enter_native_yield as *const () as u64)?;
        encoder.ret(Gpr::x(30))
    })?;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:578-581 and
    // beam_asm.hpp:388-403 (emit_setup_dispatchable_call), OTP-29.1.1.
    code.bind(trace)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(4))?;
        encoder.ldr_regoff(Gpr::x(14), Gpr::x(4), Gpr::x(24), 3)?;
        encoder.br(Gpr::x(14))
    })?;
    Ok(())
}

// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:527-540, OTP-29.1.1.
fn emit_helper_fragment(
    code: &mut CodeBuffer,
    helper: usize,
    live: usize,
) -> Result<(), BufferError> {
    code.emit(|encoder| {
        encoder.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        encoder.mov_reg(Gpr::x(29), Gpr::sp())?;
        Ok(())
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1.
    emit_enter_runtime(code, live, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        // Preserve the Erlang FP separately; x29 is the temporary host FP for this wrapper.
        // Port of beam_asm.hpp:437-440 (emit_enter_runtime_frame), OTP-29.1.1.
        let frame_pointer_slot =
            std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32 + 2 * 8;
        encoder.ldr_uoff(Gpr::x(9), Gpr::sp(), 0)?;
        encoder.str_uoff(Gpr::x(9), Gpr::x(19), frame_pointer_slot)?;
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))?;
        Ok(())
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:539-601, OTP-29.1.1.
    emit_leave_runtime(code, live, RUNTIME_UPDATE)?;
    let normal = code.new_label();
    let trap = code.new_label();
    code.emit(|encoder| encoder.cmp_imm(Gpr::x(0), THE_NON_VALUE, false))?;
    code.b_cond(arinsal_a64::enc::Cond::Ne, normal)?;
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)?;
        encoder.cmp_imm(Gpr::x(9), TRAP_REASON, false)
    })?;
    code.b_cond(arinsal_a64::enc::Cond::Ne, normal)?;
    code.bind(trap)?;
    code.emit(|encoder| {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:533-540, OTP-29.1.1.
        // The context switch resumes at c_p->i; its caller continuation stays on E.
        // That continuation is the call site's trap return, where the trap target
        // returns its result in XREG0; sites without one resume behind this call.
        encoder.ldr_uoff(Gpr::x(17), Gpr::x(19), crate::TRAP_RETURN_OFFSET as u32)?;
        encoder.str_uoff(Gpr::xzr(), Gpr::x(19), crate::TRAP_RETURN_OFFSET as u32)?;
        Ok(())
    })?;
    let continuation = code.new_label();
    code.cbnz(Gpr::x(17), continuation)?;
    code.emit(|encoder| encoder.ldr_uoff(Gpr::x(17), Gpr::sp(), 8))?;
    code.bind(continuation)?;
    code.emit(|encoder| {
        encoder.str_pre(Gpr::x(17), Gpr::x(20), -8)?;
        encoder.ldr_uoff(Gpr::x(1), Gpr::x(21), 72)?;
        encoder.mov_reg(Gpr::x(2), Gpr::x(17))?;
        encoder.mov_reg(Gpr::x(9), Gpr::xzr())?;
        encoder.str_uoff(Gpr::x(9), Gpr::x(21), 40)?;
        encoder.mov_const(Gpr::x(0), 2)
    })?;
    emit_restore_and_exit(code)?;
    code.bind(normal)?;
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(30), Gpr::sp(), 8)?;
        encoder.add_imm(Gpr::sp(), Gpr::sp(), 16, false)?;
        encoder.ret(Gpr::x(30))
    })?;
    Ok(())
}

// Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:257-334
// (emit_i_line_breakpoint_trampoline_shared), OTP-29.1.1.
fn emit_line_breakpoint_shared(
    code: &mut CodeBuffer,
    helpers: LineBreakpointHelpers,
) -> Result<arinsal_a64::buf::Label, BufferError> {
    let after_gc = code.new_label();
    let no_handler = code.new_label();
    let cleanup = code.new_label();
    let error = code.new_label();
    let exit = code.new_label();
    let live_slot = tmp_mem_offset(0);
    let pc_slot = tmp_mem_offset(1);
    let stack_needed_slot = tmp_mem_offset(3);
    let native_error_pc_slot = tmp_mem_offset(6);

    code.emit(|encoder| {
        // This Erlang frame keeps the call site's native continuation on E while the
        // breakpoint handler runs or yields.
        encoder.str_pre(Gpr::x(30), Gpr::x(20), -8)?;
        encoder.str_uoff(Gpr::x(8), Gpr::x(19), live_slot)?;
        encoder.sub_imm(Gpr::x(0), Gpr::x(30), 8, false)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), pc_slot)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), native_error_pc_slot)?;
        encoder.lsl_imm(Gpr::x(9), Gpr::x(8), 3)?;
        encoder.str_uoff(Gpr::x(9), Gpr::x(19), stack_needed_slot)?;
        encoder.add_imm(
            Gpr::x(10),
            Gpr::x(9),
            (arinsal_term::S_RESERVED * 8) as u16,
            false,
        )?;
        encoder.add_reg(Gpr::x(10), Gpr::x(10), Gpr::x(23), Shift::Lsl, 0)?;
        encoder.cmp_reg(Gpr::x(10), Gpr::x(20), Shift::Lsl, 0)
    })?;
    code.b_cond(Cond::Ls, after_gc)?;

    // The global assembler always emits this fragment (beam_asm_global.hpp.pl lists
    // `i_line_breakpoint_trampoline_shared`). Helper addresses are immediates filled by
    // the VM; unit tests that never enter the fragment pass zeros.
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
        encoder.ldr_uoff(Gpr::x(2), Gpr::x(19), live_slot)?;
        encoder.mov_reg(Gpr::x(3), Gpr::x(2))?;
        encoder.mov_reg(Gpr::w(4), Gpr::w(22))?;
        encoder.mov_const(Gpr::x(17), helpers.garbage_collect as u64)?;
        encoder.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.sub_reg(Gpr::w(22), Gpr::w(22), Gpr::w(0), Shift::Lsl, 0)?;
        encoder.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)?;
        encoder.cmp_imm(Gpr::x(9), 0, false)
    })?;
    code.b_cond(Cond::Ne, error)?;

    code.bind(after_gc)?;
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(9), Gpr::x(19), stack_needed_slot)?;
        encoder.sub_reg(Gpr::x(20), Gpr::x(20), Gpr::x(9), Shift::Lsl, 0)
    })?;

    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.ldr_uoff(Gpr::x(1), Gpr::x(19), pc_slot)?;
        encoder.ldr_uoff(Gpr::x(2), Gpr::x(19), live_slot)?;
        encoder.mov_const(Gpr::x(17), helpers.prepare_call as u64)?;
        encoder.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.cbz(Gpr::x(0), no_handler)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(13), Gpr::x(0))?;
        encoder.ldr_regoff(Gpr::x(14), Gpr::x(13), Gpr::x(24), 3)?;
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(13))?;
        encoder.blr(Gpr::x(14))
    })?;
    code.bind(cleanup)?;
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_const(Gpr::x(17), helpers.cleanup as u64)?;
        encoder.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.lsl_imm(Gpr::x(0), Gpr::x(0), 3)?;
        encoder.add_reg(Gpr::x(20), Gpr::x(20), Gpr::x(0), Shift::Lsl, 0)
    })?;
    code.b(exit)?;

    code.bind(no_handler)?;
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(9), Gpr::x(19), stack_needed_slot)?;
        encoder.add_reg(Gpr::x(20), Gpr::x(20), Gpr::x(9), Shift::Lsl, 0)
    })?;
    code.bind(exit)?;
    code.emit(|encoder| {
        encoder.ldr_post(Gpr::x(30), Gpr::x(20), 8)?;
        encoder.ret(Gpr::x(30))
    })?;

    code.bind(error)?;
    code.emit(|encoder| {
        encoder.mov_reg(Gpr::x(0), Gpr::xzr())?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(cleanup)
}

fn tmp_mem_offset(index: u32) -> u32 {
    std::mem::offset_of!(crate::SchedulerRegisters, tmp_mem) as u32 + index * 8
}

// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:context_switch_simplified,
// OTP-29.1.1.
fn emit_restore_and_exit(code: &mut CodeBuffer) -> Result<(), BufferError> {
    emit_restore_and_exit_frame(code, 16)
}

/// [`emit_restore_and_exit`] for a host frame of `frame_bytes`.
fn emit_restore_and_exit_frame(code: &mut CodeBuffer, frame_bytes: u16) -> Result<(), BufferError> {
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(30), Gpr::sp(), 8)?;
        encoder.add_imm(Gpr::sp(), Gpr::sp(), frame_bytes, false)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(())
}

/// Leaves native execution so the scheduler can interpret a call named by `sentinel`.
///
/// Expects the call continuation in `x30` (set by the caller before the branch); any
/// argument the scheduler needs (the arity, the fun) is already published in `c_p`.
fn emit_unported_fragment(code: &mut CodeBuffer, sentinel: usize) -> Result<(), BufferError> {
    code.emit(|encoder| {
        // Preserve the native continuation as a BEAM CP for the interpreter return path.
        encoder.str_pre(Gpr::x(30), Gpr::x(20), -8)?;
        encoder.mov_const(Gpr::x(0), 2)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_const(Gpr::x(1), sentinel as u64)?;
        encoder.mov_reg(Gpr::x(2), Gpr::xzr())?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(())
}
