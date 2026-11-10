//! VM interp implementation.

use super::*;

pub(crate) fn gc_stress_enabled() -> bool {
    static GC_STRESS: OnceLock<bool> = OnceLock::new();
    *GC_STRESS.get_or_init(|| {
        std::env::var_os("ARINSAL_GC_STRESS").as_deref() == Some(std::ffi::OsStr::new("1"))
    })
}

/// `ARINSAL_XREG_POISON=1` (debug builds only): at schedule-in, every X register above the
/// registers the process saved is filled with [`XREG_POISON`] instead of a stale or NIL value,
/// so code that reads a dead register faults or is caught by the root walk.
///
/// erts copies exactly `c_p->arity` registers into the scheduler array at schedule-in
/// (jit/arm/process_main.cpp, copy_in_registers) and leaves the rest of the array dirty.
#[inline]
pub(crate) fn xreg_poison_enabled() -> bool {
    crate::debug_env::slice::get() & crate::debug_env::slice::XREG_POISON != 0
}

/// A catch-tagged immediate with the largest index: no valid register value looks like it, a
/// dead register used as a list, tuple or `[]` takes the wrong branch, and the root walk can
/// recognize it.
pub(crate) const XREG_POISON: Term = Term::catch(u64::MAX >> 6);

#[cfg(feature = "pf-mem-counters")]
static PF_SPAWN_CONSTRUCTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "pf-mem-counters")]
static PF_SPAWN_CONSTRUCT_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) enum RunState {
    Done(Term),
    Yield,
    Wait { timeout_pos: Option<u64> },
}

impl Vm {
    /// Execute one exported function in a fresh process, in the interpreter. The JIT flavor
    /// has no interpreter: it evaluates only BIFs and the `erlang` fun builtins here, and
    /// [`Vm::eval_exported`] runs the rest natively.
    pub fn eval(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
    ) -> Result<EvalResult, VmError> {
        // ---- vm_funs ----
        if module == "erlang"
            && let Some(result) = self.eval_erlang_fun_builtin(function, args)
        {
            return result;
        }
        if args.len() > 1024 {
            return Err(VmError::Unsupported("more than 1024 arguments".into()));
        }
        let mut process = Process::new();
        let frame = format!("{module}:{function}/{}", args.len());
        let result = if let Some(bif) = arinsal_bifs::lookup(module, function, args.len() as u8)
            .or_else(|| natives::static_nif_lookup(module, function, args.len() as u8))
        {
            let result = {
                let mut heap = ProcessHeapHandle(&mut process.heap);
                let mut state = arinsal_bifs::BifState::default();
                let mut ctx = Ctx::with_fcalls(&mut heap, &mut state);
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bif(&mut ctx, args)))
                    .map_err(|_| VmError::Unsupported(format!("BIF {frame} panicked")))?
            };
            // ---- vm_exc ----
            Some(result.map_err(|e| {
                exceptions::direct_bif_error(&mut process, module, function, args, e)
            })?)
        } else {
            None
        };
        if let Some(term) = result {
            process.stats.heap_words = process.heap.capacity_words();
            return Ok(EvalResult {
                term,
                stats: process.stats.snapshot(),
                _process: process,
            });
        }
        if arinsal_spec::bif_lookup(module, function, args.len() as u8).is_some() {
            return Err(VmError::Unsupported(format!("BIF {frame}")));
        }
        Err(VmError::Unsupported(format!(
            "Vm::eval runs only BIFs and the erlang fun builtins, not {frame}; use Vm::eval_exported"
        )))
    }
    /// The function of the process's code address (`c_p->i`), for error texts.
    // Port of erts/emulator/beam/beam_ranges.c (erts_lookup_function_info), OTP-29.1.1.
    pub(crate) fn frame_name(&self, p: &Process) -> String {
        p.native_pc()
            .and_then(crate::native_bridge::native_function_at)
            .map_or_else(
                || "?:?/0".to_owned(),
                |f| format!("{}:{}/{}", f.module, f.function, f.arity),
            )
    }
    pub(crate) fn exception(&self, p: &Process, reason: impl Into<String>) -> VmError {
        let reason = reason.into();
        VmError::Exception {
            reason,
            frame: self.frame_name(p),
        }
    }
    /// Report whether `wait` / `wait_timeout` may block: nothing waits in the middle queue, the
    /// outer queue or the message queue past the save pointer.
    ///
    /// A scheduling quantum can expire on the wait instruction after `loop_rec`
    /// has already observed an empty mailbox. Signals that arrived since send the
    /// process back to `loop_rec`, which fetches them, instead of sleeping with them queued.
    pub(crate) fn mailbox_ready_to_wait(
        process: &mut Process,
        ctx: &mut Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Result<bool, VmError> {
        let ctx = ctx
            .as_deref_mut()
            .ok_or_else(|| VmError::Unsupported("receive requires a scheduler".into()))?;
        // erts reaches `wait` from `loop_rec` with the message queue lock held: nothing can
        // arrive in between, and `wait` does not fetch. Here signals that arrived since (or are
        // left in the middle queue) send the process back to `loop_rec`, whose receive helper
        // fetches and handles them.
        if ctx.has_pending_input() || !process.sig_cont_empty() {
            return Ok(false);
        }
        Ok(process.inbox.save() >= process.inbox.len())
    }

    /// Puts the process at the code address of function entry `target` of module `module_id`,
    /// as erts jumps to the export's code address. Every function has native code; a target
    /// that is not a function entry of it is an error.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1.
    pub(crate) fn set_position(
        &mut self,
        p: &mut Process,
        module_id: usize,
        target: usize,
    ) -> Result<(), VmError> {
        let native = self.code.modules.get(module_id).and_then(|module| {
            self.beamasm_targets.function_for_target(
                module_id,
                module,
                crate::load::native_code_range(&self.code.code_meta, module_id),
                target,
            )
        });
        let Some(native) = native else {
            return Err(VmError::Unsupported(format!(
                "position {target} of module {module_id} is not a native function entry"
            )));
        };
        p.set_native_pc(Some(native.start));
        Ok(())
    }

    /// Enters the native code at the process's code address (`c_p->i`), set by a spawn, an
    /// apply or a trap. A process without one is an error: the JIT flavor runs nothing else.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1.
    pub(crate) fn enter_native_position(&mut self, p: &mut Process) -> Result<RunState, VmError> {
        self.refresh_code();
        p.heap.abi.i = std::ptr::null();
        if p.native_retry().is_none() {
            p.set_native_retry_site(None);
        }
        // A migrated process may already be inside a module this replica has
        // not copied yet. Sync only when the id is past the local table.
        self.sync_module(p.module);
        let module_id = p.module;
        if module_id >= self.code.modules.len() {
            return Err(VmError::Unsupported(format!(
                "process module {module_id} is not loaded on this scheduler"
            )));
        }
        let (need_x, need_fr) = self.code.registers[module_id];
        p.x.ensure_x(need_x);
        p.ensure_fr(need_fr);
        if p.native_pc().is_none() {
            return Err(VmError::Unsupported(
                "process has no code address to continue at".into(),
            ));
        }
        p.native_transfer = true;
        Ok(RunState::Yield)
    }
}
