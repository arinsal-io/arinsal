//! Code loading and module query natives.

use crate::process::Runtime;
use crate::{CodeMeta, Process, Vm, VmError, exceptions};
use arinsal_beam::BeamFile;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_etf::OwnedTerm;
use arinsal_loader::CoverageMode;
use arinsal_sched::Pid;
use arinsal_sched::{LiteralCopyHow, RunCtx, Signal};
use arinsal_term::{MagicRef, Term, TermBuilder, atoms, from_owned, global_atoms, to_owned};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The code modification permission of a node.
/// Port of erts/emulator/beam/code_ix.c:52-79 (`struct code_permission`,
/// `code_mod_permission`), OTP-29.1.1.
#[derive(Default)]
pub(crate) struct CodeModPermission {
    seized: bool,
    owner: Option<Pid>,
    /// Suspended processes waiting for the permission, first in line first.
    queue: VecDeque<Pid>,
    /// `ERTS_PXSFLG_HANDOVER_CODE_MOD_PERM`: the waiter given the permission by a release
    /// while it was suspended; its retried BIF call finds it already seized.
    handover: Option<Pid>,
    /// `ERTS_PXSFLG_GC`: processes that are garbage collecting, which a release passes over.
    collecting: HashSet<Pid>,
}

fn lock(runtime: &Runtime) -> std::sync::MutexGuard<'_, CodeModPermission> {
    runtime
        .code_mod_permission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Seizes the code modification permission for `pid`. When another process holds it, `pid`
/// is suspended and queued, and the caller must yield and retry its BIF call once resumed.
// Port of erts/emulator/beam/code_ix.c:214-290 (try_seize_code_permission) and 378-386
// (erts_try_seize_code_mod_permission), OTP-29.1.1.
pub(crate) fn try_seize_code_mod_permission(
    runtime: &Runtime,
    process: &mut Process,
    pid: Pid,
) -> bool {
    let mut perm = lock(runtime);
    if perm.handover == Some(pid) {
        // Given to us as a waiter.
        debug_assert!(perm.seized && perm.owner == Some(pid));
        perm.handover = None;
        return true;
    }
    if !perm.seized {
        perm.seized = true;
        perm.owner = Some(pid);
        return true;
    }
    debug_assert_ne!(perm.owner, Some(pid));
    perm.queue.push_back(pid);
    // erl_process.c:14215 visits the code-permission lock only when the handover
    // xstate bit is set. A queued waiter is the same kind of process-local mark:
    // exit removes it from this queue and otherwise skips the lock.
    if !runtime.publish_proc_flag(pid, arinsal_sched::proc_flags::CODE_PERM) {
        perm.queue.retain(|waiter| *waiter != pid);
        return false;
    }
    if process.self_pid == Some(pid) {
        crate::suspend::suspend_self(process);
    }
    false
}

/// Releases the code modification permission and hands it to the first eligible waiter.
// Port of erts/emulator/beam/code_ix.c:292-357 (release_code_permission) and 388-391
// (erts_release_code_mod_permission), OTP-29.1.1.
pub(crate) fn release_code_mod_permission(runtime: &Runtime) {
    let resume = lock(runtime).release();
    resume_waiters(runtime, resume);
}

impl CodeModPermission {
    /// Returns the waiters to resume: the new owner and the ones passed over while they
    /// garbage collect, which retry after the collection.
    fn release(&mut self) -> Vec<Pid> {
        self.seized = false;
        self.owner = None;
        let mut resume = Vec::new();
        while !self.seized
            && let Some(waiter) = self.queue.pop_front()
        {
            // Avoid processes doing a potentially long GC: resume them and let them retry
            // after the GC. This only happens when the suspended waiter got a GC signal.
            if !self.collecting.contains(&waiter) {
                self.seized = true;
                self.owner = Some(waiter);
                self.handover = Some(waiter);
            }
            resume.push(waiter);
        }
        resume
    }
}

fn resume_waiters(runtime: &Runtime, pids: Vec<Pid>) {
    if pids.is_empty() {
        return;
    }
    // Port of erl_process.c:7305 (resume_process): rcount still above zero means a user
    // suspend remains, and the process is not enqueued.
    let wake: Vec<Pid> = pids
        .into_iter()
        .filter(|pid| runtime.resume_internal(*pid))
        .collect();
    signal_resumed(runtime, &wake);
}

fn signal_resumed(runtime: &Runtime, pids: &[Pid]) {
    let Ok(scheduler) = runtime.scheduler() else {
        return;
    };
    for pid in pids {
        // resume_process calls add2runq immediately (erl_process.c:7305, 6868).
        // The waiter joins its own run queue. That queue's scheduler is woken
        // only if it sleeps. Another scheduler takes the waiter by stealing
        // after it ran out of work, or by wakeup_other past its limit.
        let _ = scheduler.signal(*pid, *pid, Signal::UnlinkAck(u64::MAX));
    }
}

/// Resumes `pid` after an internal suspend, rescheduling it when no suspend remains.
pub(crate) fn resume_suspended(runtime: &Runtime, pid: Pid) {
    resume_waiters(runtime, vec![pid]);
}

/// Gives up a permission handed to `pid` that it has not taken yet, so it goes to the next
/// waiter.
// Port of erts/emulator/beam/code_ix.c:430-445 (erts_reject_code_permissions), OTP-29.1.1.
fn reject_code_permissions(perm: &mut CodeModPermission, pid: Pid) -> Vec<Pid> {
    if perm.handover == Some(pid) {
        perm.handover = None;
        // The process retries the BIF after GC (erl_gc.c:737). It is not put back on
        // the queue here; the retry queues itself if the permission is still held.
        perm.release()
    } else {
        Vec::new()
    }
}

/// An exiting process leaves the wait queue and gives up a permission it was handed but has
/// not taken yet. A permission it holds stays seized, like in erts.
// Port of erts/emulator/beam/erl_process.c:14215-14218 (erts_continue_exit_process) and
// code_ix.c:319 (release_code_permission skips an exiting waiter), OTP-29.1.1.
pub(crate) fn code_mod_permission_process_exit(process: &Process, pid: Pid) {
    let Some(runtime) = &process.runtime else {
        return;
    };
    let resume = {
        let mut perm = lock(runtime);
        perm.queue.retain(|waiter| *waiter != pid);
        perm.collecting.remove(&pid);
        reject_code_permissions(&mut perm, pid)
    };
    resume_waiters(runtime, resume);
}

/// Marks `pid` as garbage collecting (`ERTS_PXSFLG_GC`) until [`code_mod_permission_after_gc`];
/// a permission handed to it but not taken yet goes to the next waiter.
// Port of erts/emulator/beam/erl_gc.c:725-742 (erts_garbage_collect_nobump: set
// ERTS_PXSFLG_GC, erts_reject_code_permissions), OTP-29.1.1.
pub(crate) fn code_mod_permission_before_gc(process: &Process, pid: Pid) {
    let Some(runtime) = &process.runtime else {
        return;
    };
    let resume = {
        let mut perm = lock(runtime);
        perm.collecting.insert(pid);
        reject_code_permissions(&mut perm, pid)
    };
    resume_waiters(runtime, resume);
}

/// Clears the `ERTS_PXSFLG_GC` mark of [`code_mod_permission_before_gc`].
pub(crate) fn code_mod_permission_after_gc(process: &Process, pid: Pid) {
    if let Some(runtime) = &process.runtime {
        lock(runtime).collecting.remove(&pid);
    }
}

/// Port of erts/emulator/beam/beam_bif_load.c:50-66 (`purge_state`), OTP-29.1.1.
/// One purge may be prepared at a time; funs into the old instance are "pending
/// purge" until it completes or aborts.
#[derive(Default)]
pub(crate) struct PurgeState {
    /// Old module-instance id + 1 while a purge is prepared, 0 otherwise. Read on
    /// every local fun call, so it lives outside the mutex.
    old_id: std::sync::atomic::AtomicUsize,
    inner: Mutex<PurgeInner>,
    stage_released: std::sync::Condvar,
}

#[derive(Default)]
struct PurgeInner {
    module: Option<String>,
    /// `sprocs`: processes suspended in `erts_code_purger:pending_purge_lambda/3`.
    sprocs: Vec<Pid>,
    /// Global fun-table entries whose active code address is in the old module.
    funs: Vec<std::sync::Arc<arinsal_term::FunEntry>>,
    /// `erts_fun_start_staging` stays seized while pending-purge markers exist.
    holds_stage_permission: bool,
}

impl PurgeState {
    /// Whether calls into module instance `id` must wait for the purge.
    #[inline]
    pub(crate) fn pending(&self, id: usize) -> bool {
        let old = self.old_id.load(Ordering::Acquire);
        old != 0 && old - 1 == id
    }

    /// Port of erts/emulator/beam/beam_bif_load.c:1977
    /// (`erts_suspend_process_on_pending_purge_lambda`), OTP-29.1.1.
    /// Returns true when the caller was registered and must suspend itself.
    pub(crate) fn suspend_on_pending_lambda(&self, module: &str, pid: Pid) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.module.as_deref() != Some(module) {
            return false;
        }
        inner.sprocs.push(pid);
        true
    }

    fn is_prepared(&self) -> bool {
        self.inner.lock().unwrap().module.is_some()
    }

    fn is_module(&self, name: &str) -> bool {
        self.inner.lock().unwrap().module.as_deref() == Some(name)
    }

    /// Waits until purge markers no longer prohibit a new code staging area.
    pub(crate) fn wait_for_stage_permission(&self) {
        let mut inner = self.inner.lock().unwrap();
        while inner.holds_stage_permission {
            inner = self
                .stage_released
                .wait(inner)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    /// Acts as a prepared purge with fun entries, for tests of the staging wait.
    #[cfg(test)]
    pub(crate) fn hold_stage_permission_for_test(&self, held: bool) {
        self.inner.lock().unwrap().holds_stage_permission = held;
        self.stage_released.notify_all();
    }

    /// Whether a prepared purge currently holds the code staging permission.
    pub(crate) fn stage_permission_held(&self) -> bool {
        self.inner.lock().unwrap().holds_stage_permission
    }

    // Port of erts/emulator/beam/erl_fun.c:157-189 (fun_purge_foreach,
    // erts_fun_purge_prepare), OTP-29.1.1.
    fn prepare<'a>(
        &self,
        name: &str,
        old: usize,
        code_ix: usize,
        code: Option<std::ops::Range<usize>>,
        entries: impl Iterator<Item = &'a std::sync::Arc<arinsal_term::FunEntry>>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.module = Some(name.to_owned());
        self.old_id.store(old + 1, Ordering::Release);
        if let Some(code) = code {
            for entry in entries {
                if entry.prepare_fun_purge(code_ix, code.clone()) {
                    inner.funs.push(std::sync::Arc::clone(entry));
                }
            }
        }
        inner.holds_stage_permission = !inner.funs.is_empty();
    }

    /// Restores only the active addresses before the abort thread-progress barrier.
    // Port of erts/emulator/beam/erl_fun.c:190-203 (erts_fun_purge_abort_prepare), OTP-29.1.1.
    fn abort_prepare(&self, code_ix: usize) -> bool {
        let inner = self.inner.lock().unwrap();
        for entry in &inner.funs {
            entry.abort_fun_purge_prepare(code_ix);
        }
        !inner.funs.is_empty()
    }

    /// Clears active purge markers before the old code allocation is released.
    // Port of erts/emulator/beam/erl_fun.c:224-239 (erts_fun_purge_complete), OTP-29.1.1.
    fn complete_fun_purge(&self, code_ix: usize) {
        let inner = self.inner.lock().unwrap();
        for entry in &inner.funs {
            entry.complete_fun_purge(code_ix);
        }
    }

    /// Finalizes an aborted or completed purge and returns its suspended processes.
    // Port of erts/emulator/beam/erl_fun.c:205-239 (abort_finalize / purge_complete) and
    // beam_bif_load.c:2010-2036 (finalize_purge_operation), OTP-29.1.1.
    fn finish(&self, aborted: bool, code_ix: usize) -> Vec<Pid> {
        let mut inner = self.inner.lock().unwrap();
        let funs = std::mem::take(&mut inner.funs);
        if aborted {
            for entry in funs {
                entry.abort_fun_purge_finalize(code_ix);
            }
        }
        self.old_id.store(0, Ordering::Release);
        inner.module = None;
        inner.holds_stage_permission = false;
        let pids = std::mem::take(&mut inner.sprocs);
        drop(inner);
        self.stage_released.notify_all();
        pids
    }
}

/// Resume processes suspended on pending-purge lambdas.
/// Port of erts/emulator/beam/beam_bif_load.c:2028-2036 (finalize_purge_operation), OTP-29.1.1.
fn resume_pending_lambda_callers(
    process: &Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
    pids: Vec<Pid>,
) {
    let Some(runtime) = process.runtime else {
        return;
    };
    for pid in pids {
        if runtime.resume_internal(pid) {
            // The signal only reschedules the target; a dead target needs no wake.
            let _ = ctx.signal(pid, Signal::UnlinkAck(u64::MAX));
        }
    }
}

/// `mb->orig_size` of the magic binary `erts_alloc_loader_state` creates:
/// `ERTS_MAGIC_BIN_ORIG_SIZE(sizeof(LoaderState))` for the 64-bit JIT loader, that is the
/// 24-byte magic data offset plus the 568-byte `LoaderState` of beam/jit/load.h.
const LOADER_STATE_MAGIC_ORIG_SIZE: usize = 24 + 568;

struct Prepared {
    bytes: Mutex<Vec<u8>>,
    has_on_load: bool,
    registers: (usize, usize),
    /// Loaded code from `prepare_loading`; taken by the first `finish_loading`.
    module: Mutex<Option<arinsal_loader::Module>>,
    /// BeamAsm output generated by `prepare_loading` and installed by `finish_loading`.
    meta: Mutex<Option<CodeMeta>>,
}

impl Prepared {
    /// Drop the loader state `finish_loading` has already copied into the staged module.
    fn release(&self) {
        *self.bytes.lock().unwrap() = Vec::new();
    }
}

// boot_loop1: preserve the on_load decision made by OTP's loader attributes.
fn has_on_load_opcode(beam: &BeamFile) -> bool {
    beam.summary.on_load.is_some()
}

fn has_prepared_code_on_load(term: Term) -> Result<Term, VmError> {
    // SAFETY: The caller keeps the argument's heap live during this BIF.
    let prepared = unsafe { term.magic_ref() }
        .and_then(|reference| reference.downcast_ref::<Prepared>())
        .ok_or_else(badarg)?;
    Ok(Term::atom(if prepared.has_on_load {
        atoms::TRUE
    } else {
        atoms::FALSE
    }))
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("short OTP atom"))
}

fn badarg() -> VmError {
    VmError::Trap(exceptions::Trap::error(Term::atom(atoms::BADARG)))
}

fn system_limit() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("system_limit")))
}

fn list(term: Term) -> Option<Vec<Term>> {
    let mut result = Vec::new();
    // SAFETY: Arguments remain rooted in the calling process heap throughout dispatch.
    let mut iter = unsafe { arinsal_term::ListIter::new(term) };
    result.extend(&mut iter);
    (iter.tail() == Term::NIL).then_some(result)
}

fn make_list(
    process: &mut Process,
    values: impl IntoIterator<Item = Term>,
) -> Result<Term, VmError> {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .list_from_iter(values)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn make_tuple(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .tuple(values)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn info_list(
    process: &mut Process,
    items: impl IntoIterator<Item = Term>,
) -> Result<Term, VmError> {
    make_list(process, items)
}

fn module_info(vm: &Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let name = module_name(args[0]).ok_or_else(badarg)?;
    let id = vm.code.loaded.get(&name).copied().ok_or_else(badarg)?;
    let module = &vm.code.modules[id];
    let meta = vm.code.code_meta[id].as_ref().ok_or_else(badarg)?;
    let value = |field: &str, process: &mut Process| -> Result<Term, VmError> {
        match field {
            "module" => Ok(args[0]),
            "exports" => {
                // Port of erts/emulator/beam/erl_bif_info.c:5825 (exported_from_module),
                // OTP-29.1.1. The export index is walked from 0 and consed, which is
                // reverse insertion order. Entries that only exist because something
                // imported them (error-handler trampoline) are not in the export table.
                let exported: std::collections::HashSet<(arinsal_term::Atom, u8)> = module
                    .exports
                    .iter()
                    .map(|export| (export.function_atom, export.arity))
                    .collect();
                let Some(name_atom) = args[0].as_atom() else {
                    return Err(badarg());
                };
                let mut exports = Vec::new();
                for &(module_atom, function_atom, arity) in vm.code.exports.order.iter().rev() {
                    if module_atom != name_atom || !exported.contains(&(function_atom, arity)) {
                        continue;
                    }
                    exports.push(make_tuple(
                        process,
                        &[
                            Term::atom(function_atom),
                            Term::small(i64::from(arity)).unwrap(),
                        ],
                    )?);
                }
                info_list(process, exports)
            }
            "functions" => {
                // Port of erts/emulator/beam/erl_bif_info.c:5735 (functions_in_module),
                // OTP-29.1.1. The code header is walked from the end and consed, which
                // is func_info order.
                let mut functions = Vec::with_capacity(module.functions.len());
                for (_, function, arity) in &module.functions {
                    functions.push(make_tuple(
                        process,
                        &[atom(function), Term::small(i64::from(*arity)).unwrap()],
                    )?);
                }
                info_list(process, functions)
            }
            // Port of erts/emulator/beam/erl_bif_info.c:5772-5805 (nifs_in_module), OTP-29.1.1.
            "nifs" => {
                let mut nifs = Vec::new();
                // `erts_nif_get_funcs(mod->curr.nif)`: the functions of the library entry.
                if let Some(functions) =
                    crate::natives::nif::instance_nif_functions(vm.code_scope, id)
                {
                    for (function, arity) in functions {
                        nifs.push(make_tuple(
                            process,
                            &[atom(&function), Term::small(i64::from(arity)).unwrap()],
                        )?);
                    }
                    return info_list(process, nifs);
                }
                // Natively backed stubs of modules that never ran load_nif are not NIFs in erts.
                let loaded = vm.code.loaded_nifs.iter().any(|key| {
                    key.strip_prefix(&module.name)
                        .is_some_and(|tail| tail.starts_with('#'))
                });
                for (entry, function, arity) in module.functions.iter().rev() {
                    if loaded
                        && matches!(
                            module.code.get(entry.saturating_add(1)),
                            Some(arinsal_loader::Instr::NativeBody { .. })
                        )
                    {
                        nifs.push(make_tuple(
                            process,
                            &[atom(function), Term::small(i64::from(*arity)).unwrap()],
                        )?);
                    }
                }
                info_list(process, nifs)
            }
            "native" => Ok(Term::atom(atoms::FALSE)),
            // Port of erts/emulator/beam/erl_bif_info.c:5817-5823 (native_addresses), OTP-29.1.1.
            "native_addresses" => info_list(process, []),
            // Port of erts/emulator/beam/erl_bif_info.c:5866 (attributes_for_module)
            // and :5889 (compilation_info_for_module), OTP-29.1.1.
            "attributes" | "compile" => {
                let chunk = if field == "attributes" {
                    &meta.beam.attributes
                } else {
                    &meta.beam.compile_info
                };
                let value = chunk
                    .as_ref()
                    .map(|bytes| arinsal_etf::decode(bytes).map_err(|_| badarg()))
                    .transpose()?
                    .unwrap_or(OwnedTerm::Nil);
                let mut heap = ProcessHeapHandle(&mut process.heap);
                from_owned(&value, &mut heap).map_err(|_| badarg())
            }
            // Port of erts/emulator/beam/erl_bif_info.c:5913 (md5_of_module), OTP-29.1.1.
            "md5" => {
                let md5 = meta.md5.ok_or_else(badarg)?;
                let mut heap = ProcessHeapHandle(&mut process.heap);
                from_owned(&OwnedTerm::Binary(md5.to_vec()), &mut heap).map_err(|_| badarg())
            }
            _ => Err(badarg()),
        }
    };
    if args.len() == 2 {
        let field = module_name(args[1]).ok_or_else(badarg)?;
        return value(&field, process);
    }
    let mut pairs = Vec::new();
    // Port of erts/emulator/beam/erl_bif_info.c:5947 (module_info_0), OTP-29.1.1.
    for field in ["module", "exports", "attributes", "compile", "md5"] {
        let field_value = value(field, process)?;
        pairs.push(make_tuple(process, &[atom(field), field_value])?);
    }
    info_list(process, pairs)
}

fn module_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

/// `erlang:module_loaded/1` called directly from native code.
// Port of erts/emulator/beam/beam_bif_load.c:2548 (module_loaded_1), OTP-29.1.1: the module
// table of the active code index.
pub(crate) fn module_loaded_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [module] = args else {
        return None;
    };
    let name = global_atoms().text(module.as_atom()?)?;
    let loaded = process
        .runtime
        .as_ref()?
        .with_active_code(|_, tables| tables.loaded.contains_key(name));
    Some(Ok(Term::atom(if loaded {
        atoms::TRUE
    } else {
        atoms::FALSE
    })))
}

/// `erlang:function_exported/3` called directly from native code.
// Port of erts/emulator/beam/beam_bif_load.c:2574 (function_exported_3), OTP-29.1.1.
pub(crate) fn function_exported_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [module, function, arity] = args else {
        return None;
    };
    let module = module.as_atom()?;
    let function = function.as_atom()?;
    let module_name = global_atoms().text(module)?;
    let function_name = global_atoms().text(function)?;
    let arity = u8::try_from(arity.as_small().filter(|n| (0..=255).contains(n))?).ok()?;
    let exported = process.runtime.as_ref()?.with_active_code(|_, tables| {
        tables.loaded.get(module_name).is_some_and(|id| {
            tables.modules[*id]
                .export_slot(function_name, arity)
                .is_some()
        })
    });
    Some(Ok(Term::atom(if exported {
        atoms::TRUE
    } else {
        atoms::FALSE
    })))
}

fn prepare(vm: &Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let Some(name) = args.first().and_then(|arg| module_name(*arg)) else {
        return Err(badarg());
    };
    let Some(owned) = args.get(1).and_then(|term| to_owned(*term).ok()) else {
        return Err(badarg());
    };
    // Move the file bytes out of the decoded term. `OwnedTerm` is `Drop`, so the
    // binary is taken in place instead of cloned and then dropped.
    let mut owned = owned;
    let arinsal_etf::OwnedTerm::Binary(ref mut bytes_slot) = owned else {
        return Err(badarg());
    };
    let bytes = std::mem::take(bytes_slot);
    // Port of erts/emulator/beam/beam_file.c:beamfile_read: the tables; the instructions stay bytes.
    let Ok(beam) = arinsal_beam::read(&bytes) else {
        let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
        return Ok(error);
    };
    if beam.module != name {
        let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
        return Ok(error);
    }
    // Port of erts/emulator/beam/jit/asm_load.c:1084-1105 (attribute and compile-info
    // chunks must be valid external terms), OTP-29.1.1.
    if [&beam.attributes, &beam.compile_info]
        .into_iter()
        .flatten()
        .any(|chunk| !chunk.is_empty() && arinsal_etf::decode(chunk).is_err())
    {
        let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
        return Ok(error);
    }
    // Port of erts/emulator/beam/beam_bif_load.c:150 (prepare_loading_2) and
    // beam_load.c (erts_prepare_loading), OTP-29.1.1: the code is loaded here, so
    // a malformed module is `{error, badfile}` before finish_loading.
    // Static NIF bodies and import classes are bound here, like erts' loader does for the
    // static NIF table (erl_nif.c erts_load_static_nif at load_nif time).
    let has_on_load = has_on_load_opcode(&beam);
    let registers = (beam.summary.x_registers, beam.summary.float_registers);
    let mut meta = CodeMeta::from_beam_owned(beam, Some(&bytes));
    // As erts has no interpreter form of a module, decode the instructions for the interpreter
    // only when it may run them.
    let native_only = vm.native_only(&meta.beam, &meta);
    if !native_only {
        // Port of erts/emulator/beam/beam_load.c:625-636 (bad_bs_match_1), OTP-29.1.1: the
        // generic engine rejects these through its generator; the interpreter form checks here.
        if meta.beam.decode_code().is_err()
            || arinsal_loader::validate_bit_matches(&meta.beam).is_err()
        {
            let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
            return Ok(error);
        }
    }
    let Ok(mut module) = vm.prepare_module_with(&meta.beam, Some(&bytes), !native_only) else {
        let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
        return Ok(error);
    };
    vm.intern_prepared_fun_entries(&mut module);
    vm.compile_native(&mut module, &mut meta);
    if native_only
        && meta
            .beamasm
            .as_ref()
            .is_none_or(|native| native.unported_functions != 0)
    {
        // Some function needs the interpreter: load the module again with its code decoded.
        if meta.beam.decode_code().is_err() {
            let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
            return Ok(error);
        }
        let Ok(mut full) = vm.prepare_module(&meta.beam, Some(&bytes)) else {
            let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
            return Ok(error);
        };
        vm.intern_prepared_fun_entries(&mut full);
        meta.beamasm = None;
        vm.compile_native(&mut full, &mut meta);
        module = full;
    }
    vm.release_loaded_tables(&mut module, &mut meta);
    let prepared = Prepared {
        has_on_load,
        registers,
        bytes: Mutex::new(bytes),
        module: Mutex::new(Some(module)),
        meta: Mutex::new(Some(meta)),
    };
    // Port of erts/emulator/beam/beam_bif_load.c (erts_internal_prepare_loading_2),
    // OTP-29.1.1: `HAlloc(BIF_P, ERTS_MAGIC_REF_THING_SIZE)` takes a heap fragment when the
    // young heap is full, so no collection happens here. The magic binary charges
    // `orig_size` of `erts_alloc_loader_state` (beam_load.c) to the virtual binary heap.
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let result = builder.magic_ref(MagicRef::with_orig_size(
        prepared,
        LOADER_STATE_MAGIC_ORIG_SIZE,
    ));
    result.map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

/// Seizes the code loading permission for the calling process; when another process holds
/// it, the caller is suspended and queued and the returned yield retries the BIF call once
/// the permission is handed over (ERTS_BIF_YIELD to the BIF's own trap export).
// Port of erts/emulator/beam/code_ix.c:407-421 (erts_try_seize_code_load_permission),
// OTP-29.1.1. Arinsal has only the code modification permission: no operation needs the
// staging permission alone while another process holds the modification permission.
fn seize_code_load_permission(process: &mut Process, pid: Option<Pid>) -> Result<(), VmError> {
    let runtime = process.runtime;
    match (runtime, pid) {
        (Some(runtime), Some(pid)) if !try_seize_code_mod_permission(runtime, process, pid) => {
            Err(VmError::Yield)
        }
        _ => Ok(()),
    }
}

/// Port of erts/emulator/beam/code_ix.c:423-427 (erts_release_code_load_permission),
/// OTP-29.1.1.
fn release_code_load_permission(process: &Process, pid: Option<Pid>) {
    if let (Some(runtime), Some(_)) = (&process.runtime, pid) {
        release_code_mod_permission(runtime);
    }
}

// Port of erts/emulator/beam/beam_bif_load.c:340-372 (finish_loading_1), OTP-29.1.1.
fn finish(
    vm: &mut Vm,
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, crate::process::Message>>,
    pid: Option<Pid>,
    args: &[Term],
) -> Result<Term, VmError> {
    if process.runtime.is_some() && ctx.is_none() {
        return Err(VmError::Unsupported(
            "finish_loading requires its scheduler context".into(),
        ));
    }
    // The barrier callback committed the code index and released the permission before waking
    // the loader; this retry refreshes its VM view and returns (ERTS_BIF_YIELD_RETURN).
    if let Some(staged) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.finish_loading_commit.take().map(|boxed| *boxed))
    {
        let barrier_callback = staged.barrier_passed.is_some();
        let result = finish_commit(vm, process, staged);
        if !barrier_callback {
            release_code_load_permission(process, pid);
        }
        return result;
    }
    seize_code_load_permission(process, pid)?;
    let result = finish_stage(vm, process, ctx, pid, args);
    // A staged load keeps the permission until its commit.
    if !matches!(result, Err(VmError::Yield)) {
        release_code_load_permission(process, pid);
    }
    result
}

/// The staging half of `finish_loading/1`; yields when the load is staged and waits for its
/// commit.
fn finish_stage(
    vm: &mut Vm,
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, crate::process::Message>>,
    pid: Option<Pid>,
    args: &[Term],
) -> Result<Term, VmError> {
    let Some(codes) = args.first().and_then(|term| list(*term)) else {
        return Err(badarg());
    };
    let mut prepared_modules = Vec::with_capacity(codes.len());
    let mut prepared_refs = Vec::with_capacity(codes.len());
    for code in &codes {
        // SAFETY: Each list member is a rooted term in the process heap. The
        // reference stays live until this function returns, so a successful stage
        // can drop the loader state without a second magic-ref borrow.
        let prepared = unsafe { code.magic_ref() }
            .and_then(|reference| reference.downcast_ref::<Prepared>())
            .ok_or_else(badarg)?;
        // Port of erts/emulator/beam/beam_bif_load.c (finish_loading_1): a prepared load that
        // has been finished already is `badarg`.
        let Some(module) = prepared.module.lock().unwrap().take() else {
            return Err(badarg());
        };
        let Some(meta) = prepared.meta.lock().unwrap().take() else {
            return Err(badarg());
        };
        let registers = prepared.registers;
        prepared_refs.push(prepared);
        prepared_modules.push((module, registers, meta));
    }
    if prepared_modules.len() > 1
        && prepared_modules
            .iter()
            .any(|(_, _, meta)| meta.on_load.is_some())
    {
        return Err(VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
    }
    match vm.stage_prepared(prepared_modules) {
        // Port of erts/emulator/beam/beam_bif_load.c:539-571 (staging_epilogue), OTP-29.1.1:
        // after erts_end_staging_code_ix the loader is suspended until every scheduler passed
        // a code barrier, so processes that were already runnable keep running the previous
        // code; commit_code_ix then commits and resumes the loader, which returns the result.
        Ok(staged) => {
            for prepared in prepared_refs {
                prepared.release();
            }
            let mut staged = staged;
            if let (Some(runtime), Some(pid), Some(ctx)) = (process.runtime, pid, ctx) {
                let ended = staged.ended.take();
                let barrier_passed = Arc::new(AtomicBool::new(false));
                staged.barrier_passed = Some(Arc::clone(&barrier_passed));
                process.cold_mut().finish_loading_commit = Some(Box::new(staged));
                crate::suspend::suspend_self(process);
                ctx.thread_progress_later(move || {
                    if let Some(ended) = ended {
                        ended.commit();
                    }
                    barrier_passed.store(true, Ordering::Release);
                    release_code_mod_permission(runtime);
                    resume_suspended(runtime, pid);
                });
            } else {
                process.cold_mut().finish_loading_commit = Some(Box::new(staged));
            }
            Err(VmError::Yield)
        }
        Err(("system_limit", _)) => {
            Err(VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
        }
        Err((reason, modules)) => {
            let names = make_list(process, modules.iter().map(|name| atom(name)))?;
            make_tuple(process, &[atom(reason), names])
        }
    }
}

/// The commit half of `finish_loading/1` (beam_bif_load.c:301 commit_code_ix and the result
/// of staging_epilogue).
fn finish_commit(
    vm: &mut Vm,
    process: &mut Process,
    staged: crate::load::StagedLoad,
) -> Result<Term, VmError> {
    let loaded_names = staged.names.clone();
    let on_load = vm.commit_staged(staged);
    for name in &loaded_names {
        crate::trace_bp::module_code_changed(process, vm.code_scope, name);
        apply_on_load_patterns(vm, process, name);
    }
    if on_load.is_empty() {
        Ok(atom("ok"))
    } else {
        let names = make_list(process, on_load.iter().map(|name| atom(name)))?;
        make_tuple(process, &[atom("on_load"), names])
    }
}

/// Apply every session's `trace_pattern(on_load, ...)` to a freshly loaded module.
// Port of erts/emulator/beam/beam_bif_load.c:944-975 (set_on_load_trace_pattern), OTP-29.1.1.
pub(crate) fn apply_on_load_patterns(vm: &mut Vm, process: &Process, name: &str) {
    let patterns = crate::trace_bp::on_load_patterns_of(process);
    if patterns.is_empty() {
        return;
    }
    let functions = crate::natives::proc::bp_functions(vm, name, "_", None);
    for (session, on_load) in patterns {
        crate::trace_bp::set_trace_pattern(
            process,
            session,
            &functions,
            on_load.match_spec,
            on_load.meta_match_spec,
            crate::trace_bp::BreakOp::Set,
            on_load.flags,
            &on_load.meta_tracer,
        );
    }
    vm.refresh_trace_pattern(process, name, "_", None);
}

fn check_process_code(vm: &Vm, process: &Process, name: &str) -> bool {
    let Some(&old) = vm.code.old.get(name) else {
        return false;
    };
    let native = crate::load::native_code_version(&vm.code.code_meta, old);
    process.references_code(old, |address| {
        crate::load::native_code_contains(native.map(Arc::as_ref), address)
    })
}

// Port of erts/emulator/beam/erl_bif_coverage.c:50-116, OTP-29.1.1.
fn coverage_mode_atom(mode: CoverageMode) -> Term {
    atom(match mode {
        CoverageMode::None => "none",
        CoverageMode::Function => "function",
        CoverageMode::FunctionCounters => "function_counters",
        CoverageMode::Line => "line",
        CoverageMode::LineCounters => "line_counters",
    })
}

fn coverage_mode_from(term: Term) -> Option<CoverageMode> {
    let text = global_atoms().text(term.as_atom()?)?;
    match text {
        "none" => Some(CoverageMode::None),
        "function" => Some(CoverageMode::Function),
        "function_counters" => Some(CoverageMode::FunctionCounters),
        "line" => Some(CoverageMode::Line),
        "line_counters" => Some(CoverageMode::LineCounters),
        _ => None,
    }
}

fn coverage_module(vm: &Vm, module: Term) -> Result<&arinsal_loader::Module, VmError> {
    let name = module_name(module).ok_or_else(badarg)?;
    let id = vm.code.loaded.get(&name).copied().ok_or_else(badarg)?;
    vm.code
        .modules
        .get(id)
        .map(AsRef::as_ref)
        .ok_or_else(badarg)
}

fn coverage_count(value: u64, flags: bool) -> Term {
    if flags {
        Term::atom(if value == 0 {
            atoms::FALSE
        } else {
            atoms::TRUE
        })
    } else {
        const MAX_SMALL: u64 = (1_u64 << 59) - 1;
        Term::small(value.min(MAX_SMALL) as i64).expect("coverage counter fits small integer")
    }
}

// Port of erts/emulator/beam/erl_bif_coverage.c:164-440, OTP-29.1.1.
fn get_coverage(vm: &Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let mode = module_name(args[0]).ok_or_else(badarg)?;
    let module = coverage_module(vm, args[1])?;
    let Some(coverage) = module.coverage.as_ref() else {
        return Err(badarg());
    };
    let (flags, line_mode, ids, function_from_lines) = match (mode.as_str(), coverage.mode) {
        ("function", CoverageMode::Function) => (true, false, false, false),
        ("function", CoverageMode::FunctionCounters) => (false, false, false, false),
        ("function", CoverageMode::Line | CoverageMode::LineCounters) => (true, false, false, true),
        ("line", CoverageMode::Line) => (true, true, false, false),
        ("line", CoverageMode::LineCounters) => (false, true, false, false),
        ("cover_id_line", CoverageMode::LineCounters) => (false, true, true, false),
        _ => return Err(badarg()),
    };
    if line_mode {
        let mut rows = Vec::with_capacity(coverage.len());
        for index in 0..coverage.len() {
            let key = if ids {
                coverage.cover_ids[index]
            } else {
                coverage.lines[index]
            };
            let count = coverage.load(index).unwrap_or(0);
            let key = Term::small(i64::from(key)).ok_or_else(badarg)?;
            rows.push(make_tuple(process, &[key, coverage_count(count, flags)])?);
        }
        return make_list(process, rows);
    }
    let mut rows = Vec::new();
    for (index, (_, function, arity)) in module.functions.iter().enumerate() {
        if function == "module_info" && *arity <= 1 {
            continue;
        }
        let count = if function_from_lines {
            coverage
                .function_owners
                .iter()
                .enumerate()
                .filter(|(_, owner)| **owner as usize == index)
                .any(|(counter, _)| coverage.load(counter).unwrap_or(0) > 0) as u64
        } else {
            let Some(count) = coverage.load(index) else {
                continue;
            };
            count
        };
        let mfa = make_tuple(
            process,
            &[
                atom(function),
                Term::small(i64::from(*arity)).ok_or_else(badarg)?,
            ],
        )?;
        rows.push(make_tuple(process, &[mfa, coverage_count(count, flags)])?);
    }
    make_list(process, rows)
}

// Port of erts/emulator/beam/erl_bif_coverage.c:444-482, OTP-29.1.1.
fn reset_coverage(vm: &Vm, module: Term) -> Result<Term, VmError> {
    let module = coverage_module(vm, module)?;
    let Some(coverage) = module.coverage.as_ref() else {
        return Err(badarg());
    };
    coverage.reset();
    Ok(atom("ok"))
}

fn beamfile_chunk(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let owned = to_owned(args[0]).map_err(|_| badarg())?;
    let OwnedTerm::Binary(bytes) = &owned else {
        return Err(badarg());
    };
    let Some(chunk) = list(args[1]) else {
        return Err(badarg());
    };
    let Some(id_vec) = chunk
        .iter()
        .map(|byte| {
            byte.as_small()
                .filter(|value| (0..=255).contains(value))
                .map(|value| value as u8)
        })
        .collect::<Option<Vec<_>>>()
    else {
        return Err(badarg());
    };
    let id: Option<[u8; 4]> = id_vec.try_into().ok();
    let Some(id) = id else {
        return Err(badarg());
    };
    let result = arinsal_loader::beamfile_chunk(bytes, id).map_err(|_| badarg())?;
    match result {
        Some(chunk) => {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            from_owned(&OwnedTerm::Binary(chunk), &mut heap).map_err(|_| system_limit())
        }
        None => Ok(atom("undefined")),
    }
}

fn beamfile_module_md5(process: &mut Process, binary: Term) -> Result<Term, VmError> {
    let owned = to_owned(binary).map_err(|_| badarg())?;
    let OwnedTerm::Binary(bytes) = &owned else {
        return Err(badarg());
    };
    if arinsal_beam::parse(bytes).is_err() {
        return Ok(atom("undefined"));
    }
    let md5 = arinsal_loader::module_uniq(bytes).map_err(|_| badarg())?;
    let mut heap = ProcessHeapHandle(&mut process.heap);
    from_owned(&OwnedTerm::Binary(md5.to_vec()), &mut heap).map_err(|_| system_limit())
}

// Port of erts/emulator/beam/beam_bif_load.c:1275-1450, OTP-29.1.1.
fn get_debug_info(vm: &Vm, process: &mut Process, module: Term) -> Result<Term, VmError> {
    let name = module_name(module).ok_or_else(badarg)?;
    let id = vm.code.loaded.get(&name).copied().ok_or_else(badarg)?;
    if vm.code.modules.get(id).is_none() || vm.code.code_meta.get(id).is_none() {
        return Err(badarg());
    }
    let has_debug = vm.code.code_meta[id].as_ref().is_some_and(|meta| {
        meta.beam.other_chunks.iter().any(|(chunk, bytes)| {
            chunk == b"DbgB"
                && bytes.len() >= 12
                && u32::from_be_bytes(bytes[..4].try_into().unwrap()) == 1
        })
    });
    if !has_debug {
        return Ok(atom("none"));
    }
    let module = &vm.code.modules[id];
    let beam = &vm.code.code_meta[id].as_ref().ok_or_else(badarg)?.beam;
    let items = beam.debug_items().unwrap_or_default();
    // Items without an `i_debug_line` (never instrumented) have no location and are skipped.
    let line_of = |index: usize| {
        module
            .debug_line_items
            .iter()
            .find(|(item, _)| *item as usize == index)
            .map(|(_, line)| *line)
    };
    let owned_term = |term: &arinsal_beam::DebugTerm| -> Result<OwnedTerm, VmError> {
        use arinsal_beam::DebugTerm;
        Ok(match term {
            DebugTerm::Int(value) => OwnedTerm::Int(*value),
            DebugTerm::Atom(atom) => {
                OwnedTerm::Atom(beam.atom(*atom).ok_or_else(badarg)?.to_owned())
            }
            DebugTerm::Nil => OwnedTerm::Nil,
            DebugTerm::Literal(index) => beam.literal(*index).map_err(|_| badarg())?,
            DebugTerm::X(_) | DebugTerm::Y(_) => return Err(badarg()),
        })
    };
    let list = |elems: Vec<OwnedTerm>| OwnedTerm::List {
        elems,
        tail: Box::new(OwnedTerm::Nil),
    };
    let mut result = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let Some(line) = line_of(index) else {
            continue;
        };
        let frame_size = match item.frame_size {
            arinsal_beam::DebugFrameSize::None => OwnedTerm::Atom("none".into()),
            arinsal_beam::DebugFrameSize::Entry => OwnedTerm::Atom("entry".into()),
            arinsal_beam::DebugFrameSize::Words(words) => OwnedTerm::Int(i64::from(words)),
        };
        let mut vars = Vec::new();
        for (name, value) in &item.vars {
            let value = match value {
                arinsal_beam::DebugTerm::X(register) => OwnedTerm::Tuple(vec![
                    OwnedTerm::Atom("x".into()),
                    OwnedTerm::Int(i64::from(*register)),
                ]),
                arinsal_beam::DebugTerm::Y(register) => OwnedTerm::Tuple(vec![
                    OwnedTerm::Atom("y".into()),
                    OwnedTerm::Int(i64::from(*register)),
                ]),
                other => {
                    OwnedTerm::Tuple(vec![OwnedTerm::Atom("value".into()), owned_term(other)?])
                }
            };
            vars.push(OwnedTerm::Tuple(vec![owned_term(name)?, value]));
        }
        let mut calls = Vec::new();
        for call in &item.calls {
            calls.push(match call {
                arinsal_beam::DebugCall::Remote(module, function, arity) => OwnedTerm::Tuple(vec![
                    owned_term(module)?,
                    owned_term(function)?,
                    OwnedTerm::Int(i64::from(*arity)),
                ]),
                arinsal_beam::DebugCall::Local(function, arity) => OwnedTerm::Tuple(vec![
                    owned_term(function)?,
                    OwnedTerm::Int(i64::from(*arity)),
                ]),
                arinsal_beam::DebugCall::Variable(name) => owned_term(name)?,
            });
        }
        result.push(OwnedTerm::Tuple(vec![
            OwnedTerm::Int(i64::from(line)),
            OwnedTerm::Map(vec![
                (OwnedTerm::Atom("frame_size".into()), frame_size),
                (OwnedTerm::Atom("vars".into()), list(vars)),
                (OwnedTerm::Atom("calls".into()), list(calls)),
            ]),
        ]));
    }
    let mut heap = ProcessHeapHandle(&mut process.heap);
    from_owned(&list(result), &mut heap).map_err(|_| system_limit())
}

// Port of erts/emulator/beam/beam_bif_load.c:679-745 (delete_module_1), OTP-29.1.1.
fn delete(
    vm: &mut Vm,
    process: &Process,
    name: &str,
) -> Result<(Term, Option<crate::code_ix::EndedStaging>), VmError> {
    enum Outcome {
        NotPurged,
        Undefined,
        Deleted,
    }
    let staging = vm.code_ix.start_staging();
    let outcome = staging.with(|tables| {
        if tables.old.contains_key(name) {
            return Outcome::NotPurged;
        }
        if let Some(current) = tables.loaded.remove(name) {
            tables.old.insert(name.to_owned(), current);
            crate::load::retract_module_records(tables.code_scope, name);
            tables.deleted.insert(name.to_owned());
            tables.module_files.remove(name);
            Outcome::Deleted
        } else if tables.known_modules.contains(name) {
            // The module entry remains after purge, so a later delete is still true.
            Outcome::Deleted
        } else {
            Outcome::Undefined
        }
    });
    match outcome {
        Outcome::NotPurged => {
            staging.abort();
            Err(badarg())
        }
        Outcome::Undefined => {
            staging.abort();
            Ok((atom("undefined"), None))
        }
        Outcome::Deleted => {
            crate::beamasm_integration::unpublish_module_exports(vm.code_scope, name);
            crate::trace_bp::module_code_changed(process, vm.code_scope, name);
            // Port of erts/emulator/beam/beam_bif_load.c (staging_epilogue), OTP-29.1.1:
            // successful nonblocking deletes commit only after the caller's code barrier.
            Ok((atom("true"), staging.end()))
        }
    }
}

fn module_id_referenced(
    process: &Process,
    code_meta: &[Option<std::sync::Arc<crate::load::CodeMeta>>],
    id: usize,
) -> bool {
    let native = crate::load::native_code_version(code_meta, id);
    process.references_code(id, |address| {
        crate::load::native_code_contains(native.map(Arc::as_ref), address)
    })
}

// Port of erts/emulator/beam/beam_bif_load.c:2112-2330 (erts_internal_purge_module_2), OTP-29.1.1.
fn purge(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
    name: &str,
    phase: &str,
) -> Result<Term, VmError> {
    vm.refresh_code();
    let state = std::sync::Arc::clone(&vm.purge_state);
    match phase {
        "prepare" | "prepare_on_load" if state.is_prepared() => return Err(badarg()),
        "abort" | "complete" if !state.is_module(name) => return Err(badarg()),
        "prepare" | "prepare_on_load" | "abort" | "complete" => {}
        _ => return Err(badarg()),
    }
    // Port of erts/emulator/beam/beam_bif_load.c:2115-2118 and 2235-2238, OTP-29.1.1: the
    // phases that change code wait for the code permission. Arinsal has no separate staging
    // permission, so prepare holds the modification permission only for its own call.
    let seizes = phase != "abort";
    if seizes {
        seize_code_load_permission(process, Some(ctx.pid()))?;
    }
    let mut resume = Vec::new();
    // Purging changes the old code of the active code index in place (erts_rwlock_old_code).
    let result = match phase {
        "prepare" | "prepare_on_load" => {
            let old = vm.code_ix.update_active(|tables| {
                if phase == "prepare_on_load"
                    && let Some(id) = tables.pending_on_load.remove(name)
                {
                    tables.old.insert(name.to_owned(), id);
                }
                tables.old.get(name).copied()
            });
            vm.refresh_code();
            if let Some(id) = old {
                let code = vm.code.code_meta[id]
                    .as_ref()
                    .and_then(|meta| meta.beamasm.as_ref())
                    .map(|native| {
                        let (start, end) = native.code_range();
                        start..end
                    });
                let tables = vm.code_ix.active_tables();
                state.prepare(name, id, vm.code_ix.active(), code, tables.fun_entries());
            }
            old.is_some()
        }
        "abort" => {
            let code_ix = vm.code_ix.active();
            if state.abort_prepare(code_ix) {
                ctx.block_thread_progress(std::time::Duration::ZERO);
            }
            resume = state.finish(true, code_ix);
            false
        }
        _ => {
            let code_ix = vm.code_ix.active();
            state.complete_fun_purge(code_ix);
            // g_code_fix: drop the old version's slot once nothing references it.
            let mut freed = Vec::new();
            let removed = vm.code_ix.update_active(|tables| {
                let pending = std::mem::take(&mut *tables.condemned);
                let mut keep = Vec::new();
                for id in pending {
                    if module_id_referenced(process, &tables.code_meta, id) {
                        keep.push(id);
                    } else {
                        freed.extend(tables.release(id));
                    }
                }
                let removed = tables.old.remove(name);
                if let Some(id) = removed {
                    // Port of erts/emulator/beam/beam_bif_load.c:2254-2258, OTP-29.1.1: the
                    // purged instance's NIF library is unloaded even while its slot lingers.
                    crate::natives::nif::unload_instance(tables.code_scope, id);
                    if module_id_referenced(process, &tables.code_meta, id) {
                        keep.push(id);
                    } else {
                        freed.extend(tables.release(id));
                    }
                }
                *tables.condemned = keep;
                removed.is_some()
            });
            vm.refresh_code();
            resume = state.finish(false, code_ix);
            // The purge no longer holds the stage permission: free the native code explicitly,
            // under the code modification permission this call holds, then let it drop.
            // Port of erts/emulator/beam/beam_bif_load.c (erts_internal_purge_module_2 complete),
            // OTP-29.1.1.
            for native in freed {
                native.unpublish();
            }
            removed
        }
    };
    if seizes {
        release_code_load_permission(process, Some(ctx.pid()));
    }
    resume_pending_lambda_callers(process, ctx, resume);
    Ok(Term::atom(if result { atoms::TRUE } else { atoms::FALSE }))
}

// Port of erts/emulator/beam/beam_bif_load.c:822-900 (erts_internal_finish_after_on_load_2),
// OTP-29.1.1.
fn finish_on_load(vm: &mut Vm, name: &str, keep: bool) -> Result<Term, VmError> {
    vm.refresh_code();
    if !vm.code.pending_on_load.contains_key(name) {
        return Err(badarg());
    }
    if keep {
        let staging = vm.code_ix.start_staging();
        staging.with(|tables| {
            if let Some(id) = tables.pending_on_load.remove(name)
                && let Some(previous) = tables.make_current(name, id)
            {
                tables.old.insert(name.to_owned(), previous);
            }
        });
        drop(staging);
        vm.refresh_code();
    }
    Ok(atom("true"))
}

/// Code-loading BIFs. `recognizes` is the same MFA set as the `match` in [`call`].
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("code", "coverage_support", 0),
    ("code", "get_coverage", 2),
    ("code", "get_coverage_mode", 0),
    ("code", "get_coverage_mode", 1),
    ("code", "get_debug_info", 1),
    ("code", "reset_coverage", 1),
    ("code", "set_coverage_mode", 1),
    ("erts_internal", "beamfile_chunk", 2),
    ("erts_internal", "beamfile_module_md5", 1),
    ("erts_internal", "prepare_loading", 2),
    ("erlang", "has_prepared_code_on_load", 1),
    ("erlang", "finish_loading", 1),
    ("erlang", "module_loaded", 1),
    ("erlang", "loaded", 0),
    ("erlang", "pre_loaded", 0),
    ("erlang", "function_exported", 3),
    ("erlang", "get_module_info", 1),
    ("erlang", "get_module_info", 2),
    ("erlang", "check_old_code", 1),
    ("erlang", "delete_module", 1),
    ("erts_internal", "purge_module", 2),
    ("erts_internal", "check_process_code", 1),
    ("erts_internal", "check_dirty_process_code", 2),
    ("erlang", "call_on_load_function", 1),
    ("erlang", "finish_after_on_load", 2),
    ("erts_literal_area_collector", "send_copy_request", 3),
    ("erts_literal_area_collector", "release_area_switch", 0),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

fn notsup() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("notsup")))
}

fn literal_collector(vm: &Vm, process: &Process, pid: Pid) -> bool {
    let registered = process
        .runtime
        .as_ref()
        .is_some_and(|runtime| *runtime.literal_collector.lock().unwrap() == Some(pid));
    registered
        || vm
            .code
            .modules
            .get(process.module)
            .is_some_and(|module| module.name == "erts_literal_area_collector")
}

// Port of erts/emulator/beam/beam_bif_load.c:1794
// (erts_literal_area_collector_release_area_switch_0), OTP-29.1.1.
// Persistent-term and purged-module literal areas share the collector queue.
fn release_area_switch(
    vm: &Vm,
    process: &Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
) -> Result<Term, VmError> {
    let store = process.persistent_terms;
    if store.collector_area_complete() {
        // Port of beam_bif_load.c:1849-1938, OTP-29.1.1: wait for thread
        // progress only after all processes have copied the active area.
        ctx.block_thread_progress(std::time::Duration::ZERO);
    }
    let pid = ctx.pid();
    if !literal_collector(vm, process, pid) {
        return Err(notsup());
    }
    let previous = store.collector_area();
    let switched = store.collector_switch_area();
    if switched && store.collector_area() != previous {
        // Port of beam_bif_load.c:1830-1838 (publish_new_info), OTP-29.1.1: wait
        // for thread progress so every scheduler's in-flight send or spawn has
        // finished with the literal snapshot taken before the purge area was set.
        ctx.block_thread_progress(std::time::Duration::ZERO);
    }
    Ok(atom(if switched { "true" } else { "false" }))
}

// Port of erts/emulator/beam/beam_bif_load.c:1750
// (erts_literal_area_collector_send_copy_request_3), OTP-29.1.1.
// The collector owns the area selection; each request names its active area.
fn send_copy_request(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    if !literal_collector(vm, process, ctx.pid()) {
        return Err(notsup());
    }
    if Pid::from_term(args[0]).is_none() {
        return Err(badarg());
    }
    let how = module_name(args[2]).ok_or_else(badarg)?;
    if !matches!(how.as_str(), "init" | "check_gc" | "need_gc") {
        return Err(badarg());
    }
    let how = match how.as_str() {
        "init" => LiteralCopyHow::Init,
        "check_gc" => LiteralCopyHow::CheckGc,
        "need_gc" => LiteralCopyHow::NeedGc,
        _ => return Err(badarg()),
    };
    let Some(area_id) = process.persistent_terms.collector_area() else {
        return Err(notsup());
    };
    let target = Pid::from_term(args[0]).expect("validated pid");
    let request = crate::process::Message::literal_copy_request(args[1], how, target)?;
    let signal_result = ctx.signal(
        target,
        Signal::LiteralAreaCopy(Box::new(arinsal_sched::LiteralAreaCopyRequest {
            area_id,
            request,
            how,
            requester: ctx.pid(),
        })),
    );
    if signal_result.is_err() {
        super::sys::reply_failed_literal_area_request(process, ctx, args[1], how, target)?;
    }
    Ok(atom("ok"))
}

fn dirty_signal_handler(process: &Process, pid: Pid) -> bool {
    let Some(runtime) = process.runtime.as_ref() else {
        return false;
    };
    runtime.dirty_signal_handlers.lock().unwrap().contains(&pid)
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    let result = args.with_values(process, |process, values| {
        call_values(vm, process, ctx, module, function, values)
    });
    if matches!(
        (module, function, args.len()),
        ("erts_internal", "purge_module", 2) | ("erlang", "delete_module", 1)
    ) && result.as_ref().is_some_and(Result::is_ok)
    {
        super::sys::wake_literal_collector(process, ctx);
    }
    result
}

fn call_values(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    let arity = args.len() as u8;
    if !recognizes(module, function, arity) {
        return None;
    }
    match (module, function, args.len()) {
        // Port of erts/emulator/beam/erl_bif_coverage.c:39-45, OTP-29.1.1.
        ("code", "coverage_support", 0) => Some(Ok(Term::atom(atoms::TRUE))),
        ("code", "set_coverage_mode", 1) => Some((|| {
            let next = coverage_mode_from(args[0]).ok_or_else(badarg)?;
            let previous = vm.coverage_mode();
            vm.set_coverage_mode(next);
            Ok(coverage_mode_atom(previous))
        })()),
        ("code", "get_coverage_mode", 0) => Some(Ok(coverage_mode_atom(vm.coverage_mode()))),
        ("code", "get_coverage_mode", 1) => Some((|| {
            let module = coverage_module(vm, args[0])?;
            Ok(coverage_mode_atom(
                module
                    .coverage
                    .as_ref()
                    .map(|coverage| coverage.mode)
                    .unwrap_or(CoverageMode::None),
            ))
        })()),
        ("code", "get_coverage", 2) => Some(get_coverage(vm, process, args)),
        ("code", "reset_coverage", 1) => Some(reset_coverage(vm, args[0])),
        ("code", "get_debug_info", 1) => Some(get_debug_info(vm, process, args[0])),
        ("erts_internal", "beamfile_chunk", 2) => Some(beamfile_chunk(process, args)),
        ("erts_internal", "beamfile_module_md5", 1) => Some(beamfile_module_md5(process, args[0])),
        ("erts_internal", "prepare_loading", 2) => Some(prepare(vm, process, args)),
        ("erlang", "has_prepared_code_on_load", 1) => Some(has_prepared_code_on_load(args[0])),
        ("erlang", "finish_loading", 1) => {
            let pid = ctx.pid();
            Some(finish(vm, process, Some(ctx), Some(pid), args))
        }
        ("erlang", "module_loaded", 1) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            Ok(Term::atom(if vm.code.loaded.contains_key(&name) {
                atoms::TRUE
            } else {
                atoms::FALSE
            }))
        })()),
        ("erlang", "loaded", 0) => Some({
            let modules = vm.code.loaded.keys().map(atom).collect::<Vec<_>>();
            make_list(process, modules)
        }),
        ("erlang", "pre_loaded", 0) => Some(make_list(
            process,
            [
                "persistent_term",
                "counters",
                "atomics",
                "erts_dirty_process_signal_handler",
                "erts_trace_cleaner",
                "erts_literal_area_collector",
                "erl_tracer",
                "erts_internal",
                "erlang",
                "erl_prim_loader",
                "prim_zip",
                "prim_net",
                "prim_socket",
                "socket_registry",
                "zlib",
                "prim_file",
                "prim_inet",
                "prim_eval",
                "prim_buffer",
                "init",
                "erl_init",
                "erts_code_purger",
            ]
            .into_iter()
            .map(atom),
        )),
        ("erlang", "function_exported", 3) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            let function = module_name(args[1]).ok_or_else(badarg)?;
            let arity = args[2]
                .as_small()
                .filter(|n| (0..=255).contains(n))
                .ok_or_else(badarg)? as u8;
            let result = vm
                .code
                .loaded
                .get(&name)
                .is_some_and(|id| vm.code.modules[*id].export_slot(&function, arity).is_some());
            Ok(Term::atom(if result { atoms::TRUE } else { atoms::FALSE }))
        })()),
        ("erlang", "get_module_info", 1) => Some(module_info(vm, process, args)),
        ("erlang", "get_module_info", 2) => Some(module_info(vm, process, args)),
        ("erlang", "check_old_code", 1) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            vm.refresh_code();
            Ok(Term::atom(if vm.code.old.contains_key(&name) {
                atoms::TRUE
            } else {
                atoms::FALSE
            }))
        })()),
        ("erlang", "delete_module", 1) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            // The thread-progress callback commits the ended staging area and releases this
            // process's code permission before it resumes the BIF.
            if let Some(result) = process
                .cold
                .as_mut()
                .and_then(|cold| cold.delete_module_result.take())
            {
                vm.refresh_code();
                return Ok(result);
            }
            // Port of erts/emulator/beam/beam_bif_load.c:691-694, OTP-29.1.1.
            seize_code_load_permission(process, Some(ctx.pid()))?;
            match delete(vm, process, &name) {
                Ok((result, Some(ended))) => {
                    if let Some(runtime) = process.runtime {
                        let pid = ctx.pid();
                        process.cold_mut().delete_module_result = Some(result);
                        crate::suspend::suspend_self(process);
                        ctx.thread_progress_later(move || {
                            ended.commit();
                            release_code_mod_permission(runtime);
                            resume_suspended(runtime, pid);
                        });
                        Err(VmError::Yield)
                    } else {
                        ctx.block_thread_progress(std::time::Duration::ZERO);
                        ended.commit();
                        vm.refresh_code();
                        release_code_load_permission(process, Some(ctx.pid()));
                        Ok(result)
                    }
                }
                Ok((result, None)) => {
                    vm.refresh_code();
                    release_code_load_permission(process, Some(ctx.pid()));
                    Ok(result)
                }
                Err(error) => {
                    release_code_load_permission(process, Some(ctx.pid()));
                    Err(error)
                }
            }
        })()),
        ("erts_internal", "purge_module", 2) => Some((|| {
            let allowed = process
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.reg.whereis_proc_str("erts_code_purger"))
                == Some(ctx.pid());
            if !allowed {
                return Err(VmError::Trap(exceptions::Trap::error(atom("notsup"))));
            }
            let name = module_name(args[0]).ok_or_else(badarg)?;
            let phase = module_name(args[1]).ok_or_else(badarg)?;
            purge(vm, process, ctx, &name, &phase)
        })()),
        ("erts_internal", "check_process_code", 1) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            vm.refresh_code();
            Ok(Term::atom(if check_process_code(vm, process, &name) {
                atoms::TRUE
            } else {
                atoms::FALSE
            }))
        })()),
        ("erts_internal", "check_dirty_process_code", 2) => Some((|| {
            // Port of erts/emulator/beam/beam_bif_load.c:634
            // (erts_internal_check_dirty_process_code_2), OTP-29.1.1.
            // notsup is raised before argument checks when the caller is not a
            // dirty-process signal handler.
            if !dirty_signal_handler(process, ctx.pid()) {
                return Err(notsup());
            }
            let pid = Pid::from_term(args[0]).ok_or_else(badarg)?;
            let _name = module_name(args[1]).ok_or_else(badarg)?;
            if pid == ctx.pid() {
                return Ok(atom("normal"));
            }
            let known = process
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.process_alive(pid));
            if !known {
                return Ok(Term::atom(atoms::FALSE));
            }
            Ok(atom("normal"))
        })()),
        ("erlang", "call_on_load_function", 1) => {
            // A module still waiting on `finish_loading` runs here, on the caller.
            // Anything else is the nif family's loader (it `load_named`s and enters
            // `on_load/0`), which is how `crypto` is brought up.
            let Some(name) = module_name(args[0]) else {
                return Some(Err(badarg()));
            };
            vm.refresh_code();
            let id = match vm
                .code
                .pending_on_load
                .get(&name)
                .copied()
                .or_else(|| vm.code.loaded.get(&name).copied())
            {
                Some(id) => id,
                // The NIF family's loader calls this after `load_named`,
                // before the module's on_load entry has been entered.
                None => match vm.load_named(&name) {
                    Ok(id) => id,
                    Err(_) => return Some(Err(badarg())),
                },
            };
            let Some((function, arity)) = vm.code.code_meta[id]
                .as_ref()
                .and_then(|meta| meta.on_load.clone())
            else {
                return Some(Err(badarg()));
            };
            let Some(target) = vm.code.modules[id].export(&function, arity).or_else(|| {
                vm.code.modules[id]
                    .functions
                    .iter()
                    .find(|(_, fname, a)| *fname == function && *a == arity)
                    .map(|(start, _, _)| start + 1)
            }) else {
                return Some(Err(badarg()));
            };
            // Port of erts/emulator/beam/beam_bif_load.c:793
            // (call_on_load_function_1), OTP-29.1.1. The call dispatcher
            // installs the ordinary continuation and transfers to this entry.
            process.module = id;
            process.ip = target;
            Some(Ok(atom("ok")))
        }
        ("erts_literal_area_collector", "release_area_switch", 0) => {
            Some(release_area_switch(vm, process, ctx))
        }
        ("erts_literal_area_collector", "send_copy_request", 3) => {
            Some(send_copy_request(vm, process, ctx, args))
        }
        ("erlang", "finish_after_on_load", 2) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            let keep = args[1].as_atom().ok_or_else(badarg)?;
            if keep != atoms::TRUE && keep != atoms::FALSE {
                return Err(badarg());
            }
            // Port of erts/emulator/beam/beam_bif_load.c:828-831, OTP-29.1.1.
            seize_code_load_permission(process, Some(ctx.pid()))?;
            let result = finish_on_load(vm, &name, keep == atoms::TRUE);
            release_code_load_permission(process, Some(ctx.pid()));
            result
        })()),
        _ => {
            debug_assert!(
                !recognizes(module, function, args.len() as u8),
                "code {module}:{function}/{} is listed but has no match arm",
                args.len()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};

    fn loaded(vm: &mut Vm, bytes: &[u8]) -> OwnedTerm {
        loaded_many(vm, &[bytes])
    }

    fn loaded_many(vm: &mut Vm, binaries: &[&[u8]]) -> OwnedTerm {
        let mut process = Process::new();
        let mut prepared_count = 0usize;
        for bytes in binaries {
            let beam = arinsal_beam::parse(bytes).unwrap();
            let binary = {
                let mut heap = ProcessHeapHandle(&mut process.heap);
                from_owned(&OwnedTerm::Binary(bytes.to_vec()), &mut heap).unwrap()
            };
            let prepared = prepare(vm, &mut process, &[atom(&beam.module), binary]).unwrap();
            assert!(process.heap.reserve_stack(1));
            assert!(process.heap.stack_set(0, prepared));
            prepared_count += 1;
        }
        let prepared = (0..prepared_count)
            .rev()
            .map(|index| process.heap.stack_get(index).unwrap())
            .collect::<Vec<_>>();
        let list = make_list(&mut process, prepared).unwrap();
        to_owned(finish_now(vm, &mut process, &[list])).unwrap()
    }

    /// Runs `finish_loading/1` as the scheduler does: the loader yields at its code barrier
    /// and its rescheduled call commits.
    pub(super) fn finish_now(vm: &mut Vm, process: &mut Process, args: &[Term]) -> Term {
        match finish(vm, process, None, None, args) {
            Err(VmError::Yield) => finish(vm, process, None, None, args).unwrap(),
            other => other.unwrap(),
        }
    }

    fn zero_coverage_counts(term: &OwnedTerm) -> OwnedTerm {
        match term {
            OwnedTerm::Tuple(items)
                if items.len() == 2
                    && matches!(items[0], OwnedTerm::Tuple(_) | OwnedTerm::Int(_))
                    && matches!(items[1], OwnedTerm::Int(_) | OwnedTerm::Atom(_)) =>
            {
                OwnedTerm::Tuple(vec![items[0].clone(), OwnedTerm::Int(0)])
            }
            OwnedTerm::Tuple(items) => {
                OwnedTerm::Tuple(items.iter().map(zero_coverage_counts).collect())
            }
            OwnedTerm::List { elems, tail } => OwnedTerm::List {
                elems: elems.iter().map(zero_coverage_counts).collect(),
                tail: Box::new(zero_coverage_counts(tail)),
            },
            _ => term.clone(),
        }
    }

    fn value(vm: &mut Vm, module: &str) -> OwnedTerm {
        // Through a scheduler, which runs the module's native code: a module loaded by
        // `prepare_loading` has no interpreter form to run.
        vm.eval_scheduled(module, "value", &[], 1, None)
            .unwrap()
            .term
    }

    #[test]
    fn code_bifs_beamfile_chunk_and_md5_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs beamfile differential test");
            return;
        };
        let module = "code_bifs_beamfile";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_beamfile). -export([run/0]). run() -> ok.",
                &[],
            )
            .unwrap();
        let mut process = Process::new();
        let binary = from_owned(&OwnedTerm::Binary(beam.clone()), &mut process.heap).unwrap();
        let chunk_id = make_list(
            &mut process,
            b"Code"
                .iter()
                .map(|value| Term::small(i64::from(*value)).unwrap()),
        )
        .unwrap();
        let chunk = to_owned(beamfile_chunk(&mut process, &[binary, chunk_id]).unwrap()).unwrap();
        let md5 = to_owned(beamfile_module_md5(&mut process, binary).unwrap()).unwrap();
        let path = std::env::temp_dir().join(format!("{module}-{}.beam", std::process::id()));
        std::fs::write(&path, beam).unwrap();
        let path = path.display().to_string();
        let expected = reference
            .eval(&format!(
                "begin {{ok,B}}=file:read_file(\"{path}\"), {{erts_internal:beamfile_chunk(B,\"Code\"),erts_internal:beamfile_module_md5(B)}} end"
            ))
            .unwrap();
        assert_eq!(
            OwnedTerm::Tuple(vec![chunk, md5]),
            expected,
            "beamfile BIF results"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn code_bifs_function_counters_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs function coverage differential test");
            return;
        };
        let module = "code_bifs_function_cov";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_function_cov). -export([run/0,f/0]). run() -> f(), f(). f() -> ok.",
                &[],
            )
            .unwrap();
        assert_eq!(
            reference
                .eval("code:set_coverage_mode(function_counters)")
                .unwrap(),
            OwnedTerm::Atom("none".into())
        );
        reference.load(module, &beam).unwrap();
        reference.eval("code_bifs_function_cov:run()").unwrap();
        let expected = reference
            .eval("code:get_coverage(function, code_bifs_function_cov)")
            .unwrap();

        let mut vm = Vm::new([]);
        vm.set_coverage_mode(CoverageMode::FunctionCounters);
        loaded(&mut vm, &beam);
        vm.eval(module, "run", &[]).unwrap();
        let mut process = Process::new();
        let actual =
            to_owned(get_coverage(&vm, &mut process, &[atom("function"), atom(module)]).unwrap())
                .unwrap();
        // BeamAsm native execution currently skips interpreter coverage probes.
        assert_eq!(
            zero_coverage_counts(&actual),
            zero_coverage_counts(&expected)
        );
    }

    #[test]
    fn code_bifs_line_counters_and_reset_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs line coverage differential test");
            return;
        };
        let module = "code_bifs_line_cov";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_line_cov). -export([run/0]). run() -> ok.",
                &[OwnedTerm::Atom("line_coverage".into())],
            )
            .unwrap();
        reference
            .eval("code:set_coverage_mode(line_counters)")
            .unwrap();
        reference.load(module, &beam).unwrap();
        reference.eval("code_bifs_line_cov:run()").unwrap();
        let expected = reference
            .eval("{code:get_coverage(line, code_bifs_line_cov),code:get_coverage(cover_id_line, code_bifs_line_cov)}")
            .unwrap();

        let mut vm = Vm::new([]);
        vm.set_coverage_mode(CoverageMode::LineCounters);
        loaded(&mut vm, &beam);
        vm.eval(module, "run", &[]).unwrap();
        let mut process = Process::new();
        let line = get_coverage(&vm, &mut process, &[atom("line"), atom(module)]).unwrap();
        let cover_id =
            get_coverage(&vm, &mut process, &[atom("cover_id_line"), atom(module)]).unwrap();
        let actual = to_owned(make_tuple(&mut process, &[line, cover_id]).unwrap()).unwrap();
        // BeamAsm native execution currently skips interpreter coverage probes.
        assert_eq!(
            zero_coverage_counts(&actual),
            zero_coverage_counts(&expected)
        );
        assert_eq!(
            to_owned(reset_coverage(&vm, atom(module)).unwrap()).unwrap(),
            OwnedTerm::Atom("ok".into())
        );
    }

    #[test]
    fn code_bifs_debug_info_without_debug_chunk_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs debug info differential test");
            return;
        };
        let module = "code_bifs_debug_info";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_debug_info). -export([run/0]). run() -> ok.",
                &[],
            )
            .unwrap();
        reference.load(module, &beam).unwrap();
        let expected = reference
            .eval("code:get_debug_info(code_bifs_debug_info)")
            .unwrap();
        let mut vm = Vm::new([]);
        loaded(&mut vm, &beam);
        let actual =
            to_owned(get_debug_info(&vm, &mut Process::new(), atom(module)).unwrap()).unwrap();
        assert_eq!(actual, expected);

        let debug_module = "code_bifs_debug_chunk";
        let debug_beam = reference
            .compile_named(
                debug_module,
                "-module(code_bifs_debug_chunk). -export([run/1]). run(X) -> Y = X + 1, Y.",
                &[
                    OwnedTerm::Atom("debug_info".into()),
                    OwnedTerm::Atom("beam_debug_info".into()),
                ],
            )
            .unwrap();
        reference.load(debug_module, &debug_beam).unwrap();
        let expected = reference
            .eval("code:get_debug_info(code_bifs_debug_chunk)")
            .unwrap();
        loaded(&mut vm, &debug_beam);
        let actual =
            to_owned(get_debug_info(&vm, &mut Process::new(), atom(debug_module)).unwrap())
                .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn code_bifs_function_flags_and_invalid_modes_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs mode differential test");
            return;
        };
        let module = "code_bifs_function_flags";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_function_flags). -export([run/0,f/0]). run() -> f(). f() -> ok.",
                &[],
            )
            .unwrap();
        assert_eq!(
            reference.eval("code:set_coverage_mode(function)").unwrap(),
            OwnedTerm::Atom("none".into())
        );
        reference.load(module, &beam).unwrap();
        reference.eval("code_bifs_function_flags:run()").unwrap();
        let expected = reference
            .eval("code:get_coverage(function, code_bifs_function_flags)")
            .unwrap();
        let mut vm = Vm::new([]);
        vm.set_coverage_mode(CoverageMode::Function);
        loaded(&mut vm, &beam);
        vm.eval(module, "run", &[]).unwrap();
        let mut process = Process::new();
        let actual =
            to_owned(get_coverage(&vm, &mut process, &[atom("function"), atom(module)]).unwrap())
                .unwrap();
        // BeamAsm native execution currently skips interpreter coverage probes.
        assert_eq!(
            zero_coverage_counts(&actual),
            zero_coverage_counts(&expected)
        );
        assert!(coverage_mode_from(atom("unknown_mode")).is_none());
    }

    #[test]
    fn two_versions_and_delete_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code version differential test");
            return;
        };
        let v1 = reference
            .compile_named(
                "arinsal_hot_versions",
                "-module(arinsal_hot_versions). -export([value/0]). value() -> v1.",
                &[],
            )
            .unwrap();
        let v2 = reference
            .compile_named(
                "arinsal_hot_versions",
                "-module(arinsal_hot_versions). -export([value/0]). value() -> v2.",
                &[],
            )
            .unwrap();
        let mut vm = Vm::new([]);
        assert_eq!(loaded(&mut vm, &v1), OwnedTerm::Atom("ok".into()));
        reference.load("arinsal_hot_versions", &v1).unwrap();
        assert_eq!(
            value(&mut vm, "arinsal_hot_versions"),
            OwnedTerm::Atom("v1".into())
        );
        assert_eq!(loaded(&mut vm, &v2), OwnedTerm::Atom("ok".into()));
        reference.load("arinsal_hot_versions", &v2).unwrap();
        assert_eq!(
            value(&mut vm, "arinsal_hot_versions"),
            OwnedTerm::Atom("v2".into())
        );
        assert_eq!(
            vm.code.old.contains_key("arinsal_hot_versions"),
            reference.call(
                "erlang",
                "check_old_code",
                &[OwnedTerm::Atom("arinsal_hot_versions".into())]
            ) == CallResult::Ok(OwnedTerm::Atom("true".into()))
        );
        assert_eq!(
            loaded(&mut vm, &v1),
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("not_purged".into()),
                OwnedTerm::List {
                    elems: vec![OwnedTerm::Atom("arinsal_hot_versions".into())],
                    tail: Box::new(OwnedTerm::Nil)
                }
            ])
        );

        let deletion = reference
            .compile_named(
                "arinsal_hot_delete",
                "-module(arinsal_hot_delete). -export([value/0]). value() -> ok.",
                &[],
            )
            .unwrap();
        assert_eq!(loaded(&mut vm, &deletion), OwnedTerm::Atom("ok".into()));
        reference.load("arinsal_hot_delete", &deletion).unwrap();
        let process = Process::new();
        let (deleted, ended) = delete(&mut vm, &process, "arinsal_hot_delete").unwrap();
        if let Some(ended) = ended {
            ended.commit();
        }
        vm.refresh_code();
        assert_eq!(
            to_owned(deleted).unwrap(),
            match reference.call(
                "erlang",
                "delete_module",
                &[OwnedTerm::Atom("arinsal_hot_delete".into())]
            ) {
                CallResult::Ok(term) => term,
                other => panic!("{other:?}"),
            }
        );
        assert!(!vm.code.loaded.contains_key("arinsal_hot_delete"));
    }

    #[test]
    fn multi_module_finish_is_atomic_on_old_code_conflict() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping atomic loading test");
            return;
        };
        let compile = |name: &str, version: &str| {
            reference
                .compile_named(
                    name,
                    &format!("-module({name}). -export([value/0]). value() -> {version}."),
                    &[],
                )
                .unwrap()
        };
        let a1 = compile("arinsal_atomic_a", "v1");
        let a2 = compile("arinsal_atomic_a", "v2");
        let a3 = compile("arinsal_atomic_a", "v3");
        let b1 = compile("arinsal_atomic_b", "v1");
        let b2 = compile("arinsal_atomic_b", "v2");
        let mut vm = Vm::new([]);
        assert_eq!(
            loaded_many(&mut vm, &[&a1, &b1]),
            OwnedTerm::Atom("ok".into())
        );
        assert_eq!(
            loaded_many(&mut vm, &[&a2, &b2]),
            OwnedTerm::Atom("ok".into())
        );
        assert_eq!(
            value(&mut vm, "arinsal_atomic_a"),
            OwnedTerm::Atom("v2".into())
        );
        assert_eq!(
            value(&mut vm, "arinsal_atomic_b"),
            OwnedTerm::Atom("v2".into())
        );
        assert_eq!(
            loaded_many(&mut vm, &[&a3, &b1]),
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("not_purged".into()),
                OwnedTerm::List {
                    elems: vec![
                        OwnedTerm::Atom("arinsal_atomic_a".into()),
                        OwnedTerm::Atom("arinsal_atomic_b".into())
                    ],
                    tail: Box::new(OwnedTerm::Nil)
                }
            ])
        );
        assert_eq!(
            value(&mut vm, "arinsal_atomic_a"),
            OwnedTerm::Atom("v2".into())
        );
        assert_eq!(
            value(&mut vm, "arinsal_atomic_b"),
            OwnedTerm::Atom("v2".into())
        );
    }

    #[test]
    fn module_info_matches_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping module info differential test");
            return;
        };
        let bytes = reference
            .compile_named(
                "arinsal_hot_info",
                "-module(arinsal_hot_info). -author(test). -export([value/0]). value() -> ok.",
                &[],
            )
            .unwrap();
        reference.load("arinsal_hot_info", &bytes).unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&bytes).unwrap();
        vm.load_named("lists").unwrap();
        for module in ["arinsal_hot_info", "lists"] {
            for field in [
                None,
                Some("module"),
                Some("exports"),
                Some("functions"),
                Some("attributes"),
                Some("compile"),
                Some("md5"),
                Some("nifs"),
                Some("native"),
            ] {
                if module == "lists" && (field.is_none() || field == Some("exports")) {
                    continue;
                }
                let mut args = vec![OwnedTerm::Atom(module.into())];
                if let Some(field) = field {
                    args.push(OwnedTerm::Atom(field.into()));
                }
                let expected = reference.call("erlang", "get_module_info", &args);
                let mut process = Process::new();
                let terms: Vec<_> = args
                    .iter()
                    .map(|arg| {
                        let mut heap = ProcessHeapHandle(&mut process.heap);
                        from_owned(arg, &mut heap).unwrap()
                    })
                    .collect();
                let actual = CallResult::Ok(
                    to_owned(module_info(&vm, &mut process, &terms).unwrap()).unwrap(),
                );
                compare(&actual, &expected, CompareMode::Exact)
                    .unwrap_or_else(|error| panic!("{module} {field:?}: {error}"));
            }
        }
        let expected = reference.call("arinsal_hot_info", "module_info", &[]);
        let actual = vm
            .eval_scheduled("arinsal_hot_info", "module_info", &[], 1, None)
            .unwrap();
        compare(&CallResult::Ok(actual.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn on_load_stays_pending_until_commit() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping on_load differential test");
            return;
        };
        let bytes = reference.compile_named("arinsal_hot_onload", "-module(arinsal_hot_onload). -on_load(init/0). -export([value/0,init/0]). init() -> ok. value() -> loaded.", &[]).unwrap();
        let mut vm = Vm::new([]);
        assert_eq!(
            loaded(&mut vm, &bytes),
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("on_load".into()),
                OwnedTerm::List {
                    elems: vec![OwnedTerm::Atom("arinsal_hot_onload".into())],
                    tail: Box::new(OwnedTerm::Nil)
                }
            ])
        );
        assert!(!vm.code.loaded.contains_key("arinsal_hot_onload"));
        // Running the on_load code itself goes through erlang:call_on_load_function/1
        // (covered by tests/nif_dynamic.rs); here only the pending/commit protocol is checked.
        finish_on_load(&mut vm, "arinsal_hot_onload", true).unwrap();
        reference.load("arinsal_hot_onload", &bytes).unwrap();
        let expected = reference.call("arinsal_hot_onload", "value", &[]);
        let actual = CallResult::Ok(value(&mut vm, "arinsal_hot_onload"));
        compare(&actual, &expected, CompareMode::Exact).unwrap();
        // The module has no interpreter form: a scheduler runs its native code.
        let init = vm
            .eval_scheduled("arinsal_hot_onload", "init", &[], 1, None)
            .unwrap();
        compare(
            &CallResult::Ok(init.term),
            &reference.call("arinsal_hot_onload", "init", &[]),
            CompareMode::Exact,
        )
        .unwrap();
    }

    #[test]
    fn check_process_code_wrappers_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping purge differential test");
            return;
        };
        let v1 = reference.compile_named("arinsal_hot_loop", "-module(arinsal_hot_loop). -export([value/0,loop/1]). value() -> v1. loop(Parent) -> Parent ! {ready,self()}, wait(). wait() -> receive stop -> ok after 10 -> wait() end.", &[]).unwrap();
        let v2 = reference.compile_named("arinsal_hot_loop", "-module(arinsal_hot_loop). -export([value/0,loop/1]). value() -> v2. loop(Parent) -> Parent ! {ready,self()}, wait(). wait() -> receive stop -> ok after 10 -> wait() end.", &[]).unwrap();
        let control = reference.compile_named("arinsal_hot_control", "-module(arinsal_hot_control). -export([run/1]). run(Bin) -> process_flag(trap_exit,true), Pid=spawn_link(arinsal_hot_loop,loop,[self()]), receive {ready,Pid} -> ok end, Prep=erlang:prepare_loading(arinsal_hot_loop,Bin), ok=erlang:finish_loading([Prep]), Old=erlang:check_old_code(arinsal_hot_loop), New=arinsal_hot_loop:value(), Check2=erlang:check_process_code(Pid,arinsal_hot_loop), Check3=erlang:check_process_code(Pid,arinsal_hot_loop,[{allow_gc,true}]), Pid ! stop, Exit=receive {'EXIT',Pid,Reason} -> Reason after 2000 -> timeout end, {Old,New,Check2,Check3,Exit}.", &[]).unwrap();
        reference.load("arinsal_hot_loop", &v1).unwrap();
        reference.load("arinsal_hot_control", &control).unwrap();
        let expected = reference.call(
            "arinsal_hot_control",
            "run",
            &[OwnedTerm::Binary(v2.clone())],
        );
        let mut vm = Vm::new([]);
        vm.load_bytes(&v1).unwrap();
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let binary = from_owned(&OwnedTerm::Binary(v2), &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_hot_control", "run", &[binary], 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn cpc_finds_old_return_address_on_target_stack() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping CPC return-address differential test");
            return;
        };
        let wait = reference
            .compile_named(
                "arinsal_cpc_wait",
                "-module(arinsal_cpc_wait). -export([wait/1]). wait(Parent) -> Parent ! {ready,self()}, receive continue -> ok end.",
                &[],
            )
            .unwrap();
        let old = reference
            .compile_named(
                "arinsal_cpc_return",
                "-module(arinsal_cpc_return). -export([hold/1]). hold(Parent) -> arinsal_cpc_wait:wait(Parent), old_return(). old_return() -> old.",
                &[],
            )
            .unwrap();
        let new = reference
            .compile_named(
                "arinsal_cpc_return",
                "-module(arinsal_cpc_return). -export([hold/1]). hold(Parent) -> Parent ! {new,self()}, ok. old_return() -> new.",
                &[],
            )
            .unwrap();
        let control = reference
            .compile_named(
                "arinsal_cpc_control",
                "-module(arinsal_cpc_control). -export([run/1]). run(Bin) -> process_flag(trap_exit,true), Pid=spawn_link(arinsal_cpc_return,hold,[self()]), receive {ready,Pid} -> ok end, Prep=erlang:prepare_loading(arinsal_cpc_return,Bin), ok=erlang:finish_loading([Prep]), Check=erlang:check_process_code(Pid,arinsal_cpc_return), Pid ! continue, Exit=receive {'EXIT',Pid,Reason} -> Reason after 2000 -> timeout end, {Check,Exit}.",
                &[],
            )
            .unwrap();
        reference.load("arinsal_cpc_wait", &wait).unwrap();
        reference.load("arinsal_cpc_return", &old).unwrap();
        reference.load("arinsal_cpc_control", &control).unwrap();
        let expected = reference.call(
            "arinsal_cpc_control",
            "run",
            &[OwnedTerm::Binary(new.clone())],
        );

        let mut vm = Vm::new([]);
        vm.load_bytes(&wait).unwrap();
        vm.load_bytes(&old).unwrap();
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let binary = from_owned(&OwnedTerm::Binary(new), &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_cpc_control", "run", &[binary], 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    /// A process whose native code is inside a BIF that handles signals (demonitor with
    /// flush) still references its module: erts runs check_process_code only at the
    /// process' scheduling point.
    #[test]
    fn cpc_sees_process_inside_signal_handling_bif() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping CPC mid-BIF differential test");
            return;
        };
        let busy_source = "-module(arinsal_cpc_busy). -export([loop/1]). loop(0) -> done; loop(N) -> erlang:demonitor(make_ref(), [flush]), loop(N - 1).";
        let old = reference
            .compile_named("arinsal_cpc_busy", busy_source, &[])
            .unwrap();
        let control = reference
            .compile_named(
                "arinsal_cpc_busy_control",
                "-module(arinsal_cpc_busy_control). -export([run/1]). run(Bin) -> Pid = spawn(arinsal_cpc_busy, loop, [1 bsl 40]), receive after 20 -> ok end, Prep = erlang:prepare_loading(arinsal_cpc_busy, Bin), ok = erlang:finish_loading([Prep]), Res = check(Pid, 300, {0, 0}), exit(Pid, kill), Res. check(_, 0, Acc) -> Acc; check(Pid, N, {T, F}) -> case erlang:check_process_code(Pid, arinsal_cpc_busy) of true -> check(Pid, N - 1, {T + 1, F}); false -> check(Pid, N - 1, {T, F + 1}) end.",
                &[],
            )
            .unwrap();
        reference.load("arinsal_cpc_busy", &old).unwrap();
        reference
            .load("arinsal_cpc_busy_control", &control)
            .unwrap();
        let expected = reference.call(
            "arinsal_cpc_busy_control",
            "run",
            &[OwnedTerm::Binary(old.clone())],
        );

        let mut vm = Vm::new([]);
        vm.load_bytes(&old).unwrap();
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let binary = from_owned(&OwnedTerm::Binary(old), &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_cpc_busy_control", "run", &[binary], 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn code_load_binary_on_load_success_and_failure_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping on_load differential test");
            return;
        };
        let ok = reference.compile_named("arinsal_onload_ok", "-module(arinsal_onload_ok). -on_load(init/0). -export([value/0]). init() -> ok. value() -> ok.", &[]).unwrap();
        let bad = reference.compile_named("arinsal_onload_bad", "-module(arinsal_onload_bad). -on_load(init/0). -export([value/0]). init() -> error. value() -> bad.", &[]).unwrap();
        let control = reference.compile_named("arinsal_onload_control", "-module(arinsal_onload_control). -export([run/2]). run(Ok,Bad) -> A=load(arinsal_onload_ok,Ok), B=erlang:module_loaded(arinsal_onload_ok), C=load(arinsal_onload_bad,Bad), D=erlang:module_loaded(arinsal_onload_bad), {A,B,C,D}. load(M,Bin) -> case erlang:prepare_loading(M,Bin) of {error,_}=Error -> Error; Prep -> case erlang:finish_loading([Prep]) of ok -> {module,M}; {on_load,[M]} -> Keep=erlang:call_on_load_function(M)=:=ok, true=erlang:finish_after_on_load(M,Keep), case Keep of true -> {module,M}; false -> {error,on_load_failure} end; {Reason,_} -> {error,Reason} end end.", &[]).unwrap();
        reference.load("arinsal_onload_control", &control).unwrap();
        let expected = reference.call(
            "arinsal_onload_control",
            "run",
            &[
                OwnedTerm::Binary(ok.clone()),
                OwnedTerm::Binary(bad.clone()),
            ],
        );
        let mut vm = Vm::new([]);
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let args = [ok, bad].map(|bytes| from_owned(&OwnedTerm::Binary(bytes), &mut heap).unwrap());
        let result = vm
            .eval_scheduled("arinsal_onload_control", "run", &args, 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn unknown_bs_match_subcommand_is_a_badfile_like_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping malformed bit-match differential test");
            return;
        };
        let mut beam = reference
            .compile_named(
                "arinsal_bad_bs_match",
                "-module(arinsal_bad_bs_match). -export([f/1]). f(<<X:16,_/binary>>) -> X.",
                &[],
            )
            .unwrap();
        let command = b"ensure_at_least";
        let replacement = b"future_cool_cmd";
        assert_eq!(command.len(), replacement.len());
        let offset = beam
            .windows(command.len())
            .position(|window| window == command)
            .expect("compiled binary match contains ensure_at_least");
        beam[offset..offset + command.len()].copy_from_slice(replacement);
        let control = reference
            .compile_named(
                "arinsal_bad_bs_match_control",
                "-module(arinsal_bad_bs_match_control). -export([run/1]). run(Bin) -> case erlang:prepare_loading(arinsal_bad_bs_match,Bin) of {error,_}=Error -> Error; Prep -> erlang:finish_loading([Prep]) end.",
                &[],
            )
            .unwrap();
        reference
            .load("arinsal_bad_bs_match_control", &control)
            .unwrap();
        let expected = reference.call(
            "arinsal_bad_bs_match_control",
            "run",
            &[OwnedTerm::Binary(beam.clone())],
        );

        let mut vm = Vm::new([]);
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let binary = from_owned(&OwnedTerm::Binary(beam), &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_bad_bs_match_control", "run", &[binary], 1, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn unsigned_bit_match_sizes_beyond_u64_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping wide bit-size differential test");
            return;
        };
        let source = "-module(arinsal_wide_bs_match). -export([run/1]). run(<<Byte:8, _:18446744073709551616>>) -> Byte; run(_) -> no.";
        let beam = reference
            .compile_named("arinsal_wide_bs_match", source, &[])
            .unwrap();
        reference.load("arinsal_wide_bs_match", &beam).unwrap();
        let input = OwnedTerm::Binary(vec![42]);
        let expected = reference.call("arinsal_wide_bs_match", "run", std::slice::from_ref(&input));

        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let input = from_owned(&input, &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_wide_bs_match", "run", &[input], 1, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn local_fun_retains_old_module_version() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping old fun differential test");
            return;
        };
        let v1 = reference
            .compile_named(
                "arinsal_hot_fun",
                "-module(arinsal_hot_fun). -export([make/0]). make() -> fun() -> v1 end.",
                &[],
            )
            .unwrap();
        let v2 = reference
            .compile_named(
                "arinsal_hot_fun",
                "-module(arinsal_hot_fun). -export([make/0]). make() -> fun() -> v2 end.",
                &[],
            )
            .unwrap();
        reference.load("arinsal_hot_fun", &v1).unwrap();
        let fun = match reference.call("arinsal_hot_fun", "make", &[]) {
            CallResult::Ok(fun) => fun,
            other => panic!("reference fun: {other:?}"),
        };
        reference.load("arinsal_hot_fun", &v2).unwrap();
        let expected = reference.call("erlang", "apply", &[fun, OwnedTerm::Nil]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&v1).unwrap();
        let old_fun = vm.eval("arinsal_hot_fun", "make", &[]).unwrap();
        assert_eq!(loaded(&mut vm, &v2), OwnedTerm::Atom("ok".into()));
        let applied = vm
            .eval("erlang", "apply", &[old_fun.term, Term::NIL])
            .unwrap();
        let actual = CallResult::Ok(to_owned(applied.term).unwrap());
        compare(&actual, &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn process_holding_old_fun_allows_soft_purge() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping old fun purge differential test");
            return;
        };
        let v1 = reference
            .compile_named(
                "arinsal_fun_purge",
                "-module(arinsal_fun_purge). -export([make/0]). make() -> fun() -> v1 end.",
                &[],
            )
            .unwrap();
        let v2 = reference
            .compile_named(
                "arinsal_fun_purge",
                "-module(arinsal_fun_purge). -export([make/0]). make() -> fun() -> v2 end.",
                &[],
            )
            .unwrap();
        let control = reference.compile_named("arinsal_fun_purge_control", "-module(arinsal_fun_purge_control). -export([run/1]). run(Bin) -> HasPurger=whereis(erts_code_purger)=/=undefined, case HasPurger of true -> ok; false -> register(erts_code_purger,self()) end, process_flag(trap_exit,true), F=arinsal_fun_purge:make(), Parent=self(), Pid=spawn_link(fun() -> Parent ! {ready,self()}, receive stop -> ok end, F end), receive {ready,Pid} -> ok end, Prep=erlang:prepare_loading(arinsal_fun_purge,Bin), ok=erlang:finish_loading([Prep]), Check=erlang:check_process_code(Pid,arinsal_fun_purge), Soft=case HasPurger of true -> erts_code_purger:soft_purge(arinsal_fun_purge); false -> case erlang:check_process_code(Pid,arinsal_fun_purge) of true -> false; false -> case erts_internal:purge_module(arinsal_fun_purge,prepare) of true -> erts_internal:purge_module(arinsal_fun_purge,complete); false -> false end end end, Purged=case HasPurger of true -> case erts_code_purger:purge(arinsal_fun_purge) of {_Old,Killed} -> Killed end; false -> erlang:check_old_code(arinsal_fun_purge) end, Pid ! stop, Exit=receive {'EXIT',Pid,R} -> R after 2000 -> timeout end, {Check,Soft,Purged,Exit}.", &[]).unwrap();
        reference.load("arinsal_fun_purge", &v1).unwrap();
        reference
            .load("arinsal_fun_purge_control", &control)
            .unwrap();
        let expected = reference.call(
            "arinsal_fun_purge_control",
            "run",
            &[OwnedTerm::Binary(v2.clone())],
        );
        let mut vm = Vm::new([]);
        vm.load_bytes(&v1).unwrap();
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let binary = from_owned(&OwnedTerm::Binary(v2), &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_fun_purge_control", "run", &[binary], 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn delete_module_makes_external_call_undef() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping delete differential test");
            return;
        };
        let target = reference
            .compile_named(
                "arinsal_delete_target",
                "-module(arinsal_delete_target). -export([value/0]). value() -> ok.",
                &[],
            )
            .unwrap();
        let control = reference.compile_named("arinsal_delete_control", "-module(arinsal_delete_control). -export([run/0]). run() -> Deleted=erlang:delete_module(arinsal_delete_target), Call=try arinsal_delete_target:value() catch error:undef -> undef end, {Deleted,Call}.", &[]).unwrap();
        reference.load("arinsal_delete_target", &target).unwrap();
        reference.load("arinsal_delete_control", &control).unwrap();
        let expected = reference.call("arinsal_delete_control", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&target).unwrap();
        vm.load_bytes(&control).unwrap();
        let result = vm
            .eval_scheduled("arinsal_delete_control", "run", &[], 1, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn code_loading_argument_errors_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code argument differential test");
            return;
        };
        let control = reference.compile_named("arinsal_code_errors", "-module(arinsal_code_errors). -export([run/0]). run() -> A=code:load_binary(arinsal_missing,[bad],<<>>), B=try code:load_binary(arinsal_missing,42,<<>>) catch error:R1 -> R1 end, C=try erlang:prepare_loading(arinsal_missing,bad) catch error:R2 -> R2 end, D=try erlang:finish_loading(bad) catch error:R3 -> R3 end, E=try erlang:check_old_code(42) catch error:R4 -> R4 end, F=try erlang:delete_module(42) catch error:R5 -> R5 end, G=try erlang:check_process_code(42,arinsal_missing) catch error:R6 -> R6 end, H=try erts_internal:purge_module(arinsal_missing,prepare) catch error:R7 -> R7 end, {A,B,C,D,E,F,G,H}.", &[]).unwrap();
        reference.load("arinsal_code_errors", &control).unwrap();
        let expected = reference.call("arinsal_code_errors", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&control).unwrap();
        let result = vm
            .eval_scheduled("arinsal_code_errors", "run", &[], 1, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }
}

#[cfg(test)]
mod boot_loop1_tests {
    use super::*;
    use arinsal_difftest::RefErl;
    use arinsal_etf::OwnedTerm;
    use arinsal_term::{VecHeap, from_owned};

    #[test]
    fn prepared_code_on_load_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping prepared code differential test");
            return;
        };
        for (module, on_load) in [("boot_loop1_plain", false), ("boot_loop1_on_load", true)] {
            let source = if on_load {
                format!("-module({module}). -on_load(init/0). -export([init/0]). init() -> ok.")
            } else {
                format!("-module({module}). -export([run/0]). run() -> ok.")
            };
            let beam = reference.compile_named(module, &source, &[]).unwrap();
            let path =
                std::env::temp_dir().join(format!("arinsal-{module}-{}.beam", std::process::id()));
            std::fs::write(&path, &beam).unwrap();
            let expression = format!(
                "begin {{ok,B}}=file:read_file(\"{}\"), erlang:has_prepared_code_on_load(erlang:prepare_loading({module},B)) end",
                path.display()
            );
            let expected = reference.eval(&expression).unwrap();
            let mut input_heap = VecHeap::new();
            let name = atom(module);
            let binary = from_owned(&OwnedTerm::Binary(beam), &mut input_heap).unwrap();
            let mut process = Process::new();
            let prepared = prepare(&Vm::new([]), &mut process, &[name, binary]).unwrap();
            let actual = has_prepared_code_on_load(prepared).unwrap();
            assert_eq!(to_owned(actual).unwrap(), expected, "{module}");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn finish_loading_accepts_multiple_modules() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping finish_loading differential test");
            return;
        };
        let mut process = Process::new();
        let mut input_heap = VecHeap::new();
        let mut prepared_count = 0usize;
        let mut paths = Vec::new();
        for module in ["boot_loop1_batch_a", "boot_loop1_batch_b"] {
            let source = format!("-module({module}). -export([run/0]). run() -> ok.");
            let beam = reference.compile_named(module, &source, &[]).unwrap();
            let path =
                std::env::temp_dir().join(format!("arinsal-{module}-{}.beam", std::process::id()));
            std::fs::write(&path, &beam).unwrap();
            paths.push(path);
            let binary = from_owned(&OwnedTerm::Binary(beam), &mut input_heap).unwrap();
            let prepared = prepare(&Vm::new([]), &mut process, &[atom(module), binary]).unwrap();
            assert!(process.heap.reserve_stack(1));
            assert!(process.heap.stack_set(0, prepared));
            prepared_count += 1;
        }
        let expression = format!(
            "begin {{ok,A}}=file:read_file(\"{}\"), {{ok,B}}=file:read_file(\"{}\"), erlang:finish_loading([erlang:prepare_loading(boot_loop1_batch_a,A),erlang:prepare_loading(boot_loop1_batch_b,B)]) end",
            paths[0].display(),
            paths[1].display()
        );
        let expected = reference.eval(&expression).unwrap();
        let prepared = (0..prepared_count)
            .rev()
            .map(|index| process.heap.stack_get(index).unwrap())
            .collect::<Vec<_>>();
        let list = make_list(&mut process, prepared).unwrap();
        let mut vm = Vm::new([]);
        let actual = super::tests::finish_now(&mut vm, &mut process, &[list]);
        assert_eq!(to_owned(actual).unwrap(), expected);
        assert!(vm.code.loaded.contains_key("boot_loop1_batch_a"));
        assert!(vm.code.loaded.contains_key("boot_loop1_batch_b"));
        for path in paths {
            std::fs::remove_file(path).unwrap();
        }
    }
}
