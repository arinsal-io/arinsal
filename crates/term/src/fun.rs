//! OTP 29 two-word fun head and opaque code-table entries.
use crate::{Atom, FUN, LiteralArea, Term, TermError};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// Number of code indexes (`ERTS_NUM_CODE_IX`): active, staging and the one being retired.
// Port of erts/emulator/beam/code_ix.h:72-78, OTP-29.1.1.
pub const ERTS_NUM_CODE_IX: usize = 3;
/// Length of a dispatch address vector: one slot per code index plus the save_calls slot.
// Port of erts/emulator/beam/code_ix.h:79-80 (ERTS_ADDRESSV_SIZE), OTP-29.1.1.
pub const ERTS_ADDRESSV_SIZE: usize = ERTS_NUM_CODE_IX + 1;
/// Code index of a process with `process_flag(save_calls, N > 0)`.
// Port of erts/emulator/beam/code_ix.h:81 (ERTS_SAVE_CALLS_CODE_IX), OTP-29.1.1.
pub const ERTS_SAVE_CALLS_CODE_IX: usize = ERTS_ADDRESSV_SIZE - 1;

/// `beam_unloaded_fun`: the address every code index of a fun entry without loaded code enters.
static BEAM_UNLOADED_FUN: AtomicUsize = AtomicUsize::new(0);
/// `beam_save_calls_fun`: the address a process saving calls enters for every local fun.
static BEAM_SAVE_CALLS_FUN: AtomicUsize = AtomicUsize::new(0);

/// Publishes the native `unloaded_fun` and `dispatch_save_calls_fun` fragments that new fun
/// entries dispatch to until their code is loaded.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp (beam_unloaded_fun, beam_save_calls_fun
// set from the global fragments at JIT init), OTP-29.1.1.
pub fn set_fun_dispatch_fragments(unloaded_fun: usize, save_calls_fun: usize) {
    BEAM_UNLOADED_FUN.store(unloaded_fun, Ordering::Release);
    BEAM_SAVE_CALLS_FUN.store(save_calls_fun, Ordering::Release);
}

/// The `beam_unloaded_fun` address, zero before the native fragments exist.
pub fn beam_unloaded_fun() -> usize {
    BEAM_UNLOADED_FUN.load(Ordering::Acquire)
}

/// Native entry addresses, one per code index (`ErtsDispatchable`). Fun and export entries
/// both start with one, so `call_fun` loads `addresses[active_code_ix]` from either.
// Port of erts/emulator/beam/code_ix.h:81-85 (ErtsDispatchable), OTP-29.1.1.
#[derive(Debug)]
#[repr(C)]
pub struct ErtsDispatchable {
    /// Native entry addresses indexed by code index; the last slot is the save_calls entry.
    pub addresses: [AtomicUsize; ERTS_ADDRESSV_SIZE],
}

impl ErtsDispatchable {
    /// A dispatchable entering `address` in every code index and `save_calls` in
    /// `ERTS_SAVE_CALLS_CODE_IX`.
    pub const fn new(address: usize, save_calls: usize) -> Self {
        Self {
            addresses: [
                AtomicUsize::new(address),
                AtomicUsize::new(address),
                AtomicUsize::new(address),
                AtomicUsize::new(save_calls),
            ],
        }
    }

    /// The address entered in code index `ix`.
    pub fn address(&self, ix: usize) -> usize {
        self.addresses[ix].load(Ordering::Acquire)
    }

    /// Sets the address entered in code index `ix`.
    pub fn set_address(&self, ix: usize, address: usize) {
        self.addresses[ix].store(address, Ordering::Release);
    }
}

impl Default for ErtsDispatchable {
    /// A fun entry's dispatchable before its code is loaded.
    // Port of erts/emulator/beam/erl_fun.c:87-99 (fun_init), OTP-29.1.1.
    fn default() -> Self {
        Self::new(
            BEAM_UNLOADED_FUN.load(Ordering::Acquire),
            BEAM_SAVE_CALLS_FUN.load(Ordering::Acquire),
        )
    }
}

/// Immutable local fun entry, identified independently of a code address.
///
/// Layout mirrors OTP `ErlFunEntry`: the dispatchable comes first so BeamAsm loads
/// `addresses[active_code_ix]` from offset zero, as for an export entry.
#[derive(Debug)]
#[repr(C)]
pub struct FunEntry {
    /// Native entry addresses per code index (`ErlFunEntry.dispatch`).
    ///
    /// Must remain the first field: `call_fun` loads `addresses[active_code_ix]` from the
    /// fun-entry pointer.
    // Port of erts/emulator/beam/erl_fun.h:31-35, OTP-29.1.1.
    pub dispatch_target: ErtsDispatchable,
    /// Address hidden while the active code index is being purged.
    // Port of erts/emulator/beam/erl_fun.h:37, OTP-29.1.1.
    pub pend_purge_address: AtomicUsize,
    /// Defining module.
    pub module: Atom,
    /// Function arity.
    pub arity: u8,
    /// New-style index.
    pub index: u32,
    /// Module MD5-derived unique bytes.
    pub uniq: [u8; 16],
    /// Old unique number, retained for stable `phash2`.
    pub old_uniq: u32,
    /// Old index, retained for ETF compatibility.
    pub old_index: u32,
    /// Original pid carried by ETF; not part of the heap fun identity.
    pub pid: Term,
    /// Resolved BEAM dispatch targets for the two code generations.
    pub dispatch: [AtomicU64; 2],
    /// Code-table generations paired with `dispatch`.
    pub dispatch_epoch: [AtomicU64; 2],
}

impl Clone for FunEntry {
    fn clone(&self) -> Self {
        Self {
            dispatch_target: ErtsDispatchable {
                addresses: std::array::from_fn(|ix| {
                    AtomicUsize::new(self.dispatch_target.address(ix))
                }),
            },
            pend_purge_address: AtomicUsize::new(self.pend_purge_address.load(Ordering::Acquire)),
            module: self.module,
            arity: self.arity,
            index: self.index,
            uniq: self.uniq,
            old_uniq: self.old_uniq,
            old_index: self.old_index,
            pid: self.pid,
            dispatch: std::array::from_fn(|index| {
                AtomicU64::new(self.dispatch[index].load(Ordering::Acquire))
            }),
            dispatch_epoch: std::array::from_fn(|index| {
                AtomicU64::new(self.dispatch_epoch[index].load(Ordering::Acquire))
            }),
        }
    }
}

impl FunEntry {
    /// Sets the code `address` entered in code index `ix`.
    // Port of erts/emulator/beam/erl_fun.c:48-53 (erts_set_fun_code), OTP-29.1.1.
    pub fn set_fun_code(&self, ix: usize, address: usize) {
        assert_eq!(self.pend_purge_address.load(Ordering::Acquire), 0);
        self.dispatch_target.set_address(ix, address);
    }

    /// Copies one code index's fun address into the staging index.
    // Port of erts/emulator/beam/erl_fun.c:106-112 (fun_stage), OTP-29.1.1.
    pub fn stage_fun_code(&self, src_ix: usize, dst_ix: usize) {
        assert_eq!(self.pend_purge_address.load(Ordering::Acquire), 0);
        self.dispatch_target
            .set_address(dst_ix, self.dispatch_target.address(src_ix));
    }

    /// Hides this entry's active address when it belongs to the purged code area.
    // Port of erts/emulator/beam/erl_fun.c:157-179 (fun_purge_foreach), OTP-29.1.1.
    pub fn prepare_fun_purge(&self, code_ix: usize, code: std::ops::Range<usize>) -> bool {
        let address = self.dispatch_target.address(code_ix);
        if !code.contains(&address) {
            return false;
        }
        assert_eq!(self.pend_purge_address.load(Ordering::Acquire), 0);
        self.pend_purge_address.store(address, Ordering::Release);
        self.dispatch_target
            .set_address(code_ix, BEAM_UNLOADED_FUN.load(Ordering::Acquire));
        true
    }

    /// Restores the active address in the first phase of an aborted purge.
    // Port of erts/emulator/beam/erl_fun.c:190-203 (erts_fun_purge_abort_prepare), OTP-29.1.1.
    pub fn abort_fun_purge_prepare(&self, code_ix: usize) {
        assert_eq!(
            self.dispatch_target.address(code_ix),
            BEAM_UNLOADED_FUN.load(Ordering::Acquire)
        );
        let address = self.pend_purge_address.load(Ordering::Acquire);
        assert_ne!(address, 0);
        self.dispatch_target.set_address(code_ix, address);
    }

    /// Clears the purge marker after restoration and thread progress.
    // Port of erts/emulator/beam/erl_fun.c:205-222 (erts_fun_purge_abort_finalize), OTP-29.1.1.
    pub fn abort_fun_purge_finalize(&self, code_ix: usize) {
        assert_ne!(
            self.dispatch_target.address(code_ix),
            BEAM_UNLOADED_FUN.load(Ordering::Acquire)
        );
        self.pend_purge_address.store(0, Ordering::Release);
    }

    /// Clears a completed purge marker while leaving the active address unloaded.
    // Port of erts/emulator/beam/erl_fun.c:224-239 (erts_fun_purge_complete), OTP-29.1.1.
    pub fn complete_fun_purge(&self, code_ix: usize) {
        assert_eq!(
            self.dispatch_target.address(code_ix),
            BEAM_UNLOADED_FUN.load(Ordering::Acquire)
        );
        self.pend_purge_address.store(0, Ordering::Release);
    }

    /// Whether code index `ix` enters loaded code rather than `beam_unloaded_fun`.
    // Port of erts/emulator/beam/erl_fun.c:55-58 (erts_is_fun_loaded), OTP-29.1.1.
    pub fn is_fun_loaded(&self, ix: usize) -> bool {
        self.dispatch_target.address(ix) != BEAM_UNLOADED_FUN.load(Ordering::Acquire)
    }

    /// The loaded code address of code index `ix`, if any.
    pub fn fun_code(&self, ix: usize) -> Option<usize> {
        self.is_fun_loaded(ix)
            .then(|| self.dispatch_target.address(ix))
    }

    /// Publish a resolved module and code target for one OTP code index.
    pub fn set_dispatch(&self, code_index: usize, module_id: usize, target: usize, epoch: u64) {
        let Some(slot) = self.dispatch.get(code_index) else {
            return;
        };
        let Some(module_id) = u32::try_from(module_id).ok().filter(|id| *id < (1 << 26)) else {
            return;
        };
        let Some(target) = u32::try_from(target).ok() else {
            return;
        };
        // `+1` reserves zero for an unresolved entry.
        let Some(packed) = ((u64::from(module_id) << 32) | u64::from(target)).checked_add(1) else {
            return;
        };
        self.dispatch_epoch[code_index].store(epoch, Ordering::Relaxed);
        slot.store(packed, Ordering::Release);
    }

    /// Read the resolved module, target and code-table generation.
    pub fn get_dispatch(&self, code_index: usize) -> Option<(usize, usize, u64)> {
        let packed = self.dispatch.get(code_index)?.load(Ordering::Acquire);
        if packed == 0 {
            return None;
        }
        let packed = packed - 1;
        let epoch = self.dispatch_epoch[code_index].load(Ordering::Relaxed);
        Some(((packed >> 32) as usize, packed as u32 as usize, epoch))
    }
}

/// OTP's `ErtsCodeMFA` layout (`ErtsCodeInfo.mfa`): what `c_p->current` points at.
// Port of erts/emulator/beam/code_ix.h:89-99, OTP-29.1.1.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ErtsCodeMfa {
    /// Tagged module atom.
    pub module: u64,
    /// Tagged function atom.
    pub function: u64,
    /// Word-sized arity.
    pub arity: u64,
}

/// Export entry (`Export`): one per MFA and code scope, shared by external calls and by every
/// `fun M:F/A` of that MFA, whose fun thing points at it.
// Port of erts/emulator/beam/export.h:39-75 (Export: dispatch first, then the info word and
// the MFA), OTP-29.1.1.
#[derive(Debug)]
#[repr(C)]
pub struct ExportEntry {
    /// Native entry addresses indexed by code index (`Export.dispatch`); must stay first.
    pub dispatch: ErtsDispatchable,
    /// The runtime's descriptor of this export (its BIF and call class), set once when the
    /// node creates the export. Generated code reads it next to the addresses.
    pub info: AtomicUsize,
    /// Non-zero when this BIF export is traced. The light-BIF fragment loads it before the call.
    // Port of erts/emulator/beam/export.h:58 (Export.is_bif_traced), OTP-29.1.1.
    pub is_bif_traced: AtomicI32,
    /// Module.
    pub module: Atom,
    /// Function.
    pub function: Atom,
    /// Arity.
    pub arity: u8,
    /// Globally shared zero-environment fun literal for this export.
    // Port of erts/emulator/beam/export.h:62 and export.c:44-56 (Export.lambda), OTP-29.1.1.
    pub(crate) lambda: OnceLock<Term>,
    /// Index into the BIF table, or -1 when this is not a BIF (`Export.bif_number`).
    // Port of erts/emulator/beam/export.h:55 (Export.bif_number), OTP-29.1.1.
    pub bif_number: AtomicI32,
    /// `Export.trampoline`: what the shared export trampoline stands for while an address of
    /// this export enters it.
    // Port of erts/emulator/beam/export.h:64-102 (Export.trampoline), OTP-29.1.1.
    pub trampoline: ExportTrampoline,
    /// `Export.info.mfa`: `current` points here while the export's trampoline runs a BIF.
    // Port of erts/emulator/beam/export.h:66 (Export.info), OTP-29.1.1.
    pub mfa: ErtsCodeMfa,
}

/// `Export.trampoline` of the JIT: the opcode it stands for and its one argument word. BeamAsm
/// enters one shared `beam_export_trampoline` for every export, which reads these.
// Port of erts/emulator/beam/export.h:64-102, OTP-29.1.1.
#[derive(Debug)]
#[repr(C)]
pub struct ExportTrampoline {
    /// [`TRAMPOLINE_NONE`], [`TRAMPOLINE_CALL_ERROR_HANDLER`] or [`TRAMPOLINE_BREAKPOINT`]
    /// (`trampoline.common.op`).
    pub op: AtomicUsize,
    /// `trampoline.breakpoint.address` (the code a global call breakpoint continues to) or
    /// `trampoline.not_loaded.deferred` (an exported function of code whose on_load function
    /// has not finished).
    pub address: AtomicUsize,
}

/// `trampoline.common.op == 0`.
pub const TRAMPOLINE_NONE: usize = 0;
/// `op_call_error_handler`.
pub const TRAMPOLINE_CALL_ERROR_HANDLER: usize = 1;
/// `op_i_generic_breakpoint`.
pub const TRAMPOLINE_BREAKPOINT: usize = 2;
/// `op_call_bif_W`: a BIF (or a native the runtime implements) the trampoline calls.
pub const TRAMPOLINE_CALL_BIF: usize = 3;
/// Byte offset of `trampoline.common.op` for generated loads.
pub const EXPORT_TRAMPOLINE_OP_OFFSET: u32 = (core::mem::offset_of!(ExportEntry, trampoline)
    + core::mem::offset_of!(ExportTrampoline, op))
    as u32;

/// Byte offset of [`ExportEntry::info`] for generated loads.
pub const EXPORT_INFO_OFFSET: u32 = core::mem::offset_of!(ExportEntry, info) as u32;
/// Byte offset of [`ExportEntry::mfa`] (`Export.info.mfa`): the address `c_p->current` holds.
pub const EXPORT_MFA_OFFSET: u32 = core::mem::offset_of!(ExportEntry, mfa) as u32;
const _: () = assert!(core::mem::offset_of!(ExportEntry, dispatch) == 0);
const _: () = assert!(core::mem::offset_of!(FunEntry, dispatch_target) == 0);

impl ExportEntry {
    /// Creates an export entry for `module:function/arity` outside any node's export table.
    /// Calls through it enter `beam_unloaded_fun`, whose resolver finds the caller's node
    /// export; [`export_get_or_make_stub`] replaces it with the node's own entry whenever the
    /// node is known.
    pub fn new(module: Atom, function: Atom, arity: u8) -> Self {
        let unloaded = BEAM_UNLOADED_FUN.load(Ordering::Acquire);
        Self::with_addresses(module, function, arity, unloaded, unloaded)
    }

    /// Creates an export entry entering `address` in every code index and `save_calls` in
    /// `ERTS_SAVE_CALLS_CODE_IX`.
    // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
    pub const fn with_addresses(
        module: Atom,
        function: Atom,
        arity: u8,
        address: usize,
        save_calls: usize,
    ) -> Self {
        Self {
            dispatch: ErtsDispatchable::new(address, save_calls),
            info: AtomicUsize::new(0),
            is_bif_traced: AtomicI32::new(0),
            module,
            function,
            arity,
            lambda: OnceLock::new(),
            bif_number: AtomicI32::new(-1),
            // Port of erts/emulator/beam/export.c:85-87 (export_init: op_call_error_handler
            // once the opcodes are initialized), OTP-29.1.1.
            trampoline: ExportTrampoline {
                op: AtomicUsize::new(TRAMPOLINE_CALL_ERROR_HANDLER),
                address: AtomicUsize::new(0),
            },
            mfa: ErtsCodeMfa {
                module: Term::atom(module).0,
                function: Term::atom(function).0,
                arity: arity as u64,
            },
        }
    }

    /// `Export.bif_number`, -1 when this is not a BIF.
    pub fn bif_number(&self) -> i32 {
        self.bif_number.load(Ordering::Acquire)
    }

    /// Sets `Export.bif_number` (`install_bifs`).
    pub fn set_bif_number(&self, number: i32) {
        self.bif_number.store(number, Ordering::Release);
    }

    /// `trampoline.common.op`.
    pub fn trampoline_op(&self) -> usize {
        self.trampoline.op.load(Ordering::Acquire)
    }

    /// `trampoline.breakpoint.address` / `trampoline.not_loaded.deferred`.
    pub fn trampoline_address(&self) -> usize {
        self.trampoline.address.load(Ordering::Acquire)
    }

    /// Sets `trampoline.common.op`.
    pub fn set_trampoline_op(&self, op: usize) {
        self.trampoline.op.store(op, Ordering::Release);
    }

    /// Sets `trampoline.breakpoint.address` / `trampoline.not_loaded.deferred`.
    pub fn set_trampoline_address(&self, address: usize) {
        self.trampoline.address.store(address, Ordering::Release);
    }

    /// The runtime descriptor word published by [`ExportEntry::set_info`], zero before it.
    pub fn info(&self) -> usize {
        self.info.load(Ordering::Acquire)
    }

    /// Publishes the runtime descriptor word.
    pub fn set_info(&self, info: usize) {
        self.info.store(info, Ordering::Release);
    }

    /// Publishes `Export.is_bif_traced` for the light-BIF fragment's load.
    // Port of erts/emulator/beam/beam_bp.c:374 (ep->is_bif_traced = ...), OTP-29.1.1.
    pub fn set_bif_traced(&self, traced: bool) {
        self.is_bif_traced
            .store(i32::from(traced), Ordering::Release);
    }

    /// The address entered in code index `ix`.
    pub fn address(&self, ix: usize) -> usize {
        self.dispatch.address(ix)
    }

    /// Sets the address entered in code index `ix`.
    pub fn set_address(&self, ix: usize, address: usize) {
        self.dispatch.set_address(ix, address);
    }

    /// Cached `Export.lambda` literal, if one has been requested.
    pub(crate) fn lambda(&self) -> Option<Term> {
        self.lambda.get().copied()
    }

    /// Copies the address of code index `src` into `dst`.
    // Port of erts/emulator/beam/export.c:100-106 (export_stage), OTP-29.1.1.
    pub fn stage(&self, src: usize, dst: usize) {
        self.set_address(dst, self.address(src));
    }
}

/// Build and retain `Export.lambda` in the global literal area.
// Port of erts/emulator/beam/export.c:44-56 (create_shared_lambda), OTP-29.1.1.
pub(crate) fn export_lambda(entry: Arc<ExportEntry>) -> Result<Term, TermError> {
    // The lambda is published only after the entry is permanent, so a set lambda needs no
    // table lock (erts: `ep->lambda` is read directly, export.c).
    if let Some(lambda) = entry.lambda() {
        return Ok(lambda);
    }
    make_export_entry_permanent(&entry);
    static LITERALS: OnceLock<Mutex<LiteralArea>> = OnceLock::new();
    let literals = LITERALS.get_or_init(|| Mutex::new(LiteralArea::new()));
    let mut literals = literals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(lambda) = entry.lambda() {
        return Ok(lambda);
    }
    let lambda = literals.builder().export_fun_in_heap(entry.as_ref())?;
    let _ = entry.lambda.set(lambda);
    Ok(entry.lambda().unwrap_or(lambda))
}

// This table covers entries whose callers are outside a node's export table.
fn make_export_entry_permanent(entry: &Arc<ExportEntry>) {
    static ENTRIES: OnceLock<Mutex<HashMap<usize, Arc<ExportEntry>>>> = OnceLock::new();
    let entries = ENTRIES.get_or_init(Default::default);
    let mut entries = entries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    entries
        .entry(Arc::as_ptr(entry) as usize)
        .or_insert_with(|| Arc::clone(entry));
}

/// Node hook resolving an external fun identity to its global fun-table entry.
pub type FunEntryStubFn = fn(Arc<FunEntry>) -> Option<Arc<FunEntry>>;

static FUN_ENTRY_STUB: OnceLock<FunEntryStubFn> = OnceLock::new();

/// Installs the runtime's local fun-table lookup used when decoding external terms.
pub fn set_fun_entry_stub_hook(hook: FunEntryStubFn) {
    let _ = FUN_ENTRY_STUB.set(hook);
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FunKey {
    module: Atom,
    index: u32,
    arity: u8,
    uniq: [u8; 16],
}

impl From<&FunEntry> for FunKey {
    fn from(entry: &FunEntry) -> Self {
        Self {
            module: entry.module,
            index: entry.index,
            arity: entry.arity,
            uniq: entry.uniq,
        }
    }
}

impl Hash for FunKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let first = u64::from_ne_bytes(self.uniq[..8].try_into().expect("eight bytes"));
        let second = u64::from_ne_bytes(self.uniq[8..].try_into().expect("eight bytes"));
        state.write_u64(first ^ second ^ u64::from(self.index));
    }
}

fn fallback_fun_table() -> &'static Mutex<HashMap<FunKey, Arc<FunEntry>>> {
    // Standalone ETF decoding still needs a permanent table when no VM scope is active.
    static TABLE: OnceLock<Mutex<HashMap<FunKey, Arc<FunEntry>>>> = OnceLock::new();
    TABLE.get_or_init(Default::default)
}

/// Permanently owns fun entries used by terms, which hold only the table pointer.
pub(crate) fn make_fun_entry_permanent(entry: &Arc<FunEntry>) {
    // Node entries are already held by their code table; this table covers public builders.
    static ENTRIES: OnceLock<Mutex<HashMap<usize, Arc<FunEntry>>>> = OnceLock::new();
    let entries = ENTRIES.get_or_init(Default::default);
    let mut entries = entries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    entries
        .entry(Arc::as_ptr(entry) as usize)
        .or_insert_with(|| Arc::clone(entry));
}

/// Returns the global entry for a decoded local fun, inserting its stub when absent.
// Port of erts/emulator/beam/erl_fun.c:299-309 (erts_fun_entry_get_or_make_stub), OTP-29.1.1.
pub(crate) fn fun_entry_get_or_make_stub(candidate: Arc<FunEntry>) -> Arc<FunEntry> {
    if let Some(entry) = FUN_ENTRY_STUB
        .get()
        .and_then(|hook| hook(Arc::clone(&candidate)))
    {
        return entry;
    }
    let key = FunKey::from(candidate.as_ref());
    let mut table = fallback_fun_table()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(table.entry(key).or_insert(candidate))
}

/// Node hook resolving `module:function/arity` to its export entry
/// (`erts_export_get_or_make_stub`).
pub type ExportStubFn = fn(Atom, Atom, u8) -> Option<Arc<ExportEntry>>;

static EXPORT_STUB: std::sync::OnceLock<ExportStubFn> = std::sync::OnceLock::new();
type FallbackExports = HashMap<(Atom, Atom, u8), Arc<ExportEntry>>;

/// Installs the runtime's export table lookup used by terms built outside a process
/// (literals, `binary_to_term`).
pub fn set_export_stub_hook(hook: ExportStubFn) {
    let _ = EXPORT_STUB.set(hook);
}

/// The export entry of `module:function/arity`, creating a stub when it has none.
// Port of erts/emulator/beam/export.c:200-245 (erts_export_get_or_make_stub), OTP-29.1.1.
pub fn export_get_or_make_stub(module: Atom, function: Atom, arity: u8) -> Arc<ExportEntry> {
    if let Some(entry) = EXPORT_STUB
        .get()
        .and_then(|hook| hook(module, function, arity))
    {
        return entry;
    }
    // Standalone term construction has no node export table, so keep these stubs permanently.
    static FALLBACK: OnceLock<Mutex<FallbackExports>> = OnceLock::new();
    let table = FALLBACK.get_or_init(Default::default);
    let mut table = table
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(
        table
            .entry((module, function, arity))
            .or_insert_with(|| Arc::new(ExportEntry::new(module, function, arity))),
    )
}

/// Borrowed local or export fun.
pub enum FunRef<'a> {
    /// Closure with free variables.
    Local {
        entry: &'a FunEntry,
        free_vars: &'a [u64],
    },
    /// Exported function.
    Export { entry: &'a ExportEntry },
}
impl FunRef<'_> {
    /// Number of captured variables.
    pub fn num_free(&self) -> usize {
        match self {
            Self::Local { free_vars, .. } => free_vars.len(),
            Self::Export { .. } => 0,
        }
    }
    /// Borrow a captured value if this is a local closure.
    pub fn free(&self, index: usize) -> Option<Term> {
        match self {
            Self::Local { free_vars, .. } => free_vars.get(index).copied().map(Term),
            Self::Export { .. } => None,
        }
    }
}
impl Term {
    /// Borrow a fun entry and its captured variables.
    ///
    /// # Safety
    /// The owning heap and process-lifetime code-table entry must remain live during the view.
    pub unsafe fn fun_ref<'a>(self) -> Option<FunRef<'a>> {
        let h = self.header()?;
        if h & 63 != FUN {
            return None;
        }
        // SAFETY: the boxed header encodes the fun kind and environment size.
        let p = unsafe { self.raw_ptr() };
        if h & (1 << 24) != 0 {
            // SAFETY: export entries are permanent export-table entries.
            let entry = unsafe { &*(*p.add(1) as *const ExportEntry) };
            Some(FunRef::Export { entry })
        } else {
            // SAFETY: local fun entries are permanent fun-table entries.
            let entry = unsafe { &*(*p.add(1) as *const FunEntry) };
            // SAFETY: the fun header gives the number of allocated environment words.
            let free_vars =
                unsafe { std::slice::from_raw_parts(p.add(2), ((h >> 16) & 255) as usize) };
            Some(FunRef::Local { entry, free_vars })
        }
    }
}

/// Build a local closure from a retained fun-table entry.
pub(crate) fn local_header(arity: u8, free: usize) -> Option<u64> {
    if free > 255 {
        None
    } else {
        Some(FUN | ((arity as u64) << 8) | ((free as u64) << 16))
    }
}
/// Build an export fun header.
pub(crate) fn export_header(arity: u8) -> u64 {
    FUN | ((arity as u64) << 8) | (1 << 24)
}
