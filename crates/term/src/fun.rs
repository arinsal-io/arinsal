//! OTP 29 two-word fun head and opaque code-table entries.
use crate::{Atom, FUN, Term};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Immutable local fun entry, identified independently of a code address.
///
/// Layout mirrors OTP `ErlFunEntry`: native dispatch addresses come first so
/// BeamAsm can load `addresses[code_ix]` from offset zero like `ErtsDispatchable`.
#[derive(Debug)]
pub struct FunEntry {
    /// Native trampoline addresses for the two BEAM code generations.
    ///
    /// Must remain the first field: `call_fun` loads `addresses[0]` from the
    /// fun-entry pointer (Port of `ErlFunEntry.dispatch`, OTP-29.1.1).
    pub dispatch_target: [AtomicUsize; 2],
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
    /// Code allocation identities paired with `dispatch`.
    pub dispatch_code: [AtomicUsize; 2],
    /// Code-table generations paired with `dispatch`.
    pub dispatch_epoch: [AtomicU64; 2],
}

impl Clone for FunEntry {
    fn clone(&self) -> Self {
        Self {
            dispatch_target: std::array::from_fn(|index| {
                AtomicUsize::new(self.dispatch_target[index].load(Ordering::Acquire))
            }),
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
            dispatch_code: std::array::from_fn(|index| {
                AtomicUsize::new(self.dispatch_code[index].load(Ordering::Acquire))
            }),
            dispatch_epoch: std::array::from_fn(|index| {
                AtomicU64::new(self.dispatch_epoch[index].load(Ordering::Acquire))
            }),
        }
    }
}

impl FunEntry {
    /// Publish the native trampoline for one BEAM code generation.
    pub fn set_dispatch_target(&self, code_index: usize, target: usize) {
        if let Some(slot) = self.dispatch_target.get(code_index) {
            slot.store(target, Ordering::Release);
        }
    }

    /// Read the native trampoline for one BEAM code generation.
    pub fn get_dispatch_target(&self, code_index: usize) -> Option<usize> {
        let target = self
            .dispatch_target
            .get(code_index)?
            .load(Ordering::Acquire);
        (target != 0).then_some(target)
    }

    /// Publish a resolved module and code target for one OTP code index.
    pub fn set_dispatch(
        &self,
        code_index: usize,
        module_id: usize,
        target: usize,
        code: usize,
        epoch: u64,
    ) {
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
        self.dispatch_code[code_index].store(code, Ordering::Relaxed);
        self.dispatch_epoch[code_index].store(epoch, Ordering::Relaxed);
        slot.store(packed, Ordering::Release);
    }

    /// Read the resolved target if it still names this module code allocation.
    pub fn get_dispatch(&self, code_index: usize) -> Option<(usize, usize, usize, u64)> {
        let packed = self.dispatch.get(code_index)?.load(Ordering::Acquire);
        if packed == 0 {
            return None;
        }
        let packed = packed - 1;
        let code = self.dispatch_code[code_index].load(Ordering::Relaxed);
        let epoch = self.dispatch_epoch[code_index].load(Ordering::Relaxed);
        Some(((packed >> 32) as usize, packed as u32 as usize, code, epoch))
    }
}

/// Export fun entry for `fun M:F/A`, with a cached pointer to its node export slot.
#[derive(Debug)]
#[repr(C)]
pub struct ExportEntry {
    /// Export slot cached after the first native call; zero means unresolved.
    dispatch: AtomicUsize,
    /// Module.
    pub module: Atom,
    /// Function.
    pub function: Atom,
    /// Arity.
    pub arity: u8,
}

/// Byte offset of [`ExportEntry`]'s cached dispatch pointer for generated loads.
pub const EXPORT_DISPATCH_OFFSET: u32 = core::mem::offset_of!(ExportEntry, dispatch) as u32;

impl ExportEntry {
    /// Creates an unresolved export fun entry.
    pub const fn new(module: Atom, function: Atom, arity: u8) -> Self {
        Self {
            dispatch: AtomicUsize::new(0),
            module,
            function,
            arity,
        }
    }

    /// Caches the node's stable export table slot for generated export fun calls.
    pub fn set_dispatch(&self, dispatch: usize) {
        self.dispatch.store(dispatch, Ordering::Release);
    }

    /// Returns the cached export slot, if this fun has been resolved in its node.
    pub fn dispatch(&self) -> Option<usize> {
        let dispatch = self.dispatch.load(Ordering::Acquire);
        (dispatch != 0).then_some(dispatch)
    }
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
    /// The owning heap and retained entry must remain live during the view.
    pub unsafe fn fun_ref<'a>(self) -> Option<FunRef<'a>> {
        let h = self.header()?;
        if h & 63 != FUN {
            return None;
        }
        // SAFETY: fun header encodes kind and free-variable count; word one is retained Arc data.
        let p = unsafe { self.raw_ptr() };
        if h & (1 << 24) != 0 {
            // SAFETY: export funs retain their ExportEntry pointer.
            let entry = unsafe { &*(*p.add(1) as *const ExportEntry) };
            Some(FunRef::Export { entry })
        } else {
            // SAFETY: local funs retain their FunEntry pointer and allocate num_free variables.
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

/// Retain a fun-table entry by its raw heap pointer during a deep copy.
pub(crate) unsafe fn clone_fun_entry(ptr: *const FunEntry) -> Arc<FunEntry> {
    // SAFETY: The source heap retains one strong Arc reference.
    unsafe {
        Arc::increment_strong_count(ptr);
        Arc::from_raw(ptr)
    }
}
/// Retain an export-table entry by its raw heap pointer during a deep copy.
pub(crate) unsafe fn clone_export_entry(ptr: *const ExportEntry) -> Arc<ExportEntry> {
    // SAFETY: The source heap retains one strong Arc reference.
    unsafe {
        Arc::increment_strong_count(ptr);
        Arc::from_raw(ptr)
    }
}
