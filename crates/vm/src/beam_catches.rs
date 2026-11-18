//! Catch handler tables of native code: the pools of `bccix[ERTS_NUM_CODE_IX]`.
//!
//! Port of erts/emulator/beam/beam_catches.c and beam_catches.h, OTP-29.1.1. A catch tag on
//! the stack (`make_catch(i)`) indexes the table of `erts_active_code_ix()`. Each code index
//! has a pool (free list, high mark, table size, table); the table area itself is shared by
//! the pools: a staging index starts as a copy of the active pool and shares its table until
//! `beam_catches_cons` has to grow it. Used slots are read-only while their module is not
//! purged, so readers take no lock; the free lists and high marks are protected by the code
//! modification permission.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::code_ix::CodeIndexes;
use arinsal_term::ERTS_NUM_CODE_IX;

/// R14B04 has about 380 catches when starting erlang.
const DEFAULT_TABSIZE: usize = 1024;

/// End of a module's catch list (`(unsigned)-1`).
pub(crate) const BEAM_CATCHES_NIL: u32 = u32::MAX;

/// `beam_catch_t`: the handler address and the next slot of the module's list or the free list.
struct BeamCatch {
    cp: AtomicUsize,
    cdr: AtomicU32,
}

/// The `beam_catches` area of a pool, `tabsize` slots. Shared by pools through the `Arc`;
/// the last pool that drops it frees it (`gc_old_vec`).
pub(crate) struct CatchVec(Box<[BeamCatch]>);

impl CatchVec {
    fn with_size(tabsize: usize) -> Self {
        Self(
            (0..tabsize)
                .map(|_| BeamCatch {
                    cp: AtomicUsize::new(0),
                    cdr: AtomicU32::new(0),
                })
                .collect(),
        )
    }

    /// `tabsize`.
    fn tabsize(&self) -> usize {
        self.0.len()
    }
}

/// `struct bc_pool`.
#[derive(Clone)]
struct BcPool {
    free_list: i32,
    high_mark: u32,
    beam_catches: Arc<CatchVec>,
    is_staging: bool,
}

/// `static struct bc_pool bccix[ERTS_NUM_CODE_IX]`. The pools hold the loader-side state; the
/// readers' view of each `beam_catches` is published by [`CodeIndexes`] in `catch_vec`.
pub(crate) struct Bccix(Mutex<[BcPool; ERTS_NUM_CODE_IX]>);

// Port of erts/emulator/beam/beam_catches.c:59-75 (beam_catches_init), OTP-29.1.1.
/// Creates `bccix` with the default table in every pool; returns it with the shared table.
pub(crate) fn beam_catches_init() -> (Bccix, Arc<CatchVec>) {
    let vec = Arc::new(CatchVec::with_size(DEFAULT_TABSIZE));
    // erts marks the staging pool for the initial load, which never calls
    // beam_catches_start_staging; every load here stages first.
    let pools = std::array::from_fn(|_| BcPool {
        free_list: -1,
        high_mark: 0,
        beam_catches: Arc::clone(&vec),
        is_staging: false,
    });
    (Bccix(Mutex::new(pools)), vec)
}

impl Bccix {
    fn pools(&self) -> std::sync::MutexGuard<'_, [BcPool; ERTS_NUM_CODE_IX]> {
        self.0.lock().unwrap_or_else(|error| error.into_inner())
    }
}

// Port of erts/emulator/beam/beam_catches.c:89-99 (beam_catches_start_staging), OTP-29.1.1.
/// The staging pool becomes a copy of the active one (sharing its table).
pub(crate) fn beam_catches_start_staging(code: &CodeIndexes) {
    let dst = code.staging();
    let src = code.active();
    let mut pools = code.bccix().pools();
    debug_assert!(!pools[src].is_staging && !pools[dst].is_staging);
    pools[dst] = pools[src].clone();
    // The previous table of `dst` is dropped by the publish (`gc_old_vec`).
    code.store_catch_vec(dst, Arc::clone(&pools[dst].beam_catches));
    pools[dst].is_staging = true;
}

// Port of erts/emulator/beam/beam_catches.c:102-105 (beam_catches_end_staging), OTP-29.1.1.
pub(crate) fn beam_catches_end_staging(code: &CodeIndexes, _commit: bool) {
    code.bccix().pools()[code.staging()].is_staging = false;
}

// Port of erts/emulator/beam/beam_catches.c:107-144 (beam_catches_cons), OTP-29.1.1.
// The `cppp` out parameter is dropped: every caller (beam_jit_common.cpp, emu_load.c) passes NULL.
/// Adds a catch with handler `cp` to the staging pool in front of the list `cdr`; returns its
/// slot number.
pub(crate) fn beam_catches_cons(code: &CodeIndexes, cp: usize, cdr: u32) -> u32 {
    let mut pools = code.bccix().pools();
    let p = &mut pools[code.staging()];
    debug_assert!(p.is_staging);
    // Allocate from the free list while it is non-empty. If it is empty, allocate at high_mark.
    let i = if p.free_list >= 0 {
        let i = p.free_list as usize;
        p.free_list = p.beam_catches.0[i].cdr.load(Ordering::Relaxed) as i32;
        i
    } else {
        let tabsize = p.beam_catches.tabsize();
        if p.high_mark as usize >= tabsize {
            // No free slots and table is full: realloc table.
            let grown = CatchVec::with_size(tabsize * 2);
            for (new, old) in grown.0.iter().zip(p.beam_catches.0.iter()) {
                new.cp
                    .store(old.cp.load(Ordering::Relaxed), Ordering::Relaxed);
                new.cdr
                    .store(old.cdr.load(Ordering::Relaxed), Ordering::Relaxed);
            }
            let grown = Arc::new(grown);
            code.store_catch_vec(code.staging(), Arc::clone(&grown));
            p.beam_catches = grown;
        }
        let i = p.high_mark as usize;
        p.high_mark += 1;
        i
    };
    p.beam_catches.0[i].cp.store(cp, Ordering::Release);
    p.beam_catches.0[i].cdr.store(cdr, Ordering::Relaxed);
    u32::try_from(i).expect("catch table index fits 32 bits")
}

// Port of erts/emulator/beam/beam_catches.c:146-154 (beam_catches_car), OTP-29.1.1.
/// Handler address of catch `i` in `bccix[erts_active_code_ix()]`. `None` for a slot that is
/// out of range or empty: erts exits there, but this scan also meets catch tags of interpreter
/// frames, which are not in this table.
pub(crate) fn beam_catches_car(code: &CodeIndexes, i: u32) -> Option<usize> {
    let cp = code.with_active_catch_vec(|vec| {
        vec.0
            .get(usize::try_from(i).ok()?)
            .map(|c| c.cp.load(Ordering::Acquire))
    })?;
    (cp != 0).then_some(cp)
}

// Port of erts/emulator/beam/beam_catches.c:166-205 (beam_catches_delmod), OTP-29.1.1.
/// Frees the catches of a purged module: the list starting at `head`, whose handlers lie in
/// `[code_start, code_start + code_bytes)`, moves to the free list of `code_ix`.
pub(crate) fn beam_catches_delmod(
    code: &CodeIndexes,
    head: u32,
    code_start: usize,
    code_bytes: usize,
    code_ix: usize,
) {
    let mut pools = code.bccix().pools();
    let p = &mut pools[code_ix];
    let mut i = head;
    while i != BEAM_CATCHES_NIL {
        let Some(slot) = p.beam_catches.0.get(i as usize) else {
            crate::natives::node::erts_exit_dump(&format!(
                "beam_catches_delmod: index {i:#x} is out of range"
            ));
        };
        let catch_addr = slot.cp.load(Ordering::Relaxed);
        if !(code_start..code_start + code_bytes).contains(&catch_addr) {
            crate::natives::node::erts_exit_dump(&format!(
                "beam_catches_delmod: item {i:#x} has cp {catch_addr:#x} which is not in module's range [{code_start:#x},{:#x}[",
                code_start + code_bytes
            ));
        }
        slot.cp.store(0, Ordering::Release);
        let cdr = slot.cdr.load(Ordering::Relaxed);
        slot.cdr.store(p.free_list as u32, Ordering::Relaxed);
        p.free_list = i as i32;
        i = cdr;
    }
}
