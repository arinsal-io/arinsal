//! Port of erts/emulator/beam/erl_gc.c, OTP-29.1.1: the collection entry points BeamAsm
//! generated code and the BIF return path call by symbol.

use crate::Process;
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{THE_NON_VALUE, Term, exc};

/// `erts_gc_after_bif_call_lhf(p, live_hf_end, result, regs, arity)`: collects after a BIF
/// whose result left a collection desired. A term result is the only root and is returned
/// moved; the non-value keeps `regs[..arity]` live (`c_p->arity` registers after a trap).
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1.
pub(crate) fn erts_gc_after_bif_call_lhf(
    p: &mut Process,
    live_hf_end: usize,
    result: u64,
    regs: &mut [Term],
    arity: usize,
) -> u64 {
    // `if (!p->mbuf) live_hf_end = ERTS_INVALID_HFRAG_PTR` is applied where the collection
    // takes the mark (ProcessHeap::take_live_hf_end).
    p.heap.set_live_hf_end(live_hf_end);
    if !p.heap.gc_enabled() {
        // The first trap with collection disabled saves live_hf_end in `c_p->live_hf_end`.
        if result == THE_NON_VALUE && p.heap.abi.exc.freason == exc::TRAP {
            p.heap.save_live_frags_mark();
        }
        return result;
    }
    let (stats, result) = if result == THE_NON_VALUE {
        let live = if p.heap.abi.exc.freason == exc::TRAP {
            usize::from(p.heap.abi.arity)
        } else {
            arity
        };
        (
            p.collect_heap_roots_objv(&mut regs[..live], &mut [], 0),
            THE_NON_VALUE,
        )
    } else {
        let mut val = [crate::native_hooks::from_raw(result)];
        let stats = p.collect_heap_roots_objv(&mut [], &mut val, 0);
        (stats, crate::native_hooks::raw(val[0]))
    };
    // BUMP_REDS(p, cost), and the scheduler's collection statistics
    // (erl_gc.c:922-932, garbage_collect).
    crate::natives::sys::after_collection(p, stats.collections, stats.words_reclaimed);
    p.charge_gc_stats(&stats);
    result
}

/// Collects without changing the process reduction count and returns reductions spent.
// Port of erts/emulator/beam/erl_gc.c:967-980 (erts_garbage_collect_nobump), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_garbage_collect_nobump(
    c_p: *mut ProcessHeader,
    need: usize,
    objv: *mut u64,
    nobj: i32,
    fcalls: i32,
) -> i32 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return 0;
    };
    // `garbage_collect(p, ..., fcalls, ...)` takes the reductions left from the caller, whose
    // FCALLS lives in a register; a delayed collection (delay_garbage_collection) reads them
    // from `p->fcalls` here.
    process.heap.abi.fcalls = fcalls;
    let nobj = usize::try_from(nobj).expect("erts_garbage_collect_nobump: nobj >= 0");
    if process.gc_must_fetch_signals() {
        let fetched = arinsal_sched::erts_proc_sched_data(process, |process, esdp| {
            arinsal_sched::RunCtx::with_current(esdp, |ctx| process.fetch_signals(ctx))
        })
        .flatten();
        if !matches!(fetched, Some(Ok(()))) {
            set_system_limit(process);
            return 0;
        }
    }
    let reds = crate::raw::beam_common_ffi::with_mut_terms(objv, nobj, |roots| {
        process.ensure_uncharged(need, roots)
    })
    .expect("erts_garbage_collect_nobump: objv holds nobj registers");
    i32::try_from(reds).unwrap_or(i32::MAX).min(fcalls.max(0))
}

fn set_system_limit(process: &mut Process) {
    process.heap.abi.exc.freason = exc::EXC_SYSTEM_LIMIT;
    process.heap.abi.exc.fvalue =
        crate::native_hooks::raw(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_collection_symbol_signature_matches_otp() {
        let _: extern "C" fn(*mut ProcessHeader, usize, *mut u64, i32, i32) -> i32 =
            erts_garbage_collect_nobump;
    }
}
