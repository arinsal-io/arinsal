//! Port of erts/emulator/beam/erl_gc.c, OTP-29.1.1: the collection after a BIF call.

use crate::Process;
use arinsal_term::{THE_NON_VALUE, Term};

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
        if result == THE_NON_VALUE && p.heap.abi.exc.freason == arinsal_term::exc::TRAP {
            p.heap.save_live_frags_mark();
        }
        return result;
    }
    let collected = if result == THE_NON_VALUE {
        let live = if p.heap.abi.exc.freason == arinsal_term::exc::TRAP {
            usize::from(p.heap.abi.arity)
        } else {
            arity
        };
        p.collect_heap_roots_objv(&mut regs[..live], &mut [], 0)
            .map(|stats| (stats, THE_NON_VALUE))
    } else {
        let mut val = [crate::native_hooks::from_raw(result)];
        p.collect_heap_roots_objv(&mut [], &mut val, 0)
            .map(|stats| (stats, crate::native_hooks::raw(val[0])))
    };
    match collected {
        Ok((stats, result)) => {
            // BUMP_REDS(p, cost), and the scheduler's collection statistics
            // (erl_gc.c:922-932, garbage_collect).
            crate::natives::sys::after_collection(p, stats.collections, stats.words_reclaimed);
            p.charge_gc_stats(&stats);
            result
        }
        Err(_) => {
            crate::native_hooks::set_error(p, "system_limit");
            THE_NON_VALUE
        }
    }
}
