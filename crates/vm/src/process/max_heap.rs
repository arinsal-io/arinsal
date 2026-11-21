use super::*;

/// Port of erts/emulator/beam/erl_gc.c (ERTS_ABANDON_HEAP_COST), OTP-29.1.1.
pub(super) const ABANDON_HEAP_COST: i32 = 10;

/// `max_heap_size` flag. Size 0 disables the check, matching `MAX_HEAP_SIZE_GET`.
///
/// g_proc_sched. Port of erts/emulator/beam/erl_gc.c:3824 (`erts_max_heap_size`), OTP-29.1.1.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MaxHeap {
    pub size: u64,
    pub kill: bool,
    pub log: bool,
    pub include_shared_binaries: bool,
}

impl Default for MaxHeap {
    fn default() -> Self {
        Self {
            size: 0,
            kill: true,
            log: true,
            include_shared_binaries: false,
        }
    }
}

impl Process {
    /// Whether this process has a `max_heap_size` limit. The peak is tracked only then.
    pub(super) fn max_heap_limited(&self) -> bool {
        self.cold
            .as_ref()
            .is_some_and(|cold| cold.max_heap.size != 0)
    }
}

/// Called by the collection once the heap it would grow to (`used` words) is over the limit:
/// logs the error report (`MAX_HEAP_SIZE_LOG`), sends the `gc_max_heap_size` trace event to a
/// GC tracer, and returns whether the process is killed (`MAX_HEAP_SIZE_KILL`). As in erts,
/// every collection over the limit reports: a killed process collects no more.
// Port of erts/emulator/beam/erl_gc.c:3741-3822 (reached_max_heap_size), OTP-29.1.1.
pub(super) fn reached_max_heap_size(
    process: &mut Process,
    limit: MaxHeap,
    check: arinsal_term::MaxHeapCollectionCheck,
) -> bool {
    // `ERTS_IS_P_TRACED_FL(p, F_TRACE_GC)`.
    let traced = process
        .self_pid()
        .filter(|&pid| crate::trace::flags(process, pid) & crate::trace::GC != 0);
    if traced.is_some() || limit.log {
        // The first erts_process_gc_info pass sizes the exact term; the second builds it in
        // ERTS_ALC_T_TMP using the proposed capacities from this collection check.
        let (_gc_info_heap, msg) = crate::natives::proc::process_gc_info(
            process,
            check.extra_heap_size,
            check.extra_old_heap_size,
        );
        if limit.log {
            report_max_heap(process, limit, check.total_heap_size as u64, msg);
        }
        if let Some(pid) = traced {
            // `trace_gc(p, am_gc_max_heap_size, 0, msg)` (erl_trace.c:1439): `msg` is a value,
            // so it is sent as is, without the `{wordsize, Size}` entry.
            crate::trace::emit_process(process, pid, crate::trace::GC, "gc_max_heap_size", &[msg]);
        }
    }
    limit.kill
}

// g_proc_sched. Port of erl_gc.c:3756 (error_logger report in `reached_max_heap_size`),
// OTP-29.1.1.
fn report_max_heap(process: &mut Process, limit: MaxHeap, used: u64, gc_info: Term) {
    let Some(runtime) = process.runtime else {
        return;
    };
    let Some(self_pid) = process.self_pid() else {
        return;
    };
    let Some(pid) = self_pid.to_term() else {
        return;
    };
    let node_name =
        { crate::node_tables::is_alive().then(|| crate::node_tables::this_node().0.to_owned()) };
    let mut format = String::from("     Process:            ~p ");
    if node_name.is_some() {
        format.push_str("on node ~p");
    }
    format.push_str("~n     Context:            maximum heap size reached~n     Max Heap Size:      ~p~n     Total Heap Size:    ~p~n     Kill:               ~p~n     Error Logger:       ~p~n     Message Queue Len:  ~p~n     GC Info:            ~p~n     Stacktrace:         ~p~n");
    let group_leader = process
        .group_leader
        .and_then(Pid::to_term)
        .unwrap_or(Term::NIL);
    let bool_atom = |on: bool| {
        Term::atom(if on {
            arinsal_term::atoms::TRUE
        } else {
            arinsal_term::atoms::FALSE
        })
    };
    // `erts_factory_tmp_init` holds both the stacktrace and logger arguments in ERTS_ALC_T_TMP.
    let depth = crate::erl_init::erts_backtrace_depth();
    let (mut heap, stacktrace) = crate::stacktrace::build_tmp(process, depth)
        .expect("erts_build_stacktrace in temporary factory");
    let mut args = vec![pid];
    if let Some(node_name) = node_name {
        let node = arinsal_term::global_atoms()
            .intern(&node_name)
            .expect("erts_this_node system name atom");
        args.push(Term::atom(node));
    }
    args.extend([
        Term::small(limit.size as i64).expect("max_heap_size fits a small integer"),
        Term::small(used as i64).expect("total heap size fits a small integer"),
        bool_atom(limit.kill),
        Term::atom(arinsal_term::atoms::TRUE),
        Term::small(process.inbox.len() as i64).expect("message queue length fits a small integer"),
        gc_info,
        stacktrace,
    ]);
    let args = TermBuilder::new(&mut heap)
        .list_from_iter(args)
        .expect("erts_produce_heap logger arguments");
    crate::utils::send_error_term_to_logger(runtime, self_pid, group_leader, &format, args);
}
