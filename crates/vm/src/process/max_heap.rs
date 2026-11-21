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
pub(super) fn reached_max_heap_size(process: &mut Process, limit: MaxHeap, used: u64) -> bool {
    // `ERTS_IS_P_TRACED_FL(p, F_TRACE_GC)`.
    let traced = process
        .self_pid()
        .filter(|&pid| crate::trace::flags(process, pid) & crate::trace::GC != 0);
    if traced.is_some() || limit.log {
        // `msg = erts_process_gc_info(p, ...)`, shared by the report and the trace event.
        let msg = crate::natives::proc::process_gc_info(process).unwrap_or(Term::NIL);
        if limit.log {
            report_max_heap(process, limit, used, msg);
        }
        if let Some(pid) = traced {
            // `trace_gc(p, am_gc_max_heap_size, 0, msg)` (erl_trace.c:1439): `msg` is a value,
            // so it is sent as is, without the `{wordsize, Size}` entry.
            crate::trace::emit_process(process, pid, crate::trace::GC, "gc_max_heap_size", &[msg]);
        }
    }
    limit.kill
}

/// Off-heap binary words reachable from `objv` (the X register roots the caller holds), the
/// mailbox and the dictionary.
pub(super) fn off_heap_binary_words(process: &Process, objv: &[Term]) -> usize {
    let mut seen = HashSet::new();
    let mut bytes = HashMap::<usize, usize>::new();
    let mut stack = Vec::new();
    for term in objv.iter().copied().chain(process.inbox.iter().copied()) {
        stack.push(term);
    }
    if let Some(dictionary) = &process.dictionary {
        for (key, value) in dictionary.entries() {
            stack.push(key);
            stack.push(value);
        }
    }
    for index in 0..process.heap.stack_words() {
        if let Some(term) = process.heap.stack_get(index) {
            stack.push(term);
        }
    }
    while let Some(term) = stack.pop() {
        if !term.is_pointer() {
            continue;
        }
        // SAFETY: The term is a live pointer on this process heap. The bit
        // pattern is an identity for the DAG walk, not a dereference.
        let bits = unsafe { term.raw_bits() };
        if !seen.insert(bits) {
            continue;
        }
        // SAFETY: The owning heap stays live for this walk; no collection runs.
        if let Some(binary) = unsafe { term.binary_ref() } {
            if binary.bytes().len() > 64 {
                bytes
                    .entry(binary.bytes().as_ptr() as usize)
                    .or_insert(binary.bytes().len());
            }
            continue;
        }
        // SAFETY: The cons cell borrows this live heap; no collection runs.
        if let Some((head, tail)) = unsafe { term.cons_ref() } {
            stack.push(head);
            stack.push(tail);
            continue;
        }
        // SAFETY: The tuple borrows this live heap; no collection runs.
        if let Some(tuple) = unsafe { term.tuple_ref() } {
            for index in 0..tuple.len() {
                if let Some(element) = tuple.get(index) {
                    stack.push(element);
                }
            }
            continue;
        }
        // SAFETY: The map borrows this live heap; no collection runs.
        if let Some(map) = unsafe { term.flatmap_ref() } {
            for (key, value) in map.iter() {
                stack.push(key);
                stack.push(value);
            }
            continue;
        }
        // SAFETY: The fun borrows this live heap; no collection runs.
        if let Some(fun) = unsafe { term.fun_ref() } {
            for index in 0..fun.num_free() {
                if let Some(value) = fun.free(index) {
                    stack.push(value);
                }
            }
        }
    }
    bytes
        .values()
        .fold(0, |sum, len| sum.saturating_add(len.div_ceil(8)))
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
    // `erts_build_stacktrace(&hfact, p, 0, erts_backtrace_depth, 1)`.
    let depth = crate::erl_init::erts_backtrace_depth();
    let stacktrace = crate::stacktrace::build(process, depth).unwrap_or(Term::NIL);
    let built = (|| -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let mut args = vec![pid];
        if let Some(node_name) = node_name {
            args.push(Term::atom(
                arinsal_term::global_atoms()
                    .intern(&node_name)
                    .map_err(|error| VmError::Unsupported(format!("node atom: {error:?}")))?,
            ));
        }
        args.extend([
            Term::small(limit.size as i64).unwrap_or(Term::NIL),
            Term::small(used as i64).unwrap_or(Term::NIL),
            bool_atom(limit.kill),
            Term::atom(arinsal_term::atoms::TRUE),
            Term::small(process.inbox.len() as i64).unwrap_or(Term::NIL),
            gc_info,
            stacktrace,
        ]);
        builder
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("logger args: {error:?}")))
    })();
    if let Ok(args) = built {
        crate::utils::send_error_term_to_logger(runtime, self_pid, group_leader, &format, args);
    }
}
